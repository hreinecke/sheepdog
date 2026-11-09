/*
 * Copyright (C) 2026 Hannes Reinecke <hare@suse.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include "sheep.h"
#include "internal_proto.h"
#include "rbtree.h"
#include "list.h"
#include "work.h"
#include "rdma.h"

#define RESOLVE_TIMEOUT 5000

/*
 * Pooled RDMA connection to a peer node's dedicated IO NIC, modeled on the
 * QP/CQ/comp-channel setup in nvmet/rdma.c but acting as the CM initiator
 * instead of the listener. Exclusively owned by whoever holds it (checked
 * out via rdma_conn_get(), returned via rdma_conn_put()/rdma_conn_del()),
 * the same way struct sockfd works for the plain TCP path -- so only ever
 * one request is outstanding on a given connection at a time, and a single
 * pre-posted receive buffer is enough; no request/reply correlation is
 * needed.
 */
struct rdma_conn {
	struct list_node list;		/* membership in entry->idle_list */
	struct rdma_pool_entry *entry;

	struct rdma_cm_id *id;
	struct rdma_event_channel *ec;
	struct ibv_pd *pd;
	struct ibv_cq *scq, *rcq;
	struct ibv_comp_channel *comp;

	struct ibv_mr *data_mr;	/* the in-flight request's data buffer,
					 * registered by rdma_post_request()
					 * and released by rdma_finish_request()
					 */

	struct sd_rdma_ctrl_msg send_buf;
	struct ibv_mr *send_mr;
	struct sd_rdma_ctrl_msg recv_buf;
	struct ibv_mr *recv_mr;
};

struct rdma_pool_entry {
	struct rb_node rb;
	struct node_id nid;
	struct list_head idle_list;
};

static struct sd_mutex rdma_pool_lock = SD_MUTEX_INITIALIZER;
static struct rb_root rdma_pool_root = RB_ROOT;

static int rdma_pool_cmp(const struct rdma_pool_entry *a,
			 const struct rdma_pool_entry *b)
{
	return node_id_cmp(&a->nid, &b->nid);
}

static struct rdma_pool_entry *rdma_pool_search(const struct node_id *nid)
{
	struct rdma_pool_entry key = { .nid = *nid };

	return rb_search(&rdma_pool_root, &key, rb, rdma_pool_cmp);
}

static struct rdma_pool_entry *rdma_pool_get_entry(const struct node_id *nid)
{
	struct rdma_pool_entry *entry;

	sd_mutex_lock(&rdma_pool_lock);
	entry = rdma_pool_search(nid);
	if (!entry) {
		entry = xzalloc(sizeof(*entry));
		entry->nid = *nid;
		INIT_LIST_HEAD(&entry->idle_list);
		rb_insert(&rdma_pool_root, entry, rb, rdma_pool_cmp);
	}
	sd_mutex_unlock(&rdma_pool_lock);

	return entry;
}

static int rdma_conn_post_recv(struct rdma_conn *conn)
{
	struct ibv_recv_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;

	memset(&wr, 0, sizeof(wr));
	memset(&conn->recv_buf, 0, sizeof(conn->recv_buf));

	sge.addr = (uintptr_t)&conn->recv_buf;
	sge.length = sizeof(conn->recv_buf);
	sge.lkey = conn->recv_mr->lkey;

	wr.wr_id = (uintptr_t)conn;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	return ibv_post_recv(conn->id->qp, &wr, &bad_wr);
}

static int rdma_post_ctrl_send(struct rdma_conn *conn)
{
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;

	memset(&wr, 0, sizeof(wr));

	sge.addr = (uintptr_t)&conn->send_buf;
	sge.length = sizeof(conn->send_buf);
	sge.lkey = conn->send_mr->lkey;

	wr.wr_id = (uintptr_t)conn;
	wr.opcode = IBV_WR_SEND;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	return ibv_post_send(conn->id->qp, &wr, &bad_wr);
}

static void rdma_conn_destroy(struct rdma_conn *conn)
{
	if (conn->id && conn->id->qp)
		rdma_destroy_qp(conn->id);
	if (conn->data_mr)
		ibv_dereg_mr(conn->data_mr);
	if (conn->recv_mr)
		ibv_dereg_mr(conn->recv_mr);
	if (conn->send_mr)
		ibv_dereg_mr(conn->send_mr);
	if (conn->rcq)
		ibv_destroy_cq(conn->rcq);
	if (conn->scq)
		ibv_destroy_cq(conn->scq);
	if (conn->comp)
		ibv_destroy_comp_channel(conn->comp);
	if (conn->pd)
		ibv_dealloc_pd(conn->pd);
	if (conn->id)
		rdma_destroy_id(conn->id);
	if (conn->ec)
		rdma_destroy_event_channel(conn->ec);
	free(conn);
}

static int rdma_wait_cm_event(struct rdma_event_channel *ec,
			      enum rdma_cm_event_type expect)
{
	struct rdma_cm_event *event;
	int ret;

	ret = rdma_get_cm_event(ec, &event);
	if (ret) {
		sd_err("rdma_get_cm_event failed: %m");
		return -1;
	}

	if (event->event != expect) {
		sd_err("unexpected rdma cm event %s (wanted %s)",
		       rdma_event_str(event->event), rdma_event_str(expect));
		ret = -1;
	} else {
		ret = 0;
	}
	rdma_ack_cm_event(event);

	return ret;
}

static struct rdma_conn *rdma_conn_create(const struct node_id *nid)
{
	struct rdma_conn *conn;
	struct rdma_addrinfo hints, *ai = NULL;
	struct ibv_qp_init_attr qp_attr;
	struct rdma_conn_param conn_param;
	char host[64], service[16];
	int ret;

	conn = xzalloc(sizeof(*conn));

	conn->ec = rdma_create_event_channel();
	if (!conn->ec) {
		sd_err("rdma_create_event_channel failed: %m");
		goto err;
	}

	ret = rdma_create_id(conn->ec, &conn->id, NULL, RDMA_PS_TCP);
	if (ret) {
		sd_err("rdma_create_id failed: %m");
		goto err;
	}

	snprintf(host, sizeof(host), "%s", addr_to_str(nid->io_addr, 0));
	snprintf(service, sizeof(service), "%u", nid->io_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_port_space = RDMA_PS_TCP;
	hints.ai_qp_type = IBV_QPT_RC;

	ret = rdma_getaddrinfo(host, service, &hints, &ai);
	if (ret) {
		sd_err("rdma_getaddrinfo(%s:%s) failed: %s", host, service,
		       gai_strerror(ret));
		goto err;
	}

	if (rdma_resolve_addr(conn->id, ai->ai_src_addr, ai->ai_dst_addr,
			      RESOLVE_TIMEOUT)) {
		sd_err("rdma_resolve_addr(%s:%s) failed: %m", host, service);
		goto err_ai;
	}
	if (rdma_wait_cm_event(conn->ec, RDMA_CM_EVENT_ADDR_RESOLVED))
		goto err_ai;

	if (rdma_resolve_route(conn->id, RESOLVE_TIMEOUT)) {
		sd_err("rdma_resolve_route(%s:%s) failed: %m", host, service);
		goto err_ai;
	}
	if (rdma_wait_cm_event(conn->ec, RDMA_CM_EVENT_ROUTE_RESOLVED))
		goto err_ai;

	conn->pd = ibv_alloc_pd(conn->id->verbs);
	if (!conn->pd) {
		sd_err("ibv_alloc_pd failed: %m");
		goto err_ai;
	}

	conn->comp = ibv_create_comp_channel(conn->id->verbs);
	if (!conn->comp) {
		sd_err("ibv_create_comp_channel failed: %m");
		goto err_ai;
	}

	conn->scq = ibv_create_cq(conn->id->verbs, 4, NULL, conn->comp, 0);
	conn->rcq = ibv_create_cq(conn->id->verbs, 4, NULL, conn->comp, 0);
	if (!conn->scq || !conn->rcq) {
		sd_err("ibv_create_cq failed: %m");
		goto err_ai;
	}
	if (ibv_req_notify_cq(conn->scq, 0) || ibv_req_notify_cq(conn->rcq, 0)) {
		sd_err("ibv_req_notify_cq failed: %m");
		goto err_ai;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.send_cq = conn->scq;
	qp_attr.recv_cq = conn->rcq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.cap.max_send_wr = 4;
	qp_attr.cap.max_recv_wr = 2;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;

	if (rdma_create_qp(conn->id, conn->pd, &qp_attr)) {
		sd_err("rdma_create_qp failed: %m");
		goto err_ai;
	}

	conn->send_mr = ibv_reg_mr(conn->pd, &conn->send_buf,
				  sizeof(conn->send_buf),
				  IBV_ACCESS_LOCAL_WRITE);
	conn->recv_mr = ibv_reg_mr(conn->pd, &conn->recv_buf,
				  sizeof(conn->recv_buf),
				  IBV_ACCESS_LOCAL_WRITE);
	if (!conn->send_mr || !conn->recv_mr) {
		sd_err("ibv_reg_mr failed: %m");
		goto err_ai;
	}

	if (rdma_conn_post_recv(conn)) {
		sd_err("ibv_post_recv failed: %m");
		goto err_ai;
	}

	memset(&conn_param, 0, sizeof(conn_param));
	conn_param.initiator_depth = 1;
	conn_param.responder_resources = 1;
	conn_param.retry_count = 7;
	conn_param.rnr_retry_count = 7;

	if (rdma_connect(conn->id, &conn_param)) {
		sd_err("rdma_connect(%s:%s) failed: %m", host, service);
		goto err_ai;
	}
	if (rdma_wait_cm_event(conn->ec, RDMA_CM_EVENT_ESTABLISHED))
		goto err_ai;

	rdma_freeaddrinfo(ai);

	return conn;

err_ai:
	rdma_freeaddrinfo(ai);
err:
	rdma_conn_destroy(conn);
	return NULL;
}

static struct rdma_conn *rdma_conn_get(const struct node_id *nid)
{
	struct rdma_pool_entry *entry = rdma_pool_get_entry(nid);
	struct rdma_conn *conn = NULL;

	sd_mutex_lock(&rdma_pool_lock);
	if (!list_empty(&entry->idle_list)) {
		conn = list_first_entry(&entry->idle_list, struct rdma_conn,
					list);
		list_del(&conn->list);
	}
	sd_mutex_unlock(&rdma_pool_lock);

	if (conn)
		return conn;

	conn = rdma_conn_create(nid);
	if (!conn)
		return NULL;
	conn->entry = entry;

	return conn;
}

static void rdma_conn_put(struct rdma_conn *conn)
{
	sd_mutex_lock(&rdma_pool_lock);
	list_add(&conn->list, &conn->entry->idle_list);
	sd_mutex_unlock(&rdma_pool_lock);
}

static void rdma_conn_del(struct rdma_conn *conn)
{
	rdma_conn_destroy(conn);
}

static int rdma_arm_and_wait(struct rdma_conn *conn)
{
	struct ibv_cq *ev_cq;
	void *ev_ctx;

	if (ibv_get_cq_event(conn->comp, &ev_cq, &ev_ctx)) {
		sd_err("ibv_get_cq_event failed: %m");
		return -1;
	}
	ibv_ack_cq_events(ev_cq, 1);
	if (ibv_req_notify_cq(ev_cq, 0)) {
		sd_err("ibv_req_notify_cq failed: %m");
		return -1;
	}

	return 0;
}

/* Block until exactly one completion shows up on 'cq'. conn->scq/conn->rcq
 * share a single completion channel (same convention as nvmet/rdma.c), so
 * an event meant for the other cq just gets re-armed and we loop. */
static int rdma_wait_wc(struct rdma_conn *conn, struct ibv_cq *cq,
			struct ibv_wc *wc)
{
	int ret;

	for (;;) {
		ret = ibv_poll_cq(cq, 1, wc);
		if (ret < 0) {
			sd_err("ibv_poll_cq failed");
			return -1;
		}
		if (ret == 1)
			break;
		if (rdma_arm_and_wait(conn))
			return -1;
	}

	if (wc->status != IBV_WC_SUCCESS) {
		sd_err("rdma completion error: %d", wc->status);
		return -1;
	}

	return 0;
}

/* Register 'data' (if any) and post the ctrl-msg SEND for 'hdr'. Does not
 * wait for completion; see rdma_finish_request(). */
static int rdma_post_request(struct rdma_conn *conn, struct sd_req *hdr,
			     void *data)
{
	int ret;

	if (hdr->data_length) {
		int flags = IBV_ACCESS_LOCAL_WRITE |
			((hdr->flags & SD_FLAG_CMD_WRITE) ?
			 IBV_ACCESS_REMOTE_READ : IBV_ACCESS_REMOTE_WRITE);

		conn->data_mr = ibv_reg_mr(conn->pd, data, hdr->data_length,
					  flags);
		if (!conn->data_mr) {
			sd_err("ibv_reg_mr failed: %m");
			return -EBADE;
		}
	}

	memset(&conn->send_buf, 0, sizeof(conn->send_buf));
	memcpy(&conn->send_buf.hdr, hdr, sizeof(*hdr));
	if (conn->data_mr) {
		conn->send_buf.addr = (uintptr_t)data;
		conn->send_buf.rkey = conn->data_mr->rkey;
	}

	ret = rdma_post_ctrl_send(conn);
	if (ret < 0) {
		sd_err("ibv_post_send failed: %s", strerror(ret));
		if (conn->data_mr) {
			ibv_dereg_mr(conn->data_mr);
			conn->data_mr = NULL;
		}
		return ret;
	}

	return 0;
}

/* Wait for the request's SEND to complete and for the reply to arrive,
 * filling *hdr with the (struct sd_rsp-shaped) reply header. Repost the
 * recv buffer for the connection's next use on success. */
static int rdma_finish_request(struct rdma_conn *conn, struct sd_req *hdr)
{
	struct ibv_wc wc;

	if (rdma_wait_wc(conn, conn->scq, &wc))
		goto err;
	if (rdma_wait_wc(conn, conn->rcq, &wc))
		goto err;

	memcpy(hdr, &conn->recv_buf.hdr, sizeof(*hdr));

	if (conn->data_mr) {
		ibv_dereg_mr(conn->data_mr);
		conn->data_mr = NULL;
	}

	if (rdma_conn_post_recv(conn)) {
		sd_err("failed to repost recv buffer: %m");
		return -1;
	}

	return 0;

err:
	if (conn->data_mr) {
		ibv_dereg_mr(conn->data_mr);
		conn->data_mr = NULL;
	}
	return -1;
}

int rdma_exec_req(const struct node_id *nid, struct sd_req *hdr, void *data,
		  bool (*need_retry)(uint32_t epoch), uint32_t epoch,
		  uint32_t max_count)
{
	struct rdma_conn *conn;

	sd_assert(!is_main_thread());

	conn = rdma_conn_get(nid);
	if (!conn)
		return -ESTALE;

	if (rdma_post_request(conn, hdr, data)) {
		rdma_conn_del(conn);
		return -1;
	}

	if (rdma_finish_request(conn, hdr)) {
		rdma_conn_del(conn);
		return -1;
	}

	rdma_conn_put(conn);

	return 0;
}

int rdma_gw_send_req(struct rdma_forward_info_entry *fi_entry,
		     struct sd_req *hdr, void *data)
{
	struct rdma_conn *conn = rdma_conn_get(fi_entry->nid);

	if (!conn)
		return SD_RES_NETWORK_ERROR;

	if (rdma_post_request(conn, hdr, data)) {
		rdma_conn_del(conn);
		return SD_RES_NETWORK_ERROR;
	}

	fi_entry->conn = conn;

	return SD_RES_SUCCESS;
}

int rdma_gw_wait(struct rdma_forward_info *fi)
{
	int err_ret = SD_RES_SUCCESS;

	while (fi->nr_done < fi->nr_send) {
		struct pollfd pfds[SD_MAX_NODES];
		struct rdma_forward_info_entry *pfd_ent[SD_MAX_NODES];
		int i, nr_pfd = 0;

		for (i = 0; i < fi->nr_send; i++) {
			struct rdma_forward_info_entry *e = &fi->ent[i];

			if (!e->conn)
				continue;
			pfd_ent[nr_pfd] = e;
			pfds[nr_pfd].fd = e->conn->comp->fd;
			pfds[nr_pfd].events = POLLIN;
			nr_pfd++;
		}
		if (!nr_pfd)
			break;

		if (poll(pfds, nr_pfd, -1) < 0) {
			if (errno == EINTR)
				continue;
			panic("%m");
		}

		for (i = 0; i < nr_pfd; i++) {
			struct rdma_forward_info_entry *e = pfd_ent[i];
			struct sd_req rsp_hdr;
			struct sd_rsp *rsp = (struct sd_rsp *)&rsp_hdr;

			if (!(pfds[i].revents & POLLIN))
				continue;

			memset(&rsp_hdr, 0, sizeof(rsp_hdr));
			if (rdma_finish_request(e->conn, &rsp_hdr)) {
				sd_err("rdma forward request failed");
				rdma_conn_del(e->conn);
				e->conn = NULL;
				err_ret = SD_RES_NETWORK_ERROR;
				fi->nr_done++;
				continue;
			}

			rdma_conn_put(e->conn);
			e->conn = NULL;
			if (rsp->result != SD_RES_SUCCESS)
				err_ret = rsp->result;
			fi->nr_done++;
		}
	}

	return err_ret;
}
