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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sched.h>
#include <string.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include "sheep.h"
#include "internal_proto.h"
#include "event.h"
#include "work.h"
#include "sheep_priv.h"
#include "rdma.h"

#define RDMA_BACKLOG 16

/*
 * Server side of the dedicated RDMA IO channel that replaces libxio.
 *
 * Each accepted connection only ever has one request in flight at a time
 * (the client is itself a single pooled, exclusively-checked-out QP; see
 * rdma_client.c), so a single pre-posted receive buffer per connection is
 * enough -- no request/reply correlation is needed.
 *
 * scq (the QP's send-queue CQ) is touched from two different threads:
 * rdma_rx_work() (a worker thread, pulling write payloads via RDMA_READ)
 * and rdma_conn_handler() (the main thread, reaping reply SEND
 * completions). cq_lock serializes every individual ibv_poll_cq()/
 * ibv_post_send() call on a connection's CQs so the two never race on the
 * same struct ibv_cq -- it is held only around each such call, never across
 * a wait loop, so a slow RDMA_READ on a worker thread never blocks the main
 * thread for longer than a single poll.
 */
struct rdma_server_conn {
	struct client_info *ci;

	struct rdma_cm_id *id;
	struct ibv_pd *pd;
	struct ibv_cq *scq, *rcq;
	struct ibv_comp_channel *comp;

	struct sd_mutex cq_lock;

	struct sd_rdma_ctrl_msg recv_buf;
	struct ibv_mr *recv_mr;
};

struct rdma_listener {
	struct rdma_cm_id *id;
	struct rdma_event_channel *ec;
};

/* Bookkeeping for an in-flight reply, kept alive on the SEND's wr_id until
 * its completion is reaped in rdma_handle_reply_completion() -- req->data
 * must not be freed before any RDMA_WRITE of it has actually completed,
 * and RC ordering only promises that to the *receiver*, not to us. */
struct rdma_reply_ctx {
	struct rdma_server_conn *conn;
	void *data;
	struct ibv_mr *data_mr;
	struct sd_rdma_ctrl_msg send_buf;
	struct ibv_mr *send_mr;
};

static void rdma_conn_handler(int fd, int events, void *data);

static int rdma_server_post_recv(struct rdma_server_conn *conn)
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

static void rdma_server_conn_destroy(struct rdma_server_conn *conn)
{
	if (conn->id && conn->id->qp)
		rdma_destroy_qp(conn->id);
	if (conn->recv_mr)
		ibv_dereg_mr(conn->recv_mr);
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
	sd_destroy_mutex(&conn->cq_lock);
	free(conn);
}

void rdma_destroy_connection(struct client_info *ci)
{
	struct rdma_server_conn *conn = ci->rdma_conn;

	if (conn->comp)
		unregister_event(conn->comp->fd);
	rdma_server_conn_destroy(conn);
	free(ci);
}

/* Pull the write payload for 'req' via RDMA_READ from the client's
 * previously-supplied {addr,rkey}. Runs on a worker thread; blocking here
 * is fine. Only ever touches conn->scq briefly under conn->cq_lock, so it
 * never holds the main thread up for the duration of the transfer. */
static int rdma_pull_write_data(struct rdma_server_conn *conn,
				struct request *req)
{
	struct ibv_mr *mr;
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
	struct ibv_wc wc;
	int ret;

	mr = ibv_reg_mr(conn->pd, req->data, req->rq.data_length,
			IBV_ACCESS_LOCAL_WRITE);
	if (!mr) {
		sd_err("ibv_reg_mr failed: %m");
		return -1;
	}

	memset(&wr, 0, sizeof(wr));
	sge.addr = (uintptr_t)req->data;
	sge.length = req->rq.data_length;
	sge.lkey = mr->lkey;

	wr.wr_id = (uintptr_t)req;
	wr.opcode = IBV_WR_RDMA_READ;
	wr.wr.rdma.remote_addr = req->rdma_ctx->addr;
	wr.wr.rdma.rkey = req->rdma_ctx->rkey;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	sd_mutex_lock(&conn->cq_lock);
	ret = ibv_post_send(conn->id->qp, &wr, &bad_wr);
	sd_mutex_unlock(&conn->cq_lock);
	if (ret) {
		sd_err("ibv_post_send (RDMA_READ) failed: %d", ret);
		ibv_dereg_mr(mr);
		return -1;
	}

	for (;;) {
		sd_mutex_lock(&conn->cq_lock);
		ret = ibv_poll_cq(conn->scq, 1, &wc);
		sd_mutex_unlock(&conn->cq_lock);
		if (ret != 0)
			break;
		sched_yield();
	}

	ibv_dereg_mr(mr);

	if (ret < 0 || wc.status != IBV_WC_SUCCESS) {
		sd_err("rdma_read completion error");
		return -1;
	}

	return 0;
}

static void rdma_rx_work(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      rx_work);
	struct rdma_server_conn *conn = ci->rdma_conn;
	struct request *req = ci->rx_req;

	if (!(req->rq.flags & SD_FLAG_CMD_WRITE) || !req->rq.data_length)
		return;

	if (rdma_pull_write_data(conn, req)) {
		sd_err("%016"PRIx64": failed to pull write payload",
		       req->rq.obj.oid);
		ci->conn.dead = true;
	}
}

static void rdma_rx_main(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      rx_work);
	struct request *req = ci->rx_req;

	ci->rx_req = NULL;

	if (ci->conn.dead) {
		if (req) {
			free(req->rdma_ctx);
			free_request(req);
		}
		refcount_dec(&ci->refcnt);
		clear_client_info(ci);
		return;
	}

	refcount_dec(&ci->refcnt);
	queue_request(req);
}

static void rdma_handle_recv_wc(struct client_info *ci, struct ibv_wc *wc)
{
	struct rdma_server_conn *conn = ci->rdma_conn;
	struct request *req;
	struct sd_req hdr;
	uint64_t addr;
	uint32_t rkey;

	if (wc->status != IBV_WC_SUCCESS) {
		if (wc->status != IBV_WC_WR_FLUSH_ERR)
			sd_err("rdma recv completion error: %d", wc->status);
		ci->conn.dead = true;
		return;
	}

	hdr = conn->recv_buf.hdr;
	addr = conn->recv_buf.addr;
	rkey = conn->recv_buf.rkey;

	if (rdma_server_post_recv(conn)) {
		sd_err("failed to repost recv buffer: %m");
		ci->conn.dead = true;
		return;
	}

	req = alloc_request(ci, hdr.data_length);
	if (!req) {
		sd_err("failed to allocate request");
		ci->conn.dead = true;
		return;
	}
	memcpy(&req->rq, &hdr, sizeof(req->rq));

	req->rdma_ctx = xzalloc(sizeof(*req->rdma_ctx));
	req->rdma_ctx->addr = addr;
	req->rdma_ctx->rkey = rkey;

	ci->rx_req = req;
	refcount_inc(&ci->refcnt);
	ci->rx_work.fn = rdma_rx_work;
	ci->rx_work.done = rdma_rx_main;
	queue_work(sys->net_wqueue, &ci->rx_work);
}

static void rdma_handle_reply_completion(struct ibv_wc *wc)
{
	struct rdma_reply_ctx *reply = (struct rdma_reply_ctx *)wc->wr_id;

	if (wc->status != IBV_WC_SUCCESS) {
		sd_err("rdma reply send completion error: %d", wc->status);
		reply->conn->ci->conn.dead = true;
	}

	if (reply->data_mr)
		ibv_dereg_mr(reply->data_mr);
	free(reply->data);
	ibv_dereg_mr(reply->send_mr);
	free(reply);
}

static void rdma_conn_handler(int fd, int events, void *data)
{
	struct client_info *ci = data;
	struct rdma_server_conn *conn = ci->rdma_conn;
	struct ibv_cq *ev_cq;
	void *ev_ctx;
	struct ibv_wc wc;
	int ret;

	ret = ibv_get_cq_event(conn->comp, &ev_cq, &ev_ctx);
	if (ret) {
		if (errno != EAGAIN)
			sd_err("ibv_get_cq_event failed: %m");
		return;
	}
	ibv_ack_cq_events(ev_cq, 1);
	if (ibv_req_notify_cq(ev_cq, 0))
		sd_err("ibv_req_notify_cq failed: %m");

	for (;;) {
		sd_mutex_lock(&conn->cq_lock);
		ret = ibv_poll_cq(conn->rcq, 1, &wc);
		sd_mutex_unlock(&conn->cq_lock);
		if (ret != 1)
			break;
		rdma_handle_recv_wc(ci, &wc);
	}

	for (;;) {
		sd_mutex_lock(&conn->cq_lock);
		ret = ibv_poll_cq(conn->scq, 1, &wc);
		sd_mutex_unlock(&conn->cq_lock);
		if (ret != 1)
			break;
		rdma_handle_reply_completion(&wc);
	}

	if (ci->conn.dead)
		clear_client_info(ci);
}

static int rdma_post_write(struct rdma_server_conn *conn, void *buf,
			   struct ibv_mr *mr, uint32_t len, uint64_t addr,
			   uint32_t rkey)
{
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
	int ret;

	memset(&wr, 0, sizeof(wr));
	sge.addr = (uintptr_t)buf;
	sge.length = len;
	sge.lkey = mr->lkey;

	/*
	 * Unsignaled: the SEND posted right after this on the same QP send
	 * queue is signaled, and RC send-queue completions are strictly
	 * ordered, so reaping that SEND's completion is proof this WRITE
	 * also completed locally (not just "observed in order" by the
	 * remote side, which is a separate but equally relied-upon RC
	 * guarantee -- see rdma_send_reply()).
	 */
	wr.opcode = IBV_WR_RDMA_WRITE;
	wr.wr.rdma.remote_addr = addr;
	wr.wr.rdma.rkey = rkey;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	sd_mutex_lock(&conn->cq_lock);
	ret = ibv_post_send(conn->id->qp, &wr, &bad_wr);
	sd_mutex_unlock(&conn->cq_lock);

	return ret;
}

static int rdma_post_send_reply(struct rdma_server_conn *conn,
				struct rdma_reply_ctx *reply)
{
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
	int ret;

	memset(&wr, 0, sizeof(wr));
	sge.addr = (uintptr_t)&reply->send_buf;
	sge.length = sizeof(reply->send_buf);
	sge.lkey = reply->send_mr->lkey;

	wr.wr_id = (uintptr_t)reply;
	wr.opcode = IBV_WR_SEND;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	sd_mutex_lock(&conn->cq_lock);
	ret = ibv_post_send(conn->id->qp, &wr, &bad_wr);
	sd_mutex_unlock(&conn->cq_lock);

	return ret;
}

void rdma_send_reply(struct client_info *ci)
{
	struct rdma_server_conn *conn = ci->rdma_conn;
	struct request *req;
	struct rdma_req_ctx *rctx;
	struct rdma_reply_ctx *reply;
	bool ok = true;

	req = list_first_entry(&ci->done_reqs, struct request, request_list);
	list_del(&req->request_list);

	rctx = req->rdma_ctx;
	req->rdma_ctx = NULL;

	reply = xzalloc(sizeof(*reply));
	reply->conn = conn;
	reply->send_buf.hdr = *(struct sd_req *)&req->rp;

	reply->send_mr = ibv_reg_mr(conn->pd, &reply->send_buf,
				    sizeof(reply->send_buf),
				    IBV_ACCESS_LOCAL_WRITE);
	if (!reply->send_mr) {
		sd_err("ibv_reg_mr failed: %m");
		ok = false;
	}

	if (ok && req->rp.data_length) {
		void *buf = req->data;

		reply->data_mr = ibv_reg_mr(conn->pd, buf,
					    req->rp.data_length,
					    IBV_ACCESS_LOCAL_WRITE);
		if (!reply->data_mr) {
			sd_err("ibv_reg_mr failed: %m");
			ok = false;
		} else if (rdma_post_write(conn, buf, reply->data_mr,
					   req->rp.data_length, rctx->addr,
					   rctx->rkey)) {
			sd_err("ibv_post_send (RDMA_WRITE) failed: %m");
			ok = false;
		} else {
			/* ownership of the buffer moves to 'reply' until the
			 * SEND below's completion is reaped (proving this
			 * WRITE landed too; see rdma_post_write()) */
			reply->data = buf;
			req->data = NULL;
		}
	}

	if (ok && rdma_post_send_reply(conn, reply)) {
		sd_err("ibv_post_send (SEND) failed: %m");
		ok = false;
	}

	free(rctx);

	if (!ok) {
		ci->conn.dead = true;
		if (reply->data_mr)
			ibv_dereg_mr(reply->data_mr);
		free(reply->data);
		if (reply->send_mr)
			ibv_dereg_mr(reply->send_mr);
		free(reply);
	}

	free_request(req);
}

static int rdma_handle_connect_request(struct rdma_cm_event *event)
{
	struct rdma_cm_id *id = event->id;
	struct rdma_conn_param params;
	struct ibv_qp_init_attr qp_attr;
	struct rdma_server_conn *conn;
	struct client_info *ci;
	struct sockaddr *peer;
	int flags;

	conn = xzalloc(sizeof(*conn));
	conn->id = id;
	sd_init_mutex(&conn->cq_lock);

	conn->pd = ibv_alloc_pd(id->verbs);
	if (!conn->pd) {
		sd_err("ibv_alloc_pd failed: %m");
		goto reject;
	}

	conn->comp = ibv_create_comp_channel(id->verbs);
	if (!conn->comp) {
		sd_err("ibv_create_comp_channel failed: %m");
		goto reject;
	}
	flags = fcntl(conn->comp->fd, F_GETFL);
	if (fcntl(conn->comp->fd, F_SETFL, flags | O_NONBLOCK)) {
		sd_err("fcntl failed: %m");
		goto reject;
	}

	conn->scq = ibv_create_cq(id->verbs, 4, NULL, conn->comp, 0);
	conn->rcq = ibv_create_cq(id->verbs, 4, NULL, conn->comp, 0);
	if (!conn->scq || !conn->rcq) {
		sd_err("ibv_create_cq failed: %m");
		goto reject;
	}
	if (ibv_req_notify_cq(conn->scq, 0) ||
	    ibv_req_notify_cq(conn->rcq, 0)) {
		sd_err("ibv_req_notify_cq failed: %m");
		goto reject;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.send_cq = conn->scq;
	qp_attr.recv_cq = conn->rcq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.cap.max_send_wr = 4;
	qp_attr.cap.max_recv_wr = 2;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;

	if (rdma_create_qp(id, conn->pd, &qp_attr)) {
		sd_err("rdma_create_qp failed: %m");
		goto reject;
	}

	conn->recv_mr = ibv_reg_mr(conn->pd, &conn->recv_buf,
				  sizeof(conn->recv_buf),
				  IBV_ACCESS_LOCAL_WRITE);
	if (!conn->recv_mr) {
		sd_err("ibv_reg_mr failed: %m");
		goto reject;
	}

	if (rdma_server_post_recv(conn)) {
		sd_err("ibv_post_recv failed: %m");
		goto reject;
	}

	ci = xzalloc(sizeof(*ci));
	ci->type = CLIENT_INFO_TYPE_RDMA;
	ci->rdma_conn = conn;
	ci->conn.fd = -1;
	INIT_LIST_HEAD(&ci->done_reqs);
	refcount_set(&ci->refcnt, 0);
	conn->ci = ci;

	peer = rdma_get_peer_addr(id);
	if (peer && peer->sa_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)peer;

		ci->conn.port = ntohs(s->sin_port);
		inet_ntop(AF_INET, &s->sin_addr, ci->conn.ipstr,
			 sizeof(ci->conn.ipstr));
	} else if (peer && peer->sa_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)peer;

		ci->conn.port = ntohs(s->sin6_port);
		inet_ntop(AF_INET6, &s->sin6_addr, ci->conn.ipstr,
			 sizeof(ci->conn.ipstr));
	}

	memset(&params, 0, sizeof(params));
	params.initiator_depth = event->param.conn.responder_resources;
	params.responder_resources = event->param.conn.initiator_depth;
	if (!params.initiator_depth)
		params.initiator_depth = 1;
	params.flow_control = 1;
	params.retry_count = 7;
	params.rnr_retry_count = 7;

	rdma_ack_cm_event(event);

	if (rdma_accept(id, &params)) {
		sd_err("rdma_accept failed: %m");
		free(ci);
		rdma_server_conn_destroy(conn);
		return -1;
	}

	if (register_event(conn->comp->fd, rdma_conn_handler, ci)) {
		sd_err("failed to register rdma connection fd");
		free(ci);
		rdma_server_conn_destroy(conn);
		return -1;
	}

	id->context = conn;

	return 0;

reject:
	rdma_ack_cm_event(event);
	rdma_reject(id, NULL, 0);
	rdma_server_conn_destroy(conn);
	return -1;
}

static void rdma_handle_disconnect(struct rdma_cm_id *id)
{
	struct rdma_server_conn *conn = id->context;

	if (!conn)
		return;

	conn->ci->conn.dead = true;
	clear_client_info(conn->ci);
}

static void rdma_cm_handler(int fd, int events, void *data)
{
	struct rdma_listener *rl = data;
	struct rdma_cm_event *event;

	while (rdma_get_cm_event(rl->ec, &event) == 0) {
		enum rdma_cm_event_type ev = event->event;

		switch (ev) {
		case RDMA_CM_EVENT_CONNECT_REQUEST:
			/* acks (and may reject/destroy) 'event' itself */
			rdma_handle_connect_request(event);
			break;
		case RDMA_CM_EVENT_DISCONNECTED:
		case RDMA_CM_EVENT_DEVICE_REMOVAL:
		case RDMA_CM_EVENT_TIMEWAIT_EXIT:
			rdma_handle_disconnect(event->id);
			rdma_ack_cm_event(event);
			break;
		default:
			sd_debug("unhandled rdma cm event %s",
				 rdma_event_str(ev));
			rdma_ack_cm_event(event);
			break;
		}
	}
	if (errno != EAGAIN)
		sd_err("rdma_get_cm_event failed: %m");
}

int rdma_create_listen_port(const char *bindaddr, int port)
{
	struct rdma_addrinfo hints, *ai = NULL;
	struct rdma_listener *rl;
	char trsvcid[16];
	int ret, flags;

	rl = xzalloc(sizeof(*rl));

	rl->ec = rdma_create_event_channel();
	if (!rl->ec) {
		sd_err("rdma_create_event_channel failed: %m");
		goto err;
	}
	flags = fcntl(rl->ec->fd, F_GETFL);
	if (fcntl(rl->ec->fd, F_SETFL, flags | O_NONBLOCK)) {
		sd_err("fcntl failed: %m");
		goto err;
	}

	if (rdma_create_id(rl->ec, &rl->id, NULL, RDMA_PS_TCP)) {
		sd_err("rdma_create_id failed: %m");
		goto err;
	}

	snprintf(trsvcid, sizeof(trsvcid), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_qp_type = IBV_QPT_RC;
	hints.ai_port_space = RDMA_PS_TCP;
	hints.ai_flags = RAI_PASSIVE;

	ret = rdma_getaddrinfo(bindaddr, trsvcid, &hints, &ai);
	if (ret) {
		sd_err("rdma_getaddrinfo(%s:%s) failed: %s",
		       bindaddr ?: "*", trsvcid, gai_strerror(ret));
		goto err;
	}

	if (rdma_bind_addr(rl->id, ai->ai_src_addr)) {
		sd_err("rdma_bind_addr(%s:%s) failed: %m",
		       bindaddr ?: "*", trsvcid);
		goto err;
	}

	if (rdma_listen(rl->id, RDMA_BACKLOG)) {
		sd_err("rdma_listen(%s:%s) failed: %m",
		       bindaddr ?: "*", trsvcid);
		goto err;
	}

	if (register_event(rl->ec->fd, rdma_cm_handler, rl)) {
		sd_err("failed to register rdma cm event fd");
		goto err;
	}

	rdma_freeaddrinfo(ai);
	sd_info("listening on rdma port %s:%d", bindaddr ?: "*", port);

	return 0;

err:
	if (ai)
		rdma_freeaddrinfo(ai);
	if (rl->id)
		rdma_destroy_id(rl->id);
	if (rl->ec)
		rdma_destroy_event_channel(rl->ec);
	free(rl);

	return -1;
}
