// SPDX-License-Identifier: DUAL GPL-2.0/BSD
/*
 * rdma.c
 * NVMe-over-fabrics RDMA transport protocol handling.
 *
 * Copyright (c) 2026 Hannes Reinecke <hare@suse.de>
 */

#include <sys/time.h>
#include <linux/types.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include "sheep.h"
#include "nofuse.h"
#include "ops.h"
#include "configdb.h"

#define BACKLOG			16
#define RESOLVE_TIMEOUT		5000
#define EVENT_TIMEOUT		200
#define ABSURD_MAX_WRS		8192

struct rdma_pep {
	struct ibv_mr		*mr;
	struct ibv_cq		*rcq;
	struct ibv_cq		*scq;
	struct ibv_qp		*qp;
	struct rdma_cm_id	*id;
	struct rdma_event_channel *ec;
	__u8			 state;
};

#define rdma_info(e, f, x...)					\
	if (rdma_debug) {					\
		sd_debug("ctrl %d qid %d: " f,			\
			 (e)->ctrl ? (e)->ctrl->cntlid : -1,	\
			 (e)->qid, ##x);			\
	}

#define rdma_err(e, f, x...)					\
	sd_err("ctrl %d qid %d: " f,				\
	       (e)->ctrl ? (e)->ctrl->cntlid : -1,		\
	       (e)->qid, ##x)

static struct {
	int status;
	const char *str;
} wc_status_array[] = {
	{ IBV_WC_SUCCESS,		"IBV_WC_SUCCESS" },
	{ IBV_WC_LOC_LEN_ERR,		"IBV_WC_LOC_LEN_ERR" },
	{ IBV_WC_LOC_QP_OP_ERR,		"IBV_WC_LOC_QP_OP_ERR" },
	{ IBV_WC_LOC_EEC_OP_ERR,	"IBV_WC_LOC_EEC_OP_ERR" },
	{ IBV_WC_LOC_PROT_ERR,		"IBV_WC_LOC_PROT_ERR" },
	{ IBV_WC_WR_FLUSH_ERR,		"IBV_WC_WR_FLUSH_ERR" },
	{ IBV_WC_MW_BIND_ERR,		"IBV_WC_MW_BIND_ERR" },
	{ IBV_WC_BAD_RESP_ERR,		"IBV_WC_BAD_RESP_ERR" },
	{ IBV_WC_LOC_ACCESS_ERR,	"IBV_WC_LOC_ACCESS_ERR" },
	{ IBV_WC_REM_INV_REQ_ERR,	"IBV_WC_REM_INV_REQ_ERR" },
	{ IBV_WC_REM_ACCESS_ERR,	"IBV_WC_REM_ACCESS_ERR" },
	{ IBV_WC_REM_OP_ERR,		"IBV_WC_REM_OP_ERR" },
	{ IBV_WC_RETRY_EXC_ERR,		"IBV_WC_RETRY_EXC_ERR" },
	{ IBV_WC_RNR_RETRY_EXC_ERR,	"IBV_WC_RNR_RETRY_EXC_ERR" },
	{ IBV_WC_LOC_RDD_VIOL_ERR,	"IBV_WC_LOC_RDD_VIOL_ERR" },
	{ IBV_WC_REM_INV_RD_REQ_ERR,	"IBV_WC_REM_INV_RD_REQ_ERR" },
	{ IBV_WC_REM_ABORT_ERR,		"IBV_WC_REM_ABORT_ERR" },
	{ IBV_WC_INV_EECN_ERR,		"IBV_WC_INV_EECN_ERR" },
	{ IBV_WC_INV_EEC_STATE_ERR,	"IBV_WC_INV_EEC_STATE_ERR" },
	{ IBV_WC_FATAL_ERR,		"IBV_WC_FATAL_ERR" },
	{ IBV_WC_RESP_TIMEOUT_ERR,	"IBV_WC_RESP_TIMEOUT_ERR" },
	{ IBV_WC_GENERAL_ERR,		"IBV_WC_GENERAL_ERR" },
};

static inline char *wc_str_status(uint16_t status)
{
	int i;
	static char str[80] = { 0 };

	for (i = 0; i < ARRAY_SIZE(wc_status_array); i++)
		if (wc_status_array[i].status == (status & 0x3fff)) {
			strcpy(str, wc_status_array[i].str);
			break;
		}

	return str;
}

static void *alloc_buffer(struct nofuse_queue *ep, int size,
			  struct ibv_mr **mr)
{
	void *buf;
	int flags = IBV_ACCESS_LOCAL_WRITE |
		IBV_ACCESS_REMOTE_WRITE;

	if (posix_memalign(&buf, PAGE_SIZE, size)) {
		ctrl_err(ep, "posix_memalign failed: %m");
		goto err1;
	}
	memset(buf, 0, size);

	*mr = ibv_reg_mr(ep->transport.rdma.pd, buf, size, flags);
	if (!*mr)
		goto err2;


	return buf;
err2:
	free(buf);
err1:
	*mr = NULL;

	return NULL;
}

static int rdma_create_queue_recv_pool(struct nofuse_queue *ep)
{
	struct ep_qe *qe;
	struct ibv_recv_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
	int i, ret;

	qe = calloc(ep->qsize, sizeof(struct ep_qe));
	if (!qe)
		return -ENOMEM;
	ep->allocated_qsize = 0;
	for (i = 0; i < ep->qsize; i++) {
		qe[i].data = alloc_buffer(ep, PAGE_SIZE, &qe[i].data_mr);
		if (!qe[i].data) {
			errno = ENOMEM;
			goto err;
		}
		qe[i].data_len = PAGE_SIZE;
		ep->allocated_qsize++;
	}

	wr.next = NULL;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	sge.length = PAGE_SIZE;

	for (i = 0; i < ep->allocated_qsize; i++) {
		qe[i].tag = i;
		qe[i].ep = ep;
		wr.wr_id = (uintptr_t) &qe[i];
		sge.addr = (uintptr_t) qe[i].data;
		sge.lkey = qe[i].data_mr->lkey;

		ret = ibv_post_recv(ep->transport.rdma.id->qp, &wr, &bad_wr);
		if (ret)
			goto err;
	}
	memset(ep->qes_map, 0xff, sizeof(ep->qes_map));
	ep->qes = qe;

	return 0;
err:
	while (i > 0) {
		free(qe[--i].data);
		qe[i].data_len = 0;
		ibv_dereg_mr(qe[i].data_mr);
	}

	free(qe);
	ep->allocated_qsize = 0;
	return -errno;
}

static int rdma_create_completion_queues(struct nofuse_queue *ep)
{
	struct ibv_pd *pd;
	struct ibv_cq *rcq;
	struct ibv_cq *scq;
	struct ibv_context *ctx = ep->transport.rdma.id->verbs;
	struct ibv_comp_channel	*comp;
	int flags;
	int ret;

	pd = ibv_alloc_pd(ctx);
	if (!pd)
		return -errno;

	comp = ibv_create_comp_channel(ctx);
	if (!comp)
		goto err1;

	flags = fcntl(comp->fd, F_GETFL);
	ret = fcntl(comp->fd, F_SETFL, flags | O_NONBLOCK);
	if (ret < 0)
		goto err1;

	rcq = ibv_create_cq(ctx, ep->qsize, NULL, comp, 0);
	if (!rcq)
		goto err2;

	scq = ibv_create_cq(ctx, ep->qsize, NULL, comp, 0);
	if (!scq)
		goto err3;

	if (ibv_req_notify_cq(rcq, 0))
		goto err4;

	if (ibv_req_notify_cq(scq, 0))
		goto err4;

	ep->transport.rdma.pd = pd;
	ep->transport.rdma.rcq = rcq;
	ep->transport.rdma.scq = scq;
	ep->transport.rdma.comp = comp;

	return 0;
err4:
	ibv_destroy_cq(scq);
err3:
	ibv_destroy_cq(rcq);
err2:
	ibv_destroy_comp_channel(comp);
err1:
	ibv_dealloc_pd(pd);

	return -errno;
}

static void rdma_destroy_completion_queues(struct nofuse_queue *ep)
{
	if (ep->transport.rdma.scq) {
		ibv_destroy_cq(ep->transport.rdma.scq);
		ep->transport.rdma.scq = NULL;
	}
	if (ep->transport.rdma.rcq) {
		ibv_destroy_cq(ep->transport.rdma.rcq);
		ep->transport.rdma.rcq = NULL;
	}
	if (ep->transport.rdma.comp) {
		ibv_destroy_comp_channel(ep->transport.rdma.comp);
		ep->transport.rdma.comp = NULL;
	}
	if (ep->transport.rdma.pd) {
		ibv_dealloc_pd(ep->transport.rdma.pd);
		ep->transport.rdma.pd = NULL;
	}
}

static int rdma_create_queue_pairs(struct nofuse_queue *ep)
{
	struct ibv_qp_init_attr qp_attr = { NULL };
	struct ibv_device_attr dev_attr;
	const int send_wr_factor = 3; /* MR, SEND, INV */

	if (ibv_query_device(ep->transport.rdma.id->pd->context, &dev_attr))
		return -errno;

	qp_attr.send_cq = ep->transport.rdma.scq;
	qp_attr.recv_cq = ep->transport.rdma.rcq;
	qp_attr.qp_type = IBV_QPT_RC;

	qp_attr.cap.max_recv_wr = ep->qsize + 1;
	qp_attr.cap.max_recv_sge = 1;

	qp_attr.cap.max_send_sge = min(dev_attr.max_sge_rd, dev_attr.max_sge);
	if (dev_attr.max_qp_wr > ABSURD_MAX_WRS)
		qp_attr.cap.max_send_wr = send_wr_factor * ep->qsize + 1;
	else
		qp_attr.cap.max_send_wr = dev_attr.max_qp_wr;

	if (rdma_create_qp(ep->transport.rdma.id,
			   ep->transport.rdma.pd, &qp_attr))
		return -errno;

	return 0;
}

static void rdma_destroy_queue_pairs(struct nofuse_queue *ep)
{
	if (ep->transport.rdma.id && ep->transport.rdma.id->qp) {
		rdma_destroy_qp(ep->transport.rdma.id);
		ep->transport.rdma.id = NULL;
	}
}

static void rdma_destroy_queue(struct nofuse_queue *ep)
{
	int i = ep->qsize;
	struct ep_qe *qe = ep->qes;

	ep->state = DISCONNECTED;
	if (qe) {
		while (i > 0) {
			if (qe[--i].data) {
				free(qe[i].data);
				qe[i].data_len = 0;
				ibv_dereg_mr(qe[i].data_mr);
			}
		}
		free(qe);
		ep->qes = NULL;
	}
	rdma_destroy_queue_pairs(ep);
	rdma_destroy_completion_queues(ep);
	if (ep->transport.rdma.cmd) {
		ibv_dereg_mr(ep->transport.rdma.cmd_mr);
		free(ep->transport.rdma.cmd);
		ep->transport.rdma.cmd = NULL;
	}
}

static int rdma_create_queue(struct nofuse_queue *ep, void *id, int depth)
{
	int ret;

	ep->trtype = NVMF_TRTYPE_RDMA;
	ep->transport.rdma.id = id;
	ep->qsize = depth;

	ret = rdma_create_completion_queues(ep);
	if (ret < 0)
		return ret;

	ret = rdma_create_queue_pairs(ep);
	if (ret < 0)
		goto out_destroy_comp;

	ret = rdma_create_queue_recv_pool(ep);
	if (ret < 0)
		goto out_destroy_qp;

	ep->transport.rdma.cmd = alloc_buffer(ep, PAGE_SIZE,
					      &ep->transport.rdma.cmd_mr);
	if (!ep->transport.rdma.cmd) {
		rdma_destroy_queue(ep);
		return -ENOMEM;
	}
	return 0;
out_destroy_qp:
	rdma_destroy_queue_pairs(ep);
out_destroy_comp:
	rdma_destroy_completion_queues(ep);
	return ret;
}

static int rdma_init_listener(struct nofuse_port *port)
{
	struct rdma_addrinfo *ai, hints, *tmp_ai;
	char bindaddr[256];
	char trsvcid[32];
	char adrfam_str[32];
	sa_family_t adrfam = AF_INET;
	struct rdma_cm_id *listener;
	struct rdma_event_channel *ec;
	int flags;
	int ret;

	ret = configdb_get_port_attr(port->portid, "bindaddr", bindaddr);
	if (ret < 0) {
		port_err(port, "failed to get bindaddr, error %d", ret);
		return ret;
	}
	ret = configdb_get_port_attr(port->portid, "trsvcid", trsvcid);
	if (ret < 0) {
		port_err(port, "failed to get trsvcid, errot %d", ret);
		return ret;
	}
	ret = configdb_get_port_attr(port->portid, "adrfam", adrfam_str);
	if (ret < 0) {
		port_err(port, "failed to get adrfam, error %d", ret);
		return ret;
	}
	if (!strcmp(adrfam_str, "ipv6"))
		adrfam = AF_INET6;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = adrfam;
	hints.ai_qp_type = IBV_QPT_RC;
	hints.ai_port_space = RDMA_PS_TCP;
	hints.ai_flags = RAI_FAMILY | RAI_NUMERICHOST | RAI_PASSIVE;

	ret = rdma_getaddrinfo(bindaddr, trsvcid, &hints, &ai);
	if (ret != 0) {
		port_err(port, "getaddrinfo() failed: %s",
			  gai_strerror(ret));
		return -EINVAL;
	}
	if (!ai) {
		port_err(port, "no results from getaddrinfo()");
		return -EHOSTUNREACH;
	}

	ec = rdma_create_event_channel();
	if (!ec) {
		port_err(port, "failed to create event channel");
		ret = -errno;
		goto out_free_addrinfo;
	}

	flags = fcntl(ec->fd, F_GETFL);
	ret = fcntl(ec->fd, F_SETFL, flags | O_NONBLOCK);
	if (ret) {
		port_err(port, "fcntl failed, error %d", errno);
		ret = -errno;
		goto out_destroy_ec;
	}

	ret = rdma_create_id(ec, &listener, NULL, RDMA_PS_TCP);
	if (ret) {
		port_err(port, "failed to create listener");
		goto out_destroy_ec;
	}

	tmp_ai = ai;
	while (tmp_ai) {
		char host[NI_MAXHOST], service[NI_MAXSERV];

		ret = getnameinfo((struct sockaddr *)tmp_ai->ai_src_addr,
				  tmp_ai->ai_src_len, host, NI_MAXHOST,
				  service, NI_MAXSERV, NI_NUMERICSERV);
		port_info(port, "using src host '%s' service '%s'",
			  host, service);
		tmp_ai = tmp_ai->ai_next;
	}
	ret = rdma_bind_addr(listener, ai->ai_src_addr);
	if (ret) {
		port_err(port, "failed to bind address to rdma port %s:%s",
			 bindaddr, trsvcid);
		goto out_destroy_id;
	}

	ret = rdma_listen(listener, BACKLOG);
	if (ret) {
		port_err(port, "failed to listen on rdma port %s:%s",
			 bindaddr, trsvcid);
		goto out_destroy_id;
	}

	port->transport.rdma.id = listener;
	port->transport.rdma.ec = ec;
	port_info(port, "listening on rdma port %s:%s", bindaddr, trsvcid);

	return 0;

out_destroy_id:
	rdma_destroy_id(listener);
out_destroy_ec:
	rdma_destroy_event_channel(ec);
out_free_addrinfo:
	rdma_freeaddrinfo(ai);
	return ret;
}

static void rdma_destroy_listener(struct nofuse_port *port)
{
	if (port->transport.rdma.id) {
		rdma_destroy_id(port->transport.rdma.id);
		port->transport.rdma.id = NULL;
	}
	if (port->transport.rdma.ec) {
		rdma_destroy_event_channel(port->transport.rdma.ec);
		port->transport.rdma.ec = NULL;
	}
}

static int rdma_accept_connection(struct nofuse_queue *ep)
{
	struct rdma_conn_param  params = { NULL };
	struct ibv_device_attr attr;
	struct rdma_cm_id *id = ep->transport.rdma.id;
	int ret;

	ret = ibv_query_device(id->verbs, &attr);
	if (ret) {
		rdma_err(ep, "ibv_query_device failed, error %d", ret);
		return -ret;
	}

	params.initiator_depth = id->event->param.conn.responder_resources;
	params.responder_resources = id->event->param.conn.initiator_depth;

	if (!params.initiator_depth)
		params.initiator_depth = ep->qsize;

	rdma_info(ep, "initiator_depth %d responder_resources %d",
		  params.initiator_depth, params.responder_resources);
	rdma_ack_cm_event(ep->transport.rdma.id->event);
	ep->transport.rdma.id->event = NULL;

	params.flow_control = 1;
	params.retry_count = 15;
	params.rnr_retry_count = 7;

	ret = rdma_accept(ep->transport.rdma.id, &params);
	if (ret)
		rdma_err(ep, "rdma_accept() failed, error %d", ret);
	return ret;
}

static int rdma_wait_for_event(struct rdma_event_channel *ec,
			       struct rdma_cm_event **event)
{
	struct timeval tv;
	fd_set fds, rfds;
	int ret = 0;

	FD_ZERO(&fds);
	FD_SET(ec->fd, &fds);
	tv.tv_sec = 0;

	while (!ret) {
		tv.tv_usec = EVENT_TIMEOUT;
		rfds = fds;
		ret = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
		if (ret < 0)
			return ret;
		if (stopped)
			return -ESHUTDOWN;
	}

	while (rdma_get_cm_event(ec, event)) {
		if (errno != EAGAIN)
			return -errno;
		if (stopped)
			return -ESHUTDOWN;
	}

	return 0;
}

static int rdma_wait_for_connection(struct nofuse_port *port, void **_id)
{
	struct rdma_cm_event *event;
	struct rdma_cm_id *id;
	enum rdma_cm_event_type ev;

	if (rdma_wait_for_event(port->transport.rdma.ec, &event))
		return -ENOTCONN;

	id = event->id;
	ev = event->event;

	if (ev == RDMA_CM_EVENT_ESTABLISHED ||
	    ev == RDMA_CM_EVENT_DISCONNECTED) {
		rdma_ack_cm_event(event);
		return -EAGAIN;
	}

	if (ev != RDMA_CM_EVENT_CONNECT_REQUEST) {
		rdma_ack_cm_event(event);
		return -ENOTCONN;
	}

	*_id = id;
	id->event = event;

	return 0;
}

static int rdma_rma_read(struct nofuse_queue *ep, struct ep_qe *qe,
			 void *buf, uint64_t addr, size_t len,
			 uint32_t key, void *_mr)
{
	struct ibv_mr *mr = _mr;
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
	struct ibv_wc wc;
	int ret;

	memset(&wr, 0, sizeof(wr));

	wr.sg_list = &sge;
	wr.num_sge = 1;

	sge.length = len;
	sge.addr = (uintptr_t) buf;
	sge.lkey = mr->lkey;

	wr.opcode = IBV_WR_RDMA_READ;
	wr.wr.rdma.remote_addr = (uintptr_t) addr;
	wr.wr.rdma.rkey = key;
	wr.send_flags = IBV_SEND_SIGNALED;

	ret = ibv_post_send(ep->transport.rdma.id->qp, &wr, &bad_wr);
	if (ret)
		return ret;

	while (ibv_poll_cq(ep->transport.rdma.scq, 1, &wc) == 0)
		if (stopped)
			return -ESHUTDOWN;

	if (wc.status != IBV_WC_SUCCESS) {
		rdma_err(ep, "rma_read wc.status %s (%d)",
			 wc_str_status(wc.status), wc.status);
		return -ECONNRESET;
	}

	return 0;
}

static int rdma_send_msg(struct nofuse_queue *ep, struct ep_qe *qe,
			 struct nvme_completion *comp);

static int rdma_rma_write(struct nofuse_queue *ep, struct ep_qe *qe,
			  void *buf, uint64_t addr, size_t len,
			  uint32_t key, void *_mr)
{
	struct ibv_mr *mr = _mr;
	struct ibv_send_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;
	struct ibv_wc wc;
	int ret;

	memset(&wr, 0, sizeof(wr));

	wr.sg_list = &sge;
	wr.num_sge = 1;

	sge.length = len;
	sge.addr = (uintptr_t) buf;
	sge.lkey = mr->lkey;

	wr.opcode = IBV_WR_RDMA_WRITE;
	wr.wr.rdma.remote_addr = (uintptr_t) addr;
	wr.wr.rdma.rkey = key;
	wr.send_flags = IBV_SEND_SIGNALED;

	ret = ibv_post_send(ep->transport.rdma.id->qp, &wr, &bad_wr);
	if (ret)
		return ret;

	while (ibv_poll_cq(ep->transport.rdma.scq, 1, &wc) == 0)
		if (stopped)
			return -ESHUTDOWN;

	if (wc.status != IBV_WC_SUCCESS) {
		rdma_err(ep, "rma_write wc.status %s (%d)",
			 wc_str_status(wc.status), wc.status);
		return -ECONNRESET;
	}

	/*
	 * Unlike tcp_send_data() (whose last c2h_data PDU carries
	 * NVME_TCP_F_DATA_SUCCESS, doubling as the completion), RDMA has no
	 * such piggybacking: the data RDMA_WRITE above never tells the host
	 * the command is done. Every caller of ops->rma_write expects it to
	 * send the data *and* finish the command (see the comment in
	 * uring_handle_qe()), so send the completion capsule here too.
	 */
	memset(&qe->resp, 0, sizeof(qe->resp));
	set_response(&qe->resp, qe->ccid, NVME_SC_SUCCESS, true);
	return rdma_send_msg(ep, qe, &qe->resp);
}

static int rdma_repost_recv(struct nofuse_queue *ep, struct ep_qe *qe)
{
	struct ibv_recv_wr wr, *bad_wr = NULL;
	struct ibv_sge sge;

	memset(&wr, 0, sizeof(wr));

	wr.wr_id = (uintptr_t) qe;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	sge.length = PAGE_SIZE;
	sge.addr = (uintptr_t) qe->data;
	sge.lkey = qe->data_mr->lkey;

	memset(qe->data, 0, PAGE_SIZE);

	return ibv_post_recv(ep->transport.rdma.id->qp, &wr, &bad_wr);
}

static int rdma_post_msg(struct nofuse_queue *ep, void *msg, size_t len,
			 void *_mr)
{
	struct ibv_mr *mr = _mr;
	struct ibv_send_wr  wr, *bad_wr = NULL;
	struct ibv_sge sge;

	memset(&wr, 0, sizeof(wr));

	wr.opcode = IBV_WR_SEND;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.sg_list = &sge;
	wr.num_sge = 1;

	sge.length = len;
	sge.addr = (uintptr_t) msg;
	sge.lkey = mr->lkey;

	return ibv_post_send(ep->transport.rdma.id->qp, &wr, &bad_wr);
}

static int rdma_send_msg(struct nofuse_queue *ep, struct ep_qe *qe,
			 struct nvme_completion *comp)
{
	struct nvme_completion *resp = (void *)ep->transport.rdma.cmd;
	struct ibv_wc wc;
	int ret;

	memcpy(resp, comp, sizeof(*resp));
	ret = rdma_post_msg(ep, resp, sizeof(*resp),
			    ep->transport.rdma.cmd_mr);
	if (ret)
		return ret;

	while (ibv_poll_cq(ep->transport.rdma.scq, 1, &wc) == 0)
		if (stopped)
			return -ESHUTDOWN;

	if (wc.status != IBV_WC_SUCCESS) {
		if (wc.status != IBV_WC_RETRY_EXC_ERR)
			rdma_err(ep, "send wc.status %s (%d)",
				 wc_str_status(wc.status), wc.status);
		return -ECONNRESET;
	}

	rdma_repost_recv(ep, qe);
	return 0;
}

/*
 * Block for up to timeout_ms waiting for a completion event on either of
 * this queue's CQs (they share one completion channel), instead of
 * busy-polling ibv_poll_cq() in a tight loop. Drains and re-arms every
 * event the channel fd reports ready so a later ibv_poll_cq() call is
 * guaranteed to see the completions that triggered it.
 *
 * Returns 1 if at least one event was processed, 0 on timeout, or a
 * negative errno on error.
 */
int rdma_wait_for_msg(struct nofuse_queue *ep, int timeout_ms)
{
	struct ibv_comp_channel *comp = ep->transport.rdma.comp;
	struct pollfd pfd = { .fd = comp->fd, .events = POLLIN };
	struct ibv_cq *ev_cq;
	void *ev_ctx;
	int ret;

	ret = poll(&pfd, 1, timeout_ms);
	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ESHUTDOWN;

	ret = ibv_get_cq_event(comp, &ev_cq, &ev_ctx);
	if (ret) {
		rdma_err(ep, "ibv_get_cq_event failed, error %d", -errno);
		return -errno;
	}
	ibv_ack_cq_events(ev_cq, 1);
	if (ibv_req_notify_cq(ev_cq, 0)) {
		rdma_err(ep, "ibv_req_notify_cq failed, error %d",
			 errno);
		return -errno;
	}
	return 0;
}

static int rdma_poll_for_msg(struct nofuse_queue *ep,
			     struct ep_qe **qe)
{
	struct ibv_wc wc;
	struct ep_qe *_qe;
	struct nvme_command *cmd;
	int ret;

	ret = rdma_wait_for_msg(ep, ep->kato_interval * 10);
	if (ret < 0)
		return ret;
	ret = ibv_poll_cq(ep->transport.rdma.rcq, 1, &wc);
	if (ret <= 0)
		return ret;

	if (wc.status != IBV_WC_SUCCESS) {
		if (wc.status != IBV_WC_WR_FLUSH_ERR)
			rdma_err(ep, "recv wc.status %s (%d)",
				 wc_str_status(wc.status), wc.status);
		return -ECONNRESET;
	}

	_qe = (struct ep_qe *) wc.wr_id;

	_qe->data_len = wc.byte_len;
	/* ccid is considered opaque; no endian conversion */
	cmd = _qe->data;
	_qe->ccid = cmd->common.command_id;
	*qe = _qe;

	return 1;
}

static void *rdma_alloc_key(struct nofuse_queue *ep, void *buf, size_t len)
{
	struct ibv_mr *mr;
	int flags = IBV_ACCESS_LOCAL_WRITE
		| IBV_ACCESS_REMOTE_READ
		| IBV_ACCESS_REMOTE_WRITE;

	if (!ep) {
		rdma_err(ep, "invalid arguments");
		return NULL;
	}

	mr = ibv_reg_mr(ep->transport.rdma.pd, buf, len, flags);
	if (!mr) {
		rdma_err(ep, "ibv_reg_mr failed, error %d", errno);
		return NULL;
	}

	return (void *)mr;
}

static int rdma_dealloc_key(struct nofuse_queue *ep, void *_mr)
{
	struct ibv_mr *mr = (struct ibv_mr *) _mr;

	if (!_mr) {
		rdma_err(ep, "invalid arguments");
		return -EINVAL;
	}

	return ibv_dereg_mr(mr);
}

static struct xp_ops rdma_ops = {
	.create_queue		= rdma_create_queue,
	.destroy_queue		= rdma_destroy_queue,
	.init_listener		= rdma_init_listener,
	.destroy_listener	= rdma_destroy_listener,
	.wait_for_connection	= rdma_wait_for_connection,
	.accept_connection	= rdma_accept_connection,
	.rma_read		= rdma_rma_read,
	.rma_write		= rdma_rma_write,
	.send_rsp		= rdma_send_msg,
	.poll_for_msg		= rdma_poll_for_msg,
	.alloc_key		= rdma_alloc_key,
	.dealloc_key		= rdma_dealloc_key,
};

struct xp_ops *rdma_register_ops(void)
{
	return &rdma_ops;
}
