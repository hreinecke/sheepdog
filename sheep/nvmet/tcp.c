/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * tcp.c
 * NVMe-over-fabrics TCP transport protocol handling.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "sheep.h"
#include "nofuse.h"
#include "tcp.h"
#include "ops.h"
#include "configdb.h"
#include "tls.h"

#define NVME_OPCODE_MASK 0x3
#define NVME_OPCODE_H2C  0x1
#define NVME_OPCODE_C2H  0x2

#define BACKLOG			16
#define RESOLVE_TIMEOUT		5000
#define EVENT_TIMEOUT		200

#define TCP_SYNCNT		7
#define TCP_NODELAY		1

#define tcp_info(e, f, x...)					\
	if (tcp_debug) {					\
		sd_debug("ctrl %d qid %d: " f,			\
			 (e)->ctrl ? (e)->ctrl->cntlid : -1,	\
			 (e)->qid, ##x);			\
	}

#define tcp_err(e, f, x...)					\
	sd_err("ctrl %d qid %d: " f,				\
	       (e)->ctrl ? (e)->ctrl->cntlid : -1,		\
	       (e)->qid, ##x)

static int tcp_ep_read(struct nofuse_queue *ep, void *buf, size_t buf_len)
{
	return read(ep->fd, buf, buf_len);
}

static int tcp_ep_write(struct nofuse_queue *ep, void *buf, size_t buf_len)
{
	return write(ep->fd, buf, buf_len);
}

/*
 * Bounded, not indefinite: this runs on the connection's own thread
 * while it still holds 'ep', so blocking here forever if the peer never
 * drains/sends again would let some other path (e.g. keepalive timeout)
 * concurrently destroy this same 'ep' out from under it -- this thread
 * would then wake up (or never wake up, if the socket gets closed
 * first) and touch freed memory. Time out and let our own caller's
 * normal error handling tear the connection down on this thread instead.
 */
#define IO_WAIT_TIMEOUT_MS 5000

static int tcp_ep_wait(struct nofuse_queue *ep, short events)
{
	struct pollfd pfd = {
		.fd = ep->fd,
		.events = events,
	};
	int ret;

	do {
		ret = poll(&pfd, 1, IO_WAIT_TIMEOUT_MS);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ETIME;
	return 0;
}

static struct io_ops tcp_io_ops = {
	.io_read = tcp_ep_read,
	.io_write = tcp_ep_write,
	.io_wait = tcp_ep_wait,
};

struct io_ops *tcp_register_io_ops(void)
{
	return &tcp_io_ops;
}

static int tcp_create_queue(struct nofuse_queue *ep, void *id, int depth)
{
	int *conn = (int *)id;
	int flags, i;

	ep->trtype = NVMF_TRTYPE_TCP;
	ep->io_ops = tcp_register_io_ops();
	ep->fd = *conn;
	free(conn);

	flags = fcntl(ep->fd, F_GETFL);
	fcntl(ep->fd, F_SETFL, flags | O_NONBLOCK);

	ep->transport.tcp.send_pdu = malloc(sizeof(union nvme_tcp_pdu));
	if (!ep->transport.tcp.send_pdu) {
		tcp_err(ep, "no memory");
		return -ENOMEM;
	}
	memset(ep->transport.tcp.send_pdu, 0, sizeof(union nvme_tcp_pdu));

	ep->transport.tcp.recv_pdu = malloc(sizeof(union nvme_tcp_pdu));
	if (!ep->transport.tcp.recv_pdu) {
		free(ep->transport.tcp.send_pdu);
		ep->transport.tcp.send_pdu = NULL;
		tcp_err(ep, "no memory");
		return -ENOMEM;
	}
	memset(ep->transport.tcp.recv_pdu, 0, sizeof(union nvme_tcp_pdu));

	ep->qes = calloc(depth, sizeof(struct ep_qe));
	if (!ep->qes) {
		free(ep->transport.tcp.recv_pdu);
		ep->transport.tcp.recv_pdu = NULL;
		free(ep->transport.tcp.send_pdu);
		ep->transport.tcp.send_pdu = NULL;
		return -ENOMEM;
	}
	ep->qsize = ep->allocated_qsize = depth;
	for (i = 0; i < ep->qsize; i++) {
		ep->qes[i].tag = i;
		ep->qes[i].ep = ep;
	}
	/* Invert bitmap such that we can use ffs() */
	memset(ep->qes_map, 0xff, sizeof(ep->qes_map));
	return 0;
}

static void tcp_destroy_queue(struct nofuse_queue *ep)
{
	if (ep->qes) {
		int i;

		for (i = 0; i < ep->allocated_qsize; i++) {
			struct ep_qe *qe = &ep->qes[i];

			if (qe->busy && !qe->aen) {
				tcp_err(ep, "qid %d cid %#x still busy",
					ep->qid, qe->tag);
			}
			qe->busy = false;
			if (qe->data)
				free(qe->data);
		}
		free(ep->qes);
		ep->qes = NULL;
	}
	if (ep->transport.tcp.recv_pdu) {
		free(ep->transport.tcp.recv_pdu);
		ep->transport.tcp.recv_pdu = NULL;
	}
	if (ep->transport.tcp.send_pdu) {
		free(ep->transport.tcp.send_pdu);
		ep->transport.tcp.send_pdu = NULL;
	}
	tls_free_queue(ep);
	if (ep->fd >= 0) {
		close(ep->fd);
		ep->fd = -1;
	}
}

static struct ep_qe *tcp_acquire_tag(struct nofuse_queue *ep,
				     union nvme_tcp_pdu *pdu,
				     uint16_t ccid, off_t pos, size_t len)
{
	int m, i = 0, j, cid;
	int ngroups = (ep->qsize + 7) / 8;
	int last_group_size = ep->qsize % 8 ? ep->qsize % 8 : 8;
	struct ep_qe *qe = NULL;

	m = ep->qes_map_index;
retry:
	for (j = 0; j < ngroups; j++) {
		i = ffs(ep->qes_map[m] & 0xff);
		if (m == ngroups - 1 && i > last_group_size)
			i = 0;
		if (i != 0)
			break;
		m++;
		if (m == ngroups)
			m = 0;
	}
	if (!i) {
		tcp_err(ep, "qid %d all tags busy", ep->qid);
		return NULL;
	}
	cid = m * 8 + i - 1;
	if (ep->qes[cid].busy) {
		tcp_err(ep, "qid %d cid %d busy after selection",
			ep->qid, cid);
		goto retry;
	}
	if (ep->qes[cid].tag != cid) {
		tcp_err(ep, "qid %d cid %d tag mismatch (%d)",
			ep->qid, cid, ep->qes[cid].tag);
		return NULL;
	}
	ep->qes_map[m] &= ~(1 << (i - 1));
	ep->qes_map_index = m;
	qe = &ep->qes[cid];
	qe->busy = true;
	qe->ccid = ccid;
	if (len) {
		qe->data = malloc(len);
		if (!qe->data) {
			tcp_err(ep,
				"Error allocating iovec base");
			return NULL;
		}
		memset(qe->data, 0, len);
		qe->data_pos = pos;
		qe->data_len = len;
		qe->iovec.iov_base = NULL;
		qe->iovec.iov_len = 0;
		qe->iovec_offset = 0;
		qe->data_remaining = 0;
	}
	memset(&qe->resp, 0, sizeof(qe->resp));
	qe->resp.command_id = ccid;
	tcp_info(ep, "acquire tag %#x ccid %#x", qe->tag, qe->ccid);
	return qe;
}

static struct ep_qe *tcp_get_tag(struct nofuse_queue *ep, uint16_t tag)
{
	if (tag >= ep->qsize || !ep->qes[tag].busy)
		return NULL;
	return &ep->qes[tag];
}

static struct ep_qe *tcp_get_aen(struct nofuse_queue *ep)
{
	int i;

	if (!ep->qes)
		return NULL;

	for (i = 0; i < ep->qsize; i++) {
		struct ep_qe *qe = &ep->qes[i];

		if (qe->busy && qe->aen)
			return qe;
	}
	return NULL;
}

static void tcp_release_tag(struct nofuse_queue *ep, struct ep_qe *qe)
{
	if (!qe)
		return;
	if (&ep->qes[qe->tag] != qe)
		return;

	qe->busy = false;
	qe->aen = false;
	qe->async_started = false;
	if (qe->data) {
		free(qe->data);
		qe->data = NULL;
		qe->data_len = 0;
	}
	qe->iovec.iov_base = NULL;
	qe->iovec.iov_len = 0;
	ep->qes_map[qe->tag / 8] |= (1 << (qe->tag % 8));
	tcp_info(ep, "release tag %#x", qe->tag);
}

static int tcp_init_listener(struct nofuse_port *port)
{
	int listenfd;
	int ret, reuse = 1;
	struct addrinfo *ai, hints;
	char bindaddr[256];
	char trsvcid[32];
	char adrfam_str[32];
	sa_family_t adrfam = AF_INET;

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
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;

	ret = getaddrinfo(bindaddr, trsvcid, &hints, &ai);
	if (ret != 0) {
		port_err(port, "getaddrinfo() failed: %s",
			  gai_strerror(ret));
		return -EINVAL;
	}
	if (!ai) {
		port_err(port, "no results from getaddrinfo()");
		return -EHOSTUNREACH;
	}

	listenfd = socket(ai->ai_family, ai->ai_socktype,
			  ai->ai_protocol);
	if (listenfd < 0) {
		port_err(port, "socket error %d", errno);
		ret = -errno;
		goto err_free;
	}

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
		       &reuse, sizeof(int)) < 0) {
		port_err(port, "setsockopt SO_REUSEADDR error %d", errno);
		ret = -errno;
		goto err_close;
	}

	ret = bind(listenfd, ai->ai_addr, ai->ai_addrlen);
	if (ret < 0) {
		port_err(port, "socket %s:%s bind error %d",
			  bindaddr, trsvcid, errno);
		ret = -errno;
		goto err_close;
	}
	if (ai->ai_next)
		port_err(port, "duplicate addresses");
	freeaddrinfo(ai);

	ret = listen(listenfd, BACKLOG);
	if (ret < 0) {
		port_err(port, "socket listen error %d", errno);
		ret = -errno;
		goto err_close;
	}
	port_info(port, "listening on %s:%s", bindaddr, trsvcid);
	port->transport.tcp.listenfd = listenfd;
	return 0;
err_close:
	close(listenfd);
err_free:
	freeaddrinfo(ai);
	return ret;
}

static void tcp_destroy_listener(struct nofuse_port *port)
{
	if (port->transport.tcp.listenfd < 0)
		return;
	close(port->transport.tcp.listenfd);
	port->transport.tcp.listenfd = -1;
}

static int tcp_accept_connection(struct nofuse_queue *ep)
{
	struct nvme_tcp_icreq_pdu *icreq = NULL;
	struct nvme_tcp_icresp_pdu *icrep;
	size_t len, hdr_len;
	int ret;

	if (!ep)
		return -EINVAL;

	icreq = malloc(sizeof(*icreq));
	if (!icreq)
		return -ENOMEM;

	memset(icreq, 0, sizeof(*icreq));

	hdr_len = sizeof(struct nvme_tcp_hdr);
	ret = recv(ep->fd, icreq, hdr_len, MSG_PEEK);
	if (ret < 0) {
		if (errno != EAGAIN)
			tcp_err(ep, "icreq header peek error %d", errno);
		return -errno;
	}

	if (icreq->hdr.type != nvme_tcp_icreq && !ep->tls_started) {
		/*
		 * A retry of this whole function (start_queue()'s "goto
		 * retry" on -EAGAIN, e.g. because the rest of the icreq PDU
		 * below hasn't arrived yet) would otherwise land here again:
		 * the raw bytes peeked off an already-TLS-established socket
		 * are ciphertext, so they never look like a plaintext icreq
		 * header either. Calling tls_handshake() a second time on a
		 * session that's already past its handshake corrupts it
		 * (observed as GnuTLS reporting the session invalidated on
		 * the next read) instead of erroring out cleanly.
		 */
		ret = tls_handshake(ep);
		if (ret)
			return ret;
	}

	ret = ep->io_ops->io_wait(ep, POLLIN);
	if (ret < 0) {
		tcp_err(ep, "timeout waiting for icreq");
		return -ETIME;
	}
	ret = ep->io_ops->io_read(ep, icreq, hdr_len);
	if (ret < 0) {
		if (errno != EAGAIN)
			tcp_err(ep, "icreq header read error %d", errno);
		return -errno;
	}
	if (ret != hdr_len) {
		tcp_err(ep, "icreq short header read, %lu bytes missing",
			hdr_len - ret);
		ret = (ret > 0) ? -EAGAIN : -ENODATA;
		goto out_free;
	}

	if (icreq->hdr.type != nvme_tcp_icreq) {
		tcp_err(ep, "icreq header type mismatch (%02x)",
			icreq->hdr.type);
		ret = -ENOMSG;
		goto out_free;
	}
	len = icreq->hdr.hlen - hdr_len;
	ret = ep->io_ops->io_wait(ep, POLLIN);
	if (ret < 0) {
		tcp_err(ep, "timeout waiting for rest of icreq");
		ret = -ETIME;
		goto out_free;
	}
	ret = ep->io_ops->io_read(ep, (uint8_t *)icreq + hdr_len, len);
	if (ret < 0) {
		tcp_err(ep, "icreq read error %d", errno);
		ret = -errno;
		goto out_free;
	}
	if (ret != len) {
		tcp_err(ep, "icreq short read, %lu bytes missing",
			len - ret);
		ret = (ret > 0) ? -EAGAIN : -ENODATA;
		goto out_free;
	}
	if (icreq->hpda != 0) {
		ret = -EPROTO;
		goto out_free;
	}
	ep->maxr2t = le32toh(icreq->maxr2t) + 1;

	tcp_info(ep, "read %d icreq bytes (type %d, maxr2t %u)",
		 icreq->hdr.hlen, icreq->hdr.type, icreq->maxr2t);

	icrep = malloc(sizeof(*icrep));
	if (!icrep) {
		ret = -ENOMEM;
		goto out_free;
	}

	memset(icrep, 0, sizeof(*icrep));
	icrep->hdr.type = nvme_tcp_icresp;
	icrep->hdr.hlen = sizeof(*icrep);
	icrep->hdr.pdo = 0;
	icrep->hdr.plen = htole32(sizeof(*icrep));
	icrep->pfv = htole16(NVME_TCP_PFV_1_0);
	icrep->maxdata = 0xf000;
	icrep->cpda = 0;
	icrep->digest = 0;

	len = ep->io_ops->io_write(ep, icrep, sizeof(*icrep));
	if (len < 0) {
		tcp_err(ep, "icresp write error %d", errno);
		return -errno;
	}
	if (len != sizeof(*icrep)) {
		tcp_err(ep, "icrep short write, %ld bytes missing",
			sizeof(*icrep) - len);
		ret = -ENODATA;
	} else {
		tcp_info(ep, "wrote %lu icresp bytes", len);
		ret = 0;
	}

	free(icrep);
out_free:
	free(icreq);
	return ret;
}

static int tcp_wait_for_connection(struct nofuse_port *port, void **id)
{
	int *sockfd, fd;
	int ret = -ESHUTDOWN;

	sockfd = xzalloc(sizeof(int));
	while (port->transport.tcp.listenfd > 0) {
		fd_set rfd;
		struct timeval tmo;

		FD_ZERO(&rfd);
		FD_SET(port->transport.tcp.listenfd, &rfd);
		tmo.tv_sec = (KATO_INTERVAL / 1000);
		tmo.tv_usec = (KATO_INTERVAL % 1000) * 1000;
		ret = select(port->transport.tcp.listenfd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			port_err(port, "select error %d", errno);
			ret = -errno;
			break;
		}
		if (ret > 0)
			break;
	}

	if (port->transport.tcp.listenfd < 0)
		return -ESHUTDOWN;

	if (ret <= 0)
		return ret ? ret : -ETIME;

	fd = accept(port->transport.tcp.listenfd, (struct sockaddr *) NULL,
		    NULL);
	if (fd < 0) {
		if (errno != EAGAIN)
			port_err(port, "accept error %d", errno);
		ret = -EAGAIN;
	} else {
		*sockfd = fd;
		*id = sockfd;
	}
	return ret;
}

static void tcp_destroy_connection(struct nofuse_port *port, void *id)
{
	int *sockfd = id;

	close(*sockfd);
	free(sockfd);
}

static int tcp_rma_read(struct nofuse_queue *ep, struct ep_qe *qe,
			void *data, uint64_t addr, size_t data_len,
			uint32_t key, void *mr)
{
	int len = 0;
	off_t offset = 0;

	while (offset < data_len) {
		tcp_info(ep, "recv %lu data bytes",
			data_len - offset);
		len = ep->io_ops->io_read(ep, (uint8_t *)data + offset,
					  data_len - offset);

		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				int wret = ep->io_ops->io_wait(ep, POLLIN);

				if (wret < 0)
					return wret;
				continue;
			}
			tcp_err(ep, "recv returned %d", errno);
			return -errno;
		}
		if (len == 0) {
			tcp_err(ep, "disconnect during recv data");
			return -ENODATA;
		}
		offset += len;
	}
	return 0;
}

static int tcp_write_full(struct nofuse_queue *ep, void *buf, size_t len)
{
	off_t offset = 0;

	while (offset < len) {
		int ret = ep->io_ops->io_write(ep, (uint8_t *)buf + offset,
					       len - offset);

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				int wret = ep->io_ops->io_wait(ep, POLLOUT);

				if (wret < 0)
					return wret;
				continue;
			}
			tcp_err(ep, "send returned %d", errno);
			return -errno;
		}
		if (ret == 0) {
			tcp_err(ep, "%s: disconnect during send data",
				__func__);
			return -ENODATA;
		}
		offset += ret;
	}
	return 0;
}

static int tcp_send_c2h_data(struct nofuse_queue *ep, struct ep_qe *qe)
{
	int ret;
	bool last = qe->data_remaining == qe->iovec.iov_len;
	struct nvme_tcp_data_pdu *pdu = &ep->transport.tcp.send_pdu->data;
	size_t data_len = qe->iovec.iov_len;

	tcp_info(ep, "c2h data cid %x offset %"PRIu64" len %lu/%"PRIu64,
		  qe->ccid, qe->data_pos, qe->iovec.iov_len,
		  qe->data_remaining);

	if (!qe->data_remaining) {
		tcp_err(ep, "Nothing to send, %lu bytes left",
			 qe->iovec.iov_len);
		return 0;
	}
	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.type = nvme_tcp_c2h_data;
	pdu->hdr.flags = last ? (NVME_TCP_F_DATA_LAST | NVME_TCP_F_DATA_SUCCESS) : 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_data_pdu);
	pdu->hdr.plen = htole32(sizeof(struct nvme_tcp_data_pdu) +
				qe->iovec.iov_len);
	pdu->data_offset = htole32(qe->data_pos);
	pdu->data_length = htole32(qe->iovec.iov_len);
	pdu->command_id = qe->ccid;
	tcp_info(ep, "c2h hdr init %u/%u bytes",
		 pdu->hdr.hlen, pdu->hdr.plen);

	ret = tcp_write_full(ep, pdu, pdu->hdr.hlen);
	if (ret < 0) {
		tcp_err(ep, "c2h hdr write error %d", -ret);
		return ret;
	}
	tcp_info(ep, "c2h hdr wrote %u bytes", pdu->hdr.hlen);

	ret = tcp_write_full(ep, qe->iovec.iov_base, data_len);
	if (ret < 0) {
		tcp_err(ep, "c2h data write error %d", -ret);
		return ret;
	}
	qe->data_remaining -= data_len;
	qe->iovec.iov_base = (uint8_t *)qe->iovec.iov_base + data_len;
	qe->iovec.iov_len -= data_len;
	qe->iovec_offset += data_len;
	tcp_info(ep, "c2h data wrote %lu bytes", data_len);

	return 0;
}

static int tcp_send_r2t(struct nofuse_queue *ep, uint16_t tag)
{
	struct nvme_tcp_r2t_pdu *pdu = &ep->transport.tcp.send_pdu->r2t;
	struct ep_qe *qe;

	qe = tcp_get_tag(ep, tag);
	if (!qe) {
		tcp_err(ep, "invalid ttag %#x", tag);
		return -EINVAL;
	}

	tcp_info(ep, "r2t cid %#x ttag %#x offset %"PRIu64" len %lu",
		 qe->ccid, qe->tag, qe->iovec_offset,
		 qe->iovec.iov_len);

	memset(pdu, 0, sizeof(*pdu));
	pdu->hdr.type = nvme_tcp_r2t;
	pdu->hdr.flags = 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_r2t_pdu);
	pdu->hdr.plen = htole32(sizeof(struct nvme_tcp_r2t_pdu));
	pdu->ttag = qe->tag;
	pdu->command_id = qe->ccid;
	pdu->r2t_offset = htole32(qe->iovec_offset);
	pdu->r2t_length = htole32(qe->iovec.iov_len);

	return tcp_write_full(ep, pdu, sizeof(*pdu));
}

static int tcp_send_c2h_term(struct nofuse_queue *ep, uint16_t fes, uint8_t pdu_offset,
			     uint8_t parm_offset, bool hdr_digest,
			     union nvme_tcp_pdu *pdu, int pdu_len)
{
	struct nvme_tcp_term_pdu *term_pdu = &ep->transport.tcp.send_pdu->term;
	int ret, plen;

	tcp_info(ep, "c2h term fes %u offset pdu %u parm %u",
		   fes, pdu_offset, parm_offset);

	if (!pdu)
		pdu_len = 0;
	if (pdu_len > 152 - sizeof(struct nvme_tcp_term_pdu))
		pdu_len = 152 - sizeof(struct nvme_tcp_term_pdu);
	plen = sizeof(struct nvme_tcp_term_pdu) + pdu_len;
	term_pdu->hdr.type = nvme_tcp_c2h_term;
	term_pdu->hdr.flags = 0;
	term_pdu->hdr.pdo = 0;
	term_pdu->hdr.hlen = sizeof(struct nvme_tcp_term_pdu);
	term_pdu->hdr.plen = htole32(plen);
	term_pdu->fes = htole16(fes);
	term_pdu->fei = htole32(parm_offset << 6 | pdu_offset << 1);

	ret = tcp_write_full(ep, term_pdu, sizeof(*term_pdu));
	if (ret < 0) {
		tcp_err(ep, "c2h term write error %d", -ret);
	} else if (pdu) {
		ret = tcp_write_full(ep, pdu, pdu_len);
		if (ret < 0)
			tcp_err(ep, "c2h term pdu write error %d", -ret);
	}

	ep->transport.tcp.recv_state = RECV_PDU;
	ep->transport.tcp.recv_pdu_len = 0;

	/* Return -EPROTO to signal the connection should be dropped */
	return ret < 0 ? ret : -EPROTO;
}

static int tcp_send_rsp(struct nofuse_queue *ep, struct ep_qe *qe,
			struct nvme_completion *comp)
{
	struct nvme_tcp_rsp_pdu *pdu = &ep->transport.tcp.send_pdu->rsp;
	int len;

	tcp_info(ep, "rsp ccid %#x status %04x",
		  comp->command_id, comp->status);

	pdu->hdr.type = nvme_tcp_rsp;
	pdu->hdr.flags = 0;
	pdu->hdr.pdo = 0;
	pdu->hdr.hlen = sizeof(struct nvme_tcp_rsp_pdu);
	pdu->hdr.plen = sizeof(struct nvme_tcp_rsp_pdu);

	memcpy(&(pdu->cqe), comp, sizeof(struct nvme_completion));

	tcp_info(ep, "write %u pdu bytes", pdu->hdr.plen);
	len = tcp_write_full(ep, pdu, pdu->hdr.plen);
	if (len < 0)
		tcp_err(ep, "pdu write error %d", -len);
	if (qe)
		tcp_release_tag(ep, qe);
	return len;
}

static int tcp_handle_h2c_data(struct nofuse_queue *ep, union nvme_tcp_pdu *pdu)
{
	uint16_t ttag = le16toh(pdu->data.ttag);
	uint32_t data_offset = le32toh(pdu->data.data_offset);
	uint32_t data_len = le32toh(pdu->data.data_length);
	uint8_t *data;
	struct ep_qe *qe;
	int ret;

	tcp_info(ep, "h2c data tag %#x pos %u len %u",
		  ttag, data_offset, data_len);
	qe = tcp_get_tag(ep, ttag);
	if (!qe) {
		tcp_err(ep, "h2c invalid ttag %#x", ttag);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_INVALID_PDU_HDR,
				offsetof(struct nvme_tcp_data_pdu, ttag),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_offset != qe->iovec_offset) {
		tcp_err(ep, "h2c offset mismatch, is %u exp %"PRIu64,
			 data_offset, qe->iovec_offset);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offsetof(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}
	if (data_len > qe->iovec.iov_len) {
		tcp_err(ep, "h2c len overflow, is %u exp %"PRIu64,
			 data_len, qe->data_remaining);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
				offsetof(struct nvme_tcp_data_pdu, data_offset),
				0, false, pdu, sizeof(struct nvme_tcp_data_pdu));
	}

	ret = tcp_rma_read(ep, qe, qe->iovec.iov_base, 0, data_len, 0, NULL);
	if (ret < 0) {
		tcp_err(ep, "h2c data read failed, error %d", errno);
		ret = NVME_SC_SGL_INVALID_DATA;
		goto out_rsp;
	}
	qe->data_remaining -= data_len;
	qe->iovec_offset += data_len;
	data = qe->iovec.iov_base;
	data += data_len;
	qe->iovec.iov_base = data;
	qe->iovec.iov_len -= data_len;
	if (!qe->data_remaining) {
		/*
		 * All of this command's data has arrived -- restore iovec to
		 * describe the whole buffer (it was just walked down to
		 * (end, 0) tracking reception progress above) before handing
		 * off to the namespace backend, which expects to see the
		 * complete write/dsm payload, not "0 bytes left".
		 */
		qe->iovec.iov_base = qe->data;
		qe->iovec.iov_len = qe->data_len;
		return handle_data(ep, qe, -EINPROGRESS);
	}

	/*
	 * The single R2T sent for this command (handle_write()/handle_dsm(),
	 * via ns_prep_read()) already granted the entire remaining data
	 * length up front. The host is free to split its response into as
	 * many H2CData PDUs as it likes against that same grant -- nothing
	 * further needs asking for, and sending an unsolicited extra R2T
	 * here mid-transfer desyncs the host's own byte-accounting for this
	 * request (observed as a kernel-side "r2t len exceeded data len"
	 * error and a connection reset). Just acknowledge this PDU and wait
	 * for the next one.
	 */
	return 0;
out_rsp:
	memset(&qe->resp, 0, sizeof(qe->resp));
	set_response(&qe->resp, qe->ccid, ret, true);
	ret = tcp_send_rsp(ep, qe, &qe->resp);
	return ret;
}

static int tcp_read_pdu(struct nofuse_queue *ep)
{
	uint8_t *msg = (uint8_t *)ep->transport.tcp.recv_pdu +
		ep->transport.tcp.recv_pdu_len;
	size_t msg_len;
	int ret;

	if (ep->transport.tcp.recv_pdu_len < sizeof(struct nvme_tcp_hdr)) {
		msg_len = sizeof(struct nvme_tcp_hdr) -
			ep->transport.tcp.recv_pdu_len;
		tcp_info(ep, "read %lu msg bytes", msg_len);
		ret = ep->io_ops->io_read(ep, msg, msg_len);
		if (ret < 0) {
			tcp_err(ep, "failed to read msg hdr, error %d",
				errno);
			return -errno;
		}
		/* No data received, disconnected */
		if (!ret) {
			tcp_info(ep, "disconnect during read msg");
			return -ENODATA;
		}

		ep->transport.tcp.recv_pdu_len += ret;
		msg_len -= ret;
		if (msg_len) {
			tcp_err(ep, "short msg hdr read, %lu bytes missing",
				msg_len);
			return -EAGAIN;
		}
	}
	if (!ep->transport.tcp.recv_pdu->common.hlen) {
		tcp_err(ep, "corrupt hdr, hlen %d size %ld",
			ep->transport.tcp.recv_pdu->common.hlen,
			sizeof(struct nvme_tcp_hdr));
		return tcp_send_c2h_term(ep, NVME_TCP_FES_INVALID_PDU_HDR,
					offsetof(struct nvme_tcp_hdr, hlen),
					0, false, NULL, 0);
	}
	msg_len = ep->transport.tcp.recv_pdu->common.hlen -
		ep->transport.tcp.recv_pdu_len;
	if (msg_len) {
		msg = (uint8_t *)ep->transport.tcp.recv_pdu +
			ep->transport.tcp.recv_pdu_len;

		tcp_info(ep, "read %lu pdu bytes", msg_len);
		ret = ep->io_ops->io_read(ep, msg, msg_len);
		if (ret < 0) {
			if (errno != EAGAIN)
				tcp_err(ep,
					"failed to read msg payload error %d",
					errno);
			return -errno;
		}
		if (ret == 0) {
			tcp_info(ep, "disconnect during read pdu");
			return -ENODATA;
		}
		ep->transport.tcp.recv_pdu_len += ret;
		msg_len -= ret;
		if (msg_len > 0) {
			tcp_info(ep, "short msg payload read, %lu bytes missing",
				 msg_len);
			return -EAGAIN;
		}
		ep->transport.tcp.recv_state = HANDLE_PDU;
	}
	return 0;
}

static int tcp_get_qe(struct nofuse_queue *ep, struct nvme_command *cmd,
		      struct ep_qe **_qe)
{
	struct ep_qe *qe;
	uint32_t len;
	uint16_t ccid;

	len = le32toh(cmd->common.dptr.sgl.length);
	/* ccid is considered opaque; no endian conversion */
	ccid = cmd->common.command_id;
	qe = tcp_acquire_tag(ep, ep->transport.tcp.recv_pdu, ccid, 0, len);
	if (!qe) {
		struct nvme_completion resp = {
			.status = NVME_SC_NS_NOT_READY,
			.command_id = ccid,
		};

		ctrl_err(ep, "ccid %#x queue busy", ccid);
		*_qe = NULL;
		return tcp_send_rsp(ep, NULL, &resp);
	}
	memset(&qe->resp, 0, sizeof(qe->resp));
	*_qe = qe;
	return 0;
}

static int tcp_handle_msg(struct nofuse_queue *ep)
{
	union nvme_tcp_pdu *pdu = ep->transport.tcp.recv_pdu;
	struct nvme_tcp_hdr *hdr = &pdu->common;
	struct ep_qe *qe;
	int ret;

	if (ep->transport.tcp.recv_state == RECV_PDU) {
		ret = tcp_read_pdu(ep);
		if (ret || ep->transport.tcp.recv_state != HANDLE_PDU)
			return ret;
	}
	if (hdr->type == nvme_tcp_h2c_data) {
		ret = tcp_handle_h2c_data(ep, pdu);
		ep->transport.tcp.recv_pdu_len = 0;
		ep->transport.tcp.recv_state = RECV_PDU;
		return ret;
	}

	if (hdr->type == nvme_tcp_h2c_term) {
		ep->transport.tcp.recv_state = RECV_PDU;
		ep->transport.tcp.recv_pdu_len = 0;
		tcp_info(ep, "h2c term, disconnecting");
		return -ENOTCONN;
	}

	if (hdr->type != nvme_tcp_cmd) {
		tcp_err(ep, "unknown PDU type %x", hdr->type);
		return tcp_send_c2h_term(ep, NVME_TCP_FES_PDU_SEQ_ERR,
					 offsetof(struct nvme_tcp_hdr, type),
					 0, false, pdu, hdr->hlen);
	}

	ret = tcp_get_qe(ep, &pdu->cmd.cmd, &qe);
	if (ret < 0) {
		tcp_err(ep, "failed to get qe, error %d", ret);
		return ret;
	}
	if (qe) {
		ret = handle_request(ep, qe, &pdu->cmd.cmd);
		ep->transport.tcp.recv_pdu_len = 0;
		ep->transport.tcp.recv_state = RECV_PDU;
	}
	return ret;
}

static int tcp_send_data(struct nofuse_queue *ep, struct ep_qe *qe,
			 void *data, uint64_t addr, size_t data_len,
			 uint32_t key, void *mr)
{
	tcp_info(ep, "write cid %x offset %"PRIu64" len %lu",
		  qe->ccid, qe->data_pos, data_len);

	qe->data_remaining = data_len;
	qe->iovec.iov_base = data;
	qe->iovec.iov_len = (ep->mdts && data_len > ep->mdts) ?
		ep->mdts : data_len;
	qe->iovec_offset = 0;
	while (qe->data_remaining) {
		int ret = tcp_send_c2h_data(ep, qe);
		if (ret < 0) {
			tcp_release_tag(ep, qe);
			return ret;
		}
		data_len = qe->data_remaining;
		qe->iovec.iov_len = (ep->mdts && data_len > ep->mdts) ?
			ep->mdts : data_len;
	}
	tcp_release_tag(ep, qe);
	return 0;
}

static void *tcp_alloc_key(struct nofuse_queue *ep, void *buf, size_t len)
{
	return &tcp_alloc_key;
}

static int tcp_dealloc_key(struct nofuse_queue *ep, void *mr)
{
	return 0;
}

static struct xp_ops tcp_ops = {
	.create_queue		= tcp_create_queue,
	.destroy_queue		= tcp_destroy_queue,
	.init_listener		= tcp_init_listener,
	.destroy_listener	= tcp_destroy_listener,
	.wait_for_connection	= tcp_wait_for_connection,
	.accept_connection	= tcp_accept_connection,
	.destroy_connection	= tcp_destroy_connection,
	.get_aen		= tcp_get_aen,
	.rma_read		= tcp_rma_read,
	.rma_write		= tcp_send_data,
	.prep_rma_read		= tcp_send_r2t,
	.send_rsp		= tcp_send_rsp,
	.handle_msg		= tcp_handle_msg,
	.alloc_key		= tcp_alloc_key,
	.dealloc_key		= tcp_dealloc_key,
};

struct xp_ops *tcp_register_ops(void)
{
	return &tcp_ops;
}
