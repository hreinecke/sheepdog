/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * uring.c
 * Asynchronous VDI-backed I/O for NVMe-oF userspace emulation.
 *
 * Namespace reads/writes are submitted directly into sheepdog's own
 * (already-asynchronous) local request pipeline via
 * sd_read_object_async()/sd_write_object_async(), so no thread ever
 * blocks waiting for the cluster round-trip. Completions arrive on
 * the sheepdog main thread and are handed to the connection's own
 * io_uring loop (queue.c:queue_thread(), running on ep->pthread) via
 * ep->io_evtfd, so that ep/qes_map state continues to be touched
 * only from ep->pthread.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#include <stdio.h>
#include <pthread.h>
#include <sys/eventfd.h>

#include "sheep_priv.h"
#include "nofuse.h"
#include "nvme.h"
#include "ops.h"

struct uring_io_ctx {
	struct nofuse_queue *ep;
	struct ep_qe *qe;
	/*
	 * 'pending' is written once (to the sub-request count) by the
	 * submitting thread (ep->pthread) before any sub-request is
	 * fired, and from then on only ever read/decremented by
	 * uring_io_done() on the sheepdog main thread, so no lock is
	 * needed for it. 'failed' is likewise only ever touched from
	 * that same main thread.
	 */
	int pending;
	bool failed;
};

static void uring_complete(struct nofuse_queue *ep, struct ep_qe *qe, int res)
{
	qe->io_res = res;

	pthread_mutex_lock(&ep->io_done_lock);
	list_add_tail(&qe->io_node, &ep->io_done_list);
	pthread_mutex_unlock(&ep->io_done_lock);

	if (eventfd_write(ep->io_evtfd, 1) < 0)
		ctrl_err(ep, "tag %#x eventfd_write error %d", qe->tag, errno);
}

/* Runs on the sheepdog main thread (put_request()). */
static void uring_io_done(struct request *req)
{
	struct uring_io_ctx *ctx = req->local_done_arg;

	if (req->rp.result != SD_RES_SUCCESS)
		ctx->failed = true;

	if (--ctx->pending == 0) {
		uring_complete(ctx->ep, ctx->qe, ctx->failed ? -EIO : 0);
		free(ctx);
	}
}

/*
 * A single NVMe read/write can span more than one sheepdog data
 * object, so fire one async local request per object touched by
 * [qe->data_pos, qe->data_pos + iov_len).
 */
static int uring_submit_io(struct nofuse_queue *ep, struct ep_qe *qe,
			   bool is_write)
{
	uint8_t *buf = qe->iovec.iov_base;
	uint64_t pos = qe->data_pos;
	uint64_t remaining = qe->iovec.iov_len;
	struct uring_io_ctx *ctx;

	if (!remaining) {
		uring_complete(ep, qe, 0);
		return 0;
	}

	ctx = xmalloc(sizeof(*ctx));
	ctx->ep = ep;
	ctx->qe = qe;
	ctx->failed = false;
	ctx->pending = (pos + remaining - 1) / SD_DATA_OBJ_SIZE -
		       pos / SD_DATA_OBJ_SIZE + 1;

	while (remaining) {
		uint64_t idx = pos / SD_DATA_OBJ_SIZE;
		uint64_t obj_offset = pos % SD_DATA_OBJ_SIZE;
		uint64_t len = min(remaining, SD_DATA_OBJ_SIZE - obj_offset);
		uint64_t oid = vid_to_data_oid(qe->vid, idx);

		if (is_write)
			sd_write_object_async(oid, (char *)buf, len,
					      obj_offset, true,
					      uring_io_done, ctx);
		else
			sd_read_object_async(oid, (char *)buf, len,
					     obj_offset,
					     uring_io_done, ctx);

		buf += len;
		pos += len;
		remaining -= len;
	}

	return 0;
}

static int uring_submit_write(struct nofuse_queue *ep, struct ep_qe *qe)
{
	qe->opcode = nvme_cmd_write;

	return uring_submit_io(ep, qe, true);
}

static int uring_submit_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	qe->opcode = nvme_cmd_read;

	return uring_submit_io(ep, qe, false);
}

/*
 * Called from queue.c:queue_thread() (ep->pthread) once a queued
 * read/write has finished; res is qe->io_res (0 on success).
 */
static int uring_handle_qe(struct nofuse_queue *ep, struct ep_qe *qe, int res)
{
	int status = 0, ret;

	ctrl_info(ep, "tag %#x ccid %#x handle qe res %d",
		  qe->tag, qe->ccid, res);

	if (res < 0) {
		ctrl_err(ep, "tag %#x vdi %s failed, error %d", qe->tag,
			 qe->opcode == nvme_cmd_write ? "write" : "read", res);
		status = NVME_SC_INTERNAL;
	} else if (qe->opcode == nvme_cmd_read) {
		/* rma_write() sends the data and releases the tag itself. */
		return ep->ops->rma_write(ep, qe, qe->data_len);
	}

	memset(&qe->resp, 0, sizeof(qe->resp));
	set_response(&qe->resp, qe->ccid, status, true);
	ret = ep->ops->send_rsp(ep, &qe->resp);
	ep->ops->release_tag(ep, qe);
	return ret;
}

static struct ns_ops uring_ops = {
	.ns_read = uring_submit_read,
	.ns_write = uring_submit_write,
	.ns_handle_qe = uring_handle_qe,
};

struct ns_ops *uring_register_ops(void)
{
	return &uring_ops;
}
