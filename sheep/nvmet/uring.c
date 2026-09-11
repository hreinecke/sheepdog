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

static void uring_complete(struct nofuse_queue *ep, struct ep_qe *qe, int res)
{
	qe->io_res = res;

	pthread_mutex_lock(&ep->io_done_lock);
	list_add_tail(&qe->io_node, &ep->io_done_list);
	pthread_mutex_unlock(&ep->io_done_lock);

	if (eventfd_write(ep->io_evtfd, 1) < 0)
		ctrl_err(ep, "tag %#x eventfd_write error %d", qe->tag, errno);
}

static int uring_io_finish(struct ep_qe *qe, uint64_t oid,
			   off_t off, size_t len, int result)
{
	int ret;

	if (result != SD_RES_SUCCESS) {
		ctrl_err(qe->ep, "tag %d VDI oid %"PRIx64
			 " off %lu size %lu read error %s",
			 qe->tag, oid, off, len, sd_strerror(result));
		qe->async_result = result;
		ret = -EIO;
	}
	return ret;
}

/* Runs on the sheepdog main thread (put_request()). */
static void uring_io_done(struct request *req)
{
	struct ep_qe *qe = req->local_done_arg;
	int ret = 0;

	if (req->rp.result == SD_RES_NO_OBJ &&
	    req->rq.opcode == SD_OP_READ_OBJ) {
		/*
		 * Sheepdog VDIs are sparse: an object that was never
		 * written simply doesn't exist yet. Reading it isn't a
		 * failure, it just means the LBA range reads as zero
		 * (same convention as e.g. dog_vdi_read()).
		 */
		memset(req->data, 0, req->data_length);
	} else
		ret = uring_io_finish(qe, req->rq.obj.oid,
				      req->rq.obj.offset, req->data_length,
				      req->rp.result);

	if (refcount_dec(&qe->async_pending) == 0)
		uring_complete(qe->ep, qe, ret);
}

static void uring_write_retry_done(struct request *req)
{
	struct ep_qe *qe = req->local_done_arg;
	int ret = uring_io_finish(qe, req->rq.obj.oid,
				  req->rq.obj.offset,
				  req->data_length,
				  req->rp.result);

	if (refcount_dec(&qe->async_pending) == 0)
		uring_complete(qe->ep, qe, ret);
}

static void uring_write_done(struct request *req)
{
	struct ep_qe *qe = req->local_done_arg;

	if (req->rp.result == SD_RES_NO_OBJ) {
		sd_write_object_async(req->rq.obj.oid, req->data,
				      req->data_length,
				      req->rq.obj.offset, true,
				      uring_write_retry_done, qe);
		return;
	}

	uring_write_retry_done(req);
}

static int uring_submit_write(struct nofuse_queue *ep, struct ep_qe *qe)
{
	uint8_t *data = qe->data;
	size_t data_len = qe->data_len;
	off_t pos = qe->data_pos;

	if (!data_len) {
		uring_complete(ep, qe, 0);
		return 0;
	}

	refcount_set(&qe->async_pending,
		     (pos + data_len - 1) / SD_DATA_OBJ_SIZE -
		     pos / SD_DATA_OBJ_SIZE + 1);

	qe->async_result = SD_RES_SUCCESS;
	while (data_len) {
		uint64_t idx = pos / SD_DATA_OBJ_SIZE;
		off_t off = pos % SD_DATA_OBJ_SIZE;
		size_t len = min(data_len, SD_DATA_OBJ_SIZE - off);
		uint64_t oid = vid_to_data_oid(qe->vid, idx);

		sd_write_object_async(oid, (char *)data, len,
				      off, false,
				      uring_write_done, qe);
		data += len;
		pos += len;
		data_len -= len;
	}
	return 0;
}

static int uring_submit_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	uint8_t *data = qe->data;
	size_t data_len = qe->data_len;
	off_t pos = qe->data_pos;

	if (!data_len) {
		uring_complete(ep, qe, 0);
		return 0;
	}

	refcount_set(&qe->async_pending,
		     (pos + data_len - 1) / SD_DATA_OBJ_SIZE -
		     pos / SD_DATA_OBJ_SIZE + 1);
	qe->async_result = SD_RES_SUCCESS;

	while (data_len) {
		unsigned int idx = pos / SD_DATA_OBJ_SIZE;
		off_t off = pos % SD_DATA_OBJ_SIZE;
		size_t len = min(data_len, SD_DATA_OBJ_SIZE - off);
		uint64_t oid = vid_to_data_oid(qe->vid, idx);

		sd_read_object_async(oid, (char *)data, len,
				     off, uring_io_done, qe);
		data += len;
		pos += len;
		data_len -= len;
	}
	return 0;
}

/*
 * Requests transfer of a non-inline write's data via R2T/H2CData PDUs.
 * Submitting the write itself to the namespace backend happens later,
 * once that data has actually arrived (tcp_handle_h2c_data() calls
 * qe->ns_write(), set to uring_submit_write() by handle_write()).
 */
static int uring_prep_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	return ep->ops->prep_rma_read(ep, qe->tag);
}

/*
 * Called once a Dataset Management command's range descriptors have
 * fully arrived via R2T/H2CData (qe->ns_write, set by handle_dsm()).
 *
 * A range only ever gets discarded if it covers one or more whole
 * sheepdog data objects -- sheepdog has no way to punch a hole inside
 * an object, and a VDI already reads unwritten objects as zero
 * (uring_io_done()), so removing a fully-covered object is exactly
 * equivalent to (and cheaper than) actually writing zeroes over it.
 * Any partial object at either end of a range is left untouched:
 * discard is advisory, so silently keeping that data is always a
 * valid response.
 */
static int uring_submit_dsm(struct nofuse_queue *ep, struct ep_qe *qe)
{
	struct nvme_dsm_range *range = qe->data;
	int nr_ranges = qe->data_len / sizeof(*range);
	int i, ret;

	for (i = 0; i < nr_ranges; i++) {
		uint64_t slba = le64toh(range[i].slba);
		uint32_t nlb = le32toh(range[i].nlb);
		uint64_t start = slba * qe->ns->blksize;
		uint64_t end = start + (uint64_t)nlb * qe->ns->blksize;
		uint64_t idx = round_up(start, SD_DATA_OBJ_SIZE) / SD_DATA_OBJ_SIZE;
		uint64_t idx_end = round_down(end, SD_DATA_OBJ_SIZE) / SD_DATA_OBJ_SIZE;
		int nr_idx = idx_end - idx;
		uint32_t *zero;

		if (!nr_idx)
			continue;
		zero = xzalloc(nr_idx * sizeof(*zero));
		ret = sd_write_object(vid_to_vdi_oid(qe->vid), (char *)zero,
				      nr_idx * sizeof(*zero),
				      offsetof(struct sd_inode, data_vdi_id[idx]),
				      false);
		free(zero);
		if (ret != SD_RES_SUCCESS) {
			ctrl_err(ep, "dsm: failed to update inode for "
				 "discarding idx %"PRIu64"-%"PRIu64": %s",
				 idx, idx_end, sd_strerror(ret));
			return NVME_SC_INTERNAL;
		}

		for (; idx < idx_end; idx++) {
			uint64_t oid = vid_to_data_oid(qe->vid, idx);

			ret = sd_remove_object(oid);
			if (ret != SD_RES_SUCCESS && ret != SD_RES_NO_OBJ) {
				ctrl_err(ep, "dsm: failed to remove object %016"PRIx64": %s",
					 oid, sd_strerror(ret));
				return NVME_SC_INTERNAL;
			}
		}
	}
	return NVME_SC_SUCCESS;
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
	.ns_dsm = uring_submit_dsm,
	.ns_prep_read = uring_prep_read,
	.ns_handle_qe = uring_handle_qe,
};

struct ns_ops *uring_register_ops(void)
{
	return &uring_ops;
}
