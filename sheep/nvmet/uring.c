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
 * Copyright (c) 2026 Hannes Reinecke <hare@suse.de>
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
	int ret = 0;

	if (result != SD_RES_SUCCESS) {
		ctrl_err(qe->ep, "tag %d VDI oid %"PRIx64
			 " off %lu size %lu I/O error %s",
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

static void uring_write_object_complete(struct request *req)
{
	struct ep_qe *qe = req->local_done_arg;

	if (req->rq.opcode == SD_OP_CREATE_AND_WRITE_OBJ) {
		uint64_t idx = data_oid_to_idx(req->rq.obj.oid);
		uint32_t inode_vid;
		int ret;

		sd_mutex_lock(&qe->ns->inode_lock);
		inode_vid = qe->ns->inode->header.vdi_id;
		sd_inode_set_vid(qe->ns->inode, idx, inode_vid);
		ret = sd_inode_write_vid(qe->ns->inode, idx,
					 inode_vid, inode_vid,
					 SD_FLAG_CMD_TGT,
					 false, false);
		if (ret != SD_RES_SUCCESS) {
			sd_inode_set_vid(qe->ns->inode, idx, 0);
			req->rp.result = ret;
		}
		sd_mutex_unlock(&qe->ns->inode_lock);
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
		return NVME_SC_SUCCESS;
	}

	refcount_set(&qe->async_pending,
		     (pos + data_len - 1) / SD_DATA_OBJ_SIZE -
		     pos / SD_DATA_OBJ_SIZE + 1);

	qe->async_result = SD_RES_SUCCESS;
	while (data_len) {
		uint64_t idx = pos / SD_DATA_OBJ_SIZE;
		off_t off = pos % SD_DATA_OBJ_SIZE;
		size_t len = min(data_len, SD_DATA_OBJ_SIZE - off);
		uint64_t oid, old_oid = 0;
		uint32_t inode_vid, data_vid;
		bool create = false;
		bool is_writeable;

		sd_mutex_lock(&qe->ns->inode_lock);
		inode_vid = qe->ns->inode->header.vdi_id;
		data_vid = sd_inode_get_vid(qe->ns->inode, idx);
		is_writeable = (inode_vid == data_vid);
		sd_mutex_unlock(&qe->ns->inode_lock);
		if (!data_vid)
			create = true;
		else if (!is_writeable) {
			create = true;
			old_oid = vid_to_data_oid(data_vid, idx);
		}
		oid = vid_to_data_oid(inode_vid, idx);
		sd_write_object_async(oid, old_oid, (char *)data, len,
				      off, create,
				      uring_write_object_complete, qe);
		data += len;
		pos += len;
		data_len -= len;
	}
	return -EAGAIN;
}

static int uring_submit_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	uint8_t *data = qe->data;
	size_t data_len = qe->data_len;
	off_t pos = qe->data_pos;
	int ret = NVME_SC_SUCCESS;

	if (!data_len) {
		uring_complete(ep, qe, 0);
		return ret;
	}

	refcount_set(&qe->async_pending,
		     (pos + data_len - 1) / SD_DATA_OBJ_SIZE -
		     pos / SD_DATA_OBJ_SIZE + 1);
	qe->async_result = SD_RES_SUCCESS;

	while (data_len) {
		uint32_t idx = pos / SD_DATA_OBJ_SIZE;
		off_t off = pos % SD_DATA_OBJ_SIZE;
		size_t len = min(data_len, SD_DATA_OBJ_SIZE - off);
		uint64_t oid;
		uint32_t data_vid;

		sd_mutex_lock(&qe->ns->inode_lock);
		data_vid = sd_inode_get_vid(qe->ns->inode, idx);
		sd_mutex_unlock(&qe->ns->inode_lock);
		if (data_vid) {
			oid = vid_to_data_oid(data_vid, idx);
			sd_read_object_async(oid, (char *)data, len,
					     off, uring_io_done, qe);
			ret = -EAGAIN;
		} else {
			/* Todo: re-check inode */
			memset(data, 0, len);
		}
		data += len;
		pos += len;
		data_len -= len;
	}
	return ret;
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
		size_t start = slba * qe->ns->blksize;
		size_t end = start + (uint64_t)nlb * qe->ns->blksize;
		uint32_t idx = round_up(start, SD_DATA_OBJ_SIZE) / SD_DATA_OBJ_SIZE;
		uint32_t idx_end = round_down(end, SD_DATA_OBJ_SIZE) / SD_DATA_OBJ_SIZE;
		int nr_idx = idx_end - idx;
		off_t inode_off;

		if (!nr_idx)
			continue;
		ret = sd_inode_set_vid_range(qe->ns->inode, idx, idx_end, 0);
		if (ret == SD_RES_SUCCESS) {
			inode_off = offsetof(struct sd_inode, data_vdi_id[idx]);
			ret = sd_write_object(vid_to_vdi_oid(qe->vid),
					      (char *)qe->ns->inode + inode_off,
					      nr_idx * sizeof(uint32_t),
					      inode_off, false);
		}
		sd_mutex_unlock(&qe->ns->inode_lock);
		if (ret != SD_RES_SUCCESS) {
			ctrl_err(ep, "dsm: failed to write inode for "
				 "discarding idx %"PRIu32"-%"PRIu32": %s",
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
		ret = sd_inode_set_vid_range(qe->ns->inode, idx, idx_end, 0);
		if (ret == SD_RES_SUCCESS) {
			inode_off = offsetof(struct sd_inode, data_vdi_id[idx]);
			ret = sd_write_object(vid_to_vdi_oid(qe->vid),
					      (char *)qe->ns->inode + inode_off,
					      nr_idx * sizeof(uint32_t),
					      inode_off, false);
		}
		sd_mutex_unlock(&qe->ns->inode_lock);
		if (ret != SD_RES_SUCCESS) {
			ctrl_err(ep, "dsm: failed to write inode for "
				 "discarding idx %"PRIu32"-%"PRIu32": %s",
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
	int pending = refcount_read(&qe->async_pending);

	ctrl_info(ep, "tag %#x ccid %#x handle qe res %d pending %u res %d",
		  qe->tag, qe->ccid, res, pending, qe->async_result);

	if (!pending) {
		if (qe->async_result != SD_RES_SUCCESS)
			status = NVME_SC_INTERNAL;
		goto out_rsp;
	}

	if (res == -EAGAIN) {
		switch (qe->opcode) {
		case nvme_cmd_read:
			return uring_submit_read(ep, qe);
		case nvme_cmd_write:
			return uring_submit_write(ep, qe);
		case nvme_cmd_dsm:
			status = uring_submit_dsm(ep, qe);
			goto out_rsp;
		default:
			status = NVME_SC_INVALID_OPCODE;
			goto out_rsp;
		}
	}

	if (res < 0) {
		ctrl_err(ep, "tag %#x vdi %s failed, error %d", qe->tag,
			 qe->opcode == nvme_cmd_write ? "write" : "read", res);
		status = NVME_SC_INTERNAL;
	} else if (qe->opcode == nvme_cmd_read) {
		/* rma_write() sends the data and releases the tag itself. */
		return ep->ops->rma_write(ep, qe, qe->data_len);
	}

out_rsp:
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
