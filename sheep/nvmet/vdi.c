/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * vdi.c
 * synchronous VDI backend for NVMe-oF userspace emulation.
 *
 * Copyright (c) 2026 Hannes Reinecke <hare@suse.de>
 */

#include <stdio.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <pthread.h>

#include "sheep_priv.h"
#include "nofuse.h"
#include "nvme.h"
#include "ops.h"

/*
 * A write to this VDI's inode or data objects can come back with
 * SD_RES_INODE_INVALIDATED: another node sharing this VDI (nofuse
 * exposes the same VDI through every sheep node for NVMe multipath)
 * created a data object of its own and invalidated our cached inode
 * via the cluster-wide coherence protocol (sheep/vdi.c,
 * invalidate_other_nodes()/is_refresh_required()). The protocol
 * requires re-reading the whole inode (a "refresh read": the VDI
 * object, offset 0, length exactly covering the full data_vdi_id[]
 * array -- see is_inode_refresh_req() in sheep/gateway.c) before
 * retrying; that read both clears our invalidated state
 * (validate_myself()) and gives us the current data_vdi_id[] map.
 * See sheep/nvmet/uring.c's async equivalent of this dance.
 */
static int vdi_refresh_inode(struct nofuse_namespace *ns)
{
	size_t refresh_len = data_vid_offset(SD_INODE_DATA_INDEX);
	char *buf = xmalloc(refresh_len);
	int ret;

	/*
	 * No SD_FLAG_CMD_TGT: this read must go through even while we're
	 * marked invalidated (that's the whole point), and
	 * is_inode_refresh_req() doesn't require the flag to run
	 * validate_myself() on success.
	 */
	ret = sd_read_object(vid_to_vdi_oid(ns->nsid), buf, refresh_len, 0);
	if (ret == SD_RES_SUCCESS) {
		sd_mutex_lock(&ns->inode_lock);
		memcpy(ns->inode, buf, refresh_len);
		sd_mutex_unlock(&ns->inode_lock);
	}
	free(buf);
	return ret;
}

/*
 * How many times to chase a live SD_RES_INODE_INVALIDATED before giving
 * up: under concurrent multipath writes to the same VDI, every refresh
 * can race a fresh invalidation from another node, and each attempt costs
 * a full cluster coherence round-trip, so retrying forever can stall the
 * daemon under contention instead of making progress.
 */
#define INODE_INVALIDATED_MAX_RETRY 5

static int vdi_submit_write(struct nofuse_queue *ep, struct ep_qe *qe)
{
	int ret;
	uint8_t *data = qe->data;
	size_t data_len = qe->data_len;
	off_t pos = qe->data_pos;

	while (data_len) {
		uint64_t idx = pos / SD_DATA_OBJ_SIZE;
		off_t off = pos % SD_DATA_OBJ_SIZE;
		size_t len = min(data_len, SD_DATA_OBJ_SIZE - off);
		uint64_t oid, old_oid;
		uint32_t inode_vid, data_vid;
		bool create, is_writeable;
		int retry;

		for (retry = 0; ; retry++) {
			old_oid = 0;
			create = false;

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
			oid = vid_to_data_oid(qe->ns->nsid, idx);
			ret = sd_write_object_tgt(oid, old_oid, (char *)data,
						  len, off, create);
			if (ret != SD_RES_INODE_INVALIDATED)
				break;
			if (retry >= INODE_INVALIDATED_MAX_RETRY)
				break;
			ctrl_info(ep, "tag %d VDI %"PRIx32" idx %"PRIx64
				  " inode invalidated",
				  qe->tag, qe->ns->nsid, idx);
			ret = vdi_refresh_inode(qe->ns);
			if (ret != SD_RES_SUCCESS)
				break;
		}
		if (ret != SD_RES_SUCCESS) {
			ctrl_err(ep, "tag %d VDI oid %"PRIx64
				 " off %lu size %lu write error %s",
				 qe->tag, oid, off, len, sd_strerror(ret));
			return ret == SD_RES_INODE_INVALIDATED ?
				NVME_SC_CMD_INTERRUPTED : NVME_SC_INTERNAL;
		}
		if (create) {
			sd_mutex_lock(&qe->ns->inode_lock);
			sd_inode_set_vid(qe->ns->inode, idx, inode_vid);
			sd_mutex_unlock(&qe->ns->inode_lock);
			for (retry = 0; ; retry++) {
				ret = sd_inode_write_vid(qe->ns->inode, idx,
							 qe->ns->nsid,
							 qe->ns->nsid,
							 SD_FLAG_CMD_TGT,
							 false, false);
				if (ret != SD_RES_INODE_INVALIDATED)
					break;
				if (retry >= INODE_INVALIDATED_MAX_RETRY)
					break;
				ctrl_info(ep, "tag %d VDI %"PRIx32
					  " idx %"PRIx64" inode invalidated",
					  qe->tag, qe->ns->nsid, idx);
				ret = vdi_refresh_inode(qe->ns);
				if (ret != SD_RES_SUCCESS)
					break;
			}
			if (ret != SD_RES_SUCCESS) {
				sd_mutex_lock(&qe->ns->inode_lock);
				sd_inode_set_vid(qe->ns->inode, idx, 0);
				sd_mutex_unlock(&qe->ns->inode_lock);
				ctrl_err(ep, "tag %d VDI %"PRIx32
					 " idx %"PRIx64" failed to update inode: %s",
					 qe->tag, qe->ns->nsid, idx,
					 sd_strerror(ret));
				return ret == SD_RES_INODE_INVALIDATED ?
					NVME_SC_CMD_INTERRUPTED :
					NVME_SC_INTERNAL;
			}
		}

		data += len;
		pos += len;
		data_len -= len;
	}
	return NVME_SC_SUCCESS;
}

static int vdi_submit_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	uint8_t *data = qe->data;
	size_t data_len = qe->data_len;
	off_t pos = qe->data_pos;
	int ret;

	while (data_len) {
		unsigned int idx = pos / SD_DATA_OBJ_SIZE;
		off_t off = pos % SD_DATA_OBJ_SIZE;
		size_t len = min(data_len, SD_DATA_OBJ_SIZE - off);
		uint64_t oid = vid_to_data_oid(qe->ns->nsid, idx);
		uint32_t data_vid;

		sd_mutex_lock(&qe->ns->inode_lock);
		data_vid = sd_inode_get_vid(qe->ns->inode, idx);
		sd_mutex_unlock(&qe->ns->inode_lock);
		if (data_vid) {
			oid = vid_to_data_oid(data_vid, idx);
			ret = sd_read_object(oid, (char *)data, len, off);
		} else {
			memset(data, 0, len);
			ret = SD_RES_SUCCESS;
		}
		if (ret != SD_RES_SUCCESS) {
			ctrl_err(ep, "tag %d VDI oid %"PRIx64
				 " off %lu size %lu read error %s",
				 qe->tag, oid, off, len, sd_strerror(ret));
			return NVME_SC_INTERNAL;
		}
		data += len;
		pos += len;
		data_len -= len;
	}
	return NVME_SC_SUCCESS;
}

static int vdi_prep_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	return ep->ops->prep_rma_read(ep, qe->tag);
}

/*
 * A range only ever gets discarded if it covers one or more whole
 * sheepdog data objects -- sheepdog has no way to punch a hole inside
 * an object, and a VDI already reads unwritten objects as zero
 * (vdi_submit_read()), so removing a fully-covered object is exactly
 * equivalent to (and cheaper than) actually writing zeroes over it. Any
 * partial object at either end of a range is left untouched: discard is
 * advisory, so silently keeping that data is always a valid response --
 * rejecting the whole command outright (as opposed to just not acting
 * on the part we can't) is not, and reliably produces I/O errors on the
 * host for the routine case of a range that doesn't happen to fall
 * exactly on an object boundary.
 */
static int vdi_submit_dsm(struct nofuse_queue *ep, struct ep_qe *qe)
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
		uint32_t nr_idx = idx_end - idx;
		off_t inode_off;

		if (!nr_idx)
			continue;

		/* Clean the entire range in the inode */
		sd_mutex_lock(&qe->ns->inode_lock);
		for (;idx < idx_end; idx++) {
			uint32_t data_vid =
				sd_inode_get_vid(qe->ns->inode, idx);
			if (data_vid)
				break;
		}
		if (idx < idx_end) {
			sd_mutex_unlock(&qe->ns->inode_lock);
			continue;
		}
		ret = sd_inode_set_vid_range(qe->ns->inode, idx, idx_end, 0);
		if (ret == SD_RES_SUCCESS) {
			inode_off = offsetof(struct sd_inode, data_vdi_id[idx]);
			ret = sd_write_object(vid_to_vdi_oid(qe->ns->nsid),
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
			uint64_t oid = vid_to_data_oid(qe->ns->nsid, idx);

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
 * res == -EINPROGRESS means "not started yet, run it now" (handle_read()/
 * handle_write()/handle_dsm() in nvmeof.c and tcp_handle_h2c_data() in
 * tcp.c use this to kick off the actual I/O once a command's data --
 * inline, or received via H2CData -- is ready). Any other value is a
 * real completion result from elsewhere. Either way, on success this
 * function is the one place responsible for actually telling the host:
 * rma_write() for a read's data, or a response PDU for a write/dsm.
 */
static int vdi_handle_qe(struct nofuse_queue *ep, struct ep_qe *qe, int res)
{
	int status = 0, ret;

        ctrl_info(ep, "tag %#x ccid %#x handle qe res %d",
                  qe->tag, qe->ccid, res);
        if (qe->opcode != nvme_cmd_write &&
            qe->opcode != nvme_cmd_read &&
	    qe->opcode != nvme_cmd_dsm) {
                ctrl_err(ep, "tag %#x unhandled opcode %d",
                         qe->tag, qe->opcode);
                status = NVME_SC_INVALID_OPCODE;
                goto out_rsp;
        }
	if (res == -EINPROGRESS) {
		ctrl_info(ep, "tag %#x retry", qe->tag);
		switch (qe->opcode) {
		case nvme_cmd_read:
                        status = vdi_submit_read(ep, qe);
			break;
		case nvme_cmd_write:
                        status = vdi_submit_write(ep, qe);
			break;
		case nvme_cmd_dsm:
			status = vdi_submit_dsm(ep, qe);
			break;
		}
                if (status != NVME_SC_SUCCESS)
                        goto out_rsp;
	} else if (res < 0) {
		return res;
	}
        if (qe->opcode == nvme_cmd_read) {
		ctrl_info(ep, "tag %#x ccid %#x write %lu bytes payload",
			  qe->tag, qe->ccid, qe->data_len);
		return ep->ops->rma_write(ep, qe, qe->data, qe->data_addr,
					  qe->data_len, qe->data_key,
					  qe->data_mr);
	}
out_rsp:
        memset(&qe->resp, 0, sizeof(qe->resp));
        set_response(&qe->resp, qe->ccid, status, true);
        ret = ep->ops->send_rsp(ep, qe, &qe->resp);
        return ret;
}

static struct ns_ops vdi_ops = {
	.ns_read = vdi_submit_read,
	.ns_write = vdi_submit_write,
	.ns_prep_read = vdi_prep_read,
	.ns_dsm = vdi_submit_dsm,
	.ns_handle_qe = vdi_handle_qe,
};

struct ns_ops *vdi_register_ops(void)
{
	return &vdi_ops;
}
