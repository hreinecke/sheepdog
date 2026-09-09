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

static int vdi_submit_write(struct nofuse_queue *ep, struct ep_qe *qe)
{
	int ret;
	uint8_t *data = qe->data;
	size_t data_len = qe->data_len;
	off_t pos = qe->data_pos;

	while (data_len) {
		unsigned int idx = pos / SD_DATA_OBJ_SIZE;
		off_t off = pos % SD_DATA_OBJ_SIZE;
		size_t len = min(data_len, SD_DATA_OBJ_SIZE - off);
		uint64_t oid = vid_to_data_oid(qe->vid, idx);
		bool create = false;

		ret = sd_write_object(oid, (char *)data, len, off, false);
		if (ret == SD_RES_NO_OBJ) {
			create = true;
			ret = sd_write_object(oid, (char *)data, len, off, true);
		}
		if (ret != SD_RES_SUCCESS) {
			ctrl_err(ep, "tag %d VDI oid %"PRIx64
				 " off %lu size %lu write error %s",
				 qe->tag, oid, off, len, sd_strerror(ret));
			return NVME_SC_INTERNAL;
		}

		/*
		 * A freshly created data object is invisible to anything
		 * that resolves objects through the inode's index (dog vdi
		 * read/list/tree, and our own vdi_submit_read() after a
		 * restart) until that index entry is persisted -- exactly
		 * as dog/vdi.c:vdi_write() does via sd_inode_write_vid()
		 * right after dog_write_object() creates the object.
		 *
		 * The inode header only carries persistent, immutable
		 * per-VDI metadata (nr_copies/copy_policy/store_policy) --
		 * never the vid mapping table itself, which is written
		 * directly above and never read back -- so the copy taken
		 * at registration time (nvmet_register_namespace()) is all
		 * that's needed here; no need to read it off the wire again
		 * on every write.
		 */
		if (create) {
			if (sd_store_policy_is_hyper(&qe->ns->inode_hdr)) {
				ctrl_err(ep, "tag %d VDI %"PRIx32
					 " hyper store policy not supported",
					 qe->tag, qe->vid);
				return NVME_SC_INTERNAL;
			}
			ret = sd_inode_write_vid(
				(struct sd_inode *)&qe->ns->inode_hdr, idx,
				qe->vid, qe->vid, 0, false, false);
			if (ret != SD_RES_SUCCESS) {
				ctrl_err(ep, "tag %d VDI %"PRIx32
					 " idx %u failed to update inode: %s",
					 qe->tag, qe->vid, idx,
					 sd_strerror(ret));
				return NVME_SC_INTERNAL;
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
		uint64_t oid = vid_to_data_oid(qe->vid, idx);

		ret = sd_read_object(oid, (char *)data, len, off);
		if (ret == SD_RES_NO_OBJ) {
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
		uint64_t start = slba * qe->ns->blksize;
		uint64_t end = start + (uint64_t)nlb * qe->ns->blksize;
		uint64_t idx = round_up(start, SD_DATA_OBJ_SIZE) / SD_DATA_OBJ_SIZE;
		uint64_t idx_end = round_down(end, SD_DATA_OBJ_SIZE) / SD_DATA_OBJ_SIZE;
		uint64_t nr_idx = idx_end - idx;
		uint32_t *zero;

		if (!nr_idx)
			continue;

		if (sd_store_policy_is_hyper(&qe->ns->inode_hdr)) {
			ctrl_err(ep, "dsm: VDI %"PRIx32
				 " hyper store policy not supported",
				 qe->vid);
			return NVME_SC_INTERNAL;
		}

		/*
		 * Clear the inode's index entries for the whole span before
		 * removing the objects they point to -- the same batched
		 * zero-fill dog/vdi.c:vdi_reclaim() uses. A crash between
		 * the two leaves at worst an unread orphan object; doing it
		 * in the other order would leave the index still claiming
		 * an object exists after it's gone, breaking every future
		 * read of that idx (dog vdi read/list/tree included).
		 */
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
 * res == -EAGAIN means "not started yet, run it now" (handle_read()/
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
	if (res == -EAGAIN) {
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
		return ep->ops->rma_write(ep, qe, qe->data_len);
	}
out_rsp:
        memset(&qe->resp, 0, sizeof(qe->resp));
        set_response(&qe->resp, qe->ccid, status, true);
        ret = ep->ops->send_rsp(ep, &qe->resp);
        ep->ops->release_tag(ep, qe);
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
