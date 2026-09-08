/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * vdi.c
 * synchronous VDI backend for NVMe-oF userspace emulation.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
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

		ret = sd_write_object(oid, (char *)data, len, off, false);
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

static int vdi_submit_dsm(struct nofuse_queue *ep, struct ep_qe *qe)
{
	struct nvme_dsm_range *range = qe->data;
	int nr_ranges = qe->data_len / sizeof(*range);
	int i, ret;

	if (qe->data_len % sizeof(*range)) {
		sd_warn("unaligned dsm range payload");
		nr_ranges--;
	}

	for (i = 0; i < nr_ranges; i++) {
		uint64_t slba = le64toh(range[i].slba);
		uint32_t nlb = le32toh(range[i].nlb);
		uint64_t start = slba * qe->ns->blksize;
		uint64_t idx = start / SD_DATA_OBJ_SIZE;
		uint64_t oid = vid_to_data_oid(qe->vid, idx);

		if (start % SD_DATA_OBJ_SIZE) {
			ctrl_err(ep, "dsm: invalide range %d start", i);
			return NVME_SC_ONCS_NOT_SUPPORTED;
		}
		if ((uint64_t)nlb * qe->ns->blksize != SD_DATA_OBJ_SIZE) {
			ctrl_err(ep, "dsm: invalid range %d size", i);
			return NVME_SC_ONCS_NOT_SUPPORTED;
		}

		ret = sd_remove_object(oid);
		if (ret != SD_RES_SUCCESS && ret != SD_RES_NO_OBJ) {
			ctrl_err(ep, "dsm: failed to remove object %016"PRIx64": %s",
				 oid, sd_strerror(ret));
			return NVME_SC_INTERNAL;
		}
	}
	return NVME_SC_SUCCESS;
}

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
        if (res < 0) {
                if (res != -EAGAIN)
                        return res;
                ctrl_err(ep, "tag %#x retry", qe->tag);
		switch(qe->opcode) {
		case nvme_cmd_read:
                        status = vdi_submit_read(ep, qe);
			break;
		case nvme_cmd_write:
                        status = vdi_submit_write(ep, qe);
			break;
		case nvme_cmd_dsm:
			status = vdi_submit_dsm(ep, qe);
			break;
		default:
			status = NVME_SC_INVALID_OPCODE;
			break;
		}
                if (status == NVME_SC_SUCCESS)
                        return status;
                goto out_rsp;
        }
        if (qe->opcode == nvme_cmd_read) {
		ctrl_info(ep, "tag %#x ccid %#x write %lu bytes payload",
			  qe->tag, qe->ccid, qe->data_len);
		return ep->ops->rma_write(ep, qe, qe->data_len);
	}

	if (res != qe->iovec.iov_len) {
		uint8_t *data = qe->iovec.iov_base;

		ctrl_info(ep, "tag %#x ccid %#x read %d remaining bytes",
			  qe->tag, qe->ccid, res);
		data += res;
		qe->iovec.iov_base = data;
		qe->iovec.iov_len =- res;
		status = vdi_submit_read(ep, qe);
		if (status == NVME_SC_SUCCESS)
			return status;
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
