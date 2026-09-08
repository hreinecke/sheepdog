/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * uring.c
 * io_uring backend for NVMe-oF userspace emulation.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <pthread.h>

#include "common.h"
#include "nvme.h"
#include "ops.h"

int vdi_submit_write(struct nofuse_queue *ep, struct ep_qe *qe)
{
	int ret;

	while (qe->iovec.iov_len) {
		unsigned int idx = pos / SD_DATA_OBJ_SIZE;
		off_t off = pos % SD_DATA_OBJ_SIZE;
		size_t len = min(qe->iovec.iov_len, SD_DATA_OBJ_SIZE - off);
		uint64_t oid = vid_to_data_oid(qe->vid, idx);
		void *data = qe->iovec.iov.base;

		ret = sd_write_object(oid, (char *)data, len, off, false);
		if (ret != SD_RES_SUCCESS) {
			ctrl_err(ep, "tag %d VDI oid %"PRIx64
				 " off %lu size %lu read error %s",
				 qe->tag, oid, off, len, sd_strerror(ret));
			return -EIO;
		}
		data += len;
		qe->iovec.iov_base = data;
		qe->iovec.iov_len -= len;
	}
	return 0;
}

int vdi_submit_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	int ret;

	while (qe->iovec.iov_len) {
		unsigned int idx = pos / SD_DATA_OBJ_SIZE;
		off_t off = pos % SD_DATA_OBJ_SIZE;
		size_t len = min(qe->iovec.iov_len, SD_DATA_OBJ_SIZE - off);
		uint64_t oid = vid_to_data_oid(qe->vid, idx);
		void *data = qe->iovec.iov.base;

		ret = sd_write_object(oid, (char *)data, len, off, false);
		if (ret != SD_RES_SUCCESS) {
			ctrl_err(ep, "tag %d VDI oid %"PRIx64
				 " off %lu size %lu read error %s",
				 qe->tag, oid, off, len, sd_strerror(ret));
			return -EIO;
		}
		data += len;
		qe->iovec.iov_base = data;
		qe->iovec.iov_len -= len;
	}
	return 0;
}

static vdi_prep_read(struct nofuse_queue *ep, struct ep_qe *qe)
{
	return ep->ops->prep_rma_read(ep, qe->tag);
}

static struct ns_ops vdi_ops = {
	.ns_read = vdi_submit_read,
	.ns_write = vdi_submit_write,
	.ns_prep_read = vdi_prep_read,
};

struct ns_ops *vdi_register_ops(void)
{
	return &vdi_ops;
}
