/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * nofuse.c
 * NVME-over-TCP userspace daemon
 *
 * Copyright (c) 2024 Hannes Reinecke <hare@suse.de>. All rights reserved.
 *
 * Based on nvme-dem (https://github.com/linux-nvme/nvme-dem/src/endpoint)
 * Copyright (c) 2017-2019 Intel Corporation, Inc. All rights reserved.
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <getopt.h>

#include "sheep_priv.h"
#include "nofuse.h"
#include "ops.h"
#include "tls.h"
#include "configdb.h"

int stopped;
bool tcp_debug;
bool cmd_debug;
bool ep_debug;
bool port_debug;

struct nofuse_context {
	char *traddr;
	char *dbname;
	int trsvcid;
	int debug;
	int help;
};

char discovery_nqn[MAX_NQN_SIZE + 1] = {};

int lookup_namespace(struct nofuse_ctrl *ctrl, uint32_t nsid,
		     struct nofuse_namespace *ns)
{
	struct sd_inode_header *inode;
	int ret;

	inode = xzalloc(sizeof(*inode));
	ret = sd_read_object(vid_to_vdi_oid(nsid), (char *)inode,
			     sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("fail to read vdi inode (%" PRIx32 ")", nsid);
		goto out;
	}

	if (inode->name[0] == '\0') {
		ret = SD_RES_NO_VDI;
		goto out;
	}
	if (inode->vdi_flags & SD_VDI_FLAG_ACL) {
		ret = SD_RES_NO_VDI;
		goto out;
	}
	if (ctrl->subsys_vid != inode->acl_id) {
		ret = SD_RES_VDI_DENIED;
		goto out;
	}
	if (!inode->vdi_size) {
		ret = SD_RES_INVALID_PARMS;
		goto out;
	}
	ns->size = inode->vdi_size;
	ns->blksize = SECTOR_SIZE;
	ns->readonly = oid_is_readonly(vid_to_vdi_oid(nsid));
out:
	free(inode);
	return ret;
}

static int get_local_zone(void)
{
	struct vnode_info *vinfo = get_vnode_info();
	struct sd_vnode *vnode;

	rb_for_each_entry(vnode, &vinfo->vroot, rb) {
		if (vnode_is_local(vnode)) {
			return vnode->node->zone;
		}
	}
	return -1;
}

static int register_ana_groups(unsigned int agid)
{
	struct vnode_info *vinfo = get_vnode_info();
	struct sd_vnode *vnode;
	int ret = 0;

	rb_for_each_entry(vnode, &vinfo->vroot, rb) {
		int zone = vnode->node->zone;

		ret = configdb_add_ana_group(zone);
		if (ret < 0)
			sd_warn("cannot register ANA group %u", zone);

	}
	return ret;
}

#define FOR_EACH_VDI(nr, vdis) FOR_EACH_BIT(nr, vdis, SD_NR_VDIS)

static void register_namespaces(char *subsysnqn, unsigned int subsys_id,
				unsigned int agid, unsigned long *vdi_inuse,
				unsigned long *vdi_deleted)
{
	unsigned long nsid;
	struct sd_inode_header *inode = xmalloc(sizeof(*inode));

	FOR_EACH_VDI(nsid, vdi_inuse) {
		char vdi_size[64];
		uint64_t oid;
		int ret;

		if (test_bit(nsid, vdi_deleted))
			continue;

		oid = vid_to_vdi_oid(nsid);
		ret = sd_read_object(oid, (char *)inode,
				     SD_INODE_HEADER_SIZE, 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read inode header");
			continue;
		}

		/* this VDI has been deleted, and no need to handle it */
		if (inode->name[0] == '\0')
			continue;
		/* We are only interested in VDIs */
		if (vdi_is_acl(inode))
			continue;

		sd_debug("register namespace %06lx ('%s')",
			 nsid, inode->name);
		ret = configdb_add_namespace(subsysnqn, subsys_id,
					     nsid, inode->uuid, agid);
		if (ret < 0) {
			sd_warn("Failed to add namespace '%06lx'", nsid);
			continue;
		}
		sprintf(vdi_size, "%lx", inode->vdi_size);
		ret = configdb_set_namespace_attr(subsysnqn, nsid,
					       "device_size", vdi_size);
	}
	free(inode);
}

static int register_subsystems(unsigned int agid)
{
	int ret;
	unsigned long nr;
	struct sd_inode_header *inode = xmalloc(sizeof(*inode));
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;
	static DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	static DECLARE_BITMAP(vdi_deleted, SD_NR_VDIS);

	sd_init_req(&req, SD_OP_READ_VDIS);
	req.data_length = sizeof(vdi_inuse);
	ret = sheep_exec_req(&sys->this_node.nid, &req, vdi_inuse);
	if (ret < 0)
		goto out;
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		goto out;
	}

	sd_init_req(&req, SD_OP_READ_DEL_VDIS);
	req.data_length = sizeof(vdi_deleted);

	ret = sheep_exec_req(&sys->this_node.nid, &req, vdi_deleted);
	if (ret < 0)
		goto out;
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		goto out;
	}

	FOR_EACH_VDI(nr, vdi_inuse) {
		uint64_t oid;
		char value[20];

		if (test_bit(nr, vdi_deleted))
			continue;

		oid = vid_to_vdi_oid(nr);

		ret = sd_read_object(oid, (char *)inode,
				     SD_INODE_HEADER_SIZE, 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read inode header");
			continue;
		}

		/* this VDI has been deleted, and no need to handle it */
		if (inode->name[0] == '\0')
			continue;
		/* We are only interested in ACL VDIs */
		if (!vdi_is_acl(inode))
			continue;

		sd_debug("register subsystem '%s'", inode->name);
		ret = configdb_add_subsys(inode->name, NVME_NQN_NVM);
		if (ret < 0)
			sd_warn("Failed add subsyste '%s'", inode->name);
		sprintf(value, "SHEEPDOG%06lx", nr);
		ret = configdb_set_subsys_attr(inode->name,
					       "attr_serial", value);
		sprintf(value, "1");
		ret = configdb_set_subsys_attr(inode->name,
					       "attr_allow_any", value);
		register_namespaces(inode->name, nr, agid,
				   vdi_inuse, vdi_deleted);
	}
out:
	free(inode);
	return ret;
}

static void nofuse_cleanup(void *arg)
{
	struct nofuse_context *ctx = arg;

	free(ctx->traddr);
	free(ctx->dbname);
	free(arg);
}

static void *nofuse_main(void *arg)
{
	struct nofuse_context *ctx = arg;
	int tls_keyring;
	int ret, agid;
	struct nofuse_port *port;

	pthread_detach(pthread_self());

	pthread_cleanup_push(nofuse_cleanup, arg);

	ret = configdb_open(ctx->dbname);
	if (ret < 0) {
		sd_err("Failed to open configdb");
		goto out_pop;
	}

	agid = get_local_zone();
	if (agid < 0) {
		sd_err("failed to find local node");
		goto out_close;
	}

	ret = register_ana_groups(agid);
	if (ret < 0) {
		sd_err("failed to register ANA groups for port %d", agid);
		goto out_close;
	}

	sd_debug("register nvmet port traddr '%s' trsvcid '%d'",
		 ctx->traddr, ctx->trsvcid);
	port = add_port(agid, ctx->traddr, ctx->trsvcid);
	if (!port) {
		sd_err("failed to add nvmet port");
		goto out_close;
	}

	ret = configdb_add_subsys(NVME_DISC_SUBSYS_NAME, NVME_NQN_CUR);
	if (ret < 0) {
		sd_err("failed to create default discovery subsystem");
		goto out_close;
	}

	ret = register_subsystems(agid);
	if (ret < 0) {
		sd_err("failed to register ACL VDIs");
		goto out_close;
	}

	tls_keyring = tls_global_init();
	if (tls_keyring)
		port->tls = true;

	stopped = 0;

	ret = start_port(port);
	if (ret) {
		sd_err("failed to start nvmet port");
	}

	return NULL;
out_close:
	configdb_close(ctx->dbname);
out_pop:
	pthread_cleanup_pop(1);
	return NULL;
}

int nofuse_init(const char *traddr, int trsvcid)
{
	struct nofuse_context *ctx;
	sd_thread_t t;
	int err;

	ctx = malloc(sizeof(struct nofuse_context));
	if (!ctx)
		return 1;
	memset(ctx, 0, sizeof(struct nofuse_context));
	ctx->dbname = strdup("nofuse.sqlite");
	ctx->traddr = strdup(traddr);
	ctx->trsvcid = trsvcid;
	ctx->dbname = strdup("nofuse.sqlite");

	err = sd_thread_create("nofuse", &t, nofuse_main, ctx);
	if (err) {
		sd_err("failed to create nofuse thread: %s", strerror(err));
		nofuse_cleanup(ctx);
		return -1;
	}

	return 0;
}
