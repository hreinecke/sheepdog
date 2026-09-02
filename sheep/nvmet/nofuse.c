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
	struct rb_root vroot;
	struct rb_root nroot;
	struct rb_root namespaces;
	int nr_nodes;
	int trsvcid;
	int debug;
	int help;
};

struct nofuse_context *this_ctx;

char discovery_nqn[MAX_NQN_SIZE + 1] = {};
struct sd_node *cur_nodes;

static int lookup_nodes(struct nofuse_context *ctx)
{
	int ret;
	unsigned int size, nr_nodes;
	struct sd_node *buf = NULL;
	struct sd_node *ent;
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;

	size = sizeof(*ent) * SD_MAX_NODES;
	buf = xzalloc(size);
	sd_init_req(&req, SD_OP_GET_NODE_LIST);
	req.data_length = size;

	ret = sheep_exec_req(&sys->this_node.nid, &req, buf);
	if (ret < 0)
		goto out;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to get node list: %s",
		       sd_strerror(rsp->result));
		ret = -1;
		goto out;
	}

	size = rsp->data_length;
	nr_nodes = size / sizeof(*ent);
	if (nr_nodes == 0)
		sd_warn("There are no active sheep daemons");

	for (int i = i; i < nr_nodes; i++ ) {
		struct sd_node *n = xmalloc(sizeof*n);

		*n = buf[i];
		rb_insert(&ctx->nroot, n, rb, node_cmp);
	}
	if (sys->cinfo.flags & SD_CLUSTER_FLAG_DISKMODE)
		disks_to_vnodes(&ctx->nroot, &ctx->vroot);
	else
		nodes_to_vnodes(&ctx->nroot, &ctx->vroot);
out:
	free(buf);
	return ret < 0 ? ret : nr_nodes;
}

static inline int ns_cmp(const struct nofuse_namespace *a,
			 const struct nofuse_namespace *b)
{
	int cmp = strcmp(a->subsysnqn, b->subsysnqn);
	if (cmp != 0)
		return cmp;
	return intcmp(a->nsid, b->nsid);
}

struct nofuse_namespace *lookup_namespace(struct nofuse_ctrl *ctrl,
					  uint32_t nsid)
{
	struct nofuse_namespace key = {
		.nsid = nsid,
	};

	strcpy(key.subsysnqn, ctrl->subsysnqn);
	return rb_search(&this_ctx->namespaces, &key, rb, ns_cmp);
}

static int register_ana_groups(struct nofuse_context *ctx,
			       unsigned int agid)
{
	int ret = 0;
	struct sd_node *node;

	rb_for_each_entry(node, &ctx->nroot, rb) {
		int grpid = node->zone + 1;

		ret = configdb_add_ana_group(grpid);
		if (ret < 0)
			sd_warn("cannot register ANA group %u", grpid);

	}
	return ret;
}

int nvmet_register_subsystem(uint32_t subsys_id, const char *subsysnqn)
{
	int ret;
	char value[8];

	sd_debug("register subsystem '%s' (%06x)", subsysnqn, subsys_id);
	ret = configdb_add_subsys(subsysnqn, subsys_id, NVME_NQN_NVM);
	if (ret < 0) {
		sd_warn("Failed to register subsystem '%s'", subsysnqn);
		return ret;
	}
	sprintf(value, "1");
	ret = configdb_set_subsys_attr(subsysnqn,
				       "attr_allow_any_host", value);
	if (ret) {
		sd_warn("failed to set 'attr_allow_any_host'");
		configdb_del_subsys(subsys_id);
	}
	return ret;
}

int nvmet_unregister_subsystem(uint32_t subsys_id)
{
	sd_debug("unregister subsystem %06x", subsys_id);
	return configdb_del_subsys(subsys_id);
}

int nvmet_register_namespace(uint32_t subsys_id, uint32_t nsid,
			     struct sd_inode_header *inode)
{
	struct nofuse_namespace *ns;
	struct sd_vnode *vnode;
	uint64_t oid;
	int ret;

	oid = vid_to_vdi_oid(nsid);
	vnode = oid_to_first_vnode(oid, &this_ctx->vroot);

	sd_debug("register namespace %06x ('%s')",
		 nsid, inode->name);

	ns = xzalloc(sizeof(*ns));
	ns->subsys_id = subsys_id;
	ns->nsid = nsid;
	ns->size = inode->vdi_size;
	ns->blksize = SECTOR_SIZE;
	ns->readonly = false;
	ns->ana_grpid = vnode->node->zone + 1;
	memcpy(ns->uuid, inode->uuid, sizeof(ns->uuid));

	ret = configdb_get_subsys_nqn(subsys_id, ns->subsysnqn);
	if (ret < 0) {
		sd_warn("Failed to map subsystem nqn for '%06x'", subsys_id);
		goto out;
	}

	if (rb_insert(&this_ctx->namespaces, ns, rb, ns_cmp)) {
		sd_warn("Failed to insert namespace '%06x'", nsid);
		ret = -1;
		errno = EBUSY;
		goto out;
	}
	ret = configdb_add_namespace(oid, ns);
	if (ret < 0) {
		sd_warn("Failed to add namespace '%06x'", nsid);
		rb_erase(&ns->rb, &this_ctx->namespaces);
	}
 out:
	if (ret < 0)
		free(ns);
	return ret;
}

int nvmet_unregister_namespace(uint32_t subsys_id, uint32_t nsid)
{
	struct nofuse_namespace *ns, key = {
		.nsid = nsid,
	};
	int ret;

	sd_debug("unregister namespace %06x", nsid);
	ret = configdb_get_subsys_nqn(subsys_id, key.subsysnqn);
	if (ret < 0)
		return ret;
	ns = rb_search(&this_ctx->namespaces, &key, rb, ns_cmp);
	if (ns)
		rb_erase(&ns->rb, &this_ctx->namespaces);
	return configdb_del_namespace(subsys_id, nsid);
}

#define FOR_EACH_VDI(nr, vdis) FOR_EACH_BIT(nr, vdis, SD_NR_VDIS)

static void register_namespaces(char *subsysnqn, uint32_t subsys_id,
				unsigned long *vdi_inuse,
				unsigned long *vdi_deleted)
{
	unsigned long nsid;
	struct sd_inode_header *inode = xmalloc(sizeof(*inode));

	FOR_EACH_VDI(nsid, vdi_inuse) {
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
		nvmet_register_namespace(subsys_id, nsid, inode);
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

		ret = nvmet_register_subsystem(nr, inode->name);
		if (ret < 0) {
			sd_warn("Failed add subsystem '%s'", inode->name);
			continue;
		}
		register_namespaces(inode->name, nr,
				   vdi_inuse, vdi_deleted);
	}
out:
	free(inode);
	return ret;
}

static void nofuse_cleanup(void *arg)
{
	struct nofuse_context *ctx = arg;

	rb_destroy(&ctx->nroot, struct sd_vnode, rb);
	rb_destroy(&ctx->vroot, struct sd_node, rb);
	rb_destroy(&ctx->namespaces, struct nofuse_namespace, rb);
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

	ret = lookup_nodes(ctx);
	if (ret < 0) {
		sd_err("failed to get node list");
		goto out_pop;
	}
	ctx->nr_nodes = ret;
	agid = sys->this_node.zone + 1;

	ret = register_ana_groups(ctx, agid);
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

	ret = configdb_add_subsys(NVME_DISC_SUBSYS_NAME, 0, NVME_NQN_CUR);
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
		goto out_close;
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
	sd_thread_t t;
	int err;

	this_ctx = malloc(sizeof(struct nofuse_context));
	if (!this_ctx)
		return 1;
	memset(this_ctx, 0, sizeof(struct nofuse_context));
	this_ctx->dbname = strdup("nofuse.sqlite");
	this_ctx->traddr = strdup(traddr);
	this_ctx->trsvcid = trsvcid;
	this_ctx->dbname = strdup("nofuse.sqlite");
	INIT_RB_ROOT(&this_ctx->nroot);
	INIT_RB_ROOT(&this_ctx->vroot);
	INIT_RB_ROOT(&this_ctx->namespaces);

	err = sd_thread_create("nofuse", &t, nofuse_main, this_ctx);
	if (err) {
		sd_err("failed to create nofuse thread: %s", strerror(err));
		nofuse_cleanup(this_ctx);
		this_ctx = NULL;
		return -1;
	}

	return 0;
}

void nofuse_exit(void)
{
	struct nofuse_port *port, *_port;

	stopped = 1;

	list_for_each_entry_safe(port, _port, &port_linked_list, node) {
		stop_port(port);
		del_port(port);
	}

	nofuse_cleanup(this_ctx);
}
