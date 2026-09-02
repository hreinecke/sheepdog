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
#include <sys/eventfd.h>
#include <poll.h>
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
	struct rb_root ns_root;
	struct sd_mutex ns_lock;
	int nr_nodes;
	unsigned int portid;
	int trsvcid;
	int debug;
	int help;
	sd_thread_t thread;
	int event_evtfd;
	struct list_head event_list;
	struct sd_mutex event_lock;
};

struct nofuse_context *this_ctx;

/* Queued via nvmet_notify_acl_change(), drained by nofuse_main()'s loop. */
struct nvmet_acl_event {
	struct list_node node;
	uint32_t vid;
	uint32_t old_acl;
	uint32_t new_acl;
};

void nvmet_notify_acl_change(uint32_t vid, uint32_t old_acl, uint32_t new_acl)
{
	struct nvmet_acl_event *ev;

	if (!this_ctx)
		return;

	ev = xmalloc(sizeof(*ev));
	ev->vid = vid;
	ev->old_acl = old_acl;
	ev->new_acl = new_acl;

	sd_mutex_lock(&this_ctx->event_lock);
	list_add_tail(&ev->node, &this_ctx->event_list);
	sd_mutex_unlock(&this_ctx->event_lock);

	eventfd_write(this_ctx->event_evtfd, 1);
}

static void process_acl_event(struct nvmet_acl_event *ev)
{
	if (ev->new_acl) {
		struct sd_inode_header inode;
		int ret;

		ret = sd_read_object(vid_to_vdi_oid(ev->vid), (char *)&inode,
				     sizeof(inode), 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("failed to read inode of VDI %"PRIx32
			       " for nvmet: %s", ev->vid, sd_strerror(ret));
			return;
		}
		if (nvmet_register_namespace(ev->new_acl, ev->vid, &inode) < 0)
			sd_err("failed to register namespace %"PRIx32
			       " with nvmet", ev->vid);
	} else if (nvmet_unregister_namespace(ev->old_acl, ev->vid) < 0)
		sd_err("failed to unregister namespace %"PRIx32
		       " with nvmet", ev->vid);
}

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

	for (int i = 0; i < nr_nodes; i++) {
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

static int register_vdi(uint32_t subsys_id, uint32_t nsid, bool unregister)
{
	int ret;
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;
	char *buf;

	buf = xzalloc(256);
	sprintf(buf, "%s:%u", this_ctx->traddr, this_ctx->trsvcid);
	sd_init_req(&req, unregister ?
		    SD_OP_UNREGISTER_VDI : SD_OP_REGISTER_VDI);
	req.vdi_lock.vid = nsid;
	req.vdi_lock.acl = subsys_id;
	req.data_length = 256;
	req.flags = SD_FLAG_CMD_WRITE;

	ret = sheep_exec_req(&sys->this_node.nid, &req, buf);
	if (ret < 0) {
		free(buf);
		return ret;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to %sregister namespace '%06x': %s",
		       unregister ? "un" : "",
		       nsid, sd_strerror(rsp->result));
		ret = -1;
		errno = EIO;
	}
	free(buf);
	return ret;
}

static inline int ns_cmp(const struct nofuse_namespace *a,
			 const struct nofuse_namespace *b)
{
	int cmp = intcmp(a->subsys_id, b->subsys_id);
	if (cmp != 0)
		return cmp;
	return intcmp(a->nsid, b->nsid);
}

struct nofuse_namespace *lookup_namespace(struct nofuse_ctrl *ctrl,
					  uint32_t nsid)
{
	struct nofuse_namespace key = {
		.subsys_id = ctrl->subsys_id,
		.nsid = nsid,
	};

	return rb_search(&this_ctx->ns_root, &key, rb, ns_cmp);
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
	int ret, nr_zones;
	char value[8];

	sd_debug("register subsystem '%s' (%06x)", subsysnqn, subsys_id);
	ret = configdb_add_subsys(subsysnqn, subsys_id, NVME_NQN_NVM);
	if (ret < 0) {
		sd_warn("Failed to register subsystem '%s'", subsysnqn);
		return ret;
	}
	nr_zones = get_zones_nr_from(&this_ctx->nroot);
	if (nr_zones > 0) {
		int cntlid_range, cntlid_min, cntlid_max;

		cntlid_range = 65520 / nr_zones;
		cntlid_min = (sys->this_node.zone * cntlid_range) + 1;
		cntlid_max = cntlid_min + cntlid_range - 1;
		if (cntlid_max >= 65520)
			cntlid_max = 65519;
		sd_debug("restricting cntlid for subsystem '%s' to %u-%u",
			 subsysnqn, cntlid_min, cntlid_max);
		sprintf(value, "%u", cntlid_min);
		ret = configdb_set_subsys_attr(subsys_id,
					       "cntlid_min", value);
		if (ret < 0) {
			sd_warn("Failed to set 'cntlid_min'");
			return ret;
		}
		sprintf(value, "%u", cntlid_max);
		ret = configdb_set_subsys_attr(subsys_id,
					       "cntlid_max", value);
		if (ret < 0) {
			sd_warn("Failed to set 'cntlid_max'");
			return ret;
		}
	}

	sprintf(value, "1");
	ret = configdb_set_subsys_attr(subsys_id,
				       "allow_any_host", value);
	if (ret) {
		sd_warn("failed to set 'allow_any_host'");
		configdb_del_subsys(subsys_id);
		return ret;
	}
	/*
	 * Without this, the subsystem is never joined to the local
	 * port in 'subsys_port', so it can never show up in the
	 * discovery log page (configdb_host_disc_entries() joins
	 * through subsys_port).
	 */
	ret = configdb_add_subsys_port(subsys_id, this_ctx->portid);
	if (ret < 0)
		sd_warn("Failed to add port %u for subsystem '%s'",
			this_ctx->portid, subsysnqn);
	return ret;
}

int nvmet_unregister_subsystem(uint32_t subsys_id)
{
	int ret;

	sd_debug("unregister subsystem %06x", subsys_id);
	/* subsys_port.subsys_id is ON DELETE RESTRICT */
	ret = configdb_del_subsys_port(subsys_id, this_ctx->portid);
	if (ret < 0)
		sd_warn("Failed to remove port %u for subsystem '%06x'",
			this_ctx->portid, subsys_id);
	return configdb_del_subsys(subsys_id);
}

int nvmet_register_namespace(uint32_t subsys_id, uint32_t nsid,
			     struct sd_inode_header *inode)
{
	struct nofuse_namespace *ns, *new = NULL;
	struct sd_vnode *vnode;
	bool do_register = false;
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
	ns->enabled = true;
	ns->ana_grpid = vnode->node->zone + 1;
	memcpy(ns->uuid, inode->uuid, sizeof(ns->uuid));

	sd_mutex_lock(&this_ctx->ns_lock);
	new = rb_insert(&this_ctx->ns_root, ns, rb, ns_cmp);
	if (new) {
		if (memcmp(new->uuid, ns->uuid, sizeof(ns->uuid))) {
			/* Namespace has changed */
			sd_warn("Namespace '%06x' has changed", nsid);
			ret = -1;
			errno = EBUSY;
		} else {
			/* Can happen during start up */
			sd_debug("Namespace '%06x' already present", nsid);
			free(ns);
		}
		ret = 0;
	} else {
		ret = configdb_add_namespace(oid, ns);
		if (ret < 0) {
			sd_warn("Failed to add namespace '%06x'", nsid);
			rb_erase(&ns->rb, &this_ctx->ns_root);
		} else
			do_register = true;
	}
	sd_mutex_unlock(&this_ctx->ns_lock);

	if (ret < 0)
		free(ns);
	else if (do_register)
		ret = register_vdi(subsys_id, nsid, false);
	return ret;
}

int nvmet_unregister_namespace(uint32_t subsys_id, uint32_t nsid)
{
	struct nofuse_namespace *ns, key = {
		.subsys_id = subsys_id,
		.nsid = nsid,
	};
	int ret;

	sd_debug("unregister namespace %06x", nsid);
	ret = register_vdi(subsys_id, nsid, true);
	sd_mutex_lock(&this_ctx->ns_lock);
	ret = configdb_del_namespace(subsys_id, nsid);
	if (ret < 0) {
		sd_warn("Failed to delete namespace '%06x'", nsid);
	} else {
		ns = rb_search(&this_ctx->ns_root, &key, rb, ns_cmp);
		if (ns)
			rb_erase(&ns->rb, &this_ctx->ns_root);
		else {
			ret = -1;
			errno = -ENOENT;
		}
	}
	sd_mutex_unlock(&this_ctx->ns_lock);
	return ret;
}

#define FOR_EACH_VDI(nr, vdis) FOR_EACH_BIT(nr, vdis, SD_NR_VDIS)

static void register_ns_root(char *subsysnqn, uint32_t subsys_id,
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
		/* We are only interested in VDIs which belong to this ACL */
		if (vdi_is_acl(inode) || inode->acl_id != subsys_id)
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
		register_ns_root(inode->name, nr,
				   vdi_inuse, vdi_deleted);
	}
out:
	free(inode);
	return ret;
}

static void nofuse_cleanup(void *arg)
{
	struct nofuse_context *ctx = arg;
	struct nvmet_acl_event *ev, *next;

	list_for_each_entry_safe(ev, next, &ctx->event_list, node) {
		list_del(&ev->node);
		free(ev);
	}
	if (ctx->event_evtfd >= 0)
		close(ctx->event_evtfd);
	sd_destroy_mutex(&ctx->event_lock);

	rb_destroy(&ctx->nroot, struct sd_vnode, rb);
	rb_destroy(&ctx->vroot, struct sd_node, rb);
	rb_destroy(&ctx->ns_root, struct nofuse_namespace, rb);
	free(ctx->traddr);
	free(ctx->dbname);
	free(arg);
}

static void *nofuse_main(void *arg)
{
	struct nofuse_context *ctx = arg;
	int tls_keyring;
	int ret, agid;
	struct nofuse_port *port = NULL;

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
	ctx->portid = agid;

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

	/*
	 * Stay alive to process ACL-change events queued by
	 * nvmet_notify_acl_change() (called from the main thread of
	 * every node via cluster_alter_vdi_acl_main()); that thread
	 * cannot do this work itself since it involves blocking
	 * cluster round-trips (sd_read_object()).
	 */
	while (!stopped) {
		struct pollfd pfd = { .fd = ctx->event_evtfd, .events = POLLIN };
		struct nvmet_acl_event *ev, *next;
		LIST_HEAD(pending);
		eventfd_t val;

		ret = poll(&pfd, 1, 1000);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			sd_err("nofuse event poll failed: %m");
			break;
		}
		if (ret == 0)
			continue;

		eventfd_read(ctx->event_evtfd, &val);

		sd_mutex_lock(&ctx->event_lock);
		list_splice_init(&ctx->event_list, &pending);
		sd_mutex_unlock(&ctx->event_lock);

		list_for_each_entry_safe(ev, next, &pending, node) {
			list_del(&ev->node);
			process_acl_event(ev);
			free(ev);
		}
	}

out_close:
	/*
	 * Port and configdb teardown both happen here, in this thread
	 * (reached both by falling out of the loop above and by the
	 * earlier 'goto out_close' error paths), so that nofuse_exit()
	 * (running on the main sheep thread) never touches configdb
	 * concurrently with this thread's own configdb_close() below.
	 */
	if (port) {
		stop_port(port);
		del_port(port);
	}
	configdb_close(ctx->dbname);
out_pop:
	pthread_cleanup_pop(1);
	return NULL;
}

int nofuse_init(const char *traddr, int trsvcid)
{
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
	INIT_RB_ROOT(&this_ctx->ns_root);
	sd_init_mutex(&this_ctx->ns_lock);
	INIT_LIST_HEAD(&this_ctx->event_list);
	sd_init_mutex(&this_ctx->event_lock);
	this_ctx->event_evtfd = eventfd(0, EFD_NONBLOCK);
	if (this_ctx->event_evtfd < 0) {
		sd_err("failed to create nofuse event eventfd: %m");
		nofuse_cleanup(this_ctx);
		this_ctx = NULL;
		return -1;
	}

	err = sd_thread_create("nofuse", &this_ctx->thread, nofuse_main,
			       this_ctx);
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
	stopped = 1;

	/*
	 * nofuse_main() tears down the port and configdb itself, in its
	 * own thread, once it notices 'stopped'; doing that here instead
	 * would race with it accessing the same configdb connection.
	 * Just signal and wait for that, then it frees this_ctx via its
	 * own pthread_cleanup_pop().
	 */
	if (!this_ctx)
		return;

	eventfd_write(this_ctx->event_evtfd, 1);
	sd_thread_join(this_ctx->thread, NULL);
}
