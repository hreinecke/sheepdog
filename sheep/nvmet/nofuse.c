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
bool port_debug;

struct nofuse_context {
	char *traddr;
	char *dbname;
	uint32_t subsys_id;
	struct rb_root vroot;
	struct rb_root nroot;
	struct sd_mutex root_lock;
	struct rb_root ns_root;
	struct sd_mutex ns_lock;
	struct rb_root subsys_root;
	struct sd_mutex subsys_lock;
	int nr_nodes;
	int nr_zones;
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

enum nofuse_event_type {
	NOFUSE_EVENT_ACL_CHANGE,
	NOFUSE_EVENT_NODE_CHANGE,
	NOFUSE_EVENT_LOCK_CHANGE,
};

/* Queued via nvmet_notify_acl_change(), drained by nofuse_main()'s loop. */
struct nofuse_event {
	struct list_node node;
	enum nofuse_event_type type;
	uint32_t vid;
	uint32_t old_acl;
	uint32_t new_acl;
};

static int lookup_nodes(struct nofuse_context *ctx)
{
	int ret;
	unsigned int size, nr_nodes = 0;
	struct rb_root nodes;
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
	if (size / sizeof(*ent) == 0)
		sd_warn("There are no active sheep daemons");

	sd_mutex_lock(&ctx->root_lock);
	INIT_RB_ROOT(&nodes);
	nodes.rb_node = ctx->nroot.rb_node;
	INIT_RB_ROOT(&ctx->nroot);
	for (int i = 0; i < size / sizeof(*ent); i++) {
		struct sd_node *n = xmalloc(sizeof*n), *o;

		*n = buf[i];
		o = rb_search(&nodes, n, rb, node_cmp);
		if (o) {
			rb_erase(&o->rb, &nodes);
			free(n);
			n = o;
		} else {
			ret = configdb_add_ana_group(n->zone + 1);
			if (ret < 0) {
				sd_warn("Cannot add ANA group '%d'",
					n->zone + 1);
				free(n);
				continue;
			}
		}
		rb_insert(&ctx->nroot, n, rb, node_cmp);
		nr_nodes++;
	}
	rb_destroy(&nodes, struct sd_vnode, rb);
	rb_destroy(&ctx->vroot, struct sd_vnode, rb);
	if (sys->cinfo.flags & SD_CLUSTER_FLAG_DISKMODE)
		disks_to_vnodes(&ctx->nroot, &ctx->vroot);
	else
		nodes_to_vnodes(&ctx->nroot, &ctx->vroot);
	ctx->nr_nodes = nr_nodes;
	sd_mutex_unlock(&ctx->root_lock);
out:
	free(buf);
	return ret < 0 ? ret : nr_nodes;
}

static int register_vdi(struct nofuse_namespace *ns, bool unregister)
{
	int ret;
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;
	char *buf;

	sd_debug("%sregister VDI %"PRIx32, unregister ? "un" : "",
		 ns->nsid);
	buf = xzalloc(256);
	sprintf(buf, "%s:%u", this_ctx->traddr, this_ctx->trsvcid);
	sd_init_req(&req, unregister ?
		    SD_OP_UNREGISTER_VDI : SD_OP_REGISTER_VDI);
	req.vdi_lock.vid = ns->nsid;
	req.vdi_lock.acl = ns->subsys_id;
	req.data_length = 256;
	req.flags = SD_FLAG_CMD_WRITE;

	ret = sheep_exec_req(&sys->this_node.nid, &req, buf);
	if (ret < 0) {
		sd_warn("Failed to exec %s, error %d",
			unregister ?
			"SD_OP_UNREGISTER_VDI" : "SD_OP_REGISTER_VDI", -ret);
		free(buf);
		return ret;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to %sregister namespace '%06x': %s",
		       unregister ? "un" : "",
		       ns->nsid, sd_strerror(rsp->result));
		ret = -1;
		errno = EIO;
	} else {
		if (unregister)
			ns->subsys->mnan--;
		else
			ns->subsys->mnan++;
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
		.subsys_id = ctrl->subsys->id,
		.nsid = nsid,
	};

	return rb_search(&this_ctx->ns_root, &key, rb, ns_cmp);
}

/*
 * Fill in the ANA group descriptors for 'subsys_id' as seen from 'portid',
 * walking the live namespace list instead of querying configdb. A port
 * always reports itself as optimized for the ANA group matching its own
 * portid (ports and ANA groups share the same id space, see
 * lookup_nodes()/register_ana_groups()) and non-optimized for every other
 * group a namespace happens to be in; chgcnt tracking isn't wired up on
 * either the configdb or in-memory path, so it stays 0 here as it always
 * has.
 */
int ana_log_entries(uint32_t subsys_id, unsigned int portid,
		    uint8_t *log, int log_len)
{
	struct nvme_ana_rsp_hdr *hdr = (struct nvme_ana_rsp_hdr *)log;
	uint8_t *grp_ptr = (uint8_t *)hdr->entries;
	struct nofuse_namespace *ns;
	int ngrps = 0;

	sd_mutex_lock(&this_ctx->ns_lock);
	for (int grpid = 1; grpid <= this_ctx->nr_zones; grpid++) {
		struct nvme_ana_group_desc *desc =
			(struct nvme_ana_group_desc *)grp_ptr;
		size_t avail = log_len - (grp_ptr - log);
		uint32_t nnsids = 0;

		if (avail < sizeof(*desc))
			break;
		avail -= sizeof(*desc);

		rb_for_each_entry(ns, &this_ctx->ns_root, rb) {
			if (ns->subsys_id != subsys_id ||
			    ns->ana_grpid != (uint32_t)grpid)
				continue;
			if (avail < sizeof(desc->nsids[0]))
				break;
			desc->nsids[nnsids++] = htole32(ns->nsid);
			avail -= sizeof(desc->nsids[0]);
		}

		desc->grpid = htole32(grpid);
		desc->nnsids = htole32(nnsids);
		desc->chgcnt = htole64(0);
		desc->state = ((unsigned int)grpid == portid) ?
			NVME_ANA_OPTIMIZED : NVME_ANA_NONOPTIMIZED;
		memset(desc->rsvd17, 0, sizeof(desc->rsvd17));
		sd_debug("%s: grpid %u %u nsids state %d",
			 __func__, grpid, nnsids, desc->state);

		grp_ptr = (uint8_t *)&desc->nsids[nnsids];
		ngrps++;
	}
	sd_mutex_unlock(&this_ctx->ns_lock);

	hdr->ngrps = htole16(ngrps);
	sd_debug("%s: %d ana groups", __func__, ngrps);
	return grp_ptr - log;
}

static void update_vdi_lock_state(struct nofuse_namespace *ns,
				  uint32_t vid, uint32_t acl_id)
{
	size_t buf_len = 0;
	char *buf = NULL;
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;
	enum lock_state lock_state;
	struct vdi_lock_state *vls;
	int ret;

	buf_len = sizeof(struct vdi_lock_state) * 16;
	buf = xzalloc(buf_len);
	if (!buf)
		return;

	sd_init_req(&req, SD_OP_GET_VDI_LOCK_STATE);
	req.vdi_lock.vid = vid;
	req.vdi_lock.acl = acl_id;
	req.vdi_lock.index = UINT32_MAX;
retry:
	req.data_length = buf_len;
	ret = sheep_exec_req(&sys->this_node.nid, &req, buf);
	if (ret < 0) {
		sd_err("Failed to get VDI %"PRIx32" state: %m",
		       vid);
		free(buf);
		return;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		free(buf);
		if (rsp->result == SD_RES_BUFFER_SMALL) {
			buf_len *= 2;
			buf = xzalloc(buf_len);
			if (!buf) {
				sd_err("Failed to allocate buffer");
				return;
			}
			goto retry;
		}
		sd_err("Failed to get VDI %"PRIx32" state: %s",
		       vid, sd_strerror(rsp->result));
		return;
	}
	lock_state = rsp->vdi_lock.state;

	vls = (struct vdi_lock_state *)buf;
	for (int i = 0; i < rsp->data_length; i += sizeof(*vls)) {
		struct sd_node *node, node_key;
		char *traddr;
		const char *adrfam = "ipv4";
		uint16_t trsvcid;
		bool port_present;

		if (rsp->data_length - i < sizeof(*vls))
			break;
		if (!strlen(vls->owner)) {
			vls++;
			continue;
		}
		node_key.nid = vls->sender;
		node = rb_search(&this_ctx->nroot, &node_key, rb, node_cmp);
		if (!node) {
			sd_warn("failed to find node '%s'",
				node_to_str(&node_key));
			vls++;
			continue;
		}
		port_present = configdb_check_port(node->zone + 1);

		traddr = str_to_tr(vls->owner, &trsvcid);
		if (!traddr) {
			sd_warn("failed to parse owner '%s'", vls->owner);
			vls++;
			continue;
		}
		if (!strchr(traddr, '.'))
			adrfam = "ipv6";
		if (lock_state == LOCK_STATE_LOCKED) {
			sd_warn("nsid %"PRIx32" locked, disabling", ns->nsid);
			vls++;
			continue;
		} else if (lock_state == LOCK_STATE_SHARED) {
			uint16_t portid = node->zone + 1;
			sd_debug("adding port %d (%s:%d)",
				 portid, traddr, trsvcid);

			if (port_present) {
				sd_debug("port '%s:%d' present, skipping",
					 traddr, trsvcid);
				vls++;
				continue;
			}
			ret = configdb_add_port(portid,
						traddr, adrfam, trsvcid);
			if (ret < 0) {
				sd_warn("cannot add port '%s:%d', error %d",
					traddr, trsvcid, ret);
				if (traddr)
					free(traddr);
				vls++;
				continue;
			}
			ret = configdb_add_ana_port_group(portid);
			if (ret < 0) {
				sd_warn("cannot register ana port group %d",
					portid);
				configdb_del_port(portid);
			}
			ret = configdb_add_subsys_port(acl_id, portid);
			if (ret < 0) {
				sd_warn("cannot register subsys port %d",
					node->zone + 1);
				configdb_del_ana_port_group(portid);
				configdb_del_port(portid);
			}
		} else {
			sd_debug("removing port %d (%s:%d)",
				 node->zone + 1, traddr, trsvcid);
			configdb_del_subsys_port(acl_id, node->zone + 1);
			configdb_del_ana_port_group(node->zone + 1);
			configdb_del_port(node->zone + 1);
		}
		if (traddr)
			free(traddr);
		vls++;
	}
	free(buf);
}

void nvmet_notify_acl_change(uint32_t vid, uint32_t old_acl, uint32_t new_acl)
{
	struct nofuse_event *ev;

	if (!this_ctx)
		return;

	ev = xmalloc(sizeof(*ev));
	ev->vid = vid;
	ev->old_acl = old_acl;
	ev->new_acl = new_acl;
	ev->type = NOFUSE_EVENT_ACL_CHANGE;

	sd_mutex_lock(&this_ctx->event_lock);
	list_add_tail(&ev->node, &this_ctx->event_list);
	sd_mutex_unlock(&this_ctx->event_lock);

	eventfd_write(this_ctx->event_evtfd, 1);
}

void nvmet_notify_node_change(void)
{
	struct nofuse_event *ev;

	if (!this_ctx)
		return;

	ev = xmalloc(sizeof(*ev));
	ev->type = NOFUSE_EVENT_NODE_CHANGE;

	sd_mutex_lock(&this_ctx->event_lock);
	list_add_tail(&ev->node, &this_ctx->event_list);
	sd_mutex_unlock(&this_ctx->event_lock);

	eventfd_write(this_ctx->event_evtfd, 1);
}

void nvmet_notify_lock_change(uint32_t vid, uint32_t acl)
{
	struct nofuse_event *ev;

	if (!this_ctx)
		return;

	ev = xmalloc(sizeof(*ev));
	ev->type = NOFUSE_EVENT_LOCK_CHANGE;
	ev->vid = vid;
	ev->new_acl = acl;

	sd_mutex_lock(&this_ctx->event_lock);
	list_add_tail(&ev->node, &this_ctx->event_list);
	sd_mutex_unlock(&this_ctx->event_lock);

	eventfd_write(this_ctx->event_evtfd, 1);
}

static void process_acl_event(struct nofuse_event *ev)
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

static int change_subsys_cntlid(struct nofuse_subsystem *subsys,
				unsigned int nr_zones)
{
	int ret, cntlid_range, cntlid_min, cntlid_max;
	char value[32];

	cntlid_range = 65520 / nr_zones;
	cntlid_min = (sys->this_node.zone * cntlid_range) + 1;
	cntlid_max = cntlid_min + cntlid_range - 1;
	if (cntlid_max >= 65520)
		cntlid_max = 65519;
	sd_debug("restricting cntlid for subsystem '%s' (%d zones) to %u-%u",
		 subsys->nqn, nr_zones, cntlid_min, cntlid_max);
	sprintf(value, "%u", cntlid_min);
	ret = configdb_set_subsys_attr(subsys->id,
				       "cntlid_min", value);
	if (ret < 0) {
		sd_warn("Failed to set 'cntlid_min'");
		return ret;
	}
	sprintf(value, "%u", cntlid_max);
	ret = configdb_set_subsys_attr(subsys->id,
				       "cntlid_max", value);
	if (ret < 0)
		sd_warn("Failed to set 'cntlid_max'");
	return ret;
}

static void process_node_event(struct nofuse_event *ev)
{
	struct nofuse_subsystem *subsys;
	int nr_nodes;

	nr_nodes = lookup_nodes(this_ctx);
	if (nr_nodes < 0) {
		sd_err("failed to lookup nodes");
		return;
	}
	sd_debug("cluster has %d nodes", nr_nodes);

	sd_mutex_lock(&this_ctx->root_lock);
	this_ctx->nr_zones = get_zones_nr_from(&this_ctx->nroot);
	sd_mutex_unlock(&this_ctx->root_lock);

	rb_for_each_entry(subsys, &this_ctx->subsys_root, rb) {
		if (this_ctx->nr_zones > 0) {
			change_subsys_cntlid(subsys, this_ctx->nr_zones);
		}
	}
}

static void process_lock_event(struct nofuse_event *ev)
{
	struct nofuse_namespace *ns, key = {
		.subsys_id = ev->new_acl,
		.nsid = ev->vid,
	};
	ns = rb_search(&this_ctx->ns_root, &key, rb, ns_cmp);
	if (!ns) {
		sd_err("failed to find VDI %"PRIx32" namespace", ev->vid);
		return;
	}
	update_vdi_lock_state(ns, ev->vid, ev->new_acl);
}

static void process_nofuse_event(struct nofuse_event *ev)
{
	switch (ev->type) {
	case NOFUSE_EVENT_ACL_CHANGE:
		sd_debug("process 'ACL CHANGE' event");
		process_acl_event(ev);
		break;
	case NOFUSE_EVENT_NODE_CHANGE:
		sd_debug("process 'NODE CHANGE' event");
		process_node_event(ev);
		break;
	case NOFUSE_EVENT_LOCK_CHANGE:
		sd_debug("process 'LOCK CHANGE' event");
		process_lock_event(ev);
		break;
	default:
		sd_warn("Unhandled event %d", ev->type);
		break;
	}
}

static int register_ana_groups(struct nofuse_context *ctx,
			       unsigned int agid)
{
	int ret = 0;
	struct sd_node *node;

	sd_mutex_lock(&ctx->root_lock);
	rb_for_each_entry(node, &ctx->nroot, rb) {
		int grpid = node->zone + 1;

		ret = configdb_add_ana_group(grpid);
		if (ret < 0)
			sd_warn("cannot register ANA group %u", grpid);

	}
	sd_mutex_unlock(&ctx->root_lock);
	return ret;
}

static int subsys_cmp(const struct nofuse_subsystem *a,
		      const struct nofuse_subsystem *b)
{
	return intcmp(a->id, b->id);
}

int nvmet_register_subsystem(uint32_t subsys_id, const char *subsysnqn)
{
	int ret;
	char value[8];
	struct nofuse_subsystem *new, *subsys = xzalloc(sizeof(*subsys));

	strcpy(subsys->nqn, subsysnqn);
	sd_mutex_lock(&this_ctx->subsys_lock);
	subsys->id = subsys_id;
	subsys->type = NVME_NQN_NVM;
	new = rb_insert(&this_ctx->subsys_root, subsys, rb, subsys_cmp);
	if (new) {
		sd_debug("update subsystem '%s' (%06x)", new->nqn, new->id);
		free(subsys);
		subsys = new;
	} else
		sd_debug("register subsystem '%s' (%06x)",
			 subsys->nqn, subsys->id);
	sd_mutex_unlock(&this_ctx->subsys_lock);
	ret = configdb_add_subsys(subsys->nqn, subsys->id, subsys->type);
	if (ret < 0) {
		sd_warn("Failed to register subsystem '%s'", subsys->nqn);
		rb_erase(&subsys->rb, &this_ctx->subsys_root);
		free(subsys);
		return ret;
	}
	sd_mutex_lock(&this_ctx->root_lock);
	this_ctx->nr_zones = get_zones_nr_from(&this_ctx->nroot);
	sd_mutex_unlock(&this_ctx->root_lock);
	if (this_ctx->nr_zones > 0) {
		ret = change_subsys_cntlid(subsys, this_ctx->nr_zones);
		if (ret < 0)
			return ret;
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

struct nofuse_subsystem *lookup_subsystem_by_id(uint32_t subsys_id)
{
	struct nofuse_subsystem key = { .id = subsys_id };

	return rb_search(&this_ctx->subsys_root, &key, rb, subsys_cmp);
}

static int subsys_nqn_cmp(const struct nofuse_subsystem *a,
		      const struct nofuse_subsystem *b)
{
	return strcmp(a->nqn, b->nqn);
}

struct nofuse_subsystem *lookup_subsystem_by_nqn(const char *nqn)
{
	struct nofuse_subsystem key;

	strcpy(key.nqn, nqn);
	return rb_search(&this_ctx->subsys_root, &key, rb, subsys_nqn_cmp);
}

int nvmet_unregister_subsystem(uint32_t subsys_id)
{
	struct nofuse_subsystem *subsys;
	int ret;

	sd_debug("unregister subsystem %06x", subsys_id);
	sd_mutex_lock(&this_ctx->subsys_lock);
	subsys = lookup_subsystem_by_id(subsys_id);
	if (!subsys) {
		sd_mutex_unlock(&this_ctx->subsys_lock);
		sd_warn("Subsystem '%06x' not found", subsys_id);
		return -ENODEV;
	}
	rb_erase(&subsys->rb, &this_ctx->subsys_root);
	sd_mutex_unlock(&this_ctx->subsys_lock);
	/* subsys_port.subsys_id is ON DELETE RESTRICT */
	ret = configdb_del_subsys_port(subsys->id, this_ctx->portid);
	if (ret < 0)
		sd_warn("Failed to remove port %u for subsystem '%06x'",
			this_ctx->portid, subsys->id);
	ret = configdb_del_subsys(subsys->id);
	if (ret < 0)
		sd_warn("Failed to delete subsystem %06x", subsys->id);
	free(subsys);
	return ret;
}

int nvmet_register_namespace(uint32_t subsys_id, uint32_t nsid,
			     struct sd_inode_header *inode)
{
	struct nofuse_namespace *ns, *new = NULL;
	struct nofuse_subsystem *subsys;
	struct sd_vnode *vnode;
	bool do_register = false;
	uint64_t oid;
	int ret;

	oid = vid_to_vdi_oid(nsid);
	vnode = oid_to_first_vnode(oid, &this_ctx->vroot);

	subsys = lookup_subsystem_by_id(subsys_id);
	if (!subsys) {
		sd_warn("subsystem %"PRIx32" not registered", subsys_id);
		return -EINVAL;
	}
	sd_debug("register namespace %06x ('%s')",
		 nsid, inode->name);

	ns = xzalloc(sizeof(*ns));
	ns->subsys = subsys;
	ns->subsys_id = subsys_id;
	ns->nsid = nsid;
	ns->size = inode->vdi_size;
	ns->blksize = SECTOR_SIZE;
	ns->readonly = false;
	ns->enabled = true;
	ns->ana_grpid = vnode->node->zone + 1;
	memcpy(ns->uuid, inode->uuid, sizeof(ns->uuid));
	ns->ops = vdi_register_ops();

	subsys->nn++;
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
		ret = register_vdi(ns, false);
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
	sd_mutex_lock(&this_ctx->ns_lock);
	ns = rb_search(&this_ctx->ns_root, &key, rb, ns_cmp);
	if (ns)
		rb_erase(&ns->rb, &this_ctx->ns_root);
	sd_mutex_unlock(&this_ctx->ns_lock);
	if (!ns) {
		sd_warn("namespace '%06x' not found", nsid);
		return -ENODEV;
	}
	ret = register_vdi(ns, true);
	if (ret < 0)
		sd_warn("Failed to unregister namespace '%06x'", nsid);

	sd_mutex_lock(&this_ctx->ns_lock);
	ret = configdb_del_namespace(subsys_id, nsid);
	if (ret < 0)
		sd_warn("Failed to delete namespace '%06x'", nsid);
	ns->subsys->nn--;
	free(ns);
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
	struct nofuse_event *ev, *next;

	list_for_each_entry_safe(ev, next, &ctx->event_list, node) {
		list_del(&ev->node);
		free(ev);
	}
	if (ctx->event_evtfd >= 0)
		close(ctx->event_evtfd);
	sd_destroy_mutex(&ctx->event_lock);

	sd_mutex_lock(&ctx->root_lock);
	rb_destroy(&ctx->nroot, struct sd_vnode, rb);
	rb_destroy(&ctx->vroot, struct sd_node, rb);
	sd_mutex_unlock(&ctx->root_lock);
	rb_destroy(&ctx->ns_root, struct nofuse_namespace, rb);
	rb_destroy(&ctx->subsys_root, struct nofuse_subsystem, rb);
	free(ctx->traddr);
	free(ctx->dbname);
	free(arg);
}

static void *nofuse_main(void *arg)
{
	struct nofuse_context *ctx = arg;
	struct nofuse_subsystem *disc_subsys, *new;
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

	disc_subsys = xzalloc(sizeof(*disc_subsys));
	if (!disc_subsys) {
		sd_err("out of memory allocating discovery subsystem");
		goto out_close;
	}
	strcpy(disc_subsys->nqn, NVME_DISC_SUBSYS_NAME);
	disc_subsys->type = NVME_NQN_CUR;
	sd_mutex_lock(&this_ctx->subsys_lock);
	new = rb_insert(&this_ctx->subsys_root, disc_subsys,
			rb, subsys_nqn_cmp);
	sd_mutex_unlock(&this_ctx->subsys_lock);
	if (new) {
		sd_warn("discovery subsystem already present");
		free(disc_subsys);
		disc_subsys = new;
	}
	ret = configdb_add_subsys(disc_subsys->nqn, disc_subsys->id,
				  disc_subsys->type);
	if (ret < 0) {
		sd_err("failed to create default discovery subsystem");
		goto out_destroy;
	}

	ret = register_subsystems(agid);
	if (ret < 0) {
		sd_err("failed to register ACL VDIs");
		goto out_destroy;
	}

	tls_keyring = tls_global_init();
	if (tls_keyring)
		port->tls = true;

	stopped = 0;

	ret = start_port(port);
	if (ret) {
		sd_err("failed to start nvmet port");
		goto out_destroy;
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
		struct nofuse_event *ev, *next;
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
			process_nofuse_event(ev);
			free(ev);
		}
	}

out_destroy:
	rb_destroy(&this_ctx->subsys_root, struct nofuse_subsystem, rb);
	free(disc_subsys);
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

	if (!traddr)
		return 0;

	this_ctx = malloc(sizeof(struct nofuse_context));
	if (!this_ctx)
		return 1;
	memset(this_ctx, 0, sizeof(struct nofuse_context));
	this_ctx->traddr = strdup(traddr);
	this_ctx->trsvcid = trsvcid;
	this_ctx->dbname = strdup("nofuse.sqlite");
	INIT_RB_ROOT(&this_ctx->nroot);
	INIT_RB_ROOT(&this_ctx->vroot);
	sd_init_mutex(&this_ctx->root_lock);
	INIT_RB_ROOT(&this_ctx->ns_root);
	sd_init_mutex(&this_ctx->ns_lock);
	INIT_RB_ROOT(&this_ctx->subsys_root);
	sd_init_mutex(&this_ctx->subsys_lock);
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
