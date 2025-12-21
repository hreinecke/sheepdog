/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * Copyright (C) 2012 Taobao Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <semaphore.h>

#include "cluster.h"
#include "config.h"
#include "event.h"
#include "work.h"
#include "util.h"
#include "rbtree.h"
#include "etcd_client.h"

#define SESSION_TIMEOUT 30		/* seconds */

#define DEFAULT_BASE "sheepdog/"
#define MEMBER_ZNODE "member/"
#define CLUSTER_ZNODE "cluster/"
#define LOCK_ZNODE "lock/"
#define SEQ_ZNODE "seq/"
#define EV_ZNODE "events/"
#define QUEUE_POS_ZNODE "queue_pos/"

static int etcd_timeout = SESSION_TIMEOUT;

#define WAIT_TIME	1		/* second */

enum etcd_event_type {
	EVENT_JOIN = 1,
	EVENT_ACCEPT,
	EVENT_LEAVE,
	EVENT_BLOCK,
	EVENT_UNBLOCK,
	EVENT_NOTIFY,
	EVENT_UPDATE_NODE,
	EVENT_UNKNOWN,
};

const char *etcd_event_names[] = {
	[EVENT_JOIN] = "join",
	[EVENT_ACCEPT] = "accept",
	[EVENT_LEAVE] = "leave",
	[EVENT_BLOCK] = "block",
	[EVENT_UNBLOCK] = "unblock",
	[EVENT_NOTIFY] = "notify",
	[EVENT_UPDATE_NODE] = "update-node",
};

enum etcd_node_attr_type {
	ATTR_ADDR = 1 << 0,
	ATTR_IO_ADDR = 1 << 1,
	ATTR_ZONE = 1 << 2,
	ATTR_NR_VNODES = 1 << 3,
	ATTR_SPACE = 1 << 4,
	ATTR_PORT = 1 << 5,
	ATTR_IO_PORT = 1 << 6,
};

const char *etcd_node_attr_names[] = {
	[ATTR_ADDR] = "addr",
	[ATTR_IO_ADDR] = "io_addr",
	[ATTR_ZONE] = "zone",
	[ATTR_NR_VNODES] = "nr_vnodes",
	[ATTR_SPACE] = "space",
	[ATTR_PORT] = "port",
	[ATTR_IO_PORT] = "io_port",
};

struct etcd_node {
	struct list_node list;
	struct rb_node rb;
	struct etcd_ctx *ctx;
	char node_id[MAX_NODE_STR_LEN];
	struct cluster_info *cinfo;
	struct sd_node node;
	unsigned int attr_mask;
	bool callbacked;
	bool init;
};

static LIST_HEAD(etcd_block_list);

static int etcd_node_cmp(const struct etcd_node *a, const struct etcd_node *b)
{
	return strcmp(a->node_id, b->node_id);
}

static struct etcd_node this_node;
static struct etcd_ctx *this_ctx;

static enum etcd_node_attr_type etcd_attr_to_type(const char *attr)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(etcd_node_attr_names); i++) {
		if (!etcd_node_attr_names[i])
			continue;
		if (!strcmp(attr, etcd_node_attr_names[i]))
			return i;
	}
	return 0;
}

static inline bool etcd_node_exists(struct etcd_ctx *ctx, const char *node_id)
{
	char path[1024], val[MAX_NODE_STR_LEN];
	int rc;

	snprintf(path, sizeof(path),
		 DEFAULT_BASE MEMBER_ZNODE "%s/addr",
		 node_id);
	rc = etcd_kv_get(ctx, path, val, sizeof(val));
	if (rc >= 0)
		return true;
	return false;
}

static inline int etcd_node_delete(struct etcd_node *node)
{
	char key[1024];

	strcpy(key, DEFAULT_BASE);
	strcat(key, MEMBER_ZNODE);
	strcat(key, node->node_id);
	return etcd_kv_delete(node->ctx, key);
}

static inline int etcd_get_node_attr(struct etcd_node *node, const char *attr)
{
	char key[1024], val[MAX_NODE_STR_LEN], *eptr;
	enum etcd_node_attr_type attr_type = 0;
	unsigned long num;
	int rc, len;

	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/%s",
		 node->node_id, attr);
	rc = etcd_kv_get(node->ctx, key, val, sizeof(val));
	if (rc < 0)
		return rc;
	attr_type = etcd_attr_to_type(attr);
	if (!attr_type) {
		sd_warn("%s: invalid attribute '%s'", __func__, attr);
		return -EINVAL;
	}
	if (attr_type == ATTR_ADDR) {
		len = sizeof(node->node.nid.addr);
		if (rc < len)
			len = rc;
		if (!str_to_addr(val, node->node.nid.addr))
			return -EINVAL;
		node->attr_mask |= attr_type;
		return 0;
	}
	if (attr_type == ATTR_IO_ADDR) {
		len = sizeof(node->node.nid.io_addr);
		if (rc < len)
			len = rc;
		if (!str_to_addr(val, node->node.nid.io_addr))
			return -EINVAL;
		node->attr_mask |= attr_type;
		return 0;
	}
	errno = 0;
	num = strtoul(val, &eptr, 10);
	if (errno || val == eptr)
		return -ERANGE;
	switch (attr_type) {
	case ATTR_ZONE:
		node->node.zone = num;
		break;
	case ATTR_NR_VNODES:
		node->node.nr_vnodes = num;
		break;
	case ATTR_SPACE:
		node->node.space = num;
		break;
	case ATTR_PORT:
		node->node.nid.port = num;
		break;
	case ATTR_IO_PORT:
		node->node.nid.io_port = num;
		break;
	default:
		return -EINVAL;
	}
	node->attr_mask |= attr_type;
	return 0;
}

static int etcd_node_set_int_attr(struct etcd_node *node, const char *attr,
				  unsigned long num)
{
	char key[1024], val[MAX_NODE_STR_LEN];
	size_t len;

	len = snprintf(val, sizeof(val), "%lu", num);
	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/%s",
		 node->node_id, attr);
	return etcd_kv_new(node->ctx, key, val, len);
}

static int etcd_node_set_str_attr(struct etcd_node *node, const char *attr)
{
	char key[1024], val[MAX_NODE_STR_LEN];
	size_t len;

	if (!strcmp(attr, "addr")) {
		const char *addr = addr_to_str(node->node.nid.addr,
					       node->node.nid.port);
		strcpy(val, addr);
		len = strlen(val);
	} else if (!strcmp(attr, "io_addr")) {
		const char *addr = addr_to_str(node->node.nid.io_addr,
					       node->node.nid.io_port);
		strcpy(val, addr);
		len = strlen(val);
	} else
		return -EINVAL;

	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/%s",
		node->node_id, attr);
	return etcd_kv_new(node->ctx, key, val, len);
}

static int etcd_node_set_disk_attr(struct etcd_node *node, int disk_num)
{
	char key[1024], val[MAX_NODE_STR_LEN];
	size_t len;

	len = snprintf(val, sizeof(val), "%lu",
		       node->node.disks[disk_num].disk_space);
	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/disks/%lu",
		node->node_id, node->node.disks[disk_num].disk_id);
	return etcd_kv_new(node->ctx, key, val, len);
}

static inline bool etcd_node_upload(struct etcd_node *node, bool create)
{
	int rc, i;

	if (create && etcd_node_exists(node->ctx, node->node_id))
		return -EEXIST;
	for (i = 0; i < ARRAY_SIZE(etcd_node_attr_names); i++) {
		if (!etcd_node_attr_names[i])
			continue;
		switch (i) {
		case ATTR_ADDR:
			rc = etcd_node_set_str_attr(node, "addr");
			break;
		case ATTR_IO_ADDR:
			rc = etcd_node_set_str_attr(node, "io_addr");
			break;
		case ATTR_ZONE:
			rc = etcd_node_set_int_attr(node, "zone",
						    node->node.zone);
			break;
		case ATTR_NR_VNODES:
			rc = etcd_node_set_int_attr(node, "nr_vnodes",
						    node->node.nr_vnodes);
			break;
		case ATTR_SPACE:
			rc = etcd_node_set_int_attr(node, "space",
						    node->node.space);
			break;
		case ATTR_PORT:
			rc = etcd_node_set_int_attr(node, "port",
						    node->node.nid.port);
			break;
		case ATTR_IO_PORT:
			rc = etcd_node_set_int_attr(node, "io_port",
						    node->node.nid.io_port);
			break;
		default:
			rc = -EINVAL;
			break;
		}
		if (rc < 0)
			return rc;
	}
	for (i = 0; i < DISK_MAX; i++) {
		if (!node->node.disks[i].disk_id)
			continue;
		rc = etcd_node_set_disk_attr(node, i);
		if (rc < 0)
			goto out_cleanup;
	}
	return 0;
out_cleanup:
	etcd_node_delete(node);
	return rc;
}

static inline int etcd_kv_to_node(struct etcd_kv *kv,
				  struct etcd_node *node)
{
	char *attr;
	size_t len;
	unsigned long num;
	int attr_type;
	struct disk_info *disk_info = NULL;
	unsigned long disk_id;
	int i, disk_num = -1;

	attr = strrchr(kv->key, '/');
	if (!attr) {
		sd_debug("%s: skipping key '%s'",
			 __func__, kv->key);
		return -EINVAL;
	}
	attr++;
	len = kv->value_len;
	attr_type = etcd_attr_to_type(attr);
	if (attr_type == ATTR_ADDR) {
		if (len > sizeof(node->node.nid.addr))
			len = sizeof(node->node.nid.addr);
		memcpy(node->node.nid.addr, kv->value, len);
		return 0;
	}
	if (attr_type == ATTR_IO_ADDR) {
		if (len > sizeof(node->node.nid.io_addr))
			len = sizeof(node->node.nid.io_addr);
		memcpy(node->node.nid.io_addr, kv->value, len);
		return 0;
	}
		
	errno = 0;
	num = strtoul(kv->value, NULL, 10);
	if (errno) {
		sd_debug("%s: parsing error on '%s'", __func__, kv->value);
		return -errno;
	}
	switch (attr_type) {
	case ATTR_ZONE:
		node->node.zone = num;
		return 0;
	case ATTR_NR_VNODES:
		node->node.nr_vnodes = num;
		return 0;
	case ATTR_SPACE:
		node->node.space = num;
		return 0;
	case ATTR_PORT:
		node->node.nid.port = num;
		return 0;
	case ATTR_IO_PORT:
		node->node.nid.io_port = num;
		return 0;
#ifdef HAVE_ACCELIO
	case ATTR_TRANSPORT:
		node->node.nid.io_transport_type = num;
		return 0;
#endif
	default:
		break;
	}

	if (!strstr(kv->key, "disks")) {
		sd_debug("%s: unhandled attribute '%s'",
			 __func__, attr);
		return -EINVAL;
	}
	disk_id = strtoul(attr, NULL, 10);
	for (i = 0; i < DISK_MAX; i++) {
		if (!node->node.disks[i].disk_id) {
			if (disk_num == -1)
				disk_num = i;
			continue;
		}
		if (node->node.disks[i].disk_id == disk_id) {
			disk_info = &node->node.disks[i];
			break;
		}
	}
	if (!disk_info) {
		if (disk_num >= DISK_MAX)
			return -EINVAL;
		disk_info = &node->node.disks[disk_num];
	}
	disk_info->disk_id = disk_id;
	disk_info->disk_space = num;

	return 0;
}

static inline int etcd_node_download(struct etcd_node *node)
{
	char key[1024];
	struct etcd_kv *kvs;
	int i, rc, num_kvs;

	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/",
		 node->node_id);
	num_kvs = etcd_kv_range(node->ctx, key, &kvs);
	if (num_kvs < 0)
		return num_kvs;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];

		rc = etcd_kv_to_node(kv, node);
		if (rc < 0)
			return rc;
	}
	etcd_kv_free(kvs, num_kvs);
	return num_kvs;
}

static int etcd_set_cinfo_attr(struct etcd_ctx *ctx, const char *attr,
			       unsigned long num)
{
	char key[1024], val[MAX_NODE_STR_LEN];
	size_t len;

	len = snprintf(val, sizeof(val), "%lu", num);
	snprintf(key, sizeof(key), DEFAULT_BASE CLUSTER_ZNODE "%s", attr);
	return etcd_kv_store(ctx, key, val, len);
}

static int etcd_cinfo_upload(struct etcd_ctx *ctx, struct cluster_info *cinfo,
			     bool create)
{
	int rc;

	if (create) {
		char key[1024];
		struct etcd_kv *kvs;

		strcpy(key, DEFAULT_BASE CLUSTER_ZNODE);
		rc = etcd_kv_range(ctx, key, &kvs);
		if (rc < 0)
			return rc;
		etcd_kv_free(kvs, rc);
		if (rc > 0)
			return 0;
	}
	rc = etcd_set_cinfo_attr(ctx, "proto_ver", cinfo->proto_ver);
	if (rc < 0)
		return rc;
	rc = etcd_set_cinfo_attr(ctx, "disable_recovery",
				 cinfo->disable_recovery);
	if (rc < 0)
		return rc;
	rc = etcd_set_cinfo_attr(ctx, "nr_nodes", cinfo->nr_nodes);
	if (rc < 0)
		return rc;
	rc = etcd_set_cinfo_attr(ctx, "epoch", cinfo->epoch);
	if (rc < 0)
		return rc;
	rc = etcd_set_cinfo_attr(ctx, "ctime", cinfo->ctime);
	if (rc < 0)
		return rc;
	rc = etcd_set_cinfo_attr(ctx, "flags", cinfo->flags);
	if (rc < 0)
		return rc;
	rc = etcd_set_cinfo_attr(ctx, "nr_copies", cinfo->nr_copies);
	if (rc < 0)
		return rc;
	rc = etcd_set_cinfo_attr(ctx, "copy_policy", cinfo->copy_policy);
	if (rc < 0)
		return rc;
	rc = etcd_set_cinfo_attr(ctx, "block_size_shift",
				 cinfo->block_size_shift);
	if (rc < 0)
		return rc;

	rc = etcd_set_cinfo_attr(ctx, "status",
				 cinfo->status);
	if (rc < 0)
		return rc;
	return rc;
}

static int etcd_cinfo_download(struct etcd_ctx *ctx, struct cluster_info *cinfo)
{
	char key[1024];
	struct etcd_kv *kvs;
	int num_kvs, i;

	strcpy(key, DEFAULT_BASE CLUSTER_ZNODE);
	num_kvs = etcd_kv_range(ctx, key, &kvs);
	if (num_kvs < 0)
		return num_kvs;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		unsigned long val;
		char *name;

		val = strtoul(kv->value, NULL, 10);
		name = strrchr(kv->key, '/');
		name++;
		if (!strcmp(name, "proto_ver"))
			cinfo->proto_ver = val;
		else if (!strcmp(name, "disable_recovery"))
			cinfo->disable_recovery = val;
		else if (!strcmp(name, "nr_nodes"))
			cinfo->nr_nodes = val;
		else if (!strcmp(name, "epoch"))
			cinfo->epoch = val;
		else if (!strcmp(name, "ctime"))
			cinfo->ctime = val;
		else if (!strcmp(name, "flags"))
			cinfo->flags = val;
		else if (!strcmp(name, "nr_copies"))
			cinfo->flags = val;
		else if (!strcmp(name, "copy_policy"))
			cinfo->copy_policy = val;
		else if (!strcmp(name, "block_size_shift"))
			cinfo->block_size_shift = val;
		else if (!strcmp(name, "status"))
			cinfo->status = val;
		else
			sd_warn("%s: invalid attribute '%s'",
				__func__, kv->key);
	}
	etcd_kv_free(kvs, num_kvs);
	return 0;
}

static int etcd_build_node_list(struct etcd_ctx *ctx, struct rb_root *root,
				struct etcd_node *test_node)
{
	size_t num_kvs, nr_nodes = 0;
	struct etcd_node *node = NULL;
	char base[MAX_NODE_STR_LEN];
	struct etcd_kv *kvs;
	int node_size = sizeof(*node) + sizeof(struct disk_info) * DISK_MAX;
	int i, rc;

	strcpy(base, DEFAULT_BASE MEMBER_ZNODE);
	num_kvs = etcd_kv_range(ctx, base, &kvs);
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		struct etcd_node node_key;
		char *key, *a;

		key = kv->key + strlen(base);
		strcpy(node_key.node_id, key);
		a = strchr(node_key.node_id, '/');
		*a = '\0';
		node = rb_search(root, &node_key, rb, etcd_node_cmp);
		if (!node) {
			if (test_node &&
			    !strcmp(node_key.node_id, test_node->node_id))
				continue;
			node = xzalloc(node_size);
			strcpy(node->node_id, node_key.node_id);
			rb_insert(root, node, rb, etcd_node_cmp);
			nr_nodes++;
		}
		rc = etcd_kv_to_node(kv, node);
		if (rc < 0) {
			sd_err("%s: failed to load node attr '%s'",
			       __func__, key);
			etcd_kv_free(kvs, num_kvs);
			return rc;
		}
	}
	sd_debug("%s: %zu nodes", __func__, nr_nodes);
	etcd_kv_free(kvs, num_kvs);
	return nr_nodes;
}

static inline int etcd_node_is_master(struct etcd_node *node)
{
	char key[1024], *master = NULL;;
	struct etcd_kv *kvs;
	int i, num_kvs, num_nodes = 0;;
	bool is_master = false;

	strcpy(key, DEFAULT_BASE MEMBER_ZNODE);
	num_kvs = etcd_kv_range(node->ctx, key, &kvs);
	if (num_kvs < 0)
		return num_kvs;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		char *id = kv->key + strlen(key), *attr;

		attr = strrchr(id, '/');
		if (attr && !strcmp(attr, "space")) {
			/*
			 * The master node is the node
			 * with the earliest creation date.
			 * If we only have one node there
			 * is no master.
			 */
			if (num_nodes > 0) {
				master = id;
				break;
			}
			num_nodes++;
		}
	}
	if (master &&
	    !strncmp(master, node->node_id, strlen(node->node_id)))
		is_master = true;
	etcd_kv_free(kvs, num_kvs);
	return is_master;
}

static inline int etcd_event_create(struct etcd_node *node)
{
	char prefix[1024], key[MAX_NODE_STR_LEN];
	int rc = 0, i;

	snprintf(prefix, sizeof(prefix), DEFAULT_BASE EV_ZNODE "%s/",
		 node->node_id);
	memset(key, 0, sizeof(key));
	for (i = 0; i < ARRAY_SIZE(etcd_event_names); i++) {
		if (!etcd_event_names[i])
			continue;
		strcpy(key, prefix);
		strcat(key, etcd_event_names[i]);
		rc = etcd_kv_new(node->ctx, key, NULL, 0);
		if (rc < 0) {
			etcd_kv_delete(node->ctx, prefix);
			break;
		}
	}
	return rc;
}

static inline bool etcd_event_delete(struct etcd_node *node)
{
	char key[1024];

	snprintf(key, sizeof(key), DEFAULT_BASE EV_ZNODE "%s/",
		 node->node_id);
	return etcd_kv_delete(node->ctx, key);
}

static int etcd_update_event(enum etcd_event_type type, struct etcd_node *node,
			     void *buf, size_t buf_len)
{
	char key[1024];
	const char *event;
	int rc;

	event = etcd_event_names[type];
	if (!event) {
		sd_warn("%s: invalid type %d", __func__, type);
		return -EINVAL;
	}
	snprintf(key, sizeof(key), DEFAULT_BASE EV_ZNODE "%s/%s",
		 node->node_id, event);

	rc = etcd_kv_store(node->ctx, key, buf, buf_len);
	if (rc < 0) {
		sd_err("failed, type: %d, %d", type, rc);
		return SD_RES_CLUSTER_ERROR;
	}
	return 0;
}

static void block_event_list_del(struct etcd_node *n)
{
	struct etcd_node *ev;

	list_for_each_entry(ev, &etcd_block_list, list) {
		if (node_eq(&ev->node, &n->node)) {
			list_del(&ev->list);
			free(ev);
		}
	}
}

static int etcd_join(const struct sd_node *myself,
		     void *opaque, size_t opaque_len)
{
	int rc;
	struct cluster_info *cinfo = opaque;

	cinfo->proto_ver = SD_SHEEP_PROTO_VER;
	this_node.ctx = this_ctx;
	this_node.node = *myself;
	strcpy(this_node.node_id, node_to_str(myself));
	this_node.cinfo = cinfo;

	this_node.init = true;
	rc = etcd_cinfo_upload(this_ctx, cinfo, true);
	if (rc < 0) {
		sd_err("cluster init failed");
		return rc;
	}
	rc = etcd_event_create(&this_node);
	if (rc < 0) {
		sd_err("event creation failed");
		memset(&this_node.node, 0, sizeof(this_node.node));
		return rc;
	}
	rc = etcd_node_upload(&this_node, true);
	if (rc < 0) {
		etcd_event_delete(&this_node);
		if (rc == -EEXIST)
			sd_err("Previous etcd key exist, shoot myself. Please "
			       "wait for %d seconds to join me again.",
			       DIV_ROUND_UP(etcd_timeout, 1000));
		exit(1);
	}
	this_node.init = false;

	rc = etcd_update_event(EVENT_JOIN, &this_node, opaque, opaque_len);
	if (rc < 0) {
		etcd_node_delete(&this_node);
		memset(&this_node.node, 0, sizeof(this_node.node));
	}

	return rc;
}

static int etcd_leave(void)
{
	int rc;

	sd_info("leaving from cluster");
	block_event_list_del(&this_node);
	rc = etcd_event_delete(&this_node);
	if (rc < 0)
		return rc;
	return etcd_node_delete(&this_node);
}

static int etcd_notify(void *msg, size_t msg_len)
{
	return etcd_update_event(EVENT_NOTIFY, &this_node, msg, msg_len);
}

static int etcd_block(void)
{
	return etcd_update_event(EVENT_BLOCK, &this_node, NULL, 0);
}

static int etcd_unblock(void *msg, size_t msg_len)
{
	return etcd_update_event(EVENT_UNBLOCK, &this_node, msg, msg_len);
}

static void etcd_handle_join(struct etcd_node *node,
			     void *opaque, size_t opaque_len)
{
	struct rb_root node_root, sd_root;
	struct etcd_node *enode;
	int nr_nodes;

	INIT_RB_ROOT(&node_root);
	if (!etcd_node_is_master(node)) {
		/* Let's await master acking the join-request */
		sd_debug("%s: node '%s' is not master", __func__,
			 node->node_id);
		return;
	}

	nr_nodes = etcd_build_node_list(node->ctx, &node_root, node);
	if (nr_nodes < 0) {
		sd_err("%s: failed to build node list", __func__);
		return;
	}
	INIT_RB_ROOT(&sd_root);
	rb_for_each_entry(enode, &node_root, rb) {
		rb_insert(&sd_root, &enode->node, rb, node_cmp);
	}
	sd_debug("sender: %s", node_to_str(&node->node));
	if (sd_join_handler(&node->node, &sd_root, nr_nodes,
			    this_node.cinfo)) {
		sd_debug("I'm the master now");
		etcd_update_event(EVENT_ACCEPT, &this_node,
				  this_node.cinfo, sizeof(struct cluster_info));
	}
	rb_destroy(&node_root, struct etcd_node, rb);
}

static void etcd_handle_leave(struct etcd_node *node)
{
	struct rb_root node_root, sd_root;
	struct etcd_node *enode;
	int nr_nodes;

	INIT_RB_ROOT(&node_root);
	nr_nodes = etcd_build_node_list(node->ctx, &node_root, NULL);
	if (nr_nodes < 0) {
		sd_err("%s: failed to build node list", __func__);
		return;
	}
	INIT_RB_ROOT(&sd_root);
	rb_for_each_entry(enode, &node_root, rb)
		rb_insert(&sd_root, &enode->node, rb, node_cmp);
	sd_leave_handler(&node->node, &sd_root, nr_nodes);
	rb_destroy(&node_root, struct etcd_node, rb);
	memset(&this_node.node, 0, sizeof(this_node.node));
}

static void etcd_handle_accept(struct etcd_node *node,
			       void *opaque, size_t opaque_len)
{
	struct rb_root node_root, sd_root;
	struct etcd_node *enode;
	struct cluster_info cinfo;
	int nr_nodes;

	INIT_RB_ROOT(&node_root);

	sd_debug("ACCEPT");
	nr_nodes = etcd_build_node_list(node->ctx, &node_root, node);
	if (nr_nodes < 0) {
		sd_err("%s: failed to build node list", __func__);
		return;
	}
	INIT_RB_ROOT(&sd_root);
	rb_for_each_entry(enode, &node_root, rb)
		rb_insert(&sd_root, &enode->node, rb, node_cmp);
	memset(&cinfo, 0, sizeof(cinfo));
	etcd_cinfo_download(node->ctx, &cinfo);
	sd_accept_handler(&this_node.node, &sd_root, nr_nodes, &cinfo);
}

static void etcd_kick_block_event(void)
{
	struct etcd_node *block;

	if (list_empty(&etcd_block_list))
		return;
	block = list_first_entry(&etcd_block_list, typeof(*block), list);
	if (!block->callbacked)
		block->callbacked = sd_block_handler(&block->node);
}

static void etcd_handle_block(struct etcd_node *node)
{
	struct etcd_node *block = xzalloc(sizeof(*block));

	sd_debug("BLOCK");
	block->node = node->node;
	list_add_tail(&block->list, &etcd_block_list);
	block = list_first_entry(&etcd_block_list, typeof(*block), list);
	if (!block->callbacked)
		block->callbacked = sd_block_handler(&block->node);
}

static void etcd_handle_unblock(struct etcd_node *node,
				void *opaque, size_t opaque_len)
{
	struct etcd_node *block;

	sd_debug("UNBLOCK");
	if (list_empty(&etcd_block_list))
		return;
	block = list_first_entry(&etcd_block_list, typeof(*block), list);
	sd_notify_handler(&node->node, opaque, opaque_len);

	list_del(&block->list);
	free(block);
}

static void etcd_handle_notify(struct etcd_node *node,
			       void *opaque, size_t opaque_len)
{
	sd_debug("NOTIFY");
	sd_notify_handler(&node->node, opaque, opaque_len);
}

static void etcd_event_watch_cb(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	struct etcd_node *node;
	char *event;
	const char *base = DEFAULT_BASE EV_ZNODE;
	enum etcd_event_type type = EVENT_UPDATE_NODE;
	int rc, i;

	if (strncmp(kv->key, base, strlen(base)))
		return;
	node = xzalloc(sizeof(*node) + sizeof(struct disk_info) * DISK_MAX);
	node->ctx = ctx;
	strcpy(node->node_id, kv->key + strlen(base));
	event = strchr(node->node_id, '/');
	if (!event) {
		free(node);
		return;
	}
	*event++ = '\0';

	for (i = 0; i < ARRAY_SIZE(etcd_event_names); i++) {
		if (!etcd_event_names[i])
			continue;
		if (!strcmp(event, etcd_event_names[i])) {
			type = i;
			break;
		}
	}
	if (!strcmp(node->node_id, this_node.node_id) &&
	    this_node.init) {
		sd_debug("%s: event %s (%d) key %s ignored during init",
			 __func__, event, type, node->node_id);
		free(node);
		return;
	}
	sd_debug("%s: event %s (%d) key %s value_len %lu deleted %d",
		 __func__, event, type, node->node_id, kv->value_len,
		kv->deleted);
	if (kv->deleted && type != EVENT_LEAVE) {
		free(node);
		return;
	}

	rc = etcd_node_download(node);
	if (rc < 0) {
		free(node);
		return;
	}
	if (rc == 0) {
		sd_debug("%s: node '%s' does not exist", __func__,
			 node->node_id);
		free(node);
		return;
	}
	switch (type) {
	case EVENT_JOIN:
		etcd_handle_join(node, kv->value, kv->value_len);
		break;
	case EVENT_ACCEPT:
		etcd_handle_accept(node, kv->value, kv->value_len);
		break;
	case EVENT_LEAVE:
		etcd_handle_leave(node);
		break;
	case EVENT_BLOCK:
		etcd_handle_block(node);
		break;
	case EVENT_UNBLOCK:
		etcd_handle_unblock(node, kv->value, kv->value_len);
		break;
	case EVENT_NOTIFY:
		etcd_handle_notify(node, kv->value, kv->value_len);
		break;
	case EVENT_UPDATE_NODE:
		break;
	default:
		sd_err("invalid event '%s'", kv->key);
		free(node);
		return;
	}
	free(node);
	etcd_kick_block_event();
}

static void etcd_lock(uint64_t lock_id)
{
}

static void etcd_unlock(uint64_t lock_id)
{
}

static void delete_conn(void *arg)
{
	struct etcd_conn_ctx *conn = arg;

	etcd_conn_delete(conn);
}

static void *etcd_event_watcher(void *arg)
{
	struct etcd_ctx *ctx = arg;
	struct etcd_conn_ctx *conn = NULL;;
	struct etcd_kv_event ev;
	int64_t start_revision = 0;
	int ret;

	conn = etcd_conn_create(ctx);
	if (!conn) {
		pthread_exit(NULL);
	}
	pthread_cleanup_push(delete_conn, conn);

	memset(&ev, 0, sizeof(ev));
	ev.ev_revision = start_revision;
	ev.watch_cb = etcd_event_watch_cb;
	ev.watch_arg = conn->ctx;

	for (;;) {
		ret = etcd_kv_watch(conn, DEFAULT_BASE EV_ZNODE,
				    &ev, pthread_self());
		if (ret && ret != -ETIME)
			break;
	}
	if (ret && ret != -ETIME)
		fprintf(stderr, "%s: etcd_kv_watch failed with %d\n",
				__func__, ret);
	pthread_cleanup_pop(1);

	ret = pthread_detach(pthread_self());
	if (ret)
		sd_err("%s", strerror(ret));
	pthread_exit(NULL);
}

static void *etcd_lease_refresh(void *arg)
{
	struct etcd_ctx *ctx = arg;
	struct etcd_conn_ctx *conn = NULL;;
	int ret;

	conn = etcd_conn_create(ctx);
	if (!conn) {
		pthread_exit(NULL);
	}
	pthread_cleanup_push(delete_conn, conn);

	for (;;) {
		ret = etcd_lease_keepalive(ctx);
		if (ret < 0) {
			sd_err("%s: failed to refresh lease, error %d",
			       __func__, ret);
			break;
		}
		sleep(ctx->ttl / 2);
	}
	pthread_cleanup_pop(1);

	ret = pthread_detach(pthread_self());
	if (ret)
		sd_err("%s", strerror(ret));
	pthread_exit(NULL);
}

static int etcd_cluster_init(const char *option)
{
	char *hosts, *to, *p;
	sd_thread_t t;
	int ret;
	char addr[MAX_NODE_STR_LEN];

	if (!option) {
		sd_err("You must specify etcd client address.");
		return -1;
	}

	hosts = strtok((char *)option, "=");
	if ((to = strtok(NULL, "="))) {
		if (sscanf(to, "%u", &etcd_timeout) != 1) {
			sd_err("Invalid parameter for timeout");
			return -1;
		}
		p = strstr(hosts, "timeout");
		*--p = '\0';
	}
	pstrcpy(addr, MAX_NODE_STR_LEN, hosts);

	this_ctx = etcd_init(addr, NULL, etcd_timeout);
	if (!this_ctx) {
		sd_err("failed to initialize etcd '%s'", addr);
		return -1;
	}
	ret = etcd_lease_grant(this_ctx);
	if (ret < 0) {
		sd_err("no lease granted, error %d", ret);
		return -1;
	}
	ret = sd_thread_create("etcd-lease", &t, etcd_lease_refresh, this_ctx);
	if (ret) {
		sd_err("failed to start lease, error %d", ret);
		return -1;
	}
	sd_info("node %s addr %s id %s", this_ctx->node_name,
		addr, this_ctx->node_id);
	ret = sd_thread_create("etcd-watch", &t, etcd_event_watcher, this_ctx);
	if (ret) {
		sd_err("failed to start etcd, error %d", ret);
		return -1;
	}
	return 0;
}

static int etcd_update_node(struct sd_node *node)
{
	return SD_RES_NO_SUPPORT;
}

static struct cluster_driver cdrv_etcd = {
	.name       = "etcd",

	.init       = etcd_cluster_init,
	.join       = etcd_join,
	.leave      = etcd_leave,
	.notify     = etcd_notify,
	.block      = etcd_block,
	.unblock    = etcd_unblock,
	.lock         = etcd_lock,
	.unlock       = etcd_unlock,
	.update_node  = etcd_update_node,
	.get_local_addr = get_local_addr,
};

cdrv_register(cdrv_etcd);
