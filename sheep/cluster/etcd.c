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

const char *etcd_cinfo_status_names[] = {
	[SD_STATUS_OK] = "ok",
	[SD_STATUS_WAIT] = "wait",
	[SD_STATUS_SHUTDOWN] = "shutdown",
	[SD_STATUS_KILLED] = "killed",
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

static enum sd_status etcd_cinfo_status_to_type(const char *status_str)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(etcd_cinfo_status_names); i++) {
		if (!etcd_cinfo_status_names[i])
			continue;
		if (!strcmp(status_str, etcd_cinfo_status_names[i]))
			return i;
	}
	return 0;
}

static const char *etcd_cinfo_status_to_string(enum sd_status status)
{
	const char *status_str = NULL;

	if (status < ARRAY_SIZE(etcd_cinfo_status_names))
		status_str = etcd_cinfo_status_names[status];
	return status_str;
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

static int etcd_set_cinfo_status(struct etcd_ctx *ctx, const char *attr,
				 enum sd_status status)
{
	const char *status_str;
	char key[1024];
	size_t len;

	status_str = etcd_cinfo_status_to_string(status);
	if (!status_str)
		status_str = "unknown";
	len = strlen(status_str);
	snprintf(key, sizeof(key), DEFAULT_BASE CLUSTER_ZNODE "%s", attr);
	return etcd_kv_store(ctx, key, status_str, len);
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

	rc = etcd_set_cinfo_status(ctx, "status", cinfo->status);
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

		name = strrchr(kv->key, '/');
		name++;
		if (!strcmp(name, "status")) {
			cinfo->status = etcd_cinfo_status_to_type(kv->value);
			continue;
		}
		val = strtoul(kv->value, NULL, 10);
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
		else
			sd_warn("%s: invalid attribute '%s'",
				__func__, kv->key);
	}
	etcd_kv_free(kvs, num_kvs);
	return 0;
}

static void etcd_status_to_json(struct json_object *obj, enum sd_status status)
{
	const char *status_str = etcd_cinfo_status_to_string(status);

	if (!status_str)
		return;

	json_object_object_add(obj, "status",
			       json_object_new_string(status_str));
}

#define _SET_CINFO_VAL(o, c, n) \
	if ((c)->n) \
		json_object_object_add(o, #n,		\
			       json_object_new_int((c)->n))

static void etcd_cinfo_to_json(struct cluster_info *cinfo,
			       struct json_object *obj,
			       struct etcd_node *node)
{
	const char *default_store = (const char *)cinfo->default_store;
	struct json_object *cinfo_obj;

	cinfo_obj = json_object_new_object();
	_SET_CINFO_VAL(cinfo_obj, cinfo, proto_ver);
	if (cinfo->disable_recovery)
		json_object_object_add(cinfo_obj, "disable_recovery",
				       json_object_new_boolean(cinfo->disable_recovery));
	_SET_CINFO_VAL(cinfo_obj, cinfo, nr_nodes);
	_SET_CINFO_VAL(cinfo_obj, cinfo, epoch);
	if (cinfo->ctime)
		json_object_object_add(cinfo_obj, "ctime",
				       json_object_new_int64(cinfo->ctime));
	_SET_CINFO_VAL(cinfo_obj, cinfo, flags);
	_SET_CINFO_VAL(cinfo_obj, cinfo, nr_copies);
	_SET_CINFO_VAL(cinfo_obj, cinfo, copy_policy);
	_SET_CINFO_VAL(cinfo_obj, cinfo, block_size_shift);
	etcd_status_to_json(cinfo_obj, cinfo->status);
	if (strlen(default_store))
		json_object_object_add(cinfo_obj, "default_store",
				       json_object_new_string(default_store));
	json_object_object_add(obj, "cluster", cinfo_obj);
	if (node)
		json_object_object_add(obj, "node",
				       json_object_new_string(node->node_id));
}

static int etcd_json_to_cinfo(struct json_object *obj,
			      struct cluster_info *cinfo,
			      struct etcd_node *node)
{
	struct json_object_iterator itb, ite;
	struct json_object *cinfo_obj, *node_obj;
	int num_val = 0;

	cinfo_obj = json_object_object_get(obj, "cluster");
	if (!cinfo_obj) {
		sd_warn("%s: invalid json payload, 'cluster' missing",
			__func__);
		return 0;
	}
	itb = json_object_iter_begin(cinfo_obj);
	ite = json_object_iter_end(cinfo_obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "proto_ver"))
			cinfo->proto_ver = json_object_get_int(val_obj);
		else if (!strcmp(key, "disable_recovery"))
			cinfo->disable_recovery =
				json_object_get_boolean(val_obj);
		else if (!strcmp(key, "nr_nodes"))
			cinfo->nr_nodes = json_object_get_int(val_obj);
		else if (!strcmp(key, "epoch"))
			cinfo->epoch = json_object_get_int(val_obj);
		else if (!strcmp(key, "ctime"))
			cinfo->ctime = json_object_get_int64(val_obj);
		else if (!strcmp(key, "flags"))
			cinfo->flags = json_object_get_int(val_obj);
		else if (!strcmp(key, "nr_copies"))
			cinfo->nr_copies = json_object_get_int(val_obj);
		else if (!strcmp(key, "copy_policy"))
			cinfo->copy_policy = json_object_get_int(val_obj);
		else if (!strcmp(key, "block_size_shift"))
			cinfo->block_size_shift = json_object_get_int(val_obj);
		else if (!strcmp(key, "status")) {
			const char *status = json_object_get_string(val_obj);

			cinfo->status = etcd_cinfo_status_to_type(status);
		} else if (!strcmp(key, "default_store")) {
			strcpy((char *)cinfo->default_store,
			       json_object_get_string(val_obj));
		} else {
			sd_warn("%s: unhandled key '%s'", __func__, key);
			num_val--;
		}
		num_val++;
		json_object_iter_next(&itb);
	}
	node_obj = json_object_object_get(obj, "node");
	if (node && node_obj) {
		int ret;

		strcpy(node->node_id, json_object_get_string(node_obj));
		ret = etcd_node_download(node);
		if (ret < 0) {
			sd_warn("%s: failed to download '%s'",
				__func__, node->node_id);
		}
	}
	return num_val;
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
	sd_debug("%s: found %d entries for key '%s'",
		 __func__, num_kvs, key);
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
			sd_debug("%s: id %s num %d master %s",
				 __func__, id, num_nodes, master);
			if (num_nodes > 0 && !master)
				master = id;
			num_nodes++;
		}
	}
	if (master &&
	    !strncmp(master, node->node_id, strlen(node->node_id)))
		is_master = true;
	etcd_kv_free(kvs, num_kvs);
	return is_master;
}

static inline bool etcd_event_delete(struct etcd_node *node)
{
	char key[1024];

	snprintf(key, sizeof(key), DEFAULT_BASE EV_ZNODE "%s/",
		 node->node_id);
	return etcd_kv_delete(node->ctx, key);
}

static int etcd_update_event(struct etcd_ctx *ctx, enum etcd_event_type type,
			     const void *buf, size_t buf_len)
{
	char key[1024];
	const char *event;
	int rc;

	event = etcd_event_names[type];
	if (!event) {
		sd_warn("%s: invalid type %d", __func__, type);
		return -EINVAL;
	}
	snprintf(key, sizeof(key), DEFAULT_BASE EV_ZNODE "%s", event);

	rc = etcd_kv_store(ctx, key, buf, buf_len);
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
	struct json_object *cinfo_obj;
	const char *json_str;

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
	cinfo_obj = json_object_new_object();
	etcd_cinfo_to_json(cinfo, cinfo_obj, &this_node);
	json_str = json_object_to_json_string_ext(cinfo_obj,
						  JSON_C_TO_STRING_PLAIN);
	rc = etcd_update_event(this_ctx, EVENT_JOIN,
			       json_str, strlen(json_str));
	if (rc < 0) {
		etcd_node_delete(&this_node);
		memset(&this_node.node, 0, sizeof(this_node.node));
	}
	json_object_put(cinfo_obj);
	return rc;
}

static int etcd_leave(void)
{
	int rc;
	struct cluster_info cinfo;
	struct json_object *cinfo_obj;
	const char *json_str;

	sd_info("leaving from cluster");
	block_event_list_del(&this_node);
	etcd_cinfo_download(this_ctx, &cinfo);
	cinfo_obj = json_object_new_object();
	etcd_cinfo_to_json(&cinfo, cinfo_obj, &this_node);
	json_str = json_object_to_json_string_ext(cinfo_obj,
						  JSON_C_TO_STRING_PLAIN);
	rc = etcd_update_event(this_ctx, EVENT_LEAVE,
			       json_str, strlen(json_str));
	json_object_put(cinfo_obj);
	return rc;
}

static void etcd_vdi_to_json(struct sd_req *req, struct json_object *obj)
{
	json_object_object_add(obj, "vdi_size",
			       json_object_new_int64(req->vdi.vdi_size));
	json_object_object_add(obj, "base_vdi_id",
			       json_object_new_int(req->vdi.base_vdi_id));
	json_object_object_add(obj, "copies",
			       json_object_new_int(req->vdi.copies));
	json_object_object_add(obj, "copy_policy",
			       json_object_new_int(req->vdi.copy_policy));
	json_object_object_add(obj, "store_policy",
			       json_object_new_int(req->vdi.store_policy));
	json_object_object_add(obj, "block_size_shift",
			       json_object_new_int(req->vdi.block_size_shift));
	json_object_object_add(obj, "snapid",
			       json_object_new_int(req->vdi.snapid));
	json_object_object_add(obj, "type",
			       json_object_new_int(req->vdi.type));
}

static void etcd_cluster_to_json(struct sd_req *req, struct json_object *obj)
{
	json_object_object_add(obj, "oid",
			       json_object_new_int(req->cluster.oid));
	json_object_object_add(obj, "ctime",
			       json_object_new_int64(req->cluster.ctime));
	json_object_object_add(obj, "copies",
			      json_object_new_int(req->cluster.copies));
	json_object_object_add(obj, "copy_policy",
			      json_object_new_int(req->cluster.copy_policy));
	json_object_object_add(obj, "flags",
			       json_object_new_int(req->cluster.flags));
	json_object_object_add(obj, "tag",
			       json_object_new_int(req->cluster.tag));
	json_object_object_add(obj, "nodes_nr",
			       json_object_new_int(req->cluster.nodes_nr));
	json_object_object_add(obj, "block_size_shift",
			       json_object_new_int(req->cluster.block_size_shift));
}

static void etcd_obj_to_json(struct sd_req *req, struct json_object *obj)
{
	json_object_object_add(obj, "oid",
			       json_object_new_int(req->obj.oid));
	json_object_object_add(obj, "cow_oid",
			       json_object_new_int64(req->obj.cow_oid));
	json_object_object_add(obj, "copies",
			      json_object_new_int(req->obj.copies));
	json_object_object_add(obj, "copy_policy",
			      json_object_new_int(req->obj.copy_policy));
	json_object_object_add(obj, "ec_index",
			       json_object_new_int(req->obj.ec_index));
	json_object_object_add(obj, "tgt_epochj",
			       json_object_new_int(req->obj.tgt_epoch));
	json_object_object_add(obj, "offset",
			       json_object_new_int(req->obj.offset));
}

static void etcd_vdi_state_to_json(struct sd_req *req, struct json_object *obj)
{
	json_object_object_add(obj, "copies",
			       json_object_new_int(req->vdi_state.copies));
	json_object_object_add(obj, "copy_policy",
			       json_object_new_int(req->vdi_state.copy_policy));
}

static void etcd_msg_to_json(struct vdi_op_message *msg,
			     struct json_object *obj,
			     void *data, size_t data_len)
{
	struct sd_req *req = &msg->req;
	struct json_object *req_obj, *vdi_obj, *data_obj;
	struct sheepdog_vdi_attr *vdi_attr;
	uint32_t *vdi_id = (uint32_t *)data;
	struct sd_node *node;

	if (msg->req.data_length)
		json_object_object_add(obj, "data_length",
				       json_object_new_int(req->data_length));
	req_obj = json_object_new_object();
	json_object_object_add(req_obj, "proto_ver",
			       json_object_new_int(req->proto_ver));
	json_object_object_add(req_obj, "opcode",
			       json_object_new_int(req->opcode));
	json_object_object_add(req_obj, "flags",
			       json_object_new_int(req->flags));
	json_object_object_add(req_obj, "epoch",
			       json_object_new_int(req->epoch));
	json_object_object_add(req_obj, "id",
			       json_object_new_int(req->id));
	switch (req->opcode) {
	case SD_OP_NEW_VDI:
	case SD_OP_NOTIFY_VDI_ADD:
	case SD_OP_GET_VDI_INFO:
	case SD_OP_RELEASE_VDI:
		vdi_obj = json_object_new_object();
		etcd_vdi_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "vdi", vdi_obj);
		break;
	case SD_OP_DEL_VDI:
	case SD_OP_LOCK_VDI:
		data_obj = json_object_new_object();
		json_object_object_add(data_obj, "vdi_name",
				       json_object_new_string(data));
		json_object_object_add(obj, "data", data_obj);
		break;
	case SD_OP_MAKE_FS:
		vdi_obj = json_object_new_object();
		etcd_cluster_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "cluster", vdi_obj);
		data_obj = json_object_new_object();
		json_object_object_add(data_obj, "store_name",
				       json_object_new_string(data));
		json_object_object_add(obj, "data", data_obj);
		break;
	case SD_OP_GET_VDI_ATTR:
		vdi_attr = (struct sheepdog_vdi_attr *)data;
		vdi_obj = json_object_new_object();
		etcd_vdi_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "vdi", vdi_obj);
		vdi_obj = json_object_new_object();
		json_object_object_add(vdi_obj, "name",
				       json_object_new_string(vdi_attr->name));
		json_object_object_add(vdi_obj, "tag",
				       json_object_new_string(vdi_attr->tag));
		json_object_object_add(vdi_obj, "snap_id",
				       json_object_new_int(vdi_attr->snap_id));
		json_object_object_add(vdi_obj, "key",
				       json_object_new_string(vdi_attr->key));
		data_obj = json_object_new_object();
		json_object_object_add(data_obj, "vdi_attr", vdi_obj);
		json_object_object_add(obj, "data", data_obj);
		break;
	case SD_OP_NOTIFY_VDI_DEL:
		data_obj = json_object_new_object();
		json_object_object_add(data_obj, "vdi_id",
				       json_object_new_int(*vdi_id));
		json_object_object_add(req_obj, "data", data_obj);
		break;
	case SD_OP_DELETE_CACHE:
	case SD_OP_ALTER_CLUSTER_COPY:
		vdi_obj = json_object_new_object();
		etcd_cluster_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "cluster", vdi_obj);
		break;
	case SD_OP_COMPLETE_RECOVERY:
		vdi_obj = json_object_new_object();
		etcd_obj_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "obj", vdi_obj);
		node = (struct sd_node *)data;
		data_obj = json_object_new_object();
		json_object_object_add(data_obj, "node",
				       json_object_new_string(node_to_str(node)));
		json_object_object_add(obj, "data", data_obj);
		break;
	case SD_OP_ALTER_VDI_COPY:
		vdi_obj = json_object_new_object();
		etcd_vdi_state_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "vdi_state", vdi_obj);
		break;
	case SD_OP_INODE_COHERENCE:
		vdi_obj = json_object_new_object();
		json_object_object_add(vdi_obj, "vid",
				       json_object_new_int(req->inode_coherence.vid));
		json_object_object_add(vdi_obj, "validate",
				       json_object_new_int(req->inode_coherence.validate));
		json_object_object_add(req_obj, "inode_coherence",
				       vdi_obj);
		break;
	default:
		break;
	}
	json_object_object_add(obj, "req", req_obj);
}

static void etcd_json_to_vdi(struct json_object *obj,
			     struct sd_req *req)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "vdi_size")) {
			req->vdi.vdi_size =
				json_object_get_int64(val_obj);
		} else if (!strcmp(key, "base_vdi_id"))
			req->vdi.base_vdi_id =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "copies"))
			req->vdi.copies =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "copy_policy"))
			req->vdi.copy_policy =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "store_policy"))
			req->vdi.store_policy =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "block_size_shift"))
			req->vdi.block_size_shift =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "snapid"))
			req->vdi.snapid =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "type"))
			req->vdi.type =
				json_object_get_int(val_obj);
		else
			sd_warn("%s: unhandled vdi attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_cluster(struct json_object *obj,
				 struct sd_req *req)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "ctime")) {
			req->cluster.ctime =
				json_object_get_int64(val_obj);
		} else if (!strcmp(key, "oid"))
			req->cluster.oid =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "copies"))
			req->cluster.copies =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "copy_policy"))
			req->cluster.copy_policy =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "flags"))
			req->cluster.flags =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "tag"))
			req->cluster.tag =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "nodes_nr"))
			req->cluster.nodes_nr =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "block_size_shift"))
			req->cluster.block_size_shift =
				json_object_get_int(val_obj);
		else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_obj(struct json_object *obj,
			     struct sd_req *req)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "cow_oid")) {
			req->obj.cow_oid =
				json_object_get_int64(val_obj);
		} else if (!strcmp(key, "oid"))
			req->obj.oid =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "copies"))
			req->obj.copies =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "copy_policy"))
			req->obj.copy_policy =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "ec_index"))
			req->obj.ec_index =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "tgt_epoch"))
			req->obj.tgt_epoch =
				json_object_get_int(val_obj);
		else if (!strcmp(key, "offset"))
			req->obj.offset =
				json_object_get_int(val_obj);
		else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_req(struct json_object *obj,
			     struct sd_req *req)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);
		struct json_object *attr_obj;

		if (!strcmp(key, "vdi")) {
			etcd_json_to_vdi(val_obj, req);
		} else if (!strcmp(key, "cluster")) {
			etcd_json_to_cluster(val_obj, req);
		} else if (!strcmp(key, "obj")) {
			etcd_json_to_obj(val_obj, req);
		} else if (!strcmp(key, "vdi_state")) {
			attr_obj = json_object_object_get(val_obj, "copies");
			if (attr_obj)
				req->vdi_state.copies =
					json_object_get_int(attr_obj);
			attr_obj = json_object_object_get(val_obj, "copy_policy");
			if (attr_obj)
				req->vdi_state.copy_policy =
					json_object_get_int(attr_obj);
		} else if (!strcmp(key, "inode_coherence")) {
			attr_obj = json_object_object_get(val_obj, "vid");
			if (attr_obj)
				req->inode_coherence.vid =
					json_object_get_int(attr_obj);
			attr_obj = json_object_object_get(val_obj,
							  "validate");
			if (attr_obj)
				req->inode_coherence.validate =
					json_object_get_int(attr_obj);
		} else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_data(struct json_object *obj, void *data,
			      size_t data_length)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);
		struct json_object *attr_obj;

		if (!strcmp(key, "vdi_name") ||
		    !strcmp(key, "store_name")) {
			const char *val = json_object_get_string(val_obj);
			size_t data_len = strlen(val);;

			if (data_len > data_length) {
				sd_warn("%s: truncating data to %lu",
					__func__, data_length);
				data_len = data_length;
			}
			memcpy(data, val, data_len);
		} else if (!strcmp(key, "vdi_attr")) {
			struct sheepdog_vdi_attr *vdi_attr =
				(struct sheepdog_vdi_attr *)data;
			const char *val;

			if (data_length < sizeof(*vdi_attr)) {
				sd_warn("%s: invalid vdi_attr size",
					__func__);
				return;
			}
			attr_obj = json_object_object_get(val_obj, "name");
			if (attr_obj) {
				val = json_object_get_string(attr_obj);
				strcpy(vdi_attr->name, val);
			}
			attr_obj = json_object_object_get(val_obj, "tag");
			if (attr_obj) {
				val = json_object_get_string(attr_obj);
				strcpy(vdi_attr->tag, val);
			}
			attr_obj = json_object_object_get(val_obj, "snap_id");
			if (attr_obj) {
				vdi_attr->snap_id =
					json_object_get_int(attr_obj);
			}
			attr_obj = json_object_object_get(val_obj, "key");
			if (attr_obj) {
				val = json_object_get_string(attr_obj);
				strcpy(vdi_attr->key, val);
			}
		} else if (!strcmp(key, "vdi_id")) {
			uint32_t *id = (uint32_t *)data;

			*id = json_object_get_int(val_obj);
		} else if (!strcmp(key, "node")) {
			struct etcd_node tmp;
			const char *val = json_object_get_string(val_obj);
			struct sd_node *node;
			int ret;

			if (data_length < sizeof(*node)) {
				sd_warn("%s: invalde node data size",
					__func__);
				return;
			}
			strcpy(tmp.node_id, val);
			ret = etcd_node_download(&tmp);
			if (ret < 0) {
				sd_warn("%s: failed to download '%s'",
					__func__, tmp.node_id);
			} else {
				node = (struct sd_node *)data;
				memcpy(node, &tmp.node,
				       sizeof(*node));
			}
		} else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static struct vdi_op_message *etcd_json_to_msg(struct json_object *obj,
					       size_t *msg_len)
{
	struct vdi_op_message *msg;
	struct json_object *req_obj;
	struct json_object_iterator itb, ite;
	size_t data_len = 0;

	req_obj = json_object_object_get(obj, "data_length");
	if (req_obj)
		data_len = json_object_get_int(req_obj);
	msg = xzalloc(sizeof(*msg) + data_len);
	if (!msg)
		return NULL;
	*msg_len = sizeof(*msg) + data_len;
	msg->req.data_length = data_len;
	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "req")) {
			etcd_json_to_req(val_obj, &msg->req);
		} else if (!strcmp(key, "data")) {
			etcd_json_to_data(val_obj, &msg->data,
					  data_len);
		} else if (!strcmp(key, "proto_ver")) {
			msg->req.proto_ver =
				json_object_get_int(val_obj);
		} else if (!strcmp(key, "opcode")) {
			msg->req.opcode =
				json_object_get_int(val_obj);
		} else if (!strcmp(key, "flags")) {
			msg->req.flags =
				json_object_get_int(val_obj);
		} else if (!strcmp(key, "epoch")) {
			msg->req.epoch =
				json_object_get_int(val_obj);
		} else if (!strcmp(key, "id")) {
			msg->req.id =
				json_object_get_int(val_obj);
		} else if (!strcmp(key, "data_length"))
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
	return msg;
}

static int etcd_notify(void *msg, size_t msg_len)
{
	struct vdi_op_message *op = (struct vdi_op_message *)msg;
	struct json_object *obj;
	const char *json_str;
	int rc;

	obj = json_object_new_object();
	etcd_msg_to_json(op, obj, op->data, msg_len - sizeof(*op));
	json_object_object_add(obj, "node",
			       json_object_new_string(this_node.node_id));
	json_str = json_object_to_json_string_ext(obj,
						  JSON_C_TO_STRING_PLAIN);
	rc = etcd_update_event(this_ctx, EVENT_NOTIFY,
			       json_str, strlen(json_str));
	json_object_put(obj);
	return rc;
}

static int etcd_block(void)
{
	struct json_object *obj;
	const char *json_str;
	int rc;

	obj = json_object_new_object();
	json_object_object_add(obj, "node",
			       json_object_new_string(this_node.node_id));
	json_str = json_object_to_json_string_ext(obj,
						  JSON_C_TO_STRING_PLAIN);
	rc = etcd_update_event(this_ctx, EVENT_BLOCK,
			       json_str, strlen(json_str));
	json_object_put(obj);
	return rc;
}

static int etcd_unblock(void *msg, size_t msg_len)
{
	struct vdi_op_message *op = (struct vdi_op_message *)msg;
	struct json_object *obj;
	const char *json_str;
	int rc;

	obj = json_object_new_object();
	etcd_msg_to_json(op, obj, op->data, msg_len - sizeof(*op));
	json_str = json_object_to_json_string_ext(obj,
						  JSON_C_TO_STRING_PLAIN);
	rc = etcd_update_event(this_ctx, EVENT_UNBLOCK,
			       json_str, strlen(json_str));
	json_object_put(obj);
	return rc;
}

static void etcd_handle_join(struct etcd_ctx *ctx,
			     void *opaque, size_t opaque_len)
{
	struct json_object *obj;
	struct cluster_info cinfo;
	struct rb_root node_root, sd_root;
	struct etcd_node joining, *enode;
	int nr_nodes, ret;

	memset(&cinfo, 0, sizeof(cinfo));
	memset(&joining, 0, sizeof(joining));
	joining.ctx = ctx;
	obj = json_tokener_parse(opaque);
	ret = etcd_json_to_cinfo(obj, &cinfo, &joining);
	if (!ret) {
		sd_warn("%s: no elements parsed from opaque",
			__func__);
	}
	INIT_RB_ROOT(&node_root);
	if (!etcd_node_is_master(&this_node)) {
		/* Let's await master acking the join-request */
		sd_debug("%s: node '%s' is not master", __func__,
			 this_node.node_id);
		json_object_put(obj);
		return;
	}

	nr_nodes = etcd_build_node_list(ctx, &node_root, &joining);
	if (nr_nodes < 0) {
		sd_err("%s: failed to build node list", __func__);
		json_object_put(obj);
		return;
	}
	INIT_RB_ROOT(&sd_root);
	rb_for_each_entry(enode, &node_root, rb) {
		rb_insert(&sd_root, &enode->node, rb, node_cmp);
	}
	sd_debug("sender: %s", joining.node_id);
	if (sd_join_handler(&joining.node, &sd_root, nr_nodes, &cinfo)) {
		struct json_object *status_obj;
		const char *json_str;

		sd_debug("I'm the master now");
		status_obj = json_object_new_object();
		etcd_status_to_json(status_obj, cinfo.status);
		json_str = json_object_to_json_string_ext(status_obj,
							  JSON_C_TO_STRING_PLAIN);
		etcd_update_event(ctx, EVENT_ACCEPT,
				  json_str, strlen(json_str));
		json_object_put(status_obj);
	}
	rb_destroy(&node_root, struct etcd_node, rb);
	json_object_put(obj);
}

static void etcd_handle_leave(struct etcd_ctx *ctx,
			      void *opaque, int opaque_len)
{
	struct json_object *obj;
	struct cluster_info cinfo;
	struct rb_root node_root, sd_root;
	struct etcd_node *enode, leaving;
	int nr_nodes, ret;

	obj = json_tokener_parse(opaque);
	memset(&leaving, 0, sizeof(leaving));
	leaving.ctx = ctx;
	ret = etcd_json_to_cinfo(obj, &cinfo, &leaving);
	if (!ret) {
		sd_warn("%s: no elements parsed from opaque",
			__func__);
	}
	INIT_RB_ROOT(&node_root);
	nr_nodes = etcd_build_node_list(this_ctx, &node_root, NULL);
	if (nr_nodes < 0) {
		sd_err("%s: failed to build node list", __func__);
		return;
	}
	INIT_RB_ROOT(&sd_root);
	rb_for_each_entry(enode, &node_root, rb)
		rb_insert(&sd_root, &enode->node, rb, node_cmp);
	sd_leave_handler(&leaving.node, &sd_root, nr_nodes);
	rb_destroy(&node_root, struct etcd_node, rb);
	memset(&this_node.node, 0, sizeof(this_node.node));
}

static void etcd_handle_accept(struct etcd_ctx *ctx,
			       void *opaque, size_t opaque_len)
{
	struct rb_root node_root, sd_root;
	struct json_object *obj;
	struct etcd_node *enode, joining;
	struct cluster_info cinfo;
	int nr_nodes, ret;

	memset(&cinfo, 0, sizeof(cinfo));
	memset(&joining, 0, sizeof(joining));
	joining.ctx = ctx;
	obj = json_tokener_parse(opaque);
	ret = etcd_json_to_cinfo(obj, &cinfo, &joining);
	if (!ret) {
		sd_warn("%s: no elements parsed from opaque",
			__func__);
	}
	if (cinfo.status != SD_STATUS_OK) {
		const char *status_str =
			etcd_cinfo_status_to_string(cinfo.status);
		sd_warn("%s: ACCEPT failed, status %s (%d)",
			__func__, status_str, cinfo.status);
		json_object_put(obj);
		return;
	}
	INIT_RB_ROOT(&node_root);

	sd_debug("ACCEPT");
	nr_nodes = etcd_build_node_list(this_ctx, &node_root, &joining);
	if (nr_nodes < 0) {
		sd_err("%s: failed to build node list", __func__);
		json_object_put(obj);
		return;
	}
	INIT_RB_ROOT(&sd_root);
	rb_for_each_entry(enode, &node_root, rb)
		rb_insert(&sd_root, &enode->node, rb, node_cmp);

	etcd_cinfo_download(this_ctx, &cinfo);
	sd_accept_handler(&joining.node, &sd_root, nr_nodes, &cinfo);
	json_object_put(obj);
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

static void etcd_handle_block(struct etcd_ctx *ctx,
			      void *opaque, int opaque_len)
{
	struct etcd_node *block = xzalloc(sizeof(*block));
	struct json_object *obj, *node_obj;
	int ret;

	obj = json_tokener_parse(opaque);
	if (!obj) {
		sd_warn("%s: failed to parse opaque", __func__);
		return;
	}
	node_obj = json_object_object_get(obj, "node");
	if (!node_obj) {
		sd_warn("%s: failed to retrieve 'node' object", __func__);
		json_object_put(obj);
		return;
	}
	strcpy(block->node_id, json_object_get_string(node_obj));
	block->ctx = ctx;
	sd_debug("BLOCK %s", block->node_id);
	ret = etcd_node_download(block);
	if (ret < 0) {
		sd_warn("%s: failed to download '%s'",
			__func__, block->node_id);
		json_object_put(obj);
		return;
	}
	list_add_tail(&block->list, &etcd_block_list);
	block = list_first_entry(&etcd_block_list, typeof(*block), list);
	if (!block->callbacked)
		block->callbacked = sd_block_handler(&block->node);
	json_object_put(obj);
}

static void etcd_handle_unblock(struct etcd_ctx *ctx,
				void *opaque, size_t opaque_len)
{
	struct etcd_node *block;
	struct json_object *obj;
	struct vdi_op_message *msg;
	size_t msg_len = 0;

	sd_debug("UNBLOCK");
	obj = json_tokener_parse(opaque);
	if (!obj) {
		sd_warn("%s: failed to parse opaque", __func__);
		return;
	}
	msg = etcd_json_to_msg(obj, &msg_len);
	if (!msg) {
		sd_warn("%s: failed to deserialize json", __func__);
		json_object_put(obj);
		return;
	}
	if (list_empty(&etcd_block_list))
		return;
	block = list_first_entry(&etcd_block_list, typeof(*block), list);
	sd_notify_handler(&block->node, (void *)msg, msg_len);

	list_del(&block->list);
	free(block);
}

static void etcd_handle_notify(struct etcd_ctx *ctx,
			       void *opaque, size_t opaque_len)
{
	struct json_object *obj, *node_obj;
	struct etcd_node node;
	struct vdi_op_message *msg;
	size_t msg_len = 0;
	int ret;

	obj = json_tokener_parse(opaque);
	if (!obj) {
		sd_warn("%s: failed to parse opaque", __func__);
		return;
	}
	node_obj = json_object_object_get(obj, "node");
	if (!node_obj) {
		sd_warn("%s: failed to retrieve 'node' object", __func__);
		json_object_put(obj);
		return;
	}
	memset(&node, 0, sizeof(node));
	node.ctx = ctx;
	strcpy(node.node_id, json_object_get_string(node_obj));
	sd_debug("NOTIFY %s", node.node_id);
	ret = etcd_node_download(&node);
	if (ret < 0) {
		sd_warn("%s: failed to download '%s'",
			__func__, node.node_id);
		json_object_put(obj);
		return;
	}
	msg = etcd_json_to_msg(obj, &msg_len);
	if (!msg) {
		sd_warn("%s: failed to deserialize json", __func__);
		json_object_put(obj);
		return;
	}
	sd_notify_handler(&node.node, (void *)msg, msg_len);
	json_object_put(obj);
}

static void etcd_event_watch_cb(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	char *event;
	const char *base = DEFAULT_BASE EV_ZNODE;
	enum etcd_event_type type = EVENT_UPDATE_NODE;
	int i;

	if (strncmp(kv->key, base, strlen(base)))
		return;
	event = kv->key + strlen(base);
	if (!event)
		return;

	for (i = 0; i < ARRAY_SIZE(etcd_event_names); i++) {
		if (!etcd_event_names[i])
			continue;
		if (!strcmp(event, etcd_event_names[i])) {
			type = i;
			break;
		}
	}
	sd_debug("%s: event %s (%d) value '%s' deleted %d",
		 __func__, event, type, kv->value_len ? kv->value : "{}",
		kv->deleted);

	switch (type) {
	case EVENT_JOIN:
		etcd_handle_join(ctx, kv->value, kv->value_len);
		break;
	case EVENT_ACCEPT:
		etcd_handle_accept(ctx, kv->value, kv->value_len);
		break;
	case EVENT_LEAVE:
		etcd_handle_leave(ctx, kv->value, kv->value_len);
		break;
	case EVENT_BLOCK:
		etcd_handle_block(ctx, kv->value, kv->value_len);
		break;
	case EVENT_UNBLOCK:
		etcd_handle_unblock(ctx, kv->value, kv->value_len);
		break;
	case EVENT_NOTIFY:
		etcd_handle_notify(ctx, kv->value, kv->value_len);
		break;
	case EVENT_UPDATE_NODE:
		break;
	default:
		sd_err("invalid event '%s'", kv->key);
		return;
	}
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
		sd_warn("%s: etcd_kv_watch failed, error %d (%s)\n",
			__func__, ret, strerror(-ret));
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
