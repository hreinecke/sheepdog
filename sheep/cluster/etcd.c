/*
 * Copyright (C) 2025 Hannes Reinecke, SUSE
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <pthread.h>
#include <semaphore.h>

#include "cluster.h"
#include "config.h"
#include "event.h"
#include "work.h"
#include "util.h"
#include "rbtree.h"
#include "json.h"
#include "etcd_client.h"

#define SESSION_TIMEOUT 30		/* seconds */

#define DEFAULT_BASE "sheepdog/"
#define MEMBER_ZNODE "member/"
#define CLUSTER_ZNODE "cluster/"
#define LOCK_ZNODE "lock/"
#define SEQ_ZNODE "seq/"
#define EV_ZNODE "events"
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

const char *etcd_cinfo_status_names[] = {
	[SD_STATUS_INIT] = "init",
	[SD_STATUS_OK] = "ok",
	[SD_STATUS_WAIT] = "wait",
	[SD_STATUS_SHUTDOWN] = "shutdown",
	[SD_STATUS_KILLED] = "killed",
};

enum cinfo_attr_type {
	CINFO_ATTR_PROTO_VER = 1 << 0,
	CINFO_ATTR_DISABLE_RECOVERY = 1 << 1,
	CINFO_ATTR_NR_NODES = 1 << 2,
	CINFO_ATTR_EPOCH = 1 << 3,
	CINFO_ATTR_CTIME = 1 << 4,
	CINFO_ATTR_FLAGS = 1 << 5,
	CINFO_ATTR_NR_COPIES = 1 << 6,
	CINFO_ATTR_COPY_POLICY = 1 << 7,
	CINFO_ATTR_BSS = 1 << 8,
	CINFO_ATTR_DEFAULT_STORE = 1 << 9,
	CINFO_ATTR_STATUS = 1 << 10,
};

const char *etcd_cinfo_attr_names[] = {
	[CINFO_ATTR_PROTO_VER] = "proto_ver",
	[CINFO_ATTR_DISABLE_RECOVERY] = "disable_recovery",
	[CINFO_ATTR_NR_NODES] = "nr_nodes",
	[CINFO_ATTR_EPOCH] = "epoch",
	[CINFO_ATTR_CTIME] = "ctime",
	[CINFO_ATTR_FLAGS] = "flags",
	[CINFO_ATTR_NR_COPIES] = "nr_copies",
	[CINFO_ATTR_COPY_POLICY] = "copy_policy",
	[CINFO_ATTR_BSS] = "block_size_shift",
	[CINFO_ATTR_DEFAULT_STORE] = "default_store",
	[CINFO_ATTR_STATUS] = "status",
};

struct etcd_node {
	struct list_node list;
	struct rb_node rb;
	struct etcd_ctx *ctx;
	char node_id[MAX_NODE_STR_LEN];
	struct sd_node node;
	unsigned int attr_mask;
	bool callbacked;
};

struct etcd_cluster_info {
	uint8_t proto_ver;
	uint8_t disable_recovery;
	int16_t nr_nodes;
	uint32_t epoch;
	uint64_t ctime;
	uint16_t flags;
	uint8_t nr_copies;
	uint8_t copy_policy;
	enum sd_status status : 8;
	uint8_t block_size_shift;
	uint8_t default_store[STORE_LEN];
};

static struct sd_mutex etcd_block_mutex = SD_MUTEX_INITIALIZER;
static LIST_HEAD(etcd_block_list);
static struct rb_root etcd_node_root = RB_ROOT;
static struct etcd_cluster_info etcd_cinfo = {};

static int etcd_node_cmp(const struct etcd_node *a, const struct etcd_node *b)
{
	return strcmp(a->node_id, b->node_id);
}

static struct etcd_node this_node;
static struct etcd_ctx *this_ctx;

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

static int etcd_node_set_addr(struct etcd_node *node, const char *attr)
{
	char key[1024], val[MAX_NODE_STR_LEN];
	size_t len;

	if (!strcmp(attr, "addr")) {
		const char *addr = node_to_str(&node->node);

		strcpy(val, addr);
		len = strlen(val);
	} else if (!strcmp(attr, "io_addr")) {
		uint8_t empty_addr[16] = {};
		const char *addr = io_node_to_str(&node->node);

		if (!memcmp(node->node.nid.io_addr, empty_addr,
			   sizeof(empty_addr)))
			return 0;
		strcpy(val, addr);
		len = strlen(val);
#ifdef HAVE_ACCELIO
	} else if (!strcmp(attr, "io_transport_type")) {
		if (node->node.nid.io_transport_type == IO_TRANSPORT_TYPE_RDMA)
			strcpy(val, "rdma");
		else
			strcpy(val, "tcp");
		len = strlen(val);
#endif
	} else
		return -EINVAL;

	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/%s",
		node->node_id, attr);
	return etcd_kv_new(node->ctx, key, val, len);
}

#ifdef HAVE_DISKVNODES
static int etcd_node_disk_upload(struct etcd_node *node,
				 struct disk_info *di, int disk_num)
{
	char key[1024], val[MAX_NODE_STR_LEN];
	size_t len;
	int ret;

	len = snprintf(val, sizeof(val), "%" PRIu64, di->disk_id);
	snprintf(key, sizeof(key),
		 DEFAULT_BASE MEMBER_ZNODE "%s/disks/%d/disk_id",
		 node->node_id, disk_num);
	ret = etcd_kv_new(node->ctx, key, val, len);
	if (ret < 0)
		return ret;
	len = snprintf(val, sizeof(val), "%" PRIu64, di->disk_space);
	snprintf(key, sizeof(key),
		 DEFAULT_BASE MEMBER_ZNODE "%s/disks/%d/disk_space",
		 node->node_id, disk_num);
	return etcd_kv_new(node->ctx, key, val, len);
}
#endif

static inline bool etcd_node_upload(struct etcd_node *node, bool create)
{
	int rc, i;

	if (create && etcd_node_exists(node->ctx, node->node_id))
		return -EEXIST;
	rc = etcd_node_set_addr(node, "addr");
	if (rc) goto err;
	rc = etcd_node_set_addr(node, "io_addr");
	if (rc) goto err;
#ifdef HAVE_ACCELIO
	rc = etcd_node_set_addr(node, "io_transport_type");
	if (rc) goto err;
#endif
	rc = etcd_node_set_int_attr(node, "zone", node->node.zone);
	if (rc) goto err;
	rc = etcd_node_set_int_attr(node, "nr_vnodes",
				    node->node.nr_vnodes);
	if (rc) goto err;
	rc = etcd_node_set_int_attr(node, "nr_disks",
				    node->node.nr_disks);
	if (rc) goto err;
	rc = etcd_node_set_int_attr(node, "space",
				    node->node.space);
	if (rc) goto err;
#ifdef HAVE_DISKVNODES
	for (i = 0; i < node->node.nr_disks; i++) {
		struct disk_info *di = &node->node.disks[i];
		rc = etcd_node_disk_upload(node, di, i);
		if (rc < 0)
			goto err;
	}
#endif
	return 0;
err:
	etcd_node_delete(node);
	return rc;
}

static inline int etcd_kv_to_node(struct etcd_kv *kv,
				  struct etcd_node *node)
{
	char *attr;
	unsigned long num;
#ifdef HAVE_DISKVNODES
	struct disk_info *disk_info = NULL;
	char *disk;
	int ret, disk_num = -1;
#endif

	attr = strrchr(kv->key, '/');
	if (!attr) {
		sd_debug("skipping key '%s'", kv->key);
		return -EINVAL;
	}
	attr++;
	if (!strcmp(attr, "addr")) {
		str_to_node(kv->value, &node->node);
		return 0;
	}
	if (!strcmp(attr, "io_addr")) {
		str_to_io_node(kv->value, &node->node);
		return 0;
	}
#ifdef HAVE_ACCELIO
	if (!strcmp(attr, "io_transport_type")) {
		if (!strcmp(kv->value, "rdma"))
			node->node.nid.io_transport_type =
				IO_TRANSPORT_TYPE_RDMA;
		else if (!strcmp(kv->value, "tcp"))
			node->node.nid.io_transport_type =
				IO_TRANSPORT_TYPE_TCP;
		else
			sd_warn("invalid io transport type '%s'", kv->value);
		return 0;
	}
#endif
	errno = 0;
	num = strtoul(kv->value, NULL, 10);
	if (errno) {
		sd_debug("parsing error on '%s'", kv->value);
		return -errno;
	}
	if (!strcmp(attr, "zone"))
		node->node.zone = num;
	else if (!strcmp(attr, "nr_disks"))
		node->node.nr_disks = num;
	else if (!strcmp(attr, "nr_vnodes"))
		node->node.nr_vnodes = num;
	else if (!strcmp(attr, "space"))
		node->node.space = num;
#ifdef HAVE_DISKVNODES
	else if ((disk = strstr(kv->key, "disks"))) {
		ret = sscanf(disk, "disks/%u/%s", &disk_num, attr);
		if (ret != 2) {
			sd_debug("cannot parse '%s'", disk);
			return -EINVAL;
		}
		if (disk_num >= DISK_MAX)
			return -EINVAL;
		disk_info = &node->node.disks[disk_num];
		if (!strcmp(attr, "disk_id"))
			disk_info->disk_id = num;
		else if (!strcmp(attr, "disk_space"))
			disk_info->disk_space = num;
		else {
			sd_debug("unhandled disk addribute '%s'", attr);
			return -EINVAL;
		}
	}
#endif
	else {
		sd_debug("unhandled attribute '%s'", attr);
		return -EINVAL;
	}
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

static int etcd_set_cinfo_status(struct etcd_ctx *ctx, enum sd_status status)
{
	const char *attr = "status";
	const char *old_val, *new_val;
	char key[1024], cur_val[32];
	int rc;

	new_val = etcd_cinfo_status_to_string(status);
	if (!new_val) {
		sd_warn("invalid status '%d'", status);
		return -EINVAL;
	}
	old_val = etcd_cinfo_status_to_string(etcd_cinfo.status);
	if (!old_val) {
		sd_warn("invalid status '%d', setting to 'init'", status);
		old_val = "init";
	}
	switch(status) {
	case SD_STATUS_INIT:
		if (etcd_cinfo.status != status) {
			sd_warn("cannot move status from '%s' to '%s'",
				old_val, new_val);
			return -EINVAL;
		}
		break;
	case SD_STATUS_WAIT:
		if (etcd_cinfo.status != SD_STATUS_INIT &&
		    etcd_cinfo.status != status) {
			sd_warn("cannot move status from '%s' to '%s'",
				old_val, new_val);
			return -EINVAL;
		}
		break;
	case SD_STATUS_SHUTDOWN:
		if (etcd_cinfo.status == SD_STATUS_KILLED) {
			sd_warn("cannot move status from '%s' to '%s'",
				old_val, new_val);
			return -EINVAL;
		}
		break;
	case SD_STATUS_KILLED:
		if (etcd_cinfo.status == SD_STATUS_SHUTDOWN) {
			sd_warn("cannot move status from '%s' to '%s'",
				old_val, new_val);
			return -EINVAL;
		}
		break;
	default:
		break;
	}
	memset(cur_val, 0, sizeof(cur_val));
	snprintf(key, sizeof(key), DEFAULT_BASE CLUSTER_ZNODE "%s", attr);
	rc = etcd_kv_txn_update(ctx, key, old_val, new_val, cur_val);
	if (rc < 0) {
		sd_debug("failed to update '%s' from '%s' to '%s', error %d",
			 attr, old_val, new_val, -rc);
	} else if (!strlen(cur_val)) {
		sd_warn("update '%s' to '%s' failed, no value returned",
			attr, new_val);
		rc = -EINVAL;
	} else {
		etcd_cinfo.status = status;
	}
	return rc;
}

static int etcd_set_cinfo_attr(struct etcd_ctx *ctx, const char *attr,
			       unsigned long old_num, unsigned long new_num)
{
	char key[1024], cur_val[256], *new_val, *old_val;
	unsigned long val = old_num;
	int rc;

	rc = asprintf(&new_val, "%lu", new_num);
	if (rc <  0)
		return rc;
	rc = asprintf(&old_val, "%lu", old_num);
	if (rc < 0) {
		free(new_val);
		return rc;
	}
	memset(cur_val, 0, sizeof(cur_val));
	snprintf(key, sizeof(key), DEFAULT_BASE CLUSTER_ZNODE "%s", attr);
	rc = etcd_kv_txn_update(ctx, key, old_val, new_val, cur_val);
	if (rc < 0) {
		sd_debug("failed to update '%s' from '%s' to '%s', error %d",
			 attr, old_val, new_val, -rc);
		val = rc;
	} else if (!strlen(cur_val)) {
		sd_warn("update '%s' to '%s' failed, no value returned",
			attr, new_val);
		val = -EINVAL;
	} else {
		val = strtoul(cur_val, NULL, 10);
		if (val != new_num)
			sd_debug("value mismatch on '%s', '%s' should be '%s'",
				 attr, old_val, cur_val);
	}
			
	free(old_val);
	free(new_val);
	return val;
}

#define _UPDATE_CINFO(c, n, v)		\
	if (etcd_cinfo.v != (n)->v) {			\
		rc = etcd_set_cinfo_attr(c, #v, etcd_cinfo.v,	\
					 (n)->v);		\
		if (rc == 0)					\
			etcd_cinfo.v = (n)->v;			\
	}

static int etcd_cinfo_upload(struct etcd_ctx *ctx,
			     const struct cluster_info *cinfo)
{
	unsigned long rc = 0;

	_UPDATE_CINFO(ctx, cinfo, proto_ver);
	_UPDATE_CINFO(ctx, cinfo, disable_recovery);
	_UPDATE_CINFO(ctx, cinfo, nr_nodes);
	_UPDATE_CINFO(ctx, cinfo, epoch);
	_UPDATE_CINFO(ctx, cinfo, ctime);
	_UPDATE_CINFO(ctx, cinfo, flags);
	_UPDATE_CINFO(ctx, cinfo, nr_copies);
	_UPDATE_CINFO(ctx, cinfo, copy_policy);
	_UPDATE_CINFO(ctx, cinfo, block_size_shift);
	etcd_set_cinfo_status(ctx, cinfo->status);
	return rc;
}

#define UPDATE_CINFO_FROM_ETCD(c, a, k, v) \
	else if (!strcmp(k, #a)) (c)->a = v

static int etcd_cinfo_create(struct etcd_ctx *ctx)
{
	int rc = 0, num_kvs, i;
	char key[1024];
	struct etcd_kv *kvs;
	unsigned long attr_mask = -1;

	strcpy(key, DEFAULT_BASE CLUSTER_ZNODE);
	num_kvs = etcd_kv_range(ctx, key, &kvs);
	for (i = 0; i < num_kvs; i++) {
		const char *attr;
		unsigned long val;

		attr = strrchr(kvs[i].key, '/');
		if (!attr) {
			sd_warn("invalid key '%s'", kvs[i].key);
			continue;
		}
		attr++;
		if (!strcmp(attr, "default_store")) {
			if (kvs[i].value_len)
				strcpy((char *)etcd_cinfo.default_store,
				       kvs[i].value);
			continue;
		}
		if (!strcmp(attr, "status")) {
			enum sd_status status;
			status = etcd_cinfo_status_to_type(kvs[i].value);
			if (status)
				etcd_cinfo.status = status;
			continue;
		}
		val = strtoul(kvs[i].value, NULL, 10);

		if (!strcmp(attr, "proto_ver"))
			etcd_cinfo.proto_ver = val;
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, disable_recovery,
				       attr, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, nr_nodes, attr, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, epoch, attr, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, ctime, attr, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, flags, attr, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, nr_copies, attr, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, copy_policy, attr, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, block_size_shift,
				       attr, val);
		else
			sd_debug("unhandled attribute '%s'", attr + 1);
	}

	for (i = 0; i < ARRAY_SIZE(etcd_cinfo_attr_names); i++) {
		const char *n = etcd_cinfo_attr_names[i], *v;
		char val[128];

		if (!n)
			continue;
		if (!(attr_mask & i))
			continue;
		sprintf(key, DEFAULT_BASE CLUSTER_ZNODE "%s", n);
		val[0] = '\0';
		switch (i) {
		case CINFO_ATTR_PROTO_VER:
			sprintf(val, "%u", etcd_cinfo.proto_ver);
			break;
		case CINFO_ATTR_DISABLE_RECOVERY:
			sprintf(val, "%u", etcd_cinfo.disable_recovery);
			break;
		case CINFO_ATTR_NR_NODES:
			sprintf(val, "%u", etcd_cinfo.nr_nodes);
			break;
		case CINFO_ATTR_EPOCH:
			sprintf(val, "%u", etcd_cinfo.epoch);
			break;
		case CINFO_ATTR_CTIME:
			sprintf(val, "%lu", etcd_cinfo.ctime);
			break;
		case CINFO_ATTR_FLAGS:
			sprintf(val, "%u", etcd_cinfo.flags);
			break;
		case CINFO_ATTR_NR_COPIES:
			sprintf(val, "%u", etcd_cinfo.nr_copies);
			break;
		case CINFO_ATTR_COPY_POLICY:
			sprintf(val, "%u", etcd_cinfo.copy_policy);
			break;
		case CINFO_ATTR_BSS:
			sprintf(val, "%u", etcd_cinfo.block_size_shift);
			break;
		case CINFO_ATTR_DEFAULT_STORE:
			v = (const char *)etcd_cinfo.default_store;
			if (strlen(v))
				strcpy(val, v);
			break;
		case CINFO_ATTR_STATUS:
			v = etcd_cinfo_status_to_string(etcd_cinfo.status);
			if (!v || !strlen(v))
				v = "wait";
			strcpy(val, v);
			break;
		default:
			break;
		}
		if (strlen(val))
			rc = etcd_kv_store(ctx, key, val, strlen(val));
	}
	etcd_kv_free(kvs, num_kvs);
	return rc;
}

static void etcd_status_to_json(struct json_object *obj, enum sd_status status)
{
	const char *status_str = etcd_cinfo_status_to_string(status);

	if (!status_str)
		return;

	json_object_object_add(obj, "status",
			       json_object_new_string(status_str));
}

#define UPDATE_JSON_INT(o, c, n) \
	if ((c)->n)					\
		json_object_object_add(o, #n,		\
			json_object_new_int((c)->n))

static void etcd_cinfo_to_json(struct cluster_info *cinfo,
			       struct json_object *obj,
			       struct etcd_node *node)
{
	const char *default_store = (const char *)cinfo->default_store;
	struct json_object *cinfo_obj;

	cinfo_obj = json_object_new_object();
	UPDATE_JSON_INT(cinfo_obj, cinfo, proto_ver);
	if (cinfo->disable_recovery)
		json_object_object_add(cinfo_obj, "disable_recovery",
				       json_object_new_boolean(cinfo->disable_recovery));
	UPDATE_JSON_INT(cinfo_obj, cinfo, nr_nodes);
	UPDATE_JSON_INT(cinfo_obj, cinfo, epoch);
	if (cinfo->ctime)
		json_object_object_add(cinfo_obj, "ctime",
				       json_object_new_int64(cinfo->ctime));
	UPDATE_JSON_INT(cinfo_obj, cinfo, flags);
	UPDATE_JSON_INT(cinfo_obj, cinfo, nr_copies);
	UPDATE_JSON_INT(cinfo_obj, cinfo, copy_policy);
	UPDATE_JSON_INT(cinfo_obj, cinfo, block_size_shift);
	etcd_status_to_json(cinfo_obj, cinfo->status);
	if (strlen(default_store))
		json_object_object_add(cinfo_obj, "default_store",
				       json_object_new_string(default_store));

	nodes_to_json(cinfo->nodes, cinfo->nr_nodes, cinfo_obj);

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
		} else if (!strcmp(key, "nodes")) {
			int nr_nodes;
			json_to_nodes(val_obj, cinfo->nodes, &nr_nodes);
			cinfo->nr_nodes = nr_nodes;
		} else {
			sd_warn("%s: unhandled key '%s'", __func__, key);
			num_val--;
		}
		num_val++;
		json_object_iter_next(&itb);
	}
	sd_debug("cinfo proto_ver %d, flags %d, status %d",
		 cinfo->proto_ver, cinfo->flags, cinfo->status);
	node_obj = json_object_object_get(obj, "node");
	if (node && node_obj) {
		int ret;

		strcpy(node->node_id, json_object_get_string(node_obj));
		ret = etcd_node_download(node);
		if (ret < 0) {
			sd_warn("%s: failed to download '%s'",
				__func__, node->node_id);
		}
		sd_debug("node %s id %s",
			 node->node_id, node_to_str(&node->node));
	}
	return num_val;
}

static int etcd_build_node_list(struct etcd_ctx *ctx, struct rb_root *root)
{
	size_t num_kvs, nr_nodes = 0;
	struct etcd_node *node = NULL;
	char base[MAX_NODE_STR_LEN];
	struct etcd_kv *kvs;
	int node_size = sizeof(*node);
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
			node = xzalloc(node_size);
			strcpy(node->node_id, node_key.node_id);
			if (rb_insert(root, node, rb, etcd_node_cmp)) {
				sd_err("etcd node '%s' hash collision",
				       node_key.node_id);
			} else
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
	sd_debug("%zu nodes", nr_nodes);
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
		return is_master;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		char *id = kv->key + strlen(key), *attr;

		attr = strrchr(id, '/');
		*attr++ = '\0';
		if (attr && !strcmp(attr, "space")) {
			/*
			 * The master node is the node
			 * with the earliest creation date.
			 * If we only have one node there
			 * is no master.
			 */
			sd_debug("id %s num %d master %s",
				 id ? id : "<none>", num_nodes, master);
			if (!master)
				master = id;
			num_nodes++;
		}
	}
	if (master && !strcmp(master, node->node_id))
		is_master = true;
	if (!num_nodes)
		is_master = true;
	etcd_kv_free(kvs, num_kvs);
	return is_master;
}

static int etcd_update_event(struct etcd_ctx *ctx, enum etcd_event_type type,
			     struct json_object *obj)
{
	char key[1024];
	const char *event, *json_str;
	int rc;

	event = etcd_event_names[type];
	if (!event) {
		sd_warn("%s: invalid type %d", __func__, type);
		return SD_RES_CLUSTER_ERROR;
	}
	json_object_object_add(obj, "event",
			       json_object_new_string(event));
	json_str = json_object_to_json_string_ext(obj,
						  JSON_C_TO_STRING_PLAIN);
	strcpy(key, DEFAULT_BASE CLUSTER_ZNODE EV_ZNODE);

	rc = etcd_kv_store(ctx, key, json_str, strlen(json_str));
	if (rc < 0) {
		sd_err("%s: failed, event %s (%d), %d",
		       __func__, event, type, rc);
		return SD_RES_CLUSTER_ERROR;
	}
	return SD_RES_SUCCESS;
}

static void block_event_list_del(struct etcd_node *n)
{
	struct etcd_node *node;

	sd_mutex_lock(&etcd_block_mutex);
	list_for_each_entry(node, &etcd_block_list, list) {
		if (!node_eq(&node->node, &n->node))
			continue;
		list_del(&node->list);
		node->callbacked = false;
	}
	sd_mutex_unlock(&etcd_block_mutex);
}

static void etcd_vdi_to_json(struct sd_req *req, struct json_object *obj)
{
	json_object_object_add(obj, "vdi_size",
			       json_object_new_int64(req->vdi.vdi_size));
	UPDATE_JSON_INT(obj, &req->vdi, base_vdi_id);
	UPDATE_JSON_INT(obj, &req->vdi, copies);
	UPDATE_JSON_INT(obj, &req->vdi, copy_policy);
	UPDATE_JSON_INT(obj, &req->vdi, store_policy);
	UPDATE_JSON_INT(obj, &req->vdi, block_size_shift);
	UPDATE_JSON_INT(obj, &req->vdi, snapid);
	UPDATE_JSON_INT(obj, &req->vdi, type);
}

static void etcd_cluster_to_json(struct sd_req *req, struct json_object *obj)
{
	json_object_object_add(obj, "oid",
			       json_object_new_int64(req->cluster.oid));
	json_object_object_add(obj, "ctime",
			       json_object_new_int64(req->cluster.ctime));
	UPDATE_JSON_INT(obj, &req->cluster, copies);
	UPDATE_JSON_INT(obj, &req->cluster, copy_policy);
	UPDATE_JSON_INT(obj, &req->cluster, flags);
	UPDATE_JSON_INT(obj, &req->cluster, tag);
	UPDATE_JSON_INT(obj, &req->cluster, nodes_nr);
	UPDATE_JSON_INT(obj, &req->cluster, block_size_shift);
}

static void etcd_obj_to_json(struct sd_req *req, struct json_object *obj)
{
	json_object_object_add(obj, "oid",
			       json_object_new_int64(req->obj.oid));
	json_object_object_add(obj, "cow_oid",
			       json_object_new_int64(req->obj.cow_oid));
	UPDATE_JSON_INT(obj, &req->obj, copies);
	UPDATE_JSON_INT(obj, &req->obj, copy_policy);
	UPDATE_JSON_INT(obj, &req->obj, ec_index);
	UPDATE_JSON_INT(obj, &req->obj, tgt_epoch);
	UPDATE_JSON_INT(obj, &req->obj, offset);
}

static void etcd_vdi_state_to_json(struct sd_req *req, struct json_object *obj)
{
	UPDATE_JSON_INT(obj, &req->vdi_state, old_vid);
	UPDATE_JSON_INT(obj, &req->vdi_state, new_vid);
	UPDATE_JSON_INT(obj, &req->vdi_state, copies);
	if (req->vdi_state.set_bitmap)
		json_object_object_add(obj, "set_bitmap",
				       json_object_new_boolean(true));
	UPDATE_JSON_INT(obj, &req->vdi_state, copy_policy);
	UPDATE_JSON_INT(obj, &req->vdi_state, block_size_shift);
}

static int etcd_msg_to_json(struct vdi_op_message *msg,
			     struct json_object *obj,
			     void *data, size_t data_len)
{
	struct sd_req *req = &msg->req;
	struct sd_rsp *rsp = &msg->rsp;
	struct json_object *req_obj, *rsp_obj;
	struct json_object *vdi_obj, *data_obj, *node_obj;
	struct sheepdog_vdi_attr *vdi_attr;
	struct sd_node *node;

	req_obj = json_object_new_object();
	UPDATE_JSON_INT(req_obj, req, proto_ver);
	UPDATE_JSON_INT(req_obj, req, opcode);
	UPDATE_JSON_INT(req_obj, req, flags);
	UPDATE_JSON_INT(req_obj, req, epoch);
	UPDATE_JSON_INT(req_obj, req, id);
	UPDATE_JSON_INT(req_obj, req, data_length);
	switch (req->opcode) {
	case SD_OP_NEW_VDI:
		vdi_obj = json_object_new_object();
		etcd_vdi_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "vdi", vdi_obj);
		if (data_len) {
			data_obj = json_object_new_object();
			json_object_object_add(data_obj, "vdi_name",
					       json_object_new_string(data));
			json_object_object_add(obj, "data", data_obj);
		}
		break;
	case SD_OP_NOTIFY_VDI_ADD:
	case SD_OP_RELEASE_VDI:
		vdi_obj = json_object_new_object();
		etcd_vdi_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "vdi", vdi_obj);
		break;
	case SD_OP_GET_VDI_INFO:
	case SD_OP_DEL_VDI:
	case SD_OP_LOCK_VDI:
		if (data_len) {
			data_obj = json_object_new_object();
			json_object_object_add(data_obj, "vdi_name",
					       json_object_new_string(data));
			json_object_object_add(obj, "data", data_obj);
		}
		break;
	case SD_OP_MAKE_FS:
		vdi_obj = json_object_new_object();
		etcd_cluster_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "cluster", vdi_obj);
		if (data_len) {
			data_obj = json_object_new_object();
			json_object_object_add(data_obj, "store_name",
					       json_object_new_string(data));
			json_object_object_add(obj, "data", data_obj);
		}
		break;
	case SD_OP_GET_VDI_ATTR:
		if (data_len) {
			vdi_attr = (struct sheepdog_vdi_attr *)data;
			vdi_obj = json_object_new_object();
			etcd_vdi_to_json(&msg->req, vdi_obj);
			json_object_object_add(req_obj, "vdi", vdi_obj);
			vdi_obj = json_object_new_object();
			json_object_object_add(vdi_obj, "name",
					       json_object_new_string(vdi_attr->name));
			json_object_object_add(vdi_obj, "tag",
					       json_object_new_string(vdi_attr->tag));
			UPDATE_JSON_INT(vdi_obj, vdi_attr, snap_id);
			json_object_object_add(vdi_obj, "key",
					       json_object_new_string(vdi_attr->key));
			data_obj = json_object_new_object();
			json_object_object_add(data_obj, "vdi_attr", vdi_obj);
			json_object_object_add(obj, "data", data_obj);
		}
		break;
	case SD_OP_NOTIFY_VDI_DEL:
		if (data_len) {
			uint32_t *vdi_id = (uint32_t *)data;
			data_obj = json_object_new_object();
			json_object_object_add(data_obj, "vdi_id",
					       json_object_new_int(*vdi_id));
			json_object_object_add(req_obj, "data", data_obj);
		}
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
		if (data_len) {
			node = (struct sd_node *)data;
			data_obj = json_object_new_object();
			node_obj = json_object_new_object();
			node_to_json(node, node_obj);
			json_object_object_add(data_obj, "node", node_obj);
			json_object_object_add(obj, "data", data_obj);
		}
		break;
	case SD_OP_ALTER_VDI_COPY:
		vdi_obj = json_object_new_object();
		etcd_vdi_state_to_json(&msg->req, vdi_obj);
		json_object_object_add(req_obj, "vdi_state", vdi_obj);
		break;
	case SD_OP_INODE_COHERENCE:
		vdi_obj = json_object_new_object();
		UPDATE_JSON_INT(vdi_obj, &req->inode_coherence, vid);
		if (req->inode_coherence.validate)
			json_object_object_add(vdi_obj, "validate",
					       json_object_new_boolean(true));
		json_object_object_add(req_obj, "inode_coherence",
				       vdi_obj);
		break;
	case SD_OP_SHUTDOWN:
		break;
	case SD_OP_FORCE_RECOVER:
		break;
	case SD_OP_REWEIGHT:
		break;
	case SD_OP_ENABLE_RECOVER:
		break;
	case SD_OP_DISABLE_RECOVER:
	default:
		sd_warn("unhandled opcode %d", req->opcode);
		return SD_RES_INVALID_PARMS;
		break;
	}
	json_object_object_add(obj, "req", req_obj);

	rsp_obj = json_object_new_object();
	UPDATE_JSON_INT(rsp_obj, rsp, proto_ver);
	UPDATE_JSON_INT(rsp_obj, rsp, opcode);
	UPDATE_JSON_INT(rsp_obj, rsp, flags);
	UPDATE_JSON_INT(rsp_obj, rsp, epoch);
	UPDATE_JSON_INT(rsp_obj, rsp, id);
	UPDATE_JSON_INT(rsp_obj, rsp, data_length);
	UPDATE_JSON_INT(rsp_obj, rsp, result);

	switch (req->opcode) {
	case SD_OP_NEW_VDI:
	case SD_OP_DEL_VDI:
	case SD_OP_GET_VDI_INFO:
	case SD_OP_GET_VDI_ATTR:
	case SD_OP_LOCK_VDI:
		vdi_obj = json_object_new_object();
		UPDATE_JSON_INT(vdi_obj, &rsp->vdi, vdi_id);
		UPDATE_JSON_INT(vdi_obj, &rsp->vdi, attr_id);
		UPDATE_JSON_INT(vdi_obj, &rsp->vdi, copies);
		UPDATE_JSON_INT(vdi_obj, &rsp->vdi, block_size_shift);
		json_object_object_add(rsp_obj, "vdi", vdi_obj);
		break;
	default:
		break;
	}
	json_object_object_add(obj, "rsp", rsp_obj);

	return SD_RES_SUCCESS;
}

#define DEREF_JSON_INT(o, c, n, k)		\
	else if (!strcmp(k, #n)) (c)->n = json_object_get_int(o)

static void etcd_json_to_req_vdi(struct json_object *obj,
				 struct sd_req *req)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "vdi_size"))
			req->vdi.vdi_size =
				json_object_get_int64(val_obj);
		DEREF_JSON_INT(val_obj, &req->vdi, base_vdi_id, key);
		DEREF_JSON_INT(val_obj, &req->vdi, copies, key);
		DEREF_JSON_INT(val_obj, &req->vdi, copy_policy, key);
		DEREF_JSON_INT(val_obj, &req->vdi, store_policy, key);
		DEREF_JSON_INT(val_obj, &req->vdi, block_size_shift, key);
		DEREF_JSON_INT(val_obj, &req->vdi, snapid, key);
		DEREF_JSON_INT(val_obj, &req->vdi, type, key);
		else
			sd_warn("%s: unhandled vdi attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_rsp_vdi(struct json_object *obj,
				 struct sd_rsp *rsp)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "vdi_id"))
			rsp->vdi.vdi_id =
				json_object_get_int(val_obj);
		DEREF_JSON_INT(val_obj, &rsp->vdi, attr_id, key);
		DEREF_JSON_INT(val_obj, &rsp->vdi, copies, key);
		DEREF_JSON_INT(val_obj, &rsp->vdi, block_size_shift, key);
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
		DEREF_JSON_INT(val_obj, &req->cluster, copies, key);
		DEREF_JSON_INT(val_obj, &req->cluster, copy_policy, key);
		DEREF_JSON_INT(val_obj, &req->cluster, flags, key);
		DEREF_JSON_INT(val_obj, &req->cluster, tag, key);
		DEREF_JSON_INT(val_obj, &req->cluster, nodes_nr, key);
		DEREF_JSON_INT(val_obj, &req->cluster, block_size_shift, key);
		else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_req_obj(struct json_object *obj,
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
				json_object_get_int64(val_obj);
		DEREF_JSON_INT(val_obj, &req->obj, copies, key);
		DEREF_JSON_INT(val_obj, &req->obj, copy_policy, key);
		DEREF_JSON_INT(val_obj, &req->obj, ec_index, key);
		DEREF_JSON_INT(val_obj, &req->obj, tgt_epoch, key);
		DEREF_JSON_INT(val_obj, &req->obj, offset, key);
		else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_rsp_obj(struct json_object *obj,
				 struct sd_rsp *rsp)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "offset")) {
			rsp->obj.offset =
				json_object_get_int64(val_obj);
		} else if (!strcmp(key, "copies"))
			rsp->obj.copies =
				json_object_get_int(val_obj);
		else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_vdi_state(struct json_object *obj,
				   struct sd_req *req)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "set_bitmap")) {
			bool set_bitmap = json_object_get_boolean(val_obj);
			req->vdi_state.set_bitmap = set_bitmap;
		}
		DEREF_JSON_INT(val_obj, &req->vdi_state, old_vid, key);
		DEREF_JSON_INT(val_obj, &req->vdi_state, new_vid, key);
		DEREF_JSON_INT(val_obj, &req->vdi_state, copies, key);
		DEREF_JSON_INT(val_obj, &req->vdi_state, copy_policy, key);
		DEREF_JSON_INT(val_obj, &req->vdi_state, block_size_shift, key);
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
			etcd_json_to_req_vdi(val_obj, req);
		} else if (!strcmp(key, "cluster")) {
			etcd_json_to_cluster(val_obj, req);
		} else if (!strcmp(key, "obj")) {
			etcd_json_to_req_obj(val_obj, req);
		} else if (!strcmp(key, "vdi_state")) {
			etcd_json_to_vdi_state(val_obj, req);
		} else if (!strcmp(key, "inode_coherence")) {
			attr_obj = json_object_object_get(val_obj, "vid");
			if (attr_obj)
				req->inode_coherence.vid =
					json_object_get_int(attr_obj);
			attr_obj = json_object_object_get(val_obj,
							  "validate");
			if (attr_obj)
				req->inode_coherence.validate =
					json_object_get_boolean(attr_obj);
		} else if (!strcmp(key, "proto_ver")) {
			req->proto_ver = json_object_get_int(val_obj);
		} else if (!strcmp(key, "opcode")) {
			req->opcode = json_object_get_int(val_obj);
		} else if (!strcmp(key, "flags")) {
			req->flags = json_object_get_int(val_obj);
		} else if (!strcmp(key, "epoch")) {
			req->epoch = json_object_get_int(val_obj);
		} else if (!strcmp(key, "id")) {
			req->id = json_object_get_int(val_obj);
		} else if (strcmp(key, "data_length"))
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_rsp_node(struct json_object *obj,
				  struct sd_rsp *rsp)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "store_size")) {
			rsp->node.store_size =
				json_object_get_int64(val_obj);
		} else if (!strcmp(key, "store_free"))
			rsp->node.store_free =
				json_object_get_int(val_obj);
		DEREF_JSON_INT(val_obj, &rsp->node, nr_nodes, key);
		else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_rsp(struct json_object *obj,
			     struct sd_rsp *rsp)
{
	struct json_object_iterator itb, ite;

	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);
		struct json_object *val_obj = json_object_iter_peek_value(&itb);

		if (!strcmp(key, "vdi")) {
			etcd_json_to_rsp_vdi(val_obj, rsp);
		} else if (!strcmp(key, "obj")) {
			etcd_json_to_rsp_obj(val_obj, rsp);
		} else if (!strcmp(key, "node")) {
			etcd_json_to_rsp_node(val_obj, rsp);
		} else if (!strcmp(key, "proto_ver")) {
			rsp->proto_ver = json_object_get_int(val_obj);
		} else if (!strcmp(key, "opcode")) {
			rsp->opcode = json_object_get_int(val_obj);
		} else if (!strcmp(key, "flags")) {
			rsp->flags = json_object_get_int(val_obj);
		} else if (!strcmp(key, "epoch")) {
			rsp->epoch = json_object_get_int(val_obj);
		} else if (!strcmp(key, "id")) {
			rsp->id = json_object_get_int(val_obj);
		} else if (!strcmp(key, "data_length")) {
			rsp->data_length = json_object_get_int(val_obj);
		} else if (!strcmp(key, "result")) {
			rsp->result = json_object_get_int(val_obj);
		} else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static void etcd_json_to_data(struct etcd_ctx *ctx, struct json_object *obj,
			      void *data, size_t data_length)
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
			struct sd_node *node = (struct sd_node *)data;

			if (data_length < sizeof(*node)) {
				sd_warn("%s: invalde node data size",
					__func__);
				return;
			}
			memset(node, 0, sizeof(*node));
			json_to_node(val_obj, node);
		} else
			sd_warn("%s: unhandled attribute '%s'",
				__func__, key);
		json_object_iter_next(&itb);
	}
}

static struct vdi_op_message *etcd_json_to_msg(struct json_object *obj,
					       struct etcd_node *node,
					       size_t *msg_len)
{
	struct vdi_op_message *msg;
	struct json_object *req_obj, *rsp_obj, *val_obj;
	struct json_object_iterator itb, ite;
	size_t data_len = 0, req_data_len = 0, rsp_data_len = 0;
	int rsp_result = SD_RES_SUCCESS;

	req_obj = json_object_object_get(obj, "req");
	if (!req_obj) {
		sd_warn("no request element found");
		return NULL;
	}
	val_obj = json_object_object_get(req_obj, "data_length");
	if (val_obj)
		req_data_len = json_object_get_int(val_obj);

	rsp_obj = json_object_object_get(obj, "rsp");
	if (rsp_obj) {
		val_obj = json_object_object_get(rsp_obj,
						 "data_length");
		if (val_obj)
			rsp_data_len = json_object_get_int(val_obj);
		val_obj = json_object_object_get(rsp_obj, "result");
		if (val_obj)
			rsp_result = json_object_get_int(val_obj);
	}
	if (req_data_len)
		data_len = req_data_len;
	else
		data_len = rsp_data_len;

	msg = xzalloc(sizeof(*msg) + data_len);
	if (!msg)
		return NULL;
	*msg_len = sizeof(*msg) + data_len;
	if (req_data_len)
		msg->req.data_length = req_data_len;
	else
		msg->rsp.data_length = rsp_data_len;
	if (rsp_result != SD_RES_SUCCESS)
		msg->rsp.result = rsp_result;
	itb = json_object_iter_begin(obj);
	ite = json_object_iter_end(obj);

	while (!json_object_iter_equal(&itb, &ite)) {
		const char *key = json_object_iter_peek_name(&itb);

		val_obj = json_object_iter_peek_value(&itb);
		if (!strcmp(key, "req")) {
			etcd_json_to_req(val_obj, &msg->req);
		} else if (!strcmp(key, "rsp")) {
			etcd_json_to_rsp(val_obj, &msg->rsp);
		} else if (!strcmp(key, "data")) {
			etcd_json_to_data(this_ctx, val_obj, &msg->data,
					  data_len);
		} else if (!strcmp(key, "node")) {
			if (node)
				strcpy(node->node_id,
				       json_object_get_string(val_obj));
		} else if (strcmp(key, "rsp") && strcmp(key, "event"))
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
	int rc;

	obj = json_object_new_object();
	rc = etcd_msg_to_json(op, obj, op->data, msg_len - sizeof(*op));
	json_object_object_add(obj, "node",
			       json_object_new_string(this_node.node_id));
	if (rc == SD_RES_SUCCESS)
		rc = etcd_update_event(this_ctx, EVENT_NOTIFY, obj);
	json_object_put(obj);
	return rc;
}

static int etcd_block(void)
{
	struct json_object *obj;
	int rc;

	obj = json_object_new_object();
	json_object_object_add(obj, "node",
			       json_object_new_string(this_node.node_id));
	rc = etcd_update_event(this_ctx, EVENT_BLOCK, obj);
	json_object_put(obj);
	return rc;
}

static int etcd_unblock(void *msg, size_t msg_len)
{
	struct vdi_op_message *op = (struct vdi_op_message *)msg;
	struct json_object *obj;
	int rc;

	obj = json_object_new_object();
	rc = etcd_msg_to_json(op, obj, op->data, msg_len - sizeof(*op));
	json_object_object_add(obj, "node",
			       json_object_new_string(this_node.node_id));
	if (rc == SD_RES_SUCCESS)
		rc = etcd_update_event(this_ctx, EVENT_UNBLOCK, obj);
	json_object_put(obj);
	return rc;
}

static void etcd_handle_join(struct etcd_ctx *ctx,
			     struct json_object *obj)
{
	struct cluster_info cinfo;
	struct rb_root sd_root;
	struct etcd_node joining, *node;
	int nr_nodes = 0, ret;

	memset(&cinfo, 0, sizeof(cinfo));
	memset(&joining, 0, sizeof(joining));
	joining.ctx = ctx;
	rb_init_node(&joining.rb);
	ret = etcd_json_to_cinfo(obj, &cinfo, &joining);
	if (!ret) {
		sd_warn("%s: no elements parsed from opaque",
			__func__);
	}
	sd_debug("JOIN %s", joining.node_id);
	if (!etcd_node_is_master(&this_node)) {
		/* Let's await master acking the join-request */
		sd_debug("node '%s' is not master", this_node.node_id);
		return;
	}

	INIT_RB_ROOT(&sd_root);
	rb_for_each_entry(node, &etcd_node_root, rb) {
		rb_insert(&sd_root, &node->node, rb, node_cmp);
		nr_nodes++;
	}
	sd_debug("sender: %s, %d nodes", joining.node_id, nr_nodes);
	if (sd_join_handler(&joining.node, &sd_root, nr_nodes, &cinfo)) {
		struct json_object *cinfo_obj;

		sd_debug("node '%s' is master now, %d nodes, status %d",
			 this_node.node_id, nr_nodes, cinfo.status);
		cinfo_obj = json_object_new_object();
		etcd_cinfo_to_json(&cinfo, cinfo_obj, &joining);
		etcd_update_event(ctx, EVENT_ACCEPT, cinfo_obj);
		json_object_put(cinfo_obj);
	}
}

static void etcd_handle_leave(struct etcd_ctx *ctx,
			      struct json_object *obj)
{
	struct json_object *node_obj;
	struct rb_root sd_root;
	struct etcd_node *node, *sd_node, leaving;
	int nr_nodes = 0;

	node_obj = json_object_object_get(obj, "node");
	if (!node_obj) {
		sd_warn("node object not found");
		return;
	}

	memset(&leaving, 0, sizeof(leaving));
	strcpy(leaving.node_id, json_object_get_string(node_obj));
	leaving.ctx = ctx;
	rb_init_node(&leaving.rb);
	sd_debug("LEAVE %s", leaving.node_id);
	node = rb_search(&etcd_node_root, &leaving, rb, etcd_node_cmp);
	if (!node) {
		sd_warn("leaving node not registered");
		return;
	}
	rb_erase(&node->rb, &etcd_node_root);
	rb_init_node(&node->rb);
	if (!strcmp(node->node_id, this_node.node_id)) {
		sd_debug("deleting node '%s'", this_node.node_id);
		etcd_node_delete(&this_node);
	}

	INIT_RB_ROOT(&sd_root);
	rb_for_each_entry(sd_node, &etcd_node_root, rb) {
		rb_insert(&sd_root, &sd_node->node, rb, node_cmp);
		nr_nodes++;
	}
	sd_leave_handler(&node->node, &sd_root, nr_nodes);
}

static void etcd_handle_accept(struct etcd_ctx *ctx,
			       struct json_object *obj)
{
	struct rb_root sd_root;
	struct etcd_node *node, *joining;
	struct cluster_info cinfo;
	int nr_nodes = 0, ret;

	joining = xzalloc(sizeof(*joining));
	if (!joining) {
		sd_warn("failed to allocate joining node");
		return;
	}
	joining->ctx = ctx;
	rb_init_node(&joining->rb);
	memset(&cinfo, 0, sizeof(cinfo));
	ret = etcd_json_to_cinfo(obj, &cinfo, joining);
	if (!ret) {
		sd_warn("%s: no elements parsed from opaque",
			__func__);
	}
	if (rb_insert(&etcd_node_root, joining, rb, etcd_node_cmp)) {
		sd_warn("etcd node '%s' already present", joining->node_id);
	}

	INIT_RB_ROOT(&sd_root);
	rb_for_each_entry(node, &etcd_node_root, rb) {
		rb_insert(&sd_root, &node->node, rb, node_cmp);
		nr_nodes ++;
	}

	sd_debug("ACCEPT %s, %d nodes, status %d",
		 joining->node_id, nr_nodes, cinfo.status);

	sd_accept_handler(&joining->node, &sd_root, nr_nodes, &cinfo);
}

static void etcd_kick_block_event(void)
{
	struct etcd_node *block;

	sd_mutex_lock(&etcd_block_mutex);
	if (!list_empty(&etcd_block_list)) {
		block = list_first_entry(&etcd_block_list,
					 typeof(*block), list);
		if (!block->callbacked)
			block->callbacked = sd_block_handler(&block->node);
	}
	sd_mutex_unlock(&etcd_block_mutex);
}

static void etcd_handle_block(struct etcd_ctx *ctx,
			      struct json_object *obj)
{
	struct etcd_node block, *node;
	struct json_object *node_obj;

	node_obj = json_object_object_get(obj, "node");
	if (!node_obj) {
		sd_warn("%s: failed to retrieve 'node' object", __func__);
		return;
	}
	strcpy(block.node_id, json_object_get_string(node_obj));
	sd_debug("BLOCK %s", block.node_id);
	rb_init_node(&block.rb);
	node = rb_search(&etcd_node_root, &block, rb, etcd_node_cmp);
	if (!node) {
		sd_warn("blocking node not registered");
		return;
	}
	sd_mutex_lock(&etcd_block_mutex);
	list_add_tail(&node->list, &etcd_block_list);
	node = list_first_entry(&etcd_block_list, typeof(*node), list);
	if (!node->callbacked)
		node->callbacked = sd_block_handler(&node->node);
	sd_mutex_unlock(&etcd_block_mutex);
}

static void etcd_handle_unblock(struct etcd_ctx *ctx,
				struct json_object *obj)
{
	struct etcd_node unblock, *block;
	struct vdi_op_message *msg;
	size_t msg_len = 0;

	msg = etcd_json_to_msg(obj, &unblock, &msg_len);
	if (!msg) {
		sd_warn("%s: failed to deserialize json", __func__);
		return;
	}
	sd_debug("UNBLOCK %s", unblock.node_id);
	sd_mutex_lock(&etcd_block_mutex);
	if (!list_empty(&etcd_block_list)) {
		block = list_first_entry(&etcd_block_list,
					 typeof(*block), list);
		list_del(&block->list);
		block->callbacked = false;
		sd_notify_handler(&block->node, (void *)msg, msg_len);
	}
	sd_mutex_unlock(&etcd_block_mutex);
	free(msg);
}

static void etcd_handle_notify(struct etcd_ctx *ctx,
			       struct json_object *obj)
{
	struct etcd_node notify, *node;
	struct vdi_op_message *msg;
	size_t msg_len = 0;

	memset(&notify, 0, sizeof(notify));
	notify.ctx = ctx;
	rb_init_node(&notify.rb);
	msg = etcd_json_to_msg(obj, &notify, &msg_len);
	if (!msg) {
		sd_warn("%s: failed to deserialize json", __func__);
		return;
	}
	sd_debug("NOTIFY %s", notify.node_id);
	node = rb_search(&etcd_node_root, &notify, rb, etcd_node_cmp);
	if (!node) {
		sd_warn("notify node not registered");
		free(msg);
		return;
	}
	sd_notify_handler(&node->node, (void *)msg, msg_len);
	free(msg);
}

static void etcd_event_watch_cb(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	struct json_object *obj, *event_obj;
	const char *event;
	char *key;
	enum etcd_event_type type = EVENT_UPDATE_NODE;
	int i;

	key = strrchr(kv->key, '/');
	if (!key) {
		sd_debug("skipping updates to '%s'", kv->key);
		return;
	}
	key++;
	if (strcmp(key, EV_ZNODE)) {
		unsigned long val;

		if (!strcmp(key, "status")) {
			enum sd_status status;

			status = etcd_cinfo_status_to_type(kv->value);
			if (status) {
				sd_debug("update status to '%s' (%d)",
					 kv->value, status);
				etcd_cinfo.status = status;
			}
			return;
		}
		if (!strcmp(key, "default_store")) {
			if (kv->value_len)
				strcpy((char *)etcd_cinfo.default_store,
				       kv->value);
			return;
		}
		val = strtoul(kv->value, NULL, 10);
		if (!strcmp(key, "proto_ver"))
			etcd_cinfo.proto_ver = val;
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, disable_recovery,
				       key, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, nr_nodes, key, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, epoch, key, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, ctime, key, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, flags, key, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, nr_copies, key, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, copy_policy, key, val);
		UPDATE_CINFO_FROM_ETCD(&etcd_cinfo, block_size_shift,
				       key, val);
		else
			sd_debug("skipping updates to '%s'", key);
		return;
	}
	if (kv->value_len) {
		obj = json_tokener_parse(kv->value);
		if (!obj) {
			sd_warn("%s: failed to parse value", __func__);
			return;
		}
	} else {
		obj = json_object_new_object();
	}
	event_obj = json_object_object_get(obj, "event");
	if (!event_obj) {
		sd_warn("no event specified");
		json_object_put(obj);
		return;
	}
	event = json_object_get_string(event_obj);
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
	sd_debug("event %s (%d) value '%s' deleted %d created %lu mod %lu",
		 event, type, kv->value_len ? kv->value : "{}",
		 kv->deleted, kv->create_revision, kv->mod_revision);

	switch (type) {
	case EVENT_JOIN:
		etcd_handle_join(ctx, obj);
		break;
	case EVENT_ACCEPT:
		etcd_handle_accept(ctx, obj);
		break;
	case EVENT_LEAVE:
		etcd_handle_leave(ctx, obj);
		break;
	case EVENT_BLOCK:
		etcd_handle_block(ctx, obj);
		break;
	case EVENT_UNBLOCK:
		etcd_handle_unblock(ctx, obj);
		break;
	case EVENT_NOTIFY:
		etcd_handle_notify(ctx, obj);
		break;
	case EVENT_UPDATE_NODE:
		break;
	default:
		sd_err("invalid event '%s'", kv->key);
		return;
	}
	json_object_put(obj);
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
		ret = etcd_kv_watch(conn, DEFAULT_BASE CLUSTER_ZNODE,
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

static void etcd_lease_refresh(void *arg)
{
	int ret;

	if (etcd_cinfo.status == SD_STATUS_SHUTDOWN ||
	    etcd_cinfo.status == SD_STATUS_KILLED)
		return;

	sd_debug("%s: refresh lease\n", __func__);
	ret = etcd_lease_keepalive(this_ctx);
	if (ret < 0) {
		sd_err("%s: failed to refresh lease, error %d",
		       __func__, ret);
		return;
	}
	add_timer(arg, this_ctx->ttl * 500);
}

static int etcd_join(const struct sd_node *myself,
		     void *opaque, size_t opaque_len)
{
	int ret;
	struct cluster_info *cinfo = opaque;
	struct json_object *cinfo_obj;
	static sd_thread_t watch_thr;

	sd_info("node %s id %s", this_ctx->node_name, this_ctx->node_id);
	ret = sd_thread_create("etcd-watch", &watch_thr,
			       etcd_event_watcher, this_ctx);
	if (ret) {
		sd_err("failed to start etcd, error %d", ret);
		ret = -1;
	}

	cinfo->proto_ver = SD_SHEEP_PROTO_VER;

	etcd_build_node_list(this_ctx, &etcd_node_root);

	this_node.ctx = this_ctx;
	this_node.node = *myself;
	strcpy(this_node.node_id, this_ctx->node_name);
	ret = etcd_node_upload(&this_node, true);
	if (ret < 0) {
		if (ret == -EEXIST)
			sd_err("Previous etcd key exist, shoot myself. Please "
			       "wait for %d seconds to join me again.",
			       DIV_ROUND_UP(etcd_timeout, 1000));
		exit(1);
	}
	cinfo_obj = json_object_new_object();
	etcd_cinfo_to_json(cinfo, cinfo_obj, &this_node);
	ret = etcd_update_event(this_ctx, EVENT_JOIN, cinfo_obj);
	if (ret < 0) {
		etcd_node_delete(&this_node);
		memset(&this_node.node, 0, sizeof(this_node.node));
	}
	json_object_put(cinfo_obj);
	return ret;
}

static int etcd_leave(void)
{
	int rc;
	struct json_object *node_obj;

	sd_info("leaving from cluster");
	node_obj = json_object_new_object();
	json_object_object_add(node_obj, "node",
			       json_object_new_string(this_node.node_id));
	block_event_list_del(&this_node);
	rc = etcd_update_event(this_ctx, EVENT_LEAVE, node_obj);
	json_object_put(node_obj);
	return rc;
}

static int etcd_cluster_init(const char *option)
{
	char *hosts, *to, *p;
	int ret = 0;
	char *addr = NULL;
	static struct timer t = {
		.callback = etcd_lease_refresh,
		.data = &t,
	};

	if (!option) {
		sd_err("You must specify etcd client address.");
		return -1;
	}

	if (option) {
		hosts = strtok((char *)option, "=");
		if ((to = strtok(NULL, "="))) {
			if (sscanf(to, "%u", &etcd_timeout) != 1) {
				sd_err("Invalid parameter for timeout");
				return -1;
			}
			p = strstr(hosts, "timeout");
			*--p = '\0';
		}
		addr = strdup(hosts);
	}
	this_ctx = etcd_init(addr, NULL, etcd_timeout);
	if (!this_ctx) {
		sd_err("failed to initialize etcd '%s'",
		       addr ? addr: "localhost");
		ret = -1;
		goto out;
	}

	ret = etcd_lease_grant(this_ctx);
	if (ret < 0) {
		sd_err("no lease granted, error %d", ret);
		goto out;
	}
	add_timer(&t, this_ctx->ttl * 500);

	etcd_cinfo_create(this_ctx);

out:
	if (addr)
		free(addr);
	return ret < 0 ? ret : 0;
}

static int etcd_update_node(struct sd_node *node)
{
	return SD_RES_NO_SUPPORT;
}

static int etcd_get_local_addr(uint8_t *bytes)
{
	char port[16];
	struct addrinfo hints, *ai, *aip;
	int ret;

	sprintf(port, "%d", this_ctx->port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	sd_debug("resolving %s:%d", this_ctx->host, this_ctx->port);
	ret = getaddrinfo(this_ctx->host, port, &hints, &ai);
	if (ret != 0) {
		sd_warn("getaddrinfo on %s:%d failed: %s",
			this_ctx->host, this_ctx->port, gai_strerror(ret));
		return -EINVAL;
	}
	if (!ai) {
		sd_warn("no results from getaddrinfo()");
		return -EHOSTUNREACH;
	}
	for (aip = ai; aip != NULL; aip = aip->ai_next) {
		struct sockaddr_in *sin;

		if (aip->ai_family != AF_INET)
			continue;
		sin = (struct sockaddr_in *)aip->ai_addr;
		memset(bytes, 0, 12);
		memcpy(bytes + 12, &sin->sin_addr, 4);
		break;
	}
	freeaddrinfo(ai);
	return 0;
}

static int etcd_update_status(enum sd_status status)
{
	int ret;

	if (!this_ctx)
		return SD_RES_STARTUP;
	ret = etcd_set_cinfo_status(this_ctx, status);
	if (ret)
		return SD_RES_CLUSTER_ERROR;
	return SD_RES_SUCCESS;
}

static int etcd_update_cinfo(const struct cluster_info *cinfo)
{
	int ret;

	if (!this_ctx)
		return SD_RES_STARTUP;
	ret = etcd_cinfo_upload(this_ctx, cinfo);
	if (ret)
		return SD_RES_CLUSTER_ERROR;
	return SD_RES_SUCCESS;
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
	.get_local_addr = etcd_get_local_addr,
	.update_status = etcd_update_status,
	.update_cluster = etcd_update_cinfo,
};

cdrv_register(cdrv_etcd);
