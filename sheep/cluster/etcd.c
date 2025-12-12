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

#define SESSION_TIMEOUT 30000		/* millisecond */

#define DEFAULT_BASE "sheepdog/"
#define QUEUE_ZNODE "queue/"
#define MEMBER_ZNODE "member/"
#define MASTER_ZNODE "master/"
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

struct etcd_node {
	struct list_node list;
	struct rb_node rb;
	struct etcd_ctx *ctx;
	struct sd_node node;
	bool callbacked;
	bool gone;
};

static struct rb_root etcd_node_root = RB_ROOT;
static LIST_HEAD(etcd_block_list);

static int etcd_node_cmp(const struct etcd_node *a, const struct etcd_node *b)
{
	return node_id_cmp(&a->node.nid, &b->node.nid);
}

static struct etcd_node this_node;
static struct etcd_ctx *this_ctx;

static inline bool etcd_node_exists(struct etcd_ctx *ctx, const char *node_id)
{
	char path[MAX_NODE_STR_LEN], val[MAX_NODE_STR_LEN];
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
	char key[MAX_NODE_STR_LEN];

	snprintf(key, sizeof(key),
		 DEFAULT_BASE MEMBER_ZNODE "%s",
		 node_to_str(&node->node));
	return etcd_kv_delete(node->ctx, key);
}

static inline int etcd_get_node_attr(struct etcd_node *node, const char *attr)
{
	char key[MAX_NODE_STR_LEN], val[MAX_NODE_STR_LEN], *eptr;
	unsigned long num;
	int rc, len;

	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/%s",
		 node_to_str(&node->node), attr);
	rc = etcd_kv_get(node->ctx, key, val, sizeof(val));
	if (rc < 0)
		return rc;
	if (!strcmp(attr, "addr")) {
		len = sizeof(node->node.nid.addr);
		if (rc < len)
			len = rc;
		memcpy(node->node.nid.addr, val, len);
		return 0;
	}
	if (!strcmp(attr, "io_addr")) {
		len = sizeof(node->node.nid.io_addr);
		if (rc < len)
			len = rc;
		memcpy(node->node.nid.io_addr, val, len);
		return 0;
	}
	errno = 0;
	num = strtoul(val, &eptr, 10);
	if (errno || val == eptr)
		return -ERANGE;
	if (!strcmp(attr, "zone"))
		node->node.zone = num;
	else if (!strcmp(attr, "nr_vnodes"))
		node->node.nr_vnodes = num;
	else if (!strcmp(attr, "space"))
		node->node.space = num;
	else if (!strcmp(attr, "port"))
		node->node.nid.port = num;
	else if (!strcmp(attr, "io_port"))
		node->node.nid.io_port = num;
	else
		return -EINVAL;
	return 0;
}

static int etcd_set_node_attr(struct etcd_node *node, const char *attr)
{
	char key[MAX_NODE_STR_LEN], val[MAX_NODE_STR_LEN];
	size_t len;

	if (!strcmp(attr, "nr_vnodes"))
		len = snprintf(val, sizeof(val), "%u", node->node.nr_vnodes);
	else if (!strcmp(attr, "zone"))
		len = snprintf(val, sizeof(val), "%u", node->node.zone);
	else if (!strcmp(attr, "space"))
		len = snprintf(val, sizeof(val), "%lu", node->node.space);
	else if (!strcmp(attr, "port"))
		len = snprintf(val, sizeof(val), "%u", node->node.nid.port);
	else if (!strcmp(attr, "io_port"))
		len = snprintf(val, sizeof(val), "%u", node->node.nid.io_port);
	else if (!strcmp(attr, "addr")) {
		len = sizeof(node->node.nid.addr);
		memcpy(val, node->node.nid.addr, len);
	} else if (!strcmp(attr, "io_addr")) {
		len = sizeof(node->node.nid.io_addr);
		memcpy(val, node->node.nid.io_addr, len);
	} else
		return -EINVAL;

	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/%s",
		node_to_str(&node->node), attr);
	return etcd_kv_store(node->ctx, key, val, len);
}

static inline bool etcd_node_upload(struct etcd_node *node, bool create)
{
	int rc;

	if (create && etcd_node_exists(node->ctx, node_to_str(&node->node)))
		return -EEXIST;
	rc = etcd_set_node_attr(node, "addr");
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "io_addr");
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "port");
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "io_port");
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "zone");
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "nr_vnodes");
	if (rc < 0)
		goto out_cleanup;
	rc = etcd_set_node_attr(node, "space");
	if (rc < 0)
		goto out_cleanup;
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

	attr = strrchr(kv->key, '/');
	if (!attr)
		return -EINVAL;
	len = kv->value_len;
	if (!strcmp(attr, "/addr")) {
		if (len > sizeof(node->node.nid.addr))
			len = sizeof(node->node.nid.addr);
		memcpy(node->node.nid.addr, kv->value, len);
		return 0;
	}
	if (!strcmp(attr, "/io_addr")) {
		if (len > sizeof(node->node.nid.io_addr))
			len = sizeof(node->node.nid.io_addr);
		memcpy(node->node.nid.io_addr, kv->value, len);
		return 0;
	}
		
	errno = 0;
	num = strtoul(kv->value, NULL, 10);
	if (errno)
		return -errno;
	if (!strcmp(attr, "/zone"))
		node->node.zone = num;
	else if (!strcmp(attr, "/nr_vnodes"))
		node->node.nr_vnodes = num;
	else if (!strcmp(attr, "/space"))
		node->node.space = num;
	else if (!strcmp(attr, "/port"))
		node->node.nid.port = num;
	else if (!strcmp(attr, "/io_port"))
		node->node.nid.io_port = num;
#ifdef HAVE_ACCELIO
	else if (!strcmp(attr, "/io_transport_type"))
		node->node.nid.io_transport_type = num;
#endif
	else
		return -EINVAL;
	return 0;
}

static inline int etcd_node_download(struct etcd_node *node,
				     const char *node_id_str)
{
	char key[MAX_NODE_STR_LEN];
	struct etcd_kv *kvs;
	int i, rc, num_kvs;

	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/",
		node_id_str);
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
	return 0;
}

static int etcd_build_node_list(struct etcd_ctx *ctx, struct rb_root *root)
{
	size_t num_kvs, node_nr = 0;
	struct etcd_node *node = NULL;
	char key[MAX_NODE_STR_LEN];
	char *cur_key = NULL;
	struct etcd_kv *kvs;
	int i, rc;

	strcpy(key, DEFAULT_BASE MEMBER_ZNODE);
	num_kvs = etcd_kv_range(ctx, key, &kvs);
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		char *k, *a;

		k = kv->key + strlen(DEFAULT_BASE MEMBER_ZNODE);
		a = strchr(k, '/');
		*a++ = '\0';
		if (!cur_key || !strcmp(k, cur_key)) {
			if (node)
				rb_insert(&etcd_node_root, node, rb,
					  etcd_node_cmp);
			node = xzalloc(sizeof(*node));
			cur_key = k;
			node_nr++;
		}
		rc = etcd_kv_to_node(kv, node);
		if (rc < 0) {
			etcd_kv_free(kvs, num_kvs);
			return rc;
		}
	}
	if (node)
		rb_insert(&etcd_node_root, node, rb,
			  etcd_node_cmp);
	sd_debug("%zu", node_nr);
	etcd_kv_free(kvs, num_kvs);
	return node_nr;
}

static inline int etcd_node_is_master(struct etcd_node *node)
{
	char key[MAX_NODE_STR_LEN], *master = NULL;;
	const char *id_str = node_to_str(&node->node);;
	struct etcd_kv *kvs;
	int i, num_kvs;

	strcpy(key, DEFAULT_BASE MEMBER_ZNODE);
	num_kvs = etcd_kv_range(node->ctx, key, &kvs);
	if (num_kvs < 0)
		return num_kvs;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		char *id = kv->key + strlen(key);

		if (i == 0 &&
		    !strncmp(id, id_str, strlen(id_str)))
			continue;
		master = id;
		break;
	}
	etcd_kv_free(kvs, num_kvs);
	if (!master)
		return false;
	return strncmp(master, id_str, strlen(id_str));
}

static inline int etcd_event_create(struct etcd_node *node)
{
	char prefix[MAX_NODE_STR_LEN], key[MAX_NODE_STR_LEN];
	int rc = 0, i;

	snprintf(prefix, sizeof(prefix), DEFAULT_BASE EV_ZNODE "%s/",
		 node_to_str(&node->node));
	for (i = 0; i < ARRAY_SIZE(etcd_event_names); i++) {
		strcpy(key, prefix);
		strcat(key, etcd_event_names[i]);
		rc = etcd_kv_store(node->ctx, key, NULL, 0);
		if (rc < 0) {
			etcd_kv_delete(node->ctx, prefix);
			break;
		}
	}
	return rc;
}

static inline bool etcd_event_delete(struct etcd_node *node)
{
	char key[MAX_NODE_STR_LEN];

	snprintf(key, sizeof(key), DEFAULT_BASE EV_ZNODE "%s/",
		 node_to_str(&node->node));
	return etcd_kv_delete(node->ctx, key);
}

static int etcd_update_event(enum etcd_event_type type, struct etcd_node *node,
			     void *buf, size_t buf_len)
{
	char key[MAX_NODE_STR_LEN];
	const char *event;
	int rc;

	event = etcd_event_names[type];
	snprintf(key, sizeof(key), DEFAULT_BASE EV_ZNODE "%s/%s",
		 node_to_str(&node->node), event);

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

	this_node.ctx = this_ctx;
	this_node.node = *myself;

	rc = etcd_event_create(&this_node);
	if (rc < 0) {
		sd_err("event creation failed");
		memset(&this_node.node, 0, sizeof(this_node.node));
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
	struct rb_root node_root;
	int nr_nodes;

	INIT_RB_ROOT(&node_root);
	if (!etcd_node_is_master(node)) {
		/* Let's await master acking the join-request */
		return;
	}

	nr_nodes = etcd_build_node_list(node->ctx, &node_root);
	sd_debug("sender: %s", node_to_str(&node->node));
	sd_join_handler(&node->node, &node_root, nr_nodes, opaque);

	sd_debug("I'm the master now");
	etcd_update_event(EVENT_ACCEPT, &this_node, NULL, 0);
}

static void etcd_handle_leave(struct etcd_node *node)
{
	struct rb_root node_root;
	int nr_nodes;

	INIT_RB_ROOT(&node_root);
	nr_nodes = etcd_build_node_list(node->ctx, &node_root);
	sd_leave_handler(&node->node, &node_root, nr_nodes);
	memset(&this_node.node, 0, sizeof(this_node.node));
}

static void etcd_handle_accept(struct etcd_node *node,
			       void *opaque, size_t opaque_len)
{
	struct rb_root node_root;
	int nr_nodes;

	INIT_RB_ROOT(&node_root);

	sd_debug("ACCEPT");
	nr_nodes = etcd_build_node_list(node->ctx, &node_root);
	sd_accept_handler(&this_node.node, &node_root, nr_nodes, opaque);
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

void etcd_watch_cb(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	struct etcd_node *node;
	char *key, *event;
	enum etcd_event_type type = EVENT_UPDATE_NODE;
	int rc, i;

	if (strcmp(kv->key, DEFAULT_BASE EV_ZNODE))
		return;
	key = kv->key + strlen(DEFAULT_BASE EV_ZNODE);
	event = strchr(key, '/');
	if (!event)
		return;
	*event++ = '\0';

	for (i = 0; i < ARRAY_SIZE(etcd_event_names); i++) {
		if (!strcmp(event, etcd_event_names[i])) {
			type = i;
			break;
		}
	}
	if (kv->deleted && type != EVENT_LEAVE)
		return;

	if (!etcd_node_exists(ctx, key))
		return;

	node = xzalloc(sizeof(*node));
	node->ctx = ctx;

	rc = etcd_node_download(node, key);
	if (rc < 0)
		return;
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

static int etcd_cluster_init(const char *option)
{
	char *hosts, *to, *p;
	struct etcd_conn_ctx *conn;
	struct etcd_kv_event ev;
	int ret;
	char addr[MAX_NODE_STR_LEN];
	bool stopped = false;

	if (!option) {
		sd_err("You must specify zookeeper servers.");
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

	this_ctx = etcd_init(addr, hosts, etcd_timeout);
	if (!this_ctx) {
		sd_err("failed to initialize etcd '%s'", addr);
		return -1;
	}
	sd_info("node %s addr %s id %s", this_ctx->node_name,
		addr, this_ctx->node_id);
	conn = etcd_conn_create(this_ctx);
	if (!conn)
		return -1;

	memset(&ev, 0, sizeof(ev));
	ev.ev_revision = 0;
	ev.watch_cb = etcd_watch_cb;
	ev.watch_arg = conn->ctx;

	while (!stopped) {
		ret = etcd_kv_watch(conn, DEFAULT_BASE EV_ZNODE, &ev, getpid());
		if (ret && ret != -EINTR)
			break;
	}
	etcd_conn_delete(conn);
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
