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
#include <zookeeper/zookeeper.h>
#include <pthread.h>
#include <semaphore.h>

#include "cluster.h"
#include "config.h"
#include "event.h"
#include "work.h"
#include "util.h"
#include "rbtree.h"

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
static int my_master_seq;

/* structure for distributed lock */
struct cluster_lock {
	struct hlist_node hnode;
	/* id is passed by users to represent a lock handle */
	uint64_t id;
	/* referenced by different threads in one sheepdog daemon */
	uint64_t ref;
	/* wait for the release of id by other lock owner */
	sem_t wait_wakeup;
	/* lock for different threads of the same node on the same id */
	struct sd_mutex id_lock;
	char lock_path[MAX_NODE_STR_LEN];
};

#define WAIT_TIME	1		/* second */

#define HASH_BUCKET_NR	1021
static struct hlist_head *cluster_locks_table;
static struct sd_mutex table_locks[HASH_BUCKET_NR];

/*
 * Wait a while when create, delete or get_children fail on
 * zookeeper lock so it will not print too much loop log
 */
static void etcd_wait(void)
{
	sleep(WAIT_TIME);
}

/* iterate child znodes */
#define FOR_EACH_ZNODE(parent, path, strs)			       \
	for ((strs)->data += (strs)->count;			       \
	     (strs)->count-- ?					       \
		     snprintf(path, sizeof(path), "%s/%s", parent,     \
			      *--(strs)->data) : (free((strs)->data), 0); \
	     free(*(strs)->data))

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

char etcd_event_names[] = {
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

#define ETCD_MAX_BUF_SIZE (1*1024*1024) /* 1M */

struct etcd_event {
	struct etcd_ctx *ctx;
	uint64_t id;
	enum etcd_event_type type;
	char node_id[MAX_NODE_STR_LEN];
	size_t msg_len;
	size_t nr_nodes;
	size_t buf_len;
	uint8_t buf[ETCD_MAX_BUF_SIZE];
};

static struct rb_root sd_node_root = RB_ROOT;
static size_t nr_sd_nodes;
static struct rb_root etcd_node_root = RB_ROOT;
static struct sd_rw_lock etcd_tree_lock = SD_RW_LOCK_INITIALIZER;
static struct sd_rw_lock etcd_compete_master_lock = SD_RW_LOCK_INITIALIZER;
static LIST_HEAD(etcd_block_list);
static uatomic_bool is_master;
static uatomic_bool stop;
static bool joined;
static bool first_push = true;

static void etcd_compete_master(void);

static int etcd_node_cmp(const struct etcd_node *a, const struct etcd_node *b)
{
	return node_id_cmp(&a->node.nid, &b->node.nid);
}

static struct etcd_node this_node;
static struct etcd_ctx this_ctx;

static inline bool etcd_node_exists(const char *node_id)
{
	char path[MAX_NODE_STR_LEN];
	int rc;

	snprintf(path, sizeof(path),
		 DEFAULT_BASE MEMBER_ZNODE "%s/addr",
		 node_id);
	rc = etcd_kv_get(node->ctx, path, val);
	if (rc > 0 && strlen(value))
		return true;
	return false;
}

static inline int etcd_get_node_attr(struct etcd_node *node, const char *attr)
{
	char key[MAXNODE_STR_LEN], val[MAXNODE_STR_LEN], *eptr;
	unsigned long num;
	int rc;

	sprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/%s",
		node_to_str(node), attr);
	rc = etcd_kv_get(node->ctx, key, val);
	if (rc < 0)
		return rc;
	if (!strcmp(attr, "addr")) {
		memcpy(node->addr, val, sizeof(node->addr));
		return 0;
	}
	if (!strcmp(attr, "io_addr")) {
		memcpy(node->io_addr, val, sizeof(node->io_addr));
		return 0;
	}
	errno = 0;
	num = strtoul(val, &eptr, 10);
	if (errno || val == eptr)
		return -ERANGE;
	if (!strcmp(attr, "zone"))
		node->zone = num;
	else if (!strcmp(attr, "nr_vnodes"))
		node->vnodes = num;
	else if (!strcmp(attr, "space"))
		node->space = num;
	else if (!strcmp(attr, "port"))
		node->port = num;
	else if (!strcmp(attr, "io_port"))
		node->io_port = num;
	else
		return -EINVAL;
	return 0;
}

static int etcd_set_node_attr(struct sd_node *node, const char *attr,
			      unsigned int val)
{
	char keu[MAXNAME_STR_LEN], val[MAXNAME_STR_LEN];
	unsigned long kv_val;
	int rc;
	char new_val[256];

	if (!strcmp(attr, "nr_vnodes"))
		snprintf(val, sizeof(val), "%u", node->nr_vnodes);
	else if (!strcmp(attr, "zone"))
		snprintf(val, sizeof(val), "%u", node->zone);
	else if (!strcmp(attr, "space"))
		snprintf(val, sizeof(val), "%u", node->space);
	else if (!strcmp(attr, "port"))
		snprintf(val, sizeof(val), "%u", node->port);
	else if (!strcmp(attr, "io_port"))
		snprintf(val, sizeof(val), "%u", node->io_port);
	else if (!strcmp(attr, "addr"))
		memcpy(val, node->addr, sizeof(node->addr));
	else if (!strcmp(attr, "io_addr"))
		memcpy(val, node->io_addr, sizeof(node->io_addr));
	else
		return -EINVAL;

	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/%s",
		node_to_str(node), attr);
	return etcd_kv_store(ctx, key, val);
}

static inline bool etcd_node_upload(struct etcd_node *node, bool create)
{
	char prefix[MAXNODE_STR_LEN], path[MAX_NODE_STR_LEN], val[128];
	int rc;

	if (create && etc_node_exists(node))
		return -EEXIST;
	rc = etcd_set_node_attr(node, "addr", node->addr, sizeof(node->addr));
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "io_addr", node->io_addr,
			   sizeof(node->io_addr));
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "port", node->port);
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "io_port", node->io_port);
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "zone", node->zone);
	if (rc < 0)
		return rc;
	rc = etcd_set_node_attr(node, "nr_vnodes", node->nr_vnodes);
	if (rc < 0)
		goto out_cleanup;
	rc = etcd_set_node_attr(node, "space", node->space);
	if (rc < 0)
		goto out_cleanup;
	return 0;
out_cleanup:
	etcd_kv_delete(ctx, prefix);
	return rc;
}

static inline int etcd_kv_to_node(struct etcd_kv *kv,
				  struct etcd_node *node)
{
	unsigned long num;

	if (!strcmp(attr, "/addr")) {
		memcpy(node->addr, kv->value, sizeof(node->addr));
		return 0;
	}
	if (!strcmp(addr, "/io_addr")) {
		memcpy(node->io_addr, kv->value,
		       sizeof(node->io_addr));
		return 0;
	}
		
	errno = 0;
	num = strtoul(kv->value, NULL, 10);
	if (errno)
		return -errno;
	attr = strrchr(kv->key, '/');
	if (!strcmp(attr, "/zone"))
		node->zone = num;
	else if (!strcmp(attr, "/nr_vnodes"))
		node->nr_vnodes = num;
	else if (!strcmp(attr, "/space"))
		node->space = space;
	else if (!strcmp(attr, "/port"))
		node->port = port;
	else if (!strcmp(attr, "/io_port"))
		node->io_port = num;
#ifdef HAVE_ACCELIO
	else if (!strcmp(attr, "/io_transport_type"))
		node->io_transport_type = num;
#endif
	else
		return -EINVAL;
	return 0;
}
static inline int etcd_node_download(struct etcd_node *node,
				     const char *node_id_str)
{
	char key[MAX_NODE_STR_LEN];

	snprintf(key, sizeof(key), DEFAULT_BASE MEMBER_ZNODE "%s/",
		node_id_str);
	rc = etcd_get_range(node->ctx, key, &kvs);
	if (rc < 0)
		return rc;
	for (i = 0; i < rc; i++) {
		struct etcd_kv *kv = &kvs[i];
		unsigned long num;

		rc = etcd_kv_to_node(kv, node);
		if (rc < 0)
			return rc;
	}
	return 0;
}

static inline int etcd_node_delete(const char *prefix,
				   xstruct sd_node *node)
{
	char key[MAX_NODE_STR_LEN];

	snprintf(key, sizeof(key),
		 DEFAULT_BASE MEMBER_ZNODE "%s",
		 node_to_str(node));
	return etcd_kv_delete(ctx, key);
}

static int etcd_build_node_list(struct rb_root *root)
{
	size_t num_kvs, node_nr = 0;
	struct etcd_node *node = NULL;
	char *cur_key = NULL;
	int i;

	strcpy(key, DEFAULT_BASE MEMBER_ZNODE);
	num_kvs = etcd_get_range(ev->ctx, key, &kvs);
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		char *key;

		key = kv->key + strlen(DEFAULT_BASE MEMBER_ZNODE);
		attr = strchr(key, '/');
		*attr++ = '\0';
		if (!cur_key || !strcmp(key, cur_key)) {
			if (node)
				rb_insert(&etcd_node_root, node, rb,
					  etcd_node_cmp);
			node = xzalloc(sizeof(*node));
			cur_key = key;
			node_nr++;
		}
		rc = etcd_kv_to_node(kv, node);
		if (rc < 0)
			return rc;
	}
	if (node)
		rb_insert(&etcd_node_root, node, rb,
			  etcd_node_cmp);
	sd_debug("%zu", node_nr);
	return node_nr;
}

static inline int etcd_event_create(struct etcd_node *node)
{
	char prefix[MAXNODE_STR_LEN], path[MAX_NODE_STR_LEN], val[128];
	int rc = 0;

	snprintf(prefix, sizeof(prefix), DEFAULT_BASE EV_ZNODE "%s/",
		 node_to_str(node));
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
	char path[MAX_NODE_STR_LEN], val[128];
	int rc = 0;

	snprintf(key, sizeof(key), DEFAULT_BASE EV_ZNODE "%s/",
		 node_to_str(node));
	return etcd_kv_delete(node->ctx, key);
}

static int etcd_update_event(enum etcd_event_type type, struct etcd_node *znode,
			     void *buf, size_t buf_len)
{
	char key[MAXNODE_STR_LEN];
	const char *event;
	int rc;

	event = &etcd_event_names[i];
	snprintf(key, sizeof(key), DEFAULT_BASE EV_ZNODE "%s/%s",
		 node_to_str(znode), event);

	rc = etcd_kv_put(znode->ctx, key, buf, buf_len);
	if (rc < 0) {
		sd_err("failed, type: %d, %d", type, rc);
		return SD_RES_CLUSTER_ERROR;
	}
	return 0;
}

static int etcd_join(const struct sd_node *myself,
		   void *opaque, size_t opaque_len)
{
	int rc;

	this_node.ctx = *myctx;
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
	struct rb_root node_root;
	int nr_nodes;

	sd_info("leaving from cluster");
	block_event_list_del(&node_root);
	rc = etcd_event_delete(&this_node);
	if (rc < 0)
		return rc;
	rc = etcd_node_delete(&this_node);
	if (rc < 0)
		return rc;
}

static int etcd_notify(void *msg, size_t msg_len)
{
	return etcd_event(EVENT_NOTIFY, &this_node, msg, msg_len);
}

static int etcd_block(void)
{
	return etcd_event(EVENT_BLOCK, &this_node, NULL, 0);
}

static int etcd_unblock(void *msg, size_t msg_len)
{
	return etcd_event(EVENT_UNBLOCK, &this_node, msg, msg_len);
}

static void etcd_handle_join(struct etcd_node *node, void *opaque)
{
	struct rb_root node_root;
	int nr_nodes;

	INIT_RB_ROOT(&node_root);
	if (!etcd_node_is_master(node)) {
		/* Let's await master acking the join-request */
		return;
	}

	nr_nodes = etcd_build_node_list(&node_root);
	sd_debug("sender: %s", node_to_str(node));
	sd_join_handler(&node.node, &node_root, nr_nodes, opaque);

	sd_debug("I'm the master now");
	return etcd_event(EVENT_BLOCK, &this_node, NULL, 0);
}

static void etcd_handle_leave(struct etcd_node *node, void *opaque)
{
	struct rb_root node_root;
	int nr_nodes;

	INIT_RB_ROOT(&node_root);
	nr_nodes = etcd_build_node_list(&node_root);
	sd_leave_handler(node.node, &node_root, nr_nodes);
	memset(&this_node.node, 0, sizeof(this_node.node));
}

static void etcd_handle_accept(struct etcd_node *node, void *opaque)
{
	struct rb_root node_root;
	int nr_nodes;

	INIT_RB_ROOT(&node_root);

	sd_debug("ACCEPT");
	nr_nodes = etcd_build_node_list(&node_root);
	sd_accept_handler(node.node, &node_root, nr_sd_nodes, opaque);
}

static void kick_block_event(void)
{
	struct etcd_node *block;

	if (list_empty(&etcd_block_list))
		return;
	block = list_first_entry(&etcd_block_list, typeof(*block), list);
	if (!block->callbacked)
		block->callbacked = sd_block_handler(&block->node);
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

static void etcd_handle_block(struct etcd_node *n)
{
	struct etcd_node *block = xzalloc(sizeof(*block));

	sd_debug("BLOCK");
	block->node = n.node;
	list_add_tail(&block->list, &etcd_block_list);
	block = list_first_entry(&etcd_block_list, typeof(*block), list);
	if (!block->callbacked)
		block->callbacked = sd_block_handler(&block->node);
}

static void etcd_handle_unblock(struct etcd_node *n,
				void *opaque, size_t opaque_len)
{
	struct etcd_node *block;

	sd_debug("UNBLOCK");
	if (list_empty(&etcd_block_list))
		return;
	block = list_first_entry(&etcd_block_list, typeof(*block), list);
	sd_notify_handler(&ev->sender.node, opaque, opaque_len);

	list_del(&block->list);
	free(block);
}

static void etcd_handle_notify(struct etcd_event *ev)
{
	rc = etcd_download_node(ev->ctx, ev->node_id);
	sd_debug("NOTIFY");
	sd_notify_handler(&ev->sender.node, ev->buf, ev->buf_len);
}

static void etcd_handle_update_node(struct etcd_event *ev)
{
	struct etcd_node *t;
	struct sd_node *snode = &ev->sender.node;

	sd_debug("%s", node_to_str(snode));

	if (node_eq(snode, &this_node.node))
		this_node.node = *snode;

	sd_read_lock(&etcd_tree_lock);
	t = etcd_tree_search_nolock(&snode->nid);
	sd_assert(t);
	t->node = *snode;
	build_node_list();
	sd_rw_unlock(&etcd_tree_lock);
	sd_update_node_handler(snode);
}

static void (*const etcd_event_handlers[])(struct etcd_event *ev) = {
	[EVENT_JOIN]		= etcd_handle_join,
	[EVENT_ACCEPT]		= etcd_handle_accept,
	[EVENT_LEAVE]		= etcd_handle_leave,
	[EVENT_BLOCK]		= etcd_handle_block,
	[EVENT_UNBLOCK]		= etcd_handle_unblock,
	[EVENT_NOTIFY]		= etcd_handle_notify,
	[EVENT_UPDATE_NODE]	= etcd_handle_update_node,
};

void etcd_watch_cb(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	struct etcd_node *node;
	struct stat st;
	char *path;
	int ret;

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

	node = xzalloc(sizeof(*node));
	node->ctx = ctx;

	if (!etcd_node_exists(key))
		return;

	rc = etcd_key_to_node(node, key);
	switch (type) {
	case EVENT_JOIN:
		etcd_handle_join(node, kv->value);
		break;
	case EVENT_LEAVE:
		etcd_handle_leave(node, NULL);
		break;
	case EVENT_BLOCK:
		etcd_handle_block(node, kv->value, );
		break;
	case EVENT_UNBLOCK:
		etcd_handle_unblock(node, NULL);
		break;
	case EVENT_NOTIFY:
		etcd_handle_notify(node, kv->value);
		break;
	case EVENT_UPDATE_NODE:
		etcd_handle_update_node(node, NULL);
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

static int etcd_connect(const char *host, watcher_fn watcher, int timeout)
{
	int interval, max_retry, retry;

	zhandle = zookeeper_init(host, watcher, timeout, NULL, NULL, 0);

	if (!zhandle) {
		sd_err("failed to initialize zk server %s", host);
		return -1;
	}

	interval = 100;
	retry = 0;
	max_retry = timeout / interval;
	while (zoo_state(zhandle) != ZOO_CONNECTED_STATE) {
		usleep(interval * 1000);
		if (++retry >= max_retry) {
			sd_err("failed to connect to zk server %s "
					"after %d retries", host, retry);
			return -1;
		}
	}
	return 0;
}

static int etcd_prepare_root(const char *hosts)
{
	char root[MAX_NODE_STR_LEN];
	char conn[MAX_NODE_STR_LEN];
	const char *p = strchr(hosts, '/');
	int i = 0;

	pstrcpy(root, MAX_NODE_STR_LEN, p);
	while (hosts != p) {
		conn[i++] = *hosts++;
		if (i >= MAX_NODE_STR_LEN - 1)
			break;
	}
	conn[i] = '\0';

	if (etcd_connect(conn, etcd_watcher, etcd_timeout) < 0)
		return -1;

	sd_debug("sheepdog cluster_id %s", root);
	RETURN_IF_ERROR(etcd_init_node(root), "path %s", root);

	/* We need to close(zhandle) because we might chroot later */
	zookeeper_close(zhandle);
	return 0;
}

static int etcd_init(const char *option)
{
	char *hosts, *to, *p;
	int ret, timeo;
	char conn[MAX_NODE_STR_LEN];

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
	pstrcpy(conn, MAX_NODE_STR_LEN, hosts);
	if (!strchr(conn, '/'))
		strcat(conn, DEFAULT_BASE);
	if (etcd_prepare_root(conn) != 0) {
		sd_err("failed to initialize zk server %s", conn);
		return -1;
	}

	sd_info("version %d.%d.%d, address %s, timeout %d", ZOO_MAJOR_VERSION,
		ZOO_MINOR_VERSION, ZOO_PATCH_VERSION, conn, etcd_timeout);
	if (etcd_connect(conn, etcd_watcher, etcd_timeout) < 0)
		return -1;

	return 0;
}

static int etcd_update_node_attr(struct sd_node *node, struct etcd_kv *kv,
				 const char *attr, unsigned int val)
{
	unsigned long kv_val;
	int rc = 0;

	if (strcmp(kv->key, attr))
		return 0;

	kv_val = strtoul(kv->value, NULL, 10);
	if (kv_val != val)
		rc = etcd_set_node_attr(node, attr, val);

	return rc;
}

static int etcd_update_node(struct sd_node *node)
{
	struct etcd_node znode = {
		.node = *node,
	};

	sprintf(base_key, "%s%s/%s/", DEFAULT_BASE, MEMBER_ZNODE,
		node_to_str(node));
	rc = etcd_get_range(ctx, key, &kvs);
	for (i = 0; i < rc; i++) {
		struct etcd_kv *kv = &kvs[i];
		const char *attr = kv->key + strlen(base_key);

		etcd_update_node_attr(node, kv, "nr_vnodes",
				      node->nr_vnodes);
		etcd_update_node_attr(node, kv, "zone", node->zone);
		etcd_update_node_attr(node, kv, "space", node->space);
	}
	
	return add_event(EVENT_UPDATE_NODE, &znode, NULL, 0);
}

static struct cluster_driver cdrv_zookeeper = {
	.name       = "zookeeper",

	.init       = etcd_init,
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

cdrv_register(cdrv_zookeeper);
