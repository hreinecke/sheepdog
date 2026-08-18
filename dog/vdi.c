/*
 * Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <search.h>
#include <uuid/uuid.h>

#include "dog.h"
#include "treeview.h"
#include "sha1.h"
#include "fec.h"
#include "json.h"

struct rb_root oid_tree = RB_ROOT;

static struct json_object *out_obj;

#define NR_BATCHED_RECLAMATION_DEFAULT 128

static struct sd_option vdi_options[] = {
	{'P', "prealloc", false, "preallocate all the data objects"},
	{'n', "no-share", false, "share nothing with its parent"},
	{'i', "index", true, "specify the index of data objects"},
	{'s', "snapshot", true, "specify a snapshot id or tag name"},
	{'x', "exclusive", false, "write in an exclusive mode"},
	{'d', "delete", false, "delete a key"},
	{'w', "writeback", false, "use writeback mode"},
	{'c', "copies", true, "specify the data redundancy level"},
	{'F', "from", true, "create a differential backup from the snapshot"},
	{'f', "force", false, "do operation forcibly"},
	{'y', "hyper", false, "create a hyper volume"},
	{'o', "oid", true, "specify the object id of the tracking object"},
	{'e', "exist", false, "only check objects exist or not,\n"
	 "                          neither comparing nor repairing"},
	{'z', "block_size_shift", true, "specify the bit shift num for"
			       " data object size"},
	{'R', "reduce-identical-snapshots", false, "do not create snapshot if "
	 "working VDI doesn't have its own objects"},
	{'B', "nr-batched-reclamation", true, "specify a number of batched"
	 "reclamation during VDI deletion"},
	{'I', "reclamation-interval", true, "specify how long (unit: second)"
	 "in reclamation loop during VDI deletion"},
	{'m', "max-reclaim", true, "specify the maximum number of reclaimed objects "
	 "(if this option is specified, an inode object won't be reclaimed)"},
	{'A', "acl", true, "specify the ACL for accessing the VDI"},
	{'O', "owner", true, "specify the owner of the VDI lock as\n"
	 "                          <address>[:<port>] instead of the node the\n"
	 "                          request is sent to"},
	{ 0, NULL, false, NULL },
};

static struct vdi_cmd_data {
	uint64_t index;
	int snapshot_id;
	char snapshot_tag[SD_MAX_VDI_TAG_LEN];
	bool exclusive;
	bool delete;
	bool prealloc;
	int nr_copies;
	uint8_t block_size_shift;
	bool writeback;
	int from_snapshot_id;
	char from_snapshot_tag[SD_MAX_VDI_TAG_LEN];
	bool force;
	uint8_t copy_policy;
	uint8_t store_policy;
	uint64_t oid;
	bool no_share;
	bool exist;
	bool reduce_identical_snapshots;
	bool acl_vdi;
	int nr_batched_reclamation;
	int reclamation_interval;
	int nr_max_reclaim;
	char acl_name[SD_MAX_VDI_LEN];
	struct node_id owner;
} vdi_cmd_data = { ~0, };

/*
 * Resolve an ACL name to the id the sheeps know it by, complaining in the same
 * terms as 'dog acl' about the two ways this can go wrong.
 */
static int lookup_acl_name(const char *aclname, uint32_t *acl_id)
{
	int ret = find_acl_name(aclname, acl_id);

	if (ret == SD_RES_INVALID_PARMS)
		sd_err("%s is not an ACL", aclname);
	else if (ret != SD_RES_SUCCESS)
		sd_err("Failed to open ACL %s: %s", aclname, sd_strerror(ret));

	return ret;
}

static uint32_t vdi_acl_id(void)
{
	uint32_t acl_id;

	if (!strlen(vdi_cmd_data.acl_name))
		return LOCK_TYPE_NORMAL;
	if (!strcmp(vdi_cmd_data.acl_name, "shared"))
		return LOCK_TYPE_SHARED;
	if (!strcmp(vdi_cmd_data.acl_name, "any"))
		return LOCK_TYPE_ANY;

	if (lookup_acl_name(vdi_cmd_data.acl_name, &acl_id) != SD_RES_SUCCESS)
		exit(EXIT_FAILURE);
	return acl_id;
}

/* The ACL '-A' was given as, for the messages which name it back */
static const char *acl_option_name(void)
{
	if (strlen(vdi_cmd_data.acl_name))
		return vdi_cmd_data.acl_name;

	return "none";
}

static int parse_vdi_address(const char *opt, struct node_id *owner)
{
	int port = SD_LISTEN_PORT;
	char addr[MAX_NODE_STR_LEN], *p, *e = NULL;

	if (!opt)
		goto invalid;
	if (strlen(opt) >= MAX_NODE_STR_LEN)
		goto invalid;
	if (opt[0] == '[') {
		strcpy(addr, opt + 1);
		p = strchr(addr, ']');
		if (!p)
			goto invalid;
		*p = '\0';
		p++;
		p = strchr(p, ':');
	} else {
		strcpy(addr, opt);
		p = strchr(addr, ':');
	}
	if (p) {
		*p = '\0';
		p++;
		port = strtoul(p, &e, 10);
		if (p == e)
			goto invalid;
	}

	if (!str_to_addr(addr, owner->addr))
		goto invalid;
	owner->port = port;

	return 0;
invalid:
	sd_err("Invalid ip address %s", addr);
	return -1;
}

struct get_vdi_info {
	const char *name;
	const char *tag;
	uint32_t vid;
	uint32_t snapid;
	uint32_t acl;
	uint8_t nr_copies;
	uint8_t copy_policy;
	uint8_t block_size_shift;
};

int dog_bnode_writer(uint64_t oid, void *mem, unsigned int len, uint64_t offset,
		     uint32_t flags, int copies, int copy_policy, bool create,
		     bool direct)
{
	if (direct)
		flags |= SD_FLAG_CMD_DIRECT;
	return dog_write_object(oid, 0, mem, len, offset, flags, copies,
			       copy_policy, create);
}

int dog_bnode_reader(uint64_t oid, void **mem, unsigned int len,
		     uint64_t offset)
{
	return dog_read_object(oid, *mem, len, offset, true);
}

static inline bool is_data_obj_writeable(const struct sd_inode *inode,
					 uint32_t idx)
{
	return inode->header.vdi_id == sd_inode_get_vid(inode, idx);
}

/*
 * Make string description of VDI for logging.
 * Here 20 is sizeof(" (tag=, vid=abcdef)") plus 1.
 * Note that vid is 24-bit practically so its max length in hex is 6 chars.
 */
#define VDI_DESC_MAX (SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN + 20)
static inline void describe_vdi(const char *name, uint32_t snapid,
				const char *tag, uint32_t vid, char *desc)
{
	if (vid) {
		if (snapid > 0)
			snprintf(desc, VDI_DESC_MAX,
				 "%s (snapid=%" PRIu32 ", vid=%" PRIx32 ")",
				 name, snapid, vid);
		else if (tag[0])
			snprintf(desc, VDI_DESC_MAX,
				 "%s (tag=%s, vid=%" PRIx32 ")",
				 name, tag, vid);
		else
			snprintf(desc, VDI_DESC_MAX,
				 "%s (vid=%" PRIx32 ")",
				 name, vid);
	} else {
		if (snapid > 0)
			snprintf(desc, VDI_DESC_MAX, "%s (snapid=%" PRIu32 ")",
				 name, snapid);
		else if (tag[0])
			snprintf(desc, VDI_DESC_MAX, "%s (tag=%s)",
				 name, tag);
		else
			snprintf(desc, VDI_DESC_MAX, "%s", name);
	}
}

static void vdi_show_progress(uint64_t done, uint64_t total)
{
	return show_progress(done, total, false);
}

static char *redundancy_scheme(uint8_t copy_nr, uint8_t policy)
{
	static char str[10];

	if (policy > 0) {
		int d, p;
		ec_policy_to_dp(policy, &d, &p);
		snprintf(str, sizeof(str), "%d:%d", d, p);
	} else {
		snprintf(str, sizeof(str), "%d", copy_nr);
	}
	return str;
}

static void print_vdi_list(uint32_t vid, const char *name, const char *tag,
			   uint32_t snapid, uint32_t flags,
			   const struct sd_inode *i, void *data)
{
	bool is_clone = false;
	uint64_t my_objs = 0, cow_objs = 0;
	time_t ti;
	struct tm tm;
	char dbuf[128];
	const char *redundancy;
	struct get_vdi_info *info = data;
	uint32_t object_size = (UINT32_C(1) << i->header.block_size_shift);

	if (info) {
		if (info->name && strcmp(name, info->name) != 0)
			return;
		if (info->acl != LOCK_TYPE_ANY && info->acl != i->header.acl_id)
			return;
	}

	ti = i->header.create_time >> 32;
	if (raw_output) {
		snprintf(dbuf, sizeof(dbuf), "%" PRIu64, (uint64_t) ti);
	} else {
		localtime_r(&ti, &tm);
		strftime(dbuf, sizeof(dbuf), TIME_FORMAT, &tm);
	}

	sd_inode_stat(i, &my_objs, &cow_objs);

	if (i->header.snap_id == 1 && i->header.parent_vdi_id != 0)
		is_clone = true;

	redundancy = redundancy_scheme(i->header.nr_copies,
				       i->header.copy_policy);
	if (json_output) {
		struct json_object *vdi_obj =
			json_object_new_object();
		uuid_t uuid;
		char uuid_str[UUID_STR_LEN];

		JSON_ADD_STRING(vdi_obj, "name", name);
		JSON_ADD_INT(vdi_obj, "vdi_id", vid);
		if (i->header.acl_id > 0)
			JSON_ADD_INT(vdi_obj, "acl_id", i->header.acl_id);
		memcpy((char *)uuid, &i->header.uuid, 16);
		if (!uuid_is_null(uuid)) {
			uuid_unparse(uuid, uuid_str);
			JSON_ADD_STRING(vdi_obj, "uuid", uuid_str);
		}
		JSON_ADD_UINT64(vdi_obj, "vdi_size",
				i->header.vdi_size);
		if (vdi_is_snapshot(&i->header))
			JSON_ADD_INT(vdi_obj, "snapid", snapid);
		JSON_ADD_UINT64(vdi_obj, "object_size",
				my_objs * object_size);
		if (cow_objs)
			JSON_ADD_UINT64(vdi_obj, "cow_size",
					cow_objs * object_size);
		JSON_ADD_STRING(vdi_obj, "create_time", dbuf);
		JSON_ADD_BOOL(vdi_obj, "is_snapshot",
				 vdi_is_snapshot(&i->header));
		JSON_ADD_BOOL(vdi_obj, "is_clone", is_clone);
		if (i->header.copy_policy > 0)
			JSON_ADD_STRING(vdi_obj, "redundancy_scheme",
					redundancy);
		else
			JSON_ADD_INT(vdi_obj, "nr_copies",
				     i->header.nr_copies);
		if (strlen(i->header.tag))
			JSON_ADD_STRING(vdi_obj, "tag",
					i->header.tag);
		JSON_ADD_INT(vdi_obj, "block_size_shift",
			     i->header.block_size_shift);
		json_object_array_add(out_obj, vdi_obj);
	} else if (raw_output) {
		printf("%c ", vdi_is_snapshot(&i->header) ?
		       's' : (is_clone ? 'c' : '='));
		while (*name) {
			if (isspace(*name) || *name == '\\')
				putchar('\\');
			putchar(*name++);
		}
		printf(" %d %s %s %s %s %" PRIx32 " %s %s %" PRIu8 "\n",
		       snapid, strnumber(i->header.vdi_size),
		       strnumber(my_objs * object_size),
		       strnumber(cow_objs * object_size),
		       dbuf, vid, redundancy,
		       i->header.tag, i->header.block_size_shift);
	} else {
		printf("%c %-8s %5d %7s %7s %7s %s  %7" PRIx32
		       " %6s %13s %3" PRIu8 "\n",
		       vdi_is_snapshot(&i->header) ?
		       's' : (is_clone ? 'c' : ' '),
		       name, snapid,
		       strnumber(i->header.vdi_size),
		       strnumber(my_objs * object_size),
		       strnumber(cow_objs * object_size),
		       dbuf, vid,
		       redundancy_scheme(i->header.nr_copies,
					 i->header.copy_policy),
		       i->header.tag, i->header.block_size_shift);
	}
}

static struct json_object *get_parent_obj(struct json_object *cur,
					  uint32_t parent_vid)
{
	struct json_object *parent_obj = NULL;
	int nr_inodes, i;

	nr_inodes = json_object_array_length(cur);
	for (i = 0; i < nr_inodes; i++) {
		struct json_object *inode_obj =
			json_object_array_get_idx(cur, i);
		struct json_object *vid_obj, *children_obj;
		uint32_t vid;

		vid_obj = json_object_object_get(inode_obj, "vdi_id");
		if (!vid_obj)
			continue;
		vid = json_object_get_int(vid_obj);
		children_obj = json_object_object_get(inode_obj,
						      "children");
		if (!children_obj)
			continue;
		if (vid == parent_vid) {
			parent_obj = children_obj;
			break;
		}
		parent_obj = get_parent_obj(children_obj,
					    parent_vid);
		if (parent_obj)
			break;
	}
	return parent_obj;
}

static void print_vdi_tree(uint32_t vid, const char *name, const char *tag,
			   uint32_t snapid, uint32_t flags,
			   const struct sd_inode *i, void *data)
{
	time_t ti;
	struct tm tm;
	char buf[128];

	if (json_output) {
		struct json_object *children_obj, *cur_obj =
			json_object_new_object();
		struct json_object *parent_obj;

		JSON_ADD_STRING(cur_obj, "name", name);
		JSON_ADD_INT(cur_obj, "vdi_id", vid);
		if (i->header.acl_id)
			JSON_ADD_INT(cur_obj, "acl_id", i->header.acl_id);
		if (snapid > 0)
			JSON_ADD_INT(cur_obj, "snap_id", snapid);
		if (strlen(i->header.tag))
			JSON_ADD_STRING(cur_obj, "tag", i->header.tag);
		if (vdi_is_snapshot(&i->header))
			JSON_ADD_UINT64(cur_obj, "create_time",
					i->header.create_time);
		children_obj = json_object_new_array();
		json_object_object_add(cur_obj, "children", children_obj);

		parent_obj = get_parent_obj(out_obj, i->header.parent_vdi_id);
		if (parent_obj)
			json_object_array_add(parent_obj, cur_obj);
		else
			json_object_array_add(out_obj, cur_obj);
		return;
	}
	if (vdi_is_snapshot(&i->header)) {
		ti = i->header.create_time >> 32;
		localtime_r(&ti, &tm);

		strftime(buf, sizeof(buf), "[" TIME_FORMAT "]", &tm);
	} else
		pstrcpy(buf, sizeof(buf), "(you are here)");

	add_vdi_tree(name, buf, vid, i->header.parent_vdi_id,
		     highlight && !vdi_is_snapshot(&i->header));
}

static void print_vdi_graph(uint32_t vid, const char *name, const char *tag,
			    uint32_t snapid, uint32_t flags,
			    const struct sd_inode *i, void *data)
{
	time_t ti;
	struct tm tm;
	char dbuf[128], tbuf[128];

	ti = i->header.create_time >> 32;
	localtime_r(&ti, &tm);

	strftime(dbuf, sizeof(dbuf), "%Y-%m-%d", &tm);
	strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm);

	printf("  \"%x\" -> \"%x\";\n", i->header.parent_vdi_id, vid);
	printf("  \"%x\" [\n"
	       "    group = \"%s\",\n"
	       "    label = \"",
	       vid, name);
	printf("Name: %10s\\n"
	       "Tag:  %10x\\n"
	       "Size: %10s\\n"
	       "Date: %10s\\n"
	       "Time: %10s",
	       name, snapid, strnumber(i->header.vdi_size), dbuf, tbuf);

	if (vdi_is_snapshot(&i->header))
		printf("\"\n  ];\n\n");
	else
		printf("\",\n    color=\"red\"\n  ];\n\n");

}

static void for_each_node_print(uint64_t oid, struct json_object *obj)
{
	int ret;
	struct sd_node *n;
	const char *sheep;

	rb_for_each_entry(n, &sd_nroot, rb) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

		sd_init_req(&hdr, SD_OP_EXIST);
		hdr.data_length = 0;
		hdr.flags = 0;
		hdr.epoch = sd_epoch;
		hdr.obj.oid = oid;

		ret = dog_exec_req(&n->nid, &hdr, NULL);
		if (ret < 0)
			continue;
		if (rsp->result) {
			if (!obj)
				sd_err("%s", sd_strerror(rsp->result));
			continue;
		}

		sheep = addr_to_str(n->nid.addr, n->nid.port);
		switch (rsp->result) {
		case SD_RES_SUCCESS:
			if (obj)
				json_object_array_add(obj,
					json_object_new_string(sheep));
			else
				printf("%s has the object\n", sheep);
			break;
		case SD_RES_NO_OBJ:
			if (!obj)
				printf("%s doesn't have the object\n", sheep);
			break;
		case SD_RES_OLD_NODE_VER:
		case SD_RES_NEW_NODE_VER:
			sd_err("The node list has changed: please try again");
			break;
		default:
			sd_err("%s: hit an unexpected error (%s)", sheep,
			       sd_strerror(rsp->result));
			break;
		}
	}
}

static void print_obj_ref(uint32_t vid, const char *name, const char *tag,
			   uint32_t snapid, uint32_t flags,
			   const struct sd_inode *i, void *data)
{
	uint64_t oid = *(uint64_t *)data;
	uint64_t idx = data_oid_to_idx(oid);
	struct get_vdi_info info;

	if (i->data_vdi_id[idx] != 0 &&
			i->data_vdi_id[idx] == oid_to_vid(oid)) {
		memset(&info, 0, sizeof(info));
		info.name = name;
		print_vdi_list(vid, name, tag, snapid, flags, i, &info);
	}
}

/* For sorting vdi_state by vid in ascending order */
static int compare_vdi_state_by_vid(const void *lhs, const void *rhs)
{
	const struct vdi_state *a = (const struct vdi_state *)lhs;
	const struct vdi_state *b = (const struct vdi_state *)rhs;
	return a->vid < b->vid ? -1 : (a->vid > b->vid ? 1 : 0);
}

/* User data of print_lock_list */
struct lock_list_data {
	const struct vdi_state *sorted;
	size_t nmemb;
};

static void print_lock_list(uint32_t vid, const char *name, const char *tag,
			    uint32_t snapid, uint32_t flags,
			    const struct sd_inode *i, void *data)
{
	const struct sd_inode_header *h = &i->header;
	const struct lock_list_data *u = (const struct lock_list_data *)data;
	const struct vdi_state key = { .vid = vid };
	const struct vdi_state *found = bsearch(&key, u->sorted, u->nmemb,
						sizeof(struct vdi_state),
						compare_vdi_state_by_vid);
	struct json_object *lock_obj = NULL, *vdi_obj = NULL;

	if (!found || found->lock_state == LOCK_STATE_UNLOCKED)
		return;

	const bool is_clone = (h->snap_id == 1 && h->parent_vdi_id != 0);

	if (json_output) {
		vdi_obj = json_object_new_object();
		JSON_ADD_STRING(vdi_obj, "name", name);
		JSON_ADD_INT(vdi_obj, "vdi_id", vid);
		if (found->acl != 0)
			JSON_ADD_INT(vdi_obj, "acl_id", found->acl);
		if (vdi_is_snapshot(h))
			JSON_ADD_INT(vdi_obj, "snap_id", snapid);
		if (strlen(tag))
			JSON_ADD_STRING(vdi_obj, "tag", tag);
	} else
		printf("%c %-8s  %5" PRIu32 "  %6" PRIx32 " %6" PRIx32 "  %-13s ",
		       vdi_is_snapshot(h) ? 's' : (is_clone ? 'c' : ' '),
		       name, snapid, vid, found->acl, tag);

	if (found->lock_state == LOCK_STATE_LOCKED) {
		if (json_output) {
			lock_obj = json_object_new_object();
			JSON_ADD_STRING(lock_obj, "holder",
					node_id_to_str(&found->lock_owner,
						       false));
			json_object_object_add(vdi_obj, "lock_state", lock_obj);
			json_object_array_add(out_obj, vdi_obj);
		} else
			printf(" %s\n", node_id_to_str(&found->lock_owner,
						       false));
		return;
	}

	/* LOCK_STATE_SHARED */
	if (json_output)
		lock_obj = json_object_new_array();

	for (uint32_t j = 0; j < found->nr_participants; j++) {
		const struct node_id *nid = &found->participants[j];
		const uint32_t state = found->participants_state[j] & 0xF;
		const uint32_t count = found->participants_state[j] >> 8;
		const char *state_str = NULL;

		switch(state) {
		case SHARED_LOCK_STATE_MODIFIED:
			state_str = "modified";
			break;
		case SHARED_LOCK_STATE_SHARED:
			state_str = "shared";
			break;
		case SHARED_LOCK_STATE_INVALIDATED:
			state_str = "invalidated";
			break;
		default:
			if (!json_output)
				printf("(UNKNOWN %" PRIu32 ", BUG!)", state);
			break;
		}
		if (!state_str)
			continue;
		if (json_output) {
			struct json_object *holder_obj =
				json_object_new_object();
			JSON_ADD_STRING(holder_obj, "holder",
					node_id_to_str(nid, false));
			JSON_ADD_STRING(holder_obj, "state", state_str);
			JSON_ADD_INT(holder_obj, "count", count);
			json_object_array_add(lock_obj, holder_obj);
		} else {
			printf(" %s(%s)", node_id_to_str(nid, false),
			       state_str);
		}
	}
	if (json_output) {
		json_object_object_add(vdi_obj, "lock_state", lock_obj);

		json_object_array_add(out_obj, vdi_obj);
	} else
		printf("\n");
}

static int vdi_list(int argc, char **argv)
{
	const char *vdiname = argv[optind];
	struct get_vdi_info info;

	memset(&info, 0, sizeof(info));
	info.acl = vdi_acl_id();

	if (json_output)
		out_obj = json_object_new_array();
	else if (!raw_output)
		printf("  Name        Id    Size    Used  Shared"
		       "    Creation time   VDI id  Copies  Tag"
		       "   Block Size Shift\n");

	if (vdiname) {
		info.name = vdiname;
		if (parse_vdi(print_vdi_list, SD_INODE_SIZE, &info,
			      true, false) < 0)
			return EXIT_SYSFAIL;
		if (json_output) {
			const char *o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		}
		return EXIT_SUCCESS;
	}

	if (vdi_cmd_data.oid) {
		if (!is_data_obj(vdi_cmd_data.oid))
			return EXIT_FAILURE;
		if (parse_vdi(print_obj_ref, SD_INODE_SIZE,
			      &vdi_cmd_data.oid, true, false) < 0)
			return EXIT_SYSFAIL;
		if (json_output) {
			const char *o;

			o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		}
		return EXIT_SUCCESS;
	}

	if (parse_vdi(print_vdi_list, SD_INODE_SIZE, &info, true, false) < 0)
		return EXIT_SYSFAIL;

	if (json_output) {
		const char *o;

		o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}
	return EXIT_SUCCESS;
}

static int vdi_tree(int argc, char **argv)
{
	if (json_output)
		out_obj = json_object_new_array();

	init_tree();
	if (parse_vdi(print_vdi_tree, SD_INODE_HEADER_SIZE,
		      out_obj, true, false) < 0)
		return EXIT_SYSFAIL;
	dump_tree();

	if (json_output) {
		const char *o;

		o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}
	return EXIT_SUCCESS;
}

static int vdi_graph(int argc, char **argv)
{
	/* print a header */
	printf("digraph G {\n");
	printf("  node [shape = \"box\", fontname = \"Courier\"];\n\n");
	printf("  \"0\" [shape = \"ellipse\", label = \"root\"];\n\n");

	if (parse_vdi(print_vdi_graph, SD_INODE_HEADER_SIZE,
		      NULL, true, false) < 0)
		return EXIT_SYSFAIL;

	/* print a footer */
	printf("}\n");

	return EXIT_SUCCESS;
}

int read_vdi_obj(const char *vdiname, int snapid, const char *tag,
		 uint32_t acl, uint32_t *pvid, void *inode, size_t size)
{
	int ret;
	uint32_t vid;

	ret = find_vdi_name(vdiname, snapid, tag, acl, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open VDI %s (snapshot id: %d "
		       "snapshot tag: %s acl: %" PRIx32"): %s",
		       vdiname, snapid, tag, acl, sd_strerror(ret));
		return EXIT_FAILURE;
	}

	ret = dog_read_object(vid_to_vdi_oid(vid), inode, size, 0, true);
	if (ret != SD_RES_SUCCESS) {
		if (snapid) {
			sd_err("Failed to read a snapshot %s:%d", vdiname,
			       snapid);
		} else if (tag && tag[0]) {
			sd_err("Failed to read a snapshot %s:%s", vdiname, tag);
		} else {
			sd_err("Failed to read a vdi %s", vdiname);
		}
		return EXIT_FAILURE;
	}

	if (pvid)
		*pvid = vid;

	return EXIT_SUCCESS;
}

int do_vdi_create(const char *vdiname, int64_t vdi_size,
		  uint32_t base_vid, uint32_t acl_id,
		  uint32_t *vdi_id, bool snapshot,
		  uint8_t nr_copies, uint8_t copy_policy,
		  uint8_t store_policy, uint8_t block_size_shift)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;
	char buf[SD_MAX_VDI_LEN];

	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, vdiname);

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_MAX_VDI_LEN;

	hdr.vdi.base_vdi_id = base_vid;
	hdr.vdi.snapid = snapshot ? 1 : 0;
	hdr.vdi.vdi_size = vdi_size;
	hdr.vdi.copies = nr_copies;
	hdr.vdi.copy_policy = copy_policy;
	hdr.vdi.store_policy = store_policy;
	hdr.vdi.block_size_shift = block_size_shift;
	hdr.vdi.acl = acl_id;

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0)
		return EXIT_SYSFAIL;

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to create VDI %s: %s", vdiname,
		       sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	if (vdi_id)
		*vdi_id = rsp->vdi.vdi_id;

	return EXIT_SUCCESS;
}

static int vdi_create(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint64_t size;
	uint32_t vid;
	uint32_t acl_id;
	uint64_t oid;
	uint64_t idx;
	uint32_t max_idx;
	uint32_t object_size;
	uint64_t old_max_total_size = 0;
	struct sd_inode *inode = NULL;
	int ret;

	if (!argv[optind]) {
		sd_err("Please specify the VDI size");
		return EXIT_USAGE;
	}
	acl_id = vdi_acl_id();
	/* One cannot create a VDI with ACL 'any' */
	if (acl_id == LOCK_TYPE_ANY) {
		sd_err("'any' cannot be the ACL of a new VDI");
		return EXIT_FAILURE;
	}
	ret = option_parse_size(argv[optind], &size);
	if (ret < 0)
		return EXIT_USAGE;

	if (vdi_cmd_data.block_size_shift) {
		object_size = (UINT32_C(1) << vdi_cmd_data.block_size_shift);
	} else if (vdi_cmd_data.store_policy == SD_HYPER_STORE_POLICY) {
		/* Force to use default block_size_shift for hyper volume */
		vdi_cmd_data.block_size_shift = SD_DEFAULT_BLOCK_SIZE_SHIFT;
		object_size = (UINT32_C(1) << vdi_cmd_data.block_size_shift);
	} else {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

		sd_init_req(&hdr, SD_OP_CLUSTER_STATUS);
		ret = dog_exec_req(&sd_nid, &hdr, NULL);
		if (ret < 0) {
			sd_err("Fail to execute request: SD_OP_CLUSTER_STATUS");
			ret = EXIT_FAILURE;
			goto out;
		}

		if (!rsp->cluster.ctime) {
			sd_err("Failed to create VDI %s: %s", vdiname,
			       sd_strerror(SD_RES_WAIT_FOR_FORMAT));
			return EXIT_FAILURE;
		}

		if (rsp->result != SD_RES_SUCCESS) {
			sd_err("%s", sd_strerror(rsp->result));
			ret = EXIT_FAILURE;
			goto out;
		}
		object_size = (UINT32_C(1) << rsp->cluster.block_size_shift);
	}

	old_max_total_size = object_size * OLD_MAX_DATA_OBJS;

	if (size > old_max_total_size &&
	    SD_DEFAULT_STORE_POLICY == vdi_cmd_data.store_policy) {
		sd_err("VDI size is larger than %s bytes, please use '-y' to "
		       "create a hyper volume with size up to %s bytes"
		       " or use '-z' to create larger object size volume",
		       strnumber(old_max_total_size),
		       strnumber(SD_MAX_VDI_SIZE));
		return EXIT_USAGE;
	}

	if (size > SD_MAX_VDI_SIZE) {
		sd_err("VDI size is too large");
		return EXIT_USAGE;
	}

	ret = do_vdi_create(vdiname, size, 0, acl_id, &vid, false,
			    vdi_cmd_data.nr_copies, vdi_cmd_data.copy_policy,
			    vdi_cmd_data.store_policy,
			    vdi_cmd_data.block_size_shift);
	if (ret != EXIT_SUCCESS || !vdi_cmd_data.prealloc)
		goto out;

	inode = xmalloc(sizeof(*inode));

	ret = dog_read_object(vid_to_vdi_oid(vid), inode, sizeof(*inode), 0,
			      true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read a newly created VDI object");
		ret = EXIT_FAILURE;
		goto out;
	}
	object_size = (UINT32_C(1) << inode->header.block_size_shift);
	max_idx = DIV_ROUND_UP(size, object_size);

	for (idx = 0; idx < max_idx; idx++) {
		vdi_show_progress(idx * object_size, inode->header.vdi_size);
		oid = vid_to_data_oid(vid, idx);

		ret = dog_write_object(oid, 0, NULL, 0, 0,
				       SD_FLAG_CMD_DIRECT,
				       inode->header.nr_copies,
				       inode->header.copy_policy, true);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		sd_inode_set_vid(inode, idx, vid);
		ret = sd_inode_write_vid(inode, idx, vid, vid, 0, false, true);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	vdi_show_progress(idx * object_size, inode->header.vdi_size);
	ret = EXIT_SUCCESS;

out:
	if (ret == EXIT_SUCCESS && verbose) {
		if (json_output) {
			const char *o;

			out_obj = json_object_new_object();
			JSON_ADD_INT(out_obj, "vdi_id", vid);
			o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		} else if (raw_output)
			printf("%x\n", vid);
		else
			printf("VDI ID of newly created VDI: %x\n", vid);
	}

	free(inode);
	return ret;
}

static struct vdi_state *get_vdi_state(int *count)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct vdi_state *vs = NULL;
	unsigned int rlen;

#define DEFAULT_VDI_STATE_COUNT 512
	rlen = DEFAULT_VDI_STATE_COUNT * sizeof(struct vdi_state);
	vs = xzalloc(rlen);
retry:
	sd_init_req(&hdr, SD_OP_GET_VDI_COPIES);
	hdr.data_length = rlen;

	ret = dog_exec_req(&sd_nid, &hdr, (char *)vs);
	if (ret < 0)
		goto fail;

	switch (ret) {
	case SD_RES_SUCCESS:
		break;
	case SD_RES_BUFFER_SMALL:
		rlen *= 2;
		vs = xrealloc(vs, rlen);
		goto retry;
	default:
		sd_err("failed to execute SD_OP_GET_VDI_COPIES: %s",
		       sd_strerror(ret));
		goto fail;
	}

	*count = rsp->data_length / sizeof(*vs);
	return vs;

fail:
	free(vs);
	vs = NULL;
	return NULL;
}

static int has_own_objects(uint32_t vid, bool *result)
{
	struct sd_inode *inode;
	int ret = SD_RES_SUCCESS;

	*result = true;
	inode = xzalloc(sizeof(*inode));

	ret = dog_read_object(vid_to_vdi_oid(vid), inode,
			      sizeof(*inode), 0, true);
	if (ret != SD_RES_SUCCESS)
		goto out;

	for (int i = 0; i < SD_INODE_DATA_INDEX; i++) {
		if (inode->data_vdi_id[i] && inode->data_vdi_id[i] == vid)
			/* VDI has its own object */
			goto out;
	}

	*result = false;

out:
	free(inode);
	return ret;
}

static int vdi_snapshot(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint32_t vid, new_vid;
	uint32_t acl_id = vdi_acl_id();
	int ret;
	struct sd_inode_header *inode;
	bool fail_if_snapshot = false;

	if (vdi_cmd_data.snapshot_id != 0) {
		sd_err("Please specify a non-integer value for "
		       "a snapshot tag name");
		return EXIT_USAGE;
	}
	/* the snapshot joins the ACL of the VDI it is taken from */
	if (acl_id == LOCK_TYPE_ANY) {
		sd_err("'any' cannot be the ACL of a new VDI");
		return EXIT_FAILURE;
	}

	ret = find_vdi_name(vdiname, vdi_cmd_data.snapshot_id,
			    vdi_cmd_data.snapshot_tag, acl_id,
			    &vid);
	switch (ret) {
	case SD_RES_NO_TAG:
		break;
	case SD_RES_SUCCESS:
		fail_if_snapshot = true;
		break;
	default:
		sd_err("Failed to create snapshot for %s: %s",
			vdiname, sd_strerror(ret));
		return EXIT_FAILURE;
	}

	inode = xmalloc(sizeof(*inode));

	if (fail_if_snapshot) {
		ret = dog_read_object(vid_to_vdi_oid(vid), inode,
				      SD_INODE_HEADER_SIZE, 0, true);
		if (ret != SD_RES_SUCCESS) {
			free(inode);
			return EXIT_FAILURE;
		}

		if (vdi_is_snapshot(inode)) {
			sd_err("Failed to create snapshot for %s, maybe "
			       "snapshot id (%d) or tag (%s) is existed",
			       vdiname, vdi_cmd_data.snapshot_id,
			       vdi_cmd_data.snapshot_tag);
			free(inode);
			return EXIT_FAILURE;
		}
	} else {
		ret = read_vdi_obj(vdiname, 0, "", acl_id, &vid, inode,
				   SD_INODE_HEADER_SIZE);
		if (ret != SD_RES_SUCCESS) {
			free(inode);
			return EXIT_FAILURE;
		}
	}

	if (sd_store_policy_is_hyper(inode)) {
		sd_err("creating a snapshot of hypervolume is not supported");
		free(inode);
		return EXIT_FAILURE;
	}

	if (vdi_cmd_data.reduce_identical_snapshots) {
		bool result;
		ret = has_own_objects(vid, &result);

		if (ret != SD_RES_SUCCESS)
			goto out;

		if (!result) {
			if (verbose)
				sd_info("VDI %s doesn't have its own objects, "
					"skipping creation of snapshot",
					vdiname);

			goto out;
		}
	}

	ret = dog_write_object(vid_to_vdi_oid(vid), 0,
			       vdi_cmd_data.snapshot_tag,
			       SD_MAX_VDI_TAG_LEN,
			       offsetof(struct sd_inode_header, tag),
			       0, inode->nr_copies, inode->copy_policy,
			       false);
	if (ret != SD_RES_SUCCESS)
		goto out;

	ret = do_vdi_create(vdiname, inode->vdi_size,
			    vid, acl_id, &new_vid, true,
			    inode->nr_copies, inode->copy_policy,
			    inode->store_policy, inode->block_size_shift);

	if (ret == SD_RES_SUCCESS && verbose) {
		if (json_output) {
			const char *o;

			out_obj = json_object_new_object();
			JSON_ADD_INT(out_obj, "vdi_id", vid);
			JSON_ADD_INT(out_obj, "new_vdi_id", new_vid);
			o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		} else if (raw_output)
			printf("%x %x\n", new_vid, vid);
		else
			printf("new VID of original VDI: %x,"
			       " VDI ID of newly created snapshot: %x\n",
			       new_vid, vid);
	}

out:
	free(inode);
	return ret == SD_RES_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int vdi_clone(int argc, char **argv)
{
	const char *src_vdi = argv[optind++], *dst_vdi;
	uint32_t base_vid, new_vid, vdi_id;
	uint32_t acl_id = vdi_acl_id();
	uint64_t oid;
	uint64_t idx;
	uint32_t max_idx, ret;
	uint32_t object_size;
	struct sd_inode *inode = NULL, *new_inode = NULL;
	char *buf = NULL;

	dst_vdi = argv[optind];
	if (!dst_vdi) {
		sd_err("Destination VDI name must be specified");
		ret = EXIT_USAGE;
		goto out;
	}

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		sd_err("Only snapshot VDIs can be cloned");
		sd_err("Please specify the '-s' option");
		ret = EXIT_USAGE;
		goto out;
	}
	/* the clone joins the ACL of the VDI it is cloned from */
	if (acl_id == LOCK_TYPE_ANY) {
		sd_err("'any' cannot be the ACL of a new VDI");
		ret = EXIT_FAILURE;
		goto out;
	}

	inode = xmalloc(sizeof(*inode));

	ret = read_vdi_obj(src_vdi, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, acl_id,
			   &base_vid, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	if (vdi_cmd_data.no_share == true)
		base_vid = 0;

	object_size = (UINT32_C(1) << inode->header.block_size_shift);
	ret = do_vdi_create(dst_vdi, inode->header.vdi_size,
			    base_vid, acl_id, &new_vid, false,
			    inode->header.nr_copies,
			    inode->header.copy_policy,
			    inode->header.store_policy,
			    inode->header.block_size_shift);
	if (ret != EXIT_SUCCESS ||
			(!vdi_cmd_data.prealloc && !vdi_cmd_data.no_share))
		goto out;

	new_inode = xmalloc(sizeof(*inode));
	ret = read_vdi_obj(dst_vdi, 0, "", acl_id,
			   NULL, new_inode, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	buf = xzalloc(object_size);
	max_idx = count_data_objs(&inode->header);

	for (idx = 0; idx < max_idx; idx++) {
		size_t size;

		vdi_show_progress(idx * object_size, inode->header.vdi_size);
		vdi_id = sd_inode_get_vid(inode, idx);
		if (vdi_id) {
			oid = vid_to_data_oid(vdi_id, idx);
			ret = dog_read_object(oid, buf, object_size, 0,
					      true);
			if (ret) {
				ret = EXIT_FAILURE;
				goto out;
			}
			size = object_size;
		} else {
			if (vdi_cmd_data.no_share && !vdi_cmd_data.prealloc)
				continue;
			size = 0;
		}

		oid = vid_to_data_oid(new_vid, idx);
		ret = dog_write_object(oid, 0, buf, size, 0,
				       SD_FLAG_CMD_DIRECT,
				       inode->header.nr_copies,
				       inode->header.copy_policy, true);
		if (ret != SD_RES_SUCCESS) {
			ret = EXIT_FAILURE;
			goto out;
		}

		sd_inode_set_vid(new_inode, idx, new_vid);
		ret = sd_inode_write_vid(new_inode, idx, new_vid, new_vid, 0,
					 false, true);
		if (ret) {
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	vdi_show_progress(idx * object_size, inode->header.vdi_size);
	ret = EXIT_SUCCESS;

out:
	if (ret == EXIT_SUCCESS && verbose) {
		if (json_output) {
			const char *o;

			out_obj = json_object_new_object();
			JSON_ADD_INT(out_obj, "vdi_id", new_vid);
			o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		} else if (raw_output)
			printf("%x\n", new_vid);
		else
			printf("VDI ID of newly created clone: %x\n", new_vid);
	}

	free(inode);
	if (new_inode)
		free(new_inode);
	free(buf);
	return ret;
}

static int vdi_resize(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint64_t new_size, old_max_total_size;
	uint32_t vid, object_size;
	uint32_t acl_id = vdi_acl_id();
	int ret;
	struct sd_inode_header inode;

	if (!argv[optind]) {
		sd_err("Please specify the new size for the VDI");
		return EXIT_USAGE;
	}
	ret = option_parse_size(argv[optind], &new_size);
	if (ret < 0)
		return EXIT_USAGE;

	ret = read_vdi_obj(vdiname, 0, "", acl_id,
			   &vid, &inode, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		return ret;

	object_size = (UINT32_C(1) << inode.block_size_shift);
	old_max_total_size = object_size * OLD_MAX_DATA_OBJS;
	if (!sd_store_policy_is_hyper(&inode)) {
		if (new_size > old_max_total_size) {
			sd_err("New VDI size is too large."
			       " This volume's max size is %"PRIu64,
			       old_max_total_size);
			return EXIT_USAGE;
		}
	} else if (new_size > SD_MAX_VDI_SIZE) {
		sd_err("New VDI size is too large"
			" This volume's max size is %llu",
			SD_MAX_VDI_SIZE);
		return EXIT_USAGE;
	}

	if (new_size < inode.vdi_size) {
		sd_err("Shrinking VDIs is not implemented");
		return EXIT_USAGE;
	}
	inode.vdi_size = new_size;

	ret = dog_write_object(vid_to_vdi_oid(vid), 0,
			       &inode, SD_INODE_HEADER_SIZE, 0,
			       SD_FLAG_CMD_DIRECT, inode.nr_copies,
			       inode.copy_policy, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to update an inode header");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int do_vdi_delete(const char *vdiname, int snap_id, const char *snap_tag,
			 uint32_t acl, int nr_batched_reclamation,
			 int reclamation_interval)
{
	int ret, nr_objs, nr_reclaimed;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char data[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];
	uint32_t vid;
	struct sd_inode *inode = xzalloc(sizeof(*inode));
	int i = 0;

	if (!nr_batched_reclamation)
		nr_batched_reclamation = NR_BATCHED_RECLAMATION_DEFAULT;

	ret = find_vdi_name(vdiname, snap_id, snap_tag, acl, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open VDI %s (snapshot id: %d snapshot tag: %s)"
				": %s", vdiname, snap_id, snap_tag, sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = dog_read_object(vid_to_vdi_oid(vid), inode, sizeof(*inode),
			      0, false);
	if (ret) {
		sd_err("failed to read inode object: %016"PRIx64,
		       vid_to_vdi_oid(vid));
		ret = EXIT_FAILURE;
		goto out;
	}

	nr_objs = count_data_objs(&inode->header);
	nr_reclaimed = 0;
	while (i < nr_objs) {
		int start_idx, nr_filled_idx;

		if (vdi_cmd_data.nr_max_reclaim &&
		    vdi_cmd_data.nr_max_reclaim <= nr_reclaimed)
			break;

		while (i < nr_objs && !inode->data_vdi_id[i])
			i++;
		start_idx = i;

		nr_filled_idx = 0;
		while (i < nr_objs && nr_filled_idx < nr_batched_reclamation) {
			if (inode->data_vdi_id[i]) {
				inode->data_vdi_id[i] = 0;
				nr_filled_idx++;
				nr_reclaimed++;
			}

			i++;

			if (vdi_cmd_data.nr_max_reclaim &&
			    vdi_cmd_data.nr_max_reclaim <= nr_reclaimed)
				break;
		}

		ret = dog_write_object(vid_to_vdi_oid(vid), 0,
				       &inode->data_vdi_id[start_idx],
				       (i - start_idx) * sizeof(uint32_t),
				       offsetof(struct sd_inode,
						data_vdi_id[start_idx]),
				       SD_FLAG_CMD_DIRECT,
				       inode->header.nr_copies,
				       inode->header.copy_policy,
				       false);
		if (ret) {
			sd_err("failed to update inode for discarding objects:"
			       " %016"PRIx64, vid_to_vdi_oid(vid));
			ret = EXIT_FAILURE;
			goto out;
		}

		if (i < nr_objs && reclamation_interval)
			sleep(reclamation_interval);
	}

	if (vdi_cmd_data.nr_max_reclaim) {
		ret = EXIT_SUCCESS;
		goto out;
	}

	sd_init_req(&hdr, SD_OP_DEL_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(data);
	hdr.vdi.snapid = snap_id;
	hdr.vdi.acl = acl;
	memset(data, 0, sizeof(data));
	pstrcpy(data, SD_MAX_VDI_LEN, vdiname);
	if (snap_tag)
		pstrcpy(data + SD_MAX_VDI_LEN, SD_MAX_VDI_TAG_LEN, snap_tag);

	ret = dog_exec_req(&sd_nid, &hdr, data);
	if (ret < 0) {
		ret = EXIT_SYSFAIL;
		goto out;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to delete %s: %s", vdiname,
		       sd_strerror(rsp->result));
		if (rsp->result == SD_RES_NO_VDI)
			ret = EXIT_MISSING;
		else
			ret = EXIT_FAILURE;
	}

out:
	free(inode);
	return ret;
}

static int vdi_delete(int argc, char **argv)
{
	const char *vdiname = argv[optind];

	return do_vdi_delete(vdiname, vdi_cmd_data.snapshot_id,
			     vdi_cmd_data.snapshot_tag, vdi_acl_id(),
			     vdi_cmd_data.nr_batched_reclamation,
			     vdi_cmd_data.reclamation_interval);
}

static int vdi_rollback(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint32_t base_vid, new_vid;
	uint32_t snap_id = vdi_cmd_data.snapshot_id;
	uint32_t acl_id = vdi_acl_id();
	int ret;
	struct sd_inode_header inode;

	if (!snap_id && !vdi_cmd_data.snapshot_tag[0]) {
		sd_err("Please specify the '-s' option");
		return EXIT_USAGE;
	}
	/* the working VDI is recreated, so it needs an ACL to be created in */
	if (acl_id == LOCK_TYPE_ANY) {
		sd_err("'any' cannot be the ACL of a new VDI");
		return EXIT_FAILURE;
	}

	ret = read_vdi_obj(vdiname, snap_id, vdi_cmd_data.snapshot_tag,
			   acl_id, &base_vid, &inode, sizeof(inode));
	if (ret != EXIT_SUCCESS)
		return ret;

	if (!vdi_cmd_data.force)
		confirm("This operation discards any changes made since the"
			" previous\nsnapshot was taken.  Continue? [yes/no]: ");

	ret = do_vdi_delete(vdiname, 0, NULL, acl_id,
			    vdi_cmd_data.nr_batched_reclamation,
			    vdi_cmd_data.reclamation_interval);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to delete the current state");
		return EXIT_FAILURE;
	}

	ret = do_vdi_create(vdiname, inode.vdi_size, base_vid, acl_id, &new_vid,
			     false, inode.nr_copies, inode.copy_policy,
			     inode.store_policy, inode.block_size_shift);

	if (ret == EXIT_SUCCESS && verbose) {
		if (json_output) {
			const char *o;

			out_obj = json_object_new_object();
			JSON_ADD_INT(out_obj, "vdi_id", new_vid);
			o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		} else if (raw_output)
			printf("%x\n", new_vid);
		else
			printf("New VDI ID of rollbacked VDI: %x\n", new_vid);
	}

	return ret;
}


static int vdi_object_map(int argc, char **argv)
{
	const char *vdiname = argv[optind];
	uint64_t idx = vdi_cmd_data.index;
	struct sd_inode *inode = xmalloc(sizeof(*inode));
	uint32_t vid;
	int ret;

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, vdi_acl_id(),
			   NULL, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("FATAL: %s not found", vdiname);
		goto out;
	}

	if (json_output)
		out_obj = json_object_new_array();
	else
		printf("Index       VID\n");
	if (idx != ~0) {
		vid = sd_inode_get_vid(inode, idx);
		if (json_output) {
			struct json_object *vid_obj =
				json_object_new_object();
			JSON_ADD_INT(vid_obj, "index", idx);
			JSON_ADD_INT(vid_obj, "vdi_id", vid);
			json_object_array_add(out_obj, vid_obj);
		} else
			printf("%08"PRIu64" %8"PRIx32"\n", idx, vid);
	} else {
		uint64_t max_idx = count_data_objs(&inode->header);

		for (idx = 0; idx < max_idx; idx++) {
			vid = sd_inode_get_vid(inode, idx);
			if (!vid)
				continue;
			if (json_output) {
				struct json_object *vid_obj =
					json_object_new_object();
				JSON_ADD_INT(vid_obj, "index", idx);
				JSON_ADD_INT(vid_obj, "vdi_id", vid);
				json_object_array_add(out_obj, vid_obj);
			} else
				printf("%08"PRIu64" %8"PRIx32"\n", idx, vid);
		}
	}
	if (json_output) {
		const char *o;

		o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}
out:
	free(inode);
	return ret;
}

static void print_expected_location(uint64_t oid, int copies,
				    struct json_object *obj)
{
	const struct sd_vnode *vnodes[SD_MAX_COPIES];

	if (sd_nodes_nr < copies) {
		if (!obj)
			printf("\nBecause number of nodes (%d) is less than "
			       "number of copies (%d), the object should be "
			       "located at every nodes.\n",
			       sd_nodes_nr, copies);
		return;
	}

	if (!obj)
		printf("\nAccording to sheepdog algorithm, "
		       "the object should be located at:\n");
	oid_to_vnodes(oid, &sd_vroot, copies, vnodes);
	for (int i = 0; i < copies; i++) {
		const char *addr = NULL;

		if (vnodes[i])
			addr = addr_to_str(vnodes[i]->node->nid.addr,
					   vnodes[i]->node->nid.port);

		if (obj) {
			struct json_object *addr_obj;

			if (addr)
				addr_obj = json_object_new_string(addr);
			else
				addr_obj = json_object_new_object();
			json_object_array_add(obj, addr_obj);
		} else {
			printf((i < copies - 1) ? "%s " : "%s",
			       addr ? addr : "<missing>");
		}
	}
	if (!obj)
		printf("\n");
}

static int vdi_object_location(int argc, char **argv)
{
	const char *vdiname = argv[optind];
	uint64_t idx = vdi_cmd_data.index, oid;
	struct sd_inode *inode = xmalloc(sizeof(*inode));
	uint32_t vid, vdi_id, snap_id;
	struct json_object *vdi_obj = NULL, *location_obj = NULL;
	int ret;

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, vdi_acl_id(),
			   NULL, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("FATAL: no inode objects");
		goto out;
	}
	vid = inode->header.vdi_id;
	snap_id = inode->header.snap_id;

	if (json_output) {
		out_obj = json_object_new_object();
		vdi_obj = json_object_new_array();
		location_obj = json_object_new_array();
	}
	if (idx == ~0) {
		oid = vid_to_vdi_oid(vid);
		if (json_output) {
			JSON_ADD_INT(out_obj, "vdi_id", vid);
			JSON_ADD_UINT64(out_obj, "oid", oid);
			if (snap_id)
				JSON_ADD_INT(out_obj, "snap_id", snap_id);
			if (strlen(inode->header.tag))
				JSON_ADD_STRING(out_obj, "tag",
						inode->header.tag);
			JSON_ADD_INT(out_obj, "nr_copies",
				     inode->header.nr_copies);
			JSON_ADD_INT(out_obj, "nr_nodes", sd_nodes_nr);
		} else
			printf("Looking for the inode object 0x%" PRIx32
			       " with %d nodes\n\n", vid, sd_nodes_nr);
		for_each_node_print(vid_to_vdi_oid(vid), vdi_obj);
		if (json_output)
			json_object_object_add(out_obj, "location", vdi_obj);

		print_expected_location(vid_to_vdi_oid(vid),
					inode->header.nr_copies,
					location_obj);
		if (json_output)
			json_object_object_add(out_obj, "expected_location",
					       location_obj);
		ret = EXIT_SUCCESS;
		goto out;
	}

	if (idx >= MAX_DATA_OBJS) {
		sd_err("The offset is too large!");
		ret = EXIT_FAILURE;
		goto out;
	}

	vdi_id = sd_inode_get_vid(inode, idx);
	oid = vid_to_data_oid(vdi_id, idx);
	if (vdi_id) {
		if (json_output) {
			JSON_ADD_INT(out_obj, "vdi_id", vdi_id);
			JSON_ADD_UINT64(out_obj, "oid", oid);
			JSON_ADD_INT(out_obj, "nr_copies",
				     inode->header.nr_copies);
			JSON_ADD_INT(out_obj, "nr_nodes", sd_nodes_nr);
		} else
			printf("Looking for the object %016" PRIx64
			       " (vid 0x%" PRIx32 " idx %"PRIu64
			       ", %u copies) with %d nodes\n\n",
			       oid, vid, idx, inode->header.nr_copies,
			       sd_nodes_nr);

		for_each_node_print(oid, vdi_obj);
		if (json_output)
			json_object_object_add(out_obj, "location", vdi_obj);
		print_expected_location(oid, inode->header.nr_copies,
					location_obj);
		if (json_output)
			json_object_object_add(out_obj, "expected_location",
					       location_obj);
	} else if (!json_output)
		printf("The inode object 0x%" PRIx32 " idx"
		       " %"PRIu64" is not allocated\n",
		       vid, idx);

out:
	if (json_output) {
		const char *o;

		o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}
	free(inode);
	return ret;
}

#define OIDS_INIT_LENGTH 1024

static void save_oid(uint64_t oid, int copies)
{
	const struct sd_vnode *vnodes[SD_MAX_COPIES];
	struct oid_entry *entry;

	oid_to_vnodes(oid, &sd_vroot, copies, vnodes);
	for (int i = 0; i < copies; i++) {
		struct oid_entry key = {};

		if (!vnodes[i])
			continue;
		key.node = (struct sd_node *) vnodes[i]->node;
		entry = rb_search(&oid_tree, &key, rb, oid_entry_cmp);
		if (!entry)
			panic("rb_search() failure.");

		if (entry->last >= entry->end) {
			entry->end *= 2;
			entry->oids = xrealloc(entry->oids,
					sizeof(uint64_t) * entry->end);
		}
		entry->oids[entry->last] = oid;
		entry->last++;
	}
}

static void build_oid_tree(const struct sd_inode *inode)
{
	uint32_t max_idx, vid;
	uint64_t oid;
	struct sd_node *node;
	struct oid_entry *entry;
	int copies = min((int)inode->header.nr_copies, sd_zones_nr);

	rb_for_each_entry(node, &sd_nroot, rb) {
		entry = xmalloc(sizeof(*entry));
		entry->node = node;
		entry->oids = xmalloc(sizeof(uint64_t) * OIDS_INIT_LENGTH);
		entry->end  = OIDS_INIT_LENGTH;
		entry->last = 0;
		rb_insert(&oid_tree, entry, rb, oid_entry_cmp);
	}

	save_oid(vid_to_vdi_oid(inode->header.vdi_id), copies);
	max_idx = count_data_objs(&inode->header);
	for (uint32_t idx = 0; idx < max_idx; idx++) {
		vid = sd_inode_get_vid(inode, idx);
		if (vid == 0)
			continue;
		oid = vid_to_data_oid(vid, idx);
		save_oid(oid, copies);
	}
}

static void destroy_oid_tree(void)
{
	struct oid_entry *entry;

	rb_for_each_entry(entry, &oid_tree, rb)
		free(entry->oids);
	rb_destroy(&oid_tree, struct oid_entry, rb);
}

static int do_vdi_check_exist(const struct sd_inode *inode)
{
	int total = 0;
	struct oid_entry *entry;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	build_oid_tree(inode);

	rb_for_each_entry(entry, &oid_tree, rb) {
		sd_init_req(&hdr, SD_OP_OIDS_EXIST);
		hdr.data_length = sizeof(uint64_t) * entry->last;
		hdr.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_PIGGYBACK;
		int ret = dog_exec_req(&entry->node->nid, &hdr, entry->oids);
		if (ret < 0)
			panic("dog_exec_req() failure.");

		int n = rsp->data_length / sizeof(uint64_t);
		total += n;
		for (int i = 0; i < n; i++)
			printf("[%s] oid %016"PRIx64" is missing.\n",
			       addr_to_str(entry->node->nid.addr,
					   entry->node->nid.port),
			       entry->oids[i]);
	}

	destroy_oid_tree();

	if (total == 0) {
		printf("%s is fine, no object is missing.\n",
		       inode->header.name);
		return EXIT_SUCCESS;
	} else {
		printf("%s lost %d object(s).\n",
		       inode->header.name, total);
		return EXIT_FAILURE;
	}
}

static int do_track_object(uint64_t oid, uint8_t nr_copies, void *data)
{
	int i, j, ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	const struct sd_vnode *vnode_buf[SD_MAX_COPIES];
	struct epoch_log *logs, *log;
	char *next_log;
	int nr_logs, log_length;
	uint32_t nodes_nr;

	nodes_nr = sd_nodes_nr;
	log_length = sd_epoch * (sizeof(struct epoch_log)
			+ nodes_nr * sizeof(struct sd_node));
	logs = xmalloc(log_length);

retry:
	sd_init_req(&hdr, SD_OP_STAT_CLUSTER);
	hdr.data_length = log_length;
	hdr.cluster.nodes_nr = nodes_nr;

	ret = dog_exec_req(&sd_nid, &hdr, logs);
	if (ret < 0)
		goto error;

	if (rsp->result == SD_RES_BUFFER_SMALL) {
		nodes_nr *= 2;
		log_length = sd_epoch * (sizeof(struct epoch_log)
				+ nodes_nr * sizeof(struct sd_node));
		logs = xrealloc(logs, log_length);
		goto retry;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		sd_warn("%s\n", sd_strerror(rsp->result));
		goto error;
	}

	nr_logs = rsp->data_length / (sizeof(struct epoch_log)
			+ nodes_nr * sizeof(struct sd_node));
	next_log = (char *)logs;
	for (i = nr_logs - 1; i >= 0; i--) {
		struct rb_root vroot = RB_ROOT;
		struct rb_root nroot = RB_ROOT;

		log = (struct epoch_log *)next_log;
		if (json_output) {
			struct json_object *epoch_obj =
				json_object_new_object();
			struct json_object *epoch_arr_obj = data;
			JSON_ADD_UINT64(epoch_obj, "oid", oid);
			JSON_ADD_INT(epoch_obj, "epoch", log->epoch);
			JSON_ADD_INT(epoch_obj, "nr_nodes", log->nr_nodes);
			json_object_array_add(epoch_arr_obj, epoch_obj);
			goto next;
		}
		printf("\nobj %016"PRIx64" locations at epoch %d, copies = %d\n",
		       oid, log->epoch, nr_copies);
		printf("---------------------------------------------------\n");

		/*
		 * When # of nodes is less than nr_copies, we only print
		 * remaining nodes that holds all the remaining copies.
		 */
		if (log->nr_nodes < nr_copies) {
			for (j = 0; j < log->nr_nodes; j++) {
				const struct node_id *n = &log->nodes[j].nid;

				printf("%s\n", addr_to_str(n->addr, n->port));
			}
			continue;
		}
		for (int k = 0; k < log->nr_nodes; k++)
			rb_insert(&nroot, &log->nodes[k], rb, node_cmp);
		if (logs->flags & SD_CLUSTER_FLAG_DISKMODE)
			disks_to_vnodes(&nroot, &vroot);
		else
			nodes_to_vnodes(&nroot, &vroot);
		oid_to_vnodes(oid, &vroot, nr_copies, vnode_buf);
		for (j = 0; j < nr_copies; j++) {
			const struct node_id *n = NULL;

			if (vnode_buf[j])
				n = &vnode_buf[j]->node->nid;
			printf("%s\n",
			       n ? addr_to_str(n->addr, n->port) : "<missing>");
		}
		rb_destroy(&vroot, struct sd_vnode, rb);
	next:
		next_log = (char *)log->nodes
				+ nodes_nr * sizeof(struct sd_node);
	}

	free(logs);
	return EXIT_SUCCESS;
error:
	free(logs);
	return EXIT_SYSFAIL;
}

static int vdi_track(int argc, char **argv)
{
	const char *vdiname = argv[optind];
	unsigned idx = vdi_cmd_data.index;
	uint8_t nr_copies;
	uint64_t oid = vdi_cmd_data.oid;
	struct sd_inode *inode = xmalloc(sizeof(*inode));
	uint32_t vid, vdi_id;
	int ret;
	struct json_object *epoch_objs = NULL;

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, vdi_acl_id(),
			   NULL, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("FATAL: no inode objects");
		return ret;
	}
	vid = inode->header.vdi_id;
	nr_copies = inode->header.nr_copies;

	if (json_output) {
		out_obj = json_object_new_object();
		epoch_objs = json_object_new_array();
	}
	if (!oid) {
		if (idx == ~0) {
			if (json_output) {
				JSON_ADD_INT(out_obj, "vdi_id", vid);
					json_object_object_add(out_obj,
							       "epochs",
							       epoch_objs);
			} else
				printf("Tracking the inode object 0x%" PRIx32
				       " with %d nodes\n", vid, sd_nodes_nr);
			ret = do_track_object(vid_to_vdi_oid(vid), nr_copies,
					      epoch_objs);
			goto out;
		}

		if (idx >= MAX_DATA_OBJS) {
			sd_warn("The offset is too large!\n");
			ret = EXIT_FAILURE;
			goto out;
		}

		vdi_id = sd_inode_get_vid(inode, idx);
		oid = vid_to_data_oid(vdi_id, idx);

		if (json_output) {
			JSON_ADD_INT(out_obj, "vdi_id", vid);
			JSON_ADD_UINT64(out_obj, "oid", oid);
			JSON_ADD_INT(out_obj, "idx", idx);
			json_object_object_add(out_obj, "epochs",
					       epoch_objs);
		} else
			printf("Tracking the object %016" PRIx64
			       " (the inode vid 0x%" PRIx32 " idx %u)"
			       " with %d nodes\n", oid, vid, idx, sd_nodes_nr);
	} else {
		if (json_output) {
			JSON_ADD_INT(out_obj, "vdi_id", vid);
			JSON_ADD_UINT64(out_obj, "oid", oid);
			json_object_object_add(out_obj, "epochs",
					       epoch_objs);
		} else {
			printf("Tracking the object %016" PRIx64
			       " (the inode vid 0x%" PRIx32 ")"
			       " with %d nodes\n", oid, vid, sd_nodes_nr);
		}
	}
	ret = do_track_object(oid, nr_copies, epoch_objs);
out:
	free(inode);
	if (json_output) {
		const char *o;

		o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}
	return ret;
}

static int find_vdi_attr_oid(const char *vdiname, const char *tag, uint32_t snapid,
			     const char *key, void *value, unsigned int value_len,
			     uint32_t *vid, uint64_t *oid, unsigned int *nr_copies,
			     bool create, bool excl, bool delete)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;
	struct sheepdog_vdi_attr vattr;

	memset(&vattr, 0, sizeof(vattr));
	pstrcpy(vattr.name, SD_MAX_VDI_LEN, vdiname);
	pstrcpy(vattr.tag, SD_MAX_VDI_TAG_LEN, vdi_cmd_data.snapshot_tag);
	vattr.snap_id = vdi_cmd_data.snapshot_id;
	pstrcpy(vattr.key, SD_MAX_VDI_ATTR_KEY_LEN, key);
	if (value && value_len) {
		vattr.value_len = value_len;
		memcpy(vattr.value, value, value_len);
	}

	sd_init_req(&hdr, SD_OP_GET_VDI_ATTR);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_ATTR_OBJ_SIZE;
	hdr.vdi.snapid = vdi_cmd_data.snapshot_id;
	hdr.vdi.acl = vdi_acl_id();

	if (create)
		hdr.flags |= SD_FLAG_CMD_CREAT;
	if (excl)
		hdr.flags |= SD_FLAG_CMD_EXCL;
	if (delete)
		hdr.flags |= SD_FLAG_CMD_DEL;

	ret = dog_exec_req(&sd_nid, &hdr, &vattr);
	if (ret < 0)
		return SD_RES_EIO;

	if (rsp->result != SD_RES_SUCCESS)
		return rsp->result;

	*vid = rsp->vdi.vdi_id;
	*oid = vid_to_attr_oid(rsp->vdi.vdi_id, rsp->vdi.attr_id);
	*nr_copies = rsp->vdi.copies;

	return SD_RES_SUCCESS;
}

static int vdi_setattr(int argc, char **argv)
{
	int value_len = 0;
	int ret = EXIT_SUCCESS;
	uint64_t attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	const char *vdiname = argv[optind++], *key;
	char *value = NULL;
	uint64_t offset;

	key = argv[optind++];
	if (!key) {
		sd_err("Please specify the attribute key");
		ret = EXIT_USAGE;
		goto out;
	}

	value = argv[optind] ? xstrdup(argv[optind]) : NULL;
	optind++;
	if (!value && !vdi_cmd_data.delete) {
		value = xmalloc(SD_MAX_VDI_ATTR_VALUE_LEN);

		offset = 0;
reread:
		ret = read(STDIN_FILENO, value + offset,
			   SD_MAX_VDI_ATTR_VALUE_LEN - offset);
		if (ret < 0) {
			sd_err("Failed to read attribute value from stdin: %m");
			ret = EXIT_SYSFAIL;
			goto out;
		}
		if (ret > 0) {
			offset += ret;
			goto reread;
		}
	}

	if (value)
		value_len = strlen(value);

	ret = find_vdi_attr_oid(vdiname, vdi_cmd_data.snapshot_tag,
				vdi_cmd_data.snapshot_id, key, value,
				value_len, &vid, &attr_oid,
				&nr_copies, !vdi_cmd_data.delete,
				vdi_cmd_data.exclusive, vdi_cmd_data.delete);
	if (ret) {
		if (ret == SD_RES_VDI_EXIST) {
			sd_err("The attribute '%s' already exists", key);
			ret = EXIT_EXISTS;
			goto out;
		} else if (ret == SD_RES_NO_OBJ) {
			sd_err("Attribute '%s' not found", key);
			ret = EXIT_MISSING;
			goto out;
		} else if (ret == SD_RES_NO_VDI) {
			sd_err("VDI not found");
			ret = EXIT_MISSING;
			goto out;
		} else
			sd_err("Failed to set attribute: %s", sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

out:
	if (value)
		free(value);

	return ret;
}

static int vdi_getattr(int argc, char **argv)
{
	int ret;
	uint64_t oid, attr_oid = 0;
	uint32_t vid = 0, nr_copies = 0;
	const char *vdiname = argv[optind++], *key;
	struct sheepdog_vdi_attr vattr;

	key = argv[optind++];
	if (!key) {
		sd_err("Please specify the attribute key");
		return EXIT_USAGE;
	}

	ret = find_vdi_attr_oid(vdiname, vdi_cmd_data.snapshot_tag,
				vdi_cmd_data.snapshot_id, key, NULL, 0, &vid,
				&attr_oid, &nr_copies, false, false, false);
	if (ret == SD_RES_NO_OBJ) {
		sd_err("Attribute '%s' not found", key);
		return EXIT_MISSING;
	} else if (ret == SD_RES_NO_VDI) {
		sd_err("VDI not found");
		return EXIT_MISSING;
	} else if (ret) {
		sd_err("Failed to find attribute oid: %s", sd_strerror(ret));
		return EXIT_MISSING;
	}

	oid = attr_oid;

	ret = dog_read_object(oid, &vattr, SD_ATTR_OBJ_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read attribute oid: %s", sd_strerror(ret));
		return EXIT_SYSFAIL;
	}

	xwrite(STDOUT_FILENO, vattr.value, vattr.value_len);
	return EXIT_SUCCESS;
}

static int vdi_read(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	int ret;
	struct sd_inode *inode = NULL;
	uint64_t offset = 0, oid, done = 0, total = (uint64_t) -1;
	uint32_t vdi_id, idx;
	uint32_t object_size;
	uint64_t len;
	char *buf = NULL;

	if (argv[optind]) {
		ret = option_parse_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (argv[optind]) {
			ret = option_parse_size(argv[optind++], &total);
			if (ret < 0)
				return EXIT_USAGE;
		}
	}

	inode = malloc(sizeof(*inode));

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, vdi_acl_id(),
			   NULL, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto load_inode_err;

	if (inode->header.vdi_size < offset) {
		sd_err("Read offset is beyond the end of the VDI");
		ret = EXIT_FAILURE;
		goto load_inode_err;
	}

	object_size = (UINT32_C(1) << inode->header.block_size_shift);
	buf = xmalloc(object_size);

	total = min(total, inode->header.vdi_size - offset);
	idx = offset / object_size;
	offset %= object_size;
	while (done < total) {
		len = min(total - done, object_size - offset);
		vdi_id = sd_inode_get_vid(inode, idx);
		if (vdi_id) {
			oid = vid_to_data_oid(vdi_id, idx);
			ret = dog_read_object(oid, buf, len, offset, false);
			if (ret != SD_RES_SUCCESS) {
				sd_err("Failed to read VDI");
				ret = EXIT_FAILURE;
				goto out;
			}
		} else
			memset(buf, 0, len);

		ret = xwrite(STDOUT_FILENO, buf, len);
		if (ret < 0) {
			sd_err("Failed to write to stdout: %m");
			ret = EXIT_SYSFAIL;
			goto out;
		}

		offset = 0;
		idx++;
		done += len;
	}
	fsync(STDOUT_FILENO);
	ret = EXIT_SUCCESS;
out:
	free(buf);
load_inode_err:
	free(inode);

	return ret;
}

static int vdi_write(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	uint32_t vid, flags, vdi_id, idx;
	uint32_t object_size;
	int ret;
	struct sd_inode *inode = NULL;
	uint64_t offset = 0, oid, old_oid, done = 0, total = (uint64_t) -1;
	unsigned int len;
	char *buf = NULL;
	bool create;

	if (argv[optind]) {
		ret = option_parse_size(argv[optind++], &offset);
		if (ret < 0)
			return EXIT_USAGE;
		if (argv[optind]) {
			ret = option_parse_size(argv[optind++], &total);
			if (ret < 0)
				return EXIT_USAGE;
		}
	}

	inode = xmalloc(sizeof(*inode));

	ret = read_vdi_obj(vdiname, 0, "", vdi_acl_id(),
			   &vid, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto load_inode_err;

	if (inode->header.vdi_size < offset) {
		sd_err("Write offset is beyond the end of the VDI");
		ret = EXIT_FAILURE;
		goto load_inode_err;
	}

	object_size = (UINT32_C(1) << inode->header.block_size_shift);
	buf = xmalloc(object_size);

	total = min(total, inode->header.vdi_size - offset);
	idx = offset / object_size;
	offset %= object_size;
	while (done < total) {
		create = false;
		old_oid = 0;
		flags = 0;
		len = min(total - done, object_size - offset);

		vdi_id = sd_inode_get_vid(inode, idx);
		if (!vdi_id)
			create = true;
		else if (!is_data_obj_writeable(inode, idx)) {
			create = true;
			old_oid = vid_to_data_oid(vdi_id, idx);
		}

		if (vdi_cmd_data.writeback)
			flags |= SD_FLAG_CMD_CACHE;

		ret = xread(STDIN_FILENO, buf, len);
		if (ret < 0) {
			sd_err("Failed to read from stdin: %m");
			ret = EXIT_SYSFAIL;
			goto out;
		} else if (ret < len) {
			/* exit after this buffer is sent */
			memset(buf + ret, 0, len - ret);
			total = done + len;
		}

		sd_inode_set_vid(inode, idx, inode->header.vdi_id);
		oid = vid_to_data_oid(inode->header.vdi_id, idx);
		ret = dog_write_object(oid, old_oid, buf, len, offset, flags,
				       inode->header.nr_copies,
				       inode->header.copy_policy,
				       create);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to write VDI");
			ret = EXIT_FAILURE;
			goto out;
		}

		if (create) {
			ret = sd_inode_write_vid(inode, idx, vid, vid, flags,
						 false, false);
			if (ret) {
				ret = EXIT_FAILURE;
				goto out;
			}
		}

		offset += len;
		if (offset == object_size) {
			offset = 0;
			idx++;
		}
		done += len;
	}
	ret = EXIT_SUCCESS;
out:
	free(buf);
load_inode_err:
	free(inode);

	return ret;
}

static void write_object_to(const struct sd_vnode *vnode, uint64_t oid,
			void *buf, unsigned int len, bool create, uint8_t ec_index)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_PEER);
	else
		sd_init_req(&hdr, SD_OP_WRITE_PEER);
	hdr.epoch = sd_epoch;
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = len;
	hdr.obj.oid = oid;
	hdr.obj.ec_index = ec_index;

	ret = dog_exec_req(&vnode->node->nid, &hdr, buf);
	if (ret < 0)
		exit(EXIT_SYSFAIL);

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("FATAL: failed to write %016"PRIx64", %s", oid,
		       sd_strerror(rsp->result));
		exit(EXIT_FAILURE);
	}
}

struct vdi_check_work {
	struct vdi_check_info *info;
	const struct sd_vnode *vnode;
	uint8_t hash[SHA1_DIGEST_SIZE];
	uint8_t ec_index;
	uint8_t *buf;
	bool object_found;
	struct work work;
};

enum vdi_check_result {
	VDI_CHECK_NO_OBJ_FOUND,
	VDI_CHECK_NO_MAJORITY_FOUND,
	VDI_CHECK_SUCCESS,
};

struct vdi_check_info {
	uint64_t oid;
	uint8_t nr_copies;
	uint8_t copy_policy;
	uint8_t block_size_shift;
	uint64_t total;
	uint64_t *done;
	int refcnt;
	struct work_queue *wq;
	enum vdi_check_result result;
	struct vdi_check_work *majority;
	struct vdi_check_work vcw[0];
};

static void free_vdi_check_info(struct vdi_check_info *info)
{
	uint32_t object_size = (UINT32_C(1) << info->block_size_shift);
	if (info->done) {
		*info->done += object_size;
		vdi_show_progress(*info->done, info->total);
	}
	free(info);
}

static void vdi_repair_work(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;
	const struct sd_vnode *src = info->majority->vnode;
	const struct sd_vnode *dst = vcw->vnode;
	struct sd_req hdr;
	int ret;
	char n1[MAX_NODE_STR_LEN], n2[MAX_NODE_STR_LEN];

	sd_init_req(&hdr, SD_OP_REPAIR_REPLICA);
	hdr.epoch = sd_epoch;
	memcpy(hdr.forw.addr, src->node->nid.addr, sizeof(hdr.forw.addr));
	hdr.forw.port = src->node->nid.port;
	hdr.forw.oid = info->oid;

	ret = send_light_req(&dst->node->nid, &hdr);
	if (ret) {
		strcpy(n1, addr_to_str(src->node->nid.addr,
					   src->node->nid.port));
		strcpy(n2, addr_to_str(dst->node->nid.addr,
					   dst->node->nid.port));
		sd_err("failed to repair object %016"PRIx64
				" from %s to %s", info->oid, n1, n2);
	}
}

static void vdi_repair_main(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;

	if (vcw->object_found)
		fprintf(stdout, "fixed replica %016"PRIx64"\n", info->oid);
	else
		fprintf(stdout, "fixed missing %016"PRIx64"\n", info->oid);

	info->refcnt--;
	if (info->refcnt == 0)
		free_vdi_check_info(info);
}

static void vdi_check_object_work(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	if (is_erasure_oid(info->oid, info->copy_policy)) {
		sd_init_req(&hdr, SD_OP_READ_PEER);
		hdr.data_length = get_store_objsize(info->copy_policy,
						    info->block_size_shift,
						    info->oid);
		hdr.obj.ec_index = vcw->ec_index;
		hdr.epoch = sd_epoch;
		vcw->buf = xmalloc(hdr.data_length);
	} else
		sd_init_req(&hdr, SD_OP_GET_HASH);
	hdr.obj.oid = info->oid;
	hdr.obj.tgt_epoch = sd_epoch;

	ret = dog_exec_req(&vcw->vnode->node->nid, &hdr, vcw->buf);
	if (ret < 0)
		exit(EXIT_SYSFAIL);

	switch (rsp->result) {
	case SD_RES_SUCCESS:
		vcw->object_found = true;
		if (!is_erasure_oid(info->oid, info->copy_policy))
			memcpy(vcw->hash, rsp->hash.digest, sizeof(vcw->hash));
		break;
	case SD_RES_NO_OBJ:
		vcw->object_found = false;
		break;
	default:
		sd_err("failed to read %016" PRIx64 " from %s, %s", info->oid,
		       addr_to_str(vcw->vnode->node->nid.addr,
				   vcw->vnode->node->nid.port),
		       sd_strerror(rsp->result));
		exit(EXIT_FAILURE);
	}
}

static void check_replicatoin_object(struct vdi_check_info *info)
{
	if (info->majority == NULL) {
		switch (info->result) {
		case VDI_CHECK_NO_OBJ_FOUND:
			sd_err("no node has %016" PRIx64, info->oid);
			break;
		case VDI_CHECK_NO_MAJORITY_FOUND:
			sd_err("no majority of %016" PRIx64, info->oid);
			break;
		default:
			sd_err("unknown result of vdi check: %d", info->result);
			exit(EXIT_FAILURE);
			break;
		}

		/* do nothing */
		return;
	}

	for (int i = 0; i < info->nr_copies; i++) {
		if (&info->vcw[i] == info->majority)
			continue;
		/* need repair when object not found or consistency broken */
		if (!info->vcw[i].object_found ||
		    memcmp(info->majority->hash, info->vcw[i].hash,
			   sizeof(info->majority->hash)) != 0) {
			info->vcw[i].work.fn = vdi_repair_work;
			info->vcw[i].work.done = vdi_repair_main;
			info->refcnt++;
			queue_work(info->wq, &info->vcw[i].work);
		}
	}
}

static void check_erasure_object(struct vdi_check_info *info)
{
	int d = 0, p = 0, i, j, k;
	int dp = ec_policy_to_dp(info->copy_policy, &d, &p);
	struct fec *ctx = ec_init(d, dp);
	int miss_idx[dp], input_idx[dp];
	uint64_t oid = info->oid;
	uint32_t object_size = (UINT32_C(1) << info->block_size_shift);
	size_t len = get_store_objsize(info->copy_policy,
				       info->block_size_shift, oid);
	char *obj = xmalloc(len);
	uint8_t *input[dp];

	for (i = 0; i < dp; i++)
		miss_idx[i] = -1;

	for (i = 0, j = 0, k = 0; i < info->nr_copies; i++)
		if (!info->vcw[i].object_found) {
			miss_idx[j++] = i;
		} else {
			input_idx[k] = i;
			input[k] = info->vcw[i].buf;
			k++;
		}

	if (!j) { /* No object missing */
		int idx[d];

		for (i = 0; i < d; i++)
			idx[i] = i;

		for (k = 0; k < p; k++) {
			uint8_t *ds[d];
			for (j = 0; j < d; j++)
				ds[j] = info->vcw[j].buf;
			ec_decode_buffer(ctx, ds, idx, obj, d + k,
					 object_size);
			if (memcmp(obj, info->vcw[d + k].buf, len) != 0) {
				/* TODO repair the inconsistency */
				sd_err("object %016"PRIx64" is inconsistent", oid);
				goto out;
			}
		}
	} else if (j > p) {
		sd_err("failed to rebuild object %016"PRIx64". %d copies get "
		       "lost, more than %d", oid, j, p);
		goto out;
	} else {
		for (k = 0; k < j; k++) {
			int m = miss_idx[k];
			uint8_t *ds[d];

			for (i = 0; i < d; i++)
				ds[i] = input[i];
			ec_decode_buffer(ctx, ds, input_idx, obj, m,
					 object_size);
			write_object_to(info->vcw[m].vnode, oid, obj,
					len, true, info->vcw[m].ec_index);
			fprintf(stdout, "fixed missing %016"PRIx64", "
				"copy index %d\n", info->oid, m);
		}
	}
out:
	for (i = 0; i < dp; i++)
		free(info->vcw[i].buf);
	free(obj);
	ec_destroy(ctx);
}

static void vote_majority_object(struct vdi_check_info *info)
{
	/*
	 * Voting majority object from existing ones.
	 *
	 * The linear majority vote algorithm by Boyer and Moore is used:
	 * http://www.cs.utexas.edu/~moore/best-ideas/mjrty/
	 */

	int count = 0, nr_live_copies = 0;
	struct vdi_check_work *majority = NULL;

	/* step 1 */
	for (int i = 0; i < info->nr_copies; i++) {
		struct vdi_check_work *vcw = &info->vcw[i];

		if (!vcw->object_found)
			continue;
		nr_live_copies++;

		if (!count)
			majority = vcw;

		if (!memcmp(majority->hash, vcw->hash, sizeof(vcw->hash)))
			count++;
		else
			count--;
	}

	/* step 2 */
	if (count > 0 && count <= nr_live_copies / 2) {
		count = 0;
		for (int i = 0; i < info->nr_copies; i++) {
			struct vdi_check_work *vcw = &info->vcw[i];

			if (!vcw->object_found)
				continue;
			if (!memcmp(majority->hash, vcw->hash,
						sizeof(vcw->hash)))
				count++;
		}
	}

	if (!majority)
		info->result = VDI_CHECK_NO_OBJ_FOUND;
	else if (count > nr_live_copies / 2)
		info->result = VDI_CHECK_SUCCESS;
	else {
		/* no majority found */
		majority = NULL;
		info->result = VDI_CHECK_NO_MAJORITY_FOUND;
	}

	info->majority = majority;
}

static void vdi_check_object_main(struct work *work)
{
	struct vdi_check_work *vcw = container_of(work, struct vdi_check_work,
						  work);
	struct vdi_check_info *info = vcw->info;

	info->refcnt--;
	if (info->refcnt > 0)
		return;

	if (is_erasure_oid(info->oid, info->copy_policy))
		check_erasure_object(info);
	else {
		vote_majority_object(info);
		check_replicatoin_object(info);
	}

	if (info->refcnt == 0)
		free_vdi_check_info(info);
}

static void queue_vdi_check_work(const struct sd_inode *inode, uint64_t oid,
				 uint64_t *done, struct work_queue *wq,
				 int nr_copies)
{
	struct vdi_check_info *info;
	const struct sd_vnode *tgt_vnodes[SD_MAX_COPIES];

	info = xzalloc(sizeof(*info) + sizeof(info->vcw[0]) * nr_copies);
	info->oid = oid;
	info->nr_copies = nr_copies;
	info->total = inode->header.vdi_size;
	info->done = done;
	info->wq = wq;
	info->copy_policy = inode->header.copy_policy;
	info->block_size_shift = inode->header.block_size_shift;

	oid_to_vnodes(oid, &sd_vroot, nr_copies, tgt_vnodes);
	for (int i = 0; i < nr_copies; i++) {
		if (!tgt_vnodes[i])
			continue;
		info->vcw[i].info = info;
		info->vcw[i].ec_index = i;
		info->vcw[i].vnode = tgt_vnodes[i];
		info->vcw[i].work.fn = vdi_check_object_work;
		info->vcw[i].work.done = vdi_check_object_main;
		info->refcnt++;
		queue_work(info->wq, &info->vcw[i].work);
	}
}

struct check_arg {
	const struct sd_inode *inode;
	uint64_t *done;
	struct work_queue *wq;
	int nr_copies;
};

static void check_cb(struct sd_index *idx, void *arg, int ignore)
{
	struct check_arg *carg = arg;
	uint64_t oid;
	uint32_t object_size =
		(UINT32_C(1) << carg->inode->header.block_size_shift);

	if (idx->vdi_id) {
		oid = vid_to_data_oid(idx->vdi_id, idx->idx);
		*(carg->done) = (uint64_t)idx->idx * object_size;
		vdi_show_progress(*(carg->done), carg->inode->header.vdi_size);
		queue_vdi_check_work(carg->inode, oid, NULL, carg->wq,
				     carg->nr_copies);
	}
}

int do_vdi_check(const struct sd_inode *inode)
{
	uint32_t max_idx;
	uint64_t done = 0, oid;
	uint32_t vid;
	struct work_queue *wq;
	int nr_copies = min((int)inode->header.nr_copies, sd_zones_nr);
	uint32_t object_size = (UINT32_C(1) << inode->header.block_size_shift);

	if (0 < inode->header.copy_policy &&
	    sd_zones_nr < (int)inode->header.nr_copies) {
		sd_err("ABORT: Not enough active zones for consistency-checking"
		       " erasure coded VDI");
		return EXIT_FAILURE;
	}

	wq = create_work_queue("vdi check", WQ_DYNAMIC);

	init_fec();

	queue_vdi_check_work(inode, vid_to_vdi_oid(inode->header.vdi_id),
			     NULL, wq, nr_copies);

	if (!sd_store_policy_is_hyper(&inode->header)) {
		max_idx = count_data_objs(&inode->header);
		vdi_show_progress(done, inode->header.vdi_size);
		for (uint32_t idx = 0; idx < max_idx; idx++) {
			vid = sd_inode_get_vid(inode, idx);
			if (vid) {
				oid = vid_to_data_oid(vid, idx);
				queue_vdi_check_work(inode, oid, &done, wq,
						     nr_copies);
			} else {
				done += object_size;
				vdi_show_progress(done, inode->header.vdi_size);
			}
		}
	} else {
		struct check_arg arg = {inode, &done, wq, nr_copies};
		sd_inode_index_walk(inode, check_cb, &arg);
		vdi_show_progress(inode->header.vdi_size,
				  inode->header.vdi_size);
	}

	work_queue_wait(wq);

	fprintf(stdout, "finish check&repair %s\n", inode->header.name);

	return EXIT_SUCCESS;
}

static int vdi_check(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	int ret;
	struct sd_inode *inode = xmalloc(sizeof(*inode));

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, vdi_acl_id(),
			   NULL, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("FATAL: no inode objects");
		goto out;
	}

	if (vdi_cmd_data.exist)
		ret = do_vdi_check_exist(inode);
	else
		ret = do_vdi_check(inode);
out:
	free(inode);
	return ret;
}

/* vdi backup format */

#define VDI_BACKUP_FORMAT_VERSION 1
#define VDI_BACKUP_MAGIC 0x11921192

struct backup_hdr {
	uint32_t version;
	uint32_t magic;
};

struct obj_backup {
	uint32_t idx;
	uint32_t offset;
	uint32_t length;
	uint32_t reserved;
	uint8_t *data;
};

/* discards redundant area from backup data */
static void compact_obj_backup(struct obj_backup *backup, uint8_t *from_data,
			       uint32_t object_size)
{
	uint8_t *p1, *p2;

	p1 = backup->data;
	p2 = from_data;
	while (backup->length > 0 && memcmp(p1, p2, SECTOR_SIZE) == 0) {
		p1 += SECTOR_SIZE;
		p2 += SECTOR_SIZE;
		backup->offset += SECTOR_SIZE;
		backup->length -= SECTOR_SIZE;
	}

	p1 = backup->data + object_size - SECTOR_SIZE;
	p2 = from_data + object_size - SECTOR_SIZE;
	while (backup->length > 0 && memcmp(p1, p2, SECTOR_SIZE) == 0) {
		p1 -= SECTOR_SIZE;
		p2 -= SECTOR_SIZE;
		backup->length -= SECTOR_SIZE;
	}
}

static int get_obj_backup(uint32_t idx, uint32_t from_vid, uint32_t to_vid,
			  struct obj_backup *backup, uint32_t object_size)
{
	int ret;
	uint8_t *from_data = xzalloc(object_size);

	backup->idx = idx;
	backup->offset = 0;
	backup->length = object_size;

	if (to_vid) {
		ret = dog_read_object(vid_to_data_oid(to_vid, idx),
				      backup->data, object_size, 0, true);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read object %" PRIx32 ", %d", to_vid,
			       idx);
			return EXIT_FAILURE;
		}
	} else
		memset(backup->data, 0, object_size);

	if (from_vid) {
		ret = dog_read_object(vid_to_data_oid(from_vid, idx), from_data,
				      object_size, 0, true);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read object %" PRIx32 ", %d",
			       from_vid, idx);
			return EXIT_FAILURE;
		}
	}

	compact_obj_backup(backup, from_data, object_size);

	free(from_data);

	return EXIT_SUCCESS;
}

static int vdi_backup(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	int ret = EXIT_SUCCESS;
	uint32_t idx, nr_objs;
	uint32_t object_size;
	struct sd_inode *from_inode = xzalloc(sizeof(*from_inode));
	struct sd_inode *to_inode = xzalloc(sizeof(*to_inode));
	struct backup_hdr hdr = {
		.version = VDI_BACKUP_FORMAT_VERSION,
		.magic = VDI_BACKUP_MAGIC,
	};

	if ((!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) ||
	    (!vdi_cmd_data.from_snapshot_id &&
	     !vdi_cmd_data.from_snapshot_tag[0])) {
		sd_err("Please specify snapshots with '-F' and '-s' options");
		ret = EXIT_USAGE;
		goto out;
	}

	ret = read_vdi_obj(vdiname, vdi_cmd_data.from_snapshot_id,
			   vdi_cmd_data.from_snapshot_tag, vdi_acl_id(),
			   NULL, from_inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto load_inode_err;

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, vdi_acl_id(),
			   NULL, to_inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto load_inode_err;

	nr_objs = count_data_objs(&to_inode->header);

	struct obj_backup *backup = xzalloc(sizeof(*backup));
	object_size = (UINT32_C(1) << from_inode->header.block_size_shift);
	backup->data = xzalloc(sizeof(uint8_t) * object_size);

	ret = xwrite(STDOUT_FILENO, &hdr, sizeof(hdr));
	if (ret < 0) {
		sd_err("failed to write backup header, %m");
		ret = EXIT_SYSFAIL;
		goto error;
	}

	for (idx = 0; idx < nr_objs; idx++) {
		uint32_t from_vid = sd_inode_get_vid(from_inode, idx);
		uint32_t to_vid = sd_inode_get_vid(to_inode, idx);

		if (to_vid == 0 && from_vid == 0)
			continue;

		ret = get_obj_backup(idx, from_vid, to_vid,
				     backup, object_size);
		if (ret != EXIT_SUCCESS)
			goto error;

		if (backup->length == 0)
			continue;

		ret = xwrite(STDOUT_FILENO, backup,
			     sizeof(*backup) - sizeof(backup->data));
		if (ret < 0) {
			sd_err("failed to write backup data, %m");
			ret = EXIT_SYSFAIL;
			goto error;
		}
		ret = xwrite(STDOUT_FILENO, backup->data + backup->offset,
			     backup->length);
		if (ret < 0) {
			sd_err("failed to write backup data, %m");
			ret = EXIT_SYSFAIL;
			goto error;
		}
	}

	/* write end marker */
	memset(backup, 0, sizeof(*backup) - sizeof(backup->data));
	backup->idx = UINT32_MAX;
	ret = xwrite(STDOUT_FILENO, backup,
		     sizeof(*backup) - sizeof(backup->data));
	if (ret < 0) {
		sd_err("failed to write end marker, %m");
		ret = EXIT_SYSFAIL;
		goto error;
	}

	fsync(STDOUT_FILENO);
	ret = EXIT_SUCCESS;
error:
	free(backup->data);
	free(backup);
load_inode_err:
	free(from_inode);
	free(to_inode);
out:
	return ret;
}

/* restore backup data to vdi */
static int restore_obj(struct obj_backup *backup, uint32_t vid,
		       struct sd_inode *parent_inode)
{
	int ret;
	uint32_t parent_vid = sd_inode_get_vid(parent_inode, backup->idx);
	uint64_t parent_oid = 0;

	if (parent_vid)
		parent_oid = vid_to_data_oid(parent_vid, backup->idx);

	/* send a copy-on-write request */
	ret = dog_write_object(vid_to_data_oid(vid, backup->idx), parent_oid,
			backup->data, backup->length, backup->offset,
			SD_FLAG_CMD_DIRECT, parent_inode->header.nr_copies,
			parent_inode->header.copy_policy, true);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return dog_write_object(vid_to_vdi_oid(vid), 0, &vid, sizeof(vid),
			SD_INODE_HEADER_SIZE + sizeof(vid) * backup->idx,
			SD_FLAG_CMD_DIRECT, parent_inode->header.nr_copies,
			parent_inode->header.copy_policy, false);
}

static uint32_t do_restore(const char *vdiname, int snapid, const char *tag,
			   uint32_t acl_id)
{
	int ret;
	uint32_t vid;
	uint32_t object_size;
	struct backup_hdr hdr;
	struct obj_backup *backup = xzalloc(sizeof(*backup));
	struct sd_inode *inode = xzalloc(sizeof(*inode));

	ret = xread(STDIN_FILENO, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr))
		sd_err("failed to read backup header, %m");

	if (hdr.version != VDI_BACKUP_FORMAT_VERSION ||
	    hdr.magic != VDI_BACKUP_MAGIC) {
		sd_err("The backup file is corrupted");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	ret = read_vdi_obj(vdiname, snapid, tag, acl_id,
			   NULL, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = do_vdi_create(vdiname, inode->header.vdi_size,
			    inode->header.vdi_id, acl_id, &vid,
			    false, inode->header.nr_copies,
			    inode->header.copy_policy,
			    inode->header.store_policy,
			    inode->header.block_size_shift);
	if (ret != EXIT_SUCCESS) {
		sd_err("Failed to read VDI");
		goto out;
	}

	object_size = (UINT32_C(1) << inode->header.block_size_shift);
	backup->data = xzalloc(sizeof(uint8_t) * object_size);

	while (true) {
		ret = xread(STDIN_FILENO, backup,
			    sizeof(*backup) - sizeof(backup->data));
		if (ret != sizeof(*backup) - sizeof(backup->data)) {
			sd_err("failed to read backup data");
			ret = EXIT_SYSFAIL;
			break;
		}

		if (backup->idx == UINT32_MAX) {
			ret = EXIT_SUCCESS;
			break;
		}

		ret = xread(STDIN_FILENO, backup->data, backup->length);
		if (ret != backup->length) {
			sd_err("failed to read backup data");
			ret = EXIT_SYSFAIL;
			break;
		}

		ret = restore_obj(backup, vid, inode);
		if (ret != SD_RES_SUCCESS) {
			sd_err("failed to restore backup");
			do_vdi_delete(vdiname, 0, NULL, vdi_acl_id(),
				      vdi_cmd_data.nr_batched_reclamation,
				      vdi_cmd_data.reclamation_interval);
			ret = EXIT_FAILURE;
			break;
		}
	}
	free(backup->data);
out:
	free(backup);
	free(inode);

	return ret;
}

static int vdi_restore(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	int ret;
	struct sd_inode *inode_for_check = xzalloc(sizeof(*inode_for_check));
	struct sd_inode_header current;
	struct sd_inode_header parent;
	bool need_current_recovery = false;

	if (!vdi_cmd_data.snapshot_id && !vdi_cmd_data.snapshot_tag[0]) {
		sd_err("We can restore a backup file only to snapshots");
		sd_err("Please specify the '-s' option");
		ret = EXIT_USAGE;
		goto out;
	}

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, vdi_acl_id(),
			   NULL, inode_for_check, SD_INODE_SIZE);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Snapshot ID %d or tag %s doesn't exist",
		       vdi_cmd_data.snapshot_id, vdi_cmd_data.snapshot_tag);

		goto out;
	}

	/*
	 * delete the current vdi temporarily first to avoid making
	 * the current state become snapshot
	 */
	ret = read_vdi_obj(vdiname, 0, "", vdi_acl_id(),
			   NULL, &current, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = dog_read_object(vid_to_vdi_oid(current.parent_vdi_id),
			     &parent, SD_INODE_HEADER_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS) {
		printf("error\n");
		goto out;
	}

	if (is_stdin_console()) {
		sd_err("stdin must be pipe");
		ret = EXIT_USAGE;
		goto out;
	}

	ret = do_vdi_delete(vdiname, 0, NULL, vdi_acl_id(),
			    vdi_cmd_data.nr_batched_reclamation,
			    vdi_cmd_data.reclamation_interval);
	if (ret != EXIT_SUCCESS) {
		sd_err("Failed to delete the current state");
		goto out;
	}
	need_current_recovery = true;

	/* restore backup data */
	ret = do_restore(vdiname, vdi_cmd_data.snapshot_id,
			 vdi_cmd_data.snapshot_tag, vdi_acl_id());
out:
	if (need_current_recovery) {
		int recovery_ret;
		/* recreate the current vdi object */
		recovery_ret = do_vdi_create(vdiname, current.vdi_size,
					     current.parent_vdi_id,
					     vdi_acl_id(), NULL,
					     true, current.nr_copies,
					     current.copy_policy,
					     current.store_policy,
					     current.block_size_shift);
		if (recovery_ret != EXIT_SUCCESS) {
			sd_err("failed to resume the current vdi");
			ret = recovery_ret;
		}
	}
	free(inode_for_check);
	return ret;
}

static int vdi_object_dump_inode(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	struct sd_inode *inode = xzalloc(sizeof(*inode));
	struct sd_inode_header *hdr = &inode->header;
	struct json_object *data_obj = NULL;
	uuid_t uuid;
	char uuid_str[UUID_STR_LEN];
	int ret;

	ret = read_vdi_obj(vdiname, vdi_cmd_data.snapshot_id,
			   vdi_cmd_data.snapshot_tag, vdi_acl_id(),
			   NULL, inode, SD_INODE_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("no inode object");
		return EXIT_FAILURE;
	}

	if (json_output) {
		out_obj = json_object_new_object();
		JSON_ADD_STRING(out_obj, "name", hdr->name);
		if (strlen(hdr->tag))
			JSON_ADD_STRING(out_obj, "tag", hdr->tag);
		JSON_ADD_UINT64(out_obj, "create_time", hdr->create_time);
		if (hdr->snap_ctime) {
			JSON_ADD_UINT64(out_obj, "snapshot_create_time",
					hdr->snap_ctime);
		}
		JSON_ADD_UINT64(out_obj, "vdi_size", hdr->vdi_size);
	} else {
		printf("name: %s\n", hdr->name);
		printf("tag: %s\n", hdr->tag);
		printf("create_time: %"PRIx64"\n", hdr->create_time);
		printf("snap_ctime: %"PRIx64"\n", hdr->snap_ctime);
		printf("vdi_size: %"PRIu64"\n", hdr->vdi_size);
	}
	memcpy((char *)uuid, &hdr->uuid, 16);
	if (!uuid_is_null(uuid)) {
		uuid_unparse(uuid, uuid_str);
		if (json_output)
			JSON_ADD_STRING(out_obj, "uuid", uuid_str);
		else
			printf("uuid: %s\n", uuid_str);
	}

	if (json_output) {
		JSON_ADD_INT(out_obj, "copy_policy",
			     hdr->copy_policy);
		JSON_ADD_STRING(out_obj, "store_policy",
			sd_store_policy_is_hyper(hdr) ? "hyper" : "default");
		JSON_ADD_INT(out_obj, "nr_copies",
			     hdr->nr_copies);
		JSON_ADD_INT(out_obj, "block_size_shift",
			     hdr->block_size_shift);
		if (hdr->snap_id)
			JSON_ADD_INT(out_obj, "snap_id",
				     hdr->snap_id);
		JSON_ADD_INT(out_obj, "vdi_id",
			     hdr->vdi_id);
		JSON_ADD_INT(out_obj, "parent_vdi_id",
			     hdr->parent_vdi_id);
		JSON_ADD_INT(out_obj, "btree_counter",
			     hdr->btree_counter);
		if (hdr->vdi_flags & SD_VDI_FLAG_ACL) {
			JSON_ADD_BOOL(out_obj, "is_acl_vdi", true);
			JSON_ADD_INT(out_obj, "max_acl_vdi_id",
				     hdr->max_data_id_nr);
		} else if (hdr->acl_id)
			JSON_ADD_INT(out_obj, "acl_id", hdr->acl_id);
		data_obj = json_object_new_array();
	} else {
		printf("copy_policy: %d\n", hdr->copy_policy);
		printf("store_policy: %s\n",
		       sd_store_policy_is_hyper(hdr) ? "hyper" : "default");
		printf("nr_copies: %d\n", hdr->nr_copies);
		printf("block_size_shift: %d\n", hdr->block_size_shift);
		printf("snap_id: %"PRIu32"\n", hdr->snap_id);
		printf("vdi_id: %"PRIx32"\n", hdr->vdi_id);
		printf("parent_vdi_id: %"PRIx32"\n", hdr->parent_vdi_id);
		printf("btree_counter: %"PRIu32"\n", hdr->btree_counter);
		if (hdr->vdi_flags & SD_VDI_FLAG_ACL)
			printf("acl_vdi_id:\n");
		else
			printf("data_vdi_id:\n");
	}
	for (int i = 0; i < SD_INODE_DATA_INDEX; i++) {
		if (!inode->data_vdi_id[i])
			continue;
		if (json_output) {
			struct json_object *data_vdi_obj =
				json_object_new_object();
			if (hdr->vdi_flags & SD_VDI_FLAG_ACL) {
				JSON_ADD_INT(data_vdi_obj, "acl_vdi_id",
					     inode->data_vdi_id[i]);
			} else {
				struct json_object *gref_obj =
					json_object_new_object();
				JSON_ADD_INT(data_vdi_obj, "data_vdi_id",
					     inode->data_vdi_id[i]);
				JSON_ADD_INT(gref_obj, "generation",
					     inode->gref[i].generation);
				JSON_ADD_INT(gref_obj, "count",
					     inode->gref[i].count);
				json_object_object_add(data_vdi_obj, "gref",
						       gref_obj);
			}
			if ((hdr->vdi_flags & SD_VDI_FLAG_ACL) &&
			    i < hdr->max_data_id_nr)
				json_object_array_add(data_obj, data_vdi_obj);
			else
				json_object_put(data_vdi_obj);
		} else
			printf("%d: %"PRIx32"\n", i, inode->data_vdi_id[i]);
	}
	if (!json_output)
		printf("gref:\n");
	for (int i = 0; i < SD_INODE_DATA_INDEX; i++) {
		if (!inode->data_vdi_id[i]) {
			if (!json_output &&
			    (inode->gref[i].generation || inode->gref[i].count))
				printf("WARNING: index %d doesn't have data vdi"
				       " ID but its generation and count is not"
				       " zero(%d, %d)", i,
				       inode->gref[i].generation,
				       inode->gref[i].count);
			continue;
		}
		if (!json_output)
			printf("%d: %"PRIx32", %d, %d\n", i,
			       inode->data_vdi_id[i],
			       inode->gref[i].generation,
			       inode->gref[i].count);
	}

	if (json_output) {
		const char *o;

		if (hdr->vdi_flags & SD_VDI_FLAG_ACL)
			json_object_object_add(out_obj, "acl_vdi", data_obj);
		else
			json_object_object_add(out_obj, "data_vdi", data_obj);
		o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}
	return EXIT_SUCCESS;
}

static struct subcommand vdi_object_cmd[] = {
	{"location", NULL, NULL, "show object location information",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG, vdi_object_location},
	{"map", NULL, NULL, "show object map information",
	 NULL, CMD_NEED_ARG, vdi_object_map},
	{"dump-inode", NULL, NULL, "dump inode information",
	 NULL, CMD_NEED_ARG, vdi_object_dump_inode},
	{NULL},
};

static int vdi_object(int argc, char **argv)
{
	return do_generic_subcommand(vdi_object_cmd, argc, argv);
}

static void construct_vdi_tree(uint32_t vid, const char *name, const char *tag,
			       uint32_t snapid, uint32_t flags,
			       const struct sd_inode *i, void *data)
{
	add_vdi_tree(name, tag, vid, i->header.parent_vdi_id, false);
}

static bool is_vdi_standalone(uint32_t vid, const char *name)
{
	struct vdi_tree *vdi;

	init_tree();
	if (parse_vdi(construct_vdi_tree, SD_INODE_HEADER_SIZE,
		      NULL, true, false) < 0)
		return EXIT_SYSFAIL;

	vdi = find_vdi_from_root(vid, name);
	if (!vdi) {
		sd_err("failed to construct vdi tree");
		return false;
	}

	return !vdi->pvid && list_empty(&vdi->children);
}

#define ALTER_VDI_COPY_PRINT				\
	"    __\n"				\
	"   ()'`;\n"				\
	"   /\\|`  Caution! Changing VDI's redundancy level will affect\n" \
	"  /  |   the VDI itself only and trigger recovery.\n" \
	"(/_)_|_  Are you sure you want to continue? [yes/no]: "

static int vdi_alter_copy(int argc, char **argv)
{
	int ret, old_nr_copies;
	uint32_t vid;
	const char *vdiname = argv[optind++];
	struct sd_inode_header inode;
	struct sd_req hdr;

	if (vdi_cmd_data.copy_policy != 0) {
		sd_err("Changing redundancy level of erasure coded vdi "
			   "is not supported yet.");
		return EXIT_USAGE;
	}
	if (!vdi_cmd_data.nr_copies) {
		vdi_cmd_data.nr_copies = SD_DEFAULT_COPIES;
		printf("The vdi's redundancy level is not specified, "
			   "use %d as default.\n", SD_DEFAULT_COPIES);
	}

	if (!vdi_cmd_data.force && (vdi_cmd_data.nr_copies > sd_nodes_nr)) {
		char info[1024];
		snprintf(info, sizeof(info), "Number of copies (%d) is larger "
			 "than number of nodes (%d).\n"
			 "Are you sure you want to continue? [yes/no]: ",
			 vdi_cmd_data.nr_copies, sd_nodes_nr);
		confirm(info);
	}

	ret = read_vdi_obj(vdiname, 0, "", vdi_acl_id(),
			   &vid, &inode, SD_INODE_HEADER_SIZE);
	if (ret != EXIT_SUCCESS) {
		sd_err("Reading %s's vdi object failure.", vdiname);
		return EXIT_FAILURE;
	}

	if (inode.copy_policy) {
		sd_err("%s's copy policy is erasure code, "
			   "changing it is not supported yet.", vdiname);
		return EXIT_FAILURE;
	}

	old_nr_copies = inode.nr_copies;
	if (old_nr_copies == vdi_cmd_data.nr_copies) {
		sd_err("%s's redundancy level is already set to %d, "
			   "nothing changed.", vdiname, old_nr_copies);
		return EXIT_FAILURE;
	}

	if (!is_vdi_standalone(vid, inode.name)) {
		sd_err("Only standalone vdi supports "
			   "changing redundancy level.");
		sd_err("Please clone %s with -n (--no-share) "
			   "option first.", vdiname);
		return EXIT_FAILURE;
	}

	if (!vdi_cmd_data.force)
		confirm(ALTER_VDI_COPY_PRINT);

	inode.nr_copies = vdi_cmd_data.nr_copies;
	ret = dog_write_object(vid_to_vdi_oid(vid), 0, &inode,
			SD_INODE_HEADER_SIZE, 0, SD_FLAG_CMD_DIRECT,
			old_nr_copies, inode.copy_policy, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Overwrite the vdi object's header of %s failure "
			   "while setting its redundancy level.", vdiname);
		return EXIT_FAILURE;
	}

	sd_init_req(&hdr, SD_OP_ALTER_VDI_COPY);
	hdr.vdi_state.new_vid = vid;
	hdr.vdi_state.copies = vdi_cmd_data.nr_copies;
	hdr.vdi_state.copy_policy = vdi_cmd_data.copy_policy;
	hdr.vdi_state.block_size_shift = inode.block_size_shift;

	ret = send_light_req(&sd_nid, &hdr);
	if (ret == 0) {
		sd_info("%s's redundancy level is set to %d, the old one was %d.",
				vdiname, vdi_cmd_data.nr_copies, old_nr_copies);
		return EXIT_SUCCESS;
	}
	sd_err("Changing %s's redundancy level failure.", vdiname);
	return EXIT_FAILURE;
}

struct alter_acl_info {
	const char *name;
	uint32_t acl;
	uint32_t *vids;
	size_t nr_vids;
	size_t max_vids;
};

/*
 * Collect every VDI sharing the name and the ACL of the one we are about to
 * alter.  A VDI is looked up by name, so the working VDI and its snapshots
 * have to be moved to the new ACL together to stay reachable.
 */
static void collect_vdi_family(uint32_t vid, const char *name, const char *tag,
			       uint32_t snapid, uint32_t flags,
			       const struct sd_inode *i, void *data)
{
	struct alter_acl_info *info = data;

	if (strcmp(name, info->name) != 0)
		return;
	if (i->header.acl_id != info->acl)
		return;

	if (info->nr_vids == info->max_vids) {
		info->max_vids = info->max_vids ? info->max_vids * 2 : 8;
		info->vids = xrealloc(info->vids,
				      info->max_vids * sizeof(*info->vids));
	}
	info->vids[info->nr_vids++] = vid;
}

/* Set the ACL of a single inode object; returns an EXIT_ code. */
static int alter_one_acl(const char *vdiname, uint32_t vid, uint32_t old_acl,
			 uint32_t new_acl)
{
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_ALTER_VDI_ACL);
	hdr.vdi_state.old_vid = vid;
	hdr.vdi_state.old_acl = old_acl;
	hdr.vdi_state.acl = new_acl;

	if (send_light_req(&sd_nid, &hdr) != 0) {
		sd_err("Setting %s's (%"PRIx32") ACL failure.", vdiname, vid);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/*
 * A locked VDI must not change its ACL, and neither must one which some other
 * node knows under a different ACL.  Check the whole family up front, so that
 * we do not have to move half of it back on failure.
 */
static int check_vdi_family(const struct alter_acl_info *info)
{
	struct vdi_state *vs;
	int count = 0, ret = EXIT_SUCCESS;

	vs = get_vdi_state(&count);
	if (!vs) {
		sd_err("Failed to get VDI state");
		return EXIT_SYSFAIL;
	}

	for (size_t idx = 0; idx < info->nr_vids; idx++) {
		const uint32_t vid = info->vids[idx];
		const struct vdi_state *found = NULL;

		for (int j = 0; j < count; j++) {
			if (vs[j].vid == vid) {
				found = &vs[j];
				break;
			}
		}

		if (!found) {
			sd_err("Failed to find VDI state of %s (%"PRIx32").",
			       info->name, vid);
			ret = EXIT_SYSFAIL;
			break;
		}
		if (found->acl != info->acl) {
			sd_err("%s (%"PRIx32") belongs to ACL %"PRIu32
			       ", not %"PRIu32".", info->name, vid, found->acl,
			       info->acl);
			ret = EXIT_FAILURE;
			break;
		}
		if (found->lock_state != LOCK_STATE_UNLOCKED) {
			sd_err("%s (%"PRIx32") is locked, cannot change its "
			       "ACL.", info->name, vid);
			ret = EXIT_FAILURE;
			break;
		}
	}

	free(vs);
	return ret;
}

/*
 * Move a VDI and its snapshots from one ACL to another.  On failure the VDIs
 * which have been moved already are moved back, so that the family either
 * belongs to the new ACL as a whole or stays where it was.
 */
int do_vdi_alter_acl(const char *vdiname, uint32_t old_acl, uint32_t new_acl)
{
	struct alter_acl_info info = { .name = vdiname, .acl = old_acl };
	int ret = EXIT_SUCCESS;

	if (parse_vdi(collect_vdi_family, SD_INODE_HEADER_SIZE, &info,
		      true, false) < 0) {
		sd_err("Failed to read the list of VDIs.");
		ret = EXIT_SYSFAIL;
		goto out;
	}

	if (!info.nr_vids) {
		sd_err("Failed to find %s in ACL %"PRIu32".", vdiname, old_acl);
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = check_vdi_family(&info);
	if (ret != EXIT_SUCCESS)
		goto out;

	for (size_t idx = 0; idx < info.nr_vids; idx++) {
		ret = alter_one_acl(vdiname, info.vids[idx], old_acl, new_acl);
		if (ret == EXIT_SUCCESS)
			continue;

		/* undo the inodes we already moved to keep the family whole */
		while (idx-- > 0) {
			if (alter_one_acl(vdiname, info.vids[idx], new_acl,
					  old_acl) != EXIT_SUCCESS)
				sd_err("%s (%"PRIx32") is left behind in ACL %"
				       PRIu32".", vdiname, info.vids[idx],
				       new_acl);
		}
		goto out;
	}
out:
	free(info.vids);
	return ret;
}

static int vdi_alter_acl(int argc, char **argv)
{
	const char *vdiname = argv[optind++];
	const uint32_t old_acl = vdi_acl_id();
	const char *old_name = acl_option_name();
	const char *new_name = argv[optind];
	uint32_t new_acl = 0;
	int ret;

	if (!new_name) {
		sd_err("Please specify the new ACL for the VDI");
		return EXIT_USAGE;
	}
	/* 'none' drops the ACL; it shadows an ACL which goes by that name */
	if (strcmp(new_name, "none") &&
	    lookup_acl_name(new_name, &new_acl) != SD_RES_SUCCESS)
		return EXIT_FAILURE;

	if (new_acl == old_acl) {
		sd_err("%s already belongs to ACL %s.", vdiname, new_name);
		return EXIT_FAILURE;
	}

	ret = do_vdi_alter_acl(vdiname, old_acl, new_acl);
	if (ret == EXIT_SUCCESS)
		sd_info("%s's ACL is set to %s, the old one was %s", vdiname,
			new_name, old_name);

	return ret;
}

static int lock_list(int argc, char **argv)
{
	int ret = 0;

	int count = 0;
	struct vdi_state *vs = get_vdi_state(&count);
	if (!vs) {
		sd_err("Failed to get VDI state");
		ret = EXIT_SYSFAIL;
		goto out;
	}
	sd_assert(count >= 0);

	const size_t nmemb = (size_t)count;
	qsort(vs, nmemb, sizeof(struct vdi_state), compare_vdi_state_by_vid);

	if (!json_output)
		printf("  Name         Id  VDI id  Tag            Owner node(s)\n");
	else
		out_obj = json_object_new_array();

	struct lock_list_data data = { .sorted = vs, .nmemb = nmemb };
	ret = parse_vdi(print_lock_list, SD_INODE_SIZE, &data, true, false);

	if (json_output) {
		const char *o;

		o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}
	ret = ret ? EXIT_SYSFAIL : EXIT_SUCCESS;

out:
	free(vs);
	return ret;
}

static int lock_lock(int argc, char **argv)
{
	int ret = 0;
	char vdidesc[VDI_DESC_MAX] = { 0 };
	const char *vdiname = argv[optind];
	const uint32_t snapid = vdi_cmd_data.snapshot_id;
	const char *tag = vdi_cmd_data.snapshot_tag;
	uint32_t acl_id = vdi_acl_id();
	uint32_t vid = 0;
	const struct node_id *owner = &vdi_cmd_data.owner;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

	if (!vdiname) {
		sd_err("VDI name must be specified");
		return EXIT_USAGE;
	}

	ret = find_vdi_name(vdiname, snapid, tag, acl_id, &vid);
	describe_vdi(vdiname, snapid, tag, vid, vdidesc);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find VDI %s: %s",
		       vdidesc, sd_strerror(ret));
		return EXIT_FAILURE;
	}

	/* SD_OP_LOCK_VDI looks up the VDI by name, not by vid */
	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, vdiname);
	if (tag)
		pstrcpy(buf + SD_MAX_VDI_LEN, SD_MAX_VDI_TAG_LEN, tag);

	if (!node_id_is_null(owner)) {
		sd_init_req(&hdr, SD_OP_REGISTER_VDI);
		hdr.vdi_lock.snapid = snapid;
		hdr.vdi_lock.acl = acl_id;
		memcpy(hdr.vdi_lock.addr, owner->addr, sizeof(owner->addr));
		hdr.vdi_lock.port = owner->port;
	} else {
		sd_init_req(&hdr, SD_OP_LOCK_VDI);
		hdr.vdi.snapid = snapid;
		hdr.vdi.acl = acl_id;
	}
	hdr.data_length = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
	hdr.flags = SD_FLAG_CMD_WRITE;

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0) {
		sd_err("Failed to lock VDI %s", vdidesc);
		return EXIT_SYSFAIL;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to lock VDI %s: %s",
		       vdidesc, sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int lock_unlock(int argc, char **argv)
{
	struct vdi_state *vs = NULL;
	int ret = EXIT_SUCCESS;
	char vdidesc[VDI_DESC_MAX] = { 0 };

	const char *vdiname = argv[optind];
	if (!vdiname) {
		sd_err("VDI name must be specified");
		ret = EXIT_USAGE;
		goto out;
	}

	const uint32_t snapid = vdi_cmd_data.snapshot_id;
	const char *tag = vdi_cmd_data.snapshot_tag;
	uint32_t acl_id = vdi_acl_id();
	uint32_t vid = 0;

	ret = find_vdi_name(vdiname, snapid, tag, acl_id, &vid);
	describe_vdi(vdiname, snapid, tag, vid, vdidesc);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find VDI %s: %s",
		       vdidesc, sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}
	sd_assert(vid > 0);

	/* TODO: get not all the status but only the state of target VDI */
	int vs_count = 0;
	vs = get_vdi_state(&vs_count);
	if (!vs) {
		sd_err("Failed to get VDI state");
		ret = EXIT_SYSFAIL;
		goto out;
	}
	sd_assert(vs_count >= 0);

	/* run linear search to find vdi_state whose ID is vid */
	size_t nmemb = (size_t)vs_count;
	const struct vdi_state key = { .vid = vid };
	const struct vdi_state *found = lfind(&key, vs, &nmemb,
					      sizeof(struct vdi_state),
					      compare_vdi_state_by_vid);
	if (!found) {
		sd_err("Failed to find VDI state %s", vdidesc);
		ret = EXIT_SYSFAIL;
		goto out;
	}

	switch (found->lock_state) {
	case LOCK_STATE_UNLOCKED:
		sd_err("VDI %s is not locked", vdidesc);
		ret = EXIT_FAILURE;
		goto out;
	case LOCK_STATE_LOCKED:
		if (acl_id) {
			sd_err("VDI %s is locked exclusively", vdidesc);
			ret = EXIT_SYSFAIL;
			goto out;
		}
		acl_id = LOCK_TYPE_NORMAL;
		break;
	case LOCK_STATE_SHARED:
		if (!acl_id)
			acl_id = LOCK_TYPE_SHARED;
		break;
	default:
		sd_err("VDI %s unknown lock state (%" PRIu32 ")",
		       vdidesc, found->lock_state);
		ret = EXIT_SYSFAIL;
		goto out;
	}

	const struct node_id *owner = &vdi_cmd_data.owner;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	if (!node_id_is_null(owner)) {
		sd_init_req(&hdr, SD_OP_UNREGISTER_VDI);
		hdr.vdi_lock.vid = vid;
		hdr.vdi_lock.acl = acl_id;
		memcpy(hdr.vdi_lock.addr, owner->addr, sizeof(owner->addr));
		hdr.vdi_lock.port = owner->port;
	} else {
		sd_init_req(&hdr, SD_OP_RELEASE_VDI);
		hdr.vdi.base_vdi_id = vid;
		hdr.vdi.acl = acl_id;
	}

	ret = dog_exec_req(&sd_nid, &hdr, NULL);
	if (ret < 0)
		ret = EXIT_FAILURE;
	else if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to unlock VDI %s: %s", vdiname,
		       sd_strerror(rsp->result));
		ret = EXIT_FAILURE;
	} else
		ret = EXIT_SUCCESS;

out:
	free(vs);
	return ret;
}

static struct subcommand vdi_lock_cmd[] = {
	{"list", NULL, NULL, "list locked VDIs", NULL, 0, lock_list},
	{"lock", "<vdiname>", NULL, "lock VDI", NULL, CMD_NEED_ARG, lock_lock},
	{"unlock", "<vdiname>", NULL, "unlock locked VDI forcibly", NULL,
	 CMD_NEED_ARG, lock_unlock},
	{NULL},
};

static int vdi_lock(int argc, char **argv)
{
	return do_generic_subcommand(vdi_lock_cmd, argc, argv);
}

static struct subcommand vdi_cmd[] = {
	{"check", "<vdiname>", "seaphTA", "check and repair image's consistency",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_check, vdi_options},
	{"create", "<vdiname> <size>", "PycajphrvzTA", "create an image",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_create, vdi_options},
	{"snapshot", "<vdiname>", "sajphrvTRA", "create a snapshot",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_snapshot, vdi_options},
	{"clone", "<src vdi> <dst vdi>", "sPnajphrvTA", "clone an image",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_clone, vdi_options},
	{"delete", "<vdiname>", "saphTBImA", "delete an image",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_delete, vdi_options},
	{"rollback", "<vdiname>", "saphfrvTBIA", "rollback to a snapshot",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_rollback, vdi_options},
	{"list", "[vdiname]", "ajprhoTA", "list images",
	 NULL, 0, vdi_list, vdi_options},
	{"tree", NULL, "ajphTA", "show images in tree view format",
	 NULL, 0, vdi_tree, vdi_options},
	{"graph", NULL, "aphTA", "show images in Graphviz dot format",
	 NULL, 0, vdi_graph, vdi_options},
	{"object", "<vdiname>", "isajphTA",
	 "show object information in the image",
	 vdi_object_cmd, CMD_NEED_ARG,
	 vdi_object, vdi_options},
	{"track", "<vdiname>", "isajphoTA",
	 "show the object epoch trace in the image",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ARG,
	 vdi_track, vdi_options},
	{"setattr", "<vdiname> <key> [value]", "dxaphTA", "set a VDI attribute",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_setattr, vdi_options},
	{"getattr", "<vdiname> <key>", "aphTA", "get a VDI attribute",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_getattr, vdi_options},
	{"resize", "<vdiname> <new size>", "aphTA", "resize an image",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_resize, vdi_options},
	{"read", "<vdiname> [<offset> [<len>]]", "saphTA",
	 "read data from an image",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_read, vdi_options},
	{"write", "<vdiname> [<offset> [<len>]]", "apwhTA",
	 "write data to an image",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 vdi_write, vdi_options},
	{"backup", "<vdiname>", "sFaphTA",
	 "create an incremental backup between two snapshots and outputs to STDOUT",
	 NULL, CMD_NEED_ROOT|CMD_NEED_NODELIST|CMD_NEED_ARG,
	 vdi_backup, vdi_options},
	{"restore", "<vdiname>", "saphTBIA",
	 "restore snapshot images from a backup provided in STDIN",
	 NULL, CMD_NEED_ROOT|CMD_NEED_NODELIST|CMD_NEED_ARG,
	 vdi_restore, vdi_options},
	{"alter-copy", "<vdiname>", "caphTfA", "set the vdi's redundancy level",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG|CMD_NEED_NODELIST, vdi_alter_copy, vdi_options},
	{"alter-acl", "<vdiname> <new acl>", "aphTA", "set the vdi's ACL",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG, vdi_alter_acl, vdi_options},
	{"lock", NULL, "sajphTAO", "See 'dog vdi lock' for more information",
	 vdi_lock_cmd, CMD_NEED_ROOT|CMD_NEED_ARG, vdi_lock, vdi_options},
	{NULL,},
};

static int vdi_parser(int ch, const char *opt)
{
	char *p;
	uint8_t block_size_shift;

	switch (ch) {
	case 'P':
		vdi_cmd_data.prealloc = true;
		break;
	case 'n':
		vdi_cmd_data.no_share = true;
		break;
	case 'i':
		if (strncmp(opt, "0x", 2) == 0)
			vdi_cmd_data.index = strtol(opt, &p, 16);
		else
			vdi_cmd_data.index = strtol(opt, &p, 10);
		if (opt == p) {
			sd_err("The index must be a decimal integer "
				"or a hexadecimal integer started with 0x");
			exit(EXIT_FAILURE);
		}
		break;
	case 's':
		vdi_cmd_data.snapshot_id = strtol(opt, &p, 10);
		if (opt == p || *p != '\0') {
			vdi_cmd_data.snapshot_id = 0;
			pstrcpy(vdi_cmd_data.snapshot_tag,
				sizeof(vdi_cmd_data.snapshot_tag), opt);
		} else if (vdi_cmd_data.snapshot_id == 0) {
			fprintf(stderr,
				"The snapshot id must be larger than zero\n");
			exit(EXIT_FAILURE);
		}
		break;
	case 'x':
		vdi_cmd_data.exclusive = true;
		break;
	case 'd':
		vdi_cmd_data.delete = true;
		break;
	case 'w':
		vdi_cmd_data.writeback = true;
		break;
	case 'c':
		vdi_cmd_data.nr_copies = parse_copy(opt,
						    &vdi_cmd_data.copy_policy);
		if (!vdi_cmd_data.nr_copies) {
			sd_err("Invalid parameter %s\n"
			       "To create replicated vdi, set -c x\n"
			       "  x(1 to %d)   - number of replicated copies\n"
			       "To create erasure coded vdi, set -c x:y\n"
			       "  x(2,4,8,16)  - number of data strips\n"
			       "  y(1 to 15)   - number of parity strips",
			       opt, SD_MAX_COPIES);
			exit(EXIT_FAILURE);
		}
		break;
	case 'F':
		vdi_cmd_data.from_snapshot_id = strtol(opt, &p, 10);
		if (opt == p || *p != '\0') {
			vdi_cmd_data.from_snapshot_id = 0;
			pstrcpy(vdi_cmd_data.from_snapshot_tag,
				sizeof(vdi_cmd_data.from_snapshot_tag), opt);
		}
		break;
	case 'f':
		vdi_cmd_data.force = true;
		break;
	case 'y':
		vdi_cmd_data.store_policy |= SD_HYPER_STORE_POLICY;
		if (vdi_cmd_data.block_size_shift) {
			sd_info("Don't specify both -y and -z options, please");
			exit(EXIT_FAILURE);
		}
		break;
	case 'o':
		vdi_cmd_data.oid = strtoull(opt, &p, 16);
		if (opt == p) {
			sd_err("object id must be a hex integer");
			exit(EXIT_FAILURE);
		}
		break;
	case 'e':
		vdi_cmd_data.exist = true;
		break;
	case 'z':
		block_size_shift = (uint8_t)atoi(opt);
		if (block_size_shift > 31) {
			sd_err("Object Size is limited to 2^31."
			       " Please set shift bit lower than 31");
			exit(EXIT_FAILURE);
		} else if (block_size_shift < 20) {
			sd_err("Object Size is larger than 2^20."
			       " Please set shift bit larger than 20");
			exit(EXIT_FAILURE);
		}
		if (vdi_cmd_data.store_policy == SD_HYPER_STORE_POLICY) {
			sd_info("Don't specify both -y and -z options, please");
			exit(EXIT_FAILURE);
		}
		vdi_cmd_data.block_size_shift = block_size_shift;
		break;
	case 'R':
		vdi_cmd_data.reduce_identical_snapshots = true;
		break;
	case 'B':
		vdi_cmd_data.nr_batched_reclamation = strtol(opt, &p, 10);
		if (opt == p) {
			sd_err("The number of batched reclamation is"
			       " invalid: %s", opt);
			exit(EXIT_FAILURE);
		}
		if (vdi_cmd_data.nr_batched_reclamation <= 0) {
			sd_err("The number of batched reclamation must be"
				"positive integer");
			exit(EXIT_FAILURE);
		}
		break;
	case 'I':
		vdi_cmd_data.reclamation_interval = strtol(opt, &p, 10);
		if (opt == p) {
			sd_err("The interval of batched reclamation is"
			       " invalid: %s", opt);
			exit(EXIT_FAILURE);
		}
		if (vdi_cmd_data.reclamation_interval <= 0) {
			sd_err("The interval of batched reclamation must be"
				"positive integer");
			exit(EXIT_FAILURE);
		}
		break;
	case 'm':
		vdi_cmd_data.nr_max_reclaim = strtol(opt, &p, 10);
		if (opt == p) {
			sd_err("The maximum number of reclamation is"
			       " invalid: %s", opt);
			exit(EXIT_FAILURE);
		}
		if (vdi_cmd_data.nr_max_reclaim <= 0) {
			sd_err("The maximum number of reclamation must be"
				"positive integer");
			exit(EXIT_FAILURE);
		}
		break;
	case 'A':
		pstrcpy(vdi_cmd_data.acl_name, SD_MAX_VDI_LEN, opt);
		break;
	case 'O':
		if (parse_vdi_address(opt, &vdi_cmd_data.owner) < 0)
			exit(EXIT_USAGE);
		break;
	}

	return 0;
}

struct command vdi_command = {
	"vdi",
	vdi_cmd,
	vdi_parser
};
