/*
 * Copyright (C) 2025 Hannes Reinecke, SUSE
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
#include "sha1.h"
#include "fec.h"
#include "json.h"

static struct json_object *out_obj;

static struct sd_option acl_options[] = {
	{'s', "snapshot", true, "specify a snapshot id or tag name"},
	{'c', "copies", true, "specify the data redundancy level"},
	{'f', "force", false, "do operation forcibly"},
	{ 0, NULL, false, NULL },
};

static struct acl_cmd_data {
	int snapshot_id;
	char snapshot_tag[SD_MAX_VDI_TAG_LEN];
	int nr_copies;
	uint8_t copy_policy;
	uint8_t store_policy;
	bool force;
} acl_cmd_data = { ~0, };

/*
 * An ACL is an ordinary VDI carrying the SD_VDI_FLAG_ACL marker; the VDIs it
 * grants access to are listed in its data_vdi_id[] array.  Look one up by name
 * and read the first 'size' bytes of its inode, which must cover at least the
 * header.
 */
static int read_acl_inode(const char *aclname, uint32_t *acl_vid,
			  struct sd_inode *inode, size_t size)
{
	uint32_t vid;
	int ret;

	ret = find_vdi_name(aclname, 0, "", 0, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open ACL %s: %s", aclname, sd_strerror(ret));
		return ret;
	}

	ret = dog_read_object(vid_to_vdi_oid(vid), inode, size, 0, true);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (!vdi_is_acl(&inode->header)) {
		sd_err("%s is not an ACL", aclname);
		return SD_RES_INVALID_PARMS;
	}

	*acl_vid = vid;
	return SD_RES_SUCCESS;
}

struct acl_vdi_info {
	uint32_t acl;
	unsigned int count;
};

static void count_acl_objs(uint32_t vid, const char *name, const char *tag,
			   uint32_t snapid, uint32_t flags,
			   const struct sd_inode *i, void *data)
{
	struct acl_vdi_info *info = data;

	if (i->header.acl_id == info->acl)
		info->count++;
}

static int acl_create(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	char buf[SD_MAX_VDI_LEN];
	struct acl_vdi_info info;
	uint32_t acl_vid;
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	/*
	 * 'dog vdi -A any' means every ACL and 'dog vdi alter-acl <vdi> none'
	 * means no ACL at all, so neither word may name one.
	 */
	if (!strcmp(aclname, "any") || !strcmp(aclname, "none")) {
		sd_err("'%s' is reserved and cannot name an ACL", aclname);
		return EXIT_FAILURE;
	}

	sd_init_req(&hdr, SD_OP_CLUSTER_STATUS);
	ret = dog_exec_req(&sd_nid, &hdr, NULL);
	if (ret < 0) {
		sd_err("Fail to execute request: SD_OP_CLUSTER_STATUS");
		return EXIT_FAILURE;
	}

	if (!rsp->cluster.ctime) {
		sd_err("Failed to create VDI %s: %s", aclname,
		       sd_strerror(SD_RES_WAIT_FOR_FORMAT));
		return EXIT_FAILURE;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, aclname);

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_MAX_VDI_LEN;
	hdr.vdi.vdi_size = SD_INODE_SIZE;
	hdr.vdi.vdi_flags = SD_VDI_FLAG_ACL;

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0) {
		sd_err("Failed to create ACL %s",
		       aclname);
		return EXIT_FAILURE;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	acl_vid = rsp->vdi.vdi_id;

	/* Sanity check: the ACL should not be referenced by any VDI objects */
	memset(&info, 0, sizeof(info));
	info.acl = acl_vid;
	if (parse_vdi(count_acl_objs, SD_INODE_HEADER_SIZE,
		      &info, true, false) < 0)
		return EXIT_SYSFAIL;
	if (info.count) {
		sd_err("ACL %"PRIx32" referenced by %u VDI ACLs",
		       acl_vid, info.count);
		if (!acl_cmd_data.force) {
			sd_init_req(&hdr, SD_OP_DEL_VDI);
			hdr.flags = SD_FLAG_CMD_WRITE;
			hdr.data_length = sizeof(buf);
			memset(buf, 0, sizeof(buf));
			pstrcpy(buf, SD_MAX_VDI_LEN, aclname);

			ret = dog_exec_req(&sd_nid, &hdr, buf);
			if (ret < 0) {
				sd_err("Failed to execute SD_OP_DEL_VDI");
				return EXIT_SYSFAIL;
			}
			return EXIT_FAILURE;
		}
	}
	if (verbose) {
		if (json_output) {
			const char *o;

			out_obj = json_object_new_object();
			JSON_ADD_INT(out_obj, "vdi_id", acl_vid);
			o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		} else if (raw_output)
			printf("%x\n", acl_vid);
		else
			printf("VDI ID of newly created ACL: %x\n", acl_vid);
	}
	return EXIT_SUCCESS;
}

static int acl_delete(int args, char **argv)
{
	const char *aclname = argv[optind++];
	char buf[SD_MAX_VDI_LEN];
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	struct sd_inode *inode;
	struct acl_vdi_info info;
	uint32_t acl_vid;
	int ret = EXIT_SUCCESS;

	/* refuse to delete an ordinary VDI which happens to share the name */
	inode = xzalloc(SD_INODE_HEADER_SIZE);
	ret = read_acl_inode(aclname, &acl_vid, inode, SD_INODE_HEADER_SIZE);
	free(inode);
	if (ret != SD_RES_SUCCESS)
		return ret == SD_RES_NO_VDI ? EXIT_MISSING : EXIT_FAILURE;

	/* refuse to delete an ACL which is still referenced by VDI objects */
	memset(&info, 0, sizeof(info));
	info.acl = acl_vid;
	if (parse_vdi(count_acl_objs, SD_INODE_HEADER_SIZE,
		      &info, true, false) < 0)
		return EXIT_SYSFAIL;
	if (info.count) {
		sd_err("ACL %"PRIx32" is not empty, %u VDI ACLs still in use",
		       acl_vid, info.count);
		if (!acl_cmd_data.force)
			return EXIT_FAILURE;
	}
	sd_init_req(&hdr, SD_OP_DEL_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(buf);
	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, aclname);

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0) {
		sd_err("Failed to execute SD_OP_DEL_VDI");
		return EXIT_SYSFAIL;
	}

	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to delete %s: %s", aclname,
		       sd_strerror(rsp->result));
		if (rsp->result == SD_RES_NO_VDI)
			ret = EXIT_MISSING;
		else
			ret = EXIT_FAILURE;
	}
	return ret;
}

static int acl_register(int argc, char **argv)
{
	int ret = 0;
	const char *aclname = argv[optind++];
	uint32_t acl_vid;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[SD_MAX_VDI_LEN];
	const char *owner = NULL;

	if (!argv[optind]) {
		sd_err("Owner must be specified");
		return EXIT_USAGE;
	}
	owner = argv[optind];

	ret = find_acl_name(aclname, &acl_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find ACL %s: %s",
		       aclname, sd_strerror(ret));
		return EXIT_FAILURE;
	}

	memset(buf, 0, sizeof(buf));

	sd_init_req(&hdr, SD_OP_REGISTER_VDI);
	hdr.vdi_lock.vid = acl_vid;
	hdr.vdi_lock.acl = LOCK_TYPE_SHARED;
	pstrcpy(buf, SD_MAX_VDI_LEN, owner);
	hdr.data_length = SD_MAX_VDI_LEN;
	hdr.flags = SD_FLAG_CMD_WRITE;

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0) {
		sd_err("Failed to register ACL %s owner", aclname);
		return EXIT_SYSFAIL;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to register ACL %s owner: %s",
		       aclname, sd_strerror(rsp->result));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int acl_unregister(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	int ret = EXIT_SUCCESS;
	uint32_t acl_vid;
	char buf[SD_MAX_VDI_LEN];
	const char *owner;

	if (!argv[optind]) {
		sd_err("Owner must be specified");
		return EXIT_USAGE;
	}
	owner = argv[optind];

	ret = find_acl_name(aclname, &acl_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find ACL %s: %s",
		       aclname, sd_strerror(ret));
		return EXIT_FAILURE;
	}

	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	sd_init_req(&hdr, SD_OP_UNREGISTER_VDI);
	hdr.vdi_lock.vid = acl_vid;
	hdr.vdi_lock.acl = LOCK_TYPE_SHARED;
	pstrcpy(buf, sizeof(buf), owner);
	hdr.data_length = sizeof(buf);
	hdr.flags = SD_FLAG_CMD_WRITE;
	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0) {
		sd_err("Failed to unregister ACL %s: %m", aclname);
		ret = EXIT_FAILURE;
	} else if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to unregister ACL %s: %s", aclname,
		       sd_strerror(rsp->result));
		ret = EXIT_FAILURE;
	} else
		ret = EXIT_SUCCESS;

	return ret;
}

static int acl_detail(int argc, char **argv)
{
	uint32_t acl_vid;
	const char *aclname = argv[optind];
	int ret = 0;
	struct vdi_lock_state *vls_data;
	uint32_t lock_state;

	if (json_output)
		out_obj = json_object_new_array();

	if (!aclname)
		return EXIT_USAGE;

	ret = find_acl_name(aclname, &acl_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find ACL %s: %s",
		       aclname, sd_strerror(ret));
		return EXIT_FAILURE;
	}
	ret = find_vdi_lock_state(acl_vid, LOCK_TYPE_ANY, UINT32_MAX,
				  &vls_data, &lock_state);
	if (ret < 0)
		return EXIT_FAILURE;
	if (json_output) {
		struct vdi_lock_state *vls = vls_data;
		const char *state_str;

		for (int i = 0; i < ret; i += sizeof(*vls)) {
			struct json_object *st_obj =
				json_object_new_object();
			const char *lock_str = "acl";

			if (ret - i < sizeof(*vls))
				break;
			JSON_ADD_INT(st_obj, "vid", vls->vid);
			switch (vls->acl) {
			case LOCK_TYPE_NORMAL:
				lock_str = "normal";
				vls->acl = 0;
				break;
			case LOCK_TYPE_SHARED:
				lock_str = "shared";
				vls->acl = 0;
				break;
			default:
				break;
			}
			JSON_ADD_STRING(st_obj, "type", lock_str);
			if (vls->acl)
				JSON_ADD_INT(st_obj, "acl", vls->acl);
			JSON_ADD_INT(st_obj, "count", vls->count);
			JSON_ADD_INT(st_obj, "index", vls->index);
			if (strlen(vls->owner))
				JSON_ADD_STRING(st_obj, "owner", vls->owner);
			JSON_ADD_STRING(st_obj, "sender",
					node_id_to_str(&vls->sender, false));
			switch(vls->state) {
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
				state_str = NULL;
				break;
			}
			if (state_str)
				JSON_ADD_STRING(st_obj, "state", state_str);
			json_object_array_add(out_obj, st_obj);
			vls++;
		}
	}
	free(vls_data);
	if (json_output) {
		const char *o;

		o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}

	return EXIT_SUCCESS;
}

struct get_acl_info {
	struct json_object *obj;
	const char *name;
	const char *tag;
	uint32_t snapid;
	uint32_t acl;
	uint8_t nr_copies;
	uint8_t copy_policy;
};

static void print_acl_list(uint32_t vid, const char *name, const char *tag,
			   uint32_t snapid, uint32_t flags,
			   const struct sd_inode *i, void *data)
{
	bool is_clone = false;
	time_t ti;
	struct tm tm;
	char dbuf[128];
	struct get_acl_info *info = data;
	struct json_object *acl_vdi_obj = NULL;
	struct json_object *acl_member_obj = NULL;
	bool is_acl = i->header.vdi_flags & SD_VDI_FLAG_ACL;
	uint32_t j;

	if (info) {
		if (info->name && strcmp(name, info->name) != 0)
			return;
	}

	/*
	 * The VDIs an ACL guards are ordinary VDIs printed as records of their
	 * own, so only JSON output has a place to put them; in text mode they
	 * would show up as bogus rows of the ACL table.
	 */
	if (is_acl && json_output) {
		acl_vdi_obj = json_object_new_array();
		acl_member_obj = json_object_new_array();

		for (j = 0; j < i->header.max_data_id_nr; j++) {
			struct get_acl_info vdi_info = { .obj = acl_vdi_obj };
			struct sd_inode *member_inode;
			uint32_t member_vid = i->data_vdi_id[j];
			uint32_t member_snapid;

			/* Print empty entries, too */
			if (!member_vid) {
				struct json_object *vdi_obj =
					json_object_new_object();
				json_object_array_add(vdi_info.obj, vdi_obj);
				continue;
			}

			member_inode = xzalloc(SD_INODE_HEADER_SIZE);
			if (dog_read_object(vid_to_vdi_oid(member_vid),
					    member_inode, SD_INODE_HEADER_SIZE,
					    0, true) == SD_RES_SUCCESS) {
				member_snapid =
					vdi_is_snapshot(&member_inode->header) ?
					member_inode->header.snap_id : 0;
				print_acl_list(member_vid,
					       member_inode->header.name,
					       member_inode->header.tag,
					       member_snapid, 0, member_inode,
					       &vdi_info);
			} else
				sd_err("Failed to read inode of VDI %"PRIx32,
				       member_vid);
			free(member_inode);
		}
		for (j = 0; j < sizeof(i->header.metadata);
		     j += SD_MAX_VDI_LEN) {
			char *member = (char *)&i->header.metadata[j];

			if (strlen(member))
				json_object_array_add(acl_member_obj,
					json_object_new_string(member));
		}
	}
	ti = i->header.create_time >> 32;
	if (raw_output) {
		snprintf(dbuf, sizeof(dbuf), "%" PRIu64, (uint64_t) ti);
	} else {
		localtime_r(&ti, &tm);
		strftime(dbuf, sizeof(dbuf), TIME_FORMAT, &tm);
	}

	if (i->header.snap_id == 1 && i->header.parent_vdi_id != 0)
		is_clone = true;

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
		JSON_ADD_STRING(vdi_obj, "create_time", dbuf);
		JSON_ADD_UINT64(vdi_obj, "vdi_epoch",
				i->header.vdi_epoch);
		JSON_ADD_BOOL(vdi_obj, "is_snapshot",
				 vdi_is_snapshot(&i->header));
		JSON_ADD_BOOL(vdi_obj, "is_clone", is_clone);
		if (strlen(i->header.tag))
			JSON_ADD_STRING(vdi_obj, "tag",
					i->header.tag);
		if (is_acl) {
			json_object_object_add(vdi_obj, "vdi", acl_vdi_obj);
			json_object_object_add(vdi_obj, "member",
					       acl_member_obj);
		}
		json_object_array_add(info->obj, vdi_obj);
	} else if (raw_output) {
		printf("%c ", vdi_is_snapshot(&i->header) ?
		       's' : (is_clone ? 'c' : '='));
		while (*name) {
			if (isspace(*name) || *name == '\\')
				putchar('\\');
			putchar(*name++);
		}
		printf(" %d %s %s %" PRIx32 " %s %" PRIu8 "\n",
		       snapid, strnumber(i->header.vdi_size),
		       dbuf, vid,
		       i->header.tag, i->header.block_size_shift);
	} else {
		printf("%c %-8s %5d %7s %s  %7" PRIx32
		       " %13s %3" PRIu8 "\n",
		       vdi_is_snapshot(&i->header) ?
		       's' : (is_clone ? 'c' : ' '),
		       name, snapid,
		       strnumber(i->header.vdi_size),
		       dbuf, vid,
		       i->header.tag, i->header.block_size_shift);
	}
}

static int acl_list(int argc, char **argv)
{
	const char *aclname = argv[optind];
	struct get_acl_info info;

	memset(&info, 0, sizeof(info));

	if (json_output) {
		out_obj = json_object_new_array();
		info.obj = out_obj;
	}
	else if (!raw_output)
		printf("  Name        Id    Size    Used  Shared"
		       "    Creation time   ACL id  Copies  Tag"
		       "   Block Size Shift\n");

	if (aclname) {
		info.name = aclname;
		if (parse_vdi(print_acl_list, SD_INODE_SIZE, &info,
			      true, true) < 0)
			return EXIT_SYSFAIL;
		if (json_output) {
			const char *o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		}
		return EXIT_SUCCESS;
	}

	if (parse_vdi(print_acl_list, SD_INODE_SIZE, &info, true, true) < 0)
		return EXIT_SYSFAIL;

	if (json_output) {
		const char *o;

		o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}
	return EXIT_SUCCESS;
}

/*
 * Print the VDIs guarded by an ACL, straight out of its own mapping table.
 * 'acl remove vdi' leaves holes behind, so walk the table up to max_data_id_nr
 * rather than stopping at the first empty slot.  Requires a full inode.
 */
static void print_acl_vdi_list(const struct sd_inode *inode, uint32_t acl_vid)
{
	if (json_output)
		out_obj = json_object_new_array();
	else if (!raw_output)
		printf("ACL %"PRIx32" contains:\n", acl_vid);

	for (uint32_t i = 0; i < inode->header.max_data_id_nr; i++) {
		uint32_t vid = inode->data_vdi_id[i];

		if (!vid)
			continue;

		if (json_output) {
			struct json_object *vdi_obj = json_object_new_object();

			JSON_ADD_INT(vdi_obj, "vdi_id", vid);
			json_object_array_add(out_obj, vdi_obj);
		} else if (raw_output)
			printf("%08"PRIx32" ", vid);
		else
			printf("VDI %"PRIx32"\n", vid);
	}

	if (json_output) {
		const char *o = json_object_to_json_string(out_obj);

		printf("%s\n", o);
		json_object_put(out_obj);
	} else if (raw_output)
		printf("\n");
}

/* Print the members of an ACL; the header alone is enough for these. */
static void print_acl_member_list(const struct sd_inode *inode,
				  uint32_t acl_vid)
{
	if (json_output)
		out_obj = json_object_new_array();
	else if (!raw_output)
		printf("ACL %"PRIx32" contains:\n", acl_vid);

	for (uint32_t i = 0; i < sizeof(inode->header.metadata);
	     i += SD_MAX_VDI_LEN) {
		const char *member = (const char *)&inode->header.metadata[i];

		if (!strlen(member))
			continue;

		if (json_output)
			json_object_array_add(out_obj,
					      json_object_new_string(member));
		else if (raw_output)
			printf("%s ", member);
		else
			printf("member %s\n", member);
	}

	if (json_output) {
		const char *o = json_object_to_json_string(out_obj);

		printf("%s\n", o);
		json_object_put(out_obj);
	} else if (raw_output)
		printf("\n");
}

static int acl_add_vdi(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	const char *vdiname = NULL;
	uint32_t acl_vid, vid, new_idx = UINT32_MAX;
	struct sd_inode *inode = NULL;
	int ret, i;

	if (!argv[optind]) {
		sd_err("Please specify the VDI to add");
		return EXIT_USAGE;
	}
	vdiname = argv[optind];

	inode = xmalloc(sizeof(*inode));
	ret = read_acl_inode(aclname, &acl_vid, inode, sizeof(*inode));
	if (ret != SD_RES_SUCCESS) {
		ret = EXIT_FAILURE;
		goto out;
	}

	/* only a VDI which is not part of an ACL can be added */
	ret = find_vdi_name(vdiname, 0, "", 0, &vid);
	if (ret != SD_RES_SUCCESS) {
		/*
		 * A VDI already guarded by an ACL is invisible without it, so
		 * the lookup above cannot tell 'no such VDI' from 'already in
		 * this ACL'.  Retry through the ACL to pick the right message.
		 */
		if (find_vdi_name(vdiname, 0, "", acl_vid, &vid) ==
		    SD_RES_SUCCESS)
			sd_err("ACL %"PRIx32" already contains VDI %"PRIx32,
			       acl_vid, vid);
		else
			sd_err("Failed to open VDI %s: %s",
			       vdiname, sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	for (i = 0; i < inode->header.max_data_id_nr; i++) {
		if (inode->data_vdi_id[i] == vid) {
			sd_err("ACL %" PRIx32 " already contains VDI %"PRIx32,
			       acl_vid, vid);
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	/* Update the ACL VDI mapping table first */
	new_idx = inode->header.max_data_id_nr;
	inode->data_vdi_id[new_idx] = vid;
	ret = dog_write_object(vid_to_vdi_oid(acl_vid), 0,
			       &vid, sizeof(uint32_t),
			       offsetof(struct sd_inode,
					data_vdi_id[new_idx]),
			       SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_TGT,
			       inode->header.nr_copies,
			       inode->header.copy_policy, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode %"PRIx64": %s",
		       vid_to_vdi_oid(acl_vid), sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}
	/* The alter the ACL of the VDI */
	ret = do_vdi_alter_acl(vdiname, 0, acl_vid);
	if (ret != EXIT_SUCCESS) {
		/* ACL VDI mapping entry will be ignored, no need to clear it */
		sd_err("failed to update VDI %s with ACL id",
		       vdiname);
		goto out;
	}

	/* And finally update the header */
	inode->header.max_data_id_nr++;
	inode->header.vdi_epoch++;
	ret = dog_write_object(vid_to_vdi_oid(acl_vid), 0,
			       inode, sizeof(*inode), 0,
			       SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_TGT,
			       inode->header.nr_copies,
			       inode->header.copy_policy, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode %"PRIx64" header: %s",
		       vid_to_vdi_oid(acl_vid), sd_strerror(ret));
		/* Revert VDI ACL changes */
		if (do_vdi_alter_acl(vdiname, acl_vid, 0) != EXIT_SUCCESS)
			sd_err("failed to revert ACL changes for VDI %s",
			       vdiname);
		ret = EXIT_FAILURE;
		goto out;
	}

	if (verbose)
		print_acl_vdi_list(inode, acl_vid);
out:
	free(inode);
	return ret;
}

static int acl_add_member(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	char *member = NULL;
	uint32_t acl_vid;
	struct sd_inode *inode = NULL;
	int ret, i, free_idx = -1, num_entries;

	if (!argv[optind]) {
		sd_err("Please specify the VDI to add");
		return EXIT_USAGE;
	}
	member = argv[optind];
	if (!strlen(member) || strlen(member) > SD_MAX_VDI_LEN) {
		sd_err("Invalid ACL member name '%s'", member);
		return EXIT_USAGE;
	}

	inode = xmalloc(SD_INODE_HEADER_SIZE);
	ret = read_acl_inode(aclname, &acl_vid, inode, SD_INODE_HEADER_SIZE);
	if (ret != SD_RES_SUCCESS) {
		ret = EXIT_FAILURE;
		goto out;
	}

	num_entries = sizeof(inode->header.metadata) / SD_MAX_VDI_LEN;
	for (i = 0; i < num_entries; i++) {
		char *item = (char *)&inode->header.metadata[i * SD_MAX_VDI_LEN];
		if (free_idx < 0 && !strlen(item))
			free_idx = i * SD_MAX_VDI_LEN;
		if (!strcmp(item, member)) {
			sd_err("ACL %" PRIx32 " already contains member %s",
			       acl_vid, member);
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	if (free_idx < 0) {
		sd_err("ACL %" PRIx32 " member list full, cannot add",
		       acl_vid);
		ret = EXIT_FAILURE;
		goto out;
	}
	memcpy(&inode->header.metadata[free_idx], member, strlen(member));

	ret = dog_write_object(vid_to_vdi_oid(acl_vid), 0,
			       &inode->header.metadata[free_idx],
			       (unsigned int)SD_MAX_VDI_LEN,
			       offsetof(struct sd_inode_header,
					metadata[free_idx]),
			       SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_TGT,
			       inode->header.nr_copies,
			       inode->header.copy_policy, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode %"PRIx64": %s",
		       vid_to_vdi_oid(acl_vid), sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (verbose)
		print_acl_member_list(inode, acl_vid);
out:
	free(inode);
	return ret;
}

static struct subcommand acl_add_cmd[] = {
	{"vdi", NULL, NULL, "add VDI to ACL", NULL,
	 CMD_NEED_ARG, acl_add_vdi},
	{"member", NULL, NULL, "add member to ACL", NULL,
	 CMD_NEED_ARG, acl_add_member},
	{NULL},
};

static int acl_add(int argc, char **argv)
{
	return do_generic_subcommand(acl_add_cmd, argc, argv);
}

static int acl_remove_vdi(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	const char *vdiname = NULL;
	uint32_t acl_vid, vid;
	uint32_t old_idx = UINT32_MAX, limit, i;
	struct sd_inode *inode = NULL;
	int ret;

	if (!argv[optind]) {
		sd_err("Please specify the VDI to remove");
		return EXIT_USAGE;
	}
	vdiname = argv[optind];

	/* data_vdi_id[] is searched and updated below, so read the full inode */
	inode = xzalloc(sizeof(*inode));
	ret = read_acl_inode(aclname, &acl_vid, inode, sizeof(*inode));
	if (ret != SD_RES_SUCCESS) {
		ret = EXIT_FAILURE;
		goto out;
	}

	/* the VDI is only reachable through the ACL it belongs to */
	ret = find_vdi_name(vdiname, 0, "", acl_vid, &vid);
	if (ret != SD_RES_SUCCESS) {
		if (find_vdi_name(vdiname, 0, "", 0, &vid) == SD_RES_SUCCESS)
			sd_err("ACL %"PRIx32" does not contain VDI %"PRIx32,
			       acl_vid, vid);
		else
			sd_err("Failed to open VDI %s: %s",
			       vdiname, sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}
	for (i = 0; i < inode->header.max_data_id_nr; i++) {
		if (inode->data_vdi_id[i] == vid) {
			old_idx = i;
			break;
		}
	}
	if (old_idx == UINT32_MAX) {
		sd_err("ACL %" PRIx32 " does not contain VDI %"PRIx32,
		       acl_vid, vid);
		ret = EXIT_FAILURE;
		goto out;
	}
	if (acl_cmd_data.force)
		goto update_inode;

	/*
	 * Check (and clear) the VDI's own ACL id first: a locked VDI must not
	 * change its ACL, and this is the only step that can fail on that
	 * account.  Nothing in the ACL's own data_vdi_id[] is touched before
	 * this succeeds, so a locked VDI leaves the ACL exactly as it was
	 * instead of losing the member despite the reported failure.
	 */
	ret = do_vdi_alter_acl(vdiname, acl_vid, 0);
	if (ret != EXIT_SUCCESS) {
		sd_err("failed to remove ACL id %"PRIx32" from VDI %s",
		       acl_vid, vdiname);
		ret = EXIT_FAILURE;
		goto out;
	}
update_inode:
	/* Only now update the ACL's own VDI mapping table and commit it */
	inode->data_vdi_id[old_idx] = 0;
	limit = inode->header.max_data_id_nr;
	inode->header.vdi_epoch++;

	if (old_idx == limit - 1) {
		while (limit > 0 && inode->data_vdi_id[limit - 1] == 0)
			limit--;

		inode->header.max_data_id_nr = limit;
	}
	ret = dog_write_object(vid_to_vdi_oid(acl_vid), 0,
			       inode, sizeof(*inode), 0,
			       SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_TGT,
			       inode->header.nr_copies,
			       inode->header.copy_policy, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode %"PRIx64" header: %s",
		       vid_to_vdi_oid(acl_vid), sd_strerror(ret));
		/* Revert VDI ACL changes */
		if (!acl_cmd_data.force &&
		    do_vdi_alter_acl(vdiname, 0, acl_vid) != EXIT_SUCCESS)
			sd_err("VDI %"PRIx32" is left outside of ACL %"PRIx32,
			       vid, acl_vid);
		ret = EXIT_FAILURE;
		goto out;
	}
	if (verbose)
		print_acl_vdi_list(inode, acl_vid);
out:
	free(inode);
	return ret;
}

static int acl_remove_member(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	char *member = NULL;
	uint32_t acl_vid;
	struct sd_inode *inode = NULL;
	int ret, i, free_idx = -1;

	if (!argv[optind]) {
		sd_err("Please specify the VDI to add");
		return EXIT_USAGE;
	}
	member = argv[optind];
	if (!strlen(member) || strlen(member) > SD_MAX_VDI_LEN) {
		sd_err("Invalid ACL member name '%s'", member);
		return EXIT_USAGE;
	}

	inode = xmalloc(SD_INODE_HEADER_SIZE);
	ret = read_acl_inode(aclname, &acl_vid, inode, SD_INODE_HEADER_SIZE);
	if (ret != SD_RES_SUCCESS) {
		ret = EXIT_FAILURE;
		goto out;
	}

	for (i = 0; i < sizeof(inode->header.metadata); i += SD_MAX_VDI_LEN) {
		char *item = (char *)&inode->header.metadata[i];
		if (!strcmp(item, member)) {
			memset(item, 0, SD_MAX_VDI_LEN);
			free_idx = i;
			break;
		}
	}
	if (free_idx < 0) {
		sd_err("ACL %" PRIx32 " member %s not found, cannot remove",
		       acl_vid, member);
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = dog_write_object(vid_to_vdi_oid(acl_vid), 0,
			       &inode->header.metadata[free_idx],
			       (unsigned int)SD_MAX_VDI_LEN,
			       offsetof(struct sd_inode_header,
					metadata[free_idx]),
			       SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_TGT,
			       inode->header.nr_copies,
			       inode->header.copy_policy, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode %"PRIx64" header: %s",
		       vid_to_vdi_oid(acl_vid), sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (verbose)
		print_acl_member_list(inode, acl_vid);
out:
	free(inode);
	return ret;
}

static struct subcommand acl_remove_cmd[] = {
	{"vdi", NULL, NULL, "rmove VDI from ACL", NULL,
	 CMD_NEED_ARG, acl_remove_vdi},
	{"member", NULL, NULL, "remove member from ACL", NULL,
	 CMD_NEED_ARG, acl_remove_member},
	{NULL},
};

static int acl_remove(int argc, char **argv)
{
	return do_generic_subcommand(acl_remove_cmd, argc, argv);
}

static struct subcommand acl_cmd[] = {
	{"create", "<aclname>", "cfajphrvT", "create an acl",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ROOT|CMD_NEED_ARG,
	 acl_create, acl_options},
	{"delete", "<aclname>", "sfajphrvT", "delete an acl",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 acl_delete, acl_options},
	{"register", "<aclname>", "sfajphrvT", "register an ACL owner",
	 NULL, CMD_NEED_ARG, acl_register, acl_options},
	{"unregister", "<aclname>", "sfajphrvT", "unregister an ACL owner",
	 NULL, CMD_NEED_ARG, acl_unregister, acl_options},
	{"owner", "<aclname>", "ajprhvT", "list ACL owners",
	 NULL, CMD_NEED_ARG, acl_detail, acl_options},
	{"list", "[aclname]", "ajprhvT", "list images",
	 NULL, 0, acl_list, acl_options},
	{"add", "<aclname> <vdiname>", "ajprvhT", "add an entry to ACL",
	 acl_add_cmd, CMD_NEED_ARG, acl_add, acl_options},
	{"remove", "<aclname> <vdiname>", "fajprvhT", "remove an entry from ACL",
	 acl_remove_cmd, CMD_NEED_ARG, acl_remove, acl_options},
	{NULL,},
};

static int acl_parser(int ch, const char *opt)
{
	char *p;

	switch (ch) {
	case 's':
		acl_cmd_data.snapshot_id = strtol(opt, &p, 10);
		if (opt == p || *p != '\0') {
			acl_cmd_data.snapshot_id = 0;
			pstrcpy(acl_cmd_data.snapshot_tag,
				sizeof(acl_cmd_data.snapshot_tag), opt);
		} else if (acl_cmd_data.snapshot_id == 0) {
			fprintf(stderr,
				"The snapshot id must be larger than zero\n");
			exit(EXIT_FAILURE);
		}
		break;
	case 'c':
		acl_cmd_data.nr_copies = parse_copy(opt,
						    &acl_cmd_data.copy_policy);
		if (!acl_cmd_data.nr_copies) {
			sd_err("Invalid parameter %s\n"
			       "To create replicated acl, set -c x\n"
			       "  x(1 to %d)   - number of replicated copies\n"
			       "To create erasure coded acl, set -c x:y\n"
			       "  x(2,4,8,16)  - number of data strips\n"
			       "  y(1 to 15)   - number of parity strips",
			       opt, SD_MAX_COPIES);
			exit(EXIT_FAILURE);
		}
		break;
	case 'f':
		acl_cmd_data.force = true;
		break;
	}

	return 0;
}

struct command acl_command = {
	"acl",
	acl_cmd,
	acl_parser
};
