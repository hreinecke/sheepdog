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
	{ 0, NULL, false, NULL },
};

static struct acl_cmd_data {
	int snapshot_id;
	char snapshot_tag[SD_MAX_VDI_TAG_LEN];
	int nr_copies;
	uint8_t copy_policy;
	uint8_t store_policy;
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

static int acl_create(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	char buf[SD_MAX_VDI_LEN];
	uint32_t vid;
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

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

	vid = rsp->vdi.vdi_id;

	if (verbose) {
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
			printf("VDI ID of newly created ACL: %x\n", vid);
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
	uint32_t acl_vid;
	int ret = EXIT_SUCCESS;

	/* refuse to delete an ordinary VDI which happens to share the name */
	inode = xzalloc(SD_INODE_HEADER_SIZE);
	ret = read_acl_inode(aclname, &acl_vid, inode, SD_INODE_HEADER_SIZE);
	free(inode);
	if (ret != SD_RES_SUCCESS)
		return ret == SD_RES_NO_VDI ? EXIT_MISSING : EXIT_FAILURE;

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

struct get_acl_info {
	const char *name;
	const char *tag;
	uint32_t vid;
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

	if (info) {
		if (info->name && strcmp(name, info->name) != 0)
			return;
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
		JSON_ADD_BOOL(vdi_obj, "is_snapshot",
				 vdi_is_snapshot(&i->header));
		JSON_ADD_BOOL(vdi_obj, "is_clone", is_clone);
		if (strlen(i->header.tag))
			JSON_ADD_STRING(vdi_obj, "tag",
					i->header.tag);
		json_object_array_add(out_obj, vdi_obj);
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

	if (json_output)
		out_obj = json_object_new_array();
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

static int acl_add(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	const char *vdiname = NULL;
	uint32_t acl_vid, vid;
	uint32_t new_idx = UINT32_MAX;
	struct sd_inode *inode = NULL;
	int ret, i;

	if (!argv[optind]) {
		sd_err("Please specify the VDI to add");
		return EXIT_USAGE;
	}
	vdiname = argv[optind];

	ret = find_vdi_name(vdiname, 0, "", 0, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open VDI %s: %s",
		       vdiname, sd_strerror(ret));
		return EXIT_FAILURE;
	}

	inode = xmalloc(sizeof(*inode));
	ret = read_acl_inode(aclname, &acl_vid, inode, sizeof(*inode));
	if (ret != SD_RES_SUCCESS) {
		ret = EXIT_FAILURE;
		goto out;
	}
	for (i = 0; i < SD_INODE_DATA_INDEX; i++) {
		if (!inode->data_vdi_id[i])
			break;
		if (inode->data_vdi_id[i] == vid) {
			sd_err("ACL %" PRIx32 " already contains VDI %"PRIx32,
			       acl_vid, vid);
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	for (i = 0; i < SD_INODE_DATA_INDEX; i++) {
		if (!inode->data_vdi_id[i]) {
			inode->data_vdi_id[i] = vid;
			new_idx = i;
			break;
		}
	}
	if (new_idx == UINT32_MAX) {
		sd_err("ACL %"PRIx32" index table exhausted", acl_vid);
		ret = EXIT_FAILURE;
		goto out;
	}
	ret = dog_write_object(vid_to_vdi_oid(acl_vid), 0,
			       &inode->data_vdi_id[new_idx],
			       sizeof(uint32_t),
			       offsetof(struct sd_inode,
					data_vdi_id[new_idx]),
			       SD_FLAG_CMD_DIRECT, inode->header.nr_copies,
			       inode->header.copy_policy, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode for object: %016" PRIx64,
		       vid_to_vdi_oid(acl_vid));
		ret = EXIT_FAILURE;
		goto out;
	}
	if (verbose) {
		if (json_output) {
			const char *o;

			out_obj = json_object_new_array();

			for (i = 0; i < SD_INODE_DATA_INDEX; i++) {
				struct json_object *vdi_obj;

				if (!inode->data_vdi_id[i])
					break;
				vdi_obj = json_object_new_object();
				JSON_ADD_INT(vdi_obj, "vdi_id",
					     inode->data_vdi_id[i]);
				json_object_array_add(out_obj, vdi_obj);
			}
			o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		} else if (raw_output)
			printf("%x\n", vid);
		else
			printf("VDI %x added to ACL %x\n", vid, acl_vid);
	}
out:
	free(inode);
	return ret;
}

static int acl_remove(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	const char *vdiname = NULL;
	uint32_t acl_vid, vid;
	uint32_t old_idx = UINT32_MAX, last_idx = 0;
	struct sd_inode *inode = NULL;
	int ret, i;

	if (!argv[optind]) {
		sd_err("Please specify the VDI to remove");
		return EXIT_USAGE;
	}
	vdiname = argv[optind];

	ret = find_vdi_name(vdiname, 0, "", 0, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open VDI %s: %s",
		       vdiname, sd_strerror(ret));
		return EXIT_FAILURE;
	}

	inode = xmalloc(sizeof(*inode));
	ret = read_acl_inode(aclname, &acl_vid, inode, sizeof(*inode));
	if (ret != SD_RES_SUCCESS) {
		ret = EXIT_FAILURE;
		goto out;
	}
	for (i = 0; i < SD_INODE_DATA_INDEX; i++) {
		if (!inode->data_vdi_id[i])
			break;
		if (inode->data_vdi_id[i] == vid) {
			inode->data_vdi_id[i] = 0;
			old_idx = i;
			last_idx = i;
			break;
		}
	}
	if (old_idx == UINT32_MAX) {
		sd_err("ACL %" PRIx32 " does not contain VDI %"PRIx32,
		       acl_vid, vid);
		ret = EXIT_FAILURE;
		goto out;
	}
	/* Reshuffle array to avoid holes */
	for (i = old_idx; i < SD_INODE_DATA_INDEX - 1; i++) {
		if (!inode->data_vdi_id[i + 1])
			break;
		inode->data_vdi_id[i] = inode->data_vdi_id[i + 1];
		inode->data_vdi_id[i + 1] = 0;
		last_idx = i + 1;
	}
	if (old_idx == UINT32_MAX) {
		sd_err("ACL %"PRIx32" index table exhausted", acl_vid);
		ret = EXIT_FAILURE;
		goto out;
	}
	/* every slot from the removed one up to the new hole has moved */
	ret = dog_write_object(vid_to_vdi_oid(acl_vid), 0,
			       &inode->data_vdi_id[old_idx],
			       sizeof(uint32_t) * (last_idx - old_idx + 1),
			       offsetof(struct sd_inode,
					data_vdi_id[old_idx]),
			       SD_FLAG_CMD_DIRECT, inode->header.nr_copies,
			       inode->header.copy_policy, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode for object: %016" PRIx64,
		       vid_to_vdi_oid(acl_vid));
		ret = EXIT_FAILURE;
		goto out;
	}
	if (verbose) {
		if (json_output) {
			const char *o;

			out_obj = json_object_new_array();

			for (i = 0; i < SD_INODE_DATA_INDEX; i++) {
				struct json_object *vdi_obj;

				if (!inode->data_vdi_id[i])
					break;
				vdi_obj = json_object_new_object();
				JSON_ADD_INT(vdi_obj, "vdi_id",
					     inode->data_vdi_id[i]);
				json_object_array_add(out_obj, vdi_obj);
			}
			o = json_object_to_json_string(out_obj);
			printf("%s\n", o);
			json_object_put(out_obj);
		} else if (raw_output)
			printf("%x\n", vid);
		else
			printf("VDI %x removed from ACL %x\n", vid, acl_vid);
	}
out:
	free(inode);
	return ret;
}

static struct subcommand acl_cmd[] = {
	{"create", "<aclname>", "cajphrvT", "create an acl",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ROOT|CMD_NEED_ARG,
	 acl_create, acl_options},
	{"delete", "<aclname>", "sajphrvT", "delete an acl",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 acl_delete, acl_options},
	{"list", "[aclname]", "ajprhvT", "list images",
	 NULL, 0, acl_list, acl_options},
	{"add", "<aclname> <vdiname>", "ajprvhT", "add an entry to ACL",
	 NULL, CMD_NEED_ARG, acl_add, acl_options},
	{"remove", "<aclname> <vdiname>", "ajprvhT", "remove an entry from ACL",
	 NULL, CMD_NEED_ARG, acl_remove, acl_options},
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
	}

	return 0;
}

struct command acl_command = {
	"acl",
	acl_cmd,
	acl_parser
};
