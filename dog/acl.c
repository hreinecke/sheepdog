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
	{'A', "acl", true, "specify the ACL id for accessing the VDI"},
	{ 0, NULL, false, NULL },
};

static struct acl_cmd_data {
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
	int nr_batched_reclamation;
	int reclamation_interval;
	int nr_max_reclaim;
	uint32_t acl_id;
} acl_cmd_data = { ~0, };

static int acl_create(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	char buf[SD_MAX_VDI_LEN];
	uint32_t vid;
	struct sd_inode *inode = NULL;
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
	hdr.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_ACL;
	hdr.data_length = SD_MAX_VDI_LEN;
	hdr.vdi.vdi_size = sizeof(*inode);

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
	inode = xmalloc(sizeof(*inode));

	ret = dog_read_object(vid_to_acl_oid(vid), inode, sizeof(*inode), 0,
			      true);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to read a newly created ACL object");
		ret = EXIT_FAILURE;
		goto out;
	}
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
out:
	free(inode);
	return ret;
}

static int acl_delete(int args, char **argv)
{
	const char *aclname = argv[optind++];
	char buf[SD_MAX_VDI_LEN];
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret = EXIT_SUCCESS;

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

static int find_acl_name(const char *aclname, uint32_t snapid, const char *tag,
			 uint32_t *vid)
{
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];

	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, aclname);
	if (tag)
		pstrcpy(buf + SD_MAX_VDI_LEN, SD_MAX_VDI_TAG_LEN, tag);

	sd_init_req(&hdr, SD_OP_GET_VDI_INFO);
	hdr.data_length = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
	hdr.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_ACL;
	hdr.vdi.snapid = snapid;

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0)
		return SD_RES_EIO;

	if (rsp->result == SD_RES_SUCCESS)
		*vid = rsp->vdi.vdi_id;

	return rsp->result;
}

static int acl_add(int argc, char **argv)
{
	const char *aclname = argv[optind++];
	char buf[SD_MAX_VDI_LEN];
	uint32_t vid;
	struct sd_inode *inode = NULL;
	int ret;

	ret = find_acl_name(aclname, 0, "", &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open ACL %s: %s",
		       aclname, sd_strerror(ret));
		return EXIT_FAILURE;
	}
	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, aclname);

	inode = xmalloc(sizeof(*inode));
	ret = dog_read_object(vid_to_acl_oid(vid), inode, sizeof(*inode), 0,
			      true);
	if (ret != SD_RES_SUCCESS) {
		ret = EXIT_FAILURE;
		goto out;
	}
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
out:
	free(inode);
	return ret;
}

static struct subcommand acl_cmd[] = {
	{"create", "<aclname>", "PycajphrvzTA", "create an acl",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ROOT|CMD_NEED_ARG,
	 acl_create, acl_options},
	{"delete", "<aclname>", "saphTBImA", "delete an acl",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 acl_delete, acl_options},
	{"list", "[aclname]", "ajprhoTA", "list images",
	 NULL, 0, acl_list, acl_options},
	{"add", "<aclname>", "a", "add an entry to ACL",
	 NULL, CMD_NEED_ARG, acl_add, acl_options},
	{NULL,},
};

static int acl_parser(int ch, const char *opt)
{
	char *p;

	switch (ch) {
	case 'i':
		if (strncmp(opt, "0x", 2) == 0)
			acl_cmd_data.index = strtol(opt, &p, 16);
		else
			acl_cmd_data.index = strtol(opt, &p, 10);
		if (opt == p) {
			sd_err("The index must be a decimal integer "
				"or a hexadecimal integer started with 0x");
			exit(EXIT_FAILURE);
		}
		break;
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
	case 'f':
		acl_cmd_data.force = true;
		break;
	case 'o':
		acl_cmd_data.oid = strtoull(opt, &p, 16);
		if (opt == p) {
			sd_err("object id must be a hex integer");
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
