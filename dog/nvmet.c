/*
 * Copyright (C) 2026 Hannes Reinecke, SUSE
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

struct nvmet_psk_data {
	char protocol[8];
	char subsysnqn[256];
	char digest[64];
	uint8_t digest_len;
	char key[64];
	uint8_t key_len;
	uint8_t hash_len;
};

static struct sd_option nvmet_options[] = {
	{'a', "acl", true, "specify a ACL name"},
	{'m', "member", true, "specify a member name"},
	{'f', "force", false, "do operation forcibly"},
	{ 0, NULL, false, NULL },
};

static struct nvmet_cmd_data {
	char aclname[SD_MAX_VDI_TAG_LEN];
	uint32_t acl_vid;
	char member[SD_MAC_VDI_TAG_LEN];
	bool force;
} nvmet_cmd_data = { ~0, };

static int nvmet_import_psk(int argc, char **argv)
{
	const char *pskdata = argv[optind];
	char *member = NULL;
	uint32_t acl_vid, vid;
	struct sd_inode *inode = NULL;
	int ret, i, free_idx = -1, num_entries;

	if (!strlen(nvmet_cmd_data.aclname)) {
		sd_err("ACL name not present");
		return EXIT_USAGE;
	}
	ret = find_vdi_name(nvmet_cmd_data.aclname, 0, "", 0,
			    &nvmet_cmd_data.acl_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open ACL %s: %s",
		       nvmet_cmd_data.aclname, sd_strerror(ret));
		return EXIT_USAGE;
	}
	if (!strlen(nvmet_cmd_data.member)) {
		sd_err("Invalid ACL member name");
		return EXIT_USAGE;
	}

	ret = find_vdi_name(nvmet_cmd_data.member, 0, "",
			    nvmet_cmd_data.acl_vid, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open member %s: %s",
		       nvmet_cmd_data.member, sd_strerror(ret));
		return EXIT_USAGE;
	}
	inode = xmalloc(SD_INODE_SIZE);
	ret = dog_read_object(vid_to_vdi_oid(vid), inode,
			      SD_INODE_SIZE, 0, true);
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

	ret = acl_create_vdi(member, SD_VDI_FLAG_MEMBER, &vid);
	if (ret != SD_RES_SUCCESS) {
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
			       SD_MAX_COPIES, 0, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode %"PRIx64": %s",
		       vid_to_vdi_oid(acl_vid), sd_strerror(ret));
		acl_delete_vdi(member);
		ret = EXIT_FAILURE;
		goto out;
	}

	if (verbose)
		print_acl_member_list(inode, acl_vid);
out:
	free(inode);
	return ret;
}

static struct subcommand psk_modify_cmd[] = {
	{"import", NULL, NULL, "import a TLS PSK", NULL,
	 CMD_NEED_ARG, nvmet_import_psk},
	{NULL},
};

static int psk_modify(int argc, char **argv)
{
	return do_generic_subcommand(psk_modify_cmd, argc, argv);
}

static struct subcommand nvmet_cmd[] = {
	{"psk", "<psk data>", "fajphrvT", "modify a TLS PSK",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ROOT|CMD_NEED_ARG,
	 psk_modify, psk_options},
	{"dhchap", "<dhchap data>", "sfajphrvT", "modify a DH-HMAC-CHAP secret",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 dhchap_modify, dhchap_options},
	{NULL,},
};

static int acl_parser(int ch, const char *opt)
{
	char *p;

	switch (ch) {
	case 'a':
		pstrcpy(nvmet_cmd_data.aclname, SD_MAX_VDI_LEN, opt);
		break;
	case 'm':
		pstrcpy(nvmet_cmd_data.member, SD_MAX_VDI_LEN, opt);
		break;
	case 'f':
		nvmet_cmd_data.force = true;
		break;
	}

	return 0;
}

struct command acl_command = {
	"acl",
	acl_cmd,
	acl_parser
};
