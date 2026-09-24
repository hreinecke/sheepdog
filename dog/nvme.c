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
#include "crypto.h"
#include "base64.h"
#include "crc32.h"

static struct json_object *out_obj;

enum nvme_psk_flags {
	NVME_PSK_FLAG_EXPIRED,
	NVME_PSK_FLAG_REVOKED,
};

struct nvme_psk_data {
	char protocol[16];
	char subsysnqn[256];
	char digest[64];
	char key[64];
	uint8_t digest_len;
	uint8_t key_len;
	uint8_t hash_len;
	uint8_t flags;
	uint64_t ctime;
};

static struct sd_option psk_options[] = {
	{'a', "acl", true, "specify a ACL name"},
	{'f', "force", false, "do operation forcibly"},
	{ 0, NULL, false, NULL },
};

static struct nvme_cmd_data {
	char aclname[SD_MAX_VDI_TAG_LEN];
	bool force;
} nvme_cmd_data = { 0 };

static void print_psk_list(struct sd_inode *inode)
{
	unsigned int num_entries, i;
	struct nvme_psk_data *psk;

	num_entries = sizeof(inode->data_vdi_id) /
		sizeof(struct nvme_psk_data);
	psk = (struct nvme_psk_data *)inode->data_vdi_id;
	for (i = 0; i < num_entries; i++) {
		if (!strlen(psk->protocol))
			break;

		printf("%s %s %s %s\n",
		       psk->protocol, inode->header.name,
		       psk->subsysnqn, psk->digest);
		psk++;
	}
}

static int nvme_import_psk(int argc, char **argv)
{
	const char *member = argv[optind++];
	const char *keydata = NULL;
	unsigned char *configured_key, *retained_key;
	char *psk_identity;
	char *psk_protocol, *psk_subsysnqn, *psk_digest;
	uint32_t acl_vid, vid;
	struct sd_inode *inode = NULL;
	int ret, i, num_entries;
	unsigned char version, hmac;
	struct nvme_psk_data *psk, *free_psk = NULL;
	size_t key_len;
	off_t psk_index = 0;

	if (!argv[optind]) {
		sd_err("No PSK data present");
		return EXIT_USAGE;
	}
	keydata = argv[optind];

	if (!strlen(nvme_cmd_data.aclname)) {
		sd_err("ACL name not present");
		return EXIT_USAGE;
	}
	ret = find_vdi_name(nvme_cmd_data.aclname, 0, "", 0, &acl_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open ACL %s: %s",
		       nvme_cmd_data.aclname, sd_strerror(ret));
		return EXIT_USAGE;
	}

	ret = nvme_import_tls_key(keydata, &version, &hmac,
				  &key_len, &configured_key);
	if (ret < 0) {
		sd_err("Failed to import TLS key: %m");
		return EXIT_USAGE;
	}
	ret = nvme_derive_tls_key(member, nvme_cmd_data.aclname,
				  1, hmac, configured_key, key_len,
				  &psk_identity, &retained_key);

	psk_protocol = strsep(&psk_identity, " ");
	strsep(&psk_identity, " ");
	psk_subsysnqn = strsep(&psk_identity, " ");
	psk_digest = strsep(&psk_identity, " ");

	ret = find_vdi_name(member, 0, "", acl_vid, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open member %s: %s",
		       member, sd_strerror(ret));
		return EXIT_USAGE;
	}
	inode = xmalloc(SD_INODE_SIZE);
	ret = dog_read_object(vid_to_vdi_oid(vid), inode,
			      SD_INODE_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS) {
		ret = EXIT_FAILURE;
		goto out;
	}

	num_entries = sizeof(inode->data_vdi_id) /
		sizeof(struct nvme_psk_data);
	psk = (struct nvme_psk_data *)inode->data_vdi_id;
	for (i = 0; i < num_entries; i++) {
		if (!strlen(psk->protocol)) {
			free_psk = psk;
			break;
		}
		if (strcmp(psk->protocol, psk_protocol))
			continue;
		if (strcmp(psk->subsysnqn, psk_subsysnqn))
			continue;
		if (!strcmp(psk->digest, psk_digest)) {
			sd_err("Member %"PRIx32" duplicate PSK for '%s'",
			       vid, psk_subsysnqn);
			ret = EXIT_FAILURE;
			break;
		}
		psk++;
		psk_index = i * sizeof(struct nvme_psk_data) /
			sizeof(uint32_t);
	}
	if (!free_psk) {
		sd_err("Member %" PRIx32 " psk list full, cannot add",
		       vid);
		ret = EXIT_FAILURE;
		goto out;
	}
	strcpy(free_psk->protocol, psk_protocol);
	strcpy(free_psk->subsysnqn, psk_subsysnqn);
	strcpy(free_psk->digest, psk_digest);
	memcpy(free_psk->key, retained_key, key_len);
	free_psk->key_len = key_len;
	free_psk->hash_len = key_len;
	free_psk->digest_len = strlen(psk_digest);

	ret = dog_write_object(vid_to_vdi_oid(acl_vid), 0,
			       free_psk, sizeof(*free_psk),
			       psk_index,
			       SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_TGT,
			       SD_MAX_COPIES, 0, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode %"PRIx64": %s",
		       vid_to_vdi_oid(acl_vid), sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (verbose)
		print_psk_list(inode);
out:
	free(inode);
	return ret;
}

static int nvme_list_psk(int argc, char **argv)
{
	const char *member = argv[optind];
	uint32_t acl_vid, vid;
	struct sd_inode *inode = NULL;
	int ret;

	if (!strlen(nvme_cmd_data.aclname)) {
		sd_err("ACL name not present");
		return EXIT_USAGE;
	}
	ret = find_vdi_name(nvme_cmd_data.aclname, 0, "", 0, &acl_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open ACL %s: %s",
		       nvme_cmd_data.aclname, sd_strerror(ret));
		return EXIT_USAGE;
	}
	ret = find_vdi_name(member, 0, "", acl_vid, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open member %s: %s",
		       member, sd_strerror(ret));
		return EXIT_USAGE;
	}
	inode = xmalloc(SD_INODE_SIZE);
	ret = dog_read_object(vid_to_vdi_oid(vid), inode,
			      SD_INODE_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = EXIT_FAILURE;
	else
		print_psk_list(inode);

	free(inode);
	return ret;
}

static struct subcommand psk_modify_cmd[] = {
	{"import", NULL, NULL, "import a TLS PSK", NULL,
	 CMD_NEED_ARG, nvme_import_psk},
	{"list", NULL, NULL, "list existing PSKs", NULL,
	 CMD_NEED_ARG, nvme_list_psk},
	{NULL},
};

static int psk_modify(int argc, char **argv)
{
	return do_generic_subcommand(psk_modify_cmd, argc, argv);
}

static struct sd_option dhchap_options[] = {
	{'a', "acl", true, "specify a ACL name"},
	{'f', "force", false, "do operation forcibly"},
	{ 0, NULL, false, NULL },
};

static int nvme_import_dhchap(int argc, char **argv)
{
	const char *member = argv[optind++];
	const char *keydata = NULL;
	char psk_digest[9];
	unsigned char decoded_key[128];
	unsigned char transformed_key[128];
	uint32_t crc = crc32(0L, NULL, 0);
	uint32_t key_crc;
	uint32_t acl_vid, vid;
	struct sd_inode *inode = NULL;
	int ret, i, num_entries;
	unsigned char hmac;
	struct nvme_psk_data *psk, *free_psk = NULL;
	size_t decoded_len, expected_len = 0;
	off_t psk_index = 0;

	if (!argv[optind]) {
		sd_err("No PSK data present");
		return EXIT_USAGE;
	}
	keydata = argv[optind];

	if (sscanf(keydata, "DHHC-1:%02hhx:*s", &hmac) != 1) {
		sd_err("Invalid key header '%s'", keydata);
		return EXIT_USAGE;
	}
	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		break;
	case NVME_HMAC_ALG_SHA2_256:
		if (strlen(keydata) != 59) {
			sd_err("Invalid key length for SHA(256)");
			return EXIT_USAGE;
		}
		expected_len = 32;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		if (strlen(keydata) != 83) {
			sd_err("Invalid key length for SHA(384)");
			return EXIT_USAGE;
		}
		expected_len = 48;
		break;
	case NVME_HMAC_ALG_SHA2_512:
		if (strlen(keydata) != 103) {
			sd_err("Invalid key length for SHA(512)");
			return EXIT_USAGE;
		}
		expected_len = 64;
		break;
	default:
		sd_err("Invalid HMAC identifier %d", hmac);
		return EXIT_USAGE;
	}

       ret = base64_decode(keydata + 10, strlen(keydata) - 11, decoded_key);
	if (ret < 0) {
		sd_err("Base64 decoding failed, error %d", -ret);
		return EXIT_SYSFAIL;
	}
	decoded_len = ret;
	if (decoded_len < 32) {
		sd_err("Base64 decoding failed (%s, size %lu)",
		       keydata + 10, decoded_len);
		return EXIT_SYSFAIL;
	}
	decoded_len -= 4;
	if (decoded_len != expected_len) {
		sd_err("Invalid key length %lu, should be %lu",
		       decoded_len, expected_len);
		return EXIT_SYSFAIL;
	}
	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((uint32_t)decoded_key[decoded_len]) |
		   ((uint32_t)decoded_key[decoded_len + 1] << 8) |
		   ((uint32_t)decoded_key[decoded_len + 2] << 16) |
		   ((uint32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		sd_err("CRC mismatch (key %08x, crc %08x)", key_crc, crc);
		return EXIT_SYSFAIL;
	}
	sprintf(psk_digest, "%08x", crc);
	ret = nvme_gen_dhchap_key(member, hmac, decoded_len,
				  decoded_key, transformed_key);
	if (ret < 0) {
		sd_err("Failed to transform DH-HMAC-CHAP key, error %d", -ret);
		return EXIT_SYSFAIL;
	}

	if (!strlen(nvme_cmd_data.aclname)) {
		sd_err("ACL name not present");
		return EXIT_USAGE;
	}
	ret = find_vdi_name(nvme_cmd_data.aclname, 0, "", 0, &acl_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open ACL %s: %s",
		       nvme_cmd_data.aclname, sd_strerror(ret));
		return EXIT_USAGE;
	}

	ret = find_vdi_name(member, 0, "", acl_vid, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open member %s: %s",
		       member, sd_strerror(ret));
		return EXIT_USAGE;
	}
	inode = xmalloc(SD_INODE_SIZE);
	ret = dog_read_object(vid_to_vdi_oid(vid), inode,
			      SD_INODE_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS) {
		ret = EXIT_FAILURE;
		goto out;
	}

	num_entries = sizeof(inode->data_vdi_id) /
		sizeof(struct nvme_psk_data);
	psk = (struct nvme_psk_data *)inode->data_vdi_id;
	for (i = 0; i < num_entries; i++) {
		if (!strlen(psk->protocol)) {
			free_psk = psk;
			break;
		}
		if (strncmp(psk->protocol, keydata, 9))
			continue;
		if (strcmp(psk->subsysnqn, nvme_cmd_data.aclname))
			continue;
		if (!strcmp(psk->digest, psk_digest)) {
			sd_err("Member %"PRIx32" duplicate PSK for '%s'",
			       vid, nvme_cmd_data.aclname);
			ret = EXIT_FAILURE;
			break;
		}
		psk++;
		psk_index = i * sizeof(struct nvme_psk_data) /
			sizeof(uint32_t);
	}
	if (!free_psk) {
		sd_err("Member %" PRIx32 " psk list full, cannot add",
		       vid);
		ret = EXIT_FAILURE;
		goto out;
	}
	memset(free_psk, 0, sizeof(*free_psk));
	strncpy(free_psk->protocol, keydata, 9);
	strcpy(free_psk->subsysnqn, nvme_cmd_data.aclname);
	memcpy(free_psk->key, decoded_key, decoded_len);
	free_psk->key_len = decoded_len;
	free_psk->digest_len = strlen(psk_digest);

	ret = dog_write_object(vid_to_vdi_oid(acl_vid), 0,
			       free_psk, sizeof(*free_psk),
			       psk_index,
			       SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_TGT,
			       SD_MAX_COPIES, 0, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update ACL inode %"PRIx64": %s",
		       vid_to_vdi_oid(acl_vid), sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (verbose)
		print_psk_list(inode);
out:
	free(inode);
	return ret;
}

static struct subcommand dhchap_modify_cmd[] = {
	{ "import", NULL, NULL, "import a DH-HMAC-CHAP PSK", NULL,
	  CMD_NEED_ARG, nvme_import_dhchap},
	{NULL},
};

static int dhchap_modify(int argc, char **argv)
{
	return do_generic_subcommand(dhchap_modify_cmd, argc, argv);
}

static struct subcommand nvme_cmd[] = {
	{"psk", "<psk data>", "fajphrvT", "modify a TLS PSK",
	 NULL, CMD_NEED_NODELIST|CMD_NEED_ROOT|CMD_NEED_ARG,
	 psk_modify, psk_options},
	{"dhchap", "<dhchap data>", "sfajphrvT", "modify a DH-HMAC-CHAP secret",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 dhchap_modify, dhchap_options},
	{NULL,},
};

static int nvme_parser(int ch, const char *opt)
{
	switch (ch) {
	case 'a':
		pstrcpy(nvme_cmd_data.aclname, SD_MAX_VDI_LEN, opt);
		break;
	case 'f':
		nvme_cmd_data.force = true;
		break;
	}

	return 0;
}

struct command nvme_command = {
	"nvme",
	nvme_cmd,
	nvme_parser
};
