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

static struct sd_option nvme_options[] = {
	{'A', "acl", true, "specify a ACL name"},
	{'f', "force", false, "do operation forcibly"},
	{ 0, NULL, false, NULL },
};

static struct nvme_cmd_data {
	char aclname[SD_MAX_VDI_TAG_LEN];
	bool force;
} nvme_cmd_data = { 0 };

static int nvme_create_host(const char *hostnqn, uint32_t *vid)
{
	char buf[SD_MAX_VDI_LEN];
	int ret;
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, hostnqn);

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_MAX_VDI_LEN;
	hdr.vdi.vdi_size = SD_INODE_SIZE;
	hdr.vdi.vdi_flags = SD_VDI_FLAG_MEMBER;

	ret = dog_exec_req(&sd_nid, &hdr, buf);
	if (ret < 0) {
		sd_err("Failed to create host %s: error %d",
		       hostnqn, ret);
		return SD_RES_EIO;
	}
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("Failed to create host %s: %s",
		       hostnqn, sd_strerror(rsp->result));
		ret = rsp->result;;
	} else
		*vid = rsp->vdi.vdi_id;

	return ret;
}

static void print_psk_list(struct sd_inode *inode,
			   const char *protocol, const char *aclname)
{
	unsigned int num_entries, i;
	struct nvme_psk_data *psk;

	if (json_output)
		out_obj = json_object_new_array();

	num_entries = sizeof(inode->data_vdi_id) /
		sizeof(struct nvme_psk_data);
	psk = (struct nvme_psk_data *)inode->data_vdi_id;
	for (i = 0; i < num_entries; i++, psk++) {
		if (!strlen(psk->protocol))
			break;

		if (strncmp(psk->protocol, protocol, strlen(protocol)))
			continue;
		if (aclname && strlen(aclname) && strcmp(aclname, psk->subsysnqn))
			continue;

		if (json_output) {
			struct json_object *psk_obj =
				json_object_new_object();
			JSON_ADD_STRING(psk_obj, "protocol", psk->protocol);
			JSON_ADD_STRING(psk_obj, "hostnqn", inode->header.name);
			JSON_ADD_STRING(psk_obj, "subsysnqn", psk->subsysnqn);
			JSON_ADD_STRING(psk_obj, "digest", psk->digest);
			json_object_array_add(out_obj, psk_obj);
		} else
			printf("%s %s %s %s\n",
			       psk->protocol, inode->header.name,
			       psk->subsysnqn, psk->digest);
	}
	if (json_output) {
		const char *o = json_object_to_json_string(out_obj);
		printf("%s\n", o);
		json_object_put(out_obj);
	}
}

static int nvme_import_psk(int argc, char **argv)
{
	const char *hostnqn = argv[optind++];
	const char *keydata = NULL;
	unsigned char *configured_key, *retained_key;
	char *psk_identity;
	char *psk_protocol, *psk_subsysnqn, *psk_digest;
	uint32_t acl_vid = LOCK_TYPE_ANY, vid;
	struct sd_inode *inode = NULL;
	int ret, i, num_entries;
	unsigned char version, hmac;
	struct nvme_psk_data *psk, *free_psk = NULL;
	size_t key_len;

	if (!argv[optind]) {
		sd_err("No PSK data present");
		return EXIT_USAGE;
	}
	keydata = argv[optind];

	if (!strlen(nvme_cmd_data.aclname)) {
		sd_err("ACL name not present");
		return EXIT_USAGE;
	}
	if (!strcmp(nvme_cmd_data.aclname, "shared") ||
	    !strcmp(nvme_cmd_data.aclname, "any")) {
		sd_err("Invalid ACL name %s", nvme_cmd_data.aclname);
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
	ret = nvme_derive_tls_key(hostnqn, nvme_cmd_data.aclname,
				  1, hmac, configured_key, key_len,
				  &psk_identity, &retained_key);

	psk_protocol = strsep(&psk_identity, " ");
	if (!psk_protocol) {
		sd_err("invalid PSK identity '%s'", psk_identity);
		return EXIT_USAGE;
	}
	if (!strsep(&psk_identity, " ")) {
		sd_err("invalid PSK identity '%s'", psk_identity);
		return EXIT_USAGE;
	}
	psk_subsysnqn = strsep(&psk_identity, " ");
	if (!psk_subsysnqn) {
		sd_err("invalid PSK identity '%s'", psk_identity);
		return EXIT_USAGE;
	}
	psk_digest = strsep(&psk_identity, " ");
	if (!psk_digest) {
		sd_err("invalid PSK identity '%s'", psk_identity);
		return EXIT_USAGE;
	}

	ret = find_vdi_name(hostnqn, 0, "", 0, &vid);
	if (ret != SD_RES_SUCCESS) {
		ret = nvme_create_host(hostnqn, &vid);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to create host %s: %s",
			       hostnqn, sd_strerror(ret));
			return EXIT_USAGE;
		}
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
		if (!strcmp(psk->protocol, psk_protocol) &&
		    !strcmp(psk->subsysnqn, psk_subsysnqn) &&
		    !strcmp(psk->digest, psk_digest)) {
			sd_err("Host %"PRIx32" duplicate PSK for '%s'",
			       vid, psk_subsysnqn);
			ret = EXIT_FAILURE;
			break;
		}
		psk++;
	}
	if (!free_psk) {
		sd_err("Host %" PRIx32 " psk list full (%d entries), cannot add",
		       vid, i);
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

	ret = dog_write_object(vid_to_vdi_oid(vid), 0,
			       free_psk, sizeof(*free_psk),
			       (char *)free_psk - (char *)inode,
			       SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_TGT,
			       SD_MAX_COPIES, 0, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update host inode %"PRIx64": %s",
		       vid_to_vdi_oid(vid), sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (verbose)
		print_psk_list(inode, "NVMe", NULL);
out:
	free(inode);
	return ret;
}

static int nvme_list_psk(int argc, char **argv)
{
	const char *hostnqn = argv[optind];
	uint32_t acl_vid = LOCK_TYPE_ANY, vid;
	struct sd_inode *inode = NULL;
	int ret;

	if (strlen(nvme_cmd_data.aclname)) {
		if (!strcmp(nvme_cmd_data.aclname, "shared") ||
		    !strcmp(nvme_cmd_data.aclname, "any")) {
			sd_err("Invalid ACL name '%s'",
			       nvme_cmd_data.aclname);
			return EXIT_USAGE;
		}
		ret = find_vdi_name(nvme_cmd_data.aclname,
				    0, "", 0, &acl_vid);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to find ACL %s: %s",
			       nvme_cmd_data.aclname, sd_strerror(ret));
			return EXIT_USAGE;
		}
	}
	ret = find_vdi_name(hostnqn, 0, "", 0, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open hostnqn %s with acl %"PRIx32": %s",
		       hostnqn, acl_vid, sd_strerror(ret));
		return EXIT_USAGE;
	}
	inode = xmalloc(SD_INODE_SIZE);
	ret = dog_read_object(vid_to_vdi_oid(vid), inode,
			      SD_INODE_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = EXIT_FAILURE;
	else
		print_psk_list(inode, "NVMe", nvme_cmd_data.aclname);

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

static int nvme_import_dhchap(int argc, char **argv)
{
	const char *hostnqn = argv[optind++];
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
	if (expected_len && decoded_len != expected_len) {
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
	ret = nvme_gen_dhchap_key(hostnqn, hmac, decoded_len,
				  decoded_key, transformed_key);
	if (ret < 0) {
		sd_err("Failed to transform DH-HMAC-CHAP key, error %d", -ret);
		return EXIT_SYSFAIL;
	}

	if (!strlen(nvme_cmd_data.aclname)) {
		sd_err("ACL name not present");
		return EXIT_USAGE;
	}
	if (!strcmp(nvme_cmd_data.aclname, "shared") ||
	    !strcmp(nvme_cmd_data.aclname, "any")) {
		sd_err("Invalid ACL name %s", nvme_cmd_data.aclname);
		return EXIT_USAGE;
	}

	ret = find_vdi_name(nvme_cmd_data.aclname, 0, "", 0, &acl_vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to find ACL %s: %s",
		       nvme_cmd_data.aclname, sd_strerror(ret));
		return EXIT_USAGE;
	}

	ret = find_vdi_name(hostnqn, 0, "", 0, &vid);
	if (ret != SD_RES_SUCCESS) {
		ret = nvme_create_host(hostnqn, &vid);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to create host %s: %s",
			       hostnqn, sd_strerror(ret));
			return EXIT_USAGE;
		}
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
		if (!strncmp(psk->protocol, keydata, 9) &&
		    !strcmp(psk->subsysnqn, nvme_cmd_data.aclname) &&
		    !strcmp(psk->digest, psk_digest)) {
			sd_err("Host %"PRIx32" duplicate PSK for '%s'",
			       vid, nvme_cmd_data.aclname);
			ret = EXIT_FAILURE;
			break;
		}
		psk++;
	}
	if (!free_psk) {
		sd_err("Host %" PRIx32 " dhchap list full (%d entries), cannot add",
		       vid, i);
		ret = EXIT_FAILURE;
		goto out;
	}
	memset(free_psk, 0, sizeof(*free_psk));
	strncpy(free_psk->protocol, keydata, 9);
	strcpy(free_psk->subsysnqn, nvme_cmd_data.aclname);
	strcpy(free_psk->digest, psk_digest);
	memcpy(free_psk->key, transformed_key, decoded_len);
	free_psk->key_len = decoded_len;
	free_psk->digest_len = strlen(psk_digest);

	ret = dog_write_object(vid_to_vdi_oid(vid), 0,
			       free_psk, sizeof(*free_psk),
			       (char *)free_psk - (char *)inode,
			       SD_FLAG_CMD_DIRECT | SD_FLAG_CMD_TGT,
			       SD_MAX_COPIES, 0, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update host inode %"PRIx64": %s",
		       vid_to_vdi_oid(vid), sd_strerror(ret));
		ret = EXIT_FAILURE;
		goto out;
	}

	if (verbose)
		print_psk_list(inode, "DHHC", NULL);
out:
	free(inode);
	return ret;
}

static int nvme_list_dhchap(int argc, char **argv)
{
	const char *hostnqn = argv[optind];
	uint32_t acl_vid = LOCK_TYPE_ANY, vid;
	struct sd_inode *inode = NULL;
	int ret;

	if (strlen(nvme_cmd_data.aclname)) {
		if (!strcmp(nvme_cmd_data.aclname, "shared") ||
		    !strcmp(nvme_cmd_data.aclname, "any")) {
			sd_err("Invalid ACL name '%s'",
			       nvme_cmd_data.aclname);
			return EXIT_USAGE;
		}
		ret = find_vdi_name(nvme_cmd_data.aclname,
				    0, "", 0, &acl_vid);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to find ACL %s: %s",
			       nvme_cmd_data.aclname, sd_strerror(ret));
			return EXIT_USAGE;
		}
	}
	ret = find_vdi_name(hostnqn, 0, "", 0, &vid);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to open hostnqn %s with acl %"PRIx32": %s",
		       hostnqn, acl_vid, sd_strerror(ret));
		return EXIT_USAGE;
	}
	inode = xmalloc(SD_INODE_SIZE);
	ret = dog_read_object(vid_to_vdi_oid(vid), inode,
			      SD_INODE_SIZE, 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = EXIT_FAILURE;
	else
		print_psk_list(inode, "DHHC", nvme_cmd_data.aclname);

	free(inode);
	return ret;
}

static struct subcommand dhchap_modify_cmd[] = {
	{ "import", NULL, NULL, "import a DH-HMAC-CHAP PSK", NULL,
	  CMD_NEED_ARG, nvme_import_dhchap},
	{ "list", NULL, NULL, "list DH-HMAC-CHAP PSKs", NULL,
	  CMD_NEED_ARG, nvme_list_dhchap},
	{NULL},
};

static int dhchap_modify(int argc, char **argv)
{
	return do_generic_subcommand(dhchap_modify_cmd, argc, argv);
}

static struct subcommand nvme_cmd[] = {
	{"psk", "<hostnqn>", "fajphrvTA", "modify a TLS PSK",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 psk_modify, nvme_options},
	{"dhchap", "<hostnqn>", "fajphrvTA", "modify a DH-HMAC-CHAP secret",
	 NULL, CMD_NEED_ROOT|CMD_NEED_ARG,
	 dhchap_modify, nvme_options},
	{NULL,},
};

static int nvme_parser(int ch, const char *opt)
{
	switch (ch) {
	case 'A':
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
