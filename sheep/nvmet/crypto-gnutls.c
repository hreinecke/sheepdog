/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * auth.c
 * NVMe-over-fabrics authentication
 *
 * Copyright (c) 2026 Hannes Reinecke <hare@suse.de>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "sheep.h"
#include "nofuse.h"
#include "ops.h"
#include "nvme.h"
#include "tcp.h"
#include "crypto.h"

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>

void get_random_bytes(uint8_t *bytes, uint32_t len)
{
	int ret = gnutls_rnd(GNUTLS_RND_NONCE, bytes, len);
	sd_assert(ret == 0);
}

static gnutls_mac_algorithm_t select_hmac(int hmac, size_t hash_len,
					  size_t *hmac_len)
{
	gnutls_mac_algorithm_t mac = GNUTLS_MAC_UNKNOWN;

	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		*hmac_len = hash_len;
		break;
	case NVME_HMAC_ALG_SHA2_256:
		mac = GNUTLS_MAC_SHA256;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		mac = GNUTLS_MAC_SHA384;
		break;
	case NVME_HMAC_ALG_SHA2_512:
		mac = GNUTLS_MAC_SHA512;
		break;
	default:
		*hmac_len = 0;
		break;
	}
	if (mac != GNUTLS_MAC_UNKNOWN)
		*hmac_len = gnutls_hmac_get_len(mac);
	return mac;
}

bool auth_hmac_supported(int hmac)
{
	gnutls_mac_algorithm_t mac;
	size_t hmac_len, hash_len = 32;

	mac = select_hmac(hmac, hash_len, &hmac_len);
	if (mac != GNUTLS_MAC_UNKNOWN)
		return true;
	return (hmac_len > 0);
}

static uint8_t *auth_transform_key(gnutls_mac_algorithm_t hmac,
				   const uint8_t *key, size_t key_len,
				   const char *nqn)
{
	gnutls_hmac_hd_t hmac_ctx;
	uint8_t *transformed_key;
	int ret;

	if (!key)
		return NULL;

	if (hmac == GNUTLS_MAC_UNKNOWN) {
		transformed_key = xmalloc(key_len);
		if (!transformed_key)
			return NULL;
		memcpy(transformed_key, key, key_len);
		return transformed_key;
	}

	transformed_key = xmalloc(key_len);
	if (!transformed_key)
		return NULL;

	if (gnutls_hmac_init(&hmac_ctx, hmac, key, key_len) < 0) {
		ret = -ENOMEM;
		goto out_free;
	}
	
	if (gnutls_hmac(hmac_ctx, nqn, strlen(nqn)) < 0 ||
	    gnutls_hmac(hmac_ctx, "NVMe-over-Fabrics", 17) < 0)
		ret = -ENOKEY;
	else
		ret = 0;
	gnutls_hmac_deinit(hmac_ctx, transformed_key);
out_free:
	if (ret < 0) {
		memset(transformed_key, 0, key_len);
		free(transformed_key);
		transformed_key = NULL;
	}
		
	return transformed_key;
}

unsigned int auth_dhgroup_bits(int dh_gid)
{
	int bits;

	switch (dh_gid) {
	case NVME_AUTH_DHGROUP_2048:
		bits = GNUTLS_CURVE_TO_BITS(GNUTLS_GROUP_FFDHE2048);
		break;
	case NVME_AUTH_DHGROUP_3072:
		bits = GNUTLS_CURVE_TO_BITS(GNUTLS_GROUP_FFDHE3072);
		break;
	case NVME_AUTH_DHGROUP_4096:
		bits = GNUTLS_CURVE_TO_BITS(GNUTLS_GROUP_FFDHE4096);
		break;
	case NVME_AUTH_DHGROUP_6144:
		bits = GNUTLS_CURVE_TO_BITS(GNUTLS_GROUP_FFDHE6144);
		break;
	case NVME_AUTH_DHGROUP_8192:
		bits = GNUTLS_CURVE_TO_BITS(GNUTLS_GROUP_FFDHE8192);
		break;
	default:
		bits = 0;
		break;
	}
	return bits;
}

int setup_dhgroup(struct nofuse_queue *ep, uint8_t dh_gid)
{
	struct nofuse_queue_auth *auth = &ep->auth;
	int bits, ret;

	bits = auth_dhgroup_bits(dh_gid);
	if (!bits)
		return 0;

	auth->dh_gid = dh_gid;
	ctrl_info(ep, "setup DH group %d", auth->dh_gid);
	gnutls_privkey_init(&auth->dh_privkey);
	ret = gnutls_privkey_generate2(auth->dh_privkey, GNUTLS_PK_DH, bits,
				       0, NULL, 0);
	
	if (ret != GNUTLS_E_SUCCESS) {
		ctrl_info(ep, "failed to generate private key, err %d", ret);
		auth->dh_gid = 0;
		return -1;
	}
	gnutls_pubkey_init(&auth->dh_pubkey);
	ret = gnutls_pubkey_import_privkey(auth->dh_pubkey, auth->dh_privkey,
					   GNUTLS_KEY_KEY_AGREEMENT, 0);
	if (ret != GNUTLS_E_SUCCESS) {
		ctrl_info(ep, "failed to generate public key, err %d", ret);
		auth->dh_gid = 0;
		ret = -1;
	}

	return ret;
}

int auth_host_hash(struct nofuse_queue *ep, uint8_t *response,
		   unsigned int shash_len)
{
	struct nofuse_queue_auth *auth = &ep->auth;
	gnutls_mac_algorithm_t hmac = GNUTLS_MAC_UNKNOWN;;
	gnutls_hmac_hd_t hmac_ctx;
	uint8_t *challenge = auth->dhchap_c1;
	uint8_t *transformed_key;
	uint8_t buf[4];
	size_t hmac_len;
	int ret;

	hmac = select_hmac(auth->shash_id, shash_len, &hmac_len);
	if (hmac_len != shash_len) {
		ctrl_info(ep, "hash len mismatch (len %u digest %zu)",
			shash_len, hmac_len);
		return -EINVAL;
	}

	transformed_key = auth_transform_key(hmac, ep->ctrl->host_key,
					     ep->ctrl->host_key_len,
					     ep->ctrl->hostnqn);
	if (!transformed_key)
		return -ENOMEM;

	if (auth->dh_gid != NVME_AUTH_DHGROUP_NULL) {
		challenge = xmalloc(shash_len);
		if (!challenge) {
			ret = -ENOMEM;
			goto out_free_key;
		}

		if (gnutls_hmac_init(&hmac_ctx, hmac, auth->dhchap_skey,
				     auth->dhchap_skey_len) < 0) {
			ret = -ENOMEM;
			goto out_free_challenge;
		}
		if (gnutls_hmac(hmac_ctx, auth->dhchap_c1, shash_len) < 0)
			ret = -ENOKEY;
		gnutls_hmac_deinit(hmac_ctx, challenge);
		if (ret)
			goto out_free_challenge;
	} else
		challenge = auth->dhchap_c1;

	ctrl_info(ep, "host response seq %u transaction %d",
		  auth->dhchap_s1, auth->dhchap_tid);

	if (gnutls_hmac_init(&hmac_ctx, hmac, response, shash_len) < 0)
		return -ENOKEY;
	
	ret = -ENOKEY;
	if (gnutls_hmac(hmac_ctx, challenge, shash_len) < 0)
		goto out_deinit;
	if (gnutls_hmac(hmac_ctx, &auth->dhchap_s1, 4) < 0)
		goto out_deinit;
	if (gnutls_hmac(hmac_ctx, &auth->dhchap_tid, 2) < 0)
		goto out_deinit;

	if (gnutls_hmac(hmac_ctx, &auth->sc_c, 1) < 0 ||
	    gnutls_hmac(hmac_ctx, "HostHost", 8) < 0 ||
	    gnutls_hmac(hmac_ctx, ep->ctrl->hostnqn,
			strlen(ep->ctrl->hostnqn)) < 0)
		goto out_deinit;
	memset(buf, 0, 4);
	if (gnutls_hmac(hmac_ctx, buf, 1) < 0 ||
	    gnutls_hmac(hmac_ctx, ep->ctrl->subsys->nqn,
			strlen(ep->ctrl->subsys->nqn) < 0))
		goto out_deinit;
	ret = 0;
out_deinit:
	gnutls_hmac_deinit(hmac_ctx, response);
	if (ret != 0)
		memset(response, 0, shash_len);
out_free_challenge:
	if (challenge != auth->dhchap_c1)
		free(challenge);
out_free_key:
	free(transformed_key);
	return ret;
}

int auth_ctrl_hash(struct nofuse_queue *ep, uint8_t *response,
		   unsigned int shash_len)
{
	struct nofuse_queue_auth *auth = &ep->auth;
	gnutls_mac_algorithm_t hmac = GNUTLS_MAC_UNKNOWN;;
	gnutls_hmac_hd_t hmac_ctx;
	uint8_t *challenge = auth->dhchap_c2;
	uint8_t *transformed_key;
	uint8_t buf[4];
	size_t hmac_len;
	int ret;

	hmac = select_hmac(auth->shash_id, shash_len, &hmac_len);
	if (hmac_len != shash_len) {
		sd_warn("hash len mismatch (len %u digest %zu)",
			shash_len, hmac_len);
		return -EINVAL;
	}

	transformed_key = auth_transform_key(hmac, ep->ctrl->ctrl_key,
					     ep->ctrl->ctrl_key_len,
					     ep->ctrl->hostnqn);
	if (!transformed_key)
		return -ENOMEM;

	if (auth->dh_gid != NVME_AUTH_DHGROUP_NULL) {
		challenge = xmalloc(shash_len);
		if (!challenge) {
			ret = -ENOMEM;
			goto out_free_key;
		}
		if (gnutls_hmac_init(&hmac_ctx, hmac, auth->dhchap_skey,
				     auth->dhchap_skey_len) < 0) {
			ret = -ENOMEM;
			goto out_free_key;
		}
		if (gnutls_hmac(hmac_ctx, auth->dhchap_c2, shash_len) < 0)
			ret = -ENOKEY;
		gnutls_hmac_deinit(hmac_ctx, challenge);
		if (ret)
			goto out_free_challenge;
	}

	ctrl_info(ep, "ctrl response seq %u transaction %d\n",
		  auth->dhchap_s2, auth->dhchap_tid);

	if (gnutls_hmac_init(&hmac_ctx, hmac, response, shash_len) < 0)
		return -ENOKEY;
	
	ret = -ENOKEY;
	if (gnutls_hmac(hmac_ctx, challenge, shash_len) < 0)
		goto out_deinit;
	if (gnutls_hmac(hmac_ctx, &auth->dhchap_s2, 4) < 0)
		goto out_deinit;
	if (gnutls_hmac(hmac_ctx, &auth->dhchap_tid, 2) < 0)
		goto out_deinit;

	if (gnutls_hmac(hmac_ctx, &auth->sc_c, 1) < 0 ||
	    gnutls_hmac(hmac_ctx, "Controller", 10) < 0 ||
	    gnutls_hmac(hmac_ctx, ep->ctrl->subsys->nqn,
			strlen(ep->ctrl->subsys->nqn)) < 0)
		goto out_deinit;
	memset(buf, 0, 4);
	if (gnutls_hmac(hmac_ctx, buf, 1) < 0 ||
	    gnutls_hmac(hmac_ctx, ep->ctrl->hostnqn,
			strlen(ep->ctrl->hostnqn) < 0))
		goto out_deinit;
	ret = 0;
out_deinit:
	gnutls_hmac_deinit(hmac_ctx, response);
	if (ret != 0)
		memset(response, 0, shash_len);
out_free_challenge:
	if (challenge != auth->dhchap_c1)
		free(challenge);
out_free_key:
	free(transformed_key);
	return ret;
}
