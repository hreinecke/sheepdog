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

int _gnutls_dh_generate_key(gnutls_dh_params_t dh_params,
                            gnutls_datum_t *priv_key, gnutls_datum_t *pub_key);

int _gnutls_dh_compute_key(gnutls_dh_params_t dh_params,
                           const gnutls_datum_t *priv_key,
                           const gnutls_datum_t *pub_key,
                           const gnutls_datum_t *peer_key, gnutls_datum_t *Z);


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

static int auth_hmac_digest_id(uint8_t hmac_id, gnutls_digest_algorithm_t *dig)
{
	switch (hmac_id) {
	case NVME_AUTH_HASH_SHA256:
		*dig = GNUTLS_DIG_SHA256;
		break;
	case NVME_AUTH_HASH_SHA384:
		*dig = GNUTLS_DIG_SHA384;
		break;
	case NVME_AUTH_HASH_SHA512:
		*dig = GNUTLS_DIG_SHA512;
		break;
	default:
		return -EINVAL;
	}
	return 0;
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

/*
 * Byte length of the DH modulus (and thus of the public value g^x mod p)
 * for a given NVMe DH group, i.e. NVME_AUTH_DHGROUP_2048 -> 2048 bits.
 */
static size_t auth_dhgroup_dh_len(uint8_t dhgroup_id)
{
	static const uint16_t dhgroup_bits[] = {
		[NVME_AUTH_DHGROUP_NULL]	= 0,
		[NVME_AUTH_DHGROUP_2048]	= 2048,
		[NVME_AUTH_DHGROUP_3072]	= 3072,
		[NVME_AUTH_DHGROUP_4096]	= 4096,
		[NVME_AUTH_DHGROUP_6144]	= 6144,
		[NVME_AUTH_DHGROUP_8192]	= 8192,
	};

	if (dhgroup_id >= ARRAY_SIZE(dhgroup_bits))
		return 0;
	return dhgroup_bits[dhgroup_id] / 8;
}

/*
 * auth_dhgroup_params() - Build gnutls DH parameters for an NVMe DH group
 *
 * NVMe DH groups are the RFC 7919 FFDHE groups; gnutls exports the
 * well-known (prime, generator) pairs for these groups directly, so no
 * parameter negotiation or generation is required.
 */
static int auth_dhgroup_params(uint8_t dhgroup_id, gnutls_dh_params_t *dh_params)
{
	static const struct {
		const gnutls_datum_t *prime;
		const gnutls_datum_t *generator;
	} ffdhe[] = {
		[NVME_AUTH_DHGROUP_2048] = {
			&gnutls_ffdhe_2048_group_prime,
			&gnutls_ffdhe_2048_group_generator },
		[NVME_AUTH_DHGROUP_3072] = {
			&gnutls_ffdhe_3072_group_prime,
			&gnutls_ffdhe_3072_group_generator },
		[NVME_AUTH_DHGROUP_4096] = {
			&gnutls_ffdhe_4096_group_prime,
			&gnutls_ffdhe_4096_group_generator },
		[NVME_AUTH_DHGROUP_6144] = {
			&gnutls_ffdhe_6144_group_prime,
			&gnutls_ffdhe_6144_group_generator },
		[NVME_AUTH_DHGROUP_8192] = {
			&gnutls_ffdhe_8192_group_prime,
			&gnutls_ffdhe_8192_group_generator },
	};
	int ret;

	if (dhgroup_id >= ARRAY_SIZE(ffdhe) || !ffdhe[dhgroup_id].prime)
		return -EINVAL;

	ret = gnutls_dh_params_init(dh_params);
	if (ret < 0)
		return -ENOMEM;

	ret = gnutls_dh_params_import_raw(*dh_params, ffdhe[dhgroup_id].prime,
					  ffdhe[dhgroup_id].generator);
	if (ret < 0) {
		gnutls_dh_params_deinit(*dh_params);
		return -EINVAL;
	}
	return 0;
}

int setup_dhgroup(struct nofuse_queue *ep, uint8_t dh_gid)
{
	struct nofuse_queue_auth *auth = &ep->auth;
	gnutls_dh_params_t dh_params;
	int ret;

	ctrl_info(ep, "setup DH group %d", dh_gid);
	ret = auth_dhgroup_params(dh_gid, &dh_params);
	if (ret != 0) {
		ctrl_info(ep, "failed to setup dh_param");
		return -1;
	}
	auth->dh_gid = dh_gid;
	auth->dh_gid_size = auth_dhgroup_dh_len(dh_gid);
	return ret;
}

/**
 * nvme_auth_gen_session_key() - Generate an ephemeral session key
 * @ctrl: Controller holding the local DH private key generated for
 *	  this negotiation (see auth_ctrl_exponential())
 * @public_key: Peer's DH public value, zero-padded to the group size
 * @public_key_len: Length of @public_key
 * @sess_key: Output buffer for the session key
 * @sess_key_len: Size of @sess_key buffer
 *
 * NVMe base specification 8.3.4.5.9: The session key Ks shall be computed
 * from the ephemeral DH key (i.e., g^xy mod p) ... by applying the hash
 * function H() selected by the HashID parameter ... (i.e., Ks = H(g^xy mod
 * p)).
 *
 * Consumes and releases @auth->dh_privkey.
 *
 * Return: 0 on success, negative errno on failure.
 */
int auth_gen_session_key(struct nofuse_queue_auth *auth,
		const uint8_t *public_key, size_t public_key_len,
		uint8_t *sess_key, size_t sess_key_len)
{
	gnutls_dh_params_t dh_params;
	gnutls_datum_t peer_pubkey, secret = { NULL, 0 };
	gnutls_digest_algorithm_t dig;
	uint8_t *dh_secret;
	int ret;

	if (!auth->dh_privkey.size)
		return -EINVAL;

	ret = auth_hmac_digest_id(auth->shash_id, &dig);
	if (ret < 0)
		return ret;

	if (sess_key_len != (size_t)gnutls_hash_get_len(dig))
		return -EINVAL;

	ret = auth_dhgroup_params(auth->dh_gid, &dh_params);
	if (ret < 0)
		return -EPROTO;

	peer_pubkey.data = (uint8_t *)public_key;
	peer_pubkey.size = public_key_len;
	ret = _gnutls_dh_compute_key(dh_params, &auth->dh_privkey,
				     &auth->dh_pubkey, &peer_pubkey, &secret);
	if (ret < 0) {
		return -ENOKEY;
	}

	/*
	 * gnutls strips leading zero bytes from the raw DH secret (same
	 * convention as TLS) and may prepend a single sign byte when the
	 * most significant bit of the value is set; re-pad to the modulus
	 * size before hashing, as the peer's implementation will have
	 * done the same.
	 */
	if (secret.size > auth->dh_gid_size) {
		if (secret.size != auth->dh_gid_size + 1 ||
		    secret.data[0] != 0) {
			gnutls_free(secret.data);
			return -EINVAL;
		}
		memmove(secret.data, secret.data + 1, auth->dh_gid_size);
		secret.size = auth->dh_gid_size;
	}
	dh_secret = xzalloc(auth->dh_gid_size);
	if (!dh_secret) {
		gnutls_free(secret.data);
		return -ENOMEM;
	}
	memcpy(dh_secret + (auth->dh_gid_size - secret.size), secret.data,
	       secret.size);
	gnutls_free(secret.data);
	ret = gnutls_hash_fast(dig, dh_secret, auth->dh_gid_size, sess_key);
	free(dh_secret);

	return ret < 0 ? -EIO : 0;
}

/**
 * auth_ctrl_exponential() - Generate the ctrl's ephemeral DH keypair
 * @qe: Queue entry of the Challenge command being built
 * @cval: Output buffer for the DH public value, at least @dh_keysize bytes
 * @dh_keysize: Size of @cval, i.e. nvme_dhchap_dh_len(ctrl->dh_gid)
 *
 * Generates a fresh DH keypair for the negotiated group and stores the
 * private key in ctrl->dh_privkey until the host's Reply message arrives
 * and nvme_auth_gen_session_key() can compute the shared secret.
 *
 * Return: 0 on success, negative errno on failure.
 */
int auth_ctrl_exponential(struct nofuse_queue_auth *auth,
			  uint8_t *cval, size_t dh_keysize)
{
	gnutls_dh_params_t dh_params;
	int ret;

	ret = auth_dhgroup_params(auth->dh_gid, &dh_params);
	if (ret < 0)
		return ret;

	ret = _gnutls_dh_generate_key(dh_params, &auth->dh_privkey,
				      &auth->dh_pubkey);
	if (ret != GNUTLS_E_SUCCESS)
		return -ENOKEY;
	/*
	 * gnutls strips leading zero bytes from the raw DH secret (same
	 * convention as TLS) and may prepend a single sign byte when the
	 * most significant bit of the value is set; re-pad to the modulus
	 * size before hashing, as the peer's implementation will have
	 * done the same.
	 */
	if (auth->dh_pubkey.size > dh_keysize) {
		if (auth->dh_pubkey.size != dh_keysize + 1 ||
		    auth->dh_pubkey.data[0] != 0) {
			sd_err("public key size mismatch (should be %ld, is %d)",
			       dh_keysize, auth->dh_pubkey.size);
			return -ENODATA;
		}
		memcpy(cval, auth->dh_pubkey.data + 1,
		       dh_keysize);
	} else
		memcpy(cval, auth->dh_pubkey.data, dh_keysize);
	return 0;
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
	if (!transformed_key) {
		ctrl_err(ep, "transform key failed");
		return -ENOMEM;
	}

	if (auth->dh_gid != NVME_AUTH_DHGROUP_NULL) {
		if (!auth->dhchap_skey_len ||
		    !auth->dhchap_skey) {
			ctrl_err(ep, "session key is not set");
			ret = -ENOKEY;
			goto out_free_key;
		}
		challenge = xmalloc(shash_len);
		if (!challenge) {
			ret = -ENOMEM;
			goto out_free_key;
		}

		ret = gnutls_hmac_init(&hmac_ctx, hmac, auth->dhchap_skey,
				       auth->dhchap_skey_len);
		if (ret < 0) {
			ctrl_err(ep, "hmac init failed: %d", ret);
			ret = -ENOMEM;
			goto out_free_challenge;
		}
		ret = gnutls_hmac(hmac_ctx, auth->dhchap_c1, shash_len);
		if (ret < 0) {
			ctrl_err(ep, "hmac failed: %d", ret);
			ret = -ENOKEY;
		}
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
