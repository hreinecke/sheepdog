// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 * 	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#if NVME_HAVE_SYS_RANDOM
#include <sys/random.h>
#endif
#include <sys/param.h>
#include <sys/stat.h>

#ifdef HAVE_GNUTLS
#include <gnutls/crypto.h>
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

#ifdef HAVE_KEYUTILS
#include <keyutils.h>

#define NVME_TLS_DEFAULT_KEYRING ".nvme"
#endif

#include "crc32.h"
#include "base64.h"
#include "crypto.h"

static unsigned char default_hmac(size_t key_len)
{
	unsigned char hmac = NVME_HMAC_ALG_NONE;

	switch (key_len) {
	case 32:
		hmac = NVME_HMAC_ALG_SHA2_256;
		break;
	case 48:
		hmac = NVME_HMAC_ALG_SHA2_384;
		break;
	case 64:
		hmac = NVME_HMAC_ALG_SHA2_512;
		break;
	default:
		break;
	}
	return hmac;
}

#ifdef HAVE_GNUTLS
static gnutls_mac_algorithm_t select_hmac(int hmac, size_t *hmac_len)
{
	gnutls_mac_algorithm_t mac = GNUTLS_MAC_UNKNOWN;

	switch (hmac) {
	case NVME_HMAC_ALG_SHA2_256:
		mac = GNUTLS_MAC_SHA256;
		*hmac_len = 32;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		mac = GNUTLS_MAC_SHA384;
		*hmac_len = 48;
		break;
	default:
		*hmac_len = 0;
		break;
	}
	return mac;
}
#else
static const EVP_MD *select_hmac(int hmac, size_t *hmac_len)
{
	const EVP_MD *md = NULL;

	switch (hmac) {
	case NVME_HMAC_ALG_SHA2_256:
		md = EVP_sha256();
		*hmac_len = 32;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		md = EVP_sha384();
		*hmac_len = 48;
		break;
	default:
		*hmac_len = 0;
		break;
	}
	return md;
}
#endif

/* NVMe is using the TLS 1.3 HkdfLabel structure */
#define HKDF_INFO_MAX_LEN 514
#define HKDF_INFO_LABEL_MAX 256
#define HKDF_INFO_CONTEXT_MAX 256

/*
 * derive_retained_key()
 *
 * Derive a retained key according to NVMe TCP Transport specification:
 *
 * The retained PSK is derived from the configured PSK. The configured PSK
 * shall be destroyed as soon as the retained PSK is generated and stored.
 * Each NVMe/TCP entity shall support:
 * 1) transforming the configured PSK into a retained PSK before it is stored
 *    by the NVMe/TCP entity for repeated use with another NVMe/TCP entity; and
 * 2) using the configured PSK as a retained PSK.
 *
 * The method to derive a retained PSK from a configured PSK shall be using
 * the HKDF-Extract and HKDF-Expand-Label operations (refer to RFC 5869 and
 * RFC 8446):
 * 1. PRK = HKDF-Extract(0, Configured PSK); and
 * 2. Retained PSK = HKDF-Expand-Label(PRK, “HostNQN”, NQNh,
 *                                     Length(Configured PSK)),
 * where NQNh is the NQN of the host.
 *
 * 'hmac' indicates the hash function to be used to transform the configured
 * PSK in a retained PSK, encoded as follows:
 *
 * - 0 indicates no transform (i.e., the configured PSK is used as a
 *   retained PSK)
 * - 1 indicates SHA-256
 * - 2 indicates SHA-384
 */
static int derive_retained_key(int hmac, const char *hostnqn,
		unsigned char *configured, unsigned char *retained,
		size_t key_len)
{
	uint8_t *hkdf_info = NULL;
	const char *hkdf_label = "tls13 HostNQN";
#ifdef HAVE_GNUTLS
	gnutls_mac_algorithm_t mac;
	gnutls_datum_t ikm, salt, prk, info;
	unsigned char prk_buf[64];
#else
	EVP_PKEY_CTX *ectx = NULL;
	const EVP_MD *md;
#endif
	size_t hmac_len;
	char *pos;
	int ret;

	if (hmac == NVME_HMAC_ALG_NONE) {
		memcpy(retained, configured, key_len);
		return key_len;
	}

	if (key_len > USHRT_MAX)
		return -EINVAL;

	/* +1 byte so that the snprintf terminating null can not overflow */
	hkdf_info = malloc(HKDF_INFO_MAX_LEN + 1);
	if (!hkdf_info)
		return -ENOMEM;

	pos = (char *)hkdf_info;
	*(uint16_t *)pos = htons(key_len & 0xFFFF);
	pos += sizeof(uint16_t);

	ret = snprintf(pos, HKDF_INFO_LABEL_MAX + 1, "%c%s",
		       (int)strlen(hkdf_label), hkdf_label);
	if (ret <= 0 || ret > HKDF_INFO_LABEL_MAX) {
		ret = -ENOKEY;
		goto out_free_hkdf;
	}
	pos += ret;

	ret = snprintf(pos, HKDF_INFO_CONTEXT_MAX + 1, "%c%s",
		       (int)strlen(hostnqn), hostnqn);
	if (ret <= 0 || ret > HKDF_INFO_CONTEXT_MAX) {
		ret = -ENOKEY;
		goto out_free_hkdf;
	}
	pos += ret;

#ifdef HAVE_GNUTLS
	mac = select_hmac(hmac, &hmac_len);
	if (!mac || !hmac_len) {
		ret = -EINVAL;
		goto out_free_hkdf;
	}

	ikm.data = configured;
	ikm.size = key_len;
	salt.data = NULL;
	salt.size = 0;
	if (gnutls_hkdf_extract(mac, &ikm, &salt, prk_buf) < 0) {
		ret = -ENOKEY;
		goto out_free_hkdf;
	}
	prk.data = prk_buf;
	prk.size = hmac_len;
	info.data = hkdf_info;
	info.size = pos - (char *)hkdf_info;

	if (gnutls_hkdf_expand(mac, &prk, &info, retained, key_len) < 0)
		ret = -ENOKEY;
	else
		ret = 0;
#else
	md = select_hmac(hmac, &hmac_len);
	if (!md || !hmac_len) {
		ret = -EINVAL;
		goto out_free_hkdf;
	}

	ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ectx) {
		ret = -ENOMEM;
		goto out_free_hkdf;
	}

	if (EVP_PKEY_derive_init(ectx) <= 0) {
		ret = -ENOMEM;
		goto out_free_evp;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(ectx, md) <= 0) {
		ret = -ENOKEY;
		goto out_free_evp;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(ectx, configured, key_len) <= 0) {
		ret = -ENOKEY;
		goto out_free_evp;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(ectx, hkdf_info,
					(pos - (char *)hkdf_info)) <= 0) {
		ret = -ENOKEY;
		goto out_free_evp;
	}

	if (EVP_PKEY_derive(ectx, retained, &key_len) <= 0)
		ret = -ENOKEY;
	else
		ret = 0;
out_free_evp:
	EVP_PKEY_CTX_free(ectx);
#endif
out_free_hkdf:
	free(hkdf_info);
	return ret < 0 ? ret : key_len;
}

/*
 * derive_tls_key()
 *
 * Derive a TLS PSK from a retained PSK.
 *
 * The TLS PSK shall be derived as follows from an input PSK (i.e., either
 * a retained PSK or a generated PSK) and a PSK identity using the HKDF-Extract
 * and HKDF-Expand-Label operations (refer to RFC 5869 and RFC 8446) where the
 * hash function is the one specified by the hash specifier of the PSK identity:
 * 1. PRK = HKDF-Extract(0, Input PSK); and
 * 2. TLS PSK = HKDF-Expand-Label(PRK, “nvme-tls-psk”, PskIdentity, L),
 * where PskIdentity is the PSK identity and L is the output size in bytes of
 * the hash function (i.e., 32 for SHA-256 and 48 for SHA-384).
 *
 * Note that this is _not_ the hash value as specified by the configured key,
 * but rather the hash function of the cipher suite associated with the
 * PSK:
 * - 1 indicates SHA-245 (for the TLS_AES_128_GCM_SHA256 cipher suite)
 * - 2 indicates SHA-384 (for the TLS_AES_256_GCM_SHA384 cipher suite)
 *
 * and the value '0' is invalid here.
 */

static int derive_tls_key(int version, unsigned char cipher,
		const char *context, unsigned char *retained,
		unsigned char *psk, size_t key_len)
{
	uint8_t *hkdf_info = NULL;
	const char *hkdf_label = "tls13 nvme-tls-psk";
#ifdef HAVE_GNUTLS
	gnutls_mac_algorithm_t mac;
	gnutls_datum_t ikm, salt, prk, info;
	unsigned char prk_buf[64];
#else
	EVP_PKEY_CTX *ectx = NULL;
	const EVP_MD *md;
#endif
	size_t hmac_len;
	char *pos;
	int ret;

	if (key_len > USHRT_MAX)
		return -EINVAL;

	/* +1 byte so that the snprintf terminating null can not overflow */
	hkdf_info = malloc(HKDF_INFO_MAX_LEN + 1);
	if (!hkdf_info)
		return -ENOMEM;

	pos = (char *)hkdf_info;
	*(uint16_t *)pos = htons(key_len & 0xFFFF);
	pos += sizeof(uint16_t);

	ret = snprintf(pos, HKDF_INFO_LABEL_MAX + 1, "%c%s",
		       (int)strlen(hkdf_label), hkdf_label);
	if (ret <= 0 || ret > HKDF_INFO_LABEL_MAX) {
		ret = -ENOKEY;
		goto out_free_hkdf;
	}
	pos += ret;

	switch (version) {
	case 0:
		ret = snprintf(pos, HKDF_INFO_CONTEXT_MAX + 1, "%c%s",
			       (int)strlen(context), context);
		if (ret <= 0 || ret > HKDF_INFO_CONTEXT_MAX) {
			ret = -ENOKEY;
			goto out_free_hkdf;
		}
		pos += ret;
		break;
	case 1:
		ret = snprintf(pos, HKDF_INFO_CONTEXT_MAX + 1, "%c%02d %s",
			       (int)strlen(context) + 3, cipher, context);
		if (ret <= 0 || ret > HKDF_INFO_CONTEXT_MAX) {
			ret = -ENOKEY;
			goto out_free_hkdf;
		}
		pos += ret;
		break;
	default:
		ret = -ENOKEY;
		goto out_free_hkdf;
	}

#ifdef HAVE_GNUTLS
	mac = select_hmac(cipher, &hmac_len);
	if (!mac || !hmac_len) {
		ret = -EINVAL;
		goto out_free_hkdf;
	}

	ikm.data = retained;
	ikm.size = key_len;
	salt.data = NULL;
	salt.size = 0;
	if (gnutls_hkdf_extract(mac, &ikm, &salt, prk_buf) < 0) {
		ret = -ENOKEY;
		goto out_free_hkdf;
	}

	prk.data = prk_buf;
	prk.size = hmac_len;
	info.data = hkdf_info;
	info.size = pos - (char *)hkdf_info;

	if (gnutls_hkdf_expand(mac, &prk, &info, psk, key_len) < 0)
		ret = -ENOKEY;
	else
		ret = 0;
#else
	md = select_hmac(cipher, &hmac_len);
	if (!md || !hmac_len) {
		ret = -EINVAL;
		goto out_free_hkdf;
	}

	ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ectx) {
		ret = -ENOMEM;
		goto out_free_hkdf;
	}

	if (EVP_PKEY_derive_init(ectx) <= 0) {
		ret = -ENOMEM;
		goto out_free_evp;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(ectx, md) <= 0) {
		ret = -ENOKEY;
		goto out_free_evp;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(ectx, retained, key_len) <= 0) {
		ret = -ENOKEY;
		goto out_free_evp;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(ectx, hkdf_info,
					(pos - (char *)hkdf_info)) <= 0) {
		ret = -ENOKEY;
		goto out_free_evp;
	}

	if (EVP_PKEY_derive(ectx, psk, &key_len) <= 0)
		ret = -ENOKEY;
	else
		ret = 0;

out_free_evp:
	EVP_PKEY_CTX_free(ectx);
#endif
out_free_hkdf:
	free(hkdf_info);
	return ret < 0 ? ret : key_len;
}

int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
		unsigned int key_len, unsigned char *secret,
		unsigned char *key)
{
	static const char hmac_seed[] = "NVMe-over-Fabrics";
#ifdef HAVE_GNUTLS
	gnutls_hmac_hd_t hmac_ctx;
	gnutls_mac_algorithm_t mac;
#else
	OSSL_LIB_CTX *lib_ctx = NULL;
	EVP_MAC_CTX *mac_ctx = NULL;
	EVP_MAC *mac = NULL;
	OSSL_PARAM params[2], *p = params;
	char *progq = NULL;
	const char *digest;
#endif
	size_t len;
	int ret = -ENOMEM;

#ifdef HAVE_GNUTLS
	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		memcpy(key, secret, key_len);
		return 0;
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
		return -EINVAL;
	}

	len = gnutls_hmac_get_len(mac);
	if (len != key_len)
		return -EINVAL;

	if (gnutls_hmac_init(&hmac_ctx, mac, secret, key_len) < 0)
		return -ENOKEY;

	if (gnutls_hmac(hmac_ctx, hostnqn, strlen(hostnqn)) < 0 ||
	    gnutls_hmac(hmac_ctx, hmac_seed, strlen(hmac_seed)) < 0) {
		gnutls_hmac_deinit(hmac_ctx, key);
		memset(key, 0, key_len);
		ret = -ENOKEY;
	} else {
		gnutls_hmac_deinit(hmac_ctx, key);
		ret = 0;
	}
#else
	lib_ctx = OSSL_LIB_CTX_new();
	if (!lib_ctx)
		return ret;

	mac = EVP_MAC_fetch(lib_ctx, OSSL_MAC_NAME_HMAC, progq);
	if (!mac)
		goto out_free_lib;

	mac_ctx = EVP_MAC_CTX_new(mac);
	if (!mac_ctx)
		goto out_free_mac;

	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		memcpy(key, secret, key_len);
		ret = 0;
		goto out_free_mac_ctx;
		break;
	case NVME_HMAC_ALG_SHA2_256:
		digest = OSSL_DIGEST_NAME_SHA2_256;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		digest = OSSL_DIGEST_NAME_SHA2_384;
		break;
	case NVME_HMAC_ALG_SHA2_512:
		digest = OSSL_DIGEST_NAME_SHA2_512;
		break;
	default:
		ret = -EINVAL;
		goto out_free_mac_ctx;
		break;
	}
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						(char *)digest, 0);
	*p = OSSL_PARAM_construct_end();

	ret = -ENOKEY;
	if (!EVP_MAC_init(mac_ctx, secret, key_len, params))
		goto out_free_mac_ctx;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hostnqn,
			    strlen(hostnqn)))
		goto out_free_mac_ctx;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hmac_seed,
			    strlen(hmac_seed)))
		goto out_free_mac_ctx;

	if (!EVP_MAC_final(mac_ctx, key, &len, key_len))
		goto out_free_mac_ctx;
	if (len != key_len)
		ret = -EINVAL;
	else
		ret = 0;

out_free_mac_ctx:
	EVP_MAC_CTX_free(mac_ctx);
out_free_mac:
	EVP_MAC_free(mac);
out_free_lib:
	OSSL_LIB_CTX_free(lib_ctx);;
#endif
	return ret;
}

static int derive_psk_digest(const char *hostnqn, const char *subsysnqn,
		int version, int cipher,
		unsigned char *retained, size_t key_len,
		char *digest, size_t digest_len)
{
	static const char hmac_seed[] = "NVMe-over-Fabrics";
	unsigned char *psk_ctx = NULL;
#ifdef HAVE_GNUTLS
	gnutls_hmac_hd_t hmac_ctx;
	gnutls_mac_algorithm_t mac;
#else
	OSSL_LIB_CTX *lib_ctx = NULL;
	EVP_MAC_CTX *mac_ctx = NULL;
	EVP_MAC *mac = NULL;
	OSSL_PARAM params[2], *p = params;
	char *progq = NULL;
	const char *dig = NULL;
#endif
	size_t hmac_len;
	int ret;

	psk_ctx = malloc(key_len);
	if (!psk_ctx)
		return -ENOMEM;

#ifdef HAVE_GNUTLS
	switch (cipher) {
	case NVME_HMAC_ALG_SHA2_256:
		mac = GNUTLS_MAC_SHA256;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		mac = GNUTLS_MAC_SHA384;
		break;
	default:
		return -EINVAL;
	}

	hmac_len = gnutls_hmac_get_len(mac);
	if (hmac_len > key_len)
		return -EINVAL;

	ret = -ENOKEY;
	if (gnutls_hmac_init(&hmac_ctx, mac, retained, key_len) < 0)
		goto out_free_psk_ctx;

	if (gnutls_hmac(hmac_ctx, hostnqn, strlen(hostnqn)) < 0 ||
	    gnutls_hmac(hmac_ctx, " ", 1) < 0 ||
	    gnutls_hmac(hmac_ctx, subsysnqn, strlen(subsysnqn)) < 0 ||
	    gnutls_hmac(hmac_ctx, " ", 1) < 0 ||
	    gnutls_hmac(hmac_ctx, hmac_seed, strlen(hmac_seed)) < 0) {
		gnutls_hmac_deinit(hmac_ctx, psk_ctx);
		goto out_free_psk_ctx;
	}

	gnutls_hmac_deinit(hmac_ctx, psk_ctx);
	ret = 0;
#else
	switch (cipher) {
	case NVME_HMAC_ALG_SHA2_256:
		dig = OSSL_DIGEST_NAME_SHA2_256;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		dig = OSSL_DIGEST_NAME_SHA2_384;
		break;
	default:
		ret = -EINVAL;
		goto out_free_mac;
		break;
	}

	lib_ctx = OSSL_LIB_CTX_new();
	if (!lib_ctx) {
		ret = -ENOMEM;
		goto out_free_mac_ctx;
	}

	mac = EVP_MAC_fetch(lib_ctx, OSSL_MAC_NAME_HMAC, progq);
	if (!mac)
		goto out_free_lib;

	mac_ctx = EVP_MAC_CTX_new(mac);
	if (!mac_ctx)
		goto out_free_mac;

	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						(char *)dig, 0);
	*p = OSSL_PARAM_construct_end();

	ret = -ENOKEY;
	if (!EVP_MAC_init(mac_ctx, retained, key_len, params))
		goto out_free_psk_ctx;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hostnqn,
			    strlen(hostnqn)))
		goto out_free_psk_ctx;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)" ", 1))
		goto out_free_psk_ctx;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)subsysnqn,
			    strlen(subsysnqn)))
		goto out_free_psk_ctx;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)" ", 1))
		goto out_free_psk_ctx;

	if (!EVP_MAC_update(mac_ctx, (unsigned char *)hmac_seed,
			    strlen(hmac_seed)))
		goto out_free_psk_ctx;

	if (!EVP_MAC_final(mac_ctx, psk_ctx, &hmac_len, key_len))
		goto out_free_psk_ctx;
#endif

	if (hmac_len * 2 > digest_len) {
		ret = -EINVAL;
		goto out_free_psk_ctx;
	}
	memset(digest, 0, digest_len);
	ret = base64_encode(psk_ctx, hmac_len, digest);
	if (ret > 0)
		ret = strlen(digest);
#ifndef HAVE_GNUTLS
	out_free_mac_ctx:
	EVP_MAC_CTX_free(mac_ctx);
out_free_mac:
	EVP_MAC_free(mac);
out_free_lib:
	OSSL_LIB_CTX_free(lib_ctx);;
#endif
out_free_psk_ctx:
	free(psk_ctx);
	return ret;
}

static int gen_tls_identity(const char *hostnqn, const char *subsysnqn,
			    int version, int cipher, char *digest,
			    char *identity)
{
	if (version == 0) {
		sprintf(identity, "NVMe%01dR%02d %s %s",
			version, cipher, hostnqn, subsysnqn);
		return strlen(identity);
	}
	if (version > 1 || !digest)
		return -EINVAL;

	sprintf(identity, "NVMe%01dR%02d %s %s %s",
		version, cipher, hostnqn, subsysnqn, digest);
	return strlen(identity);
}

static int derive_nvme_keys(const char *hostnqn, const char *subsysnqn,
		char *identity, int version,
		int hmac, unsigned char *configured,
		unsigned char *psk, int key_len)
{
	unsigned char *retained = NULL;
	char *digest = NULL;
	char *context = identity;
	unsigned char cipher;
	int ret = -1;

	if (!hostnqn || !subsysnqn || !identity || !psk)
		return -EINVAL;

	retained = malloc(key_len);
	if (!retained)
		return -ENOMEM;

	ret = derive_retained_key(hmac, hostnqn, configured,
				  retained, key_len);
	if (ret < 0)
		goto out_free;

	if (hmac == NVME_HMAC_ALG_NONE)
		cipher = default_hmac(key_len);
	else
		cipher = hmac;

	if (version == 1) {
		size_t digest_len = 2 * key_len;

		digest = malloc(digest_len);
		if (!digest) {
			ret = -ENOMEM;
			goto out_free;
		}

		ret = derive_psk_digest(hostnqn, subsysnqn, version,
					cipher, retained, key_len, digest,
					digest_len);
		if (ret < 0)
			goto out_free_digest;

		context = digest;
	}
	ret = gen_tls_identity(hostnqn, subsysnqn, version, cipher,
			       digest, identity);
	if (ret > 0)
		ret = derive_tls_key(version, cipher, context, retained,
				     psk, key_len);
out_free_digest:
	if (digest)
		free(digest);
out_free:
	free(retained);
	return ret;
}

static ssize_t nvme_identity_len(int hmac, int version, const char *hostnqn,
				 const char *subsysnqn)
{
	ssize_t len;

	if (!hostnqn || !subsysnqn)
		return -EINVAL;

	len = strlen(hostnqn) + strlen(subsysnqn) + 12;
	if (version == 1) {
		len += 66;
		if (hmac == NVME_HMAC_ALG_SHA2_384)
			len += 32;
	} else if (version > 1) {
		return -EINVAL;
	}
	return len;
}

int nvme_generate_tls_key_identity(const char *hostnqn,
		const char *subsysnqn, int version, int hmac,
		unsigned char *configured_key, int key_len, char **ident)
{
	unsigned char *psk = NULL;
	char *identity = NULL;
	ssize_t identity_len;
	int ret;

	identity_len = nvme_identity_len(hmac, version, hostnqn, subsysnqn);
	if (identity_len < 0)
		return -EINVAL;

	identity = malloc(identity_len);
	if (!identity)
		return -ENOMEM;

	psk = malloc(key_len);
	if (!psk) {
		free(identity);
		return -ENOMEM;
	}

	memset(psk, 0, key_len);
	ret = derive_nvme_keys(hostnqn, subsysnqn, identity, version, hmac,
			       configured_key, psk, key_len);
	if (ret != key_len) {
		free(psk);
		free(identity);
		if (ret < 0)
			return ret;
		return -ENOKEY;
	}

	free(psk);
	*ident = identity;
	identity = NULL;

	return 0;
}

#ifdef HAVE_KEYUTILS
int nvme_lookup_keyring(const char *keyring, long *key)
{
	key_serial_t keyring_id;

	if (!keyring)
		keyring = NVME_TLS_DEFAULT_KEYRING;
	keyring_id = find_key_by_type_and_desc("keyring", keyring, 0);
	if (keyring_id < 0)
		return -errno;

	*key = keyring_id;
	return 0;
}

char *nvme_describe_key_serial(long key_id)
{
	char *str = NULL, *serial;
	char *last;

	if (keyctl_describe_alloc(key_id, &str) < 0)
		return NULL;

	last = strrchr(str, ';');
	if (!last) {
		free(str);
		return NULL;
	}

	last++;
	if (strlen(last) == 0) {
		free(str);
		return NULL;
	}
	serial = strdup(last);
	free(str);
	return serial;
}

int nvme_lookup_key(const char *type,
		    const char *identity, long *keyp)
{
	key_serial_t key;

	key = keyctl_search(KEY_SPEC_SESSION_KEYRING, type, identity, 0);
	if (key < 0)
		return -errno;

	*keyp = key;
	return 0;
}

int nvme_set_keyring(long key_id)
{
	long err;

	if (key_id == 0) {
		if (nvme_lookup_keyring(NULL, &key_id))
			return -ENOKEY;
	}

	err = keyctl_link(key_id, KEY_SPEC_SESSION_KEYRING);
	if (err < 0)
		return -errno;
	return 0;
}

int nvme_read_key(long keyring_id, long key_id,
		  int *len, unsigned char **key)
{
	void *buffer;
	int ret;

	ret = nvme_set_keyring(keyring_id);
	if (ret < 0)
		return ret;

	ret = keyctl_read_alloc(key_id, &buffer);
	if (ret < 0)
		return ret;

	*len = ret;
	*key = buffer;
	return 0;
}

int nvme_update_key(long keyring_id, const char *key_type,
		    const char *identity,
		    unsigned char *key_data, int key_len, long *keyp)
{
	long key;

	key = keyctl_search(keyring_id, key_type, identity, 0);
	if (key > 0) {
		if (keyctl_revoke(key) < 0)
			return -errno;
	}
	key = add_key(key_type, identity,
		      key_data, key_len, keyring_id);
	if (key < 0)
		return -errno;

	*keyp = key;
	return 0;
}

static int __nvme_insert_tls_key(key_serial_t keyring_id, const char *key_type,
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac, unsigned char *configured_key,
		int key_len, long *keyp)
{
	unsigned char *psk = NULL;
	char *identity = NULL;
	ssize_t identity_len;
	long key;
	int ret;

	identity_len = nvme_identity_len(hmac, version, hostnqn, subsysnqn);
	if (identity_len < 0)
		return identity_len;

	identity = malloc(identity_len);
	if (!identity)
		return -ENOMEM;
	memset(identity, 0, identity_len);

	psk = malloc(key_len);
	if (!psk) {
		free(identity);
		return -ENOMEM;
	}
	memset(psk, 0, key_len);
	ret = derive_nvme_keys(hostnqn, subsysnqn, identity, version, hmac,
			       configured_key, psk, key_len);
	if (ret != key_len) {
		free(psk);
		free(identity);
		if (ret < 0)
			return ret;
		return -ENOKEY;
	}

	ret = nvme_update_key(keyring_id, key_type, identity,
			      psk, key_len, &key);
	if (!ret)
		*keyp = key;

	free(psk);
	free(identity);
	return ret;
}

int nvme_insert_tls_key(const char *keyring, const char *key_type,
			const char *hostnqn, const char *subsysnqn,
			int version, int hmac,
			unsigned char *configured_key, int key_len,
			long *key)
{
	long keyring_id = 0;
	int ret;

	ret = nvme_lookup_keyring(keyring, &keyring_id);
	if (!ret && !keyring_id)
		ret = -ENOKEY;
	if (ret)
		return ret;

	ret = nvme_set_keyring(keyring_id);
	if (ret < 0)
		return 0;

	return __nvme_insert_tls_key(keyring_id, key_type,
		hostnqn, subsysnqn, version, hmac,
		configured_key, key_len, key);
}

int nvme_revoke_tls_key(const char *keyring, const char *key_type,
			const char *identity)
{
	long keyring_id = 0, key;
	int ret;

	ret = nvme_lookup_keyring(keyring, &keyring_id);
	if (!ret && !keyring_id)
		ret = -ENOKEY;
	if (ret)
		return ret;

	key = keyctl_search(keyring_id, key_type, identity, 0);
	if (key < 0)
		return -errno;

	key = keyctl_revoke(key);
	if (key < 0)
		return -errno;

	return 0;
}

#endif

/*
 * PSK Interchange Format
 * NVMeTLSkey-<v>:<xx>:<s>:
 *
 * x: version as one ASCII char
 * yy: hmac encoded as two ASCII chars
 *     00: no transform ('configured PSK')
 *     01: SHA-256
 *     02: SHA-384
 * s:  32 or 48 bytes binary followed by a CRC-32 of the configured PSK
 *     (4 bytes) encoded as base64
 */
int nvme_export_tls_key(unsigned char version,
		unsigned char hmac, const unsigned char *key_data,
		size_t key_len, char **encoded_keyp)
{
	unsigned int raw_len, encoded_len, len;
	unsigned long crc = crc32(0L, NULL, 0);
	unsigned char raw_secret[52];
	char *encoded_key;

	switch (hmac) {
	case NVME_HMAC_ALG_NONE:
		if (key_len != 32 && key_len != 48)
			return -EINVAL;
		break;
	case NVME_HMAC_ALG_SHA2_256:
		if (key_len != 32)
			return -EINVAL;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		if (key_len != 48)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	raw_len = key_len;

	memcpy(raw_secret, key_data, raw_len);
	crc = crc32(crc, raw_secret, raw_len);
	raw_secret[raw_len++] = crc & 0xff;
	raw_secret[raw_len++] = (crc >> 8) & 0xff;
	raw_secret[raw_len++] = (crc >> 16) & 0xff;
	raw_secret[raw_len++] = (crc >> 24) & 0xff;

	encoded_len = (raw_len * 2) + 20;
	encoded_key = malloc(encoded_len);
	if (!encoded_key)
		return -ENOMEM;

	memset(encoded_key, 0, encoded_len);
	len = sprintf(encoded_key, "NVMeTLSkey-%x:%02x:", version, hmac);
	len += base64_encode(raw_secret, raw_len, encoded_key + len);
	encoded_key[len++] = ':';
	encoded_key[len++] = '\0';

	*encoded_keyp = encoded_key;
	return 0;
}

int nvme_import_tls_key(const char *encoded_key,
			unsigned char *version, unsigned char *hmac,
			size_t *key_len, unsigned char **keyp)
{
	unsigned char decoded_key[128], *key_data;
	unsigned int crc = crc32(0L, NULL, 0);
	unsigned int key_crc;
	int err, _version, _hmac, decoded_len;
	size_t len;

	if (sscanf(encoded_key, "NVMeTLSkey-%d:%02x:*s",
		   &_version, &_hmac) != 2)
		return -EINVAL;

	if (_version != 1)
		return -EINVAL;

	*version = _version;

	len = strlen(encoded_key);
	switch (_hmac) {
	case NVME_HMAC_ALG_NONE:
		if (len != 65 && len != 89)
			return -EINVAL;
		break;
	case NVME_HMAC_ALG_SHA2_256:
		if (len != 65)
			return -EINVAL;
		break;
	case NVME_HMAC_ALG_SHA2_384:
		if (len != 89)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	*hmac = _hmac;

	err = base64_decode(encoded_key + 16, len - 17, decoded_key);
	if (err < 0)
		return -ENOKEY;

	decoded_len = err;
	decoded_len -= 4;
	if (decoded_len != 32 && decoded_len != 48)
		return -ENOKEY;

	crc = crc32(crc, decoded_key, decoded_len);
	key_crc = ((uint32_t)decoded_key[decoded_len]) |
		((uint32_t)decoded_key[decoded_len + 1] << 8) |
		((uint32_t)decoded_key[decoded_len + 2] << 16) |
		((uint32_t)decoded_key[decoded_len + 3] << 24);
	if (key_crc != crc) {
		return -EKEYREJECTED;
	}

	key_data = malloc(decoded_len);
	if (!key_data)
		return -ENOMEM;
	memcpy(key_data, decoded_key, decoded_len);

	*key_len = decoded_len;
	*keyp = key_data;
	return 0;
}
