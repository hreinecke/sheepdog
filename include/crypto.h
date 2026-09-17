// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *	    Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 *	    Daniel Wagner <dwagner@suse.de>
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * DOC: crypto.h
 *
 * crypto utility functions
 */
/**
 * enum nvme_hmac_alg - HMAC algorithm
 * @NVME_HMAC_ALG_NONE:	No HMAC algorithm
 * @NVME_HMAC_ALG_SHA2_256:	SHA2-256
 * @NVME_HMAC_ALG_SHA2_384:	SHA2-384
 * @NVME_HMAC_ALG_SHA2_512:	SHA2-512
 */
enum nvme_hmac_alg {
	NVME_HMAC_ALG_NONE	= 0,
	NVME_HMAC_ALG_SHA2_256	= 1,
	NVME_HMAC_ALG_SHA2_384	= 2,
	NVME_HMAC_ALG_SHA2_512	= 3,
};

/**
 * nvme_gen_dhchap_key() - DH-HMAC-CHAP key generation
 * @hostnqn:	Host NVMe Qualified Name
 * @hmac:	HMAC algorithm
 * @key_len:	Output key length
 * @secret:	Secret to used for digest
 * @key:	Generated DH-HMAC-CHAP key
 *
 * Return: If key generation was successful the function returns 0 or
 * a negative error code otherwise.
 */
int nvme_gen_dhchap_key(char *hostnqn, enum nvme_hmac_alg hmac,
		unsigned int key_len, unsigned char *secret,
		unsigned char *key);

/**
 * nvme_lookup_keyring() - Lookup keyring serial number
 * @keyring:    Keyring name
 * @key:	Key serial number to return
 *
 * Looks up the serial number of the keyring @keyring.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_lookup_keyring(const char *keyring, long *key);

/**
 * nvme_describe_key_serial() - Return key description
 * @key_id:    Key serial number
 *
 * Fetches the description of the key or keyring identified
 * by the serial number @key_id.
 *
 * Return: The description of @key_id or NULL on failure.
 * The returned string needs to be freed by the caller.
 */
char *nvme_describe_key_serial(long key_id);

/**
 * nvme_lookup_key() - Lookup key serial number
 * @type:	Key type
 * @identity:	Key description
 * @key:	Key serial number to return
 *
 * Looks up the serial number of the key @identity
 * with type %type in the current session keyring.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_lookup_key(const char *type,
		    const char *identity, long *key);

/**
 * nvme_set_keyring() - Link keyring for lookup
 * @keyring_id:    Keyring id
 *
 * Links @keyring_id into the session keyring such that
 * its keys are available for further key lookups.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_set_keyring(long keyring_id);

/**
 * nvme_create_raw_secret - Generate a raw secret buffer from input data
 * @secret:		Input secret data
 * @key_len:		The length of the raw_secret in bytes
 * @raw_secret:		Return buffer with the generated raw secret
 *
 * Transforms the provided @secret into a raw secret buffer suitable for
 * use with NVMe key management operations.
 *
 * The generated raw secret can subsequently be passed to nvme_read_key()
 * or nvme_update_key().
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_create_raw_secret(const char *secret, size_t key_len,
			   unsigned char **raw_secret);

/**
 * nvme_read_key() - Read key raw data
 * @keyring_id:		Id of the keyring holding %key_id
 * @key_id:		Key id
 * @len:		Length of the returned data
 * @key:		Key serial to return
 *
 * Links the keyring specified by @keyring_id into the session
 * keyring and reads the payload of the key specified by @key_id.
 * @len holds the size of the returned buffer.
 * If @keyring is 0 the default keyring '.nvme' is used.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_read_key(long keyring_id, long key_id,
		  int *len, unsigned char **key);

/**
 * nvme_update_key() - Update key raw data
 * @keyring_id:	Id of the keyring holding %key_id
 * @key_type:	Type of the key to insert
 * @identity:	Key identity string
 * @key_data:	Raw data of the key
 * @key_len:	Length of @key_data
 * @key:	Key serial to return
 *
 * Links the keyring specified by @keyring_id into the session
 * keyring and updates the key reference by @identity with @key_data.
 * The old key with identity @identity will be revoked to make it
 * inaccessible.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_update_key(long keyring_id, const char *key_type, const char *identity,
		unsigned char *key_data, int key_len, long *key);

/**
 * nvme_insert_tls_key() - Derive and insert TLS key
 * @keyring:    Keyring to use
 * @key_type:	Type of the resulting key
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	Key version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 * @key:	Key serial to return
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP 1.0a (if
 * @version s set to '0') or NVMe TP8028 (if @version is set to '1) and
 * stores it as type @key_type in the keyring specified by @keyring.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_insert_tls_key(const char *keyring, const char *key_type,
			const char *hostnqn, const char *subsysnqn,
			int version, int hmac,
			unsigned char *configured_key, int key_len,
			long *key);

/**
 * nvme_generate_tls_key_identity() - Generate the TLS key identity
 * @hostnqn:	Host NVMe Qualified Name
 * @subsysnqn:	Subsystem NVMe Qualified Name
 * @version:	Key version to use
 * @hmac:	HMAC algorithm
 * @configured_key:	Configured key data to derive the key from
 * @key_len:	Length of @configured_key
 * @identity:	TLS identity to return
 *
 * Derives a 'retained' TLS key as specified in NVMe TCP and
 * generate the corresponding TLs identity.
 *
 * It is the responsibility of the caller to free the returned string.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_generate_tls_key_identity(
		const char *hostnqn, const char *subsysnqn,
		int version, int hmac,
		unsigned char *configured_key, int key_len,
		char **identity);

/**
 * nvme_revoke_tls_key() - Revoke TLS key from keyring
 * @keyring:    Keyring to use
 * @key_type:    Type of the key to revoke
 * @identity:    Key identity string
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_revoke_tls_key(const char *keyring,
		const char *key_type, const char *identity);

/**
 * nvme_export_tls_key() - Export a TLS pre-shared key
 * @version:	Indicated the representation of the TLS PSK
 * @hmac:	HMAC algorithm used to transfor the configured PSK
 *		in a retained PSK
 * @key_data:	Raw data of the key
 * @key_len:	Length of @key_data
 * @identity:	TLS identity to return
 *
 * Returns @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * It is the responsibility of the caller to free the returned
 * string.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_export_tls_key(unsigned char version, unsigned char hmac,
		const unsigned char *key_data,
		size_t key_len, char **identity);

/**
 * nvme_import_tls_key() - Import a TLS key
 * @encoded_key:	TLS key in PSK interchange format
 * @version:		Indicated the representation of the TLS PSK
 * @hmac:		HMAC algorithm used to transfor the configured
 *			PSK in a retained PSK
 * @key_len:		Length of the resulting key data
 * @key:		Key serial to return
 *
 * Imports @key_data in the PSK Interchange format as defined in section
 * 3.6.1.5 of the NVMe TCP Transport specification.
 *
 * It is the responsibility of the caller to free the returned string.
 *
 * Return: 0 on success, negative error code otherwise.
 */
int nvme_import_tls_key(const char *encoded_key,
		unsigned char *version, unsigned char *hmac,
		size_t *key_len, unsigned char **key);
