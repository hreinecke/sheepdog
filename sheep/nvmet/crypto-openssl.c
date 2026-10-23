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

#include <openssl/rand.h>

#include "sheep.h"
#include "nofuse.h"
#include "ops.h"
#include "nvme.h"
#include "tcp.h"
#include "crypto.h"

void get_random_bytes(uint8_t *bytes, uint32_t len)
{
	int ret = RAND_bytes(bytes, len);
	sd_assert(ret == 0);
}

int setup_dhgroup(struct nofuse_queue *ep, uint8_t dh_gid)
{
	return -1;
}

int auth_gen_session_key(struct nofuse_queue_auth *auth,
		const uint8_t *public_key, size_t public_key_len,
		uint8_t *sess_key, size_t sess_key_len)
{
	return -EOPNOTSUPP;
}

int auth_host_hash(struct nofuse_queue *ep, uint8_t *response,
		   unsigned int shash_len)
{
	return -EOPNOTSUPP;
}

int auth_ctrl_hash(struct nofuse_queue *ep, uint8_t *response,
		   unsigned int shash_len)
{
	return -EOPNOTSUPP;
}

int auth_ctrl_exponential(struct nofuse_queue_auth *auth,
			  uint8_t *cval, size_t dh_keysize)
{
	return -EOPNOTSUPP;
}
