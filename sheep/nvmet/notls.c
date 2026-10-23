/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * tls.c
 * TLS support for NVMe-oF userspace emulation.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "sheep.h"
#include "nofuse.h"
#include "tls.h"

int tls_global_init(void)
{
	return 0;
}

int tls_handshake(struct nofuse_queue *ep)
{
	return -EOPNOTSUPP;
}

void tls_free_queue(struct nofuse_queue *ep) { }
