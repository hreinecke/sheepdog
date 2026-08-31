/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * nofuse.c
 * NVME-over-TCP userspace daemon
 *
 * Copyright (c) 2024 Hannes Reinecke <hare@suse.de>. All rights reserved.
 *
 * Based on nvme-dem (https://github.com/linux-nvme/nvme-dem/src/endpoint)
 * Copyright (c) 2017-2019 Intel Corporation, Inc. All rights reserved.
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <getopt.h>

#include "nvmet.h"
#include "ops.h"
#include "tls.h"

LINKED_LIST(device_linked_list);

int stopped;
bool tcp_debug;
bool cmd_debug;
bool ep_debug;
bool port_debug;

struct nofuse_context {
	const char *subsysnqn;
	const char *traddr;
	const char *dbname;
	int debug;
	int help;
};

char discovery_nqn[MAX_NQN_SIZE + 1] = {};

static void free_ports(void)
{
	struct nofuse_port *port, *_port;

	list_for_each_entry_safe(port, _port, &port_linked_list, node)
		del_port(port);
}

int init_nvmet(const char *traddr, int trsvcid)
{
	int tls_keyring;
	int ret = 1;
	struct nofuse_context *ctx;
	struct nofuse_port *port;

	ctx = malloc(sizeof(struct nofuse_context));
	if (!ctx)
		return 1;
	memset(ctx, 0, sizeof(struct nofuse_context));
	ctx->traddr = strdup(traddr);
	port = add_port(1, ctx->traddr, trsvcid);
	if (ret < 0) {
		fprintf(stderr, "failed to add nvmet port");
		return -1;
	}

	tls_keyring = tls_global_init();
	if (tls_keyring)
		port->tls = true;

	stopped = 0;

	start_port(port);

	stopped = 1;

	list_for_each_entry(port, &port_linked_list, node)
		stop_port(port);

	free_ports();

	free(ctx);

	return ret;
}
