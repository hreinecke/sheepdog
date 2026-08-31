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

#include "sheep_priv.h"
#include "nvmet.h"
#include "ops.h"
#include "tls.h"
#include "configdb.h"

LIST_HEAD(device_linked_list);

int stopped;
bool tcp_debug;
bool cmd_debug;
bool ep_debug;
bool port_debug;

char discovery_nqn[MAX_NQN_SIZE + 1] = {};

struct nofuse_namespace *find_namespace(const char *subsysnqn, uint32_t nsid)
{
	struct nofuse_namespace *ns;

	list_for_each_entry(ns, &device_linked_list, node) {
		if (!strcmp(ns->subsysnqn, subsysnqn) &&
		    ns->nsid == nsid)
			return ns;
	}
	return NULL;
}

static void free_ports(void)
{
	struct nofuse_port *port, *_port;

	list_for_each_entry_safe(port, _port, &port_linked_list, node)
		del_port(port);
}

#define FOR_EACH_VDI(nr, vdis) FOR_EACH_BIT(nr, vdis, SD_NR_VDIS)

static int register_subsystems(void)
{
	int ret;
	unsigned long nr;
	struct sd_inode *i = xmalloc(sizeof(*i));
	struct sd_req req;
	struct sd_rsp *rsp = (struct sd_rsp *)&req;
	static DECLARE_BITMAP(vdi_inuse, SD_NR_VDIS);
	static DECLARE_BITMAP(vdi_deleted, SD_NR_VDIS);

	sd_init_req(&req, SD_OP_READ_VDIS);
	req.data_length = sizeof(vdi_inuse);
	ret = sheep_exec_req(&sys->this_node.nid, &req, vdi_inuse);
	if (ret < 0)
		goto out;
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		goto out;
	}

	sd_init_req(&req, SD_OP_READ_DEL_VDIS);
	req.data_length = sizeof(vdi_deleted);

	ret = sheep_exec_req(&sys->this_node.nid, &req, vdi_deleted);
	if (ret < 0)
		goto out;
	if (rsp->result != SD_RES_SUCCESS) {
		sd_err("%s", sd_strerror(rsp->result));
		goto out;
	}

	FOR_EACH_VDI(nr, vdi_inuse) {
		uint64_t oid;

		if (test_bit(nr, vdi_deleted))
			continue;

		oid = vid_to_vdi_oid(nr);

		ret = sd_read_object(oid, (char *)i,
				     SD_INODE_HEADER_SIZE, 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("Failed to read inode header");
			continue;
		}

		/* this VDI has been deleted, and no need to handle it */
		if (i->header.name[0] == '\0')
			continue;
		/* We are only interested in ACL VDIs */
		if (!vdi_is_acl(&i->header))
			continue;

		ret = configdb_add_subsys(i->header.name, NVME_NQN_NVM);
		if (ret < 0)
			sd_warn("Failed add subsyste '%s'", i->header.name);
		else
			sd_debug("registered subsystem '%s'", i->header.name);
	}
out:
	free(i);
	return ret;
}

int nofuse_init(const char *traddr, int trsvcid)
{
	int tls_keyring;
	int ret = 1;
	struct nofuse_port *port;
	const char *dbname = "nofuse.sqlite";

	ret = configdb_open(dbname);
	if (ret < 0) {
		sd_err("Failed to open configdb");
		return -1;
	}
	ret = configdb_add_subsys(NVME_DISC_SUBSYS_NAME, NVME_NQN_CUR);
	if (ret < 0) {
		sd_err("failed to create default discovery subsystem");
		goto out_close;
	}

	ret = register_subsystems();
	if (ret < 0) {
		sd_err("failed to register ACL VDIs");
		goto out_close;
	}

	sd_debug("register nvmet port traddr '%s' trsvcid '%d',
		 traddr, trsvcid);
	port = add_port(1, traddr, trsvcid);
	if (ret < 0) {
		fprintf(stderr, "failed to add nvmet port");
		goto out_close;
	}

	tls_keyring = tls_global_init();
	if (tls_keyring)
		port->tls = true;

	stopped = 0;

	start_port(port);

	stopped = 1;

	stop_port(port);

	free_ports();
out_close:
	configdb_close(dbname);

	return ret;
}
