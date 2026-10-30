/*
 * Copyright (C) 2026 Hannes Reinecke <hare@suse.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SHEEP_RDMA_H__
#define __SHEEP_RDMA_H__

#include "sheep.h"

/*
 * Control message SEND/RECV'd on the dedicated RDMA IO channel that
 * replaces libxio for gateway-forward and peer-RPC traffic (see
 * rdma_client.c/rdma_server.c). 'hdr' carries the usual struct sd_req on
 * the way out and is reinterpreted as struct sd_rsp on the way back, same
 * convention used elsewhere in the code (sd_rsp *rsp = (sd_rsp *)hdr).
 *
 * addr/rkey are only meaningful when hdr.data_length is nonzero: for a
 * write (SD_FLAG_CMD_WRITE), they describe the sender's payload buffer for
 * the receiver to RDMA_READ; for a request whose reply carries data (e.g.
 * READ_OBJ), they describe the sender's destination buffer for the
 * responder to RDMA_WRITE into before acking. Unused on the reply message
 * itself.
 */
struct sd_rdma_ctrl_msg {
	struct sd_req hdr;
	uint64_t addr;
	uint32_t rkey;
	uint32_t pad;
};

/* ---- client side (rdma_client.c) ---- */

int rdma_exec_req(const struct node_id *nid, struct sd_req *hdr, void *data,
		   bool (*need_retry)(uint32_t epoch), uint32_t epoch,
		   uint32_t max_count);

struct rdma_conn;

struct rdma_forward_info_entry {
	const struct node_id *nid;
	struct rdma_conn *conn;	/* NULL once this entry's reply has been
				 * collected by rdma_gw_wait() */
};

struct rdma_forward_info {
	struct rdma_forward_info_entry ent[SD_MAX_NODES];
	int nr_send, nr_done;
};

/*
 * Get (or create) a pooled connection to nid for fi_entry, and post hdr/data
 * as a request on it. Returns SD_RES_SUCCESS on successful post (not
 * completion); the reply is collected later by rdma_gw_wait().
 */
int rdma_gw_send_req(struct rdma_forward_info_entry *fi_entry,
		      struct sd_req *hdr, void *data);

/*
 * Block until every entry posted via rdma_gw_send_req() for this fi has
 * either received its reply or failed. Returns the first non-success
 * result seen, SD_RES_SUCCESS if all replicas succeeded.
 */
int rdma_gw_wait(struct rdma_forward_info *fi);

/* ---- server side (rdma_server.c) ---- */

struct client_info;

int rdma_create_listen_port(const char *bindaddr, int port);
void rdma_send_reply(struct client_info *ci);
void rdma_destroy_connection(struct client_info *ci);

/* Per in-flight request bookkeeping; see struct request::rdma_ctx. */
struct rdma_req_ctx {
	uint64_t addr;
	uint32_t rkey;
};

#endif	/* __SHEEP_RDMA_H__ */
