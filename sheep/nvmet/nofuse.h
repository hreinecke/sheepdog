/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * nvmet.h
 * Common definitions for NVMe-over-TCP userspace daemon
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>. All rights reserved.
 */
#ifndef __NVMET_H__
#define __NVMET_H__

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>
#include <liburing.h>

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#else
#include <openssl/ssl.h>
#endif

#include "nvme.h"
#include "tcp.h"

extern bool tcp_debug;
extern bool cmd_debug;
extern bool port_debug;
extern bool fuse_debug;

extern struct list_head device_linked_list;
extern struct list_head port_linked_list;

#define NVME_NR_AEN_COMMANDS	4
#define NVMF_AQ_DEPTH		32
#define NVMF_SQ_DEPTH		128
#define NVMF_NUM_QUEUES		8

#define MAX_NQN_SIZE		256
#define MAX_ALIAS_SIZE		64

#define MAX_NSID		256
#define MAX_ANAGRPID		64

#define PAGE_SIZE		4096

#define KATO_INTERVAL	500	/* in ms as per spec */
#define RETRY_COUNT	2400	/* 2 min; multiplied with kato interval */


#define ADRFAM_STR_IPV4 "ipv4"
#define ADRFAM_STR_IPV6 "ipv6"
#define ADRFAM_STR_FC "fc"
#define ADRFAM_STR_IB "ib"
#define ADRFAM_STR_PCI "pci"
#define ADRFAM_STR_LOOP "loop"

#define NOFUSE_OUI 0x0efd37
#define NOFUSE_NVME_VER 0x00020400

enum { CONNECTED, STOPPED, DISCONNECTED };

extern int stopped;

struct ep_qe {
	int tag;
	struct nofuse_queue *ep;
	struct nofuse_namespace *ns;
	union nvme_tcp_pdu pdu;
	struct iovec iovec;
	struct nvme_completion resp;
	void *data;
	uint64_t data_len;
	uint64_t data_pos;
	uint64_t data_remaining;
	uint64_t iovec_offset;

	/*
	 * Backing store for the inode-index write in
	 * uring_create_object_complete() (uring.c). sd_write_object_async()
	 * doesn't copy its data argument -- it just stores the pointer for
	 * the actual write to read later, asynchronously, on another
	 * thread. A stack-local variable there would be long gone by then;
	 * qe stays alive for the whole command, so this is.
	 */
	uint32_t inode_vid_buf;
	refcnt_t async_pending;
	int async_result;
	/*
	 * Distinguishes the initial kickoff call into ns_handle_qe() (res
	 * == -EINPROGRESS, nothing submitted yet) from the later completion
	 * call once all of a command's sub-I/Os have finished (also res
	 * == -EINPROGRESS, async_pending back down to 0) -- async_pending
	 * alone can't tell the two apart, since it reads 0 in both cases.
	 */
	bool async_started;
	struct list_node io_node;
	int ccid;
	int opcode;
	bool busy;
	bool aen;
	bool fua;
};

enum { RECV_PDU, RECV_DATA, HANDLE_PDU };

struct nofuse_queue {
	struct list_node node;
	pthread_t pthread;
	struct io_uring uring;
	struct io_ops *io_ops;
	struct xp_ops *ops;
	struct nofuse_port *port;
	struct nofuse_ctrl *ctrl;
	struct ep_qe *qes;
	uint32_t qes_map[NVMF_SQ_DEPTH / 8];
	unsigned int qes_map_index;
	union nvme_tcp_pdu *recv_pdu;
	int recv_pdu_len;
	union nvme_tcp_pdu *send_pdu;
	int recv_state;
	int allocated_qsize;
	int qsize;
	int state;
	int qid;
	int kato_interval;
	int sockfd;
	int maxr2t;
	int maxh2cdata;
	int mdts;
	int io_evtfd;
	struct list_head io_done_list;
	pthread_mutex_t io_done_lock;
	/*
	 * Set once tls_handshake() has been called for this ep, successfully
	 * or not. tcp_accept_connection() detects TLS by peeking the raw
	 * socket bytes for something that isn't a plaintext icreq header --
	 * which, once a handshake has happened, is *always* true (the bytes
	 * are ciphertext), so without this guard a caller that retries
	 * tcp_accept_connection() on -EAGAIN (start_queue()'s retry loop,
	 * when e.g. the rest of the icreq PDU hasn't arrived yet) ends up
	 * calling tls_handshake() a second time on an already-established
	 * session, corrupting it.
	 */
	bool tls_started;
#ifdef HAVE_GNUTLS
	gnutls_session_t session;
	gnutls_psk_server_credentials_t psk_cred;
#else
	SSL_CTX *ctx;
	SSL *ssl;
#endif
};

struct nofuse_subsystem {
	struct rb_node rb;
	struct sd_inode_header *inode;
	struct sd_mutex inode_lock;
	char nqn[MAX_NQN_SIZE];
	uint32_t id;
	enum nvme_subsys_type type;
	unsigned int mnan;
	unsigned int nn;
	bool recycle_vid;
	bool wce;
};

struct nofuse_namespace {
	struct rb_node rb;
	struct ns_ops *ops;
	struct nofuse_subsystem *subsys;
	uint32_t subsys_id;
	uint32_t nsid;
	uint32_t ana_grpid;
	uuid_t uuid;
	size_t size;
	unsigned int blksize;
	bool readonly;
	bool enabled;
	struct sd_inode *inode;
	struct sd_mutex inode_lock;
};

struct nofuse_port {
	struct list_node node;
	pthread_t pthread;
	struct xp_ops *ops;
	struct list_head ep_list;
	pthread_mutex_t ep_mutex;
	int portid;
	int listenfd;
	bool tls;
};

struct nofuse_ctrl {
	struct list_node node;
	pthread_mutex_t ctrl_mutex;
	struct nofuse_subsystem *subsys;
	char hostnqn[MAX_NQN_SIZE + 1];
	struct sd_inode *host_inode;
	struct nofuse_queue *ep[NVMF_NUM_QUEUES + 1];
	const char *dhchap_key;
	const char *host_key;
	const char *ctrl_key;
	unsigned int dhchap_step;
	unsigned int dhchap_status;
	unsigned char *dhchap_c1;
	unsigned char *dhchap_c2;
	unsigned char *dhchap_skey;
	unsigned int dhchap_skey_len;
#ifdef HAVE_GNUTLS
	gnutls_privkey_t dh_privkey;
#endif
	uint32_t dhchap_s1;
	uint32_t dhchap_s2;
	uint16_t dhchap_tid;
	uint8_t dh_gid;
	uint8_t shash_id;
	uint8_t sc_c;
	int cntlid;
	int kato;
	int kato_countdown;
	int num_queues;
	int max_queues;
	uint32_t aen_enabled;
	uint32_t aen_masked;
	uint32_t aen_pending;
	uint64_t csts;
	uint64_t cc;
	bool authenticated;
};

struct nofuse_tls_psk {
	char subsysnqn[MAX_NQN_SIZE];
	uint8_t version[8];
	uint8_t hash[64];
	uint8_t key[64];
};

#define ctrl_info(e, f, x...)					\
	if (cmd_debug) {					\
		if ((e)->ctrl) {				\
			sd_debug("ctrl %d qid %d: " f,		\
			       (e)->ctrl->cntlid,		\
			       (e)->qid, ##x);			\
		} else {					\
			sd_debug("ep %d: " f,			\
			       (e)->sockfd, ##x);		\
		}						\
	}

#define ctrl_err(e, f, x...)					\
	do {							\
		if ((e)->ctrl) {				\
			sd_err("ctrl %d qid %d: " f,		\
				(e)->ctrl->cntlid,		\
				(e)->qid, ##x);			\
		} else {					\
			sd_err("ep %d: " f,			\
			       (e)->sockfd, ##x);		\
		}						\
	} while (0)

#define port_info(i, f, x...)			\
	if (port_debug) {			\
		sd_debug("port %d: " f,		\
			 (i)->portid, ##x);	\
	}

#define port_err(i, f, x...)			\
	sd_err("port %d: " f,			\
	       (i)->portid, ##x)

static inline void set_response(struct nvme_completion *resp,
				uint16_t ccid, uint16_t status, bool dnr)
{
	if (!status)
		dnr = false;
	resp->command_id = ccid;
	resp->status = ((dnr ? NVME_SC_DNR : 0) | status) << 1;
}

static inline void kato_reset_counter(struct nofuse_ctrl *ctrl)
{
	ctrl->kato_countdown = ctrl->kato;
}

static inline uint32_t aen_pending(struct nofuse_ctrl *ctrl)
{
	uint32_t pending;

	pending = ctrl->aen_pending & ~ctrl->aen_masked;
	return pending;
}

void raise_aen(const char *subsysnqn, uint16_t cntlid, int level);

int handle_auth_send(struct nofuse_queue *ep, struct ep_qe *qe,
		     struct nvme_command *cmd);
int handle_auth_receive(struct nofuse_queue *ep, struct ep_qe *qe,
			struct nvme_command *cmd);
int handle_auth_send_data(struct nofuse_queue *ep, struct ep_qe *qe);
int handle_request(struct nofuse_queue *ep, struct nvme_command *cmd);
int handle_data(struct nofuse_queue *ep, struct ep_qe *qe, int res);
int handle_fabrics(struct nofuse_queue *ep, struct ep_qe *qe);
int send_aen(struct nofuse_queue *ep, int type);
int connect_queue(struct nofuse_queue *ep, uint16_t cntlid,
		  const char *hostnqn, const char *subsysnqn);
struct nofuse_queue *create_queue(int conn, struct nofuse_port *port);
void destroy_queue(struct nofuse_queue *ep);
void *queue_thread(void *arg);
void terminate_queues(struct nofuse_port *port, const char *subsysnqn);

int default_subsys_type(const char *nqn);

int add_host(const char *nqn);
int del_host(const char *nqn);

int add_subsys(const char *nqn, int type);
int del_subsys(const char *nqn);

struct nofuse_port *add_port(unsigned int id, const char *traddr,
			     int trsvcid, int tls_keyring);
int del_port(struct nofuse_port *port);
int start_port(struct nofuse_port *port);
int stop_port(struct nofuse_port *port);
int add_ana_group(int portid, int ana_grpid, int ana_state);
int del_ana_group(int portid, int ana_grpid);

struct nofuse_namespace *lookup_namespace(struct nofuse_ctrl *ctrl,
					  uint32_t nsid);
int lookup_vdi_name(const char *vdiname, uint32_t acl, uint32_t *vid);
int ana_log_entries(uint32_t subsys_id, unsigned int portid,
		    uint8_t *log, int log_len);
int identify_active_ns(struct nofuse_subsystem *subsys, uint32_t nsid,
		       char *id, size_t len, bool present);
int add_namespace(const char *subsysnqn, uint32_t nsid);
int del_namespace(const char *subsysnqn, uint32_t nsid);
int enable_namespace(const char *subsysnqn, uint32_t nsid);
int disable_namespace(const char *subsysnqn, uint32_t nsid);

struct nofuse_subsystem *lookup_subsystem_by_id(uint32_t subsys_id);
struct nofuse_subsystem *lookup_subsystem_by_nqn(const char *nqn);

int check_allowed_hosts(const char *hostnqn, const char *subsysnqn,
			struct sd_inode **host_inode);

bool nofuse_node_in_recovery(void);
unsigned int nofuse_genctr(void);

const char *lookup_dhchap_psk(struct sd_inode *inode, const char *subsysnqn,
			      size_t *key_len);

int nofuse_init(const char *traddr, int trsvcid);
void nofuse_exit(void);
#endif
