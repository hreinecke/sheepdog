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

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#endif

uint32_t auth_seqnum;

static const struct auth_dhgroup_map {
	char name[16];
} dhgroup_map[] = {
	[NVME_AUTH_DHGROUP_NULL] = { .name = "null" },
	[NVME_AUTH_DHGROUP_2048] = { .name = "ffdhe2048" },
	[NVME_AUTH_DHGROUP_3072] = { .name = "ffdhe3072" },
	[NVME_AUTH_DHGROUP_4096] = { .name = "ffdhe4096" },
	[NVME_AUTH_DHGROUP_6144] = { .name = "ffdhe6144" },
	[NVME_AUTH_DHGROUP_8192] = { .name = "ffdhe8192" },
};

static const char *auth_dhgroup_name(uint8_t dhgroup_id)
{
	if (dhgroup_id >= ARRAY_SIZE(dhgroup_map))
		return NULL;
	return dhgroup_map[dhgroup_id].name;
}

/*
 * Byte length of the DH modulus (and thus of the public value g^x mod p)
 * for a given NVMe DH group, i.e. NVME_AUTH_DHGROUP_2048 -> 2048 bits.
 */
static size_t nvme_dhchap_dh_len(uint8_t dhgroup_id)
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

static uint8_t setup_auth(struct nofuse_queue *ep, struct ep_qe *qe, bool reset)
{
	int ret = 0;
	struct nofuse_ctrl *ctrl = ep->ctrl;

	if (!ctrl->host_inode) {
		ctrl_info(ep, "host %s not configured", ctrl->hostnqn);
		return NVME_AUTH_DHCHAP_FAILURE_FAILED;
	}

	if (!reset && ep->tls_started) {
		ctrl_info(ep, "host %s tls enabled\n", ctrl->hostnqn);
		return NVME_AUTH_DHCHAP_FAILURE_FAILED;
	}

	return ret;
}

static void reset_auth(struct nofuse_queue_auth *auth)
{
}


static int auth_ctrl_sesskey(struct nofuse_queue *ep,
			     const uint8_t *pkey, int pkey_size)
{
	struct nofuse_queue_auth *auth = &ep->auth;
	int ret;

	auth->dhchap_skey_len = nvme_dhchap_hash_len(auth->shash_id);
	auth->dhchap_skey = xzalloc(auth->dhchap_skey_len);
	if (!auth->dhchap_skey)
		return -ENOMEM;
	ret = auth_gen_session_key(auth, pkey, pkey_size,
				   auth->dhchap_skey,
				   auth->dhchap_skey_len);
	if (ret)
		ctrl_info(ep, "failed to compute session key, err %d", ret);
	return ret;
}

static uint8_t auth_negotiate(struct nofuse_queue *ep, struct ep_qe *qe,
			      void *d, uint32_t tl)
{
	struct nofuse_queue_auth *auth = &qe->ep->auth;
	struct nvmf_auth_dhchap_negotiate_data *data = d;
	int i, hmac_id = -1, dhgid = -1;
	bool null_dhgid = false;

	if (tl < sizeof(*data) +
	    sizeof(struct nvmf_auth_dhchap_protocol_descriptor))
		return NVME_AUTH_DHCHAP_FAILURE_INCORRECT_PAYLOAD;

	ctrl_info(ep, "data sc_d %d napd %d authid %d halen %d dhlen %d",
		   data->sc_c, data->napd,
		   data->auth_protocol[0].dhchap.authid,
		   data->auth_protocol[0].dhchap.halen,
		   data->auth_protocol[0].dhchap.dhlen);
	auth->dhchap_tid = le16toh(data->t_id);
	auth->sc_c = data->sc_c;
	if (data->sc_c != NVME_AUTH_SECP_NOSC) {
		/* No secure concatenaion for now */
		return NVME_AUTH_DHCHAP_FAILURE_CONCAT_MISMATCH;
	}

	if (data->napd != 1)
		return NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;

	if (data->auth_protocol[0].dhchap.authid !=
	    NVME_AUTH_DHCHAP_AUTH_ID)
		return NVME_AUTH_DHCHAP_FAILURE_INCORRECT_PAYLOAD;

	for (i = 0; i < data->auth_protocol[0].dhchap.halen; i++) {
		uint8_t tmp_hmac_id = data->auth_protocol[0].dhchap.idlist[i];

		if (auth_hmac_supported(tmp_hmac_id)) {
			hmac_id = tmp_hmac_id;
			break;
		}
	}
	if (hmac_id < 0) {
		ctrl_info(ep, "No usable HMAC found");
		return NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;
	}
	auth->shash_id = hmac_id;
	
	for (i = 0; i < data->auth_protocol[0].dhchap.dhlen; i++) {
		int tmp_dhgid = data->auth_protocol[0].dhchap.idlist[i + 30];

		if (tmp_dhgid == NVME_AUTH_DHGROUP_NULL)
			null_dhgid = true;
		else if (auth_dhgroup_name(tmp_dhgid)) {
			dhgid = tmp_dhgid;
			break;
		}
	}
	if (dhgid < 0) {
		if (null_dhgid) {
			auth->dh_gid = NVME_AUTH_DHGROUP_NULL;
			return 0;
		}
		ctrl_info(ep, "no usable DH group found");
		return NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
	}

	if (setup_dhgroup(ep, dhgid) < 0) {
		ctrl_info(ep, "Failed to setup DH group");
		return NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
	}
	ctrl_info(ep, "selected DH group %s (%d)",
		  auth_dhgroup_name(auth->dh_gid), auth->dh_gid);
	return 0;
}

static uint8_t nvme_auth_reply(struct ep_qe *qe, void *d, uint32_t tl)
{
	struct nofuse_queue_auth *auth = &qe->ep->auth;
	struct nvmf_auth_dhchap_reply_data *data = d;
	uint16_t dhvlen;
	uint8_t *response;

	if (tl < sizeof(*data))
		return NVME_AUTH_DHCHAP_FAILURE_INCORRECT_PAYLOAD;

	dhvlen = le16toh(data->dhvlen);

	/* Validate that hl and dhvlen fit within the transfer length */
	if (sizeof(*data) + 2 * (size_t)data->hl + dhvlen > tl)
		return NVME_AUTH_DHCHAP_FAILURE_INCORRECT_PAYLOAD;

	ctrl_info(qe->ep, "data hl %d cvalid %d dhvlen %u",
		  data->hl, data->cvalid, dhvlen);

	if (dhvlen) {
		if (auth_ctrl_sesskey(qe->ep, data->rval + 2 * data->hl,
				      dhvlen) < 0)
			return NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
	}

	response = xmalloc(data->hl);
	if (!response)
		return NVME_AUTH_DHCHAP_FAILURE_FAILED;

	if (!qe->ep->ctrl->host_key) {
		ctrl_err(qe->ep, "no host key");
		free(response);
		return NVME_AUTH_DHCHAP_FAILURE_FAILED;
	}
	if (auth_host_hash(qe->ep, response, data->hl) < 0) {
		ctrl_info(qe->ep, "host hash failed");
		free(response);
		return NVME_AUTH_DHCHAP_FAILURE_FAILED;
	}

	if (memcmp(data->rval, response, data->hl)) {
		ctrl_info(qe->ep, "host response mismatch");
#if 0
		ctrl_info(qe->ep, "rval %*ph\n",
			  data->hl, data->rval);
		ctrl_info(qe->ep, "response %*ph\n",
			  data->hl, response);
#endif
		free(response);
		return NVME_AUTH_DHCHAP_FAILURE_FAILED;
	}
	free(response);
	ctrl_info(qe->ep, "host authenticated");
	auth->dhchap_s2 = le32toh(data->seqnum);
	if (data->cvalid) {
		auth->dhchap_c2 = xmalloc(data->hl);
		if (!auth->dhchap_c2)
			return NVME_AUTH_DHCHAP_FAILURE_FAILED;
		memcpy(auth->dhchap_c2, data->rval + data->hl, data->hl);
		ctrl_info(qe->ep, "challenge %*ph\n",
			  data->hl, auth->dhchap_c2);
	}
	/*
	 * NVMe Base Spec 2.2 section 8.3.4.5.4: DH-HMAC-CHAP_Reply message
	 * Sequence Number (SEQNUM): [ .. ]
	 * The value 0h is used to indicate that bidirectional authentication
	 * is not performed, but a challenge value C2 is carried in order to
	 * generate a pre-shared key (PSK) for subsequent establishment of a
	 * secure channel.
	 */
	if (auth->dhchap_s2 == 0) {
		qe->ep->authenticated = true;
		free(auth->dhchap_c2);
		auth->dhchap_c2 = NULL;
	} else if (!data->cvalid)
		qe->ep->authenticated = true;

	return 0;
}

static uint8_t auth_failure2(void *d)
{
	struct nvmf_auth_dhchap_failure_data *data = d;

	return data->rescode_exp;
}

static uint32_t auth_send_data_len(struct nvme_command *cmd)
{
	return le32toh(cmd->auth_send.tl);
}

int handle_auth_send(struct nofuse_queue *ep, struct ep_qe *qe,
		     struct nvme_command *cmd)
{
	uint8_t sgl_type = cmd->auth_send.dptr.sgl.type;
	uint32_t tl;
	int ret;

	if (cmd->auth_send.secp != NVME_AUTH_DHCHAP_PROTOCOL_IDENTIFIER)
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;

	if (cmd->auth_send.spsp0 != 0x01)
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;
	if (cmd->auth_send.spsp1 != 0x01)
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;

	tl = auth_send_data_len(cmd);
	if (!tl)
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;
	if (qe->data_len != tl) {
		ctrl_info(ep, "transfer length mismatch (%u)",tl);
		if (cmd->common.flags & NVME_CMD_SGL_ALL)
			return NVME_SC_SGL_INVALID_DATA;
		else
			return NVME_SC_INVALID_FIELD;
	}

	qe->opcode = nvme_fabrics_command;
	qe->fctype = nvme_fabrics_type_auth_send;
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = qe->data_len;
	qe->data_remaining = qe->data_len;

	if (sgl_type == NVME_SGL_FMT_OFFSET) {
		/* Inline data */
		ret = ep->ops->rma_read(ep, qe->iovec.iov_base,
					qe->iovec.iov_len);
		if (ret < 0) {
			ctrl_err(ep, "auth_send: tag %#x rma_read error %d",
				 qe->tag, ret);
			return ret;
		}
		return handle_auth_send_data(ep, qe);
	}
	if ((sgl_type & 0x0f) != NVME_SGL_FMT_TRANSPORT_A) {
		ctrl_err(ep, "dsm: invalid sgl type %x", sgl_type);
		return NVME_SC_SGL_INVALID_TYPE;
	}

	ret = qe->ns->ops->ns_prep_read(ep, qe);
	if (ret)
		ctrl_err(ep, "auth_send: prep_rma_read failed with error %d", ret);

	return ret;
}

int handle_auth_send_data(struct nofuse_queue *ep, struct ep_qe *qe)
{
	struct nofuse_queue_auth *auth = &ep->auth;
	struct nvmf_auth_dhchap_success2_data *data = qe->data;
	unsigned int dhchap_status;
	int ret = 0;

	ctrl_info(ep, "type %d id %d step %x",
		  data->auth_type, data->auth_id,
		  auth->dhchap_step);
	if (data->auth_type != NVME_AUTH_COMMON_MESSAGES &&
	    data->auth_type != NVME_AUTH_DHCHAP_MESSAGES)
		goto done_failure1;
	if (data->auth_type == NVME_AUTH_COMMON_MESSAGES) {
		if (data->auth_id == NVME_AUTH_DHCHAP_MESSAGE_NEGOTIATE) {
			/* Restart negotiation */
			ctrl_info(ep, "reset negotiation");
			if (!ep->qid) {
				dhchap_status = setup_auth(ep, qe, true);
				if (dhchap_status) {
					ctrl_info(ep, "failed to setup re-authentication");
					auth->dhchap_status = dhchap_status;
					auth->dhchap_step =
						NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
					goto done;
				}
			}
			auth->dhchap_step =
				NVME_AUTH_DHCHAP_MESSAGE_NEGOTIATE;
		} else if (data->auth_id != auth->dhchap_step)
			goto done_failure1;
		/* Validate negotiation parameters */
		dhchap_status = auth_negotiate(ep, qe, data, qe->data_len);
		if (dhchap_status == 0)
			auth->dhchap_step =
				NVME_AUTH_DHCHAP_MESSAGE_CHALLENGE;
		else {
			auth->dhchap_step =
				NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
			auth->dhchap_status = dhchap_status;
		}
		goto done;
	}
	if (data->auth_id != auth->dhchap_step) {
		ctrl_info(ep, "step mismatch (%d != %d)",
			  data->auth_id, auth->dhchap_step);
		goto done_failure1;
	}
	if (le16toh(data->t_id) != auth->dhchap_tid) {
		ctrl_info(ep, "invalid transaction %d (expected %d)",
			  le16toh(data->t_id), auth->dhchap_tid);
		auth->dhchap_step =
			NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
		auth->dhchap_status =
			NVME_AUTH_DHCHAP_FAILURE_INCORRECT_PAYLOAD;
		goto done;
	}

	switch (data->auth_id) {
	case NVME_AUTH_DHCHAP_MESSAGE_REPLY:
		dhchap_status = nvme_auth_reply(qe, qe->data, qe->data_len);
		if (dhchap_status == 0)
			auth->dhchap_step =
				NVME_AUTH_DHCHAP_MESSAGE_SUCCESS1;
		else {
			auth->dhchap_step =
				NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
			auth->dhchap_status = dhchap_status;
		}
		goto done;
	case NVME_AUTH_DHCHAP_MESSAGE_SUCCESS2:
		ep->authenticated = true;
		ctrl_info(ep, "ctrl authenticated");
		goto done;
	case NVME_AUTH_DHCHAP_MESSAGE_FAILURE2:
		dhchap_status = auth_failure2(qe->data);
		if (dhchap_status) {
			ctrl_err(ep, "authentication failed (%d)",
				 dhchap_status);
			auth->dhchap_status = dhchap_status;
			ep->authenticated = false;
		}
		goto done;
	default:
		auth->dhchap_status =
			NVME_AUTH_DHCHAP_FAILURE_INCORRECT_MESSAGE;
		auth->dhchap_step =
			NVME_AUTH_DHCHAP_MESSAGE_FAILURE2;
		ep->authenticated = false;
		goto done;
	}
done_failure1:
	auth->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_INCORRECT_MESSAGE;
	auth->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE2;

done:
	ctrl_info(ep, "dhchap status %x step %x",
		  auth->dhchap_status, auth->dhchap_step);
	if (auth->dhchap_step != NVME_AUTH_DHCHAP_MESSAGE_SUCCESS2 &&
	    auth->dhchap_step != NVME_AUTH_DHCHAP_MESSAGE_FAILURE2) {
		ret = NVME_SC_SUCCESS;
		goto complete;
	}
	/* Final states, clear up variables */
	reset_auth(auth);
	if (auth->dhchap_step == NVME_AUTH_DHCHAP_MESSAGE_FAILURE2)
		ret = NVME_SC_SUCCESS;

complete:
	return ret;
}

static int auth_challenge(struct nofuse_queue *ep, struct ep_qe *qe)
{
	struct nofuse_queue_auth *auth = &ep->auth;
	struct nvmf_auth_dhchap_challenge_data *data = qe->data;
	size_t hash_len = nvme_dhchap_hash_len(auth->shash_id);
	size_t dh_keysize = nvme_dhchap_dh_len(auth->dh_gid);
	int data_size = sizeof(*data) + hash_len;

	if (dh_keysize)
		data_size += dh_keysize;
	if (qe->data_len < data_size) {
		ctrl_info(ep, "buffer too small (al %"PRIu64" need %d)",
			  qe->data_len, data_size);
		return NVME_AUTH_DHCHAP_FAILURE_FAILED;
	}
	qe->data_remaining = data_size;
	memset(data, 0, data_size);
	auth->dhchap_s1 = uatomic_add_return(&auth_seqnum, 1);
	data->auth_type = NVME_AUTH_DHCHAP_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_CHALLENGE;
	data->t_id = htole16(auth->dhchap_tid);
	data->hashid = auth->shash_id;
	data->hl = hash_len;
	data->seqnum = htole32(auth->dhchap_s1);
	auth->dhchap_c1 = xmalloc(data->hl);
	if (!auth->dhchap_c1)
		return NVME_AUTH_DHCHAP_FAILURE_FAILED;
	get_random_bytes(auth->dhchap_c1, data->hl);
	memcpy(data->cval, auth->dhchap_c1, data->hl);
	if (auth->dh_gid) {
		int ret;

		data->dhgid = auth->dh_gid;
		data->dhvlen = htole16(dh_keysize);
		ret = auth_ctrl_exponential(auth, data->cval + data->hl,
					    dh_keysize);
		if (ret < 0) {
			ctrl_err(ep, "seq %d transaction %d "
				 "ctrl exponential failed with %d",
				 auth->dhchap_s1, auth->dhchap_tid, ret);
			return NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;
		}

	}
	ctrl_info(ep, "seq %d transaction %d hl %d dhvlen %zu\n",
		  auth->dhchap_s1, auth->dhchap_tid,
		  data->hl, dh_keysize);
	return 0;
}

static int auth_success1(struct ep_qe *qe, void *d, int al)
{
	struct nvmf_auth_dhchap_success1_data *data = d;
	int hash_len = nvme_dhchap_hash_len(qe->ep->auth.shash_id);

	if (al < sizeof(*data))
		return NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;
	memset(data, 0, sizeof(*data));
	data->auth_type = NVME_AUTH_DHCHAP_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_SUCCESS1;
	data->t_id = htole16(qe->ep->auth.dhchap_tid);
	data->hl = hash_len;
	if (qe->ep->auth.dhchap_c2) {
		if (!qe->ep->ctrl->ctrl_key) {
			ctrl_err(qe->ep, "no ctrl key");
			return NVME_AUTH_DHCHAP_FAILURE_FAILED;
		}
		if (auth_ctrl_hash(qe->ep, data->rval, data->hl))
			return NVME_AUTH_DHCHAP_FAILURE_HASH_UNUSABLE;
		data->rvalid = 1;
		ctrl_info(qe->ep, "response %*ph\n",
			  data->hl, data->rval);
	}
	return 0;
}

static void auth_failure1(struct ep_qe *qe, void *d, int al)
{
	struct nvmf_auth_dhchap_failure_data *data = d;

	sd_assert(al >= sizeof(*data));
	data->auth_type = NVME_AUTH_COMMON_MESSAGES;
	data->auth_id = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
	data->t_id = htole16(qe->ep->auth.dhchap_tid);
	data->rescode = NVME_AUTH_DHCHAP_FAILURE_REASON_FAILED;
	data->rescode_exp = qe->ep->auth.dhchap_status;
}

static uint32_t auth_receive_data_len(struct nofuse_queue_auth *auth,
				      struct nvme_command *cmd)
{
	uint32_t al = le32toh(cmd->auth_receive.al);
	uint32_t min_len;

	/*
	 * Reject too-short al before kmalloc(al), since the SUCCESS1 and
	 * FAILURE1/default builders write fixed response headers into it.
	 */
	switch (auth->dhchap_step) {
	case NVME_AUTH_DHCHAP_MESSAGE_CHALLENGE:
		return al;
	case NVME_AUTH_DHCHAP_MESSAGE_SUCCESS1:
		min_len = sizeof(struct nvmf_auth_dhchap_success1_data);
		if (auth->dhchap_c2)
			min_len += nvme_dhchap_hash_len(auth->shash_id);
		break;
	default:
		min_len = sizeof(struct nvmf_auth_dhchap_failure_data);
		break;
	}

	if (al < min_len)
		return 0;

	return al;
}

int handle_auth_receive(struct nofuse_queue *ep, struct ep_qe *qe,
			struct nvme_command *cmd)
{
	struct nofuse_queue_auth *auth = &ep->auth;
	uint32_t al;
	uint16_t status, ret = NVME_SC_SUCCESS;

	if (cmd->auth_receive.secp != NVME_AUTH_DHCHAP_PROTOCOL_IDENTIFIER)
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;
	if (cmd->auth_receive.spsp0 != 0x01)
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;
	if (cmd->auth_receive.spsp1 != 0x01)
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;
	al = auth_receive_data_len(auth, cmd);
	if (!al)
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;
	if (qe->data_len != al) {
		ctrl_info(ep, "transfer length mismatch (%u)\n", al);
		return NVME_SC_INVALID_FIELD | NVME_SC_DNR;
	}

	qe->opcode = nvme_fabrics_command;
	qe->fctype = nvme_fabrics_type_auth_receive;

	ctrl_info(qe->ep, "step %x", auth->dhchap_step);
	switch (auth->dhchap_step) {
	case NVME_AUTH_DHCHAP_MESSAGE_CHALLENGE:
		status = auth_challenge(qe->ep, qe);
		if (status) {
			auth->dhchap_status = status;
			ep->authenticated = false;
			auth_failure1(qe, qe->data, al);
			ctrl_err(qe->ep, "challenge status (%x)",
				auth->dhchap_status);
			break;
		}
		auth->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_REPLY;
		break;
	case NVME_AUTH_DHCHAP_MESSAGE_SUCCESS1:
		status = auth_success1(qe, qe->data, al);
		if (status) {
			auth->dhchap_status = status;
			ep->authenticated = false;
			auth_failure1(qe, qe->data, al);
			ctrl_err(qe->ep, "success1 status (%x)",
				auth->dhchap_status);
			break;
		}
		auth->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_SUCCESS2;
		break;
	case NVME_AUTH_DHCHAP_MESSAGE_FAILURE1:
		ep->authenticated = false;
		auth_failure1(qe, qe->data, al);
		ctrl_err(qe->ep, "failure1 (%x)", auth->dhchap_status);
		break;
	default:
		ctrl_err(qe->ep, "unhandled step (%d)",
			 auth->dhchap_step);
		auth->dhchap_step = NVME_AUTH_DHCHAP_MESSAGE_FAILURE1;
		auth->dhchap_status = NVME_AUTH_DHCHAP_FAILURE_FAILED;
		auth_failure1(qe, qe->data, al);
		break;
	}

	ret = ep->ops->rma_write(ep, qe, qe->data_len);
	if (ret)
		ctrl_err(ep, "rma_write failed with %d", ret);
	return ret;
}
