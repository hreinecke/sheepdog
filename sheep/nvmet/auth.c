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

#ifdef HAVE_GNUTLS
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
#endif /* HAVE_GNUTLS */

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

	ret = setup_dhgroup(ep);
	if (ret < 0) {
		ctrl_info(ep, "Failed to setup DH group");
		ret = NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
	}

	return ret;
}

static void reset_auth(struct nofuse_queue_auth *auth)
{
}

#ifdef HAVE_GNUTLS
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
static int auth_gen_session_key(struct nofuse_queue_auth *auth,
		const uint8_t *public_key, size_t public_key_len,
		uint8_t *sess_key, size_t sess_key_len)
{
	gnutls_dh_params_t dh_params;
	gnutls_pubkey_t peer_pubkey;
	gnutls_datum_t peer_y, secret = { NULL, 0 };
	gnutls_digest_algorithm_t dig;
	unsigned char *dh_secret;
	size_t dh_secret_len;
	int ret;

	if (!auth->dh_privkey)
		return -EINVAL;

	ret = auth_hmac_digest_id(auth->shash_id, &dig);
	if (ret < 0)
		return ret;

	if (sess_key_len != (size_t)gnutls_hash_get_len(dig))
		return -EINVAL;

	ret = auth_dhgroup_params(auth->dh_gid, &dh_params);
	if (ret < 0)
		return ret;

	ret = gnutls_pubkey_init(&peer_pubkey);
	if (ret < 0) {
		gnutls_dh_params_deinit(dh_params);
		return -ENOMEM;
	}

	peer_y.data = (unsigned char *)public_key;
	peer_y.size = public_key_len;
	ret = gnutls_pubkey_import_dh_raw(peer_pubkey, dh_params, &peer_y);
	gnutls_dh_params_deinit(dh_params);
	if (ret < 0) {
		gnutls_pubkey_deinit(peer_pubkey);
		return -EINVAL;
	}

	ret = gnutls_privkey_derive_secret(auth->dh_privkey, peer_pubkey,
					   NULL, &secret, 0);
	gnutls_pubkey_deinit(peer_pubkey);
	gnutls_privkey_deinit(auth->dh_privkey);
	auth->dh_privkey = NULL;
	if (ret < 0)
		return -EIO;

	/*
	 * gnutls strips leading zero bytes from the raw DH secret (same
	 * convention as TLS) and may prepend a single sign byte when the
	 * most significant bit of the value is set; re-pad to the modulus
	 * size before hashing, as the peer's implementation will have
	 * done the same.
	 */
	dh_secret_len = nvme_dhchap_dh_len(auth->dh_gid);
	if (secret.size > dh_secret_len) {
		if (secret.size != dh_secret_len + 1 || secret.data[0] != 0) {
			gnutls_free(secret.data);
			return -EINVAL;
		}
		memmove(secret.data, secret.data + 1, dh_secret_len);
		secret.size = dh_secret_len;
	}
	dh_secret = xzalloc(dh_secret_len);
	if (!dh_secret) {
		gnutls_free(secret.data);
		return -ENOMEM;
	}
	memcpy(dh_secret + (dh_secret_len - secret.size), secret.data,
	       secret.size);
	gnutls_free(secret.data);

	ret = gnutls_hash_fast(dig, dh_secret, dh_secret_len, sess_key);
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
static int auth_ctrl_exponential(struct nofuse_queue_auth *auth,
				 uint8_t *cval, size_t dh_keysize)
{
	gnutls_dh_params_t dh_params;
	gnutls_keygen_data_st kdata;
	gnutls_privkey_t privkey;
	gnutls_datum_t y = { NULL, 0 };
	int ret;

	ret = auth_dhgroup_params(auth->dh_gid, &dh_params);
	if (ret < 0)
		return ret;

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0) {
		gnutls_dh_params_deinit(dh_params);
		return -ENOMEM;
	}

	kdata.type = GNUTLS_KEYGEN_DH;
	kdata.data = (unsigned char *)dh_params;
	kdata.size = 0;

	ret = gnutls_privkey_generate2(privkey, GNUTLS_PK_DH, 0, 0, &kdata, 1);
	gnutls_dh_params_deinit(dh_params);
	if (ret < 0) {
		gnutls_privkey_deinit(privkey);
		return -EIO;
	}

	ret = gnutls_privkey_export_dh_raw(privkey, NULL, &y, NULL, 0);
	if (ret < 0) {
		gnutls_privkey_deinit(privkey);
		return -EIO;
	}
	/*
	 * gnutls may prepend a single sign byte to the exported public
	 * value when its most significant bit is set; strip it, since the
	 * wire format is a fixed-width unsigned big-endian integer.
	 */
	if (y.size == dh_keysize + 1 && y.data[0] == 0) {
		memmove(y.data, y.data + 1, dh_keysize);
		y.size = dh_keysize;
	} else if (y.size > dh_keysize) {
		gnutls_free(y.data);
		gnutls_privkey_deinit(privkey);
		return -EINVAL;
	}

	memset(cval, 0, dh_keysize);
	memcpy(cval + (dh_keysize - y.size), y.data, y.size);
	gnutls_free(y.data);

	if (auth->dh_privkey)
		gnutls_privkey_deinit(auth->dh_privkey);
	auth->dh_privkey = privkey;

	return 0;
}
#else /* !HAVE_GNUTLS */
static int nvme_auth_gen_session_key(struct nofuse_queue_auth *auth,
		const uint8_t *public_key, size_t public_key_len,
		uint8_t *sess_key, size_t sess_key_len)
{
	return -EOPNOTSUPP;
}

static int auth_ctrl_exponential(struct nofuse_queue_auth *auth,
				 uint8_t *cval, size_t dh_keysize)
{
	return -EOPNOTSUPP;
}
#endif /* HAVE_GNUTLS */

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

	if (tl < sizeof(*data) +
	    sizeof(struct nvmf_auth_dhchap_protocol_descriptor))
		return NVME_AUTH_DHCHAP_FAILURE_INCORRECT_PAYLOAD;

	ctrl_info(ep, "data sc_d %d napd %d authid %d halen %d dhlen %d\n",
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
		int bits = auth_dhgroup_bits(tmp_dhgid);

		if (bits > 0) {
			dhgid = tmp_dhgid;
			break;
		}
	}
	if (dhgid < 0) {
		ctrl_info(ep, "no usable DH group found");
		return NVME_AUTH_DHCHAP_FAILURE_DHGROUP_UNUSABLE;
	}
	auth->dh_gid = dhgid;
	ctrl_info(ep, "selected DH group %s (%d)\n",
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

	ctrl_info(qe->ep, "data hl %d cvalid %d dhvlen %u\n",
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

	ctrl_info(ep, "type %d id %d step %x\n",
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
		ctrl_info(ep, "step mismatch (%d != %d)\n",
			  data->auth_id, auth->dhchap_step);
		goto done_failure1;
	}
	if (le16toh(data->t_id) != auth->dhchap_tid) {
		ctrl_info(ep, "invalid transaction %d (expected %d)\n",
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
		ret = -ETIME;
		goto complete;
	}
	/* Final states, clear up variables */
	reset_auth(auth);
	if (auth->dhchap_step == NVME_AUTH_DHCHAP_MESSAGE_FAILURE2)
		ret = -ENODATA;

complete:
	return ret;
}

static int auth_challenge(struct nofuse_queue *ep, struct ep_qe *qe,
			  void *d, int al)
{
	struct nofuse_queue_auth *auth = &ep->auth;
	struct nvmf_auth_dhchap_challenge_data *data = d;
	int ret = 0;
	size_t hash_len = nvme_dhchap_hash_len(auth->shash_id);
	size_t dh_keysize = nvme_dhchap_dh_len(auth->dh_gid);
	int data_size = sizeof(*data) + hash_len;

	if (dh_keysize)
		data_size += dh_keysize;
	if (al < data_size) {
		ctrl_info(ep, "buffer too small (al %d need %d)",
			 al, data_size);
		return -EINVAL;
	}
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
		return -ENOMEM;
	get_random_bytes(auth->dhchap_c1, data->hl);
	memcpy(data->cval, auth->dhchap_c1, data->hl);
	if (auth->dh_gid) {
		data->dhgid = auth->dh_gid;
		data->dhvlen = htole16(dh_keysize);
		ret = auth_ctrl_exponential(auth, data->cval + data->hl,
					    dh_keysize);
	}
	ctrl_info(ep, "seq %d transaction %d hl %d dhvlen %zu\n",
		  auth->dhchap_s1, auth->dhchap_tid,
		  data->hl, dh_keysize);
	return ret;
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
		if (!qe->ep->ctrl_key) {
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
	uint16_t status = 0;

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
	qe->iovec.iov_base = qe->data;
	qe->iovec.iov_len = qe->data_len;
	qe->data_remaining = qe->data_len;

	ctrl_info(qe->ep, "step %x", auth->dhchap_step);
	switch (auth->dhchap_step) {
	case NVME_AUTH_DHCHAP_MESSAGE_CHALLENGE:
		if (auth_challenge(qe->ep, qe, qe->data, al) < 0) {
			ctrl_err(qe->ep, "challenge error (%d)\n",
				 status);
			status = NVME_SC_INTERNAL;
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
		status = 0;
		break;
	}

	if (auth->dhchap_step == NVME_AUTH_DHCHAP_MESSAGE_FAILURE1)
		status = -ENODATA;

	return status;
}
