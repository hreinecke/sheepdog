/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * gnutls.c
 * NVMe-over-fabrics TCP transport GNUTLS support.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <gnutls/gnutls.h>
#include <zlib.h>
#include <keyutils.h>

#include "sheep.h"
#include "nofuse.h"
#include "tls.h"
#include "ops.h"

static int gnutls_ep_write(struct nofuse_queue *ep, void *buf, size_t buf_len)
{
	int ret;

	ret = gnutls_record_send(ep->session, buf, buf_len);
	if (ret >= 0)
		return ret;
	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
		errno = EAGAIN;
		return -1;
	}
	if (gnutls_error_is_fatal(ret)) {
		sd_err("tls fatal error (%s)", gnutls_strerror(ret));
		errno = EIO;
	} else {
		sd_warn("tls warning (%s)", gnutls_strerror(ret));
		errno = EAGAIN;
	}
	return -1;
}

static int gnutls_ep_read(struct nofuse_queue *ep, void *buf, size_t buf_len)
{
	int ret;

	ret = gnutls_record_recv(ep->session, buf, buf_len);
	if (ret >= 0)
		return ret;
	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
		errno = EAGAIN;
		return -1;
	}
	if (gnutls_error_is_fatal(ret)) {
		sd_err("tls fatal error (%s)", gnutls_strerror(ret));
		errno = EIO;
	} else {
		sd_warn("tls warning (%s)", gnutls_strerror(ret));
		errno = EAGAIN;
	}
	return -1;
}

#define IO_WAIT_TIMEOUT_MS 5000

static int gnutls_ep_wait(struct nofuse_queue *ep, short events)
{
	struct pollfd pfd = { .fd = ep->sockfd, .events = events };
	int ret;

	ret = gnutls_record_check_pending(ep->session);
	if (ret > 0)
		return 0;
	do {
		ret = poll(&pfd, 1, IO_WAIT_TIMEOUT_MS);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ETIMEDOUT;
	return 0;
}

struct io_ops tls_io_ops = {
	.io_read = gnutls_ep_read,
	.io_write = gnutls_ep_write,
	.io_wait = gnutls_ep_wait,
};

static int psk_server_cb(gnutls_session_t session, const char *identity,
			 gnutls_datum_t *key)
{
	key_serial_t keyring_id, psk;
	void *psk_key;
	int psk_len;
	const char *psk_key_type = "psk";

	sd_debug("identity %s", identity);
	if (identity == NULL) {
		sd_err("no identity given");
		return -1;
	}

	keyring_id = find_key_by_type_and_desc("keyring", ".nvme", 0);
	if (keyring_id < 0) {
		sd_err("TLS keyring not available");
		return -1;
	}

	psk = keyctl_search(keyring_id, psk_key_type, identity, 0);
	if (key < 0) {
		sd_info("psk identity %s not found", identity);
		return -1;
	}
	psk_len = keyctl_read_alloc(psk, &psk_key);
	if (psk_len < 0) {
		sd_warn("failed to read key %u", psk);
		return -1;
	}
	key->data = gnutls_malloc(psk_len);
	if (!key->data)
		return -1;
	memcpy(key->data, psk_key, psk_len);
	key->size = psk_len;
	free(psk_key);
	return 0;
}

static void tls_log(int level, const char *msg)
{
	sd_info("gnutls(%d): %s", level, msg);
}

int tls_global_init(void)
{
	key_serial_t serial;
	int ret;

	gnutls_global_init();

	gnutls_global_set_log_function(tls_log);

	gnutls_global_set_log_level(9);

	serial = find_key_by_type_and_desc("keyring", ".nvme", 0);
	if (serial < 0) {
		tls_log(3, "default '.nvme' keyring not found");
		return -1;
	}
	ret = keyctl_link(serial, KEY_SPEC_SESSION_KEYRING);
	if (ret < 0) {
		tls_log(3, "failed to link '.nvme' into session keyring");
		return ret;
	}
	return serial;
}

int tls_handshake(struct nofuse_queue *ep)
{
	const char *tls_priority = "SECURE256:+SECURE128:-COMP-ALL:-VERS-ALL:+VERS-TLS1.3:+PSK:+DHE-PSK:+ECDHE-PSK";
	int ret;
	const char *err_pos;

	ep->tls_started = true;
	gnutls_psk_allocate_server_credentials(&ep->psk_cred);

	gnutls_psk_set_server_credentials_function(ep->psk_cred,
						   psk_server_cb);
	gnutls_init(&ep->session, GNUTLS_SERVER);
	gnutls_transport_set_int(ep->session, ep->sockfd);

	gnutls_credentials_set(ep->session, GNUTLS_CRD_PSK, ep->psk_cred);

	ret = gnutls_priority_set_direct(ep->session, tls_priority, &err_pos);
	if (ret != GNUTLS_E_SUCCESS) {
		sd_warn("failed to set priorities, err %s", err_pos);
		ret = -EINVAL;
		goto out_free;
	}
	gnutls_handshake_set_timeout(ep->session, 20 * 1000);
	do {
		ret = gnutls_handshake(ep->session);
	} while (ret < 0 && !gnutls_error_is_fatal(ret));
	if (ret < 0) {
		sd_warn("handshaked failed (%s)",
			gnutls_strerror(ret));
		ret = -EOPNOTSUPP;
		goto out_free;
	}
	sd_info("switching to TLS functions");
	ep->io_ops = &tls_io_ops;
	return ret;
out_free:
	gnutls_psk_free_server_credentials(ep->psk_cred);
	gnutls_deinit(ep->session);
	return ret;
}

void tls_free_queue(struct nofuse_queue *ep)
{
	if (ep->io_ops != &tls_io_ops)
		return;
	gnutls_deinit(ep->session);
	gnutls_psk_free_server_credentials(ep->psk_cred);
}
