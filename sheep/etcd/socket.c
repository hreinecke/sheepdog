/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * etcd_socket.c
 * socket interface for etcd v3 REST API implementation
 *
 * Copyright (c) 2025 Hannes Reinecke, SUSE
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <limits.h>
#include <netdb.h>
#include <errno.h>

#include <json-c/json.h>
#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include "etcd/client.h"

#include "util.h"
#include "net.h"
#include "logger.h"

static bool http_debug = false;

static int ne_status_to_errno(int ne_status)
{
	int ret;

	switch (ne_status) {
	case NE_ERROR:
		ret = -EPROTO;
		break;
	case NE_LOOKUP:
		ret = -EHOSTUNREACH;
		break;
	case NE_AUTH:
		ret = -EPERM;
		break;
	case NE_PROXYAUTH:
		ret = -EACCES;
		break;
	case NE_CONNECT:
		ret = -ENETUNREACH;
		break;
	case NE_TIMEOUT:
		ret = -ETIMEDOUT;
		break;
	case NE_REDIRECT:
		ret = -EAGAIN;
		break;
	default:
		ret = -EIO;
		break;
	}
	return ret;
}

static ne_request *format_hdr(struct etcd_conn_ctx *conn, const char *uri)
{
	ne_request *ne_req;

	ne_req = ne_request_create(conn->priv, "POST", uri);
	if (!ne_req)
		return NULL;
	ne_add_request_header(ne_req, "Accept", "*/*");
	ne_add_request_header(ne_req, "Content-Type", "application/json");
	return ne_req;
}

static int send_http(ne_session *ne_sess, ne_request *ne_req,
		     const char *post, size_t postlen)
{
	int ret;
	bool is_ok;

	ret = ne_begin_request(ne_req);
	if (ret != NE_OK) {
		if (ret == NE_ERROR)
			sd_warn("failed to dispatch request: %s",
				ne_get_error(ne_sess));
		else
			sd_warn("failed to dispatch request: %d", ret);
		return ne_status_to_errno(ret);
	}
	is_ok = ne_get_status(ne_req)->klass == 2;
	if (is_ok)
		return 0;

	sd_debug("response status %d (%s)",
		 ne_get_status(ne_req)->code,
		 ne_get_status(ne_req)->reason_phrase);
	ret = ne_discard_response(ne_req);
	if (ret == NE_OK)
		ret = NE_ERROR;
	return ne_status_to_errno(ret);
}

static int parse_json(struct etcd_parse_data *data,
		      const char *body, size_t len)
{
	json_object *obj;

	if (!len) {
		if (http_debug)
			sd_debug("no data to parse");
		return 0;
	}
	obj = json_tokener_parse_ex(data->tokener,
				    body, len);
	if (json_tokener_get_error(data->tokener) ==
	    json_tokener_continue)
		return len;

	if (http_debug) {
		sd_debug("http data (%ld bytes)", len);
		sd_debug("%s\n%s", data->uri,
			 json_object_to_json_string(obj));
	}
	if (data->parse_cb)
		data->parse_cb(obj, data->parse_arg);
	else
		sd_warn("no parse callback");

	json_object_put(obj);
	return len;
}

static int recv_http(ne_request *ne_req, struct etcd_parse_data *data)
{
	size_t alloc_size = 1024, result_size = 0;
	char *result;
	int ret = 0;

	result = malloc(alloc_size);
	if (!result)
		return -ENOMEM;
	memset(result, 0, alloc_size);

	while (true) {
		ret = ne_read_response_block(ne_req, result, alloc_size);
		if (ret < 0) {
			sd_err("error %d during read, %ld bytes read",
			       ret, result_size);
			ret = ne_status_to_errno(ret);
			break;
		}
		if (ret == 0) {
			sd_err("socket closed during read, %ld bytes read",
			       result_size);
			break;
		}
		result_size = ret;
		if (http_debug)
			sd_debug("%ld bytes read", result_size);

		if (!parse_json(data, result, result_size)) {
			sd_info("No bytes processed: %s", result);
			break;
		}
		if (result_size < alloc_size)
			break;
		memset(result, 0, alloc_size);
	}
	free(result);
	return ret;
}

int etcd_kv_exec(struct etcd_conn_ctx *conn, const char *uri,
		 struct json_object *post_obj,
		 etcd_parse_cb parse_cb, void *parse_arg)
{
	ne_session *ne_sess = conn->priv;
	struct etcd_parse_data parse_data;
	ne_request *ne_req;
	char *post;
	size_t postlen;
	int ret = 0;

	post = strdup(json_object_to_json_string(post_obj));
	postlen = strlen(post);

	if (http_debug)
		sd_debug("%s", post);
retry:
	ne_req = format_hdr(conn, uri);
	if (!ne_req)
		return -ENOMEM;
	ne_set_request_body_buffer(ne_req, post, postlen);

	ret = send_http(ne_sess, ne_req, post, postlen);
	if (ret)
		goto done;

	parse_data.parse_cb = parse_cb;
	parse_data.parse_arg = parse_arg;
	parse_data.tokener = json_tokener_new_ex(10);
	parse_data.uri = strdup(uri);

	ret = recv_http(ne_req, &parse_data);

	if (ne_end_request(ne_req) == NE_RETRY) {
		json_tokener_reset(parse_data.tokener);
		sd_debug("retrying request %s", uri);
		goto retry;
	}

	free(parse_data.uri);
	json_tokener_free(parse_data.tokener);

done:
	free(post);
	return ret < 0 ? ret : 0;
}

int etcd_conn_init(struct etcd_conn_ctx *conn)
{
	ne_session *ne_sess;

	conn->sockfd = connect_to(conn->ctx->host, conn->ctx->port);
	if (conn->sockfd < 0) {
		sd_err("failed to connect to %s:%u, error %d\n",
		       conn->ctx->host, conn->ctx->port, errno);
		return -errno;
	}

	ne_sess = ne_session_create(conn->ctx->proto,
				    conn->ctx->host,
				    conn->ctx->port);
	if (!ne_sess) {
		sd_err("failed to initialize session");
		close(conn->sockfd);
		return -EHOSTUNREACH;
	}
	/* Disable persistent sessions */
	ne_set_session_flag(ne_sess, NE_SESSFLAG_PERSIST, 0);
	conn->priv = ne_sess;
	return 0;
}

void etcd_conn_exit(struct etcd_conn_ctx *conn)
{
	ne_session *ne_sess = conn->priv;

	if (ne_sess) {
		ne_session_destroy(ne_sess);
		conn->priv = NULL;
	}

	if (conn->sockfd > 0) {
		close(conn->sockfd);
		conn->sockfd = -1;
	}
}
