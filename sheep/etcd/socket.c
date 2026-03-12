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

int etcd_kv_exec(struct etcd_conn_ctx *conn, const char *uri,
		 struct json_object *post_obj,
		 etcd_parse_cb parse_cb, void *parse_arg)
{
	char tmpname[PATH_MAX];
	ne_session *ne_sess = conn->priv;
	ne_request *ne_req;
	char *post, *data = NULL;
	size_t postlen;
	struct json_object *ne_json = NULL;
	int fd, ret = 0;
	struct stat st;
	bool is_ok = false;

	strcpy(tmpname, "sheep-XXXXXX");
	fd = mkstemp(tmpname);
	if (!fd) {
		sd_warn("cannot open temporary files, error %d", errno);
		return -errno;
	}
	post = strdup(json_object_to_json_string(post_obj));
	postlen = strlen(post);

	ne_req = ne_request_create(ne_sess, "POST", uri);
	ne_add_request_header(ne_req, "Accept", "*/*");
	ne_add_request_header(ne_req, "Content-Type", "application/json");
	ne_print_request_header(ne_req, "Host", "%s:%d",
				conn->ctx->host, conn->ctx->port);
	ne_set_request_body_buffer(ne_req, post, postlen);

	if (http_debug)
		sd_debug("%s", post);

	ret = ne_begin_request(ne_req);
	if (ret != NE_OK) {
		if (ret == NE_ERROR)
			sd_warn("failed to dispatch request: %s",
				ne_get_error(ne_sess));
		else
			sd_warn("failed to dispatch request: %d", ret);
		ret = ne_status_to_errno(ret);
		goto done;
	}
	is_ok = ne_get_status(ne_req)->klass == 2;
	if (!is_ok) {
		sd_debug("response status %d (%s)",
			 ne_get_status(ne_req)->code,
			 ne_get_status(ne_req)->reason_phrase);
		ret = ne_discard_response(ne_req);
	} else {
		ret = ne_read_response_to_fd(ne_req, fd);
		if (ret != NE_OK)
			sd_warn("failed to read response, status %d", ret);
	}
	if (ret == NE_OK) {
		ret = ne_end_request(ne_req);
		if (ret != NE_OK) {
			sd_warn("failed to complete response, status %d",
				ret);
			ret = ne_status_to_errno(ret);
		}
		ret = 0;
	} else
		ret = ne_status_to_errno(ret);

	ne_request_destroy(ne_req);
	if (ret)
		goto done;

	ret = fstat(fd, &st);
	if (ret < 0) {
		sd_warn("failed to access response file, error %d", errno);
		goto done;
	}
	data = xzalloc(st.st_size + 1);
	if (!data) {
		sd_warn("could not allocate %lu bytes response buffer",
			st.st_size);
		goto done;
	}
	ret = read(fd, data, st.st_size);
	if (ret < 0) {
		sd_warn("could not read response buffer, error %d", errno);
		free(data);
		ret = -errno;
		goto done;
	}
	if (ret < st.st_size)
		sd_warn("read only %u of %lu bytes of response buffer",
			ret, st.st_size);
	ne_json = json_tokener_parse(data);
	if (!ne_json) {
		sd_warn("failed to parse JSON payload '%s'", data);
	} else {
		parse_cb(ne_json, parse_arg);
		json_object_put(ne_json);
	}
	free(data);
done:
	free(post);
	close(fd);
	unlink(tmpname);
	return ret;
}

int etcd_conn_init(struct etcd_conn_ctx *conn)
{
	conn->sockfd = connect_to(conn->ctx->host, conn->ctx->port);
	if (conn->sockfd < 0) {
		sd_err("failed to connect to %s:%u, error %d\n",
		       conn->ctx->host, conn->ctx->port, errno);
		return -errno;
	}

	conn->priv = ne_session_create(conn->ctx->proto,
				       conn->ctx->host,
				       conn->ctx->port);
	if (!conn->priv) {
		sd_err("failed to initialize session");
		close(conn->sockfd);
		return -EHOSTUNREACH;
	}
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
