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
#include <limits.h>
#include <netdb.h>
#include <errno.h>

#include <json-c/json.h>
#include "etcd/http_parser.h"
#include "etcd/client.h"

#include "util.h"
#include "net.h"
#include "logger.h"

static bool http_debug = false;

static char *format_hdr(struct etcd_ctx *ctx, const char *uri, int len)
{
	char *hdr;
	int hdrlen;

	hdrlen = asprintf(&hdr,
			  "POST %s HTTP/1.1\r\n"
			  "Host: %s:%d\r\n"
			  "Accept: */*\r\n"
			  "Content-Type: application/json\r\n"
			  "Content-Length: %d\r\n\r\n",
			  uri, ctx->host, ctx->port, len);
	if (hdrlen < 0)
		return NULL;
	return hdr;
}

static int send_data(int sockfd, const char *data, size_t data_len)
{
	const char *data_ptr;
	size_t data_left, len;

	data_ptr = data;
	data_left = data_len;
	while (data_left) {
		len = write(sockfd, data_ptr, data_left);
		if (len < 0) {
			sd_err("error %d sending http header", errno);
			return -errno;
		}
		if (len == 0) {
			sd_err("connection closed, %ld bytes pending",
			       data_left);
			return -ENOTCONN;
		}
		data_left -= len;
		data_ptr += len;
	}
	return data_left;
}

static int send_http(int sockfd, char *hdr, size_t hdrlen,
		     const char *post, size_t postlen)
{
	int ret;

	if (http_debug)
		sd_debug("http header (%ld bytes)", hdrlen);

	ret = send_data(sockfd, hdr, hdrlen);
	if (ret < 0)
		return ret;
	if (http_debug) {
		sd_debug("http post (%ld bytes)", postlen);
	}
	ret = send_data(sockfd, post, postlen);
	return ret;
}

static int parse_json(http_parser *http, const char *body, size_t len)
{
	struct etcd_parse_data *arg = http->data;
	json_object *resp;

	if (!len) {
		if (http_debug)
			sd_debug("no data to parse");
		return 0;
	}
	if (arg->data) {
		char *tmp;
		tmp = malloc(arg->len + len + 1);
		memset(tmp, 0, arg->len + len + 1);
		strcpy(tmp, arg->data);
		memcpy(tmp + arg->len, body, len);
		free(arg->data);
		arg->data = tmp;
		arg->len += len;
		json_tokener_reset(arg->tokener);
	} else {
		arg->data = malloc(len + 1);
		memset(arg->data, 0, len + 1);
		memcpy(arg->data, body, len);
		arg->len = len;
	}
	resp = json_tokener_parse_ex(arg->tokener,
				     arg->data, arg->len);
	if (!resp) {
		if (json_tokener_get_error(arg->tokener) ==
		    json_tokener_continue) {
			if (http_debug)
				sd_debug("continue after %ld bytes\n%s",
					 len, arg->data);
			return 0;
		}
		sd_warn("invalid response\n%s", arg->data);
		if (arg->parse_cb)
			arg->parse_cb(NULL, arg->parse_arg);
		free(arg->data);
		arg->data = NULL;
		arg->len = 0;
		return -EBADMSG;
	}

	if (http_debug) {
		sd_debug("http data (%ld bytes)", len);
		sd_debug("%s\n%s", arg->uri,
			 json_object_to_json_string(resp));
	}
	if (arg->parse_cb)
		arg->parse_cb(resp, arg->parse_arg);

	json_object_put(resp);
	free(arg->data);
	arg->data = NULL;
	arg->len = 0;
	return 0;
}

static int recv_http(struct etcd_conn_ctx *conn, http_parser *http,
		     http_parser_settings *settings)
{
	size_t alloc_size = 1024, result_size = 0;
	char *result;
	int ret = 0;

	result = malloc(alloc_size);
	if (!result)
		return -ENOMEM;
	memset(result, 0, alloc_size);

	while (true) {
		fd_set rfd;
		struct timeval tmo;

		FD_ZERO(&rfd);
		FD_SET(conn->sockfd, &rfd);
		if (conn->ctx->ttl > 0)
			tmo.tv_sec = conn->ctx->ttl;
		else
			tmo.tv_sec = 1;
		tmo.tv_usec = 0;
		ret = select(conn->sockfd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			sd_err("select error %d\n", errno);
			break;
		}
		if (!ret) {
			if (http_debug)
				sd_debug("select timeout");
			ret = -ETIME;
			break;
		}
		if (!FD_ISSET(conn->sockfd, &rfd)) {
			if (http_debug)
				sd_debug("no events");
			ret = -ENODATA;
			break;
		}
		ret = read(conn->sockfd, result, alloc_size);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			sd_err("error %d during read, %ld bytes read",
			       errno, result_size);
			ret = -errno;
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

		ret = http_parser_execute(http, settings,
					  result, result_size);
		if (!ret) {
			sd_info("No bytes processed: %s\n", result);
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
	struct etcd_parse_data *parse_data;
	http_parser_settings settings;
	http_parser *http = conn->priv;
	char *hdr, *post;
	size_t postlen;
	int ret = 0;

	if (!http || !http->data) {
		sd_warn("connection not initialized");
		return -EINVAL;
	}

	post = strdup(json_object_to_json_string_ext(post_obj,
						     JSON_C_TO_STRING_PLAIN));
	postlen = strlen(post);

	hdr = format_hdr(conn->ctx, uri, postlen);
	if (!hdr) {
		free(post);
		return -ENOMEM;
	}

	if (http_debug)
		sd_debug("%s", post);

	ret = send_http(conn->sockfd, hdr, strlen(hdr), post, postlen);
	free(hdr);
	free(post);

	if (ret < 0)
		return -errno;

	parse_data = http->data;
	parse_data->parse_cb = parse_cb;
	parse_data->parse_arg = parse_arg;
	parse_data->uri = strdup(uri);

	memset(&settings, 0, sizeof(settings));
	settings.on_body = parse_json;

	ret = recv_http(conn, http, &settings);

	parse_data->parse_cb = NULL;
	parse_data->parse_arg = NULL;
	free(parse_data->uri);
	parse_data->uri = NULL;

	return ret < 0 ? ret : 0;
}

int etcd_conn_init(struct etcd_conn_ctx *conn)
{
	struct etcd_parse_data *parse_data;
	http_parser *http;

	conn->sockfd = connect_to(conn->ctx->host, conn->ctx->port);
	if (conn->sockfd < 0) {
		sd_err("failed to connect to %s:%u, error %d\n",
		       conn->ctx->host, conn->ctx->port, errno);
		return -errno;
	}

	http = malloc(sizeof(*http));
	if (!http)
		goto out_close;

	memset(http, 0, sizeof(*http));
	http_parser_init(http, HTTP_RESPONSE);
	parse_data = malloc(sizeof(*parse_data));
	if (!parse_data)
		goto out_free;

	memset(parse_data, 0, sizeof(*parse_data));
	parse_data->tokener = json_tokener_new_ex(10);
	http->data = parse_data;
	conn->priv = http;

	return 0;
out_free:
	free(http);
out_close:
	close(conn->sockfd);
	conn->sockfd = -1;
	return -ENOMEM;
}

void etcd_conn_exit(struct etcd_conn_ctx *conn)
{
	http_parser *http = conn->priv;

	if (http) {
		if (http->data) {
			struct etcd_parse_data *parse_data;

			parse_data = http->data;
			json_tokener_free(parse_data->tokener);
			free(parse_data);
			http->data = NULL;
		}
		free(http);
	}
	if (conn->sockfd > 0) {
		close(conn->sockfd);
		conn->sockfd = -1;
	}
}
