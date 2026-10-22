/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * interface.c
 * Interface handling for NVMe-over-TCP userspace daemon.
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "sheep.h"
#include "nofuse.h"
#include "ops.h"
#include "configdb.h"

LIST_HEAD(port_linked_list);

static void *run_port(void *arg);

struct nofuse_port *add_port(unsigned int id, const char *transport,
			     const char *tsas, const char *traddr,
			     int trsvcid, int tls_keyring)
{
	struct nofuse_port *port;
	const char *adrfam = "ipv4";
	const char *treq = "required";
	int ret;

	port = malloc(sizeof(*port));
	if (!port)
		return NULL;
	memset(port, 0, sizeof(*port));
	port->transport.tcp.listenfd = -1;
	port->portid = id;
	if (traddr && !strchr(traddr, '.'))
		adrfam = "ipv6";

	ret = configdb_add_port(id, transport, traddr, adrfam, trsvcid);
	if (ret < 0) {
		port_err(port, "cannot register port, error %d", ret);
		goto out_free_port;
	}
	
	ret = configdb_add_ana_port_group(port->portid);
	if (ret < 0) {
		port_err(port, "cannot add ana group to port, error %d", ret);
		goto out_del_port;
	}
	if (tls_keyring) {
		if (!tsas) {
			treq = "not required";
			tsas = "tls1.3";
		}
	} else if (!strcmp(transport, "tcp"))
		tsas = NULL;
	else
		treq = NULL;

	if (tsas) {
		ret = configdb_set_port_attr(port->portid, "tsas", tsas);
		if (ret) {
			port_err(port, "cannot set TSAS to '%s', error %d",
				 tsas, ret);
			goto out_del_port;
		}
		if (!strcmp(transport, "tcp"))
			port->transport.tcp.tls = true;
	}
	if (treq) {
		ret = configdb_set_port_attr(port->portid, "treq", treq);
		if (ret) {
			port_err(port, "cannot set TREQ to '%s', error %d",
				 treq, ret);
			goto out_del_port;
		}
	}

	pthread_mutex_init(&port->ep_mutex, NULL);
	INIT_LIST_HEAD(&port->ep_list);
	INIT_LIST_NODE(&port->node);
	list_add_tail(&port->node, &port_linked_list);
	port_info(port, "created");

	return port;
out_del_port:
	configdb_del_port(port->portid);
out_free_port:
	free(port);
	return NULL;
}

int start_port(struct nofuse_port *port)
{
	pthread_attr_t pthread_attr;
	int ret;

	if (port->pthread)
		return 0;

	port_info(port, "starting");
	pthread_attr_init(&pthread_attr);
	ret = pthread_create(&port->pthread, &pthread_attr,
			     run_port, port);
	if (ret) {
		port->pthread = 0;
		port_err(port, "failed to start port thread");
		ret = -ret;
	}
	pthread_attr_destroy(&pthread_attr);

	return ret;
}

int stop_port(struct nofuse_port *port)
{
	struct nofuse_queue *ep, *_ep;
	pthread_t *tids = NULL;
	int ntids = 0, i;

	port_info(port, "stop pthread %ld", port->pthread);
	if (port->pthread) {
		pthread_cancel(port->pthread);
		pthread_join(port->pthread, NULL);
		port->pthread = 0;
	}

	pthread_mutex_lock(&port->ep_mutex);
	list_for_each_entry_safe(ep, _ep, &port->ep_list, node) {
		if (ep->pthread) {
			pthread_t *tmp = realloc(tids,
						 (ntids + 1) * sizeof(*tids));
			if (tmp) {
				tids = tmp;
				tids[ntids++] = ep->pthread;
			}
		}
		destroy_queue(ep);
	}
	pthread_mutex_unlock(&port->ep_mutex);

	/*
	 * destroy_queue() only requests cancellation; the cancelled
	 * thread's own cleanup (disconnect_queue(), including a
	 * configdb_del_ctrl() call, then freeing 'ep' itself via
	 * pop_free()) still runs asynchronously on its own thread. Wait
	 * for it here -- with ep_mutex already released, since pop_free()
	 * needs to take that same mutex to unlink 'ep' -- so the caller
	 * (nofuse_main(), about to call del_port()/configdb_close()) never
	 * races with a queue thread still using the port or configdb.
	 */
	for (i = 0; i < ntids; i++)
		pthread_join(tids[i], NULL);
	free(tids);

	return 0;
}

int del_port(struct nofuse_port *port)
{
	int ret;

	port_info(port, "deleting");
	if (port->pthread) {
		port_err(port, "port still running");
		return -EBUSY;
	}
	ret = configdb_del_ana_port_group(port->portid);
	if (ret < 0) {
		port_err(port, "cannot delete ana group from port, error %d",
			  ret);
		return ret;
	}
	ret = configdb_del_port(port->portid);
	if (ret < 0) {
		configdb_add_ana_port_group(port->portid);
		return ret;
	}
	pthread_mutex_destroy(&port->ep_mutex);
	list_del(&port->node);
	free(port);
	return 0;
}

static int start_listener(struct nofuse_port *port)
{
	char transport[8];
	int ret;

	ret = configdb_get_port_attr(port->portid, "trtype", transport);
	if (ret < 0)
		return ret;
	if (!strcmp(transport, "rdma")) {
#ifdef HAVE_RDMA
		port->ops = rdma_register_ops();
#else
		port_err(port, "rdma support disabled");
		return -EINVAL;
#endif
	} else
		port->ops = tcp_register_ops();

	if (!port->ops)
		return -EINVAL;

#ifdef HAVE_IO_URING
	port->thread_func = uring_queue_thread;
#else
	port->thread_func = epoll_queue_thread;
#endif

	ret = port->ops->init_listener(port);
	if (ret < 0) {
		port_err(port, "init_listener failed with %d", ret);
		return ret;
	}
	return 0;
}

static void pop_listener(void *arg)
{
	struct nofuse_port *port = arg;

	port_info(port, "destroy_listener");
	port->ops->destroy_listener(port);
}

static void *run_port(void *arg)
{
	struct nofuse_port *port = arg;
	struct nofuse_queue *ep;
	sigset_t set;
	void *id = NULL;
	pthread_attr_t pthread_attr;
	int ret;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigaddset(&set, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	ret = start_listener(port);
	if (ret) {
		port_err(port, "failed to start listener, error %d", ret);
		pthread_exit(NULL);
		return NULL;
	}

	pthread_cleanup_push(pop_listener, port);

	while (!stopped) {
		ret = port->ops->wait_for_connection(port, &id);
		if (stopped) {
			if (!ret)
				port->ops->destroy_connection(port, id);
			break;
		}

		if (ret < 0) {
			if (ret == -ESHUTDOWN)
				break;
			if (ret != -EAGAIN)
				port_err(port,
					 "wait for connection failed, error %d",
					 ret);

			continue;
		}
		ep = create_queue(id, port);
		if (!ep) {
			port->ops->destroy_connection(port, id);
			continue;
		}

		pthread_attr_init(&pthread_attr);
		pthread_attr_setdetachstate(&pthread_attr,
					    PTHREAD_CREATE_DETACHED);

		ret = pthread_create(&ep->pthread, &pthread_attr,
				     port->thread_func, ep);
		if (ret) {
			ep->pthread = 0;
			port_err(port, "pthread_create failed with %d", ret);
			destroy_queue(ep);
		}
		pthread_attr_destroy(&pthread_attr);
	}

	pthread_cleanup_pop(1);
	pthread_exit(NULL);
	return NULL;
}
