/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "rbtree.h"
#include "logger.h"
#include "util.h"
#include "event.h"

#ifdef HAVE_IO_URING
#include <liburing.h>
/* liburing.h drags in linux/fs.h, whose BLOCK_SIZE clashes with util.h's */
#undef BLOCK_SIZE
#endif

#define TRACEPOINT_DEFINE
#include "event_tp.h"

static void timer_handler(int fd, int events, void *data)
{
	struct timer *t = data;
	uint64_t val;

	if (read(fd, &val, sizeof(val)) < 0)
		return;

	t->callback(t->data);

	unregister_event(fd);
	close(fd);
}

void add_timer(struct timer *t, unsigned int mseconds)
{
	struct itimerspec it;
	int tfd;

	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (tfd < 0) {
		sd_err("timerfd_create: %m");
		return;
	}

	memset(&it, 0, sizeof(it));
	it.it_value.tv_sec = mseconds / 1000;
	it.it_value.tv_nsec = (mseconds % 1000) * 1000000;

	if (timerfd_settime(tfd, 0, &it, NULL) < 0) {
		sd_err("timerfd_settime: %m");
		return;
	}

	if (register_event(tfd, timer_handler, t) < 0)
		sd_err("failed to register timer fd");
}

#ifdef HAVE_IO_URING

/*
 * io_uring backend for the event loop.
 *
 * Each registered fd has at most one outstanding IORING_OP_POLL_ADD request
 * at a time (no IORING_POLL_ADD_MULTI): every time the poll fires, the
 * handler runs and, once it returns, the fd is re-armed with whatever
 * interest mask is current at that point. Arming a poll always makes the
 * kernel check current readiness immediately, so this reproduces epoll's
 * level-triggered behaviour: a handler that turns interest off, does some
 * asynchronous work, and later turns interest back on (from a worker
 * thread, well after its own dispatch has returned) gets an immediate
 * requeue if the fd is still ready, exactly like an epoll_ctl(MOD) followed
 * by the next epoll_wait().
 *
 * unregister_event()/modify_event() can race with the event loop thread
 * rearming or dispatching the very same fd, so all state transitions below
 * happen under events_mutex, and struct event_info is only ever freed once
 * every io_uring completion referencing it (tracked via ->pending) has been
 * reaped and nobody is mid-dispatch for it (->in_dispatch).
 */

enum ei_state {
	EI_IDLE,
	EI_ARMED,
	EI_CANCELLING,
};

struct event_info {
	event_handler_t handler;
	int fd;
	void *data;
	struct rb_node rb;
	int prio;

	unsigned events;	/* desired interest mask (EPOLLIN/EPOLLOUT) */
	enum ei_state state;
	int pending;		/* io_uring completions not yet reaped */
	bool in_dispatch;	/* handler currently running for this fd */
	bool removing;		/* unregister_event() called */
};

struct dispatch_entry {
	struct event_info *ei;
	event_handler_t handler;
	int fd;
	void *data;
	int prio;
	unsigned events;
};

static struct io_uring ring;
static struct rb_root events_tree = RB_ROOT;
static struct sd_mutex events_mutex = SD_MUTEX_INITIALIZER;

static struct dispatch_entry *dispatch_entries;
static int nr_events;

static int event_cmp(const struct event_info *e1, const struct event_info *e2)
{
	return intcmp(e1->fd, e2->fd);
}

int init_event(int nr)
{
	nr_events = nr;
	dispatch_entries = xcalloc(nr_events, sizeof(*dispatch_entries));

	if (io_uring_queue_init(nr_events, &ring, 0) < 0) {
		sd_err("failed to create io_uring instance: %m");
		return -1;
	}
	return 0;
}

/* caller holds events_mutex */
static struct event_info *lookup_event_locked(int fd)
{
	struct event_info key = { .fd = fd };

	return rb_search(&events_tree, &key, rb, event_cmp);
}

/* caller holds events_mutex; arms a poll request using ei->events */
static void arm_locked(struct event_info *ei)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
		panic("io_uring SQ ring exhausted");

	io_uring_prep_poll_add(sqe, ei->fd, ei->events);
	io_uring_sqe_set_data(sqe, ei);
	ei->pending++;
	ei->state = EI_ARMED;
}

/* caller holds events_mutex; cancels the currently-armed poll for ei */
static void cancel_locked(struct event_info *ei)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
		panic("io_uring SQ ring exhausted");

	io_uring_prep_poll_remove(sqe, (uint64_t)(uintptr_t)ei);
	io_uring_sqe_set_data(sqe, ei);
	ei->pending++;
	ei->state = EI_CANCELLING;
}

int register_event_prio(int fd, event_handler_t h, void *data, int prio)
{
	int ret = 0;
	struct event_info *ei;

	ei = xzalloc(sizeof(*ei));
	ei->fd = fd;
	ei->handler = h;
	ei->data = data;
	ei->prio = prio;
	ei->events = EPOLLIN;
	rb_init_node(&ei->rb);

	sd_mutex_lock(&events_mutex);
	if (rb_insert(&events_tree, ei, rb, event_cmp)) {
		sd_err("failed to insert io_uring event for fd %d", fd);
		ret = -1;
	} else {
		arm_locked(ei);
		/*
		 * io_uring_get_sqe()/io_uring_submit() must be serialized
		 * against every other submitting thread, so submit while
		 * still holding events_mutex rather than after releasing it.
		 */
		io_uring_submit(&ring);
	}
	sd_mutex_unlock(&events_mutex);

	if (ret) {
		free(ei);
		errno = EBUSY;
	}

	tracepoint(event, _register, fd, (void *)h, data, prio);

	return ret;
}

void unregister_event(int fd)
{
	struct event_info *ei;
	bool free_now = false;

	sd_mutex_lock(&events_mutex);
	ei = lookup_event_locked(fd);
	if (!ei) {
		sd_mutex_unlock(&events_mutex);
		return;
	}

	rb_erase(&ei->rb, &events_tree);
	ei->removing = true;

	switch (ei->state) {
	case EI_ARMED:
		cancel_locked(ei);
		io_uring_submit(&ring);
		break;
	case EI_IDLE:
		free_now = !ei->in_dispatch && ei->pending == 0;
		break;
	case EI_CANCELLING:
		break;
	}
	sd_mutex_unlock(&events_mutex);

	if (free_now)
		free(ei);

	tracepoint(event, unregister, fd);
}

int modify_event(int fd, unsigned int new_events)
{
	struct event_info *ei;

	sd_mutex_lock(&events_mutex);
	ei = lookup_event_locked(fd);
	if (!ei || ei->removing) {
		sd_mutex_unlock(&events_mutex);
		sd_err("event info for fd %d not found", fd);
		return 1;
	}

	ei->events = new_events;

	switch (ei->state) {
	case EI_IDLE:
		arm_locked(ei);
		io_uring_submit(&ring);
		break;
	case EI_ARMED:
		cancel_locked(ei);
		io_uring_submit(&ring);
		break;
	case EI_CANCELLING:
		/* already tearing down; rearm will use the updated mask */
		break;
	}
	sd_mutex_unlock(&events_mutex);

	return 0;
}

static bool event_loop_refresh;

void event_force_refresh(void)
{
	event_loop_refresh = true;
}

static int dispatch_cmp(const struct dispatch_entry *a,
			 const struct dispatch_entry *b)
{
	return intcmp(b->prio, a->prio);
}

/*
 * Reap one CQE. If it represents a real, dispatchable event, fill @out and
 * return true; the caller is then responsible for running the handler and
 * calling event_done() afterwards. Otherwise (teardown bookkeeping, or a
 * poll being re-armed after a modify_event()) everything is handled here.
 */
static bool event_reap(struct io_uring_cqe *cqe, struct dispatch_entry *out)
{
	struct event_info *ei = io_uring_cqe_get_data(cqe);
	int res = cqe->res;
	bool free_now = false, valid = false;

	sd_mutex_lock(&events_mutex);
	ei->pending--;

	if (ei->removing) {
		free_now = !ei->in_dispatch && ei->pending == 0;
		goto out;
	}

	switch (ei->state) {
	case EI_ARMED:
		ei->state = EI_IDLE;
		if (res < 0) {
			sd_err("poll error on fd %d: %s", ei->fd,
			       strerror(-res));
			break;
		}
		ei->in_dispatch = true;
		out->ei = ei;
		out->handler = ei->handler;
		out->fd = ei->fd;
		out->data = ei->data;
		out->prio = ei->prio;
		out->events = res;
		valid = true;
		break;
	case EI_CANCELLING:
		if (ei->pending == 0) {
			arm_locked(ei);
			io_uring_submit(&ring);
		}
		break;
	case EI_IDLE:
		/* an idle event has no outstanding io_uring requests */
		sd_err("unexpected completion for idle fd %d", ei->fd);
		break;
	}
out:
	sd_mutex_unlock(&events_mutex);

	if (free_now)
		free(ei);

	return valid;
}

/* run after a handler returns; rearms or frees the event as appropriate */
static void event_done(struct event_info *ei)
{
	bool do_free = false;

	sd_mutex_lock(&events_mutex);
	ei->in_dispatch = false;
	if (ei->removing) {
		do_free = ei->pending == 0;
	} else if (ei->state == EI_IDLE) {
		arm_locked(ei);
		io_uring_submit(&ring);
	}
	sd_mutex_unlock(&events_mutex);

	if (do_free)
		free(ei);
}

static void do_event_loop(int timeout, bool sort_with_prio)
{
	struct io_uring_cqe *cqe;
	struct __kernel_timespec ts;
	int ret, nr, i;

refresh:
	event_loop_refresh = false;

	if (timeout < 0) {
		ret = io_uring_wait_cqe(&ring, &cqe);
	} else {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (long)(timeout % 1000) * 1000000;
		ret = io_uring_wait_cqe_timeout(&ring, &cqe, &ts);
	}

	if (ret < 0) {
		if (ret == -ETIME)
			return;
		if (ret == -EINTR)
			return;
		sd_err("io_uring_wait_cqe failed: %s", strerror(-ret));
		exit(1);
	}

	nr = 0;
	do {
		struct dispatch_entry tmp;

		/*
		 * Always reap, even if the dispatch array is full: skipping
		 * this would leak the CQE's pending/state bookkeeping and
		 * leave that fd stuck forever. There can be at most one
		 * dispatchable CQE per registered fd per pass, so nr can't
		 * exceed nr_events in correct operation.
		 */
		if (event_reap(cqe, &tmp)) {
			if (nr >= nr_events)
				panic("more ready fds than registered events");
			dispatch_entries[nr++] = tmp;
		}
		io_uring_cqe_seen(&ring, cqe);
	} while (io_uring_peek_cqe(&ring, &cqe) == 0);

	if (!nr)
		return;

	if (sort_with_prio)
		xqsort(dispatch_entries, nr, dispatch_cmp);

	tracepoint(event, loop_start, nr_events);

	for (i = 0; i < nr; i++) {
		struct dispatch_entry *e = &dispatch_entries[i];

		e->handler(e->fd, e->events, e->data);
		event_done(e->ei);

		if (event_loop_refresh)
			goto refresh;
	}
}

void event_loop(int timeout)
{
	do_event_loop(timeout, false);
}

void event_loop_prio(int timeout)
{
	do_event_loop(timeout, true);
}

#else /* HAVE_IO_URING */

static int efd;
static struct rb_root events_tree = RB_ROOT;
static struct sd_mutex events_mutex = SD_MUTEX_INITIALIZER;

struct event_info {
	event_handler_t handler;
	int fd;
	void *data;
	struct rb_node rb;
	int prio;
};

static struct epoll_event *events;
static int nr_events;

static int event_cmp(const struct event_info *e1, const struct event_info *e2)
{
	return intcmp(e1->fd, e2->fd);
}

int init_event(int nr)
{
	nr_events = nr;
	events = xcalloc(nr_events, sizeof(struct epoll_event));

	efd = epoll_create(nr);
	if (efd < 0) {
		sd_err("failed to create epoll fd");
		return -1;
	}
	return 0;
}

static struct event_info *lookup_event(int fd)
{
	struct event_info key = { .fd = fd }, *event;

	sd_mutex_lock(&events_mutex);
	event = rb_search(&events_tree, &key, rb, event_cmp);
	sd_mutex_unlock(&events_mutex);
	return event;
}

int register_event_prio(int fd, event_handler_t h, void *data, int prio)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = xzalloc(sizeof(*ei));
	ei->fd = fd;
	ei->handler = h;
	ei->data = data;
	ei->prio = prio;
	rb_init_node(&ei->rb);

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (ret) {
		sd_err("failed to add epoll event for fd %d: %m", fd);
		free(ei);
	} else {
		sd_mutex_lock(&events_mutex);
		if (rb_insert(&events_tree, ei, rb, event_cmp)) {
			sd_err("failed to insert epoll event for fd %d", fd);
			ret = -1;
		}
		sd_mutex_unlock(&events_mutex);
		if (ret < 0) {
			ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
			if (ret)
				panic("failed to clear epoll event");
			free(ei);
			errno = EBUSY;
		}
	}

	tracepoint(event, _register, fd, (void *)h, data, prio);

	return ret;
}

void unregister_event(int fd)
{
	int ret;
	struct event_info *ei;

	ei = lookup_event(fd);
	if (!ei)
		return;

	ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
	if (ret)
		sd_err("failed to delete epoll event for fd %d: %m", fd);

	sd_mutex_lock(&events_mutex);
	rb_erase(&ei->rb, &events_tree);
	sd_mutex_unlock(&events_mutex);
	free(ei);

	/*
	 * Although ei is no longer valid pointer, ei->handler() might be about
	 * to be called in do_event_loop().  Refreshing the event loop is safe.
	 */
	event_force_refresh();

	tracepoint(event, unregister, fd);
}

int modify_event(int fd, unsigned int new_events)
{
	int ret;
	struct epoll_event ev;
	struct event_info *ei;

	ei = lookup_event(fd);
	if (!ei) {
		sd_err("event info for fd %d not found", fd);
		return 1;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = new_events;
	ev.data.ptr = ei;

	ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
	if (ret) {
		sd_err("failed to modify epoll event for fd %d: %m", fd);
		return 1;
	}
	return 0;
}

static bool event_loop_refresh;

void event_force_refresh(void)
{
	event_loop_refresh = true;
}

static int epoll_event_cmp(const struct epoll_event *_a, struct epoll_event *_b)
{
	struct event_info *a, *b;

	a = (struct event_info *)_a->data.ptr;
	b = (struct event_info *)_b->data.ptr;

	/* we need sort event_info array in reverse order */
	return intcmp(b->prio, a->prio);
}

static void do_event_loop(int timeout, bool sort_with_prio)
{
	int i, nr;

refresh:
	event_loop_refresh = false;
	nr = epoll_wait(efd, events, nr_events, timeout);
	if (sort_with_prio)
		xqsort(events, nr, epoll_event_cmp);

	if (nr < 0) {
		if (errno == EINTR)
			return;
		sd_err("epoll_wait failed: %m");
		exit(1);
	} else if (nr) {
		tracepoint(event, loop_start, nr_events);

		for (i = 0; i < nr; i++) {
			struct event_info *ei;

			ei = (struct event_info *)events[i].data.ptr;
			ei->handler(ei->fd, events[i].events, ei->data);

			if (event_loop_refresh)
				goto refresh;
		}
	}
}

void event_loop(int timeout)
{
	do_event_loop(timeout, false);
}

void event_loop_prio(int timeout)
{
	do_event_loop(timeout, true);
}

#endif /* HAVE_IO_URING */
