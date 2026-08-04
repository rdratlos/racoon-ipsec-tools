/*	$NetBSD: session.c,v 1.32 2011/03/02 15:09:16 vanhu Exp $	*/

/*	$KAME: session.c,v 1.32 2003/09/24 02:01:17 jinmei Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Modifications Copyright (C) 2024-2026 Thomas Reim
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(s)	((unsigned)(s) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(s)	(((s) & 255) == 0)
#endif

#include PATH_IPSEC_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <sys/stat.h>
#include <paths.h>
#include <err.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <resolv.h>

#include "libpfkey.h"

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "debug.h"

#include "schedule.h"
#include "session.h"
#include "grabmyaddr.h"
#include "evt.h"
#include "cfparse_proto.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_xauth.h"
#include "isakmp_cfg.h"
#include "admin_var.h"
#include "admin.h"
#include "privsep.h"
#include "oakley.h"
#include "pfkey.h"
#include "handler.h"
#include "localconf.h"
#include "remoteconf.h"
#include "backupsa.h"
#include "remoteconf.h"
#ifdef ENABLE_NATT
#include "nattraversal.h"
#endif

#include "algorithm.h" /* XXX ??? */

#include "sainfo.h"

struct fd_monitor {
	int (*callback)(void *ctx, int fd);
	void *ctx;
	int prio;
	int fd;
	TAILQ_ENTRY(fd_monitor) chain;
};

#define NUM_PRIORITIES 2

static void close_session __P((void));
static void initfds __P((void));
static void init_signal __P((void));
static int set_signal __P((int sig, RETSIGTYPE (*func) __P((int))));
static void check_sigreq __P((void));
static void check_flushsa __P((void));
static int close_sockets __P((void));

static fd_set preset_mask, active_mask;
static struct fd_monitor fd_monitors[FD_SETSIZE];
static TAILQ_HEAD(fd_monitor_list, fd_monitor) fd_monitor_tree[NUM_PRIORITIES];
static int nfds = 0;

static volatile sig_atomic_t sigreq[NSIG + 1];
static struct sched scflushsa = SCHED_INITIALIZER();

/*
 * Registers fd with the main loop's select() set. Returns 0 on success and
 * -1 if fd cannot be monitored at all, which for select() means only one
 * thing: it does not fit in an fd_set.
 *
 * That used to exit(1) on the spot. But fd here is not a fixed daemon-wide
 * resource: besides the pfkey/routing/admin-listener sockets opened once at
 * startup, it is also every accepted admin connection that asks for events
 * (evt_subscribe(), evt.c) and every ISAKMP socket opened for an address
 * that shows up while running (isakmp_open(), isakmp.c). A descriptor
 * landing past FD_SETSIZE is a property of how many descriptors the process
 * happens to hold when that one connection or address arrives -- so
 * exiting turned "this racoonctl connection cannot be watched" into
 * "every live Phase 1/2 SA dies", the same disproportionate failure shape
 * that session()'s select() loop had before prune_stale_monitored_fds()
 * (issues #102/#105). Report the failure instead and let the caller drop
 * just that connection or socket; the callers at startup still treat it as
 * fatal, which at startup it is.
 */
int
monitor_fd(int fd, int (*callback)(void *, int), void *ctx, int priority)
{
	int i;

	if (fd < 0 || fd >= FD_SETSIZE) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "cannot monitor fd %d: outside fd_set range "
		    "[0,%d)\n", fd, FD_SETSIZE);
		return -1;
	}

	/*
	 * Self-enforcing TAILQ_INIT(): fd_monitor_tree[]'s normal
	 * initialization is session_init_before_cfparse() below, called once
	 * at real startup well before this function's first real call --
	 * but that is a call-order convention, not something this function
	 * can see violated from its caller's side. A TAILQ_HEAD
	 * TAILQ_INIT() has not yet touched has tqh_last == NULL (a queue
	 * head's all-zero static default); TAILQ_INIT() itself always
	 * leaves tqh_last pointing at the head's own tqh_first, which can
	 * never be NULL for a real struct. That distinction doubles as a
	 * one-time-init guard with no extra state: any head still at its
	 * zero default gets TAILQ_INIT()ed here before the insert below
	 * ever touches it, so a future caller that reaches this function
	 * before session_init_before_cfparse() has run degrades to "still
	 * works" instead of a NULL-pointer dereference inside
	 * TAILQ_INSERT_TAIL(). Confirmed against both this project's own
	 * compat sys/queue.h (src/include-glibc, Linux) and NetBSD's native
	 * one -- both define TAILQ_HEAD with a tqh_last field and have
	 * TAILQ_INIT() set it to &head->tqh_first, never NULL. See
	 * doc/dev/v0.9.1-hardening-spec.md §2.4 for the
	 * finding this closes: privsep_init()'s child branch used to
	 * segfault calling this function directly, without
	 * session_init_before_cfparse() having run first.
	 */
	for (i = 0; i < NUM_PRIORITIES; i++) {
		if (fd_monitor_tree[i].tqh_last == NULL)
			TAILQ_INIT(&fd_monitor_tree[i]);
	}

	FD_SET(fd, &preset_mask);
	if (fd > nfds)
		nfds = fd;
	if (priority <= 0)
		priority = 0;
	if (priority >= NUM_PRIORITIES)
		priority = NUM_PRIORITIES - 1;

	fd_monitors[fd].callback = callback;
	fd_monitors[fd].ctx = ctx;
	fd_monitors[fd].prio = priority;
	fd_monitors[fd].fd = fd;
	TAILQ_INSERT_TAIL(&fd_monitor_tree[priority],
			  &fd_monitors[fd], chain);

	return 0;
}

void
unmonitor_fd(int fd)
{
	if (fd < 0 || fd >= FD_SETSIZE) {
		/*
		 * Nothing was ever registered for such an fd (monitor_fd()
		 * above refuses it), so there is nothing to undo and no
		 * shared state at risk -- unwinding a connection is not a
		 * reason to end the process.
		 */
		plog(LLV_ERROR, LOCATION, NULL,
		    "cannot unmonitor fd %d: outside fd_set range "
		    "[0,%d)\n", fd, FD_SETSIZE);
		return;
	}

	if (fd_monitors[fd].callback == NULL)
		return;

	FD_CLR(fd, &preset_mask);
	FD_CLR(fd, &active_mask);
	fd_monitors[fd].callback = NULL;
	fd_monitors[fd].ctx = NULL;
	TAILQ_REMOVE(&fd_monitor_tree[fd_monitors[fd].prio],
		     &fd_monitors[fd], chain);
}

/*
 * Scans every currently-monitored fd for validity and unmonitor_fd()s any
 * that are no longer open. Returns 1 if at least one stale fd was found
 * and dropped, 0 if none were -- see the comment at this function's call
 * site (session()'s main loop, on select() failing with EBADF) for why
 * this exists: a bug elsewhere (e.g. doc/dev/v0.9.1-hardening-spec.md §5.6's Issue 4 follow-up)
 * can close() a monitored fd directly instead of going through
 * unmonitor_fd(), leaving a stale entry that fails every subsequent
 * select() with EBADF.
 *
 * fcntl(fd, F_GETFD) is a side-effect-free, POSIX-standard way to test fd
 * validity (POSIX.1-2017 fcntl(): fails with EBADF if fildes is not a
 * valid open file descriptor) -- it neither reads nor blocks, so scanning
 * every monitored fd here is safe to do unconditionally.
 */
static int
prune_stale_monitored_fds(void)
{
	int fd, found_bad = 0;

	for (fd = 0; fd <= nfds; fd++) {
		if (fd_monitors[fd].callback == NULL)
			continue;
		if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "dropping stale monitored fd %d (closed "
			    "elsewhere without unmonitor_fd()) after a "
			    "failed select()\n", fd);
			unmonitor_fd(fd);
			found_bad = 1;
		}
	}
	return found_bad;
}

#ifdef ENABLE_UNITTEST
int
prune_stale_monitored_fds_unittest(void)
{
	return prune_stale_monitored_fds();
}

int
is_fd_monitored_unittest(int fd)
{
	if (fd < 0 || fd >= FD_SETSIZE)
		return 0;
	return fd_monitors[fd].callback != NULL;
}

/*
 * Initializes just the fd-monitoring state (preset_mask/active_mask/
 * fd_monitor_tree/nfds) that monitor_fd()/unmonitor_fd() require --
 * mirrors the relevant subset of session_init_before_cfparse() (this
 * file) without also calling sched_init()/init_signal(), which pull in
 * this project's scheduler and signal-handling machinery a unit test for
 * this fd-monitoring logic alone has no need of.
 */
void
init_fd_monitor_unittest(void)
{
	int i;

	nfds = 0;
	FD_ZERO(&preset_mask);
	FD_ZERO(&active_mask);
	for (i = 0; i < NUM_PRIORITIES; i++)
		TAILQ_INIT(&fd_monitor_tree[i]);
}
#endif

/*
 * Everything cfparse() and the grammar's kernel-algorithm checks
 * (pk_checkalg(), reached via sainfo's encryption/authentication_algorithm)
 * depend on: fd monitoring, the scheduler, and the pfkey/isakmp/auth-backend
 * state that lets the parser ask the kernel which algorithms it supports.
 *
 * Split out of session() so "racoon -t" (see main.c) can run the exact
 * same pre-parse initialization the daemon does at real startup, without
 * also opening the admin port, writing a pid file, or forking.
 */
void
session_init_before_cfparse(void)
{
	int i;

	nfds = 0;
	FD_ZERO(&preset_mask);

	for (i = 0; i < NUM_PRIORITIES; i++)
		TAILQ_INIT(&fd_monitor_tree[i]);

	/* initialize schedular */
	sched_init();
	init_signal();

	if (pfkey_init() < 0)
		errx(1, "failed to initialize pfkey socket");

	if (isakmp_init() < 0)
		errx(1, "failed to initialize ISAKMP structures");

#ifdef ENABLE_HYBRID
	if (isakmp_cfg_init(ISAKMP_CFG_INIT_COLD))
		errx(1, "could not initialize ISAKMP mode config structures");
#endif

#ifdef HAVE_LIBLDAP
	if (xauth_ldap_init_conf() != 0)
		errx(1, "could not initialize ldap config");
#endif

#ifdef HAVE_LIBRADIUS
	if (xauth_radius_init_conf(0) != 0)
		errx(1, "could not initialize radius config");
#endif

	myaddr_init_lists();

	/*
	 * in order to prefer the parameters by command line,
	 * saving some parameters before parsing configuration file.
	 */
	save_params();
}

/*
 * One iteration of session()'s live main loop: reset the working select()
 * mask from preset_mask, block in select() for up to *timeout, recover
 * from (or propagate) a failure, and dispatch every monitored fd that
 * came back readable. Split out of session() so it can be driven directly
 * by a unit test with a real socketpair()/pipe() fd and a real, small
 * timeout, instead of needing the full daemon startup (cfparse()/
 * admin_init()/myaddr_init()/privsep_init()) session()'s own while(1)
 * otherwise requires to ever reach this code at all.
 *
 * Returns 0 if the caller should keep looping (a normal dispatch pass, an
 * EINTR retry, or an EBADF recovered by prune_stale_monitored_fds()) and
 * -1 on the one path that intentionally propagates failure: an
 * unrecovered select() error, already plog()'d here.
 */
static int
session_wait_and_dispatch(struct timeval *timeout)
{
	int error;
	int i, count;
	struct fd_monitor *fdm;

	/* schedular can change select() mask, so we reset
	 * the working copy here */
	active_mask = preset_mask;

	error = select(nfds + 1, &active_mask, NULL, NULL, timeout);
	if (error < 0) {
		switch (errno) {
		case EINTR:
			return 0;
		case EBADF:
			/*
			 * At least one fd in our own monitored set is
			 * no longer valid -- somewhere, a bug closed
			 * it without calling unmonitor_fd() first
			 * (confirmed live: an admin.c ordering bug,
			 * since fixed, left a "racoonctl vd"
			 * connection's socket registered here even
			 * after admin_handler() had already close()'d
			 * it, taking the entire daemon down on the
			 * very next select() -- doc/dev/v0.9.1-hardening-spec.md §5.6's
			 * Issue 4 follow-up has the full trace).
			 * Losing every other still-live Phase 1/2 SA
			 * (and its dummy interface/SPD/routes) over
			 * one dangling fd is a disproportionate
			 * failure mode for a bug that, by
			 * construction, can only ever be in our own
			 * bookkeeping, never in the peer's control --
			 * try to find and drop just the bad fd(s) and
			 * keep running, rather than exiting
			 * unconditionally on every select() failure.
			 */
			if (prune_stale_monitored_fds())
				return 0;
			/*
			 * No bad fd actually found in our own set --
			 * this EBADF was not explained by our own
			 * bookkeeping. Fall through to the same fatal
			 * handling as any other unrecovered select()
			 * failure below.
			 */
			/* FALLTHROUGH */
		default:
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to select (%s)\n",
				strerror(errno));
			return -1;
		}
		/*NOTREACHED*/
	}

	count = 0;
	for (i = 0; i < NUM_PRIORITIES; i++) {
		TAILQ_FOREACH(fdm, &fd_monitor_tree[i], chain) {
			if (!FD_ISSET(fdm->fd, &active_mask))
				continue;

			FD_CLR(fdm->fd, &active_mask);
			if (fdm->callback != NULL) {
				fdm->callback(fdm->ctx, fdm->fd);
				count++;
			} else
				plog(LLV_ERROR, LOCATION, NULL,
				"fd %d set, but no active callback\n", i);
		}
		if (count != 0)
			break;
	}

	return 0;
}

#ifdef ENABLE_UNITTEST
/*
 * session_wait_and_dispatch() is static, and every one of its dependencies
 * (preset_mask/active_mask/nfds/fd_monitor_tree[], prune_stale_monitored_
 * fds()) is otherwise reachable only from inside session()'s live main
 * loop, which needs a fully running daemon to ever reach at all. This
 * thin wrapper lets a unit test drive it directly with a real fd and a
 * real, short timeout.
 */
int
session_wait_and_dispatch_unittest(struct timeval *timeout)
{
	return session_wait_and_dispatch(timeout);
}
#endif /* ENABLE_UNITTEST */

int
session(void)
{
	struct timeval *timeout;
	int error;
	char pid_file[MAXPATHLEN];
	FILE *fp;
	pid_t racoon_pid = 0;
	int i;

	session_init_before_cfparse();
	if (cfparse() != 0)
		errx(1, "failed to parse configuration file.");
	restore_params();

#ifdef ENABLE_ADMINPORT
	if (admin_init() < 0)
		errx(1, "failed to initialize admin port socket");
#endif


#ifdef ENABLE_HYBRID
	if(isakmp_cfg_config.network4 && isakmp_cfg_config.pool_size == 0)
		if ((error = isakmp_cfg_resize_pool(ISAKMP_CFG_MAX_CNX)) != 0)
			return error;
#endif

	if (dump_config)
		dumprmconf();

#ifdef HAVE_LIBRADIUS
	if (xauth_radius_init() != 0)
		errx(1, "could not initialize libradius");
#endif

	if (myaddr_init() != 0)
		errx(1, "failed to listen to configured addresses");
	myaddr_sync();

#ifdef ENABLE_NATT
	natt_keepalive_init ();
#endif

	/* write .pid file */
	if (lcconf->pathinfo[LC_PATHTYPE_PIDFILE] == NULL)
		strlcpy(pid_file, _PATH_VARRUN "racoon.pid", MAXPATHLEN);
	else if (lcconf->pathinfo[LC_PATHTYPE_PIDFILE][0] == '/')
		strlcpy(pid_file, lcconf->pathinfo[LC_PATHTYPE_PIDFILE], MAXPATHLEN);
	else {
		strlcat(pid_file, _PATH_VARRUN, MAXPATHLEN);
		strlcat(pid_file, lcconf->pathinfo[LC_PATHTYPE_PIDFILE], MAXPATHLEN);
	}
	fp = fopen(pid_file, "w");
	if (fp) {
		if (fchmod(fileno(fp),
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
			syslog(LOG_ERR, "%s", strerror(errno));
			fclose(fp);
			exit(1);
		}
	} else {
		plog(LLV_ERROR, LOCATION, NULL,
			"cannot open %s", pid_file);
	}

	if (privsep_init() != 0)
		exit(1);

	/*
	 * The fork()'ed privileged side will close its copy of fp.  We wait
	 * until here to get the correct child pid.
	 */
	racoon_pid = getpid();
	fprintf(fp, "%ld\n", (long)racoon_pid);
	fclose(fp);

	for (i = 0; i <= NSIG; i++)
		sigreq[i] = 0;

	while (1) {
		/*
		 * asynchronous requests via signal.
		 * make sure to reset sigreq to 0.
		 */
		check_sigreq();

		/* scheduling */
		timeout = schedular();

		error = session_wait_and_dispatch(timeout);
		if (error < 0)
			return error;
	}
}

int racoon_shutting_down = 0;

/* clear all status and exit program. */
static void
close_session()
{
	/*
	 * Must be set before flushph1() below fires any SCRIPT_PHASE1_DOWN
	 * hooks -- see the comment on this flag in session.h.
	 */
	racoon_shutting_down = 1;

	evt_generic(EVT_RACOON_QUIT, NULL);
	pfkey_send_flush(lcconf->sock_pfkey, SADB_SATYPE_UNSPEC);
	flushph2();
	flushph1();
	flushrmconf();
	flushsainfo();
	close_sockets();
	backupsa_clean();

	plog(LLV_INFO, LOCATION, NULL, "racoon process %d shutdown\n", getpid());

	exit(0);
}

static int signals[] = {
	SIGHUP,
	SIGINT,
	SIGTERM,
	SIGUSR1,
	SIGUSR2,
	SIGCHLD,
	0
};

/*
 * asynchronous requests will actually dispatched in the
 * main loop in session().
 */
RETSIGTYPE
signal_handler(sig)
	int sig;
{
	sigreq[sig] = 1;
}


/* XXX possible mem leaks and no way to go back for now !!!
 */
static void reload_conf(){
	int error;

#ifdef ENABLE_HYBRID
	if ((isakmp_cfg_init(ISAKMP_CFG_INIT_WARM)) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "ISAKMP mode config structure reset failed, "
		    "not reloading\n");
		return;
	}
#endif

	sainfo_start_reload();

	/* TODO: save / restore / flush old lcconf (?) / rmtree
	 */
	rmconf_start_reload();

#ifdef HAVE_LIBRADIUS
	/* free and init radius configuration */
	xauth_radius_init_conf(1);
#endif

	pfkey_reload();

	save_params();
	flushlcconf();
	error = cfparse();
	if (error != 0){
		plog(LLV_ERROR, LOCATION, NULL, "config reload failed\n");
		/* We are probably in an inconsistant state... */
		return;
	}
	restore_params();

#if 0
	if (dump_config)
		dumprmconf ();
#endif

	myaddr_sync();

#ifdef HAVE_LIBRADIUS
	/* re-initialize radius state */
	xauth_radius_init();
#endif

	/* Revalidate ph1 / ph2tree !!!
	 * update ctdtree if removing some ph1 !
	 */
	revalidate_ph12();
	/* Update ctdtree ?
	 */

	sainfo_finish_reload();
	rmconf_finish_reload();
}

static void
check_sigreq()
{
	int sig, s;

	for (sig = 0; sig <= NSIG; sig++) {
		if (sigreq[sig] == 0)
			continue;
		sigreq[sig] = 0;

		switch(sig) {
		case 0:
			return;

		case SIGCHLD:
			/* Reap all pending children */
			while (waitpid(-1, &s, WNOHANG) > 0)
				;
			break;

#ifdef DEBUG_RECORD_MALLOCATION
		/*
		 * XXX This operation is signal handler unsafe and may lead to
		 * crashes and security breaches: See Henning Brauer talk at
		 * EuroBSDCon 2005. Do not run in production with this option
		 * enabled.
		 */
		case SIGUSR2:
			DRM_dump();
			break;
#endif

		case SIGHUP:
			/* Save old configuration, load new one...  */
			reload_conf();
			break;

		case SIGINT:
		case SIGTERM:
			plog(LLV_INFO, LOCATION, NULL,
			    "caught signal %d\n", sig);
			close_session();
			break;

		default:
			plog(LLV_INFO, LOCATION, NULL,
			    "caught signal %d\n", sig);
			break;
		}
	}
}

#ifdef ENABLE_UNITTEST
/*
 * check_sigreq() is static, and every one of its dispatch targets
 * (reload_conf()'s config-reload orchestration, close_session()'s
 * shutdown sequence and its own exit(0)) is otherwise reachable only
 * from inside session()'s live main loop, which needs a fully running
 * daemon (real cfparse()/admin_init()/myaddr_init()/privsep_init()) to
 * ever reach at all. This thin wrapper lets a unit test set sigreq[]
 * via the real signal_handler() (exactly as a real signal delivery
 * would) and then drive the dispatch directly.
 */
void
check_sigreq_unittest(void)
{
	check_sigreq();
}
#endif /* ENABLE_UNITTEST */

static void
init_signal()
{
	int i;

	/*
	 * Ignore SIGPIPE as we check the return value of system calls
	 * that write to pipe-like fds.
	 */
	signal(SIGPIPE, SIG_IGN);

	for (i = 0; signals[i] != 0; i++)
		if (set_signal(signals[i], signal_handler) < 0) {
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to set_signal (%s)\n",
				strerror(errno));
			exit(1);
		}
}

static int
set_signal(sig, func)
	int sig;
	RETSIGTYPE (*func) __P((int));
{
	struct sigaction sa;

	memset((caddr_t)&sa, 0, sizeof(sa));
	sa.sa_handler = func;
	sa.sa_flags = SA_RESTART;

	if (sigemptyset(&sa.sa_mask) < 0)
		return -1;

	if (sigaction(sig, &sa, (struct sigaction *)0) < 0)
		return(-1);

	return 0;
}

static int
close_sockets()
{
	myaddr_close();
	pfkey_close(lcconf->sock_pfkey);
#ifdef ENABLE_ADMINPORT
	(void)admin_close();
#endif
	return 0;
}

