/*	$NetBSD: privsep.c,v 1.21.2.1 2011/08/12 05:46:06 tteras Exp $	*/

/* Id: privsep.c,v 1.15 2005/08/08 11:23:44 vanhu Exp */

/*
 * Copyright (C) 2004 Emmanuel Dreyfus
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

#include "config.h"

#include <unistd.h>
#include <string.h>
#ifdef __NetBSD__
#include <stdlib.h>	/* for setproctitle */
#endif
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <netinet/in.h>

#include "gcmalloc.h"
#include "vmbuf.h"
#include "misc.h"
#include "plog.h"
#include "var.h"

#include "crypto_openssl.h"
#include "isakmp_var.h"
#include "isakmp.h"
#ifdef ENABLE_HYBRID
#include "resolv.h"
#include "isakmp_xauth.h"
#include "isakmp_cfg.h"
#endif
#include "localconf.h"
#include "remoteconf.h"
#include "admin.h"
#include "sockmisc.h"
#include "privsep.h"
#include "session.h"

static int privsep_sock[2] = { -1, -1 };

/*
 * How long the privileged process will wait, mid-request, for privsep_sock
 * to become usable before giving up on that request (issue #105).
 *
 * Every read and write the privileged dispatch loop performs *between*
 * receiving a command and answering it must be bounded. The loop's own
 * idle wait for the next command is not -- blocking there indefinitely is
 * what the loop is for -- but once a request is in flight, the only writer
 * on the other end is the unprivileged child, and a child that simply
 * stops talking (never sends the descriptor its PRIVSEP_BIND announced,
 * never drains the replies it asked for) would otherwise block this
 * process forever. There is exactly one privileged process serving exactly
 * one child, so that is not one stalled connection among many: it is the
 * end of certificate loads, PSK lookups and hook execution for every peer,
 * with the daemon still apparently alive. An unbounded silent hang is
 * strictly worse than an exit -- the same reasoning that keeps
 * privsep_send()/privsep_recv() failures fatal below -- so bound it.
 *
 * 3s matches script_exec()'s existing bounded wait (SCRIPT_DOWN_WAIT_MAX_MS,
 * isakmp.c) and its rationale: far above anything the real exchange needs
 * (the client's send_fd() is the statement immediately after its
 * privsep_send(), with nothing that can block in between -- microseconds),
 * far below systemd's default 90s TimeoutStopSec. Polled in 50ms slices,
 * which also makes the wait EINTR-safe without a clock: a signal costs at
 * most one slice of the budget, and the only signals this process takes
 * are the SIGINT/SIGTERM it forwards to the child before shutting down
 * anyway.
 *
 * poll() rather than select(): privsep_sock's descriptor number is not
 * ours to bound, and an fd_set overrun here would be the very failure mode
 * monitor_fd() was fixed for in this same audit.
 */
#define PRIVSEP_IPC_WAIT_MAX_MS  3000
#define PRIVSEP_IPC_WAIT_POLL_MS 50

/*
 * PID of the unprivileged child, valid only in the privileged process
 * (the "default:" branch after fork() in privsep_init() below never
 * clears it; the child branch never sets it, so it stays 0 there and
 * privsep_sigterm_forward() -- which only the privileged process installs
 * a handler for -- never fires with a stale/wrong value). See
 * privsep_sigterm_forward() for why this exists.
 */
static pid_t privsep_child_pid = 0;

static int privsep_recv(int, struct privsep_com_msg **, size_t *);
static int privsep_send(int, struct privsep_com_msg *, size_t);
static int privsep_wait_io(int, int, int, const char *);
static int privsep_socket_allowed(int, int, int);
static int safety_check(struct privsep_com_msg *, int i);
static int port_check(int);
static int unsafe_env(char *const *);
static int unknown_name(int);
static int unsafe_path(char *, int);
static int rec_fd(int);
static int send_fd(int, int);

struct socket_args {
	int domain;
	int type;
	int protocol;
};

struct sockopt_args {
	int s;
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
};

struct bind_args {
	int s;
	const struct sockaddr *addr;
	socklen_t addrlen;
};

static int
privsep_send(sock, buf, len)
	int sock;
	struct privsep_com_msg *buf;
	size_t len;
{
	if (buf == NULL)
		return 0;

	if (sendto(sock, (char *)buf, len, 0, NULL, 0) == -1) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "privsep_send failed: %s\n", 
		    strerror(errno));
		return -1;
	}

	racoon_free((char *)buf);

	return 0;
}


static int
privsep_recv(sock, bufp, lenp)
	int sock;
	struct privsep_com_msg **bufp;
	size_t *lenp;
{
	struct admin_com com;
	struct admin_com *combuf;
	size_t len;

	*bufp = NULL;
	*lenp = 0;

	/* Get the header */
	while ((len = recvfrom(sock, (char *)&com, 
	    sizeof(com), MSG_PEEK, NULL, NULL)) == -1) {
		if (errno == EINTR)
			continue;
		if (errno == ECONNRESET)
		    return 1;	/* peer gone, see below */

		plog(LLV_ERROR, LOCATION, NULL,
		    "privsep_recv failed: %s\n",
		    strerror(errno));
		return -1;
	}

	/*
	 * EOF, other side has closed.
	 *
	 * Reported as 1 rather than -1 so the privileged dispatch loop can
	 * tell "my peer finished and went away" (an ordinary shutdown, exit
	 * status 0) from "this channel broke under me" (a fault, exit status
	 * 1 -- which is what lets a service manager tell the two apart and
	 * restart only the second). Every caller tests for != 0, so the
	 * distinction costs the client side nothing.
	 */
	if (len == 0)
	    return 1;

	/* Check for short packets */
	if (len < sizeof(com)) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "corrupted privsep message (short header)\n");
		return -1;
	}

	/* Allocate buffer for the whole message */
	if ((combuf = (struct admin_com *)racoon_malloc(com.ac_len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "failed to allocate memory: %s\n", strerror(errno));
		return -1;
	}

	/* Get the whole buffer */
	while ((len = recvfrom(sock, (char *)combuf,
	    com.ac_len, 0, NULL, NULL)) == -1) {
		if (errno == EINTR)
			continue;
		if (errno == ECONNRESET) {
		    racoon_free(combuf);
		    return 1;	/* peer gone, as above */
		}
		plog(LLV_ERROR, LOCATION, NULL,
		    "failed to recv privsep command: %s\n", 
		    strerror(errno));
		return -1;
	}

	/* We expect len to match */
	if (len != com.ac_len) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "corrupted privsep message (short packet)\n");
		return -1;
	}

	*bufp = (struct privsep_com_msg *)combuf;
	*lenp = len;

	return 0;
}

/*
 * Waits up to max_ms for sock to become readable (write == 0) or writable
 * (write != 0). Returns 0 once it is, -1 on timeout or error -- see
 * PRIVSEP_IPC_WAIT_MAX_MS above, which every production caller passes, for
 * why the privileged dispatch loop needs this at all.
 */
static int
privsep_wait_io(sock, write, max_ms, what)
	int sock;
	int write;
	int max_ms;
	const char *what;
{
	struct pollfd pfd;
	int elapsed, ret;

	for (elapsed = 0; elapsed < max_ms;
	     elapsed += PRIVSEP_IPC_WAIT_POLL_MS) {
		pfd.fd = sock;
		pfd.events = write ? POLLOUT : POLLIN;
		pfd.revents = 0;

		ret = poll(&pfd, 1, PRIVSEP_IPC_WAIT_POLL_MS);
		if (ret > 0)
			return 0;
		if (ret == -1 && errno != EINTR) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "privsep: poll failed waiting for %s: %s\n",
			    what, strerror(errno));
			return -1;
		}
		/*
		 * ret == 0 (slice expired) or EINTR: charge the slice to the
		 * budget either way and look again.
		 */
	}

	plog(LLV_ERROR, LOCATION, NULL,
	    "privsep: timed out after %d ms waiting for %s\n",
	    max_ms, what);

	return -1;
}

/*
 * Called when a mid-request message the client announced never arrived.
 *
 * This deliberately does NOT resume the dispatch loop -- it is the one
 * place in this hardening where a bounded failure still ends the process
 * on purpose, and the reason is framing, not severity. Nothing has been
 * read, so the stream is left at an offset only the client knows.
 * Resuming would meet the descriptor message it announced (one data byte
 * plus ancillary data) wherever it eventually lands and read it as the
 * head of the next command: a garbled admin_com whose attacker-chosen
 * ac_len then drives the next allocation and the next blocking read.
 * That re-creates the very unbounded block this wait exists to remove,
 * one iteration later and harder to see. The same "stream position is no
 * longer known" rule already makes a failed rec_fd() fatal in the
 * dispatch loop; a timeout is only how that failure looks when the peer
 * goes silent instead of loud.
 *
 * What the bound buys is therefore not survival of this request but the
 * difference between two failure modes. Unbounded, a child that stops
 * talking leaves this process blocked forever: no certificate loads, no
 * PSK lookups, no hooks, for any peer, with the daemon still apparently
 * alive until an operator notices and restarts it by hand. Bounded, it
 * becomes a prompt, logged exit that the child's privsep_do_exit() turns
 * into an ordinary SIGTERM shutdown -- which a service manager restarts
 * on its own.
 *
 * The reply still goes out first, best effort: a client that is merely
 * broken rather than gone is already waiting on privsep_recv() for it
 * (privsep_bind()/privsep_setsockopt() read the reply straight after
 * their send_fd()), and ETIMEDOUT there names the fault in the child's
 * own log instead of leaving it to be inferred from the shutdown that
 * follows.
 */
static void
privsep_handshake_failed(reply)
	struct privsep_com_msg *reply;
{
	plog(LLV_ERROR, LOCATION, NULL,
	    "privsep: unprivileged process did not complete its request; "
	    "privsep_sock cannot be resynchronised, terminating\n");

	reply->hdr.ac_errno = ETIMEDOUT;
	if (privsep_wait_io(privsep_sock[0], 1,
	    PRIVSEP_IPC_WAIT_MAX_MS, "the timeout reply to be accepted") == 0)
		(void)privsep_send(privsep_sock[0], reply,
		    reply->hdr.ac_len);
}

/*
 * Which socket() calls the privileged process is willing to make on the
 * unprivileged one's behalf (PRIVSEP_SOCKET). Returns nonzero if allowed.
 *
 * The two INET families cover the ISAKMP sockets. PF_KEY is allowed too,
 * but in exactly the one flavour libipsec's pfkey_open() uses
 * (SOCK_RAW/PF_KEY_V2) and no other: pfkey_dump_sadb() (pfkey.c) needs a
 * PF_KEY socket of its own and has no way to get one otherwise -- the
 * unprivileged process has no CAP_NET_ADMIN, so its own socket() call
 * fails, and the daemon's main pfkey socket is busy carrying the main
 * loop's traffic.
 *
 * Refusing PF_KEY, as this did until issue #105's live privsep testing
 * caught it, breaks every SADB dump under privsep: "racoonctl vd" and
 * "racoonctl show-sa esp|ah|ipsec", plus purge_remote()'s fallback path
 * (isakmp_inf.c), which is also how DPD and peer-initiated teardown reach
 * the SADB. Before the containment work in the same issue it did worse
 * than break them: the refusal ended the privileged process, so any of
 * those took the whole daemon down.
 *
 * Allowing it grants the unprivileged process nothing it does not already
 * hold. pfkey_init() (session.c) opens lcconf->sock_pfkey while still
 * root, well before privsep_init() forks, and the child inherits that
 * descriptor and keeps it for its whole life. The narrow type/protocol
 * match keeps this the exact shape of pfkey_open() rather than a general
 * "any PF_KEY socket you like".
 */
static int
privsep_socket_allowed(domain, type, protocol)
	int domain;
	int type;
	int protocol;
{
	if (domain == PF_INET || domain == PF_INET6)
		return 1;

	if (domain == PF_KEY && type == SOCK_RAW && protocol == PF_KEY_V2)
		return 1;

	return 0;
}

static int
privsep_do_exit(void *ctx, int fd)
{
	kill(getpid(), SIGTERM);
	return 0;
}

/*
 * daemon-issues.md Issue 1 (F2), privsep-specific half: under the shipped
 * Type=simple systemd unit (no KillMode=), `systemctl stop racoon` (or any
 * `kill <pid>`) targets $MAINPID, which -- since fork() leaves the
 * original pid in the parent -- is *this*, the privileged process, not
 * the unprivileged child that actually runs close_session() and
 * script_hook(). Before this fix, SIGTERM/SIGINT here used the default
 * disposition (immediate termination, no cleanup): the privileged process
 * died on the spot, before the child's privsep_script_exec() request for
 * SCRIPT_PHASE1_DOWN could ever arrive over privsep_sock. Under privsep,
 * this process is the only one that can actually fork()+execve() a hook
 * (see the PRIVSEP_SCRIPT_EXEC case in the dispatch loop below), so the
 * down hook was not just raced -- as in the non-privsep case fixed in
 * script_exec(), isakmp.c -- it was never attempted at all.
 *
 * Forwarding the signal to the child instead lets the child run its own
 * normal SIGTERM/SIGINT handling (session.c) while this process keeps
 * servicing privsep_sock exactly as before, including the child's
 * now-bounded-wait SCRIPT_EXEC request (PRIVSEP_SCRIPT_EXEC_WAIT,
 * privsep.h). This process still exits promptly after:
 * once the child finishes close_session() and exits, privsep_recv() below
 * observes EOF on privsep_sock and this process reaches its own existing
 * "out:" / _exit(0) path -- unchanged by this fix.
 *
 * kill() is async-signal-safe (POSIX.1-2008 / IEEE Std 1003.1-2008,
 * Base Definitions 2.4.3, "Signal Actions"), so calling it directly from
 * a signal handler is safe. privsep_child_pid is only ever written once,
 * by the parent branch below, before this handler is installed, so there
 * is no write/read race with the handler either.
 *
 * SIGHUP (config reload) and SIGUSR1/SIGUSR2 are deliberately left at
 * their existing SIG_DFL disposition here: reload is a different,
 * unfiled concern (this process has no config of its own to reload), and
 * changing it is out of scope for Issue 1.
 */
static RETSIGTYPE
privsep_sigterm_forward(sig)
	int sig;
{
	if (privsep_child_pid > 0)
		kill(privsep_child_pid, SIGTERM);
}

#ifdef ENABLE_UNITTEST
/*
 * Test-only accessors. privsep_child_pid is static and privsep_sigterm_forward()
 * is only ever installed as a real signal handler in production, neither
 * reachable from outside this file; these thin wrappers let a unit test
 * point the forwarding logic at a mock child and invoke it directly,
 * without waiting for a live privsep_init() fork() (which needs a real
 * PF_KEY/XFRM-capable kernel this project's test hosts do not all have).
 */
void
privsep_set_child_pid_unittest(pid_t pid)
{
	privsep_child_pid = pid;
}

void
privsep_sigterm_forward_unittest(void)
{
	privsep_sigterm_forward(SIGTERM);
}

/*
 * send_fd()/rec_fd() are static too, and are what lets the dispatch loop
 * answer a failed PRIVSEP_SOCKET request without ending the process: the
 * failing paths pass no descriptor (fd == -1) but still send a message, so
 * the client's rec_fd()/privsep_recv() pair stays in step. Exposed here so
 * that handshake can be exercised over a plain socketpair, without the
 * privileged fork() privsep_init() would need.
 */
int
privsep_send_fd_unittest(int s, int fd)
{
	return send_fd(s, fd);
}

int
privsep_rec_fd_unittest(int s)
{
	return rec_fd(s);
}

/*
 * privsep_wait_io() is what bounds the dispatch loop's mid-request waits.
 * Exposed with a caller-supplied budget so a test can assert both that it
 * returns promptly when the peer does talk and that it gives up when the
 * peer goes silent, without spending PRIVSEP_IPC_WAIT_MAX_MS to do it.
 */
int
privsep_wait_io_unittest(int sock, int write, int max_ms)
{
	return privsep_wait_io(sock, write, max_ms, "unittest");
}

/*
 * The PRIVSEP_SOCKET policy gate. Static, and reachable in production only
 * from inside privsep_init()'s privileged fork() -- which is exactly why
 * its PF_KEY omission survived until someone ran "racoonctl vd" on a live
 * privsep host. Exposed so the policy itself can be asserted in CI.
 */
int
privsep_socket_allowed_unittest(int domain, int type, int protocol)
{
	return privsep_socket_allowed(domain, type, protocol);
}
#endif /* ENABLE_UNITTEST */

int
privsep_init(void)
{
	int i;
	pid_t child_pid;

	/* If running as root, we don't use the privsep code path */
	if (lcconf->uid == 0)
		return 0;

	/* 
	 * When running privsep, certificate and script paths 
	 * are mandatory, as they enable us to check path safety
	 * in the privileged instance
	 */
	if ((lcconf->pathinfo[LC_PATHTYPE_CERT] == NULL) ||
	    (lcconf->pathinfo[LC_PATHTYPE_SCRIPT] == NULL)) {
		plog(LLV_ERROR, LOCATION, NULL, "privilege separation "
		   "require path cert and path script in the config file\n");
		return -1;
	}

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, privsep_sock) != 0) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate privsep_sock: %s\n", strerror(errno));
		return -1;
	}

	switch (child_pid = fork()) {
	case -1:
		plog(LLV_ERROR, LOCATION, NULL, "Cannot fork privsep: %s\n", 
		    strerror(errno));
		return -1;
		break;

	case 0: /* Child: drop privileges */
		(void)close(privsep_sock[0]);

		if (lcconf->chroot != NULL) {
			if (chdir(lcconf->chroot) != 0) {
				plog(LLV_ERROR, LOCATION, NULL, 
				    "Cannot chdir(%s): %s\n", lcconf->chroot, 
				    strerror(errno));
				return -1;
			}
			if (chroot(lcconf->chroot) != 0) {
				plog(LLV_ERROR, LOCATION, NULL, 
				    "Cannot chroot(%s): %s\n", lcconf->chroot, 
				    strerror(errno));
				return -1;
			}
		}

		if (setgid(lcconf->gid) != 0) {
			plog(LLV_ERROR, LOCATION, NULL, 
			    "Cannot setgid(%d): %s\n", lcconf->gid,
			    strerror(errno));
			return -1;
		}

		if (setegid(lcconf->gid) != 0) {
			plog(LLV_ERROR, LOCATION, NULL, 
			    "Cannot setegid(%d): %s\n", lcconf->gid,
			    strerror(errno));
			return -1;
		}

		if (setuid(lcconf->uid) != 0) {
			plog(LLV_ERROR, LOCATION, NULL, 
			    "Cannot setuid(%d): %s\n", lcconf->uid,
			    strerror(errno));
			return -1;
		}

		if (seteuid(lcconf->uid) != 0) {
			plog(LLV_ERROR, LOCATION, NULL, 
			    "Cannot seteuid(%d): %s\n", lcconf->uid,
			    strerror(errno));
			return -1;
		}
		if (monitor_fd(privsep_sock[1], privsep_do_exit, NULL, 0) != 0)
			return -1;

		return 0;
		break;

	default: /* Parent: privileged process */
		privsep_child_pid = child_pid;
		break;
	}

	/*
	 * Close everything except the socketpair,
	 * and stdout if running in the forground.
	 */
	for (i = sysconf(_SC_OPEN_MAX); i > 0; i--) {
		if (i == privsep_sock[0])
			continue;
		if ((f_foreground) && (i == 1))
			continue;
		(void)close(i);
	}

	/* Above trickery closed the log file, reopen it */
	ploginit();

	plog(LLV_INFO, LOCATION, NULL, 
	    "racoon privileged process running with PID %d\n", getpid());

	plog(LLV_INFO, LOCATION, NULL,
	    "racoon unprivileged process running with PID %d\n", child_pid);

#if defined(__NetBSD__) || defined(__FreeBSD__)
	setproctitle("[priv]");
#endif
	
	/*
	 * Don't catch most signals -- this duplicates session:signals[],
	 * which is static... except SIGINT/SIGTERM, forwarded to the
	 * unprivileged child instead of left at the default (immediate
	 * termination) disposition; see privsep_sigterm_forward() above for
	 * why (daemon-issues.md Issue 1).
	 */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_DFL);
	signal(SIGINT, privsep_sigterm_forward);
	signal(SIGTERM, privsep_sigterm_forward);
	signal(SIGUSR1, SIG_DFL);
	signal(SIGUSR2, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);

	/*
	 * The dispatch loop below serves one request per iteration, and every
	 * failure inside it used to "goto out" -- i.e. _exit(0) this process.
	 * (The remaining fatal paths now use "goto fail"/_exit(1); only the
	 * child closing its end of privsep_sock still reaches "out".)
	 * Under privsep this process is the only one that can fork()+execve()
	 * a hook or perform any other privileged operation (see
	 * privsep_sigterm_forward() above), and the unprivileged child kills
	 * itself as soon as privsep_sock reads EOF (privsep_do_exit(), also
	 * above), so any such exit takes the whole daemon down with it --
	 * every still-live Phase 1/2 SA included. That is the same
	 * disproportionate failure shape that session.c's main select() loop
	 * had before prune_stale_monitored_fds() (issue #102/#105): a fault
	 * scoped to a single request ending the entire process.
	 *
	 * Failures here are therefore split in two, and the split is about
	 * the *channel*, not about how serious the fault looks:
	 *
	 *  - Request-scoped: the message was framed correctly (privsep_recv()
	 *    consumed exactly ac_len bytes and, for the two fd-passing
	 *    commands, its descriptor message was consumed too), so the two
	 *    sides are still in step and this request can simply be answered
	 *    with an errno in reply->hdr.ac_errno. The requesting call in the
	 *    unprivileged process then fails on its own -- one negotiation,
	 *    one hook, one socket -- and the daemon keeps running. These now
	 *    "break" out of the switch into the normal reply path.
	 *
	 *  - Channel-scoped: privsep_sock itself is unusable or has lost
	 *    framing (EOF/reset, a descriptor that could not be handed over,
	 *    a reply that could not be sent, or no memory to build any reply
	 *    at all -- in which case the client would block forever waiting
	 *    for one). There is no way to answer this request or to trust the
	 *    next one, so these still end the process ("goto fail"), which
	 *    the child turns into its ordinary SIGTERM shutdown path -- but
	 *    with a nonzero exit status now, so a service manager can tell
	 *    them from the clean shutdown that "goto out" reports.
	 */
	while (1) {
		size_t len;
		struct privsep_com_msg *combuf;
		struct privsep_com_msg *reply;
		char *data;
		size_t *buflen;
		size_t totallen;
		char *bufs[PRIVSEP_NBUF_MAX];
		int i, ret;

		/*
		 * Channel-scoped: EOF, reset, or a message whose own framing
		 * (admin_com.ac_len) did not hold. Nothing left to answer or
		 * to resynchronise on. A positive return is the child having
		 * closed its end -- an ordinary shutdown, not a fault.
		 */
		ret = privsep_recv(privsep_sock[0], &combuf, &len);
		if (ret > 0)
			goto out;
		if (ret != 0)
			goto fail;

		/*
		 * Prepare the reply buffer up front: every path below this
		 * point answers the request it just read, and without a reply
		 * buffer there is no way to do that -- the requesting call in
		 * the unprivileged process blocks in privsep_recv() until it
		 * gets one. A failure here is therefore channel-scoped, the
		 * one "cannot even build an answer" case in this loop.
		 */
		if ((reply = racoon_malloc(sizeof(*reply))) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "Cannot allocate reply buffer: %s\n",
			    strerror(errno));
			goto fail;
		}
		bzero(reply, sizeof(*reply));
		reply->hdr.ac_cmd = combuf->hdr.ac_cmd;
		reply->hdr.ac_len = sizeof(*reply);

		/*
		 * Safety checks and gather the data.
		 *
		 * privsep_recv() already read exactly ac_len bytes and
		 * verified the count, so a message that is internally
		 * inconsistent (too short to hold the buffer-length array, or
		 * claiming more buffer bytes than it carries) has still not
		 * cost us stream synchronisation: answer it with EINVAL and
		 * take the next request. Note that the buflen array itself
		 * lies past the end of a too-short message, so that check has
		 * to come before the gathering loop touches it.
		 */
		if (len < sizeof(*combuf)) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "corrupted privsep message (short buflen)\n");
			reply->hdr.ac_errno = EINVAL;
			goto sendreply;
		}

		data = (char *)(combuf + 1);
		totallen = sizeof(*combuf);
		for (i = 0; i < PRIVSEP_NBUF_MAX; i++) {
			bufs[i] = (char *)data;
			data += combuf->bufs.buflen[i];
			totallen += combuf->bufs.buflen[i];
		}

		if (totallen > len) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "corrupted privsep message (bufs too big)\n");
			reply->hdr.ac_errno = EINVAL;
			goto sendreply;
		}

		switch(combuf->hdr.ac_cmd & ~PRIVSEP_SCRIPT_EXEC_WAIT) {
		/*
		 * XXX Improvement: instead of returning the key,
		 * stuff eay_get_pkcs1privkey and eay_get_x509sign
		 * together and sign the hash in the privileged 
		 * instance? 
		 * pro: the key remains inaccessible to unpriv
		 * con: a compromised unpriv racoon can still sign anything
		 */
		case PRIVSEP_EAY_GET_PKCS1PRIVKEY: {
			vchar_t *privkey;
			struct privsep_com_msg *newreply;

			/* Make sure the string is NULL terminated */
			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			bufs[0][combuf->bufs.buflen[0] - 1] = '\0';

			if (unsafe_path(bufs[0], LC_PATHTYPE_CERT) != 0) {
				plog(LLV_ERROR, LOCATION, NULL, 
				    "privsep_eay_get_pkcs1privkey: "
				    "unsafe cert \"%s\"\n", bufs[0]);
			}

			plog(LLV_DEBUG, LOCATION, NULL, 
			    "eay_get_pkcs1privkey(\"%s\")\n", bufs[0]);

			if ((privkey = eay_get_pkcs1privkey(bufs[0])) == NULL){
				reply->hdr.ac_errno = errno;
				break;
			}

			/*
			 * Request-scoped: growing the reply to carry the key
			 * can fail without costing us the reply we already
			 * have. Keep the original buffer (realloc() leaves it
			 * untouched on failure, which is why the result goes
			 * to a temporary first) and answer ENOMEM, rather than
			 * ending the process over one key that could not be
			 * shipped.
			 */
			reply->bufs.buflen[0] = privkey->l;
			reply->hdr.ac_len = sizeof(*reply) + privkey->l;
			newreply = racoon_realloc(reply, reply->hdr.ac_len);
			if (newreply == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "Cannot allocate reply buffer: %s\n",
				    strerror(errno));
				vfree(privkey);
				reply->bufs.buflen[0] = 0;
				reply->hdr.ac_len = sizeof(*reply);
				reply->hdr.ac_errno = ENOMEM;
				break;
			}
			reply = newreply;

			memcpy(reply + 1, privkey->v, privkey->l);
			vfree(privkey);
			break;
		}
		
		case PRIVSEP_SCRIPT_EXEC: {
			char *script;
			int name;
			char **envp = NULL;
			int envc = 0;
			int count = 0;
			int i;

			/*
			 * First count the bufs, and make sure strings
			 * are NULL terminated. 
			 *
			 * We expect: script, name, envp[], void
			 */ 
			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			bufs[0][combuf->bufs.buflen[0] - 1] = '\0';
			count++;	/* script */

			count++;	/* name */

			for (; count < PRIVSEP_NBUF_MAX; count++) {
				if (combuf->bufs.buflen[count] == 0)
					break;
				bufs[count]
				    [combuf->bufs.buflen[count] - 1] = '\0';
				envc++;
			}

			/*
			 * The loop above only exits early (break) once it
			 * finds the void terminator, at which point count is
			 * still a valid bufs[] index (< PRIVSEP_NBUF_MAX) --
			 * that is the expected, legitimate case, including
			 * when the terminator sits in the very last slot
			 * (count == PRIVSEP_NBUF_MAX - 1). Only a loop that
			 * ran off the end (count == PRIVSEP_NBUF_MAX) without
			 * ever finding one means the message truly had too
			 * many entries to fit. Checking this before accounting
			 * for the void slot below (rather than after
			 * incrementing past it) matters: incrementing first
			 * made every message whose terminator happened to land
			 * exactly in the last slot indistinguishable from a
			 * real overflow, rejecting otherwise-valid messages --
			 * live privsep testing hit this on a real
			 * ENABLE_HYBRID modecfg/split-DNS config that filled
			 * the buffer right up to that boundary.
			 */
			if (count >= PRIVSEP_NBUF_MAX) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_script_exec: too many args\n");
				reply->hdr.ac_errno = E2BIG;
				break;
			}
			count++;	/* void */


			/*
			 * Allocate the arrays for envp
			 */
			envp = racoon_malloc((envc + 1) * sizeof(char *));
			if (envp == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "cannot allocate memory: %s\n",
				    strerror(errno));
				reply->hdr.ac_errno = ENOMEM;
				break;
			}
			bzero(envp, (envc + 1) * sizeof(char *));

	
			/*
			 * Populate script, name and envp 
			 */
			count = 0;
			script = bufs[count++];

			if (combuf->bufs.buflen[count] != sizeof(name)) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_script_exec: corrupted message\n");
				racoon_free(envp);
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			memcpy((char *)&name, bufs[count++], sizeof(name));

			for (i = 0; combuf->bufs.buflen[count]; count++)
				envp[i++] = bufs[count];

			count++;		/* void */

			plog(LLV_DEBUG, LOCATION, NULL, 
			    "script_exec(\"%s\", %d, %p)\n", 
			    script, name, envp);

			/*
			 * Check env for dangerous variables
			 * Check script path and name
			 * Perform fork and execve
			 */
			if ((unsafe_env(envp) == 0) &&
			    (unknown_name(name) == 0) &&
			    (unsafe_path(script, LC_PATHTYPE_SCRIPT) == 0)) {
				(void)script_exec(script, name, envp,
				    (combuf->hdr.ac_cmd &
				    PRIVSEP_SCRIPT_EXEC_WAIT) ? 1 : 0);
			} else {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_script_exec: "
				    "unsafe script \"%s\"\n", script);
				/*
				 * Report the refusal instead of replying an
				 * all-clear: the unprivileged side asked for a
				 * hook that never ran, and its own log line
				 * (script_hook(), isakmp.c) is the only place
				 * that shows up in the child's log.
				 */
				reply->hdr.ac_errno = EPERM;
			}

			racoon_free(envp);
			break;
		}

		case PRIVSEP_GETPSK: {
			vchar_t *psk;
			int keylen;
			struct privsep_com_msg *newreply;

			/* Make sure the string is NULL terminated */
			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			bufs[0][combuf->bufs.buflen[0] - 1] = '\0';

			if (combuf->bufs.buflen[1] != sizeof(keylen)) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_getpsk: corrupted message\n");
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			memcpy(&keylen, bufs[1], sizeof(keylen));

			plog(LLV_DEBUG, LOCATION, NULL, 
			    "getpsk(\"%s\", %d)\n", bufs[0], keylen);

			if ((psk = getpsk(bufs[0], keylen)) == NULL) {
				reply->hdr.ac_errno = errno;
				break;
			}

			/* Request-scoped, as for the private key above */
			reply->bufs.buflen[0] = psk->l;
			reply->hdr.ac_len = sizeof(*reply) + psk->l;
			newreply = racoon_realloc(reply, reply->hdr.ac_len);
			if (newreply == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "Cannot allocate reply buffer: %s\n",
				    strerror(errno));
				vfree(psk);
				reply->bufs.buflen[0] = 0;
				reply->hdr.ac_len = sizeof(*reply);
				reply->hdr.ac_errno = ENOMEM;
				break;
			}
			reply = newreply;

			memcpy(reply + 1, psk->v, psk->l);
			vfree(psk);
			break;
		}

		/*
		 * This command's wire exchange is not a plain request/reply
		 * pair: privsep_socket() (below) blocks in rec_fd() before it
		 * reads the reply, so exactly one descriptor message must go
		 * out per request, on every path -- including the failing
		 * ones, where send_fd() is asked to pass no descriptor at all.
		 * Answering a failed request with the reply alone would leave
		 * the client's rec_fd() eating the reply's first byte instead,
		 * desynchronising the socket for good: hence "prepare, then
		 * always send", rather than an early break per check.
		 */
		case PRIVSEP_SOCKET: {
			struct socket_args socket_args;
			int s = -1;

			/* Make sure the string is NULL terminated */
			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
			} else if (combuf->bufs.buflen[0] !=
			    sizeof(struct socket_args)) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_socket: corrupted message\n");
				reply->hdr.ac_errno = EINVAL;
			} else {
				memcpy(&socket_args, bufs[0],
				       sizeof(struct socket_args));

				if (!privsep_socket_allowed(
				    socket_args.domain, socket_args.type,
				    socket_args.protocol)) {
					plog(LLV_ERROR, LOCATION, NULL,
					    "privsep_socket: "
					     "unauthorized domain (%d)\n",
					     socket_args.domain);
					reply->hdr.ac_errno = EPERM;
				} else if ((s = socket(socket_args.domain,
						socket_args.type,
						socket_args.protocol)) == -1) {
					reply->hdr.ac_errno = errno;
				}
			}

			/*
			 * Channel-scoped: a descriptor message that cannot be
			 * handed over leaves the client blocked in rec_fd().
			 * Bounded first, so a child that has stopped draining
			 * privsep_sock stalls this send for at most the
			 * handshake budget rather than forever.
			 */
			if (privsep_wait_io(privsep_sock[0], 1,
			    PRIVSEP_IPC_WAIT_MAX_MS,
			    "privsep_socket's descriptor to be accepted") != 0) {
				if (s != -1)
					close(s);
				goto fail;
			}

			if (send_fd(privsep_sock[0], s) < 0) {
				plog(LLV_ERROR, LOCATION, NULL,
				     "privsep_socket: send_fd failed\n");
				if (s != -1)
					close(s);
				goto fail;
			}

			if (s != -1)
				close(s);
			break;
		}

		/*
		 * The mirror image of PRIVSEP_SOCKET: here the *client* sends
		 * a descriptor immediately after the command message, always,
		 * so receive it before validating anything. Bailing out first
		 * (as every check below used to) would leave that descriptor
		 * message queued on privsep_sock, to be mistaken for the next
		 * request -- which is exactly why those checks could not
		 * simply reply an error and had to end the process instead.
		 */
		case PRIVSEP_BIND: {
			struct bind_args bind_args;
			int err, port = 0, s;

			/*
			 * Bounded: see privsep_handshake_failed() above for
			 * why a timeout here cannot be answered-and-resumed
			 * the way the request-scoped faults are.
			 */
			if (privsep_wait_io(privsep_sock[0], 0,
			    PRIVSEP_IPC_WAIT_MAX_MS,
			    "privsep_bind's descriptor") != 0) {
				privsep_handshake_failed(reply);
				goto fail;
			}

			/* Channel-scoped: the descriptor was lost */
			if ((s = rec_fd(privsep_sock[0])) < 0) {
				plog(LLV_ERROR, LOCATION, NULL,
				     "privsep_bind: rec_fd failed\n");
				goto fail;
			}

			/* Make sure the string is NULL terminated */
			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				close(s);
				break;
			}

			if (combuf->bufs.buflen[0] !=
			    sizeof(struct bind_args)) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_bind: corrupted message\n");
				reply->hdr.ac_errno = EINVAL;
				close(s);
				break;
			}
			memcpy(&bind_args, bufs[0], sizeof(struct bind_args));
			/*
			 * The descriptor received above is the one to bind:
			 * the copy carried in the message is the client's own
			 * (always -1 on the wire) and must not survive here.
			 */
			bind_args.s = s;

			if (combuf->bufs.buflen[1] != bind_args.addrlen) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_bind: corrupted message\n");
				reply->hdr.ac_errno = EINVAL;
				close(bind_args.s);
				break;
			}
			bind_args.addr = (const struct sockaddr *)bufs[1];

			port = extract_port(bind_args.addr);
			if (port != PORT_ISAKMP && port != PORT_ISAKMP_NATT &&
			    port != lcconf->port_isakmp &&
			    port != lcconf->port_isakmp_natt) {
				plog(LLV_ERROR, LOCATION, NULL,
				     "privsep_bind: "
				     "unauthorized port (%d)\n",
				     port);
				reply->hdr.ac_errno = EPERM;
				close(bind_args.s);
				break;
			}

			err = bind(bind_args.s, bind_args.addr,
				   bind_args.addrlen);

			if (err)
				reply->hdr.ac_errno = errno;

			close(bind_args.s);
			break;
		}

		/* Same descriptor-first ordering as PRIVSEP_BIND above */
		case PRIVSEP_SETSOCKOPTS: {
			struct sockopt_args sockopt_args;
			int err, s;

			/* Bounded, as for PRIVSEP_BIND above */
			if (privsep_wait_io(privsep_sock[0], 0,
			    PRIVSEP_IPC_WAIT_MAX_MS,
			    "privsep_setsockopt's descriptor") != 0) {
				privsep_handshake_failed(reply);
				goto fail;
			}

			/* Channel-scoped: the descriptor was lost */
			if ((s = rec_fd(privsep_sock[0])) < 0) {
				plog(LLV_ERROR, LOCATION, NULL,
				     "privsep_setsockopt: rec_fd failed\n");
				goto fail;
			}

			/* Make sure the string is NULL terminated */
			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				close(s);
				break;
			}

			if (combuf->bufs.buflen[0] !=
			    sizeof(struct sockopt_args)) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_setsockopt: "
				     "corrupted message\n");
				reply->hdr.ac_errno = EINVAL;
				close(s);
				break;
			}
			memcpy(&sockopt_args, bufs[0],
			       sizeof(struct sockopt_args));
			sockopt_args.s = s;

			if (combuf->bufs.buflen[1] != sockopt_args.optlen) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_setsockopt: corrupted message\n");
				reply->hdr.ac_errno = EINVAL;
				close(s);
				break;
			}
			sockopt_args.optval = bufs[1];

			if (sockopt_args.optname !=
			    (sockopt_args.level ==
			     IPPROTO_IP ? IP_IPSEC_POLICY :
			     IPV6_IPSEC_POLICY)) {
				plog(LLV_ERROR, LOCATION, NULL,
				    "privsep_setsockopt: "
				     "unauthorized option (%d)\n",
				     sockopt_args.optname);
				reply->hdr.ac_errno = EPERM;
				close(s);
				break;
			}

			err = setsockopt(sockopt_args.s,
					 sockopt_args.level,
					 sockopt_args.optname,
					 sockopt_args.optval,
					 sockopt_args.optlen);
			if (err)
				reply->hdr.ac_errno = errno;

			close(sockopt_args.s);
			break;
		}

#ifdef ENABLE_HYBRID
		case PRIVSEP_ACCOUNTING_SYSTEM: {
			int pool_size;
			int port;
			int inout;
			struct sockaddr *raddr;

			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 1) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 2) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 3) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}

			memcpy(&port, bufs[0], sizeof(port));
			raddr = (struct sockaddr *)bufs[1];

			bufs[2][combuf->bufs.buflen[2] - 1] = '\0';
			memcpy(&inout, bufs[3], sizeof(port));

			if (port_check(port) != 0) {
				reply->hdr.ac_errno = ERANGE;
				break;
			}

			plog(LLV_DEBUG, LOCATION, NULL, 
			    "accounting_system(%d, %s, %s)\n", 
			    port, saddr2str(raddr), bufs[2]); 

			errno = 0;
			if (isakmp_cfg_accounting_system(port, 
			    raddr, bufs[2], inout) != 0) {
				if (errno == 0)
					reply->hdr.ac_errno = EINVAL;
				else
					reply->hdr.ac_errno = errno;
			}
			break;
		}
		case PRIVSEP_XAUTH_LOGIN_SYSTEM: {
			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			bufs[0][combuf->bufs.buflen[0] - 1] = '\0';

			if (safety_check(combuf, 1) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			bufs[1][combuf->bufs.buflen[1] - 1] = '\0';

			plog(LLV_DEBUG, LOCATION, NULL, 
			    "xauth_login_system(\"%s\", <password>)\n", 
			    bufs[0]);

			errno = 0;
			if (xauth_login_system(bufs[0], bufs[1]) != 0) {
				if (errno == 0)
					reply->hdr.ac_errno = EINVAL;
				else
					reply->hdr.ac_errno = errno;
			}
			break;
		}
#ifdef HAVE_LIBPAM
		case PRIVSEP_ACCOUNTING_PAM: {
			int port;
			int inout;
			int pool_size;

			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 1) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 2) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}

			memcpy(&port, bufs[0], sizeof(port));
			memcpy(&inout, bufs[1], sizeof(inout));
			memcpy(&pool_size, bufs[2], sizeof(pool_size));

			if (pool_size != isakmp_cfg_config.pool_size)
				if (isakmp_cfg_resize_pool(pool_size) != 0) {
					reply->hdr.ac_errno = ENOMEM;
					break;
				}

			if (port_check(port) != 0) {
				reply->hdr.ac_errno = ERANGE;
				break;
			}

			plog(LLV_DEBUG, LOCATION, NULL, 
			    "isakmp_cfg_accounting_pam(%d, %d)\n", 
			    port, inout); 

			errno = 0;
			if (isakmp_cfg_accounting_pam(port, inout) != 0) {
				if (errno == 0)
					reply->hdr.ac_errno = EINVAL;
				else
					reply->hdr.ac_errno = errno;
			}
			break;
		}

		case PRIVSEP_XAUTH_LOGIN_PAM: {
			int port;
			int pool_size;
			struct sockaddr *raddr;

			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 1) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 2) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 3) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 4) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}

			memcpy(&port, bufs[0], sizeof(port));
			memcpy(&pool_size, bufs[1], sizeof(pool_size));
			raddr = (struct sockaddr *)bufs[2];
			
			bufs[3][combuf->bufs.buflen[3] - 1] = '\0';
			bufs[4][combuf->bufs.buflen[4] - 1] = '\0';

			if (pool_size != isakmp_cfg_config.pool_size)
				if (isakmp_cfg_resize_pool(pool_size) != 0) {
					reply->hdr.ac_errno = ENOMEM;
					break;
				}

			if (port_check(port) != 0) {
				reply->hdr.ac_errno = ERANGE;
				break;
			}

			plog(LLV_DEBUG, LOCATION, NULL, 
			    "xauth_login_pam(%d, %s, \"%s\", <password>)\n", 
			    port, saddr2str(raddr), bufs[3]); 

			errno = 0;
			if (xauth_login_pam(port, 
			    raddr, bufs[3], bufs[4]) != 0) {
				if (errno == 0)
					reply->hdr.ac_errno = EINVAL;
				else
					reply->hdr.ac_errno = errno;
			}
			break;
		}

		case PRIVSEP_CLEANUP_PAM: {
			int port;
			int pool_size;

			if (safety_check(combuf, 0) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}
			if (safety_check(combuf, 1) != 0) {
				reply->hdr.ac_errno = EINVAL;
				break;
			}

			memcpy(&port, bufs[0], sizeof(port));
			memcpy(&pool_size, bufs[1], sizeof(pool_size));

			if (pool_size != isakmp_cfg_config.pool_size)
				if (isakmp_cfg_resize_pool(pool_size) != 0) {
					reply->hdr.ac_errno = ENOMEM;
					break;
				}

			if (port_check(port) != 0) {
				reply->hdr.ac_errno = ERANGE;
				break;
			}

			plog(LLV_DEBUG, LOCATION, NULL, 
			    "cleanup_pam(%d)\n", port);

			cleanup_pam(port);
			reply->hdr.ac_errno = 0;

			break;
		}
#endif /* HAVE_LIBPAM */
#endif /* ENABLE_HYBRID */

		default:
			/*
			 * Request-scoped: an unrecognised command tells us
			 * nothing about the stream, which privsep_recv()
			 * already framed correctly. Refuse this one request.
			 */
			plog(LLV_ERROR, LOCATION, NULL,
			    "unexpected privsep command %d\n",
			    combuf->hdr.ac_cmd);
			reply->hdr.ac_errno = EINVAL;
			break;
		}

	sendreply:
		/*
		 * Channel-scoped: if the reply cannot be handed over, the
		 * requesting call in the unprivileged process is left blocked
		 * in privsep_recv() with nothing to read. Bounded first, for
		 * the same reason as the descriptor sends above: a child that
		 * queues requests without ever draining the replies would
		 * otherwise fill the socket buffer and block this send
		 * indefinitely.
		 */
		if (privsep_wait_io(privsep_sock[0], 1,
		    PRIVSEP_IPC_WAIT_MAX_MS, "the reply to be accepted") != 0) {
			racoon_free(reply);
			goto fail;
		}

		/* This frees reply */
		if (privsep_send(privsep_sock[0],
		    reply, reply->hdr.ac_len) != 0) {
			racoon_free(reply);
			goto fail;
		}

		racoon_free(combuf);
	}

fail:
	/*
	 * Exit status matters here, and used to be lost: every fault below
	 * shared the clean shutdown's _exit(0), telling a service manager
	 * that a daemon which had just lost its privileged IPC had finished
	 * normally. Under a Restart=on-failure unit that is the difference
	 * between coming back and staying down.
	 */
	plog(LLV_ERROR, LOCATION, NULL,
	    "racoon privileged process %d terminating: privsep_sock is no "
	    "longer usable\n", getpid());
	_exit(1);

out:
	plog(LLV_INFO, LOCATION, NULL, 
	    "racoon privileged process %d terminated\n", getpid());
	_exit(0);
}


vchar_t *
privsep_eay_get_pkcs1privkey(path) 
	char *path;
{
	vchar_t *privkey;
	struct privsep_com_msg *msg;
	size_t len;

	if (geteuid() == 0)
		return eay_get_pkcs1privkey(path);

	len = sizeof(*msg) + strlen(path) + 1;
	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return NULL;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_EAY_GET_PKCS1PRIVKEY;
	msg->hdr.ac_len = len;
	msg->bufs.buflen[0] = len - sizeof(*msg);
	memcpy(msg + 1, path, msg->bufs.buflen[0]);

	if (privsep_send(privsep_sock[1], msg, len) != 0)
		return NULL;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0)
		return NULL;

	if (msg->hdr.ac_errno != 0) {
		errno = msg->hdr.ac_errno;
		goto out;
	}

	if ((privkey = vmalloc(len - sizeof(*msg))) == NULL)
		goto out;

	memcpy(privkey->v, msg + 1, privkey->l);
	racoon_free(msg);
	return privkey;

out:
	racoon_free(msg);
	return NULL;
}

int
privsep_script_exec(script, name, envp, wait_for_exit)
	char *script;
	int name;
	char *const envp[];
	int wait_for_exit;
{
	int count = 0;
	char *const *c;
	char *data;
	size_t len;
	struct privsep_com_msg *msg;

	if (geteuid() == 0)
		return script_exec(script, name, envp, wait_for_exit);

	if ((msg = racoon_malloc(sizeof(*msg))) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}

	bzero(msg, sizeof(*msg));
	msg->hdr.ac_cmd = PRIVSEP_SCRIPT_EXEC |
	    (wait_for_exit ? PRIVSEP_SCRIPT_EXEC_WAIT : 0);
	msg->hdr.ac_len = sizeof(*msg);

	/*
	 * We send: 
	 * script, name, envp[0], ... envp[N], void
	 */

	/*
	 * Safety check on the counts: PRIVSEP_NBUF_MAX max
	 */
	count = 0;
	count++;					/* script */
	count++;					/* name */
	for (c = envp; *c; c++)				/* envp */
		count++;
	count++;					/* void */

	if (count > PRIVSEP_NBUF_MAX) {
		plog(LLV_ERROR, LOCATION, NULL, "Unexpected error: "
		    "privsep_script_exec count > PRIVSEP_NBUF_MAX\n");
		racoon_free(msg);
		return -1;
	}


	/*
	 * Compute the length
	 */
	count = 0;
	msg->bufs.buflen[count] = strlen(script) + 1;	/* script */
	msg->hdr.ac_len += msg->bufs.buflen[count++];

	msg->bufs.buflen[count] = sizeof(name);		/* name */
	msg->hdr.ac_len += msg->bufs.buflen[count++];

	for (c = envp; *c; c++) {			/* envp */
		msg->bufs.buflen[count] = strlen(*c) + 1;
		msg->hdr.ac_len += msg->bufs.buflen[count++];
	}

	msg->bufs.buflen[count] = 0; 			/* void */
	msg->hdr.ac_len += msg->bufs.buflen[count++];

	if ((msg = racoon_realloc(msg, msg->hdr.ac_len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}
	
	/*
	 * Now copy the data
	 */
	data = (char *)(msg + 1);
	count = 0;

	memcpy(data, (char *)script, msg->bufs.buflen[count]);	/* script */
	data += msg->bufs.buflen[count++];

	memcpy(data, (char *)&name, msg->bufs.buflen[count]);	/* name */
	data += msg->bufs.buflen[count++];

	for (c = envp; *c; c++) {				/* envp */
		memcpy(data, *c, msg->bufs.buflen[count]); 
		data += msg->bufs.buflen[count++];
	}

	count++;						/* void */

	/*
	 * And send it!
	 */
	if (privsep_send(privsep_sock[1], msg, msg->hdr.ac_len) != 0)
		return -1;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0)
		return -1;

	if (msg->hdr.ac_errno != 0) {
		errno = msg->hdr.ac_errno;
		racoon_free(msg);
		return -1;
	}

	racoon_free(msg);
	return 0;
}

vchar_t *
privsep_getpsk(str, keylen)
	const char *str;
	int keylen;
{
	vchar_t *psk;
	struct privsep_com_msg *msg;
	size_t len;
	int *keylenp;
	char *data;

	if (geteuid() == 0)
		return getpsk(str, keylen);

	len = sizeof(*msg) + strlen(str) + 1 + sizeof(keylen);
	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return NULL;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_GETPSK;
	msg->hdr.ac_len = len;

	data = (char *)(msg + 1);
	msg->bufs.buflen[0] = strlen(str) + 1;
	memcpy(data, str, msg->bufs.buflen[0]);

	data += msg->bufs.buflen[0];
	msg->bufs.buflen[1] = sizeof(keylen);
	memcpy(data, &keylen, sizeof(keylen));

	if (privsep_send(privsep_sock[1], msg, len) != 0)
		return NULL;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0)
		return NULL;

	if (msg->hdr.ac_errno != 0) {
		errno = msg->hdr.ac_errno;
		goto out;
	}

	if ((psk = vmalloc(len - sizeof(*msg))) == NULL)
		goto out;

	memcpy(psk->v, msg + 1, psk->l);
	racoon_free(msg);
	return psk;

out:
	racoon_free(msg);
	return NULL;
}

/*
 * Create a privileged socket.  On BSD systems a socket obtains special
 * capabilities if it is created by root; setsockopt(IP_IPSEC_POLICY) will
 * succeed but will be ineffective if performed on an unprivileged socket.
 */
int
privsep_socket(domain, type, protocol)
	int domain;
	int type;
	int protocol;
{
	struct privsep_com_msg *msg;
	size_t len;
	char *data;
	struct socket_args socket_args;
	int s, saved_errno = 0;

	if (geteuid() == 0)
		return socket(domain, type, protocol);

	len = sizeof(*msg) + sizeof(socket_args);

	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_SOCKET;
	msg->hdr.ac_len = len;

	socket_args.domain = domain;
	socket_args.type = type;
	socket_args.protocol = protocol;

	data = (char *)(msg + 1);
	msg->bufs.buflen[0] = sizeof(socket_args);
	memcpy(data, &socket_args, msg->bufs.buflen[0]);

	/* frees msg on success only */
	if (privsep_send(privsep_sock[1], msg, len) != 0) {
		racoon_free(msg);
		return -1;
	}

	/*
	 * Get the privileged socket descriptor from the privileged process.
	 * It answers every request with exactly one descriptor message
	 * followed by one reply, so read both even when no descriptor came
	 * with the first: returning early here (as this used to) would leave
	 * the reply queued and every later exchange one message out of step.
	 * -1 means the privileged side had nothing to pass, and the reply
	 * that follows carries the reason.
	 */
	s = rec_fd(privsep_sock[1]);

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0) {
		saved_errno = errno;
		goto out;
	}

	if (msg->hdr.ac_errno != 0) {
		saved_errno = msg->hdr.ac_errno;
		goto out;
	}

	if (s == -1) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "privsep_socket: no descriptor received\n");
		saved_errno = EIO;
		goto out;
	}

	racoon_free(msg);
	return s;

out:
	if (s != -1)
		close(s);
	racoon_free(msg);
	errno = saved_errno;
	return -1;
}

/*
 * Bind() a socket to a port.  This works just like regular bind(), except that
 * if you want to bind to the designated isakmp ports and you don't have the
 * privilege to do so, it will ask a privileged process to do it.
 */
int
privsep_bind(s, addr, addrlen)
	int s;
	const struct sockaddr *addr;
	socklen_t addrlen;
{
	struct privsep_com_msg *msg;
	size_t len;
	char *data;
	struct bind_args bind_args;
	int err, saved_errno = 0;

	err = bind(s, addr, addrlen);
	if ((err == 0) || (saved_errno = errno) != EACCES || geteuid() == 0) {
		if (saved_errno)
			plog(LLV_ERROR, LOCATION, NULL,
			     "privsep_bind (%s) = %d\n", strerror(saved_errno), err);
		errno = saved_errno;
		return err;
	}

	len = sizeof(*msg) + sizeof(bind_args) + addrlen;

	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_BIND;
	msg->hdr.ac_len = len;

	bind_args.s = -1;
	bind_args.addr = NULL;
	bind_args.addrlen = addrlen;

	data = (char *)(msg + 1);
	msg->bufs.buflen[0] = sizeof(bind_args);
	memcpy(data, &bind_args, msg->bufs.buflen[0]);

	data += msg->bufs.buflen[0];
	msg->bufs.buflen[1] = addrlen;
	memcpy(data, addr, addrlen);

	/* frees msg */
	if (privsep_send(privsep_sock[1], msg, len) != 0)
		goto out;

	/* Send the socket descriptor to the privileged process. */
	if (send_fd(privsep_sock[1], s) < 0)
		return -1;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0)
		goto out;

	if (msg->hdr.ac_errno != 0) {
		errno = msg->hdr.ac_errno;
		goto out;
	}

	racoon_free(msg);
	return 0;

out:
	racoon_free(msg);
	return -1;
}

/*
 * Set socket options.  This works just like regular setsockopt(), except that
 * if you want to change IP_IPSEC_POLICY or IPV6_IPSEC_POLICY and you don't
 * have the privilege to do so, it will ask a privileged process to do it.
 */
int
privsep_setsockopt(s, level, optname, optval, optlen)
	int s;
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
{
	struct privsep_com_msg *msg;
	size_t len;
	char *data;
	struct sockopt_args sockopt_args;
	int err, saved_errno = 0;

	if ((err = setsockopt(s, level, optname, optval, optlen) == 0) || 
	    (saved_errno = errno) != EACCES ||
	    geteuid() == 0) {
		if (saved_errno)
			plog(LLV_ERROR, LOCATION, NULL,
			     "privsep_setsockopt (%s)\n",
			     strerror(saved_errno));

		errno = saved_errno;
		return err;
	}

	len = sizeof(*msg) + sizeof(sockopt_args) + optlen;

	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_SETSOCKOPTS;
	msg->hdr.ac_len = len;

	sockopt_args.s = -1;
	sockopt_args.level = level;
	sockopt_args.optname = optname;
	sockopt_args.optval = NULL;
	sockopt_args.optlen = optlen;

	data = (char *)(msg + 1);
	msg->bufs.buflen[0] = sizeof(sockopt_args);
	memcpy(data, &sockopt_args, msg->bufs.buflen[0]);

	data += msg->bufs.buflen[0];
	msg->bufs.buflen[1] = optlen;
	memcpy(data, optval, optlen);

	/* frees msg */
	if (privsep_send(privsep_sock[1], msg, len) != 0)
		goto out;

	if (send_fd(privsep_sock[1], s) < 0)
		return -1;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0) {
	    plog(LLV_ERROR, LOCATION, NULL,
		 "privsep_recv failed\n");
		goto out;
	}

	if (msg->hdr.ac_errno != 0) {
		errno = msg->hdr.ac_errno;
		goto out;
	}

	racoon_free(msg);
	return 0;

out:
	racoon_free(msg);
	return -1;
}

#ifdef ENABLE_HYBRID
int
privsep_xauth_login_system(usr, pwd)
	char *usr;
	char *pwd;
{
	struct privsep_com_msg *msg;
	size_t len;
	char *data;

	if (geteuid() == 0)
		return xauth_login_system(usr, pwd);

	len = sizeof(*msg) + strlen(usr) + 1 + strlen(pwd) + 1;
	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_XAUTH_LOGIN_SYSTEM;
	msg->hdr.ac_len = len;

	data = (char *)(msg + 1);
	msg->bufs.buflen[0] = strlen(usr) + 1;
	memcpy(data, usr, msg->bufs.buflen[0]);
	data += msg->bufs.buflen[0];

	msg->bufs.buflen[1] = strlen(pwd) + 1;
	memcpy(data, pwd, msg->bufs.buflen[1]);
	
	/* frees msg */
	if (privsep_send(privsep_sock[1], msg, len) != 0)
		return -1;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0)
		return -1;

	if (msg->hdr.ac_errno != 0) {
		racoon_free(msg);
		return -1;
	}

	racoon_free(msg);
	return 0;
}

int 
privsep_accounting_system(port, raddr, usr, inout)
	int port;
	struct sockaddr *raddr;
	char *usr;
	int inout;
{
	struct privsep_com_msg *msg;
	size_t len;
	char *data;
	int result;

	if (geteuid() == 0)
		return isakmp_cfg_accounting_system(port, raddr,
						    usr, inout);

	len = sizeof(*msg) 
	    + sizeof(port)
	    + sysdep_sa_len(raddr) 
	    + strlen(usr) + 1
	    + sizeof(inout);

	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_ACCOUNTING_SYSTEM;
	msg->hdr.ac_len = len;
	msg->bufs.buflen[0] = sizeof(port);
	msg->bufs.buflen[1] = sysdep_sa_len(raddr);
	msg->bufs.buflen[2] = strlen(usr) + 1;
	msg->bufs.buflen[3] = sizeof(inout);

	data = (char *)(msg + 1);
	memcpy(data, &port, msg->bufs.buflen[0]);

	data += msg->bufs.buflen[0];
	memcpy(data, raddr, msg->bufs.buflen[1]);

	data += msg->bufs.buflen[1];
	memcpy(data, usr, msg->bufs.buflen[2]);

	data += msg->bufs.buflen[2];
	memcpy(data, &inout, msg->bufs.buflen[3]);

	/* frees msg */
	if (privsep_send(privsep_sock[1], msg, len) != 0)
		return -1;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0)
		return -1;

	if (msg->hdr.ac_errno != 0) {
		errno = msg->hdr.ac_errno;
		goto out;
	}

	racoon_free(msg);
	return 0;

out:
	racoon_free(msg);
	return -1;
}

static int
port_check(port)
	int port;
{
	if ((port < 0) || (port >= isakmp_cfg_config.pool_size)) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "privsep: port %d outside of allowed range [0,%zu]\n",
		    port, isakmp_cfg_config.pool_size - 1);
		return -1;
	}

	return 0;
}
#endif

static int 
safety_check(msg, index)
	struct privsep_com_msg *msg;
	int index;
{
	if (index >= PRIVSEP_NBUF_MAX) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "privsep: Corrupted message, too many buffers\n");
		return -1;
	}
		
	if (msg->bufs.buflen[index] == 0) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "privsep: Corrupted message, unexpected void buffer\n");
		return -1;
	}

	return 0;
}

/*
 * Filter unsafe environment variables
 */
static int
unsafe_env(envp)
	char *const *envp;
{
	char *const *e;
	char *const *be;
	char *const bad_env[] = { "PATH=", "LD_LIBRARY_PATH=", "IFS=", NULL };

	for (e = envp; *e; e++) {
		for (be = bad_env; *be; be++) {
			if (strncmp(*e, *be, strlen(*be)) == 0) {
				goto found;
			}
		}
	}

	return 0;
found:
	plog(LLV_ERROR, LOCATION, NULL, 
	    "privsep_script_exec: unsafe environment variable\n");
	return -1;
}

/*
 * Check path safety
 */
static int 
unsafe_path(script, pathtype)
	char *script;
	int pathtype;
{
	char *path;
	char rpath[MAXPATHLEN + 1];
	size_t len;

	if (script == NULL) 
		return -1;

	path = lcconf->pathinfo[pathtype];

	/* No path was given for scripts: skip the check */
	if (path == NULL)
		return 0;

	if (realpath(script, rpath) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "script path \"%s\" is invalid\n", script);
		return -1;
	}

	len = strlen(path);
	if (strncmp(path, rpath, len) != 0)
		return -1;

	return 0;
}

static int 
unknown_name(name)
	int name;
{
	if ((name < 0) || (name > SCRIPT_MAX)) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "privsep_script_exec: unsafe name index\n");
		return -1;
	}

	return 0;
}

/*
 * Receive a file descriptor through the argument socket.
 *
 * Returns -1 both when the message could not be received at all and when
 * it carried no descriptor -- the latter is how the privileged process
 * answers a PRIVSEP_SOCKET request it could not satisfy (send_fd() with
 * fd == -1, below), keeping one descriptor message per request on the wire
 * even on the failing paths. Checking for that empty control message also
 * keeps a truncated or EOF'd read from dereferencing CMSG_DATA(NULL).
 */
static int
rec_fd(s)
	int s;
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int *fdptr;
	int fd;
	char cmsbuf[1024];
	struct iovec iov;
	char iobuf[1];

	iov.iov_base = iobuf;
	iov.iov_len = 1;

	if (sizeof(cmsbuf) < CMSG_SPACE(sizeof(fd))) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "send_fd: buffer size too small\n");
		return -1;
	}
	bzero(&msg, sizeof(msg));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsbuf;
	msg.msg_controllen = CMSG_SPACE(sizeof(fd));

	if (recvmsg(s, &msg, MSG_WAITALL) == -1)
		return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL ||
	    cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(fd)))
		return -1;

	fdptr = (int *) CMSG_DATA(cmsg);
	return fdptr[0];
}

/*
 * Send the file descriptor fd through the argument socket s.
 *
 * fd == -1 sends the message without any descriptor attached, which
 * rec_fd() reports back as -1; see the PRIVSEP_SOCKET case of the dispatch
 * loop for why a failed request still has to send one.
 */
static int
send_fd(s, fd)
	int s;
	int fd;
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	char cmsbuf[1024];
	struct iovec iov;
	int *fdptr;

	iov.iov_base = " ";
	iov.iov_len = 1;

	if (sizeof(cmsbuf) < CMSG_SPACE(sizeof(fd))) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "send_fd: buffer size too small\n");
		return -1;
	}
	bzero(&msg, sizeof(msg));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	if (fd == -1) {
		/* The message still goes out, just with nothing attached */
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	} else {
		msg.msg_control = cmsbuf;
		msg.msg_controllen = CMSG_SPACE(sizeof(fd));

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
		fdptr = (int *)CMSG_DATA(cmsg);
		fdptr[0] = fd;
		msg.msg_controllen = cmsg->cmsg_len;
	}

	if (sendmsg(s, &msg, 0) == -1)
		return -1;

	return 0;
}

#ifdef HAVE_LIBPAM
int 
privsep_accounting_pam(port, inout)
	int port;
	int inout;
{
	struct privsep_com_msg *msg;
	size_t len;
	int *port_data;
	int *inout_data;
	int *pool_size_data;
	int result;

	if (geteuid() == 0)
		return isakmp_cfg_accounting_pam(port, inout);

	len = sizeof(*msg) 
	    + sizeof(port) 
	    + sizeof(inout)
	    + sizeof(isakmp_cfg_config.pool_size);

	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_ACCOUNTING_PAM;
	msg->hdr.ac_len = len;
	msg->bufs.buflen[0] = sizeof(port);
	msg->bufs.buflen[1] = sizeof(inout);
	msg->bufs.buflen[2] = sizeof(isakmp_cfg_config.pool_size);

	port_data = (int *)(msg + 1);
	inout_data = (int *)(port_data + 1);
	pool_size_data = (int *)(inout_data + 1);

	*port_data = port;
	*inout_data = inout;
	*pool_size_data = isakmp_cfg_config.pool_size;

	/* frees msg */
	if (privsep_send(privsep_sock[1], msg, len) != 0)
		return -1;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0)
		return -1;

	if (msg->hdr.ac_errno != 0) {
		errno = msg->hdr.ac_errno;
		goto out;
	}

	racoon_free(msg);
	return 0;

out:
	racoon_free(msg);
	return -1;
}

int 
privsep_xauth_login_pam(port, raddr, usr, pwd)
	int port;
	struct sockaddr *raddr;
	char *usr;
	char *pwd;
{
	struct privsep_com_msg *msg;
	size_t len;
	char *data;
	int result;

	if (geteuid() == 0)
		return xauth_login_pam(port, raddr, usr, pwd);

	len = sizeof(*msg) 
	    + sizeof(port)
	    + sizeof(isakmp_cfg_config.pool_size)
	    + sysdep_sa_len(raddr) 
	    + strlen(usr) + 1
	    + strlen(pwd) + 1;

	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return -1;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_XAUTH_LOGIN_PAM;
	msg->hdr.ac_len = len;
	msg->bufs.buflen[0] = sizeof(port);
	msg->bufs.buflen[1] = sizeof(isakmp_cfg_config.pool_size);
	msg->bufs.buflen[2] = sysdep_sa_len(raddr);
	msg->bufs.buflen[3] = strlen(usr) + 1;
	msg->bufs.buflen[4] = strlen(pwd) + 1;

	data = (char *)(msg + 1);
	memcpy(data, &port, msg->bufs.buflen[0]);

	data += msg->bufs.buflen[0];
	memcpy(data, &isakmp_cfg_config.pool_size, msg->bufs.buflen[1]);

	data += msg->bufs.buflen[1];
	memcpy(data, raddr, msg->bufs.buflen[2]);

	data += msg->bufs.buflen[2];
	memcpy(data, usr, msg->bufs.buflen[3]);

	data += msg->bufs.buflen[3];
	memcpy(data, pwd, msg->bufs.buflen[4]);

	/* frees msg */
	if (privsep_send(privsep_sock[1], msg, len) != 0)
		return -1;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0)
		return -1;

	if (msg->hdr.ac_errno != 0) {
		errno = msg->hdr.ac_errno;
		goto out;
	}

	racoon_free(msg);
	return 0;

out:
	racoon_free(msg);
	return -1;
}

void
privsep_cleanup_pam(port)
	int port;
{
	struct privsep_com_msg *msg;
	size_t len;
	char *data;
	int result;

	if (geteuid() == 0)
		return cleanup_pam(port);

	len = sizeof(*msg) 
	    + sizeof(port)
	    + sizeof(isakmp_cfg_config.pool_size);

	if ((msg = racoon_malloc(len)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, 
		    "Cannot allocate memory: %s\n", strerror(errno));
		return;
	}
	bzero(msg, len);
	msg->hdr.ac_cmd = PRIVSEP_CLEANUP_PAM;
	msg->hdr.ac_len = len;
	msg->bufs.buflen[0] = sizeof(port);
	msg->bufs.buflen[1] = sizeof(isakmp_cfg_config.pool_size);

	data = (char *)(msg + 1);
	memcpy(data, &port, msg->bufs.buflen[0]);

	data += msg->bufs.buflen[0];
	memcpy(data, &isakmp_cfg_config.pool_size, msg->bufs.buflen[1]);

	/* frees msg */
	if (privsep_send(privsep_sock[1], msg, len) != 0)
		return;

	if (privsep_recv(privsep_sock[1], &msg, &len) != 0)
		return;

	if (msg->hdr.ac_errno != 0)
		errno = msg->hdr.ac_errno;

	racoon_free(msg);
	return;
}
#endif
