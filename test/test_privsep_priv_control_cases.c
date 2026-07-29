// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * "A well-formed control case per command family" (privsep-priv-extraction
 * task, §3) -- the part of doc/dev/privsep-verification-runbook.md's Phase
 * 1 table that a unit test can actually reach: PRIVSEP_EAY_GET_PKCS1PRIVKEY,
 * PRIVSEP_GETPSK, PRIVSEP_SOCKET, PRIVSEP_BIND, PRIVSEP_SETSOCKOPTS and
 * PRIVSEP_SCRIPT_EXEC, driven in one continuous privsep_priv() session over
 * a real socketpair(), with a real fork() playing the privileged side.
 *
 * The point of this file, distinct from test_privsep_priv_containment.c: a
 * regression that makes *every* request fail (not just the deliberately bad
 * ones) would not be caught by a suite that only ever sends malformed
 * input -- fatal-exit-path-audit.md's §1 rule 1 ("containment must not
 * silently succeed") applies just as much to this test suite itself.
 * Running every command in one session, in sequence, also doubles as the
 * closest a unit test gets to the runbook's Phase 2 framing check: each
 * later command only succeeds if the previous one left privsep_sock
 * exactly where the protocol expects, so six requests, six replies, in
 * order, over one child that never exits early, is itself evidence against
 * drift -- see test_privsep_priv_framing.c for the case built to fail loud
 * if that drift ever appears.
 *
 * ENABLE_HYBRID's own two commands (PRIVSEP_ACCOUNTING_SYSTEM,
 * PRIVSEP_XAUTH_LOGIN_SYSTEM) are outside this file's scope: they are not
 * part of the runbook's six-command Phase 1 table this task is replacing,
 * and privsep_priv_test_stubs.c stubs them only so the switch they sit in
 * still links.
 *
 * The PRIVSEP_SOCKET/PRIVSEP_BIND/PRIVSEP_SETSOCKOPTS/PRIVSEP_SCRIPT_EXEC
 * requests below reproduce the wire shape privsep.c's own client functions
 * (privsep_socket()/privsep_bind()/privsep_setsockopt()/
 * privsep_script_exec()) build, without calling those functions: they
 * early-return via the real syscall when geteuid() == 0, which is exactly
 * how this suite is expected to run (containers/CI), so calling them here
 * would silently skip the wire protocol entirely instead of exercising it.
 * struct socket_args/bind_args/sockopt_args are file-private to privsep.c
 * by design (task brief §1: their shape is explicitly out of scope to
 * change here); this file only mirrors their existing layout, the same way
 * doc/dev/privsep-verification-runbook.md's LD_PRELOAD shim (§5b) already
 * treats the wire format as a stable, external contract.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

#include "vmbuf.h"
#include "admin.h"
#include "privsep.h"
#include "isakmp_var.h"
#include "remoteconf.h"

extern int privsep_priv(int sock);
extern void privsep_priv_test_lcconf_init(const char *certdir,
    const char *scriptdir);
extern int privsep_send_fd_unittest(int s, int fd);
extern int privsep_rec_fd_unittest(int s);

/* Mirrors privsep.c's file-private struct socket_args -- see file comment. */
struct test_socket_args {
	int domain;
	int type;
	int protocol;
};

/* Mirrors privsep.c's file-private struct bind_args. */
struct test_bind_args {
	int s;
	const struct sockaddr *addr;
	socklen_t addrlen;
};

/* Mirrors privsep.c's file-private struct sockopt_args. */
struct test_sockopt_args {
	int s;
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
};

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

#define WAIT_POLL_MS   20
#define WAIT_MAX_POLLS 250   /* 5s bound on any waitpid() poll below */

/*
 * IO_TIMEOUT_MS bounds every read below via poll() -- fatal-exit-path-audit.md
 * §1 rule 2 applies to this suite's own blocking waits as much as to
 * privsep.c: a regression that reintroduces an unbounded wait in
 * privsep_priv() must fail this test loudly (a read that gives up), not
 * hang the harness the same way. 5s is far above anything a healthy
 * exchange over a local socketpair needs.
 */
#define IO_TIMEOUT_MS 5000

static ssize_t
write_all(int fd, const void *buf, size_t len)
{
	size_t off = 0;
	ssize_t n;

	while (off < len) {
		n = write(fd, (const char *)buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return (ssize_t)off;
}

static int
elapsed_ms_since(const struct timeval *start)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	return (int)((now.tv_sec - start->tv_sec) * 1000 +
	    (now.tv_usec - start->tv_usec) / 1000);
}

/* read(), bounded by timeout_ms via poll() rather than a plain blocking
 * read -- see IO_TIMEOUT_MS above. */
static ssize_t
read_all_bounded(int fd, void *buf, size_t len, int timeout_ms)
{
	size_t off = 0;
	ssize_t n;
	struct timeval start;
	struct pollfd pfd;
	int remaining, pr;

	gettimeofday(&start, NULL);

	while (off < len) {
		remaining = timeout_ms - elapsed_ms_since(&start);
		if (remaining <= 0)
			return -1;

		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		pr = poll(&pfd, 1, remaining);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (pr == 0)
			return -1; /* timed out */

		n = read(fd, (char *)buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return (ssize_t)off; /* EOF */
		off += (size_t)n;
	}
	return (ssize_t)off;
}

/* Builds a struct privsep_com_msg with up to PRIVSEP_NBUF_MAX buffers. */
static struct privsep_com_msg *
build_msg(int cmd, size_t nbufs, const void *const *ptrs, const size_t *lens,
    size_t *out_len)
{
	size_t total = sizeof(struct privsep_com_msg);
	size_t i;
	struct privsep_com_msg *m;
	char *data;

	for (i = 0; i < nbufs; i++)
		total += lens[i];

	if ((m = calloc(1, total)) == NULL)
		return NULL;

	m->hdr.ac_cmd = (u_int16_t)cmd;
	m->hdr.ac_len = (u_int16_t)total;

	data = (char *)(m + 1);
	for (i = 0; i < nbufs; i++) {
		m->bufs.buflen[i] = lens[i];
		if (lens[i] != 0)
			memcpy(data, ptrs[i], lens[i]);
		data += lens[i];
	}

	*out_len = total;
	return m;
}

static int
send_request(int sock, int cmd, size_t nbufs, const void *const *ptrs,
    const size_t *lens)
{
	struct privsep_com_msg *m;
	size_t len;
	int ret;

	if ((m = build_msg(cmd, nbufs, ptrs, lens, &len)) == NULL)
		return -1;
	ret = write_all(sock, m, len) == (ssize_t)len ? 0 : -1;
	free(m);
	return ret;
}

/* Reads exactly one reply into buf, bounded by IO_TIMEOUT_MS; returns its
 * total length or -1. */
static ssize_t
recv_reply(int sock, void *buf, size_t bufsize)
{
	struct admin_com hdr;
	ssize_t n;

	n = read_all_bounded(sock, &hdr, sizeof(hdr), IO_TIMEOUT_MS);
	if (n != (ssize_t)sizeof(hdr))
		return -1;
	if (hdr.ac_len < sizeof(hdr) || (size_t)hdr.ac_len > bufsize)
		return -1;

	memcpy(buf, &hdr, sizeof(hdr));
	n = read_all_bounded(sock, (char *)buf + sizeof(hdr),
	    hdr.ac_len - sizeof(hdr), IO_TIMEOUT_MS);
	if (n != (ssize_t)(hdr.ac_len - sizeof(hdr)))
		return -1;

	return hdr.ac_len;
}

/* Bounded: never blocks the harness indefinitely (fatal-exit-path-audit.md
 * §1 rule 2, applied to this test suite as much as to privsep.c itself). */
static int
wait_child_bounded(pid_t child, int *status)
{
	int i;
	pid_t ret;

	for (i = 0; i < WAIT_MAX_POLLS; i++) {
		ret = waitpid(child, status, WNOHANG);
		if (ret == child)
			return 0;
		usleep(WAIT_POLL_MS * 1000);
	}
	kill(child, SIGKILL);
	waitpid(child, status, 0);
	return -1;
}

static int
test_control_cases(void)
{
	int sp[2];
	pid_t child;
	int status;
	char scriptdir[] = "/tmp/privsep_priv_control_scripts.XXXXXX";
	char scriptpath[1024];
	FILE *f;
	char replybuf[4096];
	ssize_t rlen;
	struct privsep_com_msg *reply;
	int failed = 0;

	TEST_START("well-formed request/reply for every non-HYBRID command family");

	if (mkdtemp(scriptdir) == NULL)
		TEST_FAIL("mkdtemp() failed");
	snprintf(scriptpath, sizeof(scriptpath), "%s/phase1-up.sh", scriptdir);
	if ((f = fopen(scriptpath, "w")) == NULL)
		TEST_FAIL("could not create test script file");
	fclose(f);

	privsep_priv_test_lcconf_init(NULL, scriptdir);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");

	if ((child = fork()) < 0)
		TEST_FAIL("fork() failed");

	if (child == 0) {
		close(sp[0]);
		_exit(privsep_priv(sp[1]) == 0 ? 0 : 1);
	}
	close(sp[1]);

	/* --- PRIVSEP_EAY_GET_PKCS1PRIVKEY --- */
	{
		const char path[] = "/tmp/certs/good.pem";
		const void *ptrs[1] = { path };
		size_t lens[1] = { sizeof(path) };

		if (send_request(sp[0], PRIVSEP_EAY_GET_PKCS1PRIVKEY, 1, ptrs, lens) != 0) {
			printf("\n    send failed"); failed++;
		} else if ((rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
			printf("\n    EAY_GET_PKCS1PRIVKEY: no reply"); failed++;
		} else {
			reply = (struct privsep_com_msg *)replybuf;
			if (reply->hdr.ac_errno != 0) {
				printf("\n    EAY_GET_PKCS1PRIVKEY: ac_errno=%d", reply->hdr.ac_errno);
				failed++;
			} else if ((size_t)rlen <= sizeof(*reply) ||
			    memcmp(reply + 1, "stub-pkcs1-private-key",
			        strlen("stub-pkcs1-private-key")) != 0) {
				printf("\n    EAY_GET_PKCS1PRIVKEY: unexpected key payload");
				failed++;
			}
		}
	}

	/* --- PRIVSEP_GETPSK --- */
	{
		const char ident[] = "test-identity";
		int keylen = 16;
		const void *ptrs[2] = { ident, &keylen };
		size_t lens[2] = { sizeof(ident), sizeof(keylen) };

		if (send_request(sp[0], PRIVSEP_GETPSK, 2, ptrs, lens) != 0) {
			printf("\n    send failed"); failed++;
		} else if ((rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
			printf("\n    GETPSK: no reply"); failed++;
		} else {
			reply = (struct privsep_com_msg *)replybuf;
			if (reply->hdr.ac_errno != 0) {
				printf("\n    GETPSK: ac_errno=%d", reply->hdr.ac_errno);
				failed++;
			} else if ((size_t)rlen <= sizeof(*reply) ||
			    memcmp(reply + 1, "stub-psk-secret!",
			        strlen("stub-psk-secret!")) != 0) {
				printf("\n    GETPSK: unexpected psk payload");
				failed++;
			}
		}
	}

	/* --- PRIVSEP_SOCKET --- */
	{
		struct test_socket_args sa;
		const void *ptrs[1] = { &sa };
		size_t lens[1] = { sizeof(sa) };
		int recvd_fd;

		memset(&sa, 0, sizeof(sa));
		sa.domain = PF_INET;
		sa.type = SOCK_DGRAM;
		sa.protocol = 0;

		if (send_request(sp[0], PRIVSEP_SOCKET, 1, ptrs, lens) != 0) {
			printf("\n    send failed"); failed++;
		} else if ((recvd_fd = privsep_rec_fd_unittest(sp[0])) < 0) {
			printf("\n    SOCKET: no descriptor received"); failed++;
		} else if ((rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
			close(recvd_fd);
			printf("\n    SOCKET: no reply"); failed++;
		} else {
			reply = (struct privsep_com_msg *)replybuf;
			if (reply->hdr.ac_errno != 0) {
				printf("\n    SOCKET: ac_errno=%d", reply->hdr.ac_errno);
				failed++;
			} else if (fcntl(recvd_fd, F_GETFD) < 0) {
				printf("\n    SOCKET: received descriptor is not valid");
				failed++;
			}
			close(recvd_fd);
		}
	}

	/* --- PRIVSEP_BIND --- */
	{
		int s;
		struct sockaddr_in sin;
		struct test_bind_args ba;
		const void *ptrs[2];
		size_t lens[2];
		socklen_t slen;

		if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
			printf("\n    BIND: socket() failed"); failed++;
			goto bind_done;
		}

		/*
		 * Every real caller of privsep_bind() (isakmp.c's own socket
		 * setup) sets this before ever reaching it -- SO_REUSEADDR
		 * on Linux, SO_REUSEPORT elsewhere, the same #ifdef split
		 * isakmp.c itself uses. Without it, this test's own bind to
		 * PORT_ISAKMP_NATT below collides with EADDRINUSE on any
		 * host already running a real racoon (or another NAT-T
		 * listener) bound to that port system-wide -- an environment
		 * difference, not a wire-protocol bug, but the test wasn't
		 * reproducing what a real client actually does either.
		 */
		{
			int yes = 1;
			if (setsockopt(s, SOL_SOCKET,
#ifdef __linux__
			    SO_REUSEADDR,
#else
			    SO_REUSEPORT,
#endif
			    &yes, sizeof(yes)) != 0) {
				printf("\n    BIND: setsockopt(REUSE) failed");
				failed++;
				close(s);
				goto bind_done;
			}
		}

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(PORT_ISAKMP_NATT);
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		memset(&ba, 0, sizeof(ba));
		ba.s = -1;
		ba.addr = NULL;
		ba.addrlen = sizeof(sin);

		ptrs[0] = &ba; lens[0] = sizeof(ba);
		ptrs[1] = &sin; lens[1] = sizeof(sin);

		if (send_request(sp[0], PRIVSEP_BIND, 2, ptrs, lens) != 0) {
			printf("\n    send failed"); failed++;
		} else if (privsep_send_fd_unittest(sp[0], s) != 0) {
			printf("\n    BIND: send_fd() failed"); failed++;
		} else if ((rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
			printf("\n    BIND: no reply"); failed++;
		} else {
			reply = (struct privsep_com_msg *)replybuf;
			if (reply->hdr.ac_errno != 0) {
				printf("\n    BIND: ac_errno=%d", reply->hdr.ac_errno);
				failed++;
			} else {
				struct sockaddr_in bound;
				slen = sizeof(bound);
				if (getsockname(s, (struct sockaddr *)&bound, &slen) != 0 ||
				    ntohs(bound.sin_port) != PORT_ISAKMP_NATT) {
					printf("\n    BIND: descriptor was not actually bound");
					failed++;
				}
			}
		}
		close(s);
	}
bind_done:

	/* --- PRIVSEP_SETSOCKOPTS --- */
	{
		int s;
		struct test_sockopt_args oa;
		char policy[256];
		const void *ptrs[2];
		size_t lens[2];

		if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
			printf("\n    SETSOCKOPTS: socket() failed"); failed++;
			goto setsockopts_done;
		}

		memset(policy, 0, sizeof(policy));
		memset(&oa, 0, sizeof(oa));
		oa.s = -1;
		oa.level = IPPROTO_IP;
#ifndef IP_IPSEC_POLICY
#define IP_IPSEC_POLICY 16
#endif
		oa.optname = IP_IPSEC_POLICY;
		oa.optval = NULL;
		oa.optlen = sizeof(policy);

		ptrs[0] = &oa; lens[0] = sizeof(oa);
		ptrs[1] = policy; lens[1] = sizeof(policy);

		if (send_request(sp[0], PRIVSEP_SETSOCKOPTS, 2, ptrs, lens) != 0) {
			printf("\n    send failed"); failed++;
		} else if (privsep_send_fd_unittest(sp[0], s) != 0) {
			printf("\n    SETSOCKOPTS: send_fd() failed"); failed++;
		} else if ((rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
			printf("\n    SETSOCKOPTS: no reply"); failed++;
		} else {
			reply = (struct privsep_com_msg *)replybuf;
			/*
			 * Not "== 0": a garbage-but-correctly-shaped policy
			 * blob is the kernel's business (EOPNOTSUPP/EINVAL on
			 * this sandbox, observed empirically), not privsep's.
			 * What privsep_setsockopt()'s policy gate promises is
			 * that IP_IPSEC_POLICY at IPPROTO_IP is let through to
			 * the real setsockopt() at all -- EPERM is what the
			 * gate itself would answer for a disallowed optname,
			 * so that specifically must not come back here.
			 *
			 * But EPERM is not unambiguous evidence of that: on
			 * Linux, xfrm's own setsockopt(IP_IPSEC_POLICY, ...)
			 * returns EPERM for an unprivileged (no CAP_NET_ADMIN)
			 * process regardless of what the gate did -- the exact
			 * ambiguity issue #105 pins for privsep_setsockopt()
			 * itself (test_privsep_setsockopt.c). This binary is
			 * forked from whatever ran `make check`, which is root
			 * in the containers/CI this suite targets but not
			 * guaranteed to be for a human running it locally, so
			 * only geteuid() == 0 rules the kernel's own privilege
			 * check out and leaves the gate as the sole source.
			 */
			if (reply->hdr.ac_errno == EPERM && geteuid() == 0) {
				printf("\n    SETSOCKOPTS: policy gate refused an authorized option");
				failed++;
			}
		}
		close(s);
	}
setsockopts_done:

	/* --- PRIVSEP_SCRIPT_EXEC --- */
	{
		int name = SCRIPT_PHASE1_UP;
		const void *ptrs[3];
		size_t lens[3];

		ptrs[0] = scriptpath; lens[0] = strlen(scriptpath) + 1;
		ptrs[1] = &name; lens[1] = sizeof(name);
		ptrs[2] = NULL; lens[2] = 0; /* void terminator: envc == 0 */

		if (send_request(sp[0], PRIVSEP_SCRIPT_EXEC, 3, ptrs, lens) != 0) {
			printf("\n    send failed"); failed++;
		} else if ((rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
			printf("\n    SCRIPT_EXEC: no reply"); failed++;
		} else {
			reply = (struct privsep_com_msg *)replybuf;
			if (reply->hdr.ac_errno != 0) {
				printf("\n    SCRIPT_EXEC: ac_errno=%d (refused an "
				    "authorized script)", reply->hdr.ac_errno);
				failed++;
			}
		}
	}

	/* Clean shutdown: EOF makes privsep_priv() take "out:"/_exit(0). */
	close(sp[0]);

	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("privsep_priv() child did not exit after EOF");

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("\n    child exit status: %d", status);
		printf("\n    a clean EOF-driven shutdown must report exit 0");
		failed++;
	}

	unlink(scriptpath);
	rmdir(scriptdir);

	if (failed != 0)
		TEST_FAIL("one or more command families did not round-trip cleanly");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep_priv() well-formed control cases "
	    "(privsep-priv-extraction task) ===\n");

	if (test_control_cases() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
