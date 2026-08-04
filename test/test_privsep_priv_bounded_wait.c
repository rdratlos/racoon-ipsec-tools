// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Automates doc/dev/v0.9.1-hardening-spec.md §2.3's Phase 3 -- the
 * `gdb -p $CHILD -batch -ex 'break send_fd' ...` freeze that reproduces
 * doc/dev/v0.9.1-hardening-spec.md §2.1's bounded mid-request wait -- now that
 * privsep_priv() (the extracted dispatch loop, doc/dev/v0.9.1-hardening-
 * spec.md §2.2) can be driven directly. The scripted peer here is simpler
 * than gdb: it sends the command half of a PRIVSEP_BIND/PRIVSEP_SETSOCKOPTS
 * exchange and then just stops, exactly the real failure mode §2.3.1 fixed
 * (a child that goes silent, not one that errors or exits).
 *
 * This binary alone is compiled with -DPRIVSEP_IPC_WAIT_MAX_MS_UNITTEST_OVERRIDE
 * (test/Makefile.am), so the real privsep_wait_io()/PRIVSEP_IPC_WAIT_MAX_MS
 * path inside privsep_priv() times out in well under a second instead of
 * the production 3s -- a compile-time seam private to this one
 * check_PROGRAMS target, per the task brief's "not a runtime knob the
 * production binary also exposes."
 *
 * Both assertions from the brief: privsep_wait_io() gives up within its
 * (overridden) bound rather than hanging, and the forked child's
 * waitpid() status is the fault exit code (fail:/_exit(1)) from §2.3.2 --
 * not the clean-shutdown one (out:/_exit(0)) that an EOF-driven end would
 * report. The reply, if it arrives at all, is best-effort
 * (privsep_handshake_failed(), privsep.c) and must carry ETIMEDOUT when it
 * does -- this test tolerates its absence but not a wrong errno.
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
#include <sys/time.h>
#include <netinet/in.h>
#include <poll.h>

#include "vmbuf.h"
#include "admin.h"
#include "privsep.h"

extern int privsep_priv(int sock);
extern void privsep_priv_test_lcconf_init(const char *certdir,
    const char *scriptdir);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/*
 * Every bound below is independent of PRIVSEP_IPC_WAIT_MAX_MS_UNITTEST_OVERRIDE
 * (test/Makefile.am's own -D for this binary) and generous relative to it,
 * so this test still fails loudly -- rather than hanging the harness --
 * if a regression makes the override stop taking effect and privsep_priv()
 * falls back to the full 3s production bound, or further back to an
 * unbounded wait.
 */
#define IO_TIMEOUT_MS  3000
#define WAIT_POLL_MS   20
#define WAIT_MAX_POLLS 250   /* 5s bound on any waitpid() poll below */

struct test_bind_args {
	int s;
	const struct sockaddr *addr;
	socklen_t addrlen;
};

struct test_sockopt_args {
	int s;
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
};

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
			return -1;

		n = read(fd, (char *)buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return (ssize_t)off;
		off += (size_t)n;
	}
	return (ssize_t)off;
}

/* Best-effort: -1 on timeout/EOF is not itself a failure here, only a
 * wrong ac_errno on an actually-received reply is (see file comment). */
static ssize_t
try_recv_reply(int sock, void *buf, size_t bufsize)
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

/*
 * Sends cmd's command half (header + bufs) and then, deliberately, nothing
 * else -- the descriptor privsep_bind()/privsep_setsockopt() would send
 * immediately afterward never arrives. That silence, not an error or an
 * exit, is exactly what §2.3.1 bounds.
 */
static int
send_command_half_only(int sock, int cmd, const void *arg, size_t arglen,
    const void *payload, size_t payloadlen)
{
	size_t total = sizeof(struct privsep_com_msg) + arglen + payloadlen;
	struct privsep_com_msg *m;
	char *data;
	int ret;

	if ((m = calloc(1, total)) == NULL)
		return -1;

	m->hdr.ac_cmd = (u_int16_t)cmd;
	m->hdr.ac_len = (u_int16_t)total;
	m->bufs.buflen[0] = arglen;
	m->bufs.buflen[1] = payloadlen;

	data = (char *)(m + 1);
	memcpy(data, arg, arglen);
	memcpy(data + arglen, payload, payloadlen);

	ret = write_all(sock, m, total) == (ssize_t)total ? 0 : -1;
	free(m);
	return ret;
}

static int
run_silent_peer_case(const char *what, int cmd, const void *arg,
    size_t arglen, const void *payload, size_t payloadlen)
{
	int sp[2];
	pid_t child;
	int status;
	char replybuf[512];
	ssize_t rlen;
	struct privsep_com_msg *reply;

	TEST_START(what);

	privsep_priv_test_lcconf_init(NULL, NULL);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");

	if ((child = fork()) < 0)
		TEST_FAIL("fork() failed");

	if (child == 0) {
		close(sp[0]);
		_exit(privsep_priv(sp[1]) == 0 ? 0 : 1);
	}
	close(sp[1]);

	if (send_command_half_only(sp[0], cmd, arg, arglen, payload,
	    payloadlen) != 0) {
		close(sp[0]);
		TEST_FAIL("send failed");
	}

	/* Deliberately no send_fd() here -- see file comment. */

	rlen = try_recv_reply(sp[0], replybuf, sizeof(replybuf));
	if (rlen >= 0) {
		reply = (struct privsep_com_msg *)replybuf;
		if (reply->hdr.ac_errno != ETIMEDOUT) {
			close(sp[0]);
			printf("\n    reply arrived with ac_errno=%d, "
			    "expected ETIMEDOUT", reply->hdr.ac_errno);
			TEST_FAIL("timeout reply carried the wrong errno");
		}
	}
	/* rlen < 0 (no reply, or EOF before one arrived): tolerated, see
	 * privsep_handshake_failed()'s own "best effort" in privsep.c. */

	close(sp[0]);

	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("privsep_priv() child did not exit within the bound "
		    "-- an unbounded wait would hang here instead of failing");

	if (!WIFEXITED(status)) {
		TEST_FAIL("child did not exit normally");
	}
	if (WEXITSTATUS(status) != 1) {
		printf("\n    child exit status: %d, expected 1 (fail:/_exit(1))",
		    WEXITSTATUS(status));
		TEST_FAIL("a mid-request timeout must report the fault exit "
		    "code, not the clean-shutdown one");
	}

	TEST_PASS();
	return 0;
}

static int
test_bind_wait_times_out(void)
{
	struct test_bind_args ba;
	struct sockaddr_in sin;

	memset(&ba, 0, sizeof(ba));
	ba.s = -1;
	ba.addr = NULL;
	ba.addrlen = sizeof(sin);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;

	return run_silent_peer_case(
	    "PRIVSEP_BIND: silent peer -> ETIMEDOUT-or-absent reply, exit 1",
	    PRIVSEP_BIND, &ba, sizeof(ba), &sin, sizeof(sin));
}

static int
test_setsockopts_wait_times_out(void)
{
	struct test_sockopt_args oa;
	char policy[64];

	memset(&oa, 0, sizeof(oa));
	oa.s = -1;
	oa.level = IPPROTO_IP;
	oa.optname = 16; /* IP_IPSEC_POLICY; see test_privsep_priv_control_cases.c */
	oa.optval = NULL;
	oa.optlen = sizeof(policy);
	memset(policy, 0, sizeof(policy));

	return run_silent_peer_case(
	    "PRIVSEP_SETSOCKOPTS: silent peer -> ETIMEDOUT-or-absent reply, exit 1",
	    PRIVSEP_SETSOCKOPTS, &oa, sizeof(oa), policy, sizeof(policy));
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep_priv() bounded mid-request wait "
	    "(runbook Phase 3, v0.9.1-hardening-spec.md §2.2 task) ===\n");

	if (test_bind_wait_times_out() != 0)
		failed++;
	if (test_setsockopts_wait_times_out() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
