// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression/coverage test for session_wait_and_dispatch() -- the body of
 * session()'s live main loop (select() + error recovery + fd dispatch),
 * extracted verbatim (no behavior change) so it can be driven directly
 * instead of needing the full daemon startup (cfparse()/admin_init()/
 * myaddr_init()/privsep_init()) session()'s own while(1) otherwise
 * requires to ever reach this code at all.
 *
 * Four scenarios, matching the four distinct outcomes
 * session_wait_and_dispatch() can produce:
 *
 *   - test_normal_dispatch_fires_callback_once(): a real socketpair() fd
 *     made readable is dispatched to its registered callback exactly
 *     once, and the call reports success (0).
 *   - test_ebadf_recovery_reaches_prune(): reproduces doc/dev/v0.9.1-hardening-spec.md
 *     §5.6's Issue 4 follow-up exactly -- close() a monitored fd directly
 *     (bypassing unmonitor_fd()), confirming the resulting EBADF is
 *     recovered via prune_stale_monitored_fds() (already covered in
 *     isolation by test_prune_stale_monitored_fds.c; this test's job is
 *     confirming it is actually reached from *this* call site) rather
 *     than falling through to the fatal default case.
 *   - test_eintr_causes_retry_not_fatal(): a real signal delivered during
 *     select() must cause a recoverable (0) return, not the fatal (-1)
 *     one.
 *   - test_unrecovered_select_error_is_fatal(): the one path that
 *     intentionally propagates failure -- an invalid *timeout makes
 *     select() fail with EINVAL, neither EINTR nor EBADF, and the
 *     function must report it (-1) rather than swallow or "fix" it.
 *
 * session.c is pulled in via the same local wrapper source
 * (session_unittest_src.c, -ffunction-sections/--gc-sections) and the
 * same setup accessors (init_fd_monitor_unittest(), monitor_fd(),
 * unmonitor_fd(), is_fd_monitored_unittest()) that
 * test_monitor_fd_range.c and test_prune_stale_monitored_fds.c already
 * use; session_wait_and_dispatch_unittest() is the one new
 * -DENABLE_UNITTEST-only accessor, for session_wait_and_dispatch()
 * itself (static).
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

extern int monitor_fd(int fd, int (*callback)(void *, int), void *ctx,
    int priority);
extern void unmonitor_fd(int fd);
extern int is_fd_monitored_unittest(int fd);
extern void init_fd_monitor_unittest(void);
extern int session_wait_and_dispatch_unittest(struct timeval *timeout);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int dispatch_calls;

static int
counting_callback(void *ctx, int fd)
{
	dispatch_calls++;
	return 0;
}

static int
dummy_callback(void *ctx, int fd)
{
	return 0;
}

static int
test_normal_dispatch_fires_callback_once(void)
{
	int sv[2];
	struct timeval timeout;
	int rv;
	char byte = 'x';

	TEST_START("a readable monitored fd is dispatched to its callback exactly once");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		TEST_FAIL("socketpair() failed");

	dispatch_calls = 0;
	if (monitor_fd(sv[0], counting_callback, NULL, 0) != 0) {
		close(sv[0]);
		close(sv[1]);
		TEST_FAIL("monitor_fd() refused a perfectly valid fd");
	}

	if (write(sv[1], &byte, 1) != 1) {
		unmonitor_fd(sv[0]);
		close(sv[0]);
		close(sv[1]);
		TEST_FAIL("write() to the peer socket failed");
	}

	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	rv = session_wait_and_dispatch_unittest(&timeout);

	if (rv != 0) {
		unmonitor_fd(sv[0]);
		close(sv[0]);
		close(sv[1]);
		TEST_FAIL("session_wait_and_dispatch() reported a fatal error for a normal dispatch");
	}
	if (dispatch_calls != 1) {
		unmonitor_fd(sv[0]);
		close(sv[0]);
		close(sv[1]);
		TEST_FAIL("callback did not fire exactly once");
	}

	unmonitor_fd(sv[0]);
	close(sv[0]);
	close(sv[1]);
	TEST_PASS();
	return 0;
}

static int
test_ebadf_recovery_reaches_prune(void)
{
	int fds[2];
	struct timeval timeout;
	int rv;

	TEST_START("EBADF from a stale monitored fd is recovered via prune_stale_monitored_fds()");

	if (pipe(fds) != 0)
		TEST_FAIL("pipe() failed");

	if (monitor_fd(fds[0], dummy_callback, NULL, 0) != 0) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("monitor_fd() refused a perfectly valid fd");
	}

	/* Reproduce v0.9.1-hardening-spec.md §5.6's Issue 4 follow-up exactly: close()
	 * directly, bypassing unmonitor_fd(), leaving a stale entry that
	 * fails the very next select() with EBADF. */
	close(fds[0]);

	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	rv = session_wait_and_dispatch_unittest(&timeout);

	if (rv != 0) {
		close(fds[1]);
		TEST_FAIL("session_wait_and_dispatch() did not recover from EBADF (returned fatal)");
	}
	if (is_fd_monitored_unittest(fds[0])) {
		close(fds[1]);
		TEST_FAIL("stale fd is still monitored -- prune_stale_monitored_fds() was not reached");
	}

	close(fds[1]);
	TEST_PASS();
	return 0;
}

static volatile sig_atomic_t sigalrm_delivered;

static void
sigalrm_handler(int sig)
{
	sigalrm_delivered = 1;
}

static int
test_eintr_causes_retry_not_fatal(void)
{
	struct sigaction sa, old_sa;
	struct itimerval it;
	struct timeval timeout;
	int rv;

	TEST_START("a signal interrupting select() causes a retry (0), not a fatal return (-1)");

	sigalrm_delivered = 0;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigalrm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; /* deliberately no SA_RESTART -- select()/pselect()
			  * are never auto-restarted regardless, but this
			  * documents the intent explicitly. */
	if (sigaction(SIGALRM, &sa, &old_sa) != 0)
		TEST_FAIL("sigaction() failed");

	/* No fd monitored right now (nfds == 0, preset_mask empty), so
	 * select() just blocks for the timeout below until interrupted. */
	memset(&it, 0, sizeof(it));
	it.it_value.tv_sec = 0;
	it.it_value.tv_usec = 200000; /* 200ms */
	if (setitimer(ITIMER_REAL, &it, NULL) != 0) {
		sigaction(SIGALRM, &old_sa, NULL);
		TEST_FAIL("setitimer() failed");
	}

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	rv = session_wait_and_dispatch_unittest(&timeout);

	sigaction(SIGALRM, &old_sa, NULL);

	if (!sigalrm_delivered)
		TEST_FAIL("SIGALRM was never delivered -- test did not exercise EINTR");
	if (rv != 0)
		TEST_FAIL("session_wait_and_dispatch() treated EINTR as fatal");

	TEST_PASS();
	return 0;
}

static int
test_unrecovered_select_error_is_fatal(void)
{
	struct timeval timeout;
	int rv;

	TEST_START("an unrecovered select() failure (neither EINTR nor EBADF) is reported as fatal (-1)");

	/* No fd monitored (nfds == 0), so this cannot be misread as
	 * EBADF -- an invalid timeval (tv_usec out of [0, 1000000)) makes
	 * select() itself fail with EINVAL instead, immediately. */
	timeout.tv_sec = 0;
	timeout.tv_usec = -1;
	rv = session_wait_and_dispatch_unittest(&timeout);

	if (rv != -1)
		TEST_FAIL("session_wait_and_dispatch() did not propagate an unrecovered select() failure");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== session_wait_and_dispatch() test (session()'s live main loop body) ===\n");

	init_fd_monitor_unittest();

	if (test_normal_dispatch_fires_callback_once() != 0)
		failed++;
	init_fd_monitor_unittest();
	if (test_ebadf_recovery_reaches_prune() != 0)
		failed++;
	init_fd_monitor_unittest();
	if (test_eintr_causes_retry_not_fatal() != 0)
		failed++;
	init_fd_monitor_unittest();
	if (test_unrecovered_select_error_is_fatal() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
