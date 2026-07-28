// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for daemon-issues.md's Issue 4 follow-up hardening:
 * session()'s main loop used to treat ANY select() failure other than
 * EINTR as fatal -- return -1, no cleanup, the whole daemon process
 * exits (main.c just calls session(); return 0;). A real, live bug
 * (since fixed) closed an admin-socket fd directly instead of going
 * through unmonitor_fd(), leaving it registered in the monitored set;
 * the next select() failed with EBADF and took the entire daemon down,
 * including every other still-live Phase 1/2 SA's dummy interface/SPD/
 * routes, over a single dangling fd that had nothing to do with them.
 *
 * prune_stale_monitored_fds() (session.c) is the fix: on EBADF, scan
 * every monitored fd for validity (fcntl(fd, F_GETFD), side-effect-free)
 * and unmonitor_fd() any that are no longer open, so the main loop can
 * recover and keep running instead of exiting unconditionally. This
 * drives that function directly (not the full session() main loop,
 * which needs cfparse()/admin_init()/myaddr_init()/privsep_init() and
 * all the daemon setup this project's own sandbox can't run) with real
 * pipe() fds and a real close() to reproduce the exact "closed elsewhere
 * without unmonitor_fd()" condition, not a simulated one.
 *
 * session.c is pulled in via a local wrapper source
 * (session_unittest_src.c, -ffunction-sections/--gc-sections, same
 * pattern as the other wrapped-static-function tests); monitor_fd()/
 * unmonitor_fd() are already exported (used by evt.c in production),
 * prune_stale_monitored_fds_unittest()/is_fd_monitored_unittest() are
 * new -DENABLE_UNITTEST-only accessors for prune_stale_monitored_fds()
 * (static) and fd_monitors[] (file-scope), respectively.
 *
 *   - test_prune_removes_stale_fd(): monitor a pipe's read end, close()
 *     it directly (not unmonitor_fd() -- reproducing the bug exactly),
 *     then confirm prune_stale_monitored_fds_unittest() reports it found
 *     something and that the fd is no longer monitored afterward.
 *   - test_prune_leaves_valid_fd_alone(): monitor a pipe's read end,
 *     leave it open, confirm prune_stale_monitored_fds_unittest() finds
 *     nothing and the fd is still monitored afterward.
 *   - test_prune_mixed_stale_and_valid(): monitor two fds, close only
 *     one of them directly, confirm only that one gets pruned and the
 *     other survives untouched.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>

extern int monitor_fd(int fd, int (*callback)(void *, int), void *ctx,
    int priority);
extern void unmonitor_fd(int fd);
extern int prune_stale_monitored_fds_unittest(void);
extern int is_fd_monitored_unittest(int fd);
extern void init_fd_monitor_unittest(void);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
dummy_callback(void *ctx, int fd)
{
	return 0;
}

static int
test_prune_removes_stale_fd(void)
{
	int fds[2];

	TEST_START("prune_stale_monitored_fds() drops an fd closed without unmonitor_fd()");

	if (pipe(fds) != 0)
		TEST_FAIL("pipe() failed");

	monitor_fd(fds[0], dummy_callback, NULL, 0);
	if (!is_fd_monitored_unittest(fds[0])) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("monitor_fd() did not register the fd");
	}

	/* Reproduce the bug exactly: close() directly, not unmonitor_fd(). */
	close(fds[0]);

	if (prune_stale_monitored_fds_unittest() != 1) {
		close(fds[1]);
		TEST_FAIL("prune_stale_monitored_fds() did not report finding the stale fd");
	}
	if (is_fd_monitored_unittest(fds[0])) {
		close(fds[1]);
		TEST_FAIL("stale fd is still monitored after pruning");
	}

	close(fds[1]);
	TEST_PASS();
	return 0;
}

static int
test_prune_leaves_valid_fd_alone(void)
{
	int fds[2];

	TEST_START("prune_stale_monitored_fds() leaves a still-open fd untouched");

	if (pipe(fds) != 0)
		TEST_FAIL("pipe() failed");

	monitor_fd(fds[0], dummy_callback, NULL, 0);

	if (prune_stale_monitored_fds_unittest() != 0) {
		unmonitor_fd(fds[0]);
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("prune_stale_monitored_fds() reported a stale fd that was never closed");
	}
	if (!is_fd_monitored_unittest(fds[0])) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("valid fd was unmonitored even though it was never stale");
	}

	unmonitor_fd(fds[0]);
	close(fds[0]);
	close(fds[1]);
	TEST_PASS();
	return 0;
}

static int
test_prune_mixed_stale_and_valid(void)
{
	int stale_fds[2], valid_fds[2];

	TEST_START("prune_stale_monitored_fds() prunes only the stale fd among several monitored");

	if (pipe(stale_fds) != 0)
		TEST_FAIL("pipe() failed (stale)");
	if (pipe(valid_fds) != 0) {
		close(stale_fds[0]);
		close(stale_fds[1]);
		TEST_FAIL("pipe() failed (valid)");
	}

	monitor_fd(stale_fds[0], dummy_callback, NULL, 0);
	monitor_fd(valid_fds[0], dummy_callback, NULL, 1);

	close(stale_fds[0]); /* bypasses unmonitor_fd(), same as the bug */

	if (prune_stale_monitored_fds_unittest() != 1) {
		unmonitor_fd(valid_fds[0]);
		close(stale_fds[1]);
		close(valid_fds[0]);
		close(valid_fds[1]);
		TEST_FAIL("did not report finding the one stale fd among several monitored");
	}
	if (is_fd_monitored_unittest(stale_fds[0])) {
		unmonitor_fd(valid_fds[0]);
		close(stale_fds[1]);
		close(valid_fds[0]);
		close(valid_fds[1]);
		TEST_FAIL("stale fd is still monitored after pruning");
	}
	if (!is_fd_monitored_unittest(valid_fds[0])) {
		close(stale_fds[1]);
		close(valid_fds[0]);
		close(valid_fds[1]);
		TEST_FAIL("valid fd was incorrectly pruned alongside the stale one");
	}

	unmonitor_fd(valid_fds[0]);
	close(stale_fds[1]);
	close(valid_fds[0]);
	close(valid_fds[1]);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== prune_stale_monitored_fds() test (daemon-issues.md Issue 4 follow-up) ===\n");

	init_fd_monitor_unittest();

	if (test_prune_removes_stale_fd() != 0)
		failed++;
	if (test_prune_leaves_valid_fd_alone() != 0)
		failed++;
	if (test_prune_mixed_stale_and_valid() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
