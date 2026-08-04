// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for monitor_fd()'s self-enforcing fd_monitor_tree[]
 * initialization (doc/dev/v0.9.1-hardening-spec.md §2.4).
 *
 * fd_monitor_tree[] (session.c, a static array of TAILQ_HEADs) is safe to
 * insert into only after TAILQ_INIT() has run on it. In production that
 * always happens well before monitor_fd()'s first real call --
 * session_init_before_cfparse() (session.c) runs it at daemon startup,
 * long before privsep_init() (privsep.c) ever forks the child whose own
 * privilege-drop branch calls monitor_fd(). Every *other* monitor_fd()
 * test in this suite (test_monitor_fd_range.c,
 * test_prune_stale_monitored_fds.c) calls init_fd_monitor_unittest()
 * before its own first monitor_fd() call, mirroring that same safe
 * ordering -- which means none of them can catch a regression in the
 * guard this test exists for.
 *
 * This binary's only job is to call monitor_fd() as the very first thing
 * this process ever does that could touch fd_monitor_tree[] at all --
 * with no init_fd_monitor_unittest() call anywhere, in this file or
 * pulled in from elsewhere. That is the same "call it cold" condition
 * that segfaulted test_privsep_init.c's real forked child (calling
 * privsep_init() directly, with none of session()'s own startup having
 * run) before monitor_fd() gained its own one-time-init guard. If that
 * guard ever regresses, this test crashes the same way privsep_init()'s
 * child did -- which the test harness records as a distinct failure, not
 * merely a failed assertion.
 *
 * session.c is pulled in via the same local wrapper source
 * (session_unittest_src.c, -ffunction-sections/--gc-sections) the other
 * monitor_fd() tests use; is_fd_monitored_unittest() is the same
 * pre-existing -DENABLE_UNITTEST accessor they use too. Deliberately
 * does *not* link/call init_fd_monitor_unittest() at all.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>

extern int monitor_fd(int fd, int (*callback)(void *, int), void *ctx,
    int priority);
extern int is_fd_monitored_unittest(int fd);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
dummy_callback(void *ctx, int fd)
{
	return 0;
}

static int
test_monitor_fd_before_any_init(void)
{
	int fds[2];

	TEST_START("monitor_fd() survives being called before "
	    "session_init_before_cfparse() ever ran");

	if (pipe(fds) != 0)
		TEST_FAIL("pipe() failed");

	/* fd_monitor_tree[] is still its untouched, all-zero static
	 * default here -- no TAILQ_INIT() has run on it anywhere in this
	 * process yet. A regression in monitor_fd()'s own guard crashes
	 * this process right here, not later. */
	if (monitor_fd(fds[0], dummy_callback, NULL, 0) != 0) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("monitor_fd() refused a perfectly valid fd");
	}

	if (!is_fd_monitored_unittest(fds[0])) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("fd was not actually registered");
	}

	close(fds[0]);
	close(fds[1]);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== monitor_fd(), called cold -- no fd_monitor_tree[] init "
	    "anywhere first (v0.9.1-hardening-spec.md §2.4) "
	    "===\n");

	if (test_monitor_fd_before_any_init() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
	return failed == 0 ? 0 : 1;
}
