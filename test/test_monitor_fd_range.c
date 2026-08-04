// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for the monitor_fd()/unmonitor_fd() half of issue #105
 * (the audit that followed #102's prune_stale_monitored_fds()): a fault
 * scoped to a single request or connection must not end the whole daemon.
 *
 * Both functions (session.c) used to exit(1) when handed a descriptor
 * outside the fd_set range. That descriptor is not a fixed daemon-wide
 * resource: besides the pfkey/routing/admin-listener sockets opened once
 * at startup, monitor_fd() is also called for every accepted admin
 * connection that asks for events (evt_subscribe(), evt.c) and for every
 * ISAKMP socket opened for an address that appears while running
 * (isakmp_open(), isakmp.c). Whether such a descriptor lands past
 * FD_SETSIZE depends only on how many descriptors the process happens to
 * hold at that moment -- so "this one racoonctl connection cannot be
 * watched" used to mean "every live Phase 1/2 SA dies", exactly the
 * disproportionate failure shape #102 removed from session()'s select()
 * loop.
 *
 * monitor_fd() now reports -1 and lets its caller drop just that
 * connection or socket; unmonitor_fd() just returns (nothing was ever
 * registered for such a descriptor, so there is nothing to undo).
 *
 * Note how this test detects a regression: if either function goes back
 * to exiting, this process dies right there and the harness records the
 * failure -- the checks below are only reached when it does not.
 *
 * session.c is pulled in via the same local wrapper source
 * (session_unittest_src.c, -ffunction-sections/--gc-sections) and the
 * same -DENABLE_UNITTEST accessors (init_fd_monitor_unittest(),
 * is_fd_monitored_unittest()) that test_prune_stale_monitored_fds.c uses.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>

extern int monitor_fd(int fd, int (*callback)(void *, int), void *ctx,
    int priority);
extern void unmonitor_fd(int fd);
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
test_monitor_rejects_fd_above_range(void)
{
	TEST_START("monitor_fd() refuses an fd at/above FD_SETSIZE instead of exiting");

	if (monitor_fd(FD_SETSIZE, dummy_callback, NULL, 0) == 0)
		TEST_FAIL("monitor_fd() reported success for an out-of-range fd");

	if (monitor_fd(FD_SETSIZE + 1, dummy_callback, NULL, 0) == 0)
		TEST_FAIL("monitor_fd() reported success for an out-of-range fd");

	TEST_PASS();
	return 0;
}

static int
test_monitor_rejects_negative_fd(void)
{
	TEST_START("monitor_fd() refuses a negative fd instead of exiting");

	if (monitor_fd(-1, dummy_callback, NULL, 0) == 0)
		TEST_FAIL("monitor_fd() reported success for a negative fd");

	TEST_PASS();
	return 0;
}

static int
test_unmonitor_tolerates_out_of_range_fd(void)
{
	TEST_START("unmonitor_fd() tolerates an out-of-range fd instead of exiting");

	/* Nothing to assert beyond surviving these calls. */
	unmonitor_fd(FD_SETSIZE);
	unmonitor_fd(-1);

	TEST_PASS();
	return 0;
}

/*
 * The rejection above must not disturb the monitoring state a real daemon
 * depends on: the refused connection is dropped, every other watched
 * descriptor keeps working.
 */
static int
test_valid_fd_still_monitored_after_rejection(void)
{
	int fds[2];

	TEST_START("a refused fd leaves an already-monitored fd untouched");

	if (pipe(fds) != 0)
		TEST_FAIL("pipe() failed");

	if (monitor_fd(fds[0], dummy_callback, NULL, 0) != 0) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("monitor_fd() refused a perfectly valid fd");
	}

	(void)monitor_fd(FD_SETSIZE, dummy_callback, NULL, 0);
	(void)unmonitor_fd(FD_SETSIZE);

	if (!is_fd_monitored_unittest(fds[0])) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("valid fd stopped being monitored after an out-of-range call");
	}

	unmonitor_fd(fds[0]);
	if (is_fd_monitored_unittest(fds[0])) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("unmonitor_fd() did not drop the valid fd");
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

	printf("\n=== monitor_fd()/unmonitor_fd() fd range handling test (issue #105) ===\n");

	init_fd_monitor_unittest();

	if (test_monitor_rejects_fd_above_range() != 0)
		failed++;
	if (test_monitor_rejects_negative_fd() != 0)
		failed++;
	if (test_unmonitor_tolerates_out_of_range_fd() != 0)
		failed++;
	if (test_valid_fd_still_monitored_after_rejection() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
