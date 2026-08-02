// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for admin_close() (admin.c) -- the counterpart to
 * admin_init(), called at daemon shutdown (close_session(), session.c)
 * and by "racoon -t"'s config-check path. Pre-dates the v0.9.1 churn but
 * had no coverage at all until now: admin_close() is exported, so it
 * needs no ENABLE_UNITTEST accessor, and shares admin_unittest_src.c/
 * admin_test_stubs.c (a real `lcconf`, a call-counted unmonitor_fd())
 * with the other admin.c tests.
 *
 * Note admin_close() does NOT reset lcconf->sock_admin to -1 after
 * closing it (unlike admin_init()'s own monitor_fd()-failure path) --
 * this test asserts that as the function's actual current contract, not
 * as an endorsement; a caller that calls admin_close() twice in a row
 * would unmonitor_fd()/close() the same (by then invalid) fd a second
 * time. See test_calling_twice_is_not_idempotent() below.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "vmbuf.h"
#include "localconf.h"
#include "admin.h"

extern int admin_close(void);
extern struct localconf *lcconf;
extern int admin_test_unmonitor_fd_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
fd_is_open(int fd)
{
	return fcntl(fd, F_GETFD) != -1;
}

static int
test_closes_and_unmonitors_a_valid_fd(void)
{
	int fds[2];

	TEST_START("admin_close() unmonitor_fd()s and closes a valid lcconf->sock_admin");

	if (pipe(fds) != 0)
		TEST_FAIL("pipe() failed");

	admin_test_unmonitor_fd_calls = 0;
	lcconf->sock_admin = fds[0];

	if (admin_close() != 0) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("admin_close() did not return 0");
	}
	if (admin_test_unmonitor_fd_calls != 1) {
		close(fds[1]);
		TEST_FAIL("unmonitor_fd() was not called exactly once");
	}
	if (fd_is_open(fds[0])) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("lcconf->sock_admin was not actually closed");
	}

	close(fds[1]);
	TEST_PASS();
	return 0;
}

static int
test_noop_when_already_minus_one(void)
{
	TEST_START("admin_close() is a no-op when lcconf->sock_admin is already -1");

	admin_test_unmonitor_fd_calls = 0;
	lcconf->sock_admin = -1;

	if (admin_close() != 0)
		TEST_FAIL("admin_close() did not return 0");
	if (admin_test_unmonitor_fd_calls != 0)
		TEST_FAIL("unmonitor_fd() was called despite sock_admin already being -1");

	TEST_PASS();
	return 0;
}

/*
 * admin_close() leaves lcconf->sock_admin holding the now-closed fd
 * number instead of resetting it to -1 -- so a second, unguarded call
 * unmonitor_fd()s/close()s that same stale number again. This is
 * documenting the function's actual behavior (a caller must not call it
 * twice without re-checking/resetting sock_admin itself), not asserting
 * it is correct; if this is ever "fixed" to reset sock_admin to -1
 * (matching admin_init()'s own monitor_fd()-failure path), this test
 * will fail and should be updated alongside that change.
 */
static int
test_calling_twice_is_not_idempotent(void)
{
	int fds[2];

	TEST_START("calling admin_close() twice acts on the same stale fd again");

	if (pipe(fds) != 0)
		TEST_FAIL("pipe() failed");

	admin_test_unmonitor_fd_calls = 0;
	lcconf->sock_admin = fds[0];

	admin_close();
	admin_close();

	if (admin_test_unmonitor_fd_calls != 2) {
		close(fds[1]);
		TEST_FAIL("a second admin_close() call did not re-run unmonitor_fd()/close()");
	}

	close(fds[1]);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== admin_close() test ===\n");

	if (test_closes_and_unmonitors_a_valid_fd() != 0)
		failed++;
	if (test_noop_when_already_minus_one() != 0)
		failed++;
	if (test_calling_twice_is_not_idempotent() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
