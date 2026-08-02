// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for session_init_before_cfparse() (session.c), new in
 * the v0.9.1 hardening pass: session()'s pre-cfparse() setup (fd
 * monitoring reset, scheduler, signal handling, pfkey/isakmp/mode-cfg
 * init, address-list init, save_params()) was pulled out of session()
 * itself so "racoon -t" (config syntax check, main.c) can run the exact
 * same sequence without also opening the admin port, writing a pid file,
 * or forking.
 *
 * This is pure code motion -- no logic changed -- but that is exactly
 * what a regression here would silently break: a future edit dropping
 * one of these calls, reordering them relative to the fd-monitoring
 * reset, or reintroducing them only in session() and not in this shared
 * path, would still build cleanly and would only surface as "racoon -t"
 * behaving differently from the real daemon startup it is supposed to
 * mirror.
 *
 * session_init_before_cfparse() is already exported (unlike
 * monitor_fd()/prune_stale_monitored_fds(), it needed no new
 * ENABLE_UNITTEST accessor). session_unittest_src.c is the same wrapper
 * source test_monitor_fd_range.c/test_prune_stale_monitored_fds.c use;
 * session_init_test_stubs.c stubs the heavyweight subsystem entry points
 * (pfkey_init()/isakmp_init()/isakmp_cfg_init()/myaddr_init_lists()/
 * save_params()) this test has no interest in exercising for real --
 * pfkey_init()/isakmp_init() in particular open real PF_KEY/UDP sockets
 * and call errx(1, ...) (process-ending) on failure, which this test host
 * may not have kernel IPsec support for at all. sched_init()
 * (schedule.c) and init_signal()/signal_handler() (session.c itself) are
 * both trivially self-contained and are linked/run for real.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/select.h>

extern void session_init_before_cfparse(void);
extern int monitor_fd(int fd, int (*callback)(void *, int), void *ctx,
    int priority);
extern void unmonitor_fd(int fd);
extern int is_fd_monitored_unittest(int fd);

extern int session_init_test_pfkey_init_calls;
extern int session_init_test_isakmp_init_calls;
extern int session_init_test_isakmp_cfg_init_calls;
extern int session_init_test_myaddr_init_lists_calls;
extern int session_init_test_save_params_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
dummy_callback(void *ctx, int fd)
{
	return 0;
}

static int
test_calls_every_subsystem_init_once(void)
{
	TEST_START("session_init_before_cfparse() initializes every subsystem exactly once");

	session_init_before_cfparse();

	if (session_init_test_pfkey_init_calls != 1)
		TEST_FAIL("pfkey_init() was not called exactly once");
	if (session_init_test_isakmp_init_calls != 1)
		TEST_FAIL("isakmp_init() was not called exactly once");
#ifdef ENABLE_HYBRID
	if (session_init_test_isakmp_cfg_init_calls != 1)
		TEST_FAIL("isakmp_cfg_init() was not called exactly once");
#endif
	if (session_init_test_myaddr_init_lists_calls != 1)
		TEST_FAIL("myaddr_init_lists() was not called exactly once");
	if (session_init_test_save_params_calls != 1)
		TEST_FAIL("save_params() was not called exactly once");

	TEST_PASS();
	return 0;
}

/*
 * The fd-monitoring reset (nfds/preset_mask/fd_monitor_tree[]) is the one
 * piece of session_init_before_cfparse() that used to live inline in
 * session() and is now shared with "racoon -t" too -- verify it left
 * monitor_fd()/unmonitor_fd() in a clean, working state, the same
 * observable contract test_monitor_fd_cold_start.c checks for the lazy
 * TAILQ_INIT() path.
 */
static int
test_fd_monitoring_state_is_usable_afterward(void)
{
	int fds[2];

	TEST_START("fd-monitoring state is freshly usable after session_init_before_cfparse()");

	if (pipe(fds) != 0)
		TEST_FAIL("pipe() failed");

	if (monitor_fd(fds[0], dummy_callback, NULL, 0) != 0) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("monitor_fd() failed right after session_init_before_cfparse()");
	}
	if (!is_fd_monitored_unittest(fds[0])) {
		unmonitor_fd(fds[0]);
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("fd was not recorded as monitored");
	}

	unmonitor_fd(fds[0]);
	if (is_fd_monitored_unittest(fds[0])) {
		close(fds[0]);
		close(fds[1]);
		TEST_FAIL("unmonitor_fd() did not clear the monitored fd");
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

	printf("\n=== session_init_before_cfparse() test ===\n");

	if (test_calls_every_subsystem_init_once() != 0)
		failed++;
	if (test_fd_monitoring_state_is_usable_afterward() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
