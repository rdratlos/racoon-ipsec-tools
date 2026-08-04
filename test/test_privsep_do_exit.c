// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Standalone unit test for privsep_do_exit() (privsep.c), split out per
 * doc/dev/v0.9.1-hardening-spec.md §2.4's review follow-up: in
 * production this function is reachable only as the callback
 * monitor_fd() dispatches to when privsep_sock[1] shows up readable/EOF
 * in the unprivileged child's own select() loop -- so a test that only
 * ever drove it through monitor_fd()'s full dispatch machinery could not
 * distinguish "the callback's own logic is wrong" from "the dispatch
 * around it is wrong". This file calls it directly, decoupled from
 * monitor_fd() entirely, via the new privsep_do_exit_unittest() accessor
 * (privsep.c, ENABLE_UNITTEST -- privsep_do_exit() is static).
 *
 * From source (privsep.c), not assumed: privsep_do_exit(ctx, fd) ignores
 * both arguments and does exactly one thing, unconditionally --
 * kill(getpid(), SIGTERM) -- then returns 0. That matches this project's
 * own prior description of the mechanism ("the unprivileged child raises
 * SIGTERM on itself once it detects the privileged side is gone"), but
 * the two things actually worth pinning as a regression test are:
 *
 *  1. it really does deliver SIGTERM (not, say, SIGKILL or nothing) to
 *     the calling process, confirmed the same way
 *     test_privsep_sigterm_forward.c confirms real signal delivery: fork
 *     a disposable child, have it call the function for real, and check
 *     what the kernel actually did via waitpid() -- not by inspecting
 *     the source a second time.
 *  2. when that self-sent SIGTERM does *not* terminate the process (a
 *     handler is installed, as a real unprivileged child's own
 *     session.c signal setup would have one long before this callback
 *     could ever fire) the function still returns 0 and does nothing
 *     else -- so monitor_fd()'s caller reads it as "handled successfully"
 *     rather than an error, exactly as the dispatch loop's own contract
 *     expects.
 *
 * Both cases fork a disposable child so a signal that *does* terminate
 * the process (case 1, the expected real-world shape: session.c's
 * SIGTERM handling is normally already fatal-by-way-of-graceful-shutdown)
 * takes down only that child, not this test binary itself.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

extern int privsep_do_exit_unittest(void *ctx, int fd);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

#define WAIT_POLL_MS   20
#define WAIT_MAX_POLLS 250   /* 5s bound, same as the rest of this suite */

/* Bounded, same reasoning/constants as this suite's other fork-based
 * tests: never block the harness indefinitely on a child that never
 * exits. */
static int
wait_child_bounded(pid_t child, int *status)
{
	int i;

	for (i = 0; i < WAIT_MAX_POLLS; i++) {
		if (waitpid(child, status, WNOHANG) == child)
			return 0;
		usleep(WAIT_POLL_MS * 1000);
	}
	kill(child, SIGKILL);
	waitpid(child, status, 0);
	return -1;
}

/*
 * Case 1: SIGTERM at its default disposition. privsep_do_exit_unittest()
 * ignores both arguments (confirmed from source), so what it is called
 * with here is arbitrary.
 */
static int
test_do_exit_terminates_via_sigterm(void)
{
	pid_t child;
	int status;

	TEST_START("privsep_do_exit() terminates the calling process via SIGTERM");

	if ((child = fork()) < 0)
		TEST_FAIL("fork() failed");

	if (child == 0) {
		(void)privsep_do_exit_unittest(NULL, -1);
		/* Only reached if the self-sent SIGTERM somehow did not
		 * terminate the process -- itself a failure, reported
		 * distinctly from the expected signal exit below. */
		_exit(42);
	}

	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("child did not exit within the time bound");

	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM) {
		printf("(child raw exit status: %d) ", status);
		TEST_FAIL("child was not terminated by SIGTERM");
	}

	TEST_PASS();
	return 0;
}

/*
 * Case 2: SIGTERM caught rather than fatal -- the shape a real
 * unprivileged child is normally already in by the time this callback
 * could ever fire (session.c's own signal setup runs at startup, long
 * before privsep_sock[1] could show EOF). Confirms the handler really
 * did fire (proving the signal was actually delivered, not merely that
 * the process happened to survive) and that the function's own return
 * value is 0. Communicated back through the child's exit code, the only
 * channel available across fork().
 */
static volatile sig_atomic_t handler_fired = 0;

static void
sigterm_handler(int sig)
{
	handler_fired = 1;
}

static int
test_do_exit_returns_zero_when_signal_is_caught(void)
{
	pid_t child;
	int status, ret;

	TEST_START("privsep_do_exit() returns 0 when its own SIGTERM is caught, not fatal");

	if ((child = fork()) < 0)
		TEST_FAIL("fork() failed");

	if (child == 0) {
		signal(SIGTERM, sigterm_handler);
		ret = privsep_do_exit_unittest(NULL, -1);
		/* Exit code doubles as the verdict channel:
		 *   0 -> handler fired AND return value was 0 (expected)
		 *   1 -> handler never fired (signal was not delivered)
		 *   2 -> handler fired but return value was not 0 */
		if (!handler_fired)
			_exit(1);
		if (ret != 0)
			_exit(2);
		_exit(0);
	}

	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("child did not exit within the time bound");

	if (!WIFEXITED(status))
		TEST_FAIL("child did not exit normally");

	ret = WEXITSTATUS(status);
	if (ret == 1)
		TEST_FAIL("SIGTERM handler never fired -- signal was not delivered");
	if (ret == 2)
		TEST_FAIL("privsep_do_exit() did not return 0 once its signal was caught");
	if (ret != 0)
		TEST_FAIL("child reported an unexpected verdict");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep_do_exit() (v0.9.1-hardening-spec.md §2.4 "
	    "review follow-up) ===\n");

	if (test_do_exit_terminates_via_sigterm() != 0) failed++;
	if (test_do_exit_returns_zero_when_signal_is_caught() != 0) failed++;

	if (failed) {
		printf("\n=== %d TEST(S) FAILED ===\n\n", failed);
		return 1;
	}

	printf("\n=== ALL TESTS PASSED ===\n\n");
	return 0;
}
