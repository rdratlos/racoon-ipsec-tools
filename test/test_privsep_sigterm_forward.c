// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for the privsep half of doc/dev/daemon-issues.md
 * Issue 1 (F2): under the shipped Type=simple systemd unit (no
 * KillMode=), `systemctl stop racoon` (or any `kill <pid>`) targets
 * $MAINPID, which under privsep is the privileged process, not the
 * unprivileged child that actually runs close_session()/script_hook().
 * Before this fix, privsep_init() left SIGTERM at its default
 * disposition (immediate termination, no forwarding) in the privileged
 * process, so it died on the spot -- before the child's
 * privsep_script_exec() request for SCRIPT_PHASE1_DOWN could ever
 * arrive. Under privsep, only the privileged process can actually
 * fork()+execve() a hook, so the down hook was not just raced, as in
 * the non-privsep case (script_exec()'s bounded wait, tested separately
 * in test_script_exec_wait.c) -- it was never attempted at all.
 *
 * This test cannot exercise privsep_init()'s own fork() (it needs a
 * real PF_KEY/XFRM-capable kernel, which not every host this project
 * tests on has -- see daemon-issues.md's own note that Issue 1 needs
 * live testing beyond what a unit test can reach). What it does verify,
 * with a real fork() and a real signal delivered by the kernel (not
 * simulated), is privsep_sigterm_forward() itself: given a real child
 * process, does invoking it actually deliver SIGTERM to that child.
 * privsep.c is pulled in via a local wrapper source
 * (privsep_unittest_src.c) following this project's established
 * unit-test-a-static-function pattern; privsep_set_child_pid_unittest()
 * and privsep_sigterm_forward_unittest() are new -DENABLE_UNITTEST-only
 * accessors for privsep_child_pid/privsep_sigterm_forward(), both
 * otherwise private to privsep.c.
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

extern void privsep_set_child_pid_unittest(pid_t pid);
extern void privsep_sigterm_forward_unittest(void);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/*
 * Forks a child that blocks in pause() until a real SIGTERM arrives (its
 * handler just _exit()s 0, so the parent's waitpid() below distinguishes
 * "forwarded" from "never received": a forwarded signal makes the child
 * exit almost immediately, an unforwarded one leaves it hanging in
 * pause() until this test kills it after the timeout).
 */
static void
child_sigterm_handler(int sig)
{
	_exit(0);
}

static int
test_forward_delivers_sigterm_to_child(void)
{
	pid_t child, ret;
	int status;
	int i;
	int readypipe[2];
	char buf;

	TEST_START("privsep_sigterm_forward() delivers SIGTERM to the forwarded-to child");

	if (pipe(readypipe) != 0)
		TEST_FAIL("pipe() failed");

	if ((child = fork()) < 0)
		TEST_FAIL("fork() failed");

	if (child == 0) {
		close(readypipe[0]);
		signal(SIGTERM, child_sigterm_handler);
		/* Tell the parent the handler is installed before it sends
		 * SIGTERM -- without this handshake, the parent can win the
		 * race and signal us while SIGTERM is still at its default
		 * (terminating) disposition. */
		if (write(readypipe[1], "1", 1) != 1)
			_exit(3);
		close(readypipe[1]);
		pause();
		/* pause() only returns via a caught, non-fatal signal; if
		 * something other than SIGTERM woke us, exit distinctly. */
		_exit(2);
	}
	close(readypipe[1]);
	if (read(readypipe[0], &buf, 1) != 1) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
		close(readypipe[0]);
		TEST_FAIL("child did not signal readiness");
	}
	close(readypipe[0]);

	privsep_set_child_pid_unittest(child);
	privsep_sigterm_forward_unittest();

	/* Poll briefly rather than a single blocking waitpid(): keeps this
	 * test's failure mode (child never signaled) a bounded, reported
	 * failure instead of an indefinite hang. */
	for (i = 0; i < 50; i++) {
		ret = waitpid(child, &status, WNOHANG);
		if (ret == child)
			break;
		usleep(20000); /* 20ms */
	}

	if (ret != child) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
		TEST_FAIL("child did not exit -- SIGTERM was not forwarded");
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("(child exit status: %d) ", status);
		TEST_FAIL("child exited abnormally, not via its SIGTERM handler");
	}

	TEST_PASS();
	return 0;
}

static int
test_forward_is_noop_without_a_child(void)
{
	TEST_START("privsep_sigterm_forward() is a no-op when no child pid is recorded");

	privsep_set_child_pid_unittest(0);
	/* Must not crash or send a signal to an arbitrary pid (e.g. pid 0,
	 * which means "this process's own process group" to kill()). */
	privsep_sigterm_forward_unittest();

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep_sigterm_forward() test (daemon-issues.md Issue 1) ===\n");

	if (test_forward_delivers_sigterm_to_child() != 0)
		failed++;
	if (test_forward_is_noop_without_a_child() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
