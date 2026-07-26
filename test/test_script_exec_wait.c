// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for doc/dev/daemon-issues.md Issue 1 (F2): racoon's
 * shutdown path never waited for a SCRIPT_PHASE1_DOWN hook's forked
 * child before proceeding, routinely outracing phase1-down.sh and
 * leaving its routes/DNS/SPD state behind.
 *
 * script_exec() (isakmp.c) is not static, so it is driven here directly
 * (via a real fork()+execve() of small throwaway shell scripts under
 * $TMPDIR) rather than through script_hook()/privsep_script_exec() --
 * this test is only about script_exec()'s own wait/no-wait/timeout
 * behavior, independent of how a caller decided to ask for it.
 *
 * script_exec() takes the wait decision as an explicit argument rather
 * than sniffing envp for a sentinel (an earlier version used a
 * RACOON_SCRIPT_WAIT envp entry, which turned out to contend with a
 * config's own env vars for privsep's fixed PRIVSEP_NBUF_MAX wire budget
 * -- see privsep.h/isakmp.c's script_hook()) -- envp here is just the
 * hook's ordinary environment, with nothing left to strip.
 *
 *   - test_no_wait_returns_immediately(): wait_for_exit=0 -- the
 *     original, still-default fire-and-forget behavior (e.g.
 *     SCRIPT_PHASE1_UP, or SCRIPT_PHASE1_DOWN outside of shutdown) must
 *     be unchanged: script_exec() returns long before a slow script
 *     finishes.
 *   - test_wait_flag_blocks_for_completion(): wait_for_exit=1 --
 *     script_exec() must not return until the script has actually
 *     finished (observed via a marker file the script writes right
 *     before exiting).
 *   - test_envp_reaches_hook_unmodified(): the script's own `env`
 *     output, captured to a file, must contain exactly the envp entry
 *     passed in -- script_exec() no longer filters envp at all.
 *   - test_bounded_wait_times_out(): a script that runs long past
 *     script_exec()'s wait bound must not hang script_exec() forever --
 *     it has to give up and return once the bound elapses, matching the
 *     brief's requirement that a slow hook not make shutdown hang
 *     visibly. The test then waits out and reaps the still-running
 *     script itself (script_exec() no longer will, once it gives up),
 *     so it does not leak a background process past this test's exit.
 *
 * isakmp.c is pulled in via a local wrapper source (isakmp_unittest_src.c,
 * already used by test_script_hook_leak) with -ffunction-sections,
 * linked with --gc-sections, so only script_exec()'s own reachable
 * closure (fork/execve/waitpid/nanosleep, plog.o, vmbuf.o) is retained --
 * script_hook() and its own, larger dependency closure are never pulled
 * in here.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "var.h"
#include "vmbuf.h"
#include "remoteconf.h"

extern int script_exec(char *script, int name, char *const envp[],
    int wait_for_exit);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static char script_path[256];
static char marker_path[256];
static char pidfile_path[256];

static double
elapsed_ms(struct timeval *start, struct timeval *end)
{
	return (end->tv_sec - start->tv_sec) * 1000.0 +
	    (end->tv_usec - start->tv_usec) / 1000.0;
}

/*
 * Writes a throwaway "#!/bin/sh" script to script_path. `body` runs with
 * $MARKER (marker_path) and $PIDFILE (pidfile_path) already exported.
 */
static int
write_script(const char *body)
{
	FILE *f = fopen(script_path, "w");
	if (f == NULL)
		return -1;
	fprintf(f, "#!/bin/sh\n");
	fprintf(f, "MARKER=%s\n", marker_path);
	fprintf(f, "PIDFILE=%s\n", pidfile_path);
	fprintf(f, "%s\n", body);
	fclose(f);
	if (chmod(script_path, 0700) != 0)
		return -1;
	return 0;
}

static int
file_exists(const char *path)
{
	FILE *f = fopen(path, "r");
	if (f == NULL)
		return 0;
	fclose(f);
	return 1;
}

static int
test_no_wait_returns_immediately(void)
{
	char *envp[] = { "LOCAL_ADDR=203.0.113.1", NULL };
	struct timeval t0, t1;
	double ms;

	TEST_START("script_exec() with wait_for_exit=0 returns immediately");

	unlink(marker_path);
	if (write_script("sleep 0.5; : > \"$MARKER\"") != 0)
		TEST_FAIL("could not write test script");

	gettimeofday(&t0, NULL);
	if (script_exec(script_path, SCRIPT_PHASE1_UP, envp, 0) != 0)
		TEST_FAIL("script_exec() returned an error");
	gettimeofday(&t1, NULL);

	ms = elapsed_ms(&t0, &t1);
	if (ms >= 250.0) {
		printf("(took %.0f ms) ", ms);
		TEST_FAIL("script_exec() blocked with wait_for_exit=0");
	}

	/* Let the background sleep+marker script finish and get reaped
	 * before the next test writes over script_path/marker_path. */
	sleep(1);
	unlink(marker_path);

	TEST_PASS();
	return 0;
}

static int
test_wait_flag_blocks_for_completion(void)
{
	char *envp[] = { "LOCAL_ADDR=203.0.113.1", NULL };
	struct timeval t0, t1;
	double ms;

	TEST_START("script_exec() with wait_for_exit=1 waits for completion");

	unlink(marker_path);
	if (write_script("sleep 0.5; : > \"$MARKER\"") != 0)
		TEST_FAIL("could not write test script");

	gettimeofday(&t0, NULL);
	if (script_exec(script_path, SCRIPT_PHASE1_DOWN, envp, 1) != 0)
		TEST_FAIL("script_exec() returned an error");
	gettimeofday(&t1, NULL);

	ms = elapsed_ms(&t0, &t1);
	if (ms < 400.0) {
		printf("(took only %.0f ms) ", ms);
		TEST_FAIL("script_exec() returned before the 1s script finished");
	}
	if (!file_exists(marker_path)) {
		TEST_FAIL("marker file missing after script_exec() returned");
	}

	unlink(marker_path);
	TEST_PASS();
	return 0;
}

static int
test_envp_reaches_hook_unmodified(void)
{
	char *envp[] = { "LOCAL_ADDR=203.0.113.1", NULL };
	FILE *f;
	char line[512];
	int found = 0;

	TEST_START("script_exec() passes envp through to execve() unmodified");

	unlink(marker_path);
	if (write_script("env > \"$MARKER\"") != 0)
		TEST_FAIL("could not write test script");

	/* wait_for_exit=1 -- blocks until the script (and its `env >`
	 * redirect) has completed, so the marker is ready to read as soon
	 * as script_exec() returns. */
	if (script_exec(script_path, SCRIPT_PHASE1_DOWN, envp, 1) != 0)
		TEST_FAIL("script_exec() returned an error");

	f = fopen(marker_path, "r");
	if (f == NULL)
		TEST_FAIL("marker file missing after script_exec() returned");
	while (fgets(line, sizeof(line), f) != NULL) {
		if (strncmp(line, "LOCAL_ADDR=203.0.113.1", 22) == 0) {
			found = 1;
			break;
		}
	}
	fclose(f);
	unlink(marker_path);

	if (!found)
		TEST_FAIL("LOCAL_ADDR missing from the hook script's environment");

	TEST_PASS();
	return 0;
}

static int
test_bounded_wait_times_out(void)
{
	char *envp[] = { "LOCAL_ADDR=203.0.113.1", NULL };
	struct timeval t0, t1;
	double ms;
	FILE *f;
	pid_t pid;
	int status;

	TEST_START("script_exec() gives up after its bounded wait, does not hang");

	unlink(marker_path);
	unlink(pidfile_path);
	/* Longer than script_exec()'s internal wait bound (3s); short
	 * enough to keep this test's own runtime reasonable. */
	if (write_script("echo $$ > \"$PIDFILE\"; sleep 4; : > \"$MARKER\"") != 0)
		TEST_FAIL("could not write test script");

	gettimeofday(&t0, NULL);
	if (script_exec(script_path, SCRIPT_PHASE1_DOWN, envp, 1) != 0)
		TEST_FAIL("script_exec() returned an error");
	gettimeofday(&t1, NULL);

	ms = elapsed_ms(&t0, &t1);
	/* Generous margins around the 3000ms bound for a loaded CI host. */
	if (ms < 2500.0 || ms > 4500.0) {
		printf("(took %.0f ms, expected roughly 3000 ms) ", ms);
		TEST_FAIL("script_exec() did not respect its wait bound");
	}
	if (file_exists(marker_path)) {
		TEST_FAIL("script had already finished; this run did not "
		    "exercise the timeout path");
	}

	/* Reap the still-running script ourselves (script_exec() gave up
	 * waiting, but it is still our direct child) so it does not
	 * outlive this test as an orphan. */
	f = fopen(pidfile_path, "r");
	if (f == NULL || fscanf(f, "%d", &pid) != 1) {
		if (f != NULL)
			fclose(f);
		TEST_FAIL("could not read the script's own pid");
	}
	fclose(f);

	if (waitpid((pid_t)pid, &status, 0) != (pid_t)pid)
		TEST_FAIL("failed to reap the timed-out script afterward");

	unlink(marker_path);
	unlink(pidfile_path);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;
	pid_t mypid = getpid();

	printf("\n=== script_exec() bounded-wait test (daemon-issues.md Issue 1) ===\n");

	snprintf(script_path, sizeof(script_path),
	    "/tmp/racoon_test_script_exec_%d.sh", (int)mypid);
	snprintf(marker_path, sizeof(marker_path),
	    "/tmp/racoon_test_script_exec_%d.marker", (int)mypid);
	snprintf(pidfile_path, sizeof(pidfile_path),
	    "/tmp/racoon_test_script_exec_%d.pid", (int)mypid);

	if (test_no_wait_returns_immediately() != 0)
		failed++;
	if (test_wait_flag_blocks_for_completion() != 0)
		failed++;
	if (test_envp_reaches_hook_unmodified() != 0)
		failed++;
	if (test_bounded_wait_times_out() != 0)
		failed++;

	unlink(script_path);
	unlink(marker_path);
	unlink(pidfile_path);

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
