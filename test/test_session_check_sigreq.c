// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for session.c's signal-dispatch cluster --
 * signal_handler(), check_sigreq(), reload_conf(), close_session() --
 * previously entirely uncovered. All four are reachable in production
 * only through session()'s live main loop after a real signal delivery,
 * which needs a fully running daemon (real cfparse()/admin_init()/
 * myaddr_init()/privsep_init()) to ever reach; check_sigreq_unittest()
 * (session.c, ENABLE_UNITTEST) lets this test set sigreq[] via the real,
 * exported signal_handler() -- exactly as a real signal delivery would
 * -- and then drive the dispatch directly.
 *
 * check_sigreq() is one function referencing reload_conf() and
 * close_session() directly, so -ffunction-sections/--gc-sections cannot
 * discard either one's dependency closure regardless of which signal a
 * given test drives -- session_signal_test_stubs.c supplies stand-ins
 * for all of it (the same "one dispatch function pulls in everything"
 * situation admin_test_stubs.c already documents for admin_process()).
 *
 * close_session() ends in an unconditional exit(0); -Wl,--wrap=exit
 * redirects that to __wrap_exit() below, which uses siglongjmp() to
 * return control to the test instead of actually terminating the
 * process -- there is nothing after that exit(0) call for a real
 * process exit to preserve, so unwinding early here is safe. This is
 * the same category of linker-interposition technique already used
 * elsewhere in this suite for _exit()/fork() (privsep_gcov_dump_shim.c,
 * test_privsep_init_fork_failure.c), applied to plain exit() instead.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

extern void check_sigreq_unittest(void);
extern void signal_handler(int sig);
extern int racoon_shutting_down;

extern int session_test_evt_generic_calls;
extern int session_test_pfkey_send_flush_calls;
extern int session_test_flushph2_calls;
extern int session_test_flushph1_calls;
extern int session_test_flushrmconf_calls;
extern int session_test_flushsainfo_calls;
extern int session_test_myaddr_close_calls;
extern int session_test_pfkey_close_calls;
extern int session_test_backupsa_clean_calls;
#ifdef ENABLE_ADMINPORT
extern int session_test_admin_close_calls;
#endif
#ifdef ENABLE_HYBRID
extern int session_test_isakmp_cfg_init_calls;
extern int session_test_isakmp_cfg_init_ret;
#endif
extern int session_test_sainfo_start_reload_calls;
extern int session_test_rmconf_start_reload_calls;
extern int session_test_pfkey_reload_calls;
extern int session_test_save_params_calls;
extern int session_test_flushlcconf_calls;
extern int session_test_cfparse_calls;
extern int session_test_cfparse_ret;
extern int session_test_restore_params_calls;
extern int session_test_myaddr_sync_calls;
extern int session_test_revalidate_ph12_calls;
extern int session_test_sainfo_finish_reload_calls;
extern int session_test_rmconf_finish_reload_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static sigjmp_buf exit_jmp;
static int exit_was_called;
static int wrapped_exit_status;
static int exit_trap_armed;

extern void __real_exit(int) __attribute__((__noreturn__));

/* -Wl,--wrap=exit redirects *every* undefined reference to exit() in
 * this binary's final link -- not just close_session()'s own exit(0)
 * call this file means to catch. See test_racoonctl_encode_requests.c's
 * matching comment for the full reasoning: on a toolchain where the C
 * runtime's own post-main() exit() call resolves at link time (e.g. a
 * statically-linked crt object) rather than through a shared libc,
 * --wrap reaches that call too, and siglongjmp()ing for it here is
 * undefined behaviour (exit_jmp has no live target once main() itself
 * has returned) -- observed in practice as the whole test binary
 * re-entering itself in an unbounded loop. exit_trap_armed scopes the
 * jump to only the one exit() call each test below is actively driving;
 * any other exit() takes the real exit() path and actually terminates
 * the process. */
void
__wrap_exit(int status)
{
	if (!exit_trap_armed)
		__real_exit(status);
	exit_was_called = 1;
	wrapped_exit_status = status;
	siglongjmp(exit_jmp, 1);
}

static void
reset_stub_state(void)
{
	session_test_evt_generic_calls = 0;
	session_test_pfkey_send_flush_calls = 0;
	session_test_flushph2_calls = 0;
	session_test_flushph1_calls = 0;
	session_test_flushrmconf_calls = 0;
	session_test_flushsainfo_calls = 0;
	session_test_myaddr_close_calls = 0;
	session_test_pfkey_close_calls = 0;
	session_test_backupsa_clean_calls = 0;
#ifdef ENABLE_ADMINPORT
	session_test_admin_close_calls = 0;
#endif
#ifdef ENABLE_HYBRID
	session_test_isakmp_cfg_init_calls = 0;
	session_test_isakmp_cfg_init_ret = 0;
#endif
	session_test_sainfo_start_reload_calls = 0;
	session_test_rmconf_start_reload_calls = 0;
	session_test_pfkey_reload_calls = 0;
	session_test_save_params_calls = 0;
	session_test_flushlcconf_calls = 0;
	session_test_cfparse_calls = 0;
	session_test_cfparse_ret = 0;
	session_test_restore_params_calls = 0;
	session_test_myaddr_sync_calls = 0;
	session_test_revalidate_ph12_calls = 0;
	session_test_sainfo_finish_reload_calls = 0;
	session_test_rmconf_finish_reload_calls = 0;
	exit_was_called = 0;
	wrapped_exit_status = -999;
	exit_trap_armed = 0;
}

static int
test_sigchld_reaps_pending_children(void)
{
	pid_t child;
	siginfo_t info;

	TEST_START("SIGCHLD dispatch reaps a pending zombie child");

	reset_stub_state();

	child = fork();
	if (child == 0)
		_exit(0);
	if (child < 0)
		TEST_FAIL("fork() failed");

	/* Block until the child has exited, without reaping it (WNOWAIT) --
	 * check_sigreq() itself must be the one to reap it, via its own
	 * waitpid(-1, &s, WNOHANG) loop. */
	if (waitid(P_PID, child, &info, WEXITED | WNOWAIT) != 0)
		TEST_FAIL("waitid() failed while waiting for the child to exit");

	signal_handler(SIGCHLD);
	check_sigreq_unittest();

	/* The child is now a fully reaped, no-longer-existing process: a
	 * further waitpid() on its pid must fail with ECHILD. */
	if (waitpid(child, NULL, WNOHANG) != -1 || errno != ECHILD)
		TEST_FAIL("child was not reaped by check_sigreq()'s SIGCHLD handling");

	TEST_PASS();
	return 0;
}

static int
test_unrecognized_signal_is_logged_and_ignored(void)
{
	TEST_START("an unrecognized signal falls into the default case without side effects");

	reset_stub_state();

	signal_handler(SIGWINCH);
	check_sigreq_unittest();

	if (session_test_evt_generic_calls != 0 || session_test_cfparse_calls != 0)
		TEST_FAIL("an unrecognized signal triggered reload/shutdown side effects");

	TEST_PASS();
	return 0;
}

static int
test_sighup_runs_full_reload_sequence_on_success(void)
{
	TEST_START("SIGHUP runs the complete reload sequence when cfparse() succeeds");

	reset_stub_state();
	session_test_cfparse_ret = 0;

	signal_handler(SIGHUP);
	check_sigreq_unittest();

#ifdef ENABLE_HYBRID
	if (session_test_isakmp_cfg_init_calls != 1)
		TEST_FAIL("isakmp_cfg_init() was not called exactly once");
#endif
	if (session_test_sainfo_start_reload_calls != 1)
		TEST_FAIL("sainfo_start_reload() was not called exactly once");
	if (session_test_rmconf_start_reload_calls != 1)
		TEST_FAIL("rmconf_start_reload() was not called exactly once");
	if (session_test_pfkey_reload_calls != 1)
		TEST_FAIL("pfkey_reload() was not called exactly once");
	if (session_test_save_params_calls != 1)
		TEST_FAIL("save_params() was not called exactly once");
	if (session_test_flushlcconf_calls != 1)
		TEST_FAIL("flushlcconf() was not called exactly once");
	if (session_test_cfparse_calls != 1)
		TEST_FAIL("cfparse() was not called exactly once");
	if (session_test_restore_params_calls != 1)
		TEST_FAIL("restore_params() was not called after a successful reload");
	if (session_test_myaddr_sync_calls != 1)
		TEST_FAIL("myaddr_sync() was not called after a successful reload");
	if (session_test_revalidate_ph12_calls != 1)
		TEST_FAIL("revalidate_ph12() was not called after a successful reload");
	if (session_test_sainfo_finish_reload_calls != 1)
		TEST_FAIL("sainfo_finish_reload() was not called after a successful reload");
	if (session_test_rmconf_finish_reload_calls != 1)
		TEST_FAIL("rmconf_finish_reload() was not called after a successful reload");

	TEST_PASS();
	return 0;
}

/*
 * reload_conf()'s own header comment warns "possible mem leaks and no
 * way to go back for now" for exactly this path: cfparse() failing
 * mid-reload. Confirms the function actually stops there rather than
 * limping forward with restore_params()/myaddr_sync()/revalidate_ph12()/
 * the two finish_reload() calls against a config it never finished
 * loading.
 */
static int
test_sighup_stops_after_cfparse_failure(void)
{
	TEST_START("SIGHUP stops the reload sequence when cfparse() fails");

	reset_stub_state();
	session_test_cfparse_ret = -1;

	signal_handler(SIGHUP);
	check_sigreq_unittest();

	if (session_test_cfparse_calls != 1)
		TEST_FAIL("cfparse() was not called exactly once");
	if (session_test_restore_params_calls != 0)
		TEST_FAIL("restore_params() ran despite cfparse() failing");
	if (session_test_myaddr_sync_calls != 0)
		TEST_FAIL("myaddr_sync() ran despite cfparse() failing");
	if (session_test_revalidate_ph12_calls != 0)
		TEST_FAIL("revalidate_ph12() ran despite cfparse() failing");
	if (session_test_sainfo_finish_reload_calls != 0)
		TEST_FAIL("sainfo_finish_reload() ran despite cfparse() failing");
	if (session_test_rmconf_finish_reload_calls != 0)
		TEST_FAIL("rmconf_finish_reload() ran despite cfparse() failing");

	TEST_PASS();
	return 0;
}

#ifdef ENABLE_HYBRID
static int
test_sighup_stops_immediately_on_isakmp_cfg_init_failure(void)
{
	TEST_START("SIGHUP aborts before touching sainfo/rmconf if isakmp_cfg_init() fails");

	reset_stub_state();
	session_test_isakmp_cfg_init_ret = -1;

	signal_handler(SIGHUP);
	check_sigreq_unittest();

	if (session_test_isakmp_cfg_init_calls != 1)
		TEST_FAIL("isakmp_cfg_init() was not called exactly once");
	if (session_test_sainfo_start_reload_calls != 0)
		TEST_FAIL("sainfo_start_reload() ran despite isakmp_cfg_init() failing");
	if (session_test_cfparse_calls != 0)
		TEST_FAIL("cfparse() ran despite isakmp_cfg_init() failing");

	TEST_PASS();
	return 0;
}
#endif

static int
test_sigterm_runs_shutdown_sequence_and_exits(void)
{
	TEST_START("SIGTERM runs the full shutdown sequence and calls exit(0)");

	reset_stub_state();

	if (sigsetjmp(exit_jmp, 1) == 0) {
		exit_trap_armed = 1;
		signal_handler(SIGTERM);
		check_sigreq_unittest();
		exit_trap_armed = 0;
		TEST_FAIL("close_session() returned instead of calling exit()");
	}
	exit_trap_armed = 0;

	if (!exit_was_called)
		TEST_FAIL("exit() was never called");
	if (wrapped_exit_status != 0)
		TEST_FAIL("close_session() did not exit(0)");
	if (racoon_shutting_down != 1)
		TEST_FAIL("racoon_shutting_down was not set before shutdown");
	if (session_test_evt_generic_calls != 1)
		TEST_FAIL("evt_generic(EVT_RACOON_QUIT, ...) was not called");
	if (session_test_pfkey_send_flush_calls != 1)
		TEST_FAIL("pfkey_send_flush() was not called");
	if (session_test_flushph2_calls != 1 || session_test_flushph1_calls != 1)
		TEST_FAIL("flushph1()/flushph2() were not both called");
	if (session_test_flushrmconf_calls != 1 || session_test_flushsainfo_calls != 1)
		TEST_FAIL("flushrmconf()/flushsainfo() were not both called");
	if (session_test_myaddr_close_calls != 1 || session_test_pfkey_close_calls != 1)
		TEST_FAIL("close_sockets() did not reach myaddr_close()/pfkey_close()");
#ifdef ENABLE_ADMINPORT
	if (session_test_admin_close_calls != 1)
		TEST_FAIL("close_sockets() did not reach admin_close()");
#endif
	if (session_test_backupsa_clean_calls != 1)
		TEST_FAIL("backupsa_clean() was not called");

	TEST_PASS();
	return 0;
}

static int
test_sigint_also_runs_shutdown_sequence(void)
{
	TEST_START("SIGINT triggers the same shutdown sequence as SIGTERM");

	reset_stub_state();

	if (sigsetjmp(exit_jmp, 1) == 0) {
		exit_trap_armed = 1;
		signal_handler(SIGINT);
		check_sigreq_unittest();
		exit_trap_armed = 0;
		TEST_FAIL("close_session() returned instead of calling exit()");
	}
	exit_trap_armed = 0;

	if (!exit_was_called)
		TEST_FAIL("exit() was never called");
	if (session_test_flushph1_calls != 1)
		TEST_FAIL("SIGINT did not reach the same shutdown sequence as SIGTERM");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== session.c signal-dispatch cluster test ===\n");

	if (test_sigchld_reaps_pending_children() != 0)
		failed++;
	if (test_unrecognized_signal_is_logged_and_ignored() != 0)
		failed++;
	if (test_sighup_runs_full_reload_sequence_on_success() != 0)
		failed++;
	if (test_sighup_stops_after_cfparse_failure() != 0)
		failed++;
#ifdef ENABLE_HYBRID
	if (test_sighup_stops_immediately_on_isakmp_cfg_init_failure() != 0)
		failed++;
#endif
	if (test_sigterm_runs_shutdown_sequence_and_exits() != 0)
		failed++;
	if (test_sigint_also_runs_shutdown_sequence() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
