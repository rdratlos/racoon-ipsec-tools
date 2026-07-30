// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Tests for privsep_init() itself -- the one privsep.c entry point every
 * other privsep test in this suite deliberately bypasses (they all drive
 * privsep_priv() directly over a plain socketpair(), precisely because
 * privsep_init()'s own socketpair()+fork()+chroot()+setgid()/setuid()+
 * monitor_fd() sequence needs real privilege to run at all). This file
 * drives it for real, but every side effect that matters -- the fork(),
 * the privilege drop, closing every fd but the socketpair, installing
 * global SIGINT/SIGTERM handlers -- happens inside a forked child (OC)
 * this test process never becomes; the test process (TP) itself only ever
 * calls privsep_init() when lcconf->uid == 0, the one path guaranteed to
 * return immediately with no fork and no side effects at all.
 *
 * Four scenarios:
 *
 *  1. lcconf->uid == 0: privsep_init() must return 0 having done nothing
 *     else -- no socketpair, no fork. Safe to call directly, no forked
 *     child needed.
 *  2. lcconf->uid != 0 but pathinfo[LC_PATHTYPE_CERT]/[LC_PATHTYPE_SCRIPT]
 *     are NULL: must return -1 before ever reaching socketpair()/fork().
 *     Also safe to call directly.
 *  3. lcconf->chroot points at a path that does not exist: the real forked
 *     child's chdir() must fail and privsep_init() must return -1 from
 *     inside it, before ever reaching setgid()/setuid()/monitor_fd(). Only
 *     the *failure* of chroot() setup is covered -- see the note at the
 *     end of this comment for why a real, successful chroot() stays out of
 *     scope. Needs the same real fork() as scenario 4 below.
 *  4. The real fork()+privilege-drop+privsep_priv() happy path, run
 *     entirely inside a disposable child (OC, "outer child"):
 *
 *       TP (this test binary, real root)
 *        `- fork() -> OC
 *              OC calls the real privsep_init(), which internally
 *              socketpair()s and fork()s *again* -> GC ("grandchild")
 *                GC: privsep_init()'s own child branch -- setgid()/
 *                    setuid()/seteuid() to a real unprivileged account,
 *                    monitor_fd(), returns 0. Continuing past that
 *                    return, GC calls a real ENABLE_HYBRID client-side
 *                    wrapper (privsep_accounting_system()) -- for real,
 *                    over the *real* privsep_sock privsep_init() itself
 *                    just set up, no test-only accessor involved -- then
 *                    reports the result down a pipe TP already holds the
 *                    read end of, and exits.
 *              OC: privsep_init()'s own parent branch -- closes every fd
 *                  but the socketpair, reopens the log, installs signal
 *                  handlers, and calls privsep_priv() on it for real.
 *                  privsep_priv() never returns (its only exits are
 *                  _exit(0)/_exit(1)), so OC's own call to privsep_init()
 *                  never returns either: once GC's one request is
 *                  answered and GC exits (closing its end), privsep_recv()
 *                  sees EOF and OC's privsep_priv() takes the clean
 *                  "out:"/_exit(0) shutdown path on its own.
 *
 *     TP reaps OC (bounded) and asserts its exit status is 0 -- the
 *     "out:" path above, i.e. privsep_init()'s whole fork/privilege-drop/
 *     dispatch-loop chain shut down the way a real unprivileged child
 *     disconnecting is supposed to, not the "fail:"/_exit(1) channel-fault
 *     path -- and reads GC's verdict from the pipe (bounded). GC's own
 *     exit status is not directly observable from TP: GC is OC's child,
 *     not TP's, and gets reparented once OC exits, so the pipe is the
 *     only channel back.
 *
 *     This is deliberately the one scenario in this file compiled only
 *     under ENABLE_HYBRID (the client-side call it makes is
 *     ENABLE_HYBRID-only) -- see the task brief's call-out that
 *     privsep_init() specifically needed its ENABLE_HYBRID path covered:
 *     every other privsep_priv() test in this suite reaches ENABLE_HYBRID
 *     dispatch only through a synthetic direct privsep_priv(sock) call;
 *     this is the one that reaches it through the real production
 *     privsep_init() entry point.
 *
 * Explicitly out of scope, and left as a documented gap rather than a
 * silent one: a real, *successful* chroot() (as opposed to scenario 3's
 * deliberate chdir() failure) is never exercised -- setting up a real,
 * populated jail directory is an orthogonal concern from what this file
 * is testing, and getting it wrong risks corrupting the test host rather
 * than just failing a test.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <poll.h>

#include "var.h"
#include "vmbuf.h"
#include "crypto_openssl.h"
#include "isakmp_var.h"
#include "localconf.h"
#include "admin.h"
#include "privsep.h"

extern int privsep_init(void);
extern void privsep_priv_test_lcconf_init(const char *certdir,
    const char *scriptdir);
extern void privsep_reset_state_unittest(void);
extern int privsep_get_sock_unittest(int idx);
extern struct localconf *lcconf;

/*
 * session.c, ENABLE_UNITTEST. privsep_init()'s own child branch calls
 * monitor_fd() (session.c) on privsep_sock[1], which inserts into
 * fd_monitor_tree[] (a static TAILQ_HEAD array) -- safe in production only
 * because session()'s own startup (session_init_before_cfparse()) always
 * TAILQ_INIT()s it long before privsep_init() ever forks, so the real
 * child just inherits already-initialized state. This test calls
 * privsep_init() directly, with none of that surrounding startup, so
 * fd_monitor_tree[] would otherwise still be its all-zero static default
 * -- a tqh_last of NULL, not "pointing at tqh_first" the way TAILQ_INIT()
 * leaves it -- and monitor_fd()'s TAILQ_INSERT_TAIL() dereferences that
 * NULL immediately (confirmed: segfaults the real fork()ed child before
 * this fix). Called once, before forking, so both OC and (through it) GC
 * inherit the initialized state via fork()'s copy of this process's
 * memory.
 */
extern void init_fd_monitor_unittest(void);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/*
 * A third outcome alongside 0 (pass, TEST_PASS()) and -1 (fail,
 * TEST_FAIL()): unlike test_root_is_noop()/test_missing_paths_refused(),
 * test_chroot_failure() and test_real_fork_hybrid_roundtrip() both need a
 * real fork() and (had test_chroot_failure()'s own chdir() not failed
 * first) real root (CAP_SETUID), and skip rather than fail when run
 * without it, without also skipping the two scenarios in this binary that
 * need no privilege at all -- see those functions and main()'s own
 * handling of this value.
 */
#define TEST_SKIPPED 2

#define WAIT_POLL_MS   20
#define WAIT_MAX_POLLS 250   /* 5s bound, same as the rest of this suite */
#define IO_TIMEOUT_MS  5000

static int
test_root_is_noop(void)
{
	TEST_START("privsep_init(), lcconf->uid == 0 (root): no-op");

	privsep_priv_test_lcconf_init(NULL, NULL);
	lcconf->uid = 0;
	privsep_reset_state_unittest();

	if (privsep_init() != 0)
		TEST_FAIL("must return 0 when already root");
	if (privsep_get_sock_unittest(0) != -1 ||
	    privsep_get_sock_unittest(1) != -1)
		TEST_FAIL("must not have touched privsep_sock at all");

	TEST_PASS();
	return 0;
}

static int
test_missing_paths_refused(void)
{
	TEST_START("privsep_init(), missing cert/script path: refused");

	privsep_priv_test_lcconf_init(NULL, NULL);
	lcconf->uid = 65534; /* anything nonzero */
	privsep_reset_state_unittest();

	if (privsep_init() != -1)
		TEST_FAIL("must return -1 without cert and script paths set");
	if (privsep_get_sock_unittest(0) != -1 ||
	    privsep_get_sock_unittest(1) != -1)
		TEST_FAIL("must not have touched privsep_sock at all");

	TEST_PASS();
	return 0;
}

/* Bounded read of exactly one byte -- see IO_TIMEOUT_MS above. */
static int
read_verdict_bounded(int fd, char *out)
{
	struct pollfd pfd;
	int pr;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	pr = poll(&pfd, 1, IO_TIMEOUT_MS);
	if (pr <= 0)
		return -1;

	return read(fd, out, 1) == 1 ? 0 : -1;
}

/* Bounded waitpid(), same reasoning/constants as privsep_wire_roundtrip.c's
 * own finish(). */
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
 * Shared by test_chroot_failure() below and (guarded by ENABLE_HYBRID,
 * further down) test_real_fork_hybrid_roundtrip(): both need the real
 * fork()+privsep_init() topology this file's own header comment
 * describes, differing only in what lcconf->chroot/uid/gid are set to and
 * what runs in GC once privsep_init() returns to it. gc_body(rc) is
 * called only by GC (OC's own call to privsep_init() never returns to
 * this line at all -- see the header comment) and must return the 'P'/'F'
 * verdict this function reports back to the caller via *out_verdict.
 * out_verdict and out_status are only filled in when this itself returns
 * 0; a nonzero return means the test infrastructure itself failed (mkdtemp(),
 * pipe(), fork(), or the bounded wait/read), not that the scenario's own
 * assertion failed -- the caller is expected to TEST_FAIL() on those
 * itself, since only it knows the right message.
 */
static int
run_forked_privsep_init(uid_t uid, gid_t gid, const char *chroot_path,
    char (*gc_body)(int rc), char *out_verdict, int *out_status)
{
	char certdir[] = "/tmp/privsep_init_certs.XXXXXX";
	char scriptdir[] = "/tmp/privsep_init_scripts.XXXXXX";
	int resultpipe[2];
	pid_t oc_pid;
	char verdict = 'F';

	if (mkdtemp(certdir) == NULL)
		return -1;
	if (mkdtemp(scriptdir) == NULL) {
		rmdir(certdir);
		return -1;
	}

	if (pipe(resultpipe) != 0) {
		rmdir(certdir);
		rmdir(scriptdir);
		return -1;
	}

	privsep_priv_test_lcconf_init(certdir, scriptdir);
	lcconf->uid = uid;
	lcconf->gid = gid;
	lcconf->chroot = (char *)chroot_path;
	privsep_reset_state_unittest();
	init_fd_monitor_unittest();

	if ((oc_pid = fork()) < 0) {
		close(resultpipe[0]);
		close(resultpipe[1]);
		rmdir(certdir);
		rmdir(scriptdir);
		return -1;
	}

	if (oc_pid == 0) {
		/* OC (and, if privsep_init()'s own internal fork() succeeds,
		 * GC continuing past its return -- see the file comment for
		 * why OC itself never reaches any further than this call). */
		int rc = privsep_init();
		char v = gc_body(rc);

		if (write(resultpipe[1], &v, 1) != 1)
			_exit(1);
		close(resultpipe[1]);
		_exit(rc == 0 ? 0 : 1);
	}

	/* TP: never touched by chroot()/setuid()/the fd-closing loop --
	 * all of that happened inside OC (and, if it got that far, GC). */
	close(resultpipe[1]);

	if (read_verdict_bounded(resultpipe[0], &verdict) != 0) {
		close(resultpipe[0]);
		wait_child_bounded(oc_pid, out_status);
		rmdir(certdir);
		rmdir(scriptdir);
		return -1;
	}
	close(resultpipe[0]);

	if (wait_child_bounded(oc_pid, out_status) != 0) {
		rmdir(certdir);
		rmdir(scriptdir);
		return -1;
	}

	rmdir(certdir);
	rmdir(scriptdir);
	*out_verdict = verdict;
	return 0;
}

/* GC-side body for test_chroot_failure(): privsep_init() must have failed
 * (chdir() to a nonexistent chroot) before ever reaching privilege drop. */
static char
gc_body_expect_init_failure(int rc)
{
	return (rc == -1) ? 'P' : 'F';
}

static int
test_chroot_failure(void)
{
	char badchroot[] = "/tmp/privsep_init_missing_chroot.XXXXXX";
	char verdict;
	int status;
	struct passwd *nobody;

	TEST_START("privsep_init(), chroot() setup failure: refused before privilege drop");

	/* Same reasoning as test_real_fork_hybrid_roundtrip() below: this
	 * scenario needs a real fork() and, had chdir() not failed first,
	 * would have needed CAP_SETUID too. */
	if (geteuid() != 0) {
		printf("SKIPPED (needs real root for the fork/privilege-drop "
		    "path)\n");
		return TEST_SKIPPED;
	}

	if ((nobody = getpwnam("nobody")) == NULL)
		TEST_FAIL("no \"nobody\" account on this host");

	/* mkdtemp() then rmdir(): a real, unpredictable path guaranteed not
	 * to exist by the time privsep_init()'s child calls chdir() on it --
	 * safer than a fixed guessed name, and this scenario needs the
	 * chdir() to fail, not to succeed. */
	if (mkdtemp(badchroot) == NULL)
		TEST_FAIL("mkdtemp(badchroot) failed");
	if (rmdir(badchroot) != 0)
		TEST_FAIL("rmdir(badchroot) failed");

	if (run_forked_privsep_init(nobody->pw_uid, nobody->pw_gid, badchroot,
	    gc_body_expect_init_failure, &verdict, &status) != 0)
		TEST_FAIL("test infrastructure (mkdtemp/pipe/fork/wait) failed");

	if (verdict != 'P')
		TEST_FAIL("privsep_init() did not return -1 for a chdir() "
		    "failure");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		TEST_FAIL("privileged process did not take the clean "
		    "\"out:\"/_exit(0) shutdown path");

	TEST_PASS();
	return 0;
}

#ifdef ENABLE_HYBRID

#include <netinet/in.h>
#include <arpa/inet.h>
#include "resolv.h"
#include "isakmp_xauth.h"
#include "isakmp_cfg.h"

extern int privsep_accounting_system(int port, struct sockaddr *raddr,
    char *usr, int inout);
extern struct isakmp_cfg_config isakmp_cfg_config;

static struct sockaddr_in gc_body_raddr;

/* GC-side body for test_real_fork_hybrid_roundtrip(): privsep_init() must
 * have succeeded (rc == 0), and the real ENABLE_HYBRID client-wrapper call
 * it then makes -- over the *real* privsep_sock privsep_init() itself just
 * set up, no test-only accessor involved -- must round-trip cleanly. */
static char
gc_body_hybrid_roundtrip(int rc)
{
	if (rc != 0)
		return 'F';

	memset(&gc_body_raddr, 0, sizeof(gc_body_raddr));
	gc_body_raddr.sin_family = AF_INET;
	gc_body_raddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	return (privsep_accounting_system(0,
	    (struct sockaddr *)&gc_body_raddr, "someuser", 1) == 0)
	    ? 'P' : 'F';
}

static int
test_real_fork_hybrid_roundtrip(void)
{
	char verdict;
	int status;
	struct passwd *nobody;

	TEST_START("privsep_init(), real fork+privilege-drop+ENABLE_HYBRID round trip");

	/*
	 * Unlike test_root_is_noop()/test_missing_paths_refused() above, this
	 * one scenario needs real root -- forking a child that itself
	 * setgid()s/setuid()s to a different, real unprivileged account
	 * needs CAP_SETUID, which only a process that started as root has.
	 * Skipped (not failed -- see main()'s TEST_SKIPPED handling) rather
	 * than run unprivileged and fail for an unrelated reason. See
	 * CONTRIBUTING.md's "Running the test suite" section.
	 */
	if (geteuid() != 0) {
		printf("SKIPPED (needs real root for the fork/privilege-drop "
		    "path)\n");
		return TEST_SKIPPED;
	}

	if ((nobody = getpwnam("nobody")) == NULL)
		TEST_FAIL("no \"nobody\" account on this host");

	isakmp_cfg_config.pool_size = 10;

	if (run_forked_privsep_init(nobody->pw_uid, nobody->pw_gid, NULL,
	    gc_body_hybrid_roundtrip, &verdict, &status) != 0)
		TEST_FAIL("test infrastructure (mkdtemp/pipe/fork/wait) failed");

	if (verdict != 'P')
		TEST_FAIL("the real privsep_accounting_system() round trip "
		    "did not succeed");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		TEST_FAIL("privileged process did not take the clean "
		    "\"out:\"/_exit(0) shutdown path");

	TEST_PASS();
	return 0;
}

#endif /* ENABLE_HYBRID */

int
main(void)
{
	int failed = 0;
	int rc;

	printf("\n=== privsep_init() (privsep-priv-extraction follow-up) "
	    "===\n");

	if (test_root_is_noop() != 0) failed++;
	if (test_missing_paths_refused() != 0) failed++;

	rc = test_chroot_failure();
	if (rc != 0 && rc != TEST_SKIPPED)
		failed++;

#ifdef ENABLE_HYBRID
	rc = test_real_fork_hybrid_roundtrip();
	if (rc != 0 && rc != TEST_SKIPPED)
		failed++;
#else
	printf("\n[TEST] privsep_init(), real fork+privilege-drop+ENABLE_HYBRID "
	    "round trip ... SKIPPED (ENABLE_HYBRID not compiled in)\n");
#endif

	if (failed) {
		printf("\n=== %d TEST(S) FAILED ===\n\n", failed);
		return 1;
	}

	printf("\n=== ALL TESTS PASSED ===\n\n");
	return 0;
}
