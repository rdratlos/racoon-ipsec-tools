// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Tests privsep_init()'s "case -1:" -- fork() itself failing -- which
 * test_privsep_init.c's own scenarios never reach (they need a real,
 * successful fork() for their own forked-child topology). fork() almost
 * never fails on a real, lightly-loaded host, and deliberately exhausting
 * PIDs/memory/RLIMIT_NPROC to make it fail for real would be both flaky
 * and disruptive to whatever else is running on the same host under the
 * same uid. Instead, this binary is linked with -Wl,--wrap=fork (the same
 * linker-level interposition technique test_script_hook_leak.c already
 * uses for free(), and test_privsep_* uses for _exit() under
 * --enable-coverage): every call to fork() in this binary -- there is
 * only ever the one, inside privsep_init() itself -- is redirected to
 * __wrap_fork() below, which always fails with EAGAIN, deterministically
 * and without touching any real system resource.
 *
 * Written while adding this test: privsep_init()'s socketpair() call
 * (which creates privsep_sock[]) happens *before* its fork() call, so a
 * fork() failure used to leave both descriptors open with nothing left to
 * close them -- privsep_init() returned -1 having leaked two fds every
 * time. Fixed alongside this test (privsep.c); this test's fd-count
 * assertion is what would have caught it.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>

#include "var.h"
#include "vmbuf.h"
#include "misc.h"
#include "plog.h"
#include "crypto_openssl.h"
#include "isakmp_var.h"
#include "localconf.h"
#include "admin.h"
#include "privsep.h"

extern int privsep_init(void);
extern void privsep_priv_test_lcconf_init(const char *certdir,
    const char *scriptdir);
extern void privsep_reset_state_unittest(void);
extern struct localconf *lcconf;

/*
 * -Wl,--wrap=fork (test/Makefile.am) redirects every fork() call in this
 * binary here instead of to libc's. Always fails, so privsep_init()'s own
 * "case -1:" is the only branch its internal fork() can ever take in this
 * binary -- no __real_fork() call is needed since the real one is never
 * wanted here.
 */
pid_t
__wrap_fork(void)
{
	errno = EAGAIN;
	return -1;
}

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/* Counts this process's own open file descriptors via /proc/self/fd,
 * rather than relying on any privsep.c-internal accessor, so this proves
 * an actual OS-level resource was not leaked, not just that a static
 * variable was reset back to -1. */
static int
count_open_fds(void)
{
	DIR *d;
	struct dirent *de;
	int count = 0;

	if ((d = opendir("/proc/self/fd")) == NULL)
		return -1;

	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.')
			continue;
		count++;
	}
	closedir(d);

	/* opendir()'s own fd is closed above before returning, so it never
	 * shows up in either the "before" or "after" count -- symmetric,
	 * cancels out. */
	return count;
}

static int
test_fork_failure(void)
{
	char certdir[] = "/tmp/privsep_init_fork_failure_certs.XXXXXX";
	char scriptdir[] = "/tmp/privsep_init_fork_failure_scripts.XXXXXX";
	int before, after, rc;

	TEST_START("privsep_init(), fork() failure: returns -1, leaks nothing");

	if (mkdtemp(certdir) == NULL)
		TEST_FAIL("mkdtemp(certdir) failed");
	if (mkdtemp(scriptdir) == NULL) {
		rmdir(certdir);
		TEST_FAIL("mkdtemp(scriptdir) failed");
	}

	privsep_priv_test_lcconf_init(certdir, scriptdir);
	lcconf->uid = 65534; /* anything nonzero -- must not take the
	                      * "already root" early return */
	lcconf->gid = 65534;
	lcconf->chroot = NULL;
	privsep_reset_state_unittest();

	/*
	 * Warm up plog()'s own lazy fd first, at the same priority
	 * privsep_init()'s "case -1:" branch itself logs at (LLV_ERROR):
	 * with no logfile and not foreground -- this binary's own defaults,
	 * untouched -- plogv() (plog.c) reaches vsyslog(), whose first call
	 * in a process opens (and, unlike this test's own privsep_sock,
	 * never closes) a socket to the system log. Whether that succeeds
	 * depends on whether a syslog/journald socket is actually reachable
	 * on this host -- true on a real Linux install, not necessarily true
	 * in a minimal container -- so without this, the fd count below
	 * would be comparing "no syslog fd" against "one syslog fd" on some
	 * hosts and "no syslog fd" against "no syslog fd" (the connect()
	 * failed and glibc gave up) on others, sometimes reporting a false
	 * leak that has nothing to do with privsep_sock[]. Calling it once
	 * here, before either fd count, means privsep_init()'s own identical
	 * plog() call a few lines below reuses the same already-open (or
	 * still-absent) fd instead of changing the count itself.
	 */
	plog(LLV_ERROR, LOCATION, NULL,
	    "test_privsep_init_fork_failure: warming up plog()'s lazy fd, "
	    "ignore this line\n");

	if ((before = count_open_fds()) < 0) {
		rmdir(certdir);
		rmdir(scriptdir);
		TEST_FAIL("count_open_fds() (before) failed");
	}

	rc = privsep_init();

	if ((after = count_open_fds()) < 0) {
		rmdir(certdir);
		rmdir(scriptdir);
		TEST_FAIL("count_open_fds() (after) failed");
	}

	rmdir(certdir);
	rmdir(scriptdir);

	if (rc != -1)
		TEST_FAIL("must return -1 when fork() fails");
	if (after != before)
		TEST_FAIL("privsep_sock[] descriptors leaked across the "
		    "failed fork()");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep_init(), fork() failure "
	    "(privsep-priv-extraction follow-up) ===\n");

	if (test_fork_failure() != 0) failed++;

	if (failed) {
		printf("\n=== %d TEST(S) FAILED ===\n\n", failed);
		return 1;
	}

	printf("\n=== ALL TESTS PASSED ===\n\n");
	return 0;
}
