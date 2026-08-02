// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for admin_init()'s v0.9.1 hardening (admin.c): three
 * independent fixes bolted onto the same function --
 *
 *   1. admin_check_sockpath() gates the configured path before anything
 *      else runs (a templated/careless "listen { adminsock <path> }"
 *      must not reach mkdir()/unlink()/bind() at all).
 *   2. A pre-existing path is only unlink()'d if lstat() confirms it is
 *      already a socket (S_ISSOCK) -- previously an unconditional
 *      unlink(), which would silently destroy an unrelated file a
 *      traversal-crafted or racing path pointed at.
 *   3. monitor_fd() failure is now handled (close the socket, reset
 *      lcconf->sock_admin, return -1) instead of being ignored.
 *
 * admin_init() is already exported, so no ENABLE_UNITTEST accessor is
 * needed for it; admin_unittest_src.c pulls admin.c in the same way as
 * test_admin_check_sockpath.c/test_admin_mkdir_p.c. Unlike those two,
 * admin_init() calls close_on_exec()/plog()/monitor_fd()/lcconf, so this
 * binary links admin_test_stubs.c (real `lcconf`, a controllable
 * monitor_fd() stub) plus plog.o/logger.o/vmbuf.o/misc_noplog.o, same
 * linkage as test_monitor_fd_range.c and friends.
 *
 * The mkdir_p()+chown()+chmod() directory-creation branch (fix #1's
 * sibling, covered standalone in test_admin_mkdir_p.c) additionally
 * needs real privilege to reach its own success path here, since
 * admin_init() hardcodes chown(dir, 0, adminsock_group) -- change to
 * uid 0 requires CAP_CHOWN. test_directory_creation_and_ownership()
 * below runs that scenario only under geteuid() == 0 and reports (not
 * fails) when skipped, matching this suite's existing root-dependent
 * tests (test/README.md, CONTRIBUTING.md's "Running the Test Suite").
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "vmbuf.h"
#include "localconf.h"
#include "admin.h"

extern int admin_init(void);
extern struct localconf *lcconf;
extern int admin_test_monitor_fd_calls;
extern int admin_test_monitor_fd_ret;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static void
reset_stub_state(void)
{
	admin_test_monitor_fd_calls = 0;
	admin_test_monitor_fd_ret = 0;
}

static void
close_admin_sock(void)
{
	if (lcconf->sock_admin >= 0) {
		close(lcconf->sock_admin);
		lcconf->sock_admin = -1;
	}
}

static int
test_rejects_bad_sockpath_before_touching_filesystem(void)
{
	char base[] = "/tmp/admin_init_test.XXXXXX";
	char bad[512];
	int rc;

	TEST_START("admin_init() refuses a path admin_check_sockpath() rejects");

	if (mkdtemp(base) == NULL)
		TEST_FAIL("mkdtemp() failed");
	reset_stub_state();

	/* Ends in ".sock" (so a naive suffix-only check would accept it) but
	 * carries a ".." traversal component. */
	snprintf(bad, sizeof(bad), "%s/../evil.sock", base);
	adminsock_path = bad;
	lcconf->sock_admin = -1;

	rc = admin_init();

	if (rc == 0) {
		close_admin_sock();
		rmdir(base);
		TEST_FAIL("admin_init() accepted a traversal path");
	}
	/* admin_check_sockpath() must reject before any syscall runs. */
	if (admin_test_monitor_fd_calls != 0) {
		rmdir(base);
		TEST_FAIL("admin_init() reached monitor_fd() after rejecting the path");
	}

	rmdir(base);
	TEST_PASS();
	return 0;
}

static int
test_refuses_preexisting_non_socket(void)
{
	char base[] = "/tmp/admin_init_test.XXXXXX";
	char path[512];
	FILE *f;
	struct stat before, after;
	int rc;

	TEST_START("admin_init() refuses to replace a pre-existing non-socket file");

	if (mkdtemp(base) == NULL)
		TEST_FAIL("mkdtemp() failed");
	reset_stub_state();

	snprintf(path, sizeof(path), "%s/racoon.sock", base);
	f = fopen(path, "w");
	if (f == NULL) {
		rmdir(base);
		TEST_FAIL("failed to pre-create a plain file");
	}
	fputs("not a socket", f);
	fclose(f);
	stat(path, &before);

	adminsock_path = path;
	lcconf->sock_admin = -1;
	rc = admin_init();

	if (rc == 0) {
		close_admin_sock();
		unlink(path);
		rmdir(base);
		TEST_FAIL("admin_init() bound over a pre-existing regular file");
	}
	if (stat(path, &after) != 0) {
		rmdir(base);
		TEST_FAIL("pre-existing file was removed despite admin_init() refusing it");
	}
	if (!S_ISREG(after.st_mode) || after.st_ino != before.st_ino) {
		unlink(path);
		rmdir(base);
		TEST_FAIL("pre-existing file was replaced instead of left alone");
	}

	unlink(path);
	rmdir(base);
	TEST_PASS();
	return 0;
}

static int
test_rebinds_over_preexisting_socket(void)
{
	char base[] = "/tmp/admin_init_test.XXXXXX";
	char path[512];
	int dummy;
	struct sockaddr_un sun;
	int rc;

	TEST_START("admin_init() unlinks and rebinds a pre-existing socket");

	if (mkdtemp(base) == NULL)
		TEST_FAIL("mkdtemp() failed");
	reset_stub_state();

	snprintf(path, sizeof(path), "%s/racoon.sock", base);

	dummy = socket(AF_UNIX, SOCK_STREAM, 0);
	if (dummy < 0) {
		rmdir(base);
		TEST_FAIL("socket() failed while priming a stale socket file");
	}
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(sun.sun_path)) {
		close(dummy);
		rmdir(base);
		TEST_FAIL("test path too long for sun_path");
	}
	memcpy(sun.sun_path, path, strlen(path));
	if (bind(dummy, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		close(dummy);
		rmdir(base);
		TEST_FAIL("bind() failed while priming a stale socket file");
	}
	close(dummy);

	adminsock_path = path;
	lcconf->sock_admin = -1;
	rc = admin_init();

	if (rc != 0) {
		unlink(path);
		rmdir(base);
		TEST_FAIL("admin_init() refused to rebind over a genuine stale socket");
	}
	if (admin_test_monitor_fd_calls != 1) {
		close_admin_sock();
		unlink(path);
		rmdir(base);
		TEST_FAIL("admin_init() did not reach monitor_fd() on the success path");
	}

	close_admin_sock();
	unlink(path);
	rmdir(base);
	TEST_PASS();
	return 0;
}

static int
test_monitor_fd_failure_cleans_up(void)
{
	char base[] = "/tmp/admin_init_test.XXXXXX";
	char path[512];
	int rc;

	TEST_START("admin_init() closes the socket and resets state when monitor_fd() fails");

	if (mkdtemp(base) == NULL)
		TEST_FAIL("mkdtemp() failed");
	reset_stub_state();
	admin_test_monitor_fd_ret = -1;

	snprintf(path, sizeof(path), "%s/racoon.sock", base);
	adminsock_path = path;
	lcconf->sock_admin = -1;

	rc = admin_init();

	if (rc == 0) {
		close_admin_sock();
		unlink(path);
		rmdir(base);
		TEST_FAIL("admin_init() reported success despite monitor_fd() failing");
	}
	if (lcconf->sock_admin != -1) {
		close_admin_sock();
		unlink(path);
		rmdir(base);
		TEST_FAIL("lcconf->sock_admin was not reset to -1 after monitor_fd() failure");
	}

	unlink(path);
	rmdir(base);
	reset_stub_state();
	TEST_PASS();
	return 0;
}

static int
test_null_adminsock_path_short_circuits(void)
{
	int rc;

	TEST_START("admin_init() short-circuits when adminsock_path is NULL");

	reset_stub_state();
	adminsock_path = NULL;
	lcconf->sock_admin = -123;

	rc = admin_init();

	if (rc != 0)
		TEST_FAIL("admin_init() did not return success for a disabled admin port");
	if (lcconf->sock_admin != -1)
		TEST_FAIL("lcconf->sock_admin was not set to -1");
	if (admin_test_monitor_fd_calls != 0)
		TEST_FAIL("monitor_fd() was reached despite a NULL adminsock_path");

	TEST_PASS();
	return 0;
}

/*
 * Root-only: exercises mkdir_p()+chown()+chmod() on the runtime directory,
 * the third hunk of this same v0.9.1 hunk. See this file's header comment
 * for why chown(dir, 0, adminsock_group) needs CAP_CHOWN to succeed.
 */
static int
test_directory_creation_and_ownership(void)
{
	char base[] = "/tmp/admin_init_test.XXXXXX";
	char subdir[512], path[600];
	struct stat st;
	int rc;

	TEST_START("admin_init() creates and owns a missing runtime directory (root only)");

	if (geteuid() != 0) {
		printf("SKIP (not root) ");
		TEST_PASS();
		return 0;
	}

	if (mkdtemp(base) == NULL)
		TEST_FAIL("mkdtemp() failed");
	reset_stub_state();

	snprintf(subdir, sizeof(subdir), "%s/newsubdir", base);
	snprintf(path, sizeof(path), "%s/racoon.sock", subdir);
	adminsock_path = path;
	lcconf->sock_admin = -1;

	rc = admin_init();

	if (rc != 0) {
		rmdir(subdir);
		rmdir(base);
		TEST_FAIL("admin_init() failed to create the runtime directory as root");
	}
	if (stat(subdir, &st) != 0 || !S_ISDIR(st.st_mode)) {
		close_admin_sock();
		unlink(path);
		rmdir(subdir);
		rmdir(base);
		TEST_FAIL("runtime directory was not created");
	}
	if ((st.st_mode & 0777) != 0750) {
		printf("mode = 0%o, expected 0750 ", st.st_mode & 0777);
		close_admin_sock();
		unlink(path);
		rmdir(subdir);
		rmdir(base);
		TEST_FAIL("runtime directory has the wrong mode");
	}

	close_admin_sock();
	unlink(path);
	rmdir(subdir);
	rmdir(base);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== admin_init() hardening test ===\n");

	if (test_rejects_bad_sockpath_before_touching_filesystem() != 0)
		failed++;
	if (test_refuses_preexisting_non_socket() != 0)
		failed++;
	if (test_rebinds_over_preexisting_socket() != 0)
		failed++;
	if (test_monitor_fd_failure_cleans_up() != 0)
		failed++;
	if (test_null_adminsock_path_short_circuits() != 0)
		failed++;
	if (test_directory_creation_and_ownership() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
