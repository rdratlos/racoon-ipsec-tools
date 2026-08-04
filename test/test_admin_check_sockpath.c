// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for admin_check_sockpath() (admin.c) -- racoon.conf lets
 * an admin point the admin socket at an arbitrary path via "listen {
 * adminsock <path> ... ; }". Since admin_init() runs as root (before
 * privilege separation drops), a careless or templated config pointing
 * that path at an existing system file would cause it to be unlink()'d
 * and replaced by a socket, and its parent directories to be created
 * outright. admin_check_sockpath() is the gate that rejects everything
 * but a conventional "racoon.sock"/"*.sock"/"*.socket" name with no ".."
 * traversal component.
 *
 * This is one of the two brand-new functions in the v0.9.1 admin.c
 * hardening pass (the other is mkdir_p(), test_admin_mkdir_p.c) and
 * doubles as the racoonctl-facing control-socket's own path-validation
 * surface, so it gets full branch coverage here.
 *
 * admin_check_sockpath() is already exported (admin.h), so this test
 * needs no ENABLE_UNITTEST accessor; admin_unittest_src.c just pulls
 * admin.c in as a translation unit local to test/ (matching
 * isakmp_unittest_src.c/session_unittest_src.c). It is self-contained
 * (only strlen()/strstr()/strncmp()/strcmp()/strrchr()), so unlike the
 * other admin.c tests it needs neither admin_test_stubs.c nor
 * -ffunction-sections/--gc-sections.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

extern int admin_check_sockpath(const char *path);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
expect(const char *path, int want_ok, const char *why)
{
	int got = admin_check_sockpath(path);

	if (want_ok && got != 0) {
		printf("admin_check_sockpath(\"%s\") = %d, expected 0 (%s) ",
		    path ? path : "(null)", got, why);
		return -1;
	}
	if (!want_ok && got == 0) {
		printf("admin_check_sockpath(\"%s\") = 0, expected rejection (%s) ",
		    path ? path : "(null)", why);
		return -1;
	}
	return 0;
}

static int
test_null_and_empty_rejected(void)
{
	TEST_START("NULL and empty paths are rejected");

	if (expect(NULL, 0, "NULL path") != 0)
		TEST_FAIL("NULL not rejected");
	if (expect("", 0, "empty path") != 0)
		TEST_FAIL("empty string not rejected");

	TEST_PASS();
	return 0;
}

static int
test_traversal_rejected(void)
{
	TEST_START("\"..\" path-traversal components are rejected");

	if (expect("/var/run/racoon/../../etc/passwd", 0, "embedded /../") != 0)
		TEST_FAIL("embedded /../ not rejected");
	if (expect("../racoon.sock", 0, "leading ../") != 0)
		TEST_FAIL("leading ../ not rejected");
	if (expect("..", 0, "bare ..") != 0)
		TEST_FAIL("bare .. not rejected");
	if (expect("/var/run/racoon/..", 0, "trailing /..") != 0)
		TEST_FAIL("trailing /.. not rejected");

	TEST_PASS();
	return 0;
}

static int
test_empty_basename_rejected(void)
{
	TEST_START("a path with no filename component is rejected");

	if (expect("/var/run/racoon/", 0, "trailing slash, empty basename") != 0)
		TEST_FAIL("trailing-slash path not rejected");

	TEST_PASS();
	return 0;
}

static int
test_conventional_names_accepted(void)
{
	TEST_START("racoon.sock / *.sock / *.socket are accepted");

	if (expect("racoon.sock", 1, "bare racoon.sock") != 0)
		TEST_FAIL("bare racoon.sock rejected");
	if (expect("/var/run/racoon/racoon.sock", 1, "conventional path") != 0)
		TEST_FAIL("conventional racoon.sock path rejected");
	if (expect("/var/run/racoon/custom.sock", 1, "*.sock suffix") != 0)
		TEST_FAIL(".sock suffix rejected");
	if (expect("/var/run/racoon/custom.socket", 1, "*.socket suffix") != 0)
		TEST_FAIL(".socket suffix rejected");

	TEST_PASS();
	return 0;
}

static int
test_wrong_suffix_rejected(void)
{
	TEST_START("a non-socket file name is rejected");

	if (expect("/var/run/racoon/racoon.conf", 0, "wrong suffix") != 0)
		TEST_FAIL("racoon.conf not rejected");
	if (expect("/etc/passwd", 0, "arbitrary system file") != 0)
		TEST_FAIL("/etc/passwd not rejected");

	TEST_PASS();
	return 0;
}

/*
 * The suffix checks require strictly *more* than the bare suffix itself
 * (blen > 5 / blen > 7, admin.c) -- ".sock" and ".socket" alone have no
 * base name in front of the dot and must not slip through as if they
 * were an (empty) name plus suffix.
 */
static int
test_bare_suffix_rejected(void)
{
	TEST_START("a bare \".sock\"/\".socket\" with no basename is rejected");

	if (expect(".sock", 0, "bare .sock") != 0)
		TEST_FAIL(".sock alone not rejected");
	if (expect(".socket", 0, "bare .socket") != 0)
		TEST_FAIL(".socket alone not rejected");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== admin_check_sockpath() path-validation test ===\n");

	if (test_null_and_empty_rejected() != 0)
		failed++;
	if (test_traversal_rejected() != 0)
		failed++;
	if (test_empty_basename_rejected() != 0)
		failed++;
	if (test_conventional_names_accepted() != 0)
		failed++;
	if (test_wrong_suffix_rejected() != 0)
		failed++;
	if (test_bare_suffix_rejected() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
