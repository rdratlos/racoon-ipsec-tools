// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for mkdir_p() (admin.c) -- a "mkdir -p" helper new in
 * the v0.9.1 admin.c hardening pass, letting admin_init() create the
 * admin socket's runtime directory (e.g. /var/run/racoon) itself instead
 * of depending on systemd's RuntimeDirectory= or external tmpfiles.d
 * tooling.
 *
 * mkdir_p() is static, so this drives it through the mkdir_p_unittest()
 * accessor (admin.c, ENABLE_UNITTEST) rather than admin_init() itself:
 * admin_init()'s own call site additionally needs chown()/chmod() to
 * succeed (root-only in general) just to reach mkdir_p()'s return value,
 * which is unrelated to what this test wants to isolate. See
 * test_admin_init.c for the end-to-end admin_init() coverage, including
 * the parts of this same hunk that DO need root.
 *
 * admin_unittest_src.c pulls admin.c in (-ffunction-sections/
 * --gc-sections, same pattern as isakmp_unittest_src.c/
 * session_unittest_src.c); mkdir_p() only calls strlcpy()/mkdir(), so
 * this binary needs no admin_test_stubs.c.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

extern int mkdir_p_unittest(const char *path, mode_t mode);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
is_dir(const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return 0;
	return S_ISDIR(st.st_mode);
}

static int
test_creates_nested_path(void)
{
	char base[] = "/tmp/admin_mkdir_p_test.XXXXXX";
	char nested[512];
	int rc;

	TEST_START("mkdir_p() creates every missing parent component");

	if (mkdtemp(base) == NULL)
		TEST_FAIL("mkdtemp() failed");

	snprintf(nested, sizeof(nested), "%s/a/b/c", base);
	rc = mkdir_p_unittest(nested, 0750);

	if (rc != 0) {
		rmdir(base);
		TEST_FAIL("mkdir_p() returned nonzero for a fresh nested path");
	}
	if (!is_dir(nested)) {
		rmdir(nested);
		rmdir(base);
		TEST_FAIL("leaf directory was not created");
	}

	rmdir(nested);
	{
		char b[512], a[512];
		snprintf(b, sizeof(b), "%s/a/b", base);
		snprintf(a, sizeof(a), "%s/a", base);
		rmdir(b);
		rmdir(a);
	}
	rmdir(base);
	TEST_PASS();
	return 0;
}

static int
test_tolerates_preexisting_components(void)
{
	char base[] = "/tmp/admin_mkdir_p_test.XXXXXX";
	char nested[512];
	int rc1, rc2;

	TEST_START("mkdir_p() tolerates EEXIST on already-created components");

	if (mkdtemp(base) == NULL)
		TEST_FAIL("mkdtemp() failed");

	snprintf(nested, sizeof(nested), "%s/x/y", base);
	rc1 = mkdir_p_unittest(nested, 0750);
	/* Second call: every component (including the leaf) already exists. */
	rc2 = mkdir_p_unittest(nested, 0750);

	if (rc1 != 0 || rc2 != 0) {
		rmdir(nested);
		{
			char x[512];
			snprintf(x, sizeof(x), "%s/x", base);
			rmdir(x);
		}
		rmdir(base);
		TEST_FAIL("mkdir_p() failed on a path it had already created");
	}

	rmdir(nested);
	{
		char x[512];
		snprintf(x, sizeof(x), "%s/x", base);
		rmdir(x);
	}
	rmdir(base);
	TEST_PASS();
	return 0;
}

static int
test_rejects_overlong_path(void)
{
	char toolong[8192];
	size_t i;

	TEST_START("mkdir_p() rejects a path longer than MAXPATHLEN");

	for (i = 0; i < sizeof(toolong) - 1; i++)
		toolong[i] = 'a';
	toolong[sizeof(toolong) - 1] = '\0';

	errno = 0;
	if (mkdir_p_unittest(toolong, 0750) == 0)
		TEST_FAIL("mkdir_p() accepted an oversized path");
	if (errno != ENAMETOOLONG) {
		printf("errno = %d, expected ENAMETOOLONG ", errno);
		TEST_FAIL("wrong errno for oversized path");
	}

	TEST_PASS();
	return 0;
}

static int
test_creates_single_level_directory(void)
{
	char base[] = "/tmp/admin_mkdir_p_test.XXXXXX";
	char single[512];
	int rc;

	TEST_START("mkdir_p() creates a single already-parented directory");

	if (mkdtemp(base) == NULL)
		TEST_FAIL("mkdtemp() failed");

	snprintf(single, sizeof(single), "%s/only", base);
	rc = mkdir_p_unittest(single, 0750);

	if (rc != 0 || !is_dir(single)) {
		rmdir(single);
		rmdir(base);
		TEST_FAIL("single-level directory was not created");
	}

	rmdir(single);
	rmdir(base);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== mkdir_p() \"mkdir -p\" helper test ===\n");

	if (test_creates_nested_path() != 0)
		failed++;
	if (test_tolerates_preexisting_components() != 0)
		failed++;
	if (test_rejects_overlong_path() != 0)
		failed++;
	if (test_creates_single_level_directory() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
