// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for privsep_setsockopt()'s escalation decision
 * (privsep.c): under privsep on Linux, setting the IKE sockets' bypass
 * IP_IPSEC_POLICY/IPV6_IPSEC_POLICY requires CAP_NET_ADMIN, and a
 * capable() failure for that is reported as EPERM, not EACCES. The
 * escalation check used to test only for EACCES (matching bind()'s low-
 * port restriction, which really is EACCES on both Linux and BSD), so an
 * unprivileged child's direct setsockopt() attempt -- which fails with
 * EPERM on Linux -- never actually asked the privileged process to do it;
 * it just gave up and logged "privsep_setsockopt (Operation not
 * permitted)". The IKE sockets' bypass policy was then silently never
 * applied under privsep on Linux.
 *
 * privsep_setsockopt_should_escalate() (privsep.c, static) is the
 * extracted decision this test drives directly, via the
 * -DENABLE_UNITTEST-only accessor privsep_setsockopt_should_escalate_unittest():
 * given a direct attempt's result and errno, should it be escalated to
 * the privileged process rather than returned as-is.
 *
 * privsep.c is pulled in via a local wrapper source (privsep_unittest_src.c),
 * this project's established pattern for unit-testing a static function.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <errno.h>

extern int privsep_setsockopt_should_escalate_unittest(int err,
    int saved_errno, int is_root);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
test_success_never_escalates(void)
{
	TEST_START("a successful direct attempt is never escalated");

	if (privsep_setsockopt_should_escalate_unittest(0, 0, 0) != 0)
		TEST_FAIL("escalated a successful (err == 0) attempt");

	TEST_PASS();
	return 0;
}

static int
test_eacces_escalates_when_not_root(void)
{
	TEST_START("EACCES as non-root escalates (bind()'s low-port shape)");

	if (privsep_setsockopt_should_escalate_unittest(-1, EACCES, 0) != 1)
		TEST_FAIL("did not escalate a non-root EACCES failure");

	TEST_PASS();
	return 0;
}

static int
test_eperm_escalates_when_not_root(void)
{
	TEST_START("EPERM as non-root escalates (the Linux CAP_NET_ADMIN shape -- the regression)");

	if (privsep_setsockopt_should_escalate_unittest(-1, EPERM, 0) != 1)
		TEST_FAIL("did not escalate a non-root EPERM failure -- "
		    "this is the exact bug: Linux's capable(CAP_NET_ADMIN) "
		    "check fails with EPERM, not EACCES, for "
		    "IP_IPSEC_POLICY/IPV6_IPSEC_POLICY");

	TEST_PASS();
	return 0;
}

static int
test_other_errno_never_escalates(void)
{
	TEST_START("an unrelated errno (e.g. EINVAL) is never escalated");

	if (privsep_setsockopt_should_escalate_unittest(-1, EINVAL, 0) != 0)
		TEST_FAIL("escalated a failure unrelated to privilege (EINVAL)");

	TEST_PASS();
	return 0;
}

static int
test_root_never_escalates(void)
{
	TEST_START("a failure while already root is never escalated (no privileged process to ask)");

	if (privsep_setsockopt_should_escalate_unittest(-1, EACCES, 1) != 0)
		TEST_FAIL("escalated a root EACCES failure");
	if (privsep_setsockopt_should_escalate_unittest(-1, EPERM, 1) != 0)
		TEST_FAIL("escalated a root EPERM failure");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep_setsockopt() escalation-decision test (daemon-issues.md follow-up) ===\n");

	if (test_success_never_escalates() != 0)
		failed++;
	if (test_eacces_escalates_when_not_root() != 0)
		failed++;
	if (test_eperm_escalates_when_not_root() != 0)
		failed++;
	if (test_other_errno_never_escalates() != 0)
		failed++;
	if (test_root_never_escalates() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
