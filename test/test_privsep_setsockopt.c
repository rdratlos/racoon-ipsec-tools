// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for privsep_setsockopt()'s return contract (issue #105,
 * found by live privsep testing on Linux -- see the audit report's §2.4.2).
 *
 * The function used to open with:
 *
 *      if ((err = setsockopt(s, level, optname, optval, optlen) == 0) ||
 *          (saved_errno = errno) != EACCES || geteuid() == 0) {
 *              ...
 *              return err;
 *      }
 *
 * "err = setsockopt(...) == 0" assigns the *comparison*, not the call's
 * result: err came out 1 on success and 0 on failure. Since every caller
 * tests "< 0", that meant every failure this function did not escalate was
 * reported to the caller as success.
 *
 * What it hid: the escalation condition tested EACCES alone, which is what
 * the KAME stack returns for IP_IPSEC_POLICY on an unprivileged socket.
 * Linux's xfrm returns EPERM, so under privsep on Linux the privileged
 * process was never asked, setsockopt_bypass()'s "in/out bypass" policies
 * (sockmisc.c) were never applied to racoon's own sockets, and
 * setsockopt_bypass() was told it had succeeded. The only visible trace was
 * a log line -- "privsep_setsockopt (Operation not permitted)" -- next to a
 * socket that then carried on as if nothing had happened.
 *
 * This pins the contract that made that possible, which is checkable
 * without a privsep host or a PF_KEY/XFRM kernel: whatever
 * privsep_setsockopt() decides to do about privileges, a failure it
 * returns from must look like a failure.
 *
 * Both cases below run identically as root and as an ordinary user. The
 * failing one uses an errno (ENOPROTOOPT) that is not a privilege refusal,
 * so no escalation is attempted either way; if a future change did escalate
 * it, privsep_sock is -1 in a unit test and the send fails, which is still
 * a negative return.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern int privsep_setsockopt(int s, int level, int optname,
    const void *optval, socklen_t optlen);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
test_failure_is_reported_as_failure(void)
{
	int s, ret, yes = 1;

	TEST_START("privsep_setsockopt() returns < 0 when setsockopt() fails");

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		TEST_FAIL("socket() failed");

	/*
	 * A nonexistent option: fails with ENOPROTOOPT, which is not a
	 * privilege refusal, so this exercises the non-escalating return
	 * path -- the one that used to hand back 0.
	 */
	errno = 0;
	ret = privsep_setsockopt(s, SOL_SOCKET, -1, &yes, sizeof(yes));

	close(s);

	if (ret >= 0)
		TEST_FAIL("reported success for a setsockopt() that failed");

	TEST_PASS();
	return 0;
}

static int
test_success_is_reported_as_success(void)
{
	int s, ret, yes = 1;

	TEST_START("privsep_setsockopt() returns 0 when setsockopt() succeeds");

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		TEST_FAIL("socket() failed");

	ret = privsep_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes,
	    sizeof(yes));

	close(s);

	if (ret != 0)
		TEST_FAIL("did not report plain success as 0");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep_setsockopt() return contract test (issue #105) ===\n");

	if (test_failure_is_reported_as_failure() != 0)
		failed++;
	if (test_success_is_reported_as_success() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
