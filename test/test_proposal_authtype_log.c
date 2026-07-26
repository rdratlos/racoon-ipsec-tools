// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for doc/dev/daemon-issues.md Issue 3: cmpsatrns()
 * (proposal.c) logged "authtype mismatched" at LLV_WARNING -- the
 * default visible level -- once per (peer transform, my transform)
 * candidate pair its caller's search loop (get_ph2approval()) tries, so
 * a peer legitimately offering more than one authtype alternative made
 * it fire on every non-matching pair tried before landing on one that
 * matched, even on a completely successful negotiation.
 *
 * The fix moves this specific message to LLV_DEBUG (still available with
 * `-d`, just not at the default level) and adds a single LLV_ERROR
 * "no compatible transform found" message in get_ph2approval() itself,
 * fired once, only if every candidate pair was rejected.
 *
 * This test only covers cmpsatrns() -- get_ph2approval() takes a full
 * struct ph1handle/negotiation context to construct, which is out of
 * proportion to what this logging-only change needs to verify; its own
 * one-time outcome message follows the exact same plog()-before-`goto
 * err` pattern as the proto_id/spisize/encmode mismatches immediately
 * above it in the same function (already unexercised by any existing
 * unit test in this suite), so it is covered by code review and the
 * live strace-based verification described in this PR, not a new
 * fixture-heavy unit test.
 *
 * plog(pri, ...) (plog.h) only calls _plog() at all when pri <= loglevel,
 * so this test observes the log-level change precisely by setting
 * `loglevel` to a realistic pre-`-d` value (LLV_WARNING) and a `-d`
 * value (LLV_DEBUG) around calls to cmpsatrns(), and using a stubbed
 * _plog() (below) to record whether it was invoked -- exactly the
 * mechanism racoon itself uses to decide what reaches syslog/stdout.
 *
 * proposal.c is pulled in via a local wrapper source
 * (proposal_unittest_src.c) with -ffunction-sections, linked with
 * --gc-sections, so only cmpsatrns()'s own reachable closure
 * (s_ipsecdoi_trns()/s_ipsecdoi_attr_v() from strnames.o) is retained.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "var.h"
#include "vmbuf.h"
#include "plog.h"
#include "handler.h"
#include "proposal.h"
#include "ipsec_doi.h"

extern int cmpsatrns(int proto_id, const struct satrns *tr1,
    const struct satrns *tr2, int check_level);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/* Mirrors plog.c's definition -- plog.o itself is deliberately not
 * linked here (see the file comment above), but the plog(pri, ...)
 * macro (plog.h) reads this directly to decide whether to call _plog()
 * at all. */
u_int32_t loglevel = LLV_BASE;

static int last_pri = -1;
static int plog_calls = 0;

void
_plog(int pri, const char *func, struct sockaddr *sa, const char *fmt, ...)
{
	plog_calls++;
	last_pri = pri;
}

static int
test_authtype_mismatch_hidden_at_warning_level(void)
{
	struct satrns tr1, tr2; /* tr1: peer's, tr2: mine */

	TEST_START("authtype mismatch stays silent at the default (WARNING) level");

	memset(&tr1, 0, sizeof(tr1));
	memset(&tr2, 0, sizeof(tr2));
	tr1.trns_id = tr2.trns_id = 1; /* same transform id -- only authtype differs */
	tr1.authtype = 2;
	tr2.authtype = 3;

	loglevel = LLV_WARNING;
	plog_calls = 0;
	last_pri = -1;

	if (cmpsatrns(IPSECDOI_PROTO_IPSEC_ESP, &tr1, &tr2, PROP_CHECK_OBEY) == 0)
		TEST_FAIL("cmpsatrns() reported a match despite different authtype");

	if (plog_calls != 0) {
		printf("(_plog() called %d time(s), last pri=%d) ", plog_calls, last_pri);
		TEST_FAIL("authtype mismatch logged at the default level (issue #3 regression)");
	}

	TEST_PASS();
	return 0;
}

static int
test_authtype_mismatch_visible_at_debug_level(void)
{
	struct satrns tr1, tr2;

	TEST_START("authtype mismatch detail still available under -d (DEBUG)");

	memset(&tr1, 0, sizeof(tr1));
	memset(&tr2, 0, sizeof(tr2));
	tr1.trns_id = tr2.trns_id = 1;
	tr1.authtype = 2;
	tr2.authtype = 3;

	loglevel = LLV_DEBUG;
	plog_calls = 0;
	last_pri = -1;

	if (cmpsatrns(IPSECDOI_PROTO_IPSEC_ESP, &tr1, &tr2, PROP_CHECK_OBEY) == 0)
		TEST_FAIL("cmpsatrns() reported a match despite different authtype");

	if (plog_calls == 0)
		TEST_FAIL("authtype mismatch detail no longer logged even under -d");

	if (last_pri != LLV_DEBUG) {
		printf("(logged at pri=%d, expected LLV_DEBUG=%d) ", last_pri, LLV_DEBUG);
		TEST_FAIL("authtype mismatch logged at the wrong level");
	}

	TEST_PASS();
	return 0;
}

static int
test_matching_pair_reports_no_mismatch(void)
{
	struct satrns tr1, tr2;

	TEST_START("matching transform/authtype pair returns a match, no log noise");

	memset(&tr1, 0, sizeof(tr1));
	memset(&tr2, 0, sizeof(tr2));
	tr1.trns_id = tr2.trns_id = 1;
	tr1.authtype = tr2.authtype = 2;
	tr1.encklen = tr2.encklen = 128;

	loglevel = LLV_DEBUG;
	plog_calls = 0;
	last_pri = -1;

	if (cmpsatrns(IPSECDOI_PROTO_IPSEC_ESP, &tr1, &tr2, PROP_CHECK_OBEY) != 0)
		TEST_FAIL("cmpsatrns() reported a mismatch for identical transforms");

	if (plog_calls != 0) {
		printf("(_plog() called %d time(s)) ", plog_calls);
		TEST_FAIL("cmpsatrns() logged something for a successful match");
	}

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== cmpsatrns() authtype log-level test (daemon-issues.md Issue 3) ===\n");

	if (test_authtype_mismatch_hidden_at_warning_level() != 0)
		failed++;
	if (test_authtype_mismatch_visible_at_debug_level() != 0)
		failed++;
	if (test_matching_pair_reports_no_mismatch() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
