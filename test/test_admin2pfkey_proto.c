// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for admin2pfkey_proto() (admin.c) -- maps this
 * project's own ADMIN_PROTO_* wire constants (admin.h, racoonctl-facing)
 * onto the kernel's SADB_SATYPE_* PF_KEY constants (net/pfkeyv2.h),
 * silently referencing whichever value that header currently assigns.
 *
 * A test written as
 *     admin2pfkey_proto(ADMIN_PROTO_AH) == SADB_SATYPE_AH
 * is tautological: it re-derives the same macro on both sides, so it
 * cannot fail even if pfkeyv2.h's actual numeric value drifted (a kernel
 * header update, a different PF_KEY implementation, a typo introduced
 * while editing admin2pfkey_proto() itself that happens to still compile
 * against the same macro name). This test instead pins the literal wire
 * values PF_KEY has used since RFC 2367 (SADB_SATYPE_UNSPEC=0,
 * SADB_SATYPE_AH=2, SADB_SATYPE_ESP=3) as a canary: if net/pfkeyv2.h
 * ever renumbers these, or admin2pfkey_proto()'s switch is edited to
 * return the wrong one, this test catches it even though the macro-based
 * assertion could not.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/pfkeyv2.h>

#include "admin.h"

extern int admin2pfkey_proto(u_int proto);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
test_maps_to_literal_pf_key_wire_values(void)
{
	int got;

	TEST_START("ADMIN_PROTO_* map to their literal RFC 2367 PF_KEY wire values");

	got = admin2pfkey_proto(ADMIN_PROTO_IPSEC);
	if (got != 0) {
		printf("ADMIN_PROTO_IPSEC -> %d, expected 0 (SADB_SATYPE_UNSPEC) ", got);
		TEST_FAIL("ADMIN_PROTO_IPSEC did not map to the literal UNSPEC value");
	}

	got = admin2pfkey_proto(ADMIN_PROTO_AH);
	if (got != 2) {
		printf("ADMIN_PROTO_AH -> %d, expected 2 (SADB_SATYPE_AH) ", got);
		TEST_FAIL("ADMIN_PROTO_AH did not map to the literal AH value");
	}

	got = admin2pfkey_proto(ADMIN_PROTO_ESP);
	if (got != 3) {
		printf("ADMIN_PROTO_ESP -> %d, expected 3 (SADB_SATYPE_ESP) ", got);
		TEST_FAIL("ADMIN_PROTO_ESP did not map to the literal ESP value");
	}

	TEST_PASS();
	return 0;
}

/*
 * Also assert consistency against the macros themselves: if this ever
 * fails while the literal-value test above still passes, net/pfkeyv2.h
 * has actually been renumbered underneath admin.c -- exactly the
 * scenario this file exists to catch.
 */
static int
test_macros_still_match_literal_wire_values(void)
{
	TEST_START("SADB_SATYPE_* macros still match the pinned literal values");

	if (SADB_SATYPE_UNSPEC != 0)
		TEST_FAIL("SADB_SATYPE_UNSPEC no longer equals 0 -- pfkeyv2.h was renumbered");
	if (SADB_SATYPE_AH != 2)
		TEST_FAIL("SADB_SATYPE_AH no longer equals 2 -- pfkeyv2.h was renumbered");
	if (SADB_SATYPE_ESP != 3)
		TEST_FAIL("SADB_SATYPE_ESP no longer equals 3 -- pfkeyv2.h was renumbered");

	TEST_PASS();
	return 0;
}

static int
test_unrecognized_proto_rejected(void)
{
	TEST_START("an unrecognized proto value returns -1 instead of a garbage satype");

	if (admin2pfkey_proto(ADMIN_PROTO_ISAKMP) != -1)
		TEST_FAIL("ADMIN_PROTO_ISAKMP (not a pfkey satype at all) was not rejected");
	if (admin2pfkey_proto(ADMIN_PROTO_INTERNAL) != -1)
		TEST_FAIL("ADMIN_PROTO_INTERNAL was not rejected");
	if (admin2pfkey_proto(0xdead) != -1)
		TEST_FAIL("an arbitrary garbage proto value was not rejected");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== admin2pfkey_proto() PF_KEY wire-value mapping test ===\n");

	if (test_maps_to_literal_pf_key_wire_values() != 0)
		failed++;
	if (test_macros_still_match_literal_wire_values() != 0)
		failed++;
	if (test_unrecognized_proto_rejected() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
