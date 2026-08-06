// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for flushph1() (handler.c): a live valgrind run on a
 * real roadwarrior client (racoonctl delete-sa/flush-sa against a running
 * racoon) reported an invalid write/read in unbindph12() (called from
 * remph2(), called from purge_remote()), on memory delph1() had already
 * freed several admin commands earlier via flushph1().
 *
 * Root cause: flushph1() freed every ph1handle via delph1() without first
 * discarding the ph2handles still bound to it (iph1->ph2tree). Any such
 * ph2handle survives in ph2tree with a ->ph1 pointer dangling into freed
 * memory; the first thing afterward to touch it (purge_remote()'s
 * remph2() -> unbindph12(), or a later flushph2()) dereferences that
 * pointer -- a use-after-free. isakmp_ph1delete() (the normal
 * one-ph1-at-a-time teardown path) has always discarded bound ph2handles
 * first; flushph1() never did.
 *
 * This links the real handler.o (not a wrapper-TU -- newph1()/insph1()/
 * newph2()/insph2()/bindph12()/flushph1() are all already exported) plus
 * plog.o/logger.o/vmbuf.o/misc_noplog.o (same real objects
 * test_admin_handler.c links) and handler_flushph1_test_stubs.c for
 * everything else flushph1()'s call graph needs. -ffunction-sections +
 * --gc-sections (same isolation test_admin_handler.c already relies on)
 * discards every handler.c function this test doesn't call, so nothing
 * outside that call graph needs a stub.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "vmbuf.h"
#include "schedule.h"
#include "handler.h"

extern int handler_test_delete_spd_calls;
extern int handler_test_isakmp_info_send_d1_calls;
extern int handler_test_isakmp_info_send_d2_calls;

extern int ph1tree_count_unittest(void);
extern int ph2tree_count_unittest(void);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static struct sockaddr *
dummy_sockaddr(in_addr_t addr)
{
	struct sockaddr_in *sin;

	sin = malloc(sizeof(*sin));
	if (sin == NULL)
		return NULL;
	memset(sin, 0, sizeof(*sin));
#ifdef HAVE_SA_LEN
	sin->sin_len = sizeof(*sin);
#endif
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
	return (struct sockaddr *)sin;
}

/*
 * A ph1handle with one ph2handle still bound to it when flushph1() is
 * called must come out the other side with both gone from their
 * respective trees -- not just the ph1. Before the fix, flushph1() never
 * touched the ph2, so it survived flushph1() with a dangling ->ph1
 * pointer; ph2tree_count_unittest() catches that directly (no need to
 * actually dereference the dangling pointer to prove it was left
 * behind).
 */
static int
test_flushph1_discards_bound_ph2(void)
{
	struct ph1handle *iph1;
	struct ph2handle *iph2;

	TEST_START("flushph1() discards phase2 handles still bound to the phase1 it frees");

	initph1tree();
	initph2tree();

	iph1 = newph1();
	if (iph1 == NULL)
		TEST_FAIL("newph1() returned NULL");
	iph1->remote = dummy_sockaddr(htonl(0x0a010101)); /* 10.1.1.1 */
	iph1->local = dummy_sockaddr(htonl(0x0a010102));  /* 10.1.1.2 */
	if (iph1->remote == NULL || iph1->local == NULL)
		TEST_FAIL("failed to allocate dummy addresses");
	if (insph1(iph1) != 0)
		TEST_FAIL("insph1() rejected a handle with a valid remote address");

	iph2 = newph2();
	if (iph2 == NULL)
		TEST_FAIL("newph2() returned NULL");
	bindph12(iph1, iph2);
	if (insph2(iph2) != 0)
		TEST_FAIL("insph2() failed");

	if (ph1tree_count_unittest() != 1 || ph2tree_count_unittest() != 1)
		TEST_FAIL("fixture setup did not leave exactly one ph1 and one ph2 in their trees");

	handler_test_delete_spd_calls = 0;
	handler_test_isakmp_info_send_d1_calls = 0;
	handler_test_isakmp_info_send_d2_calls = 0;

	flushph1();

	if (ph1tree_count_unittest() != 0)
		TEST_FAIL("ph1tree still has an entry after flushph1()");
	if (ph2tree_count_unittest() != 0)
		TEST_FAIL("ph2tree still has the ph2handle that was bound to the flushed ph1 -- "
		    "it is now orphaned with a dangling ->ph1 pointer, exactly the "
		    "use-after-free valgrind reported on a live roadwarrior client");
	if (handler_test_delete_spd_calls != 1)
		TEST_FAIL("delete_spd() was not called exactly once for the bound ph2handle");

	TEST_PASS();
	return 0;
}

/*
 * Established phase1/phase2 handles must still get their delete
 * notifications sent -- the fix must not turn flushph1() into a silent
 * discard for SAs a peer believes are still up.
 */
static int
test_flushph1_sends_delete_notifications_for_established_sas(void)
{
	struct ph1handle *iph1;
	struct ph2handle *iph2;

	TEST_START("flushph1() sends delete notifications for established phase1/phase2 SAs");

	initph1tree();
	initph2tree();

	iph1 = newph1();
	if (iph1 == NULL)
		TEST_FAIL("newph1() returned NULL");
	iph1->remote = dummy_sockaddr(htonl(0x0a010101));
	iph1->local = dummy_sockaddr(htonl(0x0a010102));
	if (iph1->remote == NULL || iph1->local == NULL)
		TEST_FAIL("failed to allocate dummy addresses");
	iph1->status = PHASE1ST_ESTABLISHED;
	if (insph1(iph1) != 0)
		TEST_FAIL("insph1() rejected a handle with a valid remote address");

	iph2 = newph2();
	if (iph2 == NULL)
		TEST_FAIL("newph2() returned NULL");
	iph2->status = PHASE2ST_ESTABLISHED;
	bindph12(iph1, iph2);
	if (insph2(iph2) != 0)
		TEST_FAIL("insph2() failed");

	handler_test_delete_spd_calls = 0;
	handler_test_isakmp_info_send_d1_calls = 0;
	handler_test_isakmp_info_send_d2_calls = 0;

	flushph1();

	if (handler_test_isakmp_info_send_d1_calls != 1)
		TEST_FAIL("isakmp_info_send_d1() was not called for the established phase1 SA");
	if (handler_test_isakmp_info_send_d2_calls != 1)
		TEST_FAIL("isakmp_info_send_d2() was not called for the established phase2 SA");
	if (ph1tree_count_unittest() != 0 || ph2tree_count_unittest() != 0)
		TEST_FAIL("trees were not left empty after flushph1()");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== flushph1() test ===\n");

	if (test_flushph1_discards_bound_ph2() != 0)
		failed++;
	if (test_flushph1_sends_delete_notifications_for_established_sas() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
