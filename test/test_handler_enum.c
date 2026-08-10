// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression coverage for enumph1()/enumph2() (handler.c) driven directly
 * against the real functions -- not the stand-ins status_test_stubs.c/
 * admin_test_stubs.c hand back for every other test that calls into them.
 * Coverage analysis on the wider suite showed status.c's call sites to
 * enumph1()/enumph2() as covered (status_dump() is well-tested) while
 * handler.c's own definitions showed zero coverage: every test that
 * reaches either function goes through one of those two stub files, so the
 * real loop bodies -- including the precomputed-next use-after-free fix
 * both functions carry (see their own header comments in handler.c: a live
 * valgrind run on delete-sa/flush-sa caught enumph1() dereferencing a
 * ph1handle enum_func() had just freed) -- were never actually exercised
 * anywhere in the suite.
 *
 * Links the real handler_ffs.o (same as test_handler_flushph1.c) plus
 * sockmisc_ffs.o for a real cmpsaddr() (needed by both functions'
 * selector-filtering path, which this test wants to exercise for real, not
 * stub around) and handler_enum_test_stubs.c for the rest of delph1()/
 * delph2()'s call graph.
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

/* ------------------------------------------------------------------ */
/* enumph1()                                                             */
/* ------------------------------------------------------------------ */

static int
count_ph1_cb(struct ph1handle *iph1, void *arg)
{
	(*(int *)arg)++;
	return 0;
}

static int
test_enumph1_visits_all_entries(void)
{
	struct ph1handle *a, *b, *c;
	int count = 0;

	TEST_START("enumph1(NULL, ...) visits every entry in ph1tree");

	initph1tree();

	a = newph1(); a->remote = dummy_sockaddr(htonl(0x0a010101)); a->local = dummy_sockaddr(htonl(0x0a0101fe));
	b = newph1(); b->remote = dummy_sockaddr(htonl(0x0a010102)); b->local = dummy_sockaddr(htonl(0x0a0101fe));
	c = newph1(); c->remote = dummy_sockaddr(htonl(0x0a010103)); c->local = dummy_sockaddr(htonl(0x0a0101fe));
	if (a == NULL || b == NULL || c == NULL)
		TEST_FAIL("newph1() returned NULL");
	if (insph1(a) != 0 || insph1(b) != 0 || insph1(c) != 0)
		TEST_FAIL("insph1() failed for a fixture with a valid remote address");

	if (enumph1(NULL, count_ph1_cb, &count) != 0)
		TEST_FAIL("enumph1() returned nonzero with a callback that always returns 0");
	if (count != 3)
		TEST_FAIL("expected all 3 ph1handles visited");

	remph1(a); delph1(a);
	remph1(b); delph1(b);
	remph1(c); delph1(c);

	TEST_PASS();
	return 0;
}

struct addr_match_ctx {
	struct sockaddr *want_remote;
	int matched;
	int total;
};

static int
match_remote_cb(struct ph1handle *iph1, void *arg)
{
	struct addr_match_ctx *ctx = (struct addr_match_ctx *)arg;

	ctx->total++;
	if (iph1->remote == ctx->want_remote)
		ctx->matched++;
	return 0;
}

static int
test_enumph1_selector_filters_by_remote(void)
{
	struct ph1handle *a, *b;
	struct ph1selector sel;
	struct addr_match_ctx ctx;

	TEST_START("enumph1() with a sel->remote filter visits only the matching entry");

	initph1tree();

	a = newph1(); a->remote = dummy_sockaddr(htonl(0x0a010101)); a->local = dummy_sockaddr(htonl(0x0a0101fe));
	b = newph1(); b->remote = dummy_sockaddr(htonl(0x0a010102)); b->local = dummy_sockaddr(htonl(0x0a0101fe));
	if (a == NULL || b == NULL)
		TEST_FAIL("newph1() returned NULL");
	if (insph1(a) != 0 || insph1(b) != 0)
		TEST_FAIL("insph1() failed");

	memset(&sel, 0, sizeof(sel));
	sel.remote = a->remote;

	ctx.want_remote = a->remote;
	ctx.matched = 0;
	ctx.total = 0;

	if (enumph1(&sel, match_remote_cb, &ctx) != 0)
		TEST_FAIL("enumph1() returned nonzero");
	if (ctx.total != 1)
		TEST_FAIL("expected exactly one ph1handle to pass the sel->remote filter");
	if (ctx.matched != 1)
		TEST_FAIL("the one entry that passed the filter was not the one it should have matched");

	remph1(a); delph1(a);
	remph1(b); delph1(b);

	TEST_PASS();
	return 0;
}

struct delete_all_ctx {
	int visits;
};

static int
delete_current_ph1_cb(struct ph1handle *iph1, void *arg)
{
	struct delete_all_ctx *ctx = (struct delete_all_ctx *)arg;

	ctx->visits++;
	remph1(iph1);
	delph1(iph1);
	return 0;
}

/*
 * The exact hazard enumph1()'s header comment documents: admin.c's
 * delete-sa/flush-sa path calls back into code that frees the very
 * ph1handle a plain LIST_FOREACH would only read *after* enum_func()
 * returns to advance. Confirmed live via valgrind on a roadwarrior client
 * before the precomputed-next fix; never exercised against the real
 * function by any test since.
 */
static int
test_enumph1_survives_delete_during_iteration(void)
{
	struct ph1handle *a, *b, *c;
	struct delete_all_ctx ctx;

	TEST_START("enumph1() survives enum_func() deleting the current entry");

	initph1tree();

	a = newph1(); a->remote = dummy_sockaddr(htonl(0x0a010101)); a->local = dummy_sockaddr(htonl(0x0a0101fe));
	b = newph1(); b->remote = dummy_sockaddr(htonl(0x0a010102)); b->local = dummy_sockaddr(htonl(0x0a0101fe));
	c = newph1(); c->remote = dummy_sockaddr(htonl(0x0a010103)); c->local = dummy_sockaddr(htonl(0x0a0101fe));
	if (a == NULL || b == NULL || c == NULL)
		TEST_FAIL("newph1() returned NULL");
	if (insph1(a) != 0 || insph1(b) != 0 || insph1(c) != 0)
		TEST_FAIL("insph1() failed");

	ctx.visits = 0;
	if (enumph1(NULL, delete_current_ph1_cb, &ctx) != 0)
		TEST_FAIL("enumph1() returned nonzero");

	if (ctx.visits != 3)
		TEST_FAIL("expected every entry visited exactly once despite each being "
		    "freed as it was visited -- a pre-fix build would skip or "
		    "use-after-free here");
	if (ph1tree_count_unittest() != 0)
		TEST_FAIL("ph1tree should be empty after every entry deleted itself");

	TEST_PASS();
	return 0;
}

static int
fail_on_second_ph1_cb(struct ph1handle *iph1, void *arg)
{
	int *visits = (int *)arg;

	(*visits)++;
	if (*visits == 2)
		return 42;
	return 0;
}

static int
test_enumph1_propagates_nonzero_return(void)
{
	struct ph1handle *a, *b, *c;
	int visits = 0;
	int ret;

	TEST_START("enumph1() stops and returns enum_func()'s nonzero value");

	initph1tree();

	a = newph1(); a->remote = dummy_sockaddr(htonl(0x0a010101)); a->local = dummy_sockaddr(htonl(0x0a0101fe));
	b = newph1(); b->remote = dummy_sockaddr(htonl(0x0a010102)); b->local = dummy_sockaddr(htonl(0x0a0101fe));
	c = newph1(); c->remote = dummy_sockaddr(htonl(0x0a010103)); c->local = dummy_sockaddr(htonl(0x0a0101fe));
	if (a == NULL || b == NULL || c == NULL)
		TEST_FAIL("newph1() returned NULL");
	if (insph1(a) != 0 || insph1(b) != 0 || insph1(c) != 0)
		TEST_FAIL("insph1() failed");

	ret = enumph1(NULL, fail_on_second_ph1_cb, &visits);
	if (ret != 42)
		TEST_FAIL("expected enumph1() to return enum_func()'s own nonzero value");
	if (visits != 2)
		TEST_FAIL("expected iteration to stop at the second entry, not visit the third");

	remph1(a); delph1(a);
	remph1(b); delph1(b);
	remph1(c); delph1(c);

	TEST_PASS();
	return 0;
}

/* ------------------------------------------------------------------ */
/* enumph2()                                                             */
/* ------------------------------------------------------------------ */

static int
count_ph2_cb(struct ph2handle *iph2, void *arg)
{
	(*(int *)arg)++;
	return 0;
}

static int
test_enumph2_visits_all_entries(void)
{
	struct ph2handle *a, *b, *c;
	int count = 0;

	TEST_START("enumph2(NULL, ...) visits every entry in ph2tree");

	initph2tree();

	a = newph2(); b = newph2(); c = newph2();
	if (a == NULL || b == NULL || c == NULL)
		TEST_FAIL("newph2() returned NULL");
	if (insph2(a) != 0 || insph2(b) != 0 || insph2(c) != 0)
		TEST_FAIL("insph2() failed");

	if (enumph2(NULL, count_ph2_cb, &count) != 0)
		TEST_FAIL("enumph2() returned nonzero with a callback that always returns 0");
	if (count != 3)
		TEST_FAIL("expected all 3 ph2handles visited");

	remph2(a); delph2(a);
	remph2(b); delph2(b);
	remph2(c); delph2(c);

	TEST_PASS();
	return 0;
}

struct spid_match_ctx {
	u_int32_t want_spid;
	int matched;
	int total;
};

static int
match_spid_cb(struct ph2handle *iph2, void *arg)
{
	struct spid_match_ctx *ctx = (struct spid_match_ctx *)arg;

	ctx->total++;
	if (iph2->spid == ctx->want_spid)
		ctx->matched++;
	return 0;
}

static int
test_enumph2_selector_filters_by_spid(void)
{
	struct ph2handle *a, *b;
	struct ph2selector sel;
	struct spid_match_ctx ctx;

	TEST_START("enumph2() with a sel->spid filter visits only the matching entry");

	initph2tree();

	a = newph2(); a->spid = 111;
	b = newph2(); b->spid = 222;
	if (a == NULL || b == NULL)
		TEST_FAIL("newph2() returned NULL");
	if (insph2(a) != 0 || insph2(b) != 0)
		TEST_FAIL("insph2() failed");

	memset(&sel, 0, sizeof(sel));
	sel.spid = 111;

	ctx.want_spid = 111;
	ctx.matched = 0;
	ctx.total = 0;

	if (enumph2(&sel, match_spid_cb, &ctx) != 0)
		TEST_FAIL("enumph2() returned nonzero");
	if (ctx.total != 1)
		TEST_FAIL("expected exactly one ph2handle to pass the sel->spid filter");
	if (ctx.matched != 1)
		TEST_FAIL("the one entry that passed the filter did not have the requested spid");

	remph2(a); delph2(a);
	remph2(b); delph2(b);

	TEST_PASS();
	return 0;
}

static int
delete_current_ph2_cb(struct ph2handle *iph2, void *arg)
{
	struct delete_all_ctx *ctx = (struct delete_all_ctx *)arg;

	ctx->visits++;
	remph2(iph2);
	delph2(iph2);
	return 0;
}

/* Same hazard as enumph1() above -- enumph2()'s own header comment notes
 * no caller does this today (pfkey.c's MIGRATE handlers only rewrite
 * addresses in place), which is exactly why this needs a direct test:
 * nothing in the live call graph would ever have caught a regression here. */
static int
test_enumph2_survives_delete_during_iteration(void)
{
	struct ph2handle *a, *b, *c;
	struct delete_all_ctx ctx;

	TEST_START("enumph2() survives enum_func() deleting the current entry");

	initph2tree();

	a = newph2(); b = newph2(); c = newph2();
	if (a == NULL || b == NULL || c == NULL)
		TEST_FAIL("newph2() returned NULL");
	if (insph2(a) != 0 || insph2(b) != 0 || insph2(c) != 0)
		TEST_FAIL("insph2() failed");

	ctx.visits = 0;
	if (enumph2(NULL, delete_current_ph2_cb, &ctx) != 0)
		TEST_FAIL("enumph2() returned nonzero");

	if (ctx.visits != 3)
		TEST_FAIL("expected every entry visited exactly once despite each being "
		    "freed as it was visited");
	if (ph2tree_count_unittest() != 0)
		TEST_FAIL("ph2tree should be empty after every entry deleted itself");

	TEST_PASS();
	return 0;
}

static int
fail_on_second_ph2_cb(struct ph2handle *iph2, void *arg)
{
	int *visits = (int *)arg;

	(*visits)++;
	if (*visits == 2)
		return 7;
	return 0;
}

static int
test_enumph2_propagates_nonzero_return(void)
{
	struct ph2handle *a, *b, *c;
	int visits = 0;
	int ret;

	TEST_START("enumph2() stops and returns enum_func()'s nonzero value");

	initph2tree();

	a = newph2(); b = newph2(); c = newph2();
	if (a == NULL || b == NULL || c == NULL)
		TEST_FAIL("newph2() returned NULL");
	if (insph2(a) != 0 || insph2(b) != 0 || insph2(c) != 0)
		TEST_FAIL("insph2() failed");

	ret = enumph2(NULL, fail_on_second_ph2_cb, &visits);
	if (ret != 7)
		TEST_FAIL("expected enumph2() to return enum_func()'s own nonzero value");
	if (visits != 2)
		TEST_FAIL("expected iteration to stop at the second entry, not visit the third");

	remph2(a); delph2(a);
	remph2(b); delph2(b);
	remph2(c); delph2(c);

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== enumph1()/enumph2() coverage test ===\n");

	if (test_enumph1_visits_all_entries() != 0)
		failed++;
	if (test_enumph1_selector_filters_by_remote() != 0)
		failed++;
	if (test_enumph1_survives_delete_during_iteration() != 0)
		failed++;
	if (test_enumph1_propagates_nonzero_return() != 0)
		failed++;
	if (test_enumph2_visits_all_entries() != 0)
		failed++;
	if (test_enumph2_selector_filters_by_spid() != 0)
		failed++;
	if (test_enumph2_survives_delete_during_iteration() != 0)
		failed++;
	if (test_enumph2_propagates_nonzero_return() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
