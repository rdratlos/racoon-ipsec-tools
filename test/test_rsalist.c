// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit tests for src/racoon/rsalist.c
 *
 * rsalist.c sits directly in the IKE Phase 1 RSA-signature authentication
 * path: rsa_lookup_keys() (called from oakley.c) builds the candidate key
 * list for a peer by scoring configured src/dst addresses against the
 * negotiation's actual addresses, and rsa_try_check_rsasign() (also called
 * from oakley.c) verifies the peer's signature against that candidate list.
 * Before this file, only rsa_key_dup()/rsa_key_free() were exercised
 * (via test_rsa_comprehensive.c); every other function -- including both
 * of the above -- had 0% coverage.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/rsa.h>

#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "genlist.h"
#include "handler.h"
#include "remoteconf.h"
#include "eay_rsa.h"
#include "rsalist.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while (0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* ---------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------- */

static struct netaddr *
new_netaddr(const char *ip, unsigned long prefix)
{
	struct netaddr *na = calloc(1, sizeof(*na));
	if (!na)
		return NULL;
	na->sa.sin.sin_family = AF_INET;
	na->sa.sin.sin_addr.s_addr = inet_addr(ip);
	na->prefix = prefix;
	return na;
}

/* An all-zero netaddr matches naddr_score()'s wildcard check exactly. */
static struct netaddr *
new_wildcard_netaddr(void)
{
	return calloc(1, sizeof(struct netaddr));
}

static struct rsa_key *
new_rsa_key(struct netaddr *src, struct netaddr *dst, eayRSA *rsa)
{
	struct rsa_key *k = calloc(1, sizeof(*k));
	if (!k)
		return NULL;
	k->src = src;
	k->dst = dst;
	k->rsa = rsa;
	return k;
}

static void
init_sockaddr_in(struct sockaddr_in *sin, const char *ip, unsigned short port)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr(ip);
	sin->sin_port = htons(port);
}

/* ---------------------------------------------------------------------
 * rsa_key_insert()
 * --------------------------------------------------------------------- */

static int
test_rsa_key_insert_null_src_dst_allocates(void)
{
	struct genlist *list;
	struct genlist_entry *gp = NULL;
	struct rsa_key *key;
	eayRSA *rsa;

	TEST_START("rsa_key_insert() with NULL src/dst allocates placeholders");

	rsa = eayRSA_generate(2048, RSA_F4);
	if (!rsa) TEST_FAIL("eayRSA_generate failed");

	list = genlist_init();
	if (rsa_key_insert(list, NULL, NULL, rsa) != 0) {
		eayRSA_free(rsa);
		genlist_free(list, NULL);
		TEST_FAIL("rsa_key_insert returned non-zero");
	}

	key = genlist_next(list, &gp);
	if (!key) {
		genlist_free(list, rsa_key_free);
		TEST_FAIL("no entry appended");
	}
	if (!key->src || !key->dst || key->rsa != rsa) {
		genlist_free(list, rsa_key_free);
		TEST_FAIL("src/dst not auto-allocated or rsa mismatch");
	}

	genlist_free(list, rsa_key_free);
	TEST_PASS();
	return 0;
}

static int
test_rsa_key_insert_explicit_src_dst(void)
{
	struct genlist *list;
	struct genlist_entry *gp = NULL;
	struct rsa_key *key;
	struct netaddr *src, *dst;
	eayRSA *rsa;

	TEST_START("rsa_key_insert() with explicit src/dst keeps the pointers");

	rsa = eayRSA_generate(2048, RSA_F4);
	if (!rsa) TEST_FAIL("eayRSA_generate failed");
	src = new_netaddr("192.168.1.1", 32);
	dst = new_netaddr("192.168.1.2", 32);

	list = genlist_init();
	rsa_key_insert(list, src, dst, rsa);

	key = genlist_next(list, &gp);
	if (!key || key->src != src || key->dst != dst) {
		genlist_free(list, rsa_key_free);
		TEST_FAIL("src/dst pointers not preserved");
	}

	genlist_free(list, rsa_key_free);
	TEST_PASS();
	return 0;
}

/* ---------------------------------------------------------------------
 * rsa_list_count()
 * --------------------------------------------------------------------- */

static int
test_rsa_list_count(void)
{
	struct genlist *list;
	eayRSA *rsa;
	int i;

	TEST_START("rsa_list_count() on empty and populated lists");

	list = genlist_init();
	if (rsa_list_count(list) != 0) {
		genlist_free(list, NULL);
		TEST_FAIL("empty list should count 0");
	}

	for (i = 0; i < 3; i++) {
		rsa = eayRSA_generate(2048, RSA_F4);
		if (!rsa) {
			genlist_free(list, rsa_key_free);
			TEST_FAIL("eayRSA_generate failed");
		}
		genlist_append(list, new_rsa_key(NULL, NULL, rsa));
	}
	if (rsa_list_count(list) != 3) {
		genlist_free(list, rsa_key_free);
		TEST_FAIL("expected count 3");
	}

	genlist_free(list, rsa_key_free);
	TEST_PASS();
	return 0;
}

/* ---------------------------------------------------------------------
 * rsa_key_dump() -- smoke test only (output goes to plog(), not returned);
 * this just needs to not crash across both the "concise" and "verbose"
 * (loglevel >= LLV_DEBUG, which also runs eayRSA_print()) branches.
 * --------------------------------------------------------------------- */

static int
test_rsa_key_dump_smoke(void)
{
	struct genlist *list;
	eayRSA *rsa;
	u_int32_t saved_loglevel = loglevel;

	TEST_START("rsa_key_dump() does not crash (concise and verbose)");

	rsa = eayRSA_generate(2048, RSA_F4);
	if (!rsa) TEST_FAIL("eayRSA_generate failed");

	list = genlist_init();
	genlist_append(list, new_rsa_key(new_wildcard_netaddr(),
					  new_wildcard_netaddr(), rsa));

	loglevel = LLV_BASE;
	rsa_key_dump(list);

	loglevel = LLV_DEBUG2; /* also exercises eayRSA_print() */
	rsa_key_dump(list);
	loglevel = saved_loglevel;

	genlist_free(list, rsa_key_free);
	TEST_PASS();
	return 0;
}

/* ---------------------------------------------------------------------
 * rsa_lookup_keys() -- the candidate-key scoring/selection logic used by
 * oakley.c to decide which configured keys are eligible for a peer.
 * --------------------------------------------------------------------- */

static int
test_rsa_lookup_keys_exact_match(void)
{
	struct ph1handle iph1;
	struct remoteconf rmconf;
	struct sockaddr_in local_sin, remote_sin;
	struct genlist *winners;
	eayRSA *rsa;

	TEST_START("rsa_lookup_keys() finds an exact address/address match");

	memset(&iph1, 0, sizeof(iph1));
	memset(&rmconf, 0, sizeof(rmconf));
	init_sockaddr_in(&local_sin, "10.0.0.1", 500);
	init_sockaddr_in(&remote_sin, "10.0.0.2", 500);
	iph1.local = (struct sockaddr *)&local_sin;
	iph1.remote = (struct sockaddr *)&remote_sin;
	iph1.rmconf = &rmconf;
	rmconf.rsa_private = genlist_init();
	rmconf.rsa_public = genlist_init();

	rsa = eayRSA_generate(2048, RSA_F4);
	if (!rsa) TEST_FAIL("eayRSA_generate failed");
	genlist_append(rmconf.rsa_public,
		new_rsa_key(new_netaddr("10.0.0.1", 32),
			    new_netaddr("10.0.0.2", 32), rsa));

	winners = rsa_lookup_keys(&iph1, 0);
	if (!winners || rsa_list_count(winners) != 1) {
		if (winners) genlist_free(winners, NULL);
		genlist_free(rmconf.rsa_public, rsa_key_free);
		genlist_free(rmconf.rsa_private, NULL);
		TEST_FAIL("expected exactly one winner");
	}

	genlist_free(winners, NULL);
	genlist_free(rmconf.rsa_public, rsa_key_free);
	genlist_free(rmconf.rsa_private, NULL);
	TEST_PASS();
	return 0;
}

static int
test_rsa_lookup_keys_no_match(void)
{
	struct ph1handle iph1;
	struct remoteconf rmconf;
	struct sockaddr_in local_sin, remote_sin;
	struct genlist *winners;
	eayRSA *rsa;

	TEST_START("rsa_lookup_keys() excludes a non-matching dst address");

	memset(&iph1, 0, sizeof(iph1));
	memset(&rmconf, 0, sizeof(rmconf));
	init_sockaddr_in(&local_sin, "10.0.0.1", 500);
	init_sockaddr_in(&remote_sin, "10.0.0.2", 500);
	iph1.local = (struct sockaddr *)&local_sin;
	iph1.remote = (struct sockaddr *)&remote_sin;
	iph1.rmconf = &rmconf;
	rmconf.rsa_private = genlist_init();
	rmconf.rsa_public = genlist_init();

	rsa = eayRSA_generate(2048, RSA_F4);
	if (!rsa) TEST_FAIL("eayRSA_generate failed");
	/* dst deliberately does not match iph1.remote (10.0.0.2) */
	genlist_append(rmconf.rsa_public,
		new_rsa_key(new_netaddr("10.0.0.1", 32),
			    new_netaddr("192.168.99.99", 32), rsa));

	winners = rsa_lookup_keys(&iph1, 0);
	if (!winners || rsa_list_count(winners) != 0) {
		if (winners) genlist_free(winners, NULL);
		genlist_free(rmconf.rsa_public, rsa_key_free);
		genlist_free(rmconf.rsa_private, NULL);
		TEST_FAIL("expected zero winners");
	}

	genlist_free(winners, NULL);
	genlist_free(rmconf.rsa_public, rsa_key_free);
	genlist_free(rmconf.rsa_private, NULL);
	TEST_PASS();
	return 0;
}

static int
test_rsa_lookup_keys_wildcard_matches(void)
{
	struct ph1handle iph1;
	struct remoteconf rmconf;
	struct sockaddr_in local_sin, remote_sin;
	struct genlist *winners;
	eayRSA *rsa;

	TEST_START("rsa_lookup_keys() matches a wildcard (0.0.0.0/0) key entry");

	memset(&iph1, 0, sizeof(iph1));
	memset(&rmconf, 0, sizeof(rmconf));
	init_sockaddr_in(&local_sin, "10.0.0.1", 500);
	init_sockaddr_in(&remote_sin, "10.0.0.2", 500);
	iph1.local = (struct sockaddr *)&local_sin;
	iph1.remote = (struct sockaddr *)&remote_sin;
	iph1.rmconf = &rmconf;
	rmconf.rsa_private = genlist_init();
	rmconf.rsa_public = genlist_init();

	rsa = eayRSA_generate(2048, RSA_F4);
	if (!rsa) TEST_FAIL("eayRSA_generate failed");
	genlist_append(rmconf.rsa_public,
		new_rsa_key(new_wildcard_netaddr(), new_wildcard_netaddr(), rsa));

	winners = rsa_lookup_keys(&iph1, 0);
	if (!winners || rsa_list_count(winners) != 1) {
		if (winners) genlist_free(winners, NULL);
		genlist_free(rmconf.rsa_public, rsa_key_free);
		genlist_free(rmconf.rsa_private, NULL);
		TEST_FAIL("expected the wildcard entry to match");
	}

	genlist_free(winners, NULL);
	genlist_free(rmconf.rsa_public, rsa_key_free);
	genlist_free(rmconf.rsa_private, NULL);
	TEST_PASS();
	return 0;
}

/*
 * rsa_lookup_key_one() never prunes previously-appended candidates when a
 * later entry raises req->max_score -- the genlist_free(winners) call that
 * would do so is commented out in rsalist.c. So the *final* winners list
 * can contain strictly-lower-scoring entries whenever they were processed
 * before the best match, even though only the best match is a "winner" by
 * the function's own scoring. This test characterizes that existing,
 * insertion-order-dependent behavior so a future change to the scoring
 * loop doesn't silently alter it.
 */
static int
test_rsa_lookup_keys_stale_candidate_order_dependence(void)
{
	struct ph1handle iph1;
	struct remoteconf rmconf;
	struct sockaddr_in local_sin, remote_sin;
	struct genlist *winners;
	eayRSA *rsa_low, *rsa_high;

	TEST_START("rsa_lookup_keys() keeps lower-scoring entries seen before the best match");

	memset(&iph1, 0, sizeof(iph1));
	memset(&rmconf, 0, sizeof(rmconf));
	init_sockaddr_in(&local_sin, "10.0.0.1", 500);
	init_sockaddr_in(&remote_sin, "10.0.0.2", 500);
	iph1.local = (struct sockaddr *)&local_sin;
	iph1.remote = (struct sockaddr *)&remote_sin;
	iph1.rmconf = &rmconf;
	rmconf.rsa_private = genlist_init();
	rmconf.rsa_public = genlist_init();

	rsa_low = eayRSA_generate(2048, RSA_F4);
	rsa_high = eayRSA_generate(2048, RSA_F4);
	if (!rsa_low || !rsa_high) TEST_FAIL("eayRSA_generate failed");

	/* Wildcard (score 0) inserted BEFORE the exact match (score 64). */
	genlist_append(rmconf.rsa_public,
		new_rsa_key(new_wildcard_netaddr(), new_wildcard_netaddr(), rsa_low));
	genlist_append(rmconf.rsa_public,
		new_rsa_key(new_netaddr("10.0.0.1", 32),
			    new_netaddr("10.0.0.2", 32), rsa_high));

	winners = rsa_lookup_keys(&iph1, 0);
	if (!winners || rsa_list_count(winners) != 2) {
		if (winners) genlist_free(winners, NULL);
		genlist_free(rmconf.rsa_public, rsa_key_free);
		genlist_free(rmconf.rsa_private, NULL);
		TEST_FAIL("expected both the stale low-score and the best match");
	}
	genlist_free(winners, NULL);

	/* Reverse insertion order: best match first, wildcard second --
	 * the wildcard's score (0) never exceeds or ties the running max
	 * (64), so it is correctly excluded this time. */
	genlist_free(rmconf.rsa_public, rsa_key_free);
	rmconf.rsa_public = genlist_init();
	rsa_low = eayRSA_generate(2048, RSA_F4);
	rsa_high = eayRSA_generate(2048, RSA_F4);
	if (!rsa_low || !rsa_high) TEST_FAIL("eayRSA_generate failed");
	genlist_append(rmconf.rsa_public,
		new_rsa_key(new_netaddr("10.0.0.1", 32),
			    new_netaddr("10.0.0.2", 32), rsa_high));
	genlist_append(rmconf.rsa_public,
		new_rsa_key(new_wildcard_netaddr(), new_wildcard_netaddr(), rsa_low));

	winners = rsa_lookup_keys(&iph1, 0);
	if (!winners || rsa_list_count(winners) != 1) {
		if (winners) genlist_free(winners, NULL);
		genlist_free(rmconf.rsa_public, rsa_key_free);
		genlist_free(rmconf.rsa_private, NULL);
		TEST_FAIL("expected only the best match when it is seen first");
	}

	genlist_free(winners, NULL);
	genlist_free(rmconf.rsa_public, rsa_key_free);
	genlist_free(rmconf.rsa_private, NULL);
	TEST_PASS();
	return 0;
}

/* ---------------------------------------------------------------------
 * rsa_try_check_rsasign() -- the actual signature-verification dispatch
 * used to authenticate an RSA-signature-mode IKE peer.
 * --------------------------------------------------------------------- */

static int
test_rsa_try_check_rsasign_finds_matching_key(void)
{
	struct genlist *list;
	eayRSA *wrong, *right;
	vchar_t *msg, *sig;
	eayRSA *found;

	TEST_START("rsa_try_check_rsasign() returns the key whose signature verifies");

	wrong = eayRSA_generate(2048, RSA_F4);
	right = eayRSA_generate(2048, RSA_F4);
	if (!wrong || !right) TEST_FAIL("eayRSA_generate failed");

	list = genlist_init();
	genlist_append(list, new_rsa_key(NULL, NULL, wrong));
	genlist_append(list, new_rsa_key(NULL, NULL, right));

	msg = vmalloc(32);
	if (!msg) TEST_FAIL("vmalloc failed");
	memcpy(msg->v, "rsa_try_check_rsasign test data", 32);

	sig = eayRSA_sign(right, msg);
	if (!sig) {
		vfree(msg);
		genlist_free(list, rsa_key_free);
		TEST_FAIL("eayRSA_sign failed");
	}

	found = rsa_try_check_rsasign(msg, sig, list);
	vfree(msg);
	vfree(sig);
	if (found != right) {
		genlist_free(list, rsa_key_free);
		TEST_FAIL("did not return the signing key");
	}

	genlist_free(list, rsa_key_free);
	TEST_PASS();
	return 0;
}

static int
test_rsa_try_check_rsasign_no_match_returns_null(void)
{
	struct genlist *list;
	eayRSA *wrong, *signer;
	vchar_t *msg, *sig;
	eayRSA *found;

	TEST_START("rsa_try_check_rsasign() returns NULL when no candidate key matches");

	wrong = eayRSA_generate(2048, RSA_F4);
	signer = eayRSA_generate(2048, RSA_F4); /* not part of the candidate list */
	if (!wrong || !signer) TEST_FAIL("eayRSA_generate failed");

	list = genlist_init();
	genlist_append(list, new_rsa_key(NULL, NULL, wrong));

	msg = vmalloc(16);
	if (!msg) TEST_FAIL("vmalloc failed");
	memcpy(msg->v, "no matching key!", 16);

	sig = eayRSA_sign(signer, msg);
	if (!sig) {
		vfree(msg);
		eayRSA_free(signer);
		genlist_free(list, rsa_key_free);
		TEST_FAIL("eayRSA_sign failed");
	}

	found = rsa_try_check_rsasign(msg, sig, list);
	vfree(msg);
	vfree(sig);
	eayRSA_free(signer);
	if (found != NULL) {
		genlist_free(list, rsa_key_free);
		TEST_FAIL("expected NULL, got a match");
	}

	genlist_free(list, rsa_key_free);
	TEST_PASS();
	return 0;
}

static int
test_rsa_try_check_rsasign_empty_list_returns_null(void)
{
	struct genlist *list;
	vchar_t *msg = vmalloc(8);
	vchar_t *sig = vmalloc(8);
	eayRSA *found;

	TEST_START("rsa_try_check_rsasign() on an empty candidate list returns NULL");

	if (!msg || !sig) TEST_FAIL("vmalloc failed");
	memset(msg->v, 0, msg->l);
	memset(sig->v, 0, sig->l);

	list = genlist_init();
	found = rsa_try_check_rsasign(msg, sig, list);

	vfree(msg);
	vfree(sig);
	genlist_free(list, NULL);

	if (found != NULL)
		TEST_FAIL("expected NULL for an empty list");

	TEST_PASS();
	return 0;
}

/* ---------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */

int
main(int argc, char **argv)
{
	int failed = 0;

	printf("========================================================================\n");
	printf("  Racoon IPSec - rsalist.c Unit Tests\n");
	printf("========================================================================\n");

	failed += test_rsa_key_insert_null_src_dst_allocates();
	failed += test_rsa_key_insert_explicit_src_dst();
	failed += test_rsa_list_count();
	failed += test_rsa_key_dump_smoke();
	failed += test_rsa_lookup_keys_exact_match();
	failed += test_rsa_lookup_keys_no_match();
	failed += test_rsa_lookup_keys_wildcard_matches();
	failed += test_rsa_lookup_keys_stale_candidate_order_dependence();
	failed += test_rsa_try_check_rsasign_finds_matching_key();
	failed += test_rsa_try_check_rsasign_no_match_returns_null();
	failed += test_rsa_try_check_rsasign_empty_list_returns_null();

	printf("\n========================================================================\n");
	if (failed == 0)
		printf("  ALL rsalist.c TESTS PASSED\n");
	else
		printf("  %d rsalist.c TEST(S) FAILED\n", failed);
	printf("========================================================================\n");

	return failed == 0 ? 0 : 1;
}
