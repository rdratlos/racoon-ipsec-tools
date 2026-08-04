// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression/coverage test for get_comindexes()/get_index()/get_family()/
 * get_proto()/get_ulproto() (racoonctl.c) -- the layer above
 * get_comindex() (test_racoonctl_get_comindex.c, issue #119) that turns
 * a parsed name/port/prefix triple into the real
 * struct admin_com_indexes wire layout admin.c's own dispatch (already
 * covered from the daemon side by test_admin_delete_all_sa_dst.c /
 * test_admin_establish_sa_psk.c) expects.
 *
 * get_comindexes() calls get_sockaddr() (kmpstat.c, a real getaddrinfo()
 * resolver call with no numeric-only hints) twice per invocation --
 * racoonctl_get_sockaddr_stub.c substitutes a numeric-only,
 * DNS-free stand-in (ordinary external linkage, no -Wl,--wrap= needed;
 * see that file's own header comment).
 *
 * Also the regression test for issue #120: get_comindexes() never freed
 * p_prefs/p_prefd (the prefix-length strings get_comindex() allocates)
 * on the success path, only on its "bad:" error path -- leaking one or
 * two allocations on every successful call that specified an explicit
 * prefix. test_prefix_strings_are_freed_on_success below counts real
 * free() calls via -Wl,--wrap=free (racoon_free() is a plain free() in
 * this non-debug build) around one such call, the same technique and
 * the same LTO-defeat caution as test_admin_establish_sa_psk.c's
 * -Wl,--wrap=vfree (doc/dev/wrap-based-tests-vs-lto.md): a canary
 * free() at startup confirms the wrap is actually intercepting on this
 * toolchain before any count is trusted, SKIP rather than a
 * false-reading FAIL/PASS if it is not.
 *
 * get_comindexes()/get_index()/get_family()/get_proto()/get_ulproto()
 * are static; each has a thin -DENABLE_UNITTEST accessor (racoonctl.c).
 * racoonctl.c is pulled in via racoonctl_unittest_src.c (renames its own
 * main() out of the way), -ffunction-sections/--gc-sections, same
 * pattern as test_racoonctl_get_comindex.c and
 * test_racoonctl_logoutusr.c. Unlike that file, get_comindexes() itself
 * calls vmalloc() (vmbuf.o), so this binary links it.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "var.h"
#include "vmbuf.h"
#include "admin.h"

extern int get_family_unittest(char *str);
extern int get_proto_unittest(char *str);
extern int get_ulproto_unittest(char *str);
extern vchar_t *get_comindexes_unittest(int family, int ac, char **av);
extern vchar_t *get_index_unittest(int ac, char **av);

extern int racoonctl_test_get_sockaddr_fail;
extern int racoonctl_test_get_sockaddr_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static void
reset_stub_state(void)
{
	racoonctl_test_get_sockaddr_fail = 0;
	racoonctl_test_get_sockaddr_calls = 0;
}

/* ---- get_family()/get_proto()/get_ulproto(): pure table lookups ---- */

static int
test_get_family(void)
{
	TEST_START("get_family() recognizes inet/inet6, rejects everything else");

	if (get_family_unittest("inet") != AF_INET)
		TEST_FAIL("\"inet\" did not map to AF_INET");
#ifdef INET6
	if (get_family_unittest("inet6") != AF_INET6)
		TEST_FAIL("\"inet6\" did not map to AF_INET6");
#endif
	if (get_family_unittest("bogus") != -1)
		TEST_FAIL("unknown family string was not rejected");

	TEST_PASS();
	return 0;
}

static int
test_get_proto(void)
{
	TEST_START("get_proto() recognizes every documented protocol string");

	if (get_proto_unittest("isakmp") != ADMIN_PROTO_ISAKMP)
		TEST_FAIL("\"isakmp\" mismatch");
	if (get_proto_unittest("ipsec") != ADMIN_PROTO_IPSEC)
		TEST_FAIL("\"ipsec\" mismatch");
	if (get_proto_unittest("ah") != ADMIN_PROTO_AH)
		TEST_FAIL("\"ah\" mismatch");
	if (get_proto_unittest("esp") != ADMIN_PROTO_ESP)
		TEST_FAIL("\"esp\" mismatch");
	if (get_proto_unittest("internal") != ADMIN_PROTO_INTERNAL)
		TEST_FAIL("\"internal\" mismatch");
	if (get_proto_unittest("bogus") != -1)
		TEST_FAIL("unknown protocol string was not rejected");
	if (get_proto_unittest(NULL) != -1)
		TEST_FAIL("NULL was not rejected");

	TEST_PASS();
	return 0;
}

static int
test_get_ulproto(void)
{
	TEST_START("get_ulproto() recognizes every documented upper-layer protocol string");

	if (get_ulproto_unittest("any") != 0)
		TEST_FAIL("\"any\" mismatch");
	if (get_ulproto_unittest("icmp") != IPPROTO_ICMP)
		TEST_FAIL("\"icmp\" mismatch");
	if (get_ulproto_unittest("tcp") != IPPROTO_TCP)
		TEST_FAIL("\"tcp\" mismatch");
	if (get_ulproto_unittest("udp") != IPPROTO_UDP)
		TEST_FAIL("\"udp\" mismatch");
	if (get_ulproto_unittest("bogus") != -1)
		TEST_FAIL("unknown ul_proto string was not rejected");

	TEST_PASS();
	return 0;
}

/* ---- get_comindexes(): the real struct admin_com_indexes builder ---- */

static int
test_comindexes_defaults_and_layout(void)
{
	char *av[] = { "10.0.0.1", "10.0.0.2" };
	vchar_t *buf;
	struct admin_com_indexes *ci;
	struct sockaddr_in *src, *dst;

	TEST_START("get_comindexes() with plain addresses: defaults (prefs=prefd=32, ul_proto=0)");

	reset_stub_state();
	buf = get_comindexes_unittest(AF_INET, 2, av);
	if (buf == NULL)
		TEST_FAIL("get_comindexes() returned NULL for a valid plain-address pair");

	if (buf->l != sizeof(*ci)) {
		vfree(buf);
		TEST_FAIL("returned buffer is not sizeof(struct admin_com_indexes)");
	}

	ci = (struct admin_com_indexes *)buf->v;
	if (ci->prefs != 32 || ci->prefd != 32) {
		vfree(buf);
		TEST_FAIL("prefs/prefd did not default to 32 with no explicit prefix");
	}
	if (ci->ul_proto != 0) {
		vfree(buf);
		TEST_FAIL("ul_proto did not default to 0 (\"any\") with no ul_proto argument");
	}

	src = (struct sockaddr_in *)&ci->src;
	dst = (struct sockaddr_in *)&ci->dst;
	if (src->sin_family != AF_INET || dst->sin_family != AF_INET) {
		vfree(buf);
		TEST_FAIL("src/dst family was not AF_INET");
	}
	if (memcmp(&src->sin_addr, &(struct in_addr){ htonl(0x0A000001) }, sizeof(struct in_addr)) != 0) {
		vfree(buf);
		TEST_FAIL("src address does not match 10.0.0.1");
	}
	if (memcmp(&dst->sin_addr, &(struct in_addr){ htonl(0x0A000002) }, sizeof(struct in_addr)) != 0) {
		vfree(buf);
		TEST_FAIL("dst address does not match 10.0.0.2");
	}

	if (racoonctl_test_get_sockaddr_calls != 2) {
		vfree(buf);
		TEST_FAIL("get_sockaddr() was not called exactly twice (once for src, once for dst)");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_comindexes_explicit_prefix_and_ulproto(void)
{
	char *av[] = { "10.0.0.1/24", "10.0.0.2/16", "tcp" };
	vchar_t *buf;
	struct admin_com_indexes *ci;

	TEST_START("get_comindexes() with explicit prefixes and a ul_proto argument");

	reset_stub_state();
	buf = get_comindexes_unittest(AF_INET, 3, av);
	if (buf == NULL)
		TEST_FAIL("get_comindexes() returned NULL for a valid prefix+ulproto triple");

	ci = (struct admin_com_indexes *)buf->v;
	if (ci->prefs != 24) {
		vfree(buf);
		TEST_FAIL("prefs did not pick up the explicit /24");
	}
	if (ci->prefd != 16) {
		vfree(buf);
		TEST_FAIL("prefd did not pick up the explicit /16");
	}
	if (ci->ul_proto != IPPROTO_TCP) {
		vfree(buf);
		TEST_FAIL("ul_proto did not pick up \"tcp\"");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_comindexes_bad_arg_count_rejected(void)
{
	char *av1[] = { "10.0.0.1" };
	char *av4[] = { "a", "b", "c", "d" };

	TEST_START("get_comindexes() rejects ac outside {2,3} without calling get_sockaddr()");

	reset_stub_state();
	if (get_comindexes_unittest(AF_INET, 1, av1) != NULL)
		TEST_FAIL("ac=1 was accepted");
	if (racoonctl_test_get_sockaddr_calls != 0)
		TEST_FAIL("get_sockaddr() was called despite the arg-count check failing first");

	if (get_comindexes_unittest(AF_INET, 4, av4) != NULL)
		TEST_FAIL("ac=4 was accepted");

	TEST_PASS();
	return 0;
}

static int
test_comindexes_bad_ulproto_rejected(void)
{
	char *av[] = { "10.0.0.1", "10.0.0.2", "not-a-real-ulproto" };

	TEST_START("get_comindexes() rejects an unrecognized ul_proto argument");

	reset_stub_state();
	if (get_comindexes_unittest(AF_INET, 3, av) != NULL)
		TEST_FAIL("unrecognized ul_proto was accepted");

	TEST_PASS();
	return 0;
}

static int
test_comindexes_sockaddr_resolution_failure_rejected(void)
{
	char *av[] = { "10.0.0.1", "10.0.0.2" };

	TEST_START("get_comindexes() rejects when get_sockaddr() fails (e.g. unresolvable name)");

	reset_stub_state();
	racoonctl_test_get_sockaddr_fail = 1;
	if (get_comindexes_unittest(AF_INET, 2, av) != NULL)
		TEST_FAIL("a get_sockaddr() failure was not propagated as a rejection");
	racoonctl_test_get_sockaddr_fail = 0;

	TEST_PASS();
	return 0;
}

/* ---- get_index(): family-string layer above get_comindexes() ---- */

static int
test_get_index_happy_and_bad_family(void)
{
	char *av_good[] = { "inet", "10.0.0.1", "10.0.0.2" };
	char *av_bad_family[] = { "bogus", "10.0.0.1", "10.0.0.2" };
	char *av_bad_count[] = { "inet", "10.0.0.1" };
	vchar_t *buf;

	TEST_START("get_index() consumes the family argument and delegates to get_comindexes()");

	reset_stub_state();
	buf = get_index_unittest(3, av_good);
	if (buf == NULL)
		TEST_FAIL("get_index() returned NULL for a valid \"inet\" triple");
	vfree(buf);

	reset_stub_state();
	if (get_index_unittest(3, av_bad_family) != NULL)
		TEST_FAIL("an unrecognized family string was accepted");

	reset_stub_state();
	if (get_index_unittest(2, av_bad_count) != NULL)
		TEST_FAIL("ac=2 (outside {3,4}) was accepted");

	TEST_PASS();
	return 0;
}

/* ---- issue #120: p_prefs/p_prefd leaked on the success path ---- */

extern void __real_free(void *ptr);
static int free_calls;

void
__wrap_free(void *ptr)
{
	if (ptr != NULL)
		free_calls++;
	__real_free(ptr);
}

/*
 * Confirms -Wl,--wrap=free is actually intercepting free() calls on this
 * toolchain before trusting the count below -- same caution as
 * test_admin_establish_sa_psk.c's -Wl,--wrap=vfree canary
 * (doc/dev/wrap-based-tests-vs-lto.md): under whole-program LTO, a
 * plain free() call can be resolved/inlined in a way that leaves
 * __wrap_free entirely unreferenced, which would otherwise read as a
 * false "0 leaks" pass indistinguishable from a genuine one.
 *
 * Unlike test_admin_establish_sa_psk.c/test_getcertsbyname_helpers.c
 * (each entirely about proving one wrap-dependent assertion), this
 * binary is mostly ordinary get_comindexes()/get_index() coverage that
 * does not depend on -Wl,--wrap=free at all -- so an ineffective wrap
 * here skips only the one leak assertion below, not the whole binary
 * (main()'s overall exit code is unaffected either way).
 */
static int
skip_if_wrap_free_ineffective(void)
{
	void *canary = malloc(1);

	free_calls = 0;
	free(canary);
	if (free_calls == 1)
		return 0;

	printf("\nSKIP: -Wl,--wrap=free did not intercept a canary free() call on "
	    "this toolchain -- skipping only the issue #120 leak-count assertion "
	    "below, not this binary's other (wrap-independent) tests. "
	    "See doc/dev/wrap-based-tests-vs-lto.md.\n");
	return 1;
}

static int
test_prefix_strings_are_freed_on_success(void)
{
	/* Both src and dst carry an explicit prefix, no port -- exactly
	 * the shape that leaked p_prefs/p_prefd before #120's fix.
	 * get_comindex() itself frees nothing on its own success path, so
	 * every free() counted here comes from get_comindexes(): p_name
	 * x2 (one per get_comindex() call, always non-NULL) plus, with
	 * #120's fix, p_prefs and p_prefd (both set here, no port so
	 * p_port stays NULL both times) -- 4 total. */
	char *av[] = { "10.0.0.1/24", "10.0.0.2/16" };
	vchar_t *buf;

	TEST_START("get_comindexes() frees p_prefs/p_prefd on a successful prefixed parse (issue #120)");

	reset_stub_state();
	free_calls = 0;
	buf = get_comindexes_unittest(AF_INET, 2, av);
	if (buf == NULL)
		TEST_FAIL("get_comindexes() returned NULL for a valid prefixed pair");

	if (free_calls != 4) {
		printf("(observed %d free() calls, expected 4: 2x p_name + p_prefs + p_prefd) ",
		    free_calls);
		vfree(buf);
		TEST_FAIL("p_prefs/p_prefd were not both freed on the success path");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;
	int skip_leak_test;

	printf("\n=== get_comindexes()/get_index()/get_family()/get_proto()/get_ulproto() test ===\n");

	skip_leak_test = skip_if_wrap_free_ineffective();

	if (test_get_family() != 0)
		failed++;
	if (test_get_proto() != 0)
		failed++;
	if (test_get_ulproto() != 0)
		failed++;
	if (test_comindexes_defaults_and_layout() != 0)
		failed++;
	if (test_comindexes_explicit_prefix_and_ulproto() != 0)
		failed++;
	if (test_comindexes_bad_arg_count_rejected() != 0)
		failed++;
	if (test_comindexes_bad_ulproto_rejected() != 0)
		failed++;
	if (test_comindexes_sockaddr_resolution_failure_rejected() != 0)
		failed++;
	if (test_get_index_happy_and_bad_family() != 0)
		failed++;

	if (!skip_leak_test && test_prefix_strings_are_freed_on_success() != 0)
		failed++;

	printf("\n=== %s%s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
	    skip_leak_test ? " (issue #120 leak assertion skipped)" : "");

	return failed == 0 ? 0 : 1;
}
