// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for get_comindex() (racoonctl.c) -- the parser behind
 * every "addr", "addr/prefix", and "addr/prefix[port]" argument racoonctl
 * accepts for <saopts> (usage(), esp/ah: "<src/prefixlen/port>").
 *
 * This function had never been unit-tested before (v0.9.1
 * unit-test-coverage hardening, Tier 4), which is exactly how issue #119
 * survived unnoticed: get_comindex()'s "addr/prefix[port]" branch strips
 * the trailing ']' by searching *pref (already truncated down to just
 * the prefix digits, so it can never contain ']') instead of *port
 * (which actually holds it) -- always failing, unconditionally, for
 * *every* input using prefix and port together. Confirmed present in
 * this repo's own tracked upstream/0.8.2+20140711 tag (KAME/NetBSD-era,
 * Id: racoonctl.c,v 1.11 2006/04/06 17:06:25 manubsd) and still present
 * in vendor/netbsd's current tree ($NetBSD: racoonctl.c,v 1.21
 * 2025/03/08 19:43:19 christos) -- 19+ years unexercised across two
 * active codebases. The fix is one line; this test's job is making sure
 * the next person to touch this function can't repeat that.
 *
 * Covers the full documented grammar matrix from usage()'s own printed
 * <saopts> spec, not just the previously-broken case:
 *   - addr alone (defaults: prefix 32, no port)
 *   - addr/prefix
 *   - addr/prefix[port]        (issue #119's fix)
 *   - addr[port], no prefix    (always rejected -- see this file's header
 *                               comment on why that's current, intended
 *                               behavior, not a second instance of #119)
 *   - malformed variants: trailing '/', trailing '[', missing ']'
 *
 * get_comindex() is static; get_comindex_unittest() is a thin
 * -DENABLE_UNITTEST accessor (racoonctl.c). racoonctl.c is pulled in via
 * a local wrapper source (racoonctl_unittest_src.c, which also renames
 * its own main() out of the way) with -ffunction-sections/--gc-sections,
 * the same pattern as test_racoonctl_logoutusr.c. get_comindex() itself
 * calls only racoon_strdup()/racoon_free() (plain strdup()/free() via
 * gcmalloc.h macros in a non-debug build) and strpbrk()/strchr() (libc),
 * so no stub/-Wl,--wrap= is needed here at all -- it never reaches
 * get_sockaddr() (that is get_comindexes(), one level up, out of scope
 * for this file).
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* get_comindex()'s own signature (racoonctl.c) uses old K&R char *str,
 * **name, **port, **pref -- mirrored here for the extern declaration. */
extern int get_comindex_unittest(char *str, char **name, char **port,
    char **pref);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
check_str(const char *label, char *got, const char *want)
{
	if (want == NULL) {
		if (got != NULL) {
			printf("(%s: got \"%s\", expected NULL) ", label, got);
			return -1;
		}
		return 0;
	}
	if (got == NULL) {
		printf("(%s: got NULL, expected \"%s\") ", label, want);
		return -1;
	}
	if (strcmp(got, want) != 0) {
		printf("(%s: got \"%s\", expected \"%s\") ", label, got, want);
		return -1;
	}
	return 0;
}

static void
free_all(char *name, char *port, char *pref)
{
	free(name);
	free(port);
	free(pref);
}

/*
 * Drives get_comindex_unittest() with one input string and checks it
 * against the expected name/port/pref triple (NULL for fields that
 * should stay unset) on a successful parse.
 */
static int
check_parses(const char *desc, const char *input, const char *want_name,
    const char *want_port, const char *want_pref)
{
	char *name = NULL, *port = NULL, *pref = NULL;
	char *str;
	int rv;

	TEST_START(desc);

	/* get_comindex()'s str is not modified (it racoon_strdup()s its
	 * own copy internally), but the prototype is non-const. */
	str = strdup(input);
	if (str == NULL)
		TEST_FAIL("strdup() failed");

	rv = get_comindex_unittest(str, &name, &port, &pref);
	free(str);

	if (rv != 0) {
		printf("(get_comindex() returned -1 for \"%s\") ", input);
		free_all(name, port, pref);
		TEST_FAIL("expected a successful parse");
	}

	if (check_str("name", name, want_name) != 0 ||
	    check_str("port", port, want_port) != 0 ||
	    check_str("pref", pref, want_pref) != 0) {
		free_all(name, port, pref);
		TEST_FAIL("parsed fields did not match");
	}

	free_all(name, port, pref);
	TEST_PASS();
	return 0;
}

/*
 * Drives get_comindex_unittest() with one input string and confirms it
 * is rejected (-1) with all three out-parameters left NULL (the
 * documented "bad:" cleanup contract).
 */
static int
check_rejects(const char *desc, const char *input)
{
	char *name = NULL, *port = NULL, *pref = NULL;
	char *str;
	int rv;

	TEST_START(desc);

	str = strdup(input);
	if (str == NULL)
		TEST_FAIL("strdup() failed");

	rv = get_comindex_unittest(str, &name, &port, &pref);
	free(str);

	if (rv != -1) {
		printf("(get_comindex() returned %d for \"%s\") ", rv, input);
		free_all(name, port, pref);
		TEST_FAIL("expected rejection (-1)");
	}
	if (name != NULL || port != NULL || pref != NULL) {
		free_all(name, port, pref);
		TEST_FAIL("out-parameters were not all reset to NULL on failure");
	}

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== get_comindex() address-form grammar test (issue #119) ===\n");

	/* addr alone: no '/' or '[' at all -- the unlabeled fallthrough
	 * else-branch. name is set, port/pref stay NULL (get_comindexes()
	 * itself, one level up, is what defaults prefs/prefd to 32 when
	 * pref is NULL -- not this function's job). */
	if (check_parses("plain address, no prefix or port",
	    "10.0.0.1", "10.0.0.1", NULL, NULL) != 0)
		failed++;

	if (check_parses("plain IPv6 address, no prefix or port",
	    "2001:db8::1", "2001:db8::1", NULL, NULL) != 0)
		failed++;

	/* addr/prefix: the '/' branch, no nested '[' inside *pref. */
	if (check_parses("address with prefix, no port",
	    "10.0.0.1/32", "10.0.0.1", NULL, "32") != 0)
		failed++;

	if (check_parses("address with a short prefix",
	    "192.168.0.0/16", "192.168.0.0", NULL, "16") != 0)
		failed++;

	/*
	 * address/prefix[port]: the exact case issue #119's fix targets.
	 * Before the fix, every one of these unconditionally returned -1.
	 */
	if (check_parses("address with prefix and port (issue #119)",
	    "10.0.0.1/32[4500]", "10.0.0.1", "4500", "32") != 0)
		failed++;

	if (check_parses("address with prefix and a different port",
	    "10.0.0.2/24[500]", "10.0.0.2", "500", "24") != 0)
		failed++;

	if (check_parses("IPv6 address with prefix and port",
	    "2001:db8::1/64[4500]", "2001:db8::1", "4500", "64") != 0)
		failed++;

	/*
	 * addr[port], no prefix at all: get_comindex()'s "else if (*p ==
	 * '[')" branch always rejects this -- *pref is unconditionally
	 * NULL at that point (nothing sets it before this branch can be
	 * reached; the '/' branch above is the only assignment, and
	 * strpbrk() finding '[' before any '/' is exactly what routes
	 * here instead). Checked against usage()'s own documented
	 * grammar ("<src/prefixlen/port>", no bracket-only form ever
	 * shown) before concluding this is current, intended behavior --
	 * not a second instance of #119. This test pins that down as a
	 * regression guard either way: if this ever starts succeeding,
	 * that is itself worth a deliberate decision, not a silent
	 * behavior change.
	 */
	if (check_rejects("address with port but no prefix is rejected",
	    "10.0.0.1[4500]") != 0)
		failed++;

	/* Malformed variants -- each should cleanly reject, not crash or
	 * leak a partially-built triple. */
	if (check_rejects("trailing '/' with nothing after it",
	    "10.0.0.1/") != 0)
		failed++;

	if (check_rejects("trailing '[' with nothing after it",
	    "10.0.0.1/32[") != 0)
		failed++;

	if (check_rejects("prefix with '[' but missing ']'",
	    "10.0.0.1/32[4500") != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
	return failed == 0 ? 0 : 1;
}
