// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for getcertsbyname.c's two allocation helpers,
 * getnewci() (static, exposed via the new getnewci_unittest()
 * ENABLE_UNITTEST accessor) and freecertinfo() (already exported).
 * Both were previously entirely uncovered: no test binary linked
 * getcertsbyname.o at all.
 *
 * getcertsbyname.c is pulled in via getcertsbyname_unittest_src.c
 * (-ffunction-sections/--gc-sections, the same pattern as admin.c's
 * wrapper): this binary only ever calls getnewci_unittest()/
 * freecertinfo(), never getcertsbyname() itself, so --gc-sections drops
 * that function (and its res_query()/res_init()/libresolv dependency)
 * entirely -- no -lresolv needed here. test_getcertsbyname_dnssec.c
 * covers getcertsbyname() itself.
 *
 * -Wl,--wrap=free (same linker-interposition technique
 * test_script_hook_leak.c already uses) confirms freecertinfo() frees
 * exactly two allocations per node (ci_cert and the node itself) --
 * neither more (a double-free) nor fewer (a leak).
 *
 * skip_if_wrap_free_ineffective() below guards against a real, observed
 * failure mode: under whole-program LTO (-flto=auto -ffat-lto-objects,
 * confirmed on Ubuntu 26.04 "Resolute", GCC 15.2/binutils 2.46), GCC's
 * own malloc()/free() pairing elision -- proving a freed allocation never
 * escapes and removing the whole allocate/free sequence, oblivious to the
 * linker's --wrap=free redirection, since that redirection happens
 * entirely at link time, after GCC's LTO optimization has already run --
 * can and does remove test_freecertinfo_frees_every_node_in_the_chain()'s
 * entire allocate-link-free sequence outright, leaving free_calls at 0
 * for a reason that has nothing to do with freecertinfo() itself. A
 * canary free() at startup distinguishes that (SKIP) from a genuine
 * partial-free regression (FAIL, a nonzero but wrong count) -- see
 * doc/dev/wrap-based-tests-vs-lto.md for the full writeup.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netdb_dnssec.h"

extern struct certinfo *getnewci_unittest(int qtype, int keytag,
    int algorithm, int flags, int certlen, unsigned char *cert);
extern void freecertinfo(struct certinfo *ci);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

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
 * toolchain before trusting any test below that counts them. See this
 * file's header comment for why a plain free_calls == 0 can otherwise be
 * mistaken for a genuine leak.
 *
 * The canary deliberately goes through getnewci_unittest()/freecertinfo()
 * (the same opaque, cross-translation-unit allocator/deallocator pair the
 * real tests below use) rather than a bare malloc(1)/free(): a
 * self-contained malloc()+free() with nothing in between is trivial
 * enough that GCC's own elision optimization removes it at plain -O2,
 * with no LTO involved at all, since malloc()/free() are library
 * functions GCC has built-in semantic knowledge of regardless of
 * function visibility -- that would make this canary misfire on every
 * ordinary (non-LTO) toolchain, not just the LTO one it exists to catch.
 * getnewci_unittest()/freecertinfo() are opaque, externally-defined
 * functions in a different .o without LTO, so this mirrors exactly what
 * protects the real tests below on a normal toolchain, while still
 * tripping under whole-program LTO the same way they would.
 */
static int
skip_if_wrap_free_ineffective(void)
{
	unsigned char cert[] = { 0x01 };
	struct certinfo *canary = getnewci_unittest(37, 1, 1, 0, sizeof(cert), cert);

	free_calls = 0;
	freecertinfo(canary);
	if (free_calls == 2)
		return 0;

	printf("\n=== getcertsbyname.c helper functions test ===\n"
	    "SKIP: -Wl,--wrap=free did not intercept free() calls made via a "
	    "canary getnewci_unittest()/freecertinfo() round trip on this "
	    "toolchain. This is a known interaction with whole-program LTO "
	    "(-flto=auto -ffat-lto-objects): GCC's malloc()/free() pairing "
	    "elision can remove a provably-non-escaping allocate/free sequence "
	    "outright, since it has no knowledge of the linker's --wrap=free "
	    "redirection. See doc/dev/wrap-based-tests-vs-lto.md.\n\n");
	return 1;
}

static int
test_getnewci_populates_all_fields(void)
{
	unsigned char cert[] = { 0xde, 0xad, 0xbe, 0xef, 0x01 };
	struct certinfo *ci;

	TEST_START("getnewci() populates every field and copies the cert bytes");

	ci = getnewci_unittest(37 /* T_CERT */, 12345, 1 /* RSAMD5 */, 1,
	    sizeof(cert), cert);
	if (ci == NULL)
		TEST_FAIL("getnewci() returned NULL");

	if (ci->ci_type != 37 || ci->ci_keytag != 12345 ||
	    ci->ci_algorithm != 1 || ci->ci_flags != 1) {
		freecertinfo(ci);
		TEST_FAIL("scalar fields do not match what was passed in");
	}
	if (ci->ci_certlen != sizeof(cert)) {
		freecertinfo(ci);
		TEST_FAIL("ci_certlen does not match certlen");
	}
	if (ci->ci_cert == (char *)cert ||
	    memcmp(ci->ci_cert, cert, sizeof(cert)) != 0) {
		freecertinfo(ci);
		TEST_FAIL("ci_cert is not an independent copy of the input bytes");
	}
	if (ci->ci_next != NULL) {
		freecertinfo(ci);
		TEST_FAIL("ci_next was not initialized to NULL");
	}

	freecertinfo(ci);
	TEST_PASS();
	return 0;
}

static int
test_freecertinfo_frees_every_node_in_the_chain(void)
{
	unsigned char cert[] = { 0x01, 0x02, 0x03 };
	struct certinfo *a, *b, *c;

	TEST_START("freecertinfo() frees ci_cert and the node for every entry in the chain");

	a = getnewci_unittest(37, 1, 1, 0, sizeof(cert), cert);
	b = getnewci_unittest(37, 2, 1, 0, sizeof(cert), cert);
	c = getnewci_unittest(37, 3, 1, 0, sizeof(cert), cert);
	if (a == NULL || b == NULL || c == NULL) {
		if (a) freecertinfo(a);
		if (b) freecertinfo(b);
		if (c) freecertinfo(c);
		TEST_FAIL("getnewci() failed while building the test chain");
	}
	a->ci_next = b;
	b->ci_next = c;

	free_calls = 0;
	freecertinfo(a);

	/* 3 nodes * (ci_cert + the node itself) = 6 free() calls. */
	if (free_calls != 6) {
		printf("free_calls = %d, expected 6 ", free_calls);
		TEST_FAIL("freecertinfo() did not free exactly 2 allocations per node");
	}

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	if (skip_if_wrap_free_ineffective())
		return 77;

	printf("\n=== getcertsbyname.c helper functions test ===\n");

	if (test_getnewci_populates_all_fields() != 0)
		failed++;
	if (test_freecertinfo_frees_every_node_in_the_chain() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
