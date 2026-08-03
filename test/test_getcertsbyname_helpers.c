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

	printf("\n=== getcertsbyname.c helper functions test ===\n");

	if (test_getnewci_populates_all_fields() != 0)
		failed++;
	if (test_freecertinfo_frees_every_node_in_the_chain() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
