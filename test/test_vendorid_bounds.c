// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression tests for the pre-authentication out-of-bounds reads in Vendor
 * ID handling:
 *
 *   #38  vendorid_frag_cap() (isakmp_frag.c) read the 4-byte capability dword
 *        at offset 16 of the VID data without checking the payload was long
 *        enough — a FRAGMENTATION VID truncated to just its 16-byte hash caused
 *        a 4-byte over-read.
 *
 *   #39  check_vendorid()/lookup_vendor_id_by_hash() (vendorid.c) compared up
 *        to 16 bytes of hash before validating the VID payload length, over-
 *        reading a short/last payload.
 *
 * Unlike #37, these over-reads do not change the functional result, so the
 * regressions are caught under valgrind (the repo's `make check-valgrind`):
 * every malformed payload is a heap buffer sized to exactly the bytes present,
 * so a pre-fix over-read is an invalid heap read.  The functional assertions
 * (frag cap == 0; VID classified UNKNOWN) additionally confirm the fixed
 * behaviour under a plain `make check`.
 *
 * vendorid_frag_cap() is non-static.  check_vendorid() is static, so vendorid.c
 * is compiled with -DENABLE_UNITTEST to expose check_vendorid_unittest().
 * Both sources are built with -ffunction-sections and linked with
 * --gc-sections, discarding the unused remainder of each file.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <openssl/md5.h>

#include "var.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "vendorid.h"
#include "isakmp_frag.h"

/* check_vendorid() exposed via -DENABLE_UNITTEST in vendorid.c. */
extern int check_vendorid_unittest(struct isakmp_gen *gen);

#define TEST_PASS() do { printf("✓ PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("✗ FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/*
 * #38: vendorid_frag_cap() must return the capability dword for a full-length
 * FRAGMENTATION VID, and must return 0 (rather than over-reading) for one
 * truncated to just the 16-byte hash.
 */
static int
test_frag_cap_full(void)
{
	u_char buf[sizeof(struct isakmp_gen) + MD5_DIGEST_LENGTH + sizeof(int)];
	struct isakmp_gen *gen = (struct isakmp_gen *)buf;
	u_int32_t cap = htonl(VENDORID_FRAG_IDENT);

	TEST_START("frag cap read from full-length VID");

	memset(buf, 0, sizeof(buf));
	gen->len = htons((u_int16_t)sizeof(buf));
	memcpy(buf + sizeof(struct isakmp_gen) + MD5_DIGEST_LENGTH,
	    &cap, sizeof(cap));

	if (vendorid_frag_cap(gen) != VENDORID_FRAG_IDENT)
		TEST_FAIL("capability dword not read back correctly");

	TEST_PASS();
	return 0;
}

static int
test_frag_cap_truncated(void)
{
	const size_t len = sizeof(struct isakmp_gen) + MD5_DIGEST_LENGTH;
	u_char *buf;
	struct isakmp_gen *gen;
	unsigned int cap;

	TEST_START("frag cap on hash-only (truncated) VID is rejected");

	buf = malloc(len);		/* hash only, no capability dword */
	if (buf == NULL)
		TEST_FAIL("malloc failed");

	gen = (struct isakmp_gen *)buf;
	memset(buf, 0, len);
	gen->len = htons((u_int16_t)len);

	cap = vendorid_frag_cap(gen);
	free(buf);

	if (cap != 0)
		TEST_FAIL("truncated VID did not yield 0 capability");

	TEST_PASS();
	return 0;
}

/*
 * #39: check_vendorid() must classify an empty VID and a sub-hash-length VID
 * as UNKNOWN without reading past the payload.
 */
static int
test_check_vendorid_empty(void)
{
	const size_t len = sizeof(struct isakmp_gen);	/* header only, vidlen 0 */
	u_char *buf;
	struct isakmp_gen *gen;
	int rc;

	TEST_START("empty VID (vidlen == 0) is UNKNOWN without over-read");

	/*
	 * Heap-allocated to exactly the header size: without the vidlen guard,
	 * lookup_vendor_id_by_hash() reads (gen + 1), i.e. one past the buffer,
	 * which valgrind flags as an invalid read.
	 */
	buf = malloc(len);
	if (buf == NULL)
		TEST_FAIL("malloc failed");

	gen = (struct isakmp_gen *)buf;
	memset(buf, 0, len);
	gen->len = htons((u_int16_t)len);		/* no VID data */

	rc = check_vendorid_unittest(gen);
	free(buf);

	if (rc != VENDORID_UNKNOWN)
		TEST_FAIL("empty VID not classified UNKNOWN");

	TEST_PASS();
	return 0;
}

static int
test_check_vendorid_short(void)
{
	const size_t len = sizeof(struct isakmp_gen) + 4;	/* vidlen = 4 */
	u_char *buf;
	struct isakmp_gen *gen;
	int rc;

	TEST_START("sub-hash-length VID is UNKNOWN without over-read");

	buf = malloc(len);		/* exact size: over-read would fault */
	if (buf == NULL)
		TEST_FAIL("malloc failed");

	gen = (struct isakmp_gen *)buf;
	memset(buf, 0, len);
	gen->len = htons((u_int16_t)len);
	/* 4 bytes of arbitrary data — shorter than any known VID hash */
	memcpy(buf + sizeof(struct isakmp_gen), "\xde\xad\xbe\xef", 4);

	rc = check_vendorid_unittest(gen);
	free(buf);

	if (rc != VENDORID_UNKNOWN)
		TEST_FAIL("short VID not classified UNKNOWN");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== Vendor ID bounds tests (issues #38, #39) ===\n");

	/* Populate the Vendor ID hash table used by check_vendorid(). */
	compute_vendorids();

	if (test_frag_cap_full() != 0)
		failed++;
	if (test_frag_cap_truncated() != 0)
		failed++;
	if (test_check_vendorid_empty() != 0)
		failed++;
	if (test_check_vendorid_short() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
