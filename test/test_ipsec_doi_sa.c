// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for the pre-authentication out-of-bounds read in
 * t2isakmpsa() (issue #37, CWE-125).
 *
 * When parsing the attributes of an IKE phase-1 SA transform, t2isakmpsa()
 * copied ntohs(d->lorv) bytes of a TLV (long-form) attribute value with
 * memcpy() before validating the declared length against the bytes actually
 * present in the transform.  A crafted attribute whose length field exceeds
 * the transform payload therefore drove a heap over-read of up to ~64 KB from
 * a single unauthenticated packet.
 *
 * t2isakmpsa() is static; ipsec_doi.c is compiled here with -DENABLE_UNITTEST
 * to expose the thin wrapper t2isakmpsa_unittest() used below.
 *
 * The malformed transform is placed in a heap buffer sized to exactly the
 * bytes it legitimately contains, so the pre-fix over-read is additionally
 * caught by AddressSanitizer / valgrind, while the functional assertion
 * (the parser must reject it, returning -1) makes the test self-validating
 * under a plain `make check`.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "var.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "oakley.h"
#include "remoteconf.h"

/*
 * Provided by ipsec_doi.c when compiled with -DENABLE_UNITTEST.  t2isakmpsa()
 * is static; this wrapper exposes it for the test.  The translation unit is
 * built with -ffunction-sections and linked with --gc-sections so the rest of
 * ipsec_doi.c (and its heavy dependency closure) is discarded, leaving only
 * t2isakmpsa()'s small set of always-built dependencies.
 */
extern int t2isakmpsa_unittest(struct isakmp_pl_t *trns, struct isakmpsa *sa,
    u_int32_t vendorid_mask);

/*
 * Allocate/free a zeroed struct isakmpsa locally rather than via
 * newisakmpsa()/delisakmpsa(), to avoid pulling remoteconf.o (and its
 * closure) into the link.  t2isakmpsa() only requires a zeroed struct; it
 * allocates sa->dhgrp itself.
 */
static struct isakmpsa *
sa_alloc(void)
{
	return calloc(1, sizeof(struct isakmpsa));
}

static void
sa_free(struct isakmpsa *sa)
{
	if (sa == NULL)
		return;
	if (sa->dhgrp != NULL)
		free(sa->dhgrp);
	free(sa);
}

#define TEST_PASS() do { printf("✓ PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("✗ FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/* Write a short-form (TV) attribute at p, return bytes written (4). */
static size_t
put_tv(u_char *p, u_int16_t type, u_int16_t value)
{
	struct isakmp_data d;

	d.type = htons(type | ISAKMP_GEN_TV);
	d.lorv = htons(value);
	memcpy(p, &d, sizeof(d));
	return sizeof(d);
}

/*
 * A well-formed transform built entirely from short-form attributes must be
 * accepted (returns 0). This guards against the bounds check rejecting valid
 * input.
 */
static int
test_valid_transform_accepted(void)
{
	u_char buf[sizeof(struct isakmp_pl_t) + 4 * sizeof(struct isakmp_data)];
	struct isakmp_pl_t *trns = (struct isakmp_pl_t *)buf;
	struct isakmpsa *sa;
	u_char *p;
	int rc;

	TEST_START("well-formed transform is accepted");

	memset(buf, 0, sizeof(buf));
	trns->h.np = 0;
	trns->t_no = 1;
	trns->t_id = 1;			/* KEY_IKE */
	trns->h.len = htons((u_int16_t)sizeof(buf));

	p = (u_char *)(trns + 1);
	p += put_tv(p, OAKLEY_ATTR_ENC_ALG, OAKLEY_ATTR_ENC_ALG_AES);
	p += put_tv(p, OAKLEY_ATTR_HASH_ALG, OAKLEY_ATTR_HASH_ALG_SHA);
	p += put_tv(p, OAKLEY_ATTR_AUTH_METHOD, OAKLEY_ATTR_AUTH_METHOD_PSKEY);
	p += put_tv(p, OAKLEY_ATTR_GRP_DESC, OAKLEY_ATTR_GRP_DESC_MODP1024);

	sa = sa_alloc();
	if (sa == NULL)
		TEST_FAIL("sa_alloc() returned NULL");

	rc = t2isakmpsa_unittest(trns, sa, 0);
	sa_free(sa);

	if (rc != 0)
		TEST_FAIL("valid transform rejected (expected 0)");

	TEST_PASS();
	return 0;
}

/*
 * A TLV attribute whose declared length overruns the transform payload must
 * be rejected (returns -1) instead of over-reading. The buffer is sized to
 * exactly the bytes present so the pre-fix over-read faults under ASAN/valgrind.
 */
static int
test_overlong_attribute_rejected(void)
{
	const size_t len = sizeof(struct isakmp_pl_t) + sizeof(struct isakmp_data);
	u_char *buf;
	struct isakmp_pl_t *trns;
	struct isakmp_data attr;
	struct isakmpsa *sa;
	int rc;

	TEST_START("over-long TLV attribute is rejected");

	buf = malloc(len);		/* exact size: no trailing slack */
	if (buf == NULL)
		TEST_FAIL("malloc failed");

	trns = (struct isakmp_pl_t *)buf;
	memset(buf, 0, len);
	trns->h.np = 0;
	trns->t_no = 1;
	trns->t_id = 1;			/* KEY_IKE */
	trns->h.len = htons((u_int16_t)len);

	/*
	 * TLV attribute (AF=0): claims a 0xFFFF-byte value, but no value bytes
	 * are actually present in the transform.
	 */
	attr.type = htons(OAKLEY_ATTR_GRP_PI);	/* AF bit clear -> TLV */
	attr.lorv = htons(0xFFFF);
	memcpy(buf + sizeof(struct isakmp_pl_t), &attr, sizeof(attr));

	sa = sa_alloc();
	if (sa == NULL) {
		free(buf);
		TEST_FAIL("sa_alloc() returned NULL");
	}

	rc = t2isakmpsa_unittest(trns, sa, 0);
	sa_free(sa);
	free(buf);

	if (rc != -1)
		TEST_FAIL("over-long attribute not rejected (expected -1)");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== IKE SA transform attribute bounds tests (issue #37) ===\n");

	if (test_valid_transform_accepted() != 0)
		failed++;
	if (test_overlong_attribute_rejected() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
