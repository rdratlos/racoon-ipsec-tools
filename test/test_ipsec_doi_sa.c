// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression tests for t2isakmpsa(), the IKE phase-1 SA transform attribute
 * parser:
 *
 *  - The pre-authentication out-of-bounds read (issue #37, CWE-125):
 *    t2isakmpsa() copied ntohs(d->lorv) bytes of a TLV (long-form) attribute
 *    value with memcpy() before validating the declared length against the
 *    bytes actually present in the transform. A crafted attribute whose
 *    length field exceeds the transform payload therefore drove a heap
 *    over-read of up to ~64 KB from a single unauthenticated packet.
 *  - A memory leak in the OAKLEY_ATTR_SA_LD (life duration) case (reported
 *    against PR #108 from a real gateway's check-valgrind run): every other
 *    exit from that case frees the TLV value vmalloc()'d to read it, but
 *    the ordering-check failure branch ("life duration must follow ltype")
 *    did not. See test_sa_ld_without_ltype_leaks_nothing() below.
 *
 * t2isakmpsa() is static; ipsec_doi.c is compiled here with -DENABLE_UNITTEST
 * to expose the thin wrapper t2isakmpsa_unittest() used below.
 *
 * The malformed transform in test_overlong_attribute_rejected() is placed in
 * a heap buffer sized to exactly the bytes it legitimately contains, so the
 * pre-fix over-read is additionally caught by AddressSanitizer / valgrind,
 * while the functional assertion (the parser must reject it, returning -1)
 * makes the test self-validating under a plain `make check`. The SA_LD leak
 * is the same shape: check-valgrind is what actually proves nothing leaks;
 * the functional assertions here confirm the malformed attribute is merely
 * tolerated (not silently applied), not what was actually broken.
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

/* Write a long-form (TLV) attribute at p: header plus len value bytes,
 * return total bytes written. */
static size_t
put_tlv(u_char *p, u_int16_t type, const void *value, u_int16_t len)
{
	struct isakmp_data d;

	d.type = htons(type | ISAKMP_GEN_TLV);
	d.lorv = htons(len);
	memcpy(p, &d, sizeof(d));
	memcpy(p + sizeof(d), value, len);
	return sizeof(d) + len;
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

/*
 * A life-duration (OAKLEY_ATTR_SA_LD) attribute that does not immediately
 * follow its life-type (OAKLEY_ATTR_SA_LD_TYPE) attribute is malformed --
 * t2isakmpsa() logs it and moves on rather than rejecting the whole
 * transform. Before this fix, the TLV value's vmalloc()'d backing memory
 * (allocated to read the attribute before the ordering check ran) was never
 * freed on this path, unlike every other exit from the SA_LD case -- a
 * per-occurrence leak reported against a real gateway (rdratlos/
 * racoon-ipsec-tools PR #108) after real, non-adversarial IKE traffic
 * apparently hit this exact ordering, twice, over 50+ live handshakes.
 *
 * The leak itself isn't observable from inside this process (nothing here
 * can inspect its own heap for lost blocks); check-valgrind is what
 * actually catches it, the same as test_overlong_attribute_rejected()'s own
 * ASAN/valgrind-only half above. What this test asserts directly: the
 * malformed attribute must not corrupt parsing -- the transform is still
 * accepted (this is a tolerated, logged oddity, not a fatal parse error, so
 * rc must stay 0) and sa->lifetime must be left at its default, proving the
 * bogus value was actually discarded rather than silently applied.
 */
static int
test_sa_ld_without_ltype_leaks_nothing(void)
{
	u_char buf[sizeof(struct isakmp_pl_t) + 4 * sizeof(struct isakmp_data)
	    + 4];
	struct isakmp_pl_t *trns = (struct isakmp_pl_t *)buf;
	struct isakmpsa *sa;
	u_char *p;
	u_int32_t ld_value = htonl(60); /* would mean "60 seconds" if applied */
	int rc;

	TEST_START("SA_LD without a preceding LTYPE leaks nothing (PR #108)");

	memset(buf, 0, sizeof(buf));
	trns->h.np = 0;
	trns->t_no = 1;
	trns->t_id = 1;			/* KEY_IKE */

	p = (u_char *)(trns + 1);
	p += put_tv(p, OAKLEY_ATTR_ENC_ALG, OAKLEY_ATTR_ENC_ALG_AES);
	p += put_tv(p, OAKLEY_ATTR_HASH_ALG, OAKLEY_ATTR_HASH_ALG_SHA);
	p += put_tv(p, OAKLEY_ATTR_AUTH_METHOD, OAKLEY_ATTR_AUTH_METHOD_PSKEY);
	/* No OAKLEY_ATTR_SA_LD_TYPE here -- SA_LD arrives with "prev" pointing
	 * at AUTH_METHOD instead, the exact misordering that leaked. */
	p += put_tlv(p, OAKLEY_ATTR_SA_LD, &ld_value, sizeof(ld_value));

	trns->h.len = htons((u_int16_t)(p - buf));

	sa = sa_alloc();
	if (sa == NULL)
		TEST_FAIL("sa_alloc() returned NULL");

	rc = t2isakmpsa_unittest(trns, sa, 0);

	if (rc != 0) {
		sa_free(sa);
		TEST_FAIL("malformed-but-non-fatal attribute rejected the "
		    "whole transform (expected 0)");
	}
	if (sa->lifetime != OAKLEY_ATTR_SA_LD_SEC_DEFAULT) {
		sa_free(sa);
		TEST_FAIL("bogus life duration was applied instead of "
		    "discarded");
	}
	sa_free(sa);

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
	if (test_sa_ld_without_ltype_leaks_nothing() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
