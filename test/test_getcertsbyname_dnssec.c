// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for getcertsbyname.c's DNSSEC validation fix (see the
 * diff removing the dead HAVE_LWRES_GETRRSETBYNAME variant): the
 * response-validation check used to be
 *
 *     if (hp->ad == 0 && hp->aa == 0) { ... reject ... }
 *
 * i.e. it accepted a response as DNSSEC-validated if *either* the
 * Authenticated Data (AD) bit was set *or* the Authoritative Answer (AA)
 * bit was set. AA only means "the responder claims authority for this
 * zone" -- it says nothing about whether the record was cryptographically
 * validated, and can be set by any resolver willing to claim it (a
 * malicious or compromised recursive resolver, or a spoofed response
 * racing a legitimate one) regardless of whether real DNSSEC validation
 * ever happened. Treating it as an alternate proof of validation let an
 * attacker who can get racoon to accept AA=1 responses smuggle in an
 * unvalidated (and therefore unauthenticated, possibly attacker-chosen)
 * CERT RR for a peer's identity certificate -- CWE-290 (Authentication
 * Bypass by Spoofing) / CWE-347 (Improper Verification of Cryptographic
 * Signature). The fix requires AD alone:
 *
 *     if (hp->ad == 0) { ... reject ... }
 *
 * test_rejects_aa_only_response() below is this bug's own regression
 * test: it builds a syntactically valid, otherwise-correct DNS response
 * with AA=1 but AD=0 -- exactly the shape the old code would have
 * accepted -- and asserts the fix now rejects it. Reverting the fix
 * (put "&& hp->aa == 0" back) makes this test fail.
 *
 * This drives parse_cert_answer_unittest() (getcertsbyname.c,
 * ENABLE_UNITTEST) directly against a hand-built response buffer,
 * rather than going through getcertsbyname() and intercepting its
 * res_query()/res_init() calls. An earlier version of this test did the
 * latter (-Wl,--wrap=res_query/--wrap=res_init) and passed here, but
 * was reported failing on Ubuntu Bionic 32-bit: --wrap silently did not
 * redirect those two calls on that toolchain (older glibc/binutils;
 * resolver symbols have a messier, more version-dependent history than
 * the plain libc symbols --wrap already handles reliably elsewhere in
 * this suite, e.g. free()/fork()/_exit()), so the real, network-
 * dependent res_query()/res_init() ran instead and failed outright in a
 * sandboxed test run. Two of the four tests still reported PASS there
 * despite this -- both expected rejection, which the real functions
 * failing also produced, just not for the reason the test intended: the
 * same false-positive-pass class test_admin_init.c's review already
 * caught once (a privilege-gated chown() short-circuiting before the
 * logic under test could run). parse_cert_answer() was split out of
 * getcertsbyname() specifically so this security-relevant half of the
 * file could be tested without depending on intercepting resolver calls
 * at all -- see that function's own header comment (getcertsbyname.c).
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
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

#include "netdb_dnssec.h"

extern int parse_cert_answer_unittest(unsigned char *answer, int anslen,
    struct certinfo **res);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static unsigned char fake_response[512];

static int
encode_name(unsigned char *buf, const char *name)
{
	int pos = 0;
	const char *label = name;

	while (*label != '\0') {
		const char *dot = strchr(label, '.');
		int len = dot ? (int)(dot - label) : (int)strlen(label);

		buf[pos++] = (unsigned char)len;
		memcpy(buf + pos, label, len);
		pos += len;
		label += len;
		if (*label == '.')
			label++;
	}
	buf[pos++] = 0;
	return pos;
}

/*
 * Builds a minimal, syntactically valid DNS response: one question, one
 * CERT answer RR, uncompressed (unqualified) domain-name encoding.
 * ad/aa set the header's Authenticated Data / Authoritative Answer bits
 * independently, so tests can construct exactly the AA=1,AD=0 shape the
 * fixed code must reject. qdcount overrides the header's declared
 * question count without actually encoding extra questions -- valid
 * because parse_cert_answer() bails out on a qdcount mismatch before
 * ever reading question-section content.
 */
static int
build_dns_response(unsigned char *buf, int ad, int aa, int qdcount,
    const char *name, int cert_type, int keytag, int algorithm,
    const unsigned char *certdata, size_t certlen)
{
	int pos, rdlen_pos, rdata_start, rdlength;

	memset(buf, 0, 512);

	buf[0] = 0x12;
	buf[1] = 0x34;
	buf[2] = 0x80 /* qr */ | (aa ? 0x04 : 0) | 0x01 /* rd */;
	buf[3] = 0x80 /* ra */ | (ad ? 0x20 : 0);
	buf[4] = (qdcount >> 8) & 0xff;
	buf[5] = qdcount & 0xff;
	buf[6] = 0;
	buf[7] = 1; /* ancount = 1 */
	/* nscount, arcount already zero */

	pos = 12;

	/* question section */
	pos += encode_name(buf + pos, name);
	buf[pos++] = (T_CERT >> 8) & 0xff;
	buf[pos++] = T_CERT & 0xff;
	buf[pos++] = (C_IN >> 8) & 0xff;
	buf[pos++] = C_IN & 0xff;

	/* answer section: one CERT RR */
	pos += encode_name(buf + pos, name);
	buf[pos++] = (T_CERT >> 8) & 0xff;
	buf[pos++] = T_CERT & 0xff;
	buf[pos++] = (C_IN >> 8) & 0xff;
	buf[pos++] = C_IN & 0xff;
	buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0x0e; buf[pos++] = 0x10; /* TTL */

	rdlen_pos = pos;
	pos += 2;
	rdata_start = pos;

	buf[pos++] = (cert_type >> 8) & 0xff;
	buf[pos++] = cert_type & 0xff;
	buf[pos++] = (keytag >> 8) & 0xff;
	buf[pos++] = keytag & 0xff;
	buf[pos++] = algorithm & 0xff;
	memcpy(buf + pos, certdata, certlen);
	pos += (int)certlen;

	rdlength = pos - rdata_start;
	buf[rdlen_pos] = (rdlength >> 8) & 0xff;
	buf[rdlen_pos + 1] = rdlength & 0xff;

	return pos;
}

/*
 * The regression test: AA=1, AD=0 -- exactly what the pre-fix
 * "hp->ad == 0 && hp->aa == 0" check would have accepted as "validated".
 */
static int
test_rejects_aa_only_response(void)
{
	unsigned char cert[] = { 0x01, 0x02, 0x03, 0x04 };
	struct certinfo *res = (struct certinfo *)0x1; /* sentinel, must become NULL */
	int len, rc;

	TEST_START("an AA=1/AD=0 response is rejected, not accepted as DNSSEC-validated");

	len = build_dns_response(fake_response,
	    /* ad */ 0, /* aa */ 1, /* qdcount */ 1,
	    "roadwarrior.example.test", 37, 1, 1, cert, sizeof(cert));

	rc = parse_cert_answer_unittest(fake_response, len, &res);

	if (rc == 0) {
		if (res != NULL)
			freecertinfo(res);
		TEST_FAIL("parse_cert_answer() accepted an AA=1/AD=0 response -- "
		    "this is the CWE-290/347 regression");
	}
	if (res != NULL)
		TEST_FAIL("*res was not reset to NULL on rejection");

	TEST_PASS();
	return 0;
}

static int
test_accepts_and_parses_ad_response(void)
{
	unsigned char cert[] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
	struct certinfo *res = NULL;
	int len, rc;

	TEST_START("an AD=1 response is accepted and the CERT RR parsed correctly");

	len = build_dns_response(fake_response,
	    /* ad */ 1, /* aa */ 0, /* qdcount */ 1,
	    "roadwarrior.example.test", 37, 4242, 1, cert, sizeof(cert));

	rc = parse_cert_answer_unittest(fake_response, len, &res);

	if (rc != 0)
		TEST_FAIL("parse_cert_answer() rejected a validly DNSSEC-signed response");
	if (res == NULL)
		TEST_FAIL("*res is NULL despite success");
	if (res->ci_type != 37 || res->ci_keytag != 4242 || res->ci_algorithm != 1) {
		freecertinfo(res);
		TEST_FAIL("parsed certinfo fields do not match the RR that was sent");
	}
	if (res->ci_certlen != sizeof(cert) ||
	    memcmp(res->ci_cert, cert, sizeof(cert)) != 0) {
		freecertinfo(res);
		TEST_FAIL("parsed certificate bytes do not match what was sent");
	}
	if (res->ci_next != NULL) {
		freecertinfo(res);
		TEST_FAIL("expected exactly one certinfo node, found more");
	}

	freecertinfo(res);
	TEST_PASS();
	return 0;
}

/*
 * AD=1 alone must not be sufficient if the response is otherwise
 * malformed -- confirms the AD-bit check is a necessary gate, not the
 * only one; a real attacker forging AD=1 (impossible without the
 * resolver's cooperation, but worth confirming this isn't the *only*
 * check standing between racoon and a bad response) still has to get
 * every other structural check right too.
 */
static int
test_rejects_wrong_question_count_even_with_ad_set(void)
{
	unsigned char cert[] = { 0x01 };
	struct certinfo *res = NULL;
	int len, rc;

	TEST_START("AD=1 does not bypass the qdcount sanity check");

	len = build_dns_response(fake_response,
	    /* ad */ 1, /* aa */ 0, /* qdcount */ 2,
	    "roadwarrior.example.test", 37, 1, 1, cert, sizeof(cert));

	rc = parse_cert_answer_unittest(fake_response, len, &res);

	if (rc == 0) {
		if (res != NULL)
			freecertinfo(res);
		TEST_FAIL("parse_cert_answer() accepted a response with qdcount != 1");
	}

	TEST_PASS();
	return 0;
}

/*
 * A malformed RDLENGTH that would read past the end of the message is
 * rejected rather than trusted -- an attacker-controlled field, and the
 * one bounds check standing between a bad CERT RR and an out-of-bounds
 * read via getnewci()'s memcpy().
 */
static int
test_rejects_rdlength_past_end_of_message(void)
{
	unsigned char cert[] = { 0x01, 0x02, 0x03, 0x04 };
	struct certinfo *res = NULL;
	int len, rdlen_pos, rc;

	TEST_START("an RDLENGTH claiming data past the end of the message is rejected");

	len = build_dns_response(fake_response,
	    /* ad */ 1, /* aa */ 0, /* qdcount */ 1,
	    "roadwarrior.example.test", 37, 1, 1, cert, sizeof(cert));

	/* The RDLENGTH field is the 2 bytes immediately before RDATA
	 * (cert_type/keytag/algorithm/cert, 5 + sizeof(cert) bytes). Inflate
	 * it to claim far more data than the message actually contains. */
	rdlen_pos = len - (5 + (int)sizeof(cert)) - 2;
	fake_response[rdlen_pos] = 0xff;
	fake_response[rdlen_pos + 1] = 0xff;

	rc = parse_cert_answer_unittest(fake_response, len, &res);

	if (rc == 0) {
		if (res != NULL)
			freecertinfo(res);
		TEST_FAIL("parse_cert_answer() accepted an RDLENGTH extending past the message");
	}

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== getcertsbyname.c DNSSEC AD-bit validation test ===\n");

	if (test_rejects_aa_only_response() != 0)
		failed++;
	if (test_accepts_and_parses_ad_response() != 0)
		failed++;
	if (test_rejects_wrong_question_count_even_with_ad_set() != 0)
		failed++;
	if (test_rejects_rdlength_past_end_of_message() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
