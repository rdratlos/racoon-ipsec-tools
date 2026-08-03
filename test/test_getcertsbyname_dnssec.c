// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for getcertsbyname()'s DNSSEC validation fix (admin.c-
 * adjacent churn in this same v0.9.1 pass -- see the diff removing the
 * dead HAVE_LWRES_GETRRSETBYNAME variant): the response-validation check
 * used to be
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
 * accepted -- and asserts getcertsbyname() now rejects it. Reverting the
 * fix (put "&& hp->aa == 0" back) makes this test fail.
 *
 * getcertsbyname() calls the real libresolv res_query()/res_init(),
 * which would otherwise mean a real DNS query (network-dependent,
 * non-hermetic, and unable to produce a deliberately-invalid response in
 * the first place). -Wl,--wrap=res_query/-Wl,--wrap=res_init (same
 * linker-interposition technique test_script_hook_leak.c already uses
 * for free()) substitute a hand-built wire-format response and skip
 * touching /etc/resolv.conf entirely; see build_dns_response() below for
 * the packet layout.
 *
 * getcertsbyname.c is pulled in via getcertsbyname_unittest_src.c
 * (-ffunction-sections/--gc-sections, matching admin.c's wrapper);
 * unlike test_getcertsbyname_helpers.c, this binary's one entry point
 * (getcertsbyname() itself) needs -lresolv for dn_expand()/GETSHORT.
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

extern int getcertsbyname(char *name, struct certinfo **res);
extern struct __res_state _res;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/*
 * Linker-level res_query()/res_init() interposition (-Wl,--wrap=...,
 * test/Makefile.am): every call getcertsbyname() makes is redirected
 * here instead of touching the network or /etc/resolv.conf.
 */
static unsigned char fake_response[512];
static int fake_response_len;
static int fake_res_query_force_failure;
static int res_query_calls;
static char last_queried_name[256];

int
__wrap_res_query(const char *dname, int class, int type,
    unsigned char *answer, int anslen)
{
	int tocopy;

	res_query_calls++;
	snprintf(last_queried_name, sizeof(last_queried_name), "%s", dname);

	if (fake_res_query_force_failure)
		return -1;

	tocopy = fake_response_len < anslen ? fake_response_len : anslen;
	memcpy(answer, fake_response, tocopy);
	return fake_response_len;
}

int
__wrap_res_init(void)
{
	_res.options |= RES_INIT;
	return 0;
}

static void
reset_state(void)
{
	fake_response_len = 0;
	fake_res_query_force_failure = 0;
	res_query_calls = 0;
	last_queried_name[0] = '\0';
}

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
 * because getcertsbyname() bails out on a qdcount mismatch before ever
 * reading question-section content.
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
	int rc;

	TEST_START("an AA=1/AD=0 response is rejected, not accepted as DNSSEC-validated");

	reset_state();
	fake_response_len = build_dns_response(fake_response,
	    /* ad */ 0, /* aa */ 1, /* qdcount */ 1,
	    "roadwarrior.example.test", 37, 1, 1, cert, sizeof(cert));

	rc = getcertsbyname("roadwarrior.example.test", &res);

	if (rc == 0) {
		if (res != NULL)
			freecertinfo(res);
		TEST_FAIL("getcertsbyname() accepted an AA=1/AD=0 response -- "
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
	int rc;

	TEST_START("an AD=1 response is accepted and the CERT RR parsed correctly");

	reset_state();
	fake_response_len = build_dns_response(fake_response,
	    /* ad */ 1, /* aa */ 0, /* qdcount */ 1,
	    "roadwarrior.example.test", 37, 4242, 1, cert, sizeof(cert));

	rc = getcertsbyname("roadwarrior.example.test", &res);

	if (rc != 0) {
		TEST_FAIL("getcertsbyname() rejected a validly DNSSEC-signed response");
	}
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
	if (strcmp(last_queried_name, "roadwarrior.example.test") != 0) {
		freecertinfo(res);
		TEST_FAIL("res_query() was not called with the requested FQDN");
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
	int rc;

	TEST_START("AD=1 does not bypass the qdcount sanity check");

	reset_state();
	fake_response_len = build_dns_response(fake_response,
	    /* ad */ 1, /* aa */ 0, /* qdcount */ 2,
	    "roadwarrior.example.test", 37, 1, 1, cert, sizeof(cert));

	rc = getcertsbyname("roadwarrior.example.test", &res);

	if (rc == 0) {
		if (res != NULL)
			freecertinfo(res);
		TEST_FAIL("getcertsbyname() accepted a response with qdcount != 1");
	}

	TEST_PASS();
	return 0;
}

static int
test_query_failure_is_propagated(void)
{
	struct certinfo *res = (struct certinfo *)0x1;
	int rc;

	TEST_START("a failed res_query() is propagated as an error, not a crash");

	reset_state();
	fake_res_query_force_failure = 1;

	rc = getcertsbyname("nonexistent.example.test", &res);

	if (rc == 0) {
		if (res != NULL)
			freecertinfo(res);
		TEST_FAIL("getcertsbyname() reported success despite res_query() failing");
	}
	if (res != NULL)
		TEST_FAIL("*res was not reset to NULL on query failure");
	if (res_query_calls < 1)
		TEST_FAIL("res_query() was never actually called");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== getcertsbyname() DNSSEC AD-bit validation test ===\n");

	if (test_rejects_aa_only_response() != 0)
		failed++;
	if (test_accepts_and_parses_ad_response() != 0)
		failed++;
	if (test_rejects_wrong_question_count_even_with_ad_set() != 0)
		failed++;
	if (test_query_failure_is_propagated() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
