// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit tests for the attr_device LDAP scoping helpers in
 * src/racoon/isakmp_xauth.c (issue #86 groundwork; introduced alongside
 * attr_device itself).
 *
 * Coverage:
 *   xauth_ldap_escape_filter()  -- RFC 4515 LDAP filter value escaping.
 *   xauth_peer_device_id()      -- verified-certificate subjectAltName ->
 *                                  device identity, per device_id_type.
 *
 * Both functions are static; they are reached here via thin
 * xauth_*_unittest() wrappers compiled in only under -DENABLE_UNITTEST
 * (see isakmp_xauth.c and the test_xauth_device_id target in
 * test/Makefile.am). isakmp_xauth.c itself is pulled in wholesale via
 * isakmp_xauth_unittest_src.c and isolated with
 * -ffunction-sections/-fdata-sections + -Wl,--gc-sections, the same
 * technique used by test_script_hook_leak/test_script_exec_wait for
 * isakmp.c -- so this binary never needs to satisfy xauth_login_ldap()'s
 * (or PAM's/RADIUS's) much larger dependency closure.
 *
 * Fixtures are the same real PEM certificates test_x509_cert.c uses,
 * produced by test/gen-x509-fixtures.sh: rw.cert.pem carries DNS + email
 * (+ IPv4/IPv6) subjectAltName entries, revoked.cert.pem carries a DNS-only
 * entry, and server-no-san.cert.pem has no subjectAltName extension at
 * all -- between them they exercise every branch of
 * xauth_peer_device_id()'s SAN-matching loop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "var.h"
#include "vmbuf.h"
#include "gcmalloc.h"
#include "crypto_openssl.h"
#include "handler.h"
#include "remoteconf.h"
#include "isakmp_xauth.h"

/* Test-only accessors for the static functions under test (isakmp_xauth.c,
 * -DENABLE_UNITTEST). */
extern char *xauth_ldap_escape_filter_unittest(const char *str);
extern char *xauth_peer_device_id_unittest(struct ph1handle *iph1);

#define TEST_PASS()    printf("\342\234\223 PASS\n")
#define TEST_FAIL(msg) do { printf("\342\234\227 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* Absolute path to the scratch dir holding generated fixtures. */
static char g_fixdir[4096];

static char *
fx(char *buf, size_t buflen, const char *name)
{
	int n = snprintf(buf, buflen, "%s/%s", g_fixdir, name);
	if (n < 0 || (size_t)n >= buflen) {
		fprintf(stderr, "fx: path too long: %s/%s\n", g_fixdir, name);
		abort();
	}
	return buf;
}

/* Same fixture set as test_x509_cert.c, generated via the same script --
 * see that file's setup_fixtures() for the rationale of each piece. */
static int
setup_fixtures(void)
{
	const char *srcdir = getenv("X509_FIXTURE_SRCDIR");
	char tmpl[] = "xauthfix.XXXXXX";
	char cmd[8192];
	char *dir;
	int rc;

	if (srcdir == NULL || srcdir[0] == '\0')
		srcdir = ".";

	dir = mkdtemp(tmpl);
	if (dir == NULL) {
		fprintf(stderr, "mkdtemp failed\n");
		return -1;
	}
	if (realpath(dir, g_fixdir) == NULL)
		snprintf(g_fixdir, sizeof(g_fixdir), "%s", dir);

	snprintf(cmd, sizeof(cmd),
		 "bash '%s/gen-x509-fixtures.sh' '%s'",
		 srcdir, g_fixdir);
	rc = system(cmd);
	if (rc != 0) {
		char logpath[4096];
		FILE *lf;

		fprintf(stderr, "fixture generation failed (rc=%d): %s\n", rc, cmd);
		fx(logpath, sizeof(logpath), "gen.log");
		lf = fopen(logpath, "r");
		if (lf != NULL) {
			char line[1024];
			while (fgets(line, sizeof(line), lf) != NULL)
				fputs(line, stderr);
			fclose(lf);
		}
		return -1;
	}
	return 0;
}

static void
teardown_fixtures(void)
{
	char cmd[8192];

	if (g_fixdir[0] == '\0')
		return;
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_fixdir);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: failed to clean up %s\n", g_fixdir);
}

/* ========================================================================
 * xauth_ldap_escape_filter (RFC 4515)
 * ==================================================================== */

static int
check_escape(const char *in, const char *want)
{
	char *got = xauth_ldap_escape_filter_unittest(in);
	int ok;

	if (got == NULL) {
		printf("(NULL for input \"%s\") ", in);
		return -1;
	}
	ok = strcmp(got, want) == 0;
	if (!ok)
		printf("(input \"%s\" -> \"%s\", want \"%s\") ", in, got, want);
	racoon_free(got);
	return ok ? 0 : -1;
}

static int
test_escape_filter(void)
{
	TEST_START("xauth_ldap_escape_filter (RFC 4515 metacharacters)");

	if (check_escape("", "") != 0)
		TEST_FAIL("empty string should round-trip to empty string");

	if (check_escape("plainuser", "plainuser") != 0)
		TEST_FAIL("string without metacharacters should be unchanged");

	if (check_escape("*", "\\2a") != 0)
		TEST_FAIL("'*' should escape to \\2a");
	if (check_escape("(", "\\28") != 0)
		TEST_FAIL("'(' should escape to \\28");
	if (check_escape(")", "\\29") != 0)
		TEST_FAIL("')' should escape to \\29");
	if (check_escape("\\", "\\5c") != 0)
		TEST_FAIL("'\\\\' should escape to \\5c");

	/* Combined: every metacharacter in one string, interspersed with
	 * ordinary characters. */
	if (check_escape("a*(b)\\c", "a\\2a\\28b\\29\\5cc") != 0)
		TEST_FAIL("combined metacharacter string escaped incorrectly");

	/* The scenario called out in the function's own comment: a legacy
	 * "dn" device identity with a literal parenthesized RDN. */
	if (check_escape("OU=(c) 2025 Nepomuc,DC=example",
	    "OU=\\28c\\29 2025 Nepomuc,DC=example") != 0)
		TEST_FAIL("DN with literal parentheses escaped incorrectly");

	TEST_PASS();
	return 0;
}

/* ========================================================================
 * xauth_peer_device_id (verified-certificate subjectAltName)
 * ==================================================================== */

static struct ph1handle *
make_ph1handle(vchar_t *cert_p, int verify_cert, int has_rmconf)
{
	struct ph1handle *iph1;

	iph1 = racoon_calloc(1, sizeof(*iph1));
	iph1->cert_p = cert_p;

	if (has_rmconf) {
		struct remoteconf *rmconf = racoon_calloc(1, sizeof(*rmconf));
		rmconf->verify_cert = verify_cert;
		iph1->rmconf = rmconf;
	} else {
		iph1->rmconf = NULL;
	}

	return iph1;
}

static void
free_ph1handle(struct ph1handle *iph1)
{
	if (iph1->rmconf != NULL)
		racoon_free(iph1->rmconf);
	racoon_free(iph1);
}

static int
test_peer_device_id_guards(void)
{
	struct ph1handle *iph1;
	vchar_t *rw = NULL;
	char p[4096];
	char *got;
	int ret = -1;

	TEST_START("xauth_peer_device_id: rmconf/verify_cert/cert_p guards");

	rw = eay_get_x509cert(fx(p, sizeof(p), "rw.cert.pem"));
	if (rw == NULL) TEST_FAIL("failed to load rw.cert.pem");

	/* No rmconf at all (anonymous Phase 1) -- must not dereference it. */
	iph1 = make_ph1handle(rw, TRUE, /*has_rmconf=*/0);
	xauth_ldap_config.device_id_type = XAUTH_DEVICE_ID_DNSNAME;
	got = xauth_peer_device_id_unittest(iph1);
	if (got != NULL) {
		racoon_free(got);
		free_ph1handle(iph1);
		TEST_FAIL("iph1->rmconf == NULL should yield no device identity");
	}
	free_ph1handle(iph1);

	/* verify_cert off: an unverified certificate must never be trusted
	 * for device scoping, even though cert_p itself is a well-formed,
	 * SAN-bearing certificate. */
	iph1 = make_ph1handle(rw, FALSE, /*has_rmconf=*/1);
	got = xauth_peer_device_id_unittest(iph1);
	if (got != NULL) {
		racoon_free(got);
		free_ph1handle(iph1);
		TEST_FAIL("verify_cert off should yield no device identity");
	}
	free_ph1handle(iph1);

	/* verify_cert on, but no certificate loaded at all. */
	iph1 = make_ph1handle(NULL, TRUE, /*has_rmconf=*/1);
	got = xauth_peer_device_id_unittest(iph1);
	if (got != NULL) {
		racoon_free(got);
		free_ph1handle(iph1);
		TEST_FAIL("cert_p == NULL should yield no device identity");
	}
	free_ph1handle(iph1);

	ret = 0;
	if (rw) vfree(rw);
	if (ret == 0) TEST_PASS();
	return ret;
}

static int
test_peer_device_id_matching(void)
{
	struct ph1handle *iph1;
	vchar_t *rw = NULL, *revoked = NULL, *nosan = NULL;
	char p[4096];
	char *got;
	int ret = -1;

	TEST_START("xauth_peer_device_id: DNS/email match, mismatch, no-SAN");

	rw      = eay_get_x509cert(fx(p, sizeof(p), "rw.cert.pem"));
	revoked = eay_get_x509cert(fx(p, sizeof(p), "revoked.cert.pem"));
	nosan   = eay_get_x509cert(fx(p, sizeof(p), "server-no-san.cert.pem"));
	if (!rw || !revoked || !nosan) TEST_FAIL("failed to load fixture certs");

	/* device_id_type dnsname against a cert with a DNS SAN -> match. */
	iph1 = make_ph1handle(rw, TRUE, 1);
	xauth_ldap_config.device_id_type = XAUTH_DEVICE_ID_DNSNAME;
	got = xauth_peer_device_id_unittest(iph1);
	free_ph1handle(iph1);
	if (got == NULL || strcmp(got, "rw.example.test") != 0) {
		if (got) racoon_free(got);
		TEST_FAIL("dnsname device_id_type should return the DNS SAN");
	}
	racoon_free(got);

	/* device_id_type rfc822 against the same cert (DNS entry first,
	 * email entry second) -> the loop must skip the DNS entry and match
	 * the email one, not just take the first SAN present. */
	iph1 = make_ph1handle(rw, TRUE, 1);
	xauth_ldap_config.device_id_type = XAUTH_DEVICE_ID_RFC822;
	got = xauth_peer_device_id_unittest(iph1);
	free_ph1handle(iph1);
	if (got == NULL || strcmp(got, "rw@example.test") != 0) {
		if (got) racoon_free(got);
		TEST_FAIL("rfc822 device_id_type should return the email SAN");
	}
	racoon_free(got);

	/* device_id_type dnsname against a DNS-only cert -> match, and a
	 * sanity check that the loop's starting position (pos=1) is right. */
	iph1 = make_ph1handle(revoked, TRUE, 1);
	xauth_ldap_config.device_id_type = XAUTH_DEVICE_ID_DNSNAME;
	got = xauth_peer_device_id_unittest(iph1);
	free_ph1handle(iph1);
	if (got == NULL || strcmp(got, "revoked.example.test") != 0) {
		if (got) racoon_free(got);
		TEST_FAIL("dnsname device_id_type should return the sole DNS SAN");
	}
	racoon_free(got);

	/* device_id_type rfc822 against the DNS-only cert -> the loop must
	 * skip the (mismatched) DNS entry, run out of SAN entries, and
	 * return NULL rather than the DNS value. */
	iph1 = make_ph1handle(revoked, TRUE, 1);
	xauth_ldap_config.device_id_type = XAUTH_DEVICE_ID_RFC822;
	got = xauth_peer_device_id_unittest(iph1);
	free_ph1handle(iph1);
	if (got != NULL) {
		racoon_free(got);
		TEST_FAIL("rfc822 device_id_type on a DNS-only cert should return NULL");
	}

	/* device_id_type dnsname against a cert with no subjectAltName
	 * extension at all -> NULL, not a crash. */
	iph1 = make_ph1handle(nosan, TRUE, 1);
	xauth_ldap_config.device_id_type = XAUTH_DEVICE_ID_DNSNAME;
	got = xauth_peer_device_id_unittest(iph1);
	free_ph1handle(iph1);
	if (got != NULL) {
		racoon_free(got);
		TEST_FAIL("cert with no subjectAltName extension should return NULL");
	}

	ret = 0;
	if (rw) vfree(rw);
	if (revoked) vfree(revoked);
	if (nosan) vfree(nosan);
	if (ret == 0) TEST_PASS();
	return ret;
}

int
main(void)
{
	int total = 0, failed = 0;

	if (setup_fixtures() != 0) {
		fprintf(stderr, "fixture setup failed, aborting\n");
		return 1;
	}

	total++; if (test_escape_filter() != 0) failed++;
	total++; if (test_peer_device_id_guards() != 0) failed++;
	total++; if (test_peer_device_id_matching() != 0) failed++;

	teardown_fixtures();

	printf("\n%d/%d tests passed\n", total - failed, total);
	return failed == 0 ? 0 : 1;
}
