// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit tests for the X.509 certificate functions in
 * src/racoon/crypto_openssl.c (issue #52).
 *
 * Coverage:
 *   eay_get_x509cert, eay_check_x509cert, eay_check_x509sign,
 *   eay_get_x509asn1subjectname, eay_get_x509asn1issuername,
 *   eay_get_x509subjectaltname, eay_get_x509text,
 *   eay_get_pkcs1privkey, eay_get_pkcs1pubkey, eay_get_x509sign.
 *
 * Fixtures are real PEM certs/keys/CRLs produced by the cert-framework
 * (issue #50). This binary shells out to test/gen-x509-fixtures.sh once at
 * start-up (via system()) to populate a throwaway scratch directory, then
 * fopen()s the resulting files through the eay_* API under test. See the
 * comment on setup_fixtures() for how the generator script is located.
 *
 * IMPORTANT build note: this test links a NON-EAYDEBUG build of
 * crypto_openssl.c (via crypto_openssl_x509_src.c), unlike the rest of the
 * suite which links crypto_openssl_test.o (-DEAYDEBUG). Under EAYDEBUG,
 * mem2x509() reads PEM while eay_get_x509cert() writes DER, so the
 * load/parse round-trip these tests rely on only holds in the production
 * build. See crypto_openssl_x509_src.c and test/Makefile.am.
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

#include "vmbuf.h"
#include "crypto_openssl.h"
#include "gcmalloc.h"

/*
 * Leading tag byte eay_get_x509cert() stores at cert->v[0]; the DER of the
 * certificate follows from cert->v[1]. Value mirrors ISAKMP_CERT_X509SIGN in
 * src/racoon/isakmp.h (kept local to avoid pulling that header's deps here).
 */
#define X509_TAG_X509SIGN 4

#define TEST_PASS()    printf("\342\234\223 PASS\n")
#define TEST_FAIL(msg) do { printf("\342\234\227 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* Absolute path to the scratch dir holding generated fixtures. */
static char g_fixdir[4096];

/* Build "<fixdir>/<name>" into the caller-supplied buffer. Returns a
 * non-const char* because the eay_* loaders take char* paths. Checking the
 * snprintf return value both guards against (implausible) truncation and
 * keeps -Wformat-truncation quiet. */
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

static int
path_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

/*
 * Generate the PEM fixtures. The generator script lives next to this test's
 * source; automake exports its location to us via X509_FIXTURE_SRCDIR (set in
 * test/Makefile.am's AM_TESTS_ENVIRONMENT). When the binary is run by hand
 * from the build/test dir the variable is unset, so we fall back to ".".
 */
static int
setup_fixtures(void)
{
	const char *srcdir = getenv("X509_FIXTURE_SRCDIR");
	char tmpl[] = "x509fix.XXXXXX";
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
	if (realpath(dir, g_fixdir) == NULL) {
		/* Fall back to the relative name; still usable within cwd. */
		snprintf(g_fixdir, sizeof(g_fixdir), "%s", dir);
	}

	/* The generator redirects its own (noisy) output to <fixdir>/gen.log,
	 * which we surface only on failure below.  srcdir is passed straight
	 * through as an unbounded string (not an array) so this single
	 * interpolation of the fixture-dir array does not trip
	 * -Wformat-truncation -- and, unlike a cd-based form, a relative srcdir
	 * such as "." keeps working because the cwd is never changed. */
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
 * eay_get_x509cert
 * ==================================================================== */

int test_get_x509cert(void)
{
	char p[4096];
	vchar_t *cert = NULL;
	vchar_t *bad = NULL;
	int ret = -1;

	TEST_START("eay_get_x509cert (load PEM + leading tag byte)");

	cert = eay_get_x509cert(fx(p, sizeof(p), "rw.cert.pem"));
	if (!cert) TEST_FAIL("failed to load rw.cert.pem");
	if (cert->l < 2) TEST_FAIL("certificate buffer implausibly small");
	if ((u_char)cert->v[0] != X509_TAG_X509SIGN)
		TEST_FAIL("cert->v[0] is not the ISAKMP_CERT_X509SIGN tag byte");

	/* Non-existent path must yield NULL, not a crash. */
	bad = eay_get_x509cert(fx(p, sizeof(p), "does-not-exist.pem"));
	if (bad) TEST_FAIL("loading a missing file should return NULL");

	printf("loaded %zu bytes (tag=0x%02x) ", cert->l, (u_char)cert->v[0]);
	ret = 0;

	if (cert) vfree(cert);
	if (bad) vfree(bad);
	if (ret == 0) TEST_PASS();
	return ret;
}

/* ========================================================================
 * eay_get_x509text
 * ==================================================================== */

int test_get_x509text(void)
{
	char p[4096];
	vchar_t *cert = NULL;
	char *text = NULL;
	int ret = -1;

	TEST_START("eay_get_x509text (human-readable dump)");

	cert = eay_get_x509cert(fx(p, sizeof(p), "rw.cert.pem"));
	if (!cert) TEST_FAIL("failed to load rw.cert.pem");

	text = eay_get_x509text(cert);
	if (!text) TEST_FAIL("eay_get_x509text returned NULL");
	if (strstr(text, "Certificate") == NULL &&
	    strstr(text, "Issuer") == NULL)
		TEST_FAIL("dump does not look like X509_print output");

	printf("got %zu bytes of text ", strlen(text));
	ret = 0;

	if (text) racoon_free(text);
	if (cert) vfree(cert);
	if (ret == 0) TEST_PASS();
	return ret;
}

/* ========================================================================
 * eay_get_x509asn1subjectname / eay_get_x509asn1issuername
 *
 * Compared structurally with eay_cmp_asn1dn() (per issue #52), avoiding
 * brittle raw-byte / string-encoding assumptions:
 *   - intermediate.subject == rw.issuer   (rw was issued by the intermediate)
 *   - root.subject         == root.issuer (root is self-signed)
 *   - rw.subject           != rw.issuer
 * ==================================================================== */

int test_subject_issuer_names(void)
{
	char p[4096];
	vchar_t *rw = NULL, *inter = NULL, *root = NULL;
	vchar_t *rw_sub = NULL, *rw_iss = NULL;
	vchar_t *inter_sub = NULL, *root_sub = NULL, *root_iss = NULL;
	int ret = -1;

	TEST_START("eay_get_x509asn1subjectname / issuername");

	rw    = eay_get_x509cert(fx(p, sizeof(p), "rw.cert.pem"));
	inter = eay_get_x509cert(fx(p, sizeof(p), "intermediate.cert.pem"));
	root  = eay_get_x509cert(fx(p, sizeof(p), "root.cert.pem"));
	if (!rw || !inter || !root) TEST_FAIL("failed to load one of the certs");

	rw_sub    = eay_get_x509asn1subjectname(rw);
	rw_iss    = eay_get_x509asn1issuername(rw);
	inter_sub = eay_get_x509asn1subjectname(inter);
	root_sub  = eay_get_x509asn1subjectname(root);
	root_iss  = eay_get_x509asn1issuername(root);
	if (!rw_sub || !rw_iss || !inter_sub || !root_sub || !root_iss)
		TEST_FAIL("failed to extract a subject/issuer name");

	/* rw was signed by the intermediate: rw.issuer == intermediate.subject */
	if (eay_cmp_asn1dn(rw_iss, inter_sub) != 0)
		TEST_FAIL("rw issuer != intermediate subject");

	/* root is self-signed: subject == issuer */
	if (eay_cmp_asn1dn(root_sub, root_iss) != 0)
		TEST_FAIL("root subject != root issuer (should be self-signed)");

	/* rw is not self-signed: subject != issuer */
	if (eay_cmp_asn1dn(rw_sub, rw_iss) == 0)
		TEST_FAIL("rw subject == rw issuer (should differ)");

	printf("subject/issuer relationships hold ");
	ret = 0;

	if (rw_sub) vfree(rw_sub);
	if (rw_iss) vfree(rw_iss);
	if (inter_sub) vfree(inter_sub);
	if (root_sub) vfree(root_sub);
	if (root_iss) vfree(root_iss);
	if (rw) vfree(rw);
	if (inter) vfree(inter);
	if (root) vfree(root);
	if (ret == 0) TEST_PASS();
	return ret;
}

/* ========================================================================
 * eay_get_x509subjectaltname
 *
 * rw.cert.pem carries, in order (1-based pos):
 *   1: DNS:rw.example.test
 *   2: email:rw@example.test
 *   3: IP:192.0.2.10          (IPv4)
 *   4: IP:2001:db8::1         (IPv6)
 * ==================================================================== */

static int
check_san(vchar_t *cert, int pos, int want_type, const char *want_name)
{
	char *altname = NULL;
	int type = -1;
	int rc;

	rc = eay_get_x509subjectaltname(cert, &altname, &type, pos);
	if (rc != 0 || altname == NULL) {
		printf("[pos %d rc=%d] ", pos, rc);
		return -1;
	}
	if (type != want_type || strcmp(altname, want_name) != 0) {
		printf("[pos %d got type=%d name='%s' want type=%d name='%s'] ",
		       pos, type, altname, want_type, want_name);
		racoon_free(altname);
		return -1;
	}
	racoon_free(altname);
	return 0;
}

int test_subjectaltname(void)
{
	char p[4096];
	vchar_t *rw = NULL, *srv = NULL;
	char *altname = NULL;
	int type = -1;
	int ret = -1;

	TEST_START("eay_get_x509subjectaltname (DNS/email/IPv4/IPv6, ranges)");

	rw  = eay_get_x509cert(fx(p, sizeof(p), "rw.cert.pem"));
	srv = eay_get_x509cert(fx(p, sizeof(p), "server-no-san.cert.pem"));
	if (!rw || !srv) TEST_FAIL("failed to load cert(s)");

	if (check_san(rw, 1, GENT_DNS, "rw.example.test") != 0)
		TEST_FAIL("SAN pos 1 (DNS) mismatch");
	if (check_san(rw, 2, GENT_EMAIL, "rw@example.test") != 0)
		TEST_FAIL("SAN pos 2 (email) mismatch");
	if (check_san(rw, 3, GENT_IPADD, "192.0.2.10") != 0)
		TEST_FAIL("SAN pos 3 (IPv4) mismatch");
	if (check_san(rw, 4, GENT_IPADD,
		      "2001:0db8:0000:0000:0000:0000:0000:0001") != 0)
		TEST_FAIL("SAN pos 4 (IPv6) mismatch");

	/* Out-of-range pos must fail cleanly and leave *altname NULL. */
	altname = (char *)0x1;
	if (eay_get_x509subjectaltname(rw, &altname, &type, 99) == 0)
		TEST_FAIL("out-of-range SAN pos should fail");
	if (altname != NULL)
		TEST_FAIL("out-of-range SAN pos should leave altname NULL");

	/* A cert with no SAN extension at all must fail. */
	altname = (char *)0x1;
	if (eay_get_x509subjectaltname(srv, &altname, &type, 1) == 0)
		TEST_FAIL("cert without SAN should fail");
	if (altname != NULL)
		TEST_FAIL("no-SAN cert should leave altname NULL");

	printf("all SAN branches OK ");
	ret = 0;

	if (rw) vfree(rw);
	if (srv) vfree(srv);
	if (ret == 0) TEST_PASS();
	return ret;
}

/* ========================================================================
 * eay_check_x509cert (chain + CRL verification)
 * ==================================================================== */

int test_check_x509cert_valid(void)
{
	char cp[4096], bp[4096];
	vchar_t *rw = NULL;
	int ret = -1;

	TEST_START("eay_check_x509cert (valid cert against CA + CRLs)");

	rw = eay_get_x509cert(fx(cp, sizeof(cp), "rw.cert.pem"));
	if (!rw) TEST_FAIL("failed to load rw.cert.pem");
	fx(bp, sizeof(bp), "ca-bundle.pem");

	/* remote path (local=0) */
	if (eay_check_x509cert(rw, g_fixdir, bp, 0) != 0)
		TEST_FAIL("valid cert failed verification (local=0)");
	/* local path (local=1) */
	if (eay_check_x509cert(rw, g_fixdir, bp, 1) != 0)
		TEST_FAIL("valid cert failed verification (local=1)");

	printf("chain + CRL verification OK ");
	ret = 0;

	if (rw) vfree(rw);
	if (ret == 0) TEST_PASS();
	return ret;
}

int test_check_x509cert_wrong_ca(void)
{
	char cp[4096], bp[4096];
	vchar_t *rw = NULL;
	int ret = -1;

	TEST_START("eay_check_x509cert (wrong CA -> reject)");

	rw = eay_get_x509cert(fx(cp, sizeof(cp), "rw.cert.pem"));
	if (!rw) TEST_FAIL("failed to load rw.cert.pem");
	fx(bp, sizeof(bp), "wrong-ca.cert.pem");

	if (eay_check_x509cert(rw, g_fixdir, bp, 0) == 0)
		TEST_FAIL("cert verified against an unrelated CA");

	printf("unrelated CA correctly rejected ");
	ret = 0;

	if (rw) vfree(rw);
	if (ret == 0) TEST_PASS();
	return ret;
}

int test_check_x509cert_revoked(void)
{
	char cp[4096], bp[4096];
	vchar_t *rev = NULL;
	int ret = -1;

	TEST_START("eay_check_x509cert (revoked cert -> reject)");

	rev = eay_get_x509cert(fx(cp, sizeof(cp), "revoked.cert.pem"));
	if (!rev) TEST_FAIL("failed to load revoked.cert.pem");
	fx(bp, sizeof(bp), "ca-bundle.pem");

	if (eay_check_x509cert(rev, g_fixdir, bp, 0) == 0)
		TEST_FAIL("revoked cert passed verification");

	printf("revoked cert correctly rejected ");
	ret = 0;

	if (rev) vfree(rev);
	if (ret == 0) TEST_PASS();
	return ret;
}

/* ========================================================================
 * eay_get_pkcs1privkey / eay_get_pkcs1pubkey
 *
 * NOTE: only unencrypted end-entity keys are exercised at runtime. Both
 * functions pass a NULL passphrase callback to PEM_read_*, so an
 * AES-256-encrypted key (as cert-framework issues for the Root/Intermediate
 * CAs) cannot be loaded and, worse, could block on an interactive
 * passphrase prompt in a TTY environment. Encrypted-key handling is out of
 * scope for issue #52 (flagged as follow-up).
 * ==================================================================== */

int test_pkcs1_keys(void)
{
	char p[4096];
	vchar_t *priv = NULL, *pub = NULL, *bad = NULL;
	int ret = -1;

	TEST_START("eay_get_pkcs1privkey / eay_get_pkcs1pubkey");

	priv = eay_get_pkcs1privkey(fx(p, sizeof(p), "rw.key.pem"));
	if (!priv) TEST_FAIL("failed to load unencrypted rw.key.pem");
	if (priv->l == 0) TEST_FAIL("private key DER is empty");

	/* eay_get_pkcs1pubkey actually reads an X509 cert file. */
	pub = eay_get_pkcs1pubkey(fx(p, sizeof(p), "rw.cert.pem"));
	if (!pub) TEST_FAIL("failed to extract public key from rw.cert.pem");
	if (pub->l == 0) TEST_FAIL("public key DER is empty");

	/* Missing file -> NULL. */
	bad = eay_get_pkcs1privkey(fx(p, sizeof(p), "nope.pem"));
	if (bad) TEST_FAIL("loading a missing private key should return NULL");

	printf("priv=%zu pub=%zu bytes ", priv->l, pub->l);
	ret = 0;

	if (priv) vfree(priv);
	if (pub) vfree(pub);
	if (bad) vfree(bad);
	if (ret == 0) TEST_PASS();
	return ret;
}

/* ========================================================================
 * eay_get_x509sign + eay_check_x509sign (RSA round-trip and failure paths)
 * ==================================================================== */

int test_sign_roundtrip(void)
{
	char p[4096];
	vchar_t *priv = NULL, *cert = NULL, *src = NULL, *sig = NULL;
	int ret = -1;

	TEST_START("eay_get_x509sign + eay_check_x509sign (RSA round-trip)");

	priv = eay_get_pkcs1privkey(fx(p, sizeof(p), "rw.key.pem"));
	cert = eay_get_x509cert(fx(p, sizeof(p), "rw.cert.pem"));
	if (!priv || !cert) TEST_FAIL("failed to load key/cert");

	/* Small payload: raw RSA + PKCS#1 v1.5 padding (not digest-based). */
	src = vmalloc(20);
	if (!src) TEST_FAIL("vmalloc(src) failed");
	memcpy(src->v, "racoon-x509-sign-tst", 20);

	sig = eay_get_x509sign(src, priv);
	if (!sig) TEST_FAIL("eay_get_x509sign returned NULL");

	if (eay_check_x509sign(src, sig, cert) != 0)
		TEST_FAIL("valid signature failed verification");

	/* Tamper with the signed data -> verification must fail. */
	src->v[0] ^= 0xff;
	if (eay_check_x509sign(src, sig, cert) == 0)
		TEST_FAIL("verification passed for tampered data");
	src->v[0] ^= 0xff; /* restore */

	/* Tamper with the signature -> verification must fail. */
	sig->v[0] ^= 0xff;
	if (eay_check_x509sign(src, sig, cert) == 0)
		TEST_FAIL("verification passed for tampered signature");
	sig->v[0] ^= 0xff; /* restore */

	printf("sign/verify round-trip + tamper detection OK ");
	ret = 0;

	if (priv) vfree(priv);
	if (cert) vfree(cert);
	if (src) vfree(src);
	if (sig) vfree(sig);
	if (ret == 0) TEST_PASS();
	return ret;
}

int test_check_x509sign_non_rsa(void)
{
	char p[4096];
	vchar_t *ec = NULL, *src = NULL, *sig = NULL;
	int ret = -1;

	if (!path_exists(fx(p, sizeof(p), "ec.cert.pem"))) {
		printf("\n[TEST] eay_check_x509sign (non-RSA rejection) ... "
		       "SKIP (no EC support)\n");
		return 0;
	}

	TEST_START("eay_check_x509sign (non-RSA key -> reject)");

	ec = eay_get_x509cert(fx(p, sizeof(p), "ec.cert.pem"));
	if (!ec) TEST_FAIL("failed to load ec.cert.pem");

	/* Contents of src/sig are irrelevant: rejection happens at the
	 * key-type check before any verification math. */
	src = vmalloc(20);
	sig = vmalloc(20);
	if (!src || !sig) TEST_FAIL("vmalloc failed");
	memset(src->v, 0x5a, 20);
	memset(sig->v, 0xa5, 20);

	if (eay_check_x509sign(src, sig, ec) != -1)
		TEST_FAIL("non-RSA cert was not rejected");

	printf("non-RSA key correctly rejected ");
	ret = 0;

	if (ec) vfree(ec);
	if (src) vfree(src);
	if (sig) vfree(sig);
	if (ret == 0) TEST_PASS();
	return ret;
}

/* ==================================================================== */

int main(void)
{
	int failed = 0;
	int total = 0;

	printf("\n");
	printf("========================================================================\n");
	printf("  Racoon IPSec - X.509 Certificate Function Tests (issue #52)\n");
	printf("========================================================================\n");

	eay_init();

	if (setup_fixtures() != 0) {
		fprintf(stderr, "FATAL: could not generate X.509 fixtures\n");
		return 1;
	}

	total++; if (test_get_x509cert() != 0) failed++;
	total++; if (test_get_x509text() != 0) failed++;
	total++; if (test_subject_issuer_names() != 0) failed++;
	total++; if (test_subjectaltname() != 0) failed++;
	total++; if (test_check_x509cert_valid() != 0) failed++;
	total++; if (test_check_x509cert_wrong_ca() != 0) failed++;
	total++; if (test_check_x509cert_revoked() != 0) failed++;
	total++; if (test_pkcs1_keys() != 0) failed++;
	total++; if (test_sign_roundtrip() != 0) failed++;
	total++; if (test_check_x509sign_non_rsa() != 0) failed++;

	teardown_fixtures();

	printf("\n");
	printf("========================================================================\n");
	if (failed == 0) {
		printf("  \342\234\223 ALL X.509 TESTS PASSED (%d tests)\n", total);
		printf("========================================================================\n");
		return 0;
	} else {
		printf("  \342\234\227 %d/%d TEST(S) FAILED\n", failed, total);
		printf("========================================================================\n");
		return 1;
	}
}
