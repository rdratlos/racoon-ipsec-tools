// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Unit tests for eay_rsa.c / eay_rsa.h -- the eayRSA opaque RSA object.
 *
 * Harness, assertion macros and runner structure reused verbatim from
 * test_rsa_comprehensive.c.
 *
 * Every test below is tagged:
 *   CONTRACT  -- permanent: behavioral contract + OpenSSL-change tripwire
 *   SCAFFOLD  -- migration-time belt-and-suspenders; prunable once stable
 */

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "vmbuf.h"
#include "eay_rsa.h"

extern int eay_init(void);

#define TEST_PASS() printf("\xe2\x9c\x93 PASS\n")
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

static void
dump_openssl_errors(const char *context)
{
	unsigned long e;
	while ((e = ERR_get_error()) != 0) {
		char buf[256];
		ERR_error_string_n(e, buf, sizeof(buf));
		fprintf(stderr, "  [%s] %s\n", context, buf);
	}
}

/*
 * Fixed 2048-bit RSA test key, generated once via `openssl genrsa 2048`.
 * Reused across every CONTRACT test that needs a known fixed key,
 * including T6 (which requires a 2048-bit modulus -> 256-byte size).
 */
#define K2048_N "00c71e0ce2ee1a370658106545de3b5732f0929c86544b348a24ca48ed1fea7c609bbdf8a9ef60d56a64d25ec8fe7f46592ec883022946e3af0c0b5ad1ea6c11a04569350f360eb46966a26886da7df25e6551e730c99e131d4dc35f7aef2b36f9bcdc8f8833492f34c0fde84d30867ddf11159391d5ad3d9ed6e3df3c2e520750d2d585df361adada08cd3b5743db7139c427786883be44a785a62f11d1d842ae304466e9c825d232fdc9f350da1764db8c9de21444c28f60b192946a7bf9f43c79d21e5772e0f5a1d2d944f1e4e4ac67e24b6e7fefc8401ea9f2c9b85502241bee0f7649e36cb61698786e99cd91feb88f63c8b756d65eeedfff545fdc538a3d"
#define K2048_E "10001"
#define K2048_D "4cbf5fef2e204b9a35e267ee94b861a56045da700a588c713cb9fd7eec80d89cf21ab898638c7ae60de36a2665b5cffb3b058d3d8d8465e90826ee441febb4a5866b85488e28ffcfea7fe9f3248f4c16a74df8e2fcab61a9b759f958ec8bc71e5e75d31b07cd8b14f5d8482c4c6a6264d2f4729350fd7bd557f5b00b45bd5754d8fa8964017ad91b8950e67073ee981589f926f0eab4b076e0e8d1e27e4cd38ebf84287384b5b10859bb3362be6a9662451d5d36131c6995650e24e86dc2837ceb23b95a69ff58c314d44c140ccf52f00b4b037bac30e5b2f0f0853e014fb9114fb22f28f66511fe7aaad516b4fd116a3e5b65c44eed6c5bfdd180f74a5f8ebf"
#define K2048_P "00efbff1f7f0ea64a252a663a5433356714c877c1bd4eb0f98c817f2d97a34d2401ea5333f2e8831fe642af7bf7ca3c8c32ded839fc48c0a5386ea0dee0e77672e82304a60590bb938cd6199e0f6139ccea991830e1b109ccdd56f870301056a9f5f1cb76c698a6494f2803c4484909c9e28085b5ba2521882415662489dd68feb"
#define K2048_Q "00d49d10dc308abcf643ac9801d66d17836d154eaa8a89a90276c27ecf5f98840775110e9bb21fa71b481c0a3ce97af58edc7daefbcfe3c6843bfa43c3f6fd1e756337ace01e1b661be4806132b3ab22b020c87c2ff49ff1e1163ac9a32fdc5f2886be95d4582e8906f98f593d1bd94ae1cf7c95ef2c840a0249b02892023eec77"
#define K2048_DMP1 "00c8470540454dd8f14cafd88fe6ba4d1cea7c47ae0c48acc7c967502462951b8a1acf9026d89d477e26794a6af918ed0e3720b192d6a2d1c182f3a4dd57d2612c95eef742d3401ae39b964bf084404ffec7e259a37ff279baecf074cd8a9dd6baf9be486fd51e99f55f3ac69dca4befb9a2e19047d52a55750255c256bd1bcf2f"
#define K2048_DMQ1 "31890a959285b072dbdf8966dc337c87f551428bbf4d45603a95240062b0610a6fbef29d59c9c0203e13b25af0b6e2214fc3c4920ca46feafd2258c97e7108b8a6ce20ebf277c5b977ea653aefdb4e70a4a2b134671520c0a5723aea574b4bac608064de1d5172417ac168343199d5b578a6f933c9365632a44273a158fe9a0f"
#define K2048_IQMP "008eb1d4237f522b860697d638eaab4f4ed06e04cb29a6512325a3a8799c507c4e4feedec453508e255299509c999334fe5b88dd3ebccb23cc6d1a684332ab5ac3928c181795d4d1da883b68a03b28a49ac1ee8197736e6bb7d38a48316d58c82a13d3101f5799f779a7d869901b1bb61e9bcf21d187657681d778bdb549c79351"

/*
 * T1 known-answer message and PINNED signature. RSASSA-PKCS1-v1_5 raw
 * signing (no digest step -- see eay_pkey_sign() in crypto_openssl.c) is
 * deterministic for a fixed key+message, so this hex value MUST reproduce
 * exactly on every OpenSSL build. Generated once via eayRSA_sign() itself
 * against K2048_* above and the message below.
 *
 * If this test ever fails, that means OpenSSL's RSA signing primitive
 * changed behavior -- INVESTIGATE the cause, do NOT blindly re-pin the
 * new value without understanding why it changed.
 */
#define T1_MESSAGE "racoon-ipsec-tools eayRSA T1 known-answer test message"
#define T1_PINNED_SIG \
	"576583301176554f68be394a9ba69bf1be8f60656c6400a1a6812dabce23457" \
	"f955277ff2d87f284b5561a341d6e33928e76900a337f7677e44ea1daccb1b1" \
	"feb26aec88db278e3157c4ad41f49864c8e6b80ee7d8721ec3f7fedb1249f22" \
	"1f77a40c5652681fbd4c76ad7c174eadfc2aaa1cc92244faa9b3916aac171a9" \
	"07d2946fa91ee042e844f248cf86428f8ee6873d634b82d982bd07a07688ff1" \
	"4eff194dbf446e0eafa2c0fbfc512bc71f92e07ecfed9c4c87b1ae12c326afb" \
	"9d2d333798bfe853d52091591cedccd23ae0c96aad8aaa7baa4cff96e7479cd" \
	"74082098c0bb8782dfaedbc99438169db9b6f21698582e8bbf103c1ab95e529" \
	"4da85c41"

static BIGNUM *
h2bn(const char *s)
{
	BIGNUM *b = NULL;
	BN_hex2bn(&b, s);
	return b;
}

static eayRSA *
make_fixed_priv(void)
{
	BIGNUM *n = h2bn(K2048_N), *e = h2bn(K2048_E), *d = h2bn(K2048_D);
	BIGNUM *p = h2bn(K2048_P), *q = h2bn(K2048_Q);
	BIGNUM *dmp1 = h2bn(K2048_DMP1), *dmq1 = h2bn(K2048_DMQ1), *iqmp = h2bn(K2048_IQMP);
	eayRSA *r = eayRSA_new_priv(n, e, d, p, q, dmp1, dmq1, iqmp);
	BN_free(n); BN_free(e); BN_clear_free(d);
	BN_clear_free(p); BN_clear_free(q);
	BN_clear_free(dmp1); BN_clear_free(dmq1); BN_clear_free(iqmp);
	return r;
}

static vchar_t *
msg_from_str(const char *s)
{
	vchar_t *v = vmalloc(strlen(s));
	if (v)
		memcpy(v->v, s, strlen(s));
	return v;
}

static char *
hex_from_vchar(vchar_t *v)
{
	char *out = malloc(v->l * 2 + 1);
	size_t i;
	for (i = 0; i < v->l; i++)
		sprintf(out + i * 2, "%02x", (unsigned char)v->v[i]);
	out[v->l * 2] = '\0';
	return out;
}

/* CONTRACT */
static int
test_t1_known_answer_sign(void)
{
	TEST_START("T1 known-answer sign (pinned signature tripwire)");

	eayRSA *r = make_fixed_priv();
	if (!r) { dump_openssl_errors("T1"); TEST_FAIL("make_fixed_priv failed"); }

	vchar_t *src = msg_from_str(T1_MESSAGE);
	vchar_t *sig = eayRSA_sign(r, src);
	if (!sig) {
		vfree(src);
		eayRSA_free(r);
		dump_openssl_errors("T1");
		TEST_FAIL("eayRSA_sign failed");
	}

	char *hex = hex_from_vchar(sig);
	int match = (strcasecmp(hex, T1_PINNED_SIG) == 0);

	free(hex);
	vfree(sig);
	vfree(src);
	eayRSA_free(r);

	if (!match)
		TEST_FAIL("signature does not match pinned constant -- "
		          "OpenSSL RSA signing behavior may have changed; INVESTIGATE");

	TEST_PASS();
	return 0;
}

/* CONTRACT */
static int
test_t2_sign_verify_roundtrip(void)
{
	TEST_START("T2 sign/verify round-trip");

	eayRSA *r = make_fixed_priv();
	if (!r) TEST_FAIL("make_fixed_priv failed");

	vchar_t *msg = msg_from_str("T2 round-trip message");
	vchar_t *other = msg_from_str("T2 a completely different message");
	vchar_t *sig = eayRSA_sign(r, msg);
	if (!sig) { vfree(msg); vfree(other); eayRSA_free(r); TEST_FAIL("sign failed"); }

	if (eayRSA_verify(r, msg, sig) != 0) {
		vfree(msg); vfree(other); vfree(sig); eayRSA_free(r);
		TEST_FAIL("verify(msg) != 0");
	}
	if (eayRSA_verify(r, other, sig) == 0) {
		vfree(msg); vfree(other); vfree(sig); eayRSA_free(r);
		TEST_FAIL("verify(other_msg) unexpectedly == 0");
	}

	vchar_t *tampered = vdup(sig);
	tampered->v[0] ^= 0xff;
	if (eayRSA_verify(r, msg, tampered) == 0) {
		vfree(msg); vfree(other); vfree(sig); vfree(tampered); eayRSA_free(r);
		TEST_FAIL("verify(tampered_sig) unexpectedly == 0");
	}

	vfree(msg); vfree(other); vfree(sig); vfree(tampered);
	eayRSA_free(r);
	TEST_PASS();
	return 0;
}

/* CONTRACT */
static int
test_t3_cross_construction_interop(void)
{
	TEST_START("T3 cross-construction interop (IPsec scenario)");

	eayRSA *priv = make_fixed_priv();
	if (!priv) TEST_FAIL("make_fixed_priv failed");

	BIGNUM *n = h2bn(K2048_N), *e = h2bn(K2048_E);
	eayRSA *pub = eayRSA_new_pub(n, e);
	BN_free(n); BN_free(e);
	if (!pub) { eayRSA_free(priv); TEST_FAIL("eayRSA_new_pub failed"); }

	vchar_t *msg = msg_from_str("T3 cross-construction message");
	vchar_t *sig = eayRSA_sign(priv, msg);
	if (!sig) { vfree(msg); eayRSA_free(priv); eayRSA_free(pub); TEST_FAIL("sign failed"); }

	int rc = eayRSA_verify(pub, msg, sig);

	vfree(msg); vfree(sig);
	eayRSA_free(priv);
	eayRSA_free(pub);

	if (rc != 0)
		TEST_FAIL("verify with pub-only key constructed from (n,e) failed");

	TEST_PASS();
	return 0;
}

/* CONTRACT */
static int
test_t4_param_roundtrip(void)
{
	TEST_START("T4 param round-trip (get_params pins OSSL_PARAM mapping)");

	BIGNUM *n = h2bn(K2048_N), *e = h2bn(K2048_E), *d = h2bn(K2048_D);
	BIGNUM *p = h2bn(K2048_P), *q = h2bn(K2048_Q);
	BIGNUM *dmp1 = h2bn(K2048_DMP1), *dmq1 = h2bn(K2048_DMQ1), *iqmp = h2bn(K2048_IQMP);

	eayRSA *r = eayRSA_new_priv(n, e, d, p, q, dmp1, dmq1, iqmp);
	if (!r) {
		BN_free(n); BN_free(e); BN_clear_free(d);
		BN_clear_free(p); BN_clear_free(q);
		BN_clear_free(dmp1); BN_clear_free(dmq1); BN_clear_free(iqmp);
		TEST_FAIL("eayRSA_new_priv failed");
	}

	BIGNUM *on=NULL, *oe=NULL, *od=NULL, *op=NULL, *oq=NULL, *odmp1=NULL, *odmq1=NULL, *oiqmp=NULL;
	int rc = eayRSA_get_params(r, &on, &oe, &od, &op, &oq, &odmp1, &odmq1, &oiqmp);

	int ok = (rc == 0)
	    && on && BN_cmp(on, n) == 0
	    && oe && BN_cmp(oe, e) == 0
	    && od && BN_cmp(od, d) == 0
	    && op && BN_cmp(op, p) == 0
	    && oq && BN_cmp(oq, q) == 0
	    && odmp1 && BN_cmp(odmp1, dmp1) == 0
	    && odmq1 && BN_cmp(odmq1, dmq1) == 0
	    && oiqmp && BN_cmp(oiqmp, iqmp) == 0;

	BN_free(on); BN_free(oe); BN_clear_free(od);
	BN_clear_free(op); BN_clear_free(oq);
	BN_clear_free(odmp1); BN_clear_free(odmq1); BN_clear_free(oiqmp);

	BN_free(n); BN_free(e); BN_clear_free(d);
	BN_clear_free(p); BN_clear_free(q);
	BN_clear_free(dmp1); BN_clear_free(dmq1); BN_clear_free(iqmp);
	eayRSA_free(r);

	if (!ok) TEST_FAIL("a returned param did not match the input component");

	TEST_PASS();
	return 0;
}

/* CONTRACT */
static int
test_t5_has_private(void)
{
	TEST_START("T5 has_private");

	BIGNUM *n = h2bn(K2048_N), *e = h2bn(K2048_E);
	eayRSA *pub = eayRSA_new_pub(n, e);
	BN_free(n); BN_free(e);
	if (!pub) TEST_FAIL("eayRSA_new_pub failed");
	int pub_has_priv = eayRSA_has_private(pub);
	eayRSA_free(pub);

	eayRSA *priv = make_fixed_priv();
	if (!priv) TEST_FAIL("make_fixed_priv failed");
	int priv_has_priv = eayRSA_has_private(priv);
	eayRSA_free(priv);

	if (pub_has_priv != 0) TEST_FAIL("eayRSA_has_private(pub) != 0");
	if (priv_has_priv != 1) TEST_FAIL("eayRSA_has_private(priv) != 1");

	TEST_PASS();
	return 0;
}

/* CONTRACT */
static int
test_t6_size(void)
{
	TEST_START("T6 size (2048-bit modulus -> 256 bytes)");

	eayRSA *r = make_fixed_priv();
	if (!r) TEST_FAIL("make_fixed_priv failed");
	int sz = eayRSA_size(r);
	eayRSA_free(r);

	if (sz != 256) TEST_FAIL("eayRSA_size() != 256 for 2048-bit key");

	TEST_PASS();
	return 0;
}

/* CONTRACT */
static int
test_t7_pem_private_roundtrip(void)
{
	TEST_START("T7 PEM private round-trip via tmpfile()");

	eayRSA *r = make_fixed_priv();
	if (!r) TEST_FAIL("make_fixed_priv failed");

	FILE *fp = tmpfile();
	if (!fp) { eayRSA_free(r); TEST_FAIL("tmpfile() failed"); }

	if (eayRSA_write_private_pem(fp, r) != 0) {
		fclose(fp); eayRSA_free(r);
		TEST_FAIL("eayRSA_write_private_pem failed");
	}
	rewind(fp);

	eayRSA *r2 = eayRSA_read_private_pem(fp);
	fclose(fp);
	if (!r2) { eayRSA_free(r); TEST_FAIL("eayRSA_read_private_pem failed"); }

	vchar_t *msg = msg_from_str("T7 PEM round-trip message");
	vchar_t *sig = eayRSA_sign(r2, msg);
	int rc = sig ? eayRSA_verify(r2, msg, sig) : -1;

	vfree(msg);
	if (sig) vfree(sig);
	eayRSA_free(r);
	eayRSA_free(r2);

	if (rc != 0) TEST_FAIL("sign/verify after PEM round-trip failed");

	TEST_PASS();
	return 0;
}

/* CONTRACT */
static int
test_t8_pem_public_roundtrip(void)
{
	TEST_START("T8 PEM public round-trip via tmpfile()");

	eayRSA *priv = make_fixed_priv();
	if (!priv) TEST_FAIL("make_fixed_priv failed");

	BIGNUM *n = h2bn(K2048_N), *e = h2bn(K2048_E);
	eayRSA *pub = eayRSA_new_pub(n, e);
	BN_free(n); BN_free(e);
	if (!pub) { eayRSA_free(priv); TEST_FAIL("eayRSA_new_pub failed"); }

	FILE *fp = tmpfile();
	if (!fp) { eayRSA_free(priv); eayRSA_free(pub); TEST_FAIL("tmpfile() failed"); }

	if (eayRSA_write_public_pem(fp, pub) != 0) {
		fclose(fp); eayRSA_free(priv); eayRSA_free(pub);
		TEST_FAIL("eayRSA_write_public_pem failed");
	}
	rewind(fp);

	eayRSA *pub2 = eayRSA_read_public_pem(fp);
	fclose(fp);
	if (!pub2) { eayRSA_free(priv); eayRSA_free(pub); TEST_FAIL("eayRSA_read_public_pem failed"); }

	vchar_t *msg = msg_from_str("T8 PEM public round-trip message");
	vchar_t *sig = eayRSA_sign(priv, msg);
	int rc = sig ? eayRSA_verify(pub2, msg, sig) : -1;

	vfree(msg);
	if (sig) vfree(sig);
	eayRSA_free(priv);
	eayRSA_free(pub);
	eayRSA_free(pub2);

	if (rc != 0) TEST_FAIL("verify with PEM-round-tripped public key failed");

	TEST_PASS();
	return 0;
}

/* CONTRACT */
static int
test_t9_generate(void)
{
	TEST_START("T9 generate(2048, RSA_F4)");

	eayRSA *r = eayRSA_generate(2048, RSA_F4);
	if (!r) TEST_FAIL("eayRSA_generate failed");

	int has_priv = eayRSA_has_private(r);
	int sz = eayRSA_size(r);

	vchar_t *msg = msg_from_str("T9 freshly generated key message");
	vchar_t *sig = eayRSA_sign(r, msg);
	int rc = sig ? eayRSA_verify(r, msg, sig) : -1;

	vfree(msg);
	if (sig) vfree(sig);
	eayRSA_free(r);

	if (has_priv != 1) TEST_FAIL("has_private != 1 for generated key");
	if (sz != 256) TEST_FAIL("size != 256 for generated 2048-bit key");
	if (rc != 0) TEST_FAIL("sign/verify failed for generated key");

	TEST_PASS();
	return 0;
}

/* CONTRACT */
static int
test_t10_dup_independent_free(void)
{
	TEST_START("T10 dup + independent free (EVP_PKEY refcount)");

	eayRSA *orig = make_fixed_priv();
	if (!orig) TEST_FAIL("make_fixed_priv failed");

	eayRSA *dup = eayRSA_dup(orig);
	if (!dup) { eayRSA_free(orig); TEST_FAIL("eayRSA_dup failed"); }

	eayRSA_free(orig); /* original freed; dup must still work */

	vchar_t *msg = msg_from_str("T10 dup independence message");
	vchar_t *sig = eayRSA_sign(dup, msg);
	int rc = sig ? eayRSA_verify(dup, msg, sig) : -1;

	vfree(msg);
	if (sig) vfree(sig);
	eayRSA_free(dup);

	if (rc != 0) TEST_FAIL("sign/verify on dup after freeing original failed");

	TEST_PASS();
	return 0;
}

int
main(int argc, char **argv)
{
	int failed = 0;
	int ran = 0;

	printf("\n");
	printf("========================================================================\n");
	printf("  Racoon IPSec eayRSA Unit Tests\n");
	printf("========================================================================\n");

	eay_init();

	printf("\n=== CONTRACT TESTS ===\n");
	ran++; if (test_t1_known_answer_sign() != 0) failed++;
	ran++; if (test_t2_sign_verify_roundtrip() != 0) failed++;
	ran++; if (test_t3_cross_construction_interop() != 0) failed++;
	ran++; if (test_t4_param_roundtrip() != 0) failed++;
	ran++; if (test_t5_has_private() != 0) failed++;
	ran++; if (test_t6_size() != 0) failed++;
	ran++; if (test_t7_pem_private_roundtrip() != 0) failed++;
	ran++; if (test_t8_pem_public_roundtrip() != 0) failed++;
	ran++; if (test_t9_generate() != 0) failed++;
	ran++; if (test_t10_dup_independent_free() != 0) failed++;

	printf("\n");
	printf("========================================================================\n");
	if (failed == 0) {
		printf("  \xe2\x9c\x93 ALL EAY_RSA TESTS PASSED (%d tests)\n", ran);
		printf("========================================================================\n");
		return 0;
	} else {
		printf("  \xe2\x9c\x97 %d EAY_RSA TEST(S) FAILED\n", failed);
		printf("========================================================================\n");
		return 1;
	}
}
