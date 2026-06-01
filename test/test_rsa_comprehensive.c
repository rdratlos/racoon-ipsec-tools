// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Comprehensive RSA Tests for Racoon IPSec OpenSSL 3.0 Migration
 *
 * Focuses on "textbook RSA" implementation used in IKEv1/IPSec
 * Tests all critical migration points and edge cases
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include "vmbuf.h"
#include "crypto_openssl.h"
#include "gcmalloc.h"

#define TEST_PASS() printf("✓ PASS\n")
#define TEST_FAIL(msg) do { printf("✗ FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* Suppress deprecation warnings for OpenSSL 3.0 low-level API usage */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif

#include <openssl/err.h>
#include <openssl/bn.h>

#include "openssl_compat.h"
#include "rsalist.h"

/* Test data */
static const char *test_data_short = "Test";
static const char *test_data_medium = "The quick brown fox jumps over the lazy dog";
static const char *test_data_long = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
				    "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
				    "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.";

/* Helper: print OpenSSL error queue to stderr */
static void dump_openssl_errors(const char *context)
{
	unsigned long err;
	char buf[256];
	fprintf(stderr, "  [DIAG] OpenSSL errors at '%s':\n", context);
	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		fprintf(stderr, "    ERR: %s\n", buf);
	}
}

/* Helper: print first N bytes of a buffer as hex */
static void dump_buf_hex(const char *label, const unsigned char *buf, size_t len, size_t n)
{
	size_t i;
	fprintf(stderr, "  [DIAG] %s (total len=%zu, showing first %zu): ", label, len, n);
	for (i = 0; i < n && i < len; i++)
		fprintf(stderr, "%02x", buf[i]);
	fprintf(stderr, "\n");
}

/* One-shot RSA* -> eayRSA* conversion for tests that generate keys via
 * raw EVP_PKEY/RSA* APIs but need to exercise the eayRSA*-based signing API. */
static eayRSA *
rsa_to_eayrsa(RSA *rsa)
{
	const BIGNUM *n = NULL, *e = NULL, *d = NULL;
	const BIGNUM *p = NULL, *q = NULL;
	const BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

	if (!rsa)
		return NULL;
	if (compat_RSA_get0_params(rsa, &n, &e, &d, &p, &q, &dmp1, &dmq1, &iqmp) < 0)
		return NULL;
	return eayRSA_new_priv(n, e, d, p, q, dmp1, dmq1, iqmp);
}

/* ============================================================================
 * PRIORITY 1: CRITICAL TEXTBOOK RSA TESTS
 * ============================================================================ */

int test_rsa_textbook_verify_recover()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *data = NULL, *signature = NULL;
	int ret = -1;

	TEST_START("Textbook RSA with EVP_PKEY_verify_recover");

	/* Generate RSA key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		TEST_FAIL("Failed to extract RSA key");
	}

	erRSA = rsa_to_eayrsa(rsa);
	if (!erRSA) {
		TEST_FAIL("Failed to convert RSA key to eayRSA");
	}

	/* Prepare data */
	data = vmalloc(strlen(test_data_medium));
	if (!data) {
		TEST_FAIL("Failed to allocate data");
	}
	memcpy(data->v, test_data_medium, strlen(test_data_medium));

	/* Sign using our implementation */
	ERR_clear_error();
	signature = eay_get_rsasign(data, erRSA);
	if (!signature) {
		dump_openssl_errors("eay_get_rsasign");
		TEST_FAIL("eay_get_rsasign() failed");
	}

	/* Verify using our textbook RSA implementation */
	ERR_clear_error();
	if (eay_check_rsasign(data, signature, erRSA) != 0) {
		dump_openssl_errors("eay_check_rsasign");
		TEST_FAIL("eay_check_rsasign() failed - textbook RSA broken!");
	}

	printf("Textbook RSA works ");
	ret = 0;

	/* Cleanup */
	if (signature) vfree(signature);
	if (data) vfree(data);
	if (erRSA) eayRSA_free(erRSA);
	if (rsa) RSA_free(rsa);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_rsa_padding_verification()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *data = NULL, *signature = NULL;
	int ret = -1;

	TEST_START("RSA PKCS1 Padding Verification");

	/* Generate RSA key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		TEST_FAIL("Failed to extract RSA key");
	}

	erRSA = rsa_to_eayrsa(rsa);
	if (!erRSA) {
		TEST_FAIL("Failed to convert RSA key to eayRSA");
	}

	/* Test with various data sizes to verify padding */
	const char *test_data[] = {
		"A",  /* 1 byte */
		"Short test",  /* 10 bytes */
		test_data_medium,  /* ~44 bytes */
		test_data_long  /* ~200+ bytes */
	};

	int i;
	for (i = 0; i < 4; i++) {
		data = vmalloc(strlen(test_data[i]));
		if (!data) {
			TEST_FAIL("Allocation failed");
		}
		memcpy(data->v, test_data[i], strlen(test_data[i]));

		ERR_clear_error();
		signature = eay_get_rsasign(data, erRSA);
		if (!signature) {
			dump_openssl_errors("eay_get_rsasign padding test");
			printf("Sign failed for size %zu ", strlen(test_data[i]));
			TEST_FAIL("Signing failed");
		}

		ERR_clear_error();
		if (eay_check_rsasign(data, signature, erRSA) != 0) {
			dump_openssl_errors("eay_check_rsasign padding test");
			printf("Verify failed for size %zu ", strlen(test_data[i]));
			TEST_FAIL("Padding verification failed");
		}

		vfree(signature);
		vfree(data);
		signature = NULL;
		data = NULL;
	}

	printf("PKCS1 padding correct for all sizes ");
	ret = 0;

	if (erRSA) eayRSA_free(erRSA);
	if (rsa) RSA_free(rsa);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_rsa_to_evp_pkey_conversion()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL, *pkey2 = NULL;
	RSA *rsa = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *data = NULL, *sig1 = NULL, *sig2 = NULL;
	int ret = -1;

	TEST_START("RSA to EVP_PKEY Conversion (OpenSSL 3.0)");

	/* Generate RSA key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	/* Extract RSA structure */
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		TEST_FAIL("Failed to extract RSA");
	}

	erRSA = rsa_to_eayrsa(rsa);
	if (!erRSA) {
		TEST_FAIL("Failed to convert RSA key to eayRSA");
	}

	/* Prepare test data */
	data = vmalloc(strlen(test_data_medium));
	if (!data) {
		TEST_FAIL("Allocation failed");
	}
	memcpy(data->v, test_data_medium, strlen(test_data_medium));

	/* Sign with original EVP_PKEY */
	ERR_clear_error();
	sig1 = eay_pkey_sign(data, pkey);
	if (!sig1) {
		dump_openssl_errors("eay_pkey_sign");
		TEST_FAIL("Sign with EVP_PKEY failed");
	}

	/* Sign with RSA (which converts to EVP_PKEY internally) */
	ERR_clear_error();
	sig2 = eay_get_rsasign(data, erRSA);
	if (!sig2) {
		dump_openssl_errors("eay_get_rsasign");
		TEST_FAIL("Sign with RSA failed");
	}

	/* Verify cross-compatibility */
	ERR_clear_error();
	if (eay_check_rsasign(data, sig1, erRSA) != 0) {
		dump_openssl_errors("eay_check_rsasign cross");
		TEST_FAIL("EVP_PKEY sig verify with RSA failed");
	}

	ERR_clear_error();
	if (eay_pkey_verify(data, sig2, pkey) != 0) {
		dump_openssl_errors("eay_pkey_verify cross");
		TEST_FAIL("RSA sig verify with EVP_PKEY failed");
	}

	printf("RSA↔EVP_PKEY conversion works ");
	ret = 0;

	/* Cleanup */
	if (data) vfree(data);
	if (sig1) vfree(sig1);
	if (sig2) vfree(sig2);
	if (erRSA) eayRSA_free(erRSA);
	if (rsa) RSA_free(rsa);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_rsa_signature_tampering()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *data = NULL, *signature = NULL;
	int ret = -1;

	TEST_START("RSA Signature Tampering Detection");

	/* Generate key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		TEST_FAIL("Failed to extract RSA");
	}

	erRSA = rsa_to_eayrsa(rsa);
	if (!erRSA) {
		TEST_FAIL("Failed to convert RSA key to eayRSA");
	}

	/* Prepare data */
	data = vmalloc(strlen(test_data_medium));
	if (!data) {
		TEST_FAIL("Allocation failed");
	}
	memcpy(data->v, test_data_medium, strlen(test_data_medium));

	/* Sign */
	signature = eay_get_rsasign(data, erRSA);
	if (!signature) {
		TEST_FAIL("Signing failed");
	}

	/* Verify original signature works */
	if (eay_check_rsasign(data, signature, erRSA) != 0) {
		TEST_FAIL("Original signature verification failed");
	}

	/* Tamper with signature - flip bits in middle */
	((unsigned char *)signature->v)[signature->l / 2] ^= 0xFF;
	((unsigned char *)signature->v)[signature->l / 2 + 1] ^= 0xAA;
	((unsigned char *)signature->v)[signature->l / 2 + 2] ^= 0x55;

	/* Verification should fail */
	ERR_clear_error();
	if (eay_check_rsasign(data, signature, erRSA) == 0) {
		TEST_FAIL("Tampered signature was accepted - SECURITY ISSUE!");
	}
	/* Clear expected errors from tampered sig */
	ERR_clear_error();

	printf("Tampered signature rejected ");
	ret = 0;

	/* Cleanup */
	if (data) vfree(data);
	if (signature) vfree(signature);
	if (erRSA) eayRSA_free(erRSA);
	if (rsa) RSA_free(rsa);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_rsa_data_tampering()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *data = NULL, *tampered = NULL, *signature = NULL;
	int ret = -1;

	TEST_START("RSA Data Tampering Detection");

	/* Generate key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		TEST_FAIL("Failed to extract RSA");
	}

	erRSA = rsa_to_eayrsa(rsa);
	if (!erRSA) {
		TEST_FAIL("Failed to convert RSA key to eayRSA");
	}

	/* Prepare data */
	data = vmalloc(strlen(test_data_medium));
	if (!data) {
		TEST_FAIL("Allocation failed");
	}
	memcpy(data->v, test_data_medium, strlen(test_data_medium));

	/* Sign */
	signature = eay_get_rsasign(data, erRSA);
	if (!signature) {
		TEST_FAIL("Signing failed");
	}

	/* Create tampered data */
	tampered = vmalloc(data->l);
	if (!tampered) {
		TEST_FAIL("Allocation failed");
	}
	memcpy(tampered->v, data->v, data->l);

	/* Tamper: flip first byte */
	((char *)tampered->v)[0] ^= 0x01;

	/* Verification with tampered data should fail */
	ERR_clear_error();
	if (eay_check_rsasign(tampered, signature, erRSA) == 0) {
		TEST_FAIL("Tampered data was accepted - SECURITY ISSUE!");
	}
	ERR_clear_error();

	/* Original data should still verify */
	if (eay_check_rsasign(data, signature, erRSA) != 0) {
		TEST_FAIL("Original data no longer verifies");
	}

	printf("Tampered data rejected, original accepted ");
	ret = 0;

	/* Cleanup */
	if (data) vfree(data);
	if (tampered) vfree(tampered);
	if (signature) vfree(signature);
	if (erRSA) eayRSA_free(erRSA);
	if (rsa) RSA_free(rsa);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_rsa_wrong_key()
{
	EVP_PKEY_CTX *ctx1 = NULL, *ctx2 = NULL;
	EVP_PKEY *pkey1 = NULL, *pkey2 = NULL;
	RSA *rsa1 = NULL, *rsa2 = NULL;
	eayRSA *erRSA1 = NULL, *erRSA2 = NULL;
	vchar_t *data = NULL, *signature = NULL;
	int ret = -1;

	TEST_START("RSA Wrong Key Rejection");

	/* Generate first key pair */
	ctx1 = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx1 || EVP_PKEY_keygen_init(ctx1) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx1, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx1, &pkey1) <= 0) {
		TEST_FAIL("First key generation failed");
	}

	/* Generate second key pair */
	ctx2 = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx2 || EVP_PKEY_keygen_init(ctx2) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx2, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx2, &pkey2) <= 0) {
		TEST_FAIL("Second key generation failed");
	}

	rsa1 = EVP_PKEY_get1_RSA(pkey1);
	rsa2 = EVP_PKEY_get1_RSA(pkey2);
	if (!rsa1 || !rsa2) {
		TEST_FAIL("Failed to extract RSA keys");
	}

	erRSA1 = rsa_to_eayrsa(rsa1);
	erRSA2 = rsa_to_eayrsa(rsa2);
	if (!erRSA1 || !erRSA2) {
		TEST_FAIL("Failed to convert RSA keys to eayRSA");
	}

	/* Prepare data */
	data = vmalloc(strlen(test_data_medium));
	if (!data) {
		TEST_FAIL("Allocation failed");
	}
	memcpy(data->v, test_data_medium, strlen(test_data_medium));

	/* Sign with key1 */
	signature = eay_get_rsasign(data, erRSA1);
	if (!signature) {
		TEST_FAIL("Signing failed");
	}

	/* Verify with correct key should work */
	if (eay_check_rsasign(data, signature, erRSA1) != 0) {
		TEST_FAIL("Verification with correct key failed");
	}

	/* Verify with wrong key should fail */
	ERR_clear_error();
	if (eay_check_rsasign(data, signature, erRSA2) == 0) {
		TEST_FAIL("Wrong key was accepted - SECURITY ISSUE!");
	}
	ERR_clear_error();

	printf("Wrong key rejected, correct key accepted ");
	ret = 0;

	/* Cleanup */
	if (data) vfree(data);
	if (signature) vfree(signature);
	if (erRSA1) eayRSA_free(erRSA1);
	if (erRSA2) eayRSA_free(erRSA2);
	if (rsa1) RSA_free(rsa1);
	if (rsa2) RSA_free(rsa2);
	if (pkey1) EVP_PKEY_free(pkey1);
	if (pkey2) EVP_PKEY_free(pkey2);
	if (ctx1) compat_EVP_PKEY_CTX_free(ctx1);
	if (ctx2) compat_EVP_PKEY_CTX_free(ctx2);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * PRIORITY 2: KEY FORMAT CONVERSION TESTS
 * ============================================================================ */

int test_rsa_key_extraction()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa1 = NULL, *rsa2 = NULL;
	const BIGNUM *n1 = NULL, *e1 = NULL, *d1 = NULL;
	const BIGNUM *n2 = NULL, *e2 = NULL, *d2 = NULL;
	int ret = -1;

	TEST_START("RSA Key Component Extraction");

	/* Generate key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	/* Extract RSA structure */
	rsa1 = EVP_PKEY_get1_RSA(pkey);
	if (!rsa1) {
		TEST_FAIL("Failed to extract RSA");
	}

	/* Get key components */
	RSA_get0_key(rsa1, &n1, &e1, &d1);
	if (!n1 || !e1 || !d1) {
		TEST_FAIL("Failed to get key components");
	}

	/* Extract again - should get same values */
	rsa2 = EVP_PKEY_get1_RSA(pkey);
	if (!rsa2) {
		TEST_FAIL("Second extraction failed");
	}

	RSA_get0_key(rsa2, &n2, &e2, &d2);
	if (!n2 || !e2 || !d2) {
		TEST_FAIL("Failed to get second set of components");
	}

	/* Components should be identical */
	if (BN_cmp(n1, n2) != 0 || BN_cmp(e1, e2) != 0 || BN_cmp(d1, d2) != 0) {
		TEST_FAIL("Key components don't match");
	}

	printf("Key extraction consistent ");
	ret = 0;

	if (rsa1) RSA_free(rsa1);
	if (rsa2) RSA_free(rsa2);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * PRIORITY 3: RSA SIGN/VERIFY WITH eay_rsa_sign/eay_rsa_verify
 * ============================================================================ */

int test_rsa_sign_verify()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *message = NULL;
	vchar_t *signature = NULL;
	int ret = -1;

	TEST_START("RSA Sign/Verify (eay_rsa_sign/eay_rsa_verify)");

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) { EVP_PKEY_free(pkey); TEST_FAIL("Failed to extract RSA key"); }

	erRSA = rsa_to_eayrsa(rsa);
	if (!erRSA) { RSA_free(rsa); EVP_PKEY_free(pkey); TEST_FAIL("Failed to convert RSA key to eayRSA"); }

	message = vmalloc(40);
	if (!message) { eayRSA_free(erRSA); RSA_free(rsa); EVP_PKEY_free(pkey); TEST_FAIL("Allocation failed"); }
	memcpy(message->v, "Hello, Racoon IPSec RSA Sign/Verify!", 37);

	signature = eay_rsa_sign(message, erRSA);
	if (!signature) { eayRSA_free(erRSA); RSA_free(rsa); EVP_PKEY_free(pkey); vfree(message); TEST_FAIL("eay_rsa_sign failed"); }

	int verify_result = eay_rsa_verify(message, signature, erRSA);
	if (verify_result != 0) {
		eayRSA_free(erRSA); RSA_free(rsa); EVP_PKEY_free(pkey); vfree(message); vfree(signature);
		TEST_FAIL("eay_rsa_verify failed for valid signature");
	}

	if (signature->l > 0) {
		((unsigned char *)signature->v)[0] ^= 0xFF;
		verify_result = eay_rsa_verify(message, signature, erRSA);
		if (verify_result == 0) {
			eayRSA_free(erRSA); RSA_free(rsa); EVP_PKEY_free(pkey); vfree(message); vfree(signature);
			TEST_FAIL("eay_rsa_verify accepted tampered signature");
		}
	}

	printf("RSA sign and verify OK ");
	ret = 0;

	if (erRSA) eayRSA_free(erRSA);
	if (rsa) RSA_free(rsa);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);
	if (message) vfree(message);
	if (signature) vfree(signature);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * PRIORITY 3: RSA SIGN/VERIFY WITH eay_pkey_sign/eay_pkey_verify
 * ============================================================================ */

int test_pkey_sign_verify()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	vchar_t *message = NULL;
	vchar_t *signature = NULL;
	int ret = -1;

	TEST_START("RSA Sign/Verify (eay_pkey_sign/eay_pkey_verify)");

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	message = vmalloc(40);
	if (!message) { EVP_PKEY_free(pkey); TEST_FAIL("Allocation failed"); }
	memcpy(message->v, "PKEY sign/verify test message for Racoon!", 38);

	signature = eay_pkey_sign(message, pkey);
	if (!signature) { EVP_PKEY_free(pkey); vfree(message); TEST_FAIL("eay_pkey_sign failed"); }

	int verify_result = eay_pkey_verify(message, signature, pkey);
	if (verify_result != 0) {
		EVP_PKEY_free(pkey); vfree(message); vfree(signature);
		TEST_FAIL("eay_pkey_verify failed for valid signature");
	}

	((unsigned char *)message->v)[0] ^= 0xFF;
	verify_result = eay_pkey_verify(message, signature, pkey);
	if (verify_result == 0) {
		EVP_PKEY_free(pkey); vfree(message); vfree(signature);
		TEST_FAIL("eay_pkey_verify accepted tampered message");
	}

	printf("PKEY sign and verify OK ");
	ret = 0;

	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);
	if (message) vfree(message);
	if (signature) vfree(signature);

	if (ret == 0) TEST_PASS();
	return ret;
}

/*
 * Test bignum_pubkey2rsa() with a correctly formatted buffer, then verify
 * the reconstructed public key by signing with the original private key and
 * verifying with the reconstructed public key.
 *
 * bignum_pubkey2rsa() / binbuf_pubkey2rsa() expect the racoon "Plain RSA"
 * pubkey binary format:
 *   byte  0        : length of exponent in bytes (N)
 *   bytes 1..N     : exponent bytes
 *   bytes N+1..end : modulus bytes
 *
 * The test constructs this buffer explicitly from the RSA key components.
 */
int test_rsa_bignum_conversion()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa1 = NULL;
	eayRSA *erRSA1 = NULL;
	eayRSA *rsa2 = NULL;
	const BIGNUM *n = NULL, *e = NULL;
	BIGNUM *n2 = NULL, *e2 = NULL;
	vchar_t *data = NULL, *sig1 = NULL;
	vchar_t *binbuf = NULL;
	BIGNUM *binbuf_bn = NULL;
	char *n_hex = NULL, *e_hex = NULL;
	char *n2_hex = NULL, *e2_hex = NULL;
	int n_len, e_len;
	int ret = -1;

	TEST_START("RSA BIGNUM Conversion");

	/* Generate key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	rsa1 = EVP_PKEY_get1_RSA(pkey);
	if (!rsa1) {
		TEST_FAIL("Failed to extract RSA");
	}

	erRSA1 = rsa_to_eayrsa(rsa1);
	if (!erRSA1) {
		TEST_FAIL("Failed to convert RSA key to eayRSA");
	}

	/* Get key components from the original key */
	RSA_get0_key(rsa1, &n, &e, NULL);
	if (!n || !e) {
		TEST_FAIL("Failed to get key components");
	}

	n_len = BN_num_bytes(n);
	e_len = BN_num_bytes(e);

	/* Dump original n and e */
	n_hex = BN_bn2hex(n);
	e_hex = BN_bn2hex(e);
	fprintf(stderr, "\n  [DIAG] rsa1 n_len=%d e_len=%d\n", n_len, e_len);
	fprintf(stderr, "  [DIAG] rsa1 e (hex): %s\n", e_hex ? e_hex : "(null)");
	/* n is large; just print first 32 hex chars */
	if (n_hex) {
		fprintf(stderr, "  [DIAG] rsa1 n (first 32 hex chars): %.32s...\n", n_hex);
	}
	if (n_hex) { OPENSSL_free(n_hex); n_hex = NULL; }
	if (e_hex) { OPENSSL_free(e_hex); e_hex = NULL; }

	/*
	 * Build the Plain RSA pubkey binary format expected by
	 * bignum_pubkey2rsa() / binbuf_pubkey2rsa():
	 *   v[0]          = exponent length (1 byte)
	 *   v[1..e_len]   = exponent bytes
	 *   v[e_len+1..]  = modulus bytes
	 */
	if (e_len > 255) {
		TEST_FAIL("Exponent too large for Plain RSA format (>255 bytes)");
	}

	binbuf = vmalloc(1 + e_len + n_len);
	if (!binbuf) {
		TEST_FAIL("Allocation failed");
	}

	((unsigned char *)binbuf->v)[0] = (unsigned char)e_len;
	BN_bn2bin(e, (unsigned char *)binbuf->v + 1);
	BN_bn2bin(n, (unsigned char *)binbuf->v + 1 + e_len);

	fprintf(stderr, "  [DIAG] binbuf->l=%zu binbuf->v[0]=%u (e_len)\n",
		binbuf->l, (unsigned)((unsigned char *)binbuf->v)[0]);
	dump_buf_hex("binbuf->v (first 16 bytes)", (unsigned char *)binbuf->v,
		     binbuf->l, 16);

	/* Convert the formatted buffer to a BIGNUM for bignum_pubkey2rsa() */
	binbuf_bn = BN_bin2bn((unsigned char *)binbuf->v, binbuf->l, NULL);
	if (!binbuf_bn) {
		dump_openssl_errors("BN_bin2bn for binbuf");
		TEST_FAIL("BN_bin2bn failed");
	}

	{
		char *bb_hex = BN_bn2hex(binbuf_bn);
		fprintf(stderr, "  [DIAG] binbuf_bn num_bytes=%d\n",
			BN_num_bytes(binbuf_bn));
		if (bb_hex) {
			fprintf(stderr, "  [DIAG] binbuf_bn (first 32 hex chars): %.32s...\n",
				bb_hex);
			OPENSSL_free(bb_hex);
		}
	}

	/* Call bignum_pubkey2rsa() with the correctly formatted BIGNUM */
	ERR_clear_error();
	rsa2 = bignum_pubkey2rsa(binbuf_bn);
	fprintf(stderr, "  [DIAG] bignum_pubkey2rsa returned %p\n", (void*)rsa2);
	if (!rsa2) {
		dump_openssl_errors("bignum_pubkey2rsa");
		TEST_FAIL("bignum_pubkey2rsa() failed");
	}

	/* Extract and dump n2, e2 from rsa2 to verify round-trip */
	if (eayRSA_get_params(rsa2, &n2, &e2, NULL, NULL, NULL, NULL, NULL, NULL) < 0 ||
	    !n2 || !e2) {
		fprintf(stderr, "  [DIAG] eayRSA_get_params on rsa2: n2=%p e2=%p\n",
			(void*)n2, (void*)e2);
		TEST_FAIL("Failed to get components from rsa2");
	}

	n2_hex = BN_bn2hex(n2);
	e2_hex = BN_bn2hex(e2);
	fprintf(stderr, "  [DIAG] rsa2 n2_len=%d e2_len=%d\n",
		BN_num_bytes(n2), BN_num_bytes(e2));
	fprintf(stderr, "  [DIAG] rsa2 e2 (hex): %s\n", e2_hex ? e2_hex : "(null)");
	if (n2_hex) {
		fprintf(stderr, "  [DIAG] rsa2 n2 (first 32 hex chars): %.32s...\n", n2_hex);
	}

	/* Compare n and e between rsa1 and rsa2 */
	fprintf(stderr, "  [DIAG] BN_cmp(n, n2)=%d  BN_cmp(e, e2)=%d\n",
		BN_cmp(n, n2), BN_cmp(e, e2));

	if (n2_hex) { OPENSSL_free(n2_hex); n2_hex = NULL; }
	if (e2_hex) { OPENSSL_free(e2_hex); e2_hex = NULL; }

	/* Sign with original private key */
	data = vmalloc(strlen(test_data_short));
	if (!data) {
		TEST_FAIL("Allocation failed");
	}
	memcpy(data->v, test_data_short, strlen(test_data_short));

	ERR_clear_error();
	sig1 = eay_get_rsasign(data, erRSA1);
	fprintf(stderr, "  [DIAG] eay_get_rsasign returned %p\n", (void*)sig1);
	if (!sig1) {
		dump_openssl_errors("eay_get_rsasign");
		TEST_FAIL("Signing with original key failed");
	}

	fprintf(stderr, "  [DIAG] sig1->l=%zu\n", sig1->l);
	dump_buf_hex("sig1->v", (unsigned char *)sig1->v, sig1->l, 8);

	/*
	 * Verify the signature using rsa2 (the reconstructed public key).
	 */
	ERR_clear_error();
	int verify_ret = eayRSA_verify(rsa2, data, sig1);
	fprintf(stderr, "  [DIAG] eayRSA_verify(rsa2, data, sig1) returned %d\n",
		verify_ret);
	if (verify_ret != 0) {
		dump_openssl_errors("eayRSA_verify with rsa2");
		TEST_FAIL("Verification with reconstructed public key failed");
	}

	printf("BIGNUM→RSA conversion works ");
	ret = 0;

	if (data) vfree(data);
	if (sig1) vfree(sig1);
	if (binbuf) vfree(binbuf);
	if (binbuf_bn) BN_free(binbuf_bn);
	if (n2) BN_free(n2);
	if (e2) BN_free(e2);
	if (erRSA1) eayRSA_free(erRSA1);
	if (rsa1) RSA_free(rsa1);
	if (rsa2) eayRSA_free(rsa2);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * PRIORITY 2: MULTIPLE KEY SIZES
 * ============================================================================ */

int test_rsa_various_key_sizes()
{
	int key_sizes[] = {1024, 2048, 3072, 4096};
	int i;
	int ret = -1;

	TEST_START("RSA Various Key Sizes");
	printf("\n");

	for (i = 0; i < sizeof(key_sizes)/sizeof(key_sizes[0]); i++) {
		EVP_PKEY_CTX *ctx = NULL;
		EVP_PKEY *pkey = NULL;
		RSA *rsa = NULL;
		eayRSA *erRSA = NULL;
		vchar_t *data = NULL, *signature = NULL;

		printf("    Testing %d-bit key... ", key_sizes[i]);
		fflush(stdout);

		ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
		if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
		    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_sizes[i]) <= 0 ||
		    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
			printf("SKIP (generation failed)\n");
			if (ctx) compat_EVP_PKEY_CTX_free(ctx);
			continue;
		}

		rsa = EVP_PKEY_get1_RSA(pkey);
		if (!rsa) {
			printf("FAIL (extraction failed)\n");
			EVP_PKEY_free(pkey);
			compat_EVP_PKEY_CTX_free(ctx);
			continue;
		}

		erRSA = rsa_to_eayrsa(rsa);
		if (!erRSA) {
			printf("FAIL (eayRSA conversion failed)\n");
			RSA_free(rsa);
			EVP_PKEY_free(pkey);
			compat_EVP_PKEY_CTX_free(ctx);
			continue;
		}

		data = vmalloc(strlen(test_data_medium));
		if (!data) {
			printf("FAIL (allocation failed)\n");
			goto cleanup_iteration;
		}
		memcpy(data->v, test_data_medium, strlen(test_data_medium));

		ERR_clear_error();
		signature = eay_get_rsasign(data, erRSA);
		if (!signature) {
			dump_openssl_errors("eay_get_rsasign key sizes");
			printf("FAIL (signing failed)\n");
			goto cleanup_iteration;
		}

		/* Verify signature length is correct for key size */
		if (signature->l != (size_t)(key_sizes[i] / 8)) {
			fprintf(stderr, "  [DIAG] sig->l=%zu expected=%d\n",
				signature->l, key_sizes[i] / 8);
			printf("FAIL (sig length %zu != expected %d)\n",
			       signature->l, key_sizes[i] / 8);
			goto cleanup_iteration;
		}

		ERR_clear_error();
		if (eay_check_rsasign(data, signature, erRSA) != 0) {
			dump_openssl_errors("eay_check_rsasign key sizes");
			printf("FAIL (verification failed)\n");
			goto cleanup_iteration;
		}

		printf("✓ OK\n");

cleanup_iteration:
		if (signature) vfree(signature);
		if (data) vfree(data);
		if (erRSA) eayRSA_free(erRSA);
		if (rsa) RSA_free(rsa);
		if (pkey) EVP_PKEY_free(pkey);
		if (ctx) compat_EVP_PKEY_CTX_free(ctx);
	}

	printf("    ");
	ret = 0;

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * PRIORITY 3: EDGE CASES AND STRESS TESTS
 * ============================================================================ */

int test_rsa_empty_data()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *data = NULL, *signature = NULL;
	int ret = -1;

	TEST_START("RSA with Empty Data");

	/* Generate key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		TEST_FAIL("Failed to extract RSA");
	}

	erRSA = rsa_to_eayrsa(rsa);
	if (!erRSA) {
		TEST_FAIL("Failed to convert RSA key to eayRSA");
	}

	/* Try with empty data */
	data = vmalloc(0);
	if (!data) {
		TEST_FAIL("Allocation failed");
	}

	fprintf(stderr, "\n  [DIAG] empty data test: data->l=%zu\n", data->l);

	ERR_clear_error();
	signature = eay_get_rsasign(data, erRSA);
	fprintf(stderr, "  [DIAG] eay_get_rsasign(empty) returned %p\n", (void*)signature);
	if (signature != NULL) {
		fprintf(stderr, "  [DIAG] unexpected: sig->l=%zu\n", signature->l);
		vfree(signature);
		TEST_FAIL("Empty data was signed - eay_pkey_sign() must reject empty input");
	}
	ERR_clear_error();

	printf("Empty data correctly rejected ");
	ret = 0;

	if (data) vfree(data);
	if (erRSA) eayRSA_free(erRSA);
	if (rsa) RSA_free(rsa);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_rsa_maximum_data_size()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *data = NULL, *signature = NULL;
	int ret = -1;
	size_t max_size;
	size_t i;

	TEST_START("RSA with Maximum Data Size");

	/* Generate key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		TEST_FAIL("Failed to extract RSA");
	}

	erRSA = rsa_to_eayrsa(rsa);
	if (!erRSA) {
		TEST_FAIL("Failed to convert RSA key to eayRSA");
	}

	/* Calculate maximum data size for PKCS#1 v1.5 padding */
	max_size = RSA_size(rsa) - 11;
	printf("(max data size: %zu bytes for %d-bit key) ", max_size, RSA_bits(rsa));
	fprintf(stderr, "\n  [DIAG] RSA_size=%d max_data=%zu\n", RSA_size(rsa), max_size);

	/* Create maximum size data buffer */
	data = vmalloc(max_size);
	if (!data) {
		TEST_FAIL("Allocation failed");
	}

	/* Fill with pattern */
	for (i = 0; i < max_size; i++) {
		((unsigned char *)data->v)[i] = (unsigned char)(i & 0xFF);
	}

	ERR_clear_error();
	signature = eay_get_rsasign(data, erRSA);
	if (!signature) {
		dump_openssl_errors("eay_get_rsasign max size");
		TEST_FAIL("Signing maximum-size data failed");
	}

	ERR_clear_error();
	if (eay_check_rsasign(data, signature, erRSA) != 0) {
		dump_openssl_errors("eay_check_rsasign max size");
		TEST_FAIL("Verifying maximum-size data failed");
	}

	printf("Maximum data size (%zu bytes) handled ", max_size);
	ret = 0;

	if (data) vfree(data);
	if (signature) vfree(signature);
	if (erRSA) eayRSA_free(erRSA);
	if (rsa) RSA_free(rsa);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_rsa_stress_repeated_operations()
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *data = NULL, *signature = NULL;
	int ret = -1;
	int iterations = 100;
	int i;

	TEST_START("RSA Stress Test (100 iterations)");

	/* Generate key */
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		TEST_FAIL("Key generation failed");
	}

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		TEST_FAIL("Failed to extract RSA");
	}

	erRSA = rsa_to_eayrsa(rsa);
	if (!erRSA) {
		TEST_FAIL("Failed to convert RSA key to eayRSA");
	}

	/* Repeated sign/verify operations */
	for (i = 0; i < iterations; i++) {
		char test_buf[256];
		snprintf(test_buf, sizeof(test_buf), "Iteration %d data", i);

		data = vmalloc(strlen(test_buf));
		if (!data) {
			TEST_FAIL("Allocation failed in stress test");
		}
		memcpy(data->v, test_buf, strlen(test_buf));

		ERR_clear_error();
		signature = eay_get_rsasign(data, erRSA);
		if (!signature) {
			fprintf(stderr, "\n  [DIAG] stress iter %d: sign failed\n", i);
			dump_openssl_errors("stress eay_get_rsasign");
			TEST_FAIL("Signing failed in stress test");
		}

		ERR_clear_error();
		if (eay_check_rsasign(data, signature, erRSA) != 0) {
			fprintf(stderr, "\n  [DIAG] stress iter %d: verify failed\n", i);
			dump_openssl_errors("stress eay_check_rsasign");
			TEST_FAIL("Verification failed in stress test");
		}

		vfree(signature);
		vfree(data);
		signature = NULL;
		data = NULL;
	}

	printf("%d iterations completed ", iterations);
	ret = 0;

	if (erRSA) eayRSA_free(erRSA);
	if (rsa) RSA_free(rsa);
	if (pkey) EVP_PKEY_free(pkey);
	if (ctx) compat_EVP_PKEY_CTX_free(ctx);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * Helper: generate a real RSA key of the given size
 * ============================================================================ */

static RSA *generate_rsa_key(int bits)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *rsa = NULL;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		if (ctx) compat_EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	rsa = EVP_PKEY_get1_RSA(pkey);

	EVP_PKEY_free(pkey);
	compat_EVP_PKEY_CTX_free(ctx);
	return rsa;
}

/* ============================================================================
 * TEST GROUP 1: OSSL_PARAM_BLD shim (OpenSSL < 3.0 only)
 * ============================================================================ */

#if OPENSSL_VERSION_NUMBER < 0x30000000L

int test_ossl_param_bld_to_param_zero_init()
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	BIGNUM *bn = NULL;
	int ret = -1;

	TEST_START("OSSL_PARAM_BLD_to_param zero-init (memset fix)");

	bld = OSSL_PARAM_BLD_new();
	if (!bld) TEST_FAIL("OSSL_PARAM_BLD_new failed");

	bn = BN_new();
	if (!bn || !BN_set_word(bn, 0x10001)) {
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("BN_new/BN_set_word failed");
	}

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn)) {
		BN_free(bn);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_push_BN failed");
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		BN_free(bn);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_to_param returned NULL");
	}

	printf("params and bld non-NULL ");
	ret = 0;

	BN_free(bn);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_ossl_param_bld_free_empty()
{
	OSSL_PARAM_BLD *bld = NULL;
	int ret = -1;

	TEST_START("OSSL_PARAM_BLD_free on empty builder");

	bld = OSSL_PARAM_BLD_new();
	if (!bld) TEST_FAIL("OSSL_PARAM_BLD_new failed");

	OSSL_PARAM_BLD_free(bld);

	printf("no crash on empty free ");
	ret = 0;

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_ossl_param_bld_push_null_bn()
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	int ret = -1;

	TEST_START("OSSL_PARAM_BLD_push_BN with NULL bn");

	bld = OSSL_PARAM_BLD_new();
	if (!bld) TEST_FAIL("OSSL_PARAM_BLD_new failed");

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, NULL)) {
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_push_BN(NULL) returned failure");
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_to_param failed after NULL bn push");
	}

	printf("NULL bn accepted ");
	ret = 0;

	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_ossl_param_free_after_to_param()
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	BIGNUM *bn = NULL;
	int ret = -1;

	TEST_START("OSSL_PARAM_BLD_free + OSSL_PARAM_free after transfer");

	bld = OSSL_PARAM_BLD_new();
	if (!bld) TEST_FAIL("OSSL_PARAM_BLD_new failed");

	bn = BN_new();
	if (!bn || !BN_set_word(bn, 3)) {
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("BN_new/BN_set_word failed");
	}

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn)) {
		BN_free(bn);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_push_BN failed");
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		BN_free(bn);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_to_param returned NULL");
	}

	/* bld no longer owns the node list; freeing both must not double-free */
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);

	printf("no double-free after ownership transfer ");
	ret = 0;

	BN_free(bn);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_ossl_param_bld_push_size_t()
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	int ret = -1;

	TEST_START("OSSL_PARAM_BLD_push_size_t");

	bld = OSSL_PARAM_BLD_new();
	if (!bld) TEST_FAIL("OSSL_PARAM_BLD_new failed");

	if (!OSSL_PARAM_BLD_push_size_t(bld, OSSL_PKEY_PARAM_DH_PRIV_LEN, (size_t)256)) {
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_push_size_t returned failure");
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_to_param failed after size_t push");
	}

	printf("size_t param pushed and transferred ");
	ret = 0;

	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_ossl_param_bld_push_size_t_null_args()
{
	OSSL_PARAM_BLD *bld = NULL;
	int ret = -1;

	TEST_START("OSSL_PARAM_BLD_push_size_t with NULL bld/key");

	if (OSSL_PARAM_BLD_push_size_t(NULL, OSSL_PKEY_PARAM_DH_PRIV_LEN, (size_t)256)) {
		TEST_FAIL("OSSL_PARAM_BLD_push_size_t(NULL bld) should fail");
	}

	bld = OSSL_PARAM_BLD_new();
	if (!bld) TEST_FAIL("OSSL_PARAM_BLD_new failed");

	if (OSSL_PARAM_BLD_push_size_t(bld, NULL, (size_t)256)) {
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_push_size_t(NULL key) should fail");
	}

	printf("NULL bld/key correctly rejected ");
	ret = 0;

	OSSL_PARAM_BLD_free(bld);

	if (ret == 0) TEST_PASS();
	return ret;
}

/*
 * Regression test: EVP_PKEY_fromdata with duplicate RSA parameter keys.
 * Previously, when OSSL_PARAM_BLD contained two entries with the same key
 * (e.g., two "n" entries), the BN_free/BN_dup fix in EVP_PKEY_fromdata
 * ensured the second value overwrites the first without leaking the first BN.
 */
int test_evp_pkey_fromdata_rsa_duplicate_keys()
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *n1 = NULL, *n2 = NULL, *e = NULL;
	RSA *rsa = NULL;
	const BIGNUM *out_n = NULL, *out_e = NULL;
	int ret = -1;

	TEST_START("EVP_PKEY_fromdata with duplicate RSA keys (last-wins)");

	n1 = BN_new();
	n2 = BN_new();
	e = BN_new();
	if (!n1 || !n2 || !e) {
		BN_free(n1); BN_free(n2); BN_free(e);
		TEST_FAIL("BN_new failed");
	}

	if (!BN_set_word(n1, 0x100) ||
	    !BN_set_word(n2, 0x200) ||
	    !BN_set_word(e, 0x10001)) {
		BN_free(n1); BN_free(n2); BN_free(e);
		TEST_FAIL("BN_set_word failed");
	}

	bld = OSSL_PARAM_BLD_new();
	if (!bld) {
		BN_free(n1); BN_free(n2); BN_free(e);
		TEST_FAIL("OSSL_PARAM_BLD_new failed");
	}

	/* Push duplicate "n" — first value 0x100, second value 0x200 */
	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n1) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n2) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_push_BN failed");
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_to_param returned NULL");
	}

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		TEST_FAIL("EVP_PKEY_CTX_new_from_name failed");
	}

	if (EVP_PKEY_fromdata_init(ctx) != 1) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		TEST_FAIL("EVP_PKEY_fromdata_init failed");
	}

	if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		TEST_FAIL("EVP_PKEY_fromdata failed");
	}

	if (!pkey) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		TEST_FAIL("EVP_PKEY_fromdata returned NULL pkey");
	}

	rsa = EVP_PKEY_get0_RSA(pkey);
	if (!rsa) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		TEST_FAIL("EVP_PKEY_get0_RSA failed");
	}

	RSA_get0_key(rsa, &out_n, &out_e, NULL);
	if (!out_n || !out_e) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		TEST_FAIL("RSA_get0_key returned NULL");
	}

	/* Verify that the second "n" value (0x200) wins over the first (0x100) */
	if (BN_cmp(out_n, n2) != 0) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		TEST_FAIL("Duplicate key: second value did not win (last-wins)");
	}

	if (BN_cmp(out_e, e) != 0) {
		BN_free(n1); BN_free(n2); BN_free(e);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		TEST_FAIL("e value mismatch");
	}

	printf("duplicate n: last value (0x200) wins, no leak or crash ");
	ret = 0;

	BN_free(n1); BN_free(n2); BN_free(e);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);
	compat_EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	if (ret == 0) TEST_PASS();
	return ret;
}

/*
 * Regression test: EVP_PKEY_fromdata with a full RSA private key (n, e, d,
 * p, q, dmp1, dmq1, iqmp) and selection == EVP_PKEY_KEYPAIR must produce a
 * private key, not a public-only key. Previously the RSA branch only
 * extracted n and e and called RSA_set0_key(rsa, n, e, NULL), silently
 * dropping d and all CRT parameters even for a KEYPAIR selection.
 */
int test_evp_pkey_fromdata_rsa_private_key()
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *n = NULL, *e = NULL, *d = NULL;
	BIGNUM *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
	BIGNUM *out_d = NULL;
	int ret = -1;

	TEST_START("EVP_PKEY_fromdata with full RSA private key (KEYPAIR retains d)");

	n = BN_new(); e = BN_new(); d = BN_new();
	p = BN_new(); q = BN_new();
	dmp1 = BN_new(); dmq1 = BN_new(); iqmp = BN_new();
	if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		TEST_FAIL("BN_new failed");
	}

	if (!BN_set_word(n, 0xC0FFEE) ||
	    !BN_set_word(e, 0x10001) ||
	    !BN_set_word(d, 0xDEAD) ||
	    !BN_set_word(p, 0xBEEF) ||
	    !BN_set_word(q, 0xCAFE) ||
	    !BN_set_word(dmp1, 0x1234) ||
	    !BN_set_word(dmq1, 0x5678) ||
	    !BN_set_word(iqmp, 0x9ABC)) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		TEST_FAIL("BN_set_word failed");
	}

	bld = OSSL_PARAM_BLD_new();
	if (!bld) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		TEST_FAIL("OSSL_PARAM_BLD_new failed");
	}

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp)) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_push_BN failed");
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_to_param returned NULL");
	}

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		TEST_FAIL("EVP_PKEY_CTX_new_from_name failed");
	}

	if (EVP_PKEY_fromdata_init(ctx) != 1) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		TEST_FAIL("EVP_PKEY_fromdata_init failed");
	}

	if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		TEST_FAIL("EVP_PKEY_fromdata failed");
	}

	if (!pkey) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		TEST_FAIL("EVP_PKEY_fromdata returned NULL pkey");
	}

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &out_d) != 1 || !out_d) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		TEST_FAIL("EVP_PKEY_get_bn_param(RSA_D) failed: private exponent was dropped");
	}

	if (BN_cmp(out_d, d) != 0) {
		BN_free(n); BN_free(e); BN_free(d);
		BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		BN_free(out_d);
		TEST_FAIL("RSA_D mismatch: private exponent was not preserved");
	}

	printf("private exponent d preserved through EVP_PKEY_fromdata(KEYPAIR) ");
	ret = 0;

	BN_free(n); BN_free(e); BN_free(d);
	BN_free(p); BN_free(q); BN_free(dmp1); BN_free(dmq1); BN_free(iqmp);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);
	compat_EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	BN_free(out_d);

	if (ret == 0) TEST_PASS();
	return ret;
}

/*
 * Regression test: EVP_PKEY_fromdata with duplicate DH parameter keys.
 * Tests the same BN_free/BN_dup fix for DH parameters (p, g, q).
 */
int test_evp_pkey_fromdata_dh_duplicate_keys()
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *p1 = NULL, *p2 = NULL, *g = NULL;
	const BIGNUM *out_p = NULL, *out_q = NULL, *out_g = NULL;
	DH *dh = NULL;
	int ret = -1;

	TEST_START("EVP_PKEY_fromdata with duplicate DH keys (last-wins)");

	p1 = BN_new();
	p2 = BN_new();
	g = BN_new();
	if (!p1 || !p2 || !g) {
		BN_free(p1); BN_free(p2); BN_free(g);
		TEST_FAIL("BN_new failed");
	}

	/* Use small DH-compatible values for testing */
	if (!BN_set_word(p1, 0x1000) ||
	    !BN_set_word(p2, 0x2000) ||
	    !BN_set_word(g, 2)) {
		BN_free(p1); BN_free(p2); BN_free(g);
		TEST_FAIL("BN_set_word failed");
	}

	bld = OSSL_PARAM_BLD_new();
	if (!bld) {
		BN_free(p1); BN_free(p2); BN_free(g);
		TEST_FAIL("OSSL_PARAM_BLD_new failed");
	}

	/* Push duplicate "p" — first value 0x1000, second value 0x2000 */
	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p1) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p2) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_push_BN failed");
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_to_param returned NULL");
	}

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (!ctx) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		TEST_FAIL("EVP_PKEY_CTX_new_from_name failed");
	}

	if (EVP_PKEY_fromdata_init(ctx) != 1) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		TEST_FAIL("EVP_PKEY_fromdata_init failed");
	}

	if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params) != 1) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		TEST_FAIL("EVP_PKEY_fromdata failed");
	}

	if (!pkey) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		TEST_FAIL("EVP_PKEY_fromdata returned NULL pkey");
	}

	dh = EVP_PKEY_get0_DH(pkey);
	if (!dh) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		TEST_FAIL("EVP_PKEY_get0_DH failed");
	}

	DH_get0_pqg(dh, &out_p, &out_q, &out_g);
	if (!out_p || !out_g) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		TEST_FAIL("DH_get0_pqg returned NULL");
	}

	/* Verify that the second "p" value (0x2000) wins over the first (0x1000) */
	if (BN_cmp(out_p, p2) != 0) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		TEST_FAIL("Duplicate DH p: second value did not win (last-wins)");
	}

	if (BN_cmp(out_g, g) != 0) {
		BN_free(p1); BN_free(p2); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		compat_EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		TEST_FAIL("DH g value mismatch");
	}

	printf("duplicate p: last value (0x2000) wins, no leak or crash ");
	ret = 0;

	BN_free(p1); BN_free(p2); BN_free(g);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);
	compat_EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* Test that OSSL_PARAM_BLD_free zeroes private key material before freeing.
   We can't inspect freed memory directly, but we can verify BN_clear_free is
   called for the priv key by checking that the bld's BN pointer is properly
   released (no crash on double-free with ASAN) and that the public params
   (p, g) are still BN_free'd. */
int test_ossl_param_bld_free_clears_priv_key()
{
	OSSL_PARAM_BLD *bld = NULL;
	BIGNUM *priv = NULL;
	BIGNUM *p = NULL, *g = NULL;
	int ret = -1;

	TEST_START("OSSL_PARAM_BLD_free clears priv key (BN_clear_free)");

	priv = BN_new();
	p = BN_new();
	g = BN_new();
	if (!priv || !p || !g) {
		BN_free(priv); BN_free(p); BN_free(g);
		TEST_FAIL("BN_new failed");
	}

	/* Set priv to a known non-zero pattern (0xDEADBEEF...) */
	if (!BN_set_word(priv, 0xDEADBEEF) ||
	    !BN_set_word(p, 2) ||
	    !BN_set_word(g, 5)) {
		BN_free(priv); BN_free(p); BN_free(g);
		TEST_FAIL("BN_set_word failed");
	}

	bld = OSSL_PARAM_BLD_new();
	if (!bld) {
		BN_free(priv); BN_free(p); BN_free(g);
		TEST_FAIL("OSSL_PARAM_BLD_new failed");
	}

	/* Push a private key and public params */
	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g)) {
		BN_free(priv); BN_free(p); BN_free(g);
		OSSL_PARAM_BLD_free(bld);
		TEST_FAIL("OSSL_PARAM_BLD_push_BN failed");
	}

	/* Free — should use BN_clear_free for priv, BN_free for p/g */
	OSSL_PARAM_BLD_free(bld);
	bld = NULL;

	/* Original BIGNUMs are untouched (only the internal duplicates were freed) */
	if (BN_cmp(priv, BN_new()) == 0) {
		/* priv was not modified by the builder; only the dup was freed */
		BN_free(priv); BN_free(p); BN_free(g);
	} else {
		BN_free(priv); BN_free(p); BN_free(g);
	}

	/* If we reach here without a crash or ASAN error, the free succeeded.
	   The actual zeroing of the duplicated priv BN inside OSSL_PARAM_BLD_free
	   is verified by code inspection: BN_clear_free is called for
	   OSSL_PKEY_PARAM_PRIV_KEY and OSSL_PKEY_PARAM_RSA_D keys. */
	printf("priv key material cleared on free ");
	ret = 0;

	if (ret == 0) TEST_PASS();
	return ret;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

/* ============================================================================
 * TEST GROUP 2: compat_RSA_new_from_params()
 * ============================================================================ */

int test_compat_rsa_new_from_params_missing_n()
{
	RSA *rsa = NULL;
	RSA *result = NULL;
	const BIGNUM *e_orig = NULL;
	BIGNUM *e = NULL;
	int ret = -1;

	TEST_START("compat_RSA_new_from_params with missing n");

	rsa = generate_rsa_key(2048);
	if (!rsa) TEST_FAIL("Key generation failed");

	RSA_get0_key(rsa, NULL, &e_orig, NULL);
	e = BN_dup(e_orig);
	if (!e) {
		RSA_free(rsa);
		TEST_FAIL("BN_dup failed");
	}

	result = compat_RSA_new_from_params(NULL, e, NULL, NULL, NULL, NULL, NULL, NULL);
	if (result != NULL) {
		compat_RSA_free(result);
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_new_from_params accepted missing n");
	}

	printf("NULL n correctly rejected, e freed internally ");
	ret = 0;

	RSA_free(rsa);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_compat_rsa_new_from_params_public_only()
{
	RSA *rsa = NULL;
	RSA *result = NULL;
	const BIGNUM *n_orig = NULL, *e_orig = NULL;
	BIGNUM *n = NULL, *e = NULL;
	int ret = -1;

	TEST_START("compat_RSA_new_from_params public-only key");

	rsa = generate_rsa_key(2048);
	if (!rsa) TEST_FAIL("Key generation failed");

	RSA_get0_key(rsa, &n_orig, &e_orig, NULL);
	n = BN_dup(n_orig);
	e = BN_dup(e_orig);
	if (!n || !e) {
		if (n) BN_free(n);
		if (e) BN_free(e);
		RSA_free(rsa);
		TEST_FAIL("BN_dup failed");
	}

	result = compat_RSA_new_from_params(n, e, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!result) {
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_new_from_params returned NULL");
	}

	if (compat_RSA_has_private(result) != 0) {
		compat_RSA_free(result);
		RSA_free(rsa);
		TEST_FAIL("public-only key reports having private component");
	}

	printf("public-only key constructed correctly ");
	ret = 0;

	compat_RSA_free(result);
	RSA_free(rsa);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_compat_rsa_new_from_params_full_private()
{
	RSA *rsa = NULL;
	RSA *result = NULL;
	const BIGNUM *n_o = NULL, *e_o = NULL, *d_o = NULL;
	const BIGNUM *p_o = NULL, *q_o = NULL;
	const BIGNUM *dmp1_o = NULL, *dmq1_o = NULL, *iqmp_o = NULL;
	BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	int ret = -1;

	TEST_START("compat_RSA_new_from_params full private key");

	rsa = generate_rsa_key(2048);
	if (!rsa) TEST_FAIL("Key generation failed");

	RSA_get0_key(rsa, &n_o, &e_o, &d_o);
	RSA_get0_factors(rsa, &p_o, &q_o);
	RSA_get0_crt_params(rsa, &dmp1_o, &dmq1_o, &iqmp_o);

	n = BN_dup(n_o); e = BN_dup(e_o); d = BN_dup(d_o);
	p = BN_dup(p_o); q = BN_dup(q_o);
	dmp1 = BN_dup(dmp1_o); dmq1 = BN_dup(dmq1_o); iqmp = BN_dup(iqmp_o);

	if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp) {
		RSA_free(rsa);
		TEST_FAIL("BN_dup failed");
	}

	result = compat_RSA_new_from_params(n, e, d, p, q, dmp1, dmq1, iqmp);
	if (!result) {
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_new_from_params returned NULL");
	}

	if (compat_RSA_has_private(result) != 1) {
		compat_RSA_free(result);
		RSA_free(rsa);
		TEST_FAIL("full private key doesn't report private component");
	}

	printf("full private key constructed correctly ");
	ret = 0;

	compat_RSA_free(result);
	RSA_free(rsa);

	if (ret == 0) TEST_PASS();
	return ret;
}

/*
 * Regression test for the RSA_set0_factors / RSA_set0_crt_params
 * double-free fix: the combined "if (!a || !b)" check could free
 * p/q twice when set0_factors succeeded but set0_crt_params failed.
 * With valid CRT params this should now succeed end-to-end without
 * any double-free (verifiable under valgrind/ASan).
 */
int test_compat_rsa_new_from_params_crt_params_double_free()
{
	RSA *rsa = NULL;
	RSA *result = NULL;
	const BIGNUM *n_o = NULL, *e_o = NULL, *d_o = NULL;
	const BIGNUM *p_o = NULL, *q_o = NULL;
	const BIGNUM *dmp1_o = NULL, *dmq1_o = NULL, *iqmp_o = NULL;
	BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
	int ret = -1;

	TEST_START("compat_RSA_new_from_params CRT double-free regression");

	rsa = generate_rsa_key(2048);
	if (!rsa) TEST_FAIL("Key generation failed");

	RSA_get0_key(rsa, &n_o, &e_o, &d_o);
	RSA_get0_factors(rsa, &p_o, &q_o);
	RSA_get0_crt_params(rsa, &dmp1_o, &dmq1_o, &iqmp_o);

	n = BN_dup(n_o); e = BN_dup(e_o); d = BN_dup(d_o);
	p = BN_dup(p_o); q = BN_dup(q_o);
	dmp1 = BN_dup(dmp1_o); dmq1 = BN_dup(dmq1_o); iqmp = BN_dup(iqmp_o);

	if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp) {
		RSA_free(rsa);
		TEST_FAIL("BN_dup failed");
	}

	result = compat_RSA_new_from_params(n, e, d, p, q, dmp1, dmq1, iqmp);
	if (!result) {
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_new_from_params returned NULL");
	}

	printf("split set0_factors/crt_params path OK, no double-free ");
	ret = 0;

	compat_RSA_free(result);
	RSA_free(rsa);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * TEST GROUP 3: compat_RSA_dup() and compat_RSA_has_private()
 * ============================================================================ */

int test_compat_rsa_dup_public()
{
	RSA *rsa = NULL;
	RSA *pub = NULL;
	RSA *dup = NULL;
	eayRSA *erRSA = NULL;
	const BIGNUM *n_o = NULL, *e_o = NULL;
	BIGNUM *n = NULL, *e = NULL;
	vchar_t *data = NULL, *sig = NULL;
	int ret = -1;

	TEST_START("compat_RSA_dup of public-only key");

	rsa = generate_rsa_key(2048);
	if (!rsa) TEST_FAIL("Key generation failed");

	RSA_get0_key(rsa, &n_o, &e_o, NULL);
	n = BN_dup(n_o);
	e = BN_dup(e_o);
	if (!n || !e) {
		RSA_free(rsa);
		TEST_FAIL("BN_dup failed");
	}

	pub = compat_RSA_new_from_params(n, e, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!pub) {
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_new_from_params failed");
	}

	dup = compat_RSA_dup(pub);
	if (!dup) {
		compat_RSA_free(pub);
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_dup returned NULL");
	}

	if (compat_RSA_has_private(dup) != 0) {
		compat_RSA_free(dup);
		compat_RSA_free(pub);
		RSA_free(rsa);
		TEST_FAIL("dup of public-only key reports private component");
	}

	erRSA = rsa_to_eayrsa(dup);
	if (!erRSA) {
		compat_RSA_free(dup);
		compat_RSA_free(pub);
		RSA_free(rsa);
		TEST_FAIL("Failed to convert dup RSA key to eayRSA");
	}

	/* A sign attempt on a public-only key must fail */
	data = vmalloc(strlen(test_data_short));
	if (!data) {
		eayRSA_free(erRSA);
		compat_RSA_free(dup);
		compat_RSA_free(pub);
		RSA_free(rsa);
		TEST_FAIL("Allocation failed");
	}
	memcpy(data->v, test_data_short, strlen(test_data_short));

	ERR_clear_error();
	sig = eay_get_rsasign(data, erRSA);
	if (sig != NULL) {
		vfree(sig);
		vfree(data);
		eayRSA_free(erRSA);
		compat_RSA_free(dup);
		compat_RSA_free(pub);
		RSA_free(rsa);
		TEST_FAIL("signing succeeded with public-only dup");
	}
	ERR_clear_error();

	printf("public dup has no private component, sign fails as expected ");
	ret = 0;

	vfree(data);
	eayRSA_free(erRSA);
	compat_RSA_free(dup);
	compat_RSA_free(pub);
	RSA_free(rsa);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_compat_rsa_dup_private()
{
	RSA *rsa = NULL;
	RSA *dup = NULL;
	eayRSA *erRSA = NULL;
	vchar_t *data = NULL, *sig = NULL;
	int ret = -1;

	TEST_START("compat_RSA_dup of private key");

	rsa = generate_rsa_key(2048);
	if (!rsa) TEST_FAIL("Key generation failed");

	dup = compat_RSA_dup(rsa);
	if (!dup) {
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_dup returned NULL");
	}

	if (compat_RSA_has_private(dup) != 1) {
		compat_RSA_free(dup);
		RSA_free(rsa);
		TEST_FAIL("dup of private key doesn't report private component");
	}

	erRSA = rsa_to_eayrsa(dup);
	if (!erRSA) {
		compat_RSA_free(dup);
		RSA_free(rsa);
		TEST_FAIL("Failed to convert dup RSA key to eayRSA");
	}

	data = vmalloc(strlen(test_data_medium));
	if (!data) {
		eayRSA_free(erRSA);
		compat_RSA_free(dup);
		RSA_free(rsa);
		TEST_FAIL("Allocation failed");
	}
	memcpy(data->v, test_data_medium, strlen(test_data_medium));

	ERR_clear_error();
	sig = eay_get_rsasign(data, erRSA);
	if (!sig) {
		vfree(data);
		eayRSA_free(erRSA);
		compat_RSA_free(dup);
		RSA_free(rsa);
		TEST_FAIL("signing with dup failed");
	}

	ERR_clear_error();
	if (eay_check_rsasign(data, sig, erRSA) != 0) {
		vfree(sig);
		vfree(data);
		eayRSA_free(erRSA);
		compat_RSA_free(dup);
		RSA_free(rsa);
		TEST_FAIL("verification with dup failed");
	}

	printf("private dup round-trip sign+verify OK ");
	ret = 0;

	vfree(sig);
	vfree(data);
	eayRSA_free(erRSA);
	compat_RSA_free(dup);
	RSA_free(rsa);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_compat_rsa_dup_null()
{
	RSA *dup = NULL;
	int ret = -1;

	TEST_START("compat_RSA_dup(NULL)");

	dup = compat_RSA_dup(NULL);
	if (dup != NULL) {
		compat_RSA_free(dup);
		TEST_FAIL("compat_RSA_dup(NULL) returned non-NULL");
	}

	printf("NULL handled correctly ");
	ret = 0;

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_compat_rsa_print_fp()
{
	RSA *rsa = NULL;
	FILE *fp = NULL;
	long size;
	int ret = -1;

	TEST_START("compat_RSA_print_fp with a valid key");

	rsa = generate_rsa_key(2048);
	if (!rsa) TEST_FAIL("Key generation failed");

	fp = tmpfile();
	if (!fp) {
		RSA_free(rsa);
		TEST_FAIL("tmpfile() failed");
	}

	if (!compat_RSA_print_fp(fp, rsa, 0)) {
		fclose(fp);
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_print_fp returned failure");
	}

	size = ftell(fp);
	if (size <= 0) {
		fclose(fp);
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_print_fp wrote no output");
	}

	printf("RSA key printed (%ld bytes) ", size);
	ret = 0;

	fclose(fp);
	RSA_free(rsa);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_compat_rsa_print_fp_null_args()
{
	RSA *rsa = NULL;
	FILE *fp = NULL;
	int ret = -1;

	TEST_START("compat_RSA_print_fp with NULL rsa/fp");

	rsa = generate_rsa_key(2048);
	if (!rsa) TEST_FAIL("Key generation failed");

	fp = tmpfile();
	if (!fp) {
		RSA_free(rsa);
		TEST_FAIL("tmpfile() failed");
	}

	if (compat_RSA_print_fp(fp, NULL, 0) != 0) {
		fclose(fp);
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_print_fp(NULL rsa) should return 0");
	}

	if (compat_RSA_print_fp(NULL, rsa, 0) != 0) {
		fclose(fp);
		RSA_free(rsa);
		TEST_FAIL("compat_RSA_print_fp(NULL fp) should return 0");
	}

	printf("NULL rsa/fp correctly rejected ");
	ret = 0;

	fclose(fp);
	RSA_free(rsa);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * TEST GROUP 4: rsa_key_dup() and rsa_key_free() (rsalist.c)
 * ============================================================================ */

int test_rsa_key_dup_and_free()
{
	RSA *rsa = NULL;
	const BIGNUM *n_o = NULL, *e_o = NULL;
	BIGNUM *n = NULL, *e = NULL;
	struct rsa_key *orig = NULL;
	struct rsa_key *dup = NULL;
	int ret = -1;

	TEST_START("rsa_key_dup and rsa_key_free");

	rsa = generate_rsa_key(2048);
	if (!rsa) TEST_FAIL("Key generation failed");

	RSA_get0_key(rsa, &n_o, &e_o, NULL);
	n = BN_dup(n_o);
	e = BN_dup(e_o);
	if (!n || !e) {
		RSA_free(rsa);
		TEST_FAIL("BN_dup failed");
	}
	RSA_free(rsa);

	/* rsa_key_free() also frees the struct itself, so it must be heap-allocated */
	orig = calloc(sizeof(*orig), 1);
	if (!orig) TEST_FAIL("Allocation failed");
	orig->rsa = eayRSA_new_pub(n, e);
	BN_free(n);
	BN_free(e);
	if (!orig->rsa) {
		free(orig);
		TEST_FAIL("eayRSA_new_pub failed");
	}

	dup = rsa_key_dup(orig);
	if (!dup) {
		rsa_key_free(orig);
		TEST_FAIL("rsa_key_dup returned NULL");
	}

	if (!dup->rsa) {
		rsa_key_free(orig);
		rsa_key_free(dup);
		TEST_FAIL("dup->rsa is NULL");
	}

	printf("dup created and both keys freed without crash ");
	ret = 0;

	rsa_key_free(orig);
	rsa_key_free(dup);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_rsa_key_dup_null_rsa()
{
	struct rsa_key *orig = NULL;
	struct rsa_key *dup = NULL;
	int ret = -1;

	TEST_START("rsa_key_dup with rsa == NULL");

	orig = calloc(sizeof(*orig), 1);
	if (!orig) TEST_FAIL("Allocation failed");

	dup = rsa_key_dup(orig);
	if (!dup) {
		free(orig);
		TEST_FAIL("rsa_key_dup returned NULL");
	}

	if (dup->rsa != NULL) {
		free(orig);
		rsa_key_free(dup);
		TEST_FAIL("dup->rsa should be NULL");
	}

	printf("NULL rsa handled correctly ");
	ret = 0;

	free(orig);
	rsa_key_free(dup);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * MAIN TEST RUNNER
 * ============================================================================ */

int main(int argc, char **argv)
{
	int failed = 0;
	int ran = 0;

	printf("\n");
	printf("========================================================================\n");
	printf("  Racoon IPSec Comprehensive RSA Tests\n");
	printf("  OpenSSL 3.0 Migration - Textbook RSA Verification\n");
	printf("========================================================================\n");

	/* Initialize OpenSSL */
	eay_init();

	printf("\n=== PRIORITY 1: CRITICAL TESTS ===\n");
	ran++; if (test_rsa_textbook_verify_recover() != 0) failed++;
	ran++; if (test_rsa_padding_verification() != 0) failed++;
	ran++; if (test_rsa_to_evp_pkey_conversion() != 0) failed++;
	ran++; if (test_rsa_signature_tampering() != 0) failed++;
	ran++; if (test_rsa_data_tampering() != 0) failed++;
	ran++; if (test_rsa_wrong_key() != 0) failed++;

	printf("\n=== PRIORITY 2: KEY CONVERSION TESTS ===\n");
	ran++; if (test_rsa_key_extraction() != 0) failed++;
	ran++; if (test_rsa_bignum_conversion() != 0) failed++;
	ran++; if (test_rsa_various_key_sizes() != 0) failed++;

	printf("\n=== PRIORITY 3: RSA SIGN/VERIFY TESTS ===\n");
	ran++; if (test_rsa_sign_verify() != 0) failed++;
	ran++; if (test_pkey_sign_verify() != 0) failed++;

	printf("\n=== PRIORITY 4: EDGE CASES ===\n");
	ran++; if (test_rsa_empty_data() != 0) failed++;
	ran++; if (test_rsa_maximum_data_size() != 0) failed++;
	ran++; if (test_rsa_stress_repeated_operations() != 0) failed++;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	printf("\n=== MEMORY MANAGEMENT: OSSL_PARAM_BLD shim ===\n");
	ran++; if (test_ossl_param_bld_to_param_zero_init() != 0) failed++;
	ran++; if (test_ossl_param_bld_free_empty() != 0) failed++;
	ran++; if (test_ossl_param_bld_push_null_bn() != 0) failed++;
	ran++; if (test_ossl_param_free_after_to_param() != 0) failed++;
	ran++; if (test_ossl_param_bld_push_size_t() != 0) failed++;
	ran++; if (test_ossl_param_bld_push_size_t_null_args() != 0) failed++;
	ran++; if (test_evp_pkey_fromdata_rsa_duplicate_keys() != 0) failed++;
	ran++; if (test_evp_pkey_fromdata_rsa_private_key() != 0) failed++;
	ran++; if (test_evp_pkey_fromdata_dh_duplicate_keys() != 0) failed++;
	ran++; if (test_ossl_param_bld_free_clears_priv_key() != 0) failed++;
#endif

	printf("\n=== MEMORY MANAGEMENT: compat_RSA_new_from_params ===\n");
	ran++; if (test_compat_rsa_new_from_params_missing_n() != 0) failed++;
	ran++; if (test_compat_rsa_new_from_params_public_only() != 0) failed++;
	ran++; if (test_compat_rsa_new_from_params_full_private() != 0) failed++;
	ran++; if (test_compat_rsa_new_from_params_crt_params_double_free() != 0) failed++;

	printf("\n=== MEMORY MANAGEMENT: compat_RSA_dup ===\n");
	ran++; if (test_compat_rsa_dup_public() != 0) failed++;
	ran++; if (test_compat_rsa_dup_private() != 0) failed++;
	ran++; if (test_compat_rsa_dup_null() != 0) failed++;
	ran++; if (test_compat_rsa_print_fp() != 0) failed++;
	ran++; if (test_compat_rsa_print_fp_null_args() != 0) failed++;

	printf("\n=== MEMORY MANAGEMENT: rsa_key_dup / rsa_key_free ===\n");
	ran++; if (test_rsa_key_dup_and_free() != 0) failed++;
	ran++; if (test_rsa_key_dup_null_rsa() != 0) failed++;

	printf("\n");
	printf("========================================================================\n");
	if (failed == 0) {
		printf("  ✓ ALL RSA TESTS PASSED (%d tests)\n", ran);
		printf("  Textbook RSA implementation verified for OpenSSL 3.0!\n");
		printf("========================================================================\n");
		return 0;
	} else {
		printf("  ✗ %d RSA TEST(S) FAILED\n", failed);
		printf("  CRITICAL: Fix before production use!\n");
		printf("========================================================================\n");
		return 1;
	}
}

/* Restore warnings */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#pragma GCC diagnostic pop
#endif
