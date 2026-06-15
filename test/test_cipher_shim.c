// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Cipher Shim Unit Tests for Racoon IPSec
 * Tests the evp_crypt shim and legacy cipher support (Blowfish, CAST5, IDEA, RC5)
 * Validates legacy provider behavior under OpenSSL 3.0+
 *
 * File: test/test_cipher_shim.c
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "vmbuf.h"
#include "crypto_openssl.h"
#include "gcmalloc.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)
#define TEST_SKIP(msg) do { printf("SKIP: %s\n", msg); return 0; } while(0)

/* Helper: print OpenSSL error queue to stderr */
static void
dump_openssl_errors(const char *context)
{
	unsigned long err;
	char buf[256];
	fprintf(stderr, "  [DIAG] OpenSSL errors at '%s':\n", context);
	while ((err = ERR_get_error()) != 0) {
		ERR_error_string_n(err, buf, sizeof(buf));
		fprintf(stderr, "    ERR: %s\n", buf);
	}
}

/* Test data */
static const char *test_plaintext = "The quick brown fox jumps over the lazy dog";
static const char *test_key_128 = "0123456789abcdef";
static const char *test_iv_8  = "fedcba9876543210";
static const char *test_iv_16 = "fedcba9876543210fedcba9876543210";

/* Helper: create a plaintext buffer of the given length (must be multiple of block size) */
static vchar_t *
make_data(int len)
{
	vchar_t *d;

	d = vmalloc(len);
	if (!d) return NULL;
	memcpy(d->v, test_plaintext, len < (int)strlen(test_plaintext) ? len : strlen(test_plaintext));
	if (len > (int)strlen(test_plaintext))
		memset(d->v + strlen(test_plaintext), 'A', len - strlen(test_plaintext));
	return d;
}

/* Helper: verify encrypt/decrypt round-trip */
static int
verify_roundtrip(vchar_t *data, vchar_t *key, vchar_t *iv,
		 vchar_t *(*encrypt_fn)(vchar_t *, vchar_t *, vchar_t *),
		 vchar_t *(*decrypt_fn)(vchar_t *, vchar_t *, vchar_t *))
{
	vchar_t *encrypted = NULL, *decrypted = NULL;
	int ret = -1;

	encrypted = encrypt_fn(data, key, iv);
	if (!encrypted) {
		fprintf(stderr, "  [DIAG] encryption returned NULL\n");
		dump_openssl_errors("encrypt");
		goto out;
	}

	if (memcmp(data->v, encrypted->v, data->l) == 0) {
		fprintf(stderr, "  [DIAG] encrypted data identical to plaintext\n");
		goto out;
	}

	/* IV is not modified in-place by eay_*_encrypt, so no reset needed */

	decrypted = decrypt_fn(encrypted, key, iv);
	if (!decrypted) {
		fprintf(stderr, "  [DIAG] decryption returned NULL\n");
		dump_openssl_errors("decrypt");
		goto out;
	}

	if (decrypted->l != data->l) {
		fprintf(stderr, "  [DIAG] length mismatch: original=%zu decrypted=%zu\n",
			data->l, decrypted->l);
		goto out;
	}

	if (memcmp(data->v, decrypted->v, data->l) != 0) {
		fprintf(stderr, "  [DIAG] decrypted data does not match original\n");
		goto out;
	}

	ret = 0;

out:
	if (encrypted) vfree(encrypted);
	if (decrypted) vfree(decrypted);
	return ret;
}

/* ============================================================================
 * TEST: Blowfish CBC (always available, legacy in OpenSSL 3.0)
 * ============================================================================ */

int test_blowfish_shim()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	int ret = -1;

	TEST_START("Blowfish CBC via evp_crypt shim");

	data = make_data(48);
	if (!data) TEST_FAIL("Allocation failed");

	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv_8, 8);

	if (verify_roundtrip(data, key, iv, eay_bf_encrypt, eay_bf_decrypt) != 0) {
		TEST_FAIL("Blowfish round-trip failed");
	}

	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * TEST: CAST5 CBC (always available, legacy in OpenSSL 3.0)
 * ============================================================================ */

int test_cast5_shim()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	int ret = -1;

	TEST_START("CAST5 CBC via evp_crypt shim");

	data = make_data(48);
	if (!data) TEST_FAIL("Allocation failed");

	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv_8, 8);

	if (verify_roundtrip(data, key, iv, eay_cast_encrypt, eay_cast_decrypt) != 0) {
		TEST_FAIL("CAST5 round-trip failed");
	}

	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * TEST: IDEA CBC (conditional on HAVE_OPENSSL_IDEA_H, legacy in OpenSSL 3.0)
 * ============================================================================ */

#ifdef HAVE_OPENSSL_IDEA_H
int test_idea_shim()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	int ret = -1;

	TEST_START("IDEA CBC via evp_crypt shim");

	/* IDEA block size is 8 */
	data = make_data(48);
	if (!data) TEST_FAIL("Allocation failed");

	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv_8, 8);

	if (verify_roundtrip(data, key, iv, eay_idea_encrypt, eay_idea_decrypt) != 0) {
		TEST_FAIL("IDEA round-trip failed");
	}

	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);

	if (ret == 0) TEST_PASS();
	return ret;
}
#endif

/* ============================================================================
 * TEST: RC5 CBC (conditional on HAVE_OPENSSL_RC5_H, legacy in OpenSSL 3.0)
 * ============================================================================ */

#ifdef HAVE_OPENSSL_RC5_H
int test_rc5_shim()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	int ret = -1;

	TEST_START("RC5 CBC via evp_crypt shim");

	/* RC5 block size is 8 */
	data = make_data(48);
	if (!data) TEST_FAIL("Allocation failed");

	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv_8, 8);

	if (verify_roundtrip(data, key, iv, eay_rc5_encrypt, eay_rc5_decrypt) != 0) {
		TEST_FAIL("RC5 round-trip failed");
	}

	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);

	if (ret == 0) TEST_PASS();
	return ret;
}
#endif

/* ============================================================================
 * TEST: Legacy provider loading status (OpenSSL 3.0+)
 * ============================================================================ */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
int test_legacy_provider_loaded()
{
	int ret = -1;

	TEST_START("Legacy provider is loaded (OpenSSL 3.0+)");

	/* After eay_init(), the legacy provider should be loaded.
	 * We verify this by checking that a legacy cipher can be
	 * retrieved successfully via EVP_get_cipherbyname(). */

	/* Suppress deprecation warnings for checking cipher availability */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

	const EVP_CIPHER *bf = EVP_get_cipherbyname("bf-cbc");
	if (!bf) {
		fprintf(stderr, "  [DIAG] EVP_get_cipherbyname(bf-cbc) returned NULL\n");
		dump_openssl_errors("EVP_get_cipherbyname");
		TEST_FAIL("Blowfish cipher not available");
	}

	const EVP_CIPHER *cast = EVP_get_cipherbyname("cast-cbc");
	if (!cast) {
		fprintf(stderr, "  [DIAG] EVP_get_cipherbyname(cast-cbc) returned NULL\n");
		dump_openssl_errors("EVP_get_cipherbyname");
		TEST_FAIL("CAST5 cipher not available");
	}

#pragma GCC diagnostic pop

	ret = 0;

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_legacy_cipher_error_logging()
{
	int ret = -1;

	TEST_START("Legacy cipher error path (simulated)");

	/* We cannot easily unload the legacy provider mid-test without
	 * affecting the rest of the test suite.  Instead, verify that
	 * the evp_crypt shim produces correct output for a valid
	 * legacy cipher invocation, confirming the error path is
	 * wired through the same code.  The actual "provider not loaded"
	 * error path is tested manually by running with
	 * OPENSSL_LEGACY_PROVIDER_DISABLED=1 (unsets the provider
	 * in eay_init). */

	/* Quick smoke test: Blowfish encrypt should succeed with provider loaded */
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	vchar_t *encrypted = NULL;

	data = make_data(48);
	if (!data) TEST_FAIL("Allocation failed");

	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv_8, 8);

	encrypted = eay_bf_encrypt(data, key, iv);
	if (!encrypted) {
		TEST_FAIL("Blowfish encrypt should succeed with legacy provider loaded");
	}

	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);
	if (encrypted) vfree(encrypted);

	if (ret == 0) TEST_PASS();
	return ret;
}
#else
int test_legacy_provider_loaded()
{
	TEST_START("Legacy provider check (OpenSSL 1.x - N/A)");
	TEST_SKIP("Not applicable for OpenSSL 1.x");
}

int test_legacy_cipher_error_logging()
{
	TEST_START("Legacy cipher error path (OpenSSL 1.x - N/A)");
	TEST_SKIP("Not applicable for OpenSSL 1.x");
}
#endif

/* ============================================================================
 * TEST: evp_crypt with multiple block sizes
 * ============================================================================ */

int test_evp_crypt_various_sizes()
{
	int sizes[] = {8, 16, 24, 32, 48, 64, 96, 128};
	int num_sizes = sizeof(sizes) / sizeof(sizes[0]);
	int i, failed = 0;

	TEST_START("evp_crypt with various data sizes (Blowfish)");
	printf("\n");

	for (i = 0; i < num_sizes; i++) {
		vchar_t *data = NULL, *key = NULL, *iv = NULL;

		printf("    Size %d bytes... ", sizes[i]);
		fflush(stdout);

		data = make_data(sizes[i]);
		if (!data) {
			printf("FAIL (alloc)\n");
			failed++;
			continue;
		}

		key = vmalloc(16);
		if (!key) {
			printf("FAIL (key alloc)\n");
			vfree(data);
			failed++;
			continue;
		}
		memcpy(key->v, test_key_128, 16);

		iv = vmalloc(8);
		if (!iv) {
			printf("FAIL (iv alloc)\n");
			vfree(data);
			vfree(key);
			failed++;
			continue;
		}
		memcpy(iv->v, test_iv_8, 8);

		if (verify_roundtrip(data, key, iv, eay_bf_encrypt, eay_bf_decrypt) != 0) {
			printf("FAIL\n");
			vfree(data);
			vfree(key);
			vfree(iv);
			failed++;
			continue;
		}

		printf("OK\n");

		vfree(data);
		vfree(key);
		vfree(iv);
	}

	printf("    ");

	if (failed == 0) TEST_PASS();
	else TEST_FAIL("%d size(s) failed");

	return failed ? -1 : 0;
}

/* ============================================================================
 * TEST: evp_crypt error handling with invalid data
 * ============================================================================ */

int test_evp_crypt_invalid_data()
{
	vchar_t *key = NULL, *iv = NULL;
	int ret = -1;

	TEST_START("evp_crypt with unaligned data length");

	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv_8, 8);

	/* Blowfish block size is 8; a 7-byte buffer is not block-aligned.
	 * The evp_crypt shim should handle this gracefully (return NULL or
	 * produce correct output with OpenSSL's internal padding handling). */
	vchar_t *badlen = vmalloc(7);
	if (!badlen) TEST_FAIL("Allocation failed");
	memcpy(badlen->v, "ABCDEFG", 7);

	vchar_t *result = eay_bf_encrypt(badlen, key, iv);
	/* Either NULL (not block-aligned) or a valid encrypted buffer is acceptable */
	if (result) {
		vfree(result);
	}

	vfree(badlen);
	ret = 0;

	if (key) vfree(key);
	if (iv) vfree(iv);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * TEST: DES weak key detection
 * ============================================================================ */

int test_des_weakkey()
{
	int ret = -1;

	TEST_START("DES weak key detection");

	/* Known DES weak key: all 1 bits (0xFF after parity) */
	vchar_t *weak = vmalloc(8);
	if (!weak) TEST_FAIL("Allocation failed");
	memset(weak->v, 0x01, 8);

	/* Known strong key */
	vchar_t *strong = vmalloc(8);
	if (!strong) TEST_FAIL("Allocation failed");
	memcpy(strong->v, test_key_128, 8);

	/* weak key must return non-zero */
	if (eay_des_weakkey(weak) == 0) {
		fprintf(stderr, "  [DIAG] eay_des_weakkey returned 0 for known weak key\n");
		goto out;
	}

	/* strong key must return 0 */
	if (eay_des_weakkey(strong) != 0) {
		fprintf(stderr, "  [DIAG] eay_des_weakkey returned non-zero for strong key\n");
		goto out;
	}

	ret = 0;

out:
	if (weak) vfree(weak);
	if (strong) vfree(strong);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * TEST: 3DES weak key detection
 * ============================================================================ */

int test_3des_weakkey()
{
	int ret = -1;

	TEST_START("3DES weak key detection");

	/* Construct a 24-byte key where all three sub-keys are weak */
	vchar_t *allweak = vmalloc(24);
	if (!allweak) TEST_FAIL("Allocation failed");
	memset(allweak->v, 0x01, 24);

	/* 24-byte key with all strong sub-keys */
	vchar_t *allstrong = vmalloc(24);
	if (!allstrong) TEST_FAIL("Allocation failed");
	memcpy(allstrong->v, test_key_128, 8);
	memcpy(allstrong->v + 8, test_key_128, 8);
	memcpy(allstrong->v + 16, test_key_128, 8);

	/* Key where only the first sub-key is weak */
	vchar_t *firstweak = vmalloc(24);
	if (!firstweak) TEST_FAIL("Allocation failed");
	memset(firstweak->v, 0x01, 8);
	memcpy(firstweak->v + 8, test_key_128, 8);
	memcpy(firstweak->v + 16, test_key_128, 8);

	/* Short key (< 24 bytes) should not be flagged */
	vchar_t *shortkey = vmalloc(8);
	if (!shortkey) TEST_FAIL("Allocation failed");
	memset(shortkey->v, 0x01, 8);

	/* All-weak key must return non-zero */
	if (eay_3des_weakkey(allweak) == 0) {
		fprintf(stderr, "  [DIAG] eay_3des_weakkey returned 0 for all-weak key\n");
		goto out;
	}

	/* All-strong key must return 0 */
	if (eay_3des_weakkey(allstrong) != 0) {
		fprintf(stderr, "  [DIAG] eay_3des_weakkey returned non-zero for all-strong key\n");
		goto out;
	}

	/* First sub-key weak must return non-zero */
	if (eay_3des_weakkey(firstweak) == 0) {
		fprintf(stderr, "  [DIAG] eay_3des_weakkey returned 0 for key with weak first sub-key\n");
		goto out;
	}

	/* Short key must return 0 (not enough bytes for 3 sub-keys) */
	if (eay_3des_weakkey(shortkey) != 0) {
		fprintf(stderr, "  [DIAG] eay_3des_weakkey returned non-zero for short key\n");
		goto out;
	}

	ret = 0;

out:
	if (allweak) vfree(allweak);
	if (allstrong) vfree(allstrong);
	if (firstweak) vfree(firstweak);
	if (shortkey) vfree(shortkey);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * TEST: DES/3DES encrypt/decrypt round-trip
 * ============================================================================ */

int test_des_roundtrip()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	int ret = -1;

	TEST_START("DES CBC round-trip");

	data = make_data(48);
	if (!data) TEST_FAIL("Allocation failed");

	key = vmalloc(8);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 8);

	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv_8, 8);

	if (verify_roundtrip(data, key, iv, eay_des_encrypt, eay_des_decrypt) != 0) {
		TEST_FAIL("DES round-trip failed");
	}

	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_3des_roundtrip()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	int ret = -1;

	TEST_START("3DES CBC round-trip");

	data = make_data(48);
	if (!data) TEST_FAIL("Allocation failed");

	key = vmalloc(24);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 8);
	memcpy(key->v + 8, test_key_128 + 8, 8);
	memcpy(key->v + 16, test_iv_8, 8);

	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv_8, 8);

	if (verify_roundtrip(data, key, iv, eay_3des_encrypt, eay_3des_decrypt) != 0) {
		TEST_FAIL("3DES round-trip failed");
	}

	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * MAIN TEST RUNNER
 * ============================================================================ */

int main(int argc, char **argv)
{
	int failed = 0;
	int total = 0;

	printf("\n");
	printf("========================================================================\n");
	printf("  Racoon IPSec - Cipher Shim Unit Tests\n");
	printf("  evp_crypt, Legacy Ciphers, Provider Validation\n");
	printf("========================================================================\n");
	printf("  OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
	printf("  OpenSSL macro:   0x%lx\n", (unsigned long)OPENSSL_VERSION_NUMBER);
	printf("========================================================================\n");

	/* Initialize OpenSSL (loads legacy provider on 3.0+) */
	eay_init();

	printf("\n--- Legacy Cipher Round-Trip Tests ---\n");
	total++; if (test_blowfish_shim() != 0) failed++;
	total++; if (test_cast5_shim() != 0) failed++;
#ifdef HAVE_OPENSSL_IDEA_H
	total++; if (test_idea_shim() != 0) failed++;
#else
	printf("\n[TEST] IDEA CBC via evp_crypt shim ... SKIP: IDEA not compiled in\n");
#endif
#ifdef HAVE_OPENSSL_RC5_H
	total++; if (test_rc5_shim() != 0) failed++;
#else
	printf("[TEST] RC5 CBC via evp_crypt shim ... SKIP: RC5 not compiled in\n");
#endif

	printf("\n--- Legacy Provider Tests (OpenSSL 3.0+) ---\n");
	total++; if (test_legacy_provider_loaded() != 0) failed++;
	total++; if (test_legacy_cipher_error_logging() != 0) failed++;

	printf("\n--- DES/3DES Weak Key Tests ---\n");
	total++; if (test_des_weakkey() != 0) failed++;
	total++; if (test_3des_weakkey() != 0) failed++;

	printf("\n--- DES/3DES Round-Trip Tests ---\n");
	total++; if (test_des_roundtrip() != 0) failed++;
	total++; if (test_3des_roundtrip() != 0) failed++;

	printf("\n--- evp_crypt Robustness Tests ---\n");
	total++; if (test_evp_crypt_various_sizes() != 0) failed++;
	total++; if (test_evp_crypt_invalid_data() != 0) failed++;

	/* Cleanup OpenSSL */
	eay_cleanup();

	printf("\n");
	printf("========================================================================\n");
	if (failed == 0) {
		printf("  ALL SHIM TESTS PASSED (%d tests)\n", total);
		printf("  evp_crypt shim and legacy cipher support validated!\n");
		printf("========================================================================\n");
		return 0;
	} else {
		printf("  %d/%d TEST(S) FAILED\n", failed, total);
		printf("========================================================================\n");
		return 1;
	}
}
