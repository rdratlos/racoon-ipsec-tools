// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit test for ISSUE #5: eay_dh_compute undersized buffer handling
 *
 * The function eay_dh_compute() writes the DH shared secret into (*key)->v,
 * right-aligned within a buffer of length prime->l.  The memcpy() at
 * crypto_openssl.c:3200 uses the offset (prime->l - secret_len), so the
 * write extends from that offset up to prime->l.  If the caller allocates
 * a buffer smaller than prime->l, this becomes an out-of-bounds write.
 *
 * This test provokes the condition by passing a deliberately undersized
 * buffer and verifying the function rejects it rather than corrupting memory.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/err.h>
#include <openssl/bn.h>

#include "vmbuf.h"
#include "crypto_openssl.h"
#include "gcmalloc.h"
#include "dhgroup.h"

#define TEST_PASS() printf("✓ PASS\n")
#define TEST_FAIL(msg) do { printf("✗ FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

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

/*
 * hex_prime_to_vchar - convert a spaced hex string to a vchar_t.
 * Copied from test_dh_modp_groups.c (self-contained).
 */
static vchar_t *
hex_prime_to_vchar(const char *hex_with_spaces)
{
	char *clean = NULL;
	size_t src_len, dst_len, i, j;
	BIGNUM *bn = NULL;
	int bn_bytes;
	vchar_t *result = NULL;

	if (!hex_with_spaces)
		return NULL;

	src_len = strlen(hex_with_spaces);
	clean = malloc(src_len + 1);
	if (!clean)
		return NULL;

	j = 0;
	for (i = 0; i < src_len; i++) {
		char c = hex_with_spaces[i];
		if ((c >= '0' && c <= '9') ||
		    (c >= 'a' && c <= 'f') ||
		    (c >= 'A' && c <= 'F')) {
			clean[j++] = c;
		}
	}
	clean[j] = '\0';
	dst_len = j;

	if (dst_len == 0) {
		free(clean);
		return NULL;
	}

	if (BN_hex2bn(&bn, clean) == 0 || bn == NULL) {
		free(clean);
		return NULL;
	}
	free(clean);

	bn_bytes = BN_num_bytes(bn);
	result = vmalloc(bn_bytes);
	if (!result) {
		BN_free(bn);
		return NULL;
	}

	BN_bn2bin(bn, (unsigned char *)result->v);
	BN_free(bn);
	return result;
}

/*
 * TEST 1: Undersized buffer must be rejected
 *
 * Generate two DH key pairs, allocate an output buffer that is SHORTER
 * than prime->l, and call eay_dh_compute().  The function MUST return
 * failure (-1) rather than writing beyond the buffer boundary.
 *
 * With the current buggy code, this test will likely succeed silently
 * (corrupting the guard bytes beyond the buffer) or crash.  After the
 * fix, eay_dh_compute() should detect the mismatch and return -1.
 */
int test_dh_undersized_buffer_rejected()
{
	vchar_t *prime = NULL;
	vchar_t *pub1 = NULL, *priv1 = NULL;
	vchar_t *pub2 = NULL, *priv2 = NULL;
	vchar_t *key = NULL;
	int ret;

	TEST_START("DH undersized buffer rejection (ISSUE #5)");

	/* Use MODP 768 for speed — small enough for quick keygen */
	prime = hex_prime_to_vchar(OAKLEY_PRIME_MODP768);
	if (!prime)
		TEST_FAIL("failed to convert prime");

	fprintf(stderr, "  [DIAG] prime->l = %zu\n", prime->l);

	/* Generate Alice's key pair */
	ERR_clear_error();
	ret = eay_dh_generate(prime, 2, 0, &pub1, &priv1);
	if (ret != 0) {
		dump_openssl_errors("Alice eay_dh_generate");
		vfree(prime);
		TEST_FAIL("Alice keygen failed");
	}

	/* Generate Bob's key pair */
	ERR_clear_error();
	ret = eay_dh_generate(prime, 2, 0, &pub2, &priv2);
	if (ret != 0) {
		dump_openssl_errors("Bob eay_dh_generate");
		vfree(prime); vfree(pub1); vfree(priv1);
		TEST_FAIL("Bob keygen failed");
	}

	/* Allocate undersized buffer: prime->l - 10 bytes */
	size_t undersized_len = prime->l - 10;
	key = vmalloc(undersized_len);
	if (!key) {
		vfree(prime); vfree(pub1); vfree(priv1);
		vfree(pub2); vfree(priv2);
		TEST_FAIL("vmalloc failed");
	}

	fprintf(stderr, "  [DIAG] buffer->l = %zu (prime->l = %zu, short by %zu)\n",
		key->l, prime->l, prime->l - undersized_len);

	/* Fill with guard pattern to detect corruption */
	memset(key->v, 0xAA, key->l);

	/* Call eay_dh_compute with the undersized buffer */
	ERR_clear_error();
	ret = eay_dh_compute(prime, 2, pub1, priv1, pub2, &key);
	fprintf(stderr, "  [DIAG] eay_dh_compute returned %d (expected -1)\n", ret);

	/*
	 * Expected behavior after fix: eay_dh_compute() must detect that
	 * (*key)->l < prime->l and return -1 without touching the buffer.
	 *
	 * Buggy behavior: the function writes at offset (prime->l - secret_len)
	 * within a buffer of only undersized_len bytes, causing OOB write.
	 */
	if (ret == 0) {
		dump_openssl_errors("eay_dh_compute");
		vfree(prime); vfree(pub1); vfree(priv1);
		vfree(pub2); vfree(priv2); vfree(key);
		TEST_FAIL("eay_dh_compute succeeded with undersized buffer (should have rejected it)");
	}

	/* Success: function correctly rejected the undersized buffer */
	vfree(prime); vfree(pub1); vfree(priv1);
	vfree(pub2); vfree(priv2); vfree(key);
	TEST_PASS();
	return 0;
}

/*
 * TEST 2: Zero-length buffer must be rejected
 *
 * Edge case: pass a buffer with l == 0.
 */
int test_dh_zero_length_buffer_rejected()
{
	vchar_t *prime = NULL;
	vchar_t *pub1 = NULL, *priv1 = NULL;
	vchar_t *pub2 = NULL, *priv2 = NULL;
	vchar_t *key = NULL;
	int ret;

	TEST_START("DH zero-length buffer rejection (ISSUE #5 edge case)");

	prime = hex_prime_to_vchar(OAKLEY_PRIME_MODP768);
	if (!prime)
		TEST_FAIL("failed to convert prime");

	ERR_clear_error();
	ret = eay_dh_generate(prime, 2, 0, &pub1, &priv1);
	if (ret != 0) {
		vfree(prime);
		TEST_FAIL("Alice keygen failed");
	}

	ERR_clear_error();
	ret = eay_dh_generate(prime, 2, 0, &pub2, &priv2);
	if (ret != 0) {
		vfree(prime); vfree(pub1); vfree(priv1);
		TEST_FAIL("Bob keygen failed");
	}

	/* Allocate zero-length buffer */
	key = vmalloc(0);
	if (!key) {
		vfree(prime); vfree(pub1); vfree(priv1);
		vfree(pub2); vfree(priv2);
		TEST_FAIL("vmalloc(0) failed");
	}

	ERR_clear_error();
	ret = eay_dh_compute(prime, 2, pub1, priv1, pub2, &key);
	fprintf(stderr, "  [DIAG] eay_dh_compute returned %d (expected -1)\n", ret);

	if (ret == 0) {
		vfree(prime); vfree(pub1); vfree(priv1);
		vfree(pub2); vfree(priv2); vfree(key);
		TEST_FAIL("eay_dh_compute succeeded with zero-length buffer");
	}

	vfree(prime); vfree(pub1); vfree(priv1);
	vfree(pub2); vfree(priv2); vfree(key);
	TEST_PASS();
	return 0;
}

/*
 * TEST 3: Exact-size buffer must succeed (regression check)
 *
 * Verify that the fix does not break the normal path: a buffer of exactly
 * prime->l bytes must still work correctly.
 */
int test_dh_exact_buffer_succeeds()
{
	vchar_t *prime = NULL;
	vchar_t *pub1 = NULL, *priv1 = NULL;
	vchar_t *pub2 = NULL, *priv2 = NULL;
	vchar_t *key1 = NULL, *key2 = NULL;
	int ret;

	TEST_START("DH exact-size buffer (regression check)");

	prime = hex_prime_to_vchar(OAKLEY_PRIME_MODP768);
	if (!prime)
		TEST_FAIL("failed to convert prime");

	ERR_clear_error();
	ret = eay_dh_generate(prime, 2, 0, &pub1, &priv1);
	if (ret != 0) {
		vfree(prime);
		TEST_FAIL("Alice keygen failed");
	}

	ERR_clear_error();
	ret = eay_dh_generate(prime, 2, 0, &pub2, &priv2);
	if (ret != 0) {
		vfree(prime); vfree(pub1); vfree(priv1);
		TEST_FAIL("Bob keygen failed");
	}

	/* Allocate exact-size buffers */
	key1 = vmalloc(prime->l);
	key2 = vmalloc(prime->l);
	if (!key1 || !key2) {
		vfree(prime); vfree(pub1); vfree(priv1);
		vfree(pub2); vfree(priv2);
		vfree(key1); vfree(key2);
		TEST_FAIL("vmalloc failed");
	}

	/* Alice computes shared secret */
	ERR_clear_error();
	ret = eay_dh_compute(prime, 2, pub1, priv1, pub2, &key1);
	if (ret != 0) {
		dump_openssl_errors("Alice eay_dh_compute");
		vfree(prime); vfree(pub1); vfree(priv1);
		vfree(pub2); vfree(priv2); vfree(key1); vfree(key2);
		TEST_FAIL("Alice compute failed (should succeed)");
	}

	/* Bob computes shared secret */
	ERR_clear_error();
	ret = eay_dh_compute(prime, 2, pub2, priv2, pub1, &key2);
	if (ret != 0) {
		dump_openssl_errors("Bob eay_dh_compute");
		vfree(prime); vfree(pub1); vfree(priv1);
		vfree(pub2); vfree(priv2); vfree(key1); vfree(key2);
		TEST_FAIL("Bob compute failed (should succeed)");
	}

	/* Shared secrets must match */
	if (key1->l != key2->l || memcmp(key1->v, key2->v, key1->l) != 0) {
		vfree(prime); vfree(pub1); vfree(priv1);
		vfree(pub2); vfree(priv2); vfree(key1); vfree(key2);
		TEST_FAIL("shared secrets do not match");
	}

	vfree(prime); vfree(pub1); vfree(priv1);
	vfree(pub2); vfree(priv2); vfree(key1); vfree(key2);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== DH Buffer Size Safety Tests (ISSUE #5) ===\n");

	if (test_dh_undersized_buffer_rejected() != 0)
		failed++;
	if (test_dh_zero_length_buffer_rejected() != 0)
		failed++;
	if (test_dh_exact_buffer_succeeds() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}

#pragma GCC diagnostic pop
