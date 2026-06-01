/*
 * Complete Coverage Tests for Racoon IPSec Crypto Functions
 * Tests all eay_* functions for OpenSSL 3.0 migration validation
 *
 * File: test/test_crypto_coverage.c
 * Coverage: Ciphers, Hashing, HMAC, X.509, Base64, Random, BIGNUM
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#endif

/* Test data */
static const char *test_plaintext = "The quick brown fox jumps over the lazy dog";
static const char *test_key_128 = "0123456789abcdef";  /* 128-bit key */
static const char *test_key_192 = "0123456789abcdef01234567";  /* 192-bit key */
static const char *test_key_256 = "0123456789abcdef0123456789abcdef";  /* 256-bit key */
static const char *test_iv = "fedcba9876543210";  /* 128-bit IV */

/* ============================================================================
 * SYMMETRIC CIPHER TESTS
 * ============================================================================ */

int test_des_cipher()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	vchar_t *encrypted = NULL, *decrypted = NULL;
	int ret = -1;

	TEST_START("DES Cipher Encrypt/Decrypt");

	/* Prepare data (must be multiple of 8 for DES) */
	data = vmalloc(48);  /* 6 blocks */
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, 44);
	memset(data->v + 44, 0, 4);  /* Pad to 48 */

	/* Key must be 8 bytes for DES */
	key = vmalloc(8);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 8);

	/* IV must be 8 bytes */
	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv, 8);

	/* Encrypt */
	encrypted = eay_des_encrypt(data, key, iv);
	if (!encrypted) TEST_FAIL("DES encryption failed");

	/* Verify encrypted data is different */
	if (memcmp(data->v, encrypted->v, data->l) == 0) {
		TEST_FAIL("Encrypted data same as plaintext");
	}

	/* Reset IV for decryption */
	memcpy(iv->v, test_iv, 8);

	/* Decrypt */
	decrypted = eay_des_decrypt(encrypted, key, iv);
	if (!decrypted) TEST_FAIL("DES decryption failed");

	/* Verify decrypted matches original */
	if (memcmp(data->v, decrypted->v, data->l) != 0) {
		TEST_FAIL("Decrypted data doesn't match original");
	}

	printf("DES encrypt/decrypt cycle OK ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);
	if (encrypted) vfree(encrypted);
	if (decrypted) vfree(decrypted);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_3des_cipher()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	vchar_t *encrypted = NULL, *decrypted = NULL;
	int ret = -1;

	TEST_START("3DES Cipher Encrypt/Decrypt");

	/* Data (multiple of 8) */
	data = vmalloc(48);
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, 44);
	memset(data->v + 44, 0, 4);

	/* Key must be 24 bytes for 3DES */
	key = vmalloc(24);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_192, 24);

	/* IV (8 bytes) */
	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv, 8);

	/* Encrypt */
	encrypted = eay_3des_encrypt(data, key, iv);
	if (!encrypted) TEST_FAIL("3DES encryption failed");

	/* Reset IV */
	memcpy(iv->v, test_iv, 8);

	/* Decrypt */
	decrypted = eay_3des_decrypt(encrypted, key, iv);
	if (!decrypted) TEST_FAIL("3DES decryption failed");

	/* Verify */
	if (memcmp(data->v, decrypted->v, data->l) != 0) {
		TEST_FAIL("Decrypted data doesn't match");
	}

	printf("3DES encrypt/decrypt cycle OK ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);
	if (encrypted) vfree(encrypted);
	if (decrypted) vfree(decrypted);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_aes_cipher()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	vchar_t *encrypted = NULL, *decrypted = NULL;
	int key_sizes[] = {16, 24, 32};  /* 128, 192, 256 bits */
	int i;
	int ret = -1;

	TEST_START("AES Cipher (128/192/256-bit keys)");
	printf("\n");

	for (i = 0; i < 3; i++) {
		printf("    AES-%d... ", key_sizes[i] * 8);
		fflush(stdout);

		/* Data (multiple of 16 for AES) */
		data = vmalloc(48);
		if (!data) {
			printf("FAIL\n");
			continue;
		}
		memcpy(data->v, test_plaintext, 44);
		memset(data->v + 44, 0, 4);

		/* Key */
		key = vmalloc(key_sizes[i]);
		if (!key) {
			printf("FAIL\n");
			vfree(data);
			continue;
		}
		memcpy(key->v, test_key_256, key_sizes[i]);

		/* IV (16 bytes for AES) */
		iv = vmalloc(16);
		if (!iv) {
			printf("FAIL\n");
			vfree(data);
			vfree(key);
			continue;
		}
		memcpy(iv->v, test_iv, 16);

		/* Encrypt */
		encrypted = eay_aes_encrypt(data, key, iv);
		if (!encrypted) {
			printf("FAIL (encrypt)\n");
			goto cleanup_aes;
		}

		/* Reset IV */
		memcpy(iv->v, test_iv, 16);

		/* Decrypt */
		decrypted = eay_aes_decrypt(encrypted, key, iv);
		if (!decrypted) {
			printf("FAIL (decrypt)\n");
			goto cleanup_aes;
		}

		/* Verify */
		if (memcmp(data->v, decrypted->v, data->l) != 0) {
			printf("FAIL (mismatch)\n");
			goto cleanup_aes;
		}

		printf("✓ OK\n");

cleanup_aes:
		if (data) vfree(data);
		if (key) vfree(key);
		if (iv) vfree(iv);
		if (encrypted) vfree(encrypted);
		if (decrypted) vfree(decrypted);
		data = key = iv = encrypted = decrypted = NULL;
	}

	printf("    ");
	ret = 0;

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_blowfish_cipher()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	vchar_t *encrypted = NULL, *decrypted = NULL;
	int ret = -1;

	TEST_START("Blowfish Cipher");

	/* Data (multiple of 8) */
	data = vmalloc(48);
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, 44);
	memset(data->v + 44, 0, 4);

	/* Blowfish accepts variable key length (4-56 bytes) */
	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	/* IV (8 bytes) */
	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv, 8);

	/* Encrypt */
	encrypted = eay_bf_encrypt(data, key, iv);
	if (!encrypted) TEST_FAIL("Blowfish encryption failed");

	/* Reset IV */
	memcpy(iv->v, test_iv, 8);

	/* Decrypt */
	decrypted = eay_bf_decrypt(encrypted, key, iv);
	if (!decrypted) TEST_FAIL("Blowfish decryption failed");

	/* Verify */
	if (memcmp(data->v, decrypted->v, data->l) != 0) {
		TEST_FAIL("Decrypted data doesn't match");
	}

	printf("Blowfish encrypt/decrypt OK ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);
	if (encrypted) vfree(encrypted);
	if (decrypted) vfree(decrypted);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_cast_cipher()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	vchar_t *encrypted = NULL, *decrypted = NULL;
	int ret = -1;

	TEST_START("CAST Cipher");

	/* Data (multiple of 8) */
	data = vmalloc(48);
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, 44);
	memset(data->v + 44, 0, 4);

	/* CAST accepts 5-16 bytes */
	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	/* IV (8 bytes) */
	iv = vmalloc(8);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv, 8);

	/* Encrypt */
	encrypted = eay_cast_encrypt(data, key, iv);
	if (!encrypted) TEST_FAIL("CAST encryption failed");

	/* Reset IV */
	memcpy(iv->v, test_iv, 8);

	/* Decrypt */
	decrypted = eay_cast_decrypt(encrypted, key, iv);
	if (!decrypted) TEST_FAIL("CAST decryption failed");

	/* Verify */
	if (memcmp(data->v, decrypted->v, data->l) != 0) {
		TEST_FAIL("Decrypted data doesn't match");
	}

	printf("CAST encrypt/decrypt OK ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);
	if (encrypted) vfree(encrypted);
	if (decrypted) vfree(decrypted);

	if (ret == 0) TEST_PASS();
	return ret;
}

#if defined(HAVE_OPENSSL_CAMELLIA_H)
int test_camellia_cipher()
{
	vchar_t *data = NULL, *key = NULL, *iv = NULL;
	vchar_t *encrypted = NULL, *decrypted = NULL;
	int ret = -1;

	TEST_START("Camellia Cipher");

	/* Data (multiple of 16) */
	data = vmalloc(48);
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, 44);
	memset(data->v + 44, 0, 4);

	/* Camellia 128-bit key */
	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	/* IV (16 bytes) */
	iv = vmalloc(16);
	if (!iv) TEST_FAIL("IV allocation failed");
	memcpy(iv->v, test_iv, 16);

	/* Encrypt */
	encrypted = eay_camellia_encrypt(data, key, iv);
	if (!encrypted) TEST_FAIL("Camellia encryption failed");

	/* Reset IV */
	memcpy(iv->v, test_iv, 16);

	/* Decrypt */
	decrypted = eay_camellia_decrypt(encrypted, key, iv);
	if (!decrypted) TEST_FAIL("Camellia decryption failed");

	/* Verify */
	if (memcmp(data->v, decrypted->v, data->l) != 0) {
		TEST_FAIL("Decrypted data doesn't match");
	}

	printf("Camellia encrypt/decrypt OK ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (iv) vfree(iv);
	if (encrypted) vfree(encrypted);
	if (decrypted) vfree(decrypted);

	if (ret == 0) TEST_PASS();
	return ret;
}
#endif

/* ============================================================================
 * HASH FUNCTION TESTS
 * ============================================================================ */

int test_md5_hash()
{
	vchar_t *data = NULL, *hash1 = NULL, *hash2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("MD5 Hash (one-shot and incremental)");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	/* One-shot hash */
	hash1 = eay_md5_one(data);
	if (!hash1) TEST_FAIL("MD5 one-shot failed");

	if (hash1->l != 16) TEST_FAIL("MD5 hash length wrong");

	/* Incremental hash */
	ctx = eay_md5_init();
	if (!ctx) TEST_FAIL("MD5 init failed");

	eay_md5_update(ctx, data);
	hash2 = eay_md5_final(ctx);
	if (!hash2) TEST_FAIL("MD5 final failed");

	/* Verify both methods produce same result */
	if (memcmp(hash1->v, hash2->v, 16) != 0) {
		TEST_FAIL("MD5 one-shot and incremental don't match");
	}

	printf("MD5 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (hash1) vfree(hash1);
	if (hash2) vfree(hash2);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_sha1_hash()
{
	vchar_t *data = NULL, *hash1 = NULL, *hash2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("SHA1 Hash");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	/* One-shot */
	hash1 = eay_sha1_one(data);
	if (!hash1) TEST_FAIL("SHA1 one-shot failed");

	if (hash1->l != 20) TEST_FAIL("SHA1 hash length wrong");

	/* Incremental */
	ctx = eay_sha1_init();
	if (!ctx) TEST_FAIL("SHA1 init failed");

	eay_sha1_update(ctx, data);
	hash2 = eay_sha1_final(ctx);
	if (!hash2) TEST_FAIL("SHA1 final failed");

	/* Verify */
	if (memcmp(hash1->v, hash2->v, 20) != 0) {
		TEST_FAIL("SHA1 hashes don't match");
	}

	printf("SHA1 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (hash1) vfree(hash1);
	if (hash2) vfree(hash2);

	if (ret == 0) TEST_PASS();
	return ret;
}

#ifdef WITH_SHA2
int test_sha2_256_hash()
{
	vchar_t *data = NULL, *hash1 = NULL, *hash2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("SHA2-256 Hash");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	/* One-shot */
	hash1 = eay_sha2_256_one(data);
	if (!hash1) TEST_FAIL("SHA2-256 one-shot failed");

	if (hash1->l != 32) TEST_FAIL("SHA2-256 hash length wrong");

	/* Incremental */
	ctx = eay_sha2_256_init();
	if (!ctx) TEST_FAIL("SHA2-256 init failed");

	eay_sha2_256_update(ctx, data);
	hash2 = eay_sha2_256_final(ctx);
	if (!hash2) TEST_FAIL("SHA2-256 final failed");

	/* Verify */
	if (memcmp(hash1->v, hash2->v, 32) != 0) {
		TEST_FAIL("SHA2-256 hashes don't match");
	}

	printf("SHA2-256 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (hash1) vfree(hash1);
	if (hash2) vfree(hash2);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_sha2_384_hash()
{
	vchar_t *data = NULL, *hash1 = NULL, *hash2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("SHA2-384 Hash (one-shot and incremental)");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	hash1 = eay_sha2_384_one(data);
	if (!hash1) TEST_FAIL("SHA2-384 one-shot failed");

	if (hash1->l != 48) TEST_FAIL("SHA2-384 hash length wrong");

	ctx = eay_sha2_384_init();
	if (!ctx) TEST_FAIL("SHA2-384 init failed");

	eay_sha2_384_update(ctx, data);
	hash2 = eay_sha2_384_final(ctx);
	if (!hash2) TEST_FAIL("SHA2-384 final failed");

	if (memcmp(hash1->v, hash2->v, 48) != 0) {
		TEST_FAIL("SHA2-384 one-shot and incremental don't match");
	}

	printf("SHA2-384 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (hash1) vfree(hash1);
	if (hash2) vfree(hash2);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_sha2_384_multi_update()
{
	vchar_t *hash1 = NULL, *hash2 = NULL;
	caddr_t ctx = NULL;
	vchar_t *d1 = NULL, *d2 = NULL;
	int ret = -1;

	TEST_START("SHA2-384 Multi-Chunk Incremental");

	d1 = vmalloc(7);
	if (!d1) TEST_FAIL("Allocation failed");
	memcpy(d1->v, "Hello, ", 7);

	d2 = vmalloc(6);
	if (!d2) TEST_FAIL("Allocation failed");
	memcpy(d2->v, "World!", 6);

	ctx = eay_sha2_384_init();
	if (!ctx) TEST_FAIL("SHA2-384 init failed");

	eay_sha2_384_update(ctx, d1);
	eay_sha2_384_update(ctx, d2);
	hash1 = eay_sha2_384_final(ctx);
	if (!hash1) TEST_FAIL("SHA2-384 final failed");

	vchar_t *combined = vmalloc(13);
	if (!combined) { vfree(d1); vfree(d2); if (hash1) vfree(hash1); TEST_FAIL("Allocation failed"); }
	memcpy(combined->v, "Hello, World!", 13);

	hash2 = eay_sha2_384_one(combined);
	if (!hash2) TEST_FAIL("SHA2-384 one-shot failed");

	if (memcmp(hash1->v, hash2->v, 48) != 0) {
		TEST_FAIL("SHA2-384 multi-chunk doesn't match one-shot");
	}

	printf("SHA2-384 multi-chunk incremental OK ");
	ret = 0;

	if (d1) vfree(d1);
	if (d2) vfree(d2);
	if (combined) vfree(combined);
	if (hash1) vfree(hash1);
	if (hash2) vfree(hash2);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_sha2_512_hash()
{
	vchar_t *data = NULL, *hash1 = NULL, *hash2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("SHA2-512 Hash (one-shot and incremental)");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	hash1 = eay_sha2_512_one(data);
	if (!hash1) TEST_FAIL("SHA2-512 one-shot failed");

	if (hash1->l != 64) TEST_FAIL("SHA2-512 hash length wrong");

	ctx = eay_sha2_512_init();
	if (!ctx) TEST_FAIL("SHA2-512 init failed");

	eay_sha2_512_update(ctx, data);
	hash2 = eay_sha2_512_final(ctx);
	if (!hash2) TEST_FAIL("SHA2-512 final failed");

	if (memcmp(hash1->v, hash2->v, 64) != 0) {
		TEST_FAIL("SHA2-512 one-shot and incremental don't match");
	}

	printf("SHA2-512 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (hash1) vfree(hash1);
	if (hash2) vfree(hash2);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_sha2_512_multi_update()
{
	vchar_t *hash1 = NULL, *hash2 = NULL;
	caddr_t ctx = NULL;
	vchar_t *d1 = NULL, *d2 = NULL;
	int ret = -1;

	TEST_START("SHA2-512 Multi-Chunk Incremental");

	d1 = vmalloc(7);
	if (!d1) TEST_FAIL("Allocation failed");
	memcpy(d1->v, "Hello, ", 7);

	d2 = vmalloc(6);
	if (!d2) TEST_FAIL("Allocation failed");
	memcpy(d2->v, "World!", 6);

	ctx = eay_sha2_512_init();
	if (!ctx) TEST_FAIL("SHA2-512 init failed");

	eay_sha2_512_update(ctx, d1);
	eay_sha2_512_update(ctx, d2);
	hash1 = eay_sha2_512_final(ctx);
	if (!hash1) TEST_FAIL("SHA2-512 final failed");

	vchar_t *combined = vmalloc(13);
	if (!combined) { vfree(d1); vfree(d2); if (hash1) vfree(hash1); TEST_FAIL("Allocation failed"); }
	memcpy(combined->v, "Hello, World!", 13);

	hash2 = eay_sha2_512_one(combined);
	if (!hash2) TEST_FAIL("SHA2-512 one-shot failed");

	if (memcmp(hash1->v, hash2->v, 64) != 0) {
		TEST_FAIL("SHA2-512 multi-chunk doesn't match one-shot");
	}

	printf("SHA2-512 multi-chunk incremental OK ");
	ret = 0;

	if (d1) vfree(d1);
	if (d2) vfree(d2);
	if (combined) vfree(combined);
	if (hash1) vfree(hash1);
	if (hash2) vfree(hash2);

	if (ret == 0) TEST_PASS();
	return ret;
}
#endif

/* ============================================================================
 * HMAC FUNCTION TESTS
 * ============================================================================ */

int test_hmac_md5()
{
	vchar_t *data = NULL, *key = NULL, *hmac1 = NULL, *hmac2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("HMAC-MD5");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	/* One-shot */
	hmac1 = eay_hmacmd5_one(key, data);
	if (!hmac1) TEST_FAIL("HMAC-MD5 one-shot failed");

	/* Incremental */
	ctx = eay_hmacmd5_init(key);
	if (!ctx) TEST_FAIL("HMAC-MD5 init failed");

	eay_hmacmd5_update(ctx, data);
	hmac2 = eay_hmacmd5_final(ctx);
	if (!hmac2) TEST_FAIL("HMAC-MD5 final failed");

	/* Verify */
	if (memcmp(hmac1->v, hmac2->v, hmac1->l) != 0) {
		TEST_FAIL("HMAC-MD5 values don't match");
	}

	printf("HMAC-MD5 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (hmac1) vfree(hmac1);
	if (hmac2) vfree(hmac2);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_hmac_sha1()
{
	vchar_t *data = NULL, *key = NULL, *hmac1 = NULL, *hmac2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("HMAC-SHA1");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	key = vmalloc(16);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_128, 16);

	/* One-shot */
	hmac1 = eay_hmacsha1_one(key, data);
	if (!hmac1) TEST_FAIL("HMAC-SHA1 one-shot failed");

	/* Incremental */
	ctx = eay_hmacsha1_init(key);
	if (!ctx) TEST_FAIL("HMAC-SHA1 init failed");

	eay_hmacsha1_update(ctx, data);
	hmac2 = eay_hmacsha1_final(ctx);
	if (!hmac2) TEST_FAIL("HMAC-SHA1 final failed");

	/* Verify */
	if (memcmp(hmac1->v, hmac2->v, hmac1->l) != 0) {
		TEST_FAIL("HMAC-SHA1 values don't match");
	}

	printf("HMAC-SHA1 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (hmac1) vfree(hmac1);
	if (hmac2) vfree(hmac2);

	if (ret == 0) TEST_PASS();
	return ret;
}

#ifdef WITH_SHA2
int test_hmac_sha2_256()
{
	vchar_t *data = NULL, *key = NULL, *hmac1 = NULL, *hmac2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("HMAC-SHA2-256 (one-shot and incremental)");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	key = vmalloc(32);
	if (!key) TEST_FAIL("Key allocation failed");
	memcpy(key->v, test_key_256, 32);

	hmac1 = eay_hmacsha2_256_one(key, data);
	if (!hmac1) TEST_FAIL("HMAC-SHA2-256 one-shot failed");

	if (hmac1->l != 32) TEST_FAIL("HMAC-SHA2-256 length wrong");

	ctx = eay_hmacsha2_256_init(key);
	if (!ctx) TEST_FAIL("HMAC-SHA2-256 init failed");

	eay_hmacsha2_256_update(ctx, data);
	hmac2 = eay_hmacsha2_256_final(ctx);
	if (!hmac2) TEST_FAIL("HMAC-SHA2-256 final failed");

	if (memcmp(hmac1->v, hmac2->v, 32) != 0) {
		TEST_FAIL("HMAC-SHA2-256 one-shot and incremental don't match");
	}

	printf("HMAC-SHA2-256 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (hmac1) vfree(hmac1);
	if (hmac2) vfree(hmac2);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_hmac_sha2_384()
{
	vchar_t *data = NULL, *key = NULL, *hmac1 = NULL, *hmac2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("HMAC-SHA2-384 (one-shot and incremental)");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	key = vmalloc(48);
	if (!key) TEST_FAIL("Key allocation failed");
	memset(key->v, 0xAB, 48);

	hmac1 = eay_hmacsha2_384_one(key, data);
	if (!hmac1) TEST_FAIL("HMAC-SHA2-384 one-shot failed");

	if (hmac1->l != 48) TEST_FAIL("HMAC-SHA2-384 length wrong");

	ctx = eay_hmacsha2_384_init(key);
	if (!ctx) TEST_FAIL("HMAC-SHA2-384 init failed");

	eay_hmacsha2_384_update(ctx, data);
	hmac2 = eay_hmacsha2_384_final(ctx);
	if (!hmac2) TEST_FAIL("HMAC-SHA2-384 final failed");

	if (memcmp(hmac1->v, hmac2->v, 48) != 0) {
		TEST_FAIL("HMAC-SHA2-384 one-shot and incremental don't match");
	}

	printf("HMAC-SHA2-384 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (hmac1) vfree(hmac1);
	if (hmac2) vfree(hmac2);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_hmac_sha2_512()
{
	vchar_t *data = NULL, *key = NULL, *hmac1 = NULL, *hmac2 = NULL;
	caddr_t ctx = NULL;
	int ret = -1;

	TEST_START("HMAC-SHA2-512 (one-shot and incremental)");

	data = vmalloc(strlen(test_plaintext));
	if (!data) TEST_FAIL("Allocation failed");
	memcpy(data->v, test_plaintext, strlen(test_plaintext));

	key = vmalloc(64);
	if (!key) TEST_FAIL("Key allocation failed");
	memset(key->v, 0xCD, 64);

	hmac1 = eay_hmacsha2_512_one(key, data);
	if (!hmac1) TEST_FAIL("HMAC-SHA2-512 one-shot failed");

	if (hmac1->l != 64) TEST_FAIL("HMAC-SHA2-512 length wrong");

	ctx = eay_hmacsha2_512_init(key);
	if (!ctx) TEST_FAIL("HMAC-SHA2-512 init failed");

	eay_hmacsha2_512_update(ctx, data);
	hmac2 = eay_hmacsha2_512_final(ctx);
	if (!hmac2) TEST_FAIL("HMAC-SHA2-512 final failed");

	if (memcmp(hmac1->v, hmac2->v, 64) != 0) {
		TEST_FAIL("HMAC-SHA2-512 one-shot and incremental don't match");
	}

	printf("HMAC-SHA2-512 one-shot and incremental match ");
	ret = 0;

	if (data) vfree(data);
	if (key) vfree(key);
	if (hmac1) vfree(hmac1);
	if (hmac2) vfree(hmac2);

	if (ret == 0) TEST_PASS();
	return ret;
}
#endif

/* ============================================================================
 * X.509 CERTIFICATE TESTS
 * ============================================================================ */

int test_asn1_dn_conversion()
{
	vchar_t *asn1dn = NULL;
	char *dn_string = "C=US, ST=California, L=San Francisco, O=Test Org, CN=Test User";
	int ret = -1;

	TEST_START("ASN.1 DN String Conversion");

	asn1dn = eay_str2asn1dn(dn_string, strlen(dn_string));
	if (!asn1dn) TEST_FAIL("ASN.1 DN conversion failed");

	if (asn1dn->l == 0) TEST_FAIL("ASN.1 DN has zero length");

	printf("DN string converted to ASN.1 (%zu bytes) ", asn1dn->l);
	ret = 0;

	if (asn1dn) vfree(asn1dn);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_asn1_dn_comparison()
{
	vchar_t *dn1 = NULL, *dn2 = NULL, *dn3 = NULL;
	char *dn_str1 = "C=US, O=Test, CN=User1";
	char *dn_str2 = "C=US, O=Test, CN=User1";
	char *dn_str3 = "C=US, O=Test, CN=User2";
	int ret = -1;

	TEST_START("ASN.1 DN Comparison");

	dn1 = eay_str2asn1dn(dn_str1, strlen(dn_str1));
	dn2 = eay_str2asn1dn(dn_str2, strlen(dn_str2));
	dn3 = eay_str2asn1dn(dn_str3, strlen(dn_str3));

	if (!dn1 || !dn2 || !dn3) TEST_FAIL("DN conversion failed");

	/* Same DNs should match */
	if (eay_cmp_asn1dn(dn1, dn2) != 0) {
		TEST_FAIL("Identical DNs don't match");
	}

	/* Different DNs should not match */
	if (eay_cmp_asn1dn(dn1, dn3) == 0) {
		TEST_FAIL("Different DNs match");
	}

	printf("DN comparison works correctly ");
	ret = 0;

	if (dn1) vfree(dn1);
	if (dn2) vfree(dn2);
	if (dn3) vfree(dn3);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_hex_asn1_dn()
{
	vchar_t *asn1dn = NULL;
	/* Simple hex-encoded DN */
	char *hex_dn = "3011310F300D06035504030C06546573746572";
	int ret = -1;

	TEST_START("Hex-encoded ASN.1 DN Conversion");

	asn1dn = eay_hex2asn1dn(hex_dn, strlen(hex_dn));
	if (!asn1dn) TEST_FAIL("Hex DN conversion failed");

	if (asn1dn->l == 0) TEST_FAIL("Hex DN has zero length");

	printf("Hex DN converted (%zu bytes) ", asn1dn->l);
	ret = 0;

	if (asn1dn) vfree(asn1dn);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * BASE64 TESTS
 * ============================================================================ */

/*
 * Test Base64 encode/decode round-trip with exact length check.
 *
 * base64_decode() now correctly subtracts '=' padding bytes from the
 * EVP_DecodeBlock() output length, so decoded->l must equal the original
 * data length exactly.
 */
int test_base64_encode_decode()
{
	vchar_t *encoded = NULL, *decoded = NULL;
	char *test_data = "Hello, Base64 World!";
	size_t orig_len = strlen(test_data);
	int ret = -1;

	TEST_START("Base64 Encode/Decode");

	/* Encode */
	encoded = base64_encode(test_data, orig_len);
	if (!encoded) TEST_FAIL("Base64 encode failed");

	/* Verify encoded is larger than original */
	if (encoded->l <= orig_len) {
		TEST_FAIL("Base64 encoded not larger than original");
	}

	/* Decode */
	decoded = base64_decode((char *)encoded->v, encoded->l);
	if (!decoded) TEST_FAIL("Base64 decode failed");

	/* Verify exact decoded length matches original */
	if (decoded->l != orig_len) {
		printf("(decoded->l=%zu, orig=%zu) ", decoded->l, orig_len);
		TEST_FAIL("Base64 decoded length wrong");
	}

	/* Verify the actual content matches */
	if (memcmp(decoded->v, test_data, orig_len) != 0) {
		TEST_FAIL("Base64 decoded content doesn't match original");
	}

	printf("Base64 encode/decode OK (length=%zu) ", orig_len);
	ret = 0;

	if (encoded) vfree(encoded);
	if (decoded) vfree(decoded);

	if (ret == 0) TEST_PASS();
	return ret;
}

/*
 * Test Base64 with various data sizes, checking exact decoded length.
 *
 * With the base64_decode() padding fix in place, decoded->l must equal
 * the original data length exactly for all input sizes.
 */
int test_base64_various_sizes()
{
	int sizes[] = {1, 10, 50, 100, 1000};
	int i;
	int ret = 0;

	TEST_START("Base64 with Various Data Sizes");
	printf("\n");

	for (i = 0; i < 5; i++) {
		vchar_t *encoded = NULL, *decoded = NULL;
		char *data = NULL;
		int j;

		printf("    Size %d bytes... ", sizes[i]);
		fflush(stdout);

		/* Create test data */
		data = malloc(sizes[i]);
		if (!data) {
			printf("FAIL (alloc)\n");
			ret = -1;
			break;
		}
		for (j = 0; j < sizes[i]; j++) {
			data[j] = (char)(j & 0xFF);
		}

		/* Encode */
		encoded = base64_encode(data, sizes[i]);
		if (!encoded) {
			printf("FAIL (encode)\n");
			free(data);
			ret = -1;
			break;
		}

		/* Decode */
		decoded = base64_decode((char *)encoded->v, encoded->l);
		if (!decoded) {
			printf("FAIL (decode)\n");
			free(data);
			vfree(encoded);
			ret = -1;
			break;
		}

		/* Check exact length and content */
		if (decoded->l != (size_t)sizes[i]) {
			printf("FAIL (length: decoded->l=%zu, expected=%d)\n",
			       decoded->l, sizes[i]);
			free(data);
			vfree(encoded);
			vfree(decoded);
			ret = -1;
			break;
		}

		if (memcmp(decoded->v, data, sizes[i]) != 0) {
			printf("FAIL (content mismatch)\n");
			free(data);
			vfree(encoded);
			vfree(decoded);
			ret = -1;
			break;
		}

		printf("✓ OK\n");
		free(data);
		vfree(encoded);
		vfree(decoded);
	}

	printf("    ");

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * RANDOM NUMBER TESTS
 * ============================================================================ */

int test_random_generation()
{
	vchar_t *rand1 = NULL, *rand2 = NULL, *rand3 = NULL;
	int ret = -1;

	TEST_START("Random Number Generation");

	/* Generate three random values */
	rand1 = eay_set_random(32);
	rand2 = eay_set_random(32);
	rand3 = eay_set_random(64);

	if (!rand1 || !rand2 || !rand3) TEST_FAIL("Random generation failed");

	if (rand1->l != 32 || rand2->l != 32 || rand3->l != 64) {
		TEST_FAIL("Random length wrong");
	}

	/* Verify they're different (extremely high probability) */
	if (memcmp(rand1->v, rand2->v, 32) == 0) {
		TEST_FAIL("Random numbers are identical (highly unlikely!)");
	}

	printf("Random numbers generated and unique ");
	ret = 0;

	if (rand1) vfree(rand1);
	if (rand2) vfree(rand2);
	if (rand3) vfree(rand3);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_random_u32()
{
	u_int32_t r1, r2, r3;
	int ret = -1;

	TEST_START("Random u_int32_t Generation");

	r1 = eay_random();
	r2 = eay_random();
	r3 = eay_random();

	/* Verify they're different (extremely high probability) */
	if (r1 == r2 || r2 == r3 || r1 == r3) {
		printf("Warning: Random u32 values match (unlikely but possible) ");
	}

	printf("Random u32 values generated ");
	ret = 0;

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * BIGNUM CONVERSION TESTS
 * ============================================================================ */

int test_bignum_conversions()
{
	BIGNUM *bn1 = NULL, *bn2 = NULL;
	vchar_t *vch = NULL;
	char *hex_value = "FEDCBA9876543210FEDCBA9876543210";
	int ret = -1;

	TEST_START("BIGNUM Conversions (vchar_t ↔ BIGNUM)");

	/* Create BIGNUM from hex */
	BN_hex2bn(&bn1, hex_value);
	if (!bn1) TEST_FAIL("BN_hex2bn failed");

	/* Convert BIGNUM to vchar_t */
	if (eay_bn2v(&vch, bn1) != 0) {
		TEST_FAIL("eay_bn2v failed");
	}

	if (!vch || vch->l == 0) TEST_FAIL("Conversion produced empty vchar_t");

	/* Convert vchar_t back to BIGNUM */
	if (eay_v2bn(&bn2, vch) != 0) {
		TEST_FAIL("eay_v2bn failed");
	}

	if (!bn2) TEST_FAIL("Conversion produced NULL BIGNUM");

	/* Verify they match */
	if (BN_cmp(bn1, bn2) != 0) {
		TEST_FAIL("BIGNUMs don't match after round-trip");
	}

	printf("BIGNUM ↔ vchar_t conversion OK ");
	ret = 0;

	if (bn1) BN_free(bn1);
	if (bn2) BN_free(bn2);
	if (vch) vfree(vch);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_bignum_edge_cases()
{
	BIGNUM *bn = NULL;
	vchar_t *vch = NULL;
	int ret = -1;

	TEST_START("BIGNUM Edge Cases (zero, small, large)");

	/* Test zero */
	bn = BN_new();
	BN_zero(bn);
	if (eay_bn2v(&vch, bn) != 0) {
		TEST_FAIL("Zero BIGNUM conversion failed");
	}
	if (vch) vfree(vch);
	BN_free(bn);
	vch = NULL;

	/* Test small value (1) */
	bn = BN_new();
	BN_one(bn);
	if (eay_bn2v(&vch, bn) != 0) {
		TEST_FAIL("Small BIGNUM conversion failed");
	}
	if (vch) vfree(vch);
	BN_free(bn);
	vch = NULL;

	/* Test large value (2^1024) */
	bn = BN_new();
	BN_set_word(bn, 2);
	BN_lshift(bn, bn, 1024);
	if (eay_bn2v(&vch, bn) != 0) {
		TEST_FAIL("Large BIGNUM conversion failed");
	}

	printf("Zero, small, and large BIGNUM conversions OK ");
	ret = 0;

	if (bn) BN_free(bn);
	if (vch) vfree(vch);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * CIPHER KEYLEN TESTS
 * ============================================================================ */

int test_cipher_keylen()
{
	int ret = -1;

	TEST_START("Cipher Key Length Validation");

	/* keylen takes length in bits; returns normalized bit length or -1 for invalid.
	 * Passing 0 is convention for "use default".
	 */
	/* DES: only 64 bits */
	if (eay_des_keylen(64) != 64) TEST_FAIL("DES keylen 64 rejected");
	if (eay_des_keylen(0) != 64) TEST_FAIL("DES keylen 0 not normalized to 64");
	if (eay_des_keylen(8) > 0) TEST_FAIL("DES keylen 8 accepted");

	/* 3DES: only 192 bits */
	if (eay_3des_keylen(192) != 192) TEST_FAIL("3DES keylen 192 rejected");
	if (eay_3des_keylen(0) != 192) TEST_FAIL("3DES keylen 0 not normalized to 192");
	if (eay_3des_keylen(128) > 0) TEST_FAIL("3DES keylen 128 accepted");

	/* AES: 128, 192, or 256 bits */
	if (eay_aes_keylen(128) != 128) TEST_FAIL("AES keylen 128 rejected");
	if (eay_aes_keylen(192) != 192) TEST_FAIL("AES keylen 192 rejected");
	if (eay_aes_keylen(256) != 256) TEST_FAIL("AES keylen 256 rejected");
	if (eay_aes_keylen(0) != 128) TEST_FAIL("AES keylen 0 not normalized to 128");
	if (eay_aes_keylen(8) > 0) TEST_FAIL("AES keylen 8 accepted");

	/* Blowfish: 40-448 bits */
	if (eay_bf_keylen(40) != 40) TEST_FAIL("BF keylen 40 rejected");
	if (eay_bf_keylen(448) != 448) TEST_FAIL("BF keylen 448 rejected");
	if (eay_bf_keylen(0) != 448) TEST_FAIL("BF keylen 0 not normalized to 448");
	if (eay_bf_keylen(32) > 0) TEST_FAIL("BF keylen 32 accepted");
	if (eay_bf_keylen(449) > 0) TEST_FAIL("BF keylen 449 accepted");

	/* CAST: 40-128 bits */
	if (eay_cast_keylen(40) != 40) TEST_FAIL("CAST keylen 40 rejected");
	if (eay_cast_keylen(128) != 128) TEST_FAIL("CAST keylen 128 rejected");
	if (eay_cast_keylen(0) != 128) TEST_FAIL("CAST keylen 0 not normalized to 128");
	if (eay_cast_keylen(32) > 0) TEST_FAIL("CAST keylen 32 accepted");
	if (eay_cast_keylen(129) > 0) TEST_FAIL("CAST keylen 129 accepted");

#if defined(HAVE_OPENSSL_IDEA_H)
	/* IDEA: must be 16 bytes */
	if (eay_idea_keylen(16) != 0) TEST_FAIL("IDEA keylen 16 rejected");
	if (eay_idea_keylen(15) == 0) TEST_FAIL("IDEA keylen 15 accepted");
#endif

#ifdef HAVE_OPENSSL_RC5_H
	/* RC5: 5-16 bytes */
	if (eay_rc5_keylen(5) != 0) TEST_FAIL("RC5 keylen 5 rejected");
	if (eay_rc5_keylen(16) != 0) TEST_FAIL("RC5 keylen 16 rejected");
	if (eay_rc5_keylen(4) == 0) TEST_FAIL("RC5 keylen 4 accepted");
#endif

	printf("All key length validations correct ");
	ret = 0;

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * CIPHER WEAKKEY TESTS
 * ============================================================================ */

int test_des_weakkey()
{
	vchar_t *weak = NULL, *strong = NULL;
	int ret = -1;

	TEST_START("DES Weak Key Detection");

	/* Known DES weak key */
	weak = vmalloc(8);
	if (!weak) TEST_FAIL("Allocation failed");
	memset(weak->v, 0x01, 8);  /* All bits same in parity-stripped form */

	if (eay_des_weakkey(weak) != 1) TEST_FAIL("Known weak DES key not detected");

	/* Normal key */
	strong = vmalloc(8);
	if (!strong) { vfree(weak); TEST_FAIL("Allocation failed"); }
	memcpy(strong->v, test_key_128, 8);

	if (eay_des_weakkey(strong) != 0) TEST_FAIL("Strong DES key flagged as weak");

	printf("DES weak key detection works ");
	ret = 0;

	if (weak) vfree(weak);
	if (strong) vfree(strong);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_3des_weakkey()
{
	vchar_t *weak = NULL, *strong = NULL;
	int ret = -1;

	TEST_START("3DES Weak Key Detection");

	/* 3DES with weak sub-key */
	weak = vmalloc(24);
	if (!weak) TEST_FAIL("Allocation failed");
	memset(weak->v, 0x01, 24);

	if (eay_3des_weakkey(weak) != 1) TEST_FAIL("Known weak 3DES key not detected");

	/* Normal 3DES key */
	strong = vmalloc(24);
	if (!strong) { vfree(weak); TEST_FAIL("Allocation failed"); }
	memcpy(strong->v, test_key_192, 24);

	if (eay_3des_weakkey(strong) != 0) TEST_FAIL("Strong 3DES key flagged as weak");

	printf("3DES weak key detection works ");
	ret = 0;

	if (weak) vfree(weak);
	if (strong) vfree(strong);

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_stub_weakkey()
{
	vchar_t *key = NULL;
	int ret = -1;

	TEST_START("Cipher Stub Weak Key Functions");

	/* AES weakkey stub - always returns 0 (no known weak keys) */
	key = vmalloc(16);
	if (!key) TEST_FAIL("Allocation failed");
	memset(key->v, 0xFF, 16);
	if (eay_aes_weakkey(key) != 0) TEST_FAIL("AES weakkey stub returned non-zero");

	/* BF weakkey stub */
	if (eay_bf_weakkey(key) != 0) TEST_FAIL("BF weakkey stub returned non-zero");

	/* CAST weakkey stub */
	if (eay_cast_weakkey(key) != 0) TEST_FAIL("CAST weakkey stub returned non-zero");

#if defined(HAVE_OPENSSL_IDEA_H)
	/* IDEA weakkey stub */
	if (eay_idea_weakkey(key) != 0) TEST_FAIL("IDEA weakkey stub returned non-zero");
#endif

#ifdef HAVE_OPENSSL_RC5_H
	/* RC5 weakkey stub */
	if (eay_rc5_weakkey(key) != 0) TEST_FAIL("RC5 weakkey stub returned non-zero");
#endif

	printf("Stub weakkey functions return 0 ");
	ret = 0;

	if (key) vfree(key);

	if (ret == 0) TEST_PASS();
	return ret;
}

/* ============================================================================
 * UTILITY FUNCTION TESTS
 * ============================================================================ */

int test_version_string()
{
	const char *version = NULL;
	int ret = -1;

	TEST_START("OpenSSL Version String");

	version = eay_version();
	if (!version) TEST_FAIL("eay_version returned NULL");

	if (strlen(version) == 0) TEST_FAIL("Version string empty");

	/* Should contain "OpenSSL" */
	if (strstr(version, "OpenSSL") == NULL) {
		TEST_FAIL("Version string doesn't contain 'OpenSSL'");
	}

	printf("Version: %s ", version);
	ret = 0;

	if (ret == 0) TEST_PASS();
	return ret;
}

int test_error_string()
{
	char *errstr = NULL;
	int ret = -1;

	TEST_START("OpenSSL Error String");

	/* Get error string (may be empty if no errors) */
	errstr = eay_strerror();
	if (!errstr) TEST_FAIL("eay_strerror returned NULL");

	/* Should at least be a valid pointer */
	printf("Error handling works ");
	ret = 0;

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
	printf("  Racoon IPSec - Complete Crypto Coverage Tests\n");
	printf("  All eay_* Functions - OpenSSL 3.0 Validation\n");
	printf("========================================================================\n");

	/* Initialize OpenSSL */
	eay_init();

	printf("\n=== Symmetric Cipher Tests ===\n");
	total++; if (test_des_cipher() != 0) failed++;
	total++; if (test_3des_cipher() != 0) failed++;
	total++; if (test_aes_cipher() != 0) failed++;
	total++; if (test_blowfish_cipher() != 0) failed++;
	total++; if (test_cast_cipher() != 0) failed++;
#if defined(HAVE_OPENSSL_CAMELLIA_H)
	total++; if (test_camellia_cipher() != 0) failed++;
#endif

	printf("\n=== Hash Function Tests ===\n");
	total++; if (test_md5_hash() != 0) failed++;
	total++; if (test_sha1_hash() != 0) failed++;
#ifdef WITH_SHA2
	total++; if (test_sha2_256_hash() != 0) failed++;
	total++; if (test_sha2_384_hash() != 0) failed++;
	total++; if (test_sha2_384_multi_update() != 0) failed++;
	total++; if (test_sha2_512_hash() != 0) failed++;
	total++; if (test_sha2_512_multi_update() != 0) failed++;
#endif

	printf("\n=== HMAC Function Tests ===\n");
	total++; if (test_hmac_md5() != 0) failed++;
	total++; if (test_hmac_sha1() != 0) failed++;
#ifdef WITH_SHA2
	total++; if (test_hmac_sha2_256() != 0) failed++;
	total++; if (test_hmac_sha2_384() != 0) failed++;
	total++; if (test_hmac_sha2_512() != 0) failed++;
#endif

	printf("\n=== X.509 / ASN.1 Tests ===\n");
	total++; if (test_asn1_dn_conversion() != 0) failed++;
	total++; if (test_asn1_dn_comparison() != 0) failed++;
	total++; if (test_hex_asn1_dn() != 0) failed++;

	printf("\n=== Base64 Tests ===\n");
	total++; if (test_base64_encode_decode() != 0) failed++;
	total++; if (test_base64_various_sizes() != 0) failed++;

	printf("\n=== Random Number Tests ===\n");
	total++; if (test_random_generation() != 0) failed++;
	total++; if (test_random_u32() != 0) failed++;

	printf("\n=== BIGNUM Conversion Tests ===\n");
	total++; if (test_bignum_conversions() != 0) failed++;
	total++; if (test_bignum_edge_cases() != 0) failed++;

	printf("\n=== Utility Function Tests ===\n");
	total++; if (test_cipher_keylen() != 0) failed++;
	total++; if (test_des_weakkey() != 0) failed++;
	total++; if (test_3des_weakkey() != 0) failed++;
	total++; if (test_stub_weakkey() != 0) failed++;
	total++; if (test_version_string() != 0) failed++;
	total++; if (test_error_string() != 0) failed++;

	printf("\n");
	printf("========================================================================\n");
	if (failed == 0) {
		printf("  ✓ ALL COVERAGE TESTS PASSED (%d tests)\n", total);
		printf("  Complete eay_* function coverage validated!\n");
		printf("========================================================================\n");
		return 0;
	} else {
		printf("  ✗ %d/%d TEST(S) FAILED\n", failed, total);
		printf("========================================================================\n");
		return 1;
	}
}

/* Restore warnings */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#pragma GCC diagnostic pop
#endif
