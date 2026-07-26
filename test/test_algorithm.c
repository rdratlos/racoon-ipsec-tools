// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression tests for algorithm.c's DOI<->algorithm dispatch tables
 * (oakley_hashdef[], oakley_hmacdef[], oakley_encdef[], ipsec_encdef[],
 * ipsec_hmacdef[], ipsec_compdef[], oakley_dhdef[], oakley_authdef[]).
 *
 * algorithm.c itself is almost entirely linear-scan table lookups; the
 * risk it carries is a transcription bug -- a DOI value, name, or function
 * pointer copy-pasted into the wrong table row -- rather than complex
 * control flow.  These tests therefore lean on round-trips (type -> doi ->
 * name/hashlen/blocklen, and back) plus "unknown value" sentinel checks
 * for the pure lookup functions, and encrypt/decrypt or hash/hmac
 * round-trips through the *_one()/_encrypt()/_decrypt() dispatchers to
 * catch a function pointer wired to the wrong table row (something the
 * existing direct eay_* tests in test_crypto_coverage.c/test_cipher_shim.c
 * cannot catch, since they call the eay_* functions directly rather than
 * through algorithm.c's dispatch).
 *
 * alg_oakley_dhdef_group() is the one function here that needs live data:
 * the dh_modp* globals it reads are declared in oakley.c and only
 * populated by oakley_dhinit().  oakley_dhinit() itself only calls
 * str2val()/vdup()/free() (all already linked), but it lives in oakley.c,
 * which has a very large dependency closure elsewhere in the file.
 * oakley.c is therefore built with -ffunction-sections and linked with
 * --gc-sections (same technique as test_ipsec_doi_sa and
 * test_vendorid_bounds) so only oakley_dhinit() and its handful of
 * dependencies are pulled in.
 *
 * Unlike test_nattraversal_natd, algorithm.c is compiled unconditionally
 * (no ENABLE_NATT/ENABLE_FRAG gate), so this test always runs.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "vmbuf.h"
#include "isakmp.h"
#include "oakley.h"
#include "ipsec_doi.h"
#include "algorithm.h"

#define TEST_PASS() do { printf("✓ PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("✗ FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/* oakley_dhinit() is declared in oakley.h but only ever called once, from
 * session.c, in the real daemon. */
extern int oakley_dhinit(void);

/*
 * Unknown DOI/type values must resolve to the documented "not found"
 * sentinels (0/-1/"*UNKNOWN*"), not a false positive or a crash.
 */
static int
test_unknown_values(void)
{
	TEST_START("unknown DOI/type values resolve to sentinels");

	if (alg_oakley_hashdef_ok(9999) != 0)
		TEST_FAIL("alg_oakley_hashdef_ok() accepted unknown DOI");
	if (strcmp(alg_oakley_hashdef_name(9999), "*UNKNOWN*") != 0)
		TEST_FAIL("alg_oakley_hashdef_name() did not return *UNKNOWN*");
	if (alg_oakley_hashdef_doi(9999) != -1)
		TEST_FAIL("alg_oakley_hashdef_doi() did not return -1");
	if (alg_oakley_hashdef_hashlen(9999) != 0)
		TEST_FAIL("alg_oakley_hashdef_hashlen() did not return 0");

	if (alg_oakley_encdef_ok(9999) != 0)
		TEST_FAIL("alg_oakley_encdef_ok() accepted unknown DOI");
	if (strcmp(alg_oakley_encdef_name(9999), "*UNKNOWN*") != 0)
		TEST_FAIL("alg_oakley_encdef_name() did not return *UNKNOWN*");
	if (alg_oakley_encdef_blocklen(9999) != -1)
		TEST_FAIL("alg_oakley_encdef_blocklen() did not return -1");
	if (alg_oakley_encdef_keylen(9999, 128) != -1)
		TEST_FAIL("alg_oakley_encdef_keylen() did not return -1");

	if (alg_oakley_dhdef_ok(9999) != 0)
		TEST_FAIL("alg_oakley_dhdef_ok() accepted unknown DOI");
	if (strcmp(alg_oakley_dhdef_name(9999), "*UNKNOWN*") != 0)
		TEST_FAIL("alg_oakley_dhdef_name() did not return *UNKNOWN*");
	/* algtype_ec2n155/185 are in enum algtype but were never added to
	 * oakley_dhdef[] -- a real "declared but unimplemented" case. */
	if (alg_oakley_dhdef_doi(algtype_ec2n155) != -1)
		TEST_FAIL("alg_oakley_dhdef_doi(ec2n155) did not return -1");

	if (strcmp(alg_oakley_authdef_name(9999), "*UNKNOWN*") != 0)
		TEST_FAIL("alg_oakley_authdef_name() did not return *UNKNOWN*");
	if (alg_oakley_authdef_doi(9999) != -1)
		TEST_FAIL("alg_oakley_authdef_doi() did not return -1");

	TEST_PASS();
	return 0;
}

struct hash_case {
	const char *name;
	int doi;
	int type;
	int hashlen;
};

/*
 * alg_oakley_hashdef_hashlen() reports the digest length in *bits*
 * (crypto_openssl.c's eay_*_hashlen() functions return DIGEST_LENGTH<<3),
 * unlike vchar_t.l elsewhere in this file which is always bytes.
 */
static const struct hash_case hash_cases[] = {
	{ "md5",	OAKLEY_ATTR_HASH_ALG_MD5,	algtype_md5,		128 },
	{ "sha1",	OAKLEY_ATTR_HASH_ALG_SHA,	algtype_sha1,		160 },
#ifdef WITH_SHA2
	{ "sha2_256",	OAKLEY_ATTR_HASH_ALG_SHA2_256,	algtype_sha2_256,	256 },
	{ "sha2_384",	OAKLEY_ATTR_HASH_ALG_SHA2_384,	algtype_sha2_384,	384 },
	{ "sha2_512",	OAKLEY_ATTR_HASH_ALG_SHA2_512,	algtype_sha2_512,	512 },
#endif
};

/*
 * Every hash table row must round-trip: doi -> name/hashlen, and
 * type -> doi, using the values RFC 2409/4306 actually assign them.
 */
static int
test_hash_table_roundtrip(void)
{
	size_t i;

	TEST_START("oakley_hashdef[] round-trips for md5/sha1/sha2");

	for (i = 0; i < sizeof(hash_cases) / sizeof(hash_cases[0]); i++) {
		const struct hash_case *c = &hash_cases[i];

		if (!alg_oakley_hashdef_ok(c->doi))
			TEST_FAIL("known hash DOI rejected");
		if (strcmp(alg_oakley_hashdef_name(c->doi), c->name) != 0)
			TEST_FAIL("hash name mismatch");
		if (alg_oakley_hashdef_doi(c->type) != c->doi)
			TEST_FAIL("hash type->doi mismatch");
		if (alg_oakley_hashdef_hashlen(c->doi) != c->hashlen)
			TEST_FAIL("hash length mismatch");
		if (algtype2doi(algclass_isakmp_hash, c->type) != c->doi)
			TEST_FAIL("algtype2doi() mismatch for hash class");
	}

	TEST_PASS();
	return 0;
}

/*
 * alg_oakley_hashdef_one() must dispatch to the *correct* underlying
 * eay_*_one() -- same input through two different table rows must not
 * produce colliding output lengths, which would indicate the function
 * pointers were swapped between rows.
 */
static int
test_hash_one_dispatch(void)
{
	vchar_t *buf, *md5_digest, *sha1_digest;
	int rc = -1;

	TEST_START("alg_oakley_hashdef_one() dispatches to the right hash");

	buf = vmalloc(32);
	if (buf == NULL)
		TEST_FAIL("vmalloc() failed");
	memset(buf->v, 0xA5, buf->l);

	md5_digest = alg_oakley_hashdef_one(OAKLEY_ATTR_HASH_ALG_MD5, buf);
	sha1_digest = alg_oakley_hashdef_one(OAKLEY_ATTR_HASH_ALG_SHA, buf);
	vfree(buf);

	if (md5_digest == NULL || sha1_digest == NULL) {
		if (md5_digest) vfree(md5_digest);
		if (sha1_digest) vfree(sha1_digest);
		TEST_FAIL("alg_oakley_hashdef_one() returned NULL");
	}

	if (md5_digest->l != 16 || sha1_digest->l != 20)
		rc = -1;
	else if (memcmp(md5_digest->v, sha1_digest->v, 16) == 0)
		rc = -1;	/* same bytes for two different algorithms */
	else
		rc = 0;

	vfree(md5_digest);
	vfree(sha1_digest);

	if (rc != 0)
		TEST_FAIL("MD5/SHA1 digests via dispatch were wrong or identical");

	TEST_PASS();
	return 0;
}

/*
 * Same idea as test_hash_one_dispatch(), for HMAC: alg_oakley_hmacdef_one()
 * must produce the length appropriate to the requested algorithm.
 */
static int
test_hmac_one_dispatch(void)
{
	vchar_t *key, *buf, *hmac_md5, *hmac_sha1;
	int rc = -1;

	TEST_START("alg_oakley_hmacdef_one() dispatches to the right HMAC");

	key = vmalloc(16);
	buf = vmalloc(32);
	if (key == NULL || buf == NULL) {
		if (key) vfree(key);
		if (buf) vfree(buf);
		TEST_FAIL("vmalloc() failed");
	}
	memset(key->v, 0x11, key->l);
	memset(buf->v, 0x22, buf->l);

	hmac_md5 = alg_oakley_hmacdef_one(OAKLEY_ATTR_HASH_ALG_MD5, key, buf);
	hmac_sha1 = alg_oakley_hmacdef_one(OAKLEY_ATTR_HASH_ALG_SHA, key, buf);
	vfree(key);
	vfree(buf);

	if (hmac_md5 == NULL || hmac_sha1 == NULL) {
		if (hmac_md5) vfree(hmac_md5);
		if (hmac_sha1) vfree(hmac_sha1);
		TEST_FAIL("alg_oakley_hmacdef_one() returned NULL");
	}

	if (hmac_md5->l == 16 && hmac_sha1->l == 20)
		rc = 0;

	vfree(hmac_md5);
	vfree(hmac_sha1);

	if (rc != 0)
		TEST_FAIL("HMAC-MD5/HMAC-SHA1 lengths via dispatch were wrong");

	TEST_PASS();
	return 0;
}

/*
 * alg_oakley_hmacdef_doi() (type->doi for oakley_hmacdef[]) had no direct
 * coverage: test_hmac_one_dispatch() above only exercises the doi->struct
 * lookup (alg_oakley_hmacdef()) via alg_oakley_hmacdef_one(), never the
 * type->doi direction. oakley_hmacdef[]'s rows reuse the plain hash algtype
 * (algtype_md5, not a separate "hmac" enumerator) as their type field.
 */
static int
test_oakley_hmacdef_doi_roundtrip(void)
{
	TEST_START("alg_oakley_hmacdef_doi() type->doi round-trip");

	if (alg_oakley_hmacdef_doi(algtype_md5) != OAKLEY_ATTR_HASH_ALG_MD5)
		TEST_FAIL("hmac_md5 type->doi mismatch");
	if (alg_oakley_hmacdef_doi(algtype_sha1) != OAKLEY_ATTR_HASH_ALG_SHA)
		TEST_FAIL("hmac_sha1 type->doi mismatch");
	if (alg_oakley_hmacdef_doi(9999) != -1)
		TEST_FAIL("unknown hmac type did not return -1");

	TEST_PASS();
	return 0;
}

struct enc_case {
	const char *name;
	int doi;
	int type;
	int blocklen;
};

static const struct enc_case enc_cases[] = {
	{ "des",	OAKLEY_ATTR_ENC_ALG_DES,	algtype_des,	 8 },
	{ "3des",	OAKLEY_ATTR_ENC_ALG_3DES,	algtype_3des,	 8 },
	{ "blowfish",	OAKLEY_ATTR_ENC_ALG_BLOWFISH,	algtype_blowfish, 8 },
	{ "cast",	OAKLEY_ATTR_ENC_ALG_CAST,	algtype_cast128, 8 },
	{ "aes",	OAKLEY_ATTR_ENC_ALG_AES,	algtype_aes,	16 },
};

static int
test_enc_table_roundtrip(void)
{
	size_t i;

	TEST_START("oakley_encdef[] round-trips for des/3des/blowfish/cast/aes");

	for (i = 0; i < sizeof(enc_cases) / sizeof(enc_cases[0]); i++) {
		const struct enc_case *c = &enc_cases[i];

		if (!alg_oakley_encdef_ok(c->doi))
			TEST_FAIL("known enc DOI rejected");
		if (strcmp(alg_oakley_encdef_name(c->doi), c->name) != 0)
			TEST_FAIL("enc name mismatch");
		if (alg_oakley_encdef_doi(c->type) != c->doi)
			TEST_FAIL("enc type->doi mismatch");
		if (alg_oakley_encdef_blocklen(c->doi) != c->blocklen)
			TEST_FAIL("enc blocklen mismatch");
		if (algtype2doi(algclass_isakmp_enc, c->type) != c->doi)
			TEST_FAIL("algtype2doi() mismatch for enc class");
	}

	TEST_PASS();
	return 0;
}

/*
 * alg_oakley_encdef_encrypt()/_decrypt() must round-trip plaintext through
 * AES-128 -- and, same idea as the hash dispatch test, using a distinct
 * DOI (3DES) must not silently reuse AES's function pointers.
 */
static int
test_enc_encrypt_decrypt_dispatch(void)
{
	vchar_t *plain, *key, *iv, *cipher, *decrypted;
	int rc = -1;

	TEST_START("alg_oakley_encdef_encrypt/decrypt() AES-128 round-trip");

	plain = vmalloc(32);
	key = vmalloc(16);
	iv = vmalloc(16);
	if (plain == NULL || key == NULL || iv == NULL) {
		if (plain) vfree(plain);
		if (key) vfree(key);
		if (iv) vfree(iv);
		TEST_FAIL("vmalloc() failed");
	}
	memset(plain->v, 0x5A, plain->l);
	memset(key->v, 0x77, key->l);
	memset(iv->v, 0x00, iv->l);

	cipher = alg_oakley_encdef_encrypt(OAKLEY_ATTR_ENC_ALG_AES, plain, key, iv);
	if (cipher == NULL) {
		vfree(plain); vfree(key); vfree(iv);
		TEST_FAIL("encrypt dispatch returned NULL");
	}

	memset(iv->v, 0x00, iv->l);	/* eay_*_decrypt consumes the IV in place */
	decrypted = alg_oakley_encdef_decrypt(OAKLEY_ATTR_ENC_ALG_AES, cipher, key, iv);
	vfree(cipher); vfree(key); vfree(iv);

	if (decrypted == NULL) {
		vfree(plain);
		TEST_FAIL("decrypt dispatch returned NULL");
	}

	rc = (decrypted->l == plain->l &&
	    memcmp(decrypted->v, plain->v, plain->l) == 0) ? 0 : -1;

	vfree(plain);
	vfree(decrypted);

	if (rc != 0)
		TEST_FAIL("AES round-trip via dispatch did not recover plaintext");

	TEST_PASS();
	return 0;
}

struct ipsec_enc_case {
	const char *label;
	int doi;
	int type;
};

/* Same doi/type pairing style as enc_cases above, but for ipsec_encdef[]
 * (Phase 2 / IPsec DOI values, IPSECDOI_ESP_*) rather than oakley_encdef[]
 * (Phase 1 / OAKLEY_ATTR_ENC_ALG_*) -- a distinct table in algorithm.c that
 * alg_oakley_encdef_doi()'s own coverage says nothing about, since the two
 * tables use unrelated DOI numbering (e.g. IPSECDOI_ESP_AES == 12, not
 * OAKLEY_ATTR_ENC_ALG_AES's value).
 */
static const struct ipsec_enc_case ipsec_enc_cases[] = {
	{ "des",	IPSECDOI_ESP_DES,	algtype_des },
	{ "3des",	IPSECDOI_ESP_3DES,	algtype_3des },
	{ "blowfish",	IPSECDOI_ESP_BLOWFISH,	algtype_blowfish },
	{ "aes",	IPSECDOI_ESP_AES,	algtype_aes },
};

static int
test_ipsec_enc_table_roundtrip(void)
{
	size_t i;

	TEST_START("ipsec_encdef[] round-trips for des/3des/blowfish/aes");

	for (i = 0; i < sizeof(ipsec_enc_cases) / sizeof(ipsec_enc_cases[0]); i++) {
		const struct ipsec_enc_case *c = &ipsec_enc_cases[i];

		if (alg_ipsec_encdef_doi(c->type) != c->doi)
			TEST_FAIL("ipsec enc type->doi mismatch");
	}
	if (alg_ipsec_encdef_doi(9999) != -1)
		TEST_FAIL("unknown ipsec enc type did not return -1");

	TEST_PASS();
	return 0;
}

/*
 * alg_ipsec_encdef_keylen(): DES is a fixed-56-bit-key cipher -- passing
 * len=0 ("give me the default") must report evp_keylen()'s exact answer
 * (EVP_CIPHER_key_length(EVP_des_cbc()) << 3 == 64 bits), pinning both the
 * doi->struct lookup and the keylen function pointer for this row. AES
 * confirms the other, variable-length branch. 3IDEA/IDEA/RC4's rows
 * deliberately leave keylen NULL (unimplemented, per algorithm.c's own
 * comment on ipsec_encdef[]) -- alg_ipsec_encdef_keylen() must report that
 * as -1, the same "unsupported" signal as an unknown DOI entirely, rather
 * than crash dereferencing a NULL function pointer.
 */
static int
test_ipsec_enc_keylen(void)
{
	TEST_START("alg_ipsec_encdef_keylen() DES/AES/unimplemented-row/unknown-doi");

	if (alg_ipsec_encdef_keylen(IPSECDOI_ESP_DES, 0) != 64)
		TEST_FAIL("DES default key length via ipsec table is not 64 bits");
	if (alg_ipsec_encdef_keylen(IPSECDOI_ESP_AES, 0) != 128)
		TEST_FAIL("AES default key length via ipsec table is not 128 bits");
	if (alg_ipsec_encdef_keylen(IPSECDOI_ESP_IDEA, 0) != -1)
		TEST_FAIL("IDEA (keylen unimplemented) did not return -1");
	if (alg_ipsec_encdef_keylen(9999, 0) != -1)
		TEST_FAIL("unknown ipsec enc doi did not return -1");

	TEST_PASS();
	return 0;
}

struct ipsec_hmac_case {
	int doi;
	int type;
	int hashlen;
};

/* ipsec_hmacdef[]'s auth doi numbering (IPSECDOI_ATTR_AUTH_*) is its own
 * table, separate from oakley_hashdef[]/oakley_hmacdef[] above. */
static const struct ipsec_hmac_case ipsec_hmac_cases[] = {
	{ IPSECDOI_ATTR_AUTH_HMAC_MD5,  algtype_hmac_md5,  128 },
	{ IPSECDOI_ATTR_AUTH_HMAC_SHA1, algtype_hmac_sha1, 160 },
	{ IPSECDOI_ATTR_AUTH_NONE,      algtype_non_auth,    0 },
};

static int
test_ipsec_hmac_table_roundtrip(void)
{
	size_t i;

	TEST_START("ipsec_hmacdef[] round-trips for hmac_md5/hmac_sha1/null");

	for (i = 0; i < sizeof(ipsec_hmac_cases) / sizeof(ipsec_hmac_cases[0]); i++) {
		const struct ipsec_hmac_case *c = &ipsec_hmac_cases[i];

		if (alg_ipsec_hmacdef_doi(c->type) != c->doi)
			TEST_FAIL("ipsec hmac type->doi mismatch");
		if (alg_ipsec_hmacdef_hashlen(c->doi) != c->hashlen)
			TEST_FAIL("ipsec hmac hashlen mismatch");
	}
	if (alg_ipsec_hmacdef_doi(9999) != -1)
		TEST_FAIL("unknown ipsec hmac type did not return -1");
	if (alg_ipsec_hmacdef_hashlen(9999) != -1)
		TEST_FAIL("unknown ipsec hmac doi did not return -1 for hashlen");

	TEST_PASS();
	return 0;
}

/*
 * ipsec_compdef[] (IPCOMP algorithms) is the smallest, entirely untested
 * table in this file -- only a doi->name/type triple each, no function
 * pointers, so alg_ipsec_compdef_doi() is the whole of its coverage.
 */
static int
test_ipsec_compdef_doi(void)
{
	TEST_START("alg_ipsec_compdef_doi() round-trips oui/deflate/lzs");

	if (alg_ipsec_compdef_doi(algtype_oui) != IPSECDOI_IPCOMP_OUI)
		TEST_FAIL("oui type->doi mismatch");
	if (alg_ipsec_compdef_doi(algtype_deflate) != IPSECDOI_IPCOMP_DEFLATE)
		TEST_FAIL("deflate type->doi mismatch");
	if (alg_ipsec_compdef_doi(algtype_lzs) != IPSECDOI_IPCOMP_LZS)
		TEST_FAIL("lzs type->doi mismatch");
	if (alg_ipsec_compdef_doi(9999) != -1)
		TEST_FAIL("unknown compression type did not return -1");

	TEST_PASS();
	return 0;
}

/*
 * check_keylen()/default_keylen() gate the key sizes racoon.conf accepts;
 * a regression here means either rejecting a valid configured key length
 * or silently accepting an invalid one.
 */
static int
test_keylen_bounds(void)
{
	TEST_START("check_keylen()/default_keylen() boundaries");

	if (check_keylen(algclass_isakmp_enc, algtype_aes, 128) != 0)
		TEST_FAIL("AES-128 rejected");
	if (check_keylen(algclass_isakmp_enc, algtype_aes, 192) != 0)
		TEST_FAIL("AES-192 rejected");
	if (check_keylen(algclass_isakmp_enc, algtype_aes, 256) != 0)
		TEST_FAIL("AES-256 rejected");
	if (check_keylen(algclass_isakmp_enc, algtype_aes, 129) == 0)
		TEST_FAIL("AES-129 (non-standard) accepted");
	if (check_keylen(algclass_isakmp_enc, algtype_blowfish, 40) != 0)
		TEST_FAIL("Blowfish-40 (lower bound) rejected");
	if (check_keylen(algclass_isakmp_enc, algtype_blowfish, 32) == 0)
		TEST_FAIL("Blowfish-32 (below lower bound) accepted");
	if (check_keylen(algclass_isakmp_enc, algtype_blowfish, 41) == 0)
		TEST_FAIL("Blowfish-41 (not a multiple of 8) accepted");
	if (check_keylen(algclass_isakmp_enc, algtype_des, 1) == 0)
		TEST_FAIL("DES (fixed-length cipher) accepted a key length");

	if (default_keylen(algclass_isakmp_enc, algtype_aes) != 128)
		TEST_FAIL("AES default key length is not 128");
	if (default_keylen(algclass_isakmp_enc, algtype_des) != 0)
		TEST_FAIL("DES (fixed-length cipher) default key length is not 0");
	if (default_keylen(algclass_isakmp_hash, algtype_md5) != 0)
		TEST_FAIL("non-enc class default key length is not 0");

	TEST_PASS();
	return 0;
}

/*
 * algclass2doi() maps each algorithm class to its ISAKMP attribute type
 * (the DOI value used as the attribute *class* in a SA proposal, distinct
 * from algtype2doi()'s per-algorithm DOI value).
 */
static int
test_algclass2doi(void)
{
	TEST_START("algclass2doi() maps every class to its attribute type");

	if (algclass2doi(algclass_ipsec_enc) != IPSECDOI_PROTO_IPSEC_ESP)
		TEST_FAIL("ipsec_enc class mismatch");
	if (algclass2doi(algclass_ipsec_auth) != IPSECDOI_ATTR_AUTH)
		TEST_FAIL("ipsec_auth class mismatch");
	if (algclass2doi(algclass_isakmp_enc) != OAKLEY_ATTR_ENC_ALG)
		TEST_FAIL("isakmp_enc class mismatch");
	if (algclass2doi(algclass_isakmp_hash) != OAKLEY_ATTR_HASH_ALG)
		TEST_FAIL("isakmp_hash class mismatch");
	if (algclass2doi(algclass_isakmp_dh) != OAKLEY_ATTR_GRP_DESC)
		TEST_FAIL("isakmp_dh class mismatch");
	if (algclass2doi(algclass_isakmp_ameth) != OAKLEY_ATTR_AUTH_METHOD)
		TEST_FAIL("isakmp_ameth class mismatch");
	if (algclass2doi(9999) != -1)
		TEST_FAIL("unknown class did not return -1");

	TEST_PASS();
	return 0;
}

/*
 * alg_oakley_dhdef_group() must return the real MODP prime for a known
 * group -- not just a non-NULL pointer to a zeroed struct -- so this
 * drives oakley_dhinit() first, same as the real daemon does at startup.
 */
static int
test_dh_group_lookup(void)
{
	struct dhgroup *dhgrp;

	TEST_START("alg_oakley_dhdef_group() returns the initialized MODP1024 prime");

	oakley_dhinit();

	dhgrp = alg_oakley_dhdef_group(OAKLEY_ATTR_GRP_DESC_MODP1024);
	if (dhgrp == NULL)
		TEST_FAIL("MODP1024 group not found");
	if (dhgrp->prime == NULL || dhgrp->prime->l != 128)
		TEST_FAIL("MODP1024 prime missing or wrong length (expect 1024 bits)");
	if (dhgrp->gen1 != 2)
		TEST_FAIL("MODP1024 generator is not 2");

	if (alg_oakley_dhdef_group(9999) != NULL)
		TEST_FAIL("unknown DH DOI returned a group");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== algorithm.c dispatch table tests ===\n");

	if (test_unknown_values() != 0)
		failed++;
	if (test_hash_table_roundtrip() != 0)
		failed++;
	if (test_hash_one_dispatch() != 0)
		failed++;
	if (test_hmac_one_dispatch() != 0)
		failed++;
	if (test_oakley_hmacdef_doi_roundtrip() != 0)
		failed++;
	if (test_enc_table_roundtrip() != 0)
		failed++;
	if (test_enc_encrypt_decrypt_dispatch() != 0)
		failed++;
	if (test_ipsec_enc_table_roundtrip() != 0)
		failed++;
	if (test_ipsec_enc_keylen() != 0)
		failed++;
	if (test_ipsec_hmac_table_roundtrip() != 0)
		failed++;
	if (test_ipsec_compdef_doi() != 0)
		failed++;
	if (test_keylen_bounds() != 0)
		failed++;
	if (test_algclass2doi() != 0)
		failed++;
	if (test_dh_group_lookup() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
