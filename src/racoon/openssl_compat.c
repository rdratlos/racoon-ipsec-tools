/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "openssl_compat.h"

#include <string.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* Suppress deprecation warnings for OpenSSL 3.0 low-level API usage */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void *OPENSSL_zalloc(size_t num)
{
    void *ret = OPENSSL_malloc(num);

    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        BN_free(r->p);
        r->p = p;
    }
    if (q != NULL) {
        BN_free(r->q);
        r->q = q;
    }

    return 1;
}

int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        BN_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL) {
        BN_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL) {
        BN_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

void RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
        || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the field pub_key in dh is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    if (dh->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}

int DH_set_length(DH *dh, long length)
{
    dh->length = length;
    return 1;
}

HMAC_CTX *HMAC_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(HMAC_CTX));
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}

RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_RSA) {
        return NULL;
    }
    return pkey->pkey.rsa;
}


#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

/*
 * Compatibility functions that work across OpenSSL 1.1.0, 1.1.1, and 3.0+
 * These use low-level RSA API which is deprecated in 3.0 but still maintained.
 * All deprecation warnings are suppressed at the top of this file.
 */

/* Check if RSA key has private component */
int compat_RSA_has_private(const RSA *rsa)
{
	const BIGNUM *d = NULL;

	if (rsa == NULL)
		return 0;

	RSA_get0_key(rsa, NULL, NULL, &d);
	return (d != NULL);
}

/* Duplicate RSA key (handles both public and private keys) */
RSA *compat_RSA_dup(const RSA *rsa)
{
	RSA *ret = NULL;

	if (rsa == NULL)
		return NULL;

	/* Use i2d/d2i approach which works for all versions.
     * This creates a true deep copy via DER encoding. */
	if (compat_RSA_has_private(rsa)) {
		unsigned char *der = NULL;
		const unsigned char *der_const = NULL;
		int der_len = 0;

		/* Encode private key to DER format */
		der_len = i2d_RSAPrivateKey(rsa, &der);
		if (der_len <= 0)
			return NULL;

		/* Decode back to create a new RSA structure */
		der_const = der;
		ret = d2i_RSAPrivateKey(NULL, &der_const, der_len);
		OPENSSL_free(der);
	} else {
		unsigned char *der = NULL;
		const unsigned char *der_const = NULL;
		int der_len = 0;

		/* Encode public key to DER format */
		der_len = i2d_RSAPublicKey(rsa, &der);
		if (der_len <= 0)
			return NULL;

		/* Decode back to create a new RSA structure */
		der_const = der;
		ret = d2i_RSAPublicKey(NULL, &der_const, der_len);
		OPENSSL_free(der);
	}

	return ret;
}

/* Print RSA key to file pointer */
int compat_RSA_print_fp(FILE *fp, const RSA *rsa, int indent)
{
	BIO *bio = NULL;
	int ret = 0;

	if (rsa == NULL || fp == NULL)
		return 0;

	/* Create a BIO from the file pointer */
	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	if (bio == NULL)
		return 0;

	/* Use RSA_print which works for all versions */
	ret = RSA_print(bio, (RSA *)rsa, indent);

	BIO_free(bio);
	return ret;
}

/*
 * Allocate a new RSA key and populate it from individual BIGNUMs.
 * Takes ownership of all passed BIGNUMs.
 * Returns NULL on failure (all BIGNUMs are freed on error).
 */
RSA *compat_RSA_new_from_params(BIGNUM *n, BIGNUM *e, BIGNUM *d,
                                BIGNUM *p, BIGNUM *q,
                                BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
	RSA *rsa = RSA_new();
	if (rsa == NULL) {
		BN_free(n);
		BN_free(e);
		BN_free(d);
		if (p)    BN_clear_free(p);
		if (q)    BN_clear_free(q);
		if (dmp1) BN_clear_free(dmp1);
		if (dmq1) BN_clear_free(dmq1);
		if (iqmp) BN_clear_free(iqmp);
		return NULL;
	}

	if (!RSA_set0_key(rsa, n, e, d)) {
		RSA_free(rsa);
		BN_free(n);
		BN_free(e);
		BN_free(d);
		if (p)    BN_clear_free(p);
		if (q)    BN_clear_free(q);
		if (dmp1) BN_clear_free(dmp1);
		if (dmq1) BN_clear_free(dmq1);
		if (iqmp) BN_clear_free(iqmp);
		return NULL;
	}

	/* Optional CRT parameters - only set if all are present */
	if (p && q && dmp1 && dmq1 && iqmp) {
		if (!RSA_set0_factors(rsa, p, q) ||
		    !RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)) {
			RSA_free(rsa);
			if (p)    BN_clear_free(p);
			if (q)    BN_clear_free(q);
			if (dmp1) BN_clear_free(dmp1);
			if (dmq1) BN_clear_free(dmq1);
			if (iqmp) BN_clear_free(iqmp);
			return NULL;
		}
	}

	return rsa;
}

/*
 * Wrapper around RSA_free() to avoid deprecated-declarations warnings
 * in caller code when building against OpenSSL 3.0+.
 */
void compat_RSA_free(RSA *rsa)
{
	if (rsa != NULL)
		RSA_free(rsa);
}

/* Restore warnings */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#pragma GCC diagnostic pop
#endif
