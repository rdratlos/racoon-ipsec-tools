// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>     /* RSA_PKCS1_PADDING, RSA_F4 (constants only) */
#include <openssl/pem.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/core_names.h>
# include <openssl/param_build.h>
#endif

#include "vmbuf.h"
#include "misc.h"             /* LOCATION */
#include "plog.h"
#include "openssl_compat.h"   /* < 3.0 EVP_PKEY_get_bn_param / OSSL_PARAM shims */
#include "crypto_openssl.h"   /* eay_strerror() */
#include "eay_rsa.h"

struct eay_rsa_st {
	EVP_PKEY *pkey;           /* the one and only representation */
};

/* Wrap an already-built EVP_PKEY; takes ownership (frees pkey on failure). */
static eayRSA *
eayRSA_wrap(EVP_PKEY *pkey)
{
	eayRSA *r;

	if (pkey == NULL) {
		return NULL;
	}
	r = calloc(1, sizeof(*r));
	if (r == NULL) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	r->pkey = pkey;
	return r;
}

/* ===================================================================== */
/* Construction from components                                          */
/* ===================================================================== */

eayRSA *
eayRSA_new_priv(const BIGNUM *n, const BIGNUM *e, const BIGNUM *d,
                const BIGNUM *p, const BIGNUM *q,
                const BIGNUM *dmp1, const BIGNUM *dmq1, const BIGNUM *iqmp)
{
	EVP_PKEY *pkey = NULL;

	if (n == NULL || e == NULL) {
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	/*
	 * 3.0+ path: OSSL_PARAM + EVP_PKEY_fromdata. NO deprecated symbols.
	 * This is what a 4.0 build compiles, and it is already clean.
	 */
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;

	bld = OSSL_PARAM_BLD_new();
	if (bld == NULL) {
		goto done;
	}
	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
		goto done;
	}
	if (d    && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d)) {
		goto done;
	}
	if (p    && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p)) {
		goto done;
	}
	if (q    && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q)) {
		goto done;
	}
	if (dmp1 && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1)) {
		goto done;
	}
	if (dmq1 && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1)) {
		goto done;
	}
	if (iqmp && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp)) {
		goto done;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL || params == NULL) {
		goto done;
	}
	if (EVP_PKEY_fromdata_init(ctx) <= 0) {
		goto done;
	}
	if (EVP_PKEY_fromdata(ctx, &pkey,
	                      d ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
	                      params) <= 0) {
		pkey = NULL;
	}
done:
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);

#else
	/*
	 * < 3.0 path: low-level RSA_set0_*. DEPRECATED, but this branch is never
	 * compiled on >= 3.0, so the deprecated symbols are confined to versions
	 * that still have them. The pragma silences the warning where it warns.
	 */
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	RSA *rsa = RSA_new();
	BIGNUM *n_dup = NULL, *e_dup = NULL, *d_dup = NULL;
	BIGNUM *p_dup = NULL, *q_dup = NULL;
	BIGNUM *dmp1_dup = NULL, *dmq1_dup = NULL, *iqmp_dup = NULL;

	if (rsa == NULL) {
		goto l_done;
	}

	n_dup = BN_dup(n);
	e_dup = BN_dup(e);
	d_dup = d ? BN_dup(d) : NULL;
	if (n_dup == NULL || e_dup == NULL || (d != NULL && d_dup == NULL)) {
		BN_free(n_dup);
		BN_free(e_dup);
		BN_clear_free(d_dup);
		goto l_fail;
	}
	if (!RSA_set0_key(rsa, n_dup, e_dup, d_dup)) {
		BN_free(n_dup);
		BN_free(e_dup);
		BN_clear_free(d_dup);
		goto l_fail;
	}
	n_dup = e_dup = d_dup = NULL; /* ownership transferred to rsa */

	if (p && q) {
		p_dup = BN_dup(p);
		q_dup = BN_dup(q);
		if (p_dup == NULL || q_dup == NULL) {
			BN_clear_free(p_dup);
			BN_clear_free(q_dup);
			goto l_fail;
		}
		if (!RSA_set0_factors(rsa, p_dup, q_dup)) {
			BN_clear_free(p_dup);
			BN_clear_free(q_dup);
			goto l_fail;
		}
		p_dup = q_dup = NULL; /* ownership transferred to rsa */
	}
	if (dmp1 && dmq1 && iqmp) {
		dmp1_dup = BN_dup(dmp1);
		dmq1_dup = BN_dup(dmq1);
		iqmp_dup = BN_dup(iqmp);
		if (dmp1_dup == NULL || dmq1_dup == NULL || iqmp_dup == NULL) {
			BN_clear_free(dmp1_dup);
			BN_clear_free(dmq1_dup);
			BN_clear_free(iqmp_dup);
			goto l_fail;
		}
		if (!RSA_set0_crt_params(rsa, dmp1_dup, dmq1_dup, iqmp_dup)) {
			BN_clear_free(dmp1_dup);
			BN_clear_free(dmq1_dup);
			BN_clear_free(iqmp_dup);
			goto l_fail;
		}
		/* dmp1_dup/dmq1_dup/iqmp_dup ownership transferred to rsa */
	}
	pkey = EVP_PKEY_new();
	if (pkey == NULL || !EVP_PKEY_assign_RSA(pkey, rsa)) {
		if (pkey != NULL) {
			EVP_PKEY_free(pkey);
			pkey = NULL;
		}
		goto l_fail;
	}
	rsa = NULL;            /* ownership transferred to pkey */
	goto l_done;
l_fail:
	RSA_free(rsa);
l_done:
# pragma GCC diagnostic pop
#endif

	return eayRSA_wrap(pkey);
}

eayRSA *
eayRSA_new_pub(const BIGNUM *n, const BIGNUM *e)
{
	return eayRSA_new_priv(n, e, NULL, NULL, NULL, NULL, NULL, NULL);
}

/* ===================================================================== */
/* Generation -- single path, no deprecated symbols, works 1.1.x .. 4.0  */
/* ===================================================================== */

eayRSA *
eayRSA_generate(int bits, unsigned long e)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	BIGNUM *eb = NULL;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (ctx == NULL) {
		return NULL;
	}
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		goto done;
	}
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		goto done;
	}
	eb = BN_new();
	if (eb == NULL || !BN_set_word(eb, e)) {
		goto done;
	}
	if (COMPAT_RSA_KEYGEN_PUBEXP(ctx, eb) <= 0) {
		goto done;
	}
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		pkey = NULL;
	}
done:
	BN_free(eb);      /* caller always owns eb under the normalized convention */
	EVP_PKEY_CTX_free(ctx);
	return eayRSA_wrap(pkey);
}

/* ===================================================================== */
/* Lifecycle                                                             */
/* ===================================================================== */

eayRSA *
eayRSA_dup(const eayRSA *src)
{
	eayRSA *r;

	if (src == NULL || src->pkey == NULL) {
		return NULL;
	}
	if (!EVP_PKEY_up_ref(src->pkey)) {   /* shared ref; keys are immutable */
		return NULL;
	}
	r = calloc(1, sizeof(*r));
	if (r == NULL) {
		EVP_PKEY_free(src->pkey);
		return NULL;
	}
	r->pkey = src->pkey;
	return r;
}

void
eayRSA_free(eayRSA *r)
{
	if (r == NULL) {
		return;
	}
	EVP_PKEY_free(r->pkey);   /* refcounted: correct for shared dups */
	free(r);
}

/* ===================================================================== */
/* Introspection                                                         */
/* ===================================================================== */

int
eayRSA_has_private(const eayRSA *r)
{
	BIGNUM *d = NULL;
	int have = 0;

	if (r == NULL || r->pkey == NULL) {
		return 0;
	}
	/* EVP_PKEY_get_bn_param: native on 3.0, compat-shimmed on < 3.0. */
	if (EVP_PKEY_get_bn_param(r->pkey, OSSL_PKEY_PARAM_RSA_D, &d) && d != NULL) {
		have = 1;
	}
	BN_clear_free(d);
	return have;
}

int
eayRSA_size(const eayRSA *r)
{
	if (r == NULL || r->pkey == NULL) {
		return 0;
	}
	return EVP_PKEY_size(r->pkey);
}

int
eayRSA_get_params(const eayRSA *r,
                  BIGNUM **n, BIGNUM **e, BIGNUM **d,
                  BIGNUM **p, BIGNUM **q,
                  BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp)
{
	/*
	 * Each requested component is fetched as an owned copy. On any failure
	 * the caller still frees whatever came back non-NULL. Private outputs
	 * should be released with BN_clear_free by the caller.
	 */
	if (r == NULL || r->pkey == NULL) {
		return -1;
	}
#define GET(field, name) \
	do { if ((field) != NULL) { \
		*(field) = NULL; \
		(void)EVP_PKEY_get_bn_param(r->pkey, (name), (field)); \
	} } while (0)

	GET(n,    OSSL_PKEY_PARAM_RSA_N);
	GET(e,    OSSL_PKEY_PARAM_RSA_E);
	GET(d,    OSSL_PKEY_PARAM_RSA_D);
	GET(p,    OSSL_PKEY_PARAM_RSA_FACTOR1);
	GET(q,    OSSL_PKEY_PARAM_RSA_FACTOR2);
	GET(dmp1, OSSL_PKEY_PARAM_RSA_EXPONENT1);
	GET(dmq1, OSSL_PKEY_PARAM_RSA_EXPONENT2);
	GET(iqmp, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
#undef GET
	return 0;
}

/* ===================================================================== */
/* Crypto operations -- pure EVP, no version split, 4.0-clean            */
/* ===================================================================== */

vchar_t *
eayRSA_sign(const eayRSA *r, vchar_t *src)
{
	EVP_PKEY_CTX *ctx = NULL;
	vchar_t *sig = NULL;
	size_t siglen = 0;

	/*
	 * Empty input is rejected: PKCS#1 v1.5 verify-recover never yields a
	 * 0-byte result, so an empty-data signature could never verify.
	 */
	if (r == NULL || r->pkey == NULL || src == NULL || src->l == 0) {
		return NULL;
	}
	ctx = EVP_PKEY_CTX_new(r->pkey, NULL);
	if (ctx == NULL) {
		return NULL;
	}
	if (EVP_PKEY_sign_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		goto done;
	}
	if (EVP_PKEY_sign(ctx, NULL, &siglen,
	                  (unsigned char *)src->v, src->l) <= 0) {
		goto done;
	}
	sig = vmalloc(siglen);
	if (sig == NULL) {
		goto done;
	}
	if (EVP_PKEY_sign(ctx, (unsigned char *)sig->v, &siglen,
	                  (unsigned char *)src->v, src->l) <= 0) {
		vfree(sig);
		sig = NULL;
		goto done;
	}
	sig->l = siglen;
done:
	EVP_PKEY_CTX_free(ctx);
	return sig;
}

/*
 * RSA verification using EVP_PKEY (OpenSSL 3.0 compatible)
 *
 * This performs RAW RSA verification (textbook RSA with PKCS#1 v1.5 padding)
 * by recovering the original data from the signature and comparing it.
 * NOT digest-based verification.
 *
 * This matches the original behavior of:
 *   RSA_public_decrypt() followed by memcmp()
 *
 * Body lifted verbatim from eay_pkey_verify() in crypto_openssl.c, retargeted
 * at r->pkey, to preserve the proven comparison logic.
 *
 * OUT: return -1 when error or verification failed
 *      return  0 on successful verification
 */
int
eayRSA_verify(const eayRSA *r, vchar_t *src, vchar_t *sig)
{
	EVP_PKEY_CTX *ctx = NULL;
	vchar_t *recovered = NULL;
	size_t recovered_len;
	int ret = -1;

	if (!r || !r->pkey || !src || !sig) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "eayRSA_verify: NULL parameter (r=%p, src=%p, sig=%p)\n",
		     r, src, sig);
		return -1;
	}

	/* Verify this is an RSA key */
	if (EVP_PKEY_get_id(r->pkey) != EVP_PKEY_RSA) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "eayRSA_verify: Expected RSA key, got type %d\n",
		     EVP_PKEY_get_id(r->pkey));
		return -1;
	}

	ctx = EVP_PKEY_CTX_new(r->pkey, NULL);
	if (!ctx) {
		plog(LLV_ERROR, LOCATION, NULL, "EVP_PKEY_CTX_new failed\n");
		return -1;
	}

	/*
	 * Use verify_recover for raw RSA verification
	 * This recovers the original data that was signed
	 */
	if (EVP_PKEY_verify_recover_init(ctx) <= 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "EVP_PKEY_verify_recover_init failed: %s\n", eay_strerror());
		goto end;
	}

	/* Set PKCS#1 v1.5 padding (matches original RSA_PKCS1_PADDING) */
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "EVP_PKEY_CTX_set_rsa_padding failed: %s\n", eay_strerror());
		goto end;
	}

	/*
	 * NOTE: We do NOT set signature MD here!
	 * This is raw RSA verification, not digest-based verification.
	 * Setting EVP_PKEY_CTX_set_signature_md would be wrong.
	 */

	/* Determine buffer length for recovered data */
	if (EVP_PKEY_verify_recover(ctx, NULL, &recovered_len,
				    (unsigned char *)sig->v, sig->l) <= 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "EVP_PKEY_verify_recover length determination failed: %s\n",
		     eay_strerror());
		goto end;
	}

	/* Allocate buffer for recovered data */
	recovered = vmalloc(recovered_len);
	if (!recovered) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "vmalloc(%zu) failed for recovered buffer\n", recovered_len);
		goto end;
	}

	/* Recover the original data from signature (raw RSA public decrypt) */
	if (EVP_PKEY_verify_recover(ctx, (unsigned char *)recovered->v, &recovered_len,
				    (unsigned char *)sig->v, sig->l) <= 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "EVP_PKEY_verify_recover failed: %s\n", eay_strerror());
		goto end;
	}

	/* Update actual recovered length */
	recovered->l = recovered_len;

	/* Compare recovered data with original (matches original memcmp behavior) */
	if (recovered->l != src->l) {
		plog(LLV_WARNING, LOCATION, NULL,
		     "Signature verification failed: length mismatch (expected %zu, got %zu)\n",
		     src->l, recovered->l);
		ret = -1;
	} else if (memcmp(recovered->v, src->v, src->l) != 0) {
		plog(LLV_WARNING, LOCATION, NULL,
		     "Signature verification failed: data mismatch\n");
		ret = -1;
	} else {
		plog(LLV_DEBUG, LOCATION, NULL,
		     "Signature verification SUCCESS (%zu bytes)\n", src->l);
		ret = 0;  /* SUCCESS - matches original return value convention */
	}

end:
	if (recovered)
		vfree(recovered);
	if (ctx)
		compat_EVP_PKEY_CTX_free(ctx);
	return ret;
}

/* ===================================================================== */
/* Serialization -- single clean path via EVP/PEM                        */
/* ===================================================================== */

eayRSA *
eayRSA_read_private_pem(FILE *fp)
{
	EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

	if (pkey != NULL && EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	return eayRSA_wrap(pkey);
}

eayRSA *
eayRSA_read_public_pem(FILE *fp)
{
	EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

	if (pkey != NULL && EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
		EVP_PKEY_free(pkey);
		return NULL;
	}
	return eayRSA_wrap(pkey);
}

int
eayRSA_write_private_pem(FILE *fp, const eayRSA *r)
{
	if (r == NULL || r->pkey == NULL) {
		return -1;
	}
	return PEM_write_PrivateKey(fp, r->pkey, NULL, NULL, 0, NULL, NULL) ? 0 : -1;
}

int
eayRSA_write_public_pem(FILE *fp, const eayRSA *r)
{
	if (r == NULL || r->pkey == NULL) {
		return -1;
	}
	return PEM_write_PUBKEY(fp, r->pkey) ? 0 : -1;
}

int
eayRSA_print(FILE *fp, const eayRSA *r)
{
	BIO *bio;
	int ret;

	if (r == NULL || r->pkey == NULL) {
		return -1;
	}
	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	if (bio == NULL) {
		return -1;
	}
	ret = EVP_PKEY_print_private(bio, r->pkey, 0, NULL) > 0 ? 0 : -1;
	BIO_free(bio);
	return ret;
}

EVP_PKEY *
eayRSA_evp_pkey(const eayRSA *r)
{
	return (r != NULL) ? r->pkey : NULL;   /* borrowed; do not free */
}

int
eayRSA_set_pkcs1_padding(EVP_PKEY_CTX *ctx)
{
	if (ctx == NULL)
		return -1;
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
		return -1;
	return 0;
}
