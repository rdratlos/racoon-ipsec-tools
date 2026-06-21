// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

#ifndef EAY_RSA_H
#define EAY_RSA_H

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include "vmbuf.h"   /* vchar_t */

/*
 * eayRSA -- opaque RSA key handle.
 *
 * The daemon, the public headers, the prsa parser %union and struct rsa_key
 * hold ONLY eayRSA* and call ONLY the functions below. The concrete
 * representation is private to eay_rsa.c.
 *
 * Representation: an EVP_PKEY. Because EVP_PKEY survives OpenSSL 4.0 and the
 * 3.0+ construction path uses OSSL_PARAM/EVP_PKEY_fromdata (non-deprecated),
 * the only deprecated RSA_* code lives in the OpenSSL < 3.0 branch -- which a
 * >= 3.0 (incl. 4.0) build never compiles. The object is therefore 4.0-ready
 * by construction, and the daemon never names the `RSA` type at all.
 *
 * This module sits ON TOP of the existing openssl_compat shims; on < 3.0 it
 * relies on the compat-provided EVP_PKEY_get_bn_param / OSSL_PARAM helpers
 * exactly as the rest of the code already does.
 */
typedef struct eay_rsa_st eayRSA;

/* --- construction (caller owns the result; release with eayRSA_free) --- */

/* Public key from modulus n and public exponent e. */
eayRSA *eayRSA_new_pub(const BIGNUM *n, const BIGNUM *e);

/*
 * Private key from components. d may be NULL (-> public key); p, q and the
 * CRT params may be NULL (-> bare n,e,d key). Inputs are COPIED; the caller
 * keeps ownership of its BIGNUMs.
 */
eayRSA *eayRSA_new_priv(const BIGNUM *n, const BIGNUM *e, const BIGNUM *d,
                        const BIGNUM *p, const BIGNUM *q,
                        const BIGNUM *dmp1, const BIGNUM *dmq1,
                        const BIGNUM *iqmp);

/* Generate a fresh keypair (e.g. for plainrsa-gen). e is e.g. RSA_F4. */
eayRSA *eayRSA_generate(int bits, unsigned long e);

/* Shared-reference duplicate (keys are immutable, so sharing is safe). */
eayRSA *eayRSA_dup(const eayRSA *src);

void eayRSA_free(eayRSA *r);

/* --- introspection --- */

int eayRSA_has_private(const eayRSA *r);   /* 1 if private key present, else 0 */
int eayRSA_size(const eayRSA *r);          /* modulus size in bytes, 0 on error */

/*
 * Extract key components. Each non-NULL output receives a NEWLY ALLOCATED
 * BIGNUM the caller must free (BN_free for public, BN_clear_free for private).
 * NOTE: this is OWNED, not borrowed -- unlike the old RSA_get0_* contract --
 * because EVP_PKEY only yields copies. Returns 0 on success, -1 on error.
 */
int eayRSA_get_params(const eayRSA *r,
                      BIGNUM **n, BIGNUM **e, BIGNUM **d,
                      BIGNUM **p, BIGNUM **q,
                      BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp);

/* --- crypto ops (RSASSA-PKCS1-v1_5, raw, matching legacy racoon) --- */

vchar_t *eayRSA_sign(const eayRSA *r, vchar_t *src);
int      eayRSA_verify(const eayRSA *r, vchar_t *src, vchar_t *sig);  /* 0 == OK */

/* --- serialization (all single-path, 4.0-clean via EVP/PEM) --- */

eayRSA *eayRSA_read_private_pem(FILE *fp);
eayRSA *eayRSA_read_public_pem(FILE *fp);
int     eayRSA_write_private_pem(FILE *fp, const eayRSA *r);
int     eayRSA_write_public_pem(FILE *fp, const eayRSA *r);

/* --- debug --- */

int eayRSA_print(FILE *fp, const eayRSA *r);

/*
 * Escape hatch: borrow the underlying EVP_PKEY (NOT owned -- do not free).
 * EVP_PKEY survives 4.0, so exposing it reintroduces no deprecated type.
 */
EVP_PKEY *eayRSA_evp_pkey(const eayRSA *r);

/*
 * Set PKCS#1 v1.5 padding on an EVP_PKEY_CTX performing raw RSA sign/verify.
 * Wraps EVP_PKEY_CTX_set_rsa_padding()/RSA_PKCS1_PADDING so callers never
 * need <openssl/rsa.h> just to pick a padding mode. Returns 0 on success,
 * -1 on error.
 */
int eayRSA_set_pkcs1_padding(EVP_PKEY_CTX *ctx);

#endif /* EAY_RSA_H */
