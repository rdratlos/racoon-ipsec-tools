#ifndef OPENSSL_COMPAT_H
#define OPENSSL_COMPAT_H

#include <openssl/opensslv.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

/* Compatibility layer for OpenSSL 1.1.x vs 3.0+ */

/* EVP_PKEY_get_id() was introduced in OpenSSL 3.0 as a replacement for
 * EVP_PKEY_id(). Provide a compatibility macro for older versions. */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define EVP_PKEY_get_id(pkey) EVP_PKEY_id(pkey)

/* Opaque types for OSSL_PARAM builder */
typedef struct ossl_param_st OSSL_PARAM_BLD;
typedef struct ossl_param_st OSSL_PARAM;
typedef void OSSL_LIB_CTX;

/* OSSL_PARAM builder API */
OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void);
void OSSL_PARAM_BLD_free(OSSL_PARAM_BLD *bld);
int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld, const char *key,
                            const BIGNUM *bn);
int OSSL_PARAM_BLD_push_size_t(OSSL_PARAM_BLD *bld, const char *key,
                                size_t val);
OSSL_PARAM *OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld);
void OSSL_PARAM_free(OSSL_PARAM *params);

/* EVP_PKEY fromdata API */
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx,
                                           const char *name,
                                           const char *propquery);
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **pkey,
                      int selection, OSSL_PARAM *params);
int EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *key_name,
                          BIGNUM **bn);

/* Selection constants */
#define EVP_PKEY_KEY_PARAMETERS 0x01
#define EVP_PKEY_PUBLIC_KEY     0x02
#define EVP_PKEY_KEYPAIR        0x03

/* DH/FFC parameter name constants */
#define OSSL_PKEY_PARAM_FFC_P        "p"
#define OSSL_PKEY_PARAM_FFC_G        "g"
#define OSSL_PKEY_PARAM_DH_PRIV_LEN  "priv_len"
#define OSSL_PKEY_PARAM_PUB_KEY      "pub"
#define OSSL_PKEY_PARAM_PRIV_KEY     "priv"

/* RSA parameter name constants */
# ifndef OSSL_PKEY_PARAM_RSA_N
#  define OSSL_PKEY_PARAM_RSA_N            "n"
# endif
# ifndef OSSL_PKEY_PARAM_RSA_E
#  define OSSL_PKEY_PARAM_RSA_E            "e"
# endif
# ifndef OSSL_PKEY_PARAM_RSA_D
#  define OSSL_PKEY_PARAM_RSA_D            "d"
# endif
# ifndef OSSL_PKEY_PARAM_RSA_FACTOR1
#  define OSSL_PKEY_PARAM_RSA_FACTOR1      "rsa-factor1"
# endif
# ifndef OSSL_PKEY_PARAM_RSA_FACTOR2
#  define OSSL_PKEY_PARAM_RSA_FACTOR2      "rsa-factor2"
# endif
# ifndef OSSL_PKEY_PARAM_RSA_EXPONENT1
#  define OSSL_PKEY_PARAM_RSA_EXPONENT1    "rsa-exponent1"
# endif
# ifndef OSSL_PKEY_PARAM_RSA_EXPONENT2
#  define OSSL_PKEY_PARAM_RSA_EXPONENT2    "rsa-exponent2"
# endif
# ifndef OSSL_PKEY_PARAM_RSA_COEFFICIENT1
#  define OSSL_PKEY_PARAM_RSA_COEFFICIENT1 "rsa-coefficient1"
# endif

#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

/*
 * Compatibility functions for RSA operations
 * These work across OpenSSL 1.1.0, 1.1.1, and 3.0+
 *
 * These all operate on the legacy RSA* type, which is unavailable when
 * building with OPENSSL_NO_DEPRECATED. Production code (crypto_openssl.c)
 * no longer needs the legacy RSA* type at all -- it uses eayRSA* throughout
 * -- so these are only declared for the remaining legacy boundary callers
 * (e.g. test code and eaytest.c that still parse RSA* out of PEM/ASN.1).
 */
#ifndef OPENSSL_NO_DEPRECATED
#include <openssl/rsa.h>

/* Check if RSA key has private component */
int compat_RSA_has_private(const RSA *rsa);

/* Duplicate RSA key (handles both public and private keys) */
RSA *compat_RSA_dup(const RSA *rsa);

/* Print RSA key to file pointer */
int compat_RSA_print_fp(FILE *fp, const RSA *rsa, int indent);

/*
 * Helper to allocate a new RSA key and populate it from individual BIGNUMs.
 * This is used by the prsa parser to avoid direct use of deprecated RSA_new()
 * in grammar action code where pragma suppression is unreliable.
 *
 * Takes ownership of all passed BIGNUMs (they must not be freed by caller).
 * Returns NULL on failure (and frees all passed BIGNUMs on error).
 */
RSA *compat_RSA_new_from_params(BIGNUM *n, BIGNUM *e, BIGNUM *d,
                                BIGNUM *p, BIGNUM *q,
                                BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);

/*
 * Wrapper around RSA_free() to avoid deprecated-declarations warnings
 * in caller code when building against OpenSSL 3.0+.
 */
void compat_RSA_free(RSA *rsa);

/*
 * Extract all RSA parameters (public and private) from an RSA key.
 * Output pointers may be NULL if the caller does not need that particular
 * parameter.  This wraps the deprecated RSA_get0_key(), RSA_get0_factors(),
 * and RSA_get0_crt_params() in a single function.
 *
 * Returns 0 on success, -1 on failure (invalid key or NULL rsa pointer).
 */
int compat_RSA_get0_params(const RSA *rsa,
                           const BIGNUM **n, const BIGNUM **e, const BIGNUM **d,
                           const BIGNUM **p, const BIGNUM **q,
                           const BIGNUM **dmp1, const BIGNUM **dmq1,
                           const BIGNUM **iqmp);

/*
 * Wrapper around EVP_PKEY_get1_RSA() to avoid deprecated-declarations warnings
 * in caller code when building against OpenSSL 3.0+.
 *
 * Returns a new reference to the RSA key embedded in the EVP_PKEY,
 * or NULL on failure.  The caller must free the returned RSA* with
 * RSA_free() or compat_RSA_free().
 */
RSA *compat_EVP_PKEY_get1_RSA(const EVP_PKEY *pkey);
#endif /* !OPENSSL_NO_DEPRECATED */

/*
 * Wrapper around DES_is_weak_key() to avoid deprecated-declarations warnings
 * in caller code when building against OpenSSL 3.0+.
 *
 * Returns non-zero if the key is weak, 0 otherwise.
 */
int compat_DES_is_weak_key(const void *key);

/* compat_EVP_PKEY_CTX_free: free EVP_PKEY_CTX and any compat shim app_data.
   On OpenSSL 3.0+, this is a no-op wrapper around EVP_PKEY_CTX_free. */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
void compat_EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
#else
static inline void compat_EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
{
	EVP_PKEY_CTX_free(ctx);
}
#endif

/*
 * compat_rsa_keygen_pubexp() / COMPAT_RSA_KEYGEN_PUBEXP(): set the RSA
 * keygen public exponent on an EVP_PKEY_CTX.
 *
 * EVP_PKEY_CTX_set1_rsa_keygen_pubexp() (3.0+) copies e and leaves
 * ownership with the caller, while the pre-3.0
 * EVP_PKEY_CTX_set_rsa_keygen_pubexp() consumes e on success. This macro
 * normalizes both to a single convention: the caller always owns and
 * frees the BIGNUM passed in.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/* set1 makes its own copy; caller retains ownership. */
#  define COMPAT_RSA_KEYGEN_PUBEXP(ctx, e) \
            EVP_PKEY_CTX_set1_rsa_keygen_pubexp((ctx), (e))
#else
/* Pre-3.0 set_ CONSUMES the BIGNUM on success. Hand it a copy so the
 * caller's "I always own e" convention holds uniformly. Not deprecated on
 * 1.0.x/1.1.x, so no pragma needed here. */
static inline int
compat_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *e)
{
	BIGNUM *copy = BN_dup(e);
	int rc;
	if (copy == NULL) { return -1; }
	rc = EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, copy);
	if (rc <= 0) { BN_free(copy); }   /* not consumed on failure */
	return rc;
}
#  define COMPAT_RSA_KEYGEN_PUBEXP(ctx, e) compat_rsa_keygen_pubexp((ctx), (e))
#endif

#endif /* OPENSSL_COMPAT_H */
