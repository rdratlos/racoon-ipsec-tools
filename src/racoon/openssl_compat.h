#ifndef OPENSSL_COMPAT_H
#define OPENSSL_COMPAT_H

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp);

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key);
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
int DH_set_length(DH *dh, long length);

HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX* ctx);

RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);

#define ASN1_STRING_length(s) s->length
#define ASN1_STRING_get0_data(s) s->data

#define X509_get_subject_name(x) x->cert_info->subject
#define X509_get_issuer_name(x) x->cert_info->issuer
#define X509_NAME_ENTRY_get_data(n) n->value
#define X509_NAME_ENTRY_get_object(n) n->object
#define X509_STORE_CTX_get_current_cert(ctx) ctx->current_cert
#define X509_STORE_CTX_get_error(ctx) ctx->error
#define X509_STORE_CTX_get_error_depth(ctx) ctx->error_depth

#define OPENSSL_VERSION SSLEAY_VERSION
#define OpenSSL_version SSLeay_version

#endif /* OPENSSL_VERSION_NUMBER */

#endif /* OPENSSL_COMPAT_H */
