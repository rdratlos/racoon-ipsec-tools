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
#include <openssl/objects.h>
#include <openssl/des.h>



/*
 * OpenSSL 3.0 API shims for OpenSSL 1.1.x
 *
 * These implement the OSSL_PARAM_BLD / EVP_PKEY fromdata API on top of
 * the OpenSSL 1.1.x legacy DH and RSA API.
 */
#if OPENSSL_VERSION_NUMBER < 0x30000000L

/* Parameter type enum */
typedef enum {
    PARAM_BN,
    PARAM_SIZE_T
} ossl_param_type_t;

/* Linked list node holding one key/value parameter */
struct ossl_param_bld_st {
    char               *key;
    BIGNUM             *bn;
    size_t              size_t_val;
    ossl_param_type_t   type;
    struct ossl_param_bld_st *next;
};

/* Container struct — OSSL_PARAM_BLD and OSSL_PARAM both typedef to this */
struct ossl_param_st {
    struct ossl_param_bld_st *head;
    int                       count;
    char                      algo[16];
};



OSSL_PARAM_BLD *
OSSL_PARAM_BLD_new(void)
{
	struct ossl_param_st *bld =
		(struct ossl_param_st *)OPENSSL_malloc(sizeof(struct ossl_param_st));
	if (bld == NULL)
		return NULL;
	memset(bld, 0, sizeof(*bld));
	return (OSSL_PARAM_BLD *)bld;
}

void
OSSL_PARAM_BLD_free(OSSL_PARAM_BLD *bld)
{
	struct ossl_param_bld_st *node, *next;

	if (bld == NULL)
		return;

	node = bld->head;
	while (node != NULL) {
		next = node->next;
		/* Free the duplicated key string */
		OPENSSL_free(node->key);
		/* Free the duplicated BIGNUM if present */
		if (node->type == PARAM_BN && node->bn != NULL)
			BN_free(node->bn);
		OPENSSL_free(node);
		node = next;
	}
	OPENSSL_free(bld);
}

int
OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *bld, const char *key,
                        const BIGNUM *bn)
{
	struct ossl_param_bld_st *node, *cur;

	if (bld == NULL || key == NULL)
		return 0;

	node = (struct ossl_param_bld_st *)
		OPENSSL_malloc(sizeof(struct ossl_param_bld_st));
	if (node == NULL)
		return 0;
	memset(node, 0, sizeof(*node));

	node->key = OPENSSL_strdup(key);
	if (node->key == NULL) {
		OPENSSL_free(node);
		return 0;
	}

	if (bn != NULL) {
		node->bn = BN_dup(bn);
		if (node->bn == NULL) {
			OPENSSL_free(node->key);
			OPENSSL_free(node);
			return 0;
		}
	}

	node->type = PARAM_BN;
	node->next = NULL;

	/* Append to end of list */
	if (bld->head == NULL) {
		bld->head = node;
	} else {
		cur = bld->head;
		while (cur->next != NULL)
			cur = cur->next;
		cur->next = node;
	}
	bld->count++;

	return 1;
}

int
OSSL_PARAM_BLD_push_size_t(OSSL_PARAM_BLD *bld, const char *key, size_t val)
{
	struct ossl_param_bld_st *node, *cur;

	if (bld == NULL || key == NULL)
		return 0;

	node = (struct ossl_param_bld_st *)
		OPENSSL_malloc(sizeof(struct ossl_param_bld_st));
	if (node == NULL)
		return 0;
	memset(node, 0, sizeof(*node));

	node->key = OPENSSL_strdup(key);
	if (node->key == NULL) {
		OPENSSL_free(node);
		return 0;
	}

	node->size_t_val = val;
	node->type = PARAM_SIZE_T;
	node->next = NULL;

	/* Append to end of list */
	if (bld->head == NULL) {
		bld->head = node;
	} else {
		cur = bld->head;
		while (cur->next != NULL)
			cur = cur->next;
		cur->next = node;
	}
	bld->count++;

	return 1;
}

OSSL_PARAM *
OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *bld)
{
	struct ossl_param_st *params;

	if (bld == NULL)
		return NULL;

	/*
	 * Allocate a new, separate container for the OSSL_PARAM.
	 * This matches the real OpenSSL 3.0 API where OSSL_PARAM_BLD_free(bld)
	 * and OSSL_PARAM_free(params) free two distinct objects.
	 */
	params = (struct ossl_param_st *)OPENSSL_malloc(sizeof(struct ossl_param_st));
	if (params == NULL)
		return NULL;

	/* Transfer ownership of the node list from bld to params */
	params->head  = bld->head;
	params->count = bld->count;

	/* Leave the builder empty — it no longer owns the node list */
	bld->head  = NULL;
	bld->count = 0;

	return (OSSL_PARAM *)params;
}

void
OSSL_PARAM_free(OSSL_PARAM *params)
{
	/* Identical to OSSL_PARAM_BLD_free */
	OSSL_PARAM_BLD_free((OSSL_PARAM_BLD *)params);
}

EVP_PKEY_CTX *
EVP_PKEY_CTX_new_from_name(void *libctx, const char *name,
                            const char *propquery)
{
	int nid;

	(void)libctx;
	(void)propquery;

	if (name == NULL)
		return NULL;

	if (strcmp(name, "DH") == 0)
		nid = EVP_PKEY_DH;
	else if (strcmp(name, "RSA") == 0)
		nid = EVP_PKEY_RSA;
	else if (strcmp(name, "EC") == 0)
		nid = EVP_PKEY_EC;
	else if (strcmp(name, "DSA") == 0)
		nid = EVP_PKEY_DSA;
	else
		return NULL;

	{
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(nid, NULL);
		char *algo_copy = OPENSSL_strdup(name);

		if (ctx && algo_copy)
			EVP_PKEY_CTX_set_app_data(ctx, algo_copy);
		else if (algo_copy) {
			OPENSSL_free(algo_copy);
			EVP_PKEY_CTX_free(ctx);
		}
		return ctx;
	}
}

void
compat_EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
{
	if (ctx) {
		char *algo_name = EVP_PKEY_CTX_get_app_data(ctx);
		OPENSSL_free(algo_name);
	}
	EVP_PKEY_CTX_free(ctx);
}

int
EVP_PKEY_fromdata_init(EVP_PKEY_CTX *ctx)
{
	(void)ctx;
	/* Real work happens in EVP_PKEY_fromdata */
	return 1;
}

int
EVP_PKEY_fromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **pkey,
                  int selection, OSSL_PARAM *params)
{
	struct ossl_param_bld_st *node;
	EVP_PKEY *pk = NULL;

	if (pkey == NULL || params == NULL)
		return 0;

	*pkey = NULL;

	/* Get algo name from ctx's app_data (set by EVP_PKEY_CTX_new_from_name) */
	if (ctx) {
		char *algo_name = EVP_PKEY_CTX_get_app_data(ctx);
		if (algo_name) {
			strncpy(params->algo, algo_name, sizeof(params->algo) - 1);
			params->algo[sizeof(params->algo) - 1] = '\0';
			EVP_PKEY_CTX_set_app_data(ctx, NULL);
			OPENSSL_free(algo_name);
		}
	}

	if (strcmp(params->algo, "DH") == 0) {
		DH *dh = NULL;
		BIGNUM *p = NULL, *g = NULL, *pub = NULL, *priv = NULL;
		long priv_len = 0;

		dh = DH_new();
		if (dh == NULL)
			return 0;

		/* Walk param list and extract DH parameters */
		for (node = params->head; node != NULL; node = node->next) {
			if (node->type == PARAM_BN && node->bn != NULL) {
				if (strcmp(node->key, OSSL_PKEY_PARAM_FFC_P) == 0) {
					p = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_FFC_G) == 0) {
					g = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_PUB_KEY) == 0) {
					pub = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_PRIV_KEY) == 0) {
					priv = BN_dup(node->bn);
				}
			} else if (node->type == PARAM_SIZE_T) {
				if (strcmp(node->key, OSSL_PKEY_PARAM_DH_PRIV_LEN) == 0) {
					priv_len = (long)node->size_t_val;
				}
			}
		}

		/* p and g are required */
		if (p == NULL || g == NULL) {
			BN_free(p);
			BN_free(g);
			BN_free(pub);
			BN_free(priv);
			DH_free(dh);
			return 0;
		}

		/* DH_set0_pqg takes ownership of p, NULL q, g */
		if (!DH_set0_pqg(dh, p, NULL, g)) {
			BN_free(p);
			BN_free(g);
			BN_free(pub);
			BN_free(priv);
			DH_free(dh);
			return 0;
		}
		/* p and g are now owned by dh */

		/* Set optional private key length */
		if (priv_len > 0)
			DH_set_length(dh, priv_len);

		/* Set keys based on selection */
		if (selection == EVP_PKEY_KEYPAIR || selection == EVP_PKEY_PUBLIC_KEY) {
			if (pub != NULL) {
				BIGNUM *priv_to_set = NULL;
				if (selection == EVP_PKEY_KEYPAIR) {
					priv_to_set = priv;
				} else {
					BN_clear_free(priv);
					priv = NULL;
				}
				if (!DH_set0_key(dh, pub, priv_to_set)) {
					BN_free(pub);
					BN_free(priv);
					DH_free(dh);
					return 0;
				}
				/* pub (and priv if keypair) now owned by dh */
			} else {
				BN_free(priv);
			}
		} else if (selection == EVP_PKEY_KEY_PARAMETERS) {
			/* Parameters only — no keys to set */
			BN_free(pub);
			BN_free(priv);
		} else {
			BN_free(pub);
			BN_free(priv);
		}

		pk = EVP_PKEY_new();
		if (pk == NULL) {
			DH_free(dh);
			return 0;
		}
		if (!EVP_PKEY_assign_DH(pk, dh)) {
			EVP_PKEY_free(pk);
			DH_free(dh);
			return 0;
		}
		/* dh now owned by pk */

	} else if (strcmp(params->algo, "RSA") == 0) {
		RSA *rsa = NULL;
		BIGNUM *n = NULL, *e = NULL, *d = NULL;
		BIGNUM *p = NULL, *q = NULL;
		BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

		rsa = RSA_new();
		if (rsa == NULL)
			return 0;

		/* Walk param list and extract RSA parameters */
		for (node = params->head; node != NULL; node = node->next) {
			if (node->type == PARAM_BN && node->bn != NULL) {
				if (strcmp(node->key, OSSL_PKEY_PARAM_RSA_N) == 0) {
					n = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_RSA_E) == 0) {
					e = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_RSA_D) == 0) {
					BN_clear_free(d);
					d = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_RSA_FACTOR1) == 0) {
					if (p) BN_clear_free(p);
					p = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_RSA_FACTOR2) == 0) {
					if (q) BN_clear_free(q);
					q = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_RSA_EXPONENT1) == 0) {
					if (dmp1) BN_clear_free(dmp1);
					dmp1 = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_RSA_EXPONENT2) == 0) {
					if (dmq1) BN_clear_free(dmq1);
					dmq1 = BN_dup(node->bn);
				} else if (strcmp(node->key, OSSL_PKEY_PARAM_RSA_COEFFICIENT1) == 0) {
					if (iqmp) BN_clear_free(iqmp);
					iqmp = BN_dup(node->bn);
				}
			}
		}

		/* n and e are required */
		if (n == NULL || e == NULL) {
			BN_free(n);
			BN_free(e);
			BN_clear_free(d);
			if (p)    BN_clear_free(p);
			if (q)    BN_clear_free(q);
			if (dmp1) BN_clear_free(dmp1);
			if (dmq1) BN_clear_free(dmq1);
			if (iqmp) BN_clear_free(iqmp);
			RSA_free(rsa);
			return 0;
		}

		/* Only set key material for KEYPAIR/PUBLIC_KEY selections;
		 * for KEY_PARAMETERS, RSA has no separate "parameters only"
		 * representation, so just discard any extracted key BNs. */
		if (selection != EVP_PKEY_KEYPAIR && selection != EVP_PKEY_PUBLIC_KEY) {
			BN_free(n);
			BN_free(e);
			BN_clear_free(d);
			if (p)    BN_clear_free(p);
			if (q)    BN_clear_free(q);
			if (dmp1) BN_clear_free(dmp1);
			if (dmq1) BN_clear_free(dmq1);
			if (iqmp) BN_clear_free(iqmp);
			RSA_free(rsa);
			return 0;
		}

		if (selection != EVP_PKEY_KEYPAIR && d != NULL) {
			/* Public key requested; drop any private material. */
			BN_clear_free(d);
			d = NULL;
			if (p)    { BN_clear_free(p); p = NULL; }
			if (q)    { BN_clear_free(q); q = NULL; }
			if (dmp1) { BN_clear_free(dmp1); dmp1 = NULL; }
			if (dmq1) { BN_clear_free(dmq1); dmq1 = NULL; }
			if (iqmp) { BN_clear_free(iqmp); iqmp = NULL; }
		}

		/* RSA_set0_key takes ownership of n, e, and d (d may be NULL) */
		if (!RSA_set0_key(rsa, n, e, d)) {
			BN_free(n);
			BN_free(e);
			BN_clear_free(d);
			if (p)    BN_clear_free(p);
			if (q)    BN_clear_free(q);
			if (dmp1) BN_clear_free(dmp1);
			if (dmq1) BN_clear_free(dmq1);
			if (iqmp) BN_clear_free(iqmp);
			RSA_free(rsa);
			return 0;
		}
		/* n, e, and d now owned by rsa */

		/* Optional CRT parameters - only set if both factors are present */
		if (p && q) {
			if (!RSA_set0_factors(rsa, p, q)) {
				RSA_free(rsa);   /* releases n, e, d */
				BN_clear_free(p);
				BN_clear_free(q);
				if (dmp1) BN_clear_free(dmp1);
				if (dmq1) BN_clear_free(dmq1);
				if (iqmp) BN_clear_free(iqmp);
				return 0;
			}
			/* p and q now owned by rsa */

			if (dmp1 && dmq1 && iqmp) {
				if (!RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)) {
					RSA_free(rsa);   /* releases n, e, d, p, q */
					BN_clear_free(dmp1);
					BN_clear_free(dmq1);
					BN_clear_free(iqmp);
					return 0;
				}
				/* dmp1, dmq1, iqmp now owned by rsa */
			} else {
				if (dmp1) BN_clear_free(dmp1);
				if (dmq1) BN_clear_free(dmq1);
				if (iqmp) BN_clear_free(iqmp);
			}
		} else {
			if (p)    BN_clear_free(p);
			if (q)    BN_clear_free(q);
			if (dmp1) BN_clear_free(dmp1);
			if (dmq1) BN_clear_free(dmq1);
			if (iqmp) BN_clear_free(iqmp);
		}

		pk = EVP_PKEY_new();
		if (pk == NULL) {
			RSA_free(rsa);
			return 0;
		}
		if (!EVP_PKEY_assign_RSA(pk, rsa)) {
			EVP_PKEY_free(pk);
			RSA_free(rsa);
			return 0;
		}
		/* rsa now owned by pk */

	} else {
		/* Unknown algorithm */
		return 0;
	}

	*pkey = pk;
	return 1;
}

int
EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *key_name, BIGNUM **bn)
{
	const BIGNUM *found = NULL;

	if (pkey == NULL || key_name == NULL || bn == NULL)
		return 0;

	*bn = NULL;

	if (EVP_PKEY_get_id(pkey) == EVP_PKEY_DH) {
		DH *dh = EVP_PKEY_get0_DH((EVP_PKEY *)pkey);
		const BIGNUM *p = NULL, *g = NULL, *pub_key = NULL, *priv_key = NULL;

		if (dh == NULL)
			return 0;

		DH_get0_pqg(dh, &p, NULL, &g);
		DH_get0_key(dh, &pub_key, &priv_key);

		if (strcmp(key_name, OSSL_PKEY_PARAM_PUB_KEY) == 0) {
			found = pub_key;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_PRIV_KEY) == 0) {
			found = priv_key;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_FFC_P) == 0) {
			found = p;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_FFC_G) == 0) {
			found = g;
		}

	} else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
		RSA *rsa;
		const BIGNUM *n = NULL, *e = NULL, *d = NULL;
		const BIGNUM *p = NULL, *q = NULL;
		const BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

		/* Borrowed reference; do NOT free. */
		rsa = EVP_PKEY_get0_RSA((EVP_PKEY *)pkey);
		if (rsa == NULL) {
			return 0;
		}
		RSA_get0_key(rsa, &n, &e, &d);
		RSA_get0_factors(rsa, &p, &q);
		RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

		if (strcmp(key_name, OSSL_PKEY_PARAM_RSA_N) == 0) {
			found = n;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_RSA_E) == 0) {
			found = e;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_RSA_D) == 0) {
			found = d;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_RSA_FACTOR1) == 0) {
			found = p;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_RSA_FACTOR2) == 0) {
			found = q;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_RSA_EXPONENT1) == 0) {
			found = dmp1;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_RSA_EXPONENT2) == 0) {
			found = dmq1;
		} else if (strcmp(key_name, OSSL_PKEY_PARAM_RSA_COEFFICIENT1) == 0) {
			found = iqmp;
		}
	}

	if (found == NULL)
		return 0;

	*bn = BN_dup(found);
	return (*bn != NULL) ? 1 : 0;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

/*
 * Compatibility functions that work across OpenSSL 1.1.0, 1.1.1, and 3.0+
 * These use low-level RSA/DH API which is deprecated in 3.0 but still maintained.
 * Deprecation warnings are suppressed only around these functions.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

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

/*
 * Extract all RSA parameters from an RSA key.
 * Output pointers may be NULL if the caller does not need that parameter.
 */
int compat_RSA_get0_params(const RSA *rsa,
                           const BIGNUM **n, const BIGNUM **e, const BIGNUM **d,
                           const BIGNUM **p, const BIGNUM **q,
                           const BIGNUM **dmp1, const BIGNUM **dmq1,
                           const BIGNUM **iqmp)
{
	if (rsa == NULL)
		return -1;

	/* Clear output pointers that the caller provided */
	if (n)    *n = NULL;
	if (e)    *e = NULL;
	if (d)    *d = NULL;
	if (p)    *p = NULL;
	if (q)    *q = NULL;
	if (dmp1) *dmp1 = NULL;
	if (dmq1) *dmq1 = NULL;
	if (iqmp) *iqmp = NULL;

	RSA_get0_key(rsa, n, e, d);

	/* Private parameters only exist if d is present */
	if (d && *d) {
		RSA_get0_factors(rsa, p, q);
		RSA_get0_crt_params(rsa, dmp1, dmq1, iqmp);
	}

	return 0;
}

/*
 * Wrapper around DES_is_weak_key() to avoid deprecated-declarations warnings
 * in caller code when building against OpenSSL 3.0+.
 */
int compat_DES_is_weak_key(const void *key)
{
	if (key == NULL)
		return 0;
	return DES_is_weak_key((void *)key);
}

/*
 * Wrapper around EVP_PKEY_get1_RSA() to avoid deprecated-declarations warnings
 * in caller code when building against OpenSSL 3.0+.
 */
RSA *compat_EVP_PKEY_get1_RSA(const EVP_PKEY *pkey)
{
	if (pkey == NULL)
		return NULL;
	return EVP_PKEY_get1_RSA((EVP_PKEY *)pkey);
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#pragma GCC diagnostic pop
#endif