/*	$NetBSD: crypto_openssl.c,v 1.20.4.3 2012/12/24 14:50:39 tteras Exp $	*/

/* Id: crypto_openssl.c,v 1.47 2006/05/06 20:42:09 manubsd Exp */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Modifications Copyright (C) 2024-2026 Thomas Reim
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.h"
#include "missing/crypto/rijndael/rijndael-api-fst.h"

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* get openssl/ssleay version number */
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error OpenSSL version 1.1.0 or later required.
#endif

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/des.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#ifdef HAVE_OPENSSL_ENGINE_H
#include <openssl/engine.h>
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#endif
#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <openssl/err.h>
#ifdef HAVE_OPENSSL_RC5_H
#include <openssl/rc5.h>
#endif
#ifdef HAVE_OPENSSL_IDEA_H
#include <openssl/idea.h>
#endif
#if defined(HAVE_OPENSSL_AES_H)
#include <openssl/aes.h>
#elif defined(HAVE_OPENSSL_RIJNDAEL_H)
#include <openssl/rijndael.h>
#else
#include "crypto/rijndael/rijndael-api-fst.h"
#endif
#if defined(HAVE_OPENSSL_CAMELLIA_H)
#include <openssl/camellia.h>
#endif
#ifdef WITH_SHA2
#if defined(HAVE_OPENSSL_SHA2_H)
#include <openssl/sha2.h>
#elif !defined(HAVE_SHA2_IN_SHA_H)
#include "crypto/sha2/sha2.h"
#endif
#endif

#include "openssl_compat.h"

#include "plog.h"

#include "package_version.h"

/* OpenSSL 3.0 providers - must persist for lifetime of program */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static OSSL_PROVIDER *openssl_legacy_provider = NULL;
static OSSL_PROVIDER *openssl_default_provider = NULL;
#endif

#define USE_NEW_DES_API

#define OpenSSL_BUG()	do { plog(LLV_ERROR, LOCATION, NULL, "OpenSSL function failed\n"); } while(0)

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "crypto_openssl.h"
#include "debug.h"
#include "gcmalloc.h"
#include "isakmp.h"

/*
 * I hate to cast every parameter to des_xx into void *, but it is
 * necessary for SSLeay/OpenSSL portability.  It sucks.
 */

static int cb_check_cert_local __P((int, X509_STORE_CTX *));
static int cb_check_cert_remote __P((int, X509_STORE_CTX *));
static X509 *mem2x509 __P((vchar_t *));

static __caddr_t eay_hmac_init __P((vchar_t *, const EVP_MD *));

/* X509 Certificate */
/*
 * convert the string of the subject name into DER
 * e.g. str = "C=JP, ST=Kanagawa";
 */
vchar_t *
eay_str2asn1dn(str, len)
	const char *str;
	int len;
{
	X509_NAME *name;
	char *buf, *dst;
	char *field, *value;
	int i;
	vchar_t *ret = NULL;
	caddr_t p;

	if (len == -1)
		len = strlen(str);

	buf = racoon_malloc(len + 1);
	if (!buf) {
		plog(LLV_WARNING, LOCATION, NULL,"failed to allocate buffer\n");
		return NULL;
	}
	memcpy(buf, str, len);

	/* Set RFC2459 recommended mode, default in OpenSSL 1.0.1h+ */
	ASN1_STRING_set_default_mask(B_ASN1_UTF8STRING);
	name = X509_NAME_new();

	dst = field = &buf[0];
	value = NULL;
	for (i = 0; i < len; i++) {
		if (buf[i] == '\\') {
			/* Escape characters specified in RFC 2253 */
			if (i < len - 1 &&
			    strchr("\\,=+<>#;", buf[i+1]) != NULL) {
				*dst++ = buf[++i];
				continue;
			} else if (i < len - 2) {
				/* RFC 2253 hexpair character escape */
				long u;
				char esc_str[3];
				char *endptr;

				esc_str[0] = buf[++i];
				esc_str[1] = buf[++i];
				esc_str[2] = '\0';
				u = strtol(esc_str, &endptr, 16);
				if (*endptr != '\0' || u < 0 || u > 255)
					goto err;
				*dst++ = u;
				continue;
			} else
				goto err;
		}
		if (!value && buf[i] == '=') {
			*dst = '\0';
			dst = value = &buf[i + 1];
			continue;
		} else if (buf[i] == ',' || buf[i] == '/') {
			*dst = '\0';

			plog(LLV_DEBUG, LOCATION, NULL, "DN: %s=%s\n",
			     field, value);

			if (!value) goto err;
			if (!X509_NAME_add_entry_by_txt(name, field,
							(value[0] == '*' && value[1] == 0) ?
								V_ASN1_PRINTABLESTRING : MBSTRING_ASC,
							(unsigned char *) value, -1, -1, 0)) {
				plog(LLV_ERROR, LOCATION, NULL,
				     "Invalid DN field: %s=%s\n",
				     field, value);
				plog(LLV_ERROR, LOCATION, NULL,
				     "%s\n", eay_strerror());
				goto err;
			}

			while (i + 1 < len && buf[i + 1] == ' ') i++;
			dst = field = &buf[i + 1];
			value = NULL;
			continue;
		} else {
			*dst++  = buf[i];
		}
	}
	*dst = '\0';

	plog(LLV_DEBUG, LOCATION, NULL, "DN: %s=%s\n",
	     field, value);

	if (!value) goto err;
	if (!X509_NAME_add_entry_by_txt(name, field,
					(value[0] == '*' && value[1] == 0) ?
						V_ASN1_PRINTABLESTRING : MBSTRING_ASC,
					(unsigned char *) value, -1, -1, 0)) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "Invalid DN field: %s=%s\n",
		     field, value);
		plog(LLV_ERROR, LOCATION, NULL,
		     "%s\n", eay_strerror());
		goto err;
	}

	i = i2d_X509_NAME(name, NULL);
	if (!i)
		goto err;
	ret = vmalloc(i);
	if (!ret)
		goto err;
	p = ret->v;
	i = i2d_X509_NAME(name, (void *)&p);
	if (!i)
		goto err;

	racoon_free(buf);
	X509_NAME_free(name);
	return ret;

err:
	if (buf)
		racoon_free(buf);
	if (name)
		X509_NAME_free(name);
	if (ret)
		vfree(ret);
	return NULL;
}

/*
 * convert the hex string of the subject name into DER
 */
vchar_t *
eay_hex2asn1dn(const char *hex, int len)
{
	BIGNUM *bn = BN_new();
	char *binbuf;
	size_t binlen;
	vchar_t *ret = NULL;

	if (len == -1)
		len = strlen(hex);

	if (BN_hex2bn(&bn, hex) != len) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "conversion of Hex-encoded ASN1 string to binary failed: %s\n",
		     eay_strerror());
		goto out;
	}

	binlen = BN_num_bytes(bn);
	ret = vmalloc(binlen);
	if (!ret) {
		plog(LLV_WARNING, LOCATION, NULL,"failed to allocate buffer\n");
		return NULL;
	}
	binbuf = ret->v;

	BN_bn2bin(bn, (unsigned char *) binbuf);

out:
	BN_free(bn);

	return ret;
}

/*
 * compare two subjectNames.
 * OUT:        0: equal
 *	positive:
 *	      -1: other error.
 */
int
eay_cmp_asn1dn(n1, n2)
	vchar_t *n1, *n2;
{
	X509_NAME *a = NULL, *b = NULL;
	caddr_t p;
	char oneLine[512];
	int i = -1;
	int idx;

	p = n1->v;
	if (!d2i_X509_NAME(&a, (void *)&p, n1->l)) {
		plog(LLV_ERROR, LOCATION, NULL, "eay_cmp_asn1dn: first dn not a dn");
		goto end;
	}
	plog(LLV_DEBUG, LOCATION, NULL, "1st name: %s\n", X509_NAME_oneline(a, oneLine, sizeof(oneLine)));
	p = n2->v;
	if (!d2i_X509_NAME(&b, (void *)&p, n2->l)) {
		plog(LLV_ERROR, LOCATION, NULL, "eay_cmp_asn1dn: second dn not a dn");
		goto end;
	}
	plog(LLV_DEBUG, LOCATION, NULL, "2nd name: %s\n", X509_NAME_oneline(b, oneLine, sizeof(oneLine)));

	/* handle wildcard: do not compare entry content but only entry object type */
	for(idx = 0; idx < X509_NAME_entry_count(a); idx++) {
		X509_NAME_ENTRY *ea = X509_NAME_get_entry(a, idx);
		X509_NAME_ENTRY *eb = X509_NAME_get_entry(b, idx);
		if (!eb) {	/* reached end of eb while still entries in ea, can not be equal... */
			i = idx+1;
			goto end;
		}
		ASN1_STRING *sa = X509_NAME_ENTRY_get_data(ea);
		ASN1_STRING *sb = X509_NAME_ENTRY_get_data(eb);
		if ((ASN1_STRING_length(sa) == 1 && ASN1_STRING_get0_data(sa)[0] == '*') ||
		    (ASN1_STRING_length(sb) == 1 && ASN1_STRING_get0_data(sb)[0] == '*')) {
			if (OBJ_cmp(X509_NAME_ENTRY_get_object(ea),
				    X509_NAME_ENTRY_get_object(eb))) {
				i = idx+1;
				goto end;
			}
			/* OK: object type equals, we don't care for this entry anymore, so let's forget it... */
			X509_NAME_delete_entry(a, idx);
			X509_NAME_delete_entry(b, idx);
			X509_NAME_ENTRY_free(ea);
			X509_NAME_ENTRY_free(eb);
			idx--;
		}
	}
	if (X509_NAME_entry_count(a) == 0 && X509_NAME_entry_count(b) == 0)
		i = 0;
	else
		i = X509_NAME_cmp(a, b);

end:
	if (a)
		X509_NAME_free(a);
	if (b)
		X509_NAME_free(b);
	return i;
}

/*
 * this functions is derived from apps/verify.c in OpenSSL0.9.5
 */
int
eay_check_x509cert(cert, CApath, CAfile, local)
	vchar_t *cert;
	char *CApath;
	char *CAfile;
	int local;
{
	X509_STORE *cert_ctx = NULL;
	X509_LOOKUP *lookup = NULL;
	X509 *x509 = NULL;
	X509_STORE_CTX *csc = NULL;
	int error = -1;

	cert_ctx = X509_STORE_new();
	if (cert_ctx == NULL)
		goto end;

	if (local)
		X509_STORE_set_verify_cb(cert_ctx, cb_check_cert_local);
	else
		X509_STORE_set_verify_cb(cert_ctx, cb_check_cert_remote);

	lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
	if (lookup == NULL)
		goto end;

	X509_LOOKUP_load_file(lookup, CAfile,
			      (CAfile == NULL) ? X509_FILETYPE_DEFAULT : X509_FILETYPE_PEM);

	lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
	if (lookup == NULL)
		goto end;
	error = X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM);
	if(!error) {
		error = -1;
		goto end;
	}
	error = -1;	/* initialized */

	/* read the certificate to be verified */
	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

	csc = X509_STORE_CTX_new();
	if (csc == NULL)
		goto end;
	if (!X509_STORE_CTX_init(csc, cert_ctx, x509, NULL))
		goto end;
	X509_STORE_CTX_set_flags (csc, X509_V_FLAG_CRL_CHECK);
	X509_STORE_CTX_set_flags (csc, X509_V_FLAG_CRL_CHECK_ALL);
	error = X509_verify_cert(csc);
	X509_STORE_CTX_free(csc);

	/*
	 * if x509_verify_cert() is successful then the value of error is
	 * set non-zero.
	 */
	error = error ? 0 : -1;

end:
	if (error)
		plog(LLV_WARNING, LOCATION, NULL,"%s\n", eay_strerror());
	if (cert_ctx != NULL)
		X509_STORE_free(cert_ctx);
	if (x509 != NULL)
		X509_free(x509);

	return(error);
}

/*
 * callback function for verifing certificate.
 * this function is derived from cb() in openssl/apps/s_server.c
 */
static int
cb_check_cert_local(ok, ctx)
	int ok;
	X509_STORE_CTX *ctx;
{
	char buf[256];
	int log_tag;

	if (!ok) {
		X509_NAME_oneline(
			X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx)),
			buf,
			256);
		/*
		 * since we are just checking the certificates, it is
		 * ok if they are self signed. But we should still warn
		 * the user.
		 */
		int ctx_error = X509_STORE_CTX_get_error(ctx);
		switch (ctx_error) {
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_INVALID_CA:
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		case X509_V_ERR_INVALID_PURPOSE:
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			ok = 1;
			log_tag = LLV_WARNING;
			break;
		default:
			log_tag = LLV_ERROR;
		}
		plog(log_tag, LOCATION, NULL,
		     "%s(%d) at depth:%d SubjectName:%s\n",
		     X509_verify_cert_error_string(ctx_error),
		     ctx_error,
		     X509_STORE_CTX_get_error_depth(ctx),
		     buf);
	}
	ERR_clear_error();

	return ok;
}

/*
 * callback function for verifing remote certificates.
 * this function is derived from cb() in openssl/apps/s_server.c
 */
static int
cb_check_cert_remote(ok, ctx)
	int ok;
	X509_STORE_CTX *ctx;
{
	char buf[256];
	int log_tag;

	if (!ok) {
		X509_NAME_oneline(
			X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx)),
			buf,
			256);
		int ctx_error=X509_STORE_CTX_get_error(ctx);
		switch (ctx_error) {
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			ok = 1;
			log_tag = LLV_WARNING;
			break;
		default:
			log_tag = LLV_ERROR;
		}
		plog(log_tag, LOCATION, NULL,
		     "%s(%d) at depth:%d SubjectName:%s\n",
		     X509_verify_cert_error_string(ctx_error),
		     ctx_error,
		     X509_STORE_CTX_get_error_depth(ctx),
		     buf);
	}
	ERR_clear_error();

	return ok;
}

/*
 * get a subjectName from X509 certificate.
 */
vchar_t *
eay_get_x509asn1subjectname(cert)
	vchar_t *cert;
{
	X509 *x509 = NULL;
	u_char *bp;
	vchar_t *name = NULL;
	int len;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto error;

	X509_NAME *subject_name = X509_get_subject_name(x509);
	/* get the length of the name */
	len = i2d_X509_NAME(subject_name, NULL);
	name = vmalloc(len);
	if (!name)
		goto error;
	/* get the name */
	bp = (unsigned char *) name->v;
	len = i2d_X509_NAME(subject_name, &bp);

	X509_free(x509);

	return name;

error:
	plog(LLV_ERROR, LOCATION, NULL, "%s\n", eay_strerror());

	if (name != NULL)
		vfree(name);

	if (x509 != NULL)
		X509_free(x509);

	return NULL;
}

/*
 * get the subjectAltName from X509 certificate.
 * the name must be terminated by '\0'.
 */
int
eay_get_x509subjectaltname(cert, altname, type, pos)
	vchar_t *cert;
	char **altname;
	int *type;
	int pos;
{
	X509 *x509 = NULL;
	GENERAL_NAMES *gens = NULL;
	GENERAL_NAME *gen;
	int len;
	int error = -1;

	*altname = NULL;
	*type = GENT_OTHERNAME;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	if (gens == NULL)
		goto end;

	/* there is no data at "pos" */
	if (pos > sk_GENERAL_NAME_num(gens))
		goto end;

	gen = sk_GENERAL_NAME_value(gens, pos - 1);

	/* read DNSName / Email */
	if (gen->type == GEN_DNS	||
	    gen->type == GEN_EMAIL	||
	    gen->type == GEN_URI )
	{
		/* make sure if the data is terminated by '\0'. */
		if (gen->d.ia5->data[gen->d.ia5->length] != '\0')
		{
			plog(LLV_ERROR, LOCATION, NULL,
			     "data is not terminated by NUL.");
			racoon_hexdump(gen->d.ia5->data, gen->d.ia5->length + 1);
			goto end;
		}

		len = gen->d.ia5->length + 1;
		*altname = racoon_malloc(len);
		if (!*altname)
			goto end;

		strlcpy(*altname, (char *) gen->d.ia5->data, len);
		*type = gen->type;
		error = 0;
	}
	/* read IP address */
	else if (gen->type == GEN_IPADD)
	{
		switch (gen->d.iPAddress->length) {
		case 4: /* IPv4 */
			*altname = racoon_malloc(4*3 + 3 + 1); /* digits + decimals + null */
			if (!*altname)
				goto end;

			snprintf(*altname, 12+3+1, "%u.%u.%u.%u",
				 (unsigned)gen->d.iPAddress->data[0],
				 (unsigned)gen->d.iPAddress->data[1],
				 (unsigned)gen->d.iPAddress->data[2],
				 (unsigned)gen->d.iPAddress->data[3]);
			break;
		case 16: { /* IPv6 */
			int i;

			*altname = racoon_malloc(16*2 + 7 + 1); /* digits + colons + null */
			if (!*altname)
				goto end;

			/* Make NULL terminated IPv6 address */
			for (i=0; i<16; ++i) {
				int pos = i*2 + i/2;

				if (i>0 && i%2==0)
					(*altname)[pos-1] = ':';

				snprintf(*altname + pos, 3, "%02x",
					 (unsigned)gen->d.iPAddress->data[i]);

			}
			plog(LLV_INFO, LOCATION, NULL,
			     "Remote X509 IPv6 addr: %s", *altname);
			break;
		}
		default:
			plog(LLV_ERROR, LOCATION, NULL,
			     "Unknown IP address length: %u octects.",
			     gen->d.iPAddress->length);
			goto end;
		}

		*type = gen->type;
		error = 0;
	}
	/* XXX other possible types ?
	 * For now, error will be -1 if unsupported type
	 */

end:
	if (error) {
		if (*altname) {
			racoon_free(*altname);
			*altname = NULL;
		}
		plog(LLV_ERROR, LOCATION, NULL, "%s\n", eay_strerror());
	}
	if (x509)
		X509_free(x509);
	if (gens)
		/* free the whole stack. */
		sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

	return error;
}

/*
 * get a issuerName from X509 certificate.
 */
vchar_t *
eay_get_x509asn1issuername(cert)
	vchar_t *cert;
{
	X509 *x509 = NULL;
	u_char *bp;
	vchar_t *name = NULL;
	int len;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto error;

	X509_NAME *issuer_name = X509_get_issuer_name(x509);
	/* get the length of the name */
	len = i2d_X509_NAME(issuer_name, NULL);
	name = vmalloc(len);
	if (name == NULL)
		goto error;

	/* get the name */
	bp = (unsigned char *) name->v;
	len = i2d_X509_NAME(issuer_name, &bp);

	X509_free(x509);

	return name;

error:
	plog(LLV_ERROR, LOCATION, NULL, "%s\n", eay_strerror());

	if (name != NULL)
		vfree(name);
	if (x509 != NULL)
		X509_free(x509);

	return NULL;
}

/*
 * decode a X509 certificate and make a readable text terminated '\n'.
 * return the buffer allocated, so must free it later.
 */
char *
eay_get_x509text(cert)
	vchar_t *cert;
{
	X509 *x509 = NULL;
	BIO *bio = NULL;
	char *text = NULL;
	u_char *bp = NULL;
	int len = 0;
	int error = -1;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto end;

	error = X509_print(bio, x509);
	if (error != 1) {
		error = -1;
		goto end;
	}

	len = BIO_get_mem_data(bio, &bp);
	text = racoon_malloc(len + 1);
	if (text == NULL)
		goto end;
	memcpy(text, bp, len);
	text[len] = '\0';

	error = 0;

end:
	if (error) {
		if (text) {
			racoon_free(text);
			text = NULL;
		}
		plog(LLV_ERROR, LOCATION, NULL, "%s\n", eay_strerror());
	}
	if (bio)
		BIO_free(bio);
	if (x509)
		X509_free(x509);

	return text;
}

/* get X509 structure from buffer. */
static X509 *
mem2x509(cert)
	vchar_t *cert;
{
	X509 *x509;

#ifndef EAYDEBUG
	{
		u_char *bp;

		bp = (unsigned char *) cert->v + 1;

		x509 = d2i_X509(NULL, (void *)&bp, cert->l - 1);
	}
#else
	{
		BIO *bio;
		int len;

		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
			return NULL;
		len = BIO_write(bio, cert->v + 1, cert->l - 1);
		if (len == -1)
			return NULL;
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}
#endif
	return x509;
}

/*
 * get a X509 certificate from local file.
 * a certificate must be PEM format.
 * Input:
 *	path to a certificate.
 * Output:
 *	NULL if error occured
 *	other is the cert.
 */
vchar_t *
eay_get_x509cert(path)
	char *path;
{
	FILE *fp;
	X509 *x509;
	vchar_t *cert;
	u_char *bp;
	int len;
	int error;

	/* Read private key */
	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;
	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose (fp);

	if (x509 == NULL)
		return NULL;

	len = i2d_X509(x509, NULL);
	cert = vmalloc(len + 1);
	if (cert == NULL) {
		X509_free(x509);
		return NULL;
	}
	cert->v[0] = ISAKMP_CERT_X509SIGN;
	bp = (unsigned char *) &cert->v[1];
	error = i2d_X509(x509, &bp);
	X509_free(x509);

	if (error == 0) {
		vfree(cert);
		return NULL;
	}

	return cert;
}

/*
 * check a X509 signature using EVP_PKEY
 * OUT: return -1 when error.
 *	0 on success
 */
int
eay_check_x509sign(source, sig, cert)
	vchar_t *source;
	vchar_t *sig;
	vchar_t *cert;
{
	X509 *x509;
	EVP_PKEY *evp;
	int res = -1;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		return -1;

	evp = X509_get_pubkey(x509);
	if (!evp) {
		plog(LLV_ERROR, LOCATION, NULL, "X509_get_pubkey(): %s\n", eay_strerror());
		X509_free(x509);
		return -1;
	}

	if (EVP_PKEY_id(evp) == EVP_PKEY_RSA) {
		/* Use EVP_PKEY operations directly */
		res = eay_pkey_verify(source, sig, evp);
	} else {
		plog(LLV_ERROR, LOCATION, NULL, "Unsupported key type for signature verification\n");
		res = -1;
	}

	EVP_PKEY_free(evp);
	X509_free(x509);

	return res;
}

/*
 * check RSA signature - thin delegation to eayRSA_verify
 * OUT: return -1 when error.
 *	0 on success
 */
int
eay_check_rsasign(source, sig, rsa)
	vchar_t *source;
	vchar_t *sig;
	eayRSA *rsa;
{
	if (!rsa) {
		plog(LLV_ERROR, LOCATION, NULL, "eay_check_rsasign: NULL RSA key\n");
		return -1;
	}

	return eayRSA_verify(rsa, source, sig);
}

/*
 * get PKCS#1 Private Key of PEM format from local file.
 */
vchar_t *
eay_get_pkcs1privkey(path)
	char *path;
{
	FILE *fp;
	EVP_PKEY *evp = NULL;
	vchar_t *pkey = NULL;
	u_char *bp;
	int pkeylen;
	int error = -1;

	/* Read private key */
	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;

	evp = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

	fclose (fp);

	if (evp == NULL)
		return NULL;

	pkeylen = i2d_PrivateKey(evp, NULL);
	if (pkeylen == 0)
		goto end;
	pkey = vmalloc(pkeylen);
	if (pkey == NULL)
		goto end;
	bp = (unsigned char *) pkey->v;
	pkeylen = i2d_PrivateKey(evp, &bp);
	if (pkeylen == 0)
		goto end;

	error = 0;

end:
	if (evp != NULL)
		EVP_PKEY_free(evp);
	if (error != 0 && pkey != NULL) {
		vfree(pkey);
		pkey = NULL;
	}

	return pkey;
}

/*
 * get PKCS#1 Public Key of PEM format from local file.
 */
vchar_t *
eay_get_pkcs1pubkey(path)
	char *path;
{
	FILE *fp;
	EVP_PKEY *evp = NULL;
	vchar_t *pkey = NULL;
	X509 *x509 = NULL;
	u_char *bp;
	int pkeylen;
	int error = -1;

	/* Read private key */
	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;

	x509 = PEM_read_X509(fp, NULL, NULL, NULL);

	fclose (fp);

	if (x509 == NULL)
		return NULL;

	/* Get public key - eay */
	evp = X509_get_pubkey(x509);
	if (evp == NULL)
		return NULL;

	pkeylen = i2d_PublicKey(evp, NULL);
	if (pkeylen == 0)
		goto end;
	pkey = vmalloc(pkeylen);
	if (pkey == NULL)
		goto end;
	bp = (unsigned char *) pkey->v;
	pkeylen = i2d_PublicKey(evp, &bp);
	if (pkeylen == 0)
		goto end;

	error = 0;
end:
	if (evp != NULL)
		EVP_PKEY_free(evp);
	if (error != 0 && pkey != NULL) {
		vfree(pkey);
		pkey = NULL;
	}

	return pkey;
}

vchar_t *
eay_get_x509sign(src, privkey)
	vchar_t *src, *privkey;
{
	EVP_PKEY *evp;
	u_char *bp = (unsigned char *) privkey->v;
	vchar_t *sig = NULL;

	/* XXX to be handled EVP_PKEY_DSA */
	evp = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (void *)&bp, privkey->l);
	if (evp == NULL)
		return NULL;

	sig = eay_pkey_sign(src, evp);

	EVP_PKEY_free(evp);

	return sig;
}

/*
 * Get RSA signature - thin delegation to eayRSA_sign
 *
 * OUT: Returns signature in vchar_t* on success, NULL on failure
 */
vchar_t *
eay_get_rsasign(src, rsa)
	vchar_t *src;
	eayRSA *rsa;
{
	if (!rsa) {
		plog(LLV_ERROR, LOCATION, NULL, "eay_get_rsasign: NULL RSA key\n");
		return NULL;
	}

	/*
	 * Reject signing attempts with a public-only key here. Some OpenSSL
	 * versions (e.g. 1.1.0) do not check for a missing private exponent
	 * before performing the modular exponentiation, which leads to a
	 * NULL pointer dereference/crash inside EVP_PKEY_sign() instead of
	 * a clean error return.
	 */
	if (!eayRSA_has_private(rsa)) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "eay_get_rsasign: RSA key has no private component\n");
		return NULL;
	}

	return eayRSA_sign(rsa, src);
}

/*
 * RSA signature using EVP_PKEY (OpenSSL 3.0 compatible)
 *
 * This performs RAW RSA signing (textbook RSA with PKCS#1 v1.5 padding)
 * NOT digest-based signing. The input 'src' is encrypted directly with
 * the private key.
 *
 * This matches the original behavior of RSA_private_encrypt().
 *
 * Empty input (src->l == 0) is explicitly rejected: OpenSSL will accept
 * 0-byte input at the sign step but the recovered data after
 * EVP_PKEY_verify_recover() will not be empty, causing verification to
 * always fail for empty-data signatures.  Rejecting here makes the
 * behaviour consistent and well-defined.
 *
 * OUT: Returns signature in vchar_t* on success, NULL on failure
 */
vchar_t *
eay_pkey_sign(src, pkey)
	vchar_t *src;
	EVP_PKEY *pkey;
{
	EVP_PKEY_CTX *ctx = NULL;
	vchar_t *sig = NULL;
	size_t siglen;

	if (!src || !pkey) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "eay_pkey_sign: NULL parameter (src=%p, pkey=%p)\n", src, pkey);
		return NULL;
	}

	/*
	 * Reject empty input explicitly.
	 *
	 * OpenSSL accepts 0-byte input at the EVP_PKEY_sign() level with
	 * PKCS#1 v1.5 padding, producing a well-formed signature block.
	 * However EVP_PKEY_verify_recover() recovers the PKCS#1 padding
	 * structure which is never 0 bytes, so verification always fails
	 * for empty-data signatures.  Rejecting here keeps sign and verify
	 * consistent.
	 */
	if (src->l == 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "eay_pkey_sign: empty input rejected\n");
		return NULL;
	}

	/* Verify this is an RSA key */
	if (EVP_PKEY_get_id(pkey) != EVP_PKEY_RSA) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "eay_pkey_sign: Expected RSA key, got type %d\n",
		     EVP_PKEY_get_id(pkey));
		return NULL;
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx) {
		plog(LLV_ERROR, LOCATION, NULL, "EVP_PKEY_CTX_new failed\n");
		return NULL;
	}

	if (EVP_PKEY_sign_init(ctx) <= 0) {
		plog(LLV_ERROR, LOCATION, NULL, "EVP_PKEY_sign_init failed\n");
		goto end;
	}

	/* Set PKCS#1 v1.5 padding */
	if (eayRSA_set_pkcs1_padding(ctx) != 0) {
		plog(LLV_ERROR, LOCATION, NULL, "eayRSA_set_pkcs1_padding failed\n");
		goto end;
	}

	/*
	 * NOTE: We do NOT set signature MD here!
	 * This is raw RSA signing, not digest-based signing.
	 * Setting EVP_PKEY_CTX_set_signature_md would be wrong.
	 */

	/* Determine required signature buffer length */
	if (EVP_PKEY_sign(ctx, NULL, &siglen, (unsigned char *)src->v, src->l) <= 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "EVP_PKEY_sign length determination failed: %s\n", eay_strerror());
		goto end;
	}

	/* Allocate signature buffer */
	sig = vmalloc(siglen);
	if (!sig) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "vmalloc(%zu) failed for signature buffer\n", siglen);
		goto end;
	}

	/* Perform actual signing (raw RSA private encrypt) */
	if (EVP_PKEY_sign(ctx, (unsigned char *)sig->v, &siglen,
			  (unsigned char *)src->v, src->l) <= 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "EVP_PKEY_sign failed: %s\n", eay_strerror());
		vfree(sig);
		sig = NULL;
		goto end;
	}

	/* Update actual signature length */
	sig->l = siglen;

	plog(LLV_DEBUG, LOCATION, NULL,
	     "RSA signature created: %zu bytes\n", siglen);

end:
	if (ctx)
		compat_EVP_PKEY_CTX_free(ctx);
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
 * OUT: return -1 when error or verification failed
 *      return  0 on successful verification
 */
int
eay_pkey_verify(src, sig, pkey)
	vchar_t *src, *sig;
	EVP_PKEY *pkey;
{
	EVP_PKEY_CTX *ctx = NULL;
	vchar_t *recovered = NULL;
	size_t recovered_len;
	int ret = -1;

	if (!src || !sig || !pkey) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "eay_pkey_verify: NULL parameter (src=%p, sig=%p, pkey=%p)\n",
		     src, sig, pkey);
		return -1;
	}

	/* Verify this is an RSA key */
	if (EVP_PKEY_get_id(pkey) != EVP_PKEY_RSA) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "eay_pkey_verify: Expected RSA key, got type %d\n",
		     EVP_PKEY_get_id(pkey));
		return -1;
	}

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
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

	/* Set PKCS#1 v1.5 padding */
	if (eayRSA_set_pkcs1_padding(ctx) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "eayRSA_set_pkcs1_padding failed: %s\n", eay_strerror());
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

/* Legacy wrappers for compatibility */
vchar_t *
eay_rsa_sign(src, rsa)
	vchar_t *src;
	eayRSA *rsa;
{
	return eay_get_rsasign(src, rsa);
}

int
eay_rsa_verify(src, sig, rsa)
	vchar_t *src, *sig;
	eayRSA *rsa;
{
	return eay_check_rsasign(src, sig, rsa);
}

/*
 * get error string
 */
char *
eay_strerror()
{
	static char ebuf[512];
	int len = 0, n;
	unsigned long err;
	const char *file = NULL, *data = NULL;
	int line = 0, flags = 0;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	const char *func;
	while ((err = ERR_get_error_all(&file, &line, &func, &data, &flags)) != 0) {
		char buf[256];
		n = snprintf(ebuf + len, sizeof(ebuf) - len,
			     "%s:%s:%d:%s ",
			     ERR_error_string(err, buf),
			     file,
			     line,
			     (flags & ERR_TXT_STRING) ? data : "");
		if (n < 0 || n >= sizeof(ebuf) - len)
			break;
		len += n;
		if (sizeof(ebuf) < len)
			break;
	}
#else
	while ((err = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
		char buf[200];
		n = snprintf(ebuf + len, sizeof(ebuf) - len,
			     "%s:%s:%d:%s ",
			     ERR_error_string(err, buf),
			     file,
			     line,
			     (flags & ERR_TXT_STRING) ? data : "");
		if (n < 0 || n >= sizeof(ebuf) - len)
			break;
		len += n;
		if (sizeof(ebuf) < len)
			break;
	}
#endif

	return ebuf;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static void
validate_legacy_ciphers(void)
{
	struct {
		const EVP_CIPHER *(*fn)(void);
		const char *name;
		int high; /* 1 = HIGH impact (IDEA/RC5), 0 = MEDIUM */
	} ciphers[] = {
		{ EVP_des_cbc,		"DES",		0 },
		{ EVP_des_ede3_cbc,	"3DES",		0 },
		{ EVP_bf_cbc,		"Blowfish",	0 },
		{ EVP_cast5_cbc,	"CAST5",		0 },
#ifdef HAVE_OPENSSL_IDEA_H
		{ EVP_idea_cbc,		"IDEA",		1 },
#endif
#ifdef HAVE_OPENSSL_RC5_H
		{ EVP_rc5_cbc,		"RC5",		1 },
#endif
	};
	size_t i;

	for (i = 0; i < ARRAYLEN(ciphers); i++) {
		const EVP_CIPHER *e = ciphers[i].fn();
		if (!e || EVP_CIPHER_nid(e) == NID_undef) {
			plog(ciphers[i].high ? LLV_ERROR : LLV_WARNING, LOCATION, NULL,
			     "Legacy cipher %s is NOT available. "
			     "The OpenSSL legacy provider may not be loaded. "
			     "Configure an alternative cipher (e.g. AES, 3DES).\n",
			     ciphers[i].name);
		}
	}
}

static int
is_legacy_cipher(int nid)
{
	switch (nid) {
	case NID_bf_cbc:
	case NID_bf_ecb:
	case NID_bf_cfb64:
	case NID_bf_ofb64:
	case NID_cast5_cbc:
	case NID_cast5_ecb:
	case NID_cast5_cfb64:
	case NID_cast5_ofb64:
	case NID_idea_cbc:
	case NID_idea_ecb:
	case NID_idea_cfb64:
	case NID_rc5_cbc:
	case NID_rc5_ecb:
	case NID_rc5_cfb64:
	case NID_rc5_ofb64:
		return 1;
	default:
		return 0;
	}
}
#endif

vchar_t *
evp_crypt(vchar_t *data, vchar_t *key, vchar_t *iv, const EVP_CIPHER *e, int enc)
{
	vchar_t *res;
	EVP_CIPHER_CTX *ctx;
	int len, final_len;

	if (!e) {
		plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: cipher is NULL\n");
		return NULL;
	}

	plog(LLV_DEBUG, LOCATION, NULL, "evp_crypt: cipher=%s, enc=%d, data_len=%zu, key_len=%zu\n",
	     EVP_CIPHER_name(e), enc, data->l, key->l);

	if (data->l % EVP_CIPHER_block_size(e)) {
		plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: data length not multiple of block size\n");
		return NULL;
	}

	if ((res = vmalloc(data->l)) == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: vmalloc failed\n");
		return NULL;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: EVP_CIPHER_CTX_new failed\n");
		vfree(res);
		return NULL;
	}

	switch(EVP_CIPHER_nid(e)){
	case NID_bf_cbc:
	case NID_bf_ecb:
	case NID_bf_cfb64:
	case NID_bf_ofb64:
	case NID_cast5_cbc:
	case NID_cast5_ecb:
	case NID_cast5_cfb64:
	case NID_cast5_ofb64:
		plog(LLV_DEBUG, LOCATION, NULL, "evp_crypt: variable key length cipher\n");
		/* init context without key/iv */
		if (!EVP_CipherInit_ex(ctx, e, NULL, NULL, NULL, enc)) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			if (!openssl_legacy_provider) {
				plog(LLV_ERROR, LOCATION, NULL,
				     "evp_crypt: %s cipher not available - legacy provider failed to load. "
				     "Use a supported cipher (AES, 3DES).\n", EVP_CIPHER_name(e));
			} else
#endif
			{
				plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: EVP_CipherInit_ex (1) failed: %s\n", eay_strerror());
			}
			goto out;
		}

		/* update key size */
		if (!EVP_CIPHER_CTX_set_key_length(ctx, key->l)) {
			plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: EVP_CIPHER_CTX_set_key_length failed: %s\n", eay_strerror());
			goto out;
		}

		/* finalize context init with desired key size */
		if (!EVP_CipherInit_ex(ctx, NULL, NULL, (u_char *) key->v,
				       (u_char *) iv->v, enc)) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			if (!openssl_legacy_provider) {
				plog(LLV_ERROR, LOCATION, NULL,
				     "evp_crypt: %s cipher not available - legacy provider failed to load. "
				     "Use a supported cipher (AES, 3DES).\n", EVP_CIPHER_name(e));
			} else
#endif
			{
				plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: EVP_CipherInit_ex (2) failed: %s\n", eay_strerror());
			}
			goto out;
		}
		break;
	default:
		plog(LLV_DEBUG, LOCATION, NULL, "evp_crypt: fixed key length cipher\n");
		if (!EVP_CipherInit_ex(ctx, e, NULL, (u_char *) key->v,
				       (u_char *) iv->v, enc)) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			if (!openssl_legacy_provider) {
				plog(LLV_ERROR, LOCATION, NULL,
				     "evp_crypt: %s cipher not available - legacy provider failed to load. "
				     "Use a supported cipher (AES, 3DES).\n", EVP_CIPHER_name(e));
			} else
#endif
			{
				plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: EVP_CipherInit_ex failed: %s\n", eay_strerror());
			}
			goto out;
		}
	}

	/* disable openssl padding */
	if (!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
		plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: EVP_CIPHER_CTX_set_padding failed: %s\n", eay_strerror());
		goto out;
	}

	plog(LLV_DEBUG, LOCATION, NULL, "evp_crypt: calling EVP_CipherUpdate\n");
	/* Process the data */
	if (!EVP_CipherUpdate(ctx, (u_char *) res->v, &len,
			      (u_char *) data->v, data->l)) {
		plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: EVP_CipherUpdate failed: %s\n", eay_strerror());
		goto out;
	}

	plog(LLV_DEBUG, LOCATION, NULL, "evp_crypt: EVP_CipherUpdate returned len=%d\n", len);

	/* Finalize */
	if (!EVP_CipherFinal_ex(ctx, (u_char *) res->v + len, &final_len)) {
		plog(LLV_ERROR, LOCATION, NULL, "evp_crypt: EVP_CipherFinal_ex failed: %s\n", eay_strerror());
		goto out;
	}

	plog(LLV_DEBUG, LOCATION, NULL, "evp_crypt: EVP_CipherFinal_ex returned final_len=%d\n", final_len);

	/* Verify we got the expected amount of data */
	if (len + final_len != data->l) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "evp_crypt: output length mismatch (%d vs %zu)\n",
		     len + final_len, data->l);
		goto out;
	}

	plog(LLV_DEBUG, LOCATION, NULL, "evp_crypt: success\n");
	EVP_CIPHER_CTX_free(ctx);

	return res;
out:
	EVP_CIPHER_CTX_free(ctx);
	OpenSSL_BUG();
	vfree(res);
	return NULL;
}

int
evp_weakkey(vchar_t *key, const EVP_CIPHER *e)
{
	return 0;
}

int
evp_keylen(int len, const EVP_CIPHER *e)
{
	if (!e)
		return -1;
	/* EVP functions return lengths in bytes, ipsec-tools
	 * uses lengths in bits, therefore conversion is required. --AK
	 */
	if (len != 0 && len != (EVP_CIPHER_key_length(e) << 3))
		return -1;

	return EVP_CIPHER_key_length(e) << 3;
}

/*
 * DES-CBC
 */
vchar_t *
eay_des_encrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_des_cbc(), 1);
}

vchar_t *
eay_des_decrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_des_cbc(), 0);
}

int
eay_des_weakkey(key)
	vchar_t *key;
{
	/* DES_is_weak_key is OSSL_DEPRECATEDIN_3_0 but remains functional at
	 * runtime.  The EVP_CIPHER API provides no equivalent weak-key check,
	 * and the DES weak-key set is well-defined (only 4 keys), so calling the
	 * deprecated function is the simplest correct approach.  The cast to
	 * (void *) silences the const_DES_cblock * vs char * warning.
	 */
	return compat_DES_is_weak_key(key->v);
}

int
eay_des_keylen(len)
	int len;
{
	return evp_keylen(len, EVP_des_cbc());
}

#if defined(HAVE_OPENSSL_IDEA_H) && ! defined(OPENSSL_NO_IDEA)
/*
 * IDEA-CBC
 */
vchar_t *
eay_idea_encrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_idea_cbc(), 1);
}

vchar_t *
eay_idea_decrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_idea_cbc(), 0);
}

int
eay_idea_weakkey(key)
	vchar_t *key;
{
	return 0;
}

int
eay_idea_keylen(len)
	int len;
{
	if (len != 0 && len != 128)
		return -1;
	return 128;
}
#endif

/*
 * BLOWFISH-CBC
 */
vchar_t *
eay_bf_encrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_bf_cbc(), 1);
}

vchar_t *
eay_bf_decrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_bf_cbc(), 0);
}

int
eay_bf_weakkey(key)
	vchar_t *key;
{
	return 0;	/* XXX to be done. refer to RFC 2451 */
}

int
eay_bf_keylen(len)
	int len;
{
	if (len == 0)
		return 448;
	if (len < 40 || len > 448)
		return -1;
	return len;
}

#ifdef HAVE_OPENSSL_RC5_H
/*
 * RC5-CBC
 */
vchar_t *
eay_rc5_encrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_rc5_cbc(), 1);
}

vchar_t *
eay_rc5_decrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_rc5_cbc(), 0);
}

int
eay_rc5_weakkey(key)
	vchar_t *key;
{
	return 0;
}

int
eay_rc5_keylen(len)
	int len;
{
	if (len == 0)
		return 128;
	if (len < 40 || len > 2040)
		return -1;
	return len;
}
#endif

/*
 * 3DES-CBC
 */
vchar_t *
eay_3des_encrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_des_ede3_cbc(), 1);
}

vchar_t *
eay_3des_decrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_des_ede3_cbc(), 0);
}

int
eay_3des_weakkey(key)
	vchar_t *key;
{
	/* Same rationale as eay_des_weakkey: DES_is_weak_key is deprecated in
	 * OpenSSL 3.0 (OSSL_DEPRECATEDIN_3_0) but functional.  3DES is just
	 * three DES sub-keys, so we check each 8-byte slice independently.
	 */
	if (key->l < 24)
		return 0;

	return (compat_DES_is_weak_key(key->v) ||
		compat_DES_is_weak_key(key->v + 8) ||
		compat_DES_is_weak_key(key->v + 16));
}

int
eay_3des_keylen(len)
	int len;
{
	if (len != 0 && len != 192)
		return -1;
	return 192;
}

/*
 * CAST-CBC
 */
vchar_t *
eay_cast_encrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_cast5_cbc(), 1);
}

vchar_t *
eay_cast_decrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, EVP_cast5_cbc(), 0);
}

int
eay_cast_weakkey(key)
	vchar_t *key;
{
	return 0;	/* No known weak keys. */
}

int
eay_cast_keylen(len)
	int len;
{
	if (len == 0)
		return 128;
	if (len < 40 || len > 128)
		return -1;
	return len;
}

/*
 * AES(RIJNDAEL)-CBC
 */
#ifndef HAVE_OPENSSL_AES_H
vchar_t *
eay_aes_encrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	vchar_t *res;
	keyInstance k;
	cipherInstance c;

	memset(&k, 0, sizeof(k));
	if (rijndael_makeKey(&k, DIR_ENCRYPT, key->l << 3, key->v) < 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* encryption data */
	memset(&c, 0, sizeof(c));
	if (rijndael_cipherInit(&c, MODE_CBC, iv->v) < 0){
		vfree(res);
		return NULL;
	}
	if (rijndael_blockEncrypt(&c, &k, data->v, data->l << 3, res->v) < 0){
		vfree(res);
		return NULL;
	}

	return res;
}

vchar_t *
eay_aes_decrypt(data, key, iv)
	vchar_t *data, *key, *iv;
{
	vchar_t *res;
	keyInstance k;
	cipherInstance c;

	memset(&k, 0, sizeof(k));
	if (rijndael_makeKey(&k, DIR_DECRYPT, key->l << 3, key->v) < 0)
		return NULL;

	/* allocate buffer for result */
	if ((res = vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	memset(&c, 0, sizeof(c));
	if (rijndael_cipherInit(&c, MODE_CBC, iv->v) < 0){
		vfree(res);
		return NULL;
	}
	if (rijndael_blockDecrypt(&c, &k, data->v, data->l << 3, res->v) < 0){
		vfree(res);
		return NULL;
	}

	return res;
}
#else
static inline const EVP_CIPHER *
aes_evp_by_keylen(int keylen)
{
	switch(keylen) {
	case 16:
	case 128:
		return EVP_aes_128_cbc();
	case 24:
	case 192:
		return EVP_aes_192_cbc();
	case 32:
	case 256:
		return EVP_aes_256_cbc();
	default:
		return NULL;
	}
}

vchar_t *
eay_aes_encrypt(data, key, iv)
       vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, aes_evp_by_keylen(key->l), 1);
}

vchar_t *
eay_aes_decrypt(data, key, iv)
       vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, aes_evp_by_keylen(key->l), 0);
}
#endif

int
eay_aes_weakkey(key)
	vchar_t *key;
{
	return 0;
}

int
eay_aes_keylen(len)
	int len;
{
	if (len == 0)
		return 128;
	if (len != 128 && len != 192 && len != 256)
		return -1;
	return len;
}

#if defined(HAVE_OPENSSL_CAMELLIA_H) && ! defined(OPENSSL_NO_CAMELLIA)
/*
 * CAMELLIA-CBC
 */
static inline const EVP_CIPHER *
camellia_evp_by_keylen(int keylen)
{
	switch(keylen) {
	case 16:
	case 128:
		return EVP_camellia_128_cbc();
	case 24:
	case 192:
		return EVP_camellia_192_cbc();
	case 32:
	case 256:
		return EVP_camellia_256_cbc();
	default:
		return NULL;
	}
}

vchar_t *
eay_camellia_encrypt(data, key, iv)
       vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, camellia_evp_by_keylen(key->l), 1);
}

vchar_t *
eay_camellia_decrypt(data, key, iv)
       vchar_t *data, *key, *iv;
{
	return evp_crypt(data, key, iv, camellia_evp_by_keylen(key->l), 0);
}

int
eay_camellia_weakkey(key)
	vchar_t *key;
{
	return 0;
}

int
eay_camellia_keylen(len)
	int len;
{
	if (len == 0)
		return 128;
	if (len != 128 && len != 192 && len != 256)
		return -1;
	return len;
}

#endif

/* for ipsec part */
int
eay_null_hashlen()
{
	return 0;
}

int
eay_kpdk_hashlen()
{
	return 0;
}

int
eay_twofish_keylen(len)
	int len;
{
	if (len < 0 || len > 256)
		return -1;
	return len;
}

int
eay_null_keylen(len)
	int len;
{
	return 0;
}

/*
 * HMAC functions - with OpenSSL 3.0 compatibility
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/* Use EVP_MAC for OpenSSL 3.0+ */
static caddr_t
eay_hmac_init(key, md)
vchar_t *key;
const EVP_MD *md;
{
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	const char *digest_name = EVP_MD_get0_name(md);

	mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (!mac) {
		plog(LLV_ERROR, LOCATION, NULL, "EVP_MAC_fetch(HMAC) failed\n");
		return NULL;
	}

	ctx = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);

	if (!ctx) {
		plog(LLV_ERROR, LOCATION, NULL, "EVP_MAC_CTX_new() failed\n");
		return NULL;
	}

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						     (char *)digest_name, 0);
	params[1] = OSSL_PARAM_construct_end();

	if (EVP_MAC_init(ctx, (unsigned char *)key->v, key->l, params) != 1) {
		plog(LLV_ERROR, LOCATION, NULL, "EVP_MAC_init() failed\n");
		EVP_MAC_CTX_free(ctx);
		return NULL;
	}

	return (caddr_t)ctx;
}

static void
	eay_hmac_update(ctx, data)
	caddr_t ctx;
vchar_t *data;
{
	EVP_MAC_update((EVP_MAC_CTX *)ctx, (unsigned char *)data->v, data->l);
}

static vchar_t *
eay_hmac_final(ctx, expected_len)
caddr_t ctx;
int expected_len;
{
	vchar_t *res;
	size_t len;

	if ((res = vmalloc(expected_len)) == NULL) {
		EVP_MAC_CTX_free((EVP_MAC_CTX *)ctx);
		return NULL;
	}

	if (EVP_MAC_final((EVP_MAC_CTX *)ctx, (unsigned char *)res->v, &len, expected_len) != 1) {
		vfree(res);
		EVP_MAC_CTX_free((EVP_MAC_CTX *)ctx);
		return NULL;
	}

	res->l = len;
	EVP_MAC_CTX_free((EVP_MAC_CTX *)ctx);

	if (expected_len != res->l) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "hmac length mismatch (expected %d, got %zd)\n", expected_len, res->l);
		vfree(res);
		return NULL;
	}

	return res;
}

#else
/* Use HMAC_* for OpenSSL 1.1.x */
static caddr_t
eay_hmac_init(key, md)
	vchar_t *key;
	const EVP_MD *md;
{
	HMAC_CTX *c = HMAC_CTX_new();

	if (!c)
		return NULL;

	HMAC_Init_ex(c, key->v, key->l, md, NULL);

	return (caddr_t)c;
}

static void
	eay_hmac_update(ctx, data)
	caddr_t ctx;
vchar_t *data;
{
	HMAC_Update((HMAC_CTX *)ctx, (unsigned char *)data->v, data->l);
}

static vchar_t *
eay_hmac_final(ctx, expected_len)
caddr_t ctx;
int expected_len;
{
	vchar_t *res;
	unsigned int l;

	if ((res = vmalloc(expected_len)) == NULL) {
		HMAC_CTX_free((HMAC_CTX *)ctx);
		return NULL;
	}

	HMAC_Final((HMAC_CTX *)ctx, (unsigned char *)res->v, &l);
	res->l = l;
	HMAC_CTX_free((HMAC_CTX *)ctx);

	if (expected_len != res->l) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "hmac length mismatch (expected %d, got %zd)\n", expected_len, res->l);
		vfree(res);
		return NULL;
	}

	return res;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/* Use EVP_MAC one-shot for OpenSSL 3.0+ */
static vchar_t *
eay_hmac_one(key, data, type)
	vchar_t *key, *data;
	const EVP_MD *type;
{
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	vchar_t *res;
	size_t outlen;
	const char *digest_name;

	digest_name = EVP_MD_get0_name(type);
	if (!digest_name)
		return NULL;

	mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (!mac)
		return NULL;

	ctx = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);
	if (!ctx)
		return NULL;

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
						 (char *)digest_name, 0);
	params[1] = OSSL_PARAM_construct_end();

	if (EVP_MAC_init(ctx, (unsigned char *)key->v, key->l, params) != 1) {
		EVP_MAC_CTX_free(ctx);
		return NULL;
	}

	res = vmalloc(EVP_MD_size(type));
	if (!res) {
		EVP_MAC_CTX_free(ctx);
		return NULL;
	}

	EVP_MAC_update(ctx, (unsigned char *)data->v, data->l);

	if (EVP_MAC_final(ctx, (unsigned char *)res->v, &outlen, res->l) != 1) {
		vfree(res);
		EVP_MAC_CTX_free(ctx);
		return NULL;
	}

	res->l = outlen;
	EVP_MAC_CTX_free(ctx);
	return res;
}
#else
/* Use legacy HMAC() for OpenSSL 1.1.x */
static vchar_t *
eay_hmac_one(key, data, type)
	vchar_t *key, *data;
	const EVP_MD *type;
{
	vchar_t *res;

	if ((res = vmalloc(EVP_MD_size(type))) == 0)
		return NULL;

	if (!HMAC(type, (void *) key->v, key->l,
		  (void *) data->v, data->l, (void *) res->v, NULL)) {
		vfree(res);
		return NULL;
	}

	return res;
}
#endif

static vchar_t *eay_digest_one(data, type)
	vchar_t *data;
	const EVP_MD *type;
{
	vchar_t *res;

	if ((res = vmalloc(EVP_MD_size(type))) == 0)
		return NULL;

	if (!EVP_Digest((void *) data->v, data->l,
			(void *) res->v, NULL, type, NULL)) {
		vfree(res);
		return NULL;
	}

	return res;
}

#ifdef WITH_SHA2
/*
 * HMAC SHA2-512
 */
vchar_t *
eay_hmacsha2_512_one(key, data)
	vchar_t *key, *data;
{
	return eay_hmac_one(key, data, EVP_sha512());
}

caddr_t
eay_hmacsha2_512_init(key)
	vchar_t *key;
{
	return eay_hmac_init(key, EVP_sha512());
}

void
eay_hmacsha2_512_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	eay_hmac_update(c, data);
}

vchar_t *
eay_hmacsha2_512_final(c)
	caddr_t c;
{
	return eay_hmac_final(c, SHA512_DIGEST_LENGTH);
}

/*
 * HMAC SHA2-384
 */
vchar_t *
eay_hmacsha2_384_one(key, data)
	vchar_t *key, *data;
{
	return eay_hmac_one(key, data, EVP_sha384());
}

caddr_t
eay_hmacsha2_384_init(key)
	vchar_t *key;
{
	return eay_hmac_init(key, EVP_sha384());
}

void
eay_hmacsha2_384_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	eay_hmac_update(c, data);
}

vchar_t *
eay_hmacsha2_384_final(c)
	caddr_t c;
{
	return eay_hmac_final(c, SHA384_DIGEST_LENGTH);
}

/*
 * HMAC SHA2-256
 */
vchar_t *
eay_hmacsha2_256_one(key, data)
	vchar_t *key, *data;
{
	return eay_hmac_one(key, data, EVP_sha256());
}

caddr_t
eay_hmacsha2_256_init(key)
	vchar_t *key;
{
	return eay_hmac_init(key, EVP_sha256());
}

void
eay_hmacsha2_256_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	eay_hmac_update(c, data);
}

vchar_t *
eay_hmacsha2_256_final(c)
	caddr_t c;
{
	return eay_hmac_final(c, SHA256_DIGEST_LENGTH);
}
#endif	/* WITH_SHA2 */

/*
 * HMAC SHA1
 */
vchar_t *
eay_hmacsha1_one(key, data)
	vchar_t *key, *data;
{
	return eay_hmac_one(key, data, EVP_sha1());
}

caddr_t
eay_hmacsha1_init(key)
	vchar_t *key;
{
	return eay_hmac_init(key, EVP_sha1());
}

void
eay_hmacsha1_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	eay_hmac_update(c, data);
}

vchar_t *
eay_hmacsha1_final(c)
	caddr_t c;
{
	return eay_hmac_final(c, SHA_DIGEST_LENGTH);
}

/*
 * HMAC MD5
 */
vchar_t *
eay_hmacmd5_one(key, data)
	vchar_t *key, *data;
{
	return eay_hmac_one(key, data, EVP_md5());
}

caddr_t
eay_hmacmd5_init(key)
	vchar_t *key;
{
	return eay_hmac_init(key, EVP_md5());
}

void
eay_hmacmd5_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	eay_hmac_update(c, data);
}

vchar_t *
eay_hmacmd5_final(c)
	caddr_t c;
{
	return eay_hmac_final(c, MD5_DIGEST_LENGTH);
}

#ifdef WITH_SHA2
/*
 * SHA2-512 functions using EVP interface
 */
caddr_t
eay_sha2_512_init()
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	if (!c)
		return NULL;

	if (!EVP_DigestInit_ex(c, EVP_sha512(), NULL)) {
		EVP_MD_CTX_free(c);
		return NULL;
	}

	return (caddr_t)c;
}

void
eay_sha2_512_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	EVP_DigestUpdate((EVP_MD_CTX *)c, (unsigned char *) data->v, data->l);
}

vchar_t *
eay_sha2_512_final(c)
	caddr_t c;
{
	vchar_t *res;
	unsigned int len;

	if ((res = vmalloc(SHA512_DIGEST_LENGTH)) == 0) {
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	if (!EVP_DigestFinal_ex((EVP_MD_CTX *)c, (unsigned char *) res->v, &len)) {
		vfree(res);
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	EVP_MD_CTX_free((EVP_MD_CTX *)c);
	return res;
}

vchar_t *
eay_sha2_512_one(data)
	vchar_t *data;
{
	return eay_digest_one(data, EVP_sha512());
}

int
eay_sha2_512_hashlen()
{
	return SHA512_DIGEST_LENGTH << 3;
}
#endif

#ifdef WITH_SHA2
/*
 * SHA2-384 functions using EVP interface
 */
caddr_t
eay_sha2_384_init()
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	if (!c)
		return NULL;

	if (!EVP_DigestInit_ex(c, EVP_sha384(), NULL)) {
		EVP_MD_CTX_free(c);
		return NULL;
	}

	return (caddr_t)c;
}

void
eay_sha2_384_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	EVP_DigestUpdate((EVP_MD_CTX *)c, (unsigned char *) data->v, data->l);
}

vchar_t *
eay_sha2_384_final(c)
	caddr_t c;
{
	vchar_t *res;
	unsigned int len;

	if ((res = vmalloc(SHA384_DIGEST_LENGTH)) == 0) {
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	if (!EVP_DigestFinal_ex((EVP_MD_CTX *)c, (unsigned char *) res->v, &len)) {
		vfree(res);
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	EVP_MD_CTX_free((EVP_MD_CTX *)c);
	return res;
}

vchar_t *
eay_sha2_384_one(data)
	vchar_t *data;
{
	return eay_digest_one(data, EVP_sha384());
}

int
eay_sha2_384_hashlen()
{
	return SHA384_DIGEST_LENGTH << 3;
}
#endif

#ifdef WITH_SHA2
/*
 * SHA2-256 functions using EVP interface
 */
caddr_t
eay_sha2_256_init()
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	if (!c)
		return NULL;

	if (!EVP_DigestInit_ex(c, EVP_sha256(), NULL)) {
		EVP_MD_CTX_free(c);
		return NULL;
	}

	return (caddr_t)c;
}

void
eay_sha2_256_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	EVP_DigestUpdate((EVP_MD_CTX *)c, (unsigned char *) data->v, data->l);
}

vchar_t *
eay_sha2_256_final(c)
	caddr_t c;
{
	vchar_t *res;
	unsigned int len;

	if ((res = vmalloc(SHA256_DIGEST_LENGTH)) == 0) {
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	if (!EVP_DigestFinal_ex((EVP_MD_CTX *)c, (unsigned char *) res->v, &len)) {
		vfree(res);
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	EVP_MD_CTX_free((EVP_MD_CTX *)c);
	return res;
}

vchar_t *
eay_sha2_256_one(data)
	vchar_t *data;
{
	return eay_digest_one(data, EVP_sha256());
}

int
eay_sha2_256_hashlen()
{
	return SHA256_DIGEST_LENGTH << 3;
}
#endif

/*
 * SHA1 functions using EVP interface
 */
caddr_t
eay_sha1_init()
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	if (!c)
		return NULL;

	if (!EVP_DigestInit_ex(c, EVP_sha1(), NULL)) {
		EVP_MD_CTX_free(c);
		return NULL;
	}

	return (caddr_t)c;
}

void
eay_sha1_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	EVP_DigestUpdate((EVP_MD_CTX *)c, data->v, data->l);
}

vchar_t *
eay_sha1_final(c)
	caddr_t c;
{
	vchar_t *res;
	unsigned int len;

	if ((res = vmalloc(SHA_DIGEST_LENGTH)) == 0) {
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	if (!EVP_DigestFinal_ex((EVP_MD_CTX *)c, (unsigned char *) res->v, &len)) {
		vfree(res);
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	EVP_MD_CTX_free((EVP_MD_CTX *)c);
	return res;
}

vchar_t *
eay_sha1_one(data)
	vchar_t *data;
{
	return eay_digest_one(data, EVP_sha1());
}

int
eay_sha1_hashlen()
{
	return SHA_DIGEST_LENGTH << 3;
}

/*
 * MD5 functions using EVP interface
 */
caddr_t
eay_md5_init()
{
	EVP_MD_CTX *c = EVP_MD_CTX_new();
	if (!c)
		return NULL;

	if (!EVP_DigestInit_ex(c, EVP_md5(), NULL)) {
		EVP_MD_CTX_free(c);
		return NULL;
	}

	return (caddr_t)c;
}

void
eay_md5_update(c, data)
	caddr_t c;
	vchar_t *data;
{
	EVP_DigestUpdate((EVP_MD_CTX *)c, data->v, data->l);
}

vchar_t *
eay_md5_final(c)
	caddr_t c;
{
	vchar_t *res;
	unsigned int len;

	if ((res = vmalloc(MD5_DIGEST_LENGTH)) == 0) {
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	if (!EVP_DigestFinal_ex((EVP_MD_CTX *)c, (unsigned char *) res->v, &len)) {
		vfree(res);
		EVP_MD_CTX_free((EVP_MD_CTX *)c);
		return NULL;
	}

	EVP_MD_CTX_free((EVP_MD_CTX *)c);
	return res;
}

vchar_t *
eay_md5_one(data)
	vchar_t *data;
{
	return eay_digest_one(data, EVP_md5());
}

int
eay_md5_hashlen()
{
	return MD5_DIGEST_LENGTH << 3;
}

/*
 * eay_set_random
 *   size: number of bytes.
 */
vchar_t *
eay_set_random(size)
	u_int32_t size;
{
	BIGNUM *r = NULL;
	vchar_t *res = 0;

	if ((r = BN_new()) == NULL)
		goto end;
	BN_rand(r, size * 8, 0, 0);
	eay_bn2v(&res, r);

end:
	if (r)
		BN_free(r);
	return(res);
}

/* DH operations using EVP_PKEY API */
int
eay_dh_generate(prime, g, publen, pub, priv)
	vchar_t *prime, **pub, **priv;
	u_int publen;
	u_int32_t g;
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *params = NULL, *pkey = NULL;
	BIGNUM *p = NULL, *BNg = NULL;
	BIGNUM *pub_key = NULL, *priv_key = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params_array = NULL;
	int error = -1;

	/*
	 * prime->v contains binary data (big-endian bytes), not a hex string.
	 * Use BN_bin2bn directly rather than eay_v2bn to make this explicit.
	 */
	p = BN_bin2bn((unsigned char *)prime->v, prime->l, NULL);
	if (!p)
		goto end;

	/* Create generator BIGNUM */
	if ((BNg = BN_new()) == NULL)
		goto end;
	if (!BN_set_word(BNg, g))
		goto end;

	/* Build DH parameters */
	bld = OSSL_PARAM_BLD_new();
	if (!bld)
		goto end;

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p))
		goto end;
	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, BNg))
		goto end;

	/* Optionally set private key length */
	if (publen != 0) {
		if (!OSSL_PARAM_BLD_push_size_t(bld, OSSL_PKEY_PARAM_DH_PRIV_LEN, publen / 8))
			goto end;
	}

	params_array = OSSL_PARAM_BLD_to_param(bld);
	if (!params_array)
		goto end;

	/* Create parameter object */
	pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (!pctx)
		goto end;

	if (EVP_PKEY_fromdata_init(pctx) <= 0)
		goto end;

	if (EVP_PKEY_fromdata(pctx, &params, EVP_PKEY_KEY_PARAMETERS, params_array) <= 0)
		goto end;

	compat_EVP_PKEY_CTX_free(pctx);
	pctx = NULL;

	/* Generate key pair from parameters */
	pctx = EVP_PKEY_CTX_new(params, NULL);
	if (!pctx)
		goto end;

	if (EVP_PKEY_keygen_init(pctx) <= 0)
		goto end;

	if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
		goto end;

	/* Extract public and private keys */
	if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key))
		goto end;
	if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_key))
		goto end;

	/* Convert to vchar_t */
	if (eay_bn2v(pub, pub_key) < 0)
		goto end;
	if (eay_bn2v(priv, priv_key) < 0) {
		vfree(*pub);
		*pub = NULL;
		goto end;
	}

	error = 0;

end:
	if (pub_key)
		BN_free(pub_key);
	if (priv_key)
		BN_clear_free(priv_key);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (params)
		EVP_PKEY_free(params);
	if (pctx)
		compat_EVP_PKEY_CTX_free(pctx);
	if (params_array)
		OSSL_PARAM_free(params_array);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (p)
		BN_free(p);
	if (BNg)
		BN_free(BNg);

	return error;
}

int
eay_dh_compute(prime, g, pub, priv, pub2, key)
	vchar_t *prime, *pub, *priv, *pub2, **key;
	u_int32_t g;
{
	EVP_PKEY_CTX *pctx = NULL, *kctx = NULL;
	EVP_PKEY *pkey = NULL, *peerkey = NULL;
	BIGNUM *p = NULL, *BNg = NULL;
	BIGNUM *pub_key = NULL, *priv_key = NULL, *peer_pub_key = NULL;
	OSSL_PARAM_BLD *key_bld = NULL, *peer_bld = NULL;
	OSSL_PARAM *key_array = NULL, *peer_array = NULL;
	unsigned char *secret = NULL;
	size_t secret_len;
	size_t secret_alloc_len;
	int error = -1;

	/* Convert parameters to BIGNUMs */
	if (eay_v2bn(&p, prime) < 0)
		goto end;
	if (eay_v2bn(&pub_key, pub) < 0)
		goto end;
	if (eay_v2bn(&priv_key, priv) < 0)
		goto end;
	if (eay_v2bn(&peer_pub_key, pub2) < 0)
		goto end;

	if ((BNg = BN_new()) == NULL)
		goto end;
	if (!BN_set_word(BNg, g))
		goto end;

	/* Build our complete DH keypair */
	key_bld = OSSL_PARAM_BLD_new();
	if (!key_bld)
		goto end;

	if (!OSSL_PARAM_BLD_push_BN(key_bld, OSSL_PKEY_PARAM_FFC_P, p))
		goto end;
	if (!OSSL_PARAM_BLD_push_BN(key_bld, OSSL_PKEY_PARAM_FFC_G, BNg))
		goto end;
	if (!OSSL_PARAM_BLD_push_BN(key_bld, OSSL_PKEY_PARAM_PUB_KEY, pub_key))
		goto end;
	if (!OSSL_PARAM_BLD_push_BN(key_bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_key))
		goto end;

	key_array = OSSL_PARAM_BLD_to_param(key_bld);
	if (!key_array)
		goto end;

	/* Create our keypair */
	pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (!pctx)
		goto end;

	if (EVP_PKEY_fromdata_init(pctx) <= 0)
		goto end;

	if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, key_array) <= 0)
		goto end;

	compat_EVP_PKEY_CTX_free(pctx);
	pctx = NULL;

	/* Build peer's public key with same parameters */
	peer_bld = OSSL_PARAM_BLD_new();
	if (!peer_bld)
		goto end;

	if (!OSSL_PARAM_BLD_push_BN(peer_bld, OSSL_PKEY_PARAM_FFC_P, p))
		goto end;
	if (!OSSL_PARAM_BLD_push_BN(peer_bld, OSSL_PKEY_PARAM_FFC_G, BNg))
		goto end;
	if (!OSSL_PARAM_BLD_push_BN(peer_bld, OSSL_PKEY_PARAM_PUB_KEY, peer_pub_key))
		goto end;

	peer_array = OSSL_PARAM_BLD_to_param(peer_bld);
	if (!peer_array)
		goto end;

	/* Create peer's public key */
	pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (!pctx)
		goto end;

	if (EVP_PKEY_fromdata_init(pctx) <= 0)
		goto end;

	if (EVP_PKEY_fromdata(pctx, &peerkey, EVP_PKEY_PUBLIC_KEY, peer_array) <= 0)
		goto end;

	compat_EVP_PKEY_CTX_free(pctx);
	pctx = NULL;

	/* Derive shared secret */
	kctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!kctx)
		goto end;

	if (EVP_PKEY_derive_init(kctx) <= 0)
		goto end;

	/* Set peer — this performs critical validation (small-subgroup, range checks).
	 * A failure here means the peer public key is invalid; treat as fatal. */
	if (EVP_PKEY_derive_set_peer(kctx, peerkey) <= 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		     "EVP_PKEY_derive_set_peer validation failed: %s\n",
		     eay_strerror());
		goto end;
	}

	/* Determine buffer length */
	if (EVP_PKEY_derive(kctx, NULL, &secret_len) <= 0)
		goto end;

	secret = racoon_malloc(secret_len);
	secret_alloc_len = secret_len;
	if (!secret)
		goto end;

	/* Derive the shared secret */
	if (EVP_PKEY_derive(kctx, secret, &secret_len) <= 0)
		goto end;

	/* Copy to output key - right-aligned in prime-length buffer.
	 * The write extends from offset (prime->l - secret_len) to prime->l,
	 * so the caller's buffer must be at least prime->l bytes. */
	if (secret_len <= prime->l && (*key)->l >= prime->l) {
		memset((*key)->v, 0, (*key)->l);
		memcpy((*key)->v + (prime->l - secret_len), secret, secret_len);
		error = 0;
	}

end:
		if (secret) {
		memset(secret, 0, secret_alloc_len);
		racoon_free(secret);
	}
	if (peer_pub_key)
		BN_free(peer_pub_key);
	if (priv_key)
		BN_clear_free(priv_key);
	if (pub_key)
		BN_free(pub_key);
	if (BNg)
		BN_free(BNg);
	if (p)
		BN_free(p);
	if (peerkey)
		EVP_PKEY_free(peerkey);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (kctx)
		compat_EVP_PKEY_CTX_free(kctx);
	if (pctx)
		compat_EVP_PKEY_CTX_free(pctx);
	if (peer_array)
		OSSL_PARAM_free(peer_array);
	if (key_array)
		OSSL_PARAM_free(key_array);
	if (peer_bld)
		OSSL_PARAM_BLD_free(peer_bld);
	if (key_bld)
		OSSL_PARAM_BLD_free(key_bld);

	if (error == 0)
		ERR_clear_error(); /* Clear any validation warnings on success */

	return error;
}

/*
 * convert vchar_t <-> BIGNUM.
 *
 * vchar_t: unit is u_char, network endian, most significant byte first.
 * BIGNUM: unit is BN_ULONG, each of BN_ULONG is in host endian,
 *	least significant BN_ULONG must come first.
 *
 * hex value of "0x3ffe050104" is represented as follows:
 *	vchar_t: 3f fe 05 01 04
 *	BIGNUM (BN_ULONG = u_int8_t): 04 01 05 fe 3f
 *	BIGNUM (BN_ULONG = u_int16_t): 0x0104 0xfe05 0x003f
 *	BIGNUM (BN_ULONG = u_int32_t_t): 0xfe050104 0x0000003f
 */
int
eay_v2bn(bn, var)
	BIGNUM **bn;
	vchar_t *var;
{
	if ((*bn = BN_bin2bn((unsigned char *) var->v, var->l, NULL)) == NULL)
		return -1;

	return 0;
}

int
eay_bn2v(var, bn)
	vchar_t **var;
	BIGNUM *bn;
{
	*var = vmalloc(BN_num_bytes(bn));
	if (*var == NULL)
		return(-1);

	(*var)->l = BN_bn2bin(bn, (unsigned char *) (*var)->v);

	return 0;
}

void
eay_init()
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	/* OpenSSL 3.0+ - load legacy provider for DES, 3DES, Blowfish, CAST, etc. */
	if (!openssl_legacy_provider) {
		openssl_legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
		if (!openssl_legacy_provider) {
			plog(LLV_ERROR, LOCATION, NULL,
			     "Failed to load legacy provider - legacy algorithms will not work: %s\n",
			     eay_strerror());
		} else {
			plog(LLV_INFO, LOCATION, NULL,
			     "Loaded OpenSSL legacy provider\n");
		}
	}

	if (!openssl_default_provider) {
		openssl_default_provider = OSSL_PROVIDER_load(NULL, "default");
		if (!openssl_default_provider) {
			plog(LLV_ERROR, LOCATION, NULL,
			     "Failed to load default provider: %s\n",
			     eay_strerror());
		} else {
			plog(LLV_INFO, LOCATION, NULL,
			     "Loaded OpenSSL default provider\n");
		}
	}
	/* Validate legacy cipher availability at startup for clear diagnostics */
	validate_legacy_ciphers();
#endif
}

void
eay_cleanup()
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (openssl_legacy_provider) {
		OSSL_PROVIDER_unload(openssl_legacy_provider);
		openssl_legacy_provider = NULL;
	}
	if (openssl_default_provider) {
		OSSL_PROVIDER_unload(openssl_default_provider);
		openssl_default_provider = NULL;
	}
#endif
}

/*
 * base64_decode - decode a Base64 string into a vchar_t buffer.
 *
 * EVP_DecodeBlock() returns the decoded length rounded up to the nearest
 * multiple of 3 and does NOT subtract bytes consumed by '=' padding
 * characters.  We count trailing '=' characters in the input and subtract
 * them from the reported length so that the returned vchar_t has exactly
 * the correct length.
 */
vchar_t *
base64_decode(const char *in, long inlen)
{
	unsigned char *buf;
	int outlen;
	int pad = 0;
	vchar_t *res = NULL;

	buf = malloc(inlen);
	if (!buf)
		return NULL;

	outlen = EVP_DecodeBlock(buf, (const unsigned char *)in, inlen);
	if (outlen < 0) {
		free(buf);
		return NULL;
	}

	/*
	 * Subtract padding bytes from the reported length.
	 * Each '=' at the end of the Base64 input represents one byte of
	 * padding that EVP_DecodeBlock() includes in its output count.
	 */
	if (inlen >= 1 && in[inlen - 1] == '=') pad++;
	if (inlen >= 2 && in[inlen - 2] == '=') pad++;
	outlen -= pad;

	res = vmalloc(outlen);
	if (res)
		memcpy(res->v, buf, outlen);
	free(buf);
	return res;
}

vchar_t *
base64_encode(const char *in, long inlen)
{
	vchar_t *res = NULL;
	int outlen;
	unsigned char *buf;

	if (!in || inlen <= 0)
		return NULL;

	/* Each 3 bytes -> 4 chars */
	outlen = 4 * ((inlen + 2) / 3);
	buf = malloc(outlen + 1);
	if (!buf)
		return NULL;

	outlen = EVP_EncodeBlock(buf, (const unsigned char *)in, inlen);
	buf[outlen] = '\0';

	res = vmalloc(outlen);
	if (res)
		memcpy(res->v, buf, outlen);
	free(buf);
	return res;
}

static eayRSA *
binbuf_pubkey2rsa(vchar_t *binbuf)
{
	BIGNUM *exp = NULL, *mod = NULL;
	eayRSA *rsa_pub = NULL;

	if (binbuf->l < 1 || (unsigned char)binbuf->v[0] > binbuf->l - 1) {
		plog(LLV_ERROR, LOCATION, NULL, "Plain RSA pubkey format error: decoded string doesn't make sense.\n");
		goto out;
	}

	/*
	 * Buffer layout:
	 *   byte[0]           : e_len (length of exponent in bytes)
	 *   byte[1..e_len]    : exponent bytes
	 *   byte[e_len+1..end]: modulus bytes
	 *
	 * Use unsigned char for e_len to avoid sign-extension issues.
	 */
	{
		unsigned char e_len = (unsigned char)binbuf->v[0];
		unsigned int mod_len = binbuf->l - 1 - e_len;

		if (mod_len == 0) {
			plog(LLV_ERROR, LOCATION, NULL, "Plain RSA pubkey format error: zero-length modulus.\n");
			goto out;
		}

		exp = BN_bin2bn((unsigned char *)(binbuf->v + 1), e_len, NULL);
		mod = BN_bin2bn((unsigned char *)(binbuf->v + 1 + e_len), mod_len, NULL);
	}

	if (!exp || !mod) {
		plog(LLV_ERROR, LOCATION, NULL, "Plain RSA pubkey parsing error: %s\n", eay_strerror());
		goto out;
	}

	rsa_pub = eayRSA_new_pub(mod, exp);

out:
	if (exp)
		BN_free(exp);
	if (mod)
		BN_free(mod);

	return rsa_pub;
}

eayRSA *
base64_pubkey2rsa(char *in)
{
	eayRSA *rsa_pub = NULL;
	vchar_t *binbuf;

	if (strncmp(in, "0s", 2) != 0) {
		plog(LLV_ERROR, LOCATION, NULL, "Plain RSA pubkey format error: doesn't start with '0s'\n");
		return NULL;
	}

	binbuf = base64_decode(in + 2, strlen(in + 2));
	if (!binbuf) {
		plog(LLV_ERROR, LOCATION, NULL, "Plain RSA pubkey format error: Base64 decoding failed.\n");
		return NULL;
	}

	rsa_pub = binbuf_pubkey2rsa(binbuf);

	vfree(binbuf);

	return rsa_pub;
}

eayRSA *
bignum_pubkey2rsa(BIGNUM *in)
{
	eayRSA *rsa_pub = NULL;
	vchar_t *binbuf;

	binbuf = vmalloc(BN_num_bytes(in));
	if (!binbuf) {
		plog(LLV_ERROR, LOCATION, NULL, "Plain RSA pubkey conversion: memory allocation failed..\n");
		return NULL;
	}

	BN_bn2bin(in, (unsigned char *) binbuf->v);

	rsa_pub = binbuf_pubkey2rsa(binbuf);

	if (binbuf)
		vfree(binbuf);

	return rsa_pub;
}

u_int32_t
eay_random()
{
	u_int32_t result;
	vchar_t *vrand;

	vrand = eay_set_random(sizeof(result));
	memcpy(&result, vrand->v, sizeof(result));
	vfree(vrand);

	return result;
}

const char *
eay_version()
{
	return OpenSSL_version(OPENSSL_VERSION);
}
