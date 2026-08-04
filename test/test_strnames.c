// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for strnames.c — all s_* string/value lookup functions
 *
 * File: test/test_strnames.c
 * Coverage: src/racoon/strnames.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/in.h>
#include PATH_IPSEC_H

#include "gnuc.h"
#include "isakmp.h"
#include "ipsec_doi.h"
#include "oakley.h"
#include "algorithm.h"
#include "var.h"
#include "handler.h"

/*
 * Extern declarations for all strnames.c functions (K&R style in source).
 */
extern char *num2str __P((int));
extern char *s_isakmp_state __P((int, int, int));
extern char *s_isakmp_certtype __P((int));
extern char *s_isakmp_etype __P((int));
extern char *s_isakmp_notify_msg __P((int));
extern char *s_isakmp_nptype __P((int));
extern char *s_ipsecdoi_proto __P((int));
extern char *s_ipsecdoi_trns_isakmp __P((int));
extern char *s_ipsecdoi_trns_ah __P((int));
extern char *s_ipsecdoi_trns_esp __P((int));
extern char *s_ipsecdoi_trns_ipcomp __P((int));
extern char *s_ipsecdoi_trns __P((int, int));
extern char *s_ipsecdoi_attr __P((int));
extern char *s_ipsecdoi_ltype __P((int));
extern char *s_ipsecdoi_encmode __P((int));
extern char *s_ipsecdoi_auth __P((int));
extern char *s_ipsecdoi_attr_v __P((int, int));
extern char *s_ipsecdoi_ident __P((int));
extern char *s_oakley_attr __P((int));
extern char *s_attr_isakmp_enc __P((int));
extern char *s_attr_isakmp_hash __P((int));
extern char *s_oakley_attr_method __P((int));
extern char *s_attr_isakmp_desc __P((int));
extern char *s_attr_isakmp_group __P((int));
extern char *s_attr_isakmp_ltype __P((int));
extern char *s_oakley_attr_v __P((int, int));
extern char *s_ipsec_level __P((int));
extern char *s_algclass __P((int));
extern char *s_algtype __P((int, int));
extern char *s_pfkey_type __P((int));
extern char *s_pfkey_satype __P((int));
extern char *s_direction __P((int));
extern char *s_proto __P((int));
extern char *s_doi __P((int));
extern char *s_etype __P((int));
extern char *s_idtype __P((int));
extern char *s_switch __P((int));

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/*
 * Assert that a function returns a non-NULL string for a known key.
 */
#define ASSERT_NOT_NULL(expr) do { \
    char *r = (expr); \
    if (!r) TEST_FAIL(#expr " returned NULL"); \
} while(0)

/*
 * Assert that a function returns the expected string (strcmp check).
 */
#define ASSERT_STR(expr, expected) do { \
    char *r = (expr); \
    if (!r || strcmp(r, (expected)) != 0) { \
        printf("FAIL: %s expected '%s' got '%s'\n", #expr, (expected), r ? r : "NULL"); \
        return -1; \
    } \
} while(0)

/*
 * Assert that a function returns a numeric fallback string for an unknown key.
 * The fallback is num2str(k), which returns a string representation of the key.
 */
#define ASSERT_NUMFALLBACK(expr, k) do { \
    char *r = (expr); \
    char buf[20]; \
    snprintf(buf, sizeof(buf), "%d", (k)); \
    if (!r || strcmp(r, buf) != 0) { \
        printf("FAIL: %s expected '%s' got '%s'\n", #expr, buf, r ? r : "NULL"); \
        return -1; \
    } \
} while(0)

/* --- num2str --- */
int test_num2str(void)
{
    TEST_START("num2str basic");
    ASSERT_STR(num2str(0), "0");
    ASSERT_STR(num2str(42), "42");
    ASSERT_STR(num2str(-1), "-1");
    ASSERT_STR(num2str(999999), "999999");
    TEST_PASS();
    return 0;
}

/* --- s_isakmp_state --- */
int test_s_isakmp_state(void)
{
    TEST_START("s_isakmp_state known states");

    /* Aggressive initiator */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_AGG, INITIATOR, PHASE1ST_MSG1SENT), "agg I msg1");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_AGG, INITIATOR, PHASE1ST_ESTABLISHED), "agg I msg2");

    /* Aggressive responder */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_AGG, RESPONDER, PHASE1ST_MSG1SENT), "agg R msg1");

    /* Base initiator */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_BASE, INITIATOR, PHASE1ST_MSG1SENT), "base I msg1");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_BASE, INITIATOR, PHASE1ST_MSG2SENT), "base I msg2");

    /* Base responder */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_BASE, RESPONDER, PHASE1ST_MSG1SENT), "base R msg1");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_BASE, RESPONDER, PHASE1ST_ESTABLISHED), "base R msg2");

    /* Identity protection initiator */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_IDENT, INITIATOR, PHASE1ST_MSG1SENT), "ident I msg1");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_IDENT, INITIATOR, PHASE1ST_MSG2SENT), "ident I msg2");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_IDENT, INITIATOR, PHASE1ST_MSG3SENT), "ident I msg3");

    /* Identity protection responder */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_IDENT, RESPONDER, PHASE1ST_MSG1SENT), "ident R msg1");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_IDENT, RESPONDER, PHASE1ST_MSG2SENT), "ident R msg2");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_IDENT, RESPONDER, PHASE1ST_ESTABLISHED), "ident R msg3");

    /* Quick initiator */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_QUICK, INITIATOR, PHASE2ST_MSG1SENT), "quick I msg1");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_QUICK, INITIATOR, PHASE2ST_ADDSA), "quick I msg2");

    /* Quick responder */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_QUICK, RESPONDER, PHASE2ST_MSG1SENT), "quick R msg1");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_QUICK, RESPONDER, PHASE2ST_COMMIT), "quick R msg2");

    /* Default / unhandled exchange types return "???" */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_NONE, INITIATOR, PHASE1ST_START), "???");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_AUTH, INITIATOR, PHASE1ST_START), "???");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_INFO, INITIATOR, PHASE1ST_START), "???");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_NEWGRP, INITIATOR, PHASE1ST_START), "???");
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_ACKINFO, INITIATOR, PHASE1ST_START), "???");

    /* Unhandled status in valid exchange/direction falls through to "???" */
    ASSERT_STR(s_isakmp_state(ISAKMP_ETYPE_AGG, INITIATOR, PHASE1ST_START), "???");

    TEST_PASS();
    return 0;
}

/* --- s_isakmp_certtype --- */
int test_s_isakmp_certtype(void)
{
    TEST_START("s_isakmp_certtype known values");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_NONE), "NONE");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_PKCS7), "PKCS #7 wrapped X.509 certificate");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_PGP), "PGP Certificate");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_DNS), "DNS Signed Key");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_X509SIGN), "X.509 Certificate Signature");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_X509KE), "X.509 Certificate Key Exchange");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_KERBEROS), "Kerberos Tokens");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_CRL), "Certificate Revocation List (CRL)");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_ARL), "Authority Revocation List (ARL)");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_SPKI), "SPKI Certificate");
    ASSERT_STR(s_isakmp_certtype(ISAKMP_CERT_X509ATTR), "X.509 Certificate Attribute");
    ASSERT_NUMFALLBACK(s_isakmp_certtype(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_isakmp_etype --- */
int test_s_isakmp_etype(void)
{
    TEST_START("s_isakmp_etype known values");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_NONE), "None");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_BASE), "Base");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_IDENT), "Identity Protection");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_AUTH), "Authentication Only");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_AGG), "Aggressive");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_INFO), "Informational");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_CFG), "Mode config");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_QUICK), "Quick");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_NEWGRP), "New Group");
    ASSERT_STR(s_isakmp_etype(ISAKMP_ETYPE_ACKINFO), "Acknowledged Informational");
    ASSERT_NUMFALLBACK(s_isakmp_etype(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_isakmp_notify_msg --- */
int test_s_isakmp_notify_msg(void)
{
    TEST_START("s_isakmp_notify_msg known values");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE), "INVALID-PAYLOAD-TYPE");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_DOI_NOT_SUPPORTED), "DOI-NOT-SUPPORTED");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_SITUATION_NOT_SUPPORTED), "SITUATION-NOT-SUPPORTED");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_COOKIE), "INVALID-COOKIE");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_MAJOR_VERSION), "INVALID-MAJOR-VERSION");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_MINOR_VERSION), "INVALID-MINOR-VERSION");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_EXCHANGE_TYPE), "INVALID-EXCHANGE-TYPE");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_FLAGS), "INVALID-FLAGS");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_MESSAGE_ID), "INVALID-MESSAGE-ID");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_PROTOCOL_ID), "INVALID-PROTOCOL-ID");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_SPI), "INVALID-SPI");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_TRANSFORM_ID), "INVALID-TRANSFORM-ID");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_ATTRIBUTES_NOT_SUPPORTED), "ATTRIBUTES-NOT-SUPPORTED");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_NO_PROPOSAL_CHOSEN), "NO-PROPOSAL-CHOSEN");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_BAD_PROPOSAL_SYNTAX), "BAD-PROPOSAL-SYNTAX");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_PAYLOAD_MALFORMED), "PAYLOAD-MALFORMED");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_KEY_INFORMATION), "INVALID-KEY-INFORMATION");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_ID_INFORMATION), "INVALID-ID-INFORMATION");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_CERT_ENCODING), "INVALID-CERT-ENCODING");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_CERTIFICATE), "INVALID-CERTIFICATE");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_BAD_CERT_REQUEST_SYNTAX), "BAD-CERT-REQUEST-SYNTAX");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_CERT_AUTHORITY), "INVALID-CERT-AUTHORITY");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_HASH_INFORMATION), "INVALID-HASH-INFORMATION");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_AUTHENTICATION_FAILED), "AUTHENTICATION-FAILED");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INVALID_SIGNATURE), "INVALID-SIGNATURE");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_ADDRESS_NOTIFICATION), "ADDRESS-NOTIFICATION");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_NOTIFY_SA_LIFETIME), "NOTIFY-SA-LIFETIME");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_CERTIFICATE_UNAVAILABLE), "CERTIFICATE-UNAVAILABLE");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_UNSUPPORTED_EXCHANGE_TYPE), "UNSUPPORTED-EXCHANGE-TYPE");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_UNEQUAL_PAYLOAD_LENGTHS), "UNEQUAL-PAYLOAD-LENGTHS");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_CONNECTED), "CONNECTED");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_RESPONDER_LIFETIME), "RESPONDER-LIFETIME");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_REPLAY_STATUS), "REPLAY-STATUS");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_INITIAL_CONTACT), "INITIAL-CONTACT");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_R_U_THERE), "R-U-THERE");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_NTYPE_R_U_THERE_ACK), "R-U-THERE-ACK");
    ASSERT_STR(s_isakmp_notify_msg(ISAKMP_LOG_RETRY_LIMIT_REACHED), "RETRY-LIMIT-REACHED");
    ASSERT_NUMFALLBACK(s_isakmp_notify_msg(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_isakmp_nptype --- */
int test_s_isakmp_nptype(void)
{
    TEST_START("s_isakmp_nptype known values");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_NONE), "none");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_SA), "sa");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_P), "prop");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_T), "trns");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_KE), "ke");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_ID), "id");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_CERT), "cert");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_CR), "cr");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_HASH), "hash");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_SIG), "sig");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_NONCE), "nonce");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_N), "notify");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_D), "delete");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_VID), "vid");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_ATTR), "attr");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_GSS), "gss id");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_NATD_RFC), "nat-d");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_NATOA_RFC), "nat-oa");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_NATD_DRAFT), "nat-d");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_NATOA_DRAFT), "nat-oa");
    ASSERT_STR(s_isakmp_nptype(ISAKMP_NPTYPE_FRAG), "ike frag");
    ASSERT_NUMFALLBACK(s_isakmp_nptype(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_proto --- */
int test_s_ipsecdoi_proto(void)
{
    TEST_START("s_ipsecdoi_proto known values");
    ASSERT_STR(s_ipsecdoi_proto(IPSECDOI_PROTO_ISAKMP), "ISAKMP");
    ASSERT_STR(s_ipsecdoi_proto(IPSECDOI_PROTO_IPSEC_AH), "AH");
    ASSERT_STR(s_ipsecdoi_proto(IPSECDOI_PROTO_IPSEC_ESP), "ESP");
    ASSERT_STR(s_ipsecdoi_proto(IPSECDOI_PROTO_IPCOMP), "IPCOMP");
    ASSERT_NUMFALLBACK(s_ipsecdoi_proto(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_trns_isakmp --- */
int test_s_ipsecdoi_trns_isakmp(void)
{
    TEST_START("s_ipsecdoi_trns_isakmp known values");
    ASSERT_STR(s_ipsecdoi_trns_isakmp(IPSECDOI_KEY_IKE), "IKE");
    ASSERT_NUMFALLBACK(s_ipsecdoi_trns_isakmp(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_trns_ah --- */
int test_s_ipsecdoi_trns_ah(void)
{
    TEST_START("s_ipsecdoi_trns_ah known values");
    ASSERT_STR(s_ipsecdoi_trns_ah(IPSECDOI_AH_MD5), "MD5");
    ASSERT_STR(s_ipsecdoi_trns_ah(IPSECDOI_AH_SHA), "SHA");
    ASSERT_STR(s_ipsecdoi_trns_ah(IPSECDOI_AH_DES), "DES");
    ASSERT_STR(s_ipsecdoi_trns_ah(IPSECDOI_AH_SHA256), "SHA256");
    ASSERT_STR(s_ipsecdoi_trns_ah(IPSECDOI_AH_SHA384), "SHA384");
    ASSERT_STR(s_ipsecdoi_trns_ah(IPSECDOI_AH_SHA512), "SHA512");
    ASSERT_NUMFALLBACK(s_ipsecdoi_trns_ah(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_trns_esp --- */
int test_s_ipsecdoi_trns_esp(void)
{
    TEST_START("s_ipsecdoi_trns_esp known values");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_DES_IV64), "DES_IV64");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_DES), "DES");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_3DES), "3DES");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_RC5), "RC5");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_IDEA), "IDEA");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_CAST), "CAST");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_BLOWFISH), "BLOWFISH");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_3IDEA), "3IDEA");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_DES_IV32), "DES_IV32");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_RC4), "RC4");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_NULL), "NULL");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_AES), "AES");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_TWOFISH), "TWOFISH");
    ASSERT_STR(s_ipsecdoi_trns_esp(IPSECDOI_ESP_CAMELLIA), "CAMELLIA");
    ASSERT_NUMFALLBACK(s_ipsecdoi_trns_esp(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_trns_ipcomp --- */
int test_s_ipsecdoi_trns_ipcomp(void)
{
    TEST_START("s_ipsecdoi_trns_ipcomp known values");
    ASSERT_STR(s_ipsecdoi_trns_ipcomp(IPSECDOI_IPCOMP_OUI), "OUI");
    ASSERT_STR(s_ipsecdoi_trns_ipcomp(IPSECDOI_IPCOMP_DEFLATE), "DEFLATE");
    ASSERT_STR(s_ipsecdoi_trns_ipcomp(IPSECDOI_IPCOMP_LZS), "LZS");
    ASSERT_NUMFALLBACK(s_ipsecdoi_trns_ipcomp(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_trns (indirect via proto dispatch) --- */
int test_s_ipsecdoi_trns(void)
{
    TEST_START("s_ipsecdoi_trns dispatch");
    ASSERT_STR(s_ipsecdoi_trns(IPSECDOI_PROTO_ISAKMP, IPSECDOI_KEY_IKE), "IKE");
    ASSERT_STR(s_ipsecdoi_trns(IPSECDOI_PROTO_IPSEC_AH, IPSECDOI_AH_MD5), "MD5");
    ASSERT_STR(s_ipsecdoi_trns(IPSECDOI_PROTO_IPSEC_ESP, IPSECDOI_ESP_3DES), "3DES");
    ASSERT_STR(s_ipsecdoi_trns(IPSECDOI_PROTO_IPCOMP, IPSECDOI_IPCOMP_DEFLATE), "DEFLATE");
    ASSERT_NUMFALLBACK(s_ipsecdoi_trns(9999, 42), 42);
    ASSERT_NUMFALLBACK(s_ipsecdoi_trns(IPSECDOI_PROTO_ISAKMP, 9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_attr --- */
int test_s_ipsecdoi_attr(void)
{
    TEST_START("s_ipsecdoi_attr known values");
    ASSERT_STR(s_ipsecdoi_attr(IPSECDOI_ATTR_SA_LD_TYPE), "SA Life Type");
    ASSERT_STR(s_ipsecdoi_attr(IPSECDOI_ATTR_SA_LD), "SA Life Duration");
    ASSERT_STR(s_ipsecdoi_attr(IPSECDOI_ATTR_GRP_DESC), "Group Description");
    ASSERT_STR(s_ipsecdoi_attr(IPSECDOI_ATTR_ENC_MODE), "Encryption Mode");
    ASSERT_STR(s_ipsecdoi_attr(IPSECDOI_ATTR_AUTH), "Authentication Algorithm");
    ASSERT_STR(s_ipsecdoi_attr(IPSECDOI_ATTR_KEY_LENGTH), "Key Length");
    ASSERT_STR(s_ipsecdoi_attr(IPSECDOI_ATTR_KEY_ROUNDS), "Key Rounds");
    ASSERT_STR(s_ipsecdoi_attr(IPSECDOI_ATTR_COMP_DICT_SIZE), "Compression Dictionary Size");
    ASSERT_STR(s_ipsecdoi_attr(IPSECDOI_ATTR_COMP_PRIVALG), "Compression Private Algorithm");
    ASSERT_NUMFALLBACK(s_ipsecdoi_attr(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_ltype --- */
int test_s_ipsecdoi_ltype(void)
{
    TEST_START("s_ipsecdoi_ltype known values");
    ASSERT_STR(s_ipsecdoi_ltype(IPSECDOI_ATTR_SA_LD_TYPE_SEC), "seconds");
    ASSERT_STR(s_ipsecdoi_ltype(IPSECDOI_ATTR_SA_LD_TYPE_KB), "kilobytes");
    ASSERT_NUMFALLBACK(s_ipsecdoi_ltype(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_encmode --- */
int test_s_ipsecdoi_encmode(void)
{
    TEST_START("s_ipsecdoi_encmode known values");
    ASSERT_STR(s_ipsecdoi_encmode(IPSECDOI_ATTR_ENC_MODE_ANY), "Any");
    ASSERT_STR(s_ipsecdoi_encmode(IPSECDOI_ATTR_ENC_MODE_TUNNEL), "Tunnel");
    ASSERT_STR(s_ipsecdoi_encmode(IPSECDOI_ATTR_ENC_MODE_TRNS), "Transport");
    ASSERT_STR(s_ipsecdoi_encmode(IPSECDOI_ATTR_ENC_MODE_UDPTUNNEL_RFC), "UDP-Tunnel");
    ASSERT_STR(s_ipsecdoi_encmode(IPSECDOI_ATTR_ENC_MODE_UDPTRNS_RFC), "UDP-Transport");
    ASSERT_STR(s_ipsecdoi_encmode(IPSECDOI_ATTR_ENC_MODE_UDPTUNNEL_DRAFT), "UDP-Tunnel");
    ASSERT_STR(s_ipsecdoi_encmode(IPSECDOI_ATTR_ENC_MODE_UDPTRNS_DRAFT), "UDP-Transport");
    ASSERT_NUMFALLBACK(s_ipsecdoi_encmode(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_auth --- */
int test_s_ipsecdoi_auth(void)
{
    TEST_START("s_ipsecdoi_auth known values");
    ASSERT_STR(s_ipsecdoi_auth(IPSECDOI_ATTR_AUTH_HMAC_MD5), "hmac-md5");
    ASSERT_STR(s_ipsecdoi_auth(IPSECDOI_ATTR_AUTH_HMAC_SHA1), "hmac-sha");
    ASSERT_STR(s_ipsecdoi_auth(IPSECDOI_ATTR_AUTH_HMAC_SHA2_256), "hmac-sha256");
    ASSERT_STR(s_ipsecdoi_auth(IPSECDOI_ATTR_AUTH_HMAC_SHA2_384), "hmac-sha384");
    ASSERT_STR(s_ipsecdoi_auth(IPSECDOI_ATTR_AUTH_HMAC_SHA2_512), "hmac-sha512");
    ASSERT_STR(s_ipsecdoi_auth(IPSECDOI_ATTR_AUTH_DES_MAC), "des-mac");
    ASSERT_STR(s_ipsecdoi_auth(IPSECDOI_ATTR_AUTH_KPDK), "kpdk");
    ASSERT_NUMFALLBACK(s_ipsecdoi_auth(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_attr_v (indirect via attr dispatch) --- */
int test_s_ipsecdoi_attr_v(void)
{
    TEST_START("s_ipsecdoi_attr_v dispatch");
    ASSERT_STR(s_ipsecdoi_attr_v(IPSECDOI_ATTR_SA_LD_TYPE, IPSECDOI_ATTR_SA_LD_TYPE_SEC), "seconds");
    ASSERT_STR(s_ipsecdoi_attr_v(IPSECDOI_ATTR_SA_LD_TYPE, IPSECDOI_ATTR_SA_LD_TYPE_KB), "kilobytes");
    ASSERT_STR(s_ipsecdoi_attr_v(IPSECDOI_ATTR_ENC_MODE, IPSECDOI_ATTR_ENC_MODE_TUNNEL), "Tunnel");
    ASSERT_STR(s_ipsecdoi_attr_v(IPSECDOI_ATTR_AUTH, IPSECDOI_ATTR_AUTH_HMAC_SHA1), "hmac-sha");
    ASSERT_NUMFALLBACK(s_ipsecdoi_attr_v(IPSECDOI_ATTR_SA_LD_TYPE, 9999), 9999);
    ASSERT_NUMFALLBACK(s_ipsecdoi_attr_v(IPSECDOI_ATTR_SA_LD, 42), 42);
    ASSERT_NUMFALLBACK(s_ipsecdoi_attr_v(9999, 42), 42);
    TEST_PASS();
    return 0;
}

/* --- s_ipsecdoi_ident --- */
int test_s_ipsecdoi_ident(void)
{
    TEST_START("s_ipsecdoi_ident known values");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_IPV4_ADDR), "IPv4_address");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_FQDN), "FQDN");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_USER_FQDN), "User_FQDN");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_IPV4_ADDR_SUBNET), "IPv4_subnet");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_IPV6_ADDR), "IPv6_address");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_IPV6_ADDR_SUBNET), "IPv6_subnet");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_IPV4_ADDR_RANGE), "IPv4_address_range");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_IPV6_ADDR_RANGE), "IPv6_address_range");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_DER_ASN1_DN), "DER_ASN1_DN");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_DER_ASN1_GN), "DER_ASN1_GN");
    ASSERT_STR(s_ipsecdoi_ident(IPSECDOI_ID_KEY_ID), "KEY_ID");
    ASSERT_NUMFALLBACK(s_ipsecdoi_ident(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_oakley_attr --- */
int test_s_oakley_attr(void)
{
    TEST_START("s_oakley_attr known values");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_ENC_ALG), "Encryption Algorithm");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_HASH_ALG), "Hash Algorithm");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_AUTH_METHOD), "Authentication Method");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_GRP_DESC), "Group Description");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_GRP_TYPE), "Group Type");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_GRP_PI), "Group Prime/Irreducible Polynomial");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_GRP_GEN_ONE), "Group Generator One");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_GRP_GEN_TWO), "Group Generator Two");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_GRP_CURVE_A), "Group Curve A");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_GRP_CURVE_B), "Group Curve B");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_SA_LD_TYPE), "Life Type");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_SA_LD), "Life Duration");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_PRF), "PRF");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_KEY_LEN), "Key Length");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_FIELD_SIZE), "Field Size");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_GRP_ORDER), "Group Order");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_BLOCK_SIZE), "Block Size");
    ASSERT_STR(s_oakley_attr(OAKLEY_ATTR_GSS_ID), "GSS-API endpoint name");
    ASSERT_NUMFALLBACK(s_oakley_attr(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_attr_isakmp_enc --- */
int test_s_attr_isakmp_enc(void)
{
    TEST_START("s_attr_isakmp_enc known values");
    ASSERT_STR(s_attr_isakmp_enc(OAKLEY_ATTR_ENC_ALG_DES), "DES-CBC");
    ASSERT_STR(s_attr_isakmp_enc(OAKLEY_ATTR_ENC_ALG_IDEA), "IDEA-CBC");
    ASSERT_STR(s_attr_isakmp_enc(OAKLEY_ATTR_ENC_ALG_BLOWFISH), "Blowfish-CBC");
    ASSERT_STR(s_attr_isakmp_enc(OAKLEY_ATTR_ENC_ALG_RC5), "RC5-R16-B64-CBC");
    ASSERT_STR(s_attr_isakmp_enc(OAKLEY_ATTR_ENC_ALG_3DES), "3DES-CBC");
    ASSERT_STR(s_attr_isakmp_enc(OAKLEY_ATTR_ENC_ALG_CAST), "CAST-CBC");
    ASSERT_STR(s_attr_isakmp_enc(OAKLEY_ATTR_ENC_ALG_AES), "AES-CBC");
    ASSERT_NUMFALLBACK(s_attr_isakmp_enc(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_attr_isakmp_hash --- */
int test_s_attr_isakmp_hash(void)
{
    TEST_START("s_attr_isakmp_hash known values");
    ASSERT_STR(s_attr_isakmp_hash(OAKLEY_ATTR_HASH_ALG_MD5), "MD5");
    ASSERT_STR(s_attr_isakmp_hash(OAKLEY_ATTR_HASH_ALG_SHA), "SHA");
    ASSERT_STR(s_attr_isakmp_hash(OAKLEY_ATTR_HASH_ALG_TIGER), "Tiger");
    ASSERT_STR(s_attr_isakmp_hash(OAKLEY_ATTR_HASH_ALG_SHA2_256), "SHA256");
    ASSERT_STR(s_attr_isakmp_hash(OAKLEY_ATTR_HASH_ALG_SHA2_384), "SHA384");
    ASSERT_STR(s_attr_isakmp_hash(OAKLEY_ATTR_HASH_ALG_SHA2_512), "SHA512");
    ASSERT_NUMFALLBACK(s_attr_isakmp_hash(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_oakley_attr_method --- */
int test_s_oakley_attr_method(void)
{
    TEST_START("s_oakley_attr_method known values");
    ASSERT_STR(s_oakley_attr_method(OAKLEY_ATTR_AUTH_METHOD_PSKEY), "pre-shared key");
    ASSERT_STR(s_oakley_attr_method(OAKLEY_ATTR_AUTH_METHOD_DSSSIG), "DSS signatures");
    ASSERT_STR(s_oakley_attr_method(OAKLEY_ATTR_AUTH_METHOD_RSASIG), "RSA signatures");
    ASSERT_STR(s_oakley_attr_method(OAKLEY_ATTR_AUTH_METHOD_RSAENC), "Encryption with RSA");
    ASSERT_STR(s_oakley_attr_method(OAKLEY_ATTR_AUTH_METHOD_RSAREV), "Revised encryption with RSA");
    ASSERT_STR(s_oakley_attr_method(OAKLEY_ATTR_AUTH_METHOD_EGENC), "Encryption with El-Gamal");
    ASSERT_STR(s_oakley_attr_method(OAKLEY_ATTR_AUTH_METHOD_EGREV), "Revised encryption with El-Gamal");
    ASSERT_NUMFALLBACK(s_oakley_attr_method(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_attr_isakmp_desc --- */
int test_s_attr_isakmp_desc(void)
{
    TEST_START("s_attr_isakmp_desc known values");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_MODP768), "768-bit MODP group");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_MODP1024), "1024-bit MODP group");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_EC2N155), "EC2N group on GP[2^155]");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_EC2N185), "EC2N group on GP[2^185]");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_MODP1536), "1536-bit MODP group");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_MODP2048), "2048-bit MODP group");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_MODP3072), "3072-bit MODP group");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_MODP4096), "4096-bit MODP group");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_MODP6144), "6144-bit MODP group");
    ASSERT_STR(s_attr_isakmp_desc(OAKLEY_ATTR_GRP_DESC_MODP8192), "8192-bit MODP group");
    ASSERT_NUMFALLBACK(s_attr_isakmp_desc(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_attr_isakmp_group --- */
int test_s_attr_isakmp_group(void)
{
    TEST_START("s_attr_isakmp_group known values");
    ASSERT_STR(s_attr_isakmp_group(OAKLEY_ATTR_GRP_TYPE_MODP), "MODP");
    ASSERT_STR(s_attr_isakmp_group(OAKLEY_ATTR_GRP_TYPE_ECP), "ECP");
    ASSERT_STR(s_attr_isakmp_group(OAKLEY_ATTR_GRP_TYPE_EC2N), "EC2N");
    ASSERT_NUMFALLBACK(s_attr_isakmp_group(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_attr_isakmp_ltype --- */
int test_s_attr_isakmp_ltype(void)
{
    TEST_START("s_attr_isakmp_ltype known values");
    ASSERT_STR(s_attr_isakmp_ltype(OAKLEY_ATTR_SA_LD_TYPE_SEC), "seconds");
    ASSERT_STR(s_attr_isakmp_ltype(OAKLEY_ATTR_SA_LD_TYPE_KB), "kilobytes");
    ASSERT_NUMFALLBACK(s_attr_isakmp_ltype(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_oakley_attr_v (indirect via oakley attr dispatch) --- */
int test_s_oakley_attr_v(void)
{
    TEST_START("s_oakley_attr_v dispatch");
    ASSERT_STR(s_oakley_attr_v(OAKLEY_ATTR_ENC_ALG, OAKLEY_ATTR_ENC_ALG_3DES), "3DES-CBC");
    ASSERT_STR(s_oakley_attr_v(OAKLEY_ATTR_HASH_ALG, OAKLEY_ATTR_HASH_ALG_SHA), "SHA");
    ASSERT_STR(s_oakley_attr_v(OAKLEY_ATTR_AUTH_METHOD, OAKLEY_ATTR_AUTH_METHOD_PSKEY), "pre-shared key");
    ASSERT_STR(s_oakley_attr_v(OAKLEY_ATTR_GRP_DESC, OAKLEY_ATTR_GRP_DESC_MODP768), "768-bit MODP group");
    ASSERT_STR(s_oakley_attr_v(OAKLEY_ATTR_GRP_TYPE, OAKLEY_ATTR_GRP_TYPE_MODP), "MODP");
    ASSERT_STR(s_oakley_attr_v(OAKLEY_ATTR_SA_LD_TYPE, OAKLEY_ATTR_SA_LD_TYPE_SEC), "seconds");
    ASSERT_NUMFALLBACK(s_oakley_attr_v(OAKLEY_ATTR_ENC_ALG, 9999), 9999);
    ASSERT_NUMFALLBACK(s_oakley_attr_v(OAKLEY_ATTR_SA_LD, 42), 42);
    ASSERT_NUMFALLBACK(s_oakley_attr_v(9999, 42), 42);
    TEST_PASS();
    return 0;
}

/* --- s_ipsec_level --- */
int test_s_ipsec_level(void)
{
    TEST_START("s_ipsec_level known values");
    ASSERT_STR(s_ipsec_level(IPSEC_LEVEL_USE), "use");
    ASSERT_STR(s_ipsec_level(IPSEC_LEVEL_REQUIRE), "require");
    ASSERT_STR(s_ipsec_level(IPSEC_LEVEL_UNIQUE), "unique");
    ASSERT_NUMFALLBACK(s_ipsec_level(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_algclass --- */
int test_s_algclass(void)
{
    TEST_START("s_algclass known values");
    ASSERT_STR(s_algclass(algclass_ipsec_enc), "ipsec enc");
    ASSERT_STR(s_algclass(algclass_ipsec_auth), "ipsec auth");
    ASSERT_STR(s_algclass(algclass_ipsec_comp), "ipsec comp");
    ASSERT_STR(s_algclass(algclass_isakmp_enc), "isakmp enc");
    ASSERT_STR(s_algclass(algclass_isakmp_hash), "isakmp hash");
    ASSERT_STR(s_algclass(algclass_isakmp_dh), "isakmp dh");
    ASSERT_STR(s_algclass(algclass_isakmp_ameth), "isakmp auth method");
    ASSERT_NUMFALLBACK(s_algclass(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_algtype (indirect via algclass dispatch) --- */
int test_s_algtype(void)
{
    TEST_START("s_algtype dispatch");
    ASSERT_STR(s_algtype(algclass_ipsec_enc, IPSECDOI_ESP_3DES), "3DES");
    ASSERT_STR(s_algtype(algclass_ipsec_auth, IPSECDOI_AH_SHA), "SHA");
    ASSERT_STR(s_algtype(algclass_ipsec_comp, IPSECDOI_IPCOMP_DEFLATE), "DEFLATE");
    ASSERT_STR(s_algtype(algclass_isakmp_enc, OAKLEY_ATTR_ENC_ALG_AES), "AES-CBC");
    ASSERT_STR(s_algtype(algclass_isakmp_hash, OAKLEY_ATTR_HASH_ALG_MD5), "MD5");
    ASSERT_STR(s_algtype(algclass_isakmp_dh, OAKLEY_ATTR_GRP_DESC_MODP1024), "1024-bit MODP group");
    ASSERT_STR(s_algtype(algclass_isakmp_ameth, OAKLEY_ATTR_AUTH_METHOD_RSASIG), "RSA signatures");
    ASSERT_NUMFALLBACK(s_algtype(algclass_ipsec_enc, 9999), 9999);
    ASSERT_NUMFALLBACK(s_algtype(9999, 42), 42);
    TEST_PASS();
    return 0;
}

/* --- s_pfkey_type --- */
int test_s_pfkey_type(void)
{
    TEST_START("s_pfkey_type known values");
    ASSERT_STR(s_pfkey_type(SADB_GETSPI), "GETSPI");
    ASSERT_STR(s_pfkey_type(SADB_UPDATE), "UPDATE");
    ASSERT_STR(s_pfkey_type(SADB_ADD), "ADD");
    ASSERT_STR(s_pfkey_type(SADB_DELETE), "DELETE");
    ASSERT_STR(s_pfkey_type(SADB_GET), "GET");
    ASSERT_STR(s_pfkey_type(SADB_ACQUIRE), "ACQUIRE");
    ASSERT_STR(s_pfkey_type(SADB_REGISTER), "REGISTER");
    ASSERT_STR(s_pfkey_type(SADB_EXPIRE), "EXPIRE");
    ASSERT_STR(s_pfkey_type(SADB_FLUSH), "FLUSH");
    ASSERT_STR(s_pfkey_type(SADB_DUMP), "DUMP");
    ASSERT_STR(s_pfkey_type(SADB_X_PROMISC), "X_PROMISC");
    ASSERT_STR(s_pfkey_type(SADB_X_PCHANGE), "X_PCHANGE");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDUPDATE), "X_SPDUPDATE");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDADD), "X_SPDADD");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDDELETE), "X_SPDDELETE");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDGET), "X_SPDGET");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDACQUIRE), "X_SPDACQUIRE");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDDUMP), "X_SPDDUMP");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDFLUSH), "X_SPDFLUSH");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDSETIDX), "X_SPDSETIDX");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDEXPIRE), "X_SPDEXPIRE");
    ASSERT_STR(s_pfkey_type(SADB_X_SPDDELETE2), "X_SPDDELETE2");
    ASSERT_NUMFALLBACK(s_pfkey_type(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_pfkey_satype --- */
int test_s_pfkey_satype(void)
{
    TEST_START("s_pfkey_satype known values");
    ASSERT_STR(s_pfkey_satype(SADB_SATYPE_UNSPEC), "UNSPEC");
    ASSERT_STR(s_pfkey_satype(SADB_SATYPE_AH), "AH");
    ASSERT_STR(s_pfkey_satype(SADB_SATYPE_ESP), "ESP");
    ASSERT_STR(s_pfkey_satype(SADB_SATYPE_RSVP), "RSVP");
    ASSERT_STR(s_pfkey_satype(SADB_SATYPE_OSPFV2), "OSPFV2");
    ASSERT_STR(s_pfkey_satype(SADB_SATYPE_RIPV2), "RIPV2");
    ASSERT_STR(s_pfkey_satype(SADB_SATYPE_MIP), "MIP");
    ASSERT_STR(s_pfkey_satype(SADB_X_SATYPE_IPCOMP), "IPCOMP");
    ASSERT_NUMFALLBACK(s_pfkey_satype(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_direction --- */
int test_s_direction(void)
{
    TEST_START("s_direction known values");
    ASSERT_STR(s_direction(IPSEC_DIR_INBOUND), "in");
    ASSERT_STR(s_direction(IPSEC_DIR_OUTBOUND), "out");
    ASSERT_NUMFALLBACK(s_direction(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_proto --- */
int test_s_proto(void)
{
    TEST_START("s_proto known values");
    ASSERT_STR(s_proto(IPPROTO_ICMP), "icmp");
    ASSERT_STR(s_proto(IPPROTO_TCP), "tcp");
    ASSERT_STR(s_proto(IPPROTO_UDP), "udp");
    ASSERT_STR(s_proto(IPPROTO_ICMPV6), "icmpv6");
    ASSERT_STR(s_proto(IPSEC_ULPROTO_ANY), "any");
    ASSERT_NUMFALLBACK(s_proto(99), 99);
    TEST_PASS();
    return 0;
}

/* --- s_doi --- */
int test_s_doi(void)
{
    TEST_START("s_doi known values");
    ASSERT_STR(s_doi(IPSEC_DOI), "ipsec_doi");
    ASSERT_NUMFALLBACK(s_doi(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_etype --- */
int test_s_etype(void)
{
    TEST_START("s_etype known values");
    ASSERT_STR(s_etype(ISAKMP_ETYPE_NONE), "_none");
    ASSERT_STR(s_etype(ISAKMP_ETYPE_BASE), "base");
    ASSERT_STR(s_etype(ISAKMP_ETYPE_IDENT), "main");
    ASSERT_STR(s_etype(ISAKMP_ETYPE_AUTH), "_auth");
    ASSERT_STR(s_etype(ISAKMP_ETYPE_AGG), "aggressive");
    ASSERT_STR(s_etype(ISAKMP_ETYPE_INFO), "_info");
    ASSERT_STR(s_etype(ISAKMP_ETYPE_QUICK), "_quick");
    ASSERT_STR(s_etype(ISAKMP_ETYPE_NEWGRP), "_newgrp");
    ASSERT_STR(s_etype(ISAKMP_ETYPE_ACKINFO), "_ackinfo");
    ASSERT_NUMFALLBACK(s_etype(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_idtype --- */
int test_s_idtype(void)
{
    TEST_START("s_idtype known values");
    ASSERT_STR(s_idtype(IDTYPE_FQDN), "fqdn");
    ASSERT_STR(s_idtype(IDTYPE_USERFQDN), "user_fqdn");
    ASSERT_STR(s_idtype(IDTYPE_KEYID), "keyid");
    ASSERT_STR(s_idtype(IDTYPE_ADDRESS), "address");
    ASSERT_STR(s_idtype(IDTYPE_ASN1DN), "asn1dn");
    ASSERT_NUMFALLBACK(s_idtype(IDTYPE_UNDEFINED), IDTYPE_UNDEFINED);
    ASSERT_NUMFALLBACK(s_idtype(IDTYPE_SUBNET), IDTYPE_SUBNET);
    ASSERT_NUMFALLBACK(s_idtype(9999), 9999);
    TEST_PASS();
    return 0;
}

/* --- s_switch --- */
int test_s_switch(void)
{
    TEST_START("s_switch known values");
    ASSERT_STR(s_switch(FALSE), "off");
    ASSERT_STR(s_switch(TRUE), "on");
    ASSERT_NUMFALLBACK(s_switch(42), 42);
    TEST_PASS();
    return 0;
}

int main(void)
{
    int failures = 0;

    printf("=== strnames.c unit tests ===\n");

    failures += test_num2str() < 0;
    failures += test_s_isakmp_state() < 0;
    failures += test_s_isakmp_certtype() < 0;
    failures += test_s_isakmp_etype() < 0;
    failures += test_s_isakmp_notify_msg() < 0;
    failures += test_s_isakmp_nptype() < 0;
    failures += test_s_ipsecdoi_proto() < 0;
    failures += test_s_ipsecdoi_trns_isakmp() < 0;
    failures += test_s_ipsecdoi_trns_ah() < 0;
    failures += test_s_ipsecdoi_trns_esp() < 0;
    failures += test_s_ipsecdoi_trns_ipcomp() < 0;
    failures += test_s_ipsecdoi_trns() < 0;
    failures += test_s_ipsecdoi_attr() < 0;
    failures += test_s_ipsecdoi_ltype() < 0;
    failures += test_s_ipsecdoi_encmode() < 0;
    failures += test_s_ipsecdoi_auth() < 0;
    failures += test_s_ipsecdoi_attr_v() < 0;
    failures += test_s_ipsecdoi_ident() < 0;
    failures += test_s_oakley_attr() < 0;
    failures += test_s_attr_isakmp_enc() < 0;
    failures += test_s_attr_isakmp_hash() < 0;
    failures += test_s_oakley_attr_method() < 0;
    failures += test_s_attr_isakmp_desc() < 0;
    failures += test_s_attr_isakmp_group() < 0;
    failures += test_s_attr_isakmp_ltype() < 0;
    failures += test_s_oakley_attr_v() < 0;
    failures += test_s_ipsec_level() < 0;
    failures += test_s_algclass() < 0;
    failures += test_s_algtype() < 0;
    failures += test_s_pfkey_type() < 0;
    failures += test_s_pfkey_satype() < 0;
    failures += test_s_direction() < 0;
    failures += test_s_proto() < 0;
    failures += test_s_doi() < 0;
    failures += test_s_etype() < 0;
    failures += test_s_idtype() < 0;
    failures += test_s_switch() < 0;

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}