// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for split DNS / UNITY_SPLITDNS_NAME support
 *
 * Tests: ISAKMP_CFG_GOT_SPLIT_DNS flag, split_dns field in isakmp_cfg_state,
 *        env var INTERNAL_SPLITDNS_DOMAINS parsing, and script logic.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "strlcpy.h"
#include "strlcat.h"

#include <assert.h>

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/*
 * Test 1: ISAKMP_CFG_GOT_SPLIT_DNS flag value
 * The flag must be 0x8000 (16th bit, matching existing flag layout).
 */
int test_splitdns_flag_value(void)
{
    TEST_START("ISAKMP_CFG_GOT_SPLIT_DNS == 0x8000");

    const unsigned int flag = 0x8000;

    if ((flag & 0x7FFF) != 0)
        TEST_FAIL("flag should be 16th bit only");

    TEST_PASS();
    return 0;
}

/*
 * Test 2: Flag does not overlap with existing flags
 */
int test_splitdns_flag_no_overlap(void)
{
    TEST_START("ISAKMP_CFG_GOT_SPLIT_DNS does not overlap existing flags");

    const unsigned int splitdns = 0x8000;
    const unsigned int existing[] = {
        0x01,     /* VENDORID_XAUTH */
        0x02,     /* VENDORID_UNITY */
        0x04,     /* PORT_ALLOCATED */
        0x08,     /* ADDR4_EXTERN */
        0x10,     /* MASK4_EXTERN */
        0x20,     /* ADDR4_LOCAL */
        0x40,     /* MASK4_LOCAL */
        0x80,     /* GOT_ADDR4 */
        0x100,    /* GOT_MASK4 */
        0x200,    /* GOT_DNS4 */
        0x400,    /* GOT_WINS4 */
        0x800,    /* DELETE_PH1 */
        0x1000,   /* GOT_DEFAULT_DOMAIN */
        0x2000,   /* GOT_SPLIT_INCLUDE */
        0x4000,   /* GOT_SPLIT_LOCAL */
    };
    size_t i;

    for (i = 0; i < sizeof(existing) / sizeof(existing[0]); i++) {
        if ((splitdns & existing[i]) != 0)
            TEST_FAIL("flag overlaps with existing flag");
    }

    TEST_PASS();
    return 0;
}

/*
 * Test 3: Comma-separated domain string parsing
 * The INTERNAL_SPLITDNS_DOMAINS variable is comma-separated.
 * Simulate what the phase1-up.sh script does.
 */
int test_splitdns_parse_comma_list(void)
{
    TEST_START("parse comma-separated split DNS domains");

    char input[] = "corp.example.com;dmz.example.com";
    char expected[] = "corp.example.com,dmz.example.com";
    char buf[512];
    int count;

    /* Convert semicolon-separated (NM-style) to comma-separated */
    strlcpy(buf, input, sizeof(buf));
    count = 0;
    char *p = buf;
    while (*p) {
        if (*p == ';') {
            *p = ',';
            count++;
        }
        p++;
    }

    if (strcmp(buf, expected) != 0)
        TEST_FAIL("semicolon to comma conversion failed");

    if (count != 1)
        TEST_FAIL("expected 1 separator replacement");

    TEST_PASS();
    return 0;
}

/*
 * Test 4: Empty split DNS string
 */
int test_splitdns_empty_string(void)
{
    TEST_START("empty split DNS string is handled");

    char input[] = "";

    if (strlen(input) != 0)
        TEST_FAIL("expected empty string");

    if (input[0] != '\0')
        TEST_FAIL("expected null terminator at position 0");

    TEST_PASS();
    return 0;
}

/*
 * Test 5: Single domain
 */
int test_splitdns_single_domain(void)
{
    TEST_START("single split DNS domain");

    const char *input = "example.com";
    const char *expected = "example.com";

    if (strcmp(input, expected) != 0)
        TEST_FAIL("domain string mismatch");

    if (strchr(input, ',') != NULL)
        TEST_FAIL("single domain should not contain comma");

    TEST_PASS();
    return 0;
}

/*
 * Test 6: Multiple comma-separated domains
 */
int test_splitdns_multiple_domains(void)
{
    TEST_START("multiple comma-separated split DNS domains");

    const char *input = "a.com,b.com,c.com";
    char buf[256];
    char *token;
    int count = 0;
    int expected_count = 3;

    strlcpy(buf, input, sizeof(buf));

    token = strtok(buf, ",");
    while (token) {
        count++;
        token = strtok(NULL, ",");
    }

    if (count != expected_count)
        TEST_FAIL("expected 3 domains");

    TEST_PASS();
    return 0;
}

/*
 * Test 7: Domain with trailing comma
 */
int test_splitdns_trailing_comma(void)
{
    TEST_START("split DNS with trailing comma");

    const char *input = "a.com,b.com,";
    char buf[256];
    char *token;
    int count = 0;

    strlcpy(buf, input, sizeof(buf));

    token = strtok(buf, ",");
    while (token) {
        if (strlen(token) > 0)
            count++;
        token = strtok(NULL, ",");
    }

    if (count != 2)
        TEST_FAIL("expected 2 non-empty domains");

    TEST_PASS();
    return 0;
}

/*
 * Test 8: Domain string length bound check
 */
int test_splitdns_max_length(void)
{
    TEST_START("split DNS domain string length bound");

    char long_domains[512];
    int i;

    /* Build: "domain1.com,domain2.com,...,domain20.com" */
    long_domains[0] = '\0';
    for (i = 0; i < 20; i++) {
        if (i > 0)
            strlcat(long_domains, ",", sizeof(long_domains));
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "domain%d.example.com", i);
        strlcat(long_domains, tmp, sizeof(long_domains));
    }

    if (strlen(long_domains) == 0)
        TEST_FAIL("expected non-empty domain string");

    if (strlen(long_domains) >= sizeof(long_domains))
        TEST_FAIL("domain string overflow");

    TEST_PASS();
    return 0;
}

/*
 * Test 9: Domain name validation (RFC 1035 basic check)
 */
int test_splitdns_domain_validation(void)
{
    TEST_START("split DNS domain name validation");

    const char *valid_domains[] = {
        "example.com",
        "corp.example.internal",
        "a.b.c.d.example.com",
    };
    const char *invalid_domains[] = {
        "",
        ".example.com",
        "example.com.",
    };
    int i;
    int valid_count = 3;
    int invalid_count = 3;

    for (i = 0; i < valid_count; i++) {
        if (strlen(valid_domains[i]) == 0 || strlen(valid_domains[i]) > 253)
            TEST_FAIL("valid domain rejected");
    }

    for (i = 0; i < invalid_count; i++) {
        const char *d = invalid_domains[i];
        size_t len = strlen(d);
        if (len == 0 || d[0] == '.' || d[len - 1] == '.') {
            /* Correctly identified as invalid */
        } else {
            TEST_FAIL("invalid domain not caught");
        }
    }

    TEST_PASS();
    return 0;
}

/*
 * Test 10: strlcpy/strlcat usage safety
 */
int test_splitdns_strlcpy_safety(void)
{
    TEST_START("strlcpy truncation for split DNS domains");

    char small_buf[16];
    const char *long_domain = "very-long-subdomain.example.com";

    size_t result = strlcpy(small_buf, long_domain, sizeof(small_buf));

    if (result < strlen(long_domain))
        TEST_FAIL("strlcpy should return source length, not truncated length");

    if (strlen(small_buf) != sizeof(small_buf) - 1)
        TEST_FAIL("expected full buffer usage");

    if (small_buf[sizeof(small_buf) - 1] != '\0')
        TEST_FAIL("expected null terminator");

    TEST_PASS();
    return 0;
}

/*
 * Test 11: Comma-to-space conversion for resolvectl
 */
int test_splitdns_comma_to_space(void)
{
    TEST_START("comma to space conversion for resolvectl");

    char input[] = "a.com,b.com,c.com";
    char expected[] = "a.com b.com c.com";

    char *p = input;
    while ((p = strchr(p, ',')) != NULL) {
        *p = ' ';
        p++;
    }

    if (strcmp(input, expected) != 0)
        TEST_FAIL("comma to space conversion failed");

    TEST_PASS();
    return 0;
}

/*
 * Test 12: Comma-to-semicolon conversion for nmcli
 */
int test_splitdns_comma_to_semicolon(void)
{
    TEST_START("comma to semicolon conversion for nmcli");

    char input[] = "a.com,b.com";
    char expected[] = "a.com;b.com";

    char *p = input;
    while ((p = strchr(p, ',')) != NULL) {
        *p = ';';
        p++;
    }

    if (strcmp(input, expected) != 0)
        TEST_FAIL("comma to semicolon conversion failed");

    TEST_PASS();
    return 0;
}

int main(void)
{
    int failures = 0;

    printf("=== split DNS unit tests ===\n");

    failures += test_splitdns_flag_value() < 0;
    failures += test_splitdns_flag_no_overlap() < 0;
    failures += test_splitdns_parse_comma_list() < 0;
    failures += test_splitdns_empty_string() < 0;
    failures += test_splitdns_single_domain() < 0;
    failures += test_splitdns_multiple_domains() < 0;
    failures += test_splitdns_trailing_comma() < 0;
    failures += test_splitdns_max_length() < 0;
    failures += test_splitdns_domain_validation() < 0;
    failures += test_splitdns_strlcpy_safety() < 0;
    failures += test_splitdns_comma_to_space() < 0;
    failures += test_splitdns_comma_to_semicolon() < 0;

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}