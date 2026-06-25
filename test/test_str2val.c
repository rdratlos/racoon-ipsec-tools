// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for str2val (hex string <-> binary conversion)
 *
 * File: test/test_str2val.c
 * Coverage: str2val(), val2str()
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "str2val.h"
#include "gcmalloc.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* Test str2val: hex string -> binary */
int test_str2val_basic()
{
    size_t len;
    char *result;

    TEST_START("str2val basic hex conversion");

    result = str2val("deadbeef", 16, &len);
    if (!result) TEST_FAIL("str2val returned NULL");
    if (len != 4) TEST_FAIL("expected length 4");
    if (result[0] != (char)0xde || result[1] != (char)0xad ||
        result[2] != (char)0xbe || result[3] != (char)0xef)
        TEST_FAIL("byte values mismatch");

    racoon_free(result);
    TEST_PASS();
    return 0;
}

/* Test str2val with spaces interspersed */
int test_str2val_with_spaces()
{
    size_t len;
    char *result;

    TEST_START("str2val with spaces");

    result = str2val("de ad be ef", 16, &len);
    if (!result) TEST_FAIL("str2val returned NULL");
    if (len != 4) TEST_FAIL("expected length 4");
    if (result[0] != (char)0xde || result[1] != (char)0xad ||
        result[2] != (char)0xbe || result[3] != (char)0xef)
        TEST_FAIL("byte values mismatch");

    racoon_free(result);
    TEST_PASS();
    return 0;
}

/* Test str2val with uppercase hex */
int test_str2val_uppercase()
{
    size_t len;
    char *result;

    TEST_START("str2val uppercase hex");

    result = str2val("DEADBEEF", 16, &len);
    if (!result) TEST_FAIL("str2val returned NULL");
    if (len != 4) TEST_FAIL("expected length 4");
    if (result[0] != (char)0xde || result[1] != (char)0xad ||
        result[2] != (char)0xbe || result[3] != (char)0xef)
        TEST_FAIL("byte values mismatch");

    racoon_free(result);
    TEST_PASS();
    return 0;
}

/* Test str2val with empty string -> should fail */
int test_str2val_empty()
{
    size_t len;
    char *result;

    TEST_START("str2val empty string returns NULL");

    result = str2val("", 16, &len);
    if (result != NULL) TEST_FAIL("expected NULL for empty string");

    TEST_PASS();
    return 0;
}

/* Test str2val with odd number of hex digits -> should fail */
int test_str2val_odd_digits()
{
    size_t len;
    char *result;

    TEST_START("str2val odd hex digits returns NULL");

    result = str2val("deadb", 16, &len);
    if (result != NULL) TEST_FAIL("expected NULL for odd hex digits");

    TEST_PASS();
    return 0;
}

/* Test str2val with invalid characters -> should fail */
int test_str2val_invalid_chars()
{
    size_t len;
    char *result;

    TEST_START("str2val invalid characters returns NULL");

    result = str2val("deXGbeef", 16, &len);
    if (result != NULL) TEST_FAIL("expected NULL for invalid characters");

    TEST_PASS();
    return 0;
}

/* Test str2val with single byte */
int test_str2val_single_byte()
{
    size_t len;
    char *result;

    TEST_START("str2val single byte");

    result = str2val("ff", 16, &len);
    if (!result) TEST_FAIL("str2val returned NULL");
    if (len != 1) TEST_FAIL("expected length 1");
    if (result[0] != (char)0xff)
        TEST_FAIL("byte value mismatch");

    racoon_free(result);
    TEST_PASS();
    return 0;
}

/* Test str2val with zeros */
int test_str2val_zeros()
{
    size_t len;
    char *result;

    TEST_START("str2val zeros");

    result = str2val("00000000", 16, &len);
    if (!result) TEST_FAIL("str2val returned NULL");
    if (len != 4) TEST_FAIL("expected length 4");
    if (result[0] != 0 || result[1] != 0 || result[2] != 0 || result[3] != 0)
        TEST_FAIL("zero bytes mismatch");

    racoon_free(result);
    TEST_PASS();
    return 0;
}

/* Test val2str: binary -> hex string */
int test_val2str_basic()
{
    unsigned char data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    char *result;

    TEST_START("val2str basic conversion");

    result = val2str((const char *)data, sizeof(data));
    if (!result) TEST_FAIL("val2str returned NULL");
    if (strcmp(result, "deadbeef") != 0)
        TEST_FAIL("expected 'deadbeef'");

    racoon_free(result);
    TEST_PASS();
    return 0;
}

/* Test val2str with spaces every 8 bytes */
int test_val2str_with_spaces()
{
    unsigned char data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    char *result;

    TEST_START("val2str with space separators");

    result = val2str((const char *)data, sizeof(data));
    if (!result) TEST_FAIL("val2str returned NULL");
    /* val2str inserts a space after every 8th byte, including at the end */
    if (strcmp(result, "0102030405060708 090a0b0c0d0e0f10 ") != 0)
        TEST_FAIL("unexpected output");

    racoon_free(result);
    TEST_PASS();
    return 0;
}

/* Test val2str with empty buffer */
int test_val2str_empty()
{
    char *result;

    TEST_START("val2str empty buffer");

    result = val2str("", 0);
    if (!result) TEST_FAIL("val2str returned NULL");
    if (strcmp(result, "") != 0)
        TEST_FAIL("expected empty string");

    racoon_free(result);
    TEST_PASS();
    return 0;
}

    /* Test val2str roundtrip: str -> binary -> str (7 bytes, no space) */
int test_str2val_val2str_roundtrip()
{
    const char *input = "0123456789abcd";
    size_t len;
    char *binary, *output;

    TEST_START("str2val/val2str roundtrip");

    binary = str2val(input, 16, &len);
    if (!binary) TEST_FAIL("str2val failed");

    output = val2str(binary, len);
    racoon_free(binary);
    if (!output) TEST_FAIL("val2str failed");

    if (strcmp(output, input) != 0)
        TEST_FAIL("roundtrip mismatch");

    racoon_free(output);
    TEST_PASS();
    return 0;
}

/* Test val2str with mixed case in binary produces lowercase hex */
int test_val2str_lowercase()
{
    unsigned char data[] = { 0x00, 0x0F, 0xA0, 0xFF };
    char *result;

    TEST_START("val2str produces lowercase hex");

    result = val2str((const char *)data, sizeof(data));
    if (!result) TEST_FAIL("val2str returned NULL");
    if (strcmp(result, "000fa0ff") != 0)
        TEST_FAIL("expected lowercase hex");

    racoon_free(result);
    TEST_PASS();
    return 0;
}

int main(void)
{
    int failures = 0;

    printf("=== str2val unit tests ===\n");

    failures += test_str2val_basic() < 0;
    failures += test_str2val_with_spaces() < 0;
    failures += test_str2val_uppercase() < 0;
    failures += test_str2val_empty() < 0;
    failures += test_str2val_odd_digits() < 0;
    failures += test_str2val_invalid_chars() < 0;
    failures += test_str2val_single_byte() < 0;
    failures += test_str2val_zeros() < 0;
    failures += test_val2str_basic() < 0;
    failures += test_val2str_with_spaces() < 0;
    failures += test_val2str_empty() < 0;
    failures += test_str2val_val2str_roundtrip() < 0;
    failures += test_val2str_lowercase() < 0;

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}
