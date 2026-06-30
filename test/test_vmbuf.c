// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for vmbuf (virtual memory buffer)
 *
 * File: test/test_vmbuf.c
 * Coverage: vmalloc(), vrealloc(), vfree(), vdup()
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "vmbuf.h"
#include "gcmalloc.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* Test vmalloc with normal size */
int test_vmalloc_basic()
{
    vchar_t *v;

    TEST_START("vmalloc basic allocation");

    v = vmalloc(32);
    if (!v) TEST_FAIL("vmalloc returned NULL");
    if (v->l != 32) TEST_FAIL("expected length 32");
    if (!v->v) TEST_FAIL("data pointer is NULL");

    /* Verify zero-initialized */
    memset(v->v, 0xAB, 32);

    vfree(v);
    TEST_PASS();
    return 0;
}

/* Test vmalloc with size 0 */
int test_vmalloc_zero_size()
{
    vchar_t *v;

    TEST_START("vmalloc zero size");

    v = vmalloc(0);
    if (!v) TEST_FAIL("vmalloc returned NULL");
    if (v->l != 0) TEST_FAIL("expected length 0");
    if (v->v != NULL) TEST_FAIL("expected NULL data for zero length");

    vfree(v);
    TEST_PASS();
    return 0;
}

/* Test vmalloc and write/read data */
int test_vmalloc_write_read()
{
    vchar_t *v;
    const uint8_t pattern[] = { 0xDE, 0xAD, 0xBE, 0xEF };

    TEST_START("vmalloc write and read");

    v = vmalloc(4);
    if (!v) TEST_FAIL("vmalloc returned NULL");

    memcpy(v->v, pattern, 4);

    if (memcmp(v->v, pattern, 4) != 0)
        TEST_FAIL("data mismatch after write/read");

    vfree(v);
    TEST_PASS();
    return 0;
}

/* Test vrealloc growing */
int test_vrealloc_grow()
{
    vchar_t *v;

    TEST_START("vrealloc grow");

    v = vmalloc(4);
    if (!v) TEST_FAIL("vmalloc returned NULL");

    memset(v->v, 0xAA, 4);

    v = vrealloc(v, 16);
    if (!v) TEST_FAIL("vrealloc returned NULL");
    if (v->l != 16) TEST_FAIL("expected length 16");
    if ((unsigned char)v->v[0] != 0xAA || (unsigned char)v->v[1] != 0xAA ||
        (unsigned char)v->v[2] != 0xAA || (unsigned char)v->v[3] != 0xAA)
        TEST_FAIL("existing data lost after grow");

    vfree(v);
    TEST_PASS();
    return 0;
}

/* Test vrealloc shrinking */
int test_vrealloc_shrink()
{
    vchar_t *v;

    TEST_START("vrealloc shrink");

    v = vmalloc(16);
    if (!v) TEST_FAIL("vmalloc returned NULL");

    memset(v->v, 0xBB, 16);

    v = vrealloc(v, 4);
    if (!v) TEST_FAIL("vrealloc returned NULL");
    if (v->l != 4) TEST_FAIL("expected length 4");
    if ((unsigned char)v->v[0] != 0xBB || (unsigned char)v->v[1] != 0xBB ||
        (unsigned char)v->v[2] != 0xBB || (unsigned char)v->v[3] != 0xBB)
        TEST_FAIL("existing data lost after shrink");

    vfree(v);
    TEST_PASS();
    return 0;
}

/* Test vrealloc with NULL pointer (should behave like vmalloc) */
int test_vrealloc_null_ptr()
{
    vchar_t *v;

    TEST_START("vrealloc NULL pointer");

    v = vrealloc(NULL, 8);
    if (!v) TEST_FAIL("vrealloc returned NULL");
    if (v->l != 8) TEST_FAIL("expected length 8");
    if (!v->v) TEST_FAIL("data pointer is NULL");

    vfree(v);
    TEST_PASS();
    return 0;
}

/* Test vrealloc from zero-length to nonzero */
int test_vrealloc_zero_to_nonzero()
{
    vchar_t *v;

    TEST_START("vrealloc zero to nonzero");

    v = vmalloc(0);
    if (!v) TEST_FAIL("vmalloc returned NULL");

    v = vrealloc(v, 8);
    if (!v) TEST_FAIL("vrealloc returned NULL");
    if (v->l != 8) TEST_FAIL("expected length 8");
    if (!v->v) TEST_FAIL("data pointer is NULL");

    vfree(v);
    TEST_PASS();
    return 0;
}

/* Test vdup */
int test_vdup_basic()
{
    vchar_t *orig, *copy;
    const uint8_t data[] = { 0x11, 0x22, 0x33, 0x44, 0x55 };

    TEST_START("vdup basic");

    orig = vmalloc(5);
    if (!orig) TEST_FAIL("vmalloc returned NULL");
    memcpy(orig->v, data, 5);

    copy = vdup(orig);
    if (!copy) TEST_FAIL("vdup returned NULL");
    if (copy->l != 5) TEST_FAIL("expected length 5");
    if (memcmp(copy->v, data, 5) != 0)
        TEST_FAIL("copied data mismatch");
    if (copy->v == orig->v)
        TEST_FAIL("vdup did not allocate separate buffer");

    /* Modify copy, verify orig unchanged */
    memcpy(copy->v, "\xFF\xFF\xFF\xFF\xFF", 5);
    if (memcmp(orig->v, data, 5) != 0)
        TEST_FAIL("orig modified after copy changed");

    vfree(orig);
    vfree(copy);
    TEST_PASS();
    return 0;
}

/* Test vdup with zero-length buffer */
int test_vdup_zero_length()
{
    vchar_t *orig, *copy;

    TEST_START("vdup zero-length buffer");

    orig = vmalloc(0);
    if (!orig) TEST_FAIL("vmalloc returned NULL");

    copy = vdup(orig);
    if (!copy) TEST_FAIL("vdup returned NULL");
    if (copy->l != 0) TEST_FAIL("expected length 0");
    if (copy->v != NULL) TEST_FAIL("expected NULL data for zero length");

    vfree(orig);
    vfree(copy);
    TEST_PASS();
    return 0;
}

/* Test vdup with NULL -> should return NULL */
int test_vdup_null()
{
    vchar_t *copy;

    TEST_START("vdup NULL returns NULL");

    copy = vdup(NULL);
    if (copy != NULL)
        TEST_FAIL("expected NULL for vdup(NULL)");

    TEST_PASS();
    return 0;
}

/* Test vfree with NULL -> should not crash */
int test_vfree_null()
{
    TEST_START("vfree NULL");

    vfree(NULL);
    TEST_PASS();
    return 0;
}

/* Test vrealloc same size */
int test_vrealloc_same_size()
{
    vchar_t *v;

    TEST_START("vrealloc same size");

    v = vmalloc(8);
    if (!v) TEST_FAIL("vmalloc returned NULL");

    memset(v->v, 0xCC, 8);

    v = vrealloc(v, 8);
    if (!v) TEST_FAIL("vrealloc returned NULL");
    if (v->l != 8) TEST_FAIL("expected length 8");
    if ((unsigned char)v->v[0] != 0xCC || (unsigned char)v->v[7] != 0xCC)
        TEST_FAIL("data lost after same-size realloc");

    vfree(v);
    TEST_PASS();
    return 0;
}

int main(void)
{
    int failures = 0;

    printf("=== vmbuf unit tests ===\n");

    failures += test_vmalloc_basic() < 0;
    failures += test_vmalloc_zero_size() < 0;
    failures += test_vmalloc_write_read() < 0;
    failures += test_vrealloc_grow() < 0;
    failures += test_vrealloc_shrink() < 0;
    failures += test_vrealloc_null_ptr() < 0;
    failures += test_vrealloc_zero_to_nonzero() < 0;
    failures += test_vdup_basic() < 0;
    failures += test_vdup_zero_length() < 0;
    failures += test_vdup_null() < 0;
    failures += test_vfree_null() < 0;
    failures += test_vrealloc_same_size() < 0;

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}
