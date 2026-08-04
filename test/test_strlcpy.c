// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for the strlcpy()/strlcat() fallbacks — src/racoon/missing/
 *
 * File: test/test_strlcpy.c
 * Coverage: src/racoon/missing/strlcpy.h, src/racoon/missing/strlcat.h
 *
 * Exercises whichever implementation the build is using: the platform's
 * native libc strlcpy()/strlcat() (HAVE_STRLCPY/HAVE_STRLCAT), or the
 * project's own fallback — the same headers misc.h, setkey.c and
 * openssl_compat.c include, so this is testing the real production code,
 * not a private copy.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "strlcpy.h"
#include "strlcat.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* ------------------------------------------------------------------ */
/* strlcpy unit tests                                                  */
/* ------------------------------------------------------------------ */

/*
 * strlcpy basic: copy fits exactly (dstsize == strlen(src) + 1).
 * dst must contain the full string, return value must be strlen(src).
 */
int test_strlcpy_exact_fit()
{
    char dst[6];
    size_t r;
    const char *src = "hello";

    TEST_START("strlcpy exact fit (dstsize == strlen(src)+1)");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, sizeof(dst));

    if (r != 5) {
        TEST_FAIL("return value must be strlen(src) == 5");
    }
    if (strcmp(dst, "hello") != 0) {
        TEST_FAIL("dst not equal to src");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: src shorter than dst — extra bytes must stay untouched.
 */
int test_strlcpy_short_src()
{
    char dst[16];
    size_t r;
    const char *src = "hi";

    TEST_START("strlcpy short src, extra bytes untouched");

    memset(dst, 0xAB, sizeof(dst));
    r = strlcpy(dst, src, sizeof(dst));

    if (r != 2) {
        TEST_FAIL("return value must be 2");
    }
    if (strcmp(dst, "hi") != 0) {
        TEST_FAIL("dst not equal to src");
    }
    if (dst[3] != (char)0xAB) {
        TEST_FAIL("byte after null terminator was overwritten");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: truncation — dstsize is one less than strlen(src) + 1.
 * dst must contain the first (dstsize-1) bytes, null-terminated.
 * Return value must be strlen(src) (full length, NOT truncated length).
 */
int test_strlcpy_truncate_one()
{
    char dst[5];
    size_t r;
    const char *src = "hello";

    TEST_START("strlcpy truncation (dstsize == strlen(src))");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, sizeof(dst));

    if (r != 5) {
        TEST_FAIL("return value must be strlen(src) == 5");
    }
    if (dst[4] != '\0') {
        TEST_FAIL("dst not null-terminated");
    }
    if (strncmp(dst, "hell", 4) != 0) {
        TEST_FAIL("dst should contain \"hell\"");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: aggressive truncation — dstsize much smaller than src.
 */
int test_strlcpy_heavy_truncate()
{
    char dst[3];
    size_t r;
    const char *src = "abcdefghij";

    TEST_START("strlcpy heavy truncation");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, sizeof(dst));

    if (r != 10) {
        TEST_FAIL("return value must be strlen(src) == 10");
    }
    if (strcmp(dst, "ab") != 0) {
        TEST_FAIL("dst should be \"ab\"");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: dstsize == 1 — only the null terminator fits.
 */
int test_strlcpy_one_byte()
{
    char dst[1];
    size_t r;
    const char *src = "nonempty";

    TEST_START("strlcpy dstsize == 1, only NUL fits");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, sizeof(dst));

    if (r != 8) {
        TEST_FAIL("return value must be strlen(src) == 8");
    }
    if (dst[0] != '\0') {
        TEST_FAIL("dst[0] must be NUL");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: dstsize == 0 — nothing can be written.
 */
int test_strlcpy_zero_size()
{
    char dst[8];
    size_t r;
    const char *src = "test";

    TEST_START("strlcpy dstsize == 0, no write");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, 0);

    if (r != 4) {
        TEST_FAIL("return value must be strlen(src) == 4");
    }
    if (dst[0] != (char)0xFF) {
        TEST_FAIL("dst must not be modified when dstsize == 0");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: empty source string.
 */
int test_strlcpy_empty_src()
{
    char dst[8];
    size_t r;
    const char *src = "";

    TEST_START("strlcpy empty source");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, sizeof(dst));

    if (r != 0) {
        TEST_FAIL("return value must be 0");
    }
    if (dst[0] != '\0') {
        TEST_FAIL("dst[0] must be NUL");
    }
    if (dst[1] != (char)0xFF) {
        TEST_FAIL("byte after NUL must be untouched");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: empty source with zero-size dst.
 */
int test_strlcpy_empty_src_zero_dst()
{
    char dst[4];
    size_t r;
    const char *src = "";

    TEST_START("strlcpy empty source, dstsize == 0");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, 0);

    if (r != 0) {
        TEST_FAIL("return value must be 0");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: single-char source, fits exactly.
 */
int test_strlcpy_single_char()
{
    char dst[2];
    size_t r;
    const char *src = "x";

    TEST_START("strlcpy single character, exact fit");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, sizeof(dst));

    if (r != 1) {
        TEST_FAIL("return value must be 1");
    }
    if (strcmp(dst, "x") != 0) {
        TEST_FAIL("dst should be \"x\"");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: single-char source, truncated to zero data bytes.
 */
int test_strlcpy_single_char_truncated()
{
    char dst[1];
    size_t r;
    const char *src = "x";

    TEST_START("strlcpy single char, dstsize == 1");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, sizeof(dst));

    if (r != 1) {
        TEST_FAIL("return value must be 1");
    }
    if (dst[0] != '\0') {
        TEST_FAIL("dst[0] must be NUL");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcpy: long string at boundary — verify truncation detection
 * via return value.
 */
int test_strlcpy_return_value_detection()
{
    char dst[4];
    size_t r;
    const char *src = "long string for testing";

    TEST_START("strlcpy return value indicates truncation");

    memset(dst, 0xFF, sizeof(dst));
    r = strlcpy(dst, src, sizeof(dst));

    if (r < sizeof(dst)) {
        TEST_FAIL("return value must be >= dstsize when truncation occurs");
    }
    if (strcmp(dst, "lon") != 0) {
        TEST_FAIL("dst should be \"lon\"");
    }

    TEST_PASS();
    return 0;
}

/* ------------------------------------------------------------------ */
/* strlcat unit tests                                                  */
/* ------------------------------------------------------------------ */

/*
 * strlcat basic: dst + src fit exactly within dstsize.
 */
int test_strlcat_exact_fit()
{
    char dst[7] = "foo";
    size_t r;

    TEST_START("strlcat exact fit (dstsize == combined length + 1)");

    r = strlcat(dst, "bar", sizeof(dst));

    if (r != 6) {
        TEST_FAIL("return value must be strlen(\"foobar\") == 6");
    }
    if (strcmp(dst, "foobar") != 0) {
        TEST_FAIL("dst should be \"foobar\"");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcat: plenty of room left over — extra bytes beyond the new
 * terminator must stay untouched.
 */
int test_strlcat_short_src()
{
    char dst[16];
    size_t r;

    TEST_START("strlcat short src, extra bytes untouched");

    memset(dst, 0xAB, sizeof(dst));
    strcpy(dst, "hi");
    r = strlcat(dst, "!", sizeof(dst));

    if (r != 3) {
        TEST_FAIL("return value must be 3");
    }
    if (strcmp(dst, "hi!") != 0) {
        TEST_FAIL("dst should be \"hi!\"");
    }
    if (dst[4] != (char)0xAB) {
        TEST_FAIL("byte after null terminator was overwritten");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcat: truncation — dstsize is one less than the combined length + 1.
 * Return value must be the full desired length, not the truncated length.
 */
int test_strlcat_truncate_one()
{
    char dst[5] = "hel";
    size_t r;

    TEST_START("strlcat truncation (dstsize == combined length)");

    r = strlcat(dst, "lo", sizeof(dst));

    if (r != 5) {
        TEST_FAIL("return value must be strlen(\"hello\") == 5");
    }
    if (dst[sizeof(dst) - 1] != '\0') {
        TEST_FAIL("dst not null-terminated within bounds");
    }
    if (strcmp(dst, "hell") != 0) {
        TEST_FAIL("dst should be \"hell\"");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcat: dst is already full (no NUL within the first dstsize bytes).
 * This is exactly the case the old `strncat(d,s,(l)-strlen(d)-1)` macro
 * got wrong: strlen(d) >= l underflowed the computed bound. The real
 * implementation must still return the correct desired length and must
 * not write past dst[dstsize-1].
 */
int test_strlcat_dst_already_full()
{
    char dst[4];
    size_t r;

    TEST_START("strlcat dst already full, no room to append");

    memset(dst, 'x', sizeof(dst)); /* no NUL within dst at all */
    r = strlcat(dst, "tail", sizeof(dst));

    if (r != sizeof(dst) + 4) {
        TEST_FAIL("return value must be dstsize + strlen(src)");
    }
    if (dst[sizeof(dst) - 1] != 'x') {
        TEST_FAIL("dst must be left untouched when already full");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcat: empty src appended to a non-empty dst is a no-op.
 */
int test_strlcat_empty_src()
{
    char dst[8] = "abc";
    size_t r;

    TEST_START("strlcat empty source");

    r = strlcat(dst, "", sizeof(dst));

    if (r != 3) {
        TEST_FAIL("return value must be 3");
    }
    if (strcmp(dst, "abc") != 0) {
        TEST_FAIL("dst should be unchanged \"abc\"");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcat: appending to an empty dst behaves like strlcpy.
 */
int test_strlcat_empty_dst()
{
    char dst[8] = "";
    size_t r;

    TEST_START("strlcat onto empty dst");

    r = strlcat(dst, "xyz", sizeof(dst));

    if (r != 3) {
        TEST_FAIL("return value must be 3");
    }
    if (strcmp(dst, "xyz") != 0) {
        TEST_FAIL("dst should be \"xyz\"");
    }

    TEST_PASS();
    return 0;
}

/*
 * strlcat: dstsize == 0 must not touch dst at all, even though dst is
 * not (and need not be) NUL-terminated within bounds.
 */
int test_strlcat_zero_size()
{
    char dst[4];
    size_t r;

    TEST_START("strlcat dstsize == 0, no write");

    memset(dst, 'y', sizeof(dst));
    r = strlcat(dst, "abc", 0);

    if (r != 3) {
        TEST_FAIL("return value must be strlen(src) == 3");
    }
    if (dst[0] != 'y') {
        TEST_FAIL("dst must not be modified when dstsize == 0");
    }

    TEST_PASS();
    return 0;
}

int main(void)
{
    int failures = 0;

    printf("=== strlcpy/strlcat fallback unit tests ===\n");

    failures += test_strlcpy_exact_fit() < 0;
    failures += test_strlcpy_short_src() < 0;
    failures += test_strlcpy_truncate_one() < 0;
    failures += test_strlcpy_heavy_truncate() < 0;
    failures += test_strlcpy_one_byte() < 0;
    failures += test_strlcpy_zero_size() < 0;
    failures += test_strlcpy_empty_src() < 0;
    failures += test_strlcpy_empty_src_zero_dst() < 0;
    failures += test_strlcpy_single_char() < 0;
    failures += test_strlcpy_single_char_truncated() < 0;
    failures += test_strlcpy_return_value_detection() < 0;

    failures += test_strlcat_exact_fit() < 0;
    failures += test_strlcat_short_src() < 0;
    failures += test_strlcat_truncate_one() < 0;
    failures += test_strlcat_dst_already_full() < 0;
    failures += test_strlcat_empty_src() < 0;
    failures += test_strlcat_empty_dst() < 0;
    failures += test_strlcat_zero_size() < 0;

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}
