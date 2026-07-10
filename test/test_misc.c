// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for misc.c — close_on_exec(), timedelta(), and strlcpy()
 *
 * File: test/test_misc.c
 * Coverage: src/racoon/misc.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <math.h>
#include <sys/param.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gnuc.h"

/*
 * close_on_exec() and timedelta() are declared with K&R style in misc.h
 * but we need them here.  misc_noplog.o already provides them.
 */
extern void close_on_exec __P((int fd));
extern double timedelta __P((struct timeval *t1, struct timeval *t2));

/*
 * Bring in strlcpy so the tests exercise whichever implementation the
 * build is using: the platform's native libc strlcpy (HAVE_STRLCPY) or
 * the project's own fallback from misc.h.  This is the same
 * implementation as in misc.h, duplicated here because misc.h pulls in
 * libpfkey.h and plog infrastructure that the test binary does not link.
 */
#ifndef HAVE_STRLCPY
static size_t __attribute__((noinline))
strlcpy(char *dst, const char *src, size_t siz)
{
    register char *d = dst;
    const register char *s = src;
    size_t n = siz;

    if (n != 0) {
        while (--n != 0) {
            if ((*d++ = *s++) == '\0')
                return s - src - 1;
        }
    }

    if (n == 0 && siz)
        *d = '\0';
    return s - src + strlen(s);
}
#endif

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/*
 * Test close_on_exec: create a pipe, apply close-on-exec, then verify
 * the FD_CLOEXEC flag is set via fcntl(F_GETFD).
 */
int test_close_on_exec_basic()
{
    int pipefd[2];
    int fdflags;

    TEST_START("close_on_exec sets FD_CLOEXEC");

    if (pipe(pipefd) < 0) {
        TEST_FAIL("pipe() failed");
    }

    close_on_exec(pipefd[0]);

    fdflags = fcntl(pipefd[0], F_GETFD);
    if (fdflags < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        TEST_FAIL("fcntl(F_GETFD) failed");
    }

    if (!(fdflags & FD_CLOEXEC)) {
        close(pipefd[0]);
        close(pipefd[1]);
        TEST_FAIL("FD_CLOEXEC not set");
    }

    close(pipefd[0]);
    close(pipefd[1]);
    TEST_PASS();
    return 0;
}

/*
 * Test close_on_exec on both ends of a pipe.
 */
int test_close_on_exec_both_ends()
{
    int pipefd[2];
    int flags0, flags1;

    TEST_START("close_on_exec on both pipe ends");

    if (pipe(pipefd) < 0) {
        TEST_FAIL("pipe() failed");
    }

    close_on_exec(pipefd[0]);
    close_on_exec(pipefd[1]);

    flags0 = fcntl(pipefd[0], F_GETFD);
    flags1 = fcntl(pipefd[1], F_GETFD);

    if (flags0 < 0 || flags1 < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        TEST_FAIL("fcntl(F_GETFD) failed");
    }

    if (!(flags0 & FD_CLOEXEC) || !(flags1 & FD_CLOEXEC)) {
        close(pipefd[0]);
        close(pipefd[1]);
        TEST_FAIL("FD_CLOEXEC not set on both ends");
    }

    close(pipefd[0]);
    close(pipefd[1]);
    TEST_PASS();
    return 0;
}

/*
 * Test timedelta: t2 > t1, no microsecond borrow needed.
 * t1 = (0, 0), t2 = (5, 0) => delta = 5.0
 */
int test_timedelta_simple()
{
    struct timeval t1, t2;
    double result;

    TEST_START("timedelta simple (no borrow)");

    memset(&t1, 0, sizeof(t1));
    memset(&t2, 0, sizeof(t2));
    t2.tv_sec = 5;

    result = timedelta(&t1, &t2);

    if (result != 5.0) {
        TEST_FAIL("expected 5.0");
    }

    TEST_PASS();
    return 0;
}

/*
 * Test timedelta: t2 > t1, with microsecond borrow.
 * t1 = (0, 500000), t2 = (5, 200000)
 * Borrow: 5 - 0 - 1 = 4, microsecond part = 1000000 + 200000 - 500000 = 700000
 * => 4.7
 */
int test_timedelta_borrow()
{
    struct timeval t1, t2;
    double result;

    TEST_START("timedelta with microsecond borrow");

    memset(&t1, 0, sizeof(t1));
    t1.tv_usec = 500000;

    memset(&t2, 0, sizeof(t2));
    t2.tv_sec = 5;
    t2.tv_usec = 200000;

    result = timedelta(&t1, &t2);

    if (fabs(result - 4.7) > 0.0001) {
        TEST_FAIL("expected 4.7");
    }

    TEST_PASS();
    return 0;
}

/*
 * Test timedelta: same times.
 * t1 = t2 => delta = 0.0
 */
int test_timedelta_zero()
{
    struct timeval t1, t2;
    double result;

    TEST_START("timedelta same times");

    t1.tv_sec = 100;
    t1.tv_usec = 5000;
    t2.tv_sec = 100;
    t2.tv_usec = 5000;

    result = timedelta(&t1, &t2);

    if (result != 0.0) {
        TEST_FAIL("expected 0.0");
    }

    TEST_PASS();
    return 0;
}

/*
 * Test timedelta: same seconds, t2.usec > t1.usec.
 * t1 = (10, 100000), t2 = (10, 400000) => 0.3
 */
int test_timedelta_us_only()
{
    struct timeval t1, t2;
    double result;

    TEST_START("timedelta microsecond difference only");

    t1.tv_sec = 10;
    t1.tv_usec = 100000;
    t2.tv_sec = 10;
    t2.tv_usec = 400000;

    result = timedelta(&t1, &t2);

    if (fabs(result - 0.3) > 0.0001) {
        TEST_FAIL("expected 0.3");
    }

    TEST_PASS();
    return 0;
}

/*
 * Test timedelta: large values.
 * t1 = (0, 0), t2 = (1000000, 500000) => 1000000.5
 */
int test_timedelta_large()
{
    struct timeval t1, t2;
    double result;

    TEST_START("timedelta large value");

    memset(&t1, 0, sizeof(t1));
    t2.tv_sec = 1000000;
    t2.tv_usec = 500000;

    result = timedelta(&t1, &t2);

    if (result != 1000000.5) {
        TEST_FAIL("expected 1000000.5");
    }

    TEST_PASS();
    return 0;
}

/*
 * Test timedelta: same seconds, t2.usec < t1.usec (pure borrow).
 * t1 = (100, 900000), t2 = (100, 100000)
 * Borrow: 100 - 100 - 1 = -1, microsecond = 1000000 + 100000 - 900000 = 200000
 * => -1 + 0.2 = -0.8
 */
int test_timedelta_negative()
{
    struct timeval t1, t2;
    double result;

    TEST_START("timedelta negative result");

    t1.tv_sec = 100;
    t1.tv_usec = 900000;
    t2.tv_sec = 100;
    t2.tv_usec = 100000;

    result = timedelta(&t1, &t2);

    if (fabs(result - (-0.8)) > 0.0001) {
        TEST_FAIL("expected -0.8");
    }

    TEST_PASS();
    return 0;
}

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

int main(void)
{
    int failures = 0;

    printf("=== misc.c unit tests ===\n");

    failures += test_close_on_exec_basic() < 0;
    failures += test_close_on_exec_both_ends() < 0;
    failures += test_timedelta_simple() < 0;
    failures += test_timedelta_borrow() < 0;
    failures += test_timedelta_zero() < 0;
    failures += test_timedelta_us_only() < 0;
    failures += test_timedelta_large() < 0;
    failures += test_timedelta_negative() < 0;
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

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}