// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for misc.c — close_on_exec() and timedelta()
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

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}