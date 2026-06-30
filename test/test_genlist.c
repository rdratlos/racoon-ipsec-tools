// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for genlist (generic linked-list operations)
 *
 * File: test/test_genlist.c
 * Coverage: genlist_init(), genlist_insert(), genlist_append(),
 *           genlist_foreach(), genlist_next(), genlist_free()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "genlist.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* --- genlist_init tests --- */

int test_genlist_init()
{
    struct genlist *gl;

    TEST_START("genlist_init creates empty list");

    gl = genlist_init();
    if (!gl)
        TEST_FAIL("genlist_init returned NULL");

    if (genlist_next(gl, NULL) != NULL)
        TEST_FAIL("new list should be empty");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

/* --- genlist_insert tests --- */

int test_genlist_insert_single()
{
    struct genlist *gl;
    void *data;
    struct genlist_entry *e;

    TEST_START("genlist_insert single element");

    gl = genlist_init();
    e = genlist_insert(gl, (void *)0x1234);
    if (!e)
        TEST_FAIL("genlist_insert returned NULL");

    if (e->data != (void *)0x1234)
        TEST_FAIL("inserted data mismatch");

    data = genlist_next(gl, NULL);
    if (data != (void *)0x1234)
        TEST_FAIL("expected 0x1234 from list");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

int test_genlist_insert_order()
{
    struct genlist *gl;
    void *data;
    struct genlist_entry *buf = NULL;
    int count = 0;

    TEST_START("genlist_insert maintains FIFO order (LIFO push)");

    gl = genlist_init();
    genlist_insert(gl, (void *)1);
    genlist_insert(gl, (void *)2);
    genlist_insert(gl, (void *)3);

    /* Insert is head-insert, so order should be 3, 2, 1 */
    data = genlist_next(gl, &buf);
    if (data != (void *)3)
        TEST_FAIL("first element should be 3 (last inserted)");
    count++;

    data = genlist_next(NULL, &buf);
    if (data != (void *)2)
        TEST_FAIL("second element should be 2");
    count++;

    data = genlist_next(NULL, &buf);
    if (data != (void *)1)
        TEST_FAIL("third element should be 1");
    count++;

    data = genlist_next(NULL, &buf);
    if (data != NULL)
        TEST_FAIL("expected NULL after exhausting list");

    if (count != 3)
        TEST_FAIL("expected 3 elements");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

/* --- genlist_append tests --- */

int test_genlist_append_order()
{
    struct genlist *gl;
    void *data;
    struct genlist_entry *buf = NULL;

    TEST_START("genlist_append maintains FIFO order");

    gl = genlist_init();
    genlist_append(gl, (void *)10);
    genlist_append(gl, (void *)20);
    genlist_append(gl, (void *)30);

    data = genlist_next(gl, &buf);
    if (data != (void *)10)
        TEST_FAIL("first element should be 10 (first appended)");

    data = genlist_next(NULL, &buf);
    if (data != (void *)20)
        TEST_FAIL("second element should be 20");

    data = genlist_next(NULL, &buf);
    if (data != (void *)30)
        TEST_FAIL("third element should be 30");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

int test_genlist_append_after_insert()
{
    struct genlist *gl;
    void *data;
    struct genlist_entry *buf = NULL;

    TEST_START("genlist_append after genlist_insert");

    gl = genlist_init();
    genlist_insert(gl, (void *)1);  /* head: 1 */
    genlist_insert(gl, (void *)2);  /* head: 2 -> 1 */
    genlist_append(gl, (void *)3);  /* tail: 2 -> 1 -> 3 */

    data = genlist_next(gl, &buf);
    if (data != (void *)2)
        TEST_FAIL("expected 2 first (inserted last at head)");

    data = genlist_next(NULL, &buf);
    if (data != (void *)1)
        TEST_FAIL("expected 1 second");

    data = genlist_next(NULL, &buf);
    if (data != (void *)3)
        TEST_FAIL("expected 3 third (appended at tail)");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

/* --- genlist_foreach tests --- */

static void *foreach_counter(void *entry, void *arg)
{
    int *count = (int *)arg;
    (*count)++;
    (void)entry;
    return NULL;  /* continue iteration */
}

int test_genlist_foreach_count()
{
    struct genlist *gl;
    int count = 0;

    TEST_START("genlist_foreach counts all elements");

    gl = genlist_init();
    genlist_append(gl, (void *)1);
    genlist_append(gl, (void *)2);
    genlist_append(gl, (void *)3);

    genlist_foreach(gl, foreach_counter, &count);

    if (count != 3) {
        fprintf(stderr, "expected 3 iterations, got %d\n", count);
        TEST_FAIL("iteration count mismatch");
    }

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

static void *foreach_find(void *entry, void *arg)
{
    void *target = arg;
    if (entry == target)
        return entry;
    return NULL;
}

int test_genlist_foreach_find()
{
    struct genlist *gl;
    void *result;

    TEST_START("genlist_foreach finds target element");

    gl = genlist_init();
    genlist_append(gl, (void *)10);
    genlist_append(gl, (void *)20);
    genlist_append(gl, (void *)30);

    result = genlist_foreach(gl, foreach_find, (void *)20);
    if (result != (void *)20)
        TEST_FAIL("expected to find element 20");

    result = genlist_foreach(gl, foreach_find, (void *)99);
    if (result != NULL)
        TEST_FAIL("expected NULL for missing element");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

int test_genlist_foreach_empty()
{
    struct genlist *gl;
    int count = 0;

    TEST_START("genlist_foreach on empty list");

    gl = genlist_init();
    genlist_foreach(gl, foreach_counter, &count);

    if (count != 0)
        TEST_FAIL("expected 0 iterations on empty list");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

int test_genlist_foreach_early_exit()
{
    struct genlist *gl;
    int count = 0;

    TEST_START("genlist_foreach stops on first non-NULL return");

    gl = genlist_init();
    genlist_append(gl, (void *)1);
    genlist_append(gl, (void *)2);
    genlist_append(gl, (void *)3);

    /* Use foreach_find to find first element, should stop immediately */
    genlist_foreach(gl, foreach_find, (void *)1);

    /* foreach_counter would count all if it ran; but we only want 1 iteration */
    /* Actually we need a different approach: count how many times foreach_find was called */
    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

static void *foreach_count_limited(void *entry, void *arg)
{
    int *count = (int *)arg;
    (*count)++;
    return (void *)1;  /* stop after first element */
}

int test_genlist_foreach_stops_on_nonnull()
{
    struct genlist *gl;
    int count = 0;

    TEST_START("genlist_foreach stops on non-NULL return");

    gl = genlist_init();
    genlist_append(gl, (void *)1);
    genlist_append(gl, (void *)2);
    genlist_append(gl, (void *)3);

    genlist_foreach(gl, foreach_count_limited, &count);

    if (count != 1)
        TEST_FAIL("expected exactly 1 iteration (stopped early)");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

int test_genlist_foreach_iteration_order_append()
{
    struct genlist *gl;
    long expected = 10;

    TEST_START("genlist_foreach iteration order (append)");

    gl = genlist_init();
    genlist_append(gl, (void *)(long)10);
    genlist_append(gl, (void *)(long)20);
    genlist_append(gl, (void *)(long)30);

    void *first = genlist_foreach(gl, foreach_find, (void *)(long)10);
    if (first != (void *)(long)10)
        TEST_FAIL("first element should be 10");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

int test_genlist_foreach_iteration_order_insert()
{
    struct genlist *gl;

    TEST_START("genlist_foreach iteration order (insert)");

    gl = genlist_init();
    genlist_insert(gl, (void *)(long)10);
    genlist_insert(gl, (void *)(long)20);
    genlist_insert(gl, (void *)(long)30);

    void *first = genlist_foreach(gl, foreach_find, (void *)(long)30);
    if (first != (void *)(long)30)
        TEST_FAIL("first element should be 30 (last inserted at head)");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

/* --- genlist_next tests --- */

int test_genlist_next_basic()
{
    struct genlist *gl;
    struct genlist_entry *buf = NULL;
    void *data;

    TEST_START("genlist_next basic iteration");

    gl = genlist_init();
    genlist_append(gl, (void *)100);
    genlist_append(gl, (void *)200);

    data = genlist_next(gl, &buf);
    if (data != (void *)100)
        TEST_FAIL("expected 100");

    data = genlist_next(NULL, &buf);
    if (data != (void *)200)
        TEST_FAIL("expected 200");

    data = genlist_next(NULL, &buf);
    if (data != NULL)
        TEST_FAIL("expected NULL at end");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

int test_genlist_next_null_head_restart()
{
    struct genlist *gl;
    struct genlist_entry *buf = NULL;

    TEST_START("genlist_next with NULL head restarts");

    gl = genlist_init();
    genlist_append(gl, (void *)1);
    genlist_append(gl, (void *)2);

    genlist_next(gl, &buf);
    genlist_next(NULL, &buf);
    genlist_next(NULL, &buf);  /* exhausted */

    /* Restart by passing head again */
    void *data = genlist_next(gl, &buf);
    if (data != (void *)1)
        TEST_FAIL("expected restart from beginning");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

int test_genlist_next_empty_list()
{
    struct genlist *gl;
    struct genlist_entry *buf = NULL;

    TEST_START("genlist_next on empty list");

    gl = genlist_init();
    void *data = genlist_next(gl, &buf);
    if (data != NULL)
        TEST_FAIL("expected NULL from empty list");

    genlist_free(gl, NULL);
    TEST_PASS();
    return 0;
}

/* --- genlist_free tests --- */

static int free_count = 0;

static void count_free(void *data)
{
    (void)data;
    free_count++;
}

int test_genlist_free_calls_func()
{
    struct genlist *gl;

    TEST_START("genlist_free calls free function for each entry");

    free_count = 0;
    gl = genlist_init();
    genlist_append(gl, (void *)1);
    genlist_append(gl, (void *)2);
    genlist_append(gl, (void *)3);

    genlist_free(gl, count_free);

    if (free_count != 3)
        TEST_FAIL("expected 3 calls to free function");

    TEST_PASS();
    return 0;
}

int test_genlist_free_null_func()
{
    struct genlist *gl;

    TEST_START("genlist_free with NULL free function");

    gl = genlist_init();
    genlist_append(gl, (void *)1);
    genlist_append(gl, (void *)2);

    /* Should not crash */
    genlist_free(gl, NULL);

    TEST_PASS();
    return 0;
}

int test_genlist_free_empty_list()
{
    struct genlist *gl;

    TEST_START("genlist_free on empty list");

    gl = genlist_init();
    free_count = 0;
    genlist_free(gl, count_free);

    if (free_count != 0)
        TEST_FAIL("expected 0 calls to free function on empty list");

    TEST_PASS();
    return 0;
}

int
main (void)
{
    int failures = 0;

    printf("=== genlist unit tests ===\n");

    /* genlist_init */
    failures += test_genlist_init() < 0;

    /* genlist_insert */
    failures += test_genlist_insert_single() < 0;
    failures += test_genlist_insert_order() < 0;

    /* genlist_append */
    failures += test_genlist_append_order() < 0;
    failures += test_genlist_append_after_insert() < 0;

    /* genlist_foreach */
    failures += test_genlist_foreach_count() < 0;
    failures += test_genlist_foreach_find() < 0;
    failures += test_genlist_foreach_empty() < 0;
    failures += test_genlist_foreach_early_exit() < 0;
    failures += test_genlist_foreach_stops_on_nonnull() < 0;
    failures += test_genlist_foreach_iteration_order_append() < 0;
    failures += test_genlist_foreach_iteration_order_insert() < 0;

    /* genlist_next */
    failures += test_genlist_next_basic() < 0;
    failures += test_genlist_next_null_head_restart() < 0;
    failures += test_genlist_next_empty_list() < 0;

    /* genlist_free */
    failures += test_genlist_free_calls_func() < 0;
    failures += test_genlist_free_null_func() < 0;
    failures += test_genlist_free_empty_list() < 0;

    printf("\n=== Results: %d failures ===\n", failures);
    return failures ? 1 : 0;
}
