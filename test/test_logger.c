// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for the ring-buffer logger (src/racoon/logger.c)
 *
 * Provides code coverage for lcov so that logger.c is not excluded.
 *
 * File: test/test_logger.c
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

#include "logger.h"
#include "gcmalloc.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return 0; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/*
 * Create a predictable temp-file path under /tmp and return the
 * length of the string written into the caller-supplied buffer.
 */
static int
make_tmpfile(char *buf, size_t bufsz)
{
	int n;

	n = snprintf(buf, bufsz, "/tmp/test_logger_%u_%d",
		     (unsigned int)getpid(), (int)time(NULL));
	if (n < 0 || (size_t)n >= bufsz)
		return -1;
	/* Remove stale file so every test starts fresh */
	unlink(buf);
	return n;
}

/* Helper that wraps log_vaprint with a variadic interface */
static void
vaprint_helper(struct log *l, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_vaprint(l, fmt, ap);
	va_end(ap);
}

/* Read a file's contents into a heap-allocated buffer.  Returns length,
   or -1 on error.  Caller must free() *out. */
static long
read_file(const char *path, char **out)
{
	FILE *fp;
	long sz;
	char *buf;

	*out = NULL;
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return -1;
	}
	sz = ftell(fp);
	if (sz < 0) {
		fclose(fp);
		return -1;
	}
	rewind(fp);
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(fp);
		return -1;
	}
	if ((long)fread(buf, 1, (size_t)sz, fp) != sz) {
		free(buf);
		fclose(fp);
		return -1;
	}
	buf[sz] = '\0';
	fclose(fp);
	*out = buf;
	return sz;
}

/* ============================================================================
 * TEST 1: log_open() with valid size and NULL fname (no file I/O)
 * ============================================================================ */

int
test_log_open_null_fname(void)
{
	struct log *l;

	TEST_START("log_open with NULL fname");

	l = log_open(16, NULL);
	if (!l)
		TEST_FAIL("log_open returned NULL");
	if (l->siz != 16)
		TEST_FAIL("siz mismatch");
	if (l->head != 0)
		TEST_FAIL("head should be 0");
	if (!l->buf)
		TEST_FAIL("buf is NULL");
	if (!l->tbuf)
		TEST_FAIL("tbuf is NULL");
	if (l->fname != NULL)
		TEST_FAIL("fname should be NULL");

	log_free(l);
	TEST_PASS();
	return 1;
}

/* ============================================================================
 * TEST 2: log_open() with valid size and a real tmpfile path
 * ============================================================================ */

int
test_log_open_with_fname(void)
{
	char path[256];
	struct log *l;

	TEST_START("log_open with real fname");

	if (make_tmpfile(path, sizeof(path)) < 0)
		TEST_FAIL("make_tmpfile failed");

	l = log_open(8, path);
	if (!l)
		TEST_FAIL("log_open returned NULL");
	if (l->siz != 8)
		TEST_FAIL("siz mismatch");
	if (!l->fname || strcmp(l->fname, path) != 0)
		TEST_FAIL("fname mismatch");

	log_free(l);
	unlink(path);
	TEST_PASS();
	return 1;
}

/* ============================================================================
 * TEST 3: log_add() fills ring buffer up to capacity without overflow
 * ============================================================================ */

int
test_log_add_fill_capacity(void)
{
	struct log *l;
	int i;

	TEST_START("log_add fills to capacity");

	l = log_open(5, NULL);
	if (!l)
		TEST_FAIL("log_open failed");

	for (i = 0; i < 5; i++) {
		char s[32];
		snprintf(s, sizeof(s), "entry%d", i);
		log_add(l, s);
	}

	if (l->head != 0)
		TEST_FAIL("head should wrap to 0 after filling buffer");

	/* Every slot should be non-NULL */
	for (i = 0; i < 5; i++) {
		if (!l->buf[i]) {
			fprintf(stderr, "  buf[%d] is NULL\n", i);
			TEST_FAIL("slot not filled");
		}
		if (l->tbuf[i] == 0)
			TEST_FAIL("tbuf slot is 0");
	}

	log_free(l);
	TEST_PASS();
	return 1;
}

/* ============================================================================
 * TEST 4: log_add() wraps around correctly (ring semantics)
 * ============================================================================ */

int
test_log_add_wraparound(void)
{
	struct log *l;
	int i;

	TEST_START("log_add ring wraparound");

	/* Buffer of size 3; add 5 entries.
	   Step by step:
	     add entry0 -> buf[0]="entry0", head=1
	     add entry1 -> buf[1]="entry1", head=2
	     add entry2 -> buf[2]="entry2", head=0
	     add entry3 -> buf[0]="entry3", head=1   (overwrites entry0)
	     add entry4 -> buf[1]="entry4", head=2   (overwrites entry1)
	   Final state: head=2, buf[0]="entry3", buf[1]="entry4", buf[2]="entry2" */
	l = log_open(3, NULL);
	if (!l)
		TEST_FAIL("log_open failed");

	for (i = 0; i < 5; i++) {
		char s[32];
		snprintf(s, sizeof(s), "entry%d", i);
		log_add(l, s);
	}

	if (l->head != 2)
		TEST_FAIL("head should be 2 after 5 adds into size-3 buffer");

	if (strcmp(l->buf[0], "entry3") != 0)
		TEST_FAIL("buf[0] should hold entry3");
	if (strcmp(l->buf[1], "entry4") != 0)
		TEST_FAIL("buf[1] should hold entry4");
	if (strcmp(l->buf[2], "entry2") != 0)
		TEST_FAIL("buf[2] should hold entry2");

	log_free(l);
	TEST_PASS();
	return 1;
}

/* ============================================================================
 * TEST 5: log_print() writes a string to the log file
 * ============================================================================ */

int
test_log_print(void)
{
	char path[256];
	struct log *l;
	char *contents;
	long sz;

	TEST_START("log_print writes to file");

	if (make_tmpfile(path, sizeof(path)) < 0)
		TEST_FAIL("make_tmpfile failed");

	l = log_open(4, path);
	if (!l)
		TEST_FAIL("log_open failed");

	if (log_print(l, "hello world\n") != 0) {
		log_free(l);
		TEST_FAIL("log_print returned non-zero");
	}

	sz = read_file(path, &contents);
	if (sz < 0 || !contents) {
		log_free(l);
		TEST_FAIL("could not read back file");
	}
	if (strstr(contents, "hello world") == NULL) {
		fprintf(stderr, "  file contents: %s\n", contents);
		free(contents);
		log_free(l);
		TEST_FAIL("expected string not found in file");
	}

	free(contents);
	log_free(l);
	unlink(path);
	TEST_PASS();
	return 1;
}

/* ============================================================================
 * TEST 6: log_vprint() writes a formatted string to the log file
 * ============================================================================ */

int
test_log_vprint(void)
{
	char path[256];
	struct log *l;
	char *contents;
	long sz;

	TEST_START("log_vprint formatted output");

	if (make_tmpfile(path, sizeof(path)) < 0)
		TEST_FAIL("make_tmpfile failed");

	l = log_open(4, path);
	if (!l)
		TEST_FAIL("log_open failed");

	if (log_vprint(l, "value=%d name=%s\n", 42, "logger") != 0) {
		log_free(l);
		TEST_FAIL("log_vprint returned non-zero");
	}

	sz = read_file(path, &contents);
	if (sz < 0 || !contents) {
		log_free(l);
		TEST_FAIL("could not read back file");
	}
	if (strstr(contents, "value=42") == NULL ||
	    strstr(contents, "name=logger") == NULL) {
		fprintf(stderr, "  file contents: %s\n", contents);
		free(contents);
		log_free(l);
		TEST_FAIL("formatted string not found in file");
	}

	free(contents);
	log_free(l);
	unlink(path);
	TEST_PASS();
	return 1;
}

/* ============================================================================
 * TEST 7: log_vaprint() writes via va_list
 * ============================================================================ */

int
test_log_vaprint(void)
{
	char path[256];
	struct log *l;
	char *contents;
	long sz;

	TEST_START("log_vaprint with va_list");

	if (make_tmpfile(path, sizeof(path)) < 0)
		TEST_FAIL("make_tmpfile failed");

	l = log_open(4, path);
	if (!l)
		TEST_FAIL("log_open failed");

	vaprint_helper(l, "va=%s num=%d\n", "test", 99);

	sz = read_file(path, &contents);
	if (sz < 0 || !contents) {
		log_free(l);
		TEST_FAIL("could not read back file");
	}
	if (strstr(contents, "va=test") == NULL ||
	    strstr(contents, "num=99") == NULL) {
		fprintf(stderr, "  file contents: %s\n", contents);
		free(contents);
		log_free(l);
		TEST_FAIL("vaprint output not found in file");
	}

	free(contents);
	log_free(l);
	unlink(path);
	TEST_PASS();
	return 1;
}

/* ============================================================================
 * TEST 8: log_close() flushes ring buffer with timestamps
 * ============================================================================ */

int
test_log_close_flush(void)
{
	char path[256];
	struct log *l;
	char *contents;
	long sz;

	TEST_START("log_close flushes ring buffer with timestamps");

	if (make_tmpfile(path, sizeof(path)) < 0)
		TEST_FAIL("make_tmpfile failed");

	l = log_open(3, path);
	if (!l)
		TEST_FAIL("log_open failed");

	log_add(l, "first line");
	log_add(l, "second line");
	log_add(l, "third line");

	log_close(l);

	sz = read_file(path, &contents);
	if (sz < 0 || !contents || sz == 0) {
		if (contents) free(contents);
		TEST_FAIL("file is empty after log_close");
	}

	/* All three entries should appear in the file */
	if (strstr(contents, "first line") == NULL) {
		fprintf(stderr, "  file contents: %s\n", contents);
		free(contents);
		TEST_FAIL("missing 'first line'");
	}
	if (strstr(contents, "second line") == NULL) {
		fprintf(stderr, "  file contents: %s\n", contents);
		free(contents);
		TEST_FAIL("missing 'second line'");
	}
	if (strstr(contents, "third line") == NULL) {
		fprintf(stderr, "  file contents: %s\n", contents);
		free(contents);
		TEST_FAIL("missing 'third line'");
	}

	/* Verify a timestamp was written (strftime produces month name) */
	if (strstr(contents, "January") == NULL &&
	    strstr(contents, "February") == NULL &&
	    strstr(contents, "March") == NULL &&
	    strstr(contents, "April") == NULL &&
	    strstr(contents, "May") == NULL &&
	    strstr(contents, "June") == NULL &&
	    strstr(contents, "July") == NULL &&
	    strstr(contents, "August") == NULL &&
	    strstr(contents, "September") == NULL &&
	    strstr(contents, "October") == NULL &&
	    strstr(contents, "November") == NULL &&
	    strstr(contents, "December") == NULL) {
		fprintf(stderr, "  file contents: %s\n", contents);
		free(contents);
		TEST_FAIL("no timestamp found in output");
	}

	free(contents);
	unlink(path);
	TEST_PASS();
	return 1;
}

/* ============================================================================
 * TEST 9: log_free() on a log opened with NULL fname
 * ============================================================================ */

int
test_log_free_no_file(void)
{
	struct log *l;
	int i;

	TEST_START("log_free with NULL fname");

	l = log_open(4, NULL);
	if (!l)
		TEST_FAIL("log_open failed");

	/* Add some entries so buf slots are populated */
	for (i = 0; i < 3; i++) {
		char s[32];
		snprintf(s, sizeof(s), "item%d", i);
		log_add(l, s);
	}

	/* log_free should not crash even though fname is NULL */
	log_free(l);

	TEST_PASS();
	return 1;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int
main(int argc, char **argv)
{
	int passed = 0;
	int total = 9;

	(void)argc;
	(void)argv;

	printf("\n");
	printf("========================================================================\n");
	printf("  Racoon IPSec - Logger Unit Tests\n");
	printf("========================================================================\n");

	passed += test_log_open_null_fname();
	passed += test_log_open_with_fname();
	passed += test_log_add_fill_capacity();
	passed += test_log_add_wraparound();
	passed += test_log_print();
	passed += test_log_vprint();
	passed += test_log_vaprint();
	passed += test_log_close_flush();
	passed += test_log_free_no_file();

	printf("\n");
	printf("========================================================================\n");
	if (passed == total) {
		printf("  ALL LOGGER TESTS PASSED (%d/%d)\n", passed, total);
		printf("========================================================================\n");
		return 0;
	} else {
		printf("  %d/%d TEST(S) FAILED\n", total - passed, total);
		printf("========================================================================\n");
		return 1;
	}
}
