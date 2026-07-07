// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit tests for src/racoon/plog.c
 *
 * plog.c had zero direct unit tests: plog.o was only linked into other
 * test binaries to satisfy symbol references. Its manual buffer/pointer
 * arithmetic (the static 800-byte buf in plog_common(), plogdump()'s
 * hex-dump sizing, binsanitize()'s compaction loop) was therefore
 * exercised only incidentally, if at all. This file exercises those
 * paths directly, capturing stdout/log-file output to verify content
 * rather than just "did it crash".
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include "var.h"
#include "plog.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return 1; } while (0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* ---------------------------------------------------------------------
 * stdout capture helper (dup/dup2-based; safe to nest a single level)
 * --------------------------------------------------------------------- */

static char capture_path[256];
static int saved_stdout_fd = -1;

static void
capture_start(void)
{
	FILE *tmp;

	snprintf(capture_path, sizeof(capture_path), "/tmp/test_plog_cap_%d",
		 (int)getpid());
	unlink(capture_path);
	tmp = fopen(capture_path, "w+");
	if (!tmp) {
		fprintf(stderr, "capture_start: fopen failed\n");
		exit(1);
	}
	fflush(stdout);
	saved_stdout_fd = dup(STDOUT_FILENO);
	dup2(fileno(tmp), STDOUT_FILENO);
	fclose(tmp);
}

/* Caller must free() the returned buffer. */
static char *
capture_end(void)
{
	FILE *fp;
	long sz;
	char *buf;

	fflush(stdout);
	dup2(saved_stdout_fd, STDOUT_FILENO);
	close(saved_stdout_fd);
	saved_stdout_fd = -1;

	fp = fopen(capture_path, "r");
	if (!fp) {
		fprintf(stderr, "capture_end: fopen failed\n");
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	rewind(fp);
	buf = malloc(sz + 1);
	if (!buf) {
		fclose(fp);
		exit(1);
	}
	if (sz > 0 && fread(buf, 1, sz, fp) != (size_t)sz) {
		fclose(fp);
		free(buf);
		exit(1);
	}
	buf[sz] = '\0';
	fclose(fp);
	unlink(capture_path);
	return buf;
}

static long
read_file(const char *path, char **out)
{
	FILE *fp;
	long sz;

	*out = NULL;
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	rewind(fp);
	*out = malloc(sz + 1);
	if (!*out) {
		fclose(fp);
		return -1;
	}
	if (sz > 0 && fread(*out, 1, sz, fp) != (size_t)sz) {
		fclose(fp);
		free(*out);
		*out = NULL;
		return -1;
	}
	(*out)[sz] = '\0';
	fclose(fp);
	return sz;
}

/* ---------------------------------------------------------------------
 * binsanitize() -- pure function, no capture needed
 * --------------------------------------------------------------------- */

static int
test_binsanitize_all_printable(void)
{
	char *out;

	TEST_START("binsanitize() leaves printable input untouched");

	out = binsanitize("Hello", 5);
	if (!out || strcmp(out, "Hello") != 0) {
		free(out);
		TEST_FAIL("expected unchanged printable string");
	}
	free(out);
	TEST_PASS();
	return 0;
}

static int
test_binsanitize_all_unprintable_collapses_to_space(void)
{
	char *out;
	char in[4] = { 0x00, 0x01, 0x02, 0x03 };

	/*
	 * binsanitize() only emits a collapsing space when at least one
	 * printable byte has already been written (the "if (q && ...)"
	 * guard). A run of unprintable bytes with nothing printable before
	 * it -- as here, where it's the whole input -- is therefore
	 * dropped entirely rather than becoming a leading space.
	 */
	TEST_START("binsanitize() drops a leading run of unprintable bytes entirely");

	out = binsanitize(in, sizeof(in));
	if (!out || out[0] != '\0') {
		free(out);
		TEST_FAIL("expected an empty string");
	}
	free(out);
	TEST_PASS();
	return 0;
}

static int
test_binsanitize_mixed(void)
{
	char *out;
	/* "AB" + 2 unprintable + "CD" -> "AB CD" (one collapsed space) */
	char in[6] = { 'A', 'B', 0x01, 0x02, 'C', 'D' };

	TEST_START("binsanitize() collapses interior unprintable runs to one space");

	out = binsanitize(in, sizeof(in));
	if (!out || strcmp(out, "AB CD") != 0) {
		free(out);
		TEST_FAIL("expected 'AB CD'");
	}
	free(out);
	TEST_PASS();
	return 0;
}

static int
test_binsanitize_empty(void)
{
	char *out;

	TEST_START("binsanitize() with n == 0 returns an empty string");

	out = binsanitize("", 0);
	if (!out || out[0] != '\0') {
		free(out);
		TEST_FAIL("expected empty string");
	}
	free(out);
	TEST_PASS();
	return 0;
}

/* ---------------------------------------------------------------------
 * _plog()/plogv()/plog_common() via captured stdout (f_foreground=1,
 * no logfile configured yet in this process).
 * --------------------------------------------------------------------- */

static int
test_syslog_dispatch_no_crash(void)
{
	/*
	 * Must run before any plogset()/ploginit() call in this binary:
	 * plogv() dispatches to vsyslog(3) only when no logfile has ever
	 * been configured. This just proves the dispatch path (and the
	 * pri >= ARRAYLEN(ptab) fallback within it) doesn't crash; the
	 * message itself lands wherever the test host's syslog does.
	 */
	u_int32_t saved_loglevel = loglevel;

	TEST_START("plog() dispatches to syslog when no logfile/foreground is set (no crash)");

	loglevel = 99;
	_plog(99, __func__, NULL, "plog syslog dispatch smoke test\n");
	loglevel = saved_loglevel;

	TEST_PASS();
	return 0;
}

static int
test_plog_priority_tag_in_output(void)
{
	char *out;

	TEST_START("plog_common() prefixes known priorities with their tag");

	f_foreground = 1;
	capture_start();
	_plog(LLV_ERROR, __func__, NULL, "boom\n");
	out = capture_end();
	f_foreground = 0;

	if (!strstr(out, "ERROR: boom")) {
		free(out);
		TEST_FAIL("expected 'ERROR: boom' in output");
	}
	free(out);
	TEST_PASS();
	return 0;
}

static int
test_plog_print_location_toggle(void)
{
	char *out_with, *out_without;

	TEST_START("print_location toggles the func():line prefix");

	f_foreground = 1;

	print_location = 1;
	capture_start();
	_plog(LLV_INFO, __func__, NULL, "with-location\n");
	out_with = capture_end();

	print_location = 0;
	capture_start();
	_plog(LLV_INFO, __func__, NULL, "without-location\n");
	out_without = capture_end();

	f_foreground = 0;

	if (!strstr(out_with, "test_plog_print_location_toggle")) {
		free(out_with); free(out_without);
		TEST_FAIL("expected func name in output when print_location=1");
	}
	if (strstr(out_without, "test_plog_print_location_toggle")) {
		free(out_with); free(out_without);
		TEST_FAIL("did not expect func name in output when print_location=0");
	}

	free(out_with);
	free(out_without);
	TEST_PASS();
	return 0;
}

static int
test_plog_sockaddr_af_inet_included(void)
{
	struct sockaddr_in sin;
	char *out;

	TEST_START("plog_common() includes an AF_INET address when sa is given");

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("203.0.113.5");
	sin.sin_port = htons(4500);

	f_foreground = 1;
	capture_start();
	_plog(LLV_INFO, __func__, (struct sockaddr *)&sin, "v4 test\n");
	out = capture_end();
	f_foreground = 0;

	if (!strstr(out, "203.0.113.5")) {
		free(out);
		TEST_FAIL("expected the IPv4 address in output");
	}
	free(out);
	TEST_PASS();
	return 0;
}

static int
test_plog_sockaddr_af_inet6_included(void)
{
	struct sockaddr_in6 sin6;
	char *out;

	TEST_START("plog_common() includes an AF_INET6 address when sa is given");

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	inet_pton(AF_INET6, "2001:db8::1", &sin6.sin6_addr);

	f_foreground = 1;
	capture_start();
	_plog(LLV_INFO, __func__, (struct sockaddr *)&sin6, "v6 test\n");
	out = capture_end();
	f_foreground = 0;

	if (!strstr(out, "2001:db8::1")) {
		free(out);
		TEST_FAIL("expected the IPv6 address in output");
	}
	free(out);
	TEST_PASS();
	return 0;
}

static int
test_plog_oversized_message_truncates_safely(void)
{
	char huge[2000];
	char *out;
	size_t len;

	TEST_START("plog_common() safely truncates a message wider than its 800-byte buffer");

	/*
	 * plog_common() copies the caller's *format template* into a
	 * static 800-byte buffer via snprintf(p, reslen, "%s", fmt) before
	 * plogv() ever calls vprintf()/vsyslog() on it. To observe that
	 * truncation directly (rather than the separate, unbounded %s
	 * argument-expansion vprintf does on its own), fmt itself must be
	 * the oversized string, with no conversion specifiers. -Wformat
	 * normally requires fmt to be a string literal here (a real
	 * safeguard against format-string bugs); it is deliberately
	 * silenced for this one call since the runtime string is fully
	 * controlled test data containing no '%' characters.
	 */
	memset(huge, 'x', sizeof(huge) - 1);
	huge[sizeof(huge) - 1] = '\0';

	f_foreground = 1;
	capture_start();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	_plog(LLV_INFO, __func__, NULL, huge);
#pragma GCC diagnostic pop
	out = capture_end();
	f_foreground = 0;

	len = strlen(out);
	if (len == 0 || len >= 800) {
		free(out);
		TEST_FAIL("expected non-empty, nul-terminated output shorter than the 800-byte buffer");
	}
	free(out);
	TEST_PASS();
	return 0;
}

static int
test_plogv_loglevel_gate_suppresses_message(void)
{
	char *out;
	u_int32_t saved_loglevel = loglevel;

	TEST_START("plog() macro suppresses messages above the current loglevel");

	loglevel = LLV_ERROR;
	f_foreground = 1;
	capture_start();
	plog(LLV_DEBUG, __func__, NULL, "should not appear\n");
	out = capture_end();
	f_foreground = 0;
	loglevel = saved_loglevel;

	if (out[0] != '\0') {
		free(out);
		TEST_FAIL("expected no output for a suppressed priority");
	}
	free(out);
	TEST_PASS();
	return 0;
}

static int
test_plogdump_hex_format(void)
{
	unsigned char data[4] = { 0xde, 0xad, 0xbe, 0xef };
	char *out;

	TEST_START("plogdump() hex-encodes the given buffer");

	f_foreground = 1;
	capture_start();
	plogdump(LLV_INFO, data, sizeof(data));
	out = capture_end();
	f_foreground = 0;

	if (!strstr(out, "deadbeef")) {
		free(out);
		TEST_FAIL("expected 'deadbeef' in hex-dump output");
	}
	free(out);
	TEST_PASS();
	return 0;
}

static int
test_plogdump_zero_length(void)
{
	char *out;

	TEST_START("plogdump() with a zero-length buffer does not crash");

	f_foreground = 1;
	capture_start();
	plogdump(LLV_INFO, NULL, 0);
	out = capture_end();
	f_foreground = 0;

	free(out);
	TEST_PASS();
	return 0;
}

static int
test_plogdump_line_wrap_boundary(void)
{
	/* 33 bytes crosses the 32-byte-per-line wrap point in plogdump():
	 * a '\n' is inserted before byte 0 and again before byte 32. */
	unsigned char data[33];
	char *out;
	int i, newlines;
	char *p;

	TEST_START("plogdump() wraps output every 32 bytes");

	for (i = 0; i < (int)sizeof(data); i++)
		data[i] = (unsigned char)i;

	f_foreground = 1;
	capture_start();
	plogdump(LLV_INFO, data, sizeof(data));
	out = capture_end();
	f_foreground = 0;

	newlines = 0;
	for (p = out; *p; p++)
		if (*p == '\n')
			newlines++;

	/* At least the wrap before byte 0 and the wrap before byte 32,
	 * plus the trailing newline plog() itself appends. */
	if (newlines < 2 || !strstr(out, "00") || !strstr(out, "20")) {
		free(out);
		TEST_FAIL("expected >=2 newlines and hex bytes '00' (byte 0) and '20' (byte 32)");
	}
	free(out);
	TEST_PASS();
	return 0;
}

/* ---------------------------------------------------------------------
 * ploginit()/plogset() file-backed logging. Runs LAST: plog.c has no
 * "unset logfile" operation, so once this sets it, it stays set for the
 * rest of the process.
 * --------------------------------------------------------------------- */

static int
test_plogset_ploginit_writes_to_file(void)
{
	char path[256];
	char *out = NULL;

	TEST_START("plogset()+ploginit() route plog() output to a real file");

	snprintf(path, sizeof(path), "/tmp/test_plog_file_%d.log", (int)getpid());
	unlink(path);

	plogset(path);
	ploginit();

	_plog(LLV_INFO, __func__, NULL, "file-backed log message\n");

	if (read_file(path, &out) < 0) {
		unlink(path);
		TEST_FAIL("failed to read back log file");
	}
	unlink(path);

	if (!strstr(out, "file-backed log message")) {
		free(out);
		TEST_FAIL("expected message content in log file");
	}
	free(out);
	TEST_PASS();
	return 0;
}

/* ---------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */

int
main(int argc, char **argv)
{
	int failed = 0;

	printf("========================================================================\n");
	printf("  Racoon IPSec - plog.c Unit Tests\n");
	printf("========================================================================\n");

	failed += test_binsanitize_all_printable();
	failed += test_binsanitize_all_unprintable_collapses_to_space();
	failed += test_binsanitize_mixed();
	failed += test_binsanitize_empty();

	/* Must run before test_plogset_ploginit_writes_to_file(). */
	failed += test_syslog_dispatch_no_crash();
	failed += test_plog_priority_tag_in_output();
	failed += test_plog_print_location_toggle();
	failed += test_plog_sockaddr_af_inet_included();
	failed += test_plog_sockaddr_af_inet6_included();
	failed += test_plog_oversized_message_truncates_safely();
	failed += test_plogv_loglevel_gate_suppresses_message();
	failed += test_plogdump_hex_format();
	failed += test_plogdump_zero_length();
	failed += test_plogdump_line_wrap_boundary();

	/* Last: permanently switches this process to file-backed logging. */
	failed += test_plogset_ploginit_writes_to_file();

	printf("\n========================================================================\n");
	if (failed == 0)
		printf("  ALL plog.c TESTS PASSED\n");
	else
		printf("  %d plog.c TEST(S) FAILED\n", failed);
	printf("========================================================================\n");

	return failed == 0 ? 0 : 1;
}
