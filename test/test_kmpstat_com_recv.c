// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for doc/dev/daemon-issues.md Issue 4: com_recv()'s
 * short-read/EOF sanity check (the "if (len < sizeof(h)) goto bad1;"
 * branch) used to goto bad1 with no diagnostic call at all, so a
 * "racoonctl vpn-disconnect" (or any other admin-socket event wait) whose
 * connection EOFed or delivered a truncated header before the expected
 * event arrived exited non-zero with zero output -- reproduced 100% of
 * the time across 8 live Task F test runs (daemon-issues.md Issue 4).
 *
 * com_recv() is not static, but the admin-socket fd it reads ("so") is a
 * static, file-scope variable private to kmpstat.c. This test reaches it
 * through the ENABLE_UNITTEST-only com_set_fd_unittest() accessor kmpstat.c
 * now defines, standing a socketpair() in for the real AF_UNIX admin
 * socket so both the clean-EOF and genuine-short-read cases can be driven
 * deterministically without a live racoon.
 *
 * kmpstat.c is pulled in via a local wrapper source (kmpstat_unittest_src.c)
 * following this project's established unit-test-a-static-function pattern
 * (see the comment on test_racoonctl_logoutusr_SOURCES in test/Makefile.am).
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "var.h"
#include "vmbuf.h"
#include "admin.h"

extern void com_set_fd_unittest(int fd);
extern int com_recv(vchar_t **combufp);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/*
 * Runs com_recv(combufp) with fd 2 redirected to a pipe, and hands back
 * whatever warn()/warnx() wrote there, NUL-terminated. Restores the real
 * fd 2 before returning either way.
 */
static int
capture_stderr(char *out, size_t outlen, vchar_t **combufp, int *recv_ret)
{
	int savedfd, pipefd[2];
	ssize_t n;

	fflush(stderr);
	if (pipe(pipefd) != 0)
		return -1;
	if ((savedfd = dup(2)) < 0)
		return -1;
	if (dup2(pipefd[1], 2) < 0)
		return -1;
	close(pipefd[1]);

	*recv_ret = com_recv(combufp);

	fflush(stderr);
	/* dup2() here closes fd 2's current target (the pipe's write end)
	 * before repointing it at savedfd, so the pipe's write side is
	 * fully closed and the read below cannot block on it. */
	dup2(savedfd, 2);
	close(savedfd);

	n = read(pipefd[0], out, outlen - 1);
	close(pipefd[0]);
	if (n < 0)
		n = 0;
	out[n] = '\0';

	return 0;
}

/*
 * Peer closes the connection without sending anything -- a clean EOF
 * (recv() via MSG_PEEK returns 0), the exact condition the live Task F
 * runs hit when racoon's admin socket closed before delivering the
 * expected event.
 */
static int
check_eof(void)
{
	int sv[2];
	vchar_t *combuf = NULL;
	char msg[256];
	int ret;

	TEST_START("com_recv() on a clean EOF reports what happened");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		TEST_FAIL("socketpair() failed");
	close(sv[1]); /* peer gone before sending a reply header */
	com_set_fd_unittest(sv[0]);

	if (capture_stderr(msg, sizeof(msg), &combuf, &ret) != 0) {
		close(sv[0]);
		TEST_FAIL("capture_stderr() failed");
	}
	close(sv[0]);

	if (ret != -1) {
		printf("(com_recv returned %d, expected -1) ", ret);
		TEST_FAIL("com_recv() did not report failure on EOF");
	}
	if (combuf != NULL)
		TEST_FAIL("com_recv() left *combufp non-NULL on failure");
	if (msg[0] == '\0')
		TEST_FAIL("com_recv() printed nothing on EOF (issue #4 regression)");
	if (strstr(msg, "EOF") == NULL) {
		printf("(stderr was: \"%s\") ", msg);
		TEST_FAIL("diagnostic does not mention EOF/closed connection");
	}

	TEST_PASS();
	return 0;
}

/*
 * Peer sends a truncated header (fewer than sizeof(struct admin_com)
 * bytes) and closes -- a genuine short read, distinct from a clean
 * zero-byte EOF, and worth a message that says how much was missing.
 */
static int
check_short_read(void)
{
	int sv[2];
	vchar_t *combuf = NULL;
	char msg[256];
	int ret;
	static const unsigned char partial[2] = { 0x00, 0x00 };

	TEST_START("com_recv() on a truncated header reports N of M bytes");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		TEST_FAIL("socketpair() failed");
	if (write(sv[1], partial, sizeof(partial)) != (ssize_t)sizeof(partial)) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("write() of partial header failed");
	}
	close(sv[1]);
	com_set_fd_unittest(sv[0]);

	if (capture_stderr(msg, sizeof(msg), &combuf, &ret) != 0) {
		close(sv[0]);
		TEST_FAIL("capture_stderr() failed");
	}
	close(sv[0]);

	if (ret != -1) {
		printf("(com_recv returned %d, expected -1) ", ret);
		TEST_FAIL("com_recv() did not report failure on short read");
	}
	if (msg[0] == '\0')
		TEST_FAIL("com_recv() printed nothing on a short read (issue #4 regression)");
	if (strstr(msg, "2") == NULL || strstr(msg, "8") == NULL) {
		printf("(stderr was: \"%s\") ", msg);
		TEST_FAIL("diagnostic does not state N of M bytes received");
	}

	TEST_PASS();
	return 0;
}

/*
 * Regression guard for the success path: a well-formed header-only reply
 * (ac_len == sizeof(struct admin_com), no payload) must still round-trip
 * cleanly and silently through com_recv() -- the Issue 4 fix must not
 * make com_recv() noisy or fail on a normal exchange.
 */
static int
check_happy_path(void)
{
	int sv[2];
	vchar_t *combuf = NULL;
	char msg[256];
	int ret;
	struct admin_com h;

	TEST_START("com_recv() on a well-formed header-only reply stays silent");

	memset(&h, 0, sizeof(h));
	h.ac_len = sizeof(h);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		TEST_FAIL("socketpair() failed");
	if (write(sv[1], &h, sizeof(h)) != (ssize_t)sizeof(h)) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("write() of header failed");
	}
	close(sv[1]);
	com_set_fd_unittest(sv[0]);

	if (capture_stderr(msg, sizeof(msg), &combuf, &ret) != 0) {
		close(sv[0]);
		TEST_FAIL("capture_stderr() failed");
	}
	close(sv[0]);

	if (ret != 0) {
		printf("(com_recv returned %d, expected 0; stderr: \"%s\") ", ret, msg);
		TEST_FAIL("com_recv() failed on a well-formed reply");
	}
	if (combuf == NULL)
		TEST_FAIL("com_recv() left *combufp NULL on success");
	if (combuf->l != sizeof(h)) {
		printf("(combuf->l=%zu, expected %zu) ", combuf->l, sizeof(h));
		vfree(combuf);
		TEST_FAIL("returned buffer has the wrong length");
	}
	if (msg[0] != '\0') {
		printf("(unexpected stderr: \"%s\") ", msg);
		vfree(combuf);
		TEST_FAIL("com_recv() printed a diagnostic on a successful reply");
	}

	vfree(combuf);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== kmpstat com_recv() short-read/EOF diagnostics test (issue #4) ===\n");

	if (check_eof() != 0)
		failed++;
	if (check_short_read() != 0)
		failed++;
	if (check_happy_path() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
