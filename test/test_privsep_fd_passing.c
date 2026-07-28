// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for the descriptor-passing half of issue #105's privsep
 * fixes.
 *
 * privsep.c's privileged dispatch loop used to answer every local fault --
 * a corrupted message, a failed allocation, an unauthorized argument, an
 * unknown command -- by falling into its "out:" label and _exit(0)ing.
 * Under privsep that process is the only one that can fork()+execve() a
 * hook, and the unprivileged child kills itself as soon as privsep_sock
 * reads EOF (privsep_do_exit()), so one bad request took the whole daemon
 * down: the same shape #102 removed from session()'s select() loop.
 *
 * Most of those faults can simply be answered with an errno in
 * reply->hdr.ac_errno now -- but only because the two sides stay in step
 * on the wire. PRIVSEP_SOCKET is where that is not free: privsep_socket()
 * blocks in rec_fd() *before* it reads the reply, so a failing request
 * that sent only a reply would leave the client's rec_fd() eating that
 * reply's first byte instead, desynchronising the socket permanently.
 * Hence send_fd(fd == -1): a descriptor message with no descriptor
 * attached, which rec_fd() reports back as -1 while the reply that follows
 * carries the real reason.
 *
 * This drives that handshake over a real socketpair() with real SCM_RIGHTS
 * messages -- what it cannot drive is privsep_priv()'s loop itself, which
 * only runs inside privsep_init()'s privileged fork() (a real,
 * privilege-dropping fork this project's test hosts cannot all perform;
 * same constraint as test_privsep_sigterm_forward.c).
 *
 *   - test_send_fd_roundtrip(): a real descriptor still arrives, and is
 *     genuinely usable (written through, read back on its twin) -- the
 *     success path must not have been broken to make the failure path
 *     work.
 *   - test_send_nofd_reports_minus_one(): the no-descriptor message is
 *     received as -1 rather than dereferencing CMSG_DATA(NULL), which is
 *     what the old rec_fd() did with an empty control buffer.
 *   - test_stream_stays_in_sync_after_nofd(): the byte that follows a
 *     no-descriptor message is still the next thing read -- i.e. the
 *     failing path really does cost nothing in stream synchronisation,
 *     which is the whole reason the dispatch loop may answer instead of
 *     exiting.
 *
 * The other half of the same exchange is the *wait*. PRIVSEP_BIND and
 * PRIVSEP_SETSOCKOPTS block reading a descriptor their client said it
 * would send, and the reply sends block on a client that is supposed to
 * be reading -- so a child that simply goes silent (never sends it, never
 * drains) used to block the privileged process forever. Since there is
 * one privileged process serving one child, that is not one stalled
 * connection among many: certificate loads, PSK lookups and hooks stop
 * for every peer while the daemon still looks alive. privsep_wait_io()
 * bounds all of those; a timeout ends the process promptly and loudly
 * instead (privsep_handshake_failed(), privsep.c, explains why it cannot
 * resume the loop rather than exit).
 *
 *   - test_wait_io_returns_when_readable(): does not spend its budget
 *     when the peer does talk.
 *   - test_wait_io_times_out_on_silent_peer(): gives up on a peer that
 *     sends nothing, rather than blocking indefinitely -- and does so
 *     within its budget, which is what makes the bound a bound.
 *   - test_wait_io_detects_writability(): the same wait works for the
 *     reply-send direction.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

extern int privsep_send_fd_unittest(int s, int fd);
extern int privsep_rec_fd_unittest(int s);
extern int privsep_wait_io_unittest(int sock, int write, int max_ms);

/* Budget used by the wait tests: long enough to be unambiguous, short
 * enough that a regression to an unbounded wait is caught by the harness
 * hanging rather than by this test passing slowly. */
#define TEST_WAIT_MS 300

static int
elapsed_ms_since(const struct timeval *start)
{
	struct timeval now;

	gettimeofday(&now, NULL);

	return (int)((now.tv_sec - start->tv_sec) * 1000 +
	    (now.tv_usec - start->tv_usec) / 1000);
}

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
test_send_fd_roundtrip(void)
{
	int sp[2], pipefds[2], received = -1;
	char c = 'x';

	TEST_START("send_fd() still passes a real, usable descriptor");

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");
	if (pipe(pipefds) != 0) {
		close(sp[0]);
		close(sp[1]);
		TEST_FAIL("pipe() failed");
	}

	if (privsep_send_fd_unittest(sp[0], pipefds[1]) != 0) {
		close(sp[0]); close(sp[1]);
		close(pipefds[0]); close(pipefds[1]);
		TEST_FAIL("send_fd() failed for a valid descriptor");
	}

	received = privsep_rec_fd_unittest(sp[1]);
	if (received < 0) {
		close(sp[0]); close(sp[1]);
		close(pipefds[0]); close(pipefds[1]);
		TEST_FAIL("rec_fd() did not receive the descriptor");
	}

	/* Prove it is the same pipe, not just some number. */
	if (write(received, &c, 1) != 1) {
		close(received);
		close(sp[0]); close(sp[1]);
		close(pipefds[0]); close(pipefds[1]);
		TEST_FAIL("received descriptor is not writable");
	}
	c = '\0';
	if (read(pipefds[0], &c, 1) != 1 || c != 'x') {
		close(received);
		close(sp[0]); close(sp[1]);
		close(pipefds[0]); close(pipefds[1]);
		TEST_FAIL("received descriptor does not refer to the sent pipe");
	}

	close(received);
	close(sp[0]); close(sp[1]);
	close(pipefds[0]); close(pipefds[1]);
	TEST_PASS();
	return 0;
}

static int
test_send_nofd_reports_minus_one(void)
{
	int sp[2], received;

	TEST_START("send_fd(-1) is received as -1, not as a wild descriptor");

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");

	if (privsep_send_fd_unittest(sp[0], -1) != 0) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("send_fd() failed for the no-descriptor case");
	}

	received = privsep_rec_fd_unittest(sp[1]);
	if (received != -1) {
		if (received >= 0)
			close(received);
		close(sp[0]); close(sp[1]);
		TEST_FAIL("rec_fd() returned a descriptor where none was sent");
	}

	close(sp[0]); close(sp[1]);
	TEST_PASS();
	return 0;
}

static int
test_stream_stays_in_sync_after_nofd(void)
{
	int sp[2];
	char sent = 'R', got = '\0';

	TEST_START("a no-descriptor message consumes exactly its own message");

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");

	if (privsep_send_fd_unittest(sp[0], -1) != 0) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("send_fd() failed for the no-descriptor case");
	}

	/* Stands in for the reply the dispatch loop sends right after. */
	if (write(sp[0], &sent, 1) != 1) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("could not queue the following reply byte");
	}

	if (privsep_rec_fd_unittest(sp[1]) != -1) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("rec_fd() returned a descriptor where none was sent");
	}

	if (read(sp[1], &got, 1) != 1 || got != sent) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("the reply following a no-descriptor message was lost or misaligned");
	}

	close(sp[0]); close(sp[1]);
	TEST_PASS();
	return 0;
}

static int
test_wait_io_returns_when_readable(void)
{
	int sp[2];
	struct timeval start;
	char c = 'q';

	TEST_START("privsep_wait_io() returns promptly when the peer has spoken");

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");

	if (write(sp[0], &c, 1) != 1) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("could not queue a byte");
	}

	gettimeofday(&start, NULL);
	if (privsep_wait_io_unittest(sp[1], 0, TEST_WAIT_MS) != 0) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("reported a timeout on a socket with data waiting");
	}
	if (elapsed_ms_since(&start) >= TEST_WAIT_MS) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("spent the whole budget on a socket already readable");
	}

	close(sp[0]); close(sp[1]);
	TEST_PASS();
	return 0;
}

static int
test_wait_io_times_out_on_silent_peer(void)
{
	int sp[2], elapsed;
	struct timeval start;

	TEST_START("privsep_wait_io() gives up on a peer that sends nothing");

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");

	/*
	 * sp[0] is deliberately left open and silent: this is the compromised
	 * or broken child that announced a descriptor and never sent it. An
	 * unbounded wait here never returns at all -- the harness would hang
	 * rather than report a failure, which is exactly the production
	 * symptom being tested for.
	 */
	gettimeofday(&start, NULL);
	if (privsep_wait_io_unittest(sp[1], 0, TEST_WAIT_MS) == 0) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("reported readable on a socket nobody wrote to");
	}
	elapsed = elapsed_ms_since(&start);

	if (elapsed < TEST_WAIT_MS / 2) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("gave up well before its budget was spent");
	}
	if (elapsed > TEST_WAIT_MS * 4) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("overran its budget by more than a scheduling margin");
	}

	close(sp[0]); close(sp[1]);
	TEST_PASS();
	return 0;
}

static int
test_wait_io_detects_writability(void)
{
	int sp[2];

	TEST_START("privsep_wait_io() works for the reply-send direction too");

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");

	if (privsep_wait_io_unittest(sp[0], 1, TEST_WAIT_MS) != 0) {
		close(sp[0]); close(sp[1]);
		TEST_FAIL("reported a timeout on an empty, writable socket");
	}

	close(sp[0]); close(sp[1]);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep descriptor-passing test (issue #105) ===\n");

	if (test_send_fd_roundtrip() != 0)
		failed++;
	if (test_send_nofd_reports_minus_one() != 0)
		failed++;
	if (test_stream_stays_in_sync_after_nofd() != 0)
		failed++;
	if (test_wait_io_returns_when_readable() != 0)
		failed++;
	if (test_wait_io_times_out_on_silent_peer() != 0)
		failed++;
	if (test_wait_io_detects_writability() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
