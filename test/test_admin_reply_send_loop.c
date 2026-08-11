// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * admin_reply()'s send() loop (admin.c) -- issue #143 F1.
 *
 * The loop exists because a single send() on a SOCK_STREAM socket may
 * legally transfer fewer bytes than requested, which for
 * ADMIN_STATUS/ADMIN_STATUS_VERBOSE means truncated, invalid JSON on the
 * wire (issue #139 Finding H-4). Its first version was written as
 *
 *     for (sent = 0; sent < tlen; sent += (size_t)n) {
 *             n = send(...);
 *             if (n < 0) { if (errno == EINTR) continue; ... }
 *
 * where "continue" runs the *increment expression* before re-testing the
 * condition -- so an EINTR retry applied "sent += (size_t)-1" and walked
 * the counter backwards. From sent == 0 it wrapped to SIZE_MAX, the loop
 * test failed immediately, and admin_reply() returned 0 for "success"
 * having written nothing at all.
 *
 * Nothing in the existing suite delivers a signal mid-send(), so this
 * needs -Wl,--wrap=send to inject the conditions deterministically rather
 * than trying to race a real SIGHUP against a send() call. racoon
 * installs SIGHUP/SIGINT/SIGTERM handlers without SA_RESTART (session.c),
 * so EINTR here is a real path, not a theoretical one.
 *
 * Driven through admin_process_unittest() over a real socketpair(), the
 * same accessor and stub set test_admin_delete_all_sa_dst.c uses -- see
 * that file's header comment for why admin_process() needs the full stub
 * set just to link.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "vmbuf.h"
#include "handler.h"
#include "admin.h"

extern int admin_process_unittest(int so2, char *combuf);
extern const char *admin_test_status_dump_payload;
extern int admin_test_status_dump_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/* A payload comfortably larger than struct admin_com, so a truncated or
 * mis-advanced loop shows up as a short read rather than an off-by-one. */
#define PAYLOAD \
    "{\"schema_version\":\"1.2\",\"phase1\":[],\"phase2\":[]}" \
    "0123456789abcdef0123456789abcdef0123456789abcdef"

/* --- send() injection ------------------------------------------------ */

extern ssize_t __real_send(int, const void *, size_t, int);

/* One-shot: the next send() call fails with EINTR, then normal service
 * resumes. This is the exact shape the bug mishandled. */
static int inject_eintr_once;
/* Fail with EINTR on exactly this 1-based send() call, so the interrupt
 * can be placed *after* a partial transfer (sent > 0) as well as before
 * any (sent == 0) -- two distinct failure modes of the old loop. 0 = off. */
static int inject_eintr_at_call;
/* When > 0, every send() transfers at most this many bytes -- a forced
 * short write, the condition the loop was added for in the first place. */
static size_t force_chunk;
/* One-shot: the next send() returns 0 without transferring anything. */
static int inject_zero_once;

static int send_calls;

ssize_t
__wrap_send(int fd, const void *buf, size_t len, int flags)
{
	send_calls++;

	if (inject_eintr_once) {
		inject_eintr_once = 0;
		errno = EINTR;
		return -1;
	}
	if (inject_eintr_at_call != 0 && send_calls == inject_eintr_at_call) {
		inject_eintr_at_call = 0;
		errno = EINTR;
		return -1;
	}
	if (inject_zero_once) {
		inject_zero_once = 0;
		return 0;
	}
	if (force_chunk > 0 && len > force_chunk)
		len = force_chunk;

	return __real_send(fd, buf, len, flags);
}

static void
reset_injection(void)
{
	inject_eintr_once = 0;
	inject_eintr_at_call = 0;
	force_chunk = 0;
	inject_zero_once = 0;
	send_calls = 0;
	admin_test_status_dump_calls = 0;
	admin_test_status_dump_payload = PAYLOAD;
}

/* --- helpers --------------------------------------------------------- */

static void
build_status_request(struct admin_com *com)
{
	memset(com, 0, sizeof(*com));
	com->ac_len = sizeof(*com);
	com->ac_cmd = ADMIN_STATUS;
	com->ac_errno = 0;
	com->ac_proto = ADMIN_STATUS_FORMAT_JSON;
}

/* Drains the client end into buf, looping until the expected byte count
 * arrives or the socket runs dry -- the reader must not itself assume a
 * single recv() sees everything, or it would reintroduce on the test side
 * the very bug it is checking for on the server side. */
static ssize_t
drain(int fd, char *buf, size_t cap, size_t want)
{
	size_t got = 0;
	ssize_t n;

	while (got < want && got < cap) {
		n = recv(fd, buf + got, cap - got, MSG_DONTWAIT);
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	return (ssize_t)got;
}

/* Runs one ADMIN_STATUS request end to end and checks the client end
 * received the complete header + payload. Returns 0 on success. */
static int
run_and_check_full_reply(const char **why)
{
	int sv[2];
	struct admin_com req;
	char buf[1024];
	size_t want = sizeof(struct admin_com) + strlen(PAYLOAD);
	ssize_t got;
	int rc;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		*why = "socketpair() failed";
		return -1;
	}

	build_status_request(&req);
	rc = admin_process_unittest(sv[0], (char *)&req);

	if (rc != 0) {
		close(sv[0]); close(sv[1]);
		*why = "admin_process() reported failure on a reply that should have succeeded";
		return -1;
	}
	if (admin_test_status_dump_calls != 1) {
		close(sv[0]); close(sv[1]);
		*why = "ADMIN_STATUS did not reach status_dump()";
		return -1;
	}

	got = drain(sv[1], buf, sizeof(buf), want);
	close(sv[0]);
	close(sv[1]);

	if (got < 0 || (size_t)got != want) {
		*why = "client end did not receive the complete reply";
		return -1;
	}
	if (memcmp(buf + sizeof(struct admin_com), PAYLOAD,
	    strlen(PAYLOAD)) != 0) {
		*why = "reply payload bytes do not match what status_dump() produced";
		return -1;
	}
	return 0;
}

/* --- tests ----------------------------------------------------------- */

/*
 * The regression proper. Pre-fix this failed with zero bytes received:
 * the EINTR retry wrapped "sent" to SIZE_MAX and admin_reply() returned
 * success without ever putting the reply on the wire.
 */
static int
test_eintr_on_first_send_still_delivers_full_reply(void)
{
	const char *why = NULL;

	TEST_START("EINTR on the first send() is retried, and the whole reply "
	    "still reaches the client (issue #143 F1)");

	reset_injection();
	inject_eintr_once = 1;

	if (run_and_check_full_reply(&why) != 0)
		TEST_FAIL(why);

	/* One interrupted call plus at least one real one -- proves the
	 * EINTR branch was actually taken rather than the injection being
	 * silently skipped. */
	if (send_calls < 2)
		TEST_FAIL("expected the interrupted send() to be retried");

	TEST_PASS();
	return 0;
}

/*
 * The condition the loop was originally added for: a short write. Forcing
 * one byte per send() makes the loop iterate over the whole reply, which
 * only terminates correctly if "sent" advances by exactly the number of
 * bytes each send() reported.
 */
static int
test_short_writes_are_resumed(void)
{
	const char *why = NULL;
	size_t want = sizeof(struct admin_com) + strlen(PAYLOAD);

	TEST_START("a send() that transfers one byte at a time is resumed "
	    "until the whole reply is written");

	reset_injection();
	force_chunk = 1;

	if (run_and_check_full_reply(&why) != 0)
		TEST_FAIL(why);

	if ((size_t)send_calls < want)
		TEST_FAIL("expected one send() call per byte with force_chunk = 1");

	TEST_PASS();
	return 0;
}

/*
 * EINTR arriving *mid-transfer* rather than on the first call: "sent" is
 * already non-zero, so the pre-fix decrement would have re-sent an
 * already-delivered byte and corrupted the stream rather than truncating
 * it. Distinct failure mode, distinct test.
 */
static int
test_eintr_midstream_does_not_duplicate_bytes(void)
{
	const char *why = NULL;

	TEST_START("EINTR after a partial transfer resumes at the right offset "
	    "without duplicating or dropping bytes");

	reset_injection();
	/* Chunked so the transfer takes several calls, with the interrupt
	 * landing on the second -- by then sent > 0, which is where the old
	 * loop's backwards step re-sent an already-delivered byte instead of
	 * truncating outright. run_and_check_full_reply() compares the whole
	 * payload byte for byte, so a duplicated byte fails as loudly as a
	 * missing one. */
	force_chunk = 8;
	inject_eintr_at_call = 2;

	if (run_and_check_full_reply(&why) != 0)
		TEST_FAIL(why);

	if (inject_eintr_at_call != 0)
		TEST_FAIL("the mid-stream EINTR was never injected");

	TEST_PASS();
	return 0;
}

/*
 * send() returning 0 on a non-zero-length request is not a normal outcome
 * on a stream socket. The original loop "break"ed out of it, which still
 * returned 0 -- reporting success on a short write, the exact failure the
 * loop exists to prevent. It must be an error instead.
 */
static int
test_zero_return_is_an_error_not_silent_success(void)
{
	int sv[2];
	struct admin_com req;
	int rc;

	TEST_START("send() returning 0 is reported as an error, not silent "
	    "success on a truncated reply");

	reset_injection();
	inject_zero_once = 1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		TEST_FAIL("socketpair() failed");

	build_status_request(&req);
	rc = admin_process_unittest(sv[0], (char *)&req);

	close(sv[0]);
	close(sv[1]);

	if (rc == 0)
		TEST_FAIL("a zero-byte send() must not be reported as a successful reply");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== admin_reply() send loop test ===\n");

	if (test_eintr_on_first_send_still_delivers_full_reply() != 0)
		failed++;
	if (test_short_writes_are_resumed() != 0)
		failed++;
	if (test_eintr_midstream_does_not_duplicate_bytes() != 0)
		failed++;
	if (test_zero_return_is_an_error_not_silent_success() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
