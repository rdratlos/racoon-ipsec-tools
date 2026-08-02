// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for the ADMIN_DELETE_ALL_SA_DST rework in admin.c's
 * v0.9.1 hardening pass (see admin_process()'s own header comment on that
 * case for the full incident writeup). The short version: an earlier fix
 * subscribed the requesting connection to phase1-down events *before*
 * replying to it. purge_remote() fires that event synchronously, so
 * racoonctl's vpn-disconnect/vd (which exits as soon as either message
 * satisfies it) could see the event, exit, and close its socket before
 * ever reading this request's own reply -- and since evt_subscribe() had
 * already registered that same fd in this process's fd-monitor/select()
 * set, the reply's later EPIPE (admin_process() returning non -2) made
 * admin_handler() close(so2) while evt.c's registration for it was still
 * live: select() then fails with EBADF and takes the *entire* daemon
 * down over one already-dead admin connection, not just it.
 *
 * The fix reorders this: reply first, and only subscribe if that reply
 * actually reached the client -- and only once, even though the
 * while-loop below may run once per matching ph1handle.
 *
 * admin_process() is static; admin_process_unittest() (admin.c,
 * ENABLE_UNITTEST) exposes it directly so this test can hand it a
 * hand-built ADMIN_DELETE_ALL_SA_DST command over a real socketpair()
 * standing in for the admin connection, without reconstructing
 * admin_handler()'s accept()/recv() plumbing.
 *
 * admin_process() is one function containing every ADMIN_* case, so
 * -ffunction-sections/--gc-sections cannot discard the cases this test
 * never drives -- admin_test_stubs.c supplies link-time stand-ins for
 * all of them; only getph1() (both getph1byaddr()/getph1bydstaddr()
 * expand to it), evt_subscribe(), isakmp_info_send_d1(), and
 * purge_remote() are "smart" stubs this test actually controls and
 * asserts against. admin_reply() itself is NOT stubbed: it is exercised
 * for real, over the real socketpair(), so this test observes the actual
 * wire bytes and the actual send()-failure path.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "vmbuf.h"
#include "handler.h"
#include "admin.h"

extern int admin_process_unittest(int so2, char *combuf);

extern struct ph1handle *admin_test_getph1_queue[];
extern int admin_test_getph1_queue_len;
extern int admin_test_getph1_calls;
extern int admin_test_evt_subscribe_calls;
extern int admin_test_evt_subscribe_ret;
extern int admin_test_isakmp_info_send_d1_calls;
extern int admin_test_purge_remote_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

struct delete_all_req {
	struct admin_com com;
	struct admin_com_indexes ndx;
};

static void
reset_stub_state(void)
{
	admin_test_getph1_queue_len = 0;
	admin_test_getph1_calls = 0;
	admin_test_evt_subscribe_calls = 0;
	admin_test_evt_subscribe_ret = -2;
	admin_test_isakmp_info_send_d1_calls = 0;
	admin_test_purge_remote_calls = 0;
}

static void
build_request(struct delete_all_req *req)
{
	memset(req, 0, sizeof(*req));
	req->com.ac_len = sizeof(*req);
	req->com.ac_cmd = ADMIN_DELETE_ALL_SA_DST;
	req->com.ac_proto = ADMIN_PROTO_ISAKMP;
	req->ndx.dst.ss_family = AF_INET;
}

/*
 * getph1() only returns pointers; admin_process() never dereferences
 * anything but ->status and ->local (via saddrwop2str(), stubbed to
 * ignore its argument), so a zeroed struct with just those two fields
 * set is a safe stand-in for a real struct ph1handle here.
 */
static struct sockaddr fake_local;

static int
test_multiple_sas_reply_before_single_subscribe(void)
{
	struct ph1handle established, not_established;
	struct delete_all_req req;
	int sv[2];
	int rc;
	char replybuf[512];
	ssize_t n;

	TEST_START("reply is sent, evt_subscribe() fires exactly once for N matching SAs");

	reset_stub_state();
	memset(&established, 0, sizeof(established));
	established.status = PHASE1ST_ESTABLISHED;
	established.local = &fake_local;
	memset(&not_established, 0, sizeof(not_established));
	not_established.status = 0;
	not_established.local = &fake_local;

	admin_test_getph1_queue[0] = &established;
	admin_test_getph1_queue[1] = &not_established;
	admin_test_getph1_queue_len = 2;
	admin_test_evt_subscribe_ret = -2;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		TEST_FAIL("socketpair() failed");

	build_request(&req);
	rc = admin_process_unittest(sv[0], (char *)&req);

	if (rc != -2) {
		close(sv[0]); close(sv[1]);
		printf("admin_process() returned %d, expected -2 ", rc);
		TEST_FAIL("wrong return value for a successful subscribe");
	}
	if (admin_test_evt_subscribe_calls != 1) {
		close(sv[0]); close(sv[1]);
		printf("evt_subscribe() called %d times, expected 1 ",
		    admin_test_evt_subscribe_calls);
		TEST_FAIL("evt_subscribe() must fire exactly once, not per-SA");
	}
	if (admin_test_isakmp_info_send_d1_calls != 1) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("isakmp_info_send_d1() should only run for the ESTABLISHED SA");
	}
	if (admin_test_purge_remote_calls != 2) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("purge_remote() should run once per matching SA regardless of status");
	}

	n = recv(sv[1], replybuf, sizeof(replybuf), MSG_DONTWAIT);
	if (n < (ssize_t)sizeof(struct admin_com)) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("client end never received the admin_reply() bytes");
	}
	{
		struct admin_com *reply = (struct admin_com *)replybuf;
		if ((reply->ac_cmd & ~ADMIN_FLAG_VERSION) != ADMIN_DELETE_ALL_SA_DST) {
			close(sv[0]); close(sv[1]);
			TEST_FAIL("reply ac_cmd does not echo the request");
		}
	}

	close(sv[0]);
	close(sv[1]);
	TEST_PASS();
	return 0;
}

static int
test_no_matching_sas_still_replies_no_subscribe(void)
{
	struct delete_all_req req;
	int sv[2];
	int rc;
	char replybuf[512];
	ssize_t n;

	TEST_START("no matching SAs: still replies, never subscribes");

	reset_stub_state();
	admin_test_getph1_queue_len = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		TEST_FAIL("socketpair() failed");

	build_request(&req);
	rc = admin_process_unittest(sv[0], (char *)&req);

	if (rc != 0) {
		close(sv[0]); close(sv[1]);
		printf("admin_process() returned %d, expected 0 ", rc);
		TEST_FAIL("wrong return value with zero matching SAs");
	}
	if (admin_test_evt_subscribe_calls != 0) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("evt_subscribe() must not fire when the peer has no live SAs");
	}
	if (admin_test_purge_remote_calls != 0) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("purge_remote() must not fire when the peer has no live SAs");
	}

	n = recv(sv[1], replybuf, sizeof(replybuf), MSG_DONTWAIT);
	if (n < (ssize_t)sizeof(struct admin_com)) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("client end never received a reply");
	}

	close(sv[0]);
	close(sv[1]);
	TEST_PASS();
	return 0;
}

/*
 * The regression itself: if the reply cannot reach the client (peer
 * already gone), evt_subscribe() must never run -- subscribing a
 * connection nothing will ever read from again is exactly the dangling
 * fd-monitor registration that used to take the whole daemon down.
 * Teardown (isakmp_info_send_d1()/purge_remote()) still proceeds
 * regardless: the SAs are gone either way, only the notification path
 * differs.
 */
static int
test_failed_reply_skips_subscribe_but_still_tears_down(void)
{
	struct ph1handle established;
	struct delete_all_req req;
	int sv[2];
	int rc;

	TEST_START("failed reply: evt_subscribe() skipped, teardown still happens");

	reset_stub_state();
	memset(&established, 0, sizeof(established));
	established.status = PHASE1ST_ESTABLISHED;
	established.local = &fake_local;
	admin_test_getph1_queue[0] = &established;
	admin_test_getph1_queue_len = 1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		TEST_FAIL("socketpair() failed");

	/* Close the peer end first: admin_reply()'s send() on sv[0] must now
	 * fail (ECONNRESET/EPIPE) instead of succeeding. */
	close(sv[1]);

	build_request(&req);
	rc = admin_process_unittest(sv[0], (char *)&req);

	if (rc == -2 || rc == 0) {
		close(sv[0]);
		printf("admin_process() returned %d ", rc);
		TEST_FAIL("admin_process() reported success despite the reply failing");
	}
	if (admin_test_evt_subscribe_calls != 0) {
		close(sv[0]);
		TEST_FAIL("evt_subscribe() fired despite the reply never reaching the client "
		    "-- this is the dangling fd-monitor registration the fix prevents");
	}
	if (admin_test_purge_remote_calls != 1) {
		close(sv[0]);
		TEST_FAIL("purge_remote() should still run even when the reply failed");
	}

	close(sv[0]);
	TEST_PASS();
	return 0;
}

static int
test_unknown_command_does_not_subscribe(void)
{
	struct delete_all_req req;
	int sv[2];
	int rc;
	char replybuf[512];
	ssize_t n;

	TEST_START("an unrecognized command replies ENOTSUP and never subscribes");

	reset_stub_state();

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		TEST_FAIL("socketpair() failed");

	build_request(&req);
	req.com.ac_cmd = 0x7fff; /* not a defined ADMIN_* command */

	rc = admin_process_unittest(sv[0], (char *)&req);

	if (rc != 0) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("admin_process() should still reply successfully for an unknown command");
	}
	if (admin_test_evt_subscribe_calls != 0) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("evt_subscribe() must not fire for an unrecognized command");
	}

	n = recv(sv[1], replybuf, sizeof(replybuf), MSG_DONTWAIT);
	if (n < (ssize_t)sizeof(struct admin_com)) {
		close(sv[0]); close(sv[1]);
		TEST_FAIL("client end never received the ENOTSUP reply");
	}

	close(sv[0]);
	close(sv[1]);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	/* admin_reply()'s send() has no MSG_NOSIGNAL; the failed-reply
	 * scenario deliberately closes the peer end first, which would
	 * otherwise deliver a real SIGPIPE and kill this process instead of
	 * letting send() return -1. */
	signal(SIGPIPE, SIG_IGN);

	printf("\n=== admin_process() ADMIN_DELETE_ALL_SA_DST regression test ===\n");

	if (test_multiple_sas_reply_before_single_subscribe() != 0)
		failed++;
	if (test_no_matching_sas_still_replies_no_subscribe() != 0)
		failed++;
	if (test_failed_reply_skips_subscribe_but_still_tears_down() != 0)
		failed++;
	if (test_unknown_command_does_not_subscribe() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
