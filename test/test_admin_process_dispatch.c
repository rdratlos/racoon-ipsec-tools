// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Dispatch-level coverage for admin_process()'s remaining ADMIN_* cases
 * (admin.c) -- ADMIN_DELETE_ALL_SA_DST has its own dedicated regression
 * test (test_admin_delete_all_sa_dst.c, the highest-priority hunk in
 * this churn); this file rounds out the rest of the switch so the
 * dispatcher itself has meaningful coverage.
 *
 * "Dispatch-level" is a deliberate scope choice, not a shortcut: what
 * each case actually calls (pfkey_dump_sadb(), isakmp_ph1begin_i(),
 * getsp_r(), ...) is real subsystem behavior that belongs to pfkey.c's/
 * isakmp.c's/policy.c's own tests -- exercising it for real here would
 * mean linking most of racoon (real PF_KEY sockets, real ISAKMP state
 * machine) or reproducing it badly with fakes, neither of which tells
 * you whether admin_process()'s own dispatch logic is correct. So each
 * test below asserts two things only: the right stub got called (proof
 * this case's code path actually ran, not a different one), and the
 * right l_ac_errno ended up on the wire in the reply's ac_errno field.
 * That is the same boundary test_ipsec_doi_sa.c already draws around
 * t2isakmpsa() (isolate the dispatch/parsing logic under test, stub
 * everything reachable-but-uninteresting so --gc-sections can still
 * link the whole function).
 *
 * Not covered here: ADMIN_ESTABLISH_SA_PSK's own id/key-parsing block
 * (falls through into ADMIN_ESTABLISH_SA, which this file does cover).
 * Its wire format is a third struct (admin_com_psk) appended after
 * admin_com_indexes, with the id/key bytes themselves appended after
 * that and their lengths cross-checked by pointer arithmetic
 * (admin.c) -- fragile to hand-construct correctly in a test buffer
 * without risking a buffer-overrun bug in the test itself rather than
 * the code under test. Flagged as a follow-up rather than rushed.
 *
 * Same admin_process_unittest() accessor and admin_test_stubs.c as
 * test_admin_delete_all_sa_dst.c; see that file's header comment for why
 * admin_process() (one function containing every case) needs the full
 * stub set to link at all.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "vmbuf.h"
#include "handler.h"
#include "admin.h"

extern int admin_process_unittest(int so2, char *combuf);

extern int admin_test_getph1_queue_len;
extern int admin_test_getph1_calls;
extern int admin_test_evt_subscribe_calls;
extern int admin_test_signal_handler_calls;
extern int admin_test_sched_dump_calls;
extern int admin_test_evt_dump_calls;
extern int admin_test_dumpph1_calls;
extern int admin_test_pfkey_dump_sadb_calls;
extern int admin_test_flushph1_calls;
extern int admin_test_pfkey_flush_sadb_calls;
extern int admin_test_enumph1_calls;
extern int admin_test_remcontacted_calls;
#ifdef ENABLE_HYBRID
extern int admin_test_purgeph1bylogin_calls;
#endif
extern int admin_test_getrmconf_calls;
extern int admin_test_getsp_r_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

struct req_with_ndx {
	struct admin_com com;
	struct admin_com_indexes ndx;
};

static void
reset_all_stub_state(void)
{
	admin_test_getph1_queue_len = 0;
	admin_test_getph1_calls = 0;
	admin_test_evt_subscribe_calls = 0;
	admin_test_signal_handler_calls = 0;
	admin_test_sched_dump_calls = 0;
	admin_test_evt_dump_calls = 0;
	admin_test_dumpph1_calls = 0;
	admin_test_pfkey_dump_sadb_calls = 0;
	admin_test_flushph1_calls = 0;
	admin_test_pfkey_flush_sadb_calls = 0;
	admin_test_enumph1_calls = 0;
	admin_test_remcontacted_calls = 0;
#ifdef ENABLE_HYBRID
	admin_test_purgeph1bylogin_calls = 0;
#endif
	admin_test_getrmconf_calls = 0;
	admin_test_getsp_r_calls = 0;
}

/* Sends combuf's ac_len bytes over a fresh socketpair(), drives
 * admin_process_unittest(), and returns the l_ac_errno the server wrote
 * into its reply (read back from the client end), or -32768 on any
 * plumbing failure (out of struct admin_com's real int16_t range, so it
 * can never collide with a genuine ac_errno value). */
static int
dispatch_and_get_reply_errno(void *combuf, size_t len, int *ret_out)
{
	int sv[2];
	int rc;
	struct admin_com reply;
	ssize_t n;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return -32768;

	rc = admin_process_unittest(sv[0], (char *)combuf);
	if (ret_out != NULL)
		*ret_out = rc;

	n = recv(sv[1], &reply, sizeof(reply), MSG_DONTWAIT);
	close(sv[0]);
	close(sv[1]);
	if (n < (ssize_t)sizeof(struct admin_com))
		return -32768;

	return reply.ac_errno;
}

static int
test_show_sched(void)
{
	struct admin_com req;
	int errno_out;

	TEST_START("ADMIN_SHOW_SCHED calls sched_dump() and reports ENOMEM on failure");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_SHOW_SCHED;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != ENOMEM)
		TEST_FAIL("reply ac_errno was not ENOMEM");
	if (admin_test_sched_dump_calls != 1)
		TEST_FAIL("sched_dump() was not called exactly once");

	TEST_PASS();
	return 0;
}

static int
test_show_evt_version_zero_dumps_directly(void)
{
	struct admin_com req;

	TEST_START("ADMIN_SHOW_EVT (version 0) calls evt_dump(), does not subscribe");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_SHOW_EVT;

	dispatch_and_get_reply_errno(&req, sizeof(req), NULL);

	if (admin_test_evt_dump_calls != 1)
		TEST_FAIL("evt_dump() was not called for a version-0 request");
	if (admin_test_evt_subscribe_calls != 0)
		TEST_FAIL("evt_subscribe() fired for a version-0 request");

	TEST_PASS();
	return 0;
}

/*
 * A versioned (>=1) request takes admin_process()'s *shared-tail*
 * evt_subscribe() call -- a different code path than
 * ADMIN_DELETE_ALL_SA_DST's own early-return subscribe (which
 * test_admin_delete_all_sa_dst.c already covers) and otherwise entirely
 * untested until now.
 */
static int
test_show_evt_versioned_subscribes_via_shared_tail(void)
{
	struct admin_com req;

	TEST_START("ADMIN_SHOW_EVT (version 1) subscribes via the shared tail, skips evt_dump()");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_SHOW_EVT | ADMIN_FLAG_VERSION;
	req.ac_version = 1;

	dispatch_and_get_reply_errno(&req, sizeof(req), NULL);

	if (admin_test_evt_dump_calls != 0)
		TEST_FAIL("evt_dump() was called for a version>=1 request (should be skipped)");
	if (admin_test_evt_subscribe_calls != 1)
		TEST_FAIL("evt_subscribe() did not fire via the shared tail");

	TEST_PASS();
	return 0;
}

static int
test_show_sa_isakmp(void)
{
	struct admin_com req;

	TEST_START("ADMIN_SHOW_SA/ISAKMP calls dumpph1(), reports ENOMEM on NULL");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_SHOW_SA;
	req.ac_proto = ADMIN_PROTO_ISAKMP;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != ENOMEM)
		TEST_FAIL("reply ac_errno was not ENOMEM");
	if (admin_test_dumpph1_calls != 1)
		TEST_FAIL("dumpph1() was not called");

	TEST_PASS();
	return 0;
}

static int
test_show_sa_ah(void)
{
	struct admin_com req;

	TEST_START("ADMIN_SHOW_SA/AH calls pfkey_dump_sadb(), reports ENOMEM on NULL");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_SHOW_SA;
	req.ac_proto = ADMIN_PROTO_AH;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != ENOMEM)
		TEST_FAIL("reply ac_errno was not ENOMEM");
	if (admin_test_pfkey_dump_sadb_calls != 1)
		TEST_FAIL("pfkey_dump_sadb() was not called");

	TEST_PASS();
	return 0;
}

static int
test_show_sa_internal_unsupported(void)
{
	struct admin_com req;

	TEST_START("ADMIN_SHOW_SA/INTERNAL reports ENOTSUP without touching any dump function");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_SHOW_SA;
	req.ac_proto = ADMIN_PROTO_INTERNAL;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != ENOTSUP)
		TEST_FAIL("reply ac_errno was not ENOTSUP");
	if (admin_test_dumpph1_calls != 0 || admin_test_pfkey_dump_sadb_calls != 0)
		TEST_FAIL("a dump function was called for an unsupported proto");

	TEST_PASS();
	return 0;
}

static int
test_get_sa_cert_non_isakmp_rejected(void)
{
	struct req_with_ndx req;

	TEST_START("ADMIN_GET_SA_CERT rejects a non-ISAKMP proto without calling getph1()");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.com.ac_len = sizeof(req);
	req.com.ac_cmd = ADMIN_GET_SA_CERT;
	req.com.ac_proto = ADMIN_PROTO_AH;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != ENOTSUP)
		TEST_FAIL("reply ac_errno was not ENOTSUP");
	if (admin_test_getph1_calls != 0)
		TEST_FAIL("getph1() was called despite the non-ISAKMP proto rejection");

	TEST_PASS();
	return 0;
}

static int
test_get_sa_cert_no_matching_ph1(void)
{
	struct req_with_ndx req;

	TEST_START("ADMIN_GET_SA_CERT/ISAKMP reports ENOENT when no ph1 matches");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.com.ac_len = sizeof(req);
	req.com.ac_cmd = ADMIN_GET_SA_CERT;
	req.com.ac_proto = ADMIN_PROTO_ISAKMP;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != ENOENT)
		TEST_FAIL("reply ac_errno was not ENOENT");
	if (admin_test_getph1_calls != 1)
		TEST_FAIL("getph1() was not called exactly once");

	TEST_PASS();
	return 0;
}

static int
test_flush_sa_isakmp(void)
{
	struct admin_com req;

	TEST_START("ADMIN_FLUSH_SA/ISAKMP calls flushph1()");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_FLUSH_SA;
	req.ac_proto = ADMIN_PROTO_ISAKMP;

	dispatch_and_get_reply_errno(&req, sizeof(req), NULL);

	if (admin_test_flushph1_calls != 1)
		TEST_FAIL("flushph1() was not called exactly once");
	if (admin_test_pfkey_flush_sadb_calls != 0)
		TEST_FAIL("pfkey_flush_sadb() was called for an ISAKMP flush");

	TEST_PASS();
	return 0;
}

static int
test_flush_sa_ah(void)
{
	struct admin_com req;

	TEST_START("ADMIN_FLUSH_SA/AH calls pfkey_flush_sadb()");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_FLUSH_SA;
	req.ac_proto = ADMIN_PROTO_AH;

	dispatch_and_get_reply_errno(&req, sizeof(req), NULL);

	if (admin_test_pfkey_flush_sadb_calls != 1)
		TEST_FAIL("pfkey_flush_sadb() was not called exactly once");
	if (admin_test_flushph1_calls != 0)
		TEST_FAIL("flushph1() was called for an AH flush");

	TEST_PASS();
	return 0;
}

static int
test_flush_sa_internal_unsupported(void)
{
	struct admin_com req;

	TEST_START("ADMIN_FLUSH_SA/INTERNAL reports ENOTSUP");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_FLUSH_SA;
	req.ac_proto = ADMIN_PROTO_INTERNAL;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != ENOTSUP)
		TEST_FAIL("reply ac_errno was not ENOTSUP");

	TEST_PASS();
	return 0;
}

static int
test_delete_sa(void)
{
	struct req_with_ndx req;

	TEST_START("ADMIN_DELETE_SA calls enumph1() and remcontacted()");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.com.ac_len = sizeof(req);
	req.com.ac_cmd = ADMIN_DELETE_SA;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != 0)
		TEST_FAIL("reply ac_errno was not 0");
	if (admin_test_enumph1_calls != 1)
		TEST_FAIL("enumph1() was not called exactly once");
	if (admin_test_remcontacted_calls != 1)
		TEST_FAIL("remcontacted() was not called exactly once");

	TEST_PASS();
	return 0;
}

#ifdef ENABLE_HYBRID
static int
test_logout_user(void)
{
	struct {
		struct admin_com com;
		char user[16];
	} req;
	const char *name = "testuser";

	TEST_START("ADMIN_LOGOUT_USER calls purgeph1bylogin() (ENABLE_HYBRID)");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	memcpy(req.user, name, strlen(name));
	req.com.ac_len = sizeof(req.com) + strlen(name);
	req.com.ac_cmd = ADMIN_LOGOUT_USER;

	dispatch_and_get_reply_errno(&req, sizeof(req), NULL);

	if (admin_test_purgeph1bylogin_calls != 1)
		TEST_FAIL("purgeph1bylogin() was not called exactly once");

	TEST_PASS();
	return 0;
}
#endif

static int
test_establish_sa_isakmp_no_rmconf(void)
{
	struct req_with_ndx req;

	TEST_START("ADMIN_ESTABLISH_SA/ISAKMP: no rmconf found leaves l_ac_errno at -1");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.com.ac_len = sizeof(req);
	req.com.ac_cmd = ADMIN_ESTABLISH_SA;
	req.com.ac_proto = ADMIN_PROTO_ISAKMP;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != -1)
		TEST_FAIL("reply ac_errno was not -1");
	if (admin_test_getph1_calls != 1)
		TEST_FAIL("getph1() was not called to check for an existing connection");
	if (admin_test_getrmconf_calls != 1)
		TEST_FAIL("getrmconf() was not called exactly once");

	TEST_PASS();
	return 0;
}

static int
test_establish_sa_ah_no_policy(void)
{
	struct req_with_ndx req;

	TEST_START("ADMIN_ESTABLISH_SA/AH: no outbound policy reports ENOENT");

	reset_all_stub_state();
	memset(&req, 0, sizeof(req));
	req.com.ac_len = sizeof(req);
	req.com.ac_cmd = ADMIN_ESTABLISH_SA;
	req.com.ac_proto = ADMIN_PROTO_AH;

	if (dispatch_and_get_reply_errno(&req, sizeof(req), NULL) != ENOENT)
		TEST_FAIL("reply ac_errno was not ENOENT");
	if (admin_test_getsp_r_calls != 1)
		TEST_FAIL("getsp_r() was not called exactly once");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	signal(SIGPIPE, SIG_IGN);

	printf("\n=== admin_process() dispatch coverage test ===\n");

	if (test_show_sched() != 0)
		failed++;
	if (test_show_evt_version_zero_dumps_directly() != 0)
		failed++;
	if (test_show_evt_versioned_subscribes_via_shared_tail() != 0)
		failed++;
	if (test_show_sa_isakmp() != 0)
		failed++;
	if (test_show_sa_ah() != 0)
		failed++;
	if (test_show_sa_internal_unsupported() != 0)
		failed++;
	if (test_get_sa_cert_non_isakmp_rejected() != 0)
		failed++;
	if (test_get_sa_cert_no_matching_ph1() != 0)
		failed++;
	if (test_flush_sa_isakmp() != 0)
		failed++;
	if (test_flush_sa_ah() != 0)
		failed++;
	if (test_flush_sa_internal_unsupported() != 0)
		failed++;
	if (test_delete_sa() != 0)
		failed++;
#ifdef ENABLE_HYBRID
	if (test_logout_user() != 0)
		failed++;
#endif
	if (test_establish_sa_isakmp_no_rmconf() != 0)
		failed++;
	if (test_establish_sa_ah_no_policy() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
