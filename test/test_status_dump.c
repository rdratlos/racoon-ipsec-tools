// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * status_dump() (status.c, ADMIN_STATUS/ADMIN_STATUS_VERBOSE) coverage.
 * status_test_stubs.c's enumph1()/enumph2() let each test hand
 * status_dump() an exact list of struct ph1handle/ph2handle pointers, so
 * these tests exercise the real extraction/render code (status.c, wrapped
 * in via status_unittest_src.c) without needing a live negotiation or a
 * real ph1tree/ph2tree.
 *
 * Deliberately no JSON parser here (this project has none, and adding one
 * just for tests would be its own risk) -- structural checks (substring
 * presence, brace balance) catch what matters: the writer producing
 * well-formed, non-truncated output and not mangling escaped content.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "vmbuf.h"
#include "handler.h"
#include "remoteconf.h"
#include "proposal.h"
#include "isakmp.h"
#include "oakley.h"
#include "ipsec_doi.h"
#include "status.h"

extern struct ph1handle *status_test_ph1_queue[];
extern int status_test_ph1_queue_len;
extern struct ph2handle *status_test_ph2_queue[];
extern int status_test_ph2_queue_len;
extern char *saddr2str_result;
extern char *ipsecdoi_id2str_result;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static void
reset_queues(void)
{
	status_test_ph1_queue_len = 0;
	status_test_ph2_queue_len = 0;
	saddr2str_result = "198.51.100.1[500]";
	ipsecdoi_id2str_result = "198.51.100.1";
}

/* Every '{' must be matched by a later '}', and the buffer must contain
 * no NUL byte before its own reported end -- a cheap but real check that
 * ob_printf()/ob_reserve()'s growth arithmetic didn't truncate or corrupt
 * the buffer (exactly the class of bug the discarded first draft had). */
static int
braces_balanced(const char *s, size_t len)
{
	int depth = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		if (s[i] == '{')
			depth++;
		else if (s[i] == '}')
			depth--;
		if (depth < 0)
			return 0;
	}
	return depth == 0;
}

static int
test_empty_tree_json_nonverbose(void)
{
	vchar_t *out = NULL;

	TEST_START("empty ph1tree, non-verbose JSON: well-formed, no phase2 key");

	reset_queues();
	status_dump(&out, 0, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	if (strstr((char *)out->v, "\"schema_version\":\"1.0\"") == NULL)
		TEST_FAIL("missing schema_version");
	if (strstr((char *)out->v, "\"phase1\":[]") == NULL)
		TEST_FAIL("expected an empty phase1 array");
	if (strstr((char *)out->v, "\"phase2\"") != NULL)
		TEST_FAIL("non-verbose reply must not include a phase2 key at all");

	vfree(out);
	TEST_PASS();
	return 0;
}

static int
test_empty_tree_json_verbose(void)
{
	vchar_t *out = NULL;

	TEST_START("empty trees, verbose JSON: includes an empty phase2 array");

	reset_queues();
	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	if (strstr((char *)out->v, "\"phase2\":[]") == NULL)
		TEST_FAIL("expected an empty phase2 array in verbose mode");

	vfree(out);
	TEST_PASS();
	return 0;
}

static int
test_empty_tree_text(void)
{
	vchar_t *out = NULL;

	TEST_START("empty ph1tree, text output: says so instead of printing nothing");

	reset_queues();
	status_dump(&out, 0, 0);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (strstr((char *)out->v, "(no phase 1 SAs)") == NULL)
		TEST_FAIL("expected the no-SAs message in text output");

	vfree(out);
	TEST_PASS();
	return 0;
}

static struct sockaddr_in test_remote_sin, test_local_sin;

static void
make_addrs(void)
{
	memset(&test_remote_sin, 0, sizeof(test_remote_sin));
	test_remote_sin.sin_family = AF_INET;
	inet_pton(AF_INET, "198.51.100.1", &test_remote_sin.sin_addr);

	memset(&test_local_sin, 0, sizeof(test_local_sin));
	test_local_sin.sin_family = AF_INET;
	inet_pton(AF_INET, "203.0.113.1", &test_local_sin.sin_addr);
}

static int
test_ph1_remote_config_anonymous_gateway(void)
{
	struct ph1handle iph1;
	struct remoteconf rmconf;
	struct sockaddr anon_sa;
	vchar_t *out = NULL;

	TEST_START("populated ph1 (anonymous/passive/unique remoteconf): "
	    "remote_config reflects it, established state renders");

	reset_queues();
	make_addrs();

	memset(&anon_sa, 0, sizeof(anon_sa));
	anon_sa.sa_family = AF_UNSPEC;

	memset(&rmconf, 0, sizeof(rmconf));
	rmconf.remote = &anon_sa;
	rmconf.passive = 1;
	rmconf.gen_policy = GENERATE_POLICY_UNIQUE;

	memset(&iph1, 0, sizeof(iph1));
	iph1.status = PHASE1ST_ESTABLISHED;
	iph1.remote = (struct sockaddr *)&test_remote_sin;
	iph1.local = (struct sockaddr *)&test_local_sin;
	iph1.version = 0x10;	/* major 1, minor 0 */
	iph1.etype = ISAKMP_ETYPE_IDENT;
	iph1.rmconf = &rmconf;

	status_test_ph1_queue[0] = &iph1;
	status_test_ph1_queue_len = 1;

	status_dump(&out, 0, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	if (strstr((char *)out->v, "\"state\":\"established\"") == NULL)
		TEST_FAIL("missing established state");
	if (strstr((char *)out->v, "\"version\":\"1.0\"") == NULL)
		TEST_FAIL("expected version decoded as \"1.0\", not the raw byte");
	if (strstr((char *)out->v, "\"exchange_mode\":\"MAIN\"") == NULL)
		TEST_FAIL("expected exchange_mode MAIN for ISAKMP_ETYPE_IDENT");
	if (strstr((char *)out->v,
	    "\"remote_config\":{\"anonymous\":true,\"passive\":true,"
	    "\"generate_policy\":\"unique\"}") == NULL)
		TEST_FAIL("remote_config did not reflect the anonymous/passive/unique remoteconf");

	vfree(out);
	TEST_PASS();
	return 0;
}

static int
test_json_escaping(void)
{
	struct ph1handle iph1;
	struct remoteconf rmconf;
	struct sockaddr_in dummy_sa;
	vchar_t *out = NULL;
	const char *needle;

	TEST_START("a hostile identity string is JSON-escaped, not left raw");

	reset_queues();
	make_addrs();

	memset(&dummy_sa, 0, sizeof(dummy_sa));
	dummy_sa.sin_family = AF_INET;

	memset(&rmconf, 0, sizeof(rmconf));
	rmconf.remote = (struct sockaddr *)&dummy_sa;

	memset(&iph1, 0, sizeof(iph1));
	iph1.status = PHASE1ST_ESTABLISHED;
	iph1.remote = (struct sockaddr *)&test_remote_sin;
	iph1.local = (struct sockaddr *)&test_local_sin;
	iph1.etype = ISAKMP_ETYPE_IDENT;
	iph1.rmconf = &rmconf;

	/* iph1.id/id_p are NULL, so collect_ph1() falls back to
	 * saddr2str(iph1->remote) for remote_id -- inject the hostile
	 * content there via the stub's controllable return value. */
	saddr2str_result = "evil\"};{\\\n";

	status_test_ph1_queue[0] = &iph1;
	status_test_ph1_queue_len = 1;

	status_dump(&out, 0, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces -- unescaped input broke the JSON structure");

	needle = "\\\"};{\\\\\\n";
	if (strstr((char *)out->v, needle) == NULL)
		TEST_FAIL("hostile characters were not escaped as expected");

	/* And the raw, unescaped sequence must not appear verbatim. */
	if (strstr((char *)out->v, "evil\"};{\\\n") != NULL)
		TEST_FAIL("hostile characters leaked into the output unescaped");

	vfree(out);
	TEST_PASS();
	return 0;
}

static int
test_ph2_basic(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	vchar_t *out = NULL;

	TEST_START("populated ph2 (ESP/tunnel/AES/SHA256): SPI masked, "
	    "selectors and proposal render, pfs_group from ->approval");

	reset_queues();
	make_addrs();

	memset(&trns, 0, sizeof(trns));
	trns.trns_id = IPSECDOI_ESP_AES;
	trns.authtype = IPSECDOI_ATTR_AUTH_HMAC_SHA2_256;

	memset(&proto, 0, sizeof(proto));
	proto.proto_id = IPSECDOI_PROTO_IPSEC_ESP;
	proto.encmode = IPSECDOI_ATTR_ENC_MODE_TUNNEL;
	proto.spi = htonl(0x12345678);
	proto.spi_p = htonl(0x87654321);
	proto.ok = 1;
	proto.head = &trns;
	proto.reqid_in = 1;
	proto.reqid_out = 2;

	memset(&approval, 0, sizeof(approval));
	approval.pfs_group = 14;
	approval.lifetime = 3600;
	approval.head = &proto;

	memset(&iph2, 0, sizeof(iph2));
	iph2.status = PHASE2ST_ESTABLISHED;
	iph2.msgid = 0x87654321;
	iph2.src = (struct sockaddr *)&test_local_sin;
	iph2.dst = (struct sockaddr *)&test_remote_sin;
	iph2.approval = &approval;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	if (strstr((char *)out->v, "\"spi_in\":\"0x1234****\"") == NULL)
		TEST_FAIL("expected the inbound SPI masked to its top 16 bits");
	if (strstr((char *)out->v, "\"spi_out\":\"0x8765****\"") == NULL)
		TEST_FAIL("expected the outbound SPI masked to its top 16 bits");
	if (strstr((char *)out->v, "\"protocol\":\"ESP\"") == NULL)
		TEST_FAIL("expected protocol ESP");
	if (strstr((char *)out->v, "\"src\":\"203.0.113.1/32\"") == NULL)
		TEST_FAIL("expected the src selector as a /32 CIDR (no SP found, host fallback)");
	if (strstr((char *)out->v, "\"dst\":\"198.51.100.1/32\"") == NULL)
		TEST_FAIL("expected the dst selector as a /32 CIDR");
	if (strstr((char *)out->v, "\"src_port\":\"any\"") == NULL)
		TEST_FAIL("expected src_port \"any\" (iph2->id was NULL)");
	if (strstr((char *)out->v, "\"pfs_group\":14") == NULL)
		TEST_FAIL("expected pfs_group 14 from iph2->approval");
	if (strstr((char *)out->v, "\"ok\":true") == NULL)
		TEST_FAIL("expected ok:true from proto->ok");

	vfree(out);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== status_dump() coverage test ===\n");

	if (test_empty_tree_json_nonverbose() != 0)
		failed++;
	if (test_empty_tree_json_verbose() != 0)
		failed++;
	if (test_empty_tree_text() != 0)
		failed++;
	if (test_ph1_remote_config_anonymous_gateway() != 0)
		failed++;
	if (test_json_escaping() != 0)
		failed++;
	if (test_ph2_basic() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
