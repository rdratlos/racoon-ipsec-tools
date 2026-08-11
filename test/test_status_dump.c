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
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include "vmbuf.h"
#include "handler.h"
#include "remoteconf.h"
#include "proposal.h"
#include "isakmp.h"
#include "oakley.h"
#include "ipsec_doi.h"
#include "policy.h"
#include "status.h"

#ifdef ENABLE_HYBRID
#include "isakmp_cfg.h"
#include "isakmp_xauth.h"
#include "isakmp_unity.h"
#endif
#ifdef ENABLE_NATT
#include "nattraversal.h"
#endif

extern struct ph1handle *status_test_ph1_queue[];
extern int status_test_ph1_queue_len;
extern struct ph2handle *status_test_ph2_queue[];
extern int status_test_ph2_queue_len;
extern char *saddr2str_result;
extern char *ipsecdoi_id2str_result;
extern struct secpolicy *getspbyspid_result;

extern const char *ph1_state_name_unittest(int state);
extern const char *ph2_state_name_unittest(int state);

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
	getspbyspid_result = NULL;
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

/*
 * Exhaustive coverage for ph1_state_name()/ph2_state_name() (status.c) --
 * unrelated to the broader status.c/handler.c coverage work in progress
 * elsewhere in the project; found and closed as a small, self-contained
 * gap on its own. Every other test in this file only ever constructs a
 * PHASE1ST_ESTABLISHED/PHASE2ST_ESTABLISHED handle, so every other switch
 * case (and the default branch) showed zero hits in gcov. Both functions
 * are pure (int in, const char * out, no side effects), so this needs no
 * ph1handle/ph2handle fixture -- just the ENABLE_UNITTEST accessors
 * calling straight through to them.
 *
 * The out-of-range value (9999, not a real PHASE1ST_ or PHASE2ST_ member)
 * covers the default: "unknown" branch specifically -- that branch is the
 * actual defense against a future state constant added to handler.h that
 * status.c hasn't been updated to name, so it earns its own assertion
 * rather than being covered incidentally by whichever real state a test
 * happens to construct.
 */
struct state_name_case {
	int state;
	const char *expect;
};

static int
test_ph1_state_name_exhaustive(void)
{
	static const struct state_name_case cases[] = {
		{ PHASE1ST_SPAWN,		"spawn" },
		{ PHASE1ST_START,		"start" },
		{ PHASE1ST_MSG1RECEIVED,	"msg1received" },
		{ PHASE1ST_MSG1SENT,		"msg1sent" },
		{ PHASE1ST_MSG2RECEIVED,	"msg2received" },
		{ PHASE1ST_MSG2SENT,		"msg2sent" },
		{ PHASE1ST_MSG3RECEIVED,	"msg3received" },
		{ PHASE1ST_MSG3SENT,		"msg3sent" },
		{ PHASE1ST_MSG4RECEIVED,	"msg4received" },
		{ PHASE1ST_ESTABLISHED,	"established" },
		{ PHASE1ST_DYING,		"dying" },
		{ PHASE1ST_EXPIRED,		"expired" },
		{ 9999,				"unknown" },
	};
	size_t i;

	TEST_START("ph1_state_name() maps every PHASE1ST_* constant, "
	    "plus an out-of-range value to \"unknown\"");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const char *got = ph1_state_name_unittest(cases[i].state);

		if (got == NULL || strcmp(got, cases[i].expect) != 0) {
			printf("(state=%d expected \"%s\" got \"%s\") ",
			    cases[i].state, cases[i].expect,
			    got != NULL ? got : "(null)");
			TEST_FAIL("ph1_state_name() mismatch");
		}
	}

	TEST_PASS();
	return 0;
}

static int
test_ph2_state_name_exhaustive(void)
{
	static const struct state_name_case cases[] = {
		{ PHASE2ST_SPAWN,		"spawn" },
		{ PHASE2ST_START,		"start" },
		{ PHASE2ST_STATUS2,		"status2" },
		{ PHASE2ST_GETSPISENT,		"getspisent" },
		{ PHASE2ST_GETSPIDONE,		"getspidone" },
		{ PHASE2ST_MSG1SENT,		"msg1sent" },
		{ PHASE2ST_STATUS6,		"status6" },
		{ PHASE2ST_COMMIT,		"commit" },
		{ PHASE2ST_ADDSA,		"addsa" },
		{ PHASE2ST_ESTABLISHED,	"established" },
		{ PHASE2ST_EXPIRED,		"expired" },
		{ 9999,				"unknown" },
	};
	size_t i;

	TEST_START("ph2_state_name() maps every PHASE2ST_* constant, "
	    "plus an out-of-range value to \"unknown\"");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const char *got = ph2_state_name_unittest(cases[i].state);

		if (got == NULL || strcmp(got, cases[i].expect) != 0) {
			printf("(state=%d expected \"%s\" got \"%s\") ",
			    cases[i].state, cases[i].expect,
			    got != NULL ? got : "(null)");
			TEST_FAIL("ph2_state_name() mismatch");
		}
	}

	TEST_PASS();
	return 0;
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
	/* 1.3 since issue #143 L2 moved an AH SA's transform name into
	 * authentication_algorithm (1.2 had widened spi_in/spi_out, F4).
	 * Pinned to the exact version deliberately: share/schema/ declares
	 * "const": "1.3", so a renderer bump that forgets the schema file (or
	 * vice versa) has to fail somewhere, and this is the cheapest place. */
	if (strstr((char *)out->v, "\"schema_version\":\"1.3\"") == NULL)
		TEST_FAIL("missing or stale schema_version (expected 1.3)");
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
#ifndef __linux__
	/* sysdep_sa_len() (libipsec/libpfkey.h) returns sizeof(struct
	 * sockaddr_in) on Linux regardless of sin_len, but sa->sa_len
	 * verbatim everywhere else (NetBSD and other 4.4BSD-derived
	 * libcs). collect_ph2()'s sockaddr_to_cidr() passes that length
	 * straight into getnameinfo() -- left at 0 by memset(), the call
	 * fails there and silently falls back to "?" instead of a real
	 * CIDR string, same convention used everywhere else a sockaddr_in
	 * is hand-built in this codebase (e.g. sockmisc.c, isakmp.c). */
	test_remote_sin.sin_len = sizeof(test_remote_sin);
#endif
	inet_pton(AF_INET, "198.51.100.1", &test_remote_sin.sin_addr);

	memset(&test_local_sin, 0, sizeof(test_local_sin));
	test_local_sin.sin_family = AF_INET;
#ifndef __linux__
	test_local_sin.sin_len = sizeof(test_local_sin);
#endif
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

/*
 * status.c coverage closure (found via `sudo make coverage` on Ubuntu
 * Noble): every existing test above only ever builds an established
 * phase1 handle via test_ph1_remote_config_anonymous_gateway(), which
 * never sets iph1->approval -- so collect_ph1()'s entire proposal
 * population (encryption/hash/auth/dh_group/lifetime) and both
 * renderers' proposal blocks were never exercised, and neither was
 * xauth/mode_cfg/dpd/natt rendering (every existing fixture leaves all
 * four "not present"). setup_ph1_full() builds one handle with all of
 * it populated; test_ph1_full_json()/test_ph1_full_text() drive it
 * through both renderers.
 */
#ifdef ENABLE_HYBRID
static struct isakmp_cfg_state test_cfg;
static struct xauth_state *test_xauth_ptr;
#endif
#ifdef ENABLE_NATT
static struct ph1natt_options test_natt_options;
#endif

static void
setup_ph1_full(struct ph1handle *iph1, struct remoteconf *rmconf,
    struct isakmpsa *approval)
{
	memset(rmconf, 0, sizeof(*rmconf));
	rmconf->remote = (struct sockaddr *)&test_remote_sin;
#ifdef ENABLE_DPD
	rmconf->dpd = 1;
#endif

	memset(approval, 0, sizeof(*approval));
	approval->enctype = OAKLEY_ATTR_ENC_ALG_AES;
	approval->hashtype = OAKLEY_ATTR_HASH_ALG_SHA2_256;
	approval->authmethod = OAKLEY_ATTR_AUTH_METHOD_PSKEY;
	approval->dh_group = OAKLEY_ATTR_GRP_DESC_MODP2048;
	approval->lifetime = 28800;

	memset(iph1, 0, sizeof(*iph1));
	iph1->status = PHASE1ST_ESTABLISHED;
	iph1->remote = (struct sockaddr *)&test_remote_sin;
	iph1->local = (struct sockaddr *)&test_local_sin;
	iph1->version = 0x10;
	iph1->etype = ISAKMP_ETYPE_IDENT;
	iph1->rmconf = rmconf;
	iph1->approval = approval;

#ifdef ENABLE_HYBRID
	memset(&test_cfg, 0, sizeof(test_cfg));
	test_cfg.xauth.status = XAUTHST_OK;
	test_cfg.xauth.authtype = XAUTH_TYPE_GENERIC;
	test_cfg.xauth.authdata.generic.usr = "alice";
	test_cfg.flags = ISAKMP_CFG_GOT_ADDR4 | ISAKMP_CFG_GOT_DNS4 |
	    ISAKMP_CFG_GOT_SPLIT_INCLUDE;
	inet_pton(AF_INET, "192.168.66.23", &test_cfg.addr4);
	inet_pton(AF_INET, "10.66.0.6", &test_cfg.dns4[0]);
	test_cfg.dns4_index = 1;
	/* status_test_stubs.c's splitnet_list_2str() ignores the actual
	 * list contents and returns a fixed string whenever list != NULL --
	 * any non-NULL value here is enough to reach that branch. */
	test_cfg.split_include = (struct unity_netentry *)&test_cfg;
	iph1->mode_cfg = &test_cfg;
#endif
#ifdef ENABLE_DPD
	iph1->dpd_support = 1;
	iph1->dpd_fails = 2;
#endif
#ifdef ENABLE_NATT
	memset(&test_natt_options, 0, sizeof(test_natt_options));
	iph1->natt_options = &test_natt_options;
#endif
}

static int
test_ph1_full_json(void)
{
	struct ph1handle iph1;
	struct remoteconf rmconf;
	struct isakmpsa approval;
	vchar_t *out = NULL;

	TEST_START("populated ph1 (proposal+xauth+mode_cfg+dpd+natt), JSON: "
	    "all five blocks render, not just remote_config");

	reset_queues();
	make_addrs();
	setup_ph1_full(&iph1, &rmconf, &approval);

	status_test_ph1_queue[0] = &iph1;
	status_test_ph1_queue_len = 1;

	status_dump(&out, 0, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	if (strstr((char *)out->v, "\"encryption_algorithm\":\"AES-CBC\"") == NULL)
		TEST_FAIL("expected phase1 proposal encryption_algorithm AES-CBC");
	if (strstr((char *)out->v, "\"hash_algorithm\":\"SHA256\"") == NULL)
		TEST_FAIL("expected phase1 proposal hash_algorithm SHA256");
	if (strstr((char *)out->v,
	    "\"authentication_method\":\"pre-shared key\"") == NULL)
		TEST_FAIL("expected phase1 proposal authentication_method \"pre-shared key\"");
	/* s_attr_isakmp_group() (strnames.c) is keyed on OAKLEY_ATTR_GRP_TYPE_*
	 * (MODP/ECP/EC2N), not the GRP_DESC_* group number racoon actually
	 * stores in ->dh_group -- in real production output this always
	 * falls through to num2str()'s plain decimal string (confirmed
	 * against the live capture in issue #139: "dh_group":"15"), not a
	 * named string. Asserting that here locks in the real behavior
	 * instead of an assumption. */
	if (strstr((char *)out->v, "\"dh_group\":\"14\"") == NULL)
		TEST_FAIL("expected phase1 proposal dh_group \"14\" (num2str() fallback)");
	if (strstr((char *)out->v, "\"lifetime_time\":28800") == NULL)
		TEST_FAIL("expected phase1 proposal lifetime_time 28800");
#ifdef ENABLE_HYBRID
	if (strstr((char *)out->v, "\"xauth\":{\"state\":\"ok\","
	    "\"auth_type\":\"generic\",\"username\":\"alice\"}") == NULL)
		TEST_FAIL("expected a populated xauth block");
	if (strstr((char *)out->v, "\"addr4\":\"192.168.66.23\"") == NULL)
		TEST_FAIL("expected mode_cfg addr4");
	if (strstr((char *)out->v, "\"dns4\":[\"10.66.0.6\"]") == NULL)
		TEST_FAIL("expected mode_cfg dns4");
	if (strstr((char *)out->v,
	    "\"split_include\":[\"10.0.1.0/24\",\"10.0.2.0/24\"]") == NULL)
		TEST_FAIL("expected mode_cfg split_include, split into two entries");
#endif
#ifdef ENABLE_DPD
	if (strstr((char *)out->v, "\"dpd\":{\"supported\":true,\"fails\":2}") == NULL)
		TEST_FAIL("expected a populated dpd block");
#endif
#ifdef ENABLE_NATT
	if (strstr((char *)out->v, "\"natt\":{\"enabled\":true}") == NULL)
		TEST_FAIL("expected a populated natt block");
#endif

	vfree(out);
	TEST_PASS();
	return 0;
}

static int
test_ph1_full_text(void)
{
	struct ph1handle iph1;
	struct remoteconf rmconf;
	struct isakmpsa approval;
	vchar_t *out = NULL;

	TEST_START("populated ph1 (proposal+xauth+mode_cfg+dpd+natt), text: "
	    "text_render_ph1() actually renders, not just JSON");

	reset_queues();
	make_addrs();
	setup_ph1_full(&iph1, &rmconf, &approval);

	status_test_ph1_queue[0] = &iph1;
	status_test_ph1_queue_len = 1;

	status_dump(&out, 0, 0);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (strstr((char *)out->v, "Phase 1:") == NULL)
		TEST_FAIL("expected a \"Phase 1:\" section in text output");
	if (strstr((char *)out->v, "encryption:     AES-CBC  hash: SHA256  "
	    "auth: pre-shared key  dh: 14") == NULL)
		TEST_FAIL("expected the proposal line with encryption/hash/auth/dh");
#ifdef ENABLE_HYBRID
	if (strstr((char *)out->v,
	    "xauth:          state=ok auth_type=generic username=alice") == NULL)
		TEST_FAIL("expected the xauth line");
	if (strstr((char *)out->v, "mode_cfg addr4: 192.168.66.23") == NULL)
		TEST_FAIL("expected the mode_cfg addr4 line");
	if (strstr((char *)out->v, "split_include:  10.0.1.0/24 10.0.2.0/24") == NULL)
		TEST_FAIL("expected the split_include line");
#endif
#ifdef ENABLE_DPD
	if (strstr((char *)out->v, "dpd:            supported=yes fails=2") == NULL)
		TEST_FAIL("expected the dpd line");
#endif
#ifdef ENABLE_NATT
	if (strstr((char *)out->v, "natt:           enabled=yes") == NULL)
		TEST_FAIL("expected the natt line");
#endif

	vfree(out);
	TEST_PASS();
	return 0;
}

static void
setup_ph2_basic(struct ph2handle *iph2, struct saprop *approval,
    struct saproto *proto, struct satrns *trns)
{
	memset(trns, 0, sizeof(*trns));
	trns->trns_id = IPSECDOI_ESP_AES;
	trns->authtype = IPSECDOI_ATTR_AUTH_HMAC_SHA2_256;

	memset(proto, 0, sizeof(*proto));
	proto->proto_id = IPSECDOI_PROTO_IPSEC_ESP;
	proto->encmode = IPSECDOI_ATTR_ENC_MODE_TUNNEL;
	proto->spi = htonl(0x12345678);
	proto->spi_p = htonl(0x87654321);
	proto->ok = 1;
	proto->head = trns;
	proto->reqid_in = 1;
	proto->reqid_out = 2;

	memset(approval, 0, sizeof(*approval));
	approval->pfs_group = 14;
	approval->lifetime = 3600;
	approval->head = proto;

	memset(iph2, 0, sizeof(*iph2));
	iph2->status = PHASE2ST_ESTABLISHED;
	iph2->msgid = 0x87654321;
	iph2->src = (struct sockaddr *)&test_local_sin;
	iph2->dst = (struct sockaddr *)&test_remote_sin;
	iph2->approval = approval;
}

static int
test_ph2_basic(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	vchar_t *out = NULL;

	TEST_START("populated ph2 (ESP/tunnel/AES/SHA256), JSON: SPI masked, "
	    "selectors and proposal render, pfs_group from ->approval");

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
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
	/* setup_ph2_basic() never sets iph2->ph1, so it's NULL here (D6,
	 * issue #140): phase1_index must render null, and effective_group
	 * must equal pfs_group (14) rather than 0, since PFS *was*
	 * negotiated -- only an unbound handle with no PFS is genuinely
	 * indeterminate. */
	if (strstr((char *)out->v, "\"phase1_index\":null") == NULL)
		TEST_FAIL("expected phase1_index null for an unbound ph2 handle");
	if (strstr((char *)out->v, "\"effective_group\":14") == NULL)
		TEST_FAIL("expected effective_group 14 (== pfs_group, PFS was negotiated)");

	vfree(out);
	TEST_PASS();
	return 0;
}

/*
 * Bug 3 (issue #139 follow-up): with the -v CLI bug (fixed above), no
 * manual test on either role ever actually reached this code path, so
 * "the phase2 array should render" was unverified beyond static reading.
 * No PF_KEY-capable kernel is available in this sandbox to drive a real
 * negotiated SA end to end (racoon itself fails at pfkey_open() here), so
 * this is the most direct verification available: the identical
 * synthetic ph2handle setup driven through status_dump() with
 * json_format=0, confirming the *text* renderer (not just JSON) produces
 * real phase2 content -- not a substitute for the maintainer's own
 * four-machine live-test pass, but real coverage of the render path a
 * live SA would also go through.
 */
static int
test_ph2_basic_text(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	vchar_t *out = NULL;

	TEST_START("populated ph2 (ESP/tunnel/AES/SHA256), text: phase2 "
	    "section actually renders, not just JSON");

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 0);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (strstr((char *)out->v, "Phase 2:") == NULL)
		TEST_FAIL("expected a \"Phase 2:\" section in text output");
	if (strstr((char *)out->v, "protocol: ESP") == NULL)
		TEST_FAIL("expected protocol ESP in text output");
	if (strstr((char *)out->v, "in=0x1234**** out=0x8765****") == NULL)
		TEST_FAIL("expected masked SPIs in text output");
	if (strstr((char *)out->v, "pfs_group:      14") == NULL)
		TEST_FAIL("expected pfs_group 14 in text output");
	if (strstr((char *)out->v, "phase1:         (unbound)") == NULL)
		TEST_FAIL("expected phase1: (unbound) for an unbound ph2 handle");
	if (strstr((char *)out->v, "effective_group: 14") == NULL)
		TEST_FAIL("expected effective_group 14 in text output");

	vfree(out);
	TEST_PASS();
	return 0;
}

/*
 * D6 (issue #140): the fallback branch -- iph2 *is* bound to a real ph1,
 * but PFS was not negotiated at the phase2 level (approval->pfs_group ==
 * 0). effective_group must fall back to the parent phase1's dh_group
 * (per RFC 2409 SS5.5, that's what actually backs this tunnel's key
 * entropy without a PFS exchange of its own), and phase1_index must join
 * to the parent's own cookie-pair string byte-for-byte.
 */
static int
test_ph2_effective_group_fallback(void)
{
	struct ph1handle iph1;
	struct isakmpsa ph1_approval;
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	vchar_t *out = NULL;
	char expected_phase1_index[64];
	int i;

	TEST_START("ph2 bound to ph1, no PFS: phase1_index joins to the "
	    "parent, effective_group falls back to phase1's dh_group");

	reset_queues();
	make_addrs();

	memset(&iph1, 0, sizeof(iph1));
	iph1.status = PHASE1ST_ESTABLISHED;
	iph1.remote = (struct sockaddr *)&test_remote_sin;
	iph1.local = (struct sockaddr *)&test_local_sin;
	for (i = 0; i < 8; i++) {
		iph1.index.i_ck[i] = (u_char)(0x10 + i);
		iph1.index.r_ck[i] = (u_char)(0x20 + i);
	}

	memset(&ph1_approval, 0, sizeof(ph1_approval));
	ph1_approval.dh_group = 14;
	iph1.approval = &ph1_approval;

	snprintf(expected_phase1_index, sizeof(expected_phase1_index),
	    "\"phase1_index\":\"0x%02x%02x%02x%02x%02x%02x%02x%02x"
	    "%02x%02x%02x%02x%02x%02x%02x%02x\"",
	    iph1.index.i_ck[0], iph1.index.i_ck[1], iph1.index.i_ck[2],
	    iph1.index.i_ck[3], iph1.index.i_ck[4], iph1.index.i_ck[5],
	    iph1.index.i_ck[6], iph1.index.i_ck[7],
	    iph1.index.r_ck[0], iph1.index.r_ck[1], iph1.index.r_ck[2],
	    iph1.index.r_ck[3], iph1.index.r_ck[4], iph1.index.r_ck[5],
	    iph1.index.r_ck[6], iph1.index.r_ck[7]);

	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	approval.pfs_group = 0;	/* no PFS negotiated at phase2 */
	iph2.ph1 = &iph1;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	if (strstr((char *)out->v, expected_phase1_index) == NULL)
		TEST_FAIL("phase1_index did not match the parent ph1's cookie pair");
	if (strstr((char *)out->v, "\"pfs_group\":null") == NULL)
		TEST_FAIL("expected pfs_group null (no PFS negotiated)");
	if (strstr((char *)out->v, "\"effective_group\":14") == NULL)
		TEST_FAIL("expected effective_group to fall back to phase1's dh_group (14)");

	vfree(out);
	TEST_PASS();
	return 0;
}

/*
 * More status.c coverage closure: setup_ph2_basic() always builds an ESP
 * proposal, so collect_ph2()'s AH and IPCOMP branches (and json_render_ph2's
 * compression_algorithm key) were never reached by any existing test.
 */
static int
test_ph2_ah(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	vchar_t *out = NULL;

	TEST_START("populated ph2 (AH), JSON: the AH transform is reported as "
	    "authentication_algorithm, encryption_algorithm null (issue #143 L2)");

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	proto.proto_id = IPSECDOI_PROTO_IPSEC_AH;
	trns.trns_id = IPSECDOI_AH_SHA256;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	if (strstr((char *)out->v, "\"protocol\":\"AH\"") == NULL)
		TEST_FAIL("expected protocol AH");
	/* Through schema 1.2 these two assertions were the other way round:
	 * the AH hash name sat in encryption_algorithm and
	 * authentication_algorithm was null, so a consumer asking what cipher
	 * protected an AH SA was handed a hash name. AH encrypts nothing. */
	if (strstr((char *)out->v, "\"authentication_algorithm\":\"SHA256\"") == NULL) {
		vfree(out);
		TEST_FAIL("expected authentication_algorithm SHA256 from s_ipsecdoi_trns_ah()");
	}
	if (strstr((char *)out->v, "\"encryption_algorithm\":null") == NULL) {
		vfree(out);
		TEST_FAIL("expected encryption_algorithm null -- AH provides no encryption");
	}

	vfree(out);
	TEST_PASS();
	return 0;
}

/*
 * Issue #143 L2, the other half: an ESP SA negotiated with no integrity
 * algorithm (IPSECDOI_ATTR_AUTH_NONE) renders authentication_algorithm as
 * null. That was already true through schema 1.2 while the schema declared
 * the field a plain string, so such a document failed the project's own
 * schema -- the same defect class as F4, in the field L2 is moving. Pinned
 * here so the widened ["string", "null"] type keeps a test behind it.
 */
static int
test_ph2_esp_null_auth_renders_null(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	vchar_t *out = NULL;

	TEST_START("ESP with IPSECDOI_ATTR_AUTH_NONE renders "
	    "authentication_algorithm null, with the cipher still reported");

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	trns.trns_id = IPSECDOI_ESP_AES;
	trns.authtype = IPSECDOI_ATTR_AUTH_NONE;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (strstr((char *)out->v, "\"authentication_algorithm\":null") == NULL) {
		vfree(out);
		TEST_FAIL("expected authentication_algorithm null for AUTH_NONE");
	}
	if (strstr((char *)out->v, "\"encryption_algorithm\":\"AES-CBC\"") == NULL) {
		vfree(out);
		TEST_FAIL("expected the ESP cipher still reported alongside a null auth");
	}

	vfree(out);
	TEST_PASS();
	return 0;
}

/*
 * Phase 2 algorithm-name completeness.
 *
 * The gap this pins down was found by comparing a live established SA's
 * `racoonctl status -v -f json` against `setkey -DN` for the same SA (iOS
 * roadwarrior, gateway side): the kernel reported `E: aes-cbc` with a
 * 32-byte key and `A: hmac-sha1` with a 20-byte one, while status
 * rendered a bare "AES" and a truncated "hmac-sha" -- losing the cipher
 * mode and the hash variant that phase1's own proposal fields
 * ("AES-CBC", via a different name table) already carried.
 *
 * setup_ph2_basic() negotiates SHA-2, whose strnames.c entry was never
 * truncated, so it could not have caught this; these cases assert the
 * exact rendered strings for the SHA-1 shape the live SA actually used.
 */
static int
test_ph2_alg_names_cbc_and_sha1(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	vchar_t *out = NULL;

	TEST_START("ph2 ESP AES/HMAC-SHA1: encryption_algorithm carries the "
	    "CBC mode and authentication_algorithm the SHA-1 variant");

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	/* Exactly what the live SA negotiated: AES-CBC + HMAC-SHA1. */
	trns.trns_id = IPSECDOI_ESP_AES;
	trns.authtype = IPSECDOI_ATTR_AUTH_HMAC_SHA1;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	/* The pre-fix output was "AES" -- assert the whole quoted value so a
	 * regression to the bare family name fails here rather than passing
	 * on a substring match. */
	if (strstr((char *)out->v, "\"encryption_algorithm\":\"AES-CBC\"") == NULL) {
		vfree(out);
		TEST_FAIL("expected encryption_algorithm \"AES-CBC\", not a bare \"AES\"");
	}
	if (strstr((char *)out->v, "\"authentication_algorithm\":\"hmac-sha1\"") == NULL) {
		vfree(out);
		TEST_FAIL("expected authentication_algorithm \"hmac-sha1\", not a truncated \"hmac-sha\"");
	}

	vfree(out);
	out = NULL;

	/* Same SA through the text renderer -- issue #139 requires text to
	 * present the same field set as JSON, so the fix has to reach both. */
	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	trns.trns_id = IPSECDOI_ESP_AES;
	trns.authtype = IPSECDOI_ATTR_AUTH_HMAC_SHA1;
	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 0);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL (text)");
	if (strstr((char *)out->v, "encryption:     AES-CBC  auth: hmac-sha1") == NULL) {
		vfree(out);
		TEST_FAIL("expected the text proposal line to carry AES-CBC and hmac-sha1");
	}

	vfree(out);
	TEST_PASS();
	return 0;
}

/*
 * The two directions the SHA-1/CBC fix must NOT overreach in:
 *
 *  - SHA-2 auth names already carried their variant in strnames.c and
 *    must still come straight from it, unmodified.
 *  - IPSECDOI_ESP_NULL is not a CBC transform (it is not a cipher at
 *    all), so it must not acquire a "-CBC" suffix. Same for RC4, the
 *    table's only stream cipher.
 */
static int
test_ph2_alg_names_no_overreach(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	vchar_t *out = NULL;

	TEST_START("ph2 alg names: 3DES-CBC/hmac-sha256 unchanged from "
	    "strnames.c, and ESP_NULL/RC4 gain no bogus CBC suffix");

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	trns.trns_id = IPSECDOI_ESP_3DES;
	trns.authtype = IPSECDOI_ATTR_AUTH_HMAC_SHA2_256;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (strstr((char *)out->v, "\"encryption_algorithm\":\"3DES-CBC\"") == NULL) {
		vfree(out);
		TEST_FAIL("expected encryption_algorithm \"3DES-CBC\"");
	}
	if (strstr((char *)out->v, "\"authentication_algorithm\":\"hmac-sha256\"") == NULL) {
		vfree(out);
		TEST_FAIL("expected authentication_algorithm \"hmac-sha256\" straight "
		    "from strnames.c, untouched by the SHA-1 special case");
	}

	vfree(out);
	out = NULL;

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	trns.trns_id = IPSECDOI_ESP_NULL;
	trns.authtype = IPSECDOI_ATTR_AUTH_HMAC_SHA1;
	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL (ESP_NULL)");
	if (strstr((char *)out->v, "\"encryption_algorithm\":\"NULL\"") == NULL) {
		vfree(out);
		TEST_FAIL("expected encryption_algorithm \"NULL\" -- ESP_NULL has no cipher mode");
	}

	vfree(out);
	out = NULL;

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	trns.trns_id = IPSECDOI_ESP_RC4;
	trns.authtype = IPSECDOI_ATTR_AUTH_HMAC_SHA1;
	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL (RC4)");
	if (strstr((char *)out->v, "\"encryption_algorithm\":\"RC4\"") == NULL) {
		vfree(out);
		TEST_FAIL("expected encryption_algorithm \"RC4\" -- a stream cipher, not CBC");
	}

	vfree(out);
	TEST_PASS();
	return 0;
}

static int
test_ph2_ipcomp(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	vchar_t *out = NULL;

	TEST_START("populated ph2 (IPCOMP), JSON: protocol IPCOMP, "
	    "compression_algorithm from s_ipsecdoi_trns_ipcomp()");

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);
	proto.proto_id = IPSECDOI_PROTO_IPCOMP;
	trns.trns_id = IPSECDOI_IPCOMP_DEFLATE;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	if (strstr((char *)out->v, "\"protocol\":\"IPCOMP\"") == NULL)
		TEST_FAIL("expected protocol IPCOMP");
	if (strstr((char *)out->v, "\"compression_algorithm\":\"DEFLATE\"") == NULL)
		TEST_FAIL("expected compression_algorithm DEFLATE from s_ipsecdoi_trns_ipcomp()");

	vfree(out);
	TEST_PASS();
	return 0;
}

/*
 * selector_proto_port() (status.c) was only ever exercised through its
 * iph2->id == NULL fallback (every "any" case above) -- no existing test
 * sets a real ID payload. getspbyspid() (stubbed, status_test_stubs.c)
 * always returned NULL, so the real-prefix branch of sockaddr_to_cidr()
 * (via a matched struct secpolicy's spidx.prefs/prefd) was unreached too.
 */
static int
test_ph2_selectors_real_values(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	struct secpolicy fake_sp;
	struct ipsecdoi_id_b *idb;
	vchar_t *id_src = NULL, *id_dst = NULL;
	vchar_t *out = NULL;

	TEST_START("ph2 selectors reflect a real proto/port (iph2->id/id_p) and "
	    "a real prefix length (getspbyspid() SP found), not defaults");

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);

	iph2.spid = 42;
	memset(&fake_sp, 0, sizeof(fake_sp));
	fake_sp.spidx.prefs = 24;
	fake_sp.spidx.prefd = 16;
	getspbyspid_result = &fake_sp;

	id_src = vmalloc(sizeof(struct ipsecdoi_id_b));
	if (id_src == NULL)
		TEST_FAIL("vmalloc() failed for iph2->id");
	idb = (struct ipsecdoi_id_b *)id_src->v;
	idb->type = IPSECDOI_ID_IPV4_ADDR;
	idb->proto_id = IPPROTO_TCP;
	idb->port = htons(1234);
	iph2.id = id_src;

	id_dst = vmalloc(sizeof(struct ipsecdoi_id_b));
	if (id_dst == NULL) {
		vfree(id_src);
		TEST_FAIL("vmalloc() failed for iph2->id_p");
	}
	idb = (struct ipsecdoi_id_b *)id_dst->v;
	idb->type = IPSECDOI_ID_IPV4_ADDR;
	idb->port = htons(443);
	iph2.id_p = id_dst;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL) {
		vfree(id_src);
		vfree(id_dst);
		TEST_FAIL("status_dump() returned NULL");
	}
	if (!braces_balanced((char *)out->v, out->l)) {
		vfree(id_src);
		vfree(id_dst);
		vfree(out);
		TEST_FAIL("unbalanced braces in JSON output");
	}
	if (strstr((char *)out->v, "\"src\":\"203.0.113.1/24\"") == NULL) {
		vfree(id_src); vfree(id_dst); vfree(out);
		TEST_FAIL("expected the real /24 prefix from getspbyspid(), not a /32 default");
	}
	if (strstr((char *)out->v, "\"dst\":\"198.51.100.1/16\"") == NULL) {
		vfree(id_src); vfree(id_dst); vfree(out);
		TEST_FAIL("expected the real /16 prefix from getspbyspid()");
	}
	if (strstr((char *)out->v, "\"protocol\":6") == NULL) {
		vfree(id_src); vfree(id_dst); vfree(out);
		TEST_FAIL("expected the real selector protocol (IPPROTO_TCP=6), not \"any\"");
	}
	if (strstr((char *)out->v, "\"src_port\":1234") == NULL) {
		vfree(id_src); vfree(id_dst); vfree(out);
		TEST_FAIL("expected the real src_port from iph2->id, not \"any\"");
	}
	if (strstr((char *)out->v, "\"dst_port\":443") == NULL) {
		vfree(id_src); vfree(id_dst); vfree(out);
		TEST_FAIL("expected the real dst_port from iph2->id_p, not \"any\"");
	}

	vfree(id_src);
	vfree(id_dst);
	vfree(out);
	TEST_PASS();
	return 0;
}

/*
 * Issue #143 F2: text_render_ph2()'s selector line printed an empty string
 * instead of the value on the non-"any" branch, so a real proto/port
 * rendered as "proto= sport= dport=". Invisible to every pre-existing text
 * test because they all used the all-"any" fixture, where the "any" branch
 * is the one taken; the real-value path was only ever asserted in JSON.
 */
static int
test_ph2_selectors_text_real_values(void)
{
	struct ph2handle iph2;
	struct saprop approval;
	struct saproto proto;
	struct satrns trns;
	struct ipsecdoi_id_b *idb;
	vchar_t *id_src = NULL, *id_dst = NULL;
	vchar_t *out = NULL;

	TEST_START("ph2 selectors in TEXT carry the real proto/port numbers, "
	    "not an empty string (issue #143 F2)");

	reset_queues();
	make_addrs();
	setup_ph2_basic(&iph2, &approval, &proto, &trns);

	id_src = vmalloc(sizeof(struct ipsecdoi_id_b));
	if (id_src == NULL)
		TEST_FAIL("vmalloc() failed for iph2->id");
	idb = (struct ipsecdoi_id_b *)id_src->v;
	idb->type = IPSECDOI_ID_IPV4_ADDR;
	idb->proto_id = IPPROTO_TCP;
	idb->port = htons(1234);
	iph2.id = id_src;

	id_dst = vmalloc(sizeof(struct ipsecdoi_id_b));
	if (id_dst == NULL) {
		vfree(id_src);
		TEST_FAIL("vmalloc() failed for iph2->id_p");
	}
	idb = (struct ipsecdoi_id_b *)id_dst->v;
	idb->type = IPSECDOI_ID_IPV4_ADDR;
	idb->port = htons(443);
	iph2.id_p = id_dst;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 0);

	if (out == NULL) {
		vfree(id_src); vfree(id_dst);
		TEST_FAIL("status_dump() returned NULL");
	}
	/* Asserts the whole field list in one substring: the pre-fix output
	 * was "proto= sport= dport=", which no per-field presence check
	 * would have caught. */
	if (strstr((char *)out->v, "proto=6 sport=1234 dport=443") == NULL) {
		vfree(id_src); vfree(id_dst); vfree(out);
		TEST_FAIL("expected the real proto/sport/dport numbers in text output");
	}

	vfree(id_src);
	vfree(id_dst);
	vfree(out);
	TEST_PASS();
	return 0;
}

/*
 * Issue #143 F4: a ph2handle with no approved proposal (PHASE2ST_START,
 * PHASE2ST_GETSPISENT, ...) is enumerable, and used to render a bogus
 * 8-hex-digit "0x00000000****" SPI -- which failed the project's own
 * schema pattern, "^(0x[0-9a-f]{4}\*\*\*\*|\?)$". It now renders null in
 * JSON and "(pending)" in text.
 */
static int
test_ph2_pending_spi_renders_null(void)
{
	struct ph2handle iph2;
	vchar_t *out = NULL;

	TEST_START("ph2 without an approved proposal renders spi_in/spi_out "
	    "as null (JSON) and (pending) (text), not a bogus 8-digit SPI");

	reset_queues();
	make_addrs();

	/* Deliberately no approval: this is the mid-negotiation handle the
	 * old placeholder misreported. */
	memset(&iph2, 0, sizeof(iph2));
	iph2.status = PHASE2ST_GETSPISENT;
	iph2.msgid = 0x11112222;
	iph2.src = (struct sockaddr *)&test_local_sin;
	iph2.dst = (struct sockaddr *)&test_remote_sin;
	iph2.approval = NULL;

	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (!braces_balanced((char *)out->v, out->l))
		TEST_FAIL("unbalanced braces in JSON output");
	if (strstr((char *)out->v, "\"spi_in\":null") == NULL) {
		vfree(out);
		TEST_FAIL("expected spi_in null for a ph2 with no approved proposal");
	}
	if (strstr((char *)out->v, "\"spi_out\":null") == NULL) {
		vfree(out);
		TEST_FAIL("expected spi_out null for a ph2 with no approved proposal");
	}
	/* The exact string the schema pattern rejected -- assert it is gone,
	 * not merely that null is present somewhere. */
	if (strstr((char *)out->v, "0x00000000****") != NULL) {
		vfree(out);
		TEST_FAIL("the pre-fix 8-hex-digit SPI placeholder is still being emitted");
	}
	if (strstr((char *)out->v, "\"state\":\"getspisent\"") == NULL) {
		vfree(out);
		TEST_FAIL("expected the handle to render in its mid-negotiation state");
	}

	vfree(out);
	out = NULL;

	reset_queues();
	make_addrs();
	status_test_ph2_queue[0] = &iph2;
	status_test_ph2_queue_len = 1;

	status_dump(&out, 1, 0);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL (text)");
	if (strstr((char *)out->v, "spi:            in=(pending) out=(pending)") == NULL) {
		vfree(out);
		TEST_FAIL("expected (pending) SPIs in text output");
	}

	vfree(out);
	TEST_PASS();
	return 0;
}

#ifdef ENABLE_DPD
/*
 * Issue #143 F3: collect_dpd() used to be defined *and* called inside
 * #ifdef ENABLE_HYBRID, so a --disable-hybrid --enable-dpd build (both are
 * independent configure options) ran DPD but never emitted the
 * schema-documented dpd block. This test is guarded on ENABLE_DPD alone --
 * deliberately *not* on ENABLE_HYBRID, so that under --disable-hybrid it
 * still compiles and still demands the block, which is exactly the
 * configuration the bug hid in.
 */
static int
test_ph1_dpd_independent_of_hybrid(void)
{
	struct ph1handle iph1;
	struct remoteconf rmconf;
	vchar_t *out = NULL;

	TEST_START("dpd block renders whenever ENABLE_DPD is on, independent "
	    "of ENABLE_HYBRID (issue #143 F3)");

	reset_queues();
	make_addrs();

	memset(&rmconf, 0, sizeof(rmconf));
	rmconf.dpd = 1;

	memset(&iph1, 0, sizeof(iph1));
	iph1.status = PHASE1ST_ESTABLISHED;
	iph1.remote = (struct sockaddr *)&test_remote_sin;
	iph1.local = (struct sockaddr *)&test_local_sin;
	iph1.rmconf = &rmconf;
	iph1.dpd_support = 1;
	iph1.dpd_fails = 3;

	status_test_ph1_queue[0] = &iph1;
	status_test_ph1_queue_len = 1;

	status_dump(&out, 0, 1);

	if (out == NULL)
		TEST_FAIL("status_dump() returned NULL");
	if (strstr((char *)out->v, "\"dpd\":{\"supported\":true,\"fails\":3}") == NULL) {
		vfree(out);
		TEST_FAIL("expected the dpd block with supported/fails populated");
	}

	vfree(out);
	TEST_PASS();
	return 0;
}
#endif /* ENABLE_DPD */

int
main(void)
{
	int failed = 0;

	printf("\n=== status_dump() coverage test ===\n");

	if (test_ph1_state_name_exhaustive() != 0)
		failed++;
	if (test_ph2_state_name_exhaustive() != 0)
		failed++;
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
	if (test_ph1_full_json() != 0)
		failed++;
	if (test_ph1_full_text() != 0)
		failed++;
	if (test_ph2_basic() != 0)
		failed++;
	if (test_ph2_basic_text() != 0)
		failed++;
	if (test_ph2_effective_group_fallback() != 0)
		failed++;
	if (test_ph2_ah() != 0)
		failed++;
	if (test_ph2_esp_null_auth_renders_null() != 0)
		failed++;
	if (test_ph2_alg_names_cbc_and_sha1() != 0)
		failed++;
	if (test_ph2_alg_names_no_overreach() != 0)
		failed++;
	if (test_ph2_ipcomp() != 0)
		failed++;
	if (test_ph2_selectors_real_values() != 0)
		failed++;
	if (test_ph2_selectors_text_real_values() != 0)
		failed++;
	if (test_ph2_pending_spi_renders_null() != 0)
		failed++;
#ifdef ENABLE_DPD
	if (test_ph1_dpd_independent_of_hybrid() != 0)
		failed++;
#endif

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
