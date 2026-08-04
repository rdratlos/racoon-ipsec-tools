// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for ADMIN_ESTABLISH_SA_PSK (admin.c) -- despite the
 * name, this is NOT Phase 1 IKE pre-shared-key material: iph1->rmconf->
 * xauth->login/pass (the only place this admin_com_psk payload's id/key
 * ever get read, isakmp_xauth.c) are the client's own XAUTH username/
 * password, sent during the *post*-Phase-1 extended-auth exchange. Real
 * Phase 1 PSK is a wholly separate lookup (getpskbyname()/getpskbyaddr(),
 * localconf.c, read by oakley.c) this command never touches. The naming
 * is inherited from upstream KAME racoon; what this command actually
 * does is let racoonctl inject XAUTH credentials for one connection
 * attempt via the admin socket instead of storing them in racoon.conf.
 * That distinction matters for what this test is actually protecting:
 * the wire-parsing of a dynamically-supplied credential, not IKE auth
 * itself -- and it is a path the certificate-based Phase 1 integration
 * tests never exercise at all.
 *
 * Wire format (admin.c, ADMIN_ESTABLISH_SA_PSK case): struct admin_com,
 * struct admin_com_indexes, struct admin_com_psk, then id_len raw bytes,
 * then key_len raw bytes -- three structs and two variable-length
 * regions back to back, entirely by pointer arithmetic
 * (acp = (struct admin_com_psk *)((char *)com + sizeof(*com) +
 * sizeof(struct admin_com_indexes)); data = (char *)(acp + 1); ... data =
 * (char *)(data + acp->id_len);). test_wire_parsing_transfers_id_and_key
 * below builds that layout directly (both sides use the same struct
 * admin.h defines, so the compiler's own layout/alignment matches on
 * both ends) and checks the *content*, not just the return code:
 * rmconf->xauth->login/pass are where admin_process() ultimately puts
 * what it parsed, so reading them back after the call is a precise,
 * end-to-end check that id_len/key_len bytes landed in the right place
 * with the right length -- exactly the kind of off-by-one/wrong-offset
 * bug pointer arithmetic like this invites.
 *
 * Also regression-tests the memory-leak fix (this same commit) for every
 * path that allocates id/key (vmalloc()) but previously never freed them:
 * an existing ph1, no matching rmconf, xauth_rmconf_used() failing, and
 * (this file's proto-AH case) falling through into a non-ISAKMP proto,
 * which never touches id/key at all. -Wl,--wrap=vfree (test/Makefile.am)
 * observes every vfree() call this binary makes; test_leak_free_counts
 * asserts the exact count for each path, including 0 on the success path
 * (ownership transferred to rmconf->xauth, not freed here at all).
 *
 * getrmconf()/xauth_rmconf_used() are "smart" stubs here (admin_test_
 * stubs.c): admin_test_getrmconf_ret/admin_test_xauth_rmconf_used_ret let
 * this file point them at a real, test-owned struct remoteconf/
 * xauth_rmconf pair, default NULL/-1 (preserving every other admin.c
 * test's existing behavior, which never sets them).
 *
 * skip_if_wrap_vfree_ineffective() below guards against a real, observed
 * failure mode: under whole-program LTO (-flto=auto -ffat-lto-objects,
 * confirmed on Ubuntu 26.04 "Resolute", GCC 15.2/binutils 2.46), vfree()'s
 * real definition (vmbuf.o, linked into this binary) is visible to LTO's
 * whole-program analysis and gets inlined directly at every call site,
 * leaving no relocation against the symbol vfree for --wrap=vfree to ever
 * redirect -- __wrap_vfree ends up entirely unreferenced (confirmed via
 * nm: it does not even appear in the linked binary). That leaves
 * vfree_calls permanently 0, which test_wire_parsing_transfers_id_and_key
 * would otherwise silently read as its own (correct) assertion that the
 * success path performs zero frees -- a false pass indistinguishable,
 * from inside that one test, from vfree() genuinely never being
 * intercepted at all. A canary vfree() at startup tells them apart: SKIP
 * if the canary itself isn't observed, FAIL only for a genuine wrong
 * count. See doc/dev/v0.9.1-hardening-spec.md §3.2 for the full writeup.
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
#include "remoteconf.h"
#include "admin.h"
#ifdef ENABLE_HYBRID
#include "isakmp_xauth.h"
#endif

extern int admin_process_unittest(int so2, char *combuf);

extern struct ph1handle *admin_test_getph1_queue[];
extern int admin_test_getph1_queue_len;
extern int admin_test_getph1_calls;
extern int admin_test_getrmconf_calls;
extern struct remoteconf *admin_test_getrmconf_ret;
#ifdef ENABLE_HYBRID
extern int admin_test_xauth_rmconf_used_calls;
extern int admin_test_xauth_rmconf_used_ret;
#endif
extern int admin_test_getsp_r_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/* Linker-level vfree() interposition (-Wl,--wrap=vfree, test/Makefile.am):
 * every vfree() call this binary makes is redirected here first. Counts
 * only non-NULL invocations -- vfree(NULL) is a documented, deliberate
 * no-op (vmbuf.c), not evidence anything was actually freed. */
extern void __real_vfree(vchar_t *v);
static int vfree_calls;

void
__wrap_vfree(vchar_t *v)
{
	if (v != NULL)
		vfree_calls++;
	__real_vfree(v);
}

/*
 * Confirms -Wl,--wrap=vfree is actually intercepting vfree() calls on
 * this toolchain before trusting any test below that counts them. See
 * this file's header comment for why a plain vfree_calls == 0 can
 * otherwise be mistaken for "ownership transferred, nothing to free".
 */
static int
skip_if_wrap_vfree_ineffective(void)
{
	vchar_t *canary = vmalloc(1);

	vfree_calls = 0;
	vfree(canary);
	if (vfree_calls == 1)
		return 0;

	printf("\n=== ADMIN_ESTABLISH_SA_PSK (XAUTH id/key injection) test ===\n"
	    "SKIP: -Wl,--wrap=vfree did not intercept a canary vfree() call on "
	    "this toolchain. This is a known interaction with whole-program "
	    "LTO (-flto=auto -ffat-lto-objects): vfree()'s real definition is "
	    "visible to LTO's whole-program analysis and gets inlined directly "
	    "at the call site, leaving no symbol reference for --wrap=vfree to "
	    "redirect. See doc/dev/v0.9.1-hardening-spec.md §3.2.\n\n");
	return 1;
}

static void
reset_stub_state(void)
{
	admin_test_getph1_queue_len = 0;
	admin_test_getph1_calls = 0;
	admin_test_getrmconf_calls = 0;
	admin_test_getrmconf_ret = NULL;
#ifdef ENABLE_HYBRID
	admin_test_xauth_rmconf_used_calls = 0;
	admin_test_xauth_rmconf_used_ret = -1;
#endif
	admin_test_getsp_r_calls = 0;
	vfree_calls = 0;
}

/*
 * admin.c's own offset math packs key right after exactly id_len bytes
 * of id, with no gap: data = (char *)(acp + 1) for id, then
 * data = (char *)(data + acp->id_len) for key. A fixed-size id_bytes[N]
 * field here would only match that when idlen == N -- for anything
 * shorter, admin.c's second data pointer lands inside this struct's own
 * zero-padding instead of at the real start of key, which is exactly
 * the offset bug this test exists to catch (and, on a first pass, did:
 * an earlier version of this test used separate fixed-size id_bytes[16]/
 * key_bytes[16] fields and failed for that reason -- a bug in the test's
 * own wire construction, not in admin.c). data[] here is instead packed
 * at runtime by build_psk_request() so key always starts at exactly
 * idlen, matching the real wire format.
 */
struct psk_req {
	struct admin_com com;
	struct admin_com_indexes ndx;
	struct admin_com_psk psk;
	char data[64];
};

static void
build_psk_request(struct psk_req *req, const char *idstr, const char *keystr,
    u_int proto)
{
	size_t idlen = strlen(idstr);
	size_t keylen = strlen(keystr);

	memset(req, 0, sizeof(*req));
	req->com.ac_cmd = ADMIN_ESTABLISH_SA_PSK;
	req->com.ac_proto = proto;
	req->psk.id_type = 1;
	req->psk.id_len = idlen;
	req->psk.key_len = keylen;
	memcpy(req->data, idstr, idlen);
	memcpy(req->data + idlen, keystr, keylen);
	req->com.ac_len = sizeof(struct admin_com) +
	    sizeof(struct admin_com_indexes) + sizeof(struct admin_com_psk) +
	    idlen + keylen;
}

#ifdef ENABLE_HYBRID
static int
test_wire_parsing_transfers_id_and_key(void)
{
	struct psk_req req;
	struct remoteconf rmconf;
	struct xauth_rmconf xauth;
	const char *idstr = "roadwarrior1";
	const char *keystr = "correct-horse-battery-staple";

	TEST_START("ADMIN_ESTABLISH_SA_PSK parses id/key and transfers them to rmconf->xauth");

	reset_stub_state();
	memset(&rmconf, 0, sizeof(rmconf));
	memset(&xauth, 0, sizeof(xauth));
	rmconf.xauth = &xauth;
	admin_test_getrmconf_ret = &rmconf;
	admin_test_xauth_rmconf_used_ret = 0;

	build_psk_request(&req, idstr, keystr, ADMIN_PROTO_ISAKMP);

	admin_process_unittest(0, (char *)&req);

	if (admin_test_getrmconf_calls != 1)
		TEST_FAIL("getrmconf() was not called exactly once");
	if (rmconf.xauth->login == NULL || rmconf.xauth->pass == NULL)
		TEST_FAIL("rmconf->xauth->login/pass were not populated at all");
	if (rmconf.xauth->login->l != strlen(idstr) ||
	    memcmp(rmconf.xauth->login->v, idstr, strlen(idstr)) != 0)
		TEST_FAIL("rmconf->xauth->login does not match the id bytes sent");
	if (rmconf.xauth->pass->l != strlen(keystr) ||
	    memcmp(rmconf.xauth->pass->v, keystr, strlen(keystr)) != 0)
		TEST_FAIL("rmconf->xauth->pass does not match the key bytes sent");
	if (vfree_calls != 0)
		TEST_FAIL("id/key were freed despite ownership transferring to rmconf->xauth");

	vfree(rmconf.xauth->login);
	vfree(rmconf.xauth->pass);
	TEST_PASS();
	return 0;
}

/*
 * xauth_rmconf_used() failing is itself a real, if narrow, production
 * path (isakmp_xauth.c: fails only on malloc failure allocating the
 * rmconf's xauth_rmconf on first use) -- confirms id/key are freed
 * rather than silently dropped when it does.
 */
static int
test_xauth_rmconf_used_failure_frees_id_and_key(void)
{
	struct psk_req req;
	struct remoteconf rmconf;

	TEST_START("xauth_rmconf_used() failure still frees id/key (no transfer happened)");

	reset_stub_state();
	memset(&rmconf, 0, sizeof(rmconf));
	rmconf.xauth = NULL;
	admin_test_getrmconf_ret = &rmconf;
	admin_test_xauth_rmconf_used_ret = -1;

	build_psk_request(&req, "user", "pass", ADMIN_PROTO_ISAKMP);
	admin_process_unittest(0, (char *)&req);

	if (vfree_calls != 2)
		TEST_FAIL("id and key were not both freed after xauth_rmconf_used() failed");

	TEST_PASS();
	return 0;
}
#endif /* ENABLE_HYBRID */

static int
test_no_matching_rmconf_frees_id_and_key(void)
{
	struct psk_req req;

	TEST_START("no matching rmconf: id/key are freed instead of leaked");

	reset_stub_state();
	/* admin_test_getrmconf_ret stays NULL: "no configuration found". */

	build_psk_request(&req, "user", "pass", ADMIN_PROTO_ISAKMP);
	admin_process_unittest(0, (char *)&req);

	if (admin_test_getrmconf_calls != 1)
		TEST_FAIL("getrmconf() was not called exactly once");
	if (vfree_calls != 2)
		TEST_FAIL("id and key were not both freed when no rmconf matched");

	TEST_PASS();
	return 0;
}

static int
test_non_isakmp_proto_after_psk_frees_id_and_key(void)
{
	struct psk_req req;

	TEST_START("PSK id/key falling through into a non-ISAKMP proto are freed, not leaked");

	reset_stub_state();
	/* getsp_r() stub returns NULL, so this exercises the ENOENT path
	 * without needing a real outbound policy. */

	build_psk_request(&req, "user", "pass", ADMIN_PROTO_AH);
	admin_process_unittest(0, (char *)&req);

	if (admin_test_getsp_r_calls != 1)
		TEST_FAIL("getsp_r() was not called (wrong code path exercised)");
	if (vfree_calls != 2)
		TEST_FAIL("id and key were not both freed for a non-ISAKMP proto");

	TEST_PASS();
	return 0;
}

static int
test_existing_ph1_frees_id_and_key(void)
{
	struct psk_req req;
	struct ph1handle existing;

	TEST_START("an already-existing ph1 short-circuits before the rmconf lookup, still frees id/key");

	reset_stub_state();
	memset(&existing, 0, sizeof(existing));
	existing.status = PHASE1ST_ESTABLISHED;
	admin_test_getph1_queue[0] = &existing;
	admin_test_getph1_queue_len = 1;

	build_psk_request(&req, "user", "pass", ADMIN_PROTO_ISAKMP);
	admin_process_unittest(0, (char *)&req);

	if (admin_test_getph1_calls != 1)
		TEST_FAIL("getph1() was not called exactly once");
	if (admin_test_getrmconf_calls != 0)
		TEST_FAIL("getrmconf() was reached despite an existing ph1");
	if (vfree_calls != 2)
		TEST_FAIL("id and key were not both freed when a ph1 already existed");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	signal(SIGPIPE, SIG_IGN);

	if (skip_if_wrap_vfree_ineffective())
		return 77;

	printf("\n=== ADMIN_ESTABLISH_SA_PSK (XAUTH id/key injection) test ===\n");

#ifdef ENABLE_HYBRID
	if (test_wire_parsing_transfers_id_and_key() != 0)
		failed++;
	if (test_xauth_rmconf_used_failure_frees_id_and_key() != 0)
		failed++;
#endif
	if (test_no_matching_rmconf_frees_id_and_key() != 0)
		failed++;
	if (test_non_isakmp_proto_after_psk_frees_id_and_key() != 0)
		failed++;
	if (test_existing_ph1_frees_id_and_key() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
