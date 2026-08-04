// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression/coverage test for f_exchangesa() (racoonctl.c) -- the
 * establish-sa encoder, and the most structurally involved of
 * racoonctl's request builders: "-u identity"/PSK injection, "-n
 * remoteconf" name append, "-w" wait-for-completion flag, and the
 * shared get_proto_and_index() index-building path, all before this
 * (v0.9.1 unit-test-coverage hardening, Tier 4) had never been unit
 * tested at all.
 *
 * The "-u identity" (PSK) case specifically cross-checks racoonctl's
 * own encoding against admin.c's own assumed wire layout
 * (test_admin_establish_sa_psk.c, ADMIN_ESTABLISH_SA_PSK): both sides
 * use the same struct admin_com/admin_com_indexes/admin_com_psk
 * definitions from admin.h, so the compiler's own layout/alignment
 * matches on both ends, but nothing before this test ever ran the real
 * producer (f_exchangesa()) and checked its output against the layout
 * the real consumer (admin_process(), admin.c) expects -- each side's
 * own test previously only exercised a hand-built buffer matching its
 * own assumptions. That gap was real: admin.c's own test sets
 * id_len = strlen(idstr) (no NUL), while f_exchangesa() actually sends
 * id_len = strlen(id) + 1 (NUL included, since it strcpy()s the id and
 * admin.c's id/key end up as NUL-terminated C strings in
 * rmconf->xauth->login/pass) -- both are "valid" from admin.c's own
 * purely length-driven parsing, so this was never caught, just an
 * unpinned assumption on both sides. test_psk_id_key_wire_layout below
 * pins the id_len/key_len-includes-NUL convention down explicitly by
 * decoding the real f_exchangesa() output through admin.c's own
 * layout.
 *
 * f_exchangesa() is static; f_exchangesa_unittest() is a thin
 * -DENABLE_UNITTEST accessor. get_proto_and_index() (and so
 * get_sockaddr(), kmpstat.c's real getaddrinfo() call) is reached via
 * the same racoonctl_get_sockaddr_stub.c stand-in as
 * test_racoonctl_get_comindexes.c/test_racoonctl_encode_requests.c.
 * getpass() (real terminal I/O, the "-u identity" branch) is reached
 * via racoonctl_getpass_stub.c -- see that file's own header comment
 * for the spike that confirmed plain symbol shadowing (no
 * -Wl,--wrap=) is safe here on this toolchain.
 *
 * ac<1 and "-u" with ac<2 both call errx() (not exit() directly), so
 * neither is testable via -Wl,--wrap=exit for the same reason
 * documented in test_racoonctl_encode_requests.c -- not attempted here.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "var.h"
#include "vmbuf.h"
#include "admin.h"
#include "evt.h"
#include "ipsec_doi.h"

extern vchar_t *f_exchangesa_unittest(int ac, char **av);

extern int racoonctl_test_get_sockaddr_calls;
extern int racoonctl_test_get_sockaddr_fail;
extern char racoonctl_test_getpass_return[256];
extern int racoonctl_test_getpass_calls;
extern char racoonctl_test_getpass_last_prompt[256];

extern int evt_quit_event;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static void
reset_stub_state(void)
{
	racoonctl_test_get_sockaddr_calls = 0;
	racoonctl_test_get_sockaddr_fail = 0;
	racoonctl_test_getpass_calls = 0;
	racoonctl_test_getpass_return[0] = '\0';
	racoonctl_test_getpass_last_prompt[0] = '\0';
	evt_quit_event = 0;
}

static int
header_ok(vchar_t *buf, u_int16_t cmd, u_int16_t proto, size_t expect_total_len)
{
	struct admin_com *head;

	if (buf == NULL) {
		printf("(buf is NULL) ");
		return 0;
	}
	if (buf->l != expect_total_len) {
		printf("(buf->l=%zu, expected %zu) ", buf->l, expect_total_len);
		return 0;
	}
	head = (struct admin_com *)buf->v;
	if ((head->ac_cmd & ~ADMIN_FLAG_VERSION) != cmd) {
		printf("(ac_cmd&~FLAG_VERSION=0x%x, expected 0x%x) ",
		    head->ac_cmd & ~ADMIN_FLAG_VERSION, cmd);
		return 0;
	}
	if (head->ac_proto != proto) {
		printf("(ac_proto=%u, expected %u) ", head->ac_proto, proto);
		return 0;
	}
	return 1;
}

static int
test_plain_isakmp_no_flags(void)
{
	vchar_t *buf;

	TEST_START("f_exchangesa() with a plain ISAKMP saopts, no flags");

	reset_stub_state();
	buf = f_exchangesa_unittest(4, (char *[]){ "isakmp", "inet", "10.0.0.1", "10.0.0.2" });
	if (!header_ok(buf, ADMIN_ESTABLISH_SA, ADMIN_PROTO_ISAKMP,
	    sizeof(struct admin_com) + sizeof(struct admin_com_indexes))) {
		vfree(buf);
		TEST_FAIL("request malformed");
	}
	if (evt_quit_event != 0) {
		vfree(buf);
		TEST_FAIL("evt_quit_event was set despite no -w flag");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_remoteconf_name_appended(void)
{
	vchar_t *buf;
	const char *name = "myconf";
	char *tail;
	size_t expect_len;

	TEST_START("f_exchangesa() -n remoteconf: name is appended, NUL-terminated, after the index");

	reset_stub_state();
	buf = f_exchangesa_unittest(6,
	    (char *[]){ "-n", (char *)name, "isakmp", "inet", "10.0.0.1", "10.0.0.2" });

	expect_len = sizeof(struct admin_com) + sizeof(struct admin_com_indexes)
	    + strlen(name) + 1;
	if (!header_ok(buf, ADMIN_ESTABLISH_SA, ADMIN_PROTO_ISAKMP, expect_len)) {
		vfree(buf);
		TEST_FAIL("request malformed");
	}

	tail = buf->v + sizeof(struct admin_com) + sizeof(struct admin_com_indexes);
	if (strcmp(tail, name) != 0) {
		printf("(tail=\"%s\", expected \"%s\") ", tail, name);
		vfree(buf);
		TEST_FAIL("remoteconf name did not round-trip");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_remoteconf_ignored_for_non_isakmp(void)
{
	vchar_t *buf;

	TEST_START("f_exchangesa() -n remoteconf is ignored for a non-ISAKMP proto (esp)");

	reset_stub_state();
	buf = f_exchangesa_unittest(7,
	    (char *[]){ "-n", "myconf", "esp", "inet", "10.0.0.1", "10.0.0.2", "tcp" });

	/* No remoteconf-name suffix for esp/ah -- request stays exactly
	 * header + index, matching test_racoonctl_encode_requests.c's own
	 * f_deletesa() esp assertion shape. */
	if (!header_ok(buf, ADMIN_ESTABLISH_SA, ADMIN_PROTO_ESP,
	    sizeof(struct admin_com) + sizeof(struct admin_com_indexes))) {
		vfree(buf);
		TEST_FAIL("request malformed, or unexpectedly carries the remoteconf name");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

/*
 * f_exchangesa()'s own "-u identity" (PSK) branch is NOT gated on
 * ENABLE_HYBRID (only f_logoutusr(), a different function, is) -- this
 * test always runs.
 *
 * Issue noted in this file's own header comment: pins down the
 * id_len/key_len-includes-NUL convention by decoding the real
 * f_exchangesa() output through the exact struct layout admin.c's own
 * ADMIN_ESTABLISH_SA_PSK test (test_admin_establish_sa_psk.c) assumes.
 */
static int
test_psk_id_key_wire_layout(void)
{
	struct psk_wire {
		struct admin_com com;
		struct admin_com_indexes ndx;
		struct admin_com_psk psk;
		char data[128];
	};
	vchar_t *buf;
	struct psk_wire *w;
	const char *idstr = "roadwarrior1";
	const char *keystr = "correct-horse-battery-staple";
	size_t expect_len;

	TEST_START("f_exchangesa() -u identity: PSK wire layout matches admin.c's own assumption");

	reset_stub_state();
	strncpy(racoonctl_test_getpass_return, keystr,
	    sizeof(racoonctl_test_getpass_return) - 1);

	buf = f_exchangesa_unittest(6,
	    (char *[]){ "-u", (char *)idstr, "isakmp", "inet", "10.0.0.1", "10.0.0.2" });

	expect_len = sizeof(struct admin_com) + sizeof(struct admin_com_indexes)
	    + sizeof(struct admin_com_psk) + strlen(idstr) + 1 + strlen(keystr) + 1;
	if (!header_ok(buf, ADMIN_ESTABLISH_SA_PSK, ADMIN_PROTO_ISAKMP, expect_len)) {
		vfree(buf);
		TEST_FAIL("request malformed");
	}

	if (racoonctl_test_getpass_calls != 1) {
		vfree(buf);
		TEST_FAIL("getpass() was not called exactly once");
	}
	if (strcmp(racoonctl_test_getpass_last_prompt, "Password: ") != 0) {
		vfree(buf);
		TEST_FAIL("getpass() was not called with the expected prompt");
	}

	w = (struct psk_wire *)buf->v;
	if (w->psk.id_type != IDTYPE_USERFQDN) {
		vfree(buf);
		TEST_FAIL("id_type is not IDTYPE_USERFQDN");
	}
	/* The convention this test pins down: id_len/key_len include the
	 * NUL terminator (strlen()+1), not just strlen(). */
	if (w->psk.id_len != strlen(idstr) + 1) {
		printf("(id_len=%zu, expected %zu) ", w->psk.id_len, strlen(idstr) + 1);
		vfree(buf);
		TEST_FAIL("id_len does not include the NUL terminator");
	}
	if (w->psk.key_len != strlen(keystr) + 1) {
		printf("(key_len=%zu, expected %zu) ", w->psk.key_len, strlen(keystr) + 1);
		vfree(buf);
		TEST_FAIL("key_len does not include the NUL terminator");
	}
	if (strcmp(w->data, idstr) != 0) {
		vfree(buf);
		TEST_FAIL("id bytes do not match, or are not NUL-terminated at id_len");
	}
	if (strcmp(w->data + w->psk.id_len, keystr) != 0) {
		vfree(buf);
		TEST_FAIL("key bytes do not immediately follow id at exactly id_len, "
		    "or are not NUL-terminated at key_len");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_wait_flag_sets_quit_event_isakmp(void)
{
	vchar_t *buf;

	TEST_START("f_exchangesa() -w sets evt_quit_event to EVT_PHASE1_MODE_CFG for isakmp");

	reset_stub_state();
	buf = f_exchangesa_unittest(5,
	    (char *[]){ "-w", "isakmp", "inet", "10.0.0.1", "10.0.0.2" });
	if (buf == NULL)
		TEST_FAIL("request was rejected");
	if (evt_quit_event != EVT_PHASE1_MODE_CFG) {
		vfree(buf);
		TEST_FAIL("evt_quit_event was not set to EVT_PHASE1_MODE_CFG");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_wait_flag_sets_quit_event_esp(void)
{
	vchar_t *buf;

	TEST_START("f_exchangesa() -w sets evt_quit_event to EVT_PHASE2_UP for esp/ah");

	reset_stub_state();
	buf = f_exchangesa_unittest(6,
	    (char *[]){ "-w", "esp", "inet", "10.0.0.1", "10.0.0.2", "tcp" });
	if (buf == NULL)
		TEST_FAIL("request was rejected");
	if (evt_quit_event != EVT_PHASE2_UP) {
		vfree(buf);
		TEST_FAIL("evt_quit_event was not set to EVT_PHASE2_UP");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_unsupported_proto_returns_null(void)
{
	vchar_t *buf;

	TEST_START("f_exchangesa() with an unsupported protocol returns NULL, does not exit");

	reset_stub_state();
	buf = f_exchangesa_unittest(2, (char *[]){ "internal", "x" });
	if (buf != NULL) {
		vfree(buf);
		TEST_FAIL("an unsupported protocol was accepted");
	}

	TEST_PASS();
	return 0;
}

static int
test_sockaddr_resolution_failure_returns_null(void)
{
	vchar_t *buf;

	TEST_START("f_exchangesa() returns NULL when get_sockaddr() fails, does not exit");

	reset_stub_state();
	racoonctl_test_get_sockaddr_fail = 1;
	buf = f_exchangesa_unittest(4, (char *[]){ "isakmp", "inet", "10.0.0.1", "10.0.0.2" });
	if (buf != NULL) {
		vfree(buf);
		TEST_FAIL("a get_sockaddr() failure was not propagated as a rejection");
	}

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== f_exchangesa() (establish-sa encoder) test ===\n");

	if (test_plain_isakmp_no_flags() != 0)
		failed++;
	if (test_remoteconf_name_appended() != 0)
		failed++;
	if (test_remoteconf_ignored_for_non_isakmp() != 0)
		failed++;
	if (test_psk_id_key_wire_layout() != 0)
		failed++;
	if (test_wait_flag_sets_quit_event_isakmp() != 0)
		failed++;
	if (test_wait_flag_sets_quit_event_esp() != 0)
		failed++;
	if (test_unsupported_proto_returns_null() != 0)
		failed++;
	if (test_sockaddr_resolution_failure_returns_null() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
	return failed == 0 ? 0 : 1;
}
