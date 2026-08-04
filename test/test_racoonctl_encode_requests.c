// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression/coverage test for racoonctl.c's simple request-encoding
 * layer -- make_request() (the struct admin_com header every request
 * shares), get_combuf() (command-string dispatch), and the f_*()
 * encoders that don't need f_exchangesa()'s own dedicated test
 * (test_racoonctl_exchangesa.c): f_reload, f_getevt, f_getsched,
 * f_getsa, f_getsacert, f_flushsa, f_deletesa, f_deleteallsadst, f_vpnd,
 * and get_proto_and_index().
 *
 * This is racoonctl's own encode side of a wire protocol admin.c's tests
 * already cover from the daemon's decode side (test_admin_process_
 * dispatch.c, test_admin_delete_all_sa_dst.c, etc. -- see this file's
 * cross-checks against struct admin_com/admin_com_indexes below) --
 * nothing here duplicates that coverage, it is racoonctl's own
 * previously entirely untested logic that builds the requests those
 * tests assume.
 *
 * f_getsacert()/f_deletesa()/f_deleteallsadst() and get_proto_and_index()
 * transitively reach get_sockaddr() (kmpstat.c, a real getaddrinfo()
 * call); racoonctl_get_sockaddr_stub.c substitutes a numeric-only,
 * DNS-free stand-in, same as test_racoonctl_get_comindexes.c.
 *
 * get_combuf()'s ac==0 path calls exit(0) directly (after printing
 * usage()) -- -Wl,--wrap=exit (same technique as
 * test_session_check_sigreq.c) lets that one case be driven via
 * siglongjmp() instead of actually terminating the process. Every
 * f_*() argument-count/protocol-validation guard in this file instead
 * calls errx(), which is NOT similarly testable this way: errx() lives
 * inside libc (a pre-built shared object on a normal dynamically-linked
 * build), so its own internal call to exit() was already resolved when
 * libc itself was compiled, long before -Wl,--wrap=exit's rewriting of
 * this binary's own object files ever applies. See the comment just
 * above main() for what confirmed this empirically. Those guards are
 * instead exercised only on their non-exit branches (e.g.
 * f_deletesa()'s unsupported-protocol case, which returns NULL rather
 * than calling errx()).
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "var.h"
#include "vmbuf.h"
#include "admin.h"
#include "evt.h"

extern vchar_t *get_combuf_unittest(int ac, char **av);
extern vchar_t *make_request_unittest(u_int16_t cmd, u_int16_t proto, size_t len);
extern vchar_t *f_reload_unittest(int ac, char **av);
extern vchar_t *f_getevt_unittest(int ac, char **av);
extern vchar_t *f_getsched_unittest(int ac, char **av);
extern vchar_t *f_getsa_unittest(int ac, char **av);
extern vchar_t *f_getsacert_unittest(int ac, char **av);
extern vchar_t *f_flushsa_unittest(int ac, char **av);
extern vchar_t *f_deletesa_unittest(int ac, char **av);
extern vchar_t *f_deleteallsadst_unittest(int ac, char **av);
extern vchar_t *f_vpnd_unittest(int ac, char **av);
extern vchar_t *get_proto_and_index_unittest(int ac, char **av, u_int16_t *proto);

extern char *pname;
extern int evt_quit_event;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static sigjmp_buf exit_jmp;
static int exit_was_called;
static int wrapped_exit_status;

void
__wrap_exit(int status)
{
	exit_was_called = 1;
	wrapped_exit_status = status;
	siglongjmp(exit_jmp, 1);
}

/* header_ok(): every make_request()-built buffer shares this shape --
 * struct admin_com, ac_len == buf->l, ADMIN_FLAG_VERSION set, the right
 * cmd (mod ADMIN_FLAG_VERSION/ADMIN_FLAG_LONG_REPLY, the same bit --
 * see admin.h), the right proto, ac_version == 1. Mirrors the same
 * masking test_admin_delete_all_sa_dst.c's own reply check uses. */
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
	if (head->ac_len != buf->l) {
		printf("(ac_len=%u, expected %zu) ", head->ac_len, buf->l);
		return 0;
	}
	if (!(head->ac_cmd & ADMIN_FLAG_VERSION)) {
		printf("(ADMIN_FLAG_VERSION not set) ");
		return 0;
	}
	if ((head->ac_cmd & ~ADMIN_FLAG_VERSION) != cmd) {
		printf("(ac_cmd&~FLAG_VERSION=0x%x, expected 0x%x) ",
		    head->ac_cmd & ~ADMIN_FLAG_VERSION, cmd);
		return 0;
	}
	if (head->ac_version != 1) {
		printf("(ac_version=%u, expected 1) ", head->ac_version);
		return 0;
	}
	if (head->ac_proto != proto) {
		printf("(ac_proto=%u, expected %u) ", head->ac_proto, proto);
		return 0;
	}
	return 1;
}

static int
test_make_request_header(void)
{
	vchar_t *buf;

	TEST_START("make_request() builds a correctly-shaped struct admin_com header");

	buf = make_request_unittest(ADMIN_RELOAD_CONF, ADMIN_PROTO_ISAKMP, 8);
	if (!header_ok(buf, ADMIN_RELOAD_CONF, ADMIN_PROTO_ISAKMP,
	    sizeof(struct admin_com) + 8)) {
		vfree(buf);
		TEST_FAIL("header fields did not match");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_trivial_encoders(void)
{
	vchar_t *buf;

	TEST_START("f_reload()/f_getsched(): no-argument, no-payload requests");

	buf = f_reload_unittest(0, NULL);
	if (!header_ok(buf, ADMIN_RELOAD_CONF, 0, sizeof(struct admin_com))) {
		vfree(buf);
		TEST_FAIL("f_reload() request malformed");
	}
	vfree(buf);

	buf = f_getsched_unittest(0, NULL);
	if (!header_ok(buf, ADMIN_SHOW_SCHED, 0, sizeof(struct admin_com))) {
		vfree(buf);
		TEST_FAIL("f_getsched() request malformed");
	}
	vfree(buf);

	TEST_PASS();
	return 0;
}

static int
test_getevt_sets_quit_event_and_builds_request(void)
{
	vchar_t *buf;

	TEST_START("f_getevt() sets evt_quit_event and builds an ADMIN_SHOW_EVT request");

	evt_quit_event = 0;
	buf = f_getevt_unittest(0, NULL);
	if (!header_ok(buf, ADMIN_SHOW_EVT, 0, sizeof(struct admin_com))) {
		vfree(buf);
		TEST_FAIL("f_getevt() request malformed");
	}
	if (evt_quit_event != -1) {
		vfree(buf);
		TEST_FAIL("evt_quit_event was not set to -1");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_getsa_and_flushsa_encode_protocol(void)
{
	vchar_t *buf;

	TEST_START("f_getsa()/f_flushsa() encode the given protocol, no payload");

	buf = f_getsa_unittest(1, (char *[]){ "esp" });
	if (!header_ok(buf, ADMIN_SHOW_SA, ADMIN_PROTO_ESP, sizeof(struct admin_com))) {
		vfree(buf);
		TEST_FAIL("f_getsa(\"esp\") request malformed");
	}
	vfree(buf);

	buf = f_getsa_unittest(1, (char *[]){ "ipsec" });
	if (!header_ok(buf, ADMIN_SHOW_SA, ADMIN_PROTO_IPSEC, sizeof(struct admin_com))) {
		vfree(buf);
		TEST_FAIL("f_getsa(\"ipsec\") request malformed");
	}
	vfree(buf);

	buf = f_flushsa_unittest(1, (char *[]){ "ah" });
	if (!header_ok(buf, ADMIN_FLUSH_SA, ADMIN_PROTO_AH, sizeof(struct admin_com))) {
		vfree(buf);
		TEST_FAIL("f_flushsa(\"ah\") request malformed");
	}
	vfree(buf);

	TEST_PASS();
	return 0;
}

static int
test_getsacert_embeds_index(void)
{
	/* f_getsacert() calls get_index(ac, av) directly with its own
	 * (ac, av) -- unlike f_deletesa()/f_deleteallsadst(), there is no
	 * leading protocol argument to strip first, so av[0] is the
	 * family string. */
	char *av[] = { "inet", "10.0.0.1", "10.0.0.2" };
	vchar_t *buf;
	struct admin_com_indexes *ci;
	struct sockaddr_in *src;

	TEST_START("f_getsacert() embeds a real admin_com_indexes payload after the header");

	buf = f_getsacert_unittest(3, av);
	if (!header_ok(buf, ADMIN_GET_SA_CERT, ADMIN_PROTO_ISAKMP,
	    sizeof(struct admin_com) + sizeof(struct admin_com_indexes))) {
		vfree(buf);
		TEST_FAIL("f_getsacert() request malformed");
	}

	ci = (struct admin_com_indexes *)(buf->v + sizeof(struct admin_com));
	src = (struct sockaddr_in *)&ci->src;
	if (src->sin_family != AF_INET) {
		vfree(buf);
		TEST_FAIL("embedded index's src family is not AF_INET");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_deletesa_embeds_index_isakmp_and_esp(void)
{
	vchar_t *buf;

	TEST_START("f_deletesa() embeds an index for both ISAKMP and ESP/AH protocols");

	buf = f_deletesa_unittest(4, (char *[]){ "isakmp", "inet", "10.0.0.1", "10.0.0.2" });
	if (!header_ok(buf, ADMIN_DELETE_SA, ADMIN_PROTO_ISAKMP,
	    sizeof(struct admin_com) + sizeof(struct admin_com_indexes))) {
		vfree(buf);
		TEST_FAIL("f_deletesa() isakmp request malformed");
	}
	vfree(buf);

	buf = f_deletesa_unittest(5, (char *[]){ "esp", "inet", "10.0.0.1", "10.0.0.2", "tcp" });
	if (!header_ok(buf, ADMIN_DELETE_SA, ADMIN_PROTO_ESP,
	    sizeof(struct admin_com) + sizeof(struct admin_com_indexes))) {
		vfree(buf);
		TEST_FAIL("f_deletesa() esp request malformed");
	}
	vfree(buf);

	TEST_PASS();
	return 0;
}

static int
test_deletesa_unsupported_proto_returns_null_not_exit(void)
{
	vchar_t *buf;

	TEST_START("f_deletesa() with an unsupported protocol (internal) returns NULL, does not exit");

	buf = f_deletesa_unittest(2, (char *[]){ "internal", "x" });
	if (buf != NULL) {
		vfree(buf);
		TEST_FAIL("an unsupported protocol was accepted");
	}

	TEST_PASS();
	return 0;
}

static int
test_deleteallsadst_embeds_index(void)
{
	vchar_t *buf;

	TEST_START("f_deleteallsadst() embeds an index (used by vpn-disconnect)");

	/* get_proto_and_index() -> get_index() requires ac in {3,4} for the
	 * family+src+dst form; f_vpnd() (this function's real caller)
	 * always supplies the 4-arg shape: family, wildcard source, and
	 * the peer address. */
	buf = f_deleteallsadst_unittest(4,
	    (char *[]){ "isakmp", "inet", "0.0.0.0", "203.0.113.5" });
	if (!header_ok(buf, ADMIN_DELETE_ALL_SA_DST, ADMIN_PROTO_ISAKMP,
	    sizeof(struct admin_com) + sizeof(struct admin_com_indexes))) {
		vfree(buf);
		TEST_FAIL("f_deleteallsadst() request malformed");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_vpnd_is_pure_and_delegates(void)
{
	vchar_t *buf;
	struct admin_com_indexes *ci;
	struct sockaddr_in *src, *dst;
	struct in_addr want_dst;

	TEST_START("f_vpnd() hardcodes 0.0.0.0 as source, no resolver, delegates to f_deleteallsadst()");

	evt_quit_event = 0;
	buf = f_vpnd_unittest(1, (char *[]){ "203.0.113.5" });
	if (!header_ok(buf, ADMIN_DELETE_ALL_SA_DST, ADMIN_PROTO_ISAKMP,
	    sizeof(struct admin_com) + sizeof(struct admin_com_indexes))) {
		vfree(buf);
		TEST_FAIL("f_vpnd() request malformed");
	}
	if (evt_quit_event != EVT_PHASE1_DOWN) {
		vfree(buf);
		TEST_FAIL("evt_quit_event was not set to EVT_PHASE1_DOWN");
	}

	ci = (struct admin_com_indexes *)(buf->v + sizeof(struct admin_com));
	src = (struct sockaddr_in *)&ci->src;
	dst = (struct sockaddr_in *)&ci->dst;

	if (src->sin_addr.s_addr != htonl(INADDR_ANY)) {
		vfree(buf);
		TEST_FAIL("src address is not the hardcoded 0.0.0.0 wildcard");
	}

	if (inet_pton(AF_INET, "203.0.113.5", &want_dst) != 1) {
		vfree(buf);
		TEST_FAIL("test setup: inet_pton() on the expected address failed");
	}
	if (dst->sin_addr.s_addr != want_dst.s_addr) {
		vfree(buf);
		TEST_FAIL("dst address does not match the VPN gateway argument");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

static int
test_get_proto_and_index_unsupported_proto(void)
{
	u_int16_t proto = 0;
	vchar_t *idx;

	TEST_START("get_proto_and_index() rejects a protocol get_index() cannot handle");

	idx = get_proto_and_index_unittest(2, (char *[]){ "internal", "x" }, &proto);
	if (idx != NULL) {
		vfree(idx);
		TEST_FAIL("an unsupported protocol was accepted");
	}

	TEST_PASS();
	return 0;
}

/* ---- Representative -Wl,--wrap=exit cases (errx()-driven guards) ---- */

static int
test_get_combuf_no_args_exits_via_usage(void)
{
	TEST_START("get_combuf() with ac=0 prints usage and exit(0)s, not a crash");

	if (sigsetjmp(exit_jmp, 1) == 0) {
		exit_was_called = 0;
		get_combuf_unittest(0, NULL);
		TEST_FAIL("get_combuf() returned instead of calling exit()");
	}

	if (!exit_was_called)
		TEST_FAIL("exit() was never called");
	if (wrapped_exit_status != 0)
		TEST_FAIL("get_combuf() with no arguments did not exit(0)");

	TEST_PASS();
	return 0;
}

static int
test_get_combuf_unknown_command_returns_null_not_exit(void)
{
	vchar_t *buf;

	TEST_START("get_combuf() with an unrecognized command returns NULL, does not exit");

	buf = get_combuf_unittest(1, (char *[]){ "this-is-not-a-command" });
	if (buf != NULL) {
		vfree(buf);
		TEST_FAIL("an unrecognized command was accepted");
	}

	TEST_PASS();
	return 0;
}

static int
test_get_combuf_known_command_dispatches(void)
{
	vchar_t *buf;

	TEST_START("get_combuf() dispatches a known command string to its handler");

	buf = get_combuf_unittest(1, (char *[]){ "reload-config" });
	if (!header_ok(buf, ADMIN_RELOAD_CONF, 0, sizeof(struct admin_com))) {
		vfree(buf);
		TEST_FAIL("\"reload-config\" did not dispatch to f_reload()");
	}
	vfree(buf);

	/* Shortcut alias, same handler. */
	buf = get_combuf_unittest(1, (char *[]){ "rc" });
	if (!header_ok(buf, ADMIN_RELOAD_CONF, 0, sizeof(struct admin_com))) {
		vfree(buf);
		TEST_FAIL("\"rc\" shortcut did not dispatch to f_reload()");
	}
	vfree(buf);

	TEST_PASS();
	return 0;
}

/*
 * NOT similarly testable: f_getsa()'s (and every other f_*() encoder's)
 * "insufficient arguments"/"unknown protocol" guards call errx(), not
 * exit() directly. errx() is a plain libc function that lives inside a
 * pre-built shared object (libc.so on a normal dynamically-linked
 * build); its own internal call to exit() was already resolved when
 * libc.so itself was compiled/linked, long before this test binary's
 * own link step ever runs -Wl,--wrap=exit -- that flag only rewrites
 * undefined references to "exit" inside the object files THIS link
 * session compiles (which is exactly why get_combuf()'s ac==0 test
 * above works: that exit(0) call is written directly in racoonctl.c,
 * one of this binary's own object files). Confirmed empirically: an
 * earlier version of this test wrapped f_getsa()'s ac!=1 guard the same
 * way and the real errx()/exit() ran anyway, killing the whole test
 * process instead of being caught. Not attempting to test any
 * errx()-driven path here as a result; get_combuf()'s direct exit(0)
 * remains the one representative case in this file.
 */

int
main(void)
{
	int failed = 0;

	printf("\n=== racoonctl.c request-encoding test (make_request/get_combuf/f_*()) ===\n");

	pname = "racoonctl";

	if (test_make_request_header() != 0)
		failed++;
	if (test_trivial_encoders() != 0)
		failed++;
	if (test_getevt_sets_quit_event_and_builds_request() != 0)
		failed++;
	if (test_getsa_and_flushsa_encode_protocol() != 0)
		failed++;
	if (test_getsacert_embeds_index() != 0)
		failed++;
	if (test_deletesa_embeds_index_isakmp_and_esp() != 0)
		failed++;
	if (test_deletesa_unsupported_proto_returns_null_not_exit() != 0)
		failed++;
	if (test_deleteallsadst_embeds_index() != 0)
		failed++;
	if (test_vpnd_is_pure_and_delegates() != 0)
		failed++;
	if (test_get_proto_and_index_unsupported_proto() != 0)
		failed++;
	if (test_get_combuf_no_args_exits_via_usage() != 0)
		failed++;
	if (test_get_combuf_unknown_command_returns_null_not_exit() != 0)
		failed++;
	if (test_get_combuf_known_command_dispatches() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");
	return failed == 0 ? 0 : 1;
}
