// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for PRIVSEP_SOCKET's policy gate (issue #105).
 *
 * The privileged process decides which socket() calls it will make on the
 * unprivileged one's behalf. That decision used to allow PF_INET and
 * PF_INET6 only -- and so refused the PF_KEY socket pfkey_dump_sadb()
 * (pfkey.c) needs, which the unprivileged process cannot open for itself
 * (no CAP_NET_ADMIN) and cannot borrow from the main loop's own pfkey
 * socket.
 *
 * That refusal broke every SADB dump under privsep: "racoonctl vd" and
 * "racoonctl show-sa esp|ah|ipsec", plus purge_remote()'s fallback path
 * (isakmp_inf.c), which is how DPD and peer-initiated teardown also reach
 * the SADB. Before this issue's containment work it did worse than break
 * them -- the refusal ran into the dispatch loop's _exit(), so any of
 * those commands took the entire daemon down with every live SA on it.
 *
 * It survived that long because it is unreachable from a test binary in
 * production: the gate runs only inside privsep_init()'s
 * privilege-dropping fork(), so nothing short of a live privsep host ever
 * evaluated it (a real "racoonctl vd" on an Arch roadwarrior is what
 * finally did). privsep_socket_allowed() exists as a separate predicate
 * precisely so the policy can be asserted here instead.
 *
 * What must hold, in both directions:
 *   - the sockets racoon legitimately asks for are allowed, or privsep
 *     silently breaks features;
 *   - nothing wider is, or privsep stops being a boundary. PF_KEY is
 *     allowed in exactly libipsec pfkey_open()'s shape
 *     (SOCK_RAW/PF_KEY_V2) and no other, so a compromised child cannot
 *     turn "I need to dump the SADB" into "open me an arbitrary socket".
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/pfkeyv2.h>

extern int privsep_socket_allowed_unittest(int domain, int type,
    int protocol);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

struct policy_case {
	int domain;
	int type;
	int protocol;
	int allowed;
	const char *what;
};

static const struct policy_case cases[] = {
	/* What racoon actually asks for -- refusing any of these is a bug */
	{ PF_INET,  SOCK_DGRAM, 0,          1, "IPv4 ISAKMP socket" },
	{ PF_INET6, SOCK_DGRAM, 0,          1, "IPv6 ISAKMP socket" },
	{ PF_KEY,   SOCK_RAW,   PF_KEY_V2,  1, "PF_KEY socket for pfkey_dump_sadb()" },

	/* PF_KEY only in pfkey_open()'s exact shape */
	{ PF_KEY,   SOCK_DGRAM, PF_KEY_V2,  0, "PF_KEY with the wrong type" },
	{ PF_KEY,   SOCK_RAW,   0,          0, "PF_KEY with the wrong protocol" },
	{ PF_KEY,   SOCK_STREAM, PF_KEY_V2, 0, "PF_KEY as a stream socket" },

	/* No other family, whatever type/protocol it claims */
	{ PF_LOCAL, SOCK_STREAM, 0,         0, "a unix-domain socket" },
	{ PF_LOCAL, SOCK_RAW,   PF_KEY_V2,  0, "unix-domain wearing PF_KEY's type/protocol" },
	{ PF_PACKET, SOCK_RAW,  0,          0, "a packet socket" },
	{ -1,       SOCK_DGRAM, 0,          0, "a negative domain" },

	/*
	 * These two document current behaviour rather than a desired
	 * property, and are the one place this table is not also an
	 * endorsement. The INET families are admitted for any type and
	 * protocol -- as they always have been -- so a compromised child
	 * can ask the privileged process for a raw socket it would need
	 * CAP_NET_RAW to open itself. Every caller in the tree
	 * (isakmp_open(), and getlocaladdr()/sendfromto() in sockmisc.c)
	 * asks for SOCK_DGRAM/0 and nothing else, so narrowing this the way
	 * PF_KEY is narrowed would cost nothing -- but it is a privilege
	 * change unrelated to the PF_KEY bug this file exists for, so it is
	 * recorded as a follow-up rather than made here. Flip these two
	 * rows to 0 in the same commit that narrows the gate.
	 */
	{ PF_INET,  SOCK_RAW,   IPPROTO_RAW, 1, "a raw IPv4 socket (current behaviour)" },
	{ PF_INET6, SOCK_RAW,   IPPROTO_RAW, 1, "a raw IPv6 socket (current behaviour)" },
};

static int
test_socket_policy(void)
{
	size_t i;
	int failures = 0;

	TEST_START("privsep_socket_allowed() admits exactly what racoon needs");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int got = privsep_socket_allowed_unittest(cases[i].domain,
		    cases[i].type, cases[i].protocol) ? 1 : 0;

		if (got != cases[i].allowed) {
			printf("\n    %s %s: expected %s",
			    got ? "allowed" : "refused", cases[i].what,
			    cases[i].allowed ? "allowed" : "refused");
			failures++;
		}
	}

	if (failures != 0)
		TEST_FAIL("policy does not match the table above");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== PRIVSEP_SOCKET policy gate test (issue #105) ===\n");

	if (test_socket_policy() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
