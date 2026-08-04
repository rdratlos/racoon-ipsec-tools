// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Unit Tests for the fixed-size mode-cfg address lists
 *
 * File: test/test_modecfg_addrlist.c
 * Coverage: isakmp_cfg_config_add_addr4() and MAXCFGADDR,
 *           src/racoon/isakmp_cfg.h
 *
 * racoon.conf's "dns4" and "wins4" statements fill dns4[MAXNS] and
 * nbns4[MAXWINS] in struct isakmp_cfg_config.  The cfparse.y rules used
 * to bound-check with "index > MAX" and write through
 * list[index++] directly, so the MAX+1'th server was stored one element
 * past the end of the array.  Both arrays are immediately followed by
 * their own int counter, so that write replaced the counter with an IP
 * address; the next server was then stored at list[address-as-int] and
 * racoon died with SIGSEGV or a glibc "*** buffer overflow detected ***"
 * abort while merely parsing racoon.conf -- reachable from an
 * unprivileged "racoon -t" config check.
 *
 * These tests pin the bound to ">= max" and pin the struct adjacency
 * that makes an off-by-one there memory-corrupting rather than merely
 * wrong.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

/*
 * Only what struct isakmp_cfg_config / struct isakmp_cfg_state need to be
 * complete types.  Deliberately not misc.h/sockmisc.h: those reach for
 * libpfkey.h and pull the daemon in behind them.
 */
#include "vmbuf.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_xauth.h"
#include "isakmp_unity.h"
#include "isakmp_cfg.h"

#define TEST_PASS() printf("PASS\n")
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); return -1; } while(0)
#define TEST_START(name) printf("\n[TEST] %s ... ", name); fflush(stdout)

/* Distinct, non-zero filler addresses; index i maps to 10.0.0.(i+1). */
static in_addr_t
test_addr(int i)
{
	return htonl(0x0a000001 + (in_addr_t)i);
}

/*
 * Test 1: a list accepts exactly max entries.
 */
static int
test_add_addr4_fills_to_max(void)
{
	in_addr_t list[4];
	int index = 0;
	int i;

	TEST_START("isakmp_cfg_config_add_addr4() accepts exactly max entries");

	memset(list, 0, sizeof(list));

	for (i = 0; i < 4; i++) {
		if (isakmp_cfg_config_add_addr4(list, &index, 4,
		    test_addr(i)) != 0)
			TEST_FAIL("append below max was rejected");
		if (index != i + 1)
			TEST_FAIL("index not advanced by one per append");
		if (list[i] != test_addr(i))
			TEST_FAIL("address stored in the wrong slot");
	}

	TEST_PASS();
	return 0;
}

/*
 * Test 2: the max+1'th append is refused, and refused *without* writing.
 *
 * The guard word stands in for the int counter that follows the array in
 * struct isakmp_cfg_config: with the old "index > max" bound it was
 * overwritten with an IP address here.
 */
static int
test_add_addr4_rejects_past_max(void)
{
	struct {
		in_addr_t list[3];
		in_addr_t guard;
	} buf;
	int index = 0;
	int i;

	TEST_START("isakmp_cfg_config_add_addr4() rejects the max+1'th entry");

	memset(&buf, 0, sizeof(buf));
	buf.guard = 0xdeadbeef;

	for (i = 0; i < 3; i++) {
		if (isakmp_cfg_config_add_addr4(buf.list, &index, 3,
		    test_addr(i)) != 0)
			TEST_FAIL("append below max was rejected");
	}

	if (isakmp_cfg_config_add_addr4(buf.list, &index, 3, test_addr(3)) == 0)
		TEST_FAIL("append at index == max was accepted");
	if (buf.guard != 0xdeadbeef)
		TEST_FAIL("rejected append wrote past the end of the list");
	if (index != 3)
		TEST_FAIL("rejected append still advanced the index");

	/* A full list stays full and stays intact for further attempts. */
	if (isakmp_cfg_config_add_addr4(buf.list, &index, 3, test_addr(4)) == 0)
		TEST_FAIL("append to a full list was accepted");
	if (buf.guard != 0xdeadbeef || index != 3)
		TEST_FAIL("second rejected append corrupted the list");

	for (i = 0; i < 3; i++) {
		if (buf.list[i] != test_addr(i))
			TEST_FAIL("rejected append disturbed a stored address");
	}

	TEST_PASS();
	return 0;
}

/*
 * Test 3: the counter really does sit immediately behind the array, in
 * both the racoon.conf-side struct and the client-side one.  This is what
 * turns an off-by-one in the bound check into memory corruption, so it is
 * worth failing loudly if the layout ever changes silently.
 */
static int
test_index_follows_list(void)
{
	TEST_START("address-list counters sit immediately behind their array");

	if (offsetof(struct isakmp_cfg_config, dns4_index) !=
	    offsetof(struct isakmp_cfg_config, dns4) +
	    sizeof(((struct isakmp_cfg_config *)0)->dns4))
		TEST_FAIL("dns4_index no longer follows dns4");

	if (offsetof(struct isakmp_cfg_config, nbns4_index) !=
	    offsetof(struct isakmp_cfg_config, nbns4) +
	    sizeof(((struct isakmp_cfg_config *)0)->nbns4))
		TEST_FAIL("nbns4_index no longer follows nbns4");

	if (offsetof(struct isakmp_cfg_state, dns4_index) !=
	    offsetof(struct isakmp_cfg_state, dns4) +
	    sizeof(((struct isakmp_cfg_state *)0)->dns4))
		TEST_FAIL("dns4_index no longer follows dns4 in cfg_state");

	if (offsetof(struct isakmp_cfg_state, wins4_index) !=
	    offsetof(struct isakmp_cfg_state, wins4) +
	    sizeof(((struct isakmp_cfg_state *)0)->wins4))
		TEST_FAIL("wins4_index no longer follows wins4 in cfg_state");

	TEST_PASS();
	return 0;
}

/*
 * Test 4: filling the real racoon.conf-side lists to their documented
 * limits leaves the neighbouring counters alone.  This is the shape of
 * the reported crash ("dns4 a, b, c, d, e;" plus a five-entry "wins4"),
 * minus the parser.
 */
static int
test_config_lists_do_not_overlap(void)
{
	struct isakmp_cfg_config icc;
	int i;

	TEST_START("dns4/nbns4 overfill does not clobber the other list");

	memset(&icc, 0, sizeof(icc));

	for (i = 0; i < MAXNS + 2; i++) {
		int rc = isakmp_cfg_config_add_addr4(icc.dns4,
		    &icc.dns4_index, MAXNS, test_addr(i));

		if ((i < MAXNS) != (rc == 0))
			TEST_FAIL("dns4 accepted/rejected at the wrong index");
	}

	if (icc.dns4_index != MAXNS)
		TEST_FAIL("dns4_index was clobbered by the overflow");
	if (icc.nbns4_index != 0)
		TEST_FAIL("dns4 overflow reached nbns4_index");
	for (i = 0; i < MAXWINS; i++) {
		if (icc.nbns4[i] != 0)
			TEST_FAIL("dns4 overflow reached the nbns4 list");
	}

	for (i = 0; i < MAXWINS + 2; i++) {
		int rc = isakmp_cfg_config_add_addr4(icc.nbns4,
		    &icc.nbns4_index, MAXWINS, test_addr(i));

		if ((i < MAXWINS) != (rc == 0))
			TEST_FAIL("nbns4 accepted/rejected at the wrong index");
	}

	if (icc.nbns4_index != MAXWINS)
		TEST_FAIL("nbns4_index was clobbered by the overflow");
	if (icc.dns4_index != MAXNS)
		TEST_FAIL("nbns4 overflow reached dns4_index");

	TEST_PASS();
	return 0;
}

/*
 * Test 5: MAXCFGADDR covers both lists.  isakmp_cfg_setenv() formats
 * either dns4 or wins4 into one scratch buffer, and used to size it from
 * MAXNS alone even though MAXWINS is larger.
 */
static int
test_maxcfgaddr_covers_both_lists(void)
{
	TEST_START("MAXCFGADDR covers both MAXNS and MAXWINS");

	if (MAXCFGADDR < MAXNS)
		TEST_FAIL("MAXCFGADDR smaller than MAXNS");
	if (MAXCFGADDR < MAXWINS)
		TEST_FAIL("MAXCFGADDR smaller than MAXWINS");
	if (MAXCFGADDR != MAXNS && MAXCFGADDR != MAXWINS)
		TEST_FAIL("MAXCFGADDR is not the larger of the two");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failures = 0;

	printf("=== mode-cfg address list unit tests ===\n");
	printf("MAXNS = %d, MAXWINS = %d, MAXCFGADDR = %d\n",
	    MAXNS, MAXWINS, MAXCFGADDR);

	failures += test_add_addr4_fills_to_max() < 0;
	failures += test_add_addr4_rejects_past_max() < 0;
	failures += test_index_follows_list() < 0;
	failures += test_config_lists_do_not_overlap() < 0;
	failures += test_maxcfgaddr_covers_both_lists() < 0;

	printf("\n=== Results: %d failures ===\n", failures);
	return failures ? 1 : 0;
}
