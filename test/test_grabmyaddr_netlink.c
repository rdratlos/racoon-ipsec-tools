// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for the uninitialised/out-of-bounds read in
 * netlink_process_route() (issue #73): the route-attribute length passed
 * to parse_rtattr() was computed with IFA_PAYLOAD(h) -- sized for
 * struct ifaddrmsg (8 bytes) -- instead of RTM_PAYLOAD(h) -- sized for the
 * struct rtmsg (12 bytes) that RTM_NEWROUTE/RTM_DELROUTE messages actually
 * carry. The 4-byte header-size mismatch makes parse_rtattr() walk 4 bytes
 * past the real attribute data.
 *
 * netlink_parse_route_attrs() is static in grabmyaddr.c; grabmyaddr.c is
 * compiled here (grabmyaddr_unittest_src.c) with -DENABLE_UNITTEST to
 * expose the thin wrapper netlink_parse_route_attrs_unittest() used below
 * (see the ENABLE_UNITTEST block next to netlink_process_route() in
 * grabmyaddr.c).
 *
 * Two cases:
 *
 *  - test_sentinel_attr_not_parsed(): builds a message in a stack buffer
 *    with 4 well-defined bytes of "trap" content immediately after the
 *    real attribute data (decoding as a spurious struct rtattr with a
 *    recognisable rta_type). Fully in-bounds, no ASan/valgrind dependency
 *    -- the wrong length makes the parser walk into the trap and record
 *    it, which the test asserts against, so it is self-validating under a
 *    plain `make check`.
 *
 *  - test_no_oob_read(): places the same real attribute data in a buffer
 *    heap-allocated to *exactly* its size, with no trailing slack at all.
 *    The wrong length then makes parse_rtattr() read 4 bytes past the end
 *    of the allocation -- a real heap buffer overread, caught by
 *    AddressSanitizer / valgrind (`make check-valgrind`), reproducing the
 *    original "Conditional jump or move depends on uninitialised value(s)"
 *    finding.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

extern void netlink_parse_route_attrs_unittest(struct nlmsghdr *h,
    struct rtmsg *rtm, struct rtattr *rta[RTA_MAX+1]);

static int failures = 0;

#define CHECK(cond, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
			failures++; \
		} else { \
			printf("PASS: %s\n", msg); \
		} \
	} while (0)

/* An RTA type that is unrelated to RTA_DST and small enough to survive
 * netlink_parse_route_attrs()'s (also-buggy) IFA_MAX bound -- see issue
 * #73's "Similar issues checked and ruled out" note on the max parameter. */
#define SENTINEL_RTA_TYPE	RTA_GATEWAY

static void
test_sentinel_attr_not_parsed(void)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		struct rtattr dst_rta;
		struct in_addr dst_addr;
		struct rtattr sentinel_rta; /* trailing "trap", outside nlmsg_len */
	} msg;
	struct rtattr *rta[RTA_MAX+1];

	memset(&msg, 0, sizeof(msg));

	msg.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)) +
	    RTA_SPACE(sizeof(msg.dst_addr));
	msg.n.nlmsg_type = RTM_NEWROUTE;

	msg.r.rtm_family = AF_INET;
	msg.r.rtm_type = RTN_LOCAL;
	msg.r.rtm_table = RT_TABLE_LOCAL;

	msg.dst_rta.rta_type = RTA_DST;
	msg.dst_rta.rta_len = RTA_LENGTH(sizeof(msg.dst_addr));
	msg.dst_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */

	/* Trap: a well-formed, in-bounds struct rtattr sitting 4 bytes past
	 * the real attribute data -- i.e. exactly where IFA_PAYLOAD(h)'s
	 * 4-byte over-count reaches, but RTM_PAYLOAD(h) would not. */
	msg.sentinel_rta.rta_type = SENTINEL_RTA_TYPE;
	msg.sentinel_rta.rta_len = RTA_LENGTH(0);

	netlink_parse_route_attrs_unittest(&msg.n, &msg.r, rta);

	CHECK(rta[RTA_DST] != NULL, "RTA_DST is parsed from the real attribute data");
	CHECK(rta[SENTINEL_RTA_TYPE] == NULL,
	    "the 4-byte trap past nlmsg_len must NOT be parsed as a real attribute "
	    "(regression test for issue #73: IFA_PAYLOAD(h) over-counted by 4 bytes)");
}

static void
test_no_oob_read(void)
{
	size_t hdr_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	size_t attr_len = RTA_SPACE(sizeof(struct in_addr));
	size_t exact_len = hdr_len + attr_len;
	struct nlmsghdr *h;
	struct rtmsg *rtm;
	struct rtattr *dst_rta;
	struct in_addr addr;
	struct rtattr *rta[RTA_MAX+1];

	/* Heap buffer sized to *exactly* the legitimate content -- no
	 * trailing slack at all, so IFA_PAYLOAD(h)'s 4-byte over-count reads
	 * past the end of this allocation and ASan/valgrind must flag it. */
	h = malloc(exact_len);
	if (h == NULL) {
		CHECK(0, "malloc for exact-size buffer failed");
		return;
	}
	memset(h, 0, exact_len);

	h->nlmsg_len = exact_len;
	h->nlmsg_type = RTM_NEWROUTE;

	rtm = NLMSG_DATA(h);
	rtm->rtm_family = AF_INET;
	rtm->rtm_type = RTN_LOCAL;
	rtm->rtm_table = RT_TABLE_LOCAL;

	dst_rta = RTM_RTA(rtm);
	dst_rta->rta_type = RTA_DST;
	dst_rta->rta_len = RTA_LENGTH(sizeof(addr));
	addr.s_addr = htonl(0x7f000001);
	memcpy(RTA_DATA(dst_rta), &addr, sizeof(addr));

	netlink_parse_route_attrs_unittest(h, rtm, rta);

	CHECK(rta[RTA_DST] != NULL,
	    "RTA_DST is still parsed correctly from an exact-size buffer");

	free(h);
}

int
main(void)
{
	test_sentinel_attr_not_parsed();
	test_no_oob_read();

	if (failures > 0) {
		fprintf(stderr, "\n%d check(s) failed\n", failures);
		return 1;
	}

	printf("\nAll checks passed\n");
	return 0;
}
