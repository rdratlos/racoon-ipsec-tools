// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for issue #34: memcmp() -> CRYPTO_memcmp() hardening of
 * cryptographic comparisons against timing side channels.
 *
 * Unlike a synthetic CRYPTO_memcmp()-vs-memcmp() equivalence check, this
 * drives the actual call site changed in nattraversal.c: natt_compare_addr_hash()
 * hashes a phase-1 handle's local/remote address with natt_hash_addr() and
 * then feeds both a matching and a tampered NAT-D payload through the
 * CRYPTO_memcmp() comparison that replaced memcmp() there.  A regression that
 * reverted the replacement, or that broke it (e.g. comparing the wrong
 * buffer or length), would show up as a wrong accept/reject result here.
 *
 * natt_hash_addr()/natt_compare_addr_hash() are non-static, but their only
 * always-built dependency is oakley_hash() (falls back to MD5 without a
 * negotiated proposal) from oakley.c, which itself has a very large
 * dependency closure (isakmp/handler/privsep/...).  Both racoon sources are
 * therefore built with -ffunction-sections and linked with --gc-sections
 * (same technique as test_ipsec_doi_sa and test_vendorid_bounds), so only
 * the functions actually reachable from this test are pulled in.
 * privsep_socket/privsep_bind/privsep_setsockopt (needed transitively via
 * sockmisc.o, which natt_hash_addr()'s plog() call drags in through
 * saddr2str()) are stubbed by rsalist_test_stubs.c, same as
 * test_rsa_comprehensive/test_sockmisc/test_rsalist.
 *
 * Built only with --enable-natt, since nattraversal.c's struct ph1handle
 * fields (natt_flags, natt_options) only exist under ENABLE_NATT.
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
#include "handler.h"
#include "remoteconf.h"
#include "oakley.h"
#include "nattraversal.h"

#define TEST_PASS() do { printf("✓ PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("✗ FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static void
init_ph1handle(struct ph1handle *iph1, struct isakmpsa *approval,
    struct sockaddr_in *local, struct sockaddr_in *remote)
{
	memset(iph1, 0, sizeof(*iph1));
	memset(approval, 0, sizeof(*approval));
	memset(local, 0, sizeof(*local));
	memset(remote, 0, sizeof(*remote));

	local->sin_family = AF_INET;
	local->sin_port = htons(500);
	local->sin_addr.s_addr = htonl(0x0A000001);	/* 10.0.0.1 */
	remote->sin_family = AF_INET;
	remote->sin_port = htons(500);
	remote->sin_addr.s_addr = htonl(0x0A000002);	/* 10.0.0.2 */

	approval->hashtype = OAKLEY_ATTR_HASH_ALG_SHA;
	iph1->approval = approval;
	iph1->local = (struct sockaddr *)local;
	iph1->remote = (struct sockaddr *)remote;
	memset(iph1->index.i_ck, 0x11, sizeof(cookie_t));
	memset(iph1->index.r_ck, 0x22, sizeof(cookie_t));
}

/*
 * A NAT-D payload that matches the locally-recomputed hash must be
 * accepted, and the corresponding NAT_DETECTED_ME flag cleared.
 */
static int
test_natd_match(void)
{
	struct ph1handle iph1;
	struct isakmpsa approval;
	struct sockaddr_in local, remote;
	vchar_t *natd;
	int ok;

	TEST_START("matching NAT-D hash is accepted");

	init_ph1handle(&iph1, &approval, &local, &remote);
	iph1.natt_flags = NAT_DETECTED_ME;

	natd = natt_hash_addr(&iph1, iph1.local);
	if (natd == NULL)
		TEST_FAIL("natt_hash_addr() returned NULL");

	ok = natt_compare_addr_hash(&iph1, natd, 0);
	vfree(natd);

	if (ok != 1)
		TEST_FAIL("matching NAT-D hash was rejected");
	if (iph1.natt_flags & NAT_DETECTED_ME)
		TEST_FAIL("NAT_DETECTED_ME flag not cleared on match");

	TEST_PASS();
	return 0;
}

/*
 * A NAT-D payload that differs from the recomputed hash by a single bit
 * must be rejected -- this is the CRYPTO_memcmp() != 0 branch introduced
 * by the hardening change.
 */
static int
test_natd_tampered(void)
{
	struct ph1handle iph1;
	struct isakmpsa approval;
	struct sockaddr_in local, remote;
	vchar_t *natd;
	int ok;

	TEST_START("tampered NAT-D hash is rejected");

	init_ph1handle(&iph1, &approval, &local, &remote);
	iph1.natt_flags = NAT_DETECTED_ME;

	natd = natt_hash_addr(&iph1, iph1.local);
	if (natd == NULL)
		TEST_FAIL("natt_hash_addr() returned NULL");

	natd->v[0] ^= 0xFF;

	ok = natt_compare_addr_hash(&iph1, natd, 0);
	vfree(natd);

	if (ok != 0)
		TEST_FAIL("tampered NAT-D hash was accepted");
	if (!(iph1.natt_flags & NAT_DETECTED_ME))
		TEST_FAIL("NAT_DETECTED_ME flag cleared despite mismatch");

	TEST_PASS();
	return 0;
}

/*
 * A NAT-D payload of the wrong length must be rejected without engaging
 * CRYPTO_memcmp() at all (the length check short-circuits it).
 */
static int
test_natd_length_mismatch(void)
{
	struct ph1handle iph1;
	struct isakmpsa approval;
	struct sockaddr_in local, remote;
	vchar_t *natd, *short_natd;
	int ok;

	TEST_START("short NAT-D hash is rejected");

	init_ph1handle(&iph1, &approval, &local, &remote);
	iph1.natt_flags = NAT_DETECTED_ME;

	natd = natt_hash_addr(&iph1, iph1.local);
	if (natd == NULL)
		TEST_FAIL("natt_hash_addr() returned NULL");

	short_natd = vmalloc(natd->l - 1);
	if (short_natd == NULL) {
		vfree(natd);
		TEST_FAIL("vmalloc() failed");
	}
	memcpy(short_natd->v, natd->v, short_natd->l);
	vfree(natd);

	ok = natt_compare_addr_hash(&iph1, short_natd, 0);
	vfree(short_natd);

	if (ok != 0)
		TEST_FAIL("short NAT-D hash was accepted");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== NAT-D CRYPTO_memcmp regression tests (issue #34) ===\n");

	if (test_natd_match() != 0)
		failed++;
	if (test_natd_tampered() != 0)
		failed++;
	if (test_natd_length_mismatch() != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
