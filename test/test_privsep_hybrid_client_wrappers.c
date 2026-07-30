// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Tests for privsep.c's ENABLE_HYBRID-only client-side wrappers and their
 * shared port_check() gate: privsep_xauth_login_system(),
 * privsep_accounting_system(), port_check(), and -- HAVE_LIBPAM on top of
 * that -- privsep_accounting_pam(), privsep_xauth_login_pam(),
 * privsep_cleanup_pam(). (The always-available ones are
 * test_privsep_client_wrappers.c.)
 *
 * Both ENABLE_HYBRID and HAVE_LIBPAM are build-time choices this test
 * binary itself does not control (this project's default is
 * ENABLE_HYBRID on, HAVE_LIBPAM only if libpam-dev was present when
 * ./configure ran -- see privsep_priv_test_stubs.c's own file comment for
 * why that matters to this exact test suite). Rather than a second
 * automake conditional/check_PROGRAMS target, this whole file's content
 * is guarded the same way privsep.c itself guards these functions'
 * definitions: #ifdef ENABLE_HYBRID around the file, a nested #ifdef
 * HAVE_LIBPAM around the three PAM cases. A build with either off still
 * gets this binary in `make check`'s output -- with fewer (or, without
 * ENABLE_HYBRID, no) cases actually run -- rather than not building it at
 * all.
 *
 * Same two-case shape per function as test_privsep_client_wrappers.c
 * ("passthrough" as this binary's own root, "wire protocol" with euid
 * dropped to "nobody" against a real forked privsep_priv()), and the same
 * privsep_wire_roundtrip.c driver.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#ifndef ENABLE_HYBRID

int
main(void)
{
	printf("\n=== privsep.c ENABLE_HYBRID client-side wrapper functions "
	    "=== \nSKIPPED: this build has ENABLE_HYBRID off "
	    "(--disable-hybrid)\n\n");
	return 0;
}

#else /* ENABLE_HYBRID */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "var.h"
#include "vmbuf.h"
#include "crypto_openssl.h"
#include "isakmp_var.h"
#include "resolv.h"
#include "isakmp_xauth.h"
#include "isakmp_cfg.h"
#include "admin.h"
#include "privsep.h"

extern int privsep_xauth_login_system(char *usr, char *pwd);
extern int privsep_accounting_system(int port, struct sockaddr *raddr,
    char *usr, int inout);
extern int port_check_unittest(int port);

extern pid_t privsep_wire_roundtrip_start(const char *certdir,
    const char *scriptdir);
extern int privsep_wire_roundtrip_finish(pid_t child_pid);
extern int privsep_wire_roundtrip_drop_priv(void);
extern int privsep_wire_roundtrip_restore_priv(void);

/* Shared global this whole switch reads (privsep.c) / this file's own
 * stub layer defines (privsep_priv_test_stubs.c). Both this process and
 * the privileged child fork() inherits from it get their own copy, so
 * setting pool_size here before forking is what puts the same value on
 * both sides of the wire -- see the file comment on
 * test_accounting_system_wire() below for why that has to line up. */
extern struct isakmp_cfg_config isakmp_cfg_config;

#define TEST_POOL_SIZE 10

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
test_port_check(void)
{
	TEST_START("port_check(), direct");

	isakmp_cfg_config.pool_size = TEST_POOL_SIZE;

	if (port_check_unittest(0) != 0)
		TEST_FAIL("port 0 must be allowed (lower bound)");
	if (port_check_unittest(TEST_POOL_SIZE - 1) != 0)
		TEST_FAIL("pool_size - 1 must be allowed (upper bound)");
	if (port_check_unittest(TEST_POOL_SIZE) == 0)
		TEST_FAIL("pool_size itself must be refused (exclusive upper bound)");
	if (port_check_unittest(-1) == 0)
		TEST_FAIL("a negative port must be refused");

	TEST_PASS();
	return 0;
}

static int
test_xauth_login_system_passthrough(void)
{
	TEST_START("privsep_xauth_login_system(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	/* Stubbed xauth_login_system() (privsep_priv_test_stubs.c) always
	 * returns 0 -- the same stub the wire case's privileged child calls. */
	if (privsep_xauth_login_system("someuser", "somepass") != 0)
		TEST_FAIL("stub xauth_login_system() call failed");

	TEST_PASS();
	return 0;
}

static int
test_xauth_login_system_wire(void)
{
	pid_t child;
	int result;

	TEST_START("privsep_xauth_login_system(), wire protocol (unprivileged)");

	if ((child = privsep_wire_roundtrip_start(NULL, NULL)) < 0)
		TEST_FAIL("privsep_wire_roundtrip_start() failed");

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("seteuid(nobody) failed");
	}

	result = privsep_xauth_login_system("someuser", "somepass");

	if (privsep_wire_roundtrip_restore_priv() != 0)
		TEST_FAIL("seteuid(0) restore failed");

	if (privsep_wire_roundtrip_finish(child) != 0)
		TEST_FAIL("privileged child did not shut down cleanly");

	if (result != 0)
		TEST_FAIL("wire round trip did not return the stub's success");

	TEST_PASS();
	return 0;
}

static int
test_accounting_system_passthrough(void)
{
	struct sockaddr_in raddr;

	TEST_START("privsep_accounting_system(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	memset(&raddr, 0, sizeof(raddr));
	raddr.sin_family = AF_INET;
	raddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (privsep_accounting_system(0, (struct sockaddr *)&raddr,
	    "someuser", 1) != 0)
		TEST_FAIL("stub isakmp_cfg_accounting_system() call failed");

	TEST_PASS();
	return 0;
}

/*
 * The wire case needs isakmp_cfg_config.pool_size set to the same value
 * on both sides of the fork before privsep_wire_roundtrip_start() forks:
 * the privileged side's PRIVSEP_ACCOUNTING_SYSTEM case answers ERANGE via
 * port_check(port) if port >= isakmp_cfg_config.pool_size, and that global
 * defaults to 0 (privsep_priv_test_stubs.c's static definition, never
 * otherwise touched) -- with pool_size left at 0, *every* port would be
 * refused, including port 0 used for the "authorized" case below. Setting
 * it here, before the fork, is what makes port 0 authorized and
 * TEST_POOL_SIZE (out of range) refused on the child's own inherited copy.
 */
static int
test_accounting_system_wire(void)
{
	pid_t child;
	struct sockaddr_in raddr;
	int allowed_result, refused_result, refused_errno;

	TEST_START("privsep_accounting_system(), wire protocol (unprivileged)");

	isakmp_cfg_config.pool_size = TEST_POOL_SIZE;

	if ((child = privsep_wire_roundtrip_start(NULL, NULL)) < 0)
		TEST_FAIL("privsep_wire_roundtrip_start() failed");

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("seteuid(nobody) failed");
	}

	memset(&raddr, 0, sizeof(raddr));
	raddr.sin_family = AF_INET;
	raddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	allowed_result = (privsep_accounting_system(0,
	    (struct sockaddr *)&raddr, "someuser", 1) == 0);

	refused_result = (privsep_accounting_system(TEST_POOL_SIZE,
	    (struct sockaddr *)&raddr, "someuser", 1) != 0);
	refused_errno = errno;

	if (privsep_wire_roundtrip_restore_priv() != 0)
		TEST_FAIL("seteuid(0) restore failed");

	if (privsep_wire_roundtrip_finish(child) != 0)
		TEST_FAIL("privileged child did not shut down cleanly");

	if (!allowed_result)
		TEST_FAIL("in-range port did not round-trip cleanly");
	if (!refused_result || refused_errno != ERANGE)
		TEST_FAIL("out-of-range port was not refused with ERANGE");

	TEST_PASS();
	return 0;
}

#ifdef HAVE_LIBPAM

extern int privsep_accounting_pam(int port, int inout);
extern int privsep_xauth_login_pam(int port, struct sockaddr *raddr,
    char *usr, char *pwd);
extern void privsep_cleanup_pam(int port);

static int
test_accounting_pam_passthrough(void)
{
	TEST_START("privsep_accounting_pam(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	if (privsep_accounting_pam(0, 1) != 0)
		TEST_FAIL("stub isakmp_cfg_accounting_pam() call failed");

	TEST_PASS();
	return 0;
}

static int
test_accounting_pam_wire(void)
{
	pid_t child;
	int allowed_result, refused_result, refused_errno;

	TEST_START("privsep_accounting_pam(), wire protocol (unprivileged)");

	isakmp_cfg_config.pool_size = TEST_POOL_SIZE;

	if ((child = privsep_wire_roundtrip_start(NULL, NULL)) < 0)
		TEST_FAIL("privsep_wire_roundtrip_start() failed");

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("seteuid(nobody) failed");
	}

	allowed_result = (privsep_accounting_pam(0, 1) == 0);
	refused_result = (privsep_accounting_pam(TEST_POOL_SIZE, 1) != 0);
	refused_errno = errno;

	if (privsep_wire_roundtrip_restore_priv() != 0)
		TEST_FAIL("seteuid(0) restore failed");

	if (privsep_wire_roundtrip_finish(child) != 0)
		TEST_FAIL("privileged child did not shut down cleanly");

	if (!allowed_result)
		TEST_FAIL("in-range port did not round-trip cleanly");
	if (!refused_result || refused_errno != ERANGE)
		TEST_FAIL("out-of-range port was not refused with ERANGE");

	TEST_PASS();
	return 0;
}

static int
test_xauth_login_pam_passthrough(void)
{
	struct sockaddr_in raddr;

	TEST_START("privsep_xauth_login_pam(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	memset(&raddr, 0, sizeof(raddr));
	raddr.sin_family = AF_INET;
	raddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (privsep_xauth_login_pam(0, (struct sockaddr *)&raddr,
	    "someuser", "somepass") != 0)
		TEST_FAIL("stub xauth_login_pam() call failed");

	TEST_PASS();
	return 0;
}

static int
test_xauth_login_pam_wire(void)
{
	pid_t child;
	struct sockaddr_in raddr;
	int allowed_result, refused_result, refused_errno;

	TEST_START("privsep_xauth_login_pam(), wire protocol (unprivileged)");

	isakmp_cfg_config.pool_size = TEST_POOL_SIZE;

	if ((child = privsep_wire_roundtrip_start(NULL, NULL)) < 0)
		TEST_FAIL("privsep_wire_roundtrip_start() failed");

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("seteuid(nobody) failed");
	}

	memset(&raddr, 0, sizeof(raddr));
	raddr.sin_family = AF_INET;
	raddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	allowed_result = (privsep_xauth_login_pam(0,
	    (struct sockaddr *)&raddr, "someuser", "somepass") == 0);
	refused_result = (privsep_xauth_login_pam(TEST_POOL_SIZE,
	    (struct sockaddr *)&raddr, "someuser", "somepass") != 0);
	refused_errno = errno;

	if (privsep_wire_roundtrip_restore_priv() != 0)
		TEST_FAIL("seteuid(0) restore failed");

	if (privsep_wire_roundtrip_finish(child) != 0)
		TEST_FAIL("privileged child did not shut down cleanly");

	if (!allowed_result)
		TEST_FAIL("in-range port did not round-trip cleanly");
	if (!refused_result || refused_errno != ERANGE)
		TEST_FAIL("out-of-range port was not refused with ERANGE");

	TEST_PASS();
	return 0;
}

static int
test_cleanup_pam_passthrough(void)
{
	TEST_START("privsep_cleanup_pam(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	errno = 0;
	privsep_cleanup_pam(0);
	if (errno != 0)
		TEST_FAIL("stub cleanup_pam() call reported an unexpected errno");

	TEST_PASS();
	return 0;
}

static int
test_cleanup_pam_wire(void)
{
	pid_t child;
	int refused_errno;

	TEST_START("privsep_cleanup_pam(), wire protocol (unprivileged)");

	isakmp_cfg_config.pool_size = TEST_POOL_SIZE;

	if ((child = privsep_wire_roundtrip_start(NULL, NULL)) < 0)
		TEST_FAIL("privsep_wire_roundtrip_start() failed");

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("seteuid(nobody) failed");
	}

	errno = 0;
	privsep_cleanup_pam(0);
	if (errno != 0) {
		privsep_wire_roundtrip_restore_priv();
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("in-range port reported an unexpected errno");
	}

	errno = 0;
	privsep_cleanup_pam(TEST_POOL_SIZE);
	refused_errno = errno;

	if (privsep_wire_roundtrip_restore_priv() != 0)
		TEST_FAIL("seteuid(0) restore failed");

	if (privsep_wire_roundtrip_finish(child) != 0)
		TEST_FAIL("privileged child did not shut down cleanly");

	if (refused_errno != ERANGE)
		TEST_FAIL("out-of-range port was not refused with ERANGE");

	TEST_PASS();
	return 0;
}

#endif /* HAVE_LIBPAM */

/*
 * Same reasoning as test_privsep_client_wrappers.c's own
 * skip_if_not_root(): every case here but test_port_check() itself needs
 * real root (CAP_SETUID, for the seteuid()-to-"nobody"-and-back dance
 * around a still-root forked privsep_priv() child), and skipping the
 * whole binary rather than only those cases keeps this suite's skip
 * granularity at the same per-binary level automake's own exit-77
 * convention already works at. See CONTRIBUTING.md's "Running the test
 * suite" section.
 */
static int
skip_if_not_root(void)
{
	if (geteuid() == 0)
		return 0;

	printf("\n=== privsep.c ENABLE_HYBRID client-side wrapper functions "
	    "(privsep-priv-extraction follow-up) ===\n"
	    "SKIP: this binary needs real root -- it seteuid()s to \"nobody\" "
	    "around a still-root forked privsep_priv() child to exercise "
	    "privsep.c's wire protocol, which itself needs CAP_SETUID. "
	    "See CONTRIBUTING.md's \"Running the test suite\" section.\n\n");
	return 1;
}

int
main(void)
{
	int failed = 0;

	if (skip_if_not_root())
		return 77;

	printf("\n=== privsep.c ENABLE_HYBRID client-side wrapper functions "
	    "(privsep-priv-extraction follow-up) ===\n");
#ifdef HAVE_LIBPAM
	printf("(HAVE_LIBPAM is on -- PAM cases included)\n");
#else
	printf("(HAVE_LIBPAM is off -- PAM cases skipped; "
	    "test_accounting_pam/xauth_login_pam/cleanup_pam are compiled "
	    "out, not run-time skipped, see this file's header comment)\n");
#endif

	if (test_port_check() != 0) failed++;
	if (test_xauth_login_system_passthrough() != 0) failed++;
	if (test_xauth_login_system_wire() != 0) failed++;
	if (test_accounting_system_passthrough() != 0) failed++;
	if (test_accounting_system_wire() != 0) failed++;
#ifdef HAVE_LIBPAM
	if (test_accounting_pam_passthrough() != 0) failed++;
	if (test_accounting_pam_wire() != 0) failed++;
	if (test_xauth_login_pam_passthrough() != 0) failed++;
	if (test_xauth_login_pam_wire() != 0) failed++;
	if (test_cleanup_pam_passthrough() != 0) failed++;
	if (test_cleanup_pam_wire() != 0) failed++;
#endif

	if (failed) {
		printf("\n=== %d TEST(S) FAILED ===\n\n", failed);
		return 1;
	}

	printf("\n=== ALL TESTS PASSED ===\n\n");
	return 0;
}

#endif /* ENABLE_HYBRID */
