// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stubs for test_script_hook_leak.
 *
 * script_hook() (isakmp.c) calls three externally-defined functions this
 * test does not want to pull the real implementations of:
 *
 *  - ipsecdoi_id2str(): the real implementation (ipsec_doi.c) has a large
 *    OpenSSL/X.509 dependency closure for some ID types and is exactly the
 *    function whose allocation contract (issue #72) is under test here --
 *    substituting a controlled test double lets the test dictate exactly
 *    what script_hook() receives (a normal allocation, or NULL to simulate
 *    ipsecdoi_id2str()'s documented OOM return) without needing a real
 *    vchar_t ID payload or OpenSSL.
 *  - privsep_script_exec(): the real implementation forks and execs the
 *    configured script. The stub records that it was called and copies out
 *    the IKE_COOKIE value it was handed (test_stub_last_ike_cookie, issue
 *    #90's regression test in test_script_hook_leak.c) -- envp itself is
 *    freed by script_hook() right after this call returns, so anything a
 *    test wants to inspect afterward has to be copied out here, not held
 *    as a pointer into envp.
 *  - isakmp_cfg_setenv(): only reachable under --enable-hybrid (the
 *    project's default); the real implementation pulls in most of
 *    isakmp_cfg.c (LDAP/PAM/RADIUS/Kerberos backends). script_hook()'s
 *    REMOTE_ID leak is independent of mode-cfg env vars, so the stub is a
 *    no-op that appends nothing.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>

#include "var.h"
#include "vmbuf.h"
#include "gcmalloc.h"
#include "handler.h"
#include "remoteconf.h"
#include "admin.h"
#include "isakmp_cfg.h"
#include "privsep.h"
#include "ipsec_doi.h"

/* script_hook()'s failed-exec error path references this global (defined
 * in remoteconf.c) by name; privsep_script_exec() is stubbed below to
 * always succeed so that branch never runs, but the symbol is still
 * referenced from script_hook()'s compiled code and must resolve at link
 * time. Mirrors remoteconf.c's definition. */
char *script_names[SCRIPT_MAX + 1] = {
	"phase1_up", "phase1_down", "phase1_dead" };

/* Set by the test before calling script_hook() to pick which behaviour of
 * the real ipsecdoi_id2str() to simulate. */
int test_stub_id2str_return_null = 0;

/* Set by this stub itself, at allocation time, so it is always correct by
 * the time script_hook() or anything it calls might free the pointer --
 * see test_script_hook_leak.c's __wrap_free(). */
char *test_stub_id2str_next_result = NULL;
int test_stub_id2str_calls = 0;

char *
ipsecdoi_id2str(const vchar_t *id)
{
	test_stub_id2str_calls++;

	if (test_stub_id2str_return_null) {
		test_stub_id2str_next_result = NULL;
		return NULL;
	}

	/* Mirror the real function's contract: a fresh racoon_malloc()'d,
	 * NUL-terminated buffer that the caller owns. */
	test_stub_id2str_next_result = racoon_malloc(32);
	if (test_stub_id2str_next_result != NULL)
		strcpy(test_stub_id2str_next_result, "test-user@example.com");
	return test_stub_id2str_next_result;
}

int test_stub_privsep_script_exec_calls = 0;

/* Copied out of envp's IKE_COOKIE entry, if present, each call; NULL if
 * this call's envp carried no IKE_COOKIE. Owned by the test; the test is
 * responsible for free()ing a non-NULL value. */
char *test_stub_last_ike_cookie = NULL;

int
privsep_script_exec(char *script, int name, char * const envp[])
{
	int i;
	static const char prefix[] = "IKE_COOKIE=";

	test_stub_privsep_script_exec_calls++;

	free(test_stub_last_ike_cookie);
	test_stub_last_ike_cookie = NULL;
	for (i = 0; envp[i] != NULL; i++) {
		if (strncmp(envp[i], prefix, sizeof(prefix) - 1) == 0) {
			test_stub_last_ike_cookie =
			    strdup(envp[i] + sizeof(prefix) - 1);
			break;
		}
	}

	return 0;
}

int
isakmp_cfg_setenv(struct ph1handle *iph1, char ***envp, int *envc)
{
	return 0;
}
