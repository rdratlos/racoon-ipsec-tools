// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Tests for privsep.c's client-side wrappers that have no ENABLE_HYBRID/
 * HAVE_LIBPAM dependency: privsep_eay_get_pkcs1privkey(), privsep_getpsk(),
 * privsep_script_exec(), privsep_socket(), privsep_bind(). (The
 * ENABLE_HYBRID/HAVE_LIBPAM ones -- port_check(), privsep_xauth_login_system(),
 * privsep_accounting_system(), privsep_accounting_pam(),
 * privsep_xauth_login_pam(), privsep_cleanup_pam() -- are
 * test_privsep_hybrid_client_wrappers.c.)
 *
 * Every one of these opens with "if (geteuid() == 0) return <real syscall
 * or function>(...)" and only builds/sends a wire message when that is
 * false; privsep_bind() instead tries the real bind() unconditionally
 * first and only escalates on EACCES-while-unprivileged. Each function
 * below therefore gets two cases:
 *
 *  - "..., passthrough": called as this test binary's own root (the
 *    normal case for `make check`), asserting the real syscall/function
 *    ran directly with no wire traffic at all. For the two that call back
 *    into a stubbed function (eay_get_pkcs1privkey()/getpsk(), both
 *    stubbed by privsep_priv_test_stubs.c, linked into this binary the
 *    same as every test_privsep_priv_*.c) this is the *same* stub the
 *    wire-protocol case's privileged child also calls -- deliberately: it
 *    is what makes the two cases comparable at all without a real
 *    OpenSSL/localconf dependency in this binary.
 *  - "..., wire protocol": this process's effective uid is dropped to
 *    "nobody" (privsep_wire_roundtrip.c) so the same call takes the wire
 *    branch instead, against a forked child running the real privsep_priv()
 *    (privsep_unittest_src.c + privsep_priv_test_stubs.c) -- i.e. real
 *    production code on both ends of the real wire protocol, the mirror
 *    image of what test_privsep_priv_*.c already covers by hand-crafting
 *    the wire messages itself instead of calling these functions.
 *
 * privsep_socket()/privsep_bind() are the two the task brief flagged as
 * "if possible, socket functions have shown to be not easily unit
 * tested": both are covered here because the real dispatch loop this
 * binary forks into does the real socket()/bind() syscalls itself (same
 * as production), so there is no socket-behaviour simulation to get
 * wrong -- only the SCM_RIGHTS fd handoff and the two policy gates
 * (privsep_socket_allowed()/the ISAKMP port check) are actually being
 * exercised here, both already real code.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "var.h"
#include "vmbuf.h"
#include "crypto_openssl.h"
#include "isakmp_var.h"
#include "remoteconf.h"
#include "admin.h"
#include "privsep.h"

extern vchar_t *privsep_eay_get_pkcs1privkey(char *path);
extern int privsep_script_exec(char *script, int name, char *const envp[],
    int wait_for_exit);
extern vchar_t *privsep_getpsk(const char *str, int keylen);
extern int privsep_socket(int domain, int type, int protocol);
extern int privsep_bind(int s, const struct sockaddr *addr, socklen_t addrlen);

extern pid_t privsep_wire_roundtrip_start(const char *certdir,
    const char *scriptdir);
extern int privsep_wire_roundtrip_finish(pid_t child_pid);
extern int privsep_wire_roundtrip_drop_priv(void);
extern int privsep_wire_roundtrip_restore_priv(void);

/* From privsep_priv_test_stubs.c -- see that file's header comment */
extern int privsep_priv_test_script_exec_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
test_eay_get_pkcs1privkey_passthrough(void)
{
	vchar_t *key;

	TEST_START("privsep_eay_get_pkcs1privkey(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	if ((key = privsep_eay_get_pkcs1privkey("/tmp/does-not-matter.pem"))
	    == NULL)
		TEST_FAIL("stub eay_get_pkcs1privkey() call failed");

	if (key->l != strlen("stub-pkcs1-private-key") ||
	    memcmp(key->v, "stub-pkcs1-private-key", key->l) != 0) {
		vfree(key);
		TEST_FAIL("unexpected key bytes");
	}
	vfree(key);

	if (privsep_eay_get_pkcs1privkey("/tmp/trigger-FAIL.pem") != NULL)
		TEST_FAIL("stub's FAIL-path marker did not propagate");
	if (errno != ENOENT)
		TEST_FAIL("expected errno ENOENT from the stub's failure path");

	TEST_PASS();
	return 0;
}

static int
test_eay_get_pkcs1privkey_wire(void)
{
	pid_t child;
	vchar_t *key;
	int ok_result, fail_result, fail_errno;

	TEST_START("privsep_eay_get_pkcs1privkey(), wire protocol (unprivileged)");

	if ((child = privsep_wire_roundtrip_start(NULL, NULL)) < 0)
		TEST_FAIL("privsep_wire_roundtrip_start() failed");

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("seteuid(nobody) failed");
	}

	key = privsep_eay_get_pkcs1privkey("/tmp/does-not-matter.pem");
	ok_result = (key != NULL);
	if (key != NULL &&
	    (key->l != strlen("stub-pkcs1-private-key") ||
	     memcmp(key->v, "stub-pkcs1-private-key", key->l) != 0))
		ok_result = 0;
	if (key != NULL)
		vfree(key);

	fail_result = (privsep_eay_get_pkcs1privkey("/tmp/trigger-FAIL.pem")
	    == NULL);
	fail_errno = errno;

	if (privsep_wire_roundtrip_restore_priv() != 0)
		TEST_FAIL("seteuid(0) restore failed");

	if (privsep_wire_roundtrip_finish(child) != 0)
		TEST_FAIL("privileged child did not shut down cleanly");

	if (!ok_result)
		TEST_FAIL("wire round trip did not return the stub's key bytes");
	if (!fail_result || fail_errno != ENOENT)
		TEST_FAIL("wire round trip did not propagate the stub's ENOENT");

	TEST_PASS();
	return 0;
}

static int
test_getpsk_passthrough(void)
{
	vchar_t *psk;

	TEST_START("privsep_getpsk(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	if ((psk = privsep_getpsk("someone@example.com", 0)) == NULL)
		TEST_FAIL("stub getpsk() call failed");
	if (psk->l != strlen("stub-psk-secret!") ||
	    memcmp(psk->v, "stub-psk-secret!", psk->l) != 0) {
		vfree(psk);
		TEST_FAIL("unexpected psk bytes");
	}
	vfree(psk);

	TEST_PASS();
	return 0;
}

static int
test_getpsk_wire(void)
{
	pid_t child;
	vchar_t *psk;
	int ok_result;

	TEST_START("privsep_getpsk(), wire protocol (unprivileged)");

	if ((child = privsep_wire_roundtrip_start(NULL, NULL)) < 0)
		TEST_FAIL("privsep_wire_roundtrip_start() failed");

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("seteuid(nobody) failed");
	}

	psk = privsep_getpsk("someone@example.com", 0);
	ok_result = (psk != NULL && psk->l == strlen("stub-psk-secret!") &&
	    memcmp(psk->v, "stub-psk-secret!", psk->l) == 0);
	if (psk != NULL)
		vfree(psk);

	if (privsep_wire_roundtrip_restore_priv() != 0)
		TEST_FAIL("seteuid(0) restore failed");

	if (privsep_wire_roundtrip_finish(child) != 0)
		TEST_FAIL("privileged child did not shut down cleanly");

	if (!ok_result)
		TEST_FAIL("wire round trip did not return the stub's psk bytes");

	TEST_PASS();
	return 0;
}

static int
test_script_exec_passthrough(void)
{
	char *envp[] = { NULL };
	int calls_before;

	TEST_START("privsep_script_exec(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	calls_before = privsep_priv_test_script_exec_calls;
	if (privsep_script_exec("/tmp/whatever.sh", SCRIPT_PHASE1_UP, envp, 0)
	    != 0)
		TEST_FAIL("stub script_exec() call failed");
	if (privsep_priv_test_script_exec_calls != calls_before + 1)
		TEST_FAIL("stub script_exec() was not actually reached");

	TEST_PASS();
	return 0;
}

static int
test_script_exec_wire(void)
{
	pid_t child;
	char scriptdir[] = "/tmp/privsep_client_wrappers_scripts.XXXXXX";
	char scriptpath[1024];
	FILE *f;
	char *envp[] = { NULL };
	int allowed_result, refused_result, refused_errno;

	TEST_START("privsep_script_exec(), wire protocol (unprivileged)");

	if (mkdtemp(scriptdir) == NULL)
		TEST_FAIL("mkdtemp() failed");
	snprintf(scriptpath, sizeof(scriptpath), "%s/phase1-up.sh", scriptdir);
	if ((f = fopen(scriptpath, "w")) == NULL) {
		rmdir(scriptdir);
		TEST_FAIL("could not create test script file");
	}
	fclose(f);

	if ((child = privsep_wire_roundtrip_start(NULL, scriptdir)) < 0) {
		unlink(scriptpath);
		rmdir(scriptdir);
		TEST_FAIL("privsep_wire_roundtrip_start() failed");
	}

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		unlink(scriptpath);
		rmdir(scriptdir);
		TEST_FAIL("seteuid(nobody) failed");
	}

	/* Authorized: script sits inside the scriptdir passed above. */
	allowed_result = (privsep_script_exec(scriptpath, SCRIPT_PHASE1_UP,
	    envp, 0) == 0);

	/* Refused: outside the authorized scriptdir -- unsafe_path() must
	 * reject it, answering EPERM without ending the privileged process
	 * (the next request above already proved the loop still serves). */
	refused_result = (privsep_script_exec("/etc/passwd", SCRIPT_PHASE1_UP,
	    envp, 0) != 0);
	refused_errno = errno;

	if (privsep_wire_roundtrip_restore_priv() != 0) {
		unlink(scriptpath);
		rmdir(scriptdir);
		TEST_FAIL("seteuid(0) restore failed");
	}

	if (privsep_wire_roundtrip_finish(child) != 0) {
		unlink(scriptpath);
		rmdir(scriptdir);
		TEST_FAIL("privileged child did not shut down cleanly");
	}

	unlink(scriptpath);
	rmdir(scriptdir);

	if (!allowed_result)
		TEST_FAIL("authorized script_exec did not round-trip cleanly");
	if (!refused_result || refused_errno != EPERM)
		TEST_FAIL("unauthorized script path was not refused with EPERM");

	TEST_PASS();
	return 0;
}

static int
test_socket_passthrough(void)
{
	int s;

	TEST_START("privsep_socket(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	if ((s = privsep_socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		TEST_FAIL("privsep_socket() failed");
	close(s);

	TEST_PASS();
	return 0;
}

static int
test_socket_wire(void)
{
	pid_t child;
	int s, allowed_ok, refused_ok, refused_errno;
	struct sockaddr_in sin;
	socklen_t slen;

	TEST_START("privsep_socket(), wire protocol (unprivileged)");

	if ((child = privsep_wire_roundtrip_start(NULL, NULL)) < 0)
		TEST_FAIL("privsep_wire_roundtrip_start() failed");

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("seteuid(nobody) failed");
	}

	/* Authorized: PF_INET/SOCK_DGRAM is always allowed
	 * (privsep_socket_allowed()). The descriptor comes back over a real
	 * SCM_RIGHTS handoff from the real dispatch loop's real socket() --
	 * confirm it is a real, usable socket, not just "not -1". */
	s = privsep_socket(PF_INET, SOCK_DGRAM, 0);
	allowed_ok = (s >= 0);
	if (allowed_ok) {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin.sin_port = 0;
		if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) != 0)
			allowed_ok = 0;
		slen = sizeof(sin);
		if (allowed_ok &&
		    (getsockname(s, (struct sockaddr *)&sin, &slen) != 0 ||
		     sin.sin_port == 0))
			allowed_ok = 0;
		close(s);
	}

	/* Refused: PF_UNIX is not in privsep_socket_allowed()'s list. */
	s = privsep_socket(PF_UNIX, SOCK_STREAM, 0);
	refused_ok = (s < 0);
	refused_errno = errno;
	if (s >= 0)
		close(s);

	if (privsep_wire_roundtrip_restore_priv() != 0)
		TEST_FAIL("seteuid(0) restore failed");

	if (privsep_wire_roundtrip_finish(child) != 0)
		TEST_FAIL("privileged child did not shut down cleanly");

	if (!allowed_ok)
		TEST_FAIL("authorized privsep_socket() did not hand back a usable socket");
	if (!refused_ok || refused_errno != EPERM)
		TEST_FAIL("unauthorized domain was not refused with EPERM");

	TEST_PASS();
	return 0;
}

static int
test_bind_passthrough(void)
{
	int s;
	struct sockaddr_in sin;

	TEST_START("privsep_bind(), passthrough (root)");

	if (geteuid() != 0)
		TEST_FAIL("must run as root for the passthrough case");

	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		TEST_FAIL("socket() failed");

	/*
	 * Every real caller of privsep_bind() (isakmp.c's own socket setup)
	 * sets this immediately before calling it -- SO_REUSEADDR on Linux,
	 * SO_REUSEPORT elsewhere, the same #ifdef split isakmp.c itself
	 * uses. Without it, this bind to PORT_ISAKMP below collides with
	 * EADDRINUSE on any host already running a real racoon (or another
	 * ISAKMP listener) bound to that port system-wide -- see
	 * test_privsep_priv_control_cases.c's identical fix for
	 * PRIVSEP_BIND's PORT_ISAKMP_NATT case, reported the same way
	 * against a real Ubuntu Bionic host running racoon.
	 */
	{
		int yes = 1;
		if (setsockopt(s, SOL_SOCKET,
#ifdef __linux__
		    SO_REUSEADDR,
#else
		    SO_REUSEPORT,
#endif
		    &yes, sizeof(yes)) != 0) {
			close(s);
			TEST_FAIL("setsockopt(REUSE) failed");
		}
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(PORT_ISAKMP);

	/* As root the real bind() succeeds directly -- privsep_bind() never
	 * even looks at privsep_sock. */
	if (privsep_bind(s, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
		close(s);
		TEST_FAIL("privsep_bind() to PORT_ISAKMP failed as root");
	}
	close(s);

	TEST_PASS();
	return 0;
}

static int
test_bind_wire(void)
{
	pid_t child;
	int s, allowed_ok, refused_ok, refused_errno;
	struct sockaddr_in sin;
	socklen_t slen;

	TEST_START("privsep_bind(), wire protocol (unprivileged)");

	if ((child = privsep_wire_roundtrip_start(NULL, NULL)) < 0)
		TEST_FAIL("privsep_wire_roundtrip_start() failed");

	if (privsep_wire_roundtrip_drop_priv() != 0) {
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("seteuid(nobody) failed");
	}

	/*
	 * Authorized: PORT_ISAKMP is a privileged (<1024) port, so the real
	 * bind() below fails EACCES as "nobody" and privsep_bind() escalates
	 * -- the descriptor is handed to the real dispatch loop's real
	 * bind(), which (still root there) succeeds and hands the same
	 * underlying socket back bound.
	 */
	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		privsep_wire_roundtrip_restore_priv();
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("socket() failed");
	}
	/* Same REUSE fix as test_bind_passthrough() above -- required here
	 * too, not just for the passthrough case, since the escalated bind
	 * below is a real bind() on the privileged side. */
	{
		int yes = 1;
		if (setsockopt(s, SOL_SOCKET,
#ifdef __linux__
		    SO_REUSEADDR,
#else
		    SO_REUSEPORT,
#endif
		    &yes, sizeof(yes)) != 0) {
			close(s);
			privsep_wire_roundtrip_restore_priv();
			privsep_wire_roundtrip_finish(child);
			TEST_FAIL("setsockopt(REUSE) failed");
		}
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(PORT_ISAKMP);

	allowed_ok = (privsep_bind(s, (struct sockaddr *)&sin, sizeof(sin))
	    == 0);
	if (allowed_ok) {
		slen = sizeof(sin);
		if (getsockname(s, (struct sockaddr *)&sin, &slen) != 0 ||
		    ntohs(sin.sin_port) != PORT_ISAKMP)
			allowed_ok = 0;
	}
	close(s);

	/* Refused: an ordinary high port is not one of the ISAKMP ports the
	 * privileged side's port_check-equivalent authorizes, so escalating
	 * still answers EPERM instead of silently binding it. */
	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		privsep_wire_roundtrip_restore_priv();
		privsep_wire_roundtrip_finish(child);
		TEST_FAIL("socket() failed");
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(1);

	refused_ok = (privsep_bind(s, (struct sockaddr *)&sin, sizeof(sin))
	    != 0);
	refused_errno = errno;
	close(s);

	if (privsep_wire_roundtrip_restore_priv() != 0)
		TEST_FAIL("seteuid(0) restore failed");

	if (privsep_wire_roundtrip_finish(child) != 0)
		TEST_FAIL("privileged child did not shut down cleanly");

	if (!allowed_ok)
		TEST_FAIL("authorized privsep_bind() did not actually bind PORT_ISAKMP");
	if (!refused_ok || refused_errno != EPERM)
		TEST_FAIL("unauthorized port was not refused with EPERM");

	TEST_PASS();
	return 0;
}

/*
 * Every case in this binary needs real root, not just permission to read
 * privsep.c's own state: the "passthrough" cases require geteuid() == 0
 * directly, and the "wire protocol" cases seteuid() to "nobody" and back
 * around a still-root forked child -- seteuid() to a *different* uid
 * (rather than back to one this process already held) needs CAP_SETUID,
 * which only a process that started as root has. There is no privileged
 * operation here fakeroot's LD_PRELOAD file-ownership shims can stand in
 * for (see CONTRIBUTING.md's "Running the test suite" section) -- this
 * binary skips (exit 77, automake's own convention -- see that section)
 * rather than failing when it is not actually root.
 */
static int
skip_if_not_root(void)
{
	if (geteuid() == 0)
		return 0;

	printf("\n=== privsep.c client-side wrapper functions "
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

	printf("\n=== privsep.c client-side wrapper functions "
	    "(privsep-priv-extraction follow-up) ===\n");

	if (test_eay_get_pkcs1privkey_passthrough() != 0) failed++;
	if (test_eay_get_pkcs1privkey_wire() != 0) failed++;
	if (test_getpsk_passthrough() != 0) failed++;
	if (test_getpsk_wire() != 0) failed++;
	if (test_script_exec_passthrough() != 0) failed++;
	if (test_script_exec_wire() != 0) failed++;
	if (test_socket_passthrough() != 0) failed++;
	if (test_socket_wire() != 0) failed++;
	if (test_bind_passthrough() != 0) failed++;
	if (test_bind_wire() != 0) failed++;

	if (failed) {
		printf("\n=== %d TEST(S) FAILED ===\n\n", failed);
		return 1;
	}

	printf("\n=== ALL TESTS PASSED ===\n\n");
	return 0;
}
