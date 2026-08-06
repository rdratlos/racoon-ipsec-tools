// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stub implementations for the symbols privsep_priv() (privsep.c) calls
 * out to on the privileged side of each command: eay_get_pkcs1privkey()
 * (crypto_openssl.c), getpsk() (localconf.c), script_exec() (isakmp.c),
 * and, since this build has ENABLE_HYBRID on by default, the
 * isakmp_cfg_config global and isakmp_cfg_accounting_system()/
 * xauth_login_system() PRIVSEP_ACCOUNTING_SYSTEM/PRIVSEP_XAUTH_LOGIN_SYSTEM
 * pull in (isakmp_cfg.c/isakmp_xauth.c) -- plus, when the build also has
 * HAVE_LIBPAM (libpam-dev auto-detected by --with-libpam=auto), the PAM
 * counterparts privsep_priv()'s PRIVSEP_ACCOUNTING_PAM/
 * PRIVSEP_XAUTH_LOGIN_PAM/PRIVSEP_CLEANUP_PAM cases pull in:
 * isakmp_cfg_resize_pool()/isakmp_cfg_accounting_pam()/cleanup_pam()
 * (isakmp_cfg.c) and xauth_login_pam() (isakmp_xauth.c). None of these
 * six commands are exercised by any test using this file (they are
 * outside the runbook's own six-command scope, doc/dev/
 * v0.9.1-hardening-spec.md §2.2 explains why), but privsep_priv()'s switch
 * still references them at compile time, so the symbols must resolve at
 * link time regardless -- and whether HAVE_LIBPAM is defined depends on
 * what's installed on the build host, not on anything this file controls,
 * so the PAM stubs must be present whenever ENABLE_HYBRID is (matching
 * privsep.c's own #ifdef HAVE_LIBPAM nesting inside #ifdef ENABLE_HYBRID),
 * not just when the author's own build happened to have libpam-dev.
 *
 * Shared by all test_privsep_priv_*.c binaries, the same way
 * rsalist_test_stubs.c is shared across the tests that pull in
 * sockmisc.o/rsalist.o.
 *
 * lcconf is a real, minimally-populated struct localconf rather than a
 * NULL stub (unlike rsalist_test_stubs.c's, which never needs one): the
 * dispatch loop's PRIVSEP_SCRIPT_EXEC case calls unsafe_path(), which
 * dereferences lcconf->pathinfo[pathtype], and PRIVSEP_BIND's port check
 * reads lcconf->port_isakmp/port_isakmp_natt. privsep_priv_test_lcconf_init()
 * points LC_PATHTYPE_CERT/LC_PATHTYPE_SCRIPT at caller-supplied directories
 * (real ones -- unsafe_path() calls realpath(), which requires the path to
 * exist) so each test controls exactly what counts as an authorized script
 * location.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "vmbuf.h"
#include "misc.h"
#include "var.h"
#include "crypto_openssl.h"
#include "isakmp_var.h"
#include "isakmp.h"
#ifdef ENABLE_HYBRID
#include "resolv.h"
#include "isakmp_xauth.h"
#include "isakmp_cfg.h"
#endif
#include "localconf.h"
#include "remoteconf.h"
#include "admin.h"
#include "privsep.h"

static struct localconf privsep_priv_test_lcconf;
struct localconf *lcconf = &privsep_priv_test_lcconf;

#ifdef ENABLE_HYBRID
struct isakmp_cfg_config isakmp_cfg_config;
#endif

void
privsep_priv_test_lcconf_init(const char *certdir, const char *scriptdir)
{
	/*
	 * Free any strings a previous call left behind first: several tests
	 * call this more than once in the same process (once per test
	 * function, all sharing this one static struct), and each fork()ed
	 * child inherits whatever the heap looks like at that moment --
	 * including a still-allocated-but-now-unreferenced string from an
	 * earlier call, which shows up as a "definitely lost" leak in that
	 * child's own valgrind run even though this file never touches it
	 * again. Found via make check-valgrind, not by inspection.
	 */
	free(privsep_priv_test_lcconf.pathinfo[LC_PATHTYPE_CERT]);
	free(privsep_priv_test_lcconf.pathinfo[LC_PATHTYPE_SCRIPT]);

	memset(&privsep_priv_test_lcconf, 0, sizeof(privsep_priv_test_lcconf));
	privsep_priv_test_lcconf.pathinfo[LC_PATHTYPE_CERT] =
	    certdir ? strdup(certdir) : NULL;
	privsep_priv_test_lcconf.pathinfo[LC_PATHTYPE_SCRIPT] =
	    scriptdir ? strdup(scriptdir) : NULL;
}

/*
 * eay_get_pkcs1privkey()'s call site (privsep.c) only *logs* an
 * unsafe_path() rejection, it does not refuse on it -- pre-existing,
 * untouched behaviour (see doc/dev/v0.9.1-hardening-spec.md §2.2), so this
 * stub does not need a path-authorization concept of its own. A path
 * containing "FAIL" reports the failure a real OpenSSL parse error would;
 * anything else succeeds with canned key bytes, so a test can assert the
 * well-formed round trip without needing a real PEM file or an OpenSSL
 * dependency in this stub.
 */
vchar_t *
eay_get_pkcs1privkey(char *path)
{
	static const char key_bytes[] = "stub-pkcs1-private-key";
	vchar_t *key;

	if (path != NULL && strstr(path, "FAIL") != NULL) {
		errno = ENOENT;
		return NULL;
	}

	if ((key = vmalloc(sizeof(key_bytes) - 1)) == NULL)
		return NULL;
	memcpy(key->v, key_bytes, key->l);
	return key;
}

/* Same canned-success/"FAIL" contract as eay_get_pkcs1privkey() above. */
vchar_t *
getpsk(const char *str, const int len)
{
	static const char psk_bytes[] = "stub-psk-secret!";
	vchar_t *psk;

	if (str != NULL && strstr(str, "FAIL") != NULL) {
		errno = ENOENT;
		return NULL;
	}

	if ((psk = vmalloc(sizeof(psk_bytes) - 1)) == NULL)
		return NULL;
	memcpy(psk->v, psk_bytes, psk->l);
	return psk;
}

/*
 * Records the most recent call so a test can assert PRIVSEP_SCRIPT_EXEC
 * actually reached this function (as opposed to being refused earlier by
 * unsafe_path()/unsafe_env()/unknown_name(), which never call it at all).
 * Real fork()+execve() is exactly what privsep_priv()'s own callers do not
 * want exercised by this suite -- the script never runs, only the request
 * to run it is observed.
 */
int privsep_priv_test_script_exec_calls = 0;
char privsep_priv_test_script_exec_last_script[1024];
int privsep_priv_test_script_exec_last_name = -1;
int privsep_priv_test_script_exec_last_wait = -1;

int
script_exec(char *script, int name, char *const envp[], int wait_for_exit)
{
	privsep_priv_test_script_exec_calls++;
	strncpy(privsep_priv_test_script_exec_last_script, script,
	    sizeof(privsep_priv_test_script_exec_last_script) - 1);
	privsep_priv_test_script_exec_last_script[
	    sizeof(privsep_priv_test_script_exec_last_script) - 1] = '\0';
	privsep_priv_test_script_exec_last_name = name;
	privsep_priv_test_script_exec_last_wait = wait_for_exit;
	return 0;
}

/*
 * extract_port() is a real implementation, not a stand-in: PRIVSEP_BIND's
 * port-authorization check (privsep.c) depends on it actually reading the
 * port out of the sockaddr a test sends, so a fake here would make that
 * check meaningless rather than merely untested. Copied from
 * sockmisc.c's own extract_port() (not linked here -- pulling in
 * sockmisc.o drags in most of the daemon, same reasoning as
 * rsalist_test_stubs.c's file comment); keep the two in sync by hand if
 * sockmisc.c's ever changes.
 */
u_int16_t
extract_port(const struct sockaddr *addr)
{
	u_int16_t port = 0;

	if (addr == NULL)
		return port;

	switch (addr->sa_family) {
	case AF_INET:
		port = ((const struct sockaddr_in *)addr)->sin_port;
		break;
	case AF_INET6:
		port = ((const struct sockaddr_in6 *)addr)->sin6_port;
		break;
	default:
		break;
	}

	return ntohs(port);
}

/*
 * saddr2str() only feeds a debug plog() in PRIVSEP_ACCOUNTING_SYSTEM
 * (ENABLE_HYBRID), which no test using this file exercises -- link target
 * only, see the file comment above.
 */
#ifdef ENABLE_HYBRID
char *
saddr2str(const struct sockaddr *addr)
{
	return "";
}

int
isakmp_cfg_accounting_system(int port, struct sockaddr *raddr, char *usr, int inout)
{
	return 0;
}

int
xauth_login_system(char *usr, char *pwd)
{
	return 0;
}

/*
 * PRIVSEP_ACCOUNTING_PAM/PRIVSEP_XAUTH_LOGIN_PAM/PRIVSEP_CLEANUP_PAM
 * (privsep.c) link targets only, same "not exercised by any test using
 * this file" reasoning as the _system stubs above -- see the file
 * comment. Only compiled in when the build also has HAVE_LIBPAM, matching
 * privsep.c's own nesting of these three cases inside its own
 * #ifdef HAVE_LIBPAM (itself inside #ifdef ENABLE_HYBRID).
 */
#ifdef HAVE_LIBPAM
int
isakmp_cfg_resize_pool(int pool_size)
{
	return 0;
}

int
isakmp_cfg_accounting_pam(int port, int inout)
{
	return 0;
}

int
xauth_login_pam(int port, struct sockaddr *raddr, char *usr, char *pwd)
{
	return 0;
}

void
cleanup_pam(int port)
{
}
#endif /* HAVE_LIBPAM */
#endif /* ENABLE_HYBRID */
