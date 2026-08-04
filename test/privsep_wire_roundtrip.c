// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Shared driver for testing privsep.c's *client-side* wrappers
 * (privsep_eay_get_pkcs1privkey(), privsep_getpsk(), privsep_script_exec(),
 * privsep_socket(), privsep_bind(), and the ENABLE_HYBRID/HAVE_LIBPAM ones)
 * over their real wire protocol, rather than only their
 * "if (geteuid() == 0) return <real syscall/function>(...)" passthrough
 * branch every one of them opens with.
 *
 * test_privsep_priv_*.c already drives privsep_priv() (the privileged
 * side) directly by hand-crafting wire messages and playing the
 * unprivileged side itself. This is the mirror image: a test calls the
 * real client-side wrapper function, over a socketpair() whose other end
 * a forked child serves with the real privsep_priv() (privsep_unittest_src.c
 * + privsep_priv_test_stubs.c, same as those tests). The two suites
 * together exercise both ends of the same protocol with the real
 * production code on each side, just never both at once in the same
 * process (which is exactly what privsep_init()'s own real fork() does --
 * see test_privsep_init.c for the one test that drives that directly).
 *
 * Every client wrapper reads the *static* privsep_sock[1] (privsep.c),
 * normally only ever set by privsep_init()'s own socketpair()/fork().
 * privsep_set_sock_unittest() (privsep.c, ENABLE_UNITTEST) points it at
 * this driver's socketpair() end instead. The wrapper's own
 * "geteuid() == 0" check means the *calling* process must not be root for
 * the wire path to be taken at all -- privsep_wire_roundtrip_start() does
 * not touch euid itself (some callers want the passthrough path on
 * purpose, to compare against); privsep_wire_roundtrip_seteuid_nobody()/
 * _restore() are separate so a test controls exactly when it drops and
 * restores privilege around its one call.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>

/* Bounded, same reasoning and constants as test_privsep_priv_control_cases.c's
 * own wait_child_bounded(): never block the harness indefinitely on a
 * privileged child that fails to exit (doc/dev/v0.9.1-hardening-spec.md §2.1 rule 2,
 * applied to this test suite as much as to privsep.c itself). */
#define WAIT_POLL_MS   20
#define WAIT_MAX_POLLS 250   /* 5s bound */

extern int privsep_priv(int sock);
extern void privsep_priv_test_lcconf_init(const char *certdir,
    const char *scriptdir);
extern void privsep_set_sock_unittest(int parent_end, int child_end);
extern void privsep_reset_state_unittest(void);
extern int privsep_get_sock_unittest(int idx);

int privsep_wire_roundtrip_client_fd(void);

/*
 * Forks a child that plays the privileged side for real: calls
 * privsep_priv_test_lcconf_init(certdir, scriptdir) (needed by
 * PRIVSEP_EAY_GET_PKCS1PRIVKEY/PRIVSEP_SCRIPT_EXEC's unsafe_path() checks
 * and PRIVSEP_BIND's port check) and then privsep_priv(sock) itself --
 * same _exit(0)/_exit(1) at "out:"/"fail:" as production, untouched. The
 * parent gets the other end wired into privsep_sock[1] via
 * privsep_set_sock_unittest() and is left free to call whatever client
 * wrapper the test is exercising. certdir/scriptdir may be NULL if the
 * scenario does not need path authorization to succeed.
 *
 * Returns the child's pid (> 0) on success, -1 on setup failure (nothing
 * forked). Never returns in the child -- it _exit()s from inside
 * privsep_priv() same as any test_privsep_priv_*.c binary's own child.
 */
pid_t
privsep_wire_roundtrip_start(const char *certdir, const char *scriptdir)
{
	int sv[2];
	pid_t pid;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sv) != 0)
		return -1;

	if ((pid = fork()) < 0) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}

	if (pid == 0) {
		/* Child: the privileged side, for real. */
		close(sv[1]);
		privsep_priv_test_lcconf_init(certdir, scriptdir);
		(void)privsep_priv(sv[0]); /* _exit()s, never returns */
		_exit(1);
	}

	/* Parent: the unprivileged side's socket end, wired in. */
	close(sv[0]);
	privsep_set_sock_unittest(-1, sv[1]);
	return pid;
}

/*
 * Waits for the privileged child started by privsep_wire_roundtrip_start()
 * to finish (it does, on its own, once the caller's one client-wrapper
 * call closes or the process exits -- privsep_recv() then sees EOF and
 * takes the "out:" / _exit(0) path) and resets privsep_sock/
 * privsep_child_pid so the next scenario starts clean. Returns 0 if the
 * child exited 0 (the clean-shutdown path every scenario here is expected
 * to take), -1 otherwise -- a nonzero exit means privsep_priv() took its
 * "fail:" path, which every scenario in this suite treats as a bug in the
 * scenario's own request, not an expected outcome to assert on.
 */
int
privsep_wire_roundtrip_finish(pid_t child_pid)
{
	int status, i;
	pid_t ret;

	close(privsep_wire_roundtrip_client_fd());
	privsep_reset_state_unittest();

	for (i = 0; i < WAIT_MAX_POLLS; i++) {
		ret = waitpid(child_pid, &status, WNOHANG);
		if (ret == child_pid)
			return (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			    ? 0 : -1;
		usleep(WAIT_POLL_MS * 1000);
	}

	kill(child_pid, SIGKILL);
	waitpid(child_pid, &status, 0);
	return -1;
}

/*
 * privsep_sock[1] itself is static/file-scope; this hands back the fd
 * privsep_wire_roundtrip_start() just wired into it, purely so
 * privsep_wire_roundtrip_finish() can close it before resetting -- closing
 * it is what lets the privileged child's privsep_recv() see EOF and reach
 * its own "out:" path instead of blocking forever.
 */
int
privsep_wire_roundtrip_client_fd(void)
{
	return privsep_get_sock_unittest(1);
}

/*
 * Drops this process's effective uid to a real, non-root account so a
 * client wrapper's "geteuid() == 0" check takes the wire-protocol branch
 * instead of the passthrough one. "nobody" (uid 65534 on every Linux this
 * project targets -- Debian/Ubuntu/Arch, see test/README.md) is used by
 * name via getpwnam() rather than the hardcoded number, falling back to
 * 65534 only if the account genuinely is not present (some minimal
 * containers). Reversible: this process's real and saved uids stay 0
 * throughout (setuid() is never called), so seteuid(0) always succeeds
 * afterwards regardless of which uid was dropped to.
 */
uid_t
privsep_wire_roundtrip_nobody_uid(void)
{
	struct passwd *pw = getpwnam("nobody");

	return pw ? pw->pw_uid : 65534;
}

int
privsep_wire_roundtrip_drop_priv(void)
{
	return seteuid(privsep_wire_roundtrip_nobody_uid());
}

int
privsep_wire_roundtrip_restore_priv(void)
{
	return seteuid(0);
}
