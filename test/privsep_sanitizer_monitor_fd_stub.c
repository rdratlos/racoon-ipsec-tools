// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Link-only stub for monitor_fd() (session.c), used exclusively by the
 * SANITIZER_BUILD variant of the privsep.c-only test binaries (see
 * test/Makefile.am and doc/dev/privsep-hardening-followup-audit.md §4/§9
 * for the full story).
 *
 * privsep_unittest_src.c pulls in the whole of privsep.c by #include, and
 * privsep.c's own privsep_init() -- not called by any of these tests,
 * which only ever exercise privsep_priv()/the client-side wrappers/
 * privsep_do_exit() directly over a plain socketpair() -- still contains
 * a real call to monitor_fd(). Under the ordinary (non-sanitizer) build,
 * -Wl,--gc-sections prunes privsep_init() away entirely because nothing
 * reachable from main() calls it, so monitor_fd() is never actually
 * needed at link time. --gc-sections cannot be used together with
 * -fsanitize=address/undefined on this project's toolchain, though (it
 * reliably drops main()'s own section, producing "undefined reference to
 * main" -- confirmed while investigating this) -- so the SANITIZER_BUILD
 * variant of these targets builds without --gc-sections at all, which
 * means the linker needs every symbol privsep.c's whole translation unit
 * references, monitor_fd() included, regardless of whether that specific
 * test ever reaches it at runtime.
 *
 * This is a stub, not the real function: it exists purely to satisfy the
 * linker for code that is compiled in but never executed by any of these
 * tests, and must never be linked alongside session_unittest_src.c (which
 * provides the real, non-stub monitor_fd() -- a duplicate-symbol error).
 * Tests that need the *real* monitor_fd() (test_monitor_fd_range.c,
 * test_prune_stale_monitored_fds.c, test_monitor_fd_cold_start.c,
 * test_privsep_init.c, test_privsep_init_fork_failure.c) link
 * session_unittest_src.c instead and are excluded from sanitizer builds
 * for a different, harder reason: session.c's own dependency closure
 * (isakmp_init(), pfkey_init(), admin_init(), cfparse(), and more --
 * effectively most of the daemon) is not practical to stub just to link
 * one test binary. See the audit document for the full reasoning either
 * way this went.
 */

int
monitor_fd(fd, callback, ctx, priority)
	int fd;
	int (*callback)(void *, int);
	void *ctx;
	int priority;
{
	return 0;
}
