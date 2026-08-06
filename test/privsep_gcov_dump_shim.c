// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * gcov flushes a process's counters to its .gcda file via an
 * atexit()-registered handler, run when a process exits through
 * exit()/return from main(). privsep_priv() (privsep.c) exits every one of
 * its own paths -- production and unchanged here -- via _exit(), which by
 * design bypasses every atexit() handler (what makes it safe to call right
 * after fork() without double-flushing an inherited stdio buffer); see
 * doc/dev/v0.9.1-hardening-spec.md §2.4 for the full writeup. Without this
 * shim, a coverage build's forked privsep_priv() child never writes its
 * .gcda, and `make coverage` reports privsep.c as effectively unexecuted
 * even though it demonstrably ran.
 *
 * Only linked into the eight test_privsep_* binaries that compile privsep.c
 * (via privsep_unittest_src.c), and only in a coverage build (ENABLE_COVERAGE,
 * test/Makefile.am) -- __gcov_dump() is provided by libgcov, which is only
 * linked in when the binary itself was built with -fprofile-arcs/
 * -ftest-coverage. Paired with -Wl,--wrap=_exit (same target's own
 * _LDFLAGS), which redirects every _exit() call in the binary through
 * __wrap__exit() below instead of libc's. This changes nothing observable
 * -- privsep_priv()'s own _exit(0)/_exit(1) contract is untouched -- it
 * only makes the coverage measurement see what already ran. Same --wrap=
 * linker technique test_script_hook_leak.c already uses for free().
 */

extern void __gcov_dump(void);
extern void __real__exit(int status);

void
__wrap__exit(int status)
{
	__gcov_dump();
	__real__exit(status);
}
