// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Test-only substitute for getpass(3), which f_exchangesa()'s "-u
 * identity" branch (racoonctl.c) calls to read the XAUTH password
 * interactively. getpass() reads from /dev/tty (falling back to stdin)
 * with echo disabled -- real terminal I/O a test binary must never
 * depend on, since it always runs with no controlling tty.
 *
 * Unlike malloc()/free(), GCC/LTO has no special builtin semantic
 * knowledge of getpass() that would let it inline away a call site and
 * defeat a linker substitution the way vfree() did under whole-program
 * LTO (doc/dev/wrap-based-tests-vs-lto.md) -- it is an ordinary external
 * libc symbol. A same-named strong definition in this test binary,
 * linked before libc resolves the reference, shadows it directly; no
 * -Wl,--wrap= needed. Spiked before relying on this broadly: confirmed
 * stable under this project's actual test-binary flags
 * (-ffunction-sections -fdata-sections + -Wl,--gc-sections, and
 * separately under -flto) on this toolchain. If this ever proves flaky
 * on a toolchain in this project's Bionic/Resolute/Arch range, the
 * fallback is the same one used for get_sockaddr() in this same test
 * suite: don't link the real thing (getpass() already isn't linked from
 * anywhere else here), or restructure the test to never reach the
 * getpass() call site at all.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

char racoonctl_test_getpass_return[256] = "";
int racoonctl_test_getpass_calls = 0;
char racoonctl_test_getpass_last_prompt[256] = "";

char *
getpass(const char *prompt)
{
	racoonctl_test_getpass_calls++;
	if (prompt != NULL)
		strncpy(racoonctl_test_getpass_last_prompt, prompt,
		    sizeof(racoonctl_test_getpass_last_prompt) - 1);
	return racoonctl_test_getpass_return;
}
