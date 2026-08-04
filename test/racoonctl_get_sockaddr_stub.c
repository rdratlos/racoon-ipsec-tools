// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Test-only substitute for get_sockaddr() (kmpstat.c), which racoonctl.c's
 * get_comindexes() calls twice per invocation (once for the source index,
 * once for the destination) to turn a name/port string pair into a
 * struct sockaddr. The real one calls getaddrinfo() with no numeric-only
 * hints, i.e. a genuine resolver call -- the same category of OS-boundary
 * dependency flagged for getcertsbyname()/res_query() (see
 * doc/dev/v0.9.1-hardening-spec.md §3.2 and issue #114): not something a
 * unit test should depend on succeeding or being fast, and not something
 * -Wl,--wrap= is the right tool for here, since it would need to survive
 * across this project's whole Bionic/Resolute/Arch toolchain range for a
 * symbol we don't even need the real behavior of.
 *
 * get_sockaddr() has ordinary external linkage (declared in racoonctl.h,
 * defined in kmpstat.c) -- unlike a static function needing an
 * ENABLE_UNITTEST accessor, a test binary that never links kmpstat.o can
 * just supply its own definition instead, and the linker never sees two
 * conflicting ones. No -Wl,--wrap= needed.
 *
 * This stub resolves only numeric IPv4/IPv6 literals via inet_pton() --
 * no DNS, no network I/O, fully deterministic -- which is all
 * get_comindexes()'s own callers in racoonctl.c ever pass in practice
 * (an SPD/SA index's src/dst are addresses, not hostnames). Racoonctl_
 * test_get_sockaddr_fail lets a test simulate resolution failure (the
 * real function's `return NULL` path on a bad name/port) without needing
 * a genuinely unresolvable name.
 *
 * get_comindexes() calls this twice (src, then dst) before copying either
 * result, so a single shared static buffer would alias: the second call
 * (dst) would silently overwrite the first call's (src) result before
 * get_comindexes() ever reads it back. Two-slot round robin keeps both
 * results independently valid, mirroring the real function's own
 * per-call-independent getaddrinfo() allocation closely enough for
 * get_comindexes()'s two-calls-per-invocation usage pattern.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int racoonctl_test_get_sockaddr_fail = 0;
int racoonctl_test_get_sockaddr_calls = 0;

struct sockaddr *
get_sockaddr(int family, char *name, char *port)
{
	static struct sockaddr_storage slots[2];
	static int next_slot = 0;
	struct sockaddr_storage *ss;
	unsigned short portnum;

	racoonctl_test_get_sockaddr_calls++;

	if (racoonctl_test_get_sockaddr_fail)
		return NULL;

	ss = &slots[next_slot];
	next_slot = (next_slot + 1) % 2;
	memset(ss, 0, sizeof(*ss));

	portnum = (unsigned short)(port ? atoi(port) : 0);

	switch (family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;

		if (inet_pton(AF_INET, name, &sin->sin_addr) != 1)
			return NULL;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(portnum);
#ifdef HAVE_SA_LEN
		sin->sin_len = sizeof(*sin);
#endif
		return (struct sockaddr *)sin;
	}
#ifdef INET6
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

		if (inet_pton(AF_INET6, name, &sin6->sin6_addr) != 1)
			return NULL;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(portnum);
#ifdef HAVE_SA_LEN
		sin6->sin6_len = sizeof(*sin6);
#endif
		return (struct sockaddr *)sin6;
	}
#endif
	default:
		return NULL;
	}
}
