// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Dead-but-linkable stand-ins for getlocaladdr()/saddr2str() (sockmisc.c),
 * needed only to satisfy the linker, never actually called.
 *
 * cmdtab[] (racoonctl.c) is a single data object holding function
 * pointers to every f_*() command handler, including f_vpnc(). Any test
 * binary that calls get_combuf_unittest() (which walks cmdtab[] to
 * dispatch a command string) needs cmdtab[] linked -- and
 * -ffunction-sections/--gc-sections can only discard or keep that array
 * as one indivisible unit, not prune individual pointers out of it. So
 * pulling in cmdtab[] pulls in every function it points to, including
 * f_vpnc() (which this suite deliberately never unit-tests: it calls a
 * real getaddrinfo() and opens a real UDP socket via getlocaladdr() to
 * discover the local source address -- see test_racoonctl_encode_
 * requests.c's own header comment for why that stays integration
 * territory), even though no test here ever actually invokes it.
 *
 * getlocaladdr()/saddr2str() have ordinary external linkage, so -- same
 * technique as racoonctl_get_sockaddr_stub.c -- a test binary that never
 * links sockmisc.o can just supply its own never-called definitions
 * instead. No -Wl,--wrap= needed, and no need to satisfy sockmisc.o's
 * own much larger dependency closure (privsep_ and ipsec_ symbols, see
 * test_grabmyaddr_netlink's own Makefile.am comment) just to link a
 * function this suite never runs.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>

struct sockaddr *
getlocaladdr(struct sockaddr *remote)
{
	return NULL;
}

char *
saddr2str(const struct sockaddr *saddr)
{
	return NULL;
}
