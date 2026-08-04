// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Dead-but-linkable stand-ins for a handful of racoonctl.c's non-static
 * external dependencies, needed only to satisfy the linker -- none of
 * them are ever actually called by any test that links this file.
 *
 * getlocaladdr()/saddr2str() (sockmisc.c): cmdtab[] (racoonctl.c) is a
 * single data object holding function pointers to every f_*() command
 * handler, including f_vpnc(). Any test binary that calls
 * get_combuf_unittest() (which walks cmdtab[] to dispatch a command
 * string) needs cmdtab[] linked -- and -ffunction-sections/
 * --gc-sections can only discard or keep that array as one indivisible
 * unit, not prune individual pointers out of it. So pulling in cmdtab[]
 * pulls in every function it points to, including f_vpnc() (which this
 * suite deliberately never unit-tests: it calls a real getaddrinfo()
 * and opens a real UDP socket via getlocaladdr() to discover the local
 * source address -- see test_racoonctl_encode_requests.c's own header
 * comment for why that stays integration territory), even though no
 * test here ever actually invokes it.
 *
 * pfkey_sadump() (libipsec/pfkey_dump.c): handle_recv()'s own
 * ADMIN_SHOW_SA/{AH,ESP,IPSEC} case calls it on the sadb_msg_errno == 0
 * branch. -ffunction-sections/--gc-sections operates per function, not
 * per branch, so handle_recv()'s single compiled body needs this symbol
 * to resolve at link time even when every test driving it (see
 * test_racoonctl_format_output.c) only ever exercises the ENOENT
 * branch, never the real pfkey_sadump() one -- linking the whole of
 * libipsec.la just for that one unreached call is unnecessary weight.
 *
 * Each of these has ordinary external linkage, so -- same technique as
 * racoonctl_get_sockaddr_stub.c/racoonctl_getpass_stub.c -- a test
 * binary that never links their real objects (sockmisc.o, libipsec.la)
 * can just supply its own never-called definitions instead. No
 * -Wl,--wrap= needed, and no need to satisfy those objects' own much
 * larger dependency closures (privsep_ and ipsec_ symbols, see
 * test_grabmyaddr_netlink's own Makefile.am comment) just to link
 * functions this suite never runs.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/pfkeyv2.h>

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

void
pfkey_sadump(struct sadb_msg *m)
{
}
