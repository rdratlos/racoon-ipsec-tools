// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Link-time-only stubs for test_grabmyaddr_netlink.
 *
 * test_grabmyaddr_netlink_LDADD reuses src/racoon/sockmisc.o as built for
 * the real racoon binary (i.e. WITHOUT -DNOUSE_PRIVSEP), since that is the
 * only pre-built copy test/Makefile.am's "reuse objects from the main
 * build" convention (see the comment on RACOON_OBJS near the top of this
 * file) can reference by path. Unlike grabmyaddr.c (compiled here with
 * -ffunction-sections specifically so --gc-sections can discard the address-
 * bookkeeping this test never calls), sockmisc.o is NOT compiled with
 * -ffunction-sections -- it is a single, undivided translation unit, so
 * --gc-sections can only keep or drop it as a whole. Whenever anything
 * pulls in any part of it (directly, or because some other instrumentation,
 * e.g. -fprofile-arcs/-ftest-coverage or -fsanitize=, keeps a reference
 * alive the way this project's own SANITIZER_BUILD comments elsewhere in
 * this file already document for AddressSanitizer), every symbol
 * sockmisc.o references must resolve -- including these six, which
 * netlink_parse_route_attrs_unittest() (the only entry point this test
 * actually calls) never reaches at runtime:
 *
 *  - privsep_socket()/privsep_bind()/privsep_setsockopt(): sockmisc.c's
 *    BIND/SOCKET/SETSOCKOPT macros resolve to these (not the plain
 *    socket(2)/bind(2)/setsockopt(2)) whenever it is compiled WITHOUT
 *    -DNOUSE_PRIVSEP.
 *  - ipsec_set_policy()/ipsec_strerror()/ipsec_get_policylen():
 *    setsockopt_bypass() (sockmisc.c) calls these libipsec functions
 *    unconditionally.
 *
 * None of the six are ever actually invoked by this test -- it only
 * exercises route-attribute parsing -- so trivial stubs are correct and
 * sufficient; no real privsep IPC or PF_KEY policy socket is needed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>

#include "var.h"
#include "vmbuf.h"
#include "admin.h"
#include "privsep.h"
#include "libpfkey.h"

int
privsep_socket(int domain, int type, int protocol)
{
	return -1;
}

int
privsep_bind(int s, const struct sockaddr *addr, socklen_t addrlen)
{
	return -1;
}

int
privsep_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	return -1;
}

/* Signatures compile-checked against libpfkey.h's own prototypes (included
 * above) rather than hand-copied, so a future signature change there fails
 * this file's build instead of silently mismatching. */

caddr_t
ipsec_set_policy(__ipsec_const char *policy, int policylen)
{
	return NULL;
}

const char *
ipsec_strerror(void)
{
	return "ipsec_strerror (link-only stub, never called)";
}

int
ipsec_get_policylen(caddr_t buf)
{
	return -1;
}
