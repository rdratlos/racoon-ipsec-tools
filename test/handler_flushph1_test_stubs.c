// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stubs for every symbol handler.o needs beyond the real plog.o/logger.o/
 * vmbuf.o/misc_noplog.o (already linked, same as test_admin_handler.c) to
 * satisfy the call graph reachable from newph1()/insph1()/newph2()/
 * insph2()/bindph12()/flushph1() -- the functions test_handler_flushph1.c
 * exercises. -ffunction-sections + --gc-sections (same flags
 * test_admin_handler.c already uses to isolate admin.c) discards every
 * handler.c function this test never calls, so nothing outside that call
 * graph (getph1(), dumpph1(), purge_remote(), and everything they in turn
 * need) has to be stubbed here.
 *
 * Each stub is a bare no-op except where the test needs to observe that
 * flushph1() actually reached a given ph2handle -- delete_spd() and
 * isakmp_info_send_d2() are call-counted for that.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include "handler.h"
#include "evt.h"

int handler_test_delete_spd_calls = 0;
int handler_test_isakmp_info_send_d1_calls = 0;
int handler_test_isakmp_info_send_d2_calls = 0;

void
script_hook(struct ph1handle *iph1, int hook)
{
}

void
evt_list_init(struct evt_listener_list *list)
{
}

void
evt_list_cleanup(struct evt_listener_list *list)
{
}

void
natt_keepalive_remove(struct sockaddr *src, struct sockaddr *dst)
{
}

void
isakmp_cfg_rmstate(struct ph1handle *iph1)
{
}

void
sched_cancel(struct sched *sc)
{
}

void
delisakmpsa(struct isakmpsa *sa)
{
}

void
oakley_delivm(struct isakmp_ivm *ivm)
{
}

void
gssapi_free_state(struct ph1handle *iph1)
{
}

void
flushsaprop(struct saprop *saprop)
{
}

void
delsp_bothdir(struct policyindex *spidx)
{
}

void
oakley_dhgrp_free(struct dhgroup *dhgrp)
{
}

void
delete_spd(struct ph2handle *iph2, u_int64_t created)
{
	handler_test_delete_spd_calls++;
}

int
isakmp_info_send_d1(struct ph1handle *iph1)
{
	handler_test_isakmp_info_send_d1_calls++;
	return 0;
}

int
isakmp_info_send_d2(struct ph2handle *iph2)
{
	handler_test_isakmp_info_send_d2_calls++;
	return 0;
}
