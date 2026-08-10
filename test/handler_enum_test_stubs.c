// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stubs for every symbol handler.o needs beyond the real plog.o/logger.o/
 * vmbuf.o/misc_noplog.o/sockmisc_ffs.o (already linked) to satisfy the call
 * graph reachable from newph1()/insph1()/newph2()/insph2()/bindph12()/
 * enumph1()/enumph2()/delph1()/delph2() -- the functions test_handler_enum.c
 * exercises. Copy of handler_flushph1_test_stubs.c's stub set (delph1()/
 * delph2()'s own dependency closures are identical whether reached via
 * flushph1() or directly, as this test does) plus sockmisc_ffs.o linked in
 * for cmpsaddr(), which flushph1()'s test never needed (insph1()/insph2()
 * don't call it, but enumph1()/enumph2()'s selector-filtering path does) --
 * kept as a real function here rather than stubbed, since this test's whole
 * point is exercising the selector-match logic for real.
 *
 * Each stub is a bare no-op except where the test needs to observe that
 * delph1()/delph2() actually reached a given handle -- delete_spd() is
 * call-counted for that.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include "handler.h"
#include "evt.h"

int handler_test_delete_spd_calls = 0;

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
	return 0;
}

int
isakmp_info_send_d2(struct ph2handle *iph2)
{
	return 0;
}
