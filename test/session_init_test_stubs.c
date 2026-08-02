// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stub implementations for the subsystem-init entry points
 * session_init_before_cfparse() (session.c, new in v0.9.1 -- see that
 * function's own header comment) calls: pfkey_init()/isakmp_init() open
 * real PF_KEY/UDP sockets and fail fatally (errx()) without kernel IPsec
 * support this test host may not have; isakmp_cfg_init()/myaddr_init_lists()/
 * save_params() pull in most of racoon's config/interface-list machinery.
 * None of that is what this test wants to isolate: it is testing that
 * session_init_before_cfparse() calls each of these exactly once and
 * resets fd-monitoring state, not what pfkey_init() etc. themselves do
 * (those already have -- or belong in -- their own tests).
 *
 * sched_init() (schedule.c) and init_signal()/signal_handler() (session.c
 * itself) are deliberately NOT stubbed here: both are trivially
 * self-contained (TAILQ_INIT() and a single static-array write,
 * respectively), so they are linked and run for real.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

int session_init_test_pfkey_init_calls = 0;
int session_init_test_isakmp_init_calls = 0;
int session_init_test_isakmp_cfg_init_calls = 0;
int session_init_test_myaddr_init_lists_calls = 0;
int session_init_test_save_params_calls = 0;

int session_init_test_pfkey_init_ret = 0;
int session_init_test_isakmp_init_ret = 0;

int
pfkey_init(void)
{
	session_init_test_pfkey_init_calls++;
	return session_init_test_pfkey_init_ret;
}

int
isakmp_init(void)
{
	session_init_test_isakmp_init_calls++;
	return session_init_test_isakmp_init_ret;
}

#ifdef ENABLE_HYBRID
int
isakmp_cfg_init(int flags)
{
	session_init_test_isakmp_cfg_init_calls++;
	return 0;
}
#endif

void
myaddr_init_lists(void)
{
	session_init_test_myaddr_init_lists_calls++;
}

void
save_params(void)
{
	session_init_test_save_params_calls++;
}
