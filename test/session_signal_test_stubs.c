// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stub implementations for the symbols check_sigreq()'s dispatch pulls
 * in: reload_conf() (SIGHUP) and close_session() (SIGINT/SIGTERM), both
 * static, both directly referenced from check_sigreq()'s own compiled
 * section, so -ffunction-sections/--gc-sections cannot discard either
 * one's dependency closure regardless of which signal a given test
 * actually drives -- the same "one dispatch function pulls in
 * everything" situation admin_test_stubs.c already documents for
 * admin_process().
 *
 * admin_close() (via close_sockets()) is stubbed here rather than
 * linked from the real admin.o: unlike this test suite's admin.c
 * wrapper (admin_unittest_src.c), the plain admin.o built for the real
 * racoon binary (src/racoon/Makefile.am) is not compiled with
 * -ffunction-sections, so it is one indivisible section --
 * --gc-sections could only keep or discard admin.o as a whole, and
 * keeping it (for admin_close() alone) would pull in admin_process()'s
 * entire ~25-symbol dependency closure (already covered, in isolation,
 * by admin_test_stubs.c) just to satisfy the linker. admin_close()
 * itself is already fully unit-tested (test_admin_close.c); this stub
 * only needs to prove close_sockets() reaches it.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <resolv.h>

#include "var.h"
#include "vmbuf.h"
#include "algorithm.h"
#include "handler.h"
#include "sainfo.h"
#include "remoteconf.h"
#include "grabmyaddr.h"
#include "localconf.h"
#include "cfparse_proto.h"
#include "evt.h"
#ifdef ENABLE_HYBRID
#include "isakmp_cfg.h"
#endif

/* close_session()/close_sockets() dereference lcconf->sock_pfkey. */
static struct localconf session_test_lcconf;
struct localconf *lcconf = &session_test_lcconf;

int session_test_evt_generic_calls = 0;
void
evt_generic(int type, vchar_t *optdata)
{
	session_test_evt_generic_calls++;
}

int session_test_pfkey_send_flush_calls = 0;
int
pfkey_send_flush(int so, u_int satype)
{
	session_test_pfkey_send_flush_calls++;
	return 0;
}

int session_test_flushph2_calls = 0;
void
flushph2(void)
{
	session_test_flushph2_calls++;
}

int session_test_flushph1_calls = 0;
void
flushph1(void)
{
	session_test_flushph1_calls++;
}

int session_test_flushrmconf_calls = 0;
void
flushrmconf(void)
{
	session_test_flushrmconf_calls++;
}

int session_test_flushsainfo_calls = 0;
void
flushsainfo(void)
{
	session_test_flushsainfo_calls++;
}

int session_test_myaddr_close_calls = 0;
void
myaddr_close(void)
{
	session_test_myaddr_close_calls++;
}

int session_test_pfkey_close_calls = 0;
void
pfkey_close(int so)
{
	session_test_pfkey_close_calls++;
}

int session_test_backupsa_clean_calls = 0;
int
backupsa_clean(void)
{
	session_test_backupsa_clean_calls++;
	return 0;
}

#ifdef ENABLE_ADMINPORT
int session_test_admin_close_calls = 0;
int
admin_close(void)
{
	session_test_admin_close_calls++;
	return 0;
}
#endif

#ifdef ENABLE_HYBRID
int session_test_isakmp_cfg_init_calls = 0;
int session_test_isakmp_cfg_init_ret = 0;
int
isakmp_cfg_init(int flags)
{
	session_test_isakmp_cfg_init_calls++;
	return session_test_isakmp_cfg_init_ret;
}
#endif

int session_test_sainfo_start_reload_calls = 0;
void
sainfo_start_reload(void)
{
	session_test_sainfo_start_reload_calls++;
}

int session_test_rmconf_start_reload_calls = 0;
void
rmconf_start_reload(void)
{
	session_test_rmconf_start_reload_calls++;
}

int session_test_pfkey_reload_calls = 0;
int
pfkey_reload(void)
{
	session_test_pfkey_reload_calls++;
	return 0;
}

int session_test_save_params_calls = 0;
void
save_params(void)
{
	session_test_save_params_calls++;
}

int session_test_flushlcconf_calls = 0;
void
flushlcconf(void)
{
	session_test_flushlcconf_calls++;
}

/* Controllable: lets tests drive both reload_conf()'s success path and
 * its "config reload failed" early-return path. */
int session_test_cfparse_calls = 0;
int session_test_cfparse_ret = 0;
int
cfparse(void)
{
	session_test_cfparse_calls++;
	return session_test_cfparse_ret;
}

int session_test_restore_params_calls = 0;
void
restore_params(void)
{
	session_test_restore_params_calls++;
}

int session_test_myaddr_sync_calls = 0;
void
myaddr_sync(void)
{
	session_test_myaddr_sync_calls++;
}

int session_test_revalidate_ph12_calls = 0;
int
revalidate_ph12(void)
{
	session_test_revalidate_ph12_calls++;
	return 0;
}

int session_test_sainfo_finish_reload_calls = 0;
void
sainfo_finish_reload(void)
{
	session_test_sainfo_finish_reload_calls++;
}

int session_test_rmconf_finish_reload_calls = 0;
void
rmconf_finish_reload(void)
{
	session_test_rmconf_finish_reload_calls++;
}
