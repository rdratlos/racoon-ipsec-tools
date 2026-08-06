// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stub implementations for the symbols admin.c's admin_process() switch
 * needs at link time. admin_process() is one C function containing every
 * ADMIN_* case in a single compiled unit, so -ffunction-sections/
 * --gc-sections cannot discard the cases a given test never drives at
 * runtime -- every symbol referenced by *any* case must still resolve.
 * Most of these are never invoked by test_admin_delete_all_sa_dst.c (which
 * only ever sends ADMIN_DELETE_ALL_SA_DST and an unrecognized command) and
 * exist purely to satisfy the linker; getph1()/evt_subscribe()/
 * isakmp_info_send_d1()/purge_remote() are the ones that case actually
 * calls, so those are "smart" stubs the test controls and asserts against.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "var.h"
#include "vmbuf.h"
#include "misc.h"
#include "localconf.h"
#include "schedule.h"
#include "isakmp.h"
#include "handler.h"
#include "remoteconf.h"
#include "isakmp_var.h"
#include "isakmp_inf.h"
#include "policy.h"
#include "pfkey.h"
#include "sockmisc.h"
#include "evt.h"
#include "admin.h"
#ifdef ENABLE_HYBRID
#include "isakmp_xauth.h"
#endif

/* admin.c/admin_init()/admin_handler() dereference lcconf->sock_admin
 * unconditionally -- unlike rsalist_test_stubs.c's NULL lcconf (fine for
 * rsalist.c/sockmisc.c, which never touch it), admin.c needs a real
 * instance. */
static struct localconf admin_test_lcconf;
struct localconf *lcconf = &admin_test_lcconf;

/*
 * monitor_fd()/unmonitor_fd() (session.c) -- stubbed rather than linked
 * for real so test_admin_init.c can force either outcome without
 * reconstructing session.c's fd_monitor_tree[]/select() machinery.
 */
int admin_test_monitor_fd_calls = 0;
int admin_test_monitor_fd_ret = 0;

int
monitor_fd(int fd, int (*callback)(void *, int), void *ctx, int priority)
{
	admin_test_monitor_fd_calls++;
	return admin_test_monitor_fd_ret;
}

int admin_test_unmonitor_fd_calls = 0;

void
unmonitor_fd(int fd)
{
	admin_test_unmonitor_fd_calls++;
}

/*
 * getph1() -- the single real function getph1byaddr()/getph1bydstaddr()
 * (handler.h macros) both expand to. test_admin_delete_all_sa_dst.c loads
 * admin_test_getph1_queue[] with the struct ph1handle * values it wants
 * ADMIN_DELETE_ALL_SA_DST's while-loop to see, one per call, then NULL to
 * end the loop -- simulating "N live SAs for this peer".
 */
#define ADMIN_TEST_PH1_QUEUE_MAX 8
struct ph1handle *admin_test_getph1_queue[ADMIN_TEST_PH1_QUEUE_MAX];
int admin_test_getph1_queue_len = 0;
int admin_test_getph1_calls = 0;

struct ph1handle *
getph1(struct ph1handle *ph1hint, struct sockaddr *local,
    struct sockaddr *remote, int flags)
{
	struct ph1handle *ret = NULL;

	if (admin_test_getph1_calls < admin_test_getph1_queue_len)
		ret = admin_test_getph1_queue[admin_test_getph1_calls];
	admin_test_getph1_calls++;
	return ret;
}

/*
 * evt_subscribe() -- controllable return value (-2 mirrors production's
 * "subscribed" sentinel, matching admin_handler()'s "keep this fd open"
 * convention) plus a call counter so the test can assert it fires exactly
 * once, only when the earlier admin_reply() succeeded.
 */
int admin_test_evt_subscribe_calls = 0;
int admin_test_evt_subscribe_ret = -2;

int
evt_subscribe(struct evt_listener_list *list, int fd)
{
	admin_test_evt_subscribe_calls++;
	return admin_test_evt_subscribe_ret;
}

int admin_test_isakmp_info_send_d1_calls = 0;

int
isakmp_info_send_d1(struct ph1handle *iph1)
{
	admin_test_isakmp_info_send_d1_calls++;
	return 0;
}

int admin_test_purge_remote_calls = 0;

void
purge_remote(struct ph1handle *iph1)
{
	admin_test_purge_remote_calls++;
}

/* Never reached by ADMIN_DELETE_ALL_SA_DST/default-case tests; only need
 * to return a non-NULL string so racoon_strdup()+STRDUP_FATAL() (admin.c,
 * ADMIN_DELETE_SA case) don't abort if some future test exercises it. */
char *
saddr2str(const struct sockaddr *saddr)
{
	return "0.0.0.0";
}

/* Actually called by ADMIN_DELETE_ALL_SA_DST for both the peer address
 * and each matching iph1->local. */
char *
saddrwop2str(const struct sockaddr *saddr)
{
	return "0.0.0.0";
}

int admin_test_signal_handler_calls = 0;

void
signal_handler(int sig)
{
	admin_test_signal_handler_calls++;
}

int admin_test_sched_dump_calls = 0;

int
sched_dump(caddr_t *p, int *len)
{
	admin_test_sched_dump_calls++;
	return -1;
}

int admin_test_evt_dump_calls = 0;

vchar_t *
evt_dump(void)
{
	admin_test_evt_dump_calls++;
	return NULL;
}

int admin_test_dumpph1_calls = 0;

vchar_t *
dumpph1(void)
{
	admin_test_dumpph1_calls++;
	return NULL;
}

int admin_test_status_dump_calls = 0;
int admin_test_status_dump_verbose = -1;

void
status_dump(vchar_t **out, int verbose)
{
	admin_test_status_dump_calls++;
	admin_test_status_dump_verbose = verbose;
	*out = NULL;
}

int admin_test_pfkey_dump_sadb_calls = 0;

vchar_t *
pfkey_dump_sadb(int satype)
{
	admin_test_pfkey_dump_sadb_calls++;
	return NULL;
}

int admin_test_flushph1_calls = 0;

void
flushph1(void)
{
	admin_test_flushph1_calls++;
}

int admin_test_pfkey_flush_sadb_calls = 0;

void
pfkey_flush_sadb(u_int proto)
{
	admin_test_pfkey_flush_sadb_calls++;
}

/*
 * enumph1() -- real enumph1() walks ph1tree and invokes enum_func() for
 * every matching struct ph1handle. A naive no-op stub here would leave
 * ADMIN_DELETE_SA's own callback, admin_ph1_delete_sa() (static, admin.c),
 * referenced (its address is taken and passed in) but never actually
 * *entered* -- gcov marks the call site's own line as executed regardless
 * (evaluating the function-pointer expression is enough for that), but
 * admin_ph1_delete_sa()'s body only runs if something calls through that
 * pointer, which nothing did. admin_test_enumph1_queue[] lets a test load
 * the struct ph1handle * values it wants the callback invoked with, one
 * per call, mirroring getph1_queue above; enum_arg is threaded through
 * unmodified, matching the real function's contract.
 */
#define ADMIN_TEST_ENUMPH1_QUEUE_MAX 8
struct ph1handle *admin_test_enumph1_queue[ADMIN_TEST_ENUMPH1_QUEUE_MAX];
int admin_test_enumph1_queue_len = 0;
int admin_test_enumph1_calls = 0;

int
enumph1(struct ph1selector *ph1sel,
    int (*enum_func)(struct ph1handle *iph1, void *arg), void *enum_arg)
{
	int i;

	admin_test_enumph1_calls++;
	for (i = 0; i < admin_test_enumph1_queue_len; i++)
		enum_func(admin_test_enumph1_queue[i], enum_arg);
	return 0;
}

int admin_test_remcontacted_calls = 0;

void
remcontacted(struct sockaddr *remote)
{
	admin_test_remcontacted_calls++;
}

#ifdef ENABLE_HYBRID
int admin_test_purgeph1bylogin_calls = 0;

int
purgeph1bylogin(char *login)
{
	admin_test_purgeph1bylogin_calls++;
	return 0;
}

/* Default -1 (failure) preserves every existing test's behavior; a test
 * that needs the ADMIN_ESTABLISH_SA_PSK id/key -> rmconf->xauth transfer
 * to actually happen sets this to 0 first. */
int admin_test_xauth_rmconf_used_calls = 0;
int admin_test_xauth_rmconf_used_ret = -1;

int
xauth_rmconf_used(struct xauth_rmconf **xauth)
{
	admin_test_xauth_rmconf_used_calls++;
	return admin_test_xauth_rmconf_used_ret;
}
#endif

/* Default NULL (no matching config) preserves every existing test's
 * behavior; a test that needs to reach past the "no configuration found"
 * check points this at a real, test-owned struct remoteconf first. */
int admin_test_getrmconf_calls = 0;
struct remoteconf *admin_test_getrmconf_ret = NULL;

struct remoteconf *
getrmconf(struct sockaddr *remote, int flags)
{
	admin_test_getrmconf_calls++;
	return admin_test_getrmconf_ret;
}

struct remoteconf *
getrmconf_by_name(const char *name)
{
	return NULL;
}

struct ph1handle *
isakmp_ph1begin_i(struct remoteconf *rmconf, struct sockaddr *remote,
    struct sockaddr *local)
{
	return NULL;
}

int admin_test_getsp_r_calls = 0;

struct secpolicy *
getsp_r(struct policyindex *spidx)
{
	admin_test_getsp_r_calls++;
	return NULL;
}

const char *
spidx2str(const struct policyindex *spidx)
{
	return "";
}

struct ph2handle *
getph2byid(struct sockaddr *src, struct sockaddr *dst, u_int32_t spid)
{
	return NULL;
}

struct ph2handle *
newph2(void)
{
	return NULL;
}

void
delph2(struct ph2handle *iph2)
{
}

struct sockaddr *
dupsaddr(struct sockaddr *saddr)
{
	return NULL;
}

u_int16_t *
set_port(struct sockaddr *addr, u_int16_t new_port)
{
	return NULL;
}

int
isakmp_get_sainfo(struct ph2handle *iph2, struct secpolicy *sp0,
    struct secpolicy *sp1)
{
	return -1;
}

int
insph2(struct ph2handle *iph2)
{
	return -1;
}

int
isakmp_post_acquire(struct ph2handle *iph2, struct ph1handle *iph1, int flag)
{
	return -1;
}

void
remph2(struct ph2handle *iph2)
{
}

u_int32_t
pk_getseq(void)
{
	return 0;
}
