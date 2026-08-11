// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stub implementations for the symbols status.c's status_dump() extraction
 * pass needs at link time, but that this test suite has no interest in
 * exercising for real: enumph1()/enumph2() (handler.c) are stubbed so a
 * test can hand status_dump() an exact, controlled list of struct
 * ph1handle/ph2handle pointers without constructing a real ph1tree/ph2tree
 * or linking handler.c's own large dependency closure; saddr2str()/
 * ipsecdoi_id2str()/getspbyspid()/splitnet_list_2str() are stubbed the same
 * way admin_test_stubs.c stubs admin.c's dependencies -- real strnames.c
 * lookups (s_attr_isakmp_enc() and friends) are linked for real via
 * RACOON_OBJS, since those are exactly the enum-to-string mappings this
 * test suite wants genuine coverage of.
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
#include "handler.h"
#include "policy.h"
#ifdef ENABLE_HYBRID
#include "isakmp.h"
#include "isakmp_unity.h"
#endif

struct status_test_ph1_queue_entry {
	struct ph1handle *p;
};

#define STATUS_TEST_QUEUE_MAX 8
struct ph1handle *status_test_ph1_queue[STATUS_TEST_QUEUE_MAX];
int status_test_ph1_queue_len = 0;
struct ph2handle *status_test_ph2_queue[STATUS_TEST_QUEUE_MAX];
int status_test_ph2_queue_len = 0;

int
enumph1(struct ph1selector *sel, int (*enum_func)(struct ph1handle *, void *),
    void *arg)
{
	int i, ret;

	for (i = 0; i < status_test_ph1_queue_len; i++) {
		if ((ret = enum_func(status_test_ph1_queue[i], arg)) != 0)
			return ret;
	}
	return 0;
}

int
enumph2(struct ph2selector *sel, int (*enum_func)(struct ph2handle *, void *),
    void *arg)
{
	int i, ret;

	for (i = 0; i < status_test_ph2_queue_len; i++) {
		if ((ret = enum_func(status_test_ph2_queue[i], arg)) != 0)
			return ret;
	}
	return 0;
}

/* Fixed, recognizable strings so tests can assert on their presence, and
 * (for saddr2str_result) so a test can inject JSON-hostile characters to
 * verify escaping without needing a real getnameinfo() round trip. */
char *saddr2str_result = "198.51.100.1[500]";
char *ipsecdoi_id2str_result = "198.51.100.1";

char *
saddr2str(const struct sockaddr *sa)
{
	return saddr2str_result;
}

char *
ipsecdoi_id2str(const vchar_t *id)
{
	/* Real ipsecdoi_id2str() (ipsec_doi.c) always racoon_malloc()s a
	 * fresh copy before returning -- its own static char buf[512] is
	 * pure scratch space, fully consumed before the function returns.
	 * The caller takes ownership of the returned pointer and is
	 * expected to racoon_free() it exactly once. A stub that just
	 * handed back a fixed literal (as this one used to) would let a
	 * caller that racoon_free()s it crash outright (freeing a string
	 * literal is undefined behavior) while masking a caller that
	 * *doesn't* free it -- i.e. it could never have caught the
	 * double-allocation leak this stub exists to guard against. Return
	 * a fresh allocation each call, matching the real ownership
	 * contract. */
	return racoon_strdup(ipsecdoi_id2str_result);
}

/* NULL (the default) reproduces the "no SP found, host fallback" path
 * every existing test exercises; a test that wants the real-prefix path
 * (sockaddr_to_cidr() given an actual prefs/prefd instead of defaulting
 * to /32) points this at its own struct secpolicy fixture instead. */
struct secpolicy *getspbyspid_result = NULL;

struct secpolicy *
getspbyspid(u_int32_t spid)
{
	return getspbyspid_result;
}

#ifdef ENABLE_HYBRID
char *
splitnet_list_2str(struct unity_netentry *list, enum splinet_ipaddr fmt)
{
	if (list == NULL)
		return NULL;
	return racoon_strdup("10.0.1.0/24 10.0.2.0/24");
}
#endif
