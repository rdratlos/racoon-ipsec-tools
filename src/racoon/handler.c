/*	$NetBSD: handler.c,v 1.39.2.1 2011/11/17 14:46:31 vanhu Exp $	*/

/* Id: handler.c,v 1.28 2006/05/26 12:17:29 manubsd Exp */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#ifdef ENABLE_HYBRID
#include <resolv.h>
#endif

#include "schedule.h"
#include "grabmyaddr.h"
#include "algorithm.h"
#include "crypto_openssl.h"
#include "policy.h"
#include "proposal.h"
#include "isakmp_var.h"
#include "evt.h"
#include "isakmp.h"
#ifdef ENABLE_HYBRID
#include "isakmp_xauth.h"
#include "isakmp_cfg.h"
#endif
#include "isakmp_inf.h"
#include "oakley.h"
#include "remoteconf.h"
#include "localconf.h"
#include "handler.h"
#include "gcmalloc.h"
#include "nattraversal.h"

#include "sainfo.h"
#include "ipsec_doi.h"
#include "strnames.h"

#ifdef HAVE_GSSAPI
#include "gssapi.h"
#endif

static LIST_HEAD(_ph1tree_, ph1handle) ph1tree;
static LIST_HEAD(_ph2tree_, ph2handle) ph2tree;
static LIST_HEAD(_ctdtree_, contacted) ctdtree;
static LIST_HEAD(_rcptree_, recvdpkt) rcptree;
static struct sched sc_sweep = SCHED_INITIALIZER();

static void del_recvdpkt __P((struct recvdpkt *));
static void rem_recvdpkt __P((struct recvdpkt *));

/*
 * functions about management of the isakmp status table
 */
/* %%% management phase 1 handler */
/*
 * search for isakmpsa handler with isakmp index.
 */

extern caddr_t val2str(const char *, size_t);

/*
 * Enumerate the Phase 1 tree.
 * If enum_func() internally return a non-zero value,  this specific
 * error value is returned. 0 is returned if everything went right.
 *
 * Note that it is ok for enum_func() to call insph1(). Those inserted
 * Phase 1 will not interfere with current enumeration process.
 */
int
enumph1(struct ph1selector *sel, int (*enum_func)(struct ph1handle *iph1, void *arg), void *enum_arg)
{
	struct ph1handle *p, *next;
	int ret;

	/*
	 * Precompute "next" before calling enum_func(): admin.c's
	 * admin_ph1_delete_sa() (the delete-sa/flush-sa racoonctl(1)
	 * commands) calls back into purge_remote()/delph1(), which frees
	 * the very "p" a plain LIST_FOREACH would only read *after* the
	 * call returns to advance -- a use-after-free confirmed by
	 * valgrind on a live delete-sa/flush-sa run. Mirrors the same
	 * precomputed-next pattern already used everywhere else in this
	 * file an entry can be deleted mid-loop (delph1(), delph2(), ...).
	 */
	for (p = LIST_FIRST(&ph1tree); p; p = next) {
		next = LIST_NEXT(p, chain);

		if (sel != NULL) {
			if (sel->local != NULL &&
			    cmpsaddr(sel->local, p->local) > CMPSADDR_WILDPORT_MATCH)
				continue;

			if (sel->remote != NULL &&
			    cmpsaddr(sel->remote, p->remote) > CMPSADDR_WILDPORT_MATCH)
				continue;
		}

		if ((ret = enum_func(p, enum_arg)) != 0)
			return ret;
	}

	return 0;
}

struct ph1handle *
getph1byindex(isakmp_index *index)
{
	struct ph1handle *p;

	LIST_FOREACH(p, &ph1tree, chain) {
		if (p->status >= PHASE1ST_EXPIRED)
			continue;
		if (memcmp(&p->index, index, sizeof(*index)) == 0)
			return p;
	}

	return NULL;
}


/*
 * search for isakmp handler by i_ck in index.
 */
struct ph1handle *
getph1byindex0(isakmp_index *index)
{
	struct ph1handle *p;

	LIST_FOREACH(p, &ph1tree, chain) {
		if (p->status >= PHASE1ST_EXPIRED)
			continue;
		if (memcmp(&p->index, index, sizeof(cookie_t)) == 0)
			return p;
	}

	return NULL;
}

/*
 * search for isakmpsa handler by source and remote address.
 * don't use port number to search because this function search
 * with phase 2's destinaion.
 */
struct ph1handle *
getph1(struct ph1handle *ph1hint, struct sockaddr *local, struct sockaddr *remote, int flags)
{
	struct ph1handle *p;

	plog(LLV_DEBUG2, LOCATION, NULL, "getph1: start\n");
	plog(LLV_DEBUG2, LOCATION, NULL, "local: %s\n", saddr2str(local));
	plog(LLV_DEBUG2, LOCATION, NULL, "remote: %s\n", saddr2str(remote));

	LIST_FOREACH(p, &ph1tree, chain) {
		if (p->status >= PHASE1ST_DYING)
			continue;

		plog(LLV_DEBUG2, LOCATION, NULL, "p->local: %s\n", saddr2str(p->local));
		plog(LLV_DEBUG2, LOCATION, NULL, "p->remote: %s\n", saddr2str(p->remote));

		if ((flags & GETPH1_F_ESTABLISHED) &&
		    (p->status != PHASE1ST_ESTABLISHED)) {
			plog(LLV_DEBUG2, LOCATION, NULL,
			     "status %d, skipping\n", p->status);
			continue;
		}

		if (local != NULL && cmpsaddr(local, p->local) == CMPSADDR_MISMATCH)
			continue;

		if (remote != NULL && cmpsaddr(remote, p->remote) == CMPSADDR_MISMATCH)
			continue;

		if (ph1hint != NULL) {
			if (ph1hint->id && ph1hint->id->l && p->id && p->id->l &&
			    (ph1hint->id->l != p->id->l ||
			     memcmp(ph1hint->id->v, p->id->v, p->id->l) != 0)) {
				plog(LLV_DEBUG2, LOCATION, NULL,
				     "local identity does match hint\n");
				continue;
			}
			if (ph1hint->id_p && ph1hint->id_p->l &&
			    p->id_p && p->id_p->l &&
			    (ph1hint->id_p->l != p->id_p->l ||
			     memcmp(ph1hint->id_p->v, p->id_p->v, p->id_p->l) != 0)) {
				plog(LLV_DEBUG2, LOCATION, NULL,
				     "remote identity does match hint\n");
				continue;
			}
		}

		plog(LLV_DEBUG2, LOCATION, NULL, "matched\n");
		return p;
	}

	plog(LLV_DEBUG2, LOCATION, NULL, "no match\n");

	return NULL;
}

int
resolveph1rmconf(struct ph1handle *iph1)
{
	struct remoteconf *rmconf;

	/* INITIATOR is always expected to know the exact rmconf. */
	if (iph1->side == INITIATOR)
		return 0;

	rmconf = getrmconf_by_ph1(iph1);
	if (rmconf == NULL)
		return -1;
	if (rmconf == RMCONF_ERR_MULTIPLE)
		return 1;

	if (iph1->rmconf != NULL) {
		if (rmconf != iph1->rmconf) {
			plog(LLV_ERROR, LOCATION, NULL,
			     "unexpected rmconf switch; killing ph1\n");
			return -1;
		}
	} else {
		iph1->rmconf = rmconf;
	}

	return 0;
}


/*
 * move phase2s from old_iph1 to new_iph1
 */
void
migrate_ph12(struct ph1handle *old_iph1, struct ph1handle *new_iph1)
{
	struct ph2handle *p, *next;

	/* Relocate phase2s to better phase1s or request a new phase1. */
	for (p = LIST_FIRST(&old_iph1->ph2tree); p; p = next) {
		next = LIST_NEXT(p, ph1bind);

		if (p->status != PHASE2ST_ESTABLISHED)
			continue;

		unbindph12(p);
		bindph12(new_iph1, p);
	}
}

/*
 * the iph1 is new, migrate all phase2s that belong to a dying or dead ph1
 */
void migrate_dying_ph12(struct ph1handle *iph1)
{
	struct ph1handle *p;

	LIST_FOREACH(p, &ph1tree, chain) {
		if (p == iph1)
			continue;
		if (p->status < PHASE1ST_DYING)
			continue;

		if (cmpsaddr(iph1->local, p->local) == CMPSADDR_MATCH
		 && cmpsaddr(iph1->remote, p->remote) == CMPSADDR_MATCH)
			migrate_ph12(p, iph1);
	}
}


/*
 * dump isakmp-sa
 */
vchar_t *
dumpph1(void)
{
	struct ph1handle *iph1;
	struct ph1dump *pd;
	int cnt = 0;
	vchar_t *buf;

	/* get length of buffer */
	LIST_FOREACH(iph1, &ph1tree, chain)
		cnt++;

	buf = vmalloc(cnt * sizeof(struct ph1dump));
	if (buf == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to get buffer\n");
		return NULL;
	}
	pd = (struct ph1dump *)buf->v;

	LIST_FOREACH(iph1, &ph1tree, chain) {
		memcpy(&pd->index, &iph1->index, sizeof(iph1->index));
		pd->status = iph1->status;
		pd->side = iph1->side;
		memcpy(&pd->remote, iph1->remote, sysdep_sa_len(iph1->remote));
		memcpy(&pd->local, iph1->local, sysdep_sa_len(iph1->local));
		pd->version = iph1->version;
		pd->etype = iph1->etype;
		pd->created = iph1->created;
		pd->ph2cnt = iph1->ph2cnt;
		pd++;
	}

	return buf;
}

static const char *
ph1_state_to_str(int state)
{
	switch (state) {
	case PHASE1ST_SPAWN:		return "spawn";
	case PHASE1ST_START:		return "start";
	case PHASE1ST_MSG1RECEIVED:	return "msg1received";
	case PHASE1ST_MSG1SENT:		return "msg1sent";
	case PHASE1ST_MSG2RECEIVED:	return "msg2received";
	case PHASE1ST_MSG2SENT:		return "msg2sent";
	case PHASE1ST_MSG3RECEIVED:	return "msg3received";
	case PHASE1ST_MSG3SENT:		return "msg3sent";
	case PHASE1ST_MSG4RECEIVED:	return "msg4received";
	case PHASE1ST_ESTABLISHED:	return "established";
	case PHASE1ST_DYING:		return "dying";
	case PHASE1ST_EXPIRED:		return "expired";
	default:			return "unknown";
	}
}

static const char *
ph2_state_to_str(int state)
{
	switch (state) {
	case PHASE2ST_SPAWN:		return "spawn";
	case PHASE2ST_START:		return "start";
	case PHASE2ST_STATUS2:		return "status2";
	case PHASE2ST_GETSPISENT:	return "getspisent";
	case PHASE2ST_GETSPIDONE:	return "getspidone";
	case PHASE2ST_MSG1SENT:		return "msg1sent";
	case PHASE2ST_STATUS6:		return "status6";
	case PHASE2ST_COMMIT:		return "commit";
	case PHASE2ST_ADDSA:		return "addsa";
	case PHASE2ST_ESTABLISHED:	return "established";
	case PHASE2ST_EXPIRED:		return "expired";
	default:			return "unknown";
	}
}

#ifdef ENABLE_HYBRID
static const char *
xauth_state_to_str(int state)
{
	switch (state) {
	case XAUTHST_NOTYET:		return "notyet";
	case XAUTHST_REQSENT:		return "reqsent";
	case XAUTHST_OK:			return "ok";
	default:			return "unknown";
	}
}

static const char *
xauth_method_to_str(int method)
{
	switch (method) {
	case XAUTH_TYPE_GENERIC:	return "generic";
	case XAUTH_TYPE_CHAP:		return "chap";
	case XAUTH_TYPE_OTP:		return "otp";
	case XAUTH_TYPE_SKEY:		return "skey";
	default:			return "unknown";
	}
}
#endif

static const char *
auth_method_to_str(int method)
{
	switch (method) {
	case OAKLEY_ATTR_AUTH_METHOD_PSKEY:	return "psk";
	case OAKLEY_ATTR_AUTH_METHOD_DSSSIG:	return "dsssig";
	case OAKLEY_ATTR_AUTH_METHOD_RSASIG:	return "rsasig";
	case OAKLEY_ATTR_AUTH_METHOD_RSAENC:	return "rsaenc";
	case OAKLEY_ATTR_AUTH_METHOD_RSAREV:	return "rsarev";
	case OAKLEY_ATTR_AUTH_METHOD_EGENC:	return "egenc";
	case OAKLEY_ATTR_AUTH_METHOD_EGREV:	return "egrev";
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_I: return "hybrid_rsa_i";
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_RSA_R: return "hybrid_rsa_r";
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_I: return "hybrid_dss_i";
	case OAKLEY_ATTR_AUTH_METHOD_HYBRID_DSS_R: return "hybrid_dss_r";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_I: return "xauth_pskey_i";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_PSKEY_R: return "xauth_pskey_r";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_I: return "xauth_dsssig_i";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_DSSSIG_R: return "xauth_dsssig_r";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_I: return "xauth_rsasig_i";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSASIG_R: return "xauth_rsasig_r";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_I: return "xauth_rsaenc_i";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAENC_R: return "xauth_rsaenc_r";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_I: return "xauth_rsarev_i";
	case OAKLEY_ATTR_AUTH_METHOD_XAUTH_RSAREV_R: return "xauth_rsarev_r";
	case OAKLEY_ATTR_AUTH_METHOD_GSSAPI_KRB: return "gssapi_krb";
	default:				return "unknown";
	}
}

static void
json_escaped_append(char **dst, size_t *dst_len, size_t *dst_pos, const char *src)
{
	size_t src_len;
	char *new_dst;

	if (src == NULL)
		return;

	src_len = strlen(src);
	while (*dst_pos + src_len + 1 >= *dst_len) {
		*dst_len *= 2;
		new_dst = racoon_realloc(*dst, *dst_len);
		if (new_dst == NULL) {
			plog(LLV_ERROR, LOCATION, NULL, "json realloc failed\n");
			return;
		}
		*dst = new_dst;
	}

	for (size_t i = 0; i < src_len; i++) {
		unsigned char c = (unsigned char)src[i];
		if (c == '"' || c == '\\') {
			(*dst)[(*dst_pos)++] = '\\';
			(*dst)[(*dst_pos)++] = c;
		} else if (c < 0x20) {
			(*dst)[(*dst_pos)++] = '\\';
			switch (c) {
			case '\b': (*dst)[(*dst_pos)++] = 'b'; break;
			case '\f': (*dst)[(*dst_pos)++] = 'f'; break;
			case '\n': (*dst)[(*dst_pos)++] = 'n'; break;
			case '\r': (*dst)[(*dst_pos)++] = 'r'; break;
			case '\t': (*dst)[(*dst_pos)++] = 't'; break;
			default:
				snprintf(*dst + *dst_pos, 7, "u%04x", c);
				*dst_pos += 6;
				break;
			}
		} else {
			(*dst)[(*dst_pos)++] = c;
		}
	}
	(*dst)[*dst_pos] = '\0';
}

static void
json_append(char **dst, size_t *dst_len, size_t *dst_pos, const char *fmt, ...)
{
	va_list ap;
	char *new_dst;
	int needed;

	if (*dst_pos >= *dst_len - 1)
		return;

	va_start(ap, fmt);
	needed = vsnprintf(*dst + *dst_pos, *dst_len - *dst_pos, fmt, ap);
	va_end(ap);

	if (needed < 0)
		return;

	if ((size_t)needed >= *dst_len - *dst_pos) {
		*dst_len = *dst_pos + needed + 256;
		new_dst = racoon_realloc(*dst, *dst_len);
		if (new_dst == NULL) {
			plog(LLV_ERROR, LOCATION, NULL, "json realloc failed\n");
			return;
		}
		*dst = new_dst;

		va_start(ap, fmt);
		needed = vsnprintf(*dst + *dst_pos, *dst_len - *dst_pos, fmt, ap);
		va_end(ap);
		if (needed < 0)
			return;
	}

	*dst_pos += needed;
}

static char *
saddr_to_cidr(struct sockaddr *sa)
{
	char addr[NI_MAXHOST];
	char *result = NULL;
	int prefixlen = 128;

	if (sa == NULL)
		return racoon_strdup("0.0.0.0/0");

	if (getnameinfo(sa, sysdep_sa_len(sa), addr, sizeof(addr), NULL, 0, NI_NUMERICHOST) != 0)
		return racoon_strdup("?");

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		prefixlen = 32;
		if (sin->sin_addr.s_addr == INADDR_ANY)
			prefixlen = 0;
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
			prefixlen = 0;
	}

	if (asprintf(&result, "%s/%d", addr, prefixlen) < 0)
		return racoon_strdup("?");

	return result;
}

static char *
mask_spi(u_int32_t spi)
{
	char *result;
	if (asprintf(&result, "0x%08x", spi) < 0)
		return racoon_strdup("?");
	return result;
}

static char *
format_time(time_t t)
{
	char *result;
	struct tm *tm;
	char buf[32];

	tm = gmtime(&t);
	if (tm == NULL)
		return racoon_strdup("1970-01-01T00:00:00Z");

	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
	result = racoon_strdup(buf);
	return result;
}

void
status_dump(vchar_t **out, int verbose)
{
	struct ph1handle *iph1;
	struct ph2handle *iph2;
	char *json = NULL;
	size_t json_len = 8192;
	size_t json_pos = 0;
	time_t now = time(NULL);
	char *timestamp;
	int first_ph1 = 1;
	int first_ph2 = 1;

	json = racoon_malloc(json_len);
	if (json == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, "status_dump: malloc failed\n");
		*out = NULL;
		return;
	}

	json_append(&json, &json_len, &json_pos, "{\"version\":1,\"timestamp\":\"");
	timestamp = format_time(now);
	json_escaped_append(&json, &json_len, &json_pos, timestamp);
	racoon_free(timestamp);
	json_append(&json, &json_len, &json_pos, "\",\"phase1\":[");

	LIST_FOREACH(iph1, &ph1tree, chain) {
		const char *remote_str = saddr2str(iph1->remote);
		const char *local_str = saddr2str(iph1->local);
		char *initiator_spi = racoon_malloc(17);
		char *responder_spi = racoon_malloc(17);
		if (initiator_spi) {
			for (int i = 0; i < 8; i++)
				snprintf(initiator_spi + i * 2, 3, "%02x", iph1->index.i_ck[i]);
		} else {
			initiator_spi = racoon_strdup("?");
		}
		if (responder_spi) {
			for (int i = 0; i < 8; i++)
				snprintf(responder_spi + i * 2, 3, "%02x", iph1->index.r_ck[i]);
		} else {
			responder_spi = racoon_strdup("?");
		}
		char *created_str = format_time(iph1->created);
		const char *auth_method_str = "unknown";
		const char *enc_alg = "unknown";
		const char *hash_alg = "unknown";
		const char *dh_group_str = "unknown";
		const char *pfs_group_str = "none";
		char *lifetime_time_str = "0";
		char *lifetime_bytes_str = "0";
		const char *xauth_state_str = "none";
		const char *xauth_method_str = "none";
		char *mode_cfg_addr = NULL;
		char *mode_cfg_dns = NULL;
		char *mode_cfg_domain = NULL;
		char *mode_cfg_pfs = NULL;

		if (!first_ph1)
			json_append(&json, &json_len, &json_pos, ",");
		first_ph1 = 0;

		if (iph1->approval) {
			auth_method_str = auth_method_to_str(iph1->approval->authmethod);
			enc_alg = s_attr_isakmp_enc(iph1->approval->enctype);
			hash_alg = s_attr_isakmp_hash(iph1->approval->hashtype);
			dh_group_str = s_attr_isakmp_group(iph1->approval->dh_group);
			if (asprintf(&lifetime_time_str, "%lu", (unsigned long)iph1->approval->lifetime) < 0)
				lifetime_time_str = racoon_strdup("0");
			if (iph1->approval->lifebyte) {
				if (asprintf(&lifetime_bytes_str, "%lu", (unsigned long)iph1->approval->lifebyte) < 0)
					lifetime_bytes_str = racoon_strdup("0");
			}
		}

#ifdef ENABLE_HYBRID
		if (iph1->mode_cfg) {
			mode_cfg_addr = saddr_to_cidr((struct sockaddr *)&iph1->mode_cfg->addr4);
			if (iph1->mode_cfg->dns4_index > 0) {
				char dns_buf[NI_MAXHOST];
				getnameinfo((struct sockaddr *)&iph1->mode_cfg->dns4[0], sizeof(struct in_addr),
					    dns_buf, sizeof(dns_buf), NULL, 0, NI_NUMERICHOST);
				mode_cfg_dns = racoon_strdup(dns_buf);
			}
			if (iph1->mode_cfg->default_domain[0])
				mode_cfg_domain = racoon_strdup(iph1->mode_cfg->default_domain);
			if (iph1->mode_cfg->xauth.status != XAUTHST_NOTYET) {
				xauth_state_str = xauth_state_to_str(iph1->mode_cfg->xauth.status);
				xauth_method_str = xauth_method_to_str(iph1->mode_cfg->xauth.authtype);
			}
		}
#endif

		json_append(&json, &json_len, &json_pos, "{");
		json_append(&json, &json_len, &json_pos, "\"state\":\"%s\",", ph1_state_to_str(iph1->status));
		json_append(&json, &json_len, &json_pos, "\"initiator_spi\":\"%s\",", initiator_spi);
		json_append(&json, &json_len, &json_pos, "\"responder_spi\":\"%s\",", responder_spi);
		json_append(&json, &json_len, &json_pos, "\"remote\":\"%s\",", remote_str);
		json_append(&json, &json_len, &json_pos, "\"local\":\"%s\",", local_str);
		json_append(&json, &json_len, &json_pos, "\"version\":%d,", iph1->version);
		json_append(&json, &json_len, &json_pos, "\"etype\":%d,", iph1->etype);
		json_append(&json, &json_len, &json_pos, "\"side\":%d,", iph1->side);
		json_append(&json, &json_len, &json_pos, "\"created\":\"%s\",", created_str);
		json_append(&json, &json_len, &json_pos, "\"auth_method\":\"%s\",", auth_method_str);
		json_append(&json, &json_len, &json_pos, "\"encryption_algorithm\":\"%s\",", enc_alg);
		json_append(&json, &json_len, &json_pos, "\"hash_algorithm\":\"%s\",", hash_alg);
		json_append(&json, &json_len, &json_pos, "\"dh_group\":\"%s\",", dh_group_str);
		json_append(&json, &json_len, &json_pos, "\"pfs_group\":\"%s\",", pfs_group_str);
		json_append(&json, &json_len, &json_pos, "\"lifetime_time\":%s,", lifetime_time_str);
		json_append(&json, &json_len, &json_pos, "\"lifetime_bytes\":%s,", lifetime_bytes_str);
		json_append(&json, &json_len, &json_pos, "\"xauth_state\":\"%s\",", xauth_state_str);
		json_append(&json, &json_len, &json_pos, "\"xauth_method\":\"%s\",", xauth_method_str);
		json_append(&json, &json_len, &json_pos, "\"mode_cfg_address\":\"%s\",", mode_cfg_addr);
		json_append(&json, &json_len, &json_pos, "\"mode_cfg_dns\":\"%s\",", mode_cfg_dns);
		json_append(&json, &json_len, &json_pos, "\"mode_cfg_domain\":\"%s\",", mode_cfg_domain);
		json_append(&json, &json_len, &json_pos, "\"mode_cfg_pfs_group\":\"%s\"", mode_cfg_pfs);
		if (verbose) {
			char *dpd_str = racoon_malloc(32);
			if (dpd_str) {
				snprintf(dpd_str, 32, "%d", iph1->dpd_support);
				json_append(&json, &json_len, &json_pos, ",\"dpd_support\":%s", dpd_str);
				racoon_free(dpd_str);
			}
			if (iph1->natt_options) {
				char *natt_str = racoon_malloc(32);
				if (natt_str) {
					snprintf(natt_str, 32, "%d", 1);
					json_append(&json, &json_len, &json_pos, ",\"natt_enabled\":%s", natt_str);
					racoon_free(natt_str);
				}
			}
			if (iph1->rmconf) {
				char *proposal_num = racoon_malloc(32);
				if (proposal_num) {
					snprintf(proposal_num, 32, "%d", iph1->rmconf->proposal ? 1 : 0);
					json_append(&json, &json_len, &json_pos, ",\"has_proposals\":%s", proposal_num);
					racoon_free(proposal_num);
				}
				char *gen_policy_str = racoon_malloc(32);
				if (gen_policy_str) {
					snprintf(gen_policy_str, 32, "%d", iph1->rmconf->gen_policy);
					json_append(&json, &json_len, &json_pos, ",\"generate_policy\":%s", gen_policy_str);
					racoon_free(gen_policy_str);
				}
			}
		}
		json_append(&json, &json_len, &json_pos, "}");

		racoon_free(initiator_spi);
		racoon_free(responder_spi);
		racoon_free(created_str);
		if (lifetime_time_str != (char *)"0")
			racoon_free(lifetime_time_str);
		if (lifetime_bytes_str != (char *)"0")
			racoon_free(lifetime_bytes_str);
		racoon_free(mode_cfg_addr);
		racoon_free(mode_cfg_dns);
		racoon_free(mode_cfg_domain);
		racoon_free(mode_cfg_pfs);
	}

	json_append(&json, &json_len, &json_pos, "],\"phase2\":[");

	LIST_FOREACH(iph2, &ph2tree, chain) {
		struct ph1handle *parent_iph1 = iph2->ph1;
		const char *remote_str = saddr2str(iph2->dst);
		const char *local_str = saddr2str(iph2->src);
		const char *protocol_str = "unknown";
		const char *enc_alg = "none";
		const char *auth_alg = "none";
		const char *comp_alg = "none";
		const char *pfs_group_str = "none";
		char *lifetime_time_str = "0";
		char *lifetime_bytes_str = "0";
		char *selector_src = "0.0.0.0/0";
		char *selector_dst = "0.0.0.0/0";
		char *selector_sport = "0";
		char *selector_dport = "0";
		char *selector_proto = "0";
		char *spi_in = NULL;
		char *spi_out = NULL;

		if (!first_ph2)
			json_append(&json, &json_len, &json_pos, ",");
		first_ph2 = 0;

		if (iph2->approval && iph2->approval->head) {
			struct saproto *proto = iph2->approval->head;
			switch (proto->proto_id) {
			case IPSECDOI_PROTO_IPSEC_ESP:
				protocol_str = "esp";
				break;
			case IPSECDOI_PROTO_IPSEC_AH:
				protocol_str = "ah";
				break;
			case IPSECDOI_PROTO_IPCOMP:
				protocol_str = "ipcomp";
				break;
			}
			spi_in = mask_spi(proto->spi);
			spi_out = mask_spi(proto->spi_p);

			for (struct satrns *trns = proto->head; trns; trns = trns->next) {
				switch (proto->proto_id) {
				case IPSECDOI_PROTO_IPSEC_ESP:
					switch (trns->trns_id) {
					case IPSECDOI_ESP_DES_IV64:
					case IPSECDOI_ESP_DES:
					case IPSECDOI_ESP_3DES:
					case IPSECDOI_ESP_RC5:
					case IPSECDOI_ESP_IDEA:
					case IPSECDOI_ESP_CAST:
					case IPSECDOI_ESP_BLOWFISH:
					case IPSECDOI_ESP_3IDEA:
					case IPSECDOI_ESP_DES_IV32:
					case IPSECDOI_ESP_RC4:
					case IPSECDOI_ESP_NULL:
					case IPSECDOI_ESP_AES:
					case IPSECDOI_ESP_CAMELLIA:
					case IPSECDOI_ESP_TWOFISH:
						enc_alg = s_ipsecdoi_trns_esp(trns->trns_id);
						break;
					}
					if (trns->authtype != IPSECDOI_ATTR_AUTH_NONE) {
						auth_alg = s_ipsecdoi_auth(trns->authtype);
					}
					break;
				case IPSECDOI_PROTO_IPSEC_AH:
					switch (trns->trns_id) {
					case IPSECDOI_AH_MD5:
					case IPSECDOI_AH_SHA:
					case IPSECDOI_AH_DES:
					case IPSECDOI_AH_SHA256:
					case IPSECDOI_AH_SHA384:
					case IPSECDOI_AH_SHA512:
						enc_alg = s_ipsecdoi_trns_ah(trns->trns_id);
						break;
					}
					break;
				case IPSECDOI_PROTO_IPCOMP:
					switch (trns->trns_id) {
					case IPSECDOI_IPCOMP_OUI:
					case IPSECDOI_IPCOMP_DEFLATE:
					case IPSECDOI_IPCOMP_LZS:
						comp_alg = s_ipsecdoi_trns_ipcomp(trns->trns_id);
						break;
					}
					break;
				}
			}
		}

		if (iph2->approval) {
			if (iph2->approval->pfs_group)
				pfs_group_str = s_attr_isakmp_group(iph2->approval->pfs_group);
			if (iph2->approval->lifetime) {
				if (asprintf(&lifetime_time_str, "%lu", (unsigned long)iph2->approval->lifetime) < 0)
					lifetime_time_str = racoon_strdup("0");
			}
			if (iph2->approval->lifebyte) {
				if (asprintf(&lifetime_bytes_str, "%lu", (unsigned long)iph2->approval->lifebyte) < 0)
					lifetime_bytes_str = racoon_strdup("0");
			}
		}

		selector_src = saddr_to_cidr(iph2->src);
		selector_dst = saddr_to_cidr(iph2->dst);
		if (iph2->sa_src) {
			struct sockaddr_in *sin = (struct sockaddr_in *)iph2->sa_src;
			if (sin->sin_family == AF_INET) {
				if (asprintf(&selector_sport, "%d", ntohs(sin->sin_port)) < 0)
					selector_sport = racoon_strdup("0");
			}
		}
		if (iph2->sa_dst) {
			struct sockaddr_in *sin = (struct sockaddr_in *)iph2->sa_dst;
			if (sin->sin_family == AF_INET) {
				if (asprintf(&selector_dport, "%d", ntohs(sin->sin_port)) < 0)
					selector_dport = racoon_strdup("0");
			}
		}
		if (iph2->id) {
			struct ipsecdoi_id_b *id_b = (struct ipsecdoi_id_b *)iph2->id->v;
			if (id_b) {
				if (asprintf(&selector_proto, "%d", id_b->proto_id) < 0)
					selector_proto = racoon_strdup("0");
			}
		}

		if (!spi_in)
			spi_in = racoon_strdup("0");
		if (!spi_out)
			spi_out = racoon_strdup("0");

		json_append(&json, &json_len, &json_pos, "{");
		json_append(&json, &json_len, &json_pos, "\"state\":\"%s\",", ph2_state_to_str(iph2->status));
		json_append(&json, &json_len, &json_pos, "\"spi_in\":\"%s\",", spi_in);
		json_append(&json, &json_len, &json_pos, "\"spi_out\":\"%s\",", spi_out);
		json_append(&json, &json_len, &json_pos, "\"protocol\":\"%s\",", protocol_str);
		json_append(&json, &json_len, &json_pos, "\"encryption_algorithm\":\"%s\",", enc_alg);
		json_append(&json, &json_len, &json_pos, "\"auth_algorithm\":\"%s\",", auth_alg);
		json_append(&json, &json_len, &json_pos, "\"comp_algorithm\":\"%s\",", comp_alg);
		json_append(&json, &json_len, &json_pos, "\"pfs_group\":\"%s\",", pfs_group_str);
		json_append(&json, &json_len, &json_pos, "\"lifetime_time\":%s,", lifetime_time_str);
		json_append(&json, &json_len, &json_pos, "\"lifetime_bytes\":%s,", lifetime_bytes_str);
		json_append(&json, &json_len, &json_pos, "\"selector\":{");
		json_append(&json, &json_len, &json_pos, "\"src\":\"%s\",", selector_src);
		json_append(&json, &json_len, &json_pos, "\"dst\":\"%s\",", selector_dst);
		json_append(&json, &json_len, &json_pos, "\"sport\":%s,", selector_sport);
		json_append(&json, &json_len, &json_pos, "\"dport\":%s,", selector_dport);
		json_append(&json, &json_len, &json_pos, "\"proto\":%s", selector_proto);
		json_append(&json, &json_len, &json_pos, "}");
		if (verbose) {
			if (iph2->approval && iph2->approval->head) {
				struct saproto *proto = iph2->approval->head;
				json_append(&json, &json_len, &json_pos, ",\"transforms\":[");
				int first_transform = 1;
				for (struct satrns *trns = proto->head; trns; trns = trns->next) {
					if (!first_transform)
						json_append(&json, &json_len, &json_pos, ",");
					first_transform = 0;
					json_append(&json, &json_len, &json_pos, "{");
					json_append(&json, &json_len, &json_pos, "\"type\":%d,", trns->trns_id);
					json_append(&json, &json_len, &json_pos, "\"authtype\":%d,", trns->authtype);
					json_append(&json, &json_len, &json_pos, "\"encklen\":%d", trns->encklen);
					json_append(&json, &json_len, &json_pos, "}");
				}
				json_append(&json, &json_len, &json_pos, "]");
			}
			char *side_str = racoon_malloc(32);
			if (side_str) {
				snprintf(side_str, 32, "%d", iph2->side);
				json_append(&json, &json_len, &json_pos, ",\"side\":%s", side_str);
				racoon_free(side_str);
			}
			if (iph2->sa) {
				char *sa_str = racoon_malloc(32);
				if (sa_str) {
					snprintf(sa_str, 32, "%p", iph2->sa);
					json_append(&json, &json_len, &json_pos, ",\"sa\":%s", sa_str);
					racoon_free(sa_str);
				}
			}
		}
		if (parent_iph1) {
			char *parent_initiator_spi = racoon_malloc(17);
			char *parent_responder_spi = racoon_malloc(17);
			if (parent_initiator_spi) {
				for (int i = 0; i < 8; i++)
					snprintf(parent_initiator_spi + i * 2, 3, "%02x", parent_iph1->index.i_ck[i]);
			} else {
				parent_initiator_spi = racoon_strdup("?");
			}
			if (parent_responder_spi) {
				for (int i = 0; i < 8; i++)
					snprintf(parent_responder_spi + i * 2, 3, "%02x", parent_iph1->index.r_ck[i]);
			} else {
				parent_responder_spi = racoon_strdup("?");
			}
			json_append(&json, &json_len, &json_pos, ",\"parent_ike_sa\":{\"initiator_spi\":\"%s\",\"responder_spi\":\"%s\"}",
				    parent_initiator_spi, parent_responder_spi);
			racoon_free(parent_initiator_spi);
			racoon_free(parent_responder_spi);
		}
		json_append(&json, &json_len, &json_pos, "}");

		racoon_free(spi_in);
		racoon_free(spi_out);
		racoon_free(selector_src);
		racoon_free(selector_dst);
		if (selector_sport != (char *)"0")
			racoon_free(selector_sport);
		if (selector_dport != (char *)"0")
			racoon_free(selector_dport);
		if (selector_proto != (char *)"0")
			racoon_free(selector_proto);
		if (lifetime_time_str != (char *)"0")
			racoon_free(lifetime_time_str);
		if (lifetime_bytes_str != (char *)"0")
			racoon_free(lifetime_bytes_str);
	}

json_append(&json, &json_len, &json_pos, "]}");

json[json_pos] = '\0';

*out = vmalloc(strlen(json) + 1);
	if (*out != NULL) {
		memcpy((*out)->v, json, strlen(json) + 1);
	}
	racoon_free(json);
}

/*
 * create new isakmp Phase 1 status record to handle isakmp in Phase1
 */
struct ph1handle *
newph1(void)
{
	struct ph1handle *iph1;

	/* create new iph1 */
	iph1 = racoon_calloc(1, sizeof(*iph1));
	if (iph1 == NULL)
		return NULL;

	iph1->status = PHASE1ST_SPAWN;

#ifdef ENABLE_DPD
	iph1->dpd_support = 0;
	iph1->dpd_seq = 0;
	iph1->dpd_fails = 0;
#endif
	evt_list_init(&iph1->evt_listeners);

	return iph1;
}

/*
 * delete new isakmp Phase 1 status record to handle isakmp in Phase1
 */
void
delph1(struct ph1handle *iph1)
{
	if (iph1 == NULL)
		return;

	/* SA down shell script hook */
	script_hook(iph1, SCRIPT_PHASE1_DOWN);
	evt_list_cleanup(&iph1->evt_listeners);

#ifdef ENABLE_NATT
	if (iph1->natt_flags & NAT_KA_QUEUED)
		natt_keepalive_remove (iph1->local, iph1->remote);

	if (iph1->natt_options) {
		racoon_free(iph1->natt_options);
		iph1->natt_options = NULL;
	}
#endif

#ifdef ENABLE_HYBRID
	if (iph1->mode_cfg)
		isakmp_cfg_rmstate(iph1);
#endif

#ifdef ENABLE_DPD
	sched_cancel(&iph1->dpd_r_u);
#endif
	sched_cancel(&iph1->sce);
	sched_cancel(&iph1->scr);

	if (iph1->remote) {
		racoon_free(iph1->remote);
		iph1->remote = NULL;
	}
	if (iph1->local) {
		racoon_free(iph1->local);
		iph1->local = NULL;
	}
	if (iph1->approval) {
		delisakmpsa(iph1->approval);
		iph1->approval = NULL;
	}

	VPTRINIT(iph1->authstr);
	VPTRINIT(iph1->sendbuf);
	VPTRINIT(iph1->dhpriv);
	VPTRINIT(iph1->dhpub);
	VPTRINIT(iph1->dhpub_p);
	VPTRINIT(iph1->dhgxy);
	VPTRINIT(iph1->nonce);
	VPTRINIT(iph1->nonce_p);
	VPTRINIT(iph1->skeyid);
	VPTRINIT(iph1->skeyid_d);
	VPTRINIT(iph1->skeyid_a);
	VPTRINIT(iph1->skeyid_e);
	VPTRINIT(iph1->key);
	VPTRINIT(iph1->hash);
	VPTRINIT(iph1->sig);
	VPTRINIT(iph1->sig_p);
	VPTRINIT(iph1->cert);
	VPTRINIT(iph1->cert_p);
	VPTRINIT(iph1->crl_p);
	VPTRINIT(iph1->cr_p);
	VPTRINIT(iph1->id);
	VPTRINIT(iph1->id_p);

	if(iph1->approval != NULL)
		delisakmpsa(iph1->approval);

	if (iph1->ivm) {
		oakley_delivm(iph1->ivm);
		iph1->ivm = NULL;
	}

	VPTRINIT(iph1->sa);
	VPTRINIT(iph1->sa_ret);

#ifdef HAVE_GSSAPI
	VPTRINIT(iph1->gi_i);
	VPTRINIT(iph1->gi_r);

	gssapi_free_state(iph1);
#endif

	racoon_free(iph1);
}

/*
 * create new isakmp Phase 1 status record to handle isakmp in Phase1
 */
int
insph1(struct ph1handle *iph1)
{
	/* validity check */
	if (iph1->remote == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid isakmp SA handler. no remote address.\n");
		return -1;
	}
	LIST_INSERT_HEAD(&ph1tree, iph1, chain);

	return 0;
}

void
remph1(struct ph1handle *iph1)
{
	LIST_REMOVE(iph1, chain);
}

/*
 * flush isakmp-sa
 */
void
flushph1(void)
{
	struct ph1handle *p, *next;
	struct ph2handle *p2, *next2;

	for (p = LIST_FIRST(&ph1tree); p; p = next) {
		next = LIST_NEXT(p, chain);

		/* send delete information */
		if (p->status >= PHASE1ST_ESTABLISHED)
			isakmp_info_send_d1(p);

		/*
		 * Discard any phase2 handles still bound to this ph1
		 * before freeing it below. delph1() does not touch
		 * p->ph2tree, so without this a bound ph2handle's ->ph1
		 * pointer is left dangling once p is freed, and any later
		 * use of that ph2handle (e.g. purge_remote()'s remph2())
		 * is a use-after-free.
		 */
		for (p2 = LIST_FIRST(&p->ph2tree); p2; p2 = next2) {
			next2 = LIST_NEXT(p2, ph1bind);
			if (p2->status == PHASE2ST_ESTABLISHED)
				isakmp_info_send_d2(p2);
			delete_spd(p2, 0);
			remph2(p2);
			delph2(p2);
		}

		remph1(p);
		delph1(p);
	}
}

void
initph1tree(void)
{
	LIST_INIT(&ph1tree);
}

int
ph1_rekey_enabled(struct ph1handle *iph1)
{
	if (iph1->rmconf == NULL)
		return 0;
	if (iph1->rmconf->rekey == REKEY_FORCE)
		return 1;
#ifdef ENABLE_DPD
	if (iph1->rmconf->rekey == REKEY_ON && iph1->dpd_support &&
	    iph1->rmconf->dpd_interval)
		return 1;
#endif
	return 0;
}

/* %%% management phase 2 handler */

int
enumph2(struct ph2selector *sel, int (*enum_func)(struct ph2handle *ph2, void *arg), void *enum_arg)
{
	struct ph2handle *p, *next;
	int ret;

	/*
	 * Precompute "next" before calling enum_func() -- same
	 * use-after-free hazard fixed in enumph1() above applies here:
	 * a plain LIST_FOREACH only reads "p" to advance *after* the
	 * call returns, which is unsafe against any enum_func() that
	 * frees the current entry (delph2()). No caller does that today
	 * (pfkey.c's MIGRATE handlers only rewrite addresses in place),
	 * but this keeps enumph2() as safe against that as enumph1() now
	 * is, matching every other iterate-and-maybe-delete loop in this
	 * file.
	 */
	for (p = LIST_FIRST(&ph2tree); p; p = next) {
		next = LIST_NEXT(p, chain);

		if (sel != NULL) {
			if (sel->spid != 0 && sel->spid != p->spid)
				continue;

			if (sel->src != NULL &&
			    cmpsaddr(sel->src, p->src) != CMPSADDR_MATCH)
				continue;

			if (sel->dst != NULL &&
			    cmpsaddr(sel->dst, p->dst) != CMPSADDR_MATCH)
				continue;
		}

		if ((ret = enum_func(p, enum_arg)) != 0)
			return ret;
	}

	return 0;
}

/*
 * search ph2handle with sequence number.
 */
struct ph2handle *
getph2byseq(u_int32_t seq)
{
	struct ph2handle *p;

	LIST_FOREACH(p, &ph2tree, chain) {
		if (p->seq == seq)
			return p;
	}

	return NULL;
}

/*
 * search ph2handle with message id.
 */
struct ph2handle *
getph2bymsgid(struct ph1handle *iph1, u_int32_t msgid)
{
	struct ph2handle *p;

	LIST_FOREACH(p, &iph1->ph2tree, ph1bind) {
		if (p->msgid == msgid && p->ph1 == iph1)
			return p;
	}

	return NULL;
}

/* Note that src and dst are not the selectors of the SP
 * but the source and destination addresses used for
 * for SA negotiation (best example is tunnel mode SA
 * where src and dst are the endpoints). There is at most
 * a unique match because racoon does not support bundles
 * which makes that there is at most a single established
 * SA for a given spid. One could say that src and dst
 * are in fact useless ...
 */
struct ph2handle *
getph2byid(struct sockaddr *src, struct sockaddr *dst, u_int32_t spid)
{
	struct ph2handle *p, *next;

	for (p = LIST_FIRST(&ph2tree); p; p = next) {
		next = LIST_NEXT(p, chain);

		if (spid == p->spid &&
		    cmpsaddr(src, p->src) <= CMPSADDR_WILDPORT_MATCH &&
		    cmpsaddr(dst, p->dst) <= CMPSADDR_WILDPORT_MATCH){
			/* Sanity check to detect zombie handlers
			 * XXX Sould be done "somewhere" more interesting,
			 * because we have lots of getph2byxxxx(), but this one
			 * is called by pk_recvacquire(), so is the most important.
			 */
			if(p->status < PHASE2ST_ESTABLISHED &&
			   p->retry_counter == 0
			   && p->sce.func == NULL && p->scr.func == NULL) {
				plog(LLV_DEBUG, LOCATION, NULL,
					 "Zombie ph2 found, expiring it\n");
				isakmp_ph2expire(p);
			}else
				return p;
		}
	}

	return NULL;
}

struct ph2handle *
getph2bysaddr(struct sockaddr *src, struct sockaddr *dst)
{
	struct ph2handle *p;

	LIST_FOREACH(p, &ph2tree, chain) {
		if (cmpsaddr(src, p->src) <= CMPSADDR_WILDPORT_MATCH &&
		    cmpsaddr(dst, p->dst) <= CMPSADDR_WILDPORT_MATCH)
			return p;
	}

	return NULL;
}

/*
 * call by pk_recvexpire().
 */
struct ph2handle *
getph2bysaidx(struct sockaddr *src, struct sockaddr *dst, u_int proto_id, u_int32_t spi)
{
	struct ph2handle *iph2;
	struct saproto *pr;

	LIST_FOREACH(iph2, &ph2tree, chain) {
		if (iph2->proposal == NULL && iph2->approval == NULL)
			continue;
		if (iph2->approval != NULL) {
			for (pr = iph2->approval->head; pr != NULL;
			     pr = pr->next) {
				if (proto_id != pr->proto_id)
					break;
				if (spi == pr->spi || spi == pr->spi_p)
					return iph2;
			}
		} else if (iph2->proposal != NULL) {
			for (pr = iph2->proposal->head; pr != NULL;
			     pr = pr->next) {
				if (proto_id != pr->proto_id)
					break;
				if (spi == pr->spi)
					return iph2;
			}
		}
	}

	return NULL;
}

/*
 * create new isakmp Phase 2 status record to handle isakmp in Phase2
 */
struct ph2handle *
newph2(void)
{
	struct ph2handle *iph2 = NULL;

	/* create new iph2 */
	iph2 = racoon_calloc(1, sizeof(*iph2));
	if (iph2 == NULL)
		return NULL;

	iph2->status = PHASE1ST_SPAWN;
	evt_list_init(&iph2->evt_listeners);

	return iph2;
}

/*
 * initialize ph2handle
 * NOTE: don't initialize src/dst.
 *       SPI in the proposal is cleared.
 */
void
initph2(struct ph2handle *iph2)
{
	evt_list_cleanup(&iph2->evt_listeners);
	unbindph12(iph2);

	sched_cancel(&iph2->sce);
	sched_cancel(&iph2->scr);

	VPTRINIT(iph2->sendbuf);
	VPTRINIT(iph2->msg1);

	/* clear spi, keep variables in the proposal */
	if (iph2->proposal) {
		struct saproto *pr;
		for (pr = iph2->proposal->head; pr != NULL; pr = pr->next)
			pr->spi = 0;
	}

	/* clear approval */
	if (iph2->approval) {
		flushsaprop(iph2->approval);
		iph2->approval = NULL;
	}

	/* clear the generated policy */
	if (iph2->spidx_gen) {
		delsp_bothdir((struct policyindex *)iph2->spidx_gen);
		racoon_free(iph2->spidx_gen);
		iph2->spidx_gen = NULL;
	}

	if (iph2->pfsgrp) {
		oakley_dhgrp_free(iph2->pfsgrp);
		iph2->pfsgrp = NULL;
	}

	VPTRINIT(iph2->dhpriv);
	VPTRINIT(iph2->dhpub);
	VPTRINIT(iph2->dhpub_p);
	VPTRINIT(iph2->dhgxy);
	VPTRINIT(iph2->id);
	VPTRINIT(iph2->id_p);
	VPTRINIT(iph2->nonce);
	VPTRINIT(iph2->nonce_p);
	VPTRINIT(iph2->sa);
	VPTRINIT(iph2->sa_ret);

	if (iph2->ivm) {
		oakley_delivm(iph2->ivm);
		iph2->ivm = NULL;
	}

#ifdef ENABLE_NATT
	if (iph2->natoa_src) {
		racoon_free(iph2->natoa_src);
		iph2->natoa_src = NULL;
	}
	if (iph2->natoa_dst) {
		racoon_free(iph2->natoa_dst);
		iph2->natoa_dst = NULL;
	}
#endif
}

/*
 * delete new isakmp Phase 2 status record to handle isakmp in Phase2
 */
void
delph2(struct ph2handle *iph2)
{
	initph2(iph2);

	if (iph2->src) {
		racoon_free(iph2->src);
		iph2->src = NULL;
	}
	if (iph2->dst) {
		racoon_free(iph2->dst);
		iph2->dst = NULL;
	}
	if (iph2->sa_src) {
		racoon_free(iph2->sa_src);
		iph2->sa_src = NULL;
	}
	if (iph2->sa_dst) {
		racoon_free(iph2->sa_dst);
		iph2->sa_dst = NULL;
	}
#ifdef ENABLE_NATT
	if (iph2->natoa_src) {
		racoon_free(iph2->natoa_src);
		iph2->natoa_src = NULL;
	}
	if (iph2->natoa_dst) {
		racoon_free(iph2->natoa_dst);
		iph2->natoa_dst = NULL;
	}
#endif

	if (iph2->proposal) {
		flushsaprop(iph2->proposal);
		iph2->proposal = NULL;
	}

	racoon_free(iph2);
}

/*
 * create new isakmp Phase 2 status record to handle isakmp in Phase2
 */
int
insph2(struct ph2handle *iph2)
{
	LIST_INSERT_HEAD(&ph2tree, iph2, chain);

	return 0;
}

void
remph2(struct ph2handle *iph2)
{
	unbindph12(iph2);
	LIST_REMOVE(iph2, chain);
}

void
initph2tree(void)
{
	LIST_INIT(&ph2tree);
}

#ifdef ENABLE_UNITTEST
/*
 * ph1tree/ph2tree are static, so a regression test verifying that
 * flushph1() leaves no ph2handle orphaned (bound to a freed ph1, and
 * therefore still reachable with a dangling ->ph1 pointer -- see the
 * comment in flushph1() itself) has no other way to confirm the tree is
 * actually empty afterward.
 */
int
ph1tree_count_unittest(void)
{
	struct ph1handle *p;
	int cnt = 0;

	LIST_FOREACH(p, &ph1tree, chain)
		cnt++;
	return cnt;
}

int
ph2tree_count_unittest(void)
{
	struct ph2handle *p;
	int cnt = 0;

	LIST_FOREACH(p, &ph2tree, chain)
		cnt++;
	return cnt;
}
#endif /* ENABLE_UNITTEST */

void
flushph2(void)
{
	struct ph2handle *p, *next;

	plog(LLV_DEBUG2, LOCATION, NULL,
		 "flushing all ph2 handlers...\n");

	for (p = LIST_FIRST(&ph2tree); p; p = next) {
		next = LIST_NEXT(p, chain);

		/* send delete information */
		if (p->status == PHASE2ST_ESTABLISHED){
			plog(LLV_DEBUG2, LOCATION, NULL,
				 "got a ph2 handler to flush...\n");
			isakmp_info_send_d2(p);
		}else{
			plog(LLV_DEBUG2, LOCATION, NULL,
				 "skipping ph2 handler (state %d)\n", p->status);
		}

		delete_spd(p, 0);
		remph2(p);
		delph2(p);
	}
}

/*
 * Delete all Phase 2 handlers for this src/dst/proto.  This
 * is used during INITIAL-CONTACT processing (so no need to
 * send a message to the peer).
 */
void
deleteallph2(struct sockaddr *src, struct sockaddr *dst, u_int proto_id)
{
	struct ph2handle *iph2, *next;
	struct saproto *pr;

	for (iph2 = LIST_FIRST(&ph2tree); iph2 != NULL; iph2 = next) {
		next = LIST_NEXT(iph2, chain);
		if (iph2->proposal == NULL && iph2->approval == NULL)
			continue;
		if (iph2->approval != NULL) {
			for (pr = iph2->approval->head; pr != NULL;
			     pr = pr->next) {
				if (proto_id == pr->proto_id)
					goto zap_it;
			}
		} else if (iph2->proposal != NULL) {
			for (pr = iph2->proposal->head; pr != NULL;
			     pr = pr->next) {
				if (proto_id == pr->proto_id)
					goto zap_it;
			}
		}
		continue;
 zap_it:
		remph2(iph2);
		delph2(iph2);
	}
}

/* %%% */
void
bindph12(struct ph1handle *iph1, struct ph2handle *iph2)
{
	unbindph12(iph2);

	iph2->ph1 = iph1;
	iph1->ph2cnt++;
	LIST_INSERT_HEAD(&iph1->ph2tree, iph2, ph1bind);
}

void
unbindph12(struct ph2handle *iph2)
{
	if (iph2->ph1 != NULL) {
		LIST_REMOVE(iph2, ph1bind);
		iph2->ph1->ph2cnt--;
		iph2->ph1 = NULL;
	}
}

/* %%% management contacted list */
/*
 * search contacted list.
 */
struct contacted *
getcontacted(struct sockaddr *remote)
{
	struct contacted *p;

	LIST_FOREACH(p, &ctdtree, chain) {
		if (cmpsaddr(remote, p->remote) <= CMPSADDR_WILDPORT_MATCH)
			return p;
	}

	return NULL;
}

/*
 * create new isakmp Phase 2 status record to handle isakmp in Phase2
 */
int
inscontacted(struct sockaddr *remote)
{
	struct contacted *new;

	/* create new iph2 */
	new = racoon_calloc(1, sizeof(*new));
	if (new == NULL)
		return -1;

	new->remote = dupsaddr(remote);
	if (new->remote == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate buffer.\n");
		racoon_free(new);
		return -1;
	}

	LIST_INSERT_HEAD(&ctdtree, new, chain);

	return 0;
}

void
remcontacted(struct sockaddr *remote)
{
	struct contacted *p, *next;

	for (p = LIST_FIRST(&ctdtree); p; p = next) {
		next = LIST_NEXT(p, chain);

		if (cmpsaddr(remote, p->remote) <= CMPSADDR_WILDPORT_MATCH) {
			LIST_REMOVE(p, chain);
			racoon_free(p->remote);
			racoon_free(p);
			break;
		}
	}	
}

void
initctdtree(void)
{
	LIST_INIT(&ctdtree);
}

/*
 * check the response has been sent to the peer.  when not, simply reply
 * the buffered packet to the peer.
 * OUT:
 *	 0:	the packet is received at the first time.
 *	 1:	the packet was processed before.
 *	 2:	the packet was processed before, but the address mismatches.
 *	-1:	error happened.
 */
int
check_recvdpkt(struct sockaddr *remote, struct sockaddr *local, vchar_t *rbuf)
{
	vchar_t *hash;
	struct recvdpkt *r;
	struct timeval now, diff;
	int len, s;

	hash = eay_md5_one(rbuf);
	if (!hash) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate buffer.\n");
		return -1;
	}

	LIST_FOREACH(r, &rcptree, chain) {
		if (memcmp(hash->v, r->hash->v, r->hash->l) == 0)
			break;
	}
	vfree(hash);

	/* this is the first time to receive the packet */
	if (r == NULL)
		return 0;

	/*
	 * the packet was processed before, but the remote address mismatches.
	 */
	if (cmpsaddr(remote, r->remote) != CMPSADDR_MATCH)
		return 2;

	/*
	 * it should not check the local address because the packet
	 * may arrive at other interface.
	 */

	/* check the previous time to send */
	sched_get_monotonic_time(&now);
	timersub(&now, &r->time_send, &diff);
	if (diff.tv_sec == 0) {
		plog(LLV_WARNING, LOCATION, NULL,
			"the packet retransmitted in a short time from %s\n",
			saddr2str(remote));
		/*XXX should it be error ? */
	}

	/* select the socket to be sent */
	s = myaddr_getfd(r->local);
	if (s == -1)
		return -1;

	/* resend the packet if needed */
	len = sendfromto(s, r->sendbuf->v, r->sendbuf->l,
			r->local, r->remote, lcconf->count_persend);
	if (len == -1) {
		plog(LLV_ERROR, LOCATION, NULL, "sendfromto failed\n");
		return -1;
	}

	/* check the retry counter */
	r->retry_counter--;
	if (r->retry_counter <= 0) {
		rem_recvdpkt(r);
		del_recvdpkt(r);
		plog(LLV_DEBUG, LOCATION, NULL,
			"deleted the retransmission packet to %s.\n",
			saddr2str(remote));
	} else
		r->time_send = now;

	return 1;
}

/*
 * adding a hash of received packet into the received list.
 */
int
add_recvdpkt(struct sockaddr *remote, struct sockaddr *local, vchar_t *sbuf, vchar_t *rbuf)
{
	struct recvdpkt *new = NULL;

	if (lcconf->retry_counter == 0) {
		/* no need to add it */
		return 0;
	}

	new = racoon_calloc(1, sizeof(*new));
	if (!new) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate buffer.\n");
		return -1;
	}

	new->hash = eay_md5_one(rbuf);
	if (!new->hash) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate buffer.\n");
		del_recvdpkt(new);
		return -1;
	}
	new->remote = dupsaddr(remote);
	if (new->remote == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate buffer.\n");
		del_recvdpkt(new);
		return -1;
	}
	new->local = dupsaddr(local);
	if (new->local == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate buffer.\n");
		del_recvdpkt(new);
		return -1;
	}
	new->sendbuf = vdup(sbuf);
	if (new->sendbuf == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate buffer.\n");
		del_recvdpkt(new);
		return -1;
	}

	new->retry_counter = lcconf->retry_counter;
	sched_get_monotonic_time(&new->time_send);

	LIST_INSERT_HEAD(&rcptree, new, chain);

	return 0;
}

void
del_recvdpkt(struct recvdpkt *r)
{
	if (r->remote)
		racoon_free(r->remote);
	if (r->local)
		racoon_free(r->local);
	if (r->hash)
		vfree(r->hash);
	if (r->sendbuf)
		vfree(r->sendbuf);
	racoon_free(r);
}

void
rem_recvdpkt(struct recvdpkt *r)
{
	LIST_REMOVE(r, chain);
}

static void
sweep_recvdpkt(struct sched *dummy)
{
	struct recvdpkt *r, *next;
	struct timeval now, diff, sweep;

	sched_get_monotonic_time(&now);

	/* calculate sweep time; delete entries older than this */
	diff.tv_sec = lcconf->retry_counter * lcconf->retry_interval;
	diff.tv_usec = 0;
	timersub(&now, &diff, &sweep);

	for (r = LIST_FIRST(&rcptree); r; r = next) {
		next = LIST_NEXT(r, chain);

		if (timercmp(&r->time_send, &sweep, <)) {
			rem_recvdpkt(r);
			del_recvdpkt(r);
		}
	}

	sched_schedule(&sc_sweep, diff.tv_sec, sweep_recvdpkt);
}

void
init_recvdpkt(void)
{
	time_t lt = lcconf->retry_counter * lcconf->retry_interval;

	LIST_INIT(&rcptree);

	sched_schedule(&sc_sweep, lt, sweep_recvdpkt);
}

#ifdef ENABLE_HYBRID
/*
 * Retruns 0 if the address was obtained by ISAKMP mode config, 1 otherwise
 * This should be in isakmp_cfg.c but ph1tree being private, it must be there
 */
int
exclude_cfg_addr(const struct sockaddr *addr)
{
	struct ph1handle *p;
	struct sockaddr_in *sin;

	LIST_FOREACH(p, &ph1tree, chain) {
		if ((p->mode_cfg != NULL) &&
		    (p->mode_cfg->flags & ISAKMP_CFG_GOT_ADDR4) &&
		    (addr->sa_family == AF_INET)) {
			sin = (struct sockaddr_in *)addr;
			if (sin->sin_addr.s_addr == p->mode_cfg->addr4.s_addr)
				return 0;
		}
	}

	return 1;
}
#endif



/*
 * Reload conf code
 */
static int revalidate_ph2(struct ph2handle *iph2){
	struct sainfoalg *alg;
	int found, check_level;
	struct sainfo *sainfo;
	struct saprop *approval;
	struct ph1handle *iph1;

	/*
	 * Get the new sainfo using values of the old one
	 */
	if (iph2->sainfo != NULL) {
		iph2->sainfo = getsainfo(iph2->sainfo->idsrc,
					  iph2->sainfo->iddst, iph2->sainfo->id_i,
					  NULL, iph2->sainfo->remoteid);
	}
	approval = iph2->approval;
	sainfo = iph2->sainfo;

	if (sainfo == NULL) {
		/*
		 * Sainfo has been removed
		 */
		plog(LLV_DEBUG, LOCATION, NULL,
			 "Reload: No sainfo for ph2\n");
		return 0;
	}

	if (approval == NULL) {
		/*
		 * XXX why do we have a NULL approval sometimes ???
		 */
		plog(LLV_DEBUG, LOCATION, NULL,
			 "No approval found !\n");
		return 0;
	}

	/*
	 * Don't care about proposals, should we do something ?
	 * We have to keep iph2->proposal valid at least for initiator,
	 * for pk_sendgetspi()
	 */

	plog(LLV_DEBUG, LOCATION, NULL, "active single bundle:\n");
	printsaprop0(LLV_DEBUG, approval);

	/*
	 * Validate approval against sainfo
	 * Note: we must have an updated ph1->rmconf before doing that,
	 * we'll set check_level to EXACT if we don't have a ph1
	 * XXX try tu find the new remote section to get the new check level ?
	 * XXX lifebyte
	 */
	if (iph2->ph1 != NULL)
		iph1=iph2->ph1;
	else
		iph1=getph1byaddr(iph2->src, iph2->dst, 0);

	if(iph1 != NULL && iph1->rmconf != NULL) {
		check_level = iph1->rmconf->pcheck_level;
	} else {
		if(iph1 != NULL)
			plog(LLV_DEBUG, LOCATION, NULL, "No phase1 rmconf found !\n");
		else
			plog(LLV_DEBUG, LOCATION, NULL, "No phase1 found !\n");
		check_level = PROP_CHECK_EXACT;
	}

	switch (check_level) {
	case PROP_CHECK_OBEY:
		plog(LLV_DEBUG, LOCATION, NULL,
			 "Reload: OBEY for ph2, ok\n");
		return 1;
		break;

	case PROP_CHECK_STRICT:
		/* FALLTHROUGH */
	case PROP_CHECK_CLAIM:
		if (sainfo->lifetime < approval->lifetime) {
			plog(LLV_DEBUG, LOCATION, NULL,
				 "Reload: lifetime mismatch\n");
			return 0;
		}

#if 0
		/* Lifebyte is deprecated, just ignore it
		 */
		if (sainfo->lifebyte < approval->lifebyte) {
			plog(LLV_DEBUG, LOCATION, NULL,
				 "Reload: lifebyte mismatch\n");
			return 0;
		}
#endif

		if (sainfo->pfs_group &&
		   sainfo->pfs_group != approval->pfs_group) {
			plog(LLV_DEBUG, LOCATION, NULL,
				 "Reload: PFS group mismatch\n");
			return 0;
		}
		break;

	case PROP_CHECK_EXACT:
		if (sainfo->lifetime != approval->lifetime ||
#if 0
			/* Lifebyte is deprecated, just ignore it
			 */
		    sainfo->lifebyte != approval->lifebyte ||
#endif
		    sainfo->pfs_group != iph2->approval->pfs_group) {
			plog(LLV_DEBUG, LOCATION, NULL,
			    "Reload: lifetime | pfs mismatch\n");
			return 0;
		}
		break;

	default:
		plog(LLV_DEBUG, LOCATION, NULL,
			 "Reload: Shouldn't be here !\n");
		return 0;
		break;
	}

	for (alg = sainfo->algs[algclass_ipsec_auth]; alg; alg = alg->next) {
		if (alg->alg == approval->head->head->authtype)
			break;
	}
	if (alg == NULL) {
		plog(LLV_DEBUG, LOCATION, NULL,
			 "Reload: alg == NULL (auth)\n");
		return 0;
	}

	found = 0;
	for (alg = sainfo->algs[algclass_ipsec_enc];
	    (found == 0 && alg != NULL); alg = alg->next) {
		plog(LLV_DEBUG, LOCATION, NULL,
			 "Reload: next ph2 enc alg...\n");

		if (alg->alg != approval->head->head->trns_id){
			plog(LLV_DEBUG, LOCATION, NULL,
				 "Reload: encmode mismatch (%d / %d)\n",
				 alg->alg, approval->head->head->trns_id);
			continue;
		}

		switch (check_level){
		/* PROP_CHECK_STRICT cannot happen here */
		case PROP_CHECK_EXACT:
			if (alg->encklen != approval->head->head->encklen) {
				plog(LLV_DEBUG, LOCATION, NULL,
					 "Reload: enclen mismatch\n");
				continue;
			}
			break;

		case PROP_CHECK_CLAIM:
			/* FALLTHROUGH */
		case PROP_CHECK_STRICT:
			if (alg->encklen > approval->head->head->encklen) {
				plog(LLV_DEBUG, LOCATION, NULL,
					 "Reload: enclen mismatch\n");
				continue;
			}
			break;

		default:
			plog(LLV_ERROR, LOCATION, NULL,
			    "unexpected check_level\n");
			continue;
			break;
		}
		found = 1;
	}

	if (!found){
		plog(LLV_DEBUG, LOCATION, NULL,
			 "Reload: No valid enc\n");
		return 0;
	}

	/*
	 * XXX comp
	 */
	plog(LLV_DEBUG, LOCATION, NULL,
		 "Reload: ph2 check ok\n");

	return 1;
}


static void
remove_ph2(struct ph2handle *iph2)
{
	u_int32_t spis[2];

	if(iph2 == NULL)
		return;

	plog(LLV_DEBUG, LOCATION, NULL,
		 "Deleting a Ph2...\n");

	if (iph2->status == PHASE2ST_ESTABLISHED)
		isakmp_info_send_d2(iph2);

	if(iph2->approval != NULL && iph2->approval->head != NULL){
		spis[0]=iph2->approval->head->spi;
		spis[1]=iph2->approval->head->spi_p;

		/* purge_ipsec_spi() will do all the work:
		 * - delete SPIs in kernel
		 * - delete generated SPD
		 * - unbind / rem / del ph2
		 */
		purge_ipsec_spi(iph2->dst, iph2->approval->head->proto_id,
						spis, 2);
	}else{
		remph2(iph2);
		delph2(iph2);
	}
}

static void remove_ph1(struct ph1handle *iph1){
	struct ph2handle *iph2, *iph2_next;

	if(iph1 == NULL)
		return;

	plog(LLV_DEBUG, LOCATION, NULL,
		 "Removing PH1...\n");

	if (iph1->status == PHASE1ST_ESTABLISHED ||
	    iph1->status == PHASE1ST_DYING) {
		for (iph2 = LIST_FIRST(&iph1->ph2tree); iph2; iph2 = iph2_next) {
			iph2_next = LIST_NEXT(iph2, ph1bind);
			remove_ph2(iph2);
		}
		isakmp_info_send_d1(iph1);
	}
	iph1->status = PHASE1ST_EXPIRED;
	/* directly call isakmp_ph1delete to avoid as possible a race
	 * condition where we'll try to access iph1->rmconf after it has
	 * freed
	 */
	isakmp_ph1delete(iph1);
}


static int revalidate_ph1tree_rmconf(void)
{
	struct ph1handle *p, *next;
	struct remoteconf *rmconf;

	for (p = LIST_FIRST(&ph1tree); p; p = next) {
		next = LIST_NEXT(p, chain);

		if (p->status >= PHASE1ST_EXPIRED)
			continue;
		if (p->rmconf == NULL)
			continue;

		rmconf = getrmconf_by_ph1(p);
		if (rmconf == NULL || rmconf == RMCONF_ERR_MULTIPLE)
			remove_ph1(p);
		else
			p->rmconf = rmconf;
	}

	return 1;
}

static int revalidate_ph2tree(void){
	struct ph2handle *p, *next;

	for (p = LIST_FIRST(&ph2tree); p; p = next) {
		next = LIST_NEXT(p, chain);

		if (p->status == PHASE2ST_EXPIRED)
			continue;

		if(!revalidate_ph2(p)){
			plog(LLV_DEBUG, LOCATION, NULL,
				 "PH2 not validated, removing it\n");
			remove_ph2(p);
		}
	}

	return 1;
}

int
revalidate_ph12(void)
{

	revalidate_ph1tree_rmconf();
	revalidate_ph2tree();

	return 1;
}

#ifdef ENABLE_HYBRID
struct ph1handle *
getph1bylogin(char *login)
{
	struct ph1handle *p;

	LIST_FOREACH(p, &ph1tree, chain) {
		if (p->mode_cfg == NULL)
			continue;
		if (strncmp(p->mode_cfg->login, login, LOGINLEN) == 0)
			return p;
	}

	return NULL;
}

int
purgeph1bylogin(char *login)
{
	struct ph1handle *p, *next;
	int found = 0;

	for (p = LIST_FIRST(&ph1tree); p; p = next) {
		next = LIST_NEXT(p, chain);

		if (p->mode_cfg == NULL)
			continue;
		if (strncmp(p->mode_cfg->login, login, LOGINLEN) == 0) {
			if (p->status >= PHASE1ST_EXPIRED)
				continue;

			if (p->status >= PHASE1ST_ESTABLISHED)
				isakmp_info_send_d1(p);
			purge_remote(p);
			found++;
		}
	}

	return found;
}
#endif
