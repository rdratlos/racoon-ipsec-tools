/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools -- https://github.com/rdratlos/racoon-ipsec-tools
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "schedule.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "handler.h"
#include "remoteconf.h"
#include "proposal.h"
#include "ipsec_doi.h"
#include "oakley.h"
#include "sockmisc.h"
#include "policy.h"
#include "strnames.h"
#include "status.h"

#ifdef ENABLE_HYBRID
#include "isakmp_cfg.h"
#include "isakmp_xauth.h"
#include "isakmp_unity.h"
#endif

/* ------------------------------------------------------------------ */
/* Growable output buffer, shared by both renderers.                   */
/* ------------------------------------------------------------------ */

struct outbuf {
	char *buf;
	size_t len;
	size_t pos;
};

static void
ob_init(struct outbuf *ob)
{
	ob->len = 4096;
	ob->pos = 0;
	ob->buf = racoon_malloc(ob->len);
	if (ob->buf != NULL)
		ob->buf[0] = '\0';
}

static void
ob_free(struct outbuf *ob)
{
	if (ob->buf != NULL)
		racoon_free(ob->buf);
	ob->buf = NULL;
	ob->len = 0;
	ob->pos = 0;
}

/* Ensures at least "need" more bytes (beyond the current position, not
 * counting the trailing NUL) are available, growing geometrically. */
static void
ob_reserve(struct outbuf *ob, size_t need)
{
	size_t want;
	char *n;

	if (ob->buf == NULL)
		return;

	if (ob->pos + need + 1 <= ob->len)
		return;

	want = ob->len;
	while (want < ob->pos + need + 1)
		want *= 2;

	n = racoon_realloc(ob->buf, want);
	if (n == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, "status: out of memory\n");
		racoon_free(ob->buf);
		ob->buf = NULL;
		return;
	}
	ob->buf = n;
	ob->len = want;
}

/* Appends raw bytes verbatim -- used for JSON punctuation/numbers/bools
 * and for the whole of the text renderer, never for untrusted strings. */
static void
ob_puts(struct outbuf *ob, const char *s)
{
	size_t n;

	if (ob->buf == NULL || s == NULL)
		return;

	n = strlen(s);
	ob_reserve(ob, n);
	if (ob->buf == NULL)
		return;
	memcpy(ob->buf + ob->pos, s, n);
	ob->pos += n;
	ob->buf[ob->pos] = '\0';
}

static void
ob_printf(struct outbuf *ob, const char *fmt, ...)
{
	va_list ap;
	int needed;

	if (ob->buf == NULL)
		return;

	va_start(ap, fmt);
	needed = vsnprintf(ob->buf + ob->pos, ob->len - ob->pos, fmt, ap);
	va_end(ap);

	if (needed < 0)
		return;

	if ((size_t)needed >= ob->len - ob->pos) {
		ob_reserve(ob, (size_t)needed);
		if (ob->buf == NULL)
			return;
		va_start(ap, fmt);
		vsnprintf(ob->buf + ob->pos, ob->len - ob->pos, fmt, ap);
		va_end(ap);
	}
	ob->pos += needed;
}

/* Appends s JSON-escaped, in double quotes. NULL renders as the JSON
 * literal null (unquoted), never the string "(null)". */
static void
json_string(struct outbuf *ob, const char *s)
{
	const unsigned char *p;

	if (s == NULL) {
		ob_puts(ob, "null");
		return;
	}

	ob_puts(ob, "\"");
	for (p = (const unsigned char *)s; *p != '\0'; p++) {
		switch (*p) {
		case '"':  ob_puts(ob, "\\\""); break;
		case '\\': ob_puts(ob, "\\\\"); break;
		case '\b': ob_puts(ob, "\\b"); break;
		case '\f': ob_puts(ob, "\\f"); break;
		case '\n': ob_puts(ob, "\\n"); break;
		case '\r': ob_puts(ob, "\\r"); break;
		case '\t': ob_puts(ob, "\\t"); break;
		default:
			if (*p < 0x20) {
				ob_printf(ob, "\\u%04x", *p);
			} else {
				/* ob_reserve() sets ob->buf to NULL on
				 * allocation failure, same as every other
				 * ob_*() helper -- guard it here too instead
				 * of writing through it unconditionally. */
				ob_reserve(ob, 1);
				if (ob->buf == NULL)
					return;
				ob->buf[ob->pos++] = (char)*p;
				ob->buf[ob->pos] = '\0';
			}
			break;
		}
	}
	ob_puts(ob, "\"");
}

/* Writes the ",\"key\":" (or "\"key\":" for the first field in an
 * object) separator -- *first is cleared as a side effect. */
static void
json_key(struct outbuf *ob, int *first, const char *key)
{
	if (!*first)
		ob_puts(ob, ",");
	*first = 0;
	json_string(ob, key);
	ob_puts(ob, ":");
}

/* ------------------------------------------------------------------ */
/* Small owned-string helpers.                                         */
/*                                                                       */
/* Every strnames.c s_*() lookup and ipsecdoi_id2str()/saddr2str() falls */
/* back to (or always uses) a function-local `static char buf[...]`     */
/* on an unrecognized/formatted value -- not reentrant, and the same    */
/* buffer is reused by the next such call. Every result that outlives   */
/* the immediate call (i.e. gets stored in a struct status_ph1/ph2      */
/* field rather than consumed on the spot) MUST be copied out with      */
/* dupstr() before any other lookup function runs, or a later field can */
/* silently overwrite an earlier one's text.                            */
/* ------------------------------------------------------------------ */

static char *
dupstr(const char *s)
{
	if (s == NULL)
		return NULL;
	return racoon_strdup(s);
}

/* SPI shown as only its top 16 bits, rest masked -- status output is a
 * diagnostic aid, not a reason to hand a peer's full SPI to anyone who
 * can read the admin socket. */
static char *
mask_spi(u_int32_t spi_netorder)
{
	char *result;
	unsigned int top;

	top = (unsigned int)(ntohl(spi_netorder) >> 16);
	if (asprintf(&result, "0x%04x****", top) < 0)
		return racoon_strdup("?");
	return result;
}

static char *
format_timestamp(time_t t)
{
	struct tm *tm;
	char buf[32];

	tm = gmtime(&t);
	if (tm == NULL)
		return racoon_strdup("1970-01-01T00:00:00Z");
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
	return racoon_strdup(buf);
}

static char *
addr4_to_str(struct in_addr addr)
{
	char buf[INET_ADDRSTRLEN];

	if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == NULL)
		return racoon_strdup("?");
	return racoon_strdup(buf);
}

/* sockaddr -> "addr/prefixlen". prefixlen < 0 means "not known", in
 * which case a host mask (/32 or /128) is used -- an honest fallback,
 * not a claim about the real SPD selector width. */
static char *
sockaddr_to_cidr(struct sockaddr *sa, int prefixlen)
{
	char addr[NI_MAXHOST];
	char *result;

	if (sa == NULL)
		return racoon_strdup("0.0.0.0/0");

	if (getnameinfo(sa, sysdep_sa_len(sa), addr, sizeof(addr), NULL, 0,
	    NI_NUMERICHOST) != 0)
		return racoon_strdup("?");

	if (prefixlen < 0)
		prefixlen = (sa->sa_family == AF_INET6) ? 128 : 32;

	if (asprintf(&result, "%s/%d", addr, prefixlen) < 0)
		return racoon_strdup("?");
	return result;
}

/* ------------------------------------------------------------------ */
/* Snapshot structures -- populated once from ph1tree/ph2tree, then     */
/* rendered by exactly one of render_text()/render_json(). Every string  */
/* field is either NULL, a compile-time literal owned by this           */
/* translation unit, or a heap pointer this snapshot owns and free_*()   */
/* releases -- never a raw pointer returned by a static-buffer lookup    */
/* function.                                                             */
/* ------------------------------------------------------------------ */

struct status_xauth {
	int present;
	const char *state;	/* literal */
	const char *auth_type;	/* literal */
	char *username;		/* heap; never authdata.generic.pwd or udn */
};

struct status_mode_cfg {
	int present;
	char *addr4;
	char **dns4;
	int dns4_count;
	char **split_include;
	int split_include_count;
};

struct status_dpd {
	int present;
	int supported;
	int fails;
};

struct status_natt {
	int present;
	int enabled;
};

struct status_remote_config {
	int present;
	int anonymous;
	int passive;
	const char *generate_policy;	/* literal: "none"/"require"/"unique" */
};

struct status_ph1 {
	char *index;
	const char *state;		/* literal */
	char *remote_id;
	char *local_id;
	char *version;
	const char *exchange_mode;	/* literal, or dup'd fallback (owned) */
	int exchange_mode_owned;
	int has_proposal;
	char *enc_alg;
	char *hash_alg;
	char *auth_method;
	char *dh_group;
	unsigned long lifetime_time;
	struct status_xauth xauth;
	struct status_mode_cfg mode_cfg;
	struct status_dpd dpd;
	struct status_natt natt;
	struct status_remote_config remote_config;
};

struct status_ph2 {
	char *index;
	char *phase1_index;	/* parent phase1's cookie-pair string (D6,
				 * issue #140); NULL if iph2->ph1 is
				 * momentarily unbound (see collect_ph2()) */
	const char *state;	/* literal */
	char *spi_in;
	char *spi_out;
	const char *protocol;	/* literal */
	char *encmode;
	char *sel_src;
	char *sel_dst;
	int sel_proto;		/* -1 = any */
	int sel_sport;		/* -1 = any */
	int sel_dport;		/* -1 = any */
	int has_proposal;
	char *enc_alg;
	char *auth_alg;
	char *comp_alg;		/* NULL = none negotiated */
	int pfs_group;		/* 0 = PFS not negotiated */
	int effective_group;	/* D6 (issue #140): pfs_group when PFS was
				 * negotiated, else the parent phase1's
				 * dh_group -- per RFC 2409 SS5.5, that's the
				 * DH secret actually backing this tunnel's
				 * key entropy when there's no PFS exchange
				 * of its own. 0 = indeterminate (only
				 * possible when phase1_index is also NULL) */
	unsigned long lifetime_time;
	unsigned long lifetime_bytes;
	int reqid_in;
	int reqid_out;
	int ok;
};

struct status_snapshot {
	char *timestamp;
	struct status_ph1 *ph1;
	int ph1_count;
	struct status_ph2 *ph2;
	int ph2_count;
	int verbose;
};

static void
free_mode_cfg(struct status_mode_cfg *mc)
{
	int i;

	racoon_free(mc->addr4);
	for (i = 0; i < mc->dns4_count; i++)
		racoon_free(mc->dns4[i]);
	racoon_free(mc->dns4);
	for (i = 0; i < mc->split_include_count; i++)
		racoon_free(mc->split_include[i]);
	racoon_free(mc->split_include);
}

static void
free_snapshot(struct status_snapshot *snap)
{
	int i;

	racoon_free(snap->timestamp);

	for (i = 0; i < snap->ph1_count; i++) {
		struct status_ph1 *p = &snap->ph1[i];

		racoon_free(p->index);
		racoon_free(p->remote_id);
		racoon_free(p->local_id);
		racoon_free(p->version);
		if (p->exchange_mode_owned)
			racoon_free((void *)p->exchange_mode);
		racoon_free(p->enc_alg);
		racoon_free(p->hash_alg);
		racoon_free(p->auth_method);
		racoon_free(p->dh_group);
		racoon_free(p->xauth.username);
		free_mode_cfg(&p->mode_cfg);
	}
	racoon_free(snap->ph1);

	for (i = 0; i < snap->ph2_count; i++) {
		struct status_ph2 *p = &snap->ph2[i];

		racoon_free(p->index);
		racoon_free(p->phase1_index);
		racoon_free(p->spi_in);
		racoon_free(p->spi_out);
		racoon_free(p->encmode);
		racoon_free(p->sel_src);
		racoon_free(p->sel_dst);
		racoon_free(p->enc_alg);
		racoon_free(p->auth_alg);
		racoon_free(p->comp_alg);
	}
	racoon_free(snap->ph2);
}

/* ------------------------------------------------------------------ */
/* Extraction: ph1handle/ph2handle -> snapshot.                         */
/* ------------------------------------------------------------------ */

static const char *
ph1_state_name(int state)
{
	switch (state) {
	case PHASE1ST_SPAWN:		return "spawn";
	case PHASE1ST_START:		return "start";
	case PHASE1ST_MSG1RECEIVED:	return "msg1received";
	case PHASE1ST_MSG1SENT:	return "msg1sent";
	case PHASE1ST_MSG2RECEIVED:	return "msg2received";
	case PHASE1ST_MSG2SENT:	return "msg2sent";
	case PHASE1ST_MSG3RECEIVED:	return "msg3received";
	case PHASE1ST_MSG3SENT:	return "msg3sent";
	case PHASE1ST_MSG4RECEIVED:	return "msg4received";
	case PHASE1ST_ESTABLISHED:	return "established";
	case PHASE1ST_DYING:		return "dying";
	case PHASE1ST_EXPIRED:		return "expired";
	default:			return "unknown";
	}
}

static const char *
ph2_state_name(int state)
{
	switch (state) {
	case PHASE2ST_SPAWN:		return "spawn";
	case PHASE2ST_START:		return "start";
	case PHASE2ST_STATUS2:		return "status2";
	case PHASE2ST_GETSPISENT:	return "getspisent";
	case PHASE2ST_GETSPIDONE:	return "getspidone";
	case PHASE2ST_MSG1SENT:	return "msg1sent";
	case PHASE2ST_STATUS6:		return "status6";
	case PHASE2ST_COMMIT:		return "commit";
	case PHASE2ST_ADDSA:		return "addsa";
	case PHASE2ST_ESTABLISHED:	return "established";
	case PHASE2ST_EXPIRED:		return "expired";
	default:			return "unknown";
	}
}

/* Short, uppercase tokens for the frozen schema -- s_isakmp_etype()
 * (strnames.c) returns human prose ("Identity Protection") for the
 * same values, which is the right choice for -dddd logs but not for a
 * machine-facing "exchange_mode" field. */
static const char *
exchange_mode_name(int etype, int *owned)
{
	*owned = 0;
	switch (etype) {
	case ISAKMP_ETYPE_IDENT:	return "MAIN";
	case ISAKMP_ETYPE_AGG:		return "AGGRESSIVE";
	case ISAKMP_ETYPE_BASE:	return "BASE";
	default:
		*owned = 1;
		return dupstr(s_isakmp_etype(etype));
	}
}

static const char *
generate_policy_name(int gen_policy)
{
	switch (gen_policy) {
	case GENERATE_POLICY_NONE:	return "none";
	case GENERATE_POLICY_REQUIRE:	return "require";
	case GENERATE_POLICY_UNIQUE:	return "unique";
	default:			return "none";
	}
}

static char *
cookie_pair_hex(const isakmp_index *idx)
{
	char *result;

	if (asprintf(&result,
	    "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	    idx->i_ck[0], idx->i_ck[1], idx->i_ck[2], idx->i_ck[3],
	    idx->i_ck[4], idx->i_ck[5], idx->i_ck[6], idx->i_ck[7],
	    idx->r_ck[0], idx->r_ck[1], idx->r_ck[2], idx->r_ck[3],
	    idx->r_ck[4], idx->r_ck[5], idx->r_ck[6], idx->r_ck[7]) < 0)
		return racoon_strdup("?");
	return result;
}

#ifdef ENABLE_HYBRID
/* Tokenizes splitnet_list_2str()'s space-separated CIDR list (heap,
 * already owned by us) into an array of individually-owned strings. */
static void
split_cidr_list(char *joined, char ***out_arr, int *out_count)
{
	char *save = NULL;
	char *tok;
	char **arr = NULL;
	int count = 0;

	if (joined == NULL) {
		*out_arr = NULL;
		*out_count = 0;
		return;
	}

	for (tok = strtok_r(joined, " ", &save); tok != NULL;
	    tok = strtok_r(NULL, " ", &save)) {
		char **n = racoon_realloc(arr, sizeof(char *) * (count + 1));
		if (n == NULL)
			break;
		arr = n;
		arr[count++] = racoon_strdup(tok);
	}

	*out_arr = arr;
	*out_count = count;
}

static void
collect_xauth(struct ph1handle *iph1, struct status_xauth *x)
{
	struct xauth_state *xst;

	memset(x, 0, sizeof(*x));

	if (iph1->mode_cfg == NULL)
		return;

	xst = &iph1->mode_cfg->xauth;
	if (xst->status == XAUTHST_NOTYET)
		return;

	x->present = 1;
	x->state = (xst->status == XAUTHST_OK) ? "ok" : "reqsent";

	switch (xst->authtype) {
	case XAUTH_TYPE_GENERIC:	x->auth_type = "generic"; break;
	case XAUTH_TYPE_CHAP:		x->auth_type = "chap"; break;
	case XAUTH_TYPE_OTP:		x->auth_type = "otp"; break;
	case XAUTH_TYPE_SKEY:		x->auth_type = "skey"; break;
	default:			x->auth_type = "unknown"; break;
	}

	/* Deliberately only the username. xst->authdata.generic.pwd (the
	 * cleartext XAuth password) and xst->udn (#ifdef HAVE_LIBLDAP, the
	 * LDAP bind DN) are never read here -- see doc/dev/
	 * racoonctl-status-analysis.md Finding H-3 / issue #139's "no
	 * secrets" acceptance criterion. */
	x->username = dupstr(xst->authdata.generic.usr);
}

static void
collect_mode_cfg(struct ph1handle *iph1, struct status_mode_cfg *mc)
{
	struct isakmp_cfg_state *cfg = iph1->mode_cfg;
	int i;
	char *joined;

	memset(mc, 0, sizeof(*mc));

	if (cfg == NULL || !(cfg->flags & ISAKMP_CFG_GOT_ADDR4))
		return;

	mc->present = 1;
	mc->addr4 = addr4_to_str(cfg->addr4);

	if (cfg->flags & ISAKMP_CFG_GOT_DNS4) {
		mc->dns4 = racoon_malloc(sizeof(char *) * cfg->dns4_index);
		if (mc->dns4 != NULL) {
			for (i = 0; i < cfg->dns4_index; i++)
				mc->dns4[i] = addr4_to_str(cfg->dns4[i]);
			mc->dns4_count = cfg->dns4_index;
		}
	}

	if (cfg->flags & ISAKMP_CFG_GOT_SPLIT_INCLUDE) {
		joined = splitnet_list_2str(cfg->split_include, CIDR);
		split_cidr_list(joined, &mc->split_include,
		    &mc->split_include_count);
		racoon_free(joined);
	}
}

#endif /* ENABLE_HYBRID */

/* Deliberately outside the ENABLE_HYBRID block above, guarded only by its
 * own ENABLE_DPD (issue #143 F3): DPD is RFC 3706 dead peer detection with
 * no dependency on hybrid auth, and --enable-hybrid/--enable-dpd are
 * separate configure options (configure.ac). Defining *and* calling this
 * inside the hybrid block meant a perfectly valid --disable-hybrid
 * --enable-dpd build -- a site-to-site gateway with no XAuth/mode-config
 * that still wants DPD -- ran DPD fine but never emitted the
 * schema-documented "dpd" block in either output format. collect_natt()
 * below is the shape this follows. */
static void
collect_dpd(struct ph1handle *iph1, struct status_dpd *dpd)
{
	memset(dpd, 0, sizeof(*dpd));
#ifdef ENABLE_DPD
	if (iph1->rmconf == NULL || !iph1->rmconf->dpd)
		return;
	dpd->present = 1;
	dpd->supported = iph1->dpd_support ? 1 : 0;
	dpd->fails = iph1->dpd_fails;
#endif
}

static void
collect_natt(struct ph1handle *iph1, struct status_natt *natt)
{
	memset(natt, 0, sizeof(*natt));
#ifdef ENABLE_NATT
	if (iph1->natt_options == NULL)
		return;
	natt->present = 1;
	natt->enabled = 1;
#endif
}

static void
collect_remote_config(struct ph1handle *iph1, struct status_remote_config *rc)
{
	memset(rc, 0, sizeof(*rc));

	if (iph1->rmconf == NULL || iph1->rmconf->remote == NULL)
		return;

	rc->present = 1;
	rc->anonymous = (iph1->rmconf->remote->sa_family == AF_UNSPEC) ? 1 : 0;
	rc->passive = iph1->rmconf->passive ? 1 : 0;
	rc->generate_policy = generate_policy_name(iph1->rmconf->gen_policy);
}

static void
collect_ph1(struct ph1handle *iph1, struct status_ph1 *p)
{
	memset(p, 0, sizeof(*p));

	p->index = cookie_pair_hex(&iph1->index);
	p->state = ph1_state_name(iph1->status);

	/* ipsecdoi_id2str() (ipsec_doi.c) uses its own static char buf[512]
	 * only as scratch space while building the string; before it
	 * returns, it always racoon_malloc()s a fresh, exact-sized copy and
	 * returns that -- the caller already owns a clean heap pointer, not
	 * a pointer into the static buffer. dupstr()-wrapping it here was a
	 * double allocation: the ipsecdoi_id2str() result itself was never
	 * referenced again and leaked on every call. saddr2str() (the
	 * fallback for an unset id/id_p) is the one that actually returns a
	 * pointer into its own static buffer and genuinely needs dupstr().
	 * See doc/dev/racoonctl-status-analysis.md's corrected H-2. */
	p->remote_id = iph1->id_p != NULL ?
	    ipsecdoi_id2str(iph1->id_p) : dupstr(saddr2str(iph1->remote));
	p->local_id = iph1->id != NULL ?
	    ipsecdoi_id2str(iph1->id) : dupstr(saddr2str(iph1->local));

	if (asprintf(&p->version, "%d.%d", (iph1->version >> 4) & 0xf,
	    iph1->version & 0xf) < 0)
		p->version = racoon_strdup("?");

	p->exchange_mode = exchange_mode_name(iph1->etype,
	    &p->exchange_mode_owned);

	if (iph1->approval != NULL) {
		p->has_proposal = 1;
		p->enc_alg = dupstr(s_attr_isakmp_enc(iph1->approval->enctype));
		p->hash_alg = dupstr(s_attr_isakmp_hash(iph1->approval->hashtype));
		p->auth_method = dupstr(s_oakley_attr_method(iph1->approval->authmethod));
		p->dh_group = dupstr(s_attr_isakmp_group(iph1->approval->dh_group));
		p->lifetime_time = (unsigned long)iph1->approval->lifetime;
	}

#ifdef ENABLE_HYBRID
	collect_xauth(iph1, &p->xauth);
	collect_mode_cfg(iph1, &p->mode_cfg);
#endif
	collect_dpd(iph1, &p->dpd);
	collect_natt(iph1, &p->natt);
	collect_remote_config(iph1, &p->remote_config);
}

static const char *
ph2_protocol_name(int proto_id)
{
	switch (proto_id) {
	case IPSECDOI_PROTO_IPSEC_ESP:	return "ESP";
	case IPSECDOI_PROTO_IPSEC_AH:	return "AH";
	case IPSECDOI_PROTO_IPCOMP:	return "IPCOMP";
	default:			return "unknown";
	}
}

/*
 * Phase 2 algorithm names: strnames.c's IPsec-DOI transform tables render
 * a bare cipher/hash family name, which loses information phase1's own
 * proposal fields carry -- the two sat side by side in one document
 * describing the same cipher family differently ("AES" vs "AES-CBC").
 * Both helpers below reconstruct the missing part from the transform ID
 * alone, which is sufficient: no key material or key length is consulted,
 * and no schema field changes type or meaning -- only the value's
 * precision improves.
 *
 * Deliberately derived here rather than by editing strnames.c: those
 * tables are also the render path for racoon's -dddd proposal logging and
 * are pinned by test/test_strnames.c, so retargeting them would change
 * unrelated output for every existing consumer. algorithm.c's
 * ipsec_encdef[]/ipsec_hmacdef[] were checked as the "sibling table"
 * alternative and rejected: they hold config-grammar keywords ("aes",
 * "sha1"), not display names, carry no mode either, are file-static, and
 * several entries are #ifdef'd out depending on the OpenSSL build.
 */

/*
 * Every ESP transform racoon can actually negotiate is a CBC-mode block
 * cipher: crypto_openssl.c implements exactly one mode per cipher
 * (EVP_aes_{128,192,256}_cbc(), EVP_camellia_*_cbc(), EVP_des_ede3_cbc(),
 * EVP_bf_cbc(), EVP_cast5_cbc(), EVP_idea_cbc(), EVP_des_cbc()), and the
 * tree has no CTR or GCM support at all -- so the mode is a property of
 * the transform ID, not something that has to be guessed from key length.
 *
 * The two exceptions are genuinely not CBC and keep their bare names:
 * IPSECDOI_ESP_NULL (no encryption, hence no mode) and IPSECDOI_ESP_RC4
 * (a stream cipher). An unrecognized transform ID falls through to
 * s_ipsecdoi_trns_esp()'s num2str() fallback and must not be labelled
 * either way, so it is not listed here.
 */
static int
esp_trns_is_cbc(int trns_id)
{
	switch (trns_id) {
	case IPSECDOI_ESP_DES_IV64:
	case IPSECDOI_ESP_DES:
	case IPSECDOI_ESP_3DES:
	case IPSECDOI_ESP_RC5:
	case IPSECDOI_ESP_IDEA:
	case IPSECDOI_ESP_CAST:
	case IPSECDOI_ESP_BLOWFISH:
	case IPSECDOI_ESP_3IDEA:
	case IPSECDOI_ESP_DES_IV32:
	case IPSECDOI_ESP_AES:
	case IPSECDOI_ESP_TWOFISH:
	case IPSECDOI_ESP_CAMELLIA:
		return 1;
	default:
		return 0;
	}
}

/* Returns an owned string, like the dupstr() call it replaces. */
static char *
esp_enc_alg_name(int trns_id)
{
	char *result;
	const char *base;

	base = s_ipsecdoi_trns_esp(trns_id);
	if (base == NULL)
		return NULL;

	if (!esp_trns_is_cbc(trns_id))
		return dupstr(base);

	/* base points into strnames.c's table (or its static num2str()
	 * buffer) -- consumed immediately here, never stored. */
	if (asprintf(&result, "%s-CBC", base) < 0)
		return dupstr(base);
	return result;
}

/*
 * strnames.c's name_attr_ipsec_auth[] renders
 * IPSECDOI_ATTR_AUTH_HMAC_SHA1 as "hmac-sha", dropping the variant digit
 * that its own SHA-2 entries do carry ("hmac-sha256"/"-sha384"/
 * "-sha512"). That lone truncated entry is the whole gap: every other
 * value in the table already names its variant, so this reproduces the
 * table's own established convention for the one entry that breaks it,
 * and defers to strnames.c for all the rest.
 */
static char *
esp_auth_alg_name(int authtype)
{
	if (authtype == IPSECDOI_ATTR_AUTH_HMAC_SHA1)
		return racoon_strdup("hmac-sha1");
	return dupstr(s_ipsecdoi_auth(authtype));
}

/* iph2->id/id_p carry the wire selector's own port/proto fields
 * (struct ipsecdoi_id_b) -- a more reliable source for the negotiated
 * selector than reinterpreting iph2->sa_src/sa_dst as sockaddr_in, which
 * are tunnel-endpoint hints, not the selector itself. */
static void
selector_proto_port(vchar_t *id, int *proto, int *port)
{
	struct ipsecdoi_id_b *id_b;

	/* proto is NULL on the iph2->id_p call (collect_ph2() only wants
	 * dst_port from the peer's ID, proto comes from the local id) --
	 * both output pointers are optional, guard each independently. */
	if (proto != NULL)
		*proto = -1;
	if (port != NULL)
		*port = -1;

	if (id == NULL)
		return;

	id_b = (struct ipsecdoi_id_b *)id->v;
	if (proto != NULL && id_b->proto_id != 0)
		*proto = id_b->proto_id;
	if (port != NULL && id_b->port != 0)
		*port = ntohs(id_b->port);
}

static void
collect_ph2(struct ph2handle *iph2, struct status_ph2 *p)
{
	struct saproto *proto;
	struct satrns *trns;
	struct secpolicy *sp;
	int prefs = -1, prefd = -1;

	memset(p, 0, sizeof(*p));

	if (asprintf(&p->index, "0x%08x", iph2->msgid) < 0)
		p->index = racoon_strdup("?");
	p->state = ph2_state_name(iph2->status);

	if (iph2->spid != 0 && (sp = getspbyspid(iph2->spid)) != NULL) {
		prefs = sp->spidx.prefs;
		prefd = sp->spidx.prefd;
	}
	p->sel_src = sockaddr_to_cidr(iph2->src, prefs);
	p->sel_dst = sockaddr_to_cidr(iph2->dst, prefd);
	selector_proto_port(iph2->id, &p->sel_proto, &p->sel_sport);
	selector_proto_port(iph2->id_p, NULL, &p->sel_dport);

	p->protocol = "unknown";
	/* Left NULL -- i.e. rendered as JSON null -- until an approved
	 * proposal actually supplies the SPIs (issue #143 F4). The previous
	 * "0x00000000****" placeholder was an 8-hex-digit string where
	 * mask_spi() and the published schema both specify 4, so any phase2
	 * handle enumerated before its proposal was approved (PHASE2ST_START,
	 * PHASE2ST_GETSPISENT, ...) emitted a document that failed the
	 * project's own schema. null says "not negotiated yet" honestly,
	 * rather than claiming an all-zero SPI that was never on the wire. */
	p->spi_in = NULL;
	p->spi_out = NULL;

	if (iph2->approval != NULL) {
		p->has_proposal = 1;
		p->pfs_group = iph2->approval->pfs_group;
		p->lifetime_time = (unsigned long)iph2->approval->lifetime;
		p->lifetime_bytes = (unsigned long)iph2->approval->lifebyte;

		proto = iph2->approval->head;
		if (proto != NULL) {
			p->protocol = ph2_protocol_name(proto->proto_id);
			p->spi_in = mask_spi(proto->spi);
			p->spi_out = mask_spi(proto->spi_p);
			p->ok = proto->ok;

			/* Issue #143 L1: this reads the single transform
			 * directly instead of walking proto->head's list.
			 * cmpsaprop_alloc() (proposal.c), which builds
			 * iph2->approval, calls newsatrns()/inssatrns()
			 * exactly once per matched saproto -- an approved
			 * proposal carries one transform per protocol by
			 * construction, so the list never had a second entry
			 * to visit. The old loop nevertheless assigned over
			 * p->enc_alg/auth_alg/comp_alg on each pass without
			 * freeing the previous pointer, which would have
			 * leaked the moment that invariant changed, and read
			 * as though it handled a case it did not. Reading
			 * ->head once says what the code actually means and
			 * cannot leak. */
			trns = proto->head;
			if (trns != NULL) {
				switch (proto->proto_id) {
				case IPSECDOI_PROTO_IPSEC_ESP:
					p->enc_alg = esp_enc_alg_name(trns->trns_id);
					if (trns->authtype != IPSECDOI_ATTR_AUTH_NONE)
						p->auth_alg = esp_auth_alg_name(trns->authtype);
					break;
				case IPSECDOI_PROTO_IPSEC_AH:
					/* Issue #143 L2: AH provides integrity
					 * only and no encryption at all, so its
					 * transform is an *authentication*
					 * algorithm. Reporting it in
					 * encryption_algorithm (as this did
					 * through schema 1.2) told a consumer
					 * asking "what cipher protects this SA"
					 * that the answer was a hash name.
					 * encryption_algorithm is left NULL --
					 * rendered as JSON null -- which is the
					 * honest answer for AH. */
					p->auth_alg = dupstr(s_ipsecdoi_trns_ah(trns->trns_id));
					break;
				case IPSECDOI_PROTO_IPCOMP:
					p->comp_alg = dupstr(s_ipsecdoi_trns_ipcomp(trns->trns_id));
					break;
				}
			}
		}
	}

	p->encmode = dupstr(s_ipsecdoi_encmode(
	    (proto = (iph2->approval != NULL ? iph2->approval->head : NULL)) != NULL ?
	    proto->encmode : 0));

	p->reqid_in = (proto != NULL) ? proto->reqid_in : 0;
	p->reqid_out = (proto != NULL) ? proto->reqid_out : 0;

	/* D6 (issue #140): iph2->ph1 is a direct back-pointer (handler.h),
	 * set by bindph12() and cleared by unbindph12() -- the latter is
	 * called from initph2() and during phase2 teardown, so iph2->ph1
	 * can genuinely be NULL for a phase2 handle that's still briefly
	 * enumerable. Render both fields as "indeterminate" in that window
	 * rather than dereferencing a NULL parent. */
	if (iph2->ph1 != NULL) {
		p->phase1_index = cookie_pair_hex(&iph2->ph1->index);
		p->effective_group = (p->pfs_group != 0) ? p->pfs_group :
		    (iph2->ph1->approval != NULL ?
		    iph2->ph1->approval->dh_group : 0);
	} else {
		p->phase1_index = NULL;
		p->effective_group = p->pfs_group;
	}
}

/*
 * ph1tree/ph2tree are static to handler.c -- status.c reaches them only
 * through the same enumph1()/enumph2() accessors admin.c's other
 * ADMIN_* cases already use (e.g. ADMIN_DELETE_SA), not by declaring
 * them extern here. A NULL selector visits every handle, unfiltered
 * (handler.c: enumph1()/enumph2()).
 */

struct count_ctx {
	int count;
};

static int
count_ph1_cb(struct ph1handle *iph1, void *arg)
{
	((struct count_ctx *)arg)->count++;
	return 0;
}

static int
count_ph2_cb(struct ph2handle *iph2, void *arg)
{
	((struct count_ctx *)arg)->count++;
	return 0;
}

struct fill_ph1_ctx {
	struct status_ph1 *arr;
	int cap;
	int i;
};

static int
fill_ph1_cb(struct ph1handle *iph1, void *arg)
{
	struct fill_ph1_ctx *ctx = arg;

	if (ctx->i < ctx->cap)
		collect_ph1(iph1, &ctx->arr[ctx->i]);
	ctx->i++;
	return 0;
}

struct fill_ph2_ctx {
	struct status_ph2 *arr;
	int cap;
	int i;
};

static int
fill_ph2_cb(struct ph2handle *iph2, void *arg)
{
	struct fill_ph2_ctx *ctx = arg;

	if (ctx->i < ctx->cap)
		collect_ph2(iph2, &ctx->arr[ctx->i]);
	ctx->i++;
	return 0;
}

static struct status_snapshot *
collect_snapshot(int verbose)
{
	struct status_snapshot *snap;
	struct count_ctx cnt;

	snap = racoon_calloc(1, sizeof(*snap));
	if (snap == NULL)
		return NULL;

	snap->timestamp = format_timestamp(time(NULL));
	snap->verbose = verbose;

	cnt.count = 0;
	enumph1(NULL, count_ph1_cb, &cnt);
	snap->ph1_count = cnt.count;
	if (snap->ph1_count > 0) {
		snap->ph1 = racoon_calloc(snap->ph1_count, sizeof(*snap->ph1));
		if (snap->ph1 != NULL) {
			struct fill_ph1_ctx fctx;
			fctx.arr = snap->ph1;
			fctx.cap = snap->ph1_count;
			fctx.i = 0;
			enumph1(NULL, fill_ph1_cb, &fctx);
		} else {
			/* Found via audit, not observed live: on allocation
			 * failure here, ph1_count must not be left nonzero
			 * with ph1 still NULL -- every reader below (both
			 * renderers, free_snapshot()) indexes snap->ph1[i]
			 * for i < ph1_count unconditionally, which would
			 * dereference NULL. */
			snap->ph1_count = 0;
		}
	}

	if (verbose) {
		cnt.count = 0;
		enumph2(NULL, count_ph2_cb, &cnt);
		snap->ph2_count = cnt.count;
		if (snap->ph2_count > 0) {
			snap->ph2 = racoon_calloc(snap->ph2_count, sizeof(*snap->ph2));
			if (snap->ph2 != NULL) {
				struct fill_ph2_ctx fctx;
				fctx.arr = snap->ph2;
				fctx.cap = snap->ph2_count;
				fctx.i = 0;
				enumph2(NULL, fill_ph2_cb, &fctx);
			} else {
				snap->ph2_count = 0;
			}
		}
	}

	return snap;
}

/* ------------------------------------------------------------------ */
/* JSON renderer.                                                       */
/* ------------------------------------------------------------------ */

static void
json_render_xauth(struct outbuf *ob, struct status_xauth *x)
{
	int first = 1;

	if (!x->present)
		return;
	ob_puts(ob, ",\"xauth\":{");
	json_key(ob, &first, "state"); json_string(ob, x->state);
	json_key(ob, &first, "auth_type"); json_string(ob, x->auth_type);
	json_key(ob, &first, "username"); json_string(ob, x->username);
	ob_puts(ob, "}");
}

static void
json_render_mode_cfg(struct outbuf *ob, struct status_mode_cfg *mc)
{
	int first = 1;
	int i;

	if (!mc->present)
		return;
	ob_puts(ob, ",\"mode_cfg\":{");
	json_key(ob, &first, "addr4"); json_string(ob, mc->addr4);
	json_key(ob, &first, "dns4"); ob_puts(ob, "[");
	for (i = 0; i < mc->dns4_count; i++) {
		if (i > 0)
			ob_puts(ob, ",");
		json_string(ob, mc->dns4[i]);
	}
	ob_puts(ob, "]");
	json_key(ob, &first, "split_include"); ob_puts(ob, "[");
	for (i = 0; i < mc->split_include_count; i++) {
		if (i > 0)
			ob_puts(ob, ",");
		json_string(ob, mc->split_include[i]);
	}
	ob_puts(ob, "]");
	ob_puts(ob, "}");
}

static void
json_render_ph1(struct outbuf *ob, struct status_ph1 *p)
{
	int first = 1;

	ob_puts(ob, "{");
	json_key(ob, &first, "index"); json_string(ob, p->index);
	json_key(ob, &first, "state"); json_string(ob, p->state);
	json_key(ob, &first, "remote_id"); json_string(ob, p->remote_id);
	json_key(ob, &first, "local_id"); json_string(ob, p->local_id);
	json_key(ob, &first, "version"); json_string(ob, p->version);
	json_key(ob, &first, "exchange_mode"); json_string(ob, p->exchange_mode);

	if (p->has_proposal) {
		json_key(ob, &first, "proposal"); ob_puts(ob, "{");
		ob_puts(ob, "\"encryption_algorithm\":"); json_string(ob, p->enc_alg);
		ob_puts(ob, ",\"hash_algorithm\":"); json_string(ob, p->hash_alg);
		ob_puts(ob, ",\"authentication_method\":"); json_string(ob, p->auth_method);
		ob_puts(ob, ",\"dh_group\":"); json_string(ob, p->dh_group);
		ob_printf(ob, ",\"lifetime_time\":%lu", p->lifetime_time);
		ob_puts(ob, "}");
	}

	json_render_xauth(ob, &p->xauth);
	json_render_mode_cfg(ob, &p->mode_cfg);

	if (p->dpd.present) {
		ob_printf(ob, ",\"dpd\":{\"supported\":%s,\"fails\":%d}",
		    p->dpd.supported ? "true" : "false", p->dpd.fails);
	}
	if (p->natt.present) {
		ob_printf(ob, ",\"natt\":{\"enabled\":%s}",
		    p->natt.enabled ? "true" : "false");
	}
	if (p->remote_config.present) {
		ob_puts(ob, ",\"remote_config\":{");
		ob_printf(ob, "\"anonymous\":%s,", p->remote_config.anonymous ? "true" : "false");
		ob_printf(ob, "\"passive\":%s,", p->remote_config.passive ? "true" : "false");
		ob_puts(ob, "\"generate_policy\":");
		json_string(ob, p->remote_config.generate_policy);
		ob_puts(ob, "}");
	}

	ob_puts(ob, "}");
}

static void
json_render_ph2(struct outbuf *ob, struct status_ph2 *p)
{
	int first = 1;

	ob_puts(ob, "{");
	json_key(ob, &first, "index"); json_string(ob, p->index);
	json_key(ob, &first, "phase1_index"); json_string(ob, p->phase1_index);
	json_key(ob, &first, "state"); json_string(ob, p->state);
	json_key(ob, &first, "spi_in"); json_string(ob, p->spi_in);
	json_key(ob, &first, "spi_out"); json_string(ob, p->spi_out);
	json_key(ob, &first, "protocol"); json_string(ob, p->protocol);
	json_key(ob, &first, "encmode"); json_string(ob, p->encmode);

	json_key(ob, &first, "selectors"); ob_puts(ob, "{");
	ob_puts(ob, "\"src\":"); json_string(ob, p->sel_src);
	ob_puts(ob, ",\"dst\":"); json_string(ob, p->sel_dst);
	ob_puts(ob, ",\"protocol\":");
	if (p->sel_proto < 0)
		json_string(ob, "any");
	else
		ob_printf(ob, "%d", p->sel_proto);
	ob_puts(ob, ",\"src_port\":");
	if (p->sel_sport < 0)
		json_string(ob, "any");
	else
		ob_printf(ob, "%d", p->sel_sport);
	ob_puts(ob, ",\"dst_port\":");
	if (p->sel_dport < 0)
		json_string(ob, "any");
	else
		ob_printf(ob, "%d", p->sel_dport);
	ob_puts(ob, "}");

	if (p->has_proposal) {
		json_key(ob, &first, "proposal"); ob_puts(ob, "{");
		ob_puts(ob, "\"encryption_algorithm\":"); json_string(ob, p->enc_alg);
		ob_puts(ob, ",\"authentication_algorithm\":"); json_string(ob, p->auth_alg);
		if (p->comp_alg != NULL) {
			ob_puts(ob, ",\"compression_algorithm\":");
			json_string(ob, p->comp_alg);
		}
		if (p->pfs_group != 0)
			ob_printf(ob, ",\"pfs_group\":%d", p->pfs_group);
		else
			ob_puts(ob, ",\"pfs_group\":null");
		/* D6 (issue #140): always a JSON number, never null/string --
		 * unlike pfs_group, this field must have one consistent type
		 * across both branches (see the issue's type-consistency
		 * rule). 0 is not a valid real DH group id, so it doubles as
		 * the "indeterminate" marker for the rare unbound iph2->ph1
		 * case without needing a separate null branch here. */
		ob_printf(ob, ",\"effective_group\":%d", p->effective_group);
		ob_printf(ob, ",\"lifetime_time\":%lu", p->lifetime_time);
		ob_printf(ob, ",\"lifetime_bytes\":%lu", p->lifetime_bytes);
		ob_puts(ob, "}");
	}

	ob_printf(ob, ",\"reqid_in\":%d,\"reqid_out\":%d,\"ok\":%s",
	    p->reqid_in, p->reqid_out, p->ok ? "true" : "false");

	ob_puts(ob, "}");
}

static void
render_json(struct status_snapshot *snap, struct outbuf *ob)
{
	int i;

	/* 1.2 (issue #143 F4): spi_in/spi_out widened from string to
	 * string-or-null -- additive, so a minor bump.
	 * 2.0 (issue #143 L2): an AH SA now reports its transform in
	 * authentication_algorithm with encryption_algorithm null, instead of
	 * the reverse. A *major* bump: the type widening that came with it is
	 * additive on its own, but a value relocating between two fields is
	 * invisible to schema validation (both fields accept string-or-null
	 * either way) while silently changing what a consumer parsing
	 * encryption_algorithm reads back for that SA class. D4 reserves major
	 * for exactly that. Shipped briefly as 1.3; see D9 in
	 * doc/dev/racoonctl-status-analysis.md for the reversal.
	 *
	 * The value itself lives in status.h, which is the single C-side
	 * source of truth: the wire string is built from it by literal
	 * concatenation here, test_status_dump.c pins its assertion against
	 * the same macro, and tools/schema_cross_check.py holds the schema
	 * file and the man page to it. See that header for the whole
	 * arrangement. */
	ob_puts(ob, "{\"schema_version\":\"" RACOONCTL_STATUS_SCHEMA_VERSION
	    "\",\"timestamp\":");
	json_string(ob, snap->timestamp);

	ob_puts(ob, ",\"phase1\":[");
	for (i = 0; i < snap->ph1_count; i++) {
		if (i > 0)
			ob_puts(ob, ",");
		json_render_ph1(ob, &snap->ph1[i]);
	}
	ob_puts(ob, "]");

	if (snap->verbose) {
		ob_puts(ob, ",\"phase2\":[");
		for (i = 0; i < snap->ph2_count; i++) {
			if (i > 0)
				ob_puts(ob, ",");
			json_render_ph2(ob, &snap->ph2[i]);
		}
		ob_puts(ob, "]");
	}

	ob_puts(ob, "}");
}

/* ------------------------------------------------------------------ */
/* Text renderer -- same field set as JSON (per issue #139: JSON is the */
/* mandatory interface, text differs only in layout), human-readable.   */
/* ------------------------------------------------------------------ */

static void
text_render_ph1(struct outbuf *ob, struct status_ph1 *p)
{
	ob_printf(ob, "Phase 1: %s\n", p->index);
	ob_printf(ob, "  state:          %s\n", p->state);
	ob_printf(ob, "  remote:         %s\n", p->remote_id);
	ob_printf(ob, "  local:          %s\n", p->local_id);
	ob_printf(ob, "  version:        %s  exchange_mode: %s\n",
	    p->version, p->exchange_mode);
	if (p->has_proposal) {
		ob_printf(ob, "  encryption:     %s  hash: %s  auth: %s  dh: %s\n",
		    p->enc_alg, p->hash_alg, p->auth_method, p->dh_group);
		ob_printf(ob, "  lifetime:       %lus\n", p->lifetime_time);
	}
	if (p->xauth.present) {
		ob_printf(ob, "  xauth:          state=%s auth_type=%s username=%s\n",
		    p->xauth.state, p->xauth.auth_type,
		    p->xauth.username != NULL ? p->xauth.username : "-");
	}
	if (p->mode_cfg.present) {
		int i;
		ob_printf(ob, "  mode_cfg addr4: %s\n", p->mode_cfg.addr4);
		if (p->mode_cfg.dns4_count > 0) {
			ob_puts(ob, "  mode_cfg dns4:  ");
			for (i = 0; i < p->mode_cfg.dns4_count; i++)
				ob_printf(ob, "%s%s", i > 0 ? " " : "", p->mode_cfg.dns4[i]);
			ob_puts(ob, "\n");
		}
		if (p->mode_cfg.split_include_count > 0) {
			ob_puts(ob, "  split_include:  ");
			for (i = 0; i < p->mode_cfg.split_include_count; i++)
				ob_printf(ob, "%s%s", i > 0 ? " " : "",
				    p->mode_cfg.split_include[i]);
			ob_puts(ob, "\n");
		}
	}
	if (p->dpd.present)
		ob_printf(ob, "  dpd:            supported=%s fails=%d\n",
		    p->dpd.supported ? "yes" : "no", p->dpd.fails);
	if (p->natt.present)
		ob_printf(ob, "  natt:           enabled=%s\n",
		    p->natt.enabled ? "yes" : "no");
	if (p->remote_config.present) {
		ob_printf(ob, "  remote_config:  anonymous=%s passive=%s generate_policy=%s\n",
		    p->remote_config.anonymous ? "yes" : "no",
		    p->remote_config.passive ? "yes" : "no",
		    p->remote_config.generate_policy);
	}
}

/* A selector's proto/port renders as its number, or "any" when unset
 * (< 0) -- mirroring json_render_ph2()'s own two branches. Writes into
 * the caller's buffer and returns it, so one ob_printf() can carry all
 * three fields. */
static const char *
selector_field_str(int v, char *buf, size_t buflen)
{
	if (v < 0)
		return "any";
	snprintf(buf, buflen, "%d", v);
	return buf;
}

static void
text_render_ph2(struct outbuf *ob, struct status_ph2 *p)
{
	char protobuf[16], sportbuf[16], dportbuf[16];

	ob_printf(ob, "Phase 2: %s\n", p->index);
	ob_printf(ob, "  phase1:         %s\n",
	    p->phase1_index != NULL ? p->phase1_index : "(unbound)");
	ob_printf(ob, "  state:          %s  protocol: %s  mode: %s\n",
	    p->state, p->protocol, p->encmode);
	/* spi_in/spi_out are NULL until the proposal is approved (issue #143
	 * F4) -- JSON renders that as null, text as "(pending)". */
	ob_printf(ob, "  spi:            in=%s out=%s\n",
	    p->spi_in != NULL ? p->spi_in : "(pending)",
	    p->spi_out != NULL ? p->spi_out : "(pending)");
	/* Issue #143 F2: the non-"any" branch used to yield an empty string,
	 * so a selector with a real proto/port rendered as "proto= sport=
	 * dport=" -- text silently omitting data JSON showed, which issue
	 * #139's mandatory-interface rule forbids. */
	ob_printf(ob, "  selector:       %s -> %s  proto=%s sport=%s dport=%s\n",
	    p->sel_src, p->sel_dst,
	    selector_field_str(p->sel_proto, protobuf, sizeof(protobuf)),
	    selector_field_str(p->sel_sport, sportbuf, sizeof(sportbuf)),
	    selector_field_str(p->sel_dport, dportbuf, sizeof(dportbuf)));
	if (p->has_proposal) {
		/* Both algorithm fields are legitimately NULL: auth_alg for an
		 * ESP transform negotiated with IPSECDOI_ATTR_AUTH_NONE, and
		 * (since issue #143 L2) enc_alg for an AH SA, which has no
		 * cipher. Passing NULL to a "%s" conversion is undefined
		 * behaviour -- glibc happens to print "(null)", but this tree
		 * also targets NetBSD, so substitute explicitly rather than
		 * relying on that. JSON renders the same two cases as null. */
		ob_printf(ob, "  encryption:     %s  auth: %s%s%s\n",
		    p->enc_alg != NULL ? p->enc_alg : "(none)",
		    p->auth_alg != NULL ? p->auth_alg : "(none)",
		    p->comp_alg != NULL ? "  comp: " : "",
		    p->comp_alg != NULL ? p->comp_alg : "");
		if (p->pfs_group != 0)
			ob_printf(ob, "  pfs_group:      %d\n", p->pfs_group);
		else
			ob_puts(ob, "  pfs_group:      (none)\n");
		ob_printf(ob, "  effective_group: %d\n", p->effective_group);
		ob_printf(ob, "  lifetime:       %lus / %lu bytes\n",
		    p->lifetime_time, p->lifetime_bytes);
	}
	ob_printf(ob, "  reqid:          in=%d out=%d  ok=%s\n",
	    p->reqid_in, p->reqid_out, p->ok ? "yes" : "no");
}

static void
render_text(struct status_snapshot *snap, struct outbuf *ob)
{
	int i;

	ob_printf(ob, "racoon status at %s\n\n", snap->timestamp);

	if (snap->ph1_count == 0)
		ob_puts(ob, "(no phase 1 SAs)\n");
	for (i = 0; i < snap->ph1_count; i++) {
		text_render_ph1(ob, &snap->ph1[i]);
		ob_puts(ob, "\n");
	}

	if (snap->verbose) {
		if (snap->ph2_count == 0)
			ob_puts(ob, "(no phase 2 SAs)\n");
		for (i = 0; i < snap->ph2_count; i++) {
			text_render_ph2(ob, &snap->ph2[i]);
			ob_puts(ob, "\n");
		}
	}
}

/* ------------------------------------------------------------------ */
/* Entry point.                                                         */
/* ------------------------------------------------------------------ */

void
status_dump(vchar_t **out, int verbose, int json_format)
{
	struct status_snapshot *snap;
	struct outbuf ob;

	*out = NULL;

	/* No locking around this extraction pass is needed: admin_process()
	 * (which calls us) and isakmp_handler()/the rest of the negotiation
	 * state machine all run on the same single-threaded monitor_fd()
	 * event loop (session.c), one ready fd at a time. Nothing can mutate
	 * ph1tree/ph2tree or any handle while this function runs -- every
	 * status poll either sees a fully consistent snapshot of a handle,
	 * or that handle simply isn't in the tree (yet, or anymore). See
	 * doc/dev/racoonctl-status-analysis.md D2's call-chain trace (also
	 * reproduced in issue #139) for the full argument. */
	snap = collect_snapshot(verbose);
	if (snap == NULL) {
		plog(LLV_ERROR, LOCATION, NULL, "status: out of memory\n");
		return;
	}

	ob_init(&ob);
	if (ob.buf == NULL) {
		free_snapshot(snap);
		racoon_free(snap);
		return;
	}

	if (json_format)
		render_json(snap, &ob);
	else
		render_text(snap, &ob);

	free_snapshot(snap);
	racoon_free(snap);

	if (ob.buf == NULL)
		return;

	/* Allocate one byte beyond the reply's wire length and leave it as
	 * vmalloc()'s calloc() zeroed it, so (*out)->v is NUL-terminated for
	 * any local caller that treats it as a C string -- but keep ->l at
	 * the real content length so that trailing NUL is never counted
	 * into, or sent as part of, the admin-socket reply (admin.c's
	 * admin_reply() sends exactly buf->l bytes). */
	*out = vmalloc(ob.pos + 1);
	if (*out != NULL) {
		memcpy((*out)->v, ob.buf, ob.pos);
		(*out)->l = ob.pos;
	}
	ob_free(&ob);
}

#ifdef ENABLE_UNITTEST
/*
 * Thin -DENABLE_UNITTEST accessors for status.c's static functions --
 * same pattern as racoonctl.c's own f_status_unittest()/get_combuf_unittest()
 * and handler.c's ph1tree_count_unittest(): no production behavior change,
 * just visibility for test_status_dump.c to call ph1_state_name()/
 * ph2_state_name() directly with every PHASE1ST_/PHASE2ST_ value
 * (including an out-of-range one, for the default: "unknown" branch)
 * without needing a ph1handle/ph2handle fixture -- both functions are
 * pure (int in, const char * out, no side effects).
 */
const char *
ph1_state_name_unittest(int state)
{
	return ph1_state_name(state);
}

const char *
ph2_state_name_unittest(int state)
{
	return ph2_state_name(state);
}
#endif /* ENABLE_UNITTEST */
