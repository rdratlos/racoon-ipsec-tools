/*	$NetBSD: admin.c,v 1.38.4.1 2013/06/03 05:49:59 tteras Exp $	*/

/* Id: admin.c,v 1.25 2006/04/06 14:31:04 manubsd Exp */

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
/*
 * Modifications Copyright (C) 2024-2026 Thomas Reim
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <net/pfkeyv2.h>

#include <netinet/in.h>
#include PATH_IPSEC_H


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef ENABLE_HYBRID
#include <resolv.h>
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "schedule.h"
#include "localconf.h"
#include "remoteconf.h"
#include "grabmyaddr.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "oakley.h"
#include "handler.h"
#include "evt.h"
#include "pfkey.h"
#include "ipsec_doi.h"
#include "policy.h"
#include "admin.h"
#include "admin_var.h"
#include "status.h"
#include "isakmp_inf.h"
#ifdef ENABLE_HYBRID
#include "isakmp_cfg.h"
#endif
#include "session.h"
#include "gcmalloc.h"

#ifdef ENABLE_ADMINPORT
char *adminsock_path = ADMINSOCK_PATH;
uid_t adminsock_owner = 0;
gid_t adminsock_group = 0;
mode_t adminsock_mode = 0600;

static struct sockaddr_un sunaddr;
static int admin_process __P((int, char *));
static int admin_reply __P((int, struct admin_com *, int, vchar_t *));
static int mkdir_p __P((const char *, mode_t));

/*
 * Create a directory and all missing parents, like "mkdir -p".
 * Pre-existing components (EEXIST) are not an error.
 */
static int
mkdir_p(const char *path, mode_t mode)
{
	char buf[MAXPATHLEN];
	char *p;

	if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	for (p = buf + 1; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(buf, mode) != 0 && errno != EEXIST)
			return -1;
		*p = '/';
	}

	if (mkdir(buf, mode) != 0 && errno != EEXIST)
		return -1;

	return 0;
}

#ifdef ENABLE_UNITTEST
/*
 * mkdir_p() is static, and admin_init() (its only production caller)
 * needs a real, unwritable-by-the-test filesystem layout to reach the
 * directory-creation branch at all. This thin wrapper lets a unit test
 * drive mkdir_p() itself directly against a throwaway temp directory.
 */
int
mkdir_p_unittest(const char *path, mode_t mode)
{
	return mkdir_p(path, mode);
}
#endif /* ENABLE_UNITTEST */

/*
 * racoon.conf lets an admin point the admin socket at an arbitrary
 * path via "listen { adminsock <path> ... ; }". Since admin_init()
 * runs as root (before privilege separation drops), a careless or
 * templated config pointing that path at an existing system file
 * would cause it to be unlink()'d and replaced by a socket, and its
 * parent directories to be created outright. Restrict the accepted
 * file name to the conventional "racoon.sock" or a "*.sock"/"*.socket"
 * suffix, and reject any ".." path traversal component, so racoon
 * only ever touches paths that look like dedicated socket locations.
 */
int
admin_check_sockpath(const char *path)
{
	const char *base;
	size_t plen, blen;

	if (path == NULL || *path == '\0')
		return -1;

	plen = strlen(path);
	if (strstr(path, "/../") != NULL ||
	    strncmp(path, "../", 3) == 0 ||
	    strcmp(path, "..") == 0 ||
	    (plen >= 3 && strcmp(path + plen - 3, "/..") == 0))
		return -1;

	base = strrchr(path, '/');
	base = (base != NULL) ? base + 1 : path;
	if (*base == '\0')
		return -1;

	if (strcmp(base, "racoon.sock") == 0)
		return 0;

	blen = strlen(base);
	if (blen > 5 && strcmp(base + blen - 5, ".sock") == 0)
		return 0;
	if (blen > 7 && strcmp(base + blen - 7, ".socket") == 0)
		return 0;

	return -1;
}

static int
admin_handler(void *ctx, int fd)
{
	int so2;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	struct admin_com com;
	char *combuf = NULL;
	int len, error = -1;

	so2 = accept(lcconf->sock_admin, (struct sockaddr *)&from, &fromlen);
	if (so2 < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to accept admin command: %s\n",
			strerror(errno));
		return -1;
	}
	close_on_exec(so2);

	/* get buffer length */
	while ((len = recv(so2, (char *)&com, sizeof(com), MSG_PEEK)) < 0) {
		if (errno == EINTR)
			continue;
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to recv admin command: %s\n",
			strerror(errno));
		goto end;
	}

	/* sanity check */
	if (len < sizeof(com)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid header length of admin command\n");
		goto end;
	}

	/* get buffer to receive */
	if ((combuf = racoon_malloc(com.ac_len)) == 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to alloc buffer for admin command\n");
		goto end;
	}

	/* get real data */
	while ((len = recv(so2, combuf, com.ac_len, 0)) < 0) {
		if (errno == EINTR)
			continue;
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to recv admin command: %s\n",
			strerror(errno));
		goto end;
	}

	error = admin_process(so2, combuf);

end:
	if (error == -2) {
		plog(LLV_DEBUG, LOCATION, NULL,
			"[%d] admin connection established\n", so2);
	} else {
		(void)close(so2);
	}

	if (combuf)
		racoon_free(combuf);

	return error;
}

#ifdef ENABLE_UNITTEST
/*
 * admin_handler() is static, and every one of its branches (accept()
 * failure, the recv(MSG_PEEK) header sanity check, the real read, and
 * the close()-unless-(-2) tail) depends on lcconf->sock_admin already
 * being a real, connected admin socket -- there is no other production
 * caller to piggyback on. This thin wrapper lets a test point
 * lcconf->sock_admin at a real listening AF_UNIX socket with a pending
 * connection and drive the whole function directly; ctx/fd are accepted
 * (matching the monitor_fd() callback signature admin_init() registers
 * this as) but unused by admin_handler() itself, so the wrapper takes
 * neither.
 */
int
admin_handler_unittest(void)
{
	return admin_handler(NULL, -1);
}
#endif /* ENABLE_UNITTEST */

static int admin_ph1_delete_sa(struct ph1handle *iph1, void *arg)
{
	if (iph1->status >= PHASE1ST_ESTABLISHED)
		isakmp_info_send_d1(iph1);
	purge_remote(iph1);
	return 0;
}

/*
 * main child's process.
 *
 * ADMIN_STATUS/ADMIN_STATUS_VERBOSE call status_dump() (status.c), whose
 * ph1tree/ph2tree extraction pass runs without any locking: admin_process()
 * and the ISAKMP negotiation state machine (isakmp_handler() and everything
 * it calls) both run on this daemon's single-threaded monitor_fd() event
 * loop, one ready fd at a time, so nothing can mutate a handle while this
 * function is reading it. See doc/dev/racoonctl-status-analysis.md's D2
 * call-chain trace (also reproduced in issue #139) for the full argument --
 * do not add locking here on the assumption it might be needed.
 */
static int
admin_process(int so2, char *combuf)
{
	struct admin_com *com = (struct admin_com *)combuf;
	vchar_t *buf = NULL;
	vchar_t *id = NULL;
	vchar_t *key = NULL;
	int idtype = 0;
	int error = 0, l_ac_errno = 0;
	struct evt_listener_list *event_list = NULL;

	if (com->ac_cmd & ADMIN_FLAG_VERSION)
		com->ac_cmd &= ~ADMIN_FLAG_VERSION;
	else
		com->ac_version = 0;

	switch (com->ac_cmd) {
	case ADMIN_RELOAD_CONF:
		signal_handler(SIGHUP);
		break;

	case ADMIN_SHOW_SCHED: {
		caddr_t p = NULL;
		int len;

		if (sched_dump(&p, &len) != -1) {
			buf = vmalloc(len);
			if (buf != NULL)
				memcpy(buf->v, p, len);
			else
				l_ac_errno = ENOMEM;
			racoon_free(p);
		} else
			l_ac_errno = ENOMEM;
		break;
	}

	case ADMIN_SHOW_EVT:
		if (com->ac_version == 0) {
			buf = evt_dump();
			l_ac_errno = 0;
		}
		break;

	case ADMIN_SHOW_SA:
		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP:
			buf = dumpph1();
			if (buf == NULL)
				l_ac_errno = ENOMEM;
			break;
		case ADMIN_PROTO_IPSEC:
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP: {
			u_int p;
			p = admin2pfkey_proto(com->ac_proto);
			if (p != -1) {
				buf = pfkey_dump_sadb(p);
				if (buf == NULL)
					l_ac_errno = ENOMEM;
			} else
				l_ac_errno = EINVAL;
			break;
		}
		case ADMIN_PROTO_INTERNAL:
		default:
			l_ac_errno = ENOTSUP;
			break;
		}
		break;

	case ADMIN_GET_SA_CERT: {
		struct admin_com_indexes *ndx;
		struct sockaddr *src, *dst;
		struct ph1handle *iph1;

		ndx = (struct admin_com_indexes *) ((caddr_t)com + sizeof(*com));
		src = (struct sockaddr *) &ndx->src;
		dst = (struct sockaddr *) &ndx->dst;

		if (com->ac_proto != ADMIN_PROTO_ISAKMP) {
			l_ac_errno = ENOTSUP;
			break;
		}

		iph1 = getph1byaddr(src, dst, 0);
		if (iph1 == NULL) {
			l_ac_errno = ENOENT;
			break;
		}

		if (iph1->cert_p != NULL) {
			vchar_t tmp;
			tmp.v = iph1->cert_p->v + 1;
			tmp.l = iph1->cert_p->l - 1;
			buf = vdup(&tmp);
		}
		break;
	}

	case ADMIN_STATUS:
		status_dump(&buf, 0, com->ac_proto == ADMIN_STATUS_FORMAT_JSON);
		if (buf == NULL)
			l_ac_errno = ENOMEM;
		break;

	case ADMIN_STATUS_VERBOSE:
		status_dump(&buf, 1, com->ac_proto == ADMIN_STATUS_FORMAT_JSON);
		if (buf == NULL)
			l_ac_errno = ENOMEM;
		break;

	case ADMIN_FLUSH_SA:
		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP:
			flushph1();
			break;
		case ADMIN_PROTO_IPSEC:
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP:
			pfkey_flush_sadb(com->ac_proto);
			break;
		case ADMIN_PROTO_INTERNAL:
			/*XXX flushph2();*/
		default:
			l_ac_errno = ENOTSUP;
			break;
		}
		break;

	case ADMIN_DELETE_SA: {
		char *loc, *rem;
		struct ph1selector sel;

		memset(&sel, 0, sizeof(sel));
		sel.local = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->src;
		sel.remote = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->dst;

		loc = racoon_strdup(saddr2str(sel.local));
		rem = racoon_strdup(saddr2str(sel.remote));
		STRDUP_FATAL(loc);
		STRDUP_FATAL(rem);

		plog(LLV_INFO, LOCATION, NULL,
		     "admin delete-sa %s %s\n", loc, rem);
		enumph1(&sel, admin_ph1_delete_sa, NULL);
		remcontacted(sel.remote);

		racoon_free(loc);
		racoon_free(rem);
		break;
	}

#ifdef ENABLE_HYBRID
	case ADMIN_LOGOUT_USER: {
		struct ph1handle *iph1;
		char user[LOGINLEN+1];
		int found = 0, len = com->ac_len - sizeof(*com);

		if (len > LOGINLEN) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "malformed message (login too long)\n");
			break;
		}

		memcpy(user, (char *)(com + 1), len);
		user[len] = 0;

		found = purgeph1bylogin(user);
		plog(LLV_INFO, LOCATION, NULL,
		    "deleted %d SA for user \"%s\"\n", found, user);

		break;
	}
#endif

	case ADMIN_DELETE_ALL_SA_DST: {
		struct ph1handle *iph1;
		struct sockaddr *dst;
		char *loc, *rem;
		int subscribed_once = 0;
		int admin_delete_all_subscribed = 0;
		int reply_error;

		dst = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->dst;

		rem = racoon_strdup(saddrwop2str(dst));
		STRDUP_FATAL(rem);

		plog(LLV_INFO, LOCATION, NULL,
		    "Flushing all SAs for peer %s\n", rem);
		racoon_free(rem);

		/*
		 * Reply to *this* request now, before triggering the
		 * teardown below -- not in this function's usual shared
		 * tail (admin_reply()/event_list, near the end of this
		 * function). purge_remote() -> isakmp_ph1delete() fires
		 * EVT_PHASE1_DOWN synchronously once subscribed (below), and
		 * racoonctl's vpn-disconnect/vd (f_vpnd(), racoonctl.c)
		 * exits its wait loop on *whichever* message satisfies
		 * evt_quit_event first -- it does not require this reply to
		 * arrive first. An earlier version of this fix subscribed
		 * before replying and left the reply for the shared tail:
		 * that let the event reach the client before this reply did,
		 * so the client (already satisfied) exited and closed its
		 * end of the socket having never read this reply at all: the
		 * shared tail's later admin_reply() then hit EPIPE on a
		 * socket the peer had already closed -- and, worse, since
		 * evt_subscribe() below also registers so2 in this process's
		 * own fd-monitor/select() set, admin_handler() closing so2
		 * in response to that EPIPE (this function returning
		 * anything other than -2) left that registration dangling:
		 * confirmed live to eventually make select() fail with
		 * EBADF and take the whole daemon down, not just this
		 * connection. Sending the reply here first, before anything
		 * that could race it, guarantees this reply is the first
		 * thing the client reads, matching what it already assumes.
		 */
		reply_error = admin_reply(so2, com, 0, NULL);

		while ((iph1 = getph1bydstaddr(dst)) != NULL) {
			loc = racoon_strdup(saddrwop2str(iph1->local));
			STRDUP_FATAL(loc);

			/*
			 * Subscribe on the first iteration, before the first
			 * purge_remote() below, and only if the reply above
			 * actually reached the client -- if it did not, this
			 * connection is already gone, and subscribing to it
			 * would only recreate the dangling-registration problem
			 * explained above for no benefit (nothing will ever
			 * read the event anyway). Subscribing to the global
			 * list (NULL) rather than any one iph1's own list
			 * matters too: evt_phase1() broadcasts to both, and
			 * dst can match more than one ph1 in this loop.
			 */
			if (!subscribed_once) {
				if (reply_error == 0 &&
				    evt_subscribe(NULL, so2) == -2)
					admin_delete_all_subscribed = 1;
				subscribed_once = 1;
			}

			if (iph1->status >= PHASE1ST_ESTABLISHED)
				isakmp_info_send_d1(iph1);
			purge_remote(iph1);

			racoon_free(loc);
		}

		/*
		 * Return directly rather than falling through to this
		 * function's shared tail: that tail's own admin_reply() call
		 * would otherwise send a second reply to this same request
		 * (the reply above already satisfied it), and its
		 * event_list-driven evt_subscribe() call is not applicable
		 * to this command (event_list is never set for it). buf/id/
		 * key are all still their initial NULL from this function's
		 * top, so nothing the shared tail would have freed is
		 * skipped by returning here instead.
		 */
		return admin_delete_all_subscribed ? -2 :
		    (reply_error != 0 ? reply_error : 0);
	}

	case ADMIN_ESTABLISH_SA_PSK: {
		struct admin_com_psk *acp;
		char *data;

		acp = (struct admin_com_psk *)
		    ((char *)com + sizeof(*com) +
		    sizeof(struct admin_com_indexes));

		idtype = acp->id_type;

		if ((id = vmalloc(acp->id_len)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "cannot allocate memory: %s\n",
			    strerror(errno));
			break;
		}
		data = (char *)(acp + 1);
		memcpy(id->v, data, id->l);

		if ((key = vmalloc(acp->key_len)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "cannot allocate memory: %s\n",
			    strerror(errno));
			vfree(id);
			id = NULL;
			break;
		}
		data = (char *)(data + acp->id_len);
		memcpy(key->v, data, key->l);
	}
	/* FALLTHROUGH */
	case ADMIN_ESTABLISH_SA: {
		struct admin_com_indexes *ndx;
		struct sockaddr *dst;
		struct sockaddr *src;
		char *name = NULL;

		ndx = (struct admin_com_indexes *) ((caddr_t)com + sizeof(*com));
		src = (struct sockaddr *) &ndx->src;
		dst = (struct sockaddr *) &ndx->dst;

		if (com->ac_cmd == ADMIN_ESTABLISH_SA &&
		    com->ac_len > sizeof(*com) + sizeof(*ndx))
			name = (char *) ((caddr_t) ndx + sizeof(*ndx));

		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP: {
			struct ph1handle *ph1;
			struct remoteconf *rmconf;
			u_int16_t port;

			l_ac_errno = -1;

			/* connected already? */
			ph1 = getph1byaddr(src, dst, 0);
			if (ph1 != NULL) {
				event_list = &ph1->evt_listeners;
				if (ph1->status == PHASE1ST_ESTABLISHED)
					l_ac_errno = EEXIST;
				else
					l_ac_errno = 0;
				break;
			}

			/* search appropreate configuration */
			if (name == NULL)
				rmconf = getrmconf(dst, 0);
			else
				rmconf = getrmconf_by_name(name);
			if (rmconf == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
					"no configuration found "
					"for %s\n", saddrwop2str(dst));
				break;
			}

#ifdef ENABLE_HYBRID
			/* XXX This overwrites rmconf information globally. */
			/* Set the id and key */
			if (id && key) {
				if (xauth_rmconf_used(&rmconf->xauth) == -1)
					break;

				if (rmconf->xauth->login != NULL) {
					vfree(rmconf->xauth->login);
					rmconf->xauth->login = NULL;
				}
				if (rmconf->xauth->pass != NULL) {
					vfree(rmconf->xauth->pass);
					rmconf->xauth->pass = NULL;
				}

				rmconf->xauth->login = id;
				rmconf->xauth->pass = key;
				id = NULL;
				key = NULL;
			}
#endif

			plog(LLV_INFO, LOCATION, NULL,
				"accept a request to establish IKE-SA: "
				"%s\n", saddrwop2str(dst));

			/* begin ident mode */
			ph1 = isakmp_ph1begin_i(rmconf, dst, src);
			if (ph1 == NULL)
				break;

			event_list = &ph1->evt_listeners;
			l_ac_errno = 0;
			break;
		}
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP: {
			struct ph2handle *iph2;
			struct secpolicy *sp_out = NULL, *sp_in = NULL;
			struct policyindex spidx;

			l_ac_errno = -1;

			/* got outbound policy */
			memset(&spidx, 0, sizeof(spidx));
			spidx.dir = IPSEC_DIR_OUTBOUND;
			memcpy(&spidx.src, src, sizeof(spidx.src));
			memcpy(&spidx.dst, dst, sizeof(spidx.dst));
			spidx.prefs = ndx->prefs;
			spidx.prefd = ndx->prefd;
			spidx.ul_proto = ndx->ul_proto;

			sp_out = getsp_r(&spidx);
			if (sp_out) {
				plog(LLV_DEBUG, LOCATION, NULL,
					"suitable outbound SP found: %s.\n",
					spidx2str(&sp_out->spidx));
			} else {
				l_ac_errno = ENOENT;
				plog(LLV_NOTIFY, LOCATION, NULL,
					"no outbound policy found: %s\n",
					spidx2str(&spidx));
				break;
			}

			iph2 = getph2byid(src, dst, sp_out->id);
			if (iph2 != NULL) {
				event_list = &iph2->evt_listeners;
				if (iph2->status == PHASE2ST_ESTABLISHED)
					l_ac_errno = EEXIST;
				else
					l_ac_errno = 0;
				break;
			}

			/* get inbound policy */
			memset(&spidx, 0, sizeof(spidx));
			spidx.dir = IPSEC_DIR_INBOUND;
			memcpy(&spidx.src, dst, sizeof(spidx.src));
			memcpy(&spidx.dst, src, sizeof(spidx.dst));
			spidx.prefs = ndx->prefd;
			spidx.prefd = ndx->prefs;
			spidx.ul_proto = ndx->ul_proto;

			sp_in = getsp_r(&spidx);
			if (sp_in) {
				plog(LLV_DEBUG, LOCATION, NULL,
					"suitable inbound SP found: %s.\n",
					spidx2str(&sp_in->spidx));
			} else {
				l_ac_errno = ENOENT;
				plog(LLV_NOTIFY, LOCATION, NULL,
					"no inbound policy found: %s\n",
				spidx2str(&spidx));
				break;
			}

			/* allocate a phase 2 */
			iph2 = newph2();
			if (iph2 == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
					"failed to allocate phase2 entry.\n");
				break;
			}
			iph2->side = INITIATOR;
			iph2->satype = admin2pfkey_proto(com->ac_proto);
			iph2->spid = sp_out->id;
			iph2->seq = pk_getseq();
			iph2->status = PHASE2ST_STATUS2;

                        if (sp_out->local && sp_out->remote) {
                            /* hints available, let's use them */
                            iph2->sa_dst = dupsaddr(dst);
                            iph2->sa_src = dupsaddr(src);
                            iph2->src = dupsaddr((struct sockaddr *)sp_out->local);
                            iph2->dst = dupsaddr((struct sockaddr *)sp_out->remote);
                        } else if (sp_out->req && sp_out->req->saidx.mode == IPSEC_MODE_TUNNEL) {
                            /* Tunnel mode and no hint, use endpoints */
                            iph2->src = dupsaddr((struct sockaddr *)&sp_out->req->saidx.src);
                            iph2->dst = dupsaddr((struct sockaddr *)&sp_out->req->saidx.dst);
                        } else {
                            /* default, use selectors as fallback */
                            iph2->sa_dst = dupsaddr(dst);
                            iph2->sa_src = dupsaddr(src);
                            iph2->dst = dupsaddr(dst);
                            iph2->src = dupsaddr(src);
                        }

                        if (iph2->dst == NULL || iph2->src == NULL) {
                            delph2(iph2);
                            break;
                        }
                        set_port(iph2->dst, 0);
                        set_port(iph2->src, 0);

			if (isakmp_get_sainfo(iph2, sp_out, sp_in) < 0) {
				delph2(iph2);
				break;
			}

			insph2(iph2);
			if (isakmp_post_acquire(iph2, NULL, FALSE) < 0) {
				remph2(iph2);
				delph2(iph2);
				break;
			}

			event_list = &iph2->evt_listeners;
			l_ac_errno = 0;
			break;
		}
		default:
			/* ignore */
			l_ac_errno = ENOTSUP;
		}
		break;
	}

	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid command: %d\n", com->ac_cmd);
		l_ac_errno = ENOTSUP;
	}

	if ((error = admin_reply(so2, com, l_ac_errno, buf)) != 0)
		goto out;

	/* start pushing events if so requested */
	if ((l_ac_errno == 0) &&
	    (com->ac_version >= 1) &&
	    (com->ac_cmd == ADMIN_SHOW_EVT || event_list != NULL))
		error = evt_subscribe(event_list, so2);
out:
	if (buf != NULL)
		vfree(buf);
	/*
	 * ADMIN_ESTABLISH_SA_PSK's id/key (XAUTH login/password supplied
	 * for this connection attempt, despite the command's name -- see
	 * the ADMIN_PROTO_ISAKMP case above) are freed here rather than at
	 * each of their several early-exit points (an existing ph1, no
	 * matching rmconf, xauth_rmconf_used() failing, a non-ISAKMP proto
	 * after PSK's FALLTHROUGH, an unrecognized command/proto, or simply
	 * ENABLE_HYBRID not being compiled in) -- every one of those used to
	 * leak both allocations. The one path that *doesn't* want them freed
	 * here already transfers ownership to rmconf->xauth->login/pass and
	 * NULLs both locals immediately after, so vfree()'s existing
	 * NULL-tolerance is what makes a single unconditional cleanup point
	 * safe for every other path.
	 */
	vfree(id);
	vfree(key);

	return error;
}

#ifdef ENABLE_UNITTEST
/*
 * admin_process() is static, and its ADMIN_DELETE_ALL_SA_DST case (the
 * reply-before-subscribe/no-dangling-fd fix documented above) is otherwise
 * reachable only through admin_handler()'s full accept()/recv() path, which
 * a unit test has no need to reconstruct. This thin wrapper lets a test
 * hand it a pre-built command buffer directly and drive the real dispatch
 * logic (including the real admin_reply() call it makes internally) over
 * a plain socketpair standing in for the admin socket connection.
 */
int
admin_process_unittest(int so2, char *combuf)
{
	return admin_process(so2, combuf);
}
#endif /* ENABLE_UNITTEST */

static int
admin_reply(int so, struct admin_com *req, int l_ac_errno, vchar_t *buf)
{
	int tlen;
	size_t sent;
	ssize_t n;
	struct admin_com *combuf;
	char *retbuf = NULL;

	if (buf != NULL)
		tlen = sizeof(*combuf) + buf->l;
	else
		tlen = sizeof(*combuf);

	retbuf = racoon_calloc(1, tlen);
	if (retbuf == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate admin buffer\n");
		return -1;
	}

	combuf = (struct admin_com *) retbuf;
	combuf->ac_len = (u_int16_t) tlen;
	combuf->ac_cmd = req->ac_cmd & ~ADMIN_FLAG_VERSION;
	if (tlen != (u_int32_t) combuf->ac_len &&
	    l_ac_errno == 0) {
		combuf->ac_len_high = tlen >> 16;
		combuf->ac_cmd |= ADMIN_FLAG_LONG_REPLY;
	} else {
		combuf->ac_errno = l_ac_errno;
	}
	combuf->ac_proto = req->ac_proto;

	if (buf != NULL)
		memcpy(retbuf + sizeof(*combuf), buf->v, buf->l);

	/* A single send() may legally return fewer bytes than requested on
	 * this SOCK_STREAM socket (admin_init(), AF_UNIX/SOCK_STREAM) once
	 * the reply exceeds the kernel's per-call transfer capacity -- no
	 * existing admin reply was ever big enough to hit this in practice,
	 * but ADMIN_STATUS/ADMIN_STATUS_VERBOSE's JSON replies (status.c)
	 * can be, and a silently truncated send here means truncated,
	 * invalid JSON on the wire. Loop until the whole reply is written,
	 * mirroring com_recv()'s existing recv() loop on the client side
	 * (kmpstat.c). See doc/dev/racoonctl-status-analysis.md Finding H-4
	 * / issue #139. */
	for (sent = 0; sent < (size_t)tlen; sent += (size_t)n) {
		n = send(so, retbuf + sent, (size_t)tlen - sent, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			plog(LLV_ERROR, LOCATION, NULL,
				"failed to send admin command: %s\n",
				strerror(errno));
			racoon_free(retbuf);
			return -1;
		}
		if (n == 0)
			break;
	}
	racoon_free(retbuf);

	return 0;
}

/* ADMIN_PROTO -> SADB_SATYPE */
int
admin2pfkey_proto(u_int proto)
{
	switch (proto) {
	case ADMIN_PROTO_IPSEC:
		return SADB_SATYPE_UNSPEC;
	case ADMIN_PROTO_AH:
		return SADB_SATYPE_AH;
	case ADMIN_PROTO_ESP:
		return SADB_SATYPE_ESP;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"unsupported proto for admin: %d\n", proto);
		return -1;
	}
	/*NOTREACHED*/
}

int
admin_init(void)
{
	if (adminsock_path == NULL) {
		lcconf->sock_admin = -1;
		return 0;
	}

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path),
		"%s", adminsock_path);

	if (admin_check_sockpath(sunaddr.sun_path) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"refusing admin socket path \"%s\": the file name "
			"must be \"racoon.sock\" or end with \".sock\"/"
			"\".socket\", and must not contain \"..\" "
			"components\n", sunaddr.sun_path);
		return -1;
	}

	/*
	 * The runtime directory (e.g. /var/run/racoon) may not exist yet:
	 * systemd's RuntimeDirectory= only creates it while the unit is
	 * running, and nothing recreates it when racoon is started
	 * manually (e.g. in foreground, for debugging). Create it here so
	 * admin_init() does not depend on external tooling.
	 *
	 * Ownership is set explicitly afterwards, unconditionally -- not
	 * only when mkdir_p() just created it. Whatever created this
	 * directory (systemd's RuntimeDirectory=, a distribution's
	 * tmpfiles.d entry, or mkdir_p() just above) has no idea which
	 * group, if any, this specific "listen { adminsock ... group ...
	 * }" directive grants access to; only this code does. This also
	 * has to be reasserted here even when the directory pre-exists
	 * with the wrong group: systemd's own RuntimeDirectory= handling
	 * reconciles ownership against the unit's User=/Group= (unset, so
	 * root:root) before *every* process it spawns for the unit, so a
	 * one-time fixup from outside racoon (e.g. an ExecStartPre chgrp)
	 * is silently undone again before ExecStart itself runs -- this
	 * runs from inside the already-spawned, still-root racoon process
	 * instead, which nothing spawned afterward can revert.
	 */
	{
		char dir[MAXPATHLEN];
		char *slash;

		strlcpy(dir, sunaddr.sun_path, sizeof(dir));
		slash = strrchr(dir, '/');
		if (slash != NULL && slash != dir) {
			*slash = '\0';
			if (mkdir_p(dir, 0750) != 0) {
				plog(LLV_ERROR, LOCATION, NULL,
					"failed to create admin socket "
					"directory %s: %s\n",
					dir, strerror(errno));
				return -1;
			}

			if (chown(dir, 0, adminsock_group) != 0) {
				plog(LLV_ERROR, LOCATION, NULL,
					"chown(%s, 0, %d): %s\n",
					dir, adminsock_group, strerror(errno));
				return -1;
			}

			if (chmod(dir, 0750) != 0) {
				plog(LLV_ERROR, LOCATION, NULL,
					"chmod(%s, 0750): %s\n",
					dir, strerror(errno));
				return -1;
			}
		}
	}

	lcconf->sock_admin = socket(AF_UNIX, SOCK_STREAM, 0);
	if (lcconf->sock_admin == -1) {
		plog(LLV_ERROR, LOCATION, NULL,
			"socket: %s\n", strerror(errno));
		return -1;
	}
	close_on_exec(lcconf->sock_admin);

	/*
	 * Only remove a pre-existing path if it is already a socket.
	 * This keeps a misconfigured/traversal-crafted path (or a
	 * symlink swapped in between checks) from causing racoon to
	 * unlink and overwrite an unrelated file.
	 */
	{
		struct stat st;

		if (lstat(sunaddr.sun_path, &st) == 0) {
			if (!S_ISSOCK(st.st_mode)) {
				plog(LLV_ERROR, LOCATION, NULL,
					"refusing to bind admin socket: "
					"%s already exists and is not a "
					"socket\n", sunaddr.sun_path);
				(void)close(lcconf->sock_admin);
				return -1;
			}
			unlink(sunaddr.sun_path);
		} else if (errno != ENOENT) {
			plog(LLV_ERROR, LOCATION, NULL,
				"lstat(%s): %s\n",
				sunaddr.sun_path, strerror(errno));
			(void)close(lcconf->sock_admin);
			return -1;
		}
	}

	if (bind(lcconf->sock_admin, (struct sockaddr *)&sunaddr,
			sizeof(sunaddr)) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"bind(sockname:%s): %s\n",
			sunaddr.sun_path, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (chown(sunaddr.sun_path, adminsock_owner, adminsock_group) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "chown(%s, %d, %d): %s\n",
		    sunaddr.sun_path, adminsock_owner,
		    adminsock_group, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (chmod(sunaddr.sun_path, adminsock_mode) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "chmod(%s, 0%03o): %s\n",
		    sunaddr.sun_path, adminsock_mode, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (listen(lcconf->sock_admin, 5) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"listen(sockname:%s): %s\n",
			sunaddr.sun_path, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (monitor_fd(lcconf->sock_admin, admin_handler, NULL, 0) != 0) {
		(void)close(lcconf->sock_admin);
		lcconf->sock_admin = -1;
		return -1;
	}
	plog(LLV_DEBUG, LOCATION, NULL,
	     "open %s as racoon management.\n", sunaddr.sun_path);

	return 0;
}

int
admin_close(void)
{
	if (lcconf->sock_admin != -1) {
		unmonitor_fd(lcconf->sock_admin);
		close(lcconf->sock_admin);
	}
	return 0;
}

#endif
