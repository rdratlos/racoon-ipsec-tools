/*	$NetBSD: privsep.h,v 1.6 2008/12/08 06:00:54 tteras Exp $	*/

/* Id: privsep.h,v 1.5 2005/06/07 12:22:11 fredsen Exp */

/*
 * Copyright (C) 2004 Emmanuel Dreyfus
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

#ifndef _PRIVSEP_H
#define _PRIVSEP_H

#define PRIVSEP_EAY_GET_PKCS1PRIVKEY	0x0801	/* admin_com_bufs follows */
#define PRIVSEP_SCRIPT_EXEC		0x0803	/* admin_com_bufs follows */
#define PRIVSEP_GETPSK			0x0804	/* admin_com_bufs follows */
#define PRIVSEP_XAUTH_LOGIN_SYSTEM	0x0805	/* admin_com_bufs follows */
#define PRIVSEP_ACCOUNTING_PAM		0x0806	/* admin_com_bufs follows */
#define PRIVSEP_XAUTH_LOGIN_PAM		0x0807	/* admin_com_bufs follows */
#define PRIVSEP_CLEANUP_PAM		0x0808	/* admin_com_bufs follows */
#define PRIVSEP_ACCOUNTING_SYSTEM	0x0809	/* admin_com_bufs follows */
#define PRIVSEP_SETSOCKOPTS		0x080A	/* admin_com_bufs follows */
#define PRIVSEP_BIND			0x080B	/* admin_com_bufs follows */
#define PRIVSEP_SOCKET			0x080C	/* admin_com_bufs follows */

/*
 * OR'd into ac_cmd alongside PRIVSEP_SCRIPT_EXEC: ask the privileged
 * process's script_exec() to wait, bounded, for this hook invocation
 * (daemon-issues.md Issue 1). A dedicated ac_cmd bit rather than an extra
 * envp entry, deliberately -- envp is marshaled into the same
 * PRIVSEP_NBUF_MAX-slot admin_com_bufs as script/name/envp below, so an
 * extra entry there contends with a config's own env vars (modecfg,
 * split-DNS) for that fixed budget instead of being free. Must not
 * collide with any PRIVSEP_* command value above, nor with
 * ADMIN_FLAG_VERSION/ADMIN_FLAG_LONG_REPLY (admin.h, 0x8000) since both
 * share the same ac_cmd wire field type.
 */
#define PRIVSEP_SCRIPT_EXEC_WAIT	0x1000

#define PRIVSEP_NBUF_MAX 24
#define PRIVSEP_BUFLEN_MAX 4096
struct admin_com_bufs {
	size_t buflen[PRIVSEP_NBUF_MAX];
	/* Followed by the buffers */
};

/*
 * PRIVSEP_SCRIPT_EXEC's wire budget accounting (daemon-issues.md's Issue
 * 4 follow-up): a PRIVSEP_SCRIPT_EXEC message packs script, name, every
 * envp[] entry, and a void terminator into the PRIVSEP_NBUF_MAX slots of
 * one admin_com_bufs above -- 3 fixed slots plus one per env var.
 *
 * The envp[] entries come from two fixed-shape call sequences that never
 * vary with anything a peer controls: script_hook()'s own explicit
 * script_env_append() calls (isakmp.c -- LOCAL_ADDR, LOCAL_PORT,
 * REMOTE_ADDR, REMOTE_PORT, REMOTE_ID, IKE_COOKIE, i.e. exactly 6), and,
 * under ENABLE_HYBRID, isakmp_cfg_setenv()'s (isakmp_cfg.c -- 14
 * unconditional plus XAUTH_USER when Xauth creds exist, i.e. up to 15).
 * Every list-shaped mode-config attribute (DNS servers, split-include/
 * -local networks, split-DNS domains) is joined into a single string
 * before being handed to script_env_append() -- never iterated into one
 * entry per item -- so a peer can make any one of these entries longer,
 * but never add more of them. This was already a one-slot-from-the-
 * ceiling landmine once: PR #94's RACOON_SCRIPT_WAIT envp entry pushed
 * the fixed count from 21 to 22 and hit this exact ceiling on a real
 * split-DNS mode-config connection.
 *
 * SCRIPT_HOOK_MAX_ENVC / ISAKMP_CFG_SETENV_MAX_ENVC below must be kept in
 * sync by hand with the actual script_env_append() call counts in
 * isakmp.c/isakmp_cfg.c -- C's preprocessor cannot derive this from the
 * calls themselves. The static assertion in isakmp.c
 * (PRIVSEP_SCRIPT_EXEC_MAX_ENVC_FITS_WIRE_BUDGET) ties their sum back to
 * PRIVSEP_NBUF_MAX, so adding one more script_env_append() call anywhere
 * without updating the matching count here fails the build instead of
 * silently reintroducing this same landmine.
 */
#define SCRIPT_HOOK_MAX_ENVC		6
#define ISAKMP_CFG_SETENV_MAX_ENVC	15
#ifdef ENABLE_HYBRID
#define PRIVSEP_SCRIPT_EXEC_MAX_ENVC \
    (SCRIPT_HOOK_MAX_ENVC + ISAKMP_CFG_SETENV_MAX_ENVC)
#else
#define PRIVSEP_SCRIPT_EXEC_MAX_ENVC SCRIPT_HOOK_MAX_ENVC
#endif

struct privsep_com_msg {
	struct admin_com hdr;
	struct admin_com_bufs bufs;
};

int privsep_init __P((void));

/*
 * The privileged dispatch loop itself, extracted out of privsep_init() so
 * it can be driven directly -- by privsep_init() over privsep_sock[0] in
 * production, and by a unit test over a plain socketpair() (see
 * test/test_privsep_priv_dispatch.c and doc/dev/privsep-priv-extraction.md).
 * Never returns: every path out of it ends in _exit(0) (an ordinary
 * shutdown) or _exit(1) (a fault), exactly as when this was still
 * privsep_init()'s inline while(1) loop.
 */
int privsep_priv __P((int));

vchar_t *privsep_eay_get_pkcs1privkey __P((char *));
int privsep_script_exec __P((char *, int, char * const *, int));
int privsep_setsockopt __P((int, int, int, const void *, socklen_t));
int privsep_socket __P((int, int, int));
int privsep_bind __P((int, const struct sockaddr *, socklen_t));
vchar_t *privsep_getpsk __P((const char *, const int));
int privsep_xauth_login_system __P((char *, char *));
#ifdef HAVE_LIBPAM
int privsep_accounting_pam __P((int, int));
int privsep_xauth_login_pam __P((int, struct sockaddr *, char *, char *));
void privsep_cleanup_pam __P((int));
#endif
int privsep_accounting_system __P((int, struct sockaddr *, char *, int));
#endif /* _PRIVSEP_H */
