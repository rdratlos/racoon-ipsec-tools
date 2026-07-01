/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors.
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "var.h"
#include "vmbuf.h"
#include "misc.h"
#include "plog.h"
#include "handler.h"
#include "kernelpaws.h"

static int xfrm_init __P((void));
static int xfrm_reload __P((void));
static int xfrm_checkalg __P((int, int, int));
static int xfrm_sendgetspi __P((struct ph2handle *));
static int xfrm_sendupdate __P((struct ph2handle *));
static int xfrm_sendadd __P((struct ph2handle *));
static int xfrm_sendeacquire __P((struct ph2handle *));
static int xfrm_sendspdadd2 __P((struct ph2handle *));
static int xfrm_sendspdupdate2 __P((struct ph2handle *));
static int xfrm_sendspddelete __P((struct ph2handle *));
static u_int32_t xfrm_getseq __P((void));
static vchar_t *xfrm_dump_sadb __P((int));
static void xfrm_flush_sadb __P((u_int));
static u_int xfrm_backend2doi_proto __P((u_int));
static u_int xfrm_doi2backend_proto __P((u_int));
static u_int xfrm_backend2doi_mode __P((u_int));
static u_int xfrm_doi2backend_mode __P((u_int));
static void xfrm_fixup_sa_addresses __P((caddr_t *));
static const char *xfrm_secas2str
    __P((struct sockaddr *, struct sockaddr *, int, u_int32_t, int));

static int
xfrm_init()
{
	return -1;
}

static int
xfrm_reload()
{
	return -1;
}

static int
xfrm_checkalg(algclass, algtype, keylen)
	int algclass;
	int algtype;
	int keylen;
{
	return -1;
}

static int
xfrm_sendgetspi(ph2)
	struct ph2handle *ph2;
{
	return -1;
}

static int
xfrm_sendupdate(ph2)
	struct ph2handle *ph2;
{
	return -1;
}

static int
xfrm_sendadd(ph2)
	struct ph2handle *ph2;
{
	return -1;
}

static int
xfrm_sendeacquire(ph2)
	struct ph2handle *ph2;
{
	return -1;
}

static int
xfrm_sendspdadd2(ph2)
	struct ph2handle *ph2;
{
	return -1;
}

static int
xfrm_sendspdupdate2(ph2)
	struct ph2handle *ph2;
{
	return -1;
}

static int
xfrm_sendspddelete(ph2)
	struct ph2handle *ph2;
{
	return -1;
}

static u_int32_t
xfrm_getseq()
{
	return 0;
}

static vchar_t *
xfrm_dump_sadb(dummy)
	int dummy;
{
	return NULL;
}

static void
xfrm_flush_sadb(satype)
	u_int satype;
{
}

static u_int
xfrm_backend2doi_proto(proto)
	u_int proto;
{
	return 0;
}

static u_int
xfrm_doi2backend_proto(proto)
	u_int proto;
{
	return 0;
}

static u_int
xfrm_backend2doi_mode(mode)
	u_int mode;
{
	return 0;
}

static u_int
xfrm_doi2backend_mode(mode)
	u_int mode;
{
	return 0;
}

static void
xfrm_fixup_sa_addresses(mhp)
	caddr_t *mhp;
{
}

static const char *
xfrm_secas2str(src, dst, proto, spi, satype)
	struct sockaddr *src;
	struct sockaddr *dst;
	int proto;
	u_int32_t spi;
	int satype;
{
	return "";
}

static const struct kernelpaws_ops xfrm_backend = {
	.init = xfrm_init,
	.reload = xfrm_reload,
	.checkalg = xfrm_checkalg,
	.sendgetspi = xfrm_sendgetspi,
	.sendupdate = xfrm_sendupdate,
	.sendadd = xfrm_sendadd,
	.sendeacquire = xfrm_sendeacquire,
	.sendspdadd2 = xfrm_sendspdadd2,
	.sendspdupdate2 = xfrm_sendspdupdate2,
	.sendspddelete = xfrm_sendspddelete,
	.getseq = xfrm_getseq,
	.dump_sadb = xfrm_dump_sadb,
	.flush_sadb = xfrm_flush_sadb,
	.backend2doi_proto = xfrm_backend2doi_proto,
	.doi2backend_proto = xfrm_doi2backend_proto,
	.backend2doi_mode = xfrm_backend2doi_mode,
	.doi2backend_mode = xfrm_doi2backend_mode,
	.fixup_sa_addresses = xfrm_fixup_sa_addresses,
	.secas2str = xfrm_secas2str,
};

const struct kernelpaws_ops *get_kernelpaws_xfrm_backend(void)
{
	return &xfrm_backend;
}