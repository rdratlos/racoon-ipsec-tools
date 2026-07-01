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
#include "localconf.h"
#include "session.h"
#include "handler.h"
#include "pfkey.h"
#include "kernelpaws.h"

static int kernelpaws_pfkeyv2_init __P((void));
static int kernelpaws_pfkeyv2_reload __P((void));
static int kernelpaws_pfkeyv2_checkalg __P((int, int, int));
static int kernelpaws_pfkeyv2_sendgetspi __P((struct ph2handle *));
static int kernelpaws_pfkeyv2_sendupdate __P((struct ph2handle *));
static int kernelpaws_pfkeyv2_sendadd __P((struct ph2handle *));
static int kernelpaws_pfkeyv2_sendeacquire __P((struct ph2handle *));
static int kernelpaws_pfkeyv2_sendspdadd2 __P((struct ph2handle *));
static int kernelpaws_pfkeyv2_sendspdupdate2 __P((struct ph2handle *));
static int kernelpaws_pfkeyv2_sendspddelete __P((struct ph2handle *));
static u_int32_t kernelpaws_pfkeyv2_getseq __P((void));
static vchar_t *kernelpaws_pfkeyv2_dump_sadb __P((int));
static void kernelpaws_pfkeyv2_flush_sadb __P((u_int));
static u_int kernelpaws_pfkeyv2_backend2doi_proto __P((u_int));
static u_int kernelpaws_pfkeyv2_doi2backend_proto __P((u_int));
static u_int kernelpaws_pfkeyv2_backend2doi_mode __P((u_int));
static u_int kernelpaws_pfkeyv2_doi2backend_mode __P((u_int));
static void kernelpaws_pfkeyv2_fixup_sa_addresses __P((caddr_t *));
static const char *kernelpaws_pfkeyv2_secas2str
    __P((struct sockaddr *, struct sockaddr *, int, u_int32_t, int));

static int
kernelpaws_pfkeyv2_init()
{
	return pfkey_init();
}

static int
kernelpaws_pfkeyv2_reload()
{
	return pfkey_reload();
}

static int
kernelpaws_pfkeyv2_checkalg(algclass, algtype, keylen)
	int algclass;
	int algtype;
	int keylen;
{
	return pk_checkalg(algclass, algtype, keylen);
}

static int
kernelpaws_pfkeyv2_sendgetspi(ph2)
	struct ph2handle *ph2;
{
	return pk_sendgetspi(ph2);
}

static int
kernelpaws_pfkeyv2_sendupdate(ph2)
	struct ph2handle *ph2;
{
	return pk_sendupdate(ph2);
}

static int
kernelpaws_pfkeyv2_sendadd(ph2)
	struct ph2handle *ph2;
{
	return pk_sendadd(ph2);
}

static int
kernelpaws_pfkeyv2_sendeacquire(ph2)
	struct ph2handle *ph2;
{
	return pk_sendeacquire(ph2);
}

static int
kernelpaws_pfkeyv2_sendspdadd2(ph2)
	struct ph2handle *ph2;
{
	return pk_sendspdadd2(ph2);
}

static int
kernelpaws_pfkeyv2_sendspdupdate2(ph2)
	struct ph2handle *ph2;
{
	return pk_sendspdupdate2(ph2);
}

static int
kernelpaws_pfkeyv2_sendspddelete(ph2)
	struct ph2handle *ph2;
{
	return pk_sendspddelete(ph2);
}

static u_int32_t
kernelpaws_pfkeyv2_getseq()
{
	return pk_getseq();
}

static vchar_t *
kernelpaws_pfkeyv2_dump_sadb(dummy)
	int dummy;
{
	return pfkey_dump_sadb(dummy);
}

static void
kernelpaws_pfkeyv2_flush_sadb(satype)
	u_int satype;
{
	pfkey_flush_sadb(satype);
}

static u_int
kernelpaws_pfkeyv2_backend2doi_proto(proto)
	u_int proto;
{
	return pfkey2ipsecdoi_proto(proto);
}

static u_int
kernelpaws_pfkeyv2_doi2backend_proto(proto)
	u_int proto;
{
	return ipsecdoi2pfkey_proto(proto);
}

static u_int
kernelpaws_pfkeyv2_backend2doi_mode(mode)
	u_int mode;
{
	return pfkey2ipsecdoi_mode(mode);
}

static u_int
kernelpaws_pfkeyv2_doi2backend_mode(mode)
	u_int mode;
{
	return ipsecdoi2pfkey_mode(mode);
}

static void
kernelpaws_pfkeyv2_fixup_sa_addresses(mhp)
	caddr_t *mhp;
{
	pk_fixup_sa_addresses(mhp);
}

static const char *
kernelpaws_pfkeyv2_secas2str(src, dst, proto, spi, satype)
	struct sockaddr *src;
	struct sockaddr *dst;
	int proto;
	u_int32_t spi;
	int satype;
{
	return sadbsecas2str(src, dst, proto, spi, satype);
}

static const struct kernelpaws_ops pfkeyv2_backend = {
	.init = kernelpaws_pfkeyv2_init,
	.reload = kernelpaws_pfkeyv2_reload,
	.checkalg = kernelpaws_pfkeyv2_checkalg,
	.sendgetspi = kernelpaws_pfkeyv2_sendgetspi,
	.sendupdate = kernelpaws_pfkeyv2_sendupdate,
	.sendadd = kernelpaws_pfkeyv2_sendadd,
	.sendeacquire = kernelpaws_pfkeyv2_sendeacquire,
	.sendspdadd2 = kernelpaws_pfkeyv2_sendspdadd2,
	.sendspdupdate2 = kernelpaws_pfkeyv2_sendspdupdate2,
	.sendspddelete = kernelpaws_pfkeyv2_sendspddelete,
	.getseq = kernelpaws_pfkeyv2_getseq,
	.dump_sadb = kernelpaws_pfkeyv2_dump_sadb,
	.flush_sadb = kernelpaws_pfkeyv2_flush_sadb,
	.backend2doi_proto = kernelpaws_pfkeyv2_backend2doi_proto,
	.doi2backend_proto = kernelpaws_pfkeyv2_doi2backend_proto,
	.backend2doi_mode = kernelpaws_pfkeyv2_backend2doi_mode,
	.doi2backend_mode = kernelpaws_pfkeyv2_doi2backend_mode,
	.fixup_sa_addresses = kernelpaws_pfkeyv2_fixup_sa_addresses,
	.secas2str = kernelpaws_pfkeyv2_secas2str,
};

const struct kernelpaws_ops *get_kernelpaws_pfkeyv2_backend(void)
{
	return &pfkeyv2_backend;
}