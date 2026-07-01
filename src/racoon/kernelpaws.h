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

#ifndef _KERNELPAWS_H
#define _KERNELPAWS_H

#include "vmbuf.h"

struct ph2handle;

struct kernelpaws_ops {
		int (*init)(void);
		int (*reload)(void);
		int (*checkalg)(int, int, int);
		int (*sendgetspi)(struct ph2handle *);
		int (*sendupdate)(struct ph2handle *);
		int (*sendadd)(struct ph2handle *);
		int (*sendeacquire)(struct ph2handle *);
		int (*sendspdadd2)(struct ph2handle *);
		int (*sendspdupdate2)(struct ph2handle *);
		int (*sendspddelete)(struct ph2handle *);
		u_int32_t (*getseq)(void);
		vchar_t *(*dump_sadb)(int);
		void (*flush_sadb)(u_int);
		u_int (*backend2doi_proto)(u_int);
		u_int (*doi2backend_proto)(u_int);
		u_int (*backend2doi_mode)(u_int);
		u_int (*doi2backend_mode)(u_int);
		void (*fixup_sa_addresses)(caddr_t *);
		const char *(*secas2str)(struct sockaddr *, struct sockaddr *,
		    int, u_int32_t, int);
	};

extern const struct kernelpaws_ops *kernelpaws_backend;

extern int kernelpaws_init __P((void));
extern int kernelpaws_reload __P((void));
extern int kernelpaws_register_fd __P((void));
extern void kernelpaws_select_backend_pfkeyv2 __P((void));

#endif /* _KERNELPAWS_H */