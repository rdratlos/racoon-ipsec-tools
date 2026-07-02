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
#include "kernelpaws.h"

extern const struct kernelpaws_ops *get_kernelpaws_pfkeyv2_backend __P((void));
#ifdef HAVE_XFRM
extern const struct kernelpaws_ops *get_kernelpaws_xfrm_backend __P((void));
#endif

const struct kernelpaws_ops *kernelpaws_backend = NULL;

int
kernelpaws_init()
{
	if (kernelpaws_backend == NULL)
		return -1;
	return kernelpaws_backend->init();
}

int
kernelpaws_reload()
{
	if (kernelpaws_backend == NULL)
		return -1;
	return kernelpaws_backend->reload();
}

int
kernelpaws_register_fd()
{
	if (kernelpaws_backend == NULL)
		return -1;
	return 0;
}

void
kernelpaws_select_backend_pfkeyv2()
{
	kernelpaws_backend = get_kernelpaws_pfkeyv2_backend();
}

#ifdef HAVE_XFRM
void
kernelpaws_select_backend_xfrm()
{
	kernelpaws_backend = get_kernelpaws_xfrm_backend();
}
#endif