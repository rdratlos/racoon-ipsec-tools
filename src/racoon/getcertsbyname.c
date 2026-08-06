/*	$NetBSD: getcertsbyname.c,v 1.4 2006/09/09 16:22:09 manu Exp $	*/

/*	$KAME: getcertsbyname.c,v 1.7 2001/11/16 04:12:59 sakane Exp $	*/

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

#include <netinet/in.h>
#include <arpa/nameser.h>
#if (defined(__APPLE__) && defined(__MACH__))
# include <nameser8_compat.h>
#endif
#include <resolv.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef DNSSEC_DEBUG
#include <stdio.h>
#include <strings.h>
#endif

#include "netdb_dnssec.h"

/* XXX should it use ci_errno to hold errno instead of h_errno ? */
extern int h_errno;

static struct certinfo *getnewci __P((int, int, int, int, int, 
			unsigned char *));

static struct certinfo *
getnewci(int qtype, int keytag, int algorithm, int flags, int certlen, unsigned char *cert)
{
	struct certinfo *res;

	res = malloc(sizeof(*res));
	if (!res)
		return NULL;

	memset(res, 0, sizeof(*res));
	res->ci_type = qtype;
	res->ci_keytag = keytag;
	res->ci_algorithm = algorithm;
	res->ci_flags = flags;
	res->ci_certlen = certlen;
	res->ci_cert = malloc(certlen);
	if (!res->ci_cert) {
		free(res);
		return NULL;
	}
	memcpy(res->ci_cert, cert, certlen);

	return res;
}

#ifdef ENABLE_UNITTEST
/*
 * getnewci() is static, and its only production caller (getcertsbyname()
 * below) needs a real DNS wire-format CERT RR to reach it at all. This
 * thin wrapper lets a unit test drive the certinfo-node allocation
 * itself directly, independent of DNS packet construction.
 */
struct certinfo *
getnewci_unittest(int qtype, int keytag, int algorithm, int flags, int certlen, unsigned char *cert)
{
	return getnewci(qtype, keytag, algorithm, flags, certlen, cert);
}
#endif /* ENABLE_UNITTEST */

void
freecertinfo(struct certinfo *ci)
{
	struct certinfo *next;

	do {
		next = ci->ci_next;
		if (ci->ci_cert)
			free(ci->ci_cert);
		free(ci);
		ci = next;
	} while (ci);
}

/*
 * Validates and parses a raw DNS response buffer (as returned by
 * res_query()) into a certinfo chain. Split out of getcertsbyname()
 * (pure code motion, no behavior change) so this -- the security-
 * relevant half of the file, including the DNSSEC Authenticated Data
 * bit check -- can be driven directly by a unit test with a hand-built
 * response buffer, without needing to intercept res_query()/res_init()
 * themselves. Those two are notably not portable interposition targets:
 * -Wl,--wrap=res_query/--wrap=res_init (this file's earlier test
 * approach) silently failed to redirect calls to them on Ubuntu Bionic
 * 32-bit, where the older glibc/binutils toolchain apparently does not
 * treat these libresolv symbols the same way -Wl,--wrap already
 * reliably handles elsewhere in this test suite for ordinary libc
 * symbols (free(), fork(), _exit()) -- res_query()/res_init() have a
 * messier, more version-dependent history (originally libresolv-only,
 * partially merged into libc across different glibc eras) that this
 * apparently exposed. Two of the four affected tests still reported
 * PASS on that platform despite this: both expected getcertsbyname() to
 * reject its input, which the real (network-dependent, therefore
 * failing outright in a sandboxed test run) res_query()/res_init() did
 * too, just not for the reason the test intended -- the same class of
 * false-positive-pass this project's own test_admin_init.c review
 * already caught once for an unrelated reason (a privilege-gated
 * chown() short-circuiting before the logic under test could run).
 */
static int
parse_cert_answer(unsigned char *answer, int anslen, struct certinfo **res)
{
	HEADER *hp;
	int qdcount, ancount, rdlength, len;
	unsigned char *cp, *eom;
	char hostbuf[1024];	/* XXX */
	int qtype, qclass, keytag, algorithm;
	struct certinfo head, *cur;
	int error = -1;

	*res = NULL;
	memset(&head, 0, sizeof(head));
	cur = &head;

	eom = answer + anslen;

	hp = (HEADER *)answer;
	qdcount = ntohs(hp->qdcount);
	ancount = ntohs(hp->ancount);

	/*
	 * Require the DNSSEC Authenticated Data (AD) bit. The
	 * Authoritative Answer (AA) bit is not a DNSSEC validation
	 * signal -- it only means the responder claims authority for
	 * the zone -- and must never be accepted as a substitute proof
	 * of DNSSEC validation.
	 */
	if (hp->ad == 0) {
#ifdef DNSSEC_DEBUG
		printf("answer is not DNSSEC validated.\n");
#endif
		h_errno = NO_RECOVERY;
		goto end;
	}

	/* question section */
	if (qdcount != 1) {
#ifdef DNSSEC_DEBUG
		printf("query count is not 1.\n");
#endif
		h_errno = NO_RECOVERY;
		goto end;
	}
	cp = (unsigned char *)(hp + 1);
	len = dn_expand(answer, eom, cp, hostbuf, sizeof(hostbuf));
	if (len < 0) {
#ifdef DNSSEC_DEBUG
		printf("dn_expand failed.\n");
#endif
		goto end;
	}
	cp += len;
	GETSHORT(qtype, cp);		/* QTYPE */
	GETSHORT(qclass, cp);		/* QCLASS */

	/* answer section */
	while (ancount-- && cp < eom) {
		len = dn_expand(answer, eom, cp, hostbuf, sizeof(hostbuf));
		if (len < 0) {
#ifdef DNSSEC_DEBUG
			printf("dn_expand failed.\n");
#endif
			goto end;
		}
		cp += len;
		GETSHORT(qtype, cp);	/* TYPE */
		GETSHORT(qclass, cp);	/* CLASS */
		cp += INT32SZ;		/* TTL */
		GETSHORT(rdlength, cp);	/* RDLENGTH */

		/* CERT RR */
		if (qtype != T_CERT) {
#ifdef DNSSEC_DEBUG
			printf("not T_CERT\n");
#endif
			h_errno = NO_RECOVERY;
			goto end;
		}
		GETSHORT(qtype, cp);	/* type */
		rdlength -= INT16SZ;
		GETSHORT(keytag, cp);	/* key tag */
		rdlength -= INT16SZ;
		algorithm = *cp++;	/* algorithm */
		rdlength -= 1;
		if (cp + rdlength > eom) {
#ifdef DNSSEC_DEBUG
			printf("rdlength is too long.\n");
#endif
			h_errno = NO_RECOVERY;
			goto end;
		}
#ifdef DNSSEC_DEBUG
		printf("type=%d keytag=%d alg=%d len=%d\n",
			qtype, keytag, algorithm, rdlength);
#endif

		/* create new certinfo */
		cur->ci_next = getnewci(qtype, keytag, algorithm,
					0, rdlength, cp);
		if (!cur->ci_next) {
#ifdef DNSSEC_DEBUG
			printf("getnewci: %s", strerror(errno));
#endif
			h_errno = NO_RECOVERY;
			goto end;
		}
		cur = cur->ci_next;

		cp += rdlength;
	}

	*res = head.ci_next;
	error = 0;

end:
	if (error && head.ci_next)
		freecertinfo(head.ci_next);

	return error;
}

#ifdef ENABLE_UNITTEST
/*
 * parse_cert_answer() is static; this thin wrapper lets a unit test
 * drive it directly against a hand-built DNS response buffer. See
 * parse_cert_answer()'s own header comment for why this exists instead
 * of intercepting res_query()/res_init().
 */
int
parse_cert_answer_unittest(unsigned char *answer, int anslen, struct certinfo **res)
{
	return parse_cert_answer(answer, anslen, res);
}
#endif /* ENABLE_UNITTEST */

/*
 * get CERT RR by FQDN and create certinfo structure chain.
 */
int
getcertsbyname(char *name, struct certinfo **res)
{
	unsigned char *answer = NULL, *p;
	int buflen, anslen;
	struct __res_state *_resp = &_res;
	u_long _res_options = 0;
	int error = -1;

	/* initialize res */
	*res = NULL;

	/* get CERT RR */
	/* Bit bang _res libc resolver global, we are single threaded */
	if ((_resp->options & RES_INIT) == 0 && res_init() == -1) {
		goto end;
	}
	_res_options = _resp->options;
	_resp->options |= (RES_USE_EDNS0|RES_USE_DNSSEC);
	buflen = 512;
	do {

		buflen *= 2;
		p = realloc(answer, buflen);
		if (!p) {
#ifdef DNSSEC_DEBUG
			printf("realloc: %s", strerror(errno));
#endif
			h_errno = NO_RECOVERY;
			goto end;
		}
		answer = p;

		anslen = res_query(name,  C_IN, T_CERT, answer, buflen);
		if (anslen == -1)
			goto end;

	} while (buflen < anslen);
	/* Undo resolver options */
	_resp->options = _res_options;

#ifdef DNSSEC_DEBUG
	printf("get a DNS packet len=%d\n", anslen);
#endif

	error = parse_cert_answer(answer, anslen, res);

end:
	if (answer)
		free(answer);

	return error;
}

#ifdef DNSSEC_DEBUG
int
b64encode(char *p, int len)
{
	static const char b64t[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/=";

	while (len > 2) {
                printf("%c", b64t[(p[0] >> 2) & 0x3f]);
                printf("%c", b64t[((p[0] << 4) & 0x30) | ((p[1] >> 4) & 0x0f)]);
                printf("%c", b64t[((p[1] << 2) & 0x3c) | ((p[2] >> 6) & 0x03)]);
                printf("%c", b64t[p[2] & 0x3f]);
		len -= 3;
		p += 3;
	}

	if (len == 2) {
                printf("%c", b64t[(p[0] >> 2) & 0x3f]);
                printf("%c", b64t[((p[0] << 4) & 0x30)| ((p[1] >> 4) & 0x0f)]);
                printf("%c", b64t[((p[1] << 2) & 0x3c)]);
                printf("%c", '=');
        } else if (len == 1) {
                printf("%c", b64t[(p[0] >> 2) & 0x3f]);
                printf("%c", b64t[((p[0] << 4) & 0x30)]);
                printf("%c", '=');
                printf("%c", '=');
	}

	return 0;
}

int
main(int ac, char **av)
{
	struct certinfo *res, *p;
	int i;

	if (ac < 2) {
		printf("Usage: a.out (FQDN)\n");
		exit(1);
	}

	i = getcertsbyname(*(av + 1), &res);
	if (i != 0) {
		herror("getcertsbyname");
		exit(1);
	}
	printf("getcertsbyname succeeded.\n");

	i = 0;
	for (p = res; p; p = p->ci_next) {
		printf("certinfo[%d]:\n", i);
		printf("\tci_type=%d\n", p->ci_type);
		printf("\tci_keytag=%d\n", p->ci_keytag);
		printf("\tci_algorithm=%d\n", p->ci_algorithm);
		printf("\tci_flags=%d\n", p->ci_flags);
		printf("\tci_certlen=%d\n", p->ci_certlen);
		printf("\tci_cert: ");
		b64encode(p->ci_cert, p->ci_certlen);
		printf("\n");
		i++;
	}

	freecertinfo(res);

	exit(0);
}
#endif
