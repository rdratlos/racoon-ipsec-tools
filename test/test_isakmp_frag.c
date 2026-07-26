/*
 * test/test_isakmp_frag.c
 *
 * Regression test for src/racoon/isakmp_frag.c: IKE phase 1 fragment
 * reassembly (scenarios 1-4, the CVE-2016-10396 follow-up below), plus
 * coverage added for the file's remaining, previously-untested entry
 * points -- isakmp_sendfrags() (the sending side's counterpart to
 * reassembly, scenario 5), vendorid_frag_cap() (capability-dword
 * extraction and its CWE-125 bounds check, scenario 6), and
 * isakmp_frag_addcap() (the vendor-ID capability dword this project's own
 * VID construction ORs bits into, scenario 7).
 *
 * Background (scenarios 1-4)
 * ---------------------------
 * The NetBSD fix for CVE-2016-10396 (remote DoS via out-of-order IKE
 * fragments) introduced a `frag_last_index` field and a completion check
 * that did not reliably detect the end of a reassembly. In this fork two
 * defects remained after the partial follow-up (commit 7fc4152):
 *
 *   1. The tail-fragment consistency check compared the boolean
 *      ISAKMP_FRAG_LAST *flag* (always 1 for a tail fragment) against the
 *      stored tail fragment *index*, so any legitimate retransmission of the
 *      tail fragment (index > 1) was misclassified as a replay attack and
 *      dropped with "Repeated last fragment index mismatch".
 *
 *   2. Completion was only ever detected in the call that processed the tail
 *      fragment itself (a function-local `last_frag`), so whenever a non-tail
 *      fragment arrived *after* the tail (reordering or retransmission), the
 *      now-complete chain was never recognised and phase 1 stalled until it
 *      timed out.
 *
 *   3. `isakmp_frag_reassembly()` never reset `frag_last_index`, so a second
 *      fragmented message on the same ph1handle inherited a stale tail index.
 *
 * This test drives the *real* isakmp_frag_extract()/isakmp_frag_reassembly()
 * code with crafted fragment sequences. It FAILS against the pre-fix code and
 * PASSES against the fixed code, while confirming the CVE-2016-10396
 * protections (conflicting tail fragments and duplicate fragment numbers are
 * still rejected) remain intact.
 *
 * The test is self-contained: it links only isakmp_frag.o and provides local
 * stubs for the daemon symbols that object references, so no part of the rest
 * of racoon needs to be linked.
 *
 * Copyright (C) 2026 Thomas Reim and the racoon-ipsec-tools contributors
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/md5.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "var.h"
#include "vmbuf.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "handler.h"
#include "isakmp_frag.h"

/* ------------------------------------------------------------------ *
 *  Stubs for symbols referenced by isakmp_frag.o                     *
 * ------------------------------------------------------------------ */

u_int32_t loglevel = 0;			/* silence plog() (pri <= loglevel) */
char *pname = "test_isakmp_frag";
int f_foreground = 1;
int print_location = 0;

const char *
debug_location(const char *file, int line, const char *func)
{
	(void)file; (void)line; (void)func;
	return "test";
}

void
_plog(int pri, const char *location, struct sockaddr *addr,
      const char *fmt, ...)
{
	(void)pri; (void)location; (void)addr; (void)fmt;
	/* no-op: reassembly logic is exercised via return values, not logs */
}

/*
 * Referenced by isakmp_sendfrags() (exercised in test_sendfrags_scenarios()
 * below). isakmp_send() records a copy of every fragment handed to it so
 * the test can check fragment count, index/flags sequencing, and payload
 * placement; set_isakmp_header1() stays a no-op -- isakmp_sendfrags() only
 * ever reads back the etype field it sets itself, never anything
 * set_isakmp_header1() would have filled in.
 */
#define MAX_RECORDED_FRAGS 16
static vchar_t *sent_frags[MAX_RECORDED_FRAGS];
static int sent_frags_count;

static void
reset_sent_frags(void)
{
	int i;

	for (i = 0; i < sent_frags_count; i++)
		vfree(sent_frags[i]);
	sent_frags_count = 0;
}

int isakmp_send(struct ph1handle *iph1, vchar_t *buf)
{
	(void)iph1;
	if (sent_frags_count < MAX_RECORDED_FRAGS) {
		vchar_t *copy = vmalloc(buf->l);
		if (copy != NULL) {
			memcpy(copy->v, buf->v, buf->l);
			sent_frags[sent_frags_count++] = copy;
		}
	}
	return 0;
}
caddr_t set_isakmp_header1(vchar_t *b, struct ph1handle *i, int n)
{
	(void)b; (void)i; (void)n;
	return NULL;
}

/* Minimal vmbuf allocator matching the semantics isakmp_frag.c relies on. */
vchar_t *
vmalloc(size_t size)
{
	vchar_t *v = calloc(1, sizeof(*v));
	if (v == NULL)
		return NULL;
	v->l = size;
	v->v = calloc(1, size ? size : 1);
	if (v->v == NULL) {
		free(v);
		return NULL;
	}
	return v;
}

vchar_t *
vrealloc(vchar_t *ptr, size_t size)
{
	if (ptr == NULL)
		return vmalloc(size);
	ptr->v = realloc(ptr->v, size ? size : 1);
	if (ptr->v == NULL) {
		free(ptr);
		return NULL;
	}
	ptr->l = size;
	return ptr;
}

void
vfree(vchar_t *ptr)
{
	if (ptr == NULL)
		return;
	free(ptr->v);
	free(ptr);
}

/* ------------------------------------------------------------------ *
 *  Test harness                                                      *
 * ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(cond, msg) do {						\
	tests_run++;							\
	if (!(cond)) {							\
		tests_failed++;						\
		printf("  FAIL: %s\n", (msg));				\
	} else {							\
		printf("  ok:   %s\n", (msg));				\
	}								\
} while (0)

/*
 * Build one IKE fragment message: [isakmp hdr][isakmp_frag hdr][payload].
 * Each fragment's payload is filled with a byte pattern derived from its
 * index, so the reassembled buffer can be checked for correct ordering.
 */
static vchar_t *
make_fragment(int index, int is_last, size_t payloadlen)
{
	size_t msglen = sizeof(struct isakmp) + sizeof(struct isakmp_frag)
	    + payloadlen;
	vchar_t *msg = vmalloc(msglen);
	struct isakmp_frag *frag;
	unsigned char *payload;
	size_t i;

	if (msg == NULL)
		return NULL;

	frag = (struct isakmp_frag *)(msg->v + sizeof(struct isakmp));
	frag->unknown0 = htons(0);
	frag->len = htons(sizeof(struct isakmp_frag) + payloadlen);
	frag->unknown1 = htons(1);
	frag->index = (u_int8_t)index;
	frag->flags = is_last ? ISAKMP_FRAG_LAST : 0;

	payload = (unsigned char *)(msg->v + sizeof(struct isakmp)
	    + sizeof(struct isakmp_frag));
	for (i = 0; i < payloadlen; i++)
		payload[i] = (unsigned char)(0x10 * index + (i & 0x0f));

	return msg;
}

static struct ph1handle *
new_iph1(void)
{
	/* ph1handle carries a lot of state; only the frag_* fields matter. */
	struct ph1handle *iph1 = calloc(1, sizeof(*iph1));
	return iph1;
}

/* Deliver a fragment to the reassembly engine; returns extract() result. */
static int
deliver(struct ph1handle *iph1, int index, int is_last, size_t payloadlen)
{
	vchar_t *msg = make_fragment(index, is_last, payloadlen);
	int r;

	if (msg == NULL)
		return -99;
	r = isakmp_frag_extract(iph1, msg);
	vfree(msg);
	return r;
}

/* Verify reassembled payload equals fragments 1..n concatenated in order. */
static int
verify_payload(vchar_t *buf, int nfrags, const size_t *lens)
{
	size_t off = 0;
	int idx;
	size_t i;

	if (buf == NULL)
		return 0;
	for (idx = 1; idx <= nfrags; idx++) {
		for (i = 0; i < lens[idx]; i++) {
			unsigned char expect =
			    (unsigned char)(0x10 * idx + (i & 0x0f));
			if ((unsigned char)buf->v[off + i] != expect)
				return 0;
		}
		off += lens[idx];
	}
	return off == buf->l;
}

/*
 * Scenario 1 (sanity): in-order delivery 1,2,3 (3 = tail).
 * Works on buggy and fixed code alike -- guards against over-correction.
 */
static void
test_inorder(void)
{
	struct ph1handle *iph1 = new_iph1();
	size_t lens[4] = { 0, 100, 100, 40 };
	vchar_t *buf;

	printf("Scenario 1: in-order 1,2,3(tail)\n");
	CHECK(deliver(iph1, 1, 0, lens[1]) == 0, "frag #1 queued, incomplete");
	CHECK(deliver(iph1, 2, 0, lens[2]) == 0, "frag #2 queued, incomplete");
	CHECK(deliver(iph1, 3, 1, lens[3]) == 1, "frag #3(tail) completes chain");

	buf = isakmp_frag_reassembly(iph1);
	CHECK(verify_payload(buf, 3, lens), "reassembled payload correct");
	CHECK(iph1->frag_chain == NULL, "chain freed after reassembly");
	CHECK(iph1->frag_last_index == 0, "tail index reset after reassembly");
	vfree(buf);
	free(iph1);
}

/*
 * Scenario 2 (PRIMARY regression): a non-tail fragment arrives AFTER the
 * tail -- exactly what packet reordering and retransmission produce.
 * Delivery order 1, 3(tail), 2.
 *
 *   Fixed code: completion is detected when #2 fills the gap  -> returns 1.
 *   Buggy code: completion is only checked in the call that carried the
 *               tail, so it is never detected here -> returns 0 forever,
 *               phase 1 would time out.
 */
static void
test_tail_not_last(void)
{
	struct ph1handle *iph1 = new_iph1();
	size_t lens[4] = { 0, 100, 100, 40 };
	vchar_t *buf;
	int r1, r2, r3;

	printf("Scenario 2: out-of-order 1,3(tail),2  [primary regression]\n");
	r1 = deliver(iph1, 1, 0, lens[1]);
	r2 = deliver(iph1, 3, 1, lens[3]);	/* tail arrives before #2 */
	r3 = deliver(iph1, 2, 0, lens[2]);	/* gap-filling fragment last */

	CHECK(r1 == 0, "frag #1 queued, incomplete");
	CHECK(r2 == 0, "frag #3(tail) queued, still missing #2");
	CHECK(r3 == 1, "frag #2 fills gap AFTER tail -> chain complete");

	buf = isakmp_frag_reassembly(iph1);
	CHECK(verify_payload(buf, 3, lens), "reassembled payload correct");
	vfree(buf);
	free(iph1);
}

/*
 * Scenario 3 (user's exact symptom): the whole fragmented phase 1 message is
 * retransmitted by the peer after it was already reassembled once. With the
 * stale-frag_last_index bug the retransmitted tail triggered
 * "Repeated last fragment index mismatch" and the second reassembly could
 * never complete.
 */
static void
test_retransmitted_message(void)
{
	struct ph1handle *iph1 = new_iph1();
	size_t lens[4] = { 0, 100, 100, 40 };
	vchar_t *buf;

	printf("Scenario 3: full retransmission of an already-reassembled message\n");

	/* First delivery completes and is consumed. */
	deliver(iph1, 1, 0, lens[1]);
	deliver(iph1, 2, 0, lens[2]);
	CHECK(deliver(iph1, 3, 1, lens[3]) == 1, "first pass completes");
	buf = isakmp_frag_reassembly(iph1);
	CHECK(buf != NULL, "first reassembly succeeds");
	vfree(buf);

	/* Peer retransmits the entire fragment set on the same ph1handle. */
	CHECK(deliver(iph1, 1, 0, lens[1]) == 0, "retransmit #1 accepted afresh");
	CHECK(deliver(iph1, 2, 0, lens[2]) == 0, "retransmit #2 accepted afresh");
	CHECK(deliver(iph1, 3, 1, lens[3]) == 1,
	    "retransmit tail completes again (no false mismatch)");
	buf = isakmp_frag_reassembly(iph1);
	CHECK(verify_payload(buf, 3, lens), "second reassembly payload correct");
	vfree(buf);
	free(iph1);
}

/*
 * Scenario 4 (CVE-2016-10396 protection preserved): a forged second tail
 * fragment with a DIFFERENT index, and a duplicate fragment number, must both
 * still be rejected -- the fix must not reopen the DoS.
 */
static void
test_security_preserved(void)
{
	struct ph1handle *iph1 = new_iph1();
	size_t lens[6] = { 0, 100, 100, 100, 100, 40 };

	printf("Scenario 4: CVE-2016-10396 protections preserved\n");

	/* Legit tail is #5. */
	CHECK(deliver(iph1, 1, 0, lens[1]) == 0, "frag #1 queued");
	CHECK(deliver(iph1, 5, 1, lens[5]) == 0, "frag #5(tail) queued");

	/* Forged: a second, conflicting tail fragment (#3 also claims last). */
	CHECK(deliver(iph1, 3, 1, lens[3]) == -1,
	    "second conflicting tail fragment rejected");

	/* Forged: fragment number beyond the tail index. */
	CHECK(deliver(iph1, 7, 0, 100) == -1,
	    "fragment number greater than tail rejected");

	/* Forged: duplicate of an already-queued fragment number. */
	CHECK(deliver(iph1, 1, 0, lens[1]) == -1,
	    "duplicate fragment number rejected");

	/* Clean up the still-incomplete chain. */
	{
		struct isakmp_frag_item *it = iph1->frag_chain, *nx;
		while (it != NULL) {
			nx = it->frag_next;
			vfree(it->frag_packet);
			free(it);
			it = nx;
		}
	}
	free(iph1);
}

/*
 * Scenario 5: isakmp_sendfrags() -- the sending side's counterpart to the
 * extract/reassembly logic above. Splits an oversized ISAKMP message into
 * ISAKMP_FRAG_MAXLEN-bounded fragments and hands each to isakmp_send(),
 * which the stub above now records instead of discarding.
 *
 * ISAKMP_FRAG_MAXLEN is 552; sizeof(struct isakmp)+sizeof(struct
 * isakmp_frag)+sizeof(trailer) is 28+8+4=40, so each fragment's payload
 * (max_datalen) tops out at 512 bytes. A 1050-byte message therefore
 * splits as 512+512+26 -- three fragments, the last strictly shorter,
 * exercising both the "more data follows" and "this is the last one"
 * branches in the same run.
 */
static void
test_sendfrags_scenarios(void)
{
	struct ph1handle *iph1 = new_iph1();
	const size_t total = 1050;
	const size_t max_datalen = ISAKMP_FRAG_MAXLEN -
	    (sizeof(struct isakmp) + sizeof(struct isakmp_frag) + sizeof(unsigned int));
	vchar_t *msg;
	struct isakmp *hdr;
	u_int8_t expect_etype;
	size_t off;
	int i, r;

	printf("Scenario 5: isakmp_sendfrags() splits an oversized message\n");

	msg = vmalloc(total);
	if (msg == NULL) {
		CHECK(0, "vmalloc() for the oversized message succeeded");
		free(iph1);
		return;
	}
	/* The whole buffer -- header bytes included -- is opaque data to
	 * isakmp_sendfrags(); fill it with a position-derived pattern so
	 * reassembly can be checked byte-for-byte below, then capture
	 * whatever byte the pattern put at the etype offset as the expected
	 * value -- the point under test is that every fragment's own header
	 * carries the SAME etype the source message had, not a specific one
	 * (setting it separately, after the fill, would just overwrite one
	 * pattern byte and complicate the payload check below for no gain).
	 */
	for (i = 0; i < (int)msg->l; i++)
		msg->v[i] = (unsigned char)(i & 0xff);
	hdr = (struct isakmp *)msg->v;
	expect_etype = hdr->etype;

	reset_sent_frags();
	r = isakmp_sendfrags(iph1, msg);

	CHECK(r == sent_frags_count,
	    "isakmp_sendfrags() return value matches fragments actually sent");
	CHECK(sent_frags_count == 3, "1050-byte message split into exactly 3 fragments");

	off = 0;
	for (i = 0; i < sent_frags_count; i++) {
		struct isakmp *fhdr = (struct isakmp *)sent_frags[i]->v;
		struct isakmp_frag *fraghdr =
		    (struct isakmp_frag *)(sent_frags[i]->v + sizeof(struct isakmp));
		unsigned char *data = (unsigned char *)(fraghdr + 1);
		size_t datalen = sent_frags[i]->l - sizeof(struct isakmp) -
		    sizeof(struct isakmp_frag);
		int expect_last = (i == sent_frags_count - 1);
		int payload_ok = 1;
		size_t j;

		CHECK(fhdr->etype == expect_etype, "fragment carries the original exchange type");
		CHECK(fraghdr->index == i + 1, "fragment index is sequential, 1-based");
		CHECK(((fraghdr->flags & ISAKMP_FRAG_LAST) != 0) == expect_last,
		    "only the final fragment carries ISAKMP_FRAG_LAST");
		if (!expect_last)
			CHECK(datalen == max_datalen,
			    "non-final fragment payload is exactly max_datalen");

		for (j = 0; j < datalen; j++) {
			if (data[j] != (unsigned char)((off + j) & 0xff)) {
				payload_ok = 0;
				break;
			}
		}
		CHECK(payload_ok, "fragment payload matches source data at its offset");
		off += datalen;
	}
	CHECK(off == msg->l, "concatenated fragment payloads cover the whole message");

	vfree(msg);
	free(iph1);
	reset_sent_frags();
}

/*
 * Scenario 6: vendorid_frag_cap() -- extracts the capability dword that
 * follows the 16-byte MD5 vendor-ID hash, and (CWE-125, see the comment in
 * isakmp_frag.c) must refuse to read past a vendor ID payload too short to
 * contain one, returning 0 instead of an out-of-bounds read.
 */
static void
test_vendorid_frag_cap_scenarios(void)
{
	unsigned char raw[sizeof(struct isakmp_gen) + MD5_DIGEST_LENGTH + sizeof(unsigned int)];
	struct isakmp_gen *gen = (struct isakmp_gen *)raw;
	unsigned int *capp = (unsigned int *)(raw + sizeof(struct isakmp_gen) + MD5_DIGEST_LENGTH);

	printf("Scenario 6: vendorid_frag_cap() capability extraction\n");

	memset(raw, 0, sizeof(raw));
	gen->len = htons((u_int16_t)sizeof(raw));

	*capp = htonl(VENDORID_FRAG_BASE);
	CHECK(vendorid_frag_cap(gen) == (unsigned int)VENDORID_FRAG_BASE,
	    "single capability bit extracted correctly");

	*capp = htonl(VENDORID_FRAG_BASE | VENDORID_FRAG_IDENT);
	CHECK(vendorid_frag_cap(gen) == (unsigned int)(VENDORID_FRAG_BASE | VENDORID_FRAG_IDENT),
	    "combined capability bits extracted correctly");

	/* Truncated VID: len covers only the header + digest, no capability
	 * dword. Must return 0, not read 4 bytes past what len declares. */
	gen->len = htons((u_int16_t)(sizeof(struct isakmp_gen) + MD5_DIGEST_LENGTH));
	CHECK(vendorid_frag_cap(gen) == 0,
	    "truncated VID (no capability dword) returns 0, not an OOB read (CWE-125)");
}

/*
 * Scenario 7: isakmp_frag_addcap() -- grows a bare 16-byte MD5 VID hash by
 * exactly sizeof(int) the first time a capability is added, then ORs
 * further capability bits into the same dword in place on later calls
 * (the fragmentation-then-hybrid/xauth vendor ID construction path).
 */
static void
test_frag_addcap_scenarios(void)
{
	vchar_t *buf;
	unsigned int *capp;

	printf("Scenario 7: isakmp_frag_addcap() growth and in-place OR\n");

	buf = vmalloc(MD5_DIGEST_LENGTH);
	if (buf == NULL) {
		CHECK(0, "vmalloc(MD5_DIGEST_LENGTH) succeeded");
		return;
	}
	memset(buf->v, 0xAA, buf->l); /* stand-in MD5 digest bytes */

	buf = isakmp_frag_addcap(buf, VENDORID_FRAG_BASE);
	CHECK(buf != NULL, "addcap() on a bare digest did not fail");
	CHECK(buf->l == MD5_DIGEST_LENGTH + sizeof(int),
	    "buffer grew by exactly sizeof(cap) on first call");
	capp = (unsigned int *)(buf->v + MD5_DIGEST_LENGTH);
	CHECK(ntohl(*capp) == (unsigned int)VENDORID_FRAG_BASE,
	    "capability dword set correctly on first call");

	buf = isakmp_frag_addcap(buf, VENDORID_FRAG_IDENT);
	CHECK(buf->l == MD5_DIGEST_LENGTH + sizeof(int),
	    "second call does not grow the buffer again");
	capp = (unsigned int *)(buf->v + MD5_DIGEST_LENGTH);
	CHECK(ntohl(*capp) == (unsigned int)(VENDORID_FRAG_BASE | VENDORID_FRAG_IDENT),
	    "second call ORs in the new bit, keeping the first");

	vfree(buf);
}

int
main(void)
{
	printf("=== IKE fragment reassembly regression tests ===\n\n");

	test_inorder();
	printf("\n");
	test_tail_not_last();
	printf("\n");
	test_retransmitted_message();
	printf("\n");
	test_security_preserved();
	printf("\n");
	test_sendfrags_scenarios();
	printf("\n");
	test_vendorid_frag_cap_scenarios();
	printf("\n");
	test_frag_addcap_scenarios();

	printf("\n=== %d checks, %d failed ===\n", tests_run, tests_failed);
	return tests_failed == 0 ? 0 : 1;
}
