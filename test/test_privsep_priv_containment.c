// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Automates doc/dev/privsep-verification-runbook.md's Phase 4 (§5a, §5b,
 * §5c) -- "a single malformed or refused request fails *itself* and the
 * daemon keeps running" -- now that privsep_priv() (the extracted dispatch
 * loop, doc/dev/privsep-priv-extraction.md) can be driven directly instead
 * of needing a live host, a real privilege drop, and either a config
 * mistake (§5a) or an LD_PRELOAD shim mangling `ac_cmd` in flight (§5b).
 *
 * The assertion that actually proves containment, per the task brief this
 * file was written against, is not just that the bad request fails: it is
 * that the *next*, well-formed request on the same connection still gets
 * served. fatal-exit-path-audit.md §1 rule 1 ("containment must not
 * silently succeed") cuts the other way here too -- a test that only
 * checks the bad request failed would also pass against a build that
 * _exit()s afterward, which is the exact regression this guards.
 *
 * §5c ("the wire budget at its ceiling") was corrected in the runbook
 * itself: a legitimate mode-config gateway cannot fill PRIVSEP_NBUF_MAX
 * (every list-shaped attribute is joined into one string, never one entry
 * per item, and PRIVSEP_SCRIPT_EXEC_MAX_ENVC_FITS_WIRE_BUDGET asserts the
 * fixed-shape envc at compile time). The E2BIG row it guards is therefore
 * reachable only by a corrupted message, same as §5b -- so this test
 * builds one directly: a PRIVSEP_SCRIPT_EXEC request whose buflen[] array
 * never carries a zero (void-terminator) entry within PRIVSEP_NBUF_MAX
 * slots, which no conformant client (privsep_script_exec()'s own count()
 * guard, privsep.c) can produce.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdint.h>
#include <poll.h>

#include "vmbuf.h"
#include "admin.h"
#include "privsep.h"
#include "remoteconf.h"

extern int privsep_priv(int sock);
extern void privsep_priv_test_lcconf_init(const char *certdir,
    const char *scriptdir);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

#define WAIT_POLL_MS   20
#define WAIT_MAX_POLLS 250   /* 5s bound -- see privsep-priv-extraction.md */

/* See test_privsep_priv_control_cases.c's IO_TIMEOUT_MS comment: every
 * blocking wait in this file is bounded so a regression that reintroduces
 * an unbounded wait in privsep_priv() fails this test loudly instead of
 * hanging the harness (fatal-exit-path-audit.md §1 rule 2). */
#define IO_TIMEOUT_MS 5000

static ssize_t
write_all(int fd, const void *buf, size_t len)
{
	size_t off = 0;
	ssize_t n;

	while (off < len) {
		n = write(fd, (const char *)buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return (ssize_t)off;
}

static int
elapsed_ms_since(const struct timeval *start)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	return (int)((now.tv_sec - start->tv_sec) * 1000 +
	    (now.tv_usec - start->tv_usec) / 1000);
}

static ssize_t
read_all_bounded(int fd, void *buf, size_t len, int timeout_ms)
{
	size_t off = 0;
	ssize_t n;
	struct timeval start;
	struct pollfd pfd;
	int remaining, pr;

	gettimeofday(&start, NULL);

	while (off < len) {
		remaining = timeout_ms - elapsed_ms_since(&start);
		if (remaining <= 0)
			return -1;

		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		pr = poll(&pfd, 1, remaining);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (pr == 0)
			return -1;

		n = read(fd, (char *)buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return (ssize_t)off;
		off += (size_t)n;
	}
	return (ssize_t)off;
}

static struct privsep_com_msg *
build_msg(int cmd, size_t nbufs, const void *const *ptrs, const size_t *lens,
    size_t *out_len)
{
	size_t total = sizeof(struct privsep_com_msg);
	size_t i;
	struct privsep_com_msg *m;
	char *data;

	for (i = 0; i < nbufs; i++)
		total += lens[i];

	if ((m = calloc(1, total)) == NULL)
		return NULL;

	m->hdr.ac_cmd = (u_int16_t)cmd;
	m->hdr.ac_len = (u_int16_t)total;

	data = (char *)(m + 1);
	for (i = 0; i < nbufs; i++) {
		m->bufs.buflen[i] = lens[i];
		if (lens[i] != 0)
			memcpy(data, ptrs[i], lens[i]);
		data += lens[i];
	}

	*out_len = total;
	return m;
}

static int
send_request(int sock, int cmd, size_t nbufs, const void *const *ptrs,
    const size_t *lens)
{
	struct privsep_com_msg *m;
	size_t len;
	int ret;

	if ((m = build_msg(cmd, nbufs, ptrs, lens, &len)) == NULL)
		return -1;
	ret = write_all(sock, m, len) == (ssize_t)len ? 0 : -1;
	free(m);
	return ret;
}

static ssize_t
recv_reply(int sock, void *buf, size_t bufsize)
{
	struct admin_com hdr;
	ssize_t n;

	n = read_all_bounded(sock, &hdr, sizeof(hdr), IO_TIMEOUT_MS);
	if (n != (ssize_t)sizeof(hdr))
		return -1;
	if (hdr.ac_len < sizeof(hdr) || (size_t)hdr.ac_len > bufsize)
		return -1;

	memcpy(buf, &hdr, sizeof(hdr));
	n = read_all_bounded(sock, (char *)buf + sizeof(hdr),
	    hdr.ac_len - sizeof(hdr), IO_TIMEOUT_MS);
	if (n != (ssize_t)(hdr.ac_len - sizeof(hdr)))
		return -1;

	return hdr.ac_len;
}

static int
wait_child_bounded(pid_t child, int *status)
{
	int i;
	pid_t ret;

	for (i = 0; i < WAIT_MAX_POLLS; i++) {
		ret = waitpid(child, status, WNOHANG);
		if (ret == child)
			return 0;
		usleep(WAIT_POLL_MS * 1000);
	}
	kill(child, SIGKILL);
	waitpid(child, status, 0);
	return -1;
}

/*
 * Sends a well-formed PRIVSEP_GETPSK request and returns 0 only if it
 * round-trips with ac_errno == 0 -- the "does the loop still serve
 * requests" half of every containment case below.
 */
static int
followup_request_succeeds(int sock)
{
	const char ident[] = "followup-identity";
	int keylen = 8;
	const void *ptrs[2] = { ident, &keylen };
	size_t lens[2] = { sizeof(ident), sizeof(keylen) };
	char replybuf[512];
	ssize_t rlen;
	struct privsep_com_msg *reply;

	if (send_request(sock, PRIVSEP_GETPSK, 2, ptrs, lens) != 0)
		return -1;
	if ((rlen = recv_reply(sock, replybuf, sizeof(replybuf))) < 0)
		return -1;
	reply = (struct privsep_com_msg *)replybuf;
	return reply->hdr.ac_errno == 0 ? 0 : -1;
}

/* Forks a privsep_priv() child over a fresh socketpair(); lcconf must
 * already be initialised by the caller before calling this. */
static int
spawn_priv(int *sock_out, pid_t *child_out)
{
	int sp[2];
	pid_t child;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		return -1;

	if ((child = fork()) < 0) {
		close(sp[0]);
		close(sp[1]);
		return -1;
	}

	if (child == 0) {
		close(sp[0]);
		_exit(privsep_priv(sp[1]) == 0 ? 0 : 1);
	}

	close(sp[1]);
	*sock_out = sp[0];
	*child_out = child;
	return 0;
}

/* §5a: a hook pointed outside "path script" is refused with EPERM, and the
 * connection is still usable afterward. */
static int
test_refused_hook_is_contained(void)
{
	char scriptdir[] = "/tmp/privsep_priv_containment_scripts.XXXXXX";
	char outsidedir[] = "/tmp/privsep_priv_containment_outside.XXXXXX";
	char outsidepath[1024];
	FILE *f;
	int sock;
	pid_t child;
	int status;
	int name = SCRIPT_PHASE1_UP;
	const void *ptrs[3];
	size_t lens[3];
	char replybuf[512];
	ssize_t rlen;
	struct privsep_com_msg *reply;

	TEST_START("a hook outside path script answers EPERM, loop keeps serving");

	if (mkdtemp(scriptdir) == NULL)
		TEST_FAIL("mkdtemp(scriptdir) failed");
	if (mkdtemp(outsidedir) == NULL)
		TEST_FAIL("mkdtemp(outsidedir) failed");
	snprintf(outsidepath, sizeof(outsidepath), "%s/not-under-path-script.sh",
	    outsidedir);
	if ((f = fopen(outsidepath, "w")) == NULL)
		TEST_FAIL("could not create outside-path script file");
	fclose(f);

	/* path script is set to scriptdir; outsidepath is deliberately not
	 * under it -- the runbook's own §5a scenario, minus the daemon. */
	privsep_priv_test_lcconf_init(NULL, scriptdir);

	if (spawn_priv(&sock, &child) != 0)
		TEST_FAIL("spawn_priv() failed");

	ptrs[0] = outsidepath; lens[0] = strlen(outsidepath) + 1;
	ptrs[1] = &name;       lens[1] = sizeof(name);
	ptrs[2] = NULL;        lens[2] = 0;

	if (send_request(sock, PRIVSEP_SCRIPT_EXEC, 3, ptrs, lens) != 0) {
		close(sock);
		TEST_FAIL("send failed");
	}
	if ((rlen = recv_reply(sock, replybuf, sizeof(replybuf))) < 0) {
		close(sock);
		TEST_FAIL("no reply to the refused hook");
	}
	reply = (struct privsep_com_msg *)replybuf;
	if (reply->hdr.ac_errno != EPERM) {
		close(sock);
		printf("\n    ac_errno=%d, expected EPERM", reply->hdr.ac_errno);
		TEST_FAIL("refused hook was not answered with EPERM");
	}

	if (followup_request_succeeds(sock) != 0) {
		close(sock);
		TEST_FAIL("loop did not keep serving after the refusal");
	}

	close(sock);
	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("child did not exit after EOF");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("\n    child exit status: %d", status);
		TEST_FAIL("clean EOF shutdown should report exit 0");
	}

	unlink(outsidepath);
	rmdir(outsidedir);
	rmdir(scriptdir);

	TEST_PASS();
	return 0;
}

/* §5b: a corrupted ac_cmd (the LD_PRELOAD shim's 0xBEEF case) is refused
 * with EINVAL, and the loop's next iteration still serves a well-formed
 * follow-up request. */
static int
test_corrupted_ac_cmd_is_contained(void)
{
	int sock;
	pid_t child;
	int status;
	struct privsep_com_msg m;
	char replybuf[512];
	ssize_t rlen;
	struct privsep_com_msg *reply;

	TEST_START("a corrupted ac_cmd (0xBEEF) answers EINVAL, loop keeps serving");

	privsep_priv_test_lcconf_init(NULL, NULL);

	if (spawn_priv(&sock, &child) != 0)
		TEST_FAIL("spawn_priv() failed");

	memset(&m, 0, sizeof(m));
	m.hdr.ac_cmd = 0xBEEF;
	m.hdr.ac_len = sizeof(m);

	if (write_all(sock, &m, sizeof(m)) != (ssize_t)sizeof(m)) {
		close(sock);
		TEST_FAIL("send failed");
	}
	if ((rlen = recv_reply(sock, replybuf, sizeof(replybuf))) < 0) {
		close(sock);
		TEST_FAIL("no reply to the corrupted command");
	}
	reply = (struct privsep_com_msg *)replybuf;
	if (reply->hdr.ac_errno != EINVAL) {
		close(sock);
		printf("\n    ac_errno=%d, expected EINVAL", reply->hdr.ac_errno);
		TEST_FAIL("corrupted ac_cmd was not answered with EINVAL");
	}

	if (followup_request_succeeds(sock) != 0) {
		close(sock);
		TEST_FAIL("loop did not keep serving after the corrupted command");
	}

	close(sock);
	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("child did not exit after EOF");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("\n    child exit status: %d", status);
		TEST_FAIL("clean EOF shutdown should report exit 0");
	}

	TEST_PASS();
	return 0;
}

/* §5c (corrected): PRIVSEP_NBUF_MAX cannot be filled by a conformant
 * client, but a corrupted message can claim it anyway -- the E2BIG row
 * exists for exactly that. Every one of the 24 buflen[] slots is nonzero,
 * so the counting loop never finds a void terminator within bounds. */
static int
test_e2big_via_corrupted_message_is_contained(void)
{
	int sock;
	pid_t child;
	int status;
	size_t nbufs = PRIVSEP_NBUF_MAX;
	const void *ptrs[PRIVSEP_NBUF_MAX];
	size_t lens[PRIVSEP_NBUF_MAX];
	char script[] = "/tmp/does-not-matter";
	int name = SCRIPT_PHASE1_UP;
	char filler = 'x';
	size_t i;
	char replybuf[512];
	ssize_t rlen;
	struct privsep_com_msg *reply;

	TEST_START("a PRIVSEP_SCRIPT_EXEC with no void terminator answers E2BIG");

	privsep_priv_test_lcconf_init(NULL, NULL);

	if (spawn_priv(&sock, &child) != 0)
		TEST_FAIL("spawn_priv() failed");

	ptrs[0] = script; lens[0] = sizeof(script);
	ptrs[1] = &name;  lens[1] = sizeof(name);
	for (i = 2; i < nbufs; i++) {
		ptrs[i] = &filler;
		lens[i] = 1; /* nonzero: never looks like the void terminator */
	}

	if (send_request(sock, PRIVSEP_SCRIPT_EXEC, nbufs, ptrs, lens) != 0) {
		close(sock);
		TEST_FAIL("send failed");
	}
	if ((rlen = recv_reply(sock, replybuf, sizeof(replybuf))) < 0) {
		close(sock);
		TEST_FAIL("no reply to the over-full message");
	}
	reply = (struct privsep_com_msg *)replybuf;
	if (reply->hdr.ac_errno != E2BIG) {
		close(sock);
		printf("\n    ac_errno=%d, expected E2BIG", reply->hdr.ac_errno);
		TEST_FAIL("over-full PRIVSEP_SCRIPT_EXEC was not answered with E2BIG");
	}

	if (followup_request_succeeds(sock) != 0) {
		close(sock);
		TEST_FAIL("loop did not keep serving after E2BIG");
	}

	close(sock);
	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("child did not exit after EOF");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("\n    child exit status: %d", status);
		TEST_FAIL("clean EOF shutdown should report exit 0");
	}

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep_priv() containment (runbook Phase 4/5a/5b/5c, "
	    "privsep-priv-extraction task) ===\n");

	if (test_refused_hook_is_contained() != 0)
		failed++;
	if (test_corrupted_ac_cmd_is_contained() != 0)
		failed++;
	if (test_e2big_via_corrupted_message_is_contained() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
