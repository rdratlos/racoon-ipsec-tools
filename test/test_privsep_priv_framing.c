// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Automates doc/dev/v0.9.1-hardening-spec.md §2.3's Phase 2 -- the
 * `strace -tt -p $PRIV -e trace=socket,bind,setsockopt,recvmsg,sendmsg,
 * sendto,recvfrom` capture that verified, by eye, that the descriptor
 * handshake goes over the wire in the order doc/dev/v0.9.1-hardening-spec.md §2.1
 * put it in. Now that privsep_priv() can be driven directly (doc/dev/
 * v0.9.1-hardening-spec.md §2.2), the same invariants are checkable
 * mechanically instead:
 *
 *   1. peeks == body reads == replies: every request this file sends gets
 *      exactly one reply, in order -- checked here as "the reply's own
 *      ac_cmd, which privsep_priv() always echoes back from the request it
 *      just answered, matches the command just sent." A drift of even one
 *      message would very likely echo the *previous* request's command
 *      instead, or fail recv_reply()'s own framing sanity check outright.
 *   2. Exactly one descriptor message per PRIVSEP_BIND/PRIVSEP_SETSOCKOPTS/
 *      PRIVSEP_SOCKET request, each in its documented order (BIND/
 *      SETSOCKOPTS: descriptor before the reply; SOCKET: descriptor before
 *      the reply too, but flowing the other way) -- if the loop ever
 *      produced zero or two descriptor messages for one request, every
 *      following exchange in this file would desync and fail loudly, not
 *      silently.
 *   3. The runbook's own "does the returned descriptor number climb
 *      across requests" leak check, reproduced by repeating
 *      PRIVSEP_SOCKET several times and keeping the descriptor spread
 *      small.
 *
 * This is deliberately a longer, repeated, mixed-order sequence -- unlike
 * test_privsep_priv_control_cases.c's one well-formed request per command
 * family, the point here is specifically to stress ordering and repetition,
 * which is where drift would show up.
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
#include <fcntl.h>
#include <poll.h>

#include "vmbuf.h"
#include "admin.h"
#include "privsep.h"

extern int privsep_priv(int sock);
extern void privsep_priv_test_lcconf_init(const char *certdir,
    const char *scriptdir);
extern int privsep_send_fd_unittest(int s, int fd);
extern int privsep_rec_fd_unittest(int s);

struct test_socket_args {
	int domain;
	int type;
	int protocol;
};

struct test_bind_args {
	int s;
	const struct sockaddr *addr;
	socklen_t addrlen;
};

struct test_sockopt_args {
	int s;
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
};

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

#define IO_TIMEOUT_MS  5000  /* see test_privsep_priv_control_cases.c */
#define WAIT_POLL_MS   20
#define WAIT_MAX_POLLS 250   /* 5s bound on any waitpid() poll below */

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
 * One request/reply cycle, asserting the "no drift" invariant: the reply's
 * echoed ac_cmd must be the command just sent, and ac_errno must be 0 for
 * a well-formed request. Descriptor exchanges (SOCKET/BIND/SETSOCKOPTS)
 * are handled by the caller around this, matching each command's own
 * documented ordering (runbook §2 "Reading it").
 */
static int
round_trip_ok(int sock, int cmd, size_t nbufs, const void *const *ptrs,
    const size_t *lens)
{
	char replybuf[4096];
	ssize_t rlen;
	struct privsep_com_msg *reply;

	if (send_request(sock, cmd, nbufs, ptrs, lens) != 0)
		return -1;
	if ((rlen = recv_reply(sock, replybuf, sizeof(replybuf))) < 0)
		return -1;

	reply = (struct privsep_com_msg *)replybuf;
	if (reply->hdr.ac_cmd != (u_int16_t)cmd)
		return -1; /* drift: this reply belongs to a different request */
	if (reply->hdr.ac_errno != 0)
		return -1;

	return 0;
}

static int
test_no_drift_across_mixed_requests(void)
{
	int sp[2];
	pid_t child;
	int status;
	int i;
	int failed = 0;
	const char ident[] = "framing-identity";
	int keylen = 8;
	const char keypath[] = "/tmp/certs/framing.pem";

	TEST_START("20 mixed GETPSK/EAY_GET_PKCS1PRIVKEY requests, no drift");

	privsep_priv_test_lcconf_init(NULL, NULL);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");
	if ((child = fork()) < 0)
		TEST_FAIL("fork() failed");
	if (child == 0) {
		close(sp[0]);
		_exit(privsep_priv(sp[1]) == 0 ? 0 : 1);
	}
	close(sp[1]);

	for (i = 0; i < 20 && failed == 0; i++) {
		if (i % 2 == 0) {
			const void *ptrs[2] = { ident, &keylen };
			size_t lens[2] = { sizeof(ident), sizeof(keylen) };
			if (round_trip_ok(sp[0], PRIVSEP_GETPSK, 2, ptrs, lens) != 0) {
				printf("\n    GETPSK #%d: drift or failure", i);
				failed++;
			}
		} else {
			const void *ptrs[1] = { keypath };
			size_t lens[1] = { sizeof(keypath) };
			if (round_trip_ok(sp[0], PRIVSEP_EAY_GET_PKCS1PRIVKEY, 1,
			    ptrs, lens) != 0) {
				printf("\n    EAY_GET_PKCS1PRIVKEY #%d: drift or failure", i);
				failed++;
			}
		}
	}

	close(sp[0]);
	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("child did not exit after EOF");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("\n    child exit status: %d", status);
		failed++;
	}

	if (failed != 0)
		TEST_FAIL("drift or a non-clean shutdown occurred");

	TEST_PASS();
	return 0;
}

static int
test_descriptor_accounting_repeated_socket(void)
{
	int sp[2];
	pid_t child;
	int status;
	int i, failed = 0;
	int fds[8];
	int minfd = -1, maxfd = -1;
	struct test_socket_args sa;
	const void *ptrs[1] = { &sa };
	size_t lens[1] = { sizeof(sa) };

	TEST_START("repeated PRIVSEP_SOCKET: one descriptor per request, no fd climb");

	privsep_priv_test_lcconf_init(NULL, NULL);
	memset(&sa, 0, sizeof(sa));
	sa.domain = PF_INET;
	sa.type = SOCK_DGRAM;
	sa.protocol = 0;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");
	if ((child = fork()) < 0)
		TEST_FAIL("fork() failed");
	if (child == 0) {
		close(sp[0]);
		_exit(privsep_priv(sp[1]) == 0 ? 0 : 1);
	}
	close(sp[1]);

	for (i = 0; i < 8; i++) {
		char replybuf[512];
		ssize_t rlen;
		struct privsep_com_msg *reply;

		if (send_request(sp[0], PRIVSEP_SOCKET, 1, ptrs, lens) != 0) {
			printf("\n    request #%d: send failed", i);
			failed++;
			break;
		}
		if ((fds[i] = privsep_rec_fd_unittest(sp[0])) < 0) {
			printf("\n    request #%d: no descriptor (expected exactly one)", i);
			failed++;
			break;
		}
		if ((rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
			printf("\n    request #%d: no reply after the descriptor", i);
			failed++;
			break;
		}
		reply = (struct privsep_com_msg *)replybuf;
		if (reply->hdr.ac_cmd != PRIVSEP_SOCKET || reply->hdr.ac_errno != 0) {
			printf("\n    request #%d: drift or ac_errno=%d", i,
			    reply->hdr.ac_errno);
			failed++;
			break;
		}

		if (minfd == -1 || fds[i] < minfd)
			minfd = fds[i];
		if (maxfd == -1 || fds[i] > maxfd)
			maxfd = fds[i];

		close(fds[i]);
	}

	close(sp[0]);
	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("child did not exit after EOF");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("\n    child exit status: %d", status);
		failed++;
	}

	if (failed == 0 && maxfd - minfd > 2) {
		printf("\n    descriptor spread %d..%d looks like a leak, not reuse",
		    minfd, maxfd);
		failed++;
	}

	if (failed != 0)
		TEST_FAIL("descriptor accounting did not hold across repeats");

	TEST_PASS();
	return 0;
}

static int
test_interleaved_bind_setsockopts_socket(void)
{
	int sp[2];
	pid_t child;
	int status;
	int failed = 0;
	int round;

	TEST_START("interleaved SOCKET/BIND/SETSOCKOPTS, each its documented "
	    "descriptor order, twice");

	privsep_priv_test_lcconf_init(NULL, NULL);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sp) != 0)
		TEST_FAIL("socketpair() failed");
	if ((child = fork()) < 0)
		TEST_FAIL("fork() failed");
	if (child == 0) {
		close(sp[0]);
		_exit(privsep_priv(sp[1]) == 0 ? 0 : 1);
	}
	close(sp[1]);

	for (round = 0; round < 2 && failed == 0; round++) {
		/* SOCKET: descriptor arrives before the reply. */
		{
			struct test_socket_args sa;
			const void *ptrs[1] = { &sa };
			size_t lens[1] = { sizeof(sa) };
			char replybuf[512];
			ssize_t rlen;
			struct privsep_com_msg *reply;
			int fd;

			memset(&sa, 0, sizeof(sa));
			sa.domain = PF_INET; sa.type = SOCK_DGRAM;

			if (send_request(sp[0], PRIVSEP_SOCKET, 1, ptrs, lens) != 0 ||
			    (fd = privsep_rec_fd_unittest(sp[0])) < 0 ||
			    (rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
				printf("\n    round %d: SOCKET desynced", round);
				failed++;
				break;
			}
			reply = (struct privsep_com_msg *)replybuf;
			if (reply->hdr.ac_cmd != PRIVSEP_SOCKET || reply->hdr.ac_errno != 0) {
				printf("\n    round %d: SOCKET drift", round);
				failed++;
			}
			close(fd);
		}

		/* BIND: descriptor sent right after the command, before the reply. */
		{
			struct test_bind_args ba;
			struct sockaddr_in sin;
			const void *ptrs[2];
			size_t lens[2];
			char replybuf[512];
			ssize_t rlen;
			struct privsep_com_msg *reply;
			int s;

			if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
				printf("\n    round %d: local socket() failed", round);
				failed++;
				break;
			}
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_port = 0; /* any ephemeral port: PORT_ISAKMP check
			                     is not what this file is testing */
			memset(&ba, 0, sizeof(ba));
			ba.addrlen = sizeof(sin);
			ptrs[0] = &ba; lens[0] = sizeof(ba);
			ptrs[1] = &sin; lens[1] = sizeof(sin);

			if (send_request(sp[0], PRIVSEP_BIND, 2, ptrs, lens) != 0 ||
			    privsep_send_fd_unittest(sp[0], s) != 0 ||
			    (rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
				printf("\n    round %d: BIND desynced", round);
				close(s);
				failed++;
				break;
			}
			reply = (struct privsep_com_msg *)replybuf;
			/* An ephemeral port (0) is outside the authorized set, so
			 * EPERM is the expected, well-framed answer here -- what
			 * matters for this file is that the reply belongs to this
			 * request (ac_cmd echo), not that the bind was authorized. */
			if (reply->hdr.ac_cmd != PRIVSEP_BIND) {
				printf("\n    round %d: BIND drift", round);
				failed++;
			}
			close(s);
		}

		/* SETSOCKOPTS: same ordering as BIND. */
		{
			struct test_sockopt_args oa;
			char policy[32];
			const void *ptrs[2];
			size_t lens[2];
			char replybuf[512];
			ssize_t rlen;
			struct privsep_com_msg *reply;
			int s;

			if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
				printf("\n    round %d: local socket() failed", round);
				failed++;
				break;
			}
			memset(policy, 0, sizeof(policy));
			memset(&oa, 0, sizeof(oa));
			oa.level = IPPROTO_IP;
			oa.optname = 16; /* IP_IPSEC_POLICY */
			oa.optlen = sizeof(policy);
			ptrs[0] = &oa; lens[0] = sizeof(oa);
			ptrs[1] = policy; lens[1] = sizeof(policy);

			if (send_request(sp[0], PRIVSEP_SETSOCKOPTS, 2, ptrs, lens) != 0 ||
			    privsep_send_fd_unittest(sp[0], s) != 0 ||
			    (rlen = recv_reply(sp[0], replybuf, sizeof(replybuf))) < 0) {
				printf("\n    round %d: SETSOCKOPTS desynced", round);
				close(s);
				failed++;
				break;
			}
			reply = (struct privsep_com_msg *)replybuf;
			if (reply->hdr.ac_cmd != PRIVSEP_SETSOCKOPTS) {
				printf("\n    round %d: SETSOCKOPTS drift", round);
				failed++;
			}
			close(s);
		}
	}

	close(sp[0]);
	if (wait_child_bounded(child, &status) != 0)
		TEST_FAIL("child did not exit after EOF");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		printf("\n    child exit status: %d", status);
		failed++;
	}

	if (failed != 0)
		TEST_FAIL("desync detected in the interleaved sequence");

	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== privsep_priv() handshake framing (runbook Phase 2, "
	    "v0.9.1-hardening-spec.md §2.2 task) ===\n");

	if (test_no_drift_across_mixed_requests() != 0)
		failed++;
	if (test_descriptor_accounting_repeated_socket() != 0)
		failed++;
	if (test_interleaved_bind_setsockopts_socket() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
