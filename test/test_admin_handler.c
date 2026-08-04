// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for admin_handler() (admin.c) -- the monitor_fd()
 * callback admin_init() registers on the admin listener socket
 * (evt.c/session.c drive it the same way any other monitored fd's
 * readable event is dispatched). Every branch depends on
 * lcconf->sock_admin already being a real, connected admin socket, so
 * this test builds one directly: a real AF_UNIX listening socket bound
 * in a throwaway temp directory, with a client already connect()ed (and,
 * for the success/short-header cases, having already send()'t its
 * request) before admin_handler_unittest() is called -- accept() on a
 * backlogged AF_UNIX listener and a peer's already-buffered send() both
 * complete synchronously, so no second thread/process is needed.
 *
 * admin_handler_unittest() (admin.c, ENABLE_UNITTEST) is a thin wrapper:
 * admin_handler() itself is static and ignores its (ctx, fd) parameters
 * in favor of lcconf->sock_admin, so the wrapper takes neither.
 *
 * Calls the real admin_process() (same as admin_handler() does in
 * production), so this reuses admin_test_stubs.c exactly as
 * test_admin_delete_all_sa_dst.c does; the request bodies below only
 * ever use ADMIN_RELOAD_CONF, whose one dependency (signal_handler()) is
 * already stubbed there.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "vmbuf.h"
#include "localconf.h"
#include "admin.h"

extern int admin_handler_unittest(void);
extern struct localconf *lcconf;
extern int admin_test_evt_subscribe_calls;

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

struct admin_fixture {
	char dir[512];
	char orig_cwd[4096];
	int listen_fd;
	int client_fd;
};

/*
 * Sets up a listening AF_UNIX socket at ./sock inside a fresh temp
 * directory (chdir()'d into, same reasoning as test_admin_init.c's
 * helper: a relative path keeps sockaddr_un.sun_path trivially short)
 * and a connected client. Does NOT accept() -- that is what
 * admin_handler_unittest() itself will do.
 */
static int
admin_fixture_setup(struct admin_fixture *f)
{
	static char base[] = "/tmp/admin_handler_test.XXXXXX";
	char tmpl[sizeof(base)];
	struct sockaddr_un sun;

	memcpy(tmpl, base, sizeof(base));
	if (mkdtemp(tmpl) == NULL)
		return -1;
	if (getcwd(f->orig_cwd, sizeof(f->orig_cwd)) == NULL) {
		rmdir(tmpl);
		return -1;
	}
	if (chdir(tmpl) != 0) {
		rmdir(tmpl);
		return -1;
	}
	snprintf(f->dir, sizeof(f->dir), "%s", tmpl);

	f->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (f->listen_fd < 0)
		return -1;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	memcpy(sun.sun_path, "sock", 4);
	if (bind(f->listen_fd, (struct sockaddr *)&sun, sizeof(sun)) != 0)
		return -1;
	if (listen(f->listen_fd, 1) != 0)
		return -1;

	f->client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (f->client_fd < 0)
		return -1;
	if (connect(f->client_fd, (struct sockaddr *)&sun, sizeof(sun)) != 0)
		return -1;

	lcconf->sock_admin = f->listen_fd;
	return 0;
}

static void
admin_fixture_teardown(struct admin_fixture *f)
{
	if (f->client_fd >= 0)
		close(f->client_fd);
	if (f->listen_fd >= 0)
		close(f->listen_fd);
	unlink("sock");
	if (chdir(f->orig_cwd) != 0) {
		fprintf(stderr, "warning: chdir(\"%s\") failed: %s\n",
		    f->orig_cwd, strerror(errno));
	}
	rmdir(f->dir);
}

static int
fd_is_open(int fd)
{
	return fcntl(fd, F_GETFD) != -1;
}

static int
test_full_round_trip_closes_connection(void)
{
	struct admin_fixture f;
	struct admin_com req, reply;
	ssize_t n;
	int rc;

	TEST_START("a well-formed request gets a reply and the connection is closed");

	if (admin_fixture_setup(&f) != 0) {
		admin_fixture_teardown(&f);
		TEST_FAIL("failed to set up the fixture admin socket");
	}
	admin_test_evt_subscribe_calls = 0;

	memset(&req, 0, sizeof(req));
	req.ac_len = sizeof(req);
	req.ac_cmd = ADMIN_RELOAD_CONF;
	if (send(f.client_fd, &req, sizeof(req), 0) != (ssize_t)sizeof(req)) {
		admin_fixture_teardown(&f);
		TEST_FAIL("failed to send the request from the client end");
	}

	rc = admin_handler_unittest();

	if (rc != 0) {
		admin_fixture_teardown(&f);
		printf("admin_handler() returned %d, expected 0 ", rc);
		TEST_FAIL("wrong return value for a well-formed, successfully-replied request");
	}

	n = recv(f.client_fd, &reply, sizeof(reply), MSG_DONTWAIT);
	if (n < (ssize_t)sizeof(struct admin_com)) {
		admin_fixture_teardown(&f);
		TEST_FAIL("client never received a reply");
	}
	if ((reply.ac_cmd & ~ADMIN_FLAG_VERSION) != ADMIN_RELOAD_CONF) {
		admin_fixture_teardown(&f);
		TEST_FAIL("reply ac_cmd does not echo the request");
	}
	if (admin_test_evt_subscribe_calls != 0) {
		admin_fixture_teardown(&f);
		TEST_FAIL("evt_subscribe() fired for an unversioned, non-event request");
	}

	/* error != -2, so admin_handler() must have close()d so2 -- observe
	 * that from the client side as EOF on its next read. */
	n = recv(f.client_fd, &reply, sizeof(reply), MSG_DONTWAIT);
	if (n != 0) {
		admin_fixture_teardown(&f);
		TEST_FAIL("server-side connection was not closed after a non-(-2) return");
	}

	admin_fixture_teardown(&f);
	TEST_PASS();
	return 0;
}

static int
test_accept_failure_returns_minus_one(void)
{
	int rc;

	TEST_START("admin_handler() reports failure instead of crashing when accept() fails");

	lcconf->sock_admin = -1; /* not a valid fd: accept() must fail */
	rc = admin_handler_unittest();

	if (rc != -1)
		TEST_FAIL("admin_handler() did not return -1 for a failed accept()");

	TEST_PASS();
	return 0;
}

static int
test_short_header_is_rejected_and_connection_closed(void)
{
	struct admin_fixture f;
	char partial[2] = { 0x01, 0x00 };
	int rc;
	ssize_t n;
	char buf[16];

	TEST_START("a header shorter than struct admin_com is rejected, connection closed");

	if (admin_fixture_setup(&f) != 0) {
		admin_fixture_teardown(&f);
		TEST_FAIL("failed to set up the fixture admin socket");
	}

	/* Fewer bytes than sizeof(struct admin_com): recv(MSG_PEEK) returns
	 * whatever is currently queued, which is less than admin_handler()
	 * requires, without waiting for more to arrive. */
	if (send(f.client_fd, partial, sizeof(partial), 0) != (ssize_t)sizeof(partial)) {
		admin_fixture_teardown(&f);
		TEST_FAIL("failed to send a short header from the client end");
	}

	rc = admin_handler_unittest();

	if (rc != -1) {
		admin_fixture_teardown(&f);
		printf("admin_handler() returned %d, expected -1 ", rc);
		TEST_FAIL("a short header should be rejected with -1");
	}

	/*
	 * The server only ever recv(MSG_PEEK)'d the 2 bytes -- never
	 * actually consumed them -- before close()ing so2. Closing an
	 * AF_UNIX SOCK_STREAM socket with unread data still queued makes
	 * Linux send RST instead of a clean FIN, so the client observes
	 * ECONNRESET rather than EOF (0) on its next read; both mean the
	 * same thing here (the server side is gone), so accept either.
	 */
	n = recv(f.client_fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (n != 0 && !(n < 0 && errno == ECONNRESET)) {
		admin_fixture_teardown(&f);
		printf("recv() returned %zd (errno=%d) ", n, errno);
		TEST_FAIL("connection was not closed after rejecting a short header");
	}

	admin_fixture_teardown(&f);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;

	printf("\n=== admin_handler() test ===\n");

	if (test_full_round_trip_closes_connection() != 0)
		failed++;
	if (test_accept_failure_returns_minus_one() != 0)
		failed++;
	if (test_short_header_is_rejected_and_connection_closed() != 0)
		failed++;

	printf("\n=== %s ===\n", failed == 0 ? "ALL TESTS PASSED" : "TESTS FAILED");

	return failed == 0 ? 0 : 1;
}
