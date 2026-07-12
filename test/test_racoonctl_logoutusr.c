// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for issue #68: f_logoutusr() (racoonctl.c) built its
 * ADMIN_LOGOUT_USER request buffer with make_request(..., userlen) --
 * exactly `userlen` payload bytes past the struct admin_com header --
 * then copied `userlen + 1` bytes into it (the username plus its NUL
 * terminator), a 1-byte heap buffer overflow that fired on every
 * non-empty invocation.
 *
 * Fixed by switching the copy to
 *   strlcpy(buf->v + sizeof(struct admin_com), user,
 *           buf->l - sizeof(struct admin_com))
 * which binds the copy to the buffer's actual allocated capacity.
 *
 * Each username buffer below is allocated to the exact size make_request()
 * would produce, so a 1-byte overflow is an invalid heap write under
 * valgrind (the repo's `make check-valgrind`) regardless of what happens
 * to sit in the adjacent heap chunk. The correctness assertions (the
 * daemon-bound username must round-trip unchanged) additionally catch a
 * plain `make check` regression if a future change to either
 * make_request()'s sizing or this copy reintroduces truncation.
 *
 * f_logoutusr() is static; f_logoutusr_unittest() is a thin -DENABLE_UNITTEST
 * wrapper in racoonctl.c. racoonctl.c is pulled in via a local wrapper
 * source (racoonctl_unittest_src.c) that renames its own main() out of the
 * way, following this project's established unit-test-a-static-function
 * pattern. Built with -ffunction-sections and linked with --gc-sections, so
 * only f_logoutusr()/make_request()'s reachable closure (vmalloc/vfree,
 * strlcpy, errx) is retained.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "var.h"
#include "vmbuf.h"
#include "admin.h"

/* f_logoutusr() exposed via -DENABLE_UNITTEST in racoonctl.c. */
extern vchar_t *f_logoutusr_unittest(int ac, char **av);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

/*
 * Drives f_logoutusr_unittest() with a single username argument and
 * checks:
 *   1. the returned buffer is exactly sizeof(struct admin_com) + strlen(user)
 *      bytes -- the same size make_request() itself would produce, so this
 *      also pins down the size assertion against a future make_request()
 *      change;
 *   2. the payload written past the header round-trips the full username,
 *      not a truncated prefix;
 *   3. the payload is NUL-terminated within the allocated buffer.
 *
 * A pre-#68-fix build overflows the vmalloc'd buffer by one byte while
 * copying (invalid write under valgrind, though the in-bounds bytes
 * happen to still hold the full username since strncpy's bound was
 * userlen+1). A build that "fixes" the overflow by shrinking the strlcpy
 * bound to fit the undersized buffer without also enlarging the buffer
 * itself stays memory-safe but truncates the last character of the
 * username -- caught here by the round-trip check, not by valgrind.
 */
static int
check_logoutusr(const char *user)
{
	char label[64];
	char *av[1];
	vchar_t *buf;
	size_t userlen = strlen(user);
	size_t expect_len = sizeof(struct admin_com) + userlen;
	char *payload;

	snprintf(label, sizeof(label), "logout-user \"%s\" (len %zu)", user, userlen);
	TEST_START(label);

	/* f_logoutusr()'s av[0] is not modified; the cast drops const. */
	av[0] = (char *)user;
	buf = f_logoutusr_unittest(1, av);
	if (buf == NULL)
		TEST_FAIL("f_logoutusr_unittest returned NULL");

	if (buf->l != expect_len) {
		printf("(buf->l=%zu, expected %zu) ", buf->l, expect_len);
		vfree(buf);
		TEST_FAIL("request buffer size mismatch");
	}

	payload = buf->v + sizeof(struct admin_com);

	if (strlen(payload) != userlen) {
		printf("(copied username length %zu, expected %zu: \"%s\") ",
		    strlen(payload), userlen, payload);
		vfree(buf);
		TEST_FAIL("username was truncated in the request buffer");
	}

	if (strcmp(payload, user) != 0) {
		printf("(copied \"%s\", expected \"%s\") ", payload, user);
		vfree(buf);
		TEST_FAIL("copied username does not match input");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;
	char maxlen_user[32]; /* LOGINLEN (31) + NUL, see isakmp_cfg.h */
	size_t i;

	printf("\n=== racoonctl f_logoutusr() request-buffer test (issue #68) ===\n");

	if (check_logoutusr("x") != 0)		/* 1 char: smallest realistic case */
		failed++;
	if (check_logoutusr("ab") != 0)	/* 2 chars */
		failed++;
	if (check_logoutusr("alice") != 0)	/* typical username */
		failed++;

	/* LOGINLEN (31): the longest username f_logoutusr() accepts. */
	for (i = 0; i < sizeof(maxlen_user) - 1; i++)
		maxlen_user[i] = 'a' + (i % 26);
	maxlen_user[sizeof(maxlen_user) - 1] = '\0';
	if (check_logoutusr(maxlen_user) != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
