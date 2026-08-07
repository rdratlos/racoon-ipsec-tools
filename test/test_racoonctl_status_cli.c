// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for the racoonctl status "-v" CLI bug (issue #139
 * follow-up): get_combuf() (racoonctl.c) shifts av[] past the subcommand
 * word ("ac--; av++;") before calling a handler, so f_status()'s av[0] is
 * already the first real flag, not a conventional argv[0] program name.
 * f_status() used to call libc getopt(ac, av, "vf:") on that shifted
 * vector -- getopt(3) always assumes index 0 is the program name and
 * starts scanning at index 1, so whatever flag landed at av[0] was
 * silently dropped. "racoonctl status -v" alone (av == {"-v"}) lost -v
 * entirely and silently fell back to non-verbose; "-v -f json" happened
 * to work by accident because only the *first* token was ever dropped and
 * -f/json occupied indices 1-2. f_status() now hand-scans av[] for -v/-f/
 * --format= instead of calling getopt() at all (same fix class as every
 * other subcommand handler in this file already uses).
 *
 * These tests exercise av[] exactly as get_combuf() constructs it --
 * "-v" as the sole, first element -- which is precisely the case a
 * combined "-v -f json" test cannot catch.
 *
 * f_status() is static; f_status_unittest() is a thin -DENABLE_UNITTEST
 * wrapper in racoonctl.c, same pattern as f_logoutusr_unittest() and
 * friends. racoonctl.c is pulled in via racoonctl_unittest_src.c, this
 * suite's established wrapper for testing this file's static functions.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "var.h"
#include "vmbuf.h"
#include "admin.h"

extern vchar_t *f_status_unittest(int ac, char **av);

#define TEST_PASS() do { printf("\xe2\x9c\x93 PASS\n"); } while (0)
#define TEST_FAIL(msg) do { printf("\xe2\x9c\x97 FAIL: %s\n", msg); return -1; } while (0)
#define TEST_START(name) do { printf("\n[TEST] %s ... ", name); fflush(stdout); } while (0)

static int
check_status(const char *label, char **av, int ac, u_int16_t expect_cmd,
    u_int16_t expect_proto)
{
	vchar_t *buf;
	struct admin_com *com;

	TEST_START(label);

	buf = f_status_unittest(ac, av);
	if (buf == NULL)
		TEST_FAIL("f_status_unittest returned NULL");
	if (buf->l != sizeof(struct admin_com)) {
		vfree(buf);
		TEST_FAIL("unexpected request size");
	}

	com = (struct admin_com *)buf->v;

	if ((com->ac_cmd & ~ADMIN_FLAG_VERSION) != expect_cmd) {
		printf("(ac_cmd=0x%04x, expected 0x%04x) ",
		    com->ac_cmd & ~ADMIN_FLAG_VERSION, expect_cmd);
		vfree(buf);
		TEST_FAIL("wrong ADMIN_STATUS command (verbose flag not honored)");
	}
	if (com->ac_proto != expect_proto) {
		printf("(ac_proto=%d, expected %d) ", com->ac_proto, expect_proto);
		vfree(buf);
		TEST_FAIL("wrong format (ac_proto)");
	}

	vfree(buf);
	TEST_PASS();
	return 0;
}

int
main(void)
{
	int failed = 0;
	char *av_v_only[] = { "-v" };
	char *av_f_json_only[] = { "-f", "json" };
	char *av_v_f_json[] = { "-v", "-f", "json" };
	char *av_v_format_json[] = { "-v", "--format=json" };
	char *av_none[] = { NULL };

	printf("\n=== racoonctl f_status() CLI parsing test (\"-v\" bug) ===\n");

	/* The case that shipped broken: "-v" as the sole argument. Before
	 * the fix, getopt() treated it as argv[0] (the assumed program
	 * name) and never saw it as an option -- this must now set
	 * ADMIN_STATUS_VERBOSE with the default text format. */
	if (check_status("status -v (alone, no -f)", av_v_only, 1,
	    ADMIN_STATUS_VERBOSE, ADMIN_STATUS_FORMAT_TEXT) != 0)
		failed++;

	/* No -v: must stay non-verbose. */
	if (check_status("status -f json (no -v)", av_f_json_only, 2,
	    ADMIN_STATUS, ADMIN_STATUS_FORMAT_JSON) != 0)
		failed++;

	/* The combination that happened to work by accident before the fix
	 * (only the first token was ever dropped) -- must still work now. */
	if (check_status("status -v -f json", av_v_f_json, 3,
	    ADMIN_STATUS_VERBOSE, ADMIN_STATUS_FORMAT_JSON) != 0)
		failed++;

	/* -v combined with the --format= long option. */
	if (check_status("status -v --format=json", av_v_format_json, 2,
	    ADMIN_STATUS_VERBOSE, ADMIN_STATUS_FORMAT_JSON) != 0)
		failed++;

	/* No flags at all: default text, non-verbose. */
	if (check_status("status (no flags)", av_none, 0,
	    ADMIN_STATUS, ADMIN_STATUS_FORMAT_TEXT) != 0)
		failed++;

	printf("\n=== Results: %d failed ===\n", failed);
	return failed ? 1 : 0;
}
