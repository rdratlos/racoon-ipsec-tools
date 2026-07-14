// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Regression test for the REMOTE_ID memory leak in script_hook() (issue
 * #72): ipsecdoi_id2str()'s return value was passed straight into
 * script_env_append() without ever being captured or freed.
 *
 * script_hook() and script_env_append() are non-static; isakmp.c is
 * compiled here (isakmp_unittest_src.c) with -ffunction-sections and linked
 * with --gc-sections so its large, otherwise-unrelated dependency closure
 * is discarded, leaving only what script_hook()'s REMOTE_ID path actually
 * calls. isakmp_script_hook_test_stubs.c substitutes test doubles for
 * ipsecdoi_id2str(), privsep_script_exec() and isakmp_cfg_setenv() -- see
 * that file's header comment for why.
 *
 * test_leak_normal_id() detects the leak itself without needing valgrind:
 * the test binary is linked with -Wl,--wrap=free (see test/Makefile.am),
 * so every free() call made from our own compiled objects is observable;
 * __wrap_free() below watches specifically for a free() of the pointer our
 * ipsecdoi_id2str() stub returned. This is additionally confirmed live with
 * `make check-valgrind`, the method that originally caught this bug.
 *
 * test_null_id2str_result_does_not_crash() is the case requested during
 * review of issue #72: what does script_hook() do if ipsecdoi_id2str()
 * returns NULL (its documented OOM path)? script_env_append() unconditionally
 * computes strlen(name) + 1 + strlen(value) + 1 -- strlen(NULL) is undefined
 * behaviour -- so this reproduces as a crash today, independently of the
 * leak itself. The child is forked off so that crash does not take the rest
 * of the test suite down with it.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "var.h"
#include "vmbuf.h"
#include "gcmalloc.h"
#include "handler.h"
#include "remoteconf.h"
#include "isakmp_var.h"

extern void script_hook(struct ph1handle *iph1, int script);

/* From isakmp_script_hook_test_stubs.c */
extern char *test_stub_id2str_next_result;
extern int test_stub_id2str_return_null;
extern int test_stub_id2str_calls;
extern int test_stub_privsep_script_exec_calls;

/* Linker-level free() interposition (-Wl,--wrap=free in test/Makefile.am):
 * every free() call made from code compiled into this binary is redirected
 * here first. We only ever compare pointer *values* against what the
 * ipsecdoi_id2str() stub last handed out -- never dereference a freed
 * pointer -- so this is safe under ASan/valgrind too. */
extern void __real_free(void *ptr);
static int id2str_result_freed = 0;

void
__wrap_free(void *ptr)
{
	if (ptr != NULL && ptr == test_stub_id2str_next_result)
		id2str_result_freed = 1;
	__real_free(ptr);
}

static struct ph1handle *
make_ph1handle_with_script(void)
{
	static struct sockaddr_in local, remote;
	static vchar_t id_p;
	static char id_p_data[4];
	struct ph1handle *iph1;
	struct remoteconf *rmconf;
	static const char script_path[] = "/bin/true";

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(500);
	inet_pton(AF_INET, "192.0.2.1", &local.sin_addr);

	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(500);
	inet_pton(AF_INET, "192.0.2.2", &remote.sin_addr);

	memset(id_p_data, 0, sizeof(id_p_data));
	id_p.v = id_p_data;
	id_p.l = sizeof(id_p_data);

	rmconf = racoon_calloc(1, sizeof(*rmconf));
	rmconf->script[SCRIPT_PHASE1_UP] = vmalloc(sizeof(script_path) - 1);
	memcpy(rmconf->script[SCRIPT_PHASE1_UP]->v, script_path,
	    sizeof(script_path) - 1);

	iph1 = racoon_calloc(1, sizeof(*iph1));
	iph1->local = (struct sockaddr *)&local;
	iph1->remote = (struct sockaddr *)&remote;
	iph1->id_p = &id_p;
	iph1->rmconf = rmconf;

	return iph1;
}

static void
free_ph1handle_with_script(struct ph1handle *iph1)
{
	vfree(iph1->rmconf->script[SCRIPT_PHASE1_UP]);
	racoon_free(iph1->rmconf);
	racoon_free(iph1);
}

static int failures = 0;

#define CHECK(cond, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
			failures++; \
		} else { \
			printf("PASS: %s\n", msg); \
		} \
	} while (0)

static void
test_leak_normal_id(void)
{
	struct ph1handle *iph1 = make_ph1handle_with_script();

	test_stub_id2str_return_null = 0;
	test_stub_id2str_calls = 0;
	test_stub_privsep_script_exec_calls = 0;
	id2str_result_freed = 0;
	test_stub_id2str_next_result = NULL;

	script_hook(iph1, SCRIPT_PHASE1_UP);

	CHECK(test_stub_id2str_calls == 1,
	    "ipsecdoi_id2str() is called once for REMOTE_ID");
	CHECK(test_stub_privsep_script_exec_calls == 1,
	    "the configured phase1_up script is invoked");
	CHECK(id2str_result_freed,
	    "the REMOTE_ID string returned by ipsecdoi_id2str() must be freed "
	    "by script_hook() (regression test for issue #72)");

	free_ph1handle_with_script(iph1);
}

static void
test_null_id2str_result_does_not_crash(void)
{
	pid_t pid;
	int status;

	fflush(stdout);
	fflush(stderr);

	pid = fork();
	if (pid < 0) {
		CHECK(0, "fork() failed");
		return;
	}
	if (pid == 0) {
		/* Child: exercise the OOM path in isolation so a crash here
		 * does not take the rest of the suite down with it. */
		struct ph1handle *iph1 = make_ph1handle_with_script();
		test_stub_id2str_return_null = 1;
		script_hook(iph1, SCRIPT_PHASE1_UP);
		free_ph1handle_with_script(iph1);
		_exit(0);
	}

	if (waitpid(pid, &status, 0) != pid) {
		CHECK(0, "waitpid() failed");
		return;
	}

	if (WIFSIGNALED(status)) {
		fprintf(stderr,
		    "FAIL: script_hook() must not crash when ipsecdoi_id2str() "
		    "returns NULL (its documented OOM path) -- child killed by "
		    "signal %d (script_env_append()'s strlen(NULL) is undefined "
		    "behaviour -- issue #72) (%s:%d)\n",
		    WTERMSIG(status), __FILE__, __LINE__);
		failures++;
	} else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		printf("PASS: script_hook() does not crash when "
		    "ipsecdoi_id2str() returns NULL\n");
	} else {
		fprintf(stderr,
		    "FAIL: child exited abnormally, status=0x%x (%s:%d)\n",
		    status, __FILE__, __LINE__);
		failures++;
	}
}

int
main(void)
{
	test_leak_normal_id();
	test_null_id2str_result_does_not_crash();

	if (failures > 0) {
		fprintf(stderr, "\n%d check(s) failed\n", failures);
		return 1;
	}

	printf("\nAll checks passed\n");
	return 0;
}
