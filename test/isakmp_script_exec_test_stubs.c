// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stub for test_script_exec_wait.
 *
 * script_exec() (isakmp.c) references script_names[] (the human-readable
 * name it logs and passes as argv[1]) by name; the real array lives in
 * remoteconf.c, which pulls in far more than this test needs. Mirrors
 * remoteconf.c's definition, same as isakmp_script_hook_test_stubs.c.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

#include "remoteconf.h"

char *script_names[SCRIPT_MAX + 1] = {
	"phase1_up", "phase1_down", "phase1_dead" };
