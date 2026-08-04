// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
 */

/*
 * Stub for test_ipsec_doi_sa.
 *
 * On builds with GSS-API support (--enable-gssapi), t2isakmpsa() references
 * the global `lcconf` in its OAKLEY_ATTR_GSS_ID branch.  That branch is never
 * exercised by the test (it sends no GSS_ID attribute), but the symbol must
 * resolve at link time.  Providing a NULL lcconf here avoids pulling in
 * localconf.o and its dependency closure.  This mirrors rsalist_test_stubs.c.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>

#include "vmbuf.h"
#include "localconf.h"

struct localconf *lcconf = NULL;
