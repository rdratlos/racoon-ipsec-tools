/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools -- https://github.com/rdratlos/racoon-ipsec-tools
 */

#ifndef _STATUS_H
#define _STATUS_H

/*
 * racoonctl status (ADMIN_STATUS / ADMIN_STATUS_VERBOSE): read-only
 * introspection over live phase1/phase2 SA state.
 *
 * status_dump() walks ph1tree/ph2tree exactly once into a plain snapshot
 * (struct status_ph1/status_ph2 below), then renders that snapshot as
 * either text or JSON depending on json_format. Two independent renderers
 * over one shared extraction pass, per the design in
 * doc/dev/racoonctl-status-analysis.md (D1) and issue #139: neither
 * renderer touches ph1tree/ph2tree directly, and the extraction pass
 * itself needs no locking -- admin_process() runs on the same
 * single-threaded monitor_fd() event loop as isakmp_handler(), so nothing
 * can mutate a handle while status_dump() is reading it (see D2's
 * call-chain trace in the analysis doc / issue #139 for why this holds).
 */
extern void status_dump(vchar_t **out, int verbose, int json_format);

#endif /* _STATUS_H */
