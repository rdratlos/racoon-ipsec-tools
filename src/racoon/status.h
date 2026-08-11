/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
 *
 * Part of rdratlos/racoon-ipsec-tools -- https://github.com/rdratlos/racoon-ipsec-tools
 */

#ifndef _STATUS_H
#define _STATUS_H

/*
 * The JSON rendering's schema_version, "major.minor" per D4: additive
 * changes bump minor, breaking changes bump major and reset minor to 0.
 *
 * This is the C-side single source of truth -- status.c's JSON renderer
 * builds the wire string from it by literal concatenation, and
 * test/test_status_dump.c pins its assertion against the same macro rather
 * than a second copy of the value, so the renderer and its test cannot
 * disagree without failing to build.
 *
 * Two more copies necessarily live outside C and cannot include this
 * header: share/schema/racoonctl-status.schema.json's
 * properties.schema_version.const, and racoonctl.1.in's worked JSON
 * example. tools/schema_cross_check.py reads this define and compares all
 * three, and is CI-wired, so a bump that updates some but not all of them
 * fails there rather than shipping a daemon and a schema that disagree.
 *
 * Deliberately NOT derived from PACKAGE_VERSION/configure.ac: the schema
 * and the racoon package are independent version ladders (D4). A package
 * release that changes no status.c JSON must not bump this, and a schema
 * change must not require an autoreconf.
 */
#define RACOONCTL_STATUS_SCHEMA_VERSION	"2.0"

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
