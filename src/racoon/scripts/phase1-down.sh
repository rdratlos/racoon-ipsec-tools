#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
#
# phase1-down.sh - racoon phase1-down script hook
#
# Called by racoon when Phase 1 tears down (timeout, error, or explicit
# disconnection). This script is a pure undo replay (§3.4): it never
# re-derives the outbound interface, the split-include networks, the DNS
# servers, or which backend was in use -- all of that already lives in
# the state file phase1-up.sh journaled, one line per step that actually
# succeeded, and that state file is the *only* thing phase1-down.sh
# consults. This is deliberate: re-deriving any of it here risks
# reaching a different answer than phase1-up.sh did (a different
# resolver having taken over in between, a route already changed by
# something else) and undoing the wrong thing.
#
# All replay logic (reverse order, per-step outcome, retry-safe partial
# failure handling) lives in racoon-hook-lib.sh's rhook_undo_replay() so
# it is exercised by the same fixture-driven tests as the rest of the
# plan/apply machinery.
#
# POSIX sh only (dash / bash / NetBSD /bin/sh); see racoon-hook-lib.sh's
# header for the shared portability rules.

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=racoon-hook-lib.sh
. "$SCRIPT_DIR/racoon-hook-lib.sh"

# shellcheck disable=SC2034
# RHOOK_HOOK_NAME/RHOOK_REPORT_HEADER (below) are read by the sourced
# library, not this file -- shellcheck cannot see across the `.` above.
RHOOK_HOOK_NAME="phase1-down"
rhook_load_config
rhook_trace_init
trap rhook_exit_trap EXIT

rhook_log step "phase1 down: remote=${REMOTE_ADDR:-?}:${REMOTE_PORT:-?} internal=${INTERNAL_ADDR4:-?}"

# --------------------------------------------------------------------------
# Issue #90: state files are matched per peer address by an exact
# IKE_COOKIE match, not by generation order. REMOTE_PORT is not part of
# the identity either (it floats on a NAT-T rebind and changes across a
# reconnect), and generation order alone is not enough: a live field test
# showed a teardown for an old SA and the setup for its replacement
# running within one second of each other for the same peer, and a
# separate live host showed a session that was never cleanly torn down
# leaving a permanent orphaned generation behind -- a later, unrelated
# session's own teardown must not accidentally consume that orphan just
# because it happens to be the oldest live one. IKE_COOKIE (exported by
# racoon's own script_hook(), src/racoon/isakmp.c) is the ISAKMP cookie
# pair, unique per Phase 1 negotiation and stable from this exact
# session's own SCRIPT_PHASE1_UP through this SCRIPT_PHASE1_DOWN call --
# rhook_state_own_generation() matches on it exactly, never guesses.
#
# An empty result means either phase1-up.sh never got far enough to
# change anything (Mode Config was rejected, or every step failed before
# any state was journaled), this generation was already consumed, or (in
# principle) IKE_COOKIE itself was unset. Either way there is nothing
# *this session* can identify as its own to undo, and nothing here
# depends on INTERNAL_ADDR4/SPLIT_INCLUDE/etc. being set at all (§3.4).
# --------------------------------------------------------------------------
RHOOK_P1D_STATE_FILE=$(rhook_state_own_generation)
if [ -z "$RHOOK_P1D_STATE_FILE" ]; then
	rhook_log warn "no live state generation matches this session's own IKE_COOKIE for remote=${REMOTE_ADDR:-unknown} -- nothing to undo"
	exit 0
fi

rhook_report_init
# shellcheck disable=SC2034  # read by rhook_emit_report() in the sourced library
RHOOK_REPORT_HEADER="undo replay for remote=${REMOTE_ADDR:-?} internal=${INTERNAL_ADDR4:-?} (state: $RHOOK_P1D_STATE_FILE)"

rhook_undo_replay "$RHOOK_P1D_STATE_FILE"
RHOOK_P1D_RC=$?

# Same policy, same rationale as phase1-up.sh (brief 3 §H): "report" and
# "rollback" both surface a non-clean teardown via this script's own exit
# status (for whatever is watching the process), "warn" (the default)
# always exits 0. "rollback" has nothing extra to do here specifically --
# a teardown has no "forward progress" left to undo beyond the teardown
# itself -- so it behaves identically to "report" in this script; the
# distinction only matters in phase1-up.sh. Either way rhook_undo_replay()
# already retained this generation's state file for anything that failed
# to undo, so a later phase1-down.sh run (or a manual retry) -- with the
# same IKE_COOKIE, since it is the same underlying connection attempt --
# will pick up this exact generation again by the same exact match,
# rather than this exit code being the only record.
if [ "$RHOOK_P1D_RC" -ne 0 ] && [ "$RHOOK_ON_DNS_FAILURE" != "warn" ]; then
	exit 1
fi
exit 0
