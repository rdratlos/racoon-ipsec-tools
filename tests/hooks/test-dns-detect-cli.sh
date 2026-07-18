#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# test-dns-detect-cli.sh - smoke tests for the racoon-dns-detect CLI (§5.4):
# argument parsing, --format=kv vs text output, --dry-run plan preview, and
# that CLI-supplied simulation parameters go through the same §4 whitelist
# validation as real Mode Config input (a CLI flag is no less untrusted).
# Run directly: sh tests/hooks/test-dns-detect-cli.sh

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CLI="$SCRIPT_DIR/../../src/scripts/racoon-dns-detect"

TESTS_RUN=0
TESTS_FAILED=0

fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "FAIL: $1"; }

assert_eq() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ "$2" = "$3" ]; then :; else fail "$1 -- expected '$3', got '$2'"; fi
}

assert_contains() {
	TESTS_RUN=$((TESTS_RUN + 1))
	case "$2" in
		*"$3"*) ;;
		*) fail "$1 -- '$3' not found in output" ;;
	esac
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/racoon-dns-detect-cli.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

export RACOON_HOOK_STATE_DIR="$WORK/run"
export RACOON_HOOK_CONF="$WORK/nonexistent-hooks.conf"

# ==========================================================================
# --help: usage text, exit 0, no state touched.
# ==========================================================================
out=$(sh "$CLI" --help 2>&1)
rc=$?
assert_eq "--help exits 0" "$rc" "0"
assert_contains "--help shows usage" "$out" "Usage: racoon-dns-detect"

# ==========================================================================
# Unrecognized option: usage on stderr, exit 1.
# ==========================================================================
out=$(sh "$CLI" --not-a-real-flag 2>&1)
rc=$?
assert_eq "unrecognized option exits 1" "$rc" "1"
assert_contains "unrecognized option names the bad flag" "$out" "unrecognized option: --not-a-real-flag"

# ==========================================================================
# --detect (default action, no flags): text report, exit 0.
# ==========================================================================
out=$(sh "$CLI" 2>&1)
rc=$?
assert_eq "no-args run (implicit --detect) exits 0" "$rc" "0"
assert_contains "default run prints the report header" "$out" "resolv.conf landscape and split-DNS backend report"
assert_contains "default run reports a classified backend" "$out" "Classified backend:"

# ==========================================================================
# --format=kv: parser output is a flat key=value stream, no prose lines.
# ==========================================================================
out=$(sh "$CLI" --detect --format=kv 2>&1)
rc=$?
assert_eq "--format=kv exits 0" "$rc" "0"
assert_contains "kv output includes backend_classified" "$out" "backend_classified="
assert_contains "kv output includes glibc_reader" "$out" "glibc_reader="
TESTS_RUN=$((TESTS_RUN + 1))
if printf '%s\n' "$out" | grep -q "^racoon-dns-detect:"; then
	fail "kv output must not include the human-readable report header"
fi

# ==========================================================================
# --dry-run with default (RFC 5737/6890 sample) parameters: a full plan,
# never executed, ending in the fallback backend on a bare test box with
# no resolver manager stubbed onto PATH.
# ==========================================================================
out=$(sh "$CLI" --dry-run --explain 2>&1)
rc=$?
assert_eq "--dry-run exits 0" "$rc" "0"
assert_contains "dry-run marks itself as simulated" "$out" "Simulated plan (nothing below is executed)"
assert_contains "dry-run --explain shows the apply command" "$out" "apply: ip link add"
assert_contains "dry-run notes it used sample values when none were given" "$out" "using RFC 5737 documentation-reserved sample values"
TESTS_RUN=$((TESTS_RUN + 1))
if [ -e "$WORK/run" ] && find "$WORK/run" -name 'plan.*' 2>/dev/null | grep -q .; then
	fail "dry-run must not leave a plan file behind (R1: no persistent state from a detect-only run)"
fi

# --dry-run without --explain: step list only, no apply/undo command lines.
out=$(sh "$CLI" --dry-run 2>&1)
TESTS_RUN=$((TESTS_RUN + 1))
if printf '%s\n' "$out" | grep -q "    apply:"; then
	fail "--dry-run without --explain must not print apply/undo command lines"
fi

# --dry-run --format=kv: numbered plan_step_N_* keys plus a total count.
out=$(sh "$CLI" --dry-run --format=kv 2>&1)
assert_contains "dry-run kv includes plan_step_1_id" "$out" "plan_step_1_id="
assert_contains "dry-run kv includes a step count" "$out" "plan_step_count="

# ==========================================================================
# CLI-supplied simulation parameters are validated exactly like real Mode
# Config input -- reject-on-first-bad-element, not sanitize, matching the
# brief's named injection vectors.
# ==========================================================================
out=$(sh "$CLI" --dry-run --dns="10.0.0.1;rm -rf /" 2>&1)
rc=$?
assert_eq "route/command injection in --dns is rejected (exit 1)" "$rc" "1"
assert_contains "--dns rejection names the reason" "$out" "--dns rejected:"

out=$(sh "$CLI" --dry-run --routes="default via 10.6.6.6" 2>&1)
rc=$?
assert_eq "named route-injection vector in --routes is rejected (exit 1)" "$rc" "1"

out=$(sh "$CLI" --dry-run --iface='eth0;touch /tmp/pwned' 2>&1)
rc=$?
assert_eq "shell metacharacters in --iface are rejected (exit 1)" "$rc" "1"
assert_contains "--iface rejection explains the whitelist" "$out" "--iface rejected:"

out=$(sh "$CLI" --dry-run --internal-addr="not-an-ip" 2>&1)
rc=$?
assert_eq "invalid --internal-addr is rejected (exit 1)" "$rc" "1"

# Valid, explicit simulation parameters flow through unchanged.
out=$(sh "$CLI" --dry-run --format=kv --dns=203.0.113.53 --domains=example.internal --routes=203.0.113.0/24 --iface=wlan0 --internal-addr=203.0.113.44 2>&1)
rc=$?
assert_eq "valid explicit simulation parameters exit 0" "$rc" "0"
assert_contains "explicit iface is reflected in the plan (route dev)" "$out" "plan_step_3_id=route_203.0.113.0/24"

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
