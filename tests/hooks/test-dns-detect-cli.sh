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
CLI="$SCRIPT_DIR/../../src/racoon/scripts/racoon-dns-detect"

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

# --------------------------------------------------------------------------
# Brief 3 §J: every captured real subprocess invocation (every `sh "$CLI"
# ... 2>&1` below) is also checked against a fixed denylist of
# shell-portability error markers -- phrases a stricter shell (NetBSD's
# /bin/sh in particular) emits for a construct it doesn't accept the way
# dash/bash do. A scenario's own assertions only check for the specific
# substrings it cares about; they would not by themselves catch a
# portability bug whose extra noise on stderr happens not to break those
# substrings. Verified (grep) that none of the shipped scripts' own
# log/error text uses any denylisted phrase, so a match here is always
# either a real portability bug or new legitimate text that needs a
# documented exception in RHOOK_STDERR_ALLOWLIST below -- never remove a
# denylist entry to make a real failure go away.
#
# Placement note: every call site below runs this *after* capturing `rc`
# from the CLI's own exit status (`rc=$?` immediately follows `out=$(...)`
# wherever the scenario checks `rc`) -- assert_stderr_clean() itself runs
# several commands and would otherwise clobber `$?` before it could be
# captured.
# --------------------------------------------------------------------------
RHOOK_STDERR_ALLOWLIST=""   # newline-separated fixed strings to excuse, if ever needed

assert_stderr_clean() {
	# $1 = description  $2 = captured output (stdout+stderr merged via
	# the caller's own `2>&1`)
	rhook_asc_out="$2"
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ -n "$RHOOK_STDERR_ALLOWLIST" ]; then
		rhook_asc_tmp=$(mktemp "${TMPDIR:-/tmp}/racoon-hook-allowlist.XXXXXX")
		printf '%s\n' "$RHOOK_STDERR_ALLOWLIST" > "$rhook_asc_tmp"
		rhook_asc_out=$(printf '%s\n' "$rhook_asc_out" | grep -vFf "$rhook_asc_tmp")
		rm -f "$rhook_asc_tmp"
	fi
	case "$rhook_asc_out" in
		*"command not found"*|*": not found"*|*"Illegal number"*|*"Syntax error"*|*"bad substitution"*|*"Bad substitution"*|*"parameter not set"*|*"unbound variable"*|*"arithmetic syntax error"*|*"divide by zero"*|*"Illegal option"*)
			fail "$1 -- shell-portability error marker found in captured output (possible dash/bash/NetBSD-sh divergence): $rhook_asc_out"
			;;
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
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_eq "--help exits 0" "$rc" "0"
assert_contains "--help shows usage" "$out" "Usage: racoon-dns-detect"

# ==========================================================================
# Unrecognized option: usage on stderr, exit 1.
# ==========================================================================
out=$(sh "$CLI" --not-a-real-flag 2>&1)
rc=$?
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_eq "unrecognized option exits 1" "$rc" "1"
assert_contains "unrecognized option names the bad flag" "$out" "unrecognized option: --not-a-real-flag"

# ==========================================================================
# --detect (default action, no flags): text report, exit 0.
# ==========================================================================
out=$(sh "$CLI" 2>&1)
rc=$?
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_eq "no-args run (implicit --detect) exits 0" "$rc" "0"
assert_contains "default run prints the report header" "$out" "resolv.conf landscape and split-DNS backend report"
assert_contains "default run reports a classified backend" "$out" "Classified backend:"

# ==========================================================================
# --format=kv: parser output is a flat key=value stream, no prose lines.
# ==========================================================================
out=$(sh "$CLI" --detect --format=kv 2>&1)
rc=$?
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
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
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
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
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
TESTS_RUN=$((TESTS_RUN + 1))
if printf '%s\n' "$out" | grep -q "    apply:"; then
	fail "--dry-run without --explain must not print apply/undo command lines"
fi

# --dry-run --format=kv: numbered plan_step_N_* keys plus a total count.
out=$(sh "$CLI" --dry-run --format=kv 2>&1)
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_contains "dry-run kv includes plan_step_1_id" "$out" "plan_step_1_id="
assert_contains "dry-run kv includes a step count" "$out" "plan_step_count="

# ==========================================================================
# CLI-supplied simulation parameters are validated exactly like real Mode
# Config input -- reject-on-first-bad-element, not sanitize, matching the
# brief's named injection vectors.
# ==========================================================================
out=$(sh "$CLI" --dry-run --dns="10.0.0.1;rm -rf /" 2>&1)
rc=$?
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_eq "route/command injection in --dns is rejected (exit 1)" "$rc" "1"
assert_contains "--dns rejection names the reason" "$out" "--dns rejected:"

out=$(sh "$CLI" --dry-run --routes="default via 10.6.6.6" 2>&1)
rc=$?
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_eq "named route-injection vector in --routes is rejected (exit 1)" "$rc" "1"

out=$(sh "$CLI" --dry-run --iface='eth0;touch /tmp/pwned' 2>&1)
rc=$?
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_eq "shell metacharacters in --iface are rejected (exit 1)" "$rc" "1"
assert_contains "--iface rejection explains the whitelist" "$out" "--iface rejected:"

out=$(sh "$CLI" --dry-run --internal-addr="not-an-ip" 2>&1)
rc=$?
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_eq "invalid --internal-addr is rejected (exit 1)" "$rc" "1"

# Valid, explicit simulation parameters flow through unchanged.
out=$(sh "$CLI" --dry-run --format=kv --dns=203.0.113.53 --domains=example.internal --routes=203.0.113.0/24 --iface=wlan0 --internal-addr=203.0.113.44 2>&1)
rc=$?
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_eq "valid explicit simulation parameters exit 0" "$rc" "0"
assert_contains "explicit iface is reflected in the plan (route dev)" "$out" "plan_step_3_id=route_203.0.113.0/24"

# ==========================================================================
# §C (brief 3): port 53 ownership survey shows up in --detect output,
# and a disagreement against the file/D-Bus classification is reported
# explicitly rather than resolved silently in favor of either side.
# ==========================================================================
mkdir -p "$WORK/port53/bin" "$WORK/port53/proc/200"
cat > "$WORK/port53/bin/ss" <<'EOF'
#!/bin/sh
echo "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess"
echo "udp   UNCONN 0      0         127.0.0.1:53        0.0.0.0:*    users:((\"dnsmasq\",pid=200,fd=6))"
EOF
chmod +x "$WORK/port53/bin/ss"
ln -sf /usr/sbin/dnsmasq "$WORK/port53/proc/200/exe"

export RACOON_HOOK_FS_ROOT="$WORK/port53"
export RACOON_HOOK_SS="$WORK/port53/bin/ss"

out=$(sh "$CLI" --detect --explain 2>&1)
rc=$?
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_eq "--detect with a port53 listener exits 0" "$rc" "0"
assert_contains "port53 listener is reported with its pid and resolved owner binary" "$out" "127.0.0.1:53 -- pid=200 owner=/usr/sbin/dnsmasq class=forwarder"
assert_contains "disagreement is reported when file survey says static but a forwarder is live" "$out" "DISAGREEMENT: port 53 survey vs. file/D-Bus classification"
assert_contains "disagreement shows the file/D-Bus conclusion" "$out" "file/D-Bus survey concluded: backend=static"
assert_contains "disagreement shows the port53 conclusion with evidence" "$out" "port 53 survey concluded:    a live resolver (owner /usr/sbin/dnsmasq)"

out=$(sh "$CLI" --detect --format=kv 2>&1)
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_contains "kv output includes the listener fields" "$out" "port53_listener_1_owner=/usr/sbin/dnsmasq"
assert_contains "kv output includes the disagreement flag" "$out" "port53_disagreement=yes"

# No listener at all -> no disagreement section, no false positive.
cat > "$WORK/port53/bin/ss" <<'EOF'
#!/bin/sh
echo "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess"
EOF
chmod +x "$WORK/port53/bin/ss"
out=$(sh "$CLI" --detect 2>&1)
assert_stderr_clean "racoon-dns-detect invocation is stderr-clean" "$out"
assert_contains "no listeners at all is reported plainly" "$out" "(none detected)"
TESTS_RUN=$((TESTS_RUN + 1))
if printf '%s' "$out" | grep -q "DISAGREEMENT"; then
	fail "no port53 listener at all must not produce a disagreement finding"
fi

unset RACOON_HOOK_FS_ROOT RACOON_HOOK_SS

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
