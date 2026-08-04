#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# test-phase1-up.sh - end-to-end tests for phase1-up.sh: the Mode Config
# guard, outbound-interface detection, §4 input validation wired to
# racoon's actual env var names (including the comma- vs space-separated
# delimiter distinction verified against src/racoon's own C source), the
# R7 no-routes refusal, brief-3 §D's FIFO generation state scheme, and
# the on_dns_failure exit code policy.
#
# Every scenario pins backend=networkmanager (nmcli stubbed) so no test
# here ever executes the fallback backend's real /etc/resolv.conf write --
# that path is exercised at the plan-building level only, in
# test-plan-builder.sh, never applied against a real filesystem.
#
# Run directly: sh tests/hooks/test-phase1-up.sh

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
HOOK="$SCRIPT_DIR/../../src/racoon/scripts/phase1-up.sh"

# CI-found: run_hook() below runs the real hook under dash specifically
# (see the §J rationale comment further down) -- but a host with no dash
# package at all (the NetBSD CI job's vmactions runner in particular)
# made every invocation fail outright with "dash: not found" rather than
# actually exercising the hook. Falls back to "sh" (this file's own
# interpreter, per its shebang/CI invocation) when dash isn't on PATH --
# on NetBSD that IS the strict target shell §J's denylist trick is
# standing in for elsewhere, not an approximation there.
RHOOK_HOOK_SHELL="dash"
command -v "$RHOOK_HOOK_SHELL" >/dev/null 2>&1 || RHOOK_HOOK_SHELL="sh"

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

assert_not_contains() {
	TESTS_RUN=$((TESTS_RUN + 1))
	case "$2" in
		*"$3"*) fail "$1 -- '$3' unexpectedly found in output" ;;
		*) ;;
	esac
}

# --------------------------------------------------------------------------
# Brief 3 §J: every real `"$RHOOK_HOOK_SHELL" "$HOOK"` invocation this
# file makes goes through run_hook() below, which checks the captured
# output against a fixed denylist of shell-portability error markers --
# phrases a stricter shell (NetBSD's /bin/sh in particular) emits for a
# construct it doesn't accept the way dash/bash do. A scenario's own
# assertions only check for the specific substrings it cares about; they
# would not by themselves catch a portability bug whose extra noise on
# stderr happens not to break those substrings. Verified (grep) that none
# of the shipped scripts' own log/error text uses any denylisted phrase,
# so a match here is always either a real portability bug or new
# legitimate text that needs a documented exception in
# RHOOK_STDERR_ALLOWLIST below -- never remove a denylist entry to make a
# real failure go away.
# --------------------------------------------------------------------------
RHOOK_STDERR_ALLOWLIST=""   # newline-separated fixed strings to excuse, if ever needed

assert_stderr_clean() {
	# $1 = description  $2 = captured output (stdout+stderr merged)
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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/racoon-phase1-up-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# ip stub: answers `-4 route get <addr>` with a fixed interface, logs
# every invocation, and lets link/addr/route subcommands succeed unless
# IP_FAIL_LINK_ADD=1 is set (used by the failure-policy scenarios).
#
# `route ... src X` reproduces the real kernel's own prefsrc validation
# (confirmed live against real iproute2/kernel behavior, not assumed):
# it only succeeds once X has actually been "assigned" via
# ASSIGNED_ADDRS_LOG, exactly like the real "Error: Invalid prefsrc
# address." (exit 2) that a plan applying routes before anything ever
# assigns their src address hits on a live host. `ip addr
# replace/add/del` maintain that log directly; the nmcli stub below adds
# to it too, since for backend=networkmanager nmcli's own `connection
# add`+`connection up` -- not a separate `ip addr` call -- is what
# assigns the address in real life.
cat > "$WORK/bin/ip" <<'STUBEOF'
#!/bin/sh
echo "ip $*" >> "$IP_LOG"
case "$1 $2" in
	"-4 route")
		[ "$3" = "get" ] && { echo "$4 dev eth0 src 192.168.1.5"; exit 0; }
		;;
	"link add")
		[ "${IP_FAIL_LINK_ADD:-0}" = "1" ] && exit 1
		;;
	"addr replace"|"addr add")
		rhook_stub_addr="${3%%/*}"
		echo "$rhook_stub_addr" >> "$ASSIGNED_ADDRS_LOG"
		;;
	"addr del")
		rhook_stub_addr="${3%%/*}"
		grep -vxF "$rhook_stub_addr" "$ASSIGNED_ADDRS_LOG" > "$ASSIGNED_ADDRS_LOG.tmp" 2>/dev/null
		mv -f "$ASSIGNED_ADDRS_LOG.tmp" "$ASSIGNED_ADDRS_LOG" 2>/dev/null
		;;
	"route add"|"route replace")
		rhook_stub_src=""
		shift 2
		while [ $# -gt 0 ]; do
			[ "$1" = "src" ] && { shift; rhook_stub_src="$1"; }
			shift
		done
		if [ -n "$rhook_stub_src" ] && ! grep -qxF "$rhook_stub_src" "$ASSIGNED_ADDRS_LOG" 2>/dev/null; then
			echo "Error: Invalid prefsrc address." >&2
			exit 2
		fi
		;;
esac
exit 0
STUBEOF
chmod +x "$WORK/bin/ip"

# nmcli stub: succeeds for `connection add`/`connection up`, and -- like
# the real nmcli/NetworkManager combination for this backend -- is what
# actually "assigns" the profile's ipv4.addresses value (see the ip
# stub's own comment above for why this matters to the route stub).
cat > "$WORK/bin/nmcli" <<'STUBEOF'
#!/bin/sh
echo "nmcli $*" >> "$NMCLI_LOG"
rhook_stub_prev=""
for rhook_stub_arg in "$@"; do
	if [ "$rhook_stub_prev" = "ipv4.addresses" ]; then
		echo "${rhook_stub_arg%%/*}" >> "$ASSIGNED_ADDRS_LOG"
	fi
	rhook_stub_prev="$rhook_stub_arg"
done
exit 0
STUBEOF
chmod +x "$WORK/bin/nmcli"

# setkey stub (brief 3 §E): logs the exact line piped to `setkey -c` on
# stdin, one line per invocation, so SPD apply/undo commands are
# verifiable the same way ip/nmcli invocations are.
cat > "$WORK/bin/setkey" <<'STUBEOF'
#!/bin/sh
{ printf 'setkey %s: ' "$*"; cat; } >> "$SETKEY_LOG"
exit 0
STUBEOF
chmod +x "$WORK/bin/setkey"

cat > "$WORK/hooks.conf" <<'EOF'
backend = networkmanager
EOF

run_hook() {
	# Fresh per-call env: caller sets the Mode Config vars it needs, then
	# calls this. STATE_DIR/logs are shared across the whole file (reset
	# per test section below where isolation matters).
	#
	# NOTE (brief 3 §J): every caller invokes this as `out=$(run_hook)`,
	# which runs the whole function body in a command-substitution
	# subshell -- any TESTS_RUN/TESTS_FAILED updates made *inside* this
	# function would be invisible to the parent shell once that subshell
	# exits. assert_stderr_clean() is therefore called by each caller
	# explicitly, after capturing $out (and $rc, where checked), not from
	# in here.
	"$RHOOK_HOOK_SHELL" "$HOOK" 2>&1
}

reset_env() {
	WORK_RUN="$WORK/run.$1"
	rm -rf "$WORK_RUN"
	export RACOON_HOOK_STATE_DIR="$WORK_RUN"
	export RACOON_HOOK_CONF="$WORK/hooks.conf"
	export RACOON_HOOK_IP="$WORK/bin/ip"
	export RACOON_HOOK_NMCLI="$WORK/bin/nmcli"
	export RACOON_HOOK_SETKEY="$WORK/bin/setkey"
	# Level 1 ("step") so the assembled report actually reaches stderr for
	# these assertions to inspect -- level 0 is syslog-only by design
	# (§5.1), which would otherwise make every report-content assertion
	# below silently see nothing.
	export RACOON_HOOK_DEBUG=1
	export IP_LOG="$WORK/ip.log.$1"
	export NMCLI_LOG="$WORK/nmcli.log.$1"
	export SETKEY_LOG="$WORK/setkey.log.$1"
	export ASSIGNED_ADDRS_LOG="$WORK/assigned-addrs.$1"
	: > "$IP_LOG"
	: > "$NMCLI_LOG"
	: > "$SETKEY_LOG"
	: > "$ASSIGNED_ADDRS_LOG"
	unset IP_FAIL_LINK_ADD OUTBOUND_IFACE
	unset INTERNAL_ADDR4 LOCAL_ADDR LOCAL_PORT REMOTE_ADDR REMOTE_PORT
	unset SPLIT_INCLUDE_CIDR SPLIT_INCLUDE INTERNAL_DNS4_LIST INTERNAL_DNS4
	unset INTERNAL_SPLITDNS_DOMAINS DEFAULT_DOMAIN
}

# ==========================================================================
# Guard: no Mode Config address assigned -- exit 0, no state file, no
# system command ever invoked.
# ==========================================================================
reset_env guard
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "no-address guard exits 0" "$rc" "0"
assert_contains "no-address guard logs why" "$out" "no Mode Config address assigned"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$IP_LOG" ] && fail "no-address guard must never invoke ip"

# ==========================================================================
# Outbound interface cannot be determined -- exit 0, nothing else runs.
# ==========================================================================
reset_env noiface
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
# ip stub prints nothing useful for an address it doesn't recognize
cat > "$WORK/bin/ip" <<'STUBEOF'
#!/bin/sh
echo "ip $*" >> "$IP_LOG"
exit 0
STUBEOF
chmod +x "$WORK/bin/ip"
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "no-interface guard exits 0" "$rc" "0"
assert_contains "no-interface guard logs why" "$out" "cannot determine outbound interface"
# restore the working ip stub for the rest of the file -- same
# prefsrc-simulating version installed above (this scenario's stub above
# is intentionally the dumb no-op one, since it exists solely to test the
# "no route found" guard before any interface/address logic runs)
cat > "$WORK/bin/ip" <<'STUBEOF'
#!/bin/sh
echo "ip $*" >> "$IP_LOG"
case "$1 $2" in
	"-4 route")
		[ "$3" = "get" ] && { echo "$4 dev eth0 src 192.168.1.5"; exit 0; }
		;;
	"link add")
		[ "${IP_FAIL_LINK_ADD:-0}" = "1" ] && exit 1
		;;
	"addr replace"|"addr add")
		rhook_stub_addr="${3%%/*}"
		echo "$rhook_stub_addr" >> "$ASSIGNED_ADDRS_LOG"
		;;
	"addr del")
		rhook_stub_addr="${3%%/*}"
		grep -vxF "$rhook_stub_addr" "$ASSIGNED_ADDRS_LOG" > "$ASSIGNED_ADDRS_LOG.tmp" 2>/dev/null
		mv -f "$ASSIGNED_ADDRS_LOG.tmp" "$ASSIGNED_ADDRS_LOG" 2>/dev/null
		;;
	"route add"|"route replace")
		rhook_stub_src=""
		shift 2
		while [ $# -gt 0 ]; do
			[ "$1" = "src" ] && { shift; rhook_stub_src="$1"; }
			shift
		done
		if [ -n "$rhook_stub_src" ] && ! grep -qxF "$rhook_stub_src" "$ASSIGNED_ADDRS_LOG" 2>/dev/null; then
			echo "Error: Invalid prefsrc address." >&2
			exit 2
		fi
		;;
esac
exit 0
STUBEOF
chmod +x "$WORK/bin/ip"

# ==========================================================================
# Happy path: split-include routes, DNS servers, and comma-separated
# split-DNS domains (INTERNAL_SPLITDNS_DOMAINS -- verified against
# src/racoon/isakmp_unity.c to be the raw, comma-joined Cisco Unity
# attribute, unlike the space-joined SPLIT_INCLUDE_CIDR/INTERNAL_DNS4_LIST)
# all flow through to a networkmanager plan and get journaled to the
# state file.
# ==========================================================================
reset_env happy
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export LOCAL_PORT="500"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
export SPLIT_INCLUDE_CIDR="198.51.100.0/24"
export INTERNAL_DNS4_LIST="198.51.100.53"
export INTERNAL_SPLITDNS_DOMAINS="corp.example.com,internal.example.com"
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "happy path exits 0" "$rc" "0"
# PARTIAL, not OK: dummy_iface/dummy_addr are legitimately SKIPPED under
# the networkmanager backend (its own `nmcli connection add` creates the
# interface and address as part of the profile) -- skipped steps make
# rhook_emit_report classify the run as PARTIAL, which is correct here,
# not a failure.
assert_contains "happy path reports PARTIAL (skips are expected, not failures)" "$out" "result: PARTIAL"
# 7 ok = nm_dns profile + 2 routes + 4 spd_entry (in/out pair per route,
# brief 3 §E -- one split-include network plus one DNS-server host route).
assert_contains "happy path has zero actually-failed steps" "$out" "7 ok, 2 skipped, 0 failed"
assert_contains "comma-separated domains split correctly in the report header" "$out" "domains=corp.example.com internal.example.com"
assert_contains "DNS-server host route added on top of split-include" "$out" "routes=198.51.100.0/24 198.51.100.53/32"
# Generation .1: a fresh WORK_RUN dir means rhook_state_max_generation()
# finds nothing, so the first ever run for this peer allocates .1
# deterministically -- no REMOTE_PORT in the filename at all (brief 3
# §D: it floats on NAT-T rebind and can't identify "the same peer").
STATE_FILE="$WORK_RUN/hook-state.203.0.113.99.1"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] || fail "happy path must leave a non-empty state file"
assert_contains "state file journals the NM profile undo command" "$(cat "$STATE_FILE" 2>/dev/null)" "nmcli connection delete racoon-vpn-dns"
assert_contains "nmcli invoked for the DNS profile" "$(cat "$NMCLI_LOG")" "connection add type dummy"
# Brief 3 §E: state file journals a full, directly-replayable spddelete per
# installed spd_entry -- phase1-down.sh never re-derives the selector.
assert_contains "state file journals the outbound spddelete undo command" \
	"$(cat "$STATE_FILE" 2>/dev/null)" "spddelete 192.0.2.44/32 198.51.100.0/24 any -P out"
assert_contains "state file journals the inbound spddelete undo command" \
	"$(cat "$STATE_FILE" 2>/dev/null)" "spddelete 198.51.100.0/24 192.0.2.44/32 any -P in"
assert_contains "setkey invoked with the outbound spdadd tunnel selector" \
	"$(cat "$SETKEY_LOG")" "spdadd 192.0.2.44/32 198.51.100.0/24 any -P out ipsec esp/tunnel/203.0.113.1[500]-203.0.113.99[500]/require"

# ==========================================================================
# R3: injected Mode Config value is rejected outright, never partially
# used -- the malicious fragment must never reach a real `ip` invocation.
# ==========================================================================
reset_env injection
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
export SPLIT_INCLUDE_CIDR="10.0.12.0/24;ip route add default via 10.6.6.6"
out=$(run_hook)
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_contains "injected split-include is rejected with a reason" "$out" "invalid split-include network list"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q '10\.6\.6\.6' "$IP_LOG" 2>/dev/null; then
	fail "injected route-add fragment must never reach a real ip invocation"
fi

# ==========================================================================
# Brief 3 §E: newline-smuggled REMOTE_ADDR must never reach setkey. Unlike
# SPLIT_INCLUDE_CIDR/INTERNAL_DNS4_LIST above, LOCAL_ADDR/REMOTE_ADDR are
# racoon's own Phase 1 environment, not a Mode Config attribute -- but they
# feed the same eval'd spdadd/spddelete text (rhook_plan_spd()), so an
# unvalidated value here is the "highest-severity finding in the
# subsystem" the brief calls out. A literal embedded newline followed by a
# second setkey command line is the injection this guards against: without
# validation it would become a second line on setkey's stdin.
# ==========================================================================
reset_env spd-injection
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="$(printf '203.0.113.99\nspdflush;')"
export REMOTE_PORT="500"
export SPLIT_INCLUDE_CIDR="198.51.100.0/24"
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "newline-smuggled REMOTE_ADDR: hook exits 0 (nothing to do, not a crash)" "$rc" "0"
assert_contains "newline-smuggled REMOTE_ADDR is rejected with a reason" "$out" "invalid REMOTE_ADDR"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$SETKEY_LOG" ] && fail "setkey must never be invoked when REMOTE_ADDR fails validation"

# A malformed LOCAL_PORT/REMOTE_PORT must not abort the hook (the address
# pair alone is still a valid tunnel selector) but must never reach setkey
# either -- ports are dropped from the selector instead, never smuggled in
# as-is.
reset_env spd-port-injection
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export LOCAL_PORT="$(printf '500]-1.2.3.4[9\nspdflush;')"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
export SPLIT_INCLUDE_CIDR="198.51.100.0/24"
# INTERNAL_DNS4_LIST: networkmanager's own nm_dns step is what assigns
# INTERNAL_ADDR4 to an interface at all (its `ip route ... src` guard is
# skipped when RHOOK_DNS_SERVERS is empty, a pre-existing, documented gap
# unrelated to what this scenario tests) -- set it so the route step this
# scenario depends on actually succeeds, same as the happy-path fixture.
export INTERNAL_DNS4_LIST="198.51.100.53"
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "malformed LOCAL_PORT: hook still exits 0 and configures the tunnel" "$rc" "0"
assert_contains "malformed LOCAL_PORT is rejected with a reason" "$out" "invalid LOCAL_PORT"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q 'spdflush' "$SETKEY_LOG" 2>/dev/null; then
	fail "injected LOCAL_PORT fragment must never reach setkey"
fi
assert_contains "SPD entry installed with ports omitted, bare address-address selector" \
	"$(cat "$SETKEY_LOG")" "esp/tunnel/203.0.113.1-203.0.113.99/require"

# ==========================================================================
# R7: no split-include and no DNS servers at all -- refuse rather than
# invent a fallback network; exit code follows on_dns_failure.
# ==========================================================================
reset_env noroutes-warn
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "no-routes with on_dns_failure=warn (default) exits 0" "$rc" "0"
assert_contains "no-routes is reported as a failed required step" "$out" "[ FAILED    ] determine networks to route through the tunnel"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -qE '^route_' "$WORK_RUN/hook-state.203.0.113.99.1" 2>/dev/null; then
	fail "no route_* entries should be journaled when there is nothing to route"
fi

reset_env noroutes-abort
cat > "$WORK/hooks.conf" <<'EOF'
backend = networkmanager
on_dns_failure = abort
EOF
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
# Brief 3 §H: "abort" is a deprecated alias for "report" -- same exit
# code, but the deprecation is logged (RACOON_HOOK_DEBUG=1 in reset_env
# puts the report on stderr, which `out` already captures).
assert_eq "no-routes with on_dns_failure=abort (deprecated) exits 1" "$rc" "1"
assert_contains "on_dns_failure=abort logs a deprecation notice" "$out" "deprecated alias for 'report'"

reset_env noroutes-report
cat > "$WORK/hooks.conf" <<'EOF'
backend = networkmanager
on_dns_failure = report
EOF
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "no-routes with on_dns_failure=report exits 1" "$rc" "1"
assert_not_contains "on_dns_failure=report (the honest, non-deprecated name) never logs a deprecation notice" "$out" "deprecated"
cat > "$WORK/hooks.conf" <<'EOF'
backend = networkmanager
EOF

# ==========================================================================
# Brief 3 §H: on_dns_failure=rollback undoes every change *this run*
# applied when a later required step fails -- exercised with a scenario
# where routes and one SPD pair already succeeded before a second SPD
# entry fails, so there is real work to roll back. Uses a dedicated
# setkey stub that fails only for the second split-include network's
# outbound entry (SETKEY_FAIL_MARKER), leaving the first network's
# routes/SPD and both routes journaled as "ok" first.
# ==========================================================================
reset_env rollback
cat > "$WORK/hooks.conf" <<'EOF'
backend = networkmanager
on_dns_failure = rollback
EOF
cat > "$WORK/bin/setkey" <<'STUBEOF'
#!/bin/sh
SETKEY_INPUT=$(cat)
printf 'setkey %s: %s\n' "$*" "$SETKEY_INPUT" >> "$SETKEY_LOG"
case "$SETKEY_INPUT" in
	*"198.51.100.128/25"*"-P out"*) exit 1 ;;
esac
exit 0
STUBEOF
chmod +x "$WORK/bin/setkey"
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
export SPLIT_INCLUDE_CIDR="198.51.100.0/24 198.51.100.128/25"
# INTERNAL_DNS4_LIST: see the spd-port-injection scenario's comment above --
# without it, nm_dns is skipped and INTERNAL_ADDR4 is never assigned
# anywhere, so both route steps below would fail on the unrelated,
# pre-existing "no DNS servers" gap before rollback logic is ever reached.
export INTERNAL_DNS4_LIST="198.51.100.53"
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "rollback: a required SPD failure still exits 1" "$rc" "1"
assert_contains "rollback: the hook announces it is undoing this run's own changes" "$out" "on_dns_failure=rollback"
assert_contains "rollback: first network's route was undone" "$(cat "$IP_LOG")" "route del 198.51.100.0/24"
assert_contains "rollback: second network's route was undone" "$(cat "$IP_LOG")" "route del 198.51.100.128/25"
assert_contains "rollback: first network's outbound SPD entry was undone" \
	"$(cat "$SETKEY_LOG")" "spddelete 192.0.2.44/32 198.51.100.0/24 any -P out"
assert_contains "rollback: first network's inbound SPD entry was undone" \
	"$(cat "$SETKEY_LOG")" "spddelete 198.51.100.0/24 192.0.2.44/32 any -P in"
TESTS_RUN=$((TESTS_RUN + 1))
if [ -f "$WORK_RUN/hook-state.203.0.113.99.1" ]; then
	fail "rollback: the state file must not be left as a live (unconsumed) generation once this run has undone itself"
fi
cat > "$WORK/hooks.conf" <<'EOF'
backend = networkmanager
EOF
cat > "$WORK/bin/setkey" <<'STUBEOF'
#!/bin/sh
{ printf 'setkey %s: ' "$*"; cat; } >> "$SETKEY_LOG"
exit 0
STUBEOF
chmod +x "$WORK/bin/setkey"

# ==========================================================================
# Brief 3 §D: an old, unconsumed generation left behind by an incomplete
# teardown is left completely untouched (no archiving, no overwriting,
# no rewriting) by a new phase1-up run for the same peer -- a fresh
# generation is simply allocated alongside it. This replaces brief 1's
# "archive as .stale.$$ and start fresh" behavior entirely: generation
# numbering means there is nothing to archive -- an old, never-consumed
# generation was never going to collide with a new one in the first
# place. (Whether that old generation is ever consumed depends on
# rhook_state_own_generation()'s IKE_COOKIE match, issue #90 -- not on
# arrival order; an orphan whose own session never calls phase1-down.sh
# again stays live indefinitely, since rhook_state_reap() only ever
# reaps aged .consumed files, never live ones.)
# ==========================================================================
reset_env fifo-old-gen
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
export SPLIT_INCLUDE_CIDR="198.51.100.0/24"
mkdir -p "$WORK_RUN"
printf 'leftover_step\tcreate_dummy\tok\tip link del racoon0\n' > "$WORK_RUN/hook-state.203.0.113.99.1"
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "run with an old unconsumed generation present still exits 0" "$rc" "0"
TESTS_RUN=$((TESTS_RUN + 1))
if [ -f "$WORK_RUN/hook-state.203.0.113.99.1" ] && grep -q 'leftover_step' "$WORK_RUN/hook-state.203.0.113.99.1" 2>/dev/null; then
	:
else
	fail "the old unconsumed generation must be left exactly as it was, not archived or modified"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if [ -s "$WORK_RUN/hook-state.203.0.113.99.2" ]; then
	:
else
	fail "a new generation (.2) should have been allocated alongside the untouched old one (.1)"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if find "$WORK_RUN" -name 'hook-state.*.stale.*' | grep -q .; then
	fail "brief 3 replaces stale-state archival entirely -- no .stale. files should ever be created"
fi

# ==========================================================================
# rhook_state_reap() runs at every phase1-up: .consumed generations for
# this peer beyond the newest RHOOK_REAP_MAX_COUNT (5) are deleted,
# oldest first; live (unconsumed) generations are never touched by it.
# ==========================================================================
reset_env reap
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
export SPLIT_INCLUDE_CIDR="198.51.100.0/24"
mkdir -p "$WORK_RUN"
i=1
while [ "$i" -le 7 ]; do
	printf 'old_step\tcreate_dummy\tok\ttrue\n' > "$WORK_RUN/hook-state.203.0.113.99.$i.consumed"
	i=$((i + 1))
done
out=$(run_hook)
rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$out"
assert_eq "run with 7 pre-existing consumed generations still exits 0" "$rc" "0"
remaining=$(find "$WORK_RUN" -name 'hook-state.203.0.113.99.*.consumed' | wc -l | tr -d ' ')
assert_eq "reaping down from 7 consumed generations keeps exactly the newest 5" "$remaining" "5"
TESTS_RUN=$((TESTS_RUN + 1))
if [ -f "$WORK_RUN/hook-state.203.0.113.99.1.consumed" ] || [ -f "$WORK_RUN/hook-state.203.0.113.99.2.consumed" ]; then
	fail "the two oldest consumed generations (1, 2) should have been reaped"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if [ -f "$WORK_RUN/hook-state.203.0.113.99.7.consumed" ]; then
	:
else
	fail "the newest consumed generation (7) should be kept, not reaped"
fi

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
