#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# test-phase1-roundtrip.sh - full apply -> teardown round-trip tests
# (§9/§11) driving the real phase1-up.sh and phase1-down.sh scripts back
# to back, exactly as racoon would invoke them for a connect/disconnect
# cycle. Verifies R4 (DNS undone before routes/interface) end to end
# through the real hooks, that a clean teardown leaves no state file and
# reverses every `ip`/`nmcli` call phase1-up.sh made, and that a stuck
# undo is retried correctly on a second phase1-down.sh invocation.
#
# Every scenario pins backend=networkmanager (nmcli stubbed) so this file
# never executes the fallback backend's real /etc/resolv.conf write.
#
# Run directly: sh tests/hooks/test-phase1-roundtrip.sh

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
HOOK_UP="$SCRIPT_DIR/../../src/racoon/scripts/phase1-up.sh"
HOOK_DOWN="$SCRIPT_DIR/../../src/racoon/scripts/phase1-down.sh"

# CI-found: real hook invocations below run under dash specifically (see
# the §J rationale comment further down) -- but a host with no dash
# package at all (the NetBSD CI job's vmactions runner in particular)
# made every single one of them fail outright with "dash: not found"
# rather than actually exercising the hooks. Falls back to "sh" (this
# file's own interpreter, per its shebang/CI invocation) when dash isn't
# on PATH -- on NetBSD that IS the strict target shell §J's denylist
# trick is standing in for elsewhere, not an approximation there.
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
# Brief 3 §J: every real `"$RHOOK_HOOK_SHELL" "$HOOK_UP"`/
# `"$RHOOK_HOOK_SHELL" "$HOOK_DOWN"` invocation below is checked against a
# fixed denylist of shell-portability error markers -- phrases a stricter
# shell (NetBSD's /bin/sh in particular) emits for a construct it doesn't
# accept the way dash/bash do. A scenario's own assertions only check for
# the specific substrings it cares about; they would not by themselves
# catch a portability bug whose extra noise on stderr happens not to
# break those substrings. Verified (grep) that none of the shipped
# scripts' own log/error text uses any denylisted phrase, so a match here
# is always either a real portability bug or new legitimate text that
# needs a documented exception in RHOOK_STDERR_ALLOWLIST below -- never
# remove a denylist entry to make a real failure go away.
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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/racoon-phase1-roundtrip.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

cat > "$WORK/bin/ip" <<'STUBEOF'
#!/bin/sh
echo "ip $*" >> "$IP_LOG"
case "$1 $2" in
	"-4 route")
		[ "$3" = "get" ] && { echo "$4 dev eth0 src 192.168.1.5"; exit 0; }
		;;
	"link del")
		[ "${IP_FAIL_LINK_DEL:-0}" = "1" ] && exit 1
		;;
esac
exit 0
STUBEOF
chmod +x "$WORK/bin/ip"

cat > "$WORK/bin/nmcli" <<'STUBEOF'
#!/bin/sh
echo "nmcli $*" >> "$NMCLI_LOG"
exit 0
STUBEOF
chmod +x "$WORK/bin/nmcli"

# setkey stub (brief 3 §E): logs the exact line piped to `setkey -c` on
# stdin, so spd_entry apply/undo commands round-trip verifiably like
# every other step type in this file.
cat > "$WORK/bin/setkey" <<'STUBEOF'
#!/bin/sh
{ printf 'setkey %s: ' "$*"; cat; } >> "$SETKEY_LOG"
exit 0
STUBEOF
chmod +x "$WORK/bin/setkey"

cat > "$WORK/hooks.conf" <<'EOF'
backend = networkmanager
EOF

reset_env() {
	WORK_RUN="$WORK/run.$1"
	rm -rf "$WORK_RUN"
	export RACOON_HOOK_STATE_DIR="$WORK_RUN"
	export RACOON_HOOK_CONF="$WORK/hooks.conf"
	export RACOON_HOOK_IP="$WORK/bin/ip"
	export RACOON_HOOK_NMCLI="$WORK/bin/nmcli"
	export RACOON_HOOK_SETKEY="$WORK/bin/setkey"
	export RACOON_HOOK_DEBUG=1
	export IP_LOG="$WORK/ip.log.$1"
	export NMCLI_LOG="$WORK/nmcli.log.$1"
	export SETKEY_LOG="$WORK/setkey.log.$1"
	: > "$IP_LOG"
	: > "$NMCLI_LOG"
	: > "$SETKEY_LOG"
	unset IP_FAIL_LINK_DEL
	unset INTERNAL_ADDR4 LOCAL_ADDR LOCAL_PORT REMOTE_ADDR REMOTE_PORT
	unset SPLIT_INCLUDE_CIDR SPLIT_INCLUDE INTERNAL_DNS4_LIST INTERNAL_DNS4
	unset INTERNAL_SPLITDNS_DOMAINS DEFAULT_DOMAIN
	# issue #90: IKE_COOKIE is racoon's own per-negotiation session token
	# (exported by script_hook() in src/racoon/isakmp.c); every scenario
	# below sets its own value explicitly around each phase1-up/
	# phase1-down pair rather than getting a default here, since the
	# whole point under test is that phase1-down.sh matches on this
	# value, not on file order.
	unset IKE_COOKIE
	export INTERNAL_ADDR4="192.0.2.44"
	export LOCAL_ADDR="203.0.113.1"
	export LOCAL_PORT="500"
	export REMOTE_ADDR="203.0.113.99"
	export REMOTE_PORT="500"
	export SPLIT_INCLUDE_CIDR="198.51.100.0/24"
	export INTERNAL_DNS4_LIST="198.51.100.53"
	export INTERNAL_SPLITDNS_DOMAINS="corp.example.com,internal.example.com"
}

# ==========================================================================
# Clean round trip: up, then down. Down must reverse every ip/nmcli call
# up made, DNS (nmcli) first (R4), and leave no state file behind.
# ==========================================================================
reset_env clean
export IKE_COOKIE="cookie-clean"
up_out=$("$RHOOK_HOOK_SHELL" "$HOOK_UP" 2>&1)
up_rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$up_out"
assert_eq "phase1-up exits 0" "$up_rc" "0"
assert_contains "phase1-up's own report ran (sanity check on the fixture)" "$up_out" "phase1-up report"
STATE_FILE="$WORK_RUN/hook-state.203.0.113.99.1"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] || fail "phase1-up must leave a non-empty state file for phase1-down to consume"

down_out=$("$RHOOK_HOOK_SHELL" "$HOOK_DOWN" 2>&1)
down_rc=$?
assert_stderr_clean "phase1-down.sh invocation is stderr-clean" "$down_out"
assert_eq "phase1-down exits 0" "$down_rc" "0"
assert_contains "phase1-down reports OK" "$down_out" "result: OK"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] && fail "phase1-down must remove the state file after a clean teardown"

# R4 end to end, both directions logged: teardown must actually reverse
# both the DNS profile and the routes phase1-up added. Note this does NOT
# assert relative order -- for backend=networkmanager specifically, R4's
# usual "DNS torn down first" no longer holds since the route-ordering fix
# (routes now depend on the address nm_dummy_profile assigns, so that step
# applies early and is therefore undone last, not first; see
# rhook_build_plan()'s own comment on that trade-off). Other backends are
# unaffected and still tear DNS down first.
nmcli_down_line=$(grep -n 'connection down racoon-vpn-dns' "$NMCLI_LOG" | head -1 | cut -d: -f1)
last_route_del_line_in_ip_log=$(grep -n 'route del' "$IP_LOG" | tail -1)
TESTS_RUN=$((TESTS_RUN + 1))
if [ -z "$nmcli_down_line" ]; then
	fail "R4: phase1-down must have torn down the NetworkManager DNS profile"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if [ -z "$last_route_del_line_in_ip_log" ]; then
	fail "R4: phase1-down must have removed the routes phase1-up added"
fi
# Every route phase1-up added must have a matching `ip route del` in the
# log by the time teardown finishes. The stub sees argv after the shell
# has already stripped phase1-up's own quoting around the eval'd undo
# command, so no literal quotes are expected here.
assert_contains "route 198.51.100.0/24 undone" "$(cat "$IP_LOG")" "route del 198.51.100.0/24"

# Brief 3 §E round trip: phase1-up installed SPD via setkey -c, and
# phase1-down's undo replay must have issued the exact reconstructed
# spddelete for both directions -- never spdflush, never `setkey -F`.
assert_contains "phase1-up installed the outbound SPD entry" "$(cat "$SETKEY_LOG")" \
	"spdadd 192.0.2.44/32 198.51.100.0/24 any -P out ipsec esp/tunnel/"
assert_contains "phase1-down undid the outbound SPD entry with the exact selector" "$(cat "$SETKEY_LOG")" \
	"spddelete 192.0.2.44/32 198.51.100.0/24 any -P out;"
assert_contains "phase1-down undid the inbound SPD entry with the exact selector" "$(cat "$SETKEY_LOG")" \
	"spddelete 198.51.100.0/24 192.0.2.44/32 any -P in;"
assert_not_contains "teardown never uses spdflush" "$(cat "$SETKEY_LOG")" "spdflush"
assert_not_contains "teardown never uses setkey -F" "$(cat "$SETKEY_LOG")" "setkey -F: "

# ==========================================================================
# Stuck teardown, then a successful retry: simulate `ip link del` failing
# on the first phase1-down.sh call (nothing here actually creates a
# dummy_iface step under the networkmanager backend, so drive this via a
# route deletion failure instead by having the ip stub fail on the first
# `route del` for one specific network) -- verifies the real hooks (not
# just the library) retain and retry via the same state file across two
# separate process invocations.
# ==========================================================================
reset_env retry
cat > "$WORK/bin/ip" <<'STUBEOF'
#!/bin/sh
echo "ip $*" >> "$IP_LOG"
case "$1 $2" in
	"-4 route")
		[ "$3" = "get" ] && { echo "$4 dev eth0 src 192.168.1.5"; exit 0; }
		;;
	"route del")
		if [ "$3" = "198.51.100.0/24" ] && [ ! -f "$STUCK_MARKER" ]; then
			: > "$STUCK_MARKER"
			exit 9
		fi
		;;
esac
exit 0
STUBEOF
chmod +x "$WORK/bin/ip"
export STUCK_MARKER="$WORK/stuck-marker"
rm -f "$STUCK_MARKER"
export IKE_COOKIE="cookie-retry"

up_out=$("$RHOOK_HOOK_SHELL" "$HOOK_UP" 2>&1)
up_rc=$?
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$up_out"
assert_eq "retry scenario: phase1-up exits 0" "$up_rc" "0"
assert_contains "retry scenario: phase1-up's own report ran (sanity check on the fixture)" "$up_out" "phase1-up report"
STATE_FILE="$WORK_RUN/hook-state.203.0.113.99.1"

down_out1=$("$RHOOK_HOOK_SHELL" "$HOOK_DOWN" 2>&1)
down_rc1=$?
assert_stderr_clean "phase1-down.sh invocation is stderr-clean" "$down_out1"
assert_eq "first phase1-down (one route del fails) exits 0 under warn policy" "$down_rc1" "0"
assert_contains "first phase1-down reports the failure" "$down_out1" "result: PARTIAL"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] || fail "state file must survive a partial-failure teardown for a retry"
assert_contains "only the stuck route survives in the retained state" "$(cat "$STATE_FILE" 2>/dev/null)" "198.51.100.0/24"

down_out2=$("$RHOOK_HOOK_SHELL" "$HOOK_DOWN" 2>&1)
down_rc2=$?
assert_stderr_clean "phase1-down.sh invocation is stderr-clean" "$down_out2"
assert_eq "retry phase1-down (marker now set, ip succeeds) exits 0" "$down_rc2" "0"
assert_contains "retry phase1-down reports OK" "$down_out2" "result: OK"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] && fail "state file must be gone after the retry finishes the job"

# ==========================================================================
# phase1-down with no prior phase1-up run at all: nothing to undo, exits
# 0, never invokes ip/nmcli. Also exercises IKE_COOKIE left unset (a
# SCRIPT_PHASE1_DEAD-style invocation, or a not-yet-patched racoon build)
# -- rhook_state_own_generation() must return empty rather than guess.
# ==========================================================================
reset_env noop
out=$("$RHOOK_HOOK_SHELL" "$HOOK_DOWN" 2>&1)
rc=$?
assert_stderr_clean "phase1-down.sh invocation is stderr-clean" "$out"
assert_eq "phase1-down with no state exits 0" "$rc" "0"
assert_contains "phase1-down with no state explains why" "$out" "nothing to undo"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$IP_LOG" ] && fail "phase1-down must never invoke ip when there is no state to replay"

# ==========================================================================
# Brief 3 §D / F1: the exact overlap the live Bionic test showed --
# phase1-down for an old SA and phase1-up for its replacement running
# within about a second of each other, for the *same peer address*. A
# single-file (or REMOTE_ADDR+REMOTE_PORT) identity scheme can match a
# teardown to the wrong generation and dismantle a tunnel that just came
# up. Each session gets its own IKE_COOKIE (issue #90); phase1-down.sh
# must match on it exactly, in either teardown order -- this scenario
# tears down in the same order the SAs came up (FIFO-compatible order,
# by coincidence, not by reliance on it: see the "lifo" scenario below
# for the order that would have broken the old oldest-first logic). Two
# split-include networks (100.64.0.0/24 for the first session,
# 100.64.1.0/24 for the second) make each generation's own routes
# individually identifiable in the ip.log.
# ==========================================================================
reset_env overlap
export SPLIT_INCLUDE_CIDR="100.64.0.0/24"
export IKE_COOKIE="cookie-overlap-sa1"
up1_out=$("$RHOOK_HOOK_SHELL" "$HOOK_UP" 2>&1)
assert_eq "overlap: first phase1-up (SA1) exits 0" "$?" "0"
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$up1_out"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.1" ] || fail "SA1 should have journaled generation .1"

export SPLIT_INCLUDE_CIDR="100.64.1.0/24"
export IKE_COOKIE="cookie-overlap-sa2"
up2_out=$("$RHOOK_HOOK_SHELL" "$HOOK_UP" 2>&1)
assert_eq "overlap: second phase1-up (SA2, same peer, SA1 still up) exits 0" "$?" "0"
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$up2_out"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.2" ] || fail "SA2 should have journaled a *new* generation .2, not reused .1"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.1" ] || fail "SA1's generation .1 must still be untouched while SA2 is also live"

# First phase1-down (tearing down SA1, by SA1's own cookie) must consume
# generation .1 -- because it's the one whose IKE_COOKIE matches, not
# because it's the oldest -- even though .2 also exists and is also live.
export IKE_COOKIE="cookie-overlap-sa1"
down1_out=$("$RHOOK_HOOK_SHELL" "$HOOK_DOWN" 2>&1)
assert_eq "overlap: first phase1-down exits 0" "$?" "0"
assert_stderr_clean "phase1-down.sh invocation is stderr-clean" "$down1_out"
assert_contains "first phase1-down undid SA1's own route (100.64.0.0/24)" "$(cat "$IP_LOG")" "route del 100.64.0.0/24"
TESTS_RUN=$((TESTS_RUN + 1))
if [ -f "$WORK_RUN/hook-state.203.0.113.99.1" ]; then
	fail "generation .1 (SA1) should be consumed (renamed away) after the first phase1-down"
fi
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.2" ] || fail "generation .2 (SA2) must still be live -- the first phase1-down must not have touched it"

# Second phase1-down (tearing down SA2, by SA2's own cookie) must now
# consume generation .2, the only one left.
export IKE_COOKIE="cookie-overlap-sa2"
: > "$IP_LOG"
down2_out=$("$RHOOK_HOOK_SHELL" "$HOOK_DOWN" 2>&1)
assert_eq "overlap: second phase1-down exits 0" "$?" "0"
assert_stderr_clean "phase1-down.sh invocation is stderr-clean" "$down2_out"
assert_contains "second phase1-down undid SA2's own route (100.64.1.0/24)" "$(cat "$IP_LOG")" "route del 100.64.1.0/24"
assert_not_contains "second phase1-down never re-touches SA1's already-undone route" "$(cat "$IP_LOG")" "100.64.0.0/24"
TESTS_RUN=$((TESTS_RUN + 1))
[ -f "$WORK_RUN/hook-state.203.0.113.99.2" ] && fail "generation .2 (SA2) should be consumed after the second phase1-down"

# ==========================================================================
# Issue #90, the live-found bug itself: SA2 (the newer session) torn down
# *before* SA1, which is left live and orphaned (as an incomplete-teardown
# session on a real host would be). Before this fix,
# rhook_state_oldest_unconsumed()'s pure FIFO order would have picked
# generation .1 (SA1's orphan) here regardless of which session's
# teardown actually ran -- consuming the wrong session's state and never
# issuing the `ip route del` SA2's own teardown needed. Exact IKE_COOKIE
# matching must instead consume SA2's own generation (.2) and leave SA1's
# live orphan (.1) completely untouched.
# ==========================================================================
reset_env lifo
export SPLIT_INCLUDE_CIDR="100.64.10.0/24"
export IKE_COOKIE="cookie-lifo-sa1"
up1_out=$("$RHOOK_HOOK_SHELL" "$HOOK_UP" 2>&1)
assert_eq "lifo: first phase1-up (SA1, will be left orphaned) exits 0" "$?" "0"
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$up1_out"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.1" ] || fail "SA1 should have journaled generation .1"

export SPLIT_INCLUDE_CIDR="100.64.11.0/24"
export IKE_COOKIE="cookie-lifo-sa2"
up2_out=$("$RHOOK_HOOK_SHELL" "$HOOK_UP" 2>&1)
assert_eq "lifo: second phase1-up (SA2, same peer, SA1 still up) exits 0" "$?" "0"
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$up2_out"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.2" ] || fail "SA2 should have journaled generation .2"

# Tear down SA2 FIRST, by its own cookie -- the reverse of arrival order.
export IKE_COOKIE="cookie-lifo-sa2"
: > "$IP_LOG"
down_out=$("$RHOOK_HOOK_SHELL" "$HOOK_DOWN" 2>&1)
assert_eq "lifo: phase1-down for SA2 exits 0" "$?" "0"
assert_stderr_clean "phase1-down.sh invocation is stderr-clean" "$down_out"
assert_contains "phase1-down undid SA2's own route (100.64.11.0/24), not SA1's" "$(cat "$IP_LOG")" "route del 100.64.11.0/24"
assert_not_contains "phase1-down for SA2 never touches SA1's route" "$(cat "$IP_LOG")" "100.64.10.0/24"
TESTS_RUN=$((TESTS_RUN + 1))
if [ -f "$WORK_RUN/hook-state.203.0.113.99.2" ]; then
	fail "generation .2 (SA2) should be consumed after its own phase1-down"
fi
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.1" ] || fail "generation .1 (SA1, the orphan) must remain live and untouched -- exact IKE_COOKIE matching, not FIFO order, decides which generation gets consumed"

# ==========================================================================
# PR #91 review row 23 (comment 5061097437): the "overlap"/"lifo" scenarios
# above both let phase1-up.sh run to a normal, complete exit -- neither
# exercises the actual crash scenario the exact-IKE_COOKIE-match fix is
# for: a phase1-up.sh SIGKILLed mid-run (OOM-kill, or any signal a shell
# trap cannot intercept), leaving a live state file that is genuinely
# incomplete rather than just "an earlier session's complete file".
#
# Proves two things the fix depends on that the scenarios above cannot:
#   1. the IKE_COOKIE sidecar is written by rhook_state_reset() before any
#      step ever runs, so a crashed generation's own phase1-down can still
#      find it by exact match, even though its state file only has a
#      partial list of completed steps;
#   2. an unrelated, fully-normal session for the *same peer* is entirely
#      unaffected by the crashed orphan sitting on disk, and the crashed
#      orphan's own eventual teardown replays only what it actually
#      completed -- not double-consumed, not silently lost.
#
# The reviewer's claimed *mechanism* for this row ("NAT-T rebind causes
# IKE_COOKIE reuse") is wrong and not what this scenario tests -- see the
# comment on rhook_conn_cookie() in racoon-hook-lib.sh for why a NAT-T port
# float cannot change the ISAKMP cookie pair. What IS real, and what this
# scenario covers, is the plain "crashed phase1-up leaves a live orphan"
# case the exact-match fix was built to handle regardless of cause.
# ==========================================================================
# The "retry" scenario above replaced $WORK/bin/ip with its own stuck-route
# variant, which stays in effect for every scenario after it (this file
# never restores the original stub) -- the "overlap"/"lifo" scenarios above
# don't need anything the original stub had that the retry one dropped, but
# this scenario does, so it gets its own tailored stub the same way "retry"
# did rather than silently depending on a version of $WORK/bin/ip that's no
# longer the one actually installed by this point in the file.
cat > "$WORK/bin/ip" <<'STUBEOF'
#!/bin/sh
echo "ip $*" >> "$IP_LOG"
case "$1 $2" in
	"-4 route")
		[ "$3" = "get" ] && { echo "$4 dev eth0 src 192.168.1.5"; exit 0; }
		;;
	"route replace")
		# Hangs here (after nm_dns has already journaled an "ok" entry,
		# before this step's own entry is written) so the crash scenario
		# below can SIGKILL phase1-up.sh mid-run and inspect the resulting
		# incomplete-but-non-empty state file.
		if [ "${IP_HANG_ROUTE_REPLACE:-0}" = "1" ]; then
			: > "${IP_HANG_MARKER:-/dev/null}"
			sleep 5
		fi
		;;
esac
exit 0
STUBEOF
chmod +x "$WORK/bin/ip"

reset_env crash
export SPLIT_INCLUDE_CIDR="100.64.20.0/24"
export IKE_COOKIE="cookie-crash-sa1"
export IP_HANG_ROUTE_REPLACE=1
export IP_HANG_MARKER="$WORK/ip-hang-marker.crash"
rm -f "$IP_HANG_MARKER"
"$RHOOK_HOOK_SHELL" "$HOOK_UP" >"$WORK/crash-up.log" 2>&1 &
crash_pid=$!

crash_waited=0
while [ ! -e "$IP_HANG_MARKER" ]; do
	crash_waited=$((crash_waited + 1))
	if [ "$crash_waited" -ge 10 ]; then
		fail "crash: phase1-up.sh never reached the hung 'ip route replace' step within 10s"
		break
	fi
	sleep 1
done

# A real crash gives no chance for any cleanup, trap-driven or otherwise
# -- SIGKILL, not a graceful stop, is the only faithful way to simulate
# one. The orphaned "ip" stub left sleeping in the background after this
# is harmless (it touches nothing else and exits on its own a few seconds
# later); reaping it here would only add flaky process-tree bookkeeping
# for no assertion that needs it.
kill -KILL "$crash_pid" 2>/dev/null
wait "$crash_pid" 2>/dev/null
unset IP_HANG_ROUTE_REPLACE IP_HANG_MARKER

TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.1" ] || fail "crash: killed generation .1 should still have a state file -- incomplete, but present"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.1.cookie" ] || fail "crash: killed generation .1's IKE_COOKIE sidecar must survive the crash -- rhook_state_reset() writes it before any step runs"
TESTS_RUN=$((TESTS_RUN + 1))
grep -q "^nm_dns	nm_dummy_profile	ok	" "$WORK_RUN/hook-state.203.0.113.99.1" || fail "crash: the nm_dns step that completed before the hang should be journaled with outcome 'ok'"
TESTS_RUN=$((TESTS_RUN + 1))
grep -q "^route_100.64.20.0/24	" "$WORK_RUN/hook-state.203.0.113.99.1" && fail "crash: the route step phase1-up.sh was killed inside must NOT appear as a completed journal entry"

# A brand-new session for the SAME peer must come up and tear down
# normally, completely ignoring the crashed orphan sitting on disk.
export SPLIT_INCLUDE_CIDR="100.64.21.0/24"
export IKE_COOKIE="cookie-crash-sa2"
: > "$IP_LOG"
: > "$NMCLI_LOG"
up2_out=$("$RHOOK_HOOK_SHELL" "$HOOK_UP" 2>&1)
assert_eq "crash: fresh phase1-up (SA2, same peer as the orphan) exits 0" "$?" "0"
assert_stderr_clean "phase1-up.sh invocation is stderr-clean" "$up2_out"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.2" ] || fail "crash: SA2 should get a new generation .2, not reuse or touch the orphaned .1"

export IKE_COOKIE="cookie-crash-sa2"
: > "$IP_LOG"
down2_out=$("$RHOOK_HOOK_SHELL" "$HOOK_DOWN" 2>&1)
assert_eq "crash: phase1-down for SA2 exits 0" "$?" "0"
assert_stderr_clean "phase1-down.sh invocation is stderr-clean" "$down2_out"
assert_contains "phase1-down for SA2 undid its own route (100.64.21.0/24)" "$(cat "$IP_LOG")" "route del 100.64.21.0/24"
TESTS_RUN=$((TESTS_RUN + 1))
[ -f "$WORK_RUN/hook-state.203.0.113.99.2" ] && fail "generation .2 (SA2) should be consumed after its own phase1-down"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$WORK_RUN/hook-state.203.0.113.99.1" ] || fail "crash: orphaned generation .1 must remain completely untouched by SA2's phase1-down"

# Finally: phase1-down for the crashed session's OWN cookie must still
# find and replay it -- not double-consumed, not silently lost -- proving
# the exact-match fix works even against an incomplete journal that only
# ever recorded one completed step.
export IKE_COOKIE="cookie-crash-sa1"
: > "$NMCLI_LOG"
: > "$IP_LOG"
down1_out=$("$RHOOK_HOOK_SHELL" "$HOOK_DOWN" 2>&1)
assert_eq "crash: phase1-down for the crashed orphan (SA1) exits 0" "$?" "0"
assert_stderr_clean "phase1-down.sh invocation is stderr-clean" "$down1_out"
assert_contains "phase1-down replayed the orphan's one completed step (nm_dns teardown)" "$(cat "$NMCLI_LOG")" "connection delete racoon-vpn-dns"
assert_not_contains "phase1-down never invokes a route undo for the step that never completed" "$(cat "$IP_LOG")" "route del"
TESTS_RUN=$((TESTS_RUN + 1))
[ -f "$WORK_RUN/hook-state.203.0.113.99.1" ] && fail "crash: generation .1 should be consumed after its own (delayed) phase1-down"

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
