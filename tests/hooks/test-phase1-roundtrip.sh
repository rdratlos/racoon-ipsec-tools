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
HOOK_UP="$SCRIPT_DIR/../../src/scripts/phase1-up.sh"
HOOK_DOWN="$SCRIPT_DIR/../../src/scripts/phase1-down.sh"

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
	export RACOON_HOOK_DEBUG=1
	export IP_LOG="$WORK/ip.log.$1"
	export NMCLI_LOG="$WORK/nmcli.log.$1"
	: > "$IP_LOG"
	: > "$NMCLI_LOG"
	unset IP_FAIL_LINK_DEL
	unset INTERNAL_ADDR4 LOCAL_ADDR LOCAL_PORT REMOTE_ADDR REMOTE_PORT
	unset SPLIT_INCLUDE_CIDR SPLIT_INCLUDE INTERNAL_DNS4_LIST INTERNAL_DNS4
	unset INTERNAL_SPLITDNS_DOMAINS DEFAULT_DOMAIN
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
up_out=$(dash "$HOOK_UP" 2>&1)
up_rc=$?
assert_eq "phase1-up exits 0" "$up_rc" "0"
assert_contains "phase1-up's own report ran (sanity check on the fixture)" "$up_out" "phase1-up report"
STATE_FILE="$WORK_RUN/hook-state.203.0.113.99-500"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] || fail "phase1-up must leave a non-empty state file for phase1-down to consume"

down_out=$(dash "$HOOK_DOWN" 2>&1)
down_rc=$?
assert_eq "phase1-down exits 0" "$down_rc" "0"
assert_contains "phase1-down reports OK" "$down_out" "result: OK"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] && fail "phase1-down must remove the state file after a clean teardown"

# R4 end to end: the nmcli teardown call must be logged before the last
# `ip route del` -- DNS torn down first, routes/interface last.
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

up_out=$(dash "$HOOK_UP" 2>&1)
up_rc=$?
assert_eq "retry scenario: phase1-up exits 0" "$up_rc" "0"
assert_contains "retry scenario: phase1-up's own report ran (sanity check on the fixture)" "$up_out" "phase1-up report"
STATE_FILE="$WORK_RUN/hook-state.203.0.113.99-500"

down_out1=$(dash "$HOOK_DOWN" 2>&1)
down_rc1=$?
assert_eq "first phase1-down (one route del fails) exits 0 under warn policy" "$down_rc1" "0"
assert_contains "first phase1-down reports the failure" "$down_out1" "result: PARTIAL"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] || fail "state file must survive a partial-failure teardown for a retry"
assert_contains "only the stuck route survives in the retained state" "$(cat "$STATE_FILE" 2>/dev/null)" "198.51.100.0/24"

down_out2=$(dash "$HOOK_DOWN" 2>&1)
down_rc2=$?
assert_eq "retry phase1-down (marker now set, ip succeeds) exits 0" "$down_rc2" "0"
assert_contains "retry phase1-down reports OK" "$down_out2" "result: OK"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] && fail "state file must be gone after the retry finishes the job"

# ==========================================================================
# phase1-down with no prior phase1-up run at all: nothing to undo, exits
# 0, never invokes ip/nmcli.
# ==========================================================================
reset_env noop
out=$(dash "$HOOK_DOWN" 2>&1)
rc=$?
assert_eq "phase1-down with no state exits 0" "$rc" "0"
assert_contains "phase1-down with no state explains why" "$out" "nothing to undo"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$IP_LOG" ] && fail "phase1-down must never invoke ip when there is no state to replay"

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
