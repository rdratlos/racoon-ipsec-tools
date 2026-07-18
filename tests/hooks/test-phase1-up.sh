#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# test-phase1-up.sh - end-to-end tests for phase1-up.sh: the Mode Config
# guard, outbound-interface detection, §4 input validation wired to
# racoon's actual env var names (including the comma- vs space-separated
# delimiter distinction verified against src/racoon's own C source), the
# R7 no-routes refusal, stale-state archival, and the on_dns_failure exit
# code policy.
#
# Every scenario pins backend=networkmanager (nmcli stubbed) so no test
# here ever executes the fallback backend's real /etc/resolv.conf write --
# that path is exercised at the plan-building level only, in
# test-plan-builder.sh, never applied against a real filesystem.
#
# Run directly: sh tests/hooks/test-phase1-up.sh

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
HOOK="$SCRIPT_DIR/../../src/scripts/phase1-up.sh"

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

WORK=$(mktemp -d "${TMPDIR:-/tmp}/racoon-phase1-up-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

# ip stub: answers `-4 route get <addr>` with a fixed interface, logs
# every invocation, and lets link/addr/route subcommands succeed unless
# IP_FAIL_LINK_ADD=1 is set (used by the failure-policy scenarios).
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
esac
exit 0
STUBEOF
chmod +x "$WORK/bin/ip"

# nmcli stub: just needs to succeed for `connection add`/`connection up`.
cat > "$WORK/bin/nmcli" <<'STUBEOF'
#!/bin/sh
echo "nmcli $*" >> "$NMCLI_LOG"
exit 0
STUBEOF
chmod +x "$WORK/bin/nmcli"

cat > "$WORK/hooks.conf" <<'EOF'
backend = networkmanager
EOF

run_hook() {
	# Fresh per-call env: caller sets the Mode Config vars it needs, then
	# calls this. STATE_DIR/logs are shared across the whole file (reset
	# per test section below where isolation matters).
	dash "$HOOK" 2>&1
}

reset_env() {
	WORK_RUN="$WORK/run.$1"
	rm -rf "$WORK_RUN"
	export RACOON_HOOK_STATE_DIR="$WORK_RUN"
	export RACOON_HOOK_CONF="$WORK/hooks.conf"
	export RACOON_HOOK_IP="$WORK/bin/ip"
	export RACOON_HOOK_NMCLI="$WORK/bin/nmcli"
	# Level 1 ("step") so the assembled report actually reaches stderr for
	# these assertions to inspect -- level 0 is syslog-only by design
	# (§5.1), which would otherwise make every report-content assertion
	# below silently see nothing.
	export RACOON_HOOK_DEBUG=1
	export IP_LOG="$WORK/ip.log.$1"
	export NMCLI_LOG="$WORK/nmcli.log.$1"
	: > "$IP_LOG"
	: > "$NMCLI_LOG"
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
assert_eq "no-interface guard exits 0" "$rc" "0"
assert_contains "no-interface guard logs why" "$out" "cannot determine outbound interface"
# restore the working ip stub for the rest of the file
cat > "$WORK/bin/ip" <<'STUBEOF'
#!/bin/sh
echo "ip $*" >> "$IP_LOG"
case "$1 $2" in
	"-4 route")
		if [ "$3" = "get" ]; then
			echo "$4 dev eth0 src 192.168.1.5"
			exit 0
		fi
		;;
	"link add")
		[ "${IP_FAIL_LINK_ADD:-0}" = "1" ] && exit 1
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
assert_eq "happy path exits 0" "$rc" "0"
# PARTIAL, not OK: dummy_iface/dummy_addr are legitimately SKIPPED under
# the networkmanager backend (its own `nmcli connection add` creates the
# interface and address as part of the profile) -- skipped steps make
# rhook_emit_report classify the run as PARTIAL, which is correct here,
# not a failure.
assert_contains "happy path reports PARTIAL (skips are expected, not failures)" "$out" "result: PARTIAL"
assert_contains "happy path has zero actually-failed steps" "$out" "3 ok, 2 skipped, 0 failed"
assert_contains "comma-separated domains split correctly in the report header" "$out" "domains=corp.example.com internal.example.com"
assert_contains "DNS-server host route added on top of split-include" "$out" "routes=198.51.100.0/24 198.51.100.53/32"
STATE_FILE="$WORK_RUN/hook-state.203.0.113.99-500"
TESTS_RUN=$((TESTS_RUN + 1))
[ -s "$STATE_FILE" ] || fail "happy path must leave a non-empty state file"
assert_contains "state file journals the NM profile undo command" "$(cat "$STATE_FILE" 2>/dev/null)" "nmcli connection delete racoon-vpn-dns"
assert_contains "nmcli invoked for the DNS profile" "$(cat "$NMCLI_LOG")" "connection add type dummy"

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
assert_contains "injected split-include is rejected with a reason" "$out" "invalid split-include network list"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q '10\.6\.6\.6' "$IP_LOG" 2>/dev/null; then
	fail "injected route-add fragment must never reach a real ip invocation"
fi

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
assert_eq "no-routes with on_dns_failure=warn (default) exits 0" "$rc" "0"
assert_contains "no-routes is reported as a failed required step" "$out" "[ FAILED    ] determine networks to route through the tunnel"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -qE '^route_' "$WORK_RUN/hook-state.203.0.113.99-500" 2>/dev/null; then
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
assert_eq "no-routes with on_dns_failure=abort exits 1" "$rc" "1"
cat > "$WORK/hooks.conf" <<'EOF'
backend = networkmanager
EOF

# ==========================================================================
# §3.4: a state file left behind by an incomplete teardown is archived,
# not silently overwritten or refused outright, and the run proceeds.
# ==========================================================================
reset_env stale
export INTERNAL_ADDR4="192.0.2.44"
export LOCAL_ADDR="203.0.113.1"
export REMOTE_ADDR="203.0.113.99"
export REMOTE_PORT="500"
export SPLIT_INCLUDE_CIDR="198.51.100.0/24"
mkdir -p "$WORK_RUN"
printf 'leftover_step\tcreate_dummy\tok\tip link del racoon0\n' > "$WORK_RUN/hook-state.203.0.113.99-500"
out=$(run_hook)
rc=$?
assert_eq "stale-state run still exits 0" "$rc" "0"
assert_contains "stale state file archival is logged" "$out" "stale state file"
TESTS_RUN=$((TESTS_RUN + 1))
find "$WORK_RUN" -name 'hook-state.*.stale.*' | grep -q . || fail "stale state file must be archived under a .stale. suffix, not deleted"
STATE_FILE="$WORK_RUN/hook-state.203.0.113.99-500"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q 'leftover_step' "$STATE_FILE" 2>/dev/null; then
	fail "the fresh state file must not contain the archived run's entries"
fi

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
