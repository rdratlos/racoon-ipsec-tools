#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# test-lib-smoke.sh - exercises racoon-hook-lib.sh's plan/apply/report/state
# machinery in isolation, without touching the real system: no root, no VPN,
# no network.  Run directly: sh tests/hooks/test-lib-smoke.sh
#
# This is a hand-rolled pass/fail harness (no external test framework
# dependency) matching the style of the rest of this repo's shell tests.

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LIB="$SCRIPT_DIR/../../src/racoon/scripts/racoon-hook-lib.sh"

TESTS_RUN=0
TESTS_FAILED=0

fail() {
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "FAIL: $1"
}

pass() {
	echo "ok: $1"
}

assert_eq() {
	# $1 = description  $2 = actual  $3 = expected
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ "$2" = "$3" ]; then
		pass "$1"
	else
		fail "$1 -- expected '$3', got '$2'"
	fi
}

assert_file_contains() {
	# $1 = description  $2 = file  $3 = pattern (grep -F)
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ -f "$2" ] && grep -F -q -- "$3" "$2" 2>/dev/null; then
		pass "$1"
	else
		fail "$1 -- '$3' not found in $2"
	fi
}

assert_file_not_contains() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ -f "$2" ] && grep -F -q -- "$3" "$2" 2>/dev/null; then
		fail "$1 -- '$3' unexpectedly found in $2"
	else
		pass "$1"
	fi
}

# --------------------------------------------------------------------------
# Fixture: isolated state dir, no config file, deterministic env.
# --------------------------------------------------------------------------
WORK=$(mktemp -d "${TMPDIR:-/tmp}/racoon-hook-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

RACOON_HOOK_STATE_DIR="$WORK/run"
RACOON_HOOK_CONF="$WORK/nonexistent-hooks.conf"
export RACOON_HOOK_STATE_DIR RACOON_HOOK_CONF
unset RACOON_HOOK_DEBUG 2>/dev/null || true

# shellcheck source=SCRIPTDIR/../../src/racoon/scripts/racoon-hook-lib.sh
# shellcheck disable=SC2034  # REMOTE_ADDR/REMOTE_PORT/RHOOK_* below are read by the sourced library, not this file
. "$LIB"

REMOTE_ADDR="203.0.113.7"
REMOTE_PORT="500"

# --------------------------------------------------------------------------
# Test 1: connection identity is REMOTE_ADDR alone, sanitized, and
# filesystem-safe. REMOTE_PORT is deliberately not part of it (brief 3
# §D: it floats 500->4500 on a NAT-T rebind and changes across a
# reconnect, so it can no longer be trusted to identify "the same peer").
# --------------------------------------------------------------------------
RHOOK_HOOK_NAME="phase1-up"
assert_eq "conn addr sanitizes the address, ignores the port" "$(rhook_conn_addr)" "203.0.113.7"

# --------------------------------------------------------------------------
# Test 2: config loading picks up known keys, warns on unknown, rejects a
# bad on_dns_failure value back to the default.
# --------------------------------------------------------------------------
cat > "$WORK/hooks.conf" <<'EOF'
# comment line
backend = resolved
on_dns_failure=bogus
debug_level =2
dummy_iface= racoon7
allow_resolv_conf_overwrite = yes
unknown_key = wat
EOF
RHOOK_CONF="$WORK/hooks.conf"
rhook_load_config 2>"$WORK/config-warnings.log"
assert_eq "backend from config" "$RHOOK_BACKEND" "resolved"
assert_eq "dummy_iface from config (whitespace trimmed)" "$RHOOK_DUMMY_IFACE" "racoon7"
assert_eq "debug_level from config (whitespace trimmed)" "$RHOOK_DEBUG_LEVEL" "2"
assert_eq "invalid on_dns_failure falls back to warn" "$RHOOK_ON_DNS_FAILURE" "warn"
assert_eq "allow_resolv_conf_overwrite from config" "$RHOOK_ALLOW_RESOLV_CONF_OVERWRITE" "yes"
assert_file_contains "unknown key warned" "$WORK/config-warnings.log" "unknown_key"

# Brief 3 §I: an invalid allow_resolv_conf_overwrite value falls back to
# the safe default ("no"), same pattern as on_dns_failure above.
cat > "$WORK/hooks.conf" <<'EOF'
allow_resolv_conf_overwrite = maybe
EOF
rhook_load_config 2>"$WORK/config-warnings2.log"
assert_eq "invalid allow_resolv_conf_overwrite falls back to no" "$RHOOK_ALLOW_RESOLV_CONF_OVERWRITE" "no"
assert_file_contains "invalid allow_resolv_conf_overwrite is warned about" "$WORK/config-warnings2.log" "allow_resolv_conf_overwrite"

# --------------------------------------------------------------------------
# Test 3: plan/apply/report round trip -- one required step that succeeds,
# one optional step that fails (must not stop the plan), one required step
# that fails (must stop the plan and mark the rest not-attempted).
# --------------------------------------------------------------------------
RHOOK_DEBUG_LEVEL=2
rhook_trace_init
TESTS_RUN=$((TESTS_RUN + 1))
if rhook_state_exists; then
	fail "state file should not exist before the first plan runs"
else
	pass "rhook_state_exists is false on a clean run"
fi
rhook_state_reset
rhook_plan_reset
rhook_plan_add step_ok      test_type required "do the thing that works"   "true"                       "true"
rhook_plan_add step_opt_bad test_type optional "optional thing that fails" "false"                       ""
rhook_plan_add step_req_bad test_type required "required thing that fails" "sh -c 'echo boom >&2; exit 3'" ""
rhook_plan_add step_never   test_type required "never reached"             "true"                        ""

rhook_report_init
rhook_apply_plan
apply_rc=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [ "$apply_rc" -ne 0 ]; then
	pass "rhook_apply_plan reports failure when a required step fails"
else
	fail "rhook_apply_plan should have returned non-zero"
fi

STATE_FILE=$(rhook_state_file)
assert_file_contains "ok step recorded in state" "$STATE_FILE" "step_ok	test_type	ok	true"
assert_file_contains "optional failure recorded, not fatal" "$STATE_FILE" "step_opt_bad	test_type	failed"
assert_file_contains "required failure recorded" "$STATE_FILE" "step_req_bad	test_type	failed"
assert_file_contains "step after a required failure is not-attempted" "$STATE_FILE" "step_never	test_type	not-attempted"

TRACE_FILE="$RHOOK_TRACE_FILE"
assert_file_contains "trace file captured failing command output" "$TRACE_FILE" "boom"

# --------------------------------------------------------------------------
# Test 4: EXIT trap emits exactly once even if called twice, and the report
# result is PARTIAL given the failures above.
# --------------------------------------------------------------------------
rhook_exit_trap 2>"$WORK/report1.log"
rhook_exit_trap 2>"$WORK/report2.log"
assert_file_contains "first EXIT trap call emits the report" "$WORK/report1.log" "result: PARTIAL"
TESTS_RUN=$((TESTS_RUN + 1))
if [ -s "$WORK/report2.log" ]; then
	fail "second EXIT trap call must be a no-op (idempotent)"
else
	pass "second EXIT trap call is a no-op"
fi

# --------------------------------------------------------------------------
# Test 5: a fully successful plan reports OK and the EXIT trap reflects it
# in its own exit status. Also demonstrates the FIFO/generation model
# (brief 3 §D): test 3's generation for this same peer address was never
# consumed (no undo replay ran against it), so it is still discoverable
# here -- rhook_state_reset() below allocates a *new*, independent
# generation for the same peer rather than reusing or clobbering it,
# which is the whole point of numbering generations instead of keeping
# one file per connection id.
# --------------------------------------------------------------------------
RHOOK_EXIT_HANDLED=0
TESTS_RUN=$((TESTS_RUN + 1))
if rhook_state_exists; then
	pass "rhook_state_exists is true after the previous plan left failures behind"
else
	fail "state file should be non-empty after test 3's plan ran"
fi
rhook_state_reset
rhook_plan_reset
rhook_plan_add only_step test_type required "single successful step" "true" "true"
rhook_report_init
rhook_apply_plan
rhook_exit_trap 2>"$WORK/report3.log"
result_line=$(grep 'result:' "$WORK/report3.log" || true)
case "$result_line" in
	*"result: OK"*) pass "all-success plan reports OK" ;;
	*) fail "all-success plan should report OK, got: $result_line" ;;
esac
TESTS_RUN=$((TESTS_RUN + 1))

# --------------------------------------------------------------------------
# Test 6: postcondition support (§7.4) -- a step whose command exits 0 but
# whose postcondition reports a reason must be downgraded to failed, not
# recorded as ok, and must still stop the plan if required.
#
# A fresh peer address isolates this from tests 3/5's still-live,
# still-unconsumed generations above -- otherwise rhook_state_exists()/
# rhook_state_oldest_unconsumed() would keep finding those instead of
# this test's own generation, exactly the FIFO ordering brief 3 §D wants
# preserved (oldest-first), which would make this test's own assertions
# meaningless.
# --------------------------------------------------------------------------
REMOTE_ADDR="203.0.113.16"
RHOOK_EXIT_HANDLED=0
rhook_postcond_no_effect_type() {
	printf 'wrote to a file nothing reads'
}
rhook_state_reset
rhook_plan_reset
rhook_plan_add fake_success no_effect_type required "looks fine, does nothing" "true" "true"
rhook_plan_add never_reached test_type required "should not run" "true" ""
rhook_report_init
rhook_apply_plan
apply_rc2=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [ "$apply_rc2" -ne 0 ]; then
	pass "postcondition failure on a required step stops the plan"
else
	fail "postcondition failure on a required step should have stopped the plan"
fi
STATE_FILE2=$(rhook_state_file)
assert_file_contains "postcondition failure recorded as failed, not ok" "$STATE_FILE2" "fake_success	no_effect_type	failed"
rhook_exit_trap 2>"$WORK/report4.log"
assert_file_contains "report explains the step reported success but had no effect" "$WORK/report4.log" "reported success, but had no effect"

# --------------------------------------------------------------------------
# Test 7: rhook_undo_replay() (§3.4/R4) -- undoes successful steps in
# reverse apply order, skips steps that never succeeded (no undo needed),
# marks the state file consumed on a fully clean teardown, and on a
# partial failure retains only the still-failing entries so a retry can
# finish the job without re-running undos that already succeeded.
#
# A fresh peer address, and passing rhook_undo_replay's target file
# explicitly (rather than via rhook_state_oldest_unconsumed()), tests
# the replay mechanism on its own terms -- *which* file the FIFO scheme
# picks is a separate concern, exercised end to end through the real
# hooks in test-phase1-roundtrip.sh.
# --------------------------------------------------------------------------
REMOTE_ADDR="203.0.113.17"
RHOOK_EXIT_HANDLED=0
UNDO_LOG="$WORK/undo-order.log"
: > "$UNDO_LOG"
rhook_state_reset
rhook_plan_reset
rhook_plan_add u_first  test_type required "first applied"          "true"  "echo undo-first >> \"$UNDO_LOG\""
rhook_plan_add u_second test_type required "second applied"         "true"  "echo undo-second >> \"$UNDO_LOG\""
rhook_plan_add u_opt    test_type optional "optional, never succeeds" "false" "echo undo-opt-SHOULD-NOT-RUN >> \"$UNDO_LOG\""
rhook_plan_add u_third  test_type required "third applied"          "true"  "echo undo-third >> \"$UNDO_LOG\""
rhook_report_init
rhook_apply_plan
rhook_exit_trap 2>/dev/null

TESTS_RUN=$((TESTS_RUN + 1))
if rhook_state_exists; then
	pass "state file is non-empty after a plan with successful steps applied"
else
	fail "state file should be non-empty before undo replay runs"
fi

UNDO_TARGET1=$(rhook_state_file)
RHOOK_EXIT_HANDLED=0
rhook_report_init
rhook_undo_replay "$UNDO_TARGET1"
undo_rc=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [ "$undo_rc" -eq 0 ]; then
	pass "rhook_undo_replay reports success when every undo succeeds"
else
	fail "rhook_undo_replay should have reported success"
fi
assert_eq "undo replay runs in reverse apply order (R4)" \
	"$(cat "$UNDO_LOG")" \
	"undo-third
undo-second
undo-first"
TESTS_RUN=$((TESTS_RUN + 1))
if rhook_state_exists; then
	fail "state file must no longer be live (consumed) after a fully successful undo replay"
else
	pass "state file is no longer live (marked consumed) after a fully successful undo replay"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if [ -f "$UNDO_TARGET1.consumed" ]; then
	pass "the consumed generation is kept on disk with a .consumed suffix, not deleted outright"
else
	fail "expected $UNDO_TARGET1.consumed to exist after a successful undo replay"
fi

# Partial failure: one undo command fails -- the rest must still run
# (best effort), and only the failed entry survives in the state file.
RHOOK_EXIT_HANDLED=0
: > "$UNDO_LOG"
rhook_state_reset
rhook_plan_reset
rhook_plan_add u_ok1 test_type required "ok 1" "true" "echo undo-ok1 >> \"$UNDO_LOG\""
rhook_plan_add u_bad test_type required "will fail to undo" "true" "sh -c 'echo undo-bad >> \"$UNDO_LOG\"; exit 5'"
rhook_plan_add u_ok2 test_type required "ok 2" "true" "echo undo-ok2 >> \"$UNDO_LOG\""
rhook_report_init
rhook_apply_plan
rhook_exit_trap 2>/dev/null

UNDO_TARGET2=$(rhook_state_file)
RHOOK_EXIT_HANDLED=0
rhook_report_init
rhook_undo_replay "$UNDO_TARGET2"
undo_rc2=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [ "$undo_rc2" -ne 0 ]; then
	pass "rhook_undo_replay reports failure when at least one undo fails"
else
	fail "rhook_undo_replay should have reported failure"
fi
assert_eq "best-effort: the other undos still ran despite one failing" \
	"$(cat "$UNDO_LOG")" \
	"undo-ok2
undo-bad
undo-ok1"
TESTS_RUN=$((TESTS_RUN + 1))
if rhook_state_exists; then
	pass "state file is retained after a partial-failure undo replay"
else
	fail "state file should be retained when something failed to undo"
fi
STATE_FILE3="$UNDO_TARGET2"
assert_file_contains "only the failed entry survives in the retained state file" "$STATE_FILE3" "u_bad"
assert_file_not_contains "the successfully-undone entries are not retained" "$STATE_FILE3" "u_ok1"
assert_file_not_contains "the successfully-undone entries are not retained (2)" "$STATE_FILE3" "u_ok2"

# Retry: fix the failing command in place and replay again -- the
# remaining entry must undo cleanly and the state file must finally go.
# `sed -i` is not POSIX (and GNU/BSD sed disagree on its syntax besides);
# redirect to a temp file and move it into place instead, matching this
# repo's other in-place-edit sites.
sed "s/exit 5/exit 0/" "$STATE_FILE3" > "$STATE_FILE3.tmp" && mv "$STATE_FILE3.tmp" "$STATE_FILE3"
RHOOK_EXIT_HANDLED=0
rhook_report_init
rhook_undo_replay "$STATE_FILE3"
undo_rc3=$?
assert_eq "retry after fixing the failing undo succeeds" "$undo_rc3" "0"
TESTS_RUN=$((TESTS_RUN + 1))
if rhook_state_exists; then
	fail "state file must no longer be live once the retry finishes the job"
else
	pass "state file is no longer live once the retry finishes the job"
fi

# --------------------------------------------------------------------------
# Test 8: in-transaction DNS-group rollback (§B.1, brief 3, F4) -- a
# required DNS-group step failing mid-apply must immediately undo every
# other DNS-group step already applied this run, but must leave
# preceding non-DNS-group steps (dummy interface/address/routes) alone,
# and the rolled-back entries must not linger in the state file.
# --------------------------------------------------------------------------
REMOTE_ADDR="203.0.113.18"
RHOOK_EXIT_HANDLED=0
: > "$UNDO_LOG"
rhook_state_reset
rhook_plan_reset
rhook_plan_add iface_up  create_dummy required "bring up the dummy iface" "true" "echo undo-iface >> \"$UNDO_LOG\""
rhook_plan_add domains   set_domains  required "set routing domains"     "true" "echo undo-domains >> \"$UNDO_LOG\""
rhook_plan_add dns_fail  set_dns      required "set DNS servers (fails)" "sh -c 'exit 9'" "echo undo-dns-SHOULD-NOT-RUN >> \"$UNDO_LOG\""
rhook_report_init
rhook_apply_plan
apply_rc3=$?
TESTS_RUN=$((TESTS_RUN + 1))
if [ "$apply_rc3" -ne 0 ]; then
	pass "a failed required DNS-group step still stops the plan"
else
	fail "a failed required DNS-group step should have stopped the plan"
fi
assert_eq "rollback undoes the domains step immediately (before the failed step's own undo, which never ran)" \
	"$(cat "$UNDO_LOG")" \
	"undo-domains"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q '^iface_up	' "$(rhook_state_file)" 2>/dev/null; then
	pass "the non-DNS-group step before the failure is left alone (not rolled back)"
else
	fail "iface_up should still be recorded ok -- only DNS-group steps roll back"
fi
STATE_FILE4=$(rhook_state_file)
assert_file_not_contains "the rolled-back domains entry is removed from state, not left as ok" "$STATE_FILE4" "domains	set_domains	ok"
assert_file_contains "the failed dns step itself is recorded failed" "$STATE_FILE4" "dns_fail	set_dns	failed"
rhook_exit_trap 2>"$WORK/report5.log"
assert_file_contains "the report shows the rollback undo succeeding" "$WORK/report5.log" "rollback undo domains"

# --------------------------------------------------------------------------
# Test 9: rhook_state_reap() age cap (brief 3 §D: "suggest 5 / 24h").
# Count-based reaping is exercised end to end through the real
# phase1-up.sh in test-phase1-up.sh; the age cap is easier to test
# directly here by backdating a .consumed file's mtime past
# RHOOK_REAP_MAX_AGE_SECONDS with `touch -t` (POSIX, unlike GNU-only
# `touch -d`) rather than waiting 24 real hours.
# --------------------------------------------------------------------------
REMOTE_ADDR="203.0.113.19"
REAP_PREFIX="$(rhook_state_file_prefix)"
rhook_ensure_state_dir
printf 'old\tcreate_dummy\tok\ttrue\n' > "${REAP_PREFIX}.1.consumed"
printf 'recent\tcreate_dummy\tok\ttrue\n' > "${REAP_PREFIX}.2.consumed"
# Two days ago, well past the 24h cap -- portable timestamp via `touch -t`.
OLD_STAMP=$("$RACOON_HOOK_DATE" -d '2 days ago' +%Y%m%d%H%M 2>/dev/null || "$RACOON_HOOK_DATE" -v-2d +%Y%m%d%H%M 2>/dev/null)
if [ -n "$OLD_STAMP" ]; then
	touch -t "$OLD_STAMP" "${REAP_PREFIX}.1.consumed" 2>/dev/null
	rhook_state_reap
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ -f "${REAP_PREFIX}.1.consumed" ]; then
		fail "a .consumed generation older than RHOOK_REAP_MAX_AGE_SECONDS must be reaped regardless of count"
	fi
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ -f "${REAP_PREFIX}.2.consumed" ]; then
		:
	else
		fail "a recent .consumed generation must survive reaping when only the age cap, not the count cap, is exceeded"
	fi
else
	echo "SKIP: neither GNU 'date -d' nor BSD 'date -v' available to backdate a file for the age-cap test"
fi

# --------------------------------------------------------------------------
# Test 11: rhook_ensure_dummy_iface() -- found live on an Ubuntu Bionic
# roadwarrior with no reboot between test runs:
#   [trace]   command: ip link add "racoon0" type dummy && ip link set "racoon0" up
#   [trace]   output: RTNETLINK answers: File exists
# An incomplete prior teardown left racoon0 already present; the old
# unconditional `ip link add` failed outright (a required step), halting
# phase1-up.sh before anything else applied. The stub below reproduces
# real iproute2 behavior verified directly against iproute2 6.1.0 (and
# cross-checked against 4.15.0's own source, the release Ubuntu Bionic
# ships): a nonexistent device exits 1 with a "does not exist" message;
# an existing device that does not match a `type KIND` filter exits 0
# with EMPTY output (not an error); a matching device exits 0 with
# non-empty output.
# --------------------------------------------------------------------------
cat > "$WORK/ip-stub" <<'STUBEOF'
#!/bin/sh
echo "ip $*" >> "$IP_CALL_LOG"
[ "$1" = "-o" ] && shift
if [ "$1 $2" = "link show" ]; then
	shift 2
	rhook_t_iface=""
	rhook_t_type=""
	while [ $# -gt 0 ]; do
		case "$1" in
			dev) shift; rhook_t_iface="$1" ;;
			type) shift; rhook_t_type="$1" ;;
		esac
		shift
	done
	if [ -z "${IFACE_STATE:-}" ]; then
		echo "Device \"$rhook_t_iface\" does not exist." >&2
		exit 1
	fi
	if [ -n "$rhook_t_type" ] && [ "$rhook_t_type" != "$IFACE_STATE" ]; then
		exit 0
	fi
	echo "1: $rhook_t_iface: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN"
	exit 0
elif [ "$1 $2" = "link add" ]; then
	exit "${IP_ADD_RC:-0}"
elif [ "$1 $2" = "link set" ]; then
	exit "${IP_SET_RC:-0}"
fi
exit 0
STUBEOF
chmod +x "$WORK/ip-stub"
RACOON_HOOK_IP="$WORK/ip-stub"

# 11a: interface does not exist at all -- creates it fresh (unchanged
# behavior from before this fix).
unset IFACE_STATE
IP_CALL_LOG="$WORK/ip-calls-11a.log"
export IP_CALL_LOG
: > "$IP_CALL_LOG"
edi_out=$(rhook_ensure_dummy_iface racoon0 2>&1)
edi_rc=$?
assert_eq "11a: nonexistent interface -- function succeeds" "$edi_rc" "0"
assert_file_contains "11a: link add was invoked" "$IP_CALL_LOG" "link add racoon0 type dummy"
assert_file_contains "11a: link set up was invoked" "$IP_CALL_LOG" "link set racoon0 up"

# 11b: interface already exists and IS dummy-typed -- the live-bug fix:
# reuse it (bring it up, idempotent) instead of failing on "File exists".
IFACE_STATE="dummy"
export IFACE_STATE
IP_CALL_LOG="$WORK/ip-calls-11b.log"
: > "$IP_CALL_LOG"
edi_out=$(rhook_ensure_dummy_iface racoon0 2>&1)
edi_rc=$?
assert_eq "11b: existing dummy-typed interface -- function succeeds (reused, not failed)" "$edi_rc" "0"
assert_file_not_contains "11b: link add is never invoked for a reused interface" "$IP_CALL_LOG" "link add"
assert_file_contains "11b: link set up still runs (idempotent bring-up)" "$IP_CALL_LOG" "link set racoon0 up"
TESTS_RUN=$((TESTS_RUN + 1))
case "$edi_out" in
	*"already exists"*) ;;
	*) fail "11b: reuse must be logged, not silent -- got: $edi_out" ;;
esac

# 11c: interface already exists but is NOT dummy-typed -- refuse outright,
# never touch an interface this hook set cannot identify as its own.
IFACE_STATE="veth"
IP_CALL_LOG="$WORK/ip-calls-11c.log"
: > "$IP_CALL_LOG"
edi_out=$(rhook_ensure_dummy_iface racoon0 2>&1)
edi_rc=$?
assert_eq "11c: existing non-dummy interface -- function fails" "$edi_rc" "1"
assert_file_not_contains "11c: link add is never invoked for a foreign interface" "$IP_CALL_LOG" "link add"
assert_file_not_contains "11c: link set is never invoked for a foreign interface" "$IP_CALL_LOG" "link set"
TESTS_RUN=$((TESTS_RUN + 1))
case "$edi_out" in
	*"not a dummy-type interface"*) ;;
	*) fail "11c: refusal must explain why -- got: $edi_out" ;;
esac

# --------------------------------------------------------------------------
# 11d: PR #91 review row 24 (comment 5061097437) -- two genuinely
# concurrent invocations racing to create the same dummy interface.
# Before rhook_dummy_iface_lock(), both could pass the "does it exist"
# check before either created it. This stub deliberately widens that
# window (a 1s sleep the first time "link show" finds nothing yet) so an
# unserialized run would reliably lose the race within this test's
# lifetime rather than only occasionally, on unlucky scheduling; with the
# lock in place, the second invocation blocks for the whole
# check-then-create section and only proceeds once the first has already
# created the interface, landing on the reuse branch instead.
# --------------------------------------------------------------------------
cat > "$WORK/ip-stub-race" <<'STUBEOF'
#!/bin/sh
echo "ip $*" >> "$RACE_CALL_LOG"
[ "$1" = "-o" ] && shift
if [ "$1 $2" = "link show" ]; then
	if [ ! -f "$RACE_STATE_FILE" ]; then
		sleep 1
	fi
	if [ ! -f "$RACE_STATE_FILE" ]; then
		echo "Device does not exist." >&2
		exit 1
	fi
	echo "1: racoon0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN"
	exit 0
elif [ "$1 $2" = "link add" ]; then
	: > "$RACE_STATE_FILE"
	exit 0
elif [ "$1 $2" = "link set" ]; then
	exit 0
fi
exit 0
STUBEOF
chmod +x "$WORK/ip-stub-race"
RACOON_HOOK_IP="$WORK/ip-stub-race"
RACE_CALL_LOG="$WORK/race-calls.log"
RACE_STATE_FILE="$WORK/race-state"
export RACOON_HOOK_IP RACE_CALL_LOG RACE_STATE_FILE
rm -f "$RACE_CALL_LOG" "$RACE_STATE_FILE"

(
	rhook_ensure_dummy_iface racoon0 >"$WORK/race-a.out" 2>&1
	echo $? > "$WORK/race-a.rc"
) &
race_pid_a=$!
(
	rhook_ensure_dummy_iface racoon0 >"$WORK/race-b.out" 2>&1
	echo $? > "$WORK/race-b.rc"
) &
race_pid_b=$!
wait "$race_pid_a"
wait "$race_pid_b"

assert_eq "11d: concurrent invocation A exits 0" "$(cat "$WORK/race-a.rc")" "0"
assert_eq "11d: concurrent invocation B exits 0" "$(cat "$WORK/race-b.rc")" "0"
TESTS_RUN=$((TESTS_RUN + 1))
race_add_count=$(grep -c "link add" "$RACE_CALL_LOG")
if [ "$race_add_count" = "1" ]; then
	pass "11d: exactly one 'ip link add' across both concurrent invocations"
else
	fail "11d: exactly one 'ip link add' expected under the dummy-iface lock, got $race_add_count -- $(cat "$RACE_CALL_LOG")"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q "already exists" "$WORK/race-a.out" "$WORK/race-b.out" 2>/dev/null; then
	pass "11d: the loser of the race took the reuse branch, not a second create attempt"
else
	fail "11d: neither invocation logged the reuse path -- got A: $(cat "$WORK/race-a.out"); B: $(cat "$WORK/race-b.out")"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q "not a dummy-type interface" "$WORK/race-a.out" "$WORK/race-b.out" 2>/dev/null; then
	fail "11d: no error should surface from either concurrent invocation"
else
	pass "11d: no error surfaced from either concurrent invocation"
fi

unset IFACE_STATE IP_CALL_LOG

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
