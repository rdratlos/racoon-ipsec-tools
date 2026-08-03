#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# Confirm the SKIPs listed in expected-skips.yml actually happen, rather
# than just trusting the configure flags imply them. Run from test/,
# after `make check` (or any build that has already produced the
# check_PROGRAMS binaries) -- see develop-build-test.yml, which runs this
# right after check-verbose.
#
# Two different strengths, matching the two lists in expected-skips.yml:
#   - always_skip_unprivileged: must be exactly SKIP (77). Deterministic
#     regardless of toolchain, so any other outcome is a real problem.
#   - lto_canary: PASS (0) or a correctly-reasoned SKIP (77) are both
#     fine -- whether the LTO defeat triggers is toolchain-dependent (see
#     expected-skips.yml's header comment). Only a genuine FAIL, or a
#     SKIP whose message doesn't match the documented canary, is a
#     problem: either would mean the binary's assumptions no longer hold.
#
# Deliberately does not re-verify every check_PROGRAMS binary for
# *unexpected* skips beyond the ones named here: check-verbose's own log
# format doesn't attribute a SKIP to a specific binary (it only tallies a
# total), and re-running the full suite a second time just to get that
# attribution wasn't judged worth the doubled test time for a check
# scoped to these known, already-tracked binaries.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/expected-skips.yml"

if [ ! -f "$MANIFEST" ]; then
    echo "::error::$MANIFEST not found." >&2
    exit 1
fi

# Minimal extraction from the manifest -- avoids a PyYAML dependency for
# a small, fixed-shape file. Each function scopes to one top-level key,
# stopping at the next unindented line.
list_binaries() {
    local section="$1"
    awk -v section="^${section}:" '
        $0 ~ section { in_section=1; next }
        /^[a-zA-Z]/ { in_section=0 }
        in_section && /- binary:/ { sub(/.*binary:[ \t]*/, ""); print }
    ' "$MANIFEST"
}

skip_message_substring_for() {
    local target="$1"
    awk -v target="$target" '
        /^lto_canary:/ { in_section=1; next }
        /^[a-zA-Z]/ { in_section=0 }
        in_section && /- binary:/ {
            sub(/.*binary:[ \t]*/, "", $0); cur=$0
        }
        in_section && cur == target && /skip_message_substring:/ {
            sub(/.*skip_message_substring:[ \t]*"?/, "");
            sub(/"?[ \t]*$/, "");
            print
        }
    ' "$MANIFEST"
}

fail=0

# Does NOT set `fail` itself -- called via command substitution below,
# which forks a subshell, so any assignment made in here would be
# invisible to the caller. Missing-binary (127) is handled by the caller.
run_binary() {
    local binary="$1"
    if [ ! -x "./$binary" ]; then
        echo "::error title=Expected-skip binary missing::$binary is listed in expected-skips.yml but was not built (check the configure/make step)." >&2
        return 127
    fi
    "./$binary" 2>&1
    return $?
}

echo "--- always_skip_unprivileged (must be exactly SKIP) ---"
while IFS= read -r binary; do
    [ -z "$binary" ] && continue
    output=$(run_binary "$binary"); rc=$?
    if [ "$rc" -eq 127 ]; then
        fail=1
        continue  # message already printed by run_binary
    fi

    if [ "$rc" -eq 77 ]; then
        echo "OK: $binary reported SKIP (exit 77) as expected."
    else
        echo "::error title=Expected SKIP not observed::$binary exited $rc instead of the expected SKIP (77). This binary is expected to skip deterministically on every unprivileged run (see CONTRIBUTING.md's 'Why some tests need root'). Output:"
        echo "$output" | sed 's/^/  /'
        fail=1
    fi
done <<< "$(list_binaries always_skip_unprivileged)"

echo "--- lto_canary (PASS or correctly-reasoned SKIP both fine) ---"
while IFS= read -r binary; do
    [ -z "$binary" ] && continue
    output=$(run_binary "$binary"); rc=$?
    if [ "$rc" -eq 127 ]; then
        fail=1
        continue  # message already printed by run_binary
    fi

    if [ "$rc" -eq 0 ]; then
        echo "OK: $binary PASSed (exit 0) -- this toolchain's LTO does not defeat its -Wl,--wrap= test double."
    elif [ "$rc" -eq 77 ]; then
        substring=$(skip_message_substring_for "$binary")
        if [ -n "$substring" ] && printf '%s' "$output" | grep -qF "$substring"; then
            echo "OK: $binary reported SKIP (exit 77) with the expected LTO-canary message -- this toolchain's LTO does defeat its -Wl,--wrap= test double."
        else
            echo "::error title=Unexplained SKIP::$binary reported SKIP (exit 77), but its output didn't contain the expected canary message ('$substring'). Output:"
            echo "$output" | sed 's/^/  /'
            echo "::error::See CONTRIBUTING.md's 'Two tests skip under whole-program LTO' section."
            fail=1
        fi
    else
        echo "::error title=Real test failure::$binary exited $rc (neither PASS nor SKIP). Output:"
        echo "$output" | sed 's/^/  /'
        echo "::error::See CONTRIBUTING.md's 'Two tests skip under whole-program LTO' section."
        fail=1
    fi
done <<< "$(list_binaries lto_canary)"

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "All expected-skip binaries confirmed as expected."
