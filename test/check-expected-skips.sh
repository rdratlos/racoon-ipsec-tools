#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# Assert that the LTO-canary tests listed under expected-skips.yml's
# "unprivileged" key actually report SKIP (exit 77) on this run, rather
# than just trusting that -flto=auto -ffat-lto-objects being present in
# the configure flags implies it. Run from test/, after `make check` (or
# any build that has already produced the check_PROGRAMS binaries) --
# see develop-build-test.yml, which runs this right after check-verbose.
#
# This intentionally does not re-verify every check_PROGRAMS binary for
# *unexpected* skips beyond the two named here: check-verbose's own log
# format doesn't attribute a SKIP to a specific binary (it only tallies a
# total), and re-running the full suite a second time just to get that
# attribution wasn't judged worth the doubled test time for a check
# scoped to two known, already-tracked binaries. If a third binary starts
# skipping under LTO in the future, add it here explicitly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/expected-skips.yml"

if [ ! -f "$MANIFEST" ]; then
    echo "::error::$MANIFEST not found." >&2
    exit 1
fi

# Minimal extraction of the "unprivileged" list's "binary:" values --
# avoids a PyYAML dependency for a two-key, list-of-scalars manifest.
# Stops at the next top-level (unindented) key, e.g. "root:".
EXPECTED=$(awk '
    /^unprivileged:/ { in_section=1; next }
    /^[a-zA-Z]/ { in_section=0 }
    in_section && /- binary:/ { sub(/.*binary:[ \t]*/, ""); print }
' "$MANIFEST")

if [ -z "$EXPECTED" ]; then
    echo "::error::No entries found under expected-skips.yml's 'unprivileged' key." >&2
    exit 1
fi

fail=0
while IFS= read -r binary; do
    [ -z "$binary" ] && continue
    if [ ! -x "./$binary" ]; then
        echo "::error title=Expected-skip binary missing::$binary is listed in expected-skips.yml but was not built (check the configure/make step)."
        fail=1
        continue
    fi

    set +e
    output=$(./"$binary" 2>&1)
    rc=$?
    set -e

    if [ "$rc" -eq 77 ]; then
        echo "OK: $binary reported SKIP (exit 77) as expected."
    elif [ "$rc" -eq 0 ]; then
        echo "::error title=Expected SKIP not observed::$binary exited 0 (PASS) instead of the expected SKIP (77). This means the -flto=auto -ffat-lto-objects canary this binary relies on to detect LTO defeating its -Wl,--wrap= test double is no longer being exercised on this toolchain -- the canary assumption may be stale. See CONTRIBUTING.md's 'Two tests skip under whole-program LTO' section."
        fail=1
    else
        echo "::error title=Expected SKIP became a real failure::$binary exited $rc instead of the expected SKIP (77). Output:"
        echo "$output" | sed 's/^/  /'
        echo "::error::See CONTRIBUTING.md's 'Two tests skip under whole-program LTO' section."
        fail=1
    fi
done <<< "$EXPECTED"

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "All expected-skip binaries (unprivileged context) confirmed SKIP as expected."
