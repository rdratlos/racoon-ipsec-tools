#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# Coverage-parity gate for the "full" NetBSD CI job
# (develop-netbsd-full-check.yml): confirms the binaries
# netbsd-parity-baseline.yml says must exist actually got built, and the
# binaries it says must PASS under real root actually did -- instead of
# trusting the configure/CI flags to have produced that outcome, the same
# lesson expected-skips.yml/check-expected-skips.sh already encode for a
# different pair of SKIP populations (see that pair's own header
# comments; this script is deliberately the same shape).
#
# Why this exists at all: doc/dev/v0.9.1-hardening-spec.md §11. In short,
# test/Makefile.am's `if !SANITIZER_BUILD` gate around roughly half this
# suite's check_PROGRAMS, combined with develop-netbsd-build-test.yml's
# sanitizer-on-by-default design, meant `develop`'s own NetBSD CI reported
# green for five weeks while never once building the binaries that would
# have caught the regression this investigation found. This script is the
# gate meant to keep that specific failure mode from recurring silently:
# run it, and a future change that re-excludes one of these binaries
# (deliberately or not) fails loudly here instead of just not showing up
# in a `make check` transcript nobody reads line-by-line.
#
# Two phases, run from test/:
#   1. must_build -- run right after `make check TESTS=` (builds every
#      check_PROGRAMS binary without running any of them). Every name
#      listed must exist as an executable file in test/.
#   2. must_pass_as_root -- run right after a real, privileged
#      `make check` (i.e. this script itself must also be invoked as
#      root for this phase to mean anything -- it does not escalate
#      privilege itself). Every name listed must exit 0 (PASS) when run
#      directly, not 77 (SKIP) -- a SKIP here means root wasn't actually
#      in effect when the suite ran, silently reproducing the exact gap
#      this job exists to close.
#
# Deliberately does not warn about binaries built but not listed here:
# the base (always-built, no automake conditional at all) and the 11
# privsep-dispatch-loop binaries built under both SANITIZER_BUILD
# settings (doc/dev/v0.9.1-hardening-spec.md §2.4) are intentionally
# absent from this baseline -- they were never the binaries this
# incident found missing, and enumerating them here just to support a
# "new coverage" heuristic would need to be kept in lockstep with
# test/Makefile.am for no safety benefit. Extending must_build/
# must_pass_as_root when a *new* !SANITIZER_BUILD-gated binary is added
# is a manual step -- see netbsd-parity-baseline.yml's own header.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/netbsd-parity-baseline.yml"

if [ ! -f "$MANIFEST" ]; then
    echo "::error::$MANIFEST not found." >&2
    exit 1
fi

# Same minimal, dependency-free extraction approach as
# check-expected-skips.sh -- this file's shape is fixed and small enough
# that a real YAML parser isn't worth requiring on the NetBSD side.
list_section() {
    local section="$1"
    awk -v section="^${section}:" '
        $0 ~ section { in_section=1; next }
        /^[a-zA-Z]/ { in_section=0 }
        in_section && /^  - / { sub(/^  - /, ""); print }
    ' "$MANIFEST"
}

fail=0

echo "--- must_build (every listed binary must exist in test/) ---"
while IFS= read -r binary; do
    [ -z "$binary" ] && continue
    if [ -x "$SCRIPT_DIR/$binary" ]; then
        echo "OK: $binary built."
    else
        echo "::error title=NetBSD parity gap::$binary is required by netbsd-parity-baseline.yml's must_build list but was not built. This is exactly the failure mode doc/dev/v0.9.1-hardening-spec.md §11 documents: a check_PROGRAMS binary silently dropped from this NetBSD build. Check test/Makefile.am's automake conditionals around this binary (most likely an !SANITIZER_BUILD-style gate) against this job's actual configure flags." >&2
        fail=1
    fi
done <<< "$(list_section must_build)"

echo "--- must_pass_as_root (every listed binary must PASS, not SKIP, under real root) ---"
if [ "$(id -u)" -ne 0 ]; then
    echo "::error::check-netbsd-parity.sh's must_pass_as_root phase was invoked as uid $(id -u), not root. It does not escalate privilege itself -- run it (and the make check it follows) via sudo, or this phase cannot mean anything." >&2
    fail=1
else
    while IFS= read -r binary; do
        [ -z "$binary" ] && continue
        if [ ! -x "$SCRIPT_DIR/$binary" ]; then
            echo "::error title=NetBSD parity gap::$binary is required by netbsd-parity-baseline.yml's must_pass_as_root list but was not built at all (see the must_build failure above, if any)." >&2
            fail=1
            continue
        fi
        output=$("$SCRIPT_DIR/$binary" 2>&1); rc=$?
        if [ "$rc" -eq 0 ]; then
            echo "OK: $binary PASSed under real root."
        elif [ "$rc" -eq 77 ]; then
            echo "::error title=Root-gated coverage still skipped::$binary reported SKIP (exit 77) even though this phase is running as root (uid 0). Its root-detection logic (CONTRIBUTING.md's 'Why some tests need root') decided it wasn't actually privileged -- check CAP_SETUID and the seteuid()/setuid() targets it needs, not just \$(id -u)." >&2
            echo "$output" | sed 's/^/  /' >&2
            fail=1
        else
            echo "::error title=Real test failure::$binary exited $rc under real root (neither PASS nor SKIP). Output:" >&2
            echo "$output" | sed 's/^/  /' >&2
            fail=1
        fi
    done <<< "$(list_section must_pass_as_root)"
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "NetBSD parity baseline confirmed: every tracked binary built, and every root-gated one passed under real root."
