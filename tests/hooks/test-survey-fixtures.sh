#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# test-survey-fixtures.sh - fixture-driven tests for the §7 resolv.conf
# landscape survey. Each subdirectory of fixtures/ is a throwaway
# filesystem tree (root/) plus stub external commands (bin/) standing in
# for a real system, and an expected.sh declaring what the survey should
# conclude about it. Run directly: sh tests/hooks/test-survey-fixtures.sh
#
# Fixture 02 (Bionic) deliberately ships no resolvectl/busctl stub to
# match the real system it models; because rhook_nm_dbus_prop() gates on
# `systemctl is-active NetworkManager` (stubbed inactive in every fixture
# that doesn't need NetworkManager) before ever touching busctl, this is
# inert for the assertions made here. Capability-matrix tests (§6) are
# where "resolvectl/busctl genuinely absent from PATH" is exercised under
# a properly sandboxed PATH; this file only cares about the file-based
# survey and the NM D-Bus probe.

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LIB="$SCRIPT_DIR/../../src/scripts/racoon-hook-lib.sh"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

TESTS_RUN=0
TESTS_FAILED=0

fail() {
	TESTS_FAILED=$((TESTS_FAILED + 1))
	echo "FAIL: $1"
}

# Runs one fixture in a subshell so PATH/env/cwd changes never leak
# between fixtures. Prints "FIXTURE_OK:<name>" or
# "FIXTURE_FAIL:<name>:<details>" on stdout; the caller decides pass/fail.
run_fixture() {
	fixture_dir="$1"
	name=$(basename "$fixture_dir")
	(
		RACOON_HOOK_FS_ROOT="$fixture_dir/root"
		PATH="$fixture_dir/bin:$PATH"
		RACOON_HOOK_STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/racoon-hook-fixture.XXXXXX")
		export RACOON_HOOK_FS_ROOT PATH RACOON_HOOK_STATE_DIR
		trap 'rm -rf "$RACOON_HOOK_STATE_DIR"' EXIT

		# shellcheck source=/dev/null
		. "$LIB"
		# shellcheck source=/dev/null
		. "$fixture_dir/expected.sh"

		survey_file=$(rhook_survey_build)
		errors=""

		glibc_reader=$(rhook_survey_glibc_reader)
		case "$glibc_reader" in
			*"$EXPECT_GLIBC_READER_SUFFIX") ;;
			*) errors="$errors|glibc_reader: got '$glibc_reader', expected suffix '$EXPECT_GLIBC_READER_SUFFIX'" ;;
		esac

		if rhook_survey_nss_uses_resolve; then nss=yes; else nss=no; fi
		[ "$nss" = "$EXPECT_NSS_RESOLVE" ] || errors="$errors|nss_uses_resolve: got '$nss', expected '$EXPECT_NSS_RESOLVE'"

		if [ "$(rhook_survey_divergent "$survey_file")" = "DIVERGENT" ]; then div=yes; else div=no; fi
		[ "$div" = "$EXPECT_DIVERGENT" ] || errors="$errors|divergent: got '$div', expected '$EXPECT_DIVERGENT'"

		if [ "$(rhook_survey_parallel_unlinked "$survey_file")" = "PARALLEL_UNLINKED" ]; then par=yes; else par=no; fi
		[ "$par" = "$EXPECT_PARALLEL_UNLINKED" ] || errors="$errors|parallel_unlinked: got '$par', expected '$EXPECT_PARALLEL_UNLINKED'"

		if [ -n "${EXPECT_NM_RCMANAGER:-}" ]; then
			rc=$(rhook_nm_dbus_prop RcManager)
			[ "$rc" = "$EXPECT_NM_RCMANAGER" ] || errors="$errors|nm_rcmanager: got '$rc', expected '$EXPECT_NM_RCMANAGER'"
		fi
		if [ -n "${EXPECT_NM_MODE:-}" ]; then
			m=$(rhook_nm_dbus_prop Mode)
			[ "$m" = "$EXPECT_NM_MODE" ] || errors="$errors|nm_mode: got '$m', expected '$EXPECT_NM_MODE'"
		fi

		if [ -n "$errors" ]; then
			printf 'FIXTURE_FAIL:%s:%s\n' "$name" "$errors"
		else
			printf 'FIXTURE_OK:%s\n' "$name"
		fi
	)
}

for fixture_dir in "$FIXTURES_DIR"/*/; do
	TESTS_RUN=$((TESTS_RUN + 1))
	out=$(run_fixture "$fixture_dir")
	case "$out" in
		FIXTURE_OK:*)
			echo "ok: ${out#FIXTURE_OK:}"
			;;
		FIXTURE_FAIL:*)
			body="${out#FIXTURE_FAIL:}"
			fixname="${body%%:*}"
			details="${body#*:}"
			old_ifs="$IFS"
			IFS='|'
			fail_msg="$fixname"
			for d in $details; do
				[ -n "$d" ] && fail_msg="$fail_msg
    $d"
			done
			IFS="$old_ifs"
			fail "$fail_msg"
			;;
		*)
			fail "$fixture_dir -- unexpected test driver output: $out"
			;;
	esac
done

echo ""
echo "$TESTS_RUN fixtures run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
