#!/usr/bin/env bash
# test/unit/cert-framework/test_helper.sh
#
# Shared assertion helpers + lib/ca.sh sourcing for cert-framework unit
# tests. Each test_*.sh sources this file, exercises the CA API against
# a throwaway workdir, and calls test_summary at the end.

CERT_FRAMEWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../cert-framework" && pwd)"
# shellcheck source=/dev/null
source "$CERT_FRAMEWORK_DIR/lib/ca.sh"

_TEST_PASS=0
_TEST_FAIL=0

pass() {
	echo "  ok - $1"
	_TEST_PASS=$((_TEST_PASS + 1))
}

fail() {
	echo "  not ok - $1"
	_TEST_FAIL=$((_TEST_FAIL + 1))
}

assert_eq() {
	local expected="$1" actual="$2" desc="$3"
	if [ "$expected" = "$actual" ]; then
		pass "$desc"
	else
		fail "$desc (expected '$expected', got '$actual')"
	fi
}

assert_contains() {
	local haystack="$1" needle="$2" desc="$3"
	if [[ "$haystack" == *"$needle"* ]]; then
		pass "$desc"
	else
		fail "$desc (expected to find '$needle')"
	fi
}

assert_not_contains() {
	local haystack="$1" needle="$2" desc="$3"
	if [[ "$haystack" != *"$needle"* ]]; then
		pass "$desc"
	else
		fail "$desc (did not expect to find '$needle')"
	fi
}

assert_success() {
	local desc="$1"
	shift
	if "$@" >/dev/null 2>&1; then
		pass "$desc"
	else
		fail "$desc (command failed: $*)"
	fi
}

assert_failure() {
	local desc="$1"
	shift
	if ! "$@" >/dev/null 2>&1; then
		pass "$desc"
	else
		fail "$desc (command unexpectedly succeeded: $*)"
	fi
}

test_summary() {
	echo
	echo "  $_TEST_PASS passed, $_TEST_FAIL failed"
	[ "$_TEST_FAIL" -eq 0 ]
}

mktempdir() {
	mktemp -d "${TMPDIR:-/tmp}/cert-framework-test.XXXXXX"
}

# cert_dn_field <cert_path> <subject|issuer> <field>
#
# Extracts a single DN attribute (e.g. commonName, organizationName) via
# openssl's "multiline" nameopt, which spells out full attribute names one
# per line and has stayed stable across OpenSSL 1.1.x-3.6.x. Plain
# "-subject"/"-issuer" (and -text's Subject/Issuer line) use whatever
# nameopt is the current version's default, which has changed between
# OpenSSL releases (e.g. RDN order/spacing), so tests must not assert on
# that literal string.
cert_dn_field() {
	local cert="$1" which="$2" field="$3"
	openssl x509 -in "$cert" -noout "-$which" -nameopt multiline,utf8 \
		| sed -n "s/^ *${field} *= *//p" | head -1
}
