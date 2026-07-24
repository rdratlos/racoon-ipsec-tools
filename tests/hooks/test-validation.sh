#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# test-validation.sh - regression tests for racoon-hook-lib.sh's §4 input
# validators, including the injection vectors named in the implementation
# brief. Run directly: sh tests/hooks/test-validation.sh

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LIB="$SCRIPT_DIR/../../src/racoon/scripts/racoon-hook-lib.sh"

TESTS_RUN=0
TESTS_FAILED=0

fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "FAIL: $1"; }
pass() { : ; }

assert_valid() {
	# $1 = description  $2 = validator fn  $3 = input
	TESTS_RUN=$((TESTS_RUN + 1))
	if "$2" "$3"; then
		pass
	else
		fail "$1 -- expected '$3' to PASS $2, but it was rejected"
	fi
}

assert_invalid() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if "$2" "$3"; then
		fail "$1 -- expected '$3' to be REJECTED by $2, but it passed"
	else
		pass
	fi
}

# Capturing via `out=$(fn ...)` runs the validator in a subshell, so a
# plain-assignment side effect like RHOOK_VALIDATION_REASON never makes it
# back to the caller. Redirect stdout to a file instead so the function
# runs in *this* shell and its variable assignments are visible after it
# returns.
RHOOK_TEST_STDOUT="${TMPDIR:-/tmp}/racoon-hook-test-validation-stdout.$$"
trap 'rm -f "$RHOOK_TEST_STDOUT"' EXIT

assert_list_valid() {
	# $1 = description  $2 = validator fn  $3 = list
	local out
	TESTS_RUN=$((TESTS_RUN + 1))
	RHOOK_VALIDATION_REASON=""
	if "$2" "$3" > "$RHOOK_TEST_STDOUT"; then
		out=$(cat "$RHOOK_TEST_STDOUT")
		if [ "$out" = "$3" ]; then
			pass
		else
			fail "$1 -- validator rewrote the input (got '$out', expected verbatim '$3')"
		fi
	else
		fail "$1 -- expected list '$3' to PASS $2, but it was rejected (reason: $RHOOK_VALIDATION_REASON)"
	fi
}

assert_list_invalid() {
	# $1 = description  $2 = validator fn  $3 = list
	local out
	TESTS_RUN=$((TESTS_RUN + 1))
	RHOOK_VALIDATION_REASON=""
	if "$2" "$3" > "$RHOOK_TEST_STDOUT"; then
		out=$(cat "$RHOOK_TEST_STDOUT")
		fail "$1 -- expected list '$3' to be REJECTED by $2, but it passed with output '$out'"
	else
		out=$(cat "$RHOOK_TEST_STDOUT")
		if [ -n "$out" ]; then
			fail "$1 -- rejected list must print nothing on stdout, got '$out'"
		elif [ -z "$RHOOK_VALIDATION_REASON" ]; then
			fail "$1 -- rejected list must set RHOOK_VALIDATION_REASON"
		else
			pass
		fi
	fi
}

# shellcheck source=SCRIPTDIR/../../src/racoon/scripts/racoon-hook-lib.sh
. "$LIB"

# ==========================================================================
# rhook_valid_ipv4
# ==========================================================================
assert_valid   "plain address"                rhook_valid_ipv4 "10.0.12.44"
assert_valid   "all-zero octet"                rhook_valid_ipv4 "0.0.0.0"
assert_valid   "max octet value"               rhook_valid_ipv4 "255.255.255.255"
assert_invalid "non-numeric octet"             rhook_valid_ipv4 "10.0.12.abc"
assert_invalid "octet out of range"            rhook_valid_ipv4 "10.0.12.256"
assert_invalid "too few octets"                rhook_valid_ipv4 "10.0.12"
assert_invalid "too many octets"               rhook_valid_ipv4 "10.0.12.44.1"
assert_invalid "leading zero (octal ambiguity)" rhook_valid_ipv4 "010.0.12.44"
assert_invalid "empty string"                  rhook_valid_ipv4 ""
assert_invalid "trailing dot"                  rhook_valid_ipv4 "10.0.12.44."
assert_invalid "double dot"                    rhook_valid_ipv4 "10.0..44"
assert_invalid "letters entirely"              rhook_valid_ipv4 "not.an.ip.addr"
assert_invalid "embedded semicolon"            rhook_valid_ipv4 "10.0.12.44;rm -rf /"
assert_invalid "embedded space"                rhook_valid_ipv4 "10.0.12.44 rm"

# ==========================================================================
# rhook_valid_cidr4 -- including the brief's named injection vector
# ==========================================================================
assert_valid   "bare address, no prefix"       rhook_valid_cidr4 "10.0.12.0"
assert_valid   "/24 network"                   rhook_valid_cidr4 "10.0.12.0/24"
assert_valid   "/0 default"                    rhook_valid_cidr4 "0.0.0.0/0"
assert_valid   "/32 host route"                rhook_valid_cidr4 "10.0.12.44/32"
assert_invalid "prefix out of range (33)"      rhook_valid_cidr4 "10.0.12.0/33"
assert_invalid "prefix with leading zero"      rhook_valid_cidr4 "10.0.12.0/024"
assert_invalid "double slash"                  rhook_valid_cidr4 "10.0.12.0/24/8"
assert_invalid "route argument injection"      rhook_valid_cidr4 "default via 10.6.6.6"
assert_invalid "route injection, no spaces"    rhook_valid_cidr4 "10.0.12.0/24;ip route add default via 10.6.6.6"

# ==========================================================================
# rhook_cidr_overlaps -- PR #91 review row 29b (comment 5061097437)
# ==========================================================================
assert_cidr_overlap() {
	# $1 = description  $2 = cidr1  $3 = cidr2
	TESTS_RUN=$((TESTS_RUN + 1))
	if rhook_cidr_overlaps "$2" "$3"; then
		pass
	else
		fail "$1 -- expected '$2' and '$3' to overlap, but they did not"
	fi
}

assert_cidr_disjoint() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if rhook_cidr_overlaps "$2" "$3"; then
		fail "$1 -- expected '$2' and '$3' to be disjoint, but they overlapped"
	else
		pass
	fi
}

assert_cidr_overlap   "one CIDR contains the other" "192.168.1.0/24" "192.168.1.128/25"
assert_cidr_disjoint  "same-size, different networks" "192.168.1.0/24" "192.168.2.0/24"
assert_cidr_overlap   "large range containing a host route" "10.0.0.0/8" "10.66.0.6/32"
assert_cidr_overlap   "0.0.0.0/0 overlaps everything" "0.0.0.0/0" "203.0.113.0/24"
assert_cidr_disjoint  "adjacent, non-overlapping halves" "203.0.113.0/25" "203.0.113.128/25"
assert_cidr_overlap   "identical CIDR" "198.51.100.0/24" "198.51.100.0/24"
assert_cidr_overlap   "large range containing another /32" "172.16.0.0/12" "172.31.255.255/32"
assert_cidr_disjoint  "just outside a large range" "172.16.0.0/12" "172.32.0.0/16"

# ==========================================================================
# rhook_valid_domain
# ==========================================================================
assert_valid   "simple domain"                 rhook_valid_domain "example.com"
assert_valid   "subdomain"                     rhook_valid_domain "corp.example.internal"
assert_valid   "hyphenated label"              rhook_valid_domain "my-corp.example.com"
assert_invalid "leading hyphen"                rhook_valid_domain "-example.com"
assert_invalid "trailing hyphen"               rhook_valid_domain "example-.com"
assert_invalid "empty label (double dot)"      rhook_valid_domain "example..com"
assert_invalid "leading dot"                   rhook_valid_domain ".example.com"
assert_invalid "trailing dot"                  rhook_valid_domain "example.com."
assert_invalid "embedded semicolon"            rhook_valid_domain "example.com;rm -rf /"
assert_invalid "embedded space"                rhook_valid_domain "example.com rm -rf /"
assert_invalid "empty string"                  rhook_valid_domain ""

# over-long label (64 bytes, one over the RFC1035/§4 limit)
long_label=$(printf 'a%.0s' $(seq 1 64))
assert_invalid "label over 63 bytes" rhook_valid_domain "${long_label}.example.com"

# over-long total (over 253 bytes): 4x 63-byte labels + dots = 255 bytes
label63=$(printf 'a%.0s' $(seq 1 63))
long_domain="${label63}.${label63}.${label63}.${label63}"
assert_invalid "total over 253 bytes" rhook_valid_domain "$long_domain"

# ==========================================================================
# rhook_valid_port
# ==========================================================================
assert_valid   "port 1"                        rhook_valid_port "1"
assert_valid   "port 65535"                     rhook_valid_port "65535"
assert_invalid "port 0"                        rhook_valid_port "0"
assert_invalid "port over 65535"               rhook_valid_port "65536"
assert_invalid "non-numeric port"              rhook_valid_port "500;rm"
assert_invalid "empty port"                    rhook_valid_port ""

# ==========================================================================
# rhook_validate_dns_list -- element-level rejects, reject-not-sanitize,
# count cap, and the brief's newline/semicolon vectors
# ==========================================================================
assert_list_valid   "two valid DNS servers"     rhook_validate_dns_list "10.0.12.53 10.0.12.54"
assert_list_invalid "0.0.0.0 rejected"          rhook_validate_dns_list "10.0.12.53 0.0.0.0"
assert_list_invalid "loopback rejected"         rhook_validate_dns_list "127.0.0.1"
assert_list_invalid "multicast low rejected"    rhook_validate_dns_list "224.0.0.1"
assert_list_invalid "multicast high rejected"   rhook_validate_dns_list "239.255.255.255"
assert_list_valid   "just below multicast ok"   rhook_validate_dns_list "223.255.255.255"

# PR #91 review row 29a (comment 5061097437): 0.0.0.0/8 (not just the one
# address), link-local, and reserved/Class E/broadcast are bogon ranges
# that are never a valid DNS server regardless of deployment -- added
# alongside the pre-existing 0.0.0.0/loopback/multicast checks above.
assert_list_invalid "0.0.0.0/8 (not just 0.0.0.0) rejected" rhook_validate_dns_list "0.1.2.3"
assert_list_invalid "link-local rejected"        rhook_validate_dns_list "169.254.1.1"
assert_list_invalid "reserved (Class E) rejected" rhook_validate_dns_list "240.0.0.1"
assert_list_invalid "broadcast address rejected" rhook_validate_dns_list "255.255.255.255"

# RFC1918 private ranges must remain fully, unconditionally allowed --
# they are the address family every one of this project's own
# live-tested internal DNS servers actually uses. Not a policy nuance:
# rejecting these would break the project's own primary confirmed-
# working scenario, so this must never regress.
assert_list_valid   "RFC1918 10/8 allowed"       rhook_validate_dns_list "10.66.0.6"
assert_list_valid   "RFC1918 172.16/12 allowed"  rhook_validate_dns_list "172.16.0.53"
assert_list_valid   "RFC1918 192.168/16 allowed" rhook_validate_dns_list "192.168.1.53"

# semicolon vector: not IFS, stays attached to a token, fails char whitelist
assert_list_invalid "semicolon injection vector" rhook_validate_dns_list "10.0.12.53;rm -rf /"

# newline vector: newline IS in IFS, so it splits the value into extra
# tokens rather than being examined as a character within one -- the whole
# list must still be rejected because the resulting extra token(s) fail
# validation (here, the literal text after the newline is not an IPv4
# address), which is what actually defeats this vector: the loop rejects
# on the *first* bad token regardless of why the split happened.
dns_with_newline=$(printf '10.0.12.53\nrm -rf /')
assert_list_invalid "newline injection vector" rhook_validate_dns_list "$dns_with_newline"

# count cap: 9 addresses, one over RHOOK_MAX_DNS_SERVERS (8)
nine_servers="10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 10.0.0.6 10.0.0.7 10.0.0.8 10.0.0.9"
assert_list_invalid "more than max DNS servers" rhook_validate_dns_list "$nine_servers"
eight_servers="10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 10.0.0.6 10.0.0.7 10.0.0.8"
assert_list_valid "exactly max DNS servers ok" rhook_validate_dns_list "$eight_servers"

# ==========================================================================
# rhook_validate_domain_list -- count cap
# ==========================================================================
assert_list_valid   "two valid domains"        rhook_validate_domain_list "example.com corp.example.internal"
i=0; many_domains=""
while [ "$i" -lt 33 ]; do
	many_domains="$many_domains d$i.example.com"
	i=$((i + 1))
done
assert_list_invalid "more than max domains" rhook_validate_domain_list "$many_domains"

# ==========================================================================
# rhook_validate_cidr_list -- the brief's named injection vector end to end,
# and the count cap
# ==========================================================================
assert_list_valid   "two valid routes"         rhook_validate_cidr_list "10.0.12.0/24 192.168.66.0/24"
assert_list_invalid "route injection vector, whole list rejected" \
	rhook_validate_cidr_list "10.0.12.0/24 default via 10.6.6.6"
i=0; many_routes=""
while [ "$i" -lt 33 ]; do
	many_routes="$many_routes 10.$i.0.0/24"
	i=$((i + 1))
done
assert_list_invalid "more than max routes" rhook_validate_cidr_list "$many_routes"

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
