#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

# Groundwork for issue #86 (GEN_OTHERNAME/MS-UPN as an attr_device
# device_id_type): before racoon's SAN-matching code
# (xauth_peer_device_id() in isakmp_xauth.c) can gain an otherName/UPN
# branch, the cert-framework test CA needs to be able to issue -- and
# openssl needs to be able to parse back -- a certificate carrying an
# otherName subjectAltName of type id-ms-san-upn (1.3.6.1.4.1.311.20.2.3,
# a UTF8String), the de-facto Windows/AD "User Principal Name" SAN.
#
# lib/ca.sh's SAN handling (ca_issue_cert -> $ENV::SAN in openssl.cnf) is a
# generic passthrough of whatever SAN string the caller supplies, so this
# needs no framework code changes -- only new coverage confirming the
# otherName syntax round-trips through issuance and chain validation the
# same way DNS/email/IP SANs already do.
#
# GENERAL_NAME_print()'s human-readable rendering of an otherName SAN --
# whether it recognizes id-ms-san-upn as "UPN" at all, and the exact
# wording if so -- is undocumented, OpenSSL-version-dependent display
# behavior, not an ASN.1 encoding fact. An earlier version of this test
# asserted on that rendered text ("othername: UPN::...") and passed on
# Ubuntu 24.04/Arch but failed on Ubuntu 25.10, where the same DER content
# apparently renders differently (or isn't recognized at all). Verify at
# the DER level instead: the OID and the UTF8String value are ASN.1
# encoding facts fixed by RFC 5280's OtherName structure and don't vary
# by OpenSSL version.

echo "test_issue_upn_othername"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"
ca_create_root
ca_create_intermediate

# DER bytes of a PEM cert, as one lowercase hex string.
der_hex() {
	openssl x509 -in "$1" -outform DER | od -An -tx1 | tr -d ' \n'
}

# DER encoding (tag+length+content) of a dotted OID, as a lowercase hex
# string. Generated through openssl's own ASN.1 template compiler rather
# than hand-transcribed, so it can't drift from whatever this machine's
# openssl actually emits.
oid_der_hex() {
	local tmp
	tmp="$(mktemp)"
	openssl asn1parse -genstr "OID:$1" -out "$tmp" -noout >/dev/null
	od -An -tx1 "$tmp" | tr -d ' \n'
	rm -f "$tmp"
}

ascii_hex() {
	printf '%s' "$1" | od -An -tx1 | tr -d ' \n'
}

upn_oid_hex="$(oid_der_hex 1.3.6.1.4.1.311.20.2.3)"

# Asserts that the certificate's DER carries an id-ms-san-upn otherName
# with exactly this UPN value: the OID's DER encoding, followed (within a
# short gap covering the [0] EXPLICIT wrapper + UTF8String tag/length) by
# the value's ASCII bytes.
assert_has_upn_san() {
	local cert="$1" upn="$2" desc="$3"
	local hex val
	hex="$(der_hex "$cert")"
	val="$(ascii_hex "$upn")"
	if printf '%s' "$hex" | grep -qE "${upn_oid_hex}.{0,24}${val}"; then
		pass "$desc"
	else
		fail "$desc (id-ms-san-upn OID/value not found together in cert DER)"
	fi
}

upn="notebook01@vpn.nepomuc.de"
upn_san="otherName:1.3.6.1.4.1.311.20.2.3;UTF8:${upn}"

# A UPN-only device certificate.
cert="$(ca_issue_roadwarrior "notebook01" "${upn_san}")"
assert_success "UPN-only roadwarrior cert file exists" test -s "$cert"

assert_has_upn_san "$cert" "$upn" \
	"UPN-only cert's DER carries the id-ms-san-upn othername"

certtext="$(openssl x509 -in "$cert" -noout -text)"
assert_contains "$certtext" "TLS Web Client Authentication" \
	"UPN-only cert still carries the roadwarrior clientAuth EKU"

# A chain built from a UPN-bearing cert must still validate: adding an
# otherName SAN must not perturb anything eay_check_x509cert() relies on.
chain="$workdir/upn-chain.pem"
ca_build_chain "$cert" "$chain"
assert_success "UPN-bearing cert's chain still verifies" ca_verify_cert "$chain"

# The realistic shape for a future attr_device device_id_type=upn cert: a
# DNS SAN (today's dnsname identity) alongside a UPN othername SAN, so a
# single certificate can support either matching strategy. Order matters
# for xauth_peer_device_id()'s pos-based scan, so exercise both orderings.
mixed1="$(ca_issue_roadwarrior "notebook02" "DNS:notebook02.vpn.nepomuc.de" "${upn_san}")"
mixed1text="$(openssl x509 -in "$mixed1" -noout -text)"
assert_contains "$mixed1text" "DNS:notebook02.vpn.nepomuc.de" \
	"DNS-then-UPN cert keeps its DNS SAN"
assert_has_upn_san "$mixed1" "$upn" \
	"DNS-then-UPN cert keeps its UPN SAN"

mixed2="$(ca_issue_roadwarrior "notebook03" "${upn_san}" "DNS:notebook03.vpn.nepomuc.de")"
mixed2text="$(openssl x509 -in "$mixed2" -noout -text)"
assert_contains "$mixed2text" "DNS:notebook03.vpn.nepomuc.de" \
	"UPN-then-DNS cert keeps its DNS SAN"
assert_has_upn_san "$mixed2" "$upn" \
	"UPN-then-DNS cert keeps its UPN SAN"

test_summary
exit $?
