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
# otherName syntax round-trips through issuance, chain validation and
# openssl's text rendering the same way DNS/email/IP SANs already do.

echo "test_issue_upn_othername"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"
ca_create_root
ca_create_intermediate

upn="notebook01@vpn.nepomuc.de"
upn_san="otherName:1.3.6.1.4.1.311.20.2.3;UTF8:${upn}"

# A UPN-only device certificate.
cert="$(ca_issue_roadwarrior "notebook01" "${upn_san}")"
assert_success "UPN-only roadwarrior cert file exists" test -s "$cert"

certtext="$(openssl x509 -in "$cert" -noout -text)"
assert_contains "$certtext" "othername: UPN::${upn}" \
	"UPN-only cert's SAN decodes as an id-ms-san-upn othername"
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
assert_contains "$mixed1text" "othername: UPN::notebook01@vpn.nepomuc.de" \
	"DNS-then-UPN cert keeps its UPN SAN"

mixed2="$(ca_issue_roadwarrior "notebook03" "${upn_san}" "DNS:notebook03.vpn.nepomuc.de")"
mixed2text="$(openssl x509 -in "$mixed2" -noout -text)"
assert_contains "$mixed2text" "DNS:notebook03.vpn.nepomuc.de" \
	"UPN-then-DNS cert keeps its DNS SAN"
assert_contains "$mixed2text" "othername: UPN::notebook01@vpn.nepomuc.de" \
	"UPN-then-DNS cert keeps its UPN SAN"

test_summary
exit $?
