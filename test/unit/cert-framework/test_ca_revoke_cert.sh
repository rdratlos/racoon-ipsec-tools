#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

echo "test_ca_revoke_cert"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"
ca_create_root
ca_create_intermediate

cert="$(ca_issue_roadwarrior "bob.example.test")"

assert_success "cert verifies before revocation" ca_verify_cert "$cert"

ca_revoke_cert "$cert" keyCompromise

assert_success "CRL file was generated" test -s "$workdir/intermediate/crl/intermediate.crl.pem"

crltext="$(openssl crl -in "$workdir/intermediate/crl/intermediate.crl.pem" -noout -text)"
serial="$(openssl x509 -in "$cert" -noout -serial | cut -d= -f2)"
assert_contains "$crltext" "$serial" "CRL lists revoked cert serial"

assert_failure "cert fails verification after revocation" ca_verify_cert "$cert"

test_summary
exit $?
