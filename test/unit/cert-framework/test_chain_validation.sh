#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

echo "test_chain_validation"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"
ca_create_root
ca_create_intermediate

cert="$(ca_issue_net2net "chain.example.test" "DNS:chain.example.test")"
chain="$workdir/certs/chain.example.test.chain.pem"

ca_build_chain "$cert" "$chain"

assert_success "chain file exists" test -s "$chain"
count="$(grep -c 'BEGIN CERTIFICATE' "$chain")"
assert_eq "3" "$count" "chain file has 3 certificates"

first_subject="$(openssl x509 -in "$cert" -noout -subject)"
chain_first_subject="$(awk '/BEGIN CERTIFICATE/{n++} n==1' "$chain" | openssl x509 -noout -subject)"
assert_eq "$first_subject" "$chain_first_subject" "leaf cert is first in chain"

assert_success "openssl verify passes on full chain" \
	openssl verify -CAfile "$workdir/root/certs/ca.cert.pem" \
	-untrusted "$workdir/intermediate/certs/intermediate.cert.pem" "$chain"

assert_success "ca_verify_cert accepts valid cert" ca_verify_cert "$cert"

other_workdir="$(mktempdir)"
trap 'rm -rf "$workdir" "$other_workdir"' EXIT
(
	ca_init "$other_workdir"
	ca_create_root
) >/dev/null

assert_failure "cert fails verification against unrelated CA" \
	openssl verify -CAfile "$other_workdir/root/certs/ca.cert.pem" "$cert"

test_summary
exit $?
