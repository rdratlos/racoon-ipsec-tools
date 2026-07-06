#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

echo "test_ca_issue_server"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"
ca_create_root
ca_create_intermediate

cert="$(ca_issue_server "ocsp.example.test" "DNS:ocsp.example.test")"

assert_success "server cert file exists" test -s "$cert"

certtext="$(openssl x509 -in "$cert" -noout -text)"
assert_contains "$certtext" "TLS Web Server Authentication" "server cert has serverAuth EKU"
assert_not_contains "$certtext" "TLS Web Client Authentication" "server cert has no clientAuth EKU"
assert_not_contains "$certtext" "Key Agreement" "server cert has no keyAgreement KU"
assert_contains "$certtext" "DNS:ocsp.example.test" "server cert has DNS SAN"

test_summary
exit $?
