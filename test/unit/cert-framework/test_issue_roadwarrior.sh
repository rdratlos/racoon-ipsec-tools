#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

echo "test_issue_roadwarrior"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"
ca_create_root
ca_create_intermediate

cert="$(ca_issue_roadwarrior "alice@example.test" "email:alice@example.test")"

assert_success "roadwarrior cert file exists" test -s "$cert"

certtext="$(openssl x509 -in "$cert" -noout -text)"
assert_contains "$certtext" "TLS Web Client Authentication" "roadwarrior cert has clientAuth EKU"
assert_not_contains "$certtext" "TLS Web Server Authentication" "roadwarrior cert has no serverAuth EKU"
assert_contains "$certtext" "Key Agreement" "roadwarrior cert has keyAgreement KU"

test_summary
exit $?
