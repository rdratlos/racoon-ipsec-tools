#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

echo "test_openssl_compat"
echo "  running against: $(openssl version)"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"

conftext="$(grep -v '^[[:space:]]*#' "$CA_CONF")"
assert_not_contains "$conftext" '@@CA_DIR@@' "rendered config has no unresolved placeholders"
assert_not_contains "$conftext" 'RANDFILE' "rendered config does not reference RANDFILE"
assert_contains "$conftext" 'default_md' "rendered config sets default_md explicitly"
assert_not_contains "$conftext" 'engine' "rendered config does not pin a legacy engine"

ca_create_root
ca_create_intermediate
cert="$(ca_issue_net2net "compat.example.test" "DNS:compat.example.test")"

assert_success "issued cert is well-formed (no deprecated defaults tripped)" \
	openssl x509 -in "$cert" -noout -sha256 -fingerprint

sigalg="$(openssl x509 -in "$cert" -noout -text | grep 'Signature Algorithm' | head -1)"
assert_contains "$sigalg" "sha256" "issued cert is signed with SHA-256"

test_summary
exit $?
