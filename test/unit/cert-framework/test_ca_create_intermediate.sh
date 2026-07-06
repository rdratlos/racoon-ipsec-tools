#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

echo "test_ca_create_intermediate"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"
ca_create_root
ca_create_intermediate

key="$workdir/intermediate/private/intermediate.key.pem"
cert="$workdir/intermediate/certs/intermediate.cert.pem"

assert_success "intermediate key file exists" test -s "$key"
assert_success "intermediate cert file exists" test -s "$cert"
assert_contains "$(head -1 "$key")" "ENCRYPTED" "intermediate key is encrypted"

keytext="$(openssl rsa -in "$key" -passin "pass:$CA_KEY_PASSWORD" -noout -text 2>&1)"
assert_contains "$keytext" "Private-Key: (2048 bit" "intermediate key is RSA 2048"

certtext="$(openssl x509 -in "$cert" -noout -text)"
assert_contains "$certtext" "CA:TRUE" "intermediate cert is a CA"
assert_contains "$certtext" "pathlen:0" "intermediate cert has pathlen:0"
assert_contains "$certtext" "CN = Nepomuc SecureNet Intermediate CA" "intermediate cert subject CN matches"

issuer="$(openssl x509 -in "$cert" -noout -issuer)"
root_subject_as_issuer="$(openssl x509 -in "$workdir/root/certs/ca.cert.pem" -noout -subject | sed 's/^subject=/issuer=/')"
assert_eq "$issuer" "$root_subject_as_issuer" "intermediate cert is signed by root"

assert_success "intermediate cert verifies against root" \
	openssl verify -CAfile "$workdir/root/certs/ca.cert.pem" "$cert"

enddate="$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
end_epoch="$(date -d "$enddate" +%s)"
now_epoch="$(date +%s)"
days=$(((end_epoch - now_epoch) / 86400))
assert_success "intermediate cert validity is ~5 years" bash -c "[ $days -gt 1815 ] && [ $days -le 1830 ]"

test_summary
exit $?
