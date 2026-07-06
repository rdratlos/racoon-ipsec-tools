#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

echo "test_ca_create_root"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"
ca_create_root

key="$workdir/root/private/ca.key.pem"
cert="$workdir/root/certs/ca.cert.pem"

assert_success "root key file exists" test -s "$key"
assert_success "root cert file exists" test -s "$cert"

assert_contains "$(head -1 "$key")" "ENCRYPTED" "root key is encrypted"

keytext="$(openssl rsa -in "$key" -passin "pass:$CA_KEY_PASSWORD" -noout -text 2>&1)"
assert_contains "$keytext" "Private-Key: (4096 bit" "root key is RSA 4096"

certtext="$(openssl x509 -in "$cert" -noout -text)"
assert_contains "$certtext" "CA:TRUE" "root cert is a CA"
assert_contains "$certtext" "Certificate Sign" "root cert has keyCertSign"
assert_contains "$certtext" "CRL Sign" "root cert has cRLSign"
cn="$(cert_dn_field "$cert" subject commonName)"
assert_eq "Nepomuc SecureNet Root CA" "$cn" "root cert subject CN matches"
o="$(cert_dn_field "$cert" subject organizationName)"
assert_eq "Nepomuc SecureNet" "$o" "root cert subject O matches"

subject="$(openssl x509 -in "$cert" -noout -subject)"
issuer_as_subject="$(openssl x509 -in "$cert" -noout -issuer | sed 's/^issuer=/subject=/')"
assert_eq "$subject" "$issuer_as_subject" "root cert is self-signed"

enddate="$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
end_epoch="$(date -d "$enddate" +%s)"
now_epoch="$(date +%s)"
days=$(((end_epoch - now_epoch) / 86400))
assert_success "root cert validity is ~10 years" bash -c "[ $days -gt 3640 ] && [ $days -le 3660 ]"

test_summary
exit $?
