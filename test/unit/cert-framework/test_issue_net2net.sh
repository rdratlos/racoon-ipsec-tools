#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

echo "test_issue_net2net"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"
ca_create_root
ca_create_intermediate

cert="$(ca_issue_net2net "gw1.example.test" "DNS:gw1.example.test" "IP:10.0.0.1")"

assert_success "net2net cert file exists" test -s "$cert"

certtext="$(openssl x509 -in "$cert" -noout -text)"
assert_contains "$certtext" "CN = gw1.example.test" "net2net cert subject CN matches"
assert_contains "$certtext" "TLS Web Server Authentication" "net2net cert has serverAuth EKU"
assert_contains "$certtext" "TLS Web Client Authentication" "net2net cert has clientAuth EKU"
assert_contains "$certtext" "Key Agreement" "net2net cert has keyAgreement KU"
assert_contains "$certtext" "DNS:gw1.example.test" "net2net cert has DNS SAN"
assert_contains "$certtext" "IP Address:10.0.0.1" "net2net cert has IP SAN"

issuer="$(openssl x509 -in "$cert" -noout -issuer)"
intermediate_subject_as_issuer="$(openssl x509 -in "$workdir/intermediate/certs/intermediate.cert.pem" -noout -subject | sed 's/^subject=/issuer=/')"
assert_eq "$issuer" "$intermediate_subject_as_issuer" "net2net cert is signed by intermediate"

enddate="$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
end_epoch="$(date -d "$enddate" +%s)"
now_epoch="$(date +%s)"
days=$(((end_epoch - now_epoch) / 86400))
assert_success "net2net cert validity is ~1 year" bash -c "[ $days -gt 360 ] && [ $days -le 366 ]"

test_summary
exit $?
