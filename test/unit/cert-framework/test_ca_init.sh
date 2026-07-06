#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./test_helper.sh

echo "test_ca_init"

workdir="$(mktempdir)"
trap 'rm -rf "$workdir"' EXIT

ca_init "$workdir"

for d in root/private root/certs root/newcerts root/crl \
	intermediate/private intermediate/certs intermediate/csr intermediate/newcerts intermediate/crl \
	certs csr private; do
	assert_success "directory $d exists" test -d "$workdir/$d"
done

assert_eq "1000" "$(cat "$workdir/root/serial")" "root serial starts at 1000"
assert_eq "1000" "$(cat "$workdir/intermediate/serial")" "intermediate serial starts at 1000"

assert_success "root index.txt exists" test -f "$workdir/root/index.txt"
assert_success "intermediate index.txt exists" test -f "$workdir/intermediate/index.txt"

assert_success "rendered openssl.cnf exists" test -f "$CA_CONF"
conf_active="$(grep -v '^[[:space:]]*#' "$CA_CONF")"
assert_not_contains "$conf_active" '$dir' 'rendered config has no $dir variable'
assert_contains "$conf_active" "$workdir" "rendered config contains absolute workdir path"

perm="$(stat -c '%a' "$workdir/root/private")"
assert_eq "700" "$perm" "root private dir is mode 700"

test_summary
exit $?
