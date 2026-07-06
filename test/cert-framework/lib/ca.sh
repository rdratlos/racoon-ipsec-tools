#!/usr/bin/env bash
# test/cert-framework/lib/ca.sh
#
# Bash API driving the Root -> Intermediate -> End-Entity test CA defined
# in ../openssl.cnf. Intended to be sourced, not executed: it does not
# set -e/-u/pipefail itself (that would mutate the sourcing shell's
# options), so callers should check function return codes or set their
# own shell options.
#
# Public API:
#   ca_init <workdir>
#   ca_create_root
#   ca_create_intermediate
#   ca_issue_cert <profile> <cn> [san...]
#   ca_issue_net2net <cn> [san...]
#   ca_issue_roadwarrior <cn> [san...]
#   ca_issue_server <cn> [san...]
#   ca_build_chain <cert_path> <out_chain_path>
#   ca_verify_cert <cert_path>
#   ca_revoke_cert <cert_path> [reason]
#
# Every function prior to ca_init fails; state (CA_DIR, CA_CONF) is
# global to the sourcing shell, mirroring a single CA instance per
# process/test script.

CA_KEY_PASSWORD="${CA_KEY_PASSWORD:-racoon-test-passphrase}"

CA_DIR=""
CA_CONF=""

# openssl expands every "$ENV::VAR" reference while parsing the whole
# config file, even in sections no invocation actually selects (e.g.
# root/intermediate creation never touches [v3_req_san]). An unset SAN
# aborts parsing entirely ("variable has no value"), so keep it defined
# (possibly empty) for every openssl invocation; ca_issue_cert overrides
# it locally only for the CSR calls that carry SANs.
export SAN="${SAN:-}"

_ca_lib_dir() {
	cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
}

_ca_require_init() {
	if [ -z "$CA_DIR" ] || [ -z "$CA_CONF" ]; then
		echo "ca.sh: ca_init must be called before using the CA API" >&2
		return 1
	fi
}

_ca_slug() {
	printf '%s' "$1" | tr '[:upper:] ' '[:lower:]-' | tr -cs 'a-z0-9-' '-' | sed 's/^-*//;s/-*$//'
}

ca_init() {
	local workdir="$1"
	if [ -z "$workdir" ]; then
		echo "ca_init: workdir required" >&2
		return 1
	fi

	mkdir -p "$workdir" || return 1
	workdir="$(cd "$workdir" && pwd)" || return 1

	mkdir -p "$workdir/root"/{private,certs,newcerts,crl} || return 1
	mkdir -p "$workdir/intermediate"/{private,certs,csr,newcerts,crl} || return 1
	mkdir -p "$workdir"/{certs,csr,private} || return 1
	chmod 700 "$workdir/root/private" "$workdir/intermediate/private" || return 1

	local ca
	for ca in root intermediate; do
		: > "$workdir/$ca/index.txt"
		echo "unique_subject = no" > "$workdir/$ca/index.txt.attr"
		echo 1000 > "$workdir/$ca/serial"
		echo 1000 > "$workdir/$ca/crlnumber"
	done

	local template="$(_ca_lib_dir)/../openssl.cnf"
	sed "s#@@CA_DIR@@#$workdir#g" "$template" > "$workdir/openssl.cnf" || return 1

	CA_DIR="$workdir"
	CA_CONF="$workdir/openssl.cnf"
}

ca_create_root() {
	_ca_require_init || return 1

	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
		-aes256 -pass "pass:$CA_KEY_PASSWORD" \
		-out "$CA_DIR/root/private/ca.key.pem" || return 1
	chmod 400 "$CA_DIR/root/private/ca.key.pem"

	openssl req -config "$CA_CONF" -new -x509 \
		-key "$CA_DIR/root/private/ca.key.pem" -passin "pass:$CA_KEY_PASSWORD" \
		-days 3650 -sha256 -extensions v3_ca_root \
		-subj "/C=DE/ST=Baden-Wuerttemberg/L=Ulm/O=Nepomuc SecureNet/OU=Racoon IpSec Tools Testing/CN=Nepomuc SecureNet Root CA" \
		-out "$CA_DIR/root/certs/ca.cert.pem" || return 1
}

ca_create_intermediate() {
	_ca_require_init || return 1

	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
		-aes256 -pass "pass:$CA_KEY_PASSWORD" \
		-out "$CA_DIR/intermediate/private/intermediate.key.pem" || return 1
	chmod 400 "$CA_DIR/intermediate/private/intermediate.key.pem"

	openssl req -config "$CA_CONF" -new \
		-key "$CA_DIR/intermediate/private/intermediate.key.pem" -passin "pass:$CA_KEY_PASSWORD" \
		-subj "/C=DE/ST=Baden-Wuerttemberg/L=Ulm/O=Nepomuc SecureNet/OU=Racoon IpSec Tools Testing/CN=Nepomuc SecureNet Intermediate CA" \
		-out "$CA_DIR/intermediate/csr/intermediate.csr.pem" || return 1

	openssl ca -batch -config "$CA_CONF" -name CA_root \
		-extensions v3_ca_intermediate -days 1825 -notext -md sha256 \
		-passin "pass:$CA_KEY_PASSWORD" \
		-in "$CA_DIR/intermediate/csr/intermediate.csr.pem" \
		-out "$CA_DIR/intermediate/certs/intermediate.cert.pem" || return 1
}

ca_issue_cert() {
	local profile="$1"
	local cn="$2"
	shift 2
	local sans=("$@")
	_ca_require_init || return 1

	local slug key csr cert
	slug="$(_ca_slug "$cn")"
	key="$CA_DIR/private/${slug}.key.pem"
	csr="$CA_DIR/csr/${slug}.csr.pem"
	cert="$CA_DIR/certs/${slug}.cert.pem"

	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
		-out "$key" || return 1
	chmod 400 "$key"

	local reqexts_args=()
	if [ "${#sans[@]}" -gt 0 ]; then
		local san_str
		san_str="$(printf ',%s' "${sans[@]}")"
		san_str="${san_str#,}"
		reqexts_args=(-reqexts v3_req_san)
		SAN="$san_str" openssl req -config "$CA_CONF" -new \
			-key "$key" \
			-subj "/C=DE/ST=Baden-Wuerttemberg/L=Ulm/O=Nepomuc SecureNet/OU=Racoon IpSec Tools Testing/CN=$cn" \
			"${reqexts_args[@]}" \
			-out "$csr" || return 1
	else
		openssl req -config "$CA_CONF" -new \
			-key "$key" \
			-subj "/C=DE/ST=Baden-Wuerttemberg/L=Ulm/O=Nepomuc SecureNet/OU=Racoon IpSec Tools Testing/CN=$cn" \
			-out "$csr" || return 1
	fi

	openssl ca -batch -config "$CA_CONF" -name CA_intermediate \
		-extensions "$profile" -days 365 -notext -md sha256 \
		-passin "pass:$CA_KEY_PASSWORD" \
		-in "$csr" -out "$cert" || return 1

	echo "$cert"
}

ca_issue_net2net() {
	local cn="$1"
	shift
	ca_issue_cert v3_gw_net2net "$cn" "$@"
}

ca_issue_roadwarrior() {
	local cn="$1"
	shift
	ca_issue_cert v3_client_roadwarrior "$cn" "$@"
}

ca_issue_server() {
	local cn="$1"
	shift
	ca_issue_cert v3_server_generic "$cn" "$@"
}

ca_build_chain() {
	local cert_path="$1"
	local out_chain_path="$2"
	_ca_require_init || return 1

	cat "$cert_path" \
		"$CA_DIR/intermediate/certs/intermediate.cert.pem" \
		"$CA_DIR/root/certs/ca.cert.pem" \
		> "$out_chain_path"
}

ca_verify_cert() {
	local cert_path="$1"
	_ca_require_init || return 1

	if [ -s "$CA_DIR/intermediate/crl/intermediate.crl.pem" ]; then
		openssl verify -CAfile "$CA_DIR/root/certs/ca.cert.pem" \
			-untrusted "$CA_DIR/intermediate/certs/intermediate.cert.pem" \
			-crl_check -CRLfile "$CA_DIR/intermediate/crl/intermediate.crl.pem" \
			"$cert_path" >/dev/null 2>&1
	else
		openssl verify -CAfile "$CA_DIR/root/certs/ca.cert.pem" \
			-untrusted "$CA_DIR/intermediate/certs/intermediate.cert.pem" \
			"$cert_path" >/dev/null 2>&1
	fi
}

ca_revoke_cert() {
	local cert_path="$1"
	local reason="${2:-unspecified}"
	_ca_require_init || return 1

	openssl ca -config "$CA_CONF" -name CA_intermediate \
		-passin "pass:$CA_KEY_PASSWORD" \
		-revoke "$cert_path" -crl_reason "$reason" >/dev/null 2>&1 || return 1

	openssl ca -config "$CA_CONF" -name CA_intermediate \
		-passin "pass:$CA_KEY_PASSWORD" \
		-gencrl -out "$CA_DIR/intermediate/crl/intermediate.crl.pem" >/dev/null 2>&1 || return 1
}
