#!/usr/bin/env bash
# test/gen-x509-fixtures.sh
#
# Populate a scratch directory with the X.509 PEM fixtures consumed by the
# C unit test test_x509_cert.c. It drives test/cert-framework/lib/ca.sh
# (issue #50) to build a real Root -> Intermediate -> End-Entity CA and
# then copies the relevant certs/keys/CRLs to canonical, slug-independent
# filenames the C test can fopen() directly.
#
# Usage: gen-x509-fixtures.sh <outdir>
#
# The C test invokes this once at start-up (see test_x509_cert.c). Written
# so it is safe to re-run into a fresh <outdir>: it never mutates the source
# tree, only the throwaway working area it creates under <outdir>.
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=cert-framework/lib/ca.sh
. "$SCRIPT_DIR/cert-framework/lib/ca.sh"

outdir="${1:-}"
if [ -z "$outdir" ]; then
	echo "gen-x509-fixtures.sh: <outdir> required" >&2
	exit 1
fi

mkdir -p "$outdir" || exit 1
outdir="$(cd "$outdir" && pwd)" || exit 1

# Keep openssl's issuance chatter off the test console: everything from here
# on lands in gen.log inside the fixture dir. The C test (test_x509_cert.c)
# dumps this log to stderr only if generation fails.
exec >"$outdir/gen.log" 2>&1

# CA working tree lives under the fixture dir; the flat canonical files the
# C test reads live directly in $outdir.
ca_workdir="$outdir/ca"
capath="$outdir/capath"
mkdir -p "$capath" || exit 1

die() { echo "gen-x509-fixtures.sh: $*" >&2; exit 1; }

ca_init "$ca_workdir"           || die "ca_init failed"
ca_create_root                  || die "ca_create_root failed"
ca_create_intermediate          || die "ca_create_intermediate failed"

# End-entity roadwarrior with a rich SAN set: DNS, email, IPv4 and IPv6.
# Exercises every branch of eay_get_x509subjectaltname() reachable from a
# well-formed cert (GEN_DNS / GEN_EMAIL / GEN_IPADD v4 / GEN_IPADD v6).
rw_cert="$(ca_issue_roadwarrior "rw.example.test" \
	"DNS:rw.example.test" \
	"email:rw@example.test" \
	"IP:192.0.2.10" \
	"IP:2001:db8::1")" || die "ca_issue_roadwarrior failed"

# A generic server cert with NO subjectAltName -- drives the "no SAN
# extension present" path of eay_get_x509subjectaltname().
srv_cert="$(ca_issue_server "server-no-san.example.test")" \
	|| die "ca_issue_server failed"

# A net2net cert we will revoke, for the CRL / revocation failure path.
rev_cert="$(ca_issue_net2net "revoked.example.test" "DNS:revoked.example.test")" \
	|| die "ca_issue_net2net failed"

# Locate the roadwarrior's unencrypted private key (end-entity keys are
# issued without a passphrase by cert-framework). The slug rule mirrors
# lib/ca.sh:_ca_slug().
rw_key="$ca_workdir/private/rw-example-test.key.pem"
[ -f "$rw_key" ] || die "roadwarrior key not found at $rw_key"

# Revoke, then (re)generate both CRLs so the assembled CA store satisfies
# eay_check_x509cert()'s X509_V_FLAG_CRL_CHECK_ALL for the whole chain.
ca_revoke_cert "$rev_cert"      || die "ca_revoke_cert failed"
ca_generate_root_crl            || die "ca_generate_root_crl failed"
# ca_revoke_cert already refreshed the intermediate CRL; make it explicit so
# the ordering does not depend on that side effect.
ca_generate_intermediate_crl    || die "ca_generate_intermediate_crl failed"

root_cert="$ca_workdir/root/certs/ca.cert.pem"
int_cert="$ca_workdir/intermediate/certs/intermediate.cert.pem"
root_crl="$ca_workdir/root/crl/ca.crl.pem"
int_crl="$ca_workdir/intermediate/crl/intermediate.crl.pem"

# Canonical fixtures for the C test.
cp "$rw_cert"   "$outdir/rw.cert.pem"          || die "cp rw cert"
cp "$rw_key"    "$outdir/rw.key.pem"           || die "cp rw key"
cp "$srv_cert"  "$outdir/server-no-san.cert.pem" || die "cp server cert"
cp "$rev_cert"  "$outdir/revoked.cert.pem"     || die "cp revoked cert"
cp "$root_cert" "$outdir/root.cert.pem"        || die "cp root cert"
cp "$int_cert"  "$outdir/intermediate.cert.pem" || die "cp intermediate cert"

# CA store for eay_check_x509cert(): the two CA certs plus both CRLs in a
# single PEM file loaded via X509_LOOKUP_load_file(FILETYPE_PEM), which
# ingests X509 and X509_CRL objects alike.
cat "$root_cert" "$int_cert" "$root_crl" "$int_crl" \
	> "$outdir/ca-bundle.pem" || die "assemble ca-bundle"

# An unrelated self-signed CA: verifying the roadwarrior cert against this
# store must fail (issuer not found) -- the "wrong CA" negative path.
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
	-subj "/C=DE/O=Unrelated Test Authority/CN=Unrelated Root CA" \
	-keyout "$outdir/wrong-ca.key.pem" \
	-out "$outdir/wrong-ca.cert.pem" >/dev/null 2>&1 \
	|| die "wrong-ca generation failed"

# A self-signed EC (non-RSA) cert to drive eay_check_x509sign()'s
# "unsupported key type" rejection path. Best-effort: skip if this build of
# OpenSSL lacks the prime256v1 curve.
if openssl ecparam -name prime256v1 -genkey -noout \
	-out "$outdir/ec.key.pem" >/dev/null 2>&1; then
	openssl req -x509 -new -key "$outdir/ec.key.pem" -sha256 -days 3650 \
		-subj "/C=DE/O=Nepomuc SecureNet/CN=ec.example.test" \
		-out "$outdir/ec.cert.pem" >/dev/null 2>&1 \
		|| die "EC cert generation failed"
fi

echo "gen-x509-fixtures.sh: fixtures written to $outdir" >&2
exit 0
