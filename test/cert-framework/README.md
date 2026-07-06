# Cert Framework

A reusable, ephemeral X.509 test CA for Racoon IPSec Tools tests: Root CA ->
Intermediate CA -> end-entity certificates (Net-to-Net gateways, roadwarrior
clients, generic servers). Provider-neutral, works against OpenSSL 1.1.0
through 3.x.

- `openssl.cnf` — single source of truth for DNs, policy, and certificate
  profiles (`v3_ca_root`, `v3_ca_intermediate`, `v3_gw_net2net`,
  `v3_client_roadwarrior`, `v3_server_generic`, `v3_req_san`). It is a
  template: every `@@CA_DIR@@` token is replaced with an absolute path.
- `lib/ca.sh` — Bash API driving `openssl` via the profiles above. Meant to
  be sourced, not executed.

## Quick start

```bash
source test/cert-framework/lib/ca.sh

workdir="$(mktemp -d)"
ca_init "$workdir"
ca_create_root
ca_create_intermediate

cert="$(ca_issue_net2net "gw1.example.test" "DNS:gw1.example.test" "IP:10.0.0.1")"
ca_build_chain "$cert" "$workdir/gw1.chain.pem"
ca_verify_cert "$cert"          # exit 0 == valid
ca_revoke_cert "$cert"
ca_verify_cert "$cert"          # now exit != 0

rm -rf "$workdir"
```

## Public API

| Function | Description |
| :--- | :--- |
| `ca_init <workdir>` | Creates the directory tree, `index.txt`/`serial`/`crlnumber` for both CAs, and renders the runtime `openssl.cnf`. |
| `ca_create_root` | Generates the encrypted Root CA key (RSA 4096) and self-signed cert (10y). |
| `ca_create_intermediate` | Generates the encrypted Intermediate key (RSA 2048), CSR, and has it signed by the Root (5y). |
| `ca_issue_cert <profile> <cn> [san...]` | Core issuance: RSA 2048 key + CSR + sign with the Intermediate CA (1y), under the given profile. |
| `ca_issue_net2net <cn> [san...]` | `ca_issue_cert v3_gw_net2net ...` |
| `ca_issue_roadwarrior <cn> [san...]` | `ca_issue_cert v3_client_roadwarrior ...` |
| `ca_issue_server <cn> [san...]` | `ca_issue_cert v3_server_generic ...` |
| `ca_build_chain <cert_path> <out_chain_path>` | Concatenates leaf + intermediate + root into one PEM file. |
| `ca_verify_cert <cert_path>` | `openssl verify` against the CA chain (and the intermediate's CRL, once one exists). |
| `ca_revoke_cert <cert_path> [reason]` | Revokes the cert against the Intermediate CA and regenerates its CRL. |

`CA_KEY_PASSWORD` (default `racoon-test-passphrase`) encrypts the Root and
Intermediate private keys; end-entity keys are left unencrypted for direct
use in test IKE configs.

Unit tests for every function above live in `test/unit/cert-framework/`; run
them with `bash test/unit/cert-framework/run_tests.sh`.
