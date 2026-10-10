# netns matrix

Live IPsec tests for racoon on a **real kernel**, built to run on a stock
GitHub-hosted runner with no containers or VMs. Two network namespaces, one
`racoon` per namespace, PSK main mode, ESP.

It is the lightweight tier beneath the Incus-based itlab of RFC 0001 and the
"fall back to `ip netns`" option named in the Risks table of RFC 0002. It
consumes the same installed `racoon` and `setkey` an operator would run.

## What a live row proves

Each `psk-*` row asserts, against the live kernel:

1. Both SADs hold ESP SAs and the negotiated HMAC carries the RFC truncation
   (`hmac(sha1)` 96 bits, `hmac(sha256)` 128 bits). An SA that installs with a
   wrong ICV length is accepted by the kernel and then silently drops traffic,
   so SA presence alone proves nothing.
2. Traffic really crosses ESP: ping succeeds, the ESP packet counters on both
   sides moved, and no XFRM error counter in `/proc/net/xfrm_stat` moved.
3. (`psk-rekey-sha256`) With a 30 s SA lifetime a new SPI replaces the old one
   while a long ping loses at most 10 %. This is the kernel EXPIRE to rekey
   path that an XFRM backend has to reproduce.

| Row | Mode | HMAC | Notes |
|-----|------|------|-------|
| `preflight` | n/a | n/a | Can this host run live rows? Reports the reason if not |
| `psk-transport-sha256` | transport | sha256 | ICV 128 bits |
| `psk-tunnel-sha1` | tunnel | sha1 | ICV 96 bits, LAN-to-LAN through the tunnel |
| `psk-rekey-sha256` | tunnel | sha256 | 30 s lifetime, SPI must change |

## Running it

```sh
# build and install racoon and setkey as usual, then:
sudo env RNM_REQUIRE_LIVE=1 sh test/netns-matrix/run.sh --min-pass 4

# one row, or a regex:
sudo sh test/netns-matrix/run.sh --cases '^psk-tunnel'

# against binaries that are not on PATH:
sudo env RACOON_BIN=/path/to/racoon SETKEY_BIN=/path/to/setkey sh test/netns-matrix/run.sh
```

The host needs root, `iproute2`, `ping`, and a kernel with PF_KEY (`af_key`)
and ESP (`esp4`). `preflight` checks all of it and says what is missing.
Per-row logs, configs, SADs and `xfrm_stat` dumps are kept in `RNM_OUT`
(default `/tmp/rnm-logs`).

## Result model

* Each row ends **PASS**, **FAIL** or **SKIP**.
* `RNM_REQUIRE_LIVE=1` (set in CI) turns a SKIP of a live row into a FAIL, so
  a runner without PF_KEY or ESP cannot go green by skipping.
* `--min-pass N` fails the run when fewer than N rows passed.
* An empty selection, or an invalid or empty `--shard K M`, is an error.

## Harness self-test

`sh test/netns-matrix/selftest.sh` needs no root and no kernel IPsec support.
It checks the parsers against canned `ip xfrm state` output (including the
96-bit ICV failure), the config and policy generators, and the runner guards.
CI runs it first.

## Adding a row

Add a line to `cases.tsv` (empty columns are written `-`, because `read(1)`
collapses tabs). Reuse an existing kind, or add `kind_<name>` in
`kinds/<name>.sh`. A kind records problems with `fail MSG` and declares an
unrunnable row with `skip REASON`. Put any new parser in `lib.sh` and cover it
in `selftest.sh`.

## Known limits

* **One kernel**: whatever the runner has. Cross-kernel behaviour needs the VM
  tier of RFC 0001.
* **PF_KEY only today.** The rows drive racoon through its current PF_KEY
  backend. Once the kernelpaws XFRM backend of RFC 0002 exists, the same rows
  should run unchanged against it; that is the point of asserting on kernel
  state and traffic rather than on racoon's logs.
* The tunnel rows deliver to a local address in the peer namespace, so they do
  not exercise forwarded (`fwd`) policies.
* IKEv1 PSK main mode only. Aggressive mode, certificates, NAT-T and DPD are
  not covered yet.

## Credits

The idea of a table-driven, sharded, netns-based live matrix, and of asserting
exact SA content, is taken from the `samples/linux-matrix` harness of
`derekm/racoon2` (see issue #145). No code was copied; this harness is written
from scratch for racoon's IKEv1 and `setkey` workflow.
