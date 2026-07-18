# Split-DNS/routing hooks rewrite — implementation report

Final report for the `racoon-hook-lib.sh` / `phase1-up.sh` / `phase1-down.sh` /
`racoon-dns-detect` rewrite, per the implementation brief's §12 requirement.
Covers: every `# UNVERIFIED:` marker left in the code and what would settle
it, every design question the brief left open and the choice made, the
fixture/test pass list, and where reality diverged from the brief's
assumptions.

## 1. `# UNVERIFIED:` markers

Three remain in `src/scripts/racoon-hook-lib.sh`, each already handled
defensively rather than left as a blind assumption:

1. **The exact header text of `/run/NetworkManager/resolv.conf` itself**
   (as opposed to `/etc/resolv.conf`'s copy of it), assumed identical since
   both are written by the same NetworkManager code path — line 788.
   Settled by: inspecting that file's content signature on a live
   NetworkManager system with `dns=default` (or any mode that writes it).
2. **The systemd release that introduced `resolvectl default-route`** —
   line 1036. Checked systemd's NEWS files for v240, v244 and v248
   directly; none mention it. Mitigated by feature-probing
   (`resolvectl --help | grep -q default-route`) instead of a version gate,
   so this is inert either way — but the exact introduction version is
   still unknown. Settled by: a `git blame`/tag search on systemd's own
   source tree for the commit that added the `default-route` verb to
   `resolvectl`'s option table.
3. **Whether `systemd-resolve --set-dns=`/`--set-domain=` accept multiple
   values per flag occurrence** or must be repeated once per value — line
   1037. Mitigated by always repeating the flag once per value (the
   standard `getopt_long` repeatable-option convention, and safe even if a
   single occurrence would also have accepted a space-separated list).
   Settled by: `systemd-resolve`'s own source (`systemd-resolve.c`) or man
   page from the specific pre-`resolvectl` systemd version in question.

## 2. Design questions the brief left open, and what was chosen

- **Connection identity**: racoon gives script hooks no explicit connection
  id. Used sanitized `REMOTE_ADDR-REMOTE_PORT` (`rhook_conn_id()`), matching
  the one-active-gateway-per-instance road-warrior topology the brief
  targets.
- **NM-spawned dnsmasq vs. standalone dnsmasq**: rather than writing
  directly into `/etc/NetworkManager/dnsmasq.d/`, the hook relies on
  NetworkManager's own DNS aggregation via the dummy connection profile
  when `backend=networkmanager`. Backend classification treats
  `networkmanager` and `dnsmasq` as mutually exclusive outcomes of the same
  detection pass (`rhook_survey_classify_backend`), so there is no code
  path that tries to combine the two.
- **`on_dns_failure` scope**: generalized from "DNS failures only" to "any
  required-step failure" (routes, the R7 no-routes refusal, DNS), since
  that is how it is actually consulted — once, at the end, against
  `rhook_apply_plan`'s overall return code. It governs the *hook's own
  exit status* only; racoon does not reject an established Phase 1 SA
  based on a hook's exit code, so `abort` surfaces the failure to whatever
  supervises the hook process rather than rejecting the tunnel.
- **Stale state file at `phase1-up.sh` start** (§3.4 leaves this
  explicitly to the implementer): archived under a `.stale.$$` suffix and
  logged loudly, then a fresh plan proceeds — refusing outright would
  permanently wedge a road-warrior client racoon keeps retrying against
  the same gateway.
- **R7 "no routes at all"**: implemented as a required, always-failing
  `no_routes` plan step (mirroring the `dnsmasq`-backend's no-domains
  refusal pattern) rather than a special-cased early exit — it flows
  through the same report/failure-policy machinery as every other step
  instead of being a parallel code path to keep in sync.
- **Packaging scope**: "Debian/Arch packaging notes" was read literally —
  documentation only (a new section in `debian/racoon.README.Debian`, a
  comment block in `packaging/arch/PKGBUILD`), not actual
  `debian/racoon.install`/`Makefile.am` install-rule wiring. Neither
  build integration point currently references `src/scripts/` at all, and
  validating a real change there would require building the full C
  project end to end, which this environment cannot do and which is a
  meaningfully different risk profile than the shell-script work the rest
  of this brief covers. Flagging this explicitly rather than silently
  under-delivering it.
- **`doc/admin/split-dns.html` styling**: built as a clean, self-contained,
  light/dark-aware page rather than importing `docs/admin-guide`'s exact
  branded fonts/logo assets from a different directory — the two docs are
  complementary (general admin guide vs. this subsystem's focused guide),
  not meant to be pixel-identical.
- **GitHub Actions NetBSD job**: uses `vmactions/netbsd-vm@v1` with
  `usesh`/`prepare`/`run` inputs. Confirmed these input names against the
  action's actual `action.yml` (fetched directly) rather than recalled
  from memory, since this workflow cannot be executed here to verify it
  end to end.
- **Dummy interface identity vs. the old prototype**: the rewrite puts the
  *real* Mode-Config-assigned internal address on the dummy interface
  (`racoon0` by default), not the old script's placeholder link-local
  address (`169.254.66.13/32` on an interface literally named
  `racoon-dns0`). This is a deliberate consequence of R5/R6, not an
  oversight — R6 asks for the interface name to be a config variable
  (done: `dummy_iface` in hooks.conf) in anticipation of a future real
  `ipsec0`, and R5's ARP-leak rationale only makes sense if the interface
  actually carries the real assigned address.

## 3. Test/fixture results

260 checks across 8 hand-rolled test suites, all passing under both `sh`
and `dash` (520 total assertions across both shells), `shellcheck
--severity=warning` clean on all four shipped scripts with every disable
backed by a justifying comment:

| Suite | Checks | Covers |
|---|---|---|
| `test-validation.sh` | 57 | §4 whitelist validators, named injection vectors |
| `test-survey-fixtures.sh` | 10 fixtures | §7 resolv.conf landscape survey |
| `test-dns-emitters.sh` | 37 | §6 capability matrix, resolvectl/systemd-resolve grammar |
| `test-lib-smoke.sh` | 32 | plan/apply/report/state machinery, postconditions, undo replay |
| `test-plan-builder.sh` | 53 | per-backend plan construction, R5/R7 |
| `test-dns-detect-cli.sh` | 27 | `racoon-dns-detect` CLI |
| `test-phase1-up.sh` | 23 | `phase1-up.sh` end to end |
| `test-phase1-roundtrip.sh` | 21 | `phase1-up.sh` + `phase1-down.sh` round trip |

All 10 survey fixtures pass:
`01-ubuntu2404-resolved-stub`, `02-bionic-systemd-resolve-only`,
`03-arch-parallel-unlinked`, `04-nm-dns-default`,
`05-nm-dns-default-systemd-resolved`, `06-nm-dns-dnsmasq`,
`07-resolvconf-openresolv`, `08-standalone-dnsmasq`,
`09-static-resolv-conf`, `10-nsswitch-resolve-override`.

## 4. Bugs found and fixed during this work

Real defects caught while building the fixture/regression suite (distinct
from the design questions above), most-recent first:

- **`rhook_emit_report()`'s outcome-counting**: `grep -c ... || printf 0`
  double-counted on a zero-match category — `grep -c` prints `"0"` *and*
  exits 1 on no match, so the `||` fallback appended a second `"0"` into
  the same command substitution, producing `"0\n0"` and breaking every
  `[ -gt 0 ]` integer test under `dash` (visible as `Illegal number` on
  stderr on literally every successful run). Found via manual end-to-end
  execution of `phase1-up.sh`, not by the unit tests — the existing tests
  exercised the affected code paths but never asserted on stderr
  cleanliness, which is why it survived until a real `dash` run surfaced
  it. Fixed with a plain capture + `${var:-0}`.
- **Backend-token naming split**: `hooks.conf`'s documented `backend =
  resolved` value and `rhook_survey_classify_backend()`'s own auto-detect
  return value disagreed with `rhook_plan_dns()`'s dispatch, which only
  recognized `systemd-resolved`. An explicit `backend = resolved` config
  value would have silently routed to the fallback (full
  `/etc/resolv.conf` overwrite) backend instead of the intended
  resolvectl/systemd-resolve path. Caught by the plan-builder tests when
  `backend = resolved` produced an empty command for `resolved_dns`.
  Standardized on `resolved` throughout the backend-token enum.
- **`rhook_plan_dns_resolved()`'s `domains_prefixed` global leak**: missing
  the `rhook_` naming convention and missing from the function's `local`
  declaration list.
- **`~.` as a "clear domains" value**: a confirmed, previously-*live*
  production bug in the old `phase1-down.sh`'s systemd-resolved teardown
  fallback. `~.` is the catch-all *routing* domain, not an empty-list
  clear value — using it promoted a DNS-less link to the system-wide
  default resolver, producing a total resolution outage ("the VPN killed
  my internet"). Fixed with dedicated `rhook_dns_emit_clear_dns`/
  `rhook_dns_emit_clear_domains` functions using an actual empty string.
- **TAB as an `IFS` delimiter silently drops empty fields**: `while
  IFS='<tab>' read -r ...` on 8-field survey rows shifted fields left
  whenever a middle field was empty, because POSIX always treats TAB as
  "IFS whitespace" regardless of what `IFS` is set to (unlike a
  non-whitespace delimiter such as `.`). Fixed by reading whole lines and
  extracting fields with `cut -f<N>` everywhere a TSV row is parsed —
  `rhook_run_step`, `rhook_apply_plan`, `rhook_undo_replay`,
  `rhook_survey_divergent`, `rhook_survey_parallel_unlinked`, and
  `racoon-dns-detect`'s own plan-printing loop all use this convention.
- **`rhook_survey_parallel_unlinked()` false positive**: counted
  `/etc/resolv.conf` itself toward the "≥2 redundant generated copies"
  tally, misclassifying an entirely normal `NetworkManager dns=dnsmasq`
  setup (main copy + exactly one `no-stub-resolv.conf`, which is supposed
  to differ by design) as `PARALLEL_UNLINKED`.
- **`rhook_valid_ipv4()` accepted a trailing dot** (`"10.0.12.44."`): IFS
  field-splitting on a trailing delimiter silently drops it rather than
  producing an empty final field, so four valid octets were seen and the
  malformed input passed.

One non-code incident, noted for transparency: while manually exercising
`phase1-up.sh`'s fallback-DNS code path outside the test harness early in
this session, this session's own container's real `/etc/resolv.conf` was
overwritten (the fallback backend writes there by design when no
supported resolver manager is detected — exactly correct behavior for a
real deployment, but not something to run against a shared dev
container's live file). Caught immediately, restored to a working
config, DNS resolution verified recovered. Every subsequent manual
end-to-end test in this session pins `backend = networkmanager` with a
stubbed `nmcli` specifically so the fallback backend's real filesystem
write is only ever exercised inside the isolated `tests/hooks/` fixtures,
never against a live system.

## 5. Where the brief's assumptions met reality

- Every specific technical claim in the brief that could be checked
  against source or documentation held up: the D-Bus bus-activation
  hazard, `ipv4.dns-priority`'s negative-means-exclusive behavior,
  NetworkManager's `dns=` being a plugin *list* requiring `Mode`+
  `--print-config` union rather than either alone, and the `~domain`
  routing-vs-search-suffix distinction were all independently confirmed
  and matched the brief's description exactly.
- **`INTERNAL_SPLITDNS_DOMAINS`'s delimiter was not specified by the
  brief and was not obvious from the old prototype's inconsistent
  handling** — resolved by reading racoon's own C source
  (`isakmp_unity.c`/`isakmp_cfg.c`) rather than guessing: it is
  comma-separated (the raw Cisco Unity `UNITY_SPLITDNS_NAME` attribute
  payload, `memcpy`'d verbatim from the peer), unlike
  `SPLIT_INCLUDE_CIDR`/`INTERNAL_DNS4_LIST`, which racoon itself
  space-joins (`isakmp_cfg_iplist_to_str`/`splitnet_list_2str`). Getting
  this backwards would have silently fed a whole comma-joined blob as one
  "domain" to §4 validation and rejected every gateway sending more than
  one split-DNS domain — a subtle, easy-to-miss defect the brief's own
  working rules (confirm against source, don't guess) exist to prevent.
- No part of the brief's design was found to be actually wrong against
  reality; the items above are gaps the brief left open by necessity
  (implementation-level decisions it couldn't have specified in advance),
  not incorrect claims.
