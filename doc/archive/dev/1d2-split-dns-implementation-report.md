> **Archived.** Superseded by [doc/dev/v0.9.1-hardening-spec.md](../../dev/v0.9.1-hardening-spec.md)#54-outcome-report--briefs-1-and-3-implemented as of 2026-08-04; retained for provenance. See also git tag `archive/pre-doc-consolidation`.

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

---

# Brief 3 addendum

Brief 3 was a follow-up rework triggered by a live test on a Xubuntu
Bionic 32-bit roadwarrior (racoon 0.9.1, OpenSSL 1.1.1, systemd 237,
`systemd-resolve` only — no `resolvectl`). It found and fixed the F1/F3/F4
reconnect-loop chain, added SPD ownership (R2', superseding Brief 1's
"never touch SPD" R2), FIFO-correct state matching, a port-53 ownership
survey, an `allow_resolv_conf_overwrite` gate, NetworkManager-aware dummy
interface teardown, honest `on_dns_failure` naming, real packaging
wiring, and an Admin Guide section — work packages A through M, with F
(needs a live host for `setkey -DP` captures) left explicitly blocked.
This section follows the same format as §1–5 above, for Brief 3's own
work specifically.

## 6. New `# UNVERIFIED:` markers introduced by Brief 3

Three, all in `src/racoon/scripts/racoon-hook-lib.sh`, all already
mitigated defensively (feature-probed or tolerant of either possible
answer) rather than left as a blind assumption — none block correct
behavior either way:

1. **NetBSD `sockstat(1)`'s exact column layout** (§C, port-53 survey) —
   modeled on FreeBSD's `sockstat` output (which NetBSD's descends from),
   since no NetBSD host was available in this environment to confirm
   directly. Settled by: running `sockstat -l` on a real NetBSD host and
   comparing column order/count against `rhook_survey_port53_raw()`'s
   `sockstat` branch.
2. **The exact byte-for-byte table layout of modern `resolvectl status`**
   (§A, DNS effectiveness check) — box-drawing characters, possible ANSI
   color codes, and `TABLE_STRV_WRAPPED` column wrapping were confirmed
   structurally by reading `resolvectl.c`'s `table_new_vertical()`/
   `dump_list()` calls (source-verified, not guessed), but the literal
   rendered bytes were not confirmed against a live run, nor was the exact
   systemd version boundary where the table format replaced the older
   `systemd-resolve --status` plain-text format. Mitigated by
   `rhook_dns_status_has()` using a plain `grep -qF` substring search
   against either tool's output rather than a structural parser tuned to
   one specific format — this is deliberately robust to both the
   confirmed-divergent v237 plain-text format and the confirmed-different
   modern table format without needing to distinguish them. Settled by: a
   live `resolvectl status <iface>` capture on a current systemd release.
3. **Whether a routing-only domain (`~domain`) is echoed back in
   `resolvectl`/`systemd-resolve status` output with its leading `~` or
   without** (§A, `rhook_postcond_set_domains()`) — not confirmed against
   a live `resolved` instance either way. Mitigated by checking for the
   domain with any leading `~` stripped from the expected value before
   searching, since the bare domain name is a substring of the
   tilde-prefixed form regardless of which way `status` actually renders
   it. Settled by: configuring a routing-only domain on a live system and
   inspecting `resolvectl status <iface>`'s literal output.

The three markers already listed in §1 above (NetworkManager's
`resolv.conf` header text, `resolvectl default-route`'s introduction
version, and whether `systemd-resolve --set-dns=`/`--set-domain=` accept
multiple values per occurrence) are unchanged by Brief 3 — still open,
same mitigations, only their line numbers shifted with the file's growth
(now approximately 1065, 1521–1522). The third of those was specifically
re-checked during Brief 3's DNS-reordering work (§B): the scope-before-
servers reordering does not introduce any new combined-flag invocation —
domains and servers are still emitted via separate `rhook_dns_emit_*`
calls, one flag occurrence per value, exactly as before — so this marker
is confirmed still-applicable and still safely mitigated, not stale.

## 7. Design questions Brief 3 resolved independently

- **Substring match over structural `--status` parsing** (§A): given
  `resolvectl status` and `systemd-resolve --status` are *confirmed*
  divergent formats (plain text vs. table) with the exact modern
  byte-layout itself unconfirmed (marker 2 above), a plain `grep -qF`
  substring search was chosen over a parser tuned to either structure —
  robust by construction to both known formats and any future
  presentation change that keeps the server address as visible text
  somewhere in the output.
- **Per-address FIFO isolation in test design** (§D): `rhook_state_exists()`/
  `rhook_state_oldest_unconsumed()` always return the *oldest* live
  generation globally for a `REMOTE_ADDR`, so reusing one address across
  many independent test scenarios in the same suite (each calling
  `rhook_state_reset()` without consuming prior generations) let later
  scenarios silently pick up earlier scenarios' leftover generations.
  Resolved by giving state-file-sensitive scenarios within
  `test-lib-smoke.sh` distinct `REMOTE_ADDR` values, and by testing FIFO
  ordering itself end-to-end in `test-phase1-roundtrip.sh`'s dedicated
  "overlap" section rather than relying on it holding incidentally in
  unrelated scenarios.
- **`mkdir`-based lock for generation allocation** (§D): a plain
  read-modify-write on a counter file cannot be made atomic in POSIX
  `sh` without a lock; `mkdir` is atomic on every POSIX filesystem this
  project targets (Linux, NetBSD) and needs no external locking utility.
  Capped at 20 one-second retries, then proceeds best-effort and logs why
  — consistent with this codebase's standing rule that a hook-side
  problem must never block a real IPsec connection from coming up.
- **Reap scope limited to `.consumed` files only** (§D): `rhook_state_reap()`
  only ever deletes generations already marked consumed by a successful
  teardown (by count beyond 5, or age beyond 24h); a live, unconsumed
  generation — including one stuck after a partial-failure teardown
  awaiting retry — is never touched by reaping regardless of age or count,
  since §3.4's "the state file is the sole teardown guard" invariant means
  only a successful replay or explicit admin action may remove one.
- **`report`/`rollback` naming over keeping `abort`** (§H): chose to rename
  rather than implement an actual fail-closed mechanism (e.g. having the
  hook call `racoonctl vpn-disconnect` on its own failure) — verified via
  source that racoon does not consult a hook's exit status when deciding
  whether to keep an SA, so no naming choice could make `on_dns_failure`
  actually reject a tunnel; a hook attempting to force a disconnect via
  `racoonctl` from inside its own synchronous invocation by racoon risked
  a self-inflicted variant of the very F2 race this brief documents
  elsewhere (§ Issue 1 in `doc/dev/daemon-issues.md`), for a guarantee it
  still could not make. `rollback` (undo this run's own changes via the
  existing `rhook_undo_replay()` machinery) was judged a more honest,
  lower-risk way to give an admin a "fail-closed-for-this-run" option.
- **`allow_resolv_conf_overwrite` default of `no`** (§I): the fallback
  backend's full DNS redirect is the single most invasive thing this hook
  set can do; refusing by default (a reported, non-silent failure) and
  requiring explicit opt-in was chosen over a more permissive default,
  consistent with R1's "no persistent reconfiguration beyond the VPN
  session" spirit even though the overwrite itself is not persistent
  strictly speaking — it is still a full, unscoped redirect an operator
  may not expect from a "split-DNS" hook set.
- **NetworkManager ownership detection via a pure `systemctl is-active`
  check, not a D-Bus property probe** (§K): reused the exact caution
  `rhook_nm_dbus_prop()` already documents — a bare `busctl get-property`
  call can bus-activate NetworkManager as a side effect on a system that
  does not otherwise run it (confirmed in the field on a Bionic box with
  no NetworkManager installed at all). A pure state read cannot have that
  side effect and is sufficient to decide dummy-interface undo-command
  ownership.
- **`hookscriptsdir = $(sysconfdir)/scripts`, not
  `$(sysconfdir)/racoon/scripts`** (§L): caught during verification, not
  assumed correct from the start — this project's own packaging
  configures with `--sysconfdir=/etc/racoon` directly (confirmed in
  `debian/rules` and `packaging/arch/PKGBUILD`), matching
  `LC_DEFAULT_CF`'s `SYSCONFDIR "/racoon.conf"` and the pre-existing
  `debian/racoon.dirs` entry `etc/racoon/scripts` (not
  `etc/racoon/racoon/scripts`). Confirmed by staging a real `make
  DESTDIR=... install` under both a generic and a Debian-matching
  `./configure` invocation before settling on the final path.

## 8. Where Brief 3's own assumptions met reality (or needed correction)

- **F5 was misattributed to stderr in the original finding.** Reading
  `src/racoon/plog.c` shows `plogv()` writes via `vprintf()`, which
  targets **stdout**, not stderr — corrected in
  `doc/dev/daemon-issues.md`'s Issue 2 rather than silently repeated. The
  practical symptom the brief described ("racoon's log output under
  systemd is unreliable") is still accurate — systemd captures a unit's
  stdout and stderr into the journal identically, and the actual
  mechanism (glibc's full block-buffering on a non-TTY fd, no
  `setvbuf()` call anywhere in `plog.c`/`main.c`) applies to stdout
  either way — only the specific file-descriptor attribution needed
  fixing.
- **§B.3's "untested assumption about `systemd-resolve` accepting
  combined flags"** (noted as an open concern in the engagement's own
  working notes going into this addendum) turned out not to correspond to
  any actual new code path: re-checking §B's scope-before-servers
  reordering confirmed it still emits one `rhook_dns_emit_*` call per
  value, exactly as Brief 1's original implementation did and as marker
  3 in §1 above already documents as mitigated. No combined-flag
  invocation was ever introduced, so there was nothing to newly verify.
- **§E's SPD-ownership claim was verified, not assumed, before
  implementation** — the brief itself flagged this as resting on a claim
  needing verification ("If either is false, stop and report"). Both
  required claims (SPD generation is responder-only; no code path
  installs SPD for a Mode Config initiator) were confirmed true by
  reading `isakmp_quick.c`'s `get_proposal_r()`/`quick_r1recv()`,
  `pfkey.c`'s `pk_sendspdadd2()`, and `isakmp.c`'s `delete_spd()` — see
  `rhook_plan_spd()`'s own header comment in `racoon-hook-lib.sh` for the
  full citation chain. The brief's premise held.
- **Task F (live-host ACQUIRE-provenance investigation) remains blocked**,
  not completed or worked around — no live Bionic (or equivalent) host
  was available in this environment. `doc/dev/teardown-investigation.md`
  records exactly what a `setkey -DP` before/after capture would still
  need to confirm once one is available, and explains why the F1→F3→F4
  causal chain is nonetheless the most parsimonious explanation
  consistent with the evidence already on record, without claiming it as
  independently confirmed at the kernel level.
- Three **pre-existing, unrelated packaging bugs** were found (not
  introduced by, or in scope for, this work) while verifying §L's
  `make distcheck`: a top-level `EXTRA_DIST` entry for a file literally
  named `README` that does not exist (only `README.md` does); a phony
  `docs/history/ChangeLog` rule that unconditionally requires a CVS
  checkout; and a stale `EXTRA_DIST` reference in
  `src/racoon/Makefile.am` to
  `samples/roadwarrior/server/racoon.conf-radius`, which is not present
  in this tree. All three confirmed pre-existing via `git stash` before
  this work began. None were fixed here, since doing so is outside this
  work package's scope; noted for whoever picks up `make distcheck`
  next.

## 9. Test/fixture results (Brief 3 additions)

392 checks across the same 8 suites (up from 260 at the end of Brief 1),
all still passing under both `sh` and `dash`, `shellcheck
--severity=warning` clean on all four shipped scripts at their new
`src/racoon/scripts/` location:

| Suite | Checks (was) | Checks (now) |
|---|---|---|
| `test-validation.sh` | 57 | 57 |
| `test-survey-fixtures.sh` | 10 fixtures | 15 fixtures |
| `test-dns-emitters.sh` | 37 | 37 |
| `test-lib-smoke.sh` | 32 | 44 |
| `test-plan-builder.sh` | 53 | 80 |
| `test-dns-detect-cli.sh` | 27 | 51 |
| `test-phase1-up.sh` | 23 | 59 |
| `test-phase1-roundtrip.sh` | 21 | 49 |

Five new port-53 survey fixtures added (11–15, alongside Brief 1's
01–10): `11-resolved-stub-port53`, `12-forwarder-dnsmasq-port53`,
`13-resolved-plus-second-forwarder`, `14-broken-nothing-bound-loopback-resolv`,
`15-ss-unprivileged-no-process`.

Also verified end to end, beyond the shell test suite: a full
`./bootstrap && ./configure && make && make DESTDIR=... install` (both a
generic invocation and one matching `debian/rules`) built and staged the
entire package — daemon, libraries, man pages, and all four hook scripts
— in one pass, and the pre-existing autotools `make check` suite (35
tests, unrelated to the hooks) still passes unmodified.
