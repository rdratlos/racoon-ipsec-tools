> **Archived.** Superseded by [doc/dev/v0.9.1-hardening-spec.md](../../dev/v0.9.1-hardening-spec.md)#51-brief-1--the-origin-spec as of 2026-08-04; retained for provenance. See also git tag `archive/pre-doc-consolidation`.

# Implementation brief: racoon phase1-up/down split-DNS and routing hooks

You are working in `rdratlos/racoon-ipsec-tools` (BSD-3-Clause, IKEv1 daemon, v0.9.0
hardening phase). This brief replaces the current `phase1-up.sh` / `phase1-down.sh`
prototypes with a designed implementation.

**Read this whole brief before writing any code.** The existing scripts were produced
by iterative trial and error against live systems; that loop is what this brief exists
to end. Do not continue patching them in place. Build the structure described below,
then port the *knowledge* out of the old scripts into it.

---

## 0. Working rules

1. **Do not guess command syntax.** For every external command you emit
   (`resolvectl`, `systemd-resolve`, `nmcli`, `resolvconf`, `dnsmasq`, `setkey`, `ip`),
   confirm the exact invocation and the option's minimum version against the man page
   or upstream source. Where a syntax is version-dependent, handle both and say so in
   a comment. If you cannot confirm something, mark it `# UNVERIFIED:` and list it in
   your final report rather than shipping a plausible guess.
2. **No GPL code.** `vpnc-script` is GPLv2; this tree is BSD-3-Clause. You may
   reimplement detection *technique* (that is fact, not expression), but write it
   fresh: your own structure, your own names, no carried-over comments or code shape.
   Do not vendor, quote, or transliterate any part of it.
3. **POSIX `sh`.** Target `dash`, `bash`, and NetBSD `/bin/sh`. `local` is not POSIX
   but is supported by every shell in the target set — you may use it, with a comment
   at first use recording that this is deliberate. No bashisms beyond that
   (no arrays, no `[[`, no `${var,,}`, no process substitution).
4. **`shellcheck` clean** at default severity for every shipped script. Add
   `# shellcheck disable=` only with a justifying comment.
5. **Preserve the hard-won comments** from the current `phase1-up.sh`. Specifically the
   D-Bus bus-activation hazard, the `RcManager`-over-file-layout rationale, the
   `ipv4.dns-priority` negative-means-exclusive finding, the "configure the NM profile
   fully before first activation" ordering, and the `Mode` ∪ `--print-config` union
   rationale. These document real field failures; carry them over intact, adapting only
   the surrounding code references.
6. **Ask before inventing policy.** If a design question arises that this brief does not
   answer (naming, config key semantics, failure defaults), stop and ask rather than
   picking one and building on it.

---

## 1. Deliverables

```
src/scripts/racoon-hook-lib.sh     # sourced by both hooks; all shared logic
src/scripts/phase1-up.sh           # thin: gather → validate → plan → apply → report
src/scripts/phase1-down.sh         # thin: read state → replay undo → report
src/scripts/racoon-dns-detect      # user-facing wrapper: --detect, --dry-run, --explain
tests/hooks/                       # fixture-driven unit tests (see §8)
etc/racoon/hooks.conf.sample       # documented configuration sample
doc/admin/split-dns.html           # Admin Guide chapter (see §9)
```

`racoon-hook-lib.sh` holds *all* detection, validation, capability probing, logging and
state I/O. The two hooks must contain no duplicated logic — in particular, validation
must exist exactly once, or the down script will eventually accept something the up
script rejected.

---

## 2. Non-negotiable design rules

**R1 — The hook only makes changes that revert at phase1-down.** Anything requiring
persistent system reconfiguration (editing `NetworkManager.conf`, changing
`nsswitch.conf`, changing the `resolv.conf` symlink, enabling a unit) is *reported to
the admin as a recommendation*, never performed.

**R2 — Never touch SAD or SPD from the hook.** Remove `setkey -f`, the generated
`spd.conf`, and `setkey -F`/`spdflush` entirely. Racoon owns that lifecycle; a shell
script racing the daemon's own teardown is a bug generator, and blanket flushes destroy
the state of any other IPsec consumer on the host. If policies genuinely linger after
phase1-down, that is a daemon defect to be filed and fixed in C, not papered over here.
The hooks own **routes, addresses, and DNS**. Nothing else.

**R3 — Everything from the peer is untrusted input.** `INTERNAL_ADDR4`,
`INTERNAL_DNS4`, `INTERNAL_DNS4_LIST`, `SPLIT_INCLUDE`, `SPLIT_INCLUDE_CIDR`,
`INTERNAL_SPLITDNS_DOMAINS`, `DEFAULT_DOMAIN`, `LOCAL_ADDR`, `REMOTE_ADDR` and the port
variables all arrive over Mode Config from the gateway and are consumed by a root
process. Whitelist-validate every one before use (§4). Reject, do not sanitize.

**R4 — DNS is configured last on the way up and torn down first on the way down.**
On teardown, DNS → routes → address → state file. Removing the tunnel while split-DNS
still points at an internal resolver leaks internal names in cleartext on every normal
disconnect.

**R5 — The VPN address goes on a dedicated dummy interface, never on the physical NIC.**
`ip addr add ${INTERNAL_ADDR4}/32 dev racoon0` where `racoon0` is `type dummy`. A `/32`
on the physical interface is answerable by ARP on the local segment (default
`arp_ignore=0`), leaking the internal address to a hostile LAN. Routes keep
`dev "$IFACE" src "$INTERNAL_ADDR4"` — `src=` only requires the address be local
somewhere, so this works unchanged. The same dummy is the anchor for per-link DNS.

**R6 — The dummy interface name is a variable, recorded in state.** Post-v0.9.0 the
XFRM migration replaces it with a real `ipsec0`; that must be a one-line change.

**R7 — No hardcoded networks.** The `10.0.12.0/24` fallback is removed with no
replacement. No split-include from the gateway ⇒ no routes installed ⇒ report and apply
the failure policy.

**R8 — Runtime state lives in `/run/racoon/`, never `/etc/`.** Create the directory once,
early, before anything can try to write into it.

---

## 3. Architecture: plan / apply / journal

The core structural change. The current scripts execute imperatively and re-derive
their own decisions at teardown. Replace that with three phases:

### 3.1 Survey
Gather facts about the system. Pure reads, **no side effects** (see the bus-activation
hazard — gate every D-Bus probe on `systemctl is-active` first). Produces a survey
record: resolv.conf landscape (§7), resolver backend, backend capabilities (§6),
outbound interface, tool versions and paths.

### 3.2 Plan
Turn survey + validated Mode Config attributes into an ordered list of **steps**. A step
is a record, not a command execution:

```
step_id | description | command | undo_command | criticality | precondition
```

`criticality` is `required` or `optional`. Building the plan performs no changes, so
`--dry-run` is simply "plan, print, exit" and costs nothing to maintain.

### 3.3 Apply
Execute steps in order through a single `run_step()` wrapper. **There is exactly one
place in the codebase where an external command that changes system state is executed.**
`run_step()`:

- evaluates the precondition; if unmet → record `skipped` with the reason
- executes, capturing stdout, stderr and exit code separately
- records outcome: `ok` | `failed` | `skipped` | `not-attempted`
- on `failed` + `required` → stop, record all remaining steps as `not-attempted`,
  and apply the failure policy
- on `failed` + `optional` → record and continue
- appends the `undo_command` of every `ok` step to the state file **as it succeeds**,
  so an interrupted run is still fully revertible

**Remove `set -e` and remove every `2>/dev/null || true`.** Both are why failures are
currently invisible. Error handling is explicit, per step, and always recorded. Use
`set -u` instead, plus an `EXIT` trap that emits the report even on abnormal exit.

### 3.4 State file
`/run/racoon/hook-state.<connection-id>` — a `key=value` / append-only record of what was
*actually done*, not what was intended. Minimum contents: schema version, timestamp,
connection identity, chosen interface, dummy device name, resolver backend, capability
flags, the resolv.conf backup path plus its SHA-256 at backup time, and the ordered undo
list.

`phase1-down.sh` reads this and replays the undo list in reverse. **It performs no
detection of its own.** Between phase1-up and phase1-down the default route can move
(Wi-Fi → LTE is the roadwarrior norm), NM can restart and change `RcManager`, and
resolv.conf can be rewritten — re-derivation silently diverges and cleans up nothing.

State-file consequences, all mandatory:
- Presence of the state file — not `INTERNAL_ADDR4` — is the teardown guard. The current
  down script exits before the DNS cleanup when no internal address is exported, which
  leaves split-DNS configured indefinitely.
- No `IFACE="${IFACE:-eth0}"` fallback anywhere. On predictable-names systems `eth0`
  does not exist, every `ip` call fails into the void, and nothing is cleaned up.
  Guessing is worse than failing loudly.
- Delete the state file only after teardown completes successfully. A partial teardown
  must remain retryable and diagnosable.
- Restore the resolv.conf backup only if the current file's SHA-256 still matches what
  was recorded at backup time. Otherwise something else rewrote it during the session —
  log and leave it alone. Write via temp file + `mv`, never `cp` onto a path that may be
  a symlink.

---

## 4. Input validation

One implementation in the library, used by both hooks.

- **Addresses**: must parse as dotted-quad IPv4, each octet 0–255. Reject `0.0.0.0`,
  loopback, and multicast for DNS servers.
- **CIDR**: address + optional `/0..32`. Reject anything containing a character outside
  `[0-9./]` — that alone kills the `default via 10.6.6.6` argument-injection vector.
- **Domains**: `[A-Za-z0-9.-]` only, each label ≤ 63 bytes, total ≤ 253, no leading
  hyphen, no empty labels. Cap the *list* length too.
- **Counts**: cap DNS servers (suggest 8) and domains (suggest 32). An unbounded list
  from the peer is a resource-exhaustion and log-flooding vector.
- Reject the whole attribute on first bad element, log which element and why at
  `warn` level, and apply the failure policy. Never silently drop or "fix" a value.

Add a regression test per vector, including at minimum: `default via …`,
a value containing a newline, a value containing `;`, an over-long domain, and a
non-numeric octet.

---

## 5. Debugging and observability (priority requirement)

The maintainer's explicit requirement: it must be possible to see **what was done, what
should have happened but did not, and why** — without editing the script.

### 5.1 Verbosity
Controlled by `RACOON_HOOK_DEBUG` (env) and `debug_level` (config), env wins:

- `0` — quiet: syslog only, errors and the one-line summary
- `1` — normal: syslog + stderr, one line per step outcome
- `2` — verbose: every step with its full command line and exit code
- `3` — trace: adds captured stdout/stderr per step, plus the full survey record and
  the reasoning behind each detection branch ("chose X because Y; did not choose Z
  because W")

Level 3 must make each detection decision self-explaining. Every branch of
`detect_resolver()` records the evidence that selected it.

### 5.2 Sinks
Syslog via `logger -t racoon-phase1-{up,down}` always. Additionally stderr at level ≥ 1
(racoon captures hook output; the current `log()` claims stderr in its comment and does
not do it). At level ≥ 2 also append to `/run/racoon/hook.trace`, timestamped, mode
0640, size-capped and truncated at each phase1-up.

### 5.3 The report
Both hooks end — including on failure, via the `EXIT` trap — with a compact
**plan-versus-outcome** report. This is the single most important output of the whole
design. Sketch:

```
racoon phase1-up report — 2026-07-18T09:14:22+02:00
  backend: systemd-resolved (via systemd-resolve, systemd 237)
  capabilities: per-link=yes  routing-domains=yes  default-route=NO  revert=NO

  [ ok        ] create dummy interface racoon0
  [ ok        ] add 10.0.12.44/32 to racoon0
  [ ok        ] route 10.0.12.0/24 dev wlan0 src 10.0.12.44
  [ ok        ] set DNS 10.0.12.53 on racoon0
  [ ok        ] set routing domain ~corp.example.com on racoon0
  [ SKIPPED   ] mark link as non-default-route
                reason: systemd-resolve 237 has no --set-default-route;
                        this systemd predates it (added in v240)
                impact: VPN DNS may serve queries outside corp.example.com
                        while the tunnel is up
  [ not-run   ] flush DNS caches

  result: PARTIAL (5 ok, 1 skipped, 1 not attempted) — policy 'warn', continuing
```

Requirements on the report:
- Every planned step appears, including ones never attempted.
- Every non-`ok` step carries **reason** and **impact** — what the user loses in
  practice. Not "command failed": *what stops working.*
- The capability line states what the system cannot do before the steps are listed.
- Machine-readable form available (`--format=kv`) for CI assertions.

### 5.4 User-facing entry points
`racoon-dns-detect` (installed in `$PATH`, no root required for `--detect`):

- `--detect` — run the survey, print the landscape, backend, capability matrix and the
  reasoning; exit `0` if a workable split-DNS path exists, `1` otherwise. This is the
  answer to every future bug report: "run this, paste the output."
- `--dry-run` — build the plan from the current environment (or from
  `--env-file` for offline testing) and print it without touching anything.
- `--explain` — print the decision tree with the branch actually taken highlighted.

`phase1-up.sh` calls the survey and logs its `--detect` summary at level ≥ 1 every run,
so post-hoc diagnosis never requires reproducing the failure.

### 5.5 Failure policy
Config key `on_dns_failure = abort | warn` (default `warn`, documented recommendation
`abort` for security-sensitive deployments).

- `abort`: a `required` DNS step failing tears down what was already applied and exits
  non-zero, so the tunnel does not come up with unprotected name resolution.
- `warn`: continue, but the report result is `PARTIAL` and the exit code is non-zero,
  with the leak spelled out explicitly.

Silent success is never acceptable when split-DNS was requested and not achieved.

---

## 6. systemd-resolved: version and capability handling (priority requirement)

Field evidence: **Xubuntu 18.04 Bionic, 32-bit, has no `resolvectl`.** It has
`systemd-resolve` only. Later Ubuntu LTS releases ship `resolvectl` with newer systemd.
The current code's fallback name `resctl` does not exist at all, so on Bionic the entire
resolved path silently no-ops — and `detect_resolver()` even *selects* that path based
on the same bogus probe. Fix both.

This is not a rename. The two tools have **different command grammars**:

| Operation | `resolvectl` (systemd ≥ 239) | `systemd-resolve` (older) |
|---|---|---|
| set servers | `resolvectl dns IF a.b.c.d …` | `systemd-resolve --interface=IF --set-dns=a.b.c.d …` |
| set domains | `resolvectl domain IF ~dom …` | `systemd-resolve --interface=IF --set-domain=~dom …` |
| default route | `resolvectl default-route IF false` | not available before v240 |
| revert link | `resolvectl revert IF` | `systemd-resolve --interface=IF --revert` |
| flush caches | `resolvectl flush-caches` | `systemd-resolve --flush-caches` |

Verify each of these against the man pages for the versions in your CI matrix before
using them; correct the table in the code comments if reality differs.

Required behaviour:

1. Probe in order: `resolvectl`, then `systemd-resolve`. **Never `resctl`** — remove it
   from every code path including `detect_resolver()`.
2. Determine the systemd version (`systemctl --version`, first line, second field) and
   record it in the survey and the state file.
3. Build a **capability matrix** from tool + version, not from assumption:
   `per_link_dns`, `routing_domains`, `default_route`, `revert`, `flush_caches`.
4. Emit the correct grammar for the detected tool. Do not build one command string and
   hope; select the emitter per tool.
5. Where a capability is missing, the plan records the step as `skipped` with the
   version reason **and the practical impact**. The Bionic case specifically: without
   `--set-default-route=no`, the VPN resolver can serve queries beyond the split
   domains. Say exactly that, in the report and in the Admin Guide.
6. If `--revert` is unavailable, the undo path must be explicit per-setting clearing,
   and it must set the domain list to the **empty string** — never `~.`, which is the
   catch-all routing domain and would promote a DNS-less link to system-wide default
   resolver. (This bug is live in the current `phase1-down.sh`. It produces a total
   resolution outage, reported by users as "the VPN killed my internet.")
7. Bionic 32-bit is a supported target. Assume no `busctl` guarantee, older `nmcli`,
   older `ip`. Feature-probe; never version-sniff the distro.

---

## 7. The resolv.conf landscape survey (priority requirement)

Field evidence: **an Arch Linux roadwarrior where NetworkManager maintains resolv.conf
content in three places in parallel, with no symlink anywhere.** Every symlink-based
detection heuristic returns nothing useful there, and the current code falls through to
"which service is running", which is the weakest signal available.

Replace single-target detection with a survey of all known locations:

```
/etc/resolv.conf
/run/systemd/resolve/stub-resolv.conf
/run/systemd/resolve/resolv.conf
/run/NetworkManager/resolv.conf
/run/NetworkManager/no-stub-resolv.conf
/run/resolvconf/resolv.conf
/etc/resolvconf/run/resolv.conf
```

For each present path record: regular file or symlink (and target), size, mtime,
SHA-256 of content, generator header if any, and the nameserver list.

Then derive:

1. **Which file glibc actually reads.** `readlink -f /etc/resolv.conf`, *plus* the
   `hosts:` line of `/etc/nsswitch.conf`. If it contains `resolve [!UNAVAIL=return]`,
   glibc talks to systemd-resolved over varlink/D-Bus and the file contents are
   largely irrelevant — this inverts the conclusion and must be surfaced prominently.
2. **Divergence.** Group the surveyed files by content hash. More than one distinct
   nameserver set ⇒ report a `DIVERGENT` landscape listing each path, its generator and
   its nameservers. Do not pick one silently.
3. **Parallel-writer detection (the Arch case).** Multiple generated files present, no
   symlink from `/etc/resolv.conf`, and `/etc/resolv.conf` a regular plain file ⇒
   classify as `PARALLEL_UNLINKED` and report:
   - which writers are present and what each produced
   - which one glibc actually consumes
   - that changes pushed to the *other* backends will have **no effect** on resolution
   - the admin-facing remediation, as a **recommendation only** (R1): link
     `/etc/resolv.conf` to the stub, or set NM's `rc-manager`, whichever the survey
     shows is coherent with the rest of the system
4. **Effectiveness check.** After applying DNS config, re-run the relevant part of the
   survey and verify the change is observable where glibc will see it (`resolvectl
   status <if>` for the resolved path, content diff for file-based paths). A step that
   "succeeded" but changed nothing the resolver reads is reported as `failed`, not `ok`.
   This is the check that catches the Arch case at runtime rather than in a bug report.

Keep the existing `RcManager` D-Bus probe as the primary signal when NM is running —
it is correct and better than file inspection — but treat it as *one input to the
survey*, not as an early return that skips the rest.

---

## 8. Backend fixes to carry into the new structure

- **dnsmasq does not currently do split DNS at all.** `server=<ip>` replaces the global
  upstream (all queries to the VPN resolver), and `domain=` is the DHCP/expansion
  domain, unrelated to query routing. Correct form is one line per domain:
  `server=/corp.example.com/10.0.12.53`. With no domains, do not write a global
  `server=` line — report that split-DNS is not achievable and apply the policy.
- **NM-spawned dnsmasq** is a separate case from standalone: config goes in
  `/etc/NetworkManager/dnsmasq.d/` and requires an NM reload. You already detect it via
  the DnsManager `Mode` property; branch on it.
- **`killall -HUP dnsmasq` is unsafe on NetBSD**, where `killall` signals every process
  the user may signal. Use `pkill -HUP -x dnsmasq`, preferring `systemctl reload dnsmasq`
  where systemd owns it.
- **resolvconf and fallback paths need the capability warning** the NM path already has:
  classic resolvconf merges nameservers with no per-domain routing, so the VPN resolver
  becomes authoritative for everything. That is not split DNS and must be reported as
  such, with the same clarity as the existing NM warning text.
- **`umask 077` is currently set globally and never restored**, so `/etc/resolv.conf` is
  written mode 0600 on the fallback path — root resolves, every unprivileged process
  stops. Scope permissions per file with explicit `chmod`; never change the process
  umask.
- **`/run/racoon` must exist before any write to it.** Currently `mkdir -p` runs only in
  the NM success path while the failure branches write the marker earlier, so the marker
  is missing exactly when it matters most.
- **Remove all `set -e`-dependent control flow.** Two live aborts to fix as part of the
  rewrite: a trailing `[ -n "$domains" ] && echo …` as the last command of a redirected
  group, and a trailing `[ -n "$DNS_SERVERS" ] && setup_fallback_dns …` as the last
  command of a `case` arm. Both kill the script on ordinary inputs. The plan/apply
  structure eliminates this class entirely.
- **NM dummy profile**: keep the existing implementation almost verbatim — the
  single-`connection add`, `autoconnect no`, `ipv4.dns-priority 50`, `never-default yes`,
  `ignore-auto-dns yes`, `ipv6.method disabled` combination is correct and hard-won.
  Change only the naming so it draws its device name from the shared dummy variable (R6),
  and keep the pre-run cleanup of stale profiles.

---

## 9. Testing

Everything above is testable without root, without a VPN, and without a network — that
is the point of the plan/apply split and the injectable tool paths.

- **Injectable externals.** Every external binary is referenced through an overridable
  variable (`RACOON_HOOK_IP`, `RACOON_HOOK_NMCLI`, `RACOON_HOOK_RESOLVECTL`,
  `RACOON_HOOK_BUSCTL`, `RACOON_HOOK_SYSTEMCTL`, …) defaulting to the real path.
  Tests point them at stub scripts that echo canned output and record their argv.
- **Fixture-driven survey tests.** A fixture is a directory tree standing in for
  `/etc` and `/run` plus a set of stub command outputs. Required fixtures, at minimum:
  1. Ubuntu 24.04, systemd-resolved stub symlink, `resolvectl` present
  2. Xubuntu Bionic 32-bit, `systemd-resolve` only, no `resolvectl`, no `busctl`
  3. Arch, `PARALLEL_UNLINKED` — three generated files, no symlink (§7)
  4. NM with `dns=default`
  5. NM with `dns=default,systemd-resolved`
  6. NM with `dns=dnsmasq`
  7. resolvconf/openresolv
  8. standalone dnsmasq
  9. static `/etc/resolv.conf`, no manager
  10. `nsswitch.conf` with `resolve [!UNAVAIL=return]` overriding a file-based landscape
  Each asserts the classified backend, the capability matrix, and the exact planned
  command sequence.
- **Injection regression tests** per §4.
- **Round-trip test**: apply a plan against stubs, feed the resulting state file to
  `phase1-down.sh`, assert the undo argv sequence is the exact inverse.
- **Negative-path tests**: required step fails → correct partial teardown, correct exit
  code, report contains reason and impact for every non-`ok` step.
- Wire into the existing GitHub Actions matrix. The fixture suite must run on every
  supported Ubuntu LTS **and on NetBSD** — NetBSD is where the `killall` and shell
  portability assumptions break.
- `shellcheck` as a CI gate.

---

## 10. Packaging and documentation

- `/etc/racoon/hooks.conf`: `backend = auto|resolved|networkmanager|resolvconf|dnsmasq|none`,
  `on_dns_failure = abort|warn`, `debug_level = 0..3`, `dummy_iface = racoon0`.
  Ship a fully commented sample; the shipped defaults are the only thing that differs
  between the Debian and Arch packages.
- Debian: hooks in the main package, `iproute2` as a hard dependency; `Suggests:` for
  `systemd-resolved` / `dnsmasq` / `resolvconf`. **No dependency on `vpnc-scripts`** —
  the asymmetric footprint against Arch is not worth one free script, and its
  `$TUNDEV`/`CISCO_SPLIT_INC_*` contract does not fit a kernel-native SPD model anyway.
- Arch: same, `optdepends` for the backends. Do not pull in `vpnc`.
- Admin Guide chapter covering: the detection table (one row per fixture in §9), the
  capability matrix and what each missing capability costs, `racoon-dns-detect --detect`
  as the first diagnostic step, the `PARALLEL_UNLINKED` landscape and its remediation,
  the Bionic `systemd-resolve` limitation, and the failure-policy choice. Cross-check
  every claim against the code as you write it — the same standard as the rest of the
  guide.

---

## 11. Suggested order of work

1. `racoon-hook-lib.sh` skeleton: logging, verbosity, report, `run_step()`, state I/O.
2. Validation (§4) + its regression tests. Nothing else lands before this.
3. Survey (§7) + fixture harness + all ten fixtures.
4. Capability matrix (§6) + the systemd-resolve/resolvectl emitters.
5. Plan builder + `--dry-run` + `racoon-dns-detect`.
6. Apply + state file + `phase1-up.sh`.
7. `phase1-down.sh` as pure undo replay + round-trip tests.
8. Remaining backends (§8).
9. Packaging + Admin Guide.

Commit at each step with the tests for that step. Do not proceed to the next while the
current one is red.

---

## 12. Final report

When done, report: every `# UNVERIFIED:` marker and what would settle it; every design
question you had to resolve yourself and the choice you made; the fixture list with
pass/fail; anything in this brief that turned out to be wrong when checked against
reality. That last one is expected and wanted — the brief is written from review of the
prototypes, not from a live system.
