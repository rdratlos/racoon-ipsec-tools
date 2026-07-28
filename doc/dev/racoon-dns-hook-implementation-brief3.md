# Brief 3: findings from the Bionic run, and all remaining work

Consolidated and **supersedes brief 2** (`racoon-hooks-followup-prompt.md`). Everything
still open from brief 2 is restated here; do not work from brief 2 in parallel.

Working rules from brief 1 remain in force: no guessed syntax (`# UNVERIFIED:` markers
instead), no GPL code, POSIX `sh`, `shellcheck` clean, ask rather than invent policy,
preserve the field-evidence comments.

---

# Part I — What the Bionic 32-bit test run established

A live `racoonctl vc` / `racoonctl vd` cycle on Xubuntu Bionic i386 (racoon 0.9.1,
OpenSSL 1.1.1, systemd 237, `systemd-resolve` only) produced evidence that settles most
of brief 2's investigation. Read this section before touching code — several work
packages below are narrowed or redirected by it.

**F1 — The daemon's teardown is correct. The observed "SAs not removed" was a
reconnect loop.** `racoonctl vd` purged both IPsec SAs and the ISAKMP SA cleanly.
One second later the kernel issued an ACQUIRE (`IPsec-SA request for 10.77.254.7 queued
due to no phase1 found`) and racoon rebuilt the entire tunnel, including a second
`phase1-up` run. The SAs visible afterwards had different SPIs from the originals. Brief
2's hypothesis H1 is confirmed; H4 is excluded.

**F2 — Daemon shutdown does not invoke the phase1-down hook.** On `SIGTERM` the log
shows `caught signal 15` → `KA remove` → `racoon process … shutdown`, with no
`[step] phase1 down`. The live tunnel's dummy interface, `/32` address and four routes
were all left installed. Brief 2's H2 is confirmed for the shutdown path specifically.

**F3 — The DNS effectiveness check can never pass on a systemd-resolved stub system.**
It asserts the DNS server is visible in `/run/systemd/resolve/stub-resolv.conf`. That
file contains `nameserver 127.0.0.53` and nothing else by design; per-link servers never
appear there. Every resolved-backend run therefore reports `FAILED` with
"reported success, but had no effect" while the setting was in fact applied.

**F4 — The false failure caused the loop in F1.** Chain: false `FAILED` on the DNS step
→ routing-domain and `default-route` steps marked `not-run` → but the server *was*
registered on `racoon0`, with no routing domain and no `default-route=no` → resolved
treated the link as default-eligible and queried `10.66.0.6` → that traffic matched a
`require` SPD policy → ACQUIRE → rebuild. A partial application left the system in a
worse state than doing nothing, and became the traffic source for its own reconnect loop.

**F5 — Racoon's log output under systemd is unreliable.** Running `-F` under systemd,
racoon writes every message to both syslog and stderr; stderr is a pipe, so libc
block-buffers it. Output arrives in delayed ~4 KB dumps with embedded timestamps that no
longer match arrival order, lines torn at buffer boundaries (`202[verbose] undo route_…`,
`6-07-19 12:29:45: INFO:`), and every message duplicated. Hook output via `logger` is
correctly ordered; racoon's own `plog` output is not. Any past diagnosis based on
ordering in these logs is suspect.

**F6 — Creating the dummy from inside the hook perturbs the daemon.** Racoon re-scans
interfaces mid-negotiation and binds ISAKMP sockets to `racoon0`
(`fe80::…%racoon0[500] used as isakmp port (fd=17)`), on every reconnect.

**F7 — Port 53 ownership is not surveyed at all.** On the test host,
`ss -tulpn` shows a single listener: `127.0.0.53%lo:53` owned by pid 566. Nothing on
`127.0.0.1:53`, nothing on `0.0.0.0:53`. This signal was in the original detection
strategy and did not survive into the implementation. Note the process name renders as
`systemd-resolve` — Linux truncates `comm` to 15 characters, which on this platform
collides exactly with the name of the legacy CLI tool.

**F8 — Minor:** `WARNING: authtype mismatched: my:hmac-sha256 peer:hmac-sha512` on every
Phase 2 negotiation.

---

# Part II — Work packages

## A. Fix the DNS effectiveness check (critical, do first)

The check is correct in principle — a step that "succeeded" without changing what the
resolver reads must be reported as failed — but it consults the wrong source for the
resolved backend, and that single defect produced F3 and F4.

Required behaviour, per backend:

- **resolved**: servers are verified from `systemd-resolve --status` (or
  `resolvectl status`), by locating the `Link n (<ifname>)` block and reading its
  `DNS Servers:` entries. **Not** from any `resolv.conf` variant.
- **resolved, domains**: search/routing domains *do* appear in `stub-resolv.conf`, so the
  domain sub-check may use it — but verify this on systemd 237 specifically before
  relying on it, and prefer `--status` for consistency if it reports them per link.
- **file-based backends** (NM `dns=default`, resolvconf, fallback, dnsmasq): verify by
  content against the file that §7's survey identified as the one glibc actually reads —
  never against a hardcoded path.
- If `nsswitch.conf` contains `resolve [!UNAVAIL=return]`, the resolved per-link state is
  authoritative regardless of any file's content; the check must follow that.

Verify the exact `--status` output shape on systemd 237 before parsing it; the per-link
section formatting changed across versions. If the shape cannot be confirmed, mark
`# UNVERIFIED:` and parse defensively (locate the link block by name, then the first
`DNS Servers:` line within it; tolerate leading whitespace and multiple servers per line).

Add a fixture per backend asserting that a correctly-applied setting verifies as `ok`
**and** that a deliberately-unapplied setting verifies as `failed`. The second assertion
is the one that was missing — the current check would have passed a test that only
covered the negative case.

## B. Roll back partial DNS application, and reorder the DNS steps

F4 shows that leaving a half-applied DNS configuration is worse than applying nothing.

1. **Rollback on failure.** If any required DNS step fails, immediately undo the DNS
   changes already applied to that link, through the normal undo machinery, before
   continuing to the failure policy. The link must end in either fully-configured or
   untouched — never populated-but-unscoped.
2. **Reorder: scope before servers.** Where the backend supports it, apply
   `default-route=no` and the routing domains *before* registering the servers, so there
   is no window in which the link is both populated and default-eligible.
3. **Where scoping is impossible, do not register servers at all.** On systemd 237 there
   is no `--set-default-route`. If routing domains can be set in the same invocation as
   the servers, that is acceptable; if neither is possible, the correct action is to skip
   the DNS configuration entirely and report it, not to register an unscoped server.
   Decide which of these applies on 237 by testing `systemd-resolve --set-domain=` and
   report the finding.
4. The report must state the resulting exposure explicitly in the impact line whenever
   scoping was not achieved.

Tests: forced failure at each DNS sub-step leaves the link in its original state;
ordering assertion on the emitted command sequence per backend.

## C. Survey port 53 ownership (new)

Add as a first-class input to the §7 survey. It is the only signal that detects a
resolver invisible to both file layout and D-Bus — for example dnsmasq on `127.0.0.1`
behind a static `resolv.conf`.

**Enumeration.** Prefer `ss -lntup 'sport = :53'`. Fall back to
`netstat -lnpu`/`netstat -lnpt` where `ss` is absent, and on NetBSD use `sockstat -l`
or `netstat -an` — this must not break the NetBSD CI job. Record the tool used in the
survey output.

**Owner identification — do not trust the process name.** F7: `comm` is truncated to 15
characters, so `systemd-resolved` renders as `systemd-resolve`, colliding with the legacy
CLI tool's real name. Resolve the binary via `readlink /proc/<pid>/exe`, falling back to
`/proc/<pid>/cmdline`, and classify from that. Record pid, resolved binary path, and the
bound address/port for every listener.

**Classification.**

- `127.0.0.53:53` → systemd-resolved stub
- `127.0.0.1:53` (or another loopback address) → a local forwarder; identify which from
  the binary path, and do not assume it is dnsmasq
- `0.0.0.0:53` / `[::]:53` → a DNS *server* that may serve a LAN rather than being the
  host's own resolver. Record it; do not conclude it is the system resolver on this
  evidence alone.
- Nothing bound, but the effective `resolv.conf` points at a loopback address →
  **broken state**: report loudly with the specific mismatch. This misconfiguration
  silently defeats every backend and is worth catching before a tunnel comes up.
- More than one listener → report all of them; do not silently pick.

**Standing.** This is a survey input of equal weight, not an override. Where it
disagrees with the classification derived from the file survey or the NM `RcManager`
probe, that disagreement is itself a reportable finding and must appear in
`racoon-dns-detect --detect` output with both conclusions and their evidence. Do not
resolve the conflict silently.

**Degradation without root.** `ss` omits process information for sockets the caller does
not own, so `--detect` run as an unprivileged user will see the listener but not its
owner. Record `owner=unknown`, state in the output that running as root gives a complete
answer, and do not fail.

**New fixtures** (in addition to the existing ten):
11. resolved stub only, single listener on `127.0.0.53` (matches the Bionic evidence)
12. dnsmasq on `127.0.0.1:53` with a static `/etc/resolv.conf` — the case only this
    check can detect
13. resolved and a second forwarder both bound — conflict reporting
14. nothing bound, `resolv.conf` → `127.0.0.53` — broken-state reporting
15. `ss` output without process columns — unprivileged degradation

## D. FIFO state matching (supersedes brief 2 §C)

Brief 2 recommended keying the connection id on the remote address alone with a
"single state file" fallback. **The Bionic log invalidates that fallback.** At
12:29:45–46, `phase1-down` for the old SA and `phase1-up` for the new one ran within one
second of each other for the same peer address. A single-file fallback can match a
teardown to a live tunnel's state and dismantle it.

- Drop `REMOTE_PORT` from the identity as previously specified — it floats 500→4500 and
  changes on NAT rebind.
- State files carry a **monotonic generation**. `phase1-up` always writes a new file.
  `phase1-down` consumes the **oldest unconsumed** file for that peer address.
- FIFO is correct under overlap in both orderings and requires no identifier racoon does
  not export. Racoon exports no ISAKMP SPI to hooks — confirm this in
  `src/racoon/isakmp_cfg.c` / `script_hook()` and record the finding; if a usable unique
  identifier *is* available, prefer it and say so.
- Mark consumed files rather than deleting immediately, so an interrupted teardown stays
  retryable; delete on successful completion.
- Reap stale/consumed files by count and age (suggest 5 / 24 h), oldest first, at every
  `phase1-up`.
- Tests: interleaved up/down for the same peer in both orderings; a rapid
  connect/disconnect/reconnect sequence modelled on the observed log timing; reaper
  honours both caps.

## E. SPD ownership — R2' (carried from brief 2 §A, reinforced by F1/F4)

Brief 1's R2 ("never touch SPD") was wrong for the roadwarrior-client case. A Mode Config
client's policies use `INTERNAL_ADDR4` as a selector, so they cannot come from a static
`setkey.conf`, and racoon does not install them for an initiator. The reconnect loop in
F1 is the direct consequence of a policy nobody removes.

**Verify first**, in `src/racoon/isakmp_cfg.c`, `src/racoon/pfkey.c`, `src/racoon/isakmp.c`:
(a) no code path installs SPD entries for an initiator that received a Mode Config
address, and (b) `generate_policy` is responder-only. If either is false, stop and report.

Then:

1. The hook installs SPD entries and owns **exactly** those it installed.
2. Each entry is recorded in state with full selector text, sufficient to construct the
   matching `spddelete` verbatim.
3. Teardown issues one `spddelete` per recorded entry, through `run_step()`.
4. **Never `spdflush`** — the old generated `spd.conf` began with it, destroying
   admin-configured and third-party policies.
5. **Never `setkey -F`** — that is the SAD, and it is racoon's exclusively. The old
   `phase1-down.sh` called it under a comment claiming it flushed SPD.
6. Any generated policy file lives in `/run/racoon/`, never `/etc/racoon/`.
7. Peer-supplied selectors are validated per brief 1 §4 **before** any `spdadd` text is
   constructed. A newline in a Mode Config value would otherwise inject arbitrary setkey
   directives into a file that is then executed. Highest-severity finding in the
   subsystem; unchanged.
8. Teardown order: **DNS → SPD → routes → address → dummy → state file.** SPD before
   routes, because a `require` policy with no route and no SA is the configuration most
   likely to generate the spurious ACQUIREs of F1.

Also settle, by reading `src/libipsec/policy_parse.y` and `policy_token.l`, whether
`esp/tunnel/LOCAL[port]-REMOTE[port]` is accepted for **tunnel endpoints** (as opposed to
selectors, where the bracket form is well established). If it is not, the old script's
NAT-T branch was producing policies that parsed differently than its comment claimed —
report which.

Tests: SPD plan construction per fixture; exact `spddelete` inverse in the round-trip
suite; injection regression asserting a newline-bearing selector never reaches the
generated file.

## F. Narrowed investigation: where does the ACQUIRE-triggering policy come from?

Brief 2's package B is closed by F1/F2 except for one question. In the test run, Phase 2
succeeded although the hook installs no SPD — so a policy existed from elsewhere.

- Capture `setkey -DP` before connect, after connect, and after disconnect on the Bionic
  host, and identify the policy that matched the ACQUIRE.
- Determine its provenance: static `/etc/ipsec-tools.conf`, a leftover from an older run
  of the pre-rewrite scripts, or racoon itself.
- If it is static admin configuration, document in the Admin Guide that static `require`
  policies and Mode Config clients do not mix: after an explicit disconnect the kernel
  will keep asking for the tunnel back. R2' is the supported arrangement.
- Record the outcome in `doc/dev/teardown-investigation.md` together with F1/F2/F5, and
  state explicitly which observations turned out to be correct-by-design. The goal is
  that none of this gets re-diagnosed as a bug in six months.

## G. Daemon-side issues — file, do not fix here

Two C-side defects. Open each as a separate issue with a reproducer drawn from the Bionic
log. **Do not modify daemon code in this work package.**

1. **stderr block buffering under `-F` (F5).** Proposed fix: `setlinebuf(stderr)` (or
   `setvbuf(…, _IOLBF, 0)`) early in `main()`. Include the decision question: should
   foreground mode log to syslog *and* stderr when stderr is already being captured by
   systemd? The duplication is half the noise.
2. **Shutdown bypasses `script_hook(SCRIPT_PHASE1_DOWN)` (F2).** Trace which teardown
   paths reach the hook — admin `vpn_disconnect`, phase-1 expiry, peer delete-notify,
   retransmit timeout, `flushph1()` on shutdown — and report the matrix in the issue. If
   the shutdown bypass is deliberate, it belongs in the Admin Guide rather than in a
   patch; if not, it leaves the dummy, the `/32` and all routes installed after
   `systemctl stop racoon`, which is what the test run showed.

Also worth one issue or one guide paragraph: **F8**, the per-Phase-2
`authtype mismatched: my:hmac-sha256 peer:hmac-sha512` warning — determine whether the
mismatch is silently accepted and what is actually negotiated.

## H. `on_dns_failure = abort` must not promise what it cannot deliver

Racoon does not reject an established Phase 1 SA based on a hook's exit status, so
`abort` does not currently prevent the tunnel from carrying traffic with unprotected name
resolution. Choose one and report which:

- **Fail-closed**: undo everything applied, then request disconnection via
  `racoonctl vpn-disconnect <gateway>`. Verify first that this is reachable from inside a
  hook — it needs the admin socket enabled, and may deadlock if the hook is invoked
  synchronously from the daemon's own path. If it is not safely reachable, say so and
  take the other option rather than shipping a best-effort version.
- **Rename honestly**: e.g. `report | rollback`, where `rollback` undoes the hook's own
  changes and exits non-zero but makes no claim about the tunnel. Document the residual
  exposure in one blunt sentence in both `hooks.conf.sample` and the Admin Guide.

Config sample, Admin Guide and code must agree exactly.

## I. Gate the fallback backend behind explicit opt-in

The fallback backend overwrote a live `/etc/resolv.conf` during manual testing — the most
destructive path in the tree is reachable by accident with no confirmation.

- New key `allow_resolv_conf_overwrite = yes|no`, **default `no`**.
- When `no`: the step is planned and reported as `skipped`, reason
  "fallback backend disabled by configuration (allow_resolv_conf_overwrite=no)", impact
  "no split-DNS; internal names resolve via the public resolver", plus a pointer to the
  setting.
- When `yes`: current behaviour including the checksummed backup.
- `racoon-dns-detect --detect` reports in its capability block when the only available
  backend is gated off, so an admin sees it before a tunnel comes up.
- Document prominently in both the sample and the guide.

## J. Assert stderr cleanliness in every suite

The `grep -c` double-count bug survived because no test looked at stderr.

- One helper in the harness; after every script invocation in every suite, assert stderr
  contains none of: `Illegal number`, `not found`, `unbound variable`, `bad substitution`,
  `Syntax error`, `cannot open`, `arithmetic`.
- All suites, under `sh` and `dash`, and on NetBSD's `/bin/sh` in CI.
- Legitimate stderr output opts out via a documented per-test allow-list, never by
  disabling the check globally.

## K. Record the dummy interface's owner in state

Created by NetworkManager (profile) on the NM path, by `ip link add` on the resolved path.
Teardown must not `ip link del` a device NM owns.

- State records `dummy_owner = nm | iproute`; teardown replays the matching undo purely
  from state, with no re-detection.
- Round-trip tests for both owners.
- Confirm that with the real Mode Config address now on the dummy, NM's `ipv4.addresses`
  and the address the routes reference come from the same variable, and that
  `ipv4.may-fail` / `ipv4.never-default` still behave as intended with a routable address.

## L. Packaging wiring (v0.9.0 blocker)

Does not require building the C tree to validate.

- `Makefile.am` under `src/racoon/scripts/` (component ownership; not `src/scripts/`),
  installing to `$(pkgdatadir)/scripts/` with correct modes; `racoon-dns-detect` into
  `$(bindir)`.
- `hooks.conf.sample` into `$(sysconfdir)/racoon/`, as a sample only — never overwriting
  an existing `hooks.conf`.
- `configure.ac` `AC_CONFIG_FILES` / `SUBDIRS` entry.
- `debian/racoon.install` and the Arch `PKGBUILD` `package()` updated.
- `make distcheck` if it runs in this environment; if not, say so and list what remains
  unverified.
- Release note: the hooks have moved out of `src/racoon/samples/roadwarrior/client/` and
  are now installed, supported code. Anyone who copied the old samples into
  `/etc/racoon/` will otherwise keep a stale copy shadowing the shipped one.

## M. Admin Guide additions

Beyond the chapter specified in brief 1:

- **Pin racoon's listeners.** F6: creating the dummy from the hook makes racoon re-scan
  interfaces mid-negotiation and bind ISAKMP sockets to it on every reconnect. Recommend
  a `listen { isakmp <local-ip>[500]; isakmp_natt <local-ip>[4500]; }` stanza for any
  deployment using these hooks, and explain why.
- **Static `require` policies and Mode Config clients do not mix** (per §F).
- **After `systemctl stop racoon`, hook-installed state may remain** (F2) — with the
  manual cleanup command, until the daemon issue is resolved.
- **Reading racoon logs under systemd** (F5): until fixed, racoon's own log lines may be
  delayed, duplicated and torn; hook output via `logger` is reliable. Say this plainly,
  because it will otherwise mislead every future diagnosis.
- **The port-53 ownership table** from §C, including the broken-state case.
- **Bionic/systemd 237 limitations**: no `resolvectl`, no `--set-default-route`, and
  whatever §B.3 concludes about scoping on that platform.

---

# Order of work

A → B → C → D → E, then F (needs a live host), then G–M in any order.

A and B together fix the loop observed in F1 and should be validated on the Bionic host
before anything else lands. E changes teardown ordering, so re-run the Bionic scenario
after it.

# Final report

As before: every `# UNVERIFIED:` marker and what would settle it; every design question
resolved independently and the choice made; test and fixture results; and anything in
**this** brief that proved wrong against reality. In particular, §E rests on a claim
about racoon's client-side policy handling that you are asked to verify before
implementing, and §B.3 rests on untested assumptions about what `systemd-resolve` on
systemd 237 will accept.
