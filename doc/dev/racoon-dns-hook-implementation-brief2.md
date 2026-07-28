# Follow-up brief: SPD ownership, teardown investigation, and open items

Continuation of the split-DNS/routing hook work in `rdratlos/racoon-ipsec-tools`.
The implementation report for the first brief is accepted. This brief covers one
**correction to that brief**, one **investigation**, and six open items.

Working rules from the first brief still apply in full: no guessed syntax
(`# UNVERIFIED:` markers instead), no GPL code, POSIX `sh`, `shellcheck` clean,
ask rather than invent policy, and preserve the field-evidence comments.

Work package A is a correctness regression and comes first. Work package B is an
investigation whose outcome may change packages C onward — **do not write fixes for B
before the evidence in B.2 has been collected.**

---

## A. Correction to R2: the hook owns the SPD entries it creates

The first brief's R2 ("never touch SAD or SPD from the hook") was wrong for the
roadwarrior-client case and must be amended. The reasoning behind it — a shell script
must not race the daemon, and blanket flushes destroy other consumers' state — is
still correct. The conclusion drawn from it was not.

**Why it was wrong.** A Mode Config client's IPsec policies use `INTERNAL_ADDR4` as a
selector. That address does not exist until Phase 1 and Mode Config complete, so the
policies cannot come from a static `setkey.conf`, and racoon does not install them
itself in initiator/client mode (`generate_policy` is a responder-side feature).
Userspace must install them. Removing SPD generation from `phase1-up.sh` without a
replacement therefore leaves the client with a tunnel that carries no traffic.

**Verify this before acting on it.** Read `src/racoon/isakmp_cfg.c`, `src/racoon/pfkey.c`
and `src/racoon/isakmp.c` and confirm: (a) no code path installs SPD entries for an
initiator that received a Mode Config address, and (b) `generate_policy` is responder-only.
If either turns out to be false, stop and report — the rest of this package changes.

**Amended rule (R2'):**

1. The hook installs SPD entries and owns **exactly** the entries it installed.
2. Every installed entry is recorded in the state file with its full selector text,
   sufficient to construct the matching `spddelete` verbatim.
3. Teardown issues one `spddelete` per recorded entry, through the normal
   `run_step()` machinery so each deletion appears in the report.
4. **Never `spdflush`.** The old generated `spd.conf` began with `spdflush;`, which
   destroys admin-configured and third-party policies. Remove it. Generate no file that
   contains it.
5. **Never `setkey -F`.** SAD remains racoon's exclusively. The old `phase1-down.sh`
   called `setkey -F` under a comment claiming it flushed SPD; it flushed the SAD
   instead, which is both the wrong table and a blanket operation.
6. The generated policy file, if one is kept for inspectability, lives in
   `/run/racoon/`, never `/etc/racoon/` (R8 unchanged).
7. Peer-supplied selectors are validated per §4 of the first brief **before** any
   `spdadd` text is constructed. A newline inside a Mode Config value would otherwise
   inject arbitrary setkey directives into a file that is then executed. This is
   unchanged and remains the highest-severity finding in the whole subsystem.
8. Teardown ordering becomes: **DNS → SPD (per-entry delete) → routes → address →
   dummy interface → state file.** Rationale for SPD before routes: a `require` policy
   with no route and no SA is the configuration most likely to generate spurious
   kernel ACQUIREs (see B).

Also verify and document, in a code comment, whether `esp/tunnel/LOCAL[port]-REMOTE[port]`
is accepted syntax for **tunnel endpoints** (not selectors) by this tree's own parser.
The port-in-brackets form is well established for selectors; for tunnel endpoints it is
not confirmed. Read the grammar in `src/libipsec/policy_parse.y` and
`src/libipsec/policy_token.l` and settle it. If ports are not accepted there, the NAT-T
branch in the old script was silently producing policies that either failed to parse or
parsed differently than intended — report which.

Add tests: SPD plan construction per fixture, exact `spddelete` inverse in the round-trip
suite, and an injection regression asserting that a newline-bearing selector never
reaches the generated file.

---

## B. Investigation: SA/SPD survive `racoonctl vd`

**Reported symptom.** `racoonctl vc` followed by `racoonctl vd`; an `isakmp`/`setkey`
inspection afterwards showed SAs and policies still present. Racoon was then stopped
completely. The maintainer reports having seen something similar occasionally with the
old scripts — i.e. the behaviour may be **intermittent**, which is itself evidence and
points toward a race or a renegotiation rather than a straightforward missing delete.

**This is an investigation, not a bug fix.** Produce a written findings document
(`doc/dev/teardown-investigation.md`) with evidence for or against each hypothesis
below. Do not modify daemon C code in this package. If a daemon defect is confirmed,
file it as a separate CWE-mapped issue with a reproducer, and stop.

### B.1 First discriminator

Before anything else, determine whether the surviving SAs are **stale** or **new**:

```
setkey -D          # read the 'created:' timestamp of each surviving SA
setkey -DP         # read policies, their spid, and 'created'/'lastused'
```

- `created` **newer** than the `racoonctl vd` ⇒ the SAs were deleted and immediately
  re-negotiated. This is a reconnect loop, not a teardown failure. Go to H1.
- `created` **older** ⇒ genuine teardown failure. Go to H2–H5.

Record both outputs verbatim, with timestamps, before and after the disconnect.

### B.2 Evidence to collect (all of it, before drawing conclusions)

1. Racoon in the foreground at maximum verbosity (`racoon -F -ddd`), full log across
   connect → disconnect → post-disconnect idle period of at least 2 minutes.
2. `setkey -D` and `setkey -DP` at four points: before connect, after connect, 5 s after
   disconnect, 120 s after disconnect.
3. `racoonctl show-sa isakmp` and `racoonctl show-sa esp` at the same four points.
4. Whether `phase1-down.sh` ran at all: `journalctl -t racoon-phase1-down` (and the
   trace file at `debug_level=3`).
5. The **complete environment** the hook received. Add a level-3 trace line dumping every
   `INTERNAL_*`, `SPLIT_*`, `LOCAL_*`, `REMOTE_*` and `DEFAULT_DOMAIN` variable at hook
   entry, including the ones that are empty. Empty-versus-absent is the distinction that
   matters here.
6. `privsep` setting in `racoon.conf`, and whether the log shows the hook being spawned.
7. NAT-T status: negotiated ports, whether the peer was detected behind NAT.

### B.3 Hypotheses

**H1 — Leftover `require` policy causes kernel ACQUIRE and racoon renegotiates.**
The prime suspect, and it explains intermittency. The old `phase1-down.sh` ran
`setkey -F` (SAD) and never `-FP` (SPD), so policies always survived teardown. A
surviving `require` policy with no SA makes the kernel emit an ACQUIRE for any matching
packet, and a running racoon answers it by rebuilding the tunnel. Discriminators:
`created` timestamps per B.1; racoon log lines about ACQUIRE / queued IPsec-SA requests /
initiating a new phase 2 *after* the disconnect. If confirmed, A.8's ordering and the
per-entry `spddelete` are the fix, and the daemon is behaving correctly.

**H2 — The phase1-down hook is never invoked on this teardown path.** Trace where
`script_hook(iph1, SCRIPT_PHASE1_DOWN)` is actually called in `src/racoon/isakmp.c`
(`isakmp_ph1delete()` / `remove_ph1()`) and determine which teardown paths reach it:
admin `vpn_disconnect`, phase-1 expiry, delete-notify from the peer, retransmit timeout,
and daemon shutdown via `flushph1()`. Report the matrix. If the shutdown path bypasses
the hook, that is expected-but-undocumented and belongs in the Admin Guide, not in a
patch.

**H3 — The hook runs, but with no Mode Config environment.** If the `mode_cfg` state is
released before the hook fires, `INTERNAL_ADDR4` and friends arrive empty. The old
script's guard (`[ -z "$INTERNAL_ADDR4" ] && exit 0`) then exits cleanly having done
nothing — silently. The new design already guards on state-file presence instead, which
would mask this bug rather than fix it, so it must be confirmed or excluded explicitly.
Evidence: B.2 item 5.

**H4 — `purge_remote()` fails to match the SAs.** Read it in `src/racoon/pfkey.c` and
determine what it matches on, then compare against the actual SA addresses under NAT-T
(where outer addresses and ports may differ from what the lookup expects). Also check
how `vpn_disconnect` locates the Phase 1 handle — if by address alone, confirm behaviour
when the peer floated to port 4500.

**H5 — Shutdown does not flush, by design.** Racoon does not flush SAD or SPD on exit.
"Stopped racoon, entries still present" is therefore likely correct behaviour and not a
second defect. Confirm from `close_session()` in `src/racoon/session.c` and state it
plainly in the findings — the goal is to stop this observation being re-diagnosed as a
bug in six months.

**H6 — privsep interferes with hook execution.** If `privsep` is enabled, confirm the
hook is spawned and its exit status observed. A silent failure here would be invisible
in the current logging.

### B.4 Output

`doc/dev/teardown-investigation.md`: evidence, hypothesis-by-hypothesis verdict,
the reproducer if one was found, and an explicit statement of which observations turned
out to be correct-by-design. Anything requiring a C change becomes a separate issue with
a reproducer, not a patch in this package.

---

## C. Connection identity must survive a port change

`rhook_conn_id()` currently uses sanitized `REMOTE_ADDR-REMOTE_PORT`. The port is
exactly the value most likely to differ between phase1-up and phase1-down (NAT-T float
500→4500, NAT rebind, keepalive gap). A changed port yields a different id, teardown
looks for a state file that does not exist, and nothing is cleaned up — silently,
which is the failure mode the state file exists to eliminate.

- Key on the remote **address** only; drop the port.
- Add a fallback: no exact match but exactly one state file present ⇒ use it and log
  that a fallback match was taken, at `warn`.
- More than one state file and no exact match ⇒ do not guess; report and apply the
  failure policy.
- Reap `.stale.$$` archives: cap by count and age (suggest 5 / 24 h), oldest first, at
  every phase1-up. A client that reconnects all day currently grows `/run/racoon`
  without bound.
- Tests: same address different port round-trips successfully; two state files with no
  exact match refuses cleanly; reaper honours both caps.

---

## D. `on_dns_failure = abort` must not promise what it cannot deliver

The report established that racoon does not reject an established Phase 1 SA based on a
hook's exit status. So `abort` currently does not prevent the tunnel from carrying
traffic with unprotected name resolution — which is the only reason the setting exists.
A security knob whose name implies fail-closed while the tunnel comes up regardless must
not ship. Choose one:

**Option 1 — make it genuinely fail-closed.** On a required-step failure, undo everything
applied so far, then request disconnection via `racoonctl vpn-disconnect <gateway>`.
Verify first whether that is reachable from inside a hook: it needs racoon's admin socket
enabled and appropriate permissions, and it may deadlock if the hook is invoked
synchronously from the daemon's own path. If it is not safely reachable, say so and take
Option 2 rather than shipping a best-effort version.

**Option 2 — rename and document honestly.** e.g. `on_dns_failure = report | rollback`,
where `rollback` undoes the hook's own changes and exits non-zero but does not claim to
stop the tunnel. Document the residual exposure in one blunt sentence in both
`hooks.conf.sample` and the Admin Guide: with the tunnel up and split-DNS not applied,
internal names are resolved by the public resolver.

Whichever is chosen, the Admin Guide text and the config sample must agree with the code
exactly. Report which option was taken and why.

---

## E. Gate the fallback backend behind explicit opt-in

The report records that the fallback backend overwrote a live `/etc/resolv.conf` during
manual testing. That is useful evidence: the most destructive path in the tree is
reachable by accident with no confirmation, and it can take a machine off the network.

- New key `allow_resolv_conf_overwrite = yes|no`, **default `no`**.
- When `no`, the fallback DNS step is planned and reported as `skipped`, reason
  "fallback backend disabled by configuration (allow_resolv_conf_overwrite=no)",
  impact "no split-DNS; internal names resolve via the public resolver", plus a one-line
  pointer to the setting.
- When `yes`, behaviour is as now, including the checksummed backup.
- `racoon-dns-detect --detect` reports, in the capability block, that the only available
  backend is gated off — so an admin sees it before a tunnel ever comes up rather than
  discovering it in a report afterwards.
- Document prominently in `hooks.conf.sample` and the Admin Guide. This is the setting
  most likely to be enabled by someone who has not read the consequences.

---

## F. Assert stderr cleanliness in every suite

The `grep -c` double-count bug survived because the tests exercised the code path but
never looked at stderr; it took a real `dash` run to surface it. Close the class:

- One helper in the test harness. After every script invocation in every suite, assert
  stderr contains no shell diagnostic: `Illegal number`, `not found`, `unbound variable`,
  `bad substitution`, `Syntax error`, `cannot open`, `arithmetic`.
- Apply to all eight suites, under both `sh` and `dash`, and on NetBSD's `/bin/sh` in CI.
- Where a test legitimately expects stderr output, it must opt out explicitly with a
  documented allow-list, never by disabling the check globally.

---

## G. Record the dummy interface's creator in state

The dummy is created by NetworkManager (via the connection profile) on the NM path and by
`ip link add` on the resolved path. Teardown must not `ip link del` a device NM owns —
NM will fight it or recreate it, and the report will claim a success that did not happen.

- State file records `dummy_owner = nm | iproute`.
- Teardown replays the matching undo (`nmcli connection down`+`delete` versus
  `ip link del`) purely from state, with no re-detection.
- Round-trip tests cover both owners.
- While here: confirm that with the real Mode Config address now on the dummy (rather
  than the old placeholder `169.254.66.13/32`), NM's `ipv4.addresses` on the profile and
  the address the routes reference are the same value from the same variable, and that
  `ipv4.may-fail`/`ipv4.never-default` still behave as intended with a routable address.

---

## H. Packaging wiring (v0.9.0 blocker)

Deferring this was the right call for the first pass, but it does not need the C tree to
be built to be validated:

- `Makefile.am` under `src/racoon/scripts/` (note: `src/racoon/scripts/`, not
  `src/scripts/` — component ownership), installing to `$(pkgdatadir)/scripts/` with
  correct modes; `racoon-dns-detect` into `$(bindir)`.
- `hooks.conf.sample` into `$(sysconfdir)/racoon/`, installed as a sample only — never
  overwriting an existing `hooks.conf`.
- `configure.ac` `AC_CONFIG_FILES` / `SUBDIRS` entry.
- `debian/racoon.install` and the Arch `PKGBUILD` `package()` updated for the real paths.
- Validate with `make distcheck` if it runs in this environment; if it does not, state
  that plainly and list exactly what remains unverified.
- Add the release-note line: the hooks have moved out of
  `src/racoon/samples/roadwarrior/client/` and are now installed, supported code. Anyone
  who copied the old samples into `/etc/racoon/` will otherwise keep a stale copy that
  shadows the shipped one.

---

## Order of work

A → B → C, D, E, F, G, H in any order. A and B may interact: if B confirms H1, A.8's
ordering is part of the fix, so land A first and re-test B against it.

## Final report

As before: `# UNVERIFIED:` markers and what would settle each; design questions resolved
independently and the choice made; test results; and anything in **this** brief that
proved wrong against reality — in particular, the R2' reasoning in package A rests on a
claim about racoon's client-side policy handling that you are asked to verify first. If
that claim is false, say so plainly and stop before implementing.
