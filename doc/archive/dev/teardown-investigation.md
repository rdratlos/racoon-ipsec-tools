> **Archived.** Superseded by [doc/dev/v0.9.1-hardening-spec.md](../../dev/v0.9.1-hardening-spec.md)#57-teardown--acquire-provenance-investigation-issue-90 as of 2026-08-04; retained for provenance. See also git tag `archive/pre-doc-consolidation`.

# Teardown / reconnect-loop investigation (brief 3 §F)

Tracks the live Bionic finding chain (F1 → F3 → F4) and §F's own
ACQUIRE-provenance question, now resolved against live evidence (see
below). Companion to `doc/dev/daemon-issues.md` (F2, F5, F8, and now a
Task-F-sourced Issue 4 — daemon-side issues filed, not fixed) and
`doc/admin/split-dns.html` (the shipped behavior after A–E landed).

## What the live test actually showed (F1)

The first live run on the Bionic roadwarrior looked like "SAs are not
removed on teardown." Investigation (§ Part I, finding F1) established
this was not a teardown defect: the daemon's own Phase 1 teardown is
correct (`close_session()`/`flushph1()`/`delph1()` do run, modulo the
F2 race documented separately). What was actually observed was a
**reconnect loop** — a new Phase 1 negotiation starting up again shortly
after a clean disconnect, which looks identical to "the SA never went
away" from the outside if you're only watching `setkey -D` at coarse
intervals.

## Root cause chain (F3 → F4), now fixed

1. **F3**: the hooks' own DNS-effectiveness postcondition
   (`rhook_postcond_set_dns()` pre-brief-3) checked
   `/run/systemd/resolve/stub-resolv.conf` for evidence that a per-link DNS
   server had been applied. On Bionic (systemd 237, `systemd-resolve` only,
   no `resolvectl` binary), that file can *never* contain a real per-link
   server by design — it always reads `nameserver 127.0.0.53`. Every
   `resolved`-backend run therefore reported the DNS step as **FAILED**
   regardless of whether `systemd-resolve --set-dns=...` actually applied.
2. **F4**: brief 1's original apply loop had no DNS-group rollback. A false
   FAILED from F3, arriving *after* the DNS server had already been
   registered with `systemd-resolve` but *before* routing-domain/
   default-route scoping was applied (or on a system where scoping
   couldn't be applied at all), left an **unscoped** VPN DNS server
   registered on the link. Traffic reaching that resolver outside of an
   established SA (a query the still-partially-configured link sent to it,
   or anything else routed toward it once the split-include route was also
   up) had no matching SPD entry to satisfy over the tunnel, which the
   kernel resolves by emitting an `ACQUIRE` — and an `ACQUIRE` for a peer
   racoon is already configured to handle typically triggers a fresh Phase
   1/Mode Config negotiation. That new negotiation looks, from a coarse
   external view, exactly like "the old SA never tore down": a session for
   the same peer is live again moments after teardown.

Both are fixed as of brief 3 §A/§B:

- §A rewrote the effectiveness check to key off `RHOOK_DNS_TOOL` (which
  tool the plan actually selected — `resolvectl` or `systemd-resolve`) and
  check that tool's own per-link `--status`/`status <iface>` output via
  `rhook_dns_status_has()`, never the stub file, whenever the `resolved`
  backend (or an active `nss-resolve` entry) is in play. This eliminates
  the false FAILED from F3 outright.
- §B reordered DNS steps so scope (routing domains, or
  `default-route=no` when no domains are available) is planned and applied
  *before* DNS servers wherever at least one scoping mechanism exists, and
  added in-transaction rollback (`rhook_apply_plan()`'s DNS-group
  tracking) so a required DNS-group failure undoes every DNS-group step
  already applied in that run, in reverse order, before returning. A link
  now ends a run either fully configured or completely untouched — the
  "unscoped server left registered" state F4 depended on can no longer
  occur as an intermediate state.

§E (SPD ownership, R2') closes the remaining half of the mechanism: even
with F3/F4 fixed, split-include *routing* traffic still had no SPD entry
telling the kernel to encrypt it (verified against `isakmp_quick.c`: SPD
generation for a Mode Config initiator never happens — see
`src/scripts/racoon-hook-lib.sh`'s `rhook_plan_spd()` header comment for
the full citation chain). The hook now installs and owns exactly the SPD
entries its own routes need, which is what actually prevents an
`ACQUIRE` from being generated for in-tunnel traffic in the first place,
rather than only preventing one specific way of accidentally routing
traffic to an unscoped resolver.

## §F resolved: ACQUIRE-provenance investigation

**Verdict: Branch B.** No external mechanism reinstalls or leaves behind
an SPD policy after a clean teardown. On-demand reconnection after
`phase1-down.sh` completes is simply not implemented (no arm/disarm
step exists in the current design) — that is the entire explanation for
what F1 originally observed. Branch A (some other path — NetworkManager,
a stray `ipsec-tools` init script, `racoon.conf`'s own `generate_policy`,
or a leftover static policy — independently installing a policy that
outlives teardown) is ruled out.

### Method

A dedicated investigation script
(`task-f-acquire-investigation.sh`, evolved through three revisions
against real evidence, see below) was run against live IPsec-capable
hosts — this repo's own sandbox has `CONFIG_NET_KEY`/`CONFIG_INET_ESP`
both unset and cannot run PF_KEY at all, so this genuinely required an
external host. Each run: capability preflight; a hard-stop guard against
a pre-existing racoon instance; baseline `setkey -DPN` (kernel-native
per-socket-policy filtering, not a custom `awk` postprocess — see the
script's own comments for why); connect, waiting for `phase1-up.sh`'s own
completion summary in syslog rather than trusting `racoonctl vpn-connect`
returning (`script_hook()` forks and returns immediately without waiting
for the child — confirmed against `isakmp_cfg.c`, `isakmp.c`, and
`privsep.c` — so "vpn-connect returned" and "the hook actually finished"
are two different moments); a connected-state SPD/hook-state snapshot;
disconnect, with the same wait discipline for `phase1-down.sh`
(`isakmp_ph1delete()`: `evt_phase1(EVT_PHASE1_DOWN)` — what
`vpn-disconnect` blocks on — fires *before* `delph1()` calls
`script_hook(SCRIPT_PHASE1_DOWN)`); a filtered SPD snapshot immediately
after that confirmed completion (**the fork in the road** — Branch A if
non-per-socket policy remains, Branch B if empty); and, in the Branch B
case, a scripted `ping` to an internal host behind the tunnel specifically
to provoke an `ACQUIRE`, with an 8s syslog watch afterward.

### Results: 8 live runs, Branch B in every one

| Host | Backend | Branch | ACQUIRE after provocation ping |
| :--- | :--- | :--- | :--- |
| Bionic i386 | NetworkManager, `rc-manager=unmanaged` | B | no |
| Bionic i386 | no NetworkManager, pure `systemd-networkd` | B | no |
| Noble | NetworkManager, `rc-manager=unmanaged` | B | no |
| Noble | no NetworkManager, pure `systemd-networkd` | B | no |
| Noble | NetworkManager, `rc-manager=auto` | B | no |
| Arch | NetworkManager, `rc-manager=unmanaged` | B | no |
| Arch | NetworkManager, `rc-manager=unmanaged` (rerun) | B | no |
| Arch | NetworkManager, `rc-manager=auto` | B | no |

Every run: `phase1-up.sh`/`phase1-down.sh` completion independently
confirmed via syslog (not inferred from `racoonctl`'s return), filtered
SPD (`setkey -DPN`, per-socket noise excluded at the kernel level) empty
after teardown, and no `ACQUIRE`-related log line in the post-ping window.
Three different distros, two different DNS/network-management backends,
one host retested from a fresh reboot — the result did not vary once.

**On the `rc-manager=auto` runs specifically**: both show
`rc-manager=unmanaged` in the live `busctl get-property ... RcManager`
ground-truth capture despite `auto` being correctly configured on disk
and the host freshly rebooted before the test — this is not a
misconfiguration. Confirmed against NetworkManager's own
`src/core/dns/nm-dns-manager.c` (`init_resolv_conf_mode()`):

```c
if (rc_manager == NM_DNS_MANAGER_RESOLV_CONF_MAN_AUTO) {
	rc_manager_was_auto = TRUE;
	if (nm_streq(mode, "systemd-resolved") || nm_streq(mode, "dnsconfd"))
		rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_UNMANAGED;
	else if (HAS_RESOLVCONF && g_file_test(RESOLVCONF_PATH, G_FILE_TEST_IS_EXECUTABLE))
		rc_manager = NM_DNS_MANAGER_RESOLV_CONF_MAN_RESOLVCONF;
	...
}
```

Both hosts run with DNS mode `systemd-resolved` (confirmed in the same
snapshot), so `auto` deterministically collapses to `unmanaged` at
NetworkManager's own runtime resolution — on any modern systemd-resolved
based desktop, `rc-manager=auto` and `rc-manager=unmanaged` are the same
thing in practice. The two `auto` runs are legitimate, correctly-configured
confirmations that happen to be behaviorally identical to the
`rc-manager=unmanaged` runs, not duplicates by mistake.

### Why the very first two archives showed a real ACQUIRE, and this isn't a contradiction

The investigation script's first version, run against Bionic before any
of the fixes below, *did* show a genuine, reproducible, gateway-directed
`ACQUIRE` roughly 15 seconds after a scripted disconnect — the opposite
of the verdict above. Close reading of those two archives (not guessing)
found two contamination sources in the script itself, both since fixed:

1. **No guard against a pre-existing racoon.** Both archives showed two
   concurrent racoon processes — the system's own already-running
   `racoon.service` plus the script's freshly-started instance — both
   registered as PF_KEY listeners simultaneously, making SPD/SA
   attribution ambiguous by construction.
2. **A disconnect-side completion check that could never pass.** The
   original wait grepped syslog for the hook's `"racoon phase1-down
   report --"` header text. That header is only emitted at hook debug
   level ≥ 1 (`racoon-hook-lib.sh`); the default is 0 ("syslog only: the
   final one-line summary"). Under default settings the check was
   structurally a no-op — the script proceeded to snapshot the SPD without
   ever actually confirming the hook had finished.

Once both were fixed (a hard-stop guard, and waiting on the hook's
*always-emitted* one-line `result: OK|PARTIAL` summary instead), the
`ACQUIRE` stopped appearing — in all 8 subsequent runs, with no
exceptions. That is not, by itself, proof of *which* defect caused the
original `ACQUIRE`. The original archives had at least two sufficient
causes present simultaneously: the dual-racoon/no-op-wait contamination
above, and the F3/F4 unscoped-resolver path (real, source-confirmed,
independently fixed by §A/§B). Both were closed off by the time the 8
clean runs happened, so a clean result is consistent with either one (or
both) having been the actual cause of the original symptom — this
evidence cannot isolate which, and no capture exists with only one of the
two fixes applied at a time, which is what isolating them would require.
This does not matter for the verdict: Branch B rests on the current,
fixed configuration's own SPD state and the absence of `ACQUIRE` after a
clean teardown, not on settling which defect explains the original,
already-resolved symptom.

### A related, separate finding surfaced during this investigation

Reading a live Arch host's `/run/racoon/hook-state.*` directory (accumulated
over several manual test sessions) found 5 generation files for one peer,
only 2 marked `.consumed` — three complete, successful connection states
were never torn down. This is expected under `rhook_state_reap()`'s
documented design (it deliberately never deletes *live* files, only aged
`.consumed` ones), but combined with `rhook_state_oldest_unconsumed()`'s
strict oldest-generation-first matching, means a `phase1-down.sh` run can
consume an *orphaned* generation from an earlier, uncleaned session instead
of its own — invisible whenever every session's undo commands are
byte-identical (same `racoon.conf` every time, as in all 8 runs above),
but a real correctness gap if they ever differ. Tracked separately — see
the FIFO generation follow-up issue — since it's a hook-library
correctness question, not part of the ACQUIRE-provenance answer itself.
A generation-verification step (`task-f-acquire-investigation.sh` step 5b)
was added to the investigation script but has not yet caught this live
(the Arch host was rebooted between the run that found the orphans and the
rerun that added the check, clearing `/run` and resetting generation
numbering to 1).

**Update:** filed as issue #90, fixed, and now live-confirmed on three
distros. `phase1-down.sh` no longer matches by generation order at all —
`script_hook()` (`src/racoon/isakmp.c`) now exports `IKE_COOKIE`,
racoon's own ISAKMP cookie pair for the negotiation, and
`rhook_state_own_generation()` (`racoon-hook-lib.sh`) matches a teardown
to its own generation by exact value instead of oldest-first.

`task-f-acquire-investigation.sh` (now `tools/racoon-hook-integration-test.sh`,
checked into the repo) gained steps 3b/4b/5c specifically to reproduce
this live rather than relying on the fixture suite alone: a synthetic
orphan generation (a fake `IKE_COOKIE`, an inert `undo_command`) is
injected before connect, so a real host's teardown either does or does
not touch it.

The first live run, against an as-yet-unpatched Noble roadwarrior, both
reproduced the bug *and* answered a question this document had left
open. Generation `.1` (the synthetic orphan) was wrongly consumed;
generation `.2` (this run's own, holding the real `spddelete`/`ip route
del`/dummy-interface undo commands) was never touched. Step 5's
post-teardown SPD dump matched generation `.2`'s own recorded selectors
exactly, and step 6's provocation ping produced a genuine ACQUIRE with a
changed SPI — a real, on-demand reconnection. In other words: on this
run, the orphan-consumption bug is *why* the real session's own teardown
never ran, which is *why* its SPD survived, which is *why* the ACQUIRE
fired — a clean, single-variable causal chain, isolated on its own with
nothing else present to confound it. This does not retroactively settle
the "cannot isolate which... caused the original symptom" hedge above
(that hedge is specifically about the *original two Bionic archives*,
and no capture exists isolating their two contamination sources from
each other — it still can't be settled after the fact). What this run
adds is new: a third, independently demonstrated sufficient cause for
the same class of symptom — the orphan-consumption bug alone, with no
F3/F4 unscoped-resolver path involved at all, is enough to reproduce a
real ACQUIRE. All three explanations (the original test-script
contamination, F3/F4, and now orphan-consumption) remain independently
real and independently fixed; this only adds one more confirmed way the
same observable symptom can arise, on top of the ones already closed.

Three subsequent runs against the patched build — Noble, Arch, and
Bionic i386, all against the same `10.77.254.7` gateway — came back
clean on every axis: `IKE_COOKIE` matched racoon's own logged SPI on
each (confirming the daemon-side export is actually deployed, not just
present in source), the synthetic orphan was left untouched by the real
teardown on each, and a direct `phase1-down.sh` invocation using the
orphan's own `IKE_COOKIE` correctly found and consumed it afterward
(confirming `rhook_state_own_generation()`'s positive match, not just
its negative one). All three also independently reconfirmed Branch B
(clean SPD, no ACQUIRE) end to end.

### Also surfaced: a daemon-side silent-exit quirk

`racoonctl vpn-disconnect` exited non-zero with zero output in **every
single one** of the 8 runs above, well under its timeout — not a hang.
Traced to `src/racoon/kmpstat.c`'s `com_recv()`: both its `MSG_PEEK`-failure
and short-read paths (`~149-154`) `goto bad1` with no `perror()` call at
all, so if the admin socket EOFs before the expected event arrives on that
specific connection, `racoonctl`'s main loop (`racoonctl.c` `~322-326`)
`exit(1)`s completely silently, while racoon's own teardown (and the hook)
proceeds and succeeds independently a moment later, exactly as every
run's syslog confirms. Filed as Issue 4 in `doc/dev/daemon-issues.md`
alongside F2/F5/F8, per this project's existing "file, don't fix
daemon-side C code" convention.
