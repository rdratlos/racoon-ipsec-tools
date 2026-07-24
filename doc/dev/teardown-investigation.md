# Teardown / reconnect-loop investigation (brief 3 §F)

Tracks the live Bionic finding chain (F1 → F3 → F4) and what §F itself
still needs a live host to settle. Companion to `doc/dev/daemon-issues.md`
(F2, F5, F8 — daemon-side issues filed, not fixed) and
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

## What §F itself still needs (blocked — no live host in this session)

The brief's own §F asks for `setkey -DP` captures **before and after**
a connect/disconnect cycle on the Bionic host, specifically to confirm:

1. That no SPD entry exists for the peer's subnet *before* `rhook_plan_spd()`
   ever runs (confirming the source-level claim in §E — that racoon
   installs no initiator-side policy of its own — actually holds at
   runtime on this exact racoon build/config, not just in the general
   case proven from source).
2. That the entries `rhook_plan_spd()` installs are the *only* new
   entries appearing in `setkey -DP` output after `phase1-up.sh` runs
   (ruling out some other path — NetworkManager, a stray `ipsec-tools`
   init script, a leftover static policy from a previous manual test —
   also contributing a policy that could independently trigger or mask
   an `ACQUIRE`).
3. That `setkey -DP` is empty for this peer again after `phase1-down.sh`
   completes a clean teardown, confirming the SPD-ownership teardown
   (exact `spddelete` reconstruction, §E) actually removes what it
   installed and nothing more.
4. Whether the specific `ACQUIRE` observed in the original F1 run (if a
   copy of that host's `/var/log` or `dmesg` capture is still available)
   correlates by selector with the unscoped-DNS-server traffic pattern
   F4 describes, or points at some other source entirely — the F3/F4
   causal chain above is the most parsimonious explanation consistent
   with the evidence recorded in brief 3, but was not itself confirmed
   with a kernel-level capture at the time.

None of this can be done from source reading or the fixture-driven test
suite alone — it requires a real kernel SPD table and a real `ACQUIRE`
event on the exact host/kernel/racoon build combination the original
finding came from. Once a Bionic (or equivalent) host is available again:

```sh
# Before phase1-up.sh
setkey -DP > /tmp/spd-before.txt

# Run a connect/disconnect cycle, e.g. via racoonctl or letting racoon
# negotiate normally
...

# Immediately after phase1-up.sh's report shows the spd_entry steps ok
setkey -DP > /tmp/spd-during.txt
diff /tmp/spd-before.txt /tmp/spd-during.txt

# Immediately after phase1-down.sh's report shows result: OK
setkey -DP > /tmp/spd-after.txt
diff /tmp/spd-before.txt /tmp/spd-after.txt   # expect empty diff

# If dmesg/journalctl still has the original ACQUIRE from the F1 run:
dmesg | grep -i acquire
journalctl -k --since "<time of the original F1 test>" | grep -i acquire
```

This document should be updated with the actual capture output the next
time a live host is available, and §F in the tracking task list closed
out at that point — it stays open (blocked) until then.
