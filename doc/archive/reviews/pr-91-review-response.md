> **Archived.** Superseded by [doc/dev/v0.9.1-hardening-spec.md](../../dev/v0.9.1-hardening-spec.md)#62-pr-91-review-response as of 2026-08-04; retained for provenance. See also git tag `archive/pre-doc-consolidation`.

# PR #91 review response tracking

Tracks the disposition of each row from the "Review summary table" posted to
PR #91 (comment 5067135235) that the maintainer chose to act on now rather
than defer to follow-up issues, beyond the CI fixes and doc/tooling items
already committed. Each entry below cites the originating comment ID so a
future reader can trace a change back to the review thread that prompted it,
without needing this file plus the PR thread open side by side.

## Row 23 -- overlap window / claimed NAT-T cookie reuse

**Comment:** 5061097437 (+ the `review/pr-91-review-reports-and-proposed-fixes`
doc). **Verdict:** Partly Accepted / Partly Rejected.

The accepted half -- "a crashed `phase1-up.sh` can leave a live orphan state
file" -- is real, expected, and already the entire reason exact-`IKE_COOKIE`
matching exists. The rejected half -- the claimed *mechanism*, "NAT-T rebind
causes `IKE_COOKIE` reuse" -- is wrong: the ISAKMP cookie pair is fixed for
the life of a Phase 1 negotiation and is set independently of the NAT-T port
float.

Resolution:

- **Test coverage.** `test-phase1-roundtrip.sh`'s pre-existing "overlap" and
  "lifo" scenarios both drive `phase1-up.sh` to a normal, complete exit --
  neither actually exercises a crashed/killed `phase1-up.sh`. Added a new
  "crash" scenario: starts the real `phase1-up.sh`, SIGKILLs it after one
  step (`nm_dns`) has journaled successfully but while the next step (a
  route) is stuck mid-command, then verifies (a) the killed generation's
  state file and `.cookie` sidecar survive with only the one completed
  step recorded, (b) a brand-new session for the same peer is unaffected by
  the orphan, and (c) the orphan's own `phase1-down.sh`, run afterwards,
  still finds it by exact cookie match and replays only what actually
  completed. All 78 checks in that file pass, including the 8 new to this
  scenario.
- **Permanent code comment.** Added a comment at `rhook_conn_cookie()` in
  `racoon-hook-lib.sh` stating plainly, with a citation into `isakmp.c`
  (`iph1 = newph1()` / `memcpy(&iph1->index.i_ck, ...)` vs. the separate
  `iph1->natt_flags` bit `NAT_PORTS_CHANGED`), that a NAT-T port float
  cannot change the cookie pair -- so a future reviewer raising the same
  concern can be pointed at a one-line, code-adjacent answer rather than
  requiring this triage to happen again.

No functional change to `racoon-hook-lib.sh`'s behavior; this row's
resolution is test coverage plus documentation.

## Row 24 -- dummy-interface check-then-create TOCTOU

**Comment:** 5061097437 (+ the `review/pr-91-review-reports-and-proposed-fixes`
doc). **Verdict:** Partly Accepted, low priority, "bounded in practice."

Real in theory, and worth closing since closing it is cheap even though the
worst pre-fix outcome was already just a harmless "already exists, reusing"
branch (the idempotent-reuse path added for the earlier "racoon0 hangs after
non-clean stop" bug), not a crash. One correction to the row's own framing:
the race is not scoped to "the same peer" -- `$RHOOK_DUMMY_IFACE` is a single
fixed name from `hooks.conf`, not derived from the peer at all, so two
concurrent sessions for *different* peers race on it exactly as much as two
for the same peer would. The fix and its lock key (the interface name, not a
peer identity or cookie) reflect that.

Resolution:

- Serialized `rhook_ensure_dummy_iface()`'s whole check-then-create body
  with a new `rhook_dummy_iface_lock()`/`rhook_dummy_iface_unlock()` pair,
  keyed by the (sanitized) interface name under `$RHOOK_STATE_DIR`.
  Primary mechanism is `flock(1)`'s file-descriptor form (`exec N>file`,
  `flock N`, `flock -u N`), verified against `flock(1)` itself (util-linux
  2.39.3 on this dev container) rather than assumed.
- **flock(1)'s availability on NetBSD could not be verified** -- no NetBSD
  environment was available to check directly, and this project has been
  bitten by an unverified BSD/Linux tool-availability assumption before
  (the `dash`-on-NetBSD CI fix). Rather than guess, the fix falls back to
  the same mkdir-based retry-and-cap lock `rhook_state_reset()` already
  uses when `flock` isn't on `PATH` -- the project's own NetBSD CI job is
  what actually exercises whichever path applies there.
- Found and fixed one bug of my own along the way: a bare `exec N>file
  2>/dev/null` (no command) applies its redirection to the rest of the
  *current shell*, not just that line -- an early version of this fix
  silenced every later stderr message in the process, including
  `rhook_ensure_dummy_iface()`'s own reuse/refusal log lines, breaking
  two pre-existing assertions (`test-lib-smoke.sh` 11b/11c). Fixed by
  probing the lock file's openability in a subshell first, and by
  dropping the redundant `2>/dev/null` from the plain `exec N>&-` close.
- Added a regression test (`test-lib-smoke.sh`, new case 11d) that runs
  two real, concurrent invocations of `rhook_ensure_dummy_iface()` against
  a stubbed `ip` with a deliberately widened check-to-create window,
  asserting exactly one `ip link add` call and no error from the loser.
  Verified the test actually catches the pre-fix bug (temporarily disabled
  the lock, confirmed the test fails; restored, confirmed it passes).

Full suite after this change: `make check` (1/1) plus all 8 hook fixture
files (445 checks total) pass; `shellcheck` clean.

## Row 29 -- validation-gaps table

**Comment:** 5061097437 (+ the `review/pr-91-review-reports-and-proposed-fixes`
doc). **Verdict:** Partly Accepted, explicitly requiring individual product
judgment per sub-item rather than a blanket accept -- the existing
validation's actual job (shell/`setkey` injection-safety) was already solid
and verified; these three sub-items are additional *policy*-level
restrictions, not injection fixes.

### 29a -- RFC1918/bogon rejection for DNS server addresses

`rhook_validate_dns_list()` already rejected `0.0.0.0`, loopback
(`127.0.0.0/8`) and multicast (`224.0.0.0/4`) for DNS server addresses --
confirmed by reading the code, not assumed from the brief. Extended to the
rest of the never-legitimate ranges: `0.0.0.0/8` as a whole (not just the
single address), link-local (`169.254.0.0/16`), and reserved/Class E plus
the broadcast address (`240.0.0.0/4`).

**RFC1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
are deliberately NOT rejected, and this must never change.** Every one of
this project's own live-tested internal DNS servers uses one of these
ranges (`10.66.0.6` throughout the issue #90 Task F evidence, the whole
`nepomuc.de` topology) -- rejecting RFC1918 by default would reject the
project's own primary confirmed-working scenario. Pinned down with a code
comment and three permanent regression tests (`test-validation.sh`), not
left as an implicit assumption.

### 29b -- CIDR overlap / `0.0.0.0/0` rejection for split-include networks

**`0.0.0.0/0` is not rejected**, and not specially rejected, warned about,
or blocked in any dedicated way -- it is treated like any other CIDR:
flagged only if it overlaps something else offered alongside it, exactly
like any other overlapping pair, never rejected outright. This project has
never taken a position on whether full-tunnel is a supported deployment
mode; nothing in `doc/dev/ARCHITECTURE.md` addresses it either way. A
`hooks.conf` opt-in/deny flag (mirroring the `allow_resolv_conf_overwrite`
pattern) would be the right shape **if the maintainer decides full-tunnel
needs deliberate gating** -- that determination was not made here, since it
is a product-scope decision, not a validation-hardening one. Flagging this
explicitly rather than silently declining it or silently implementing a
guess.

**CIDR overlap detection** is implemented as a warning, not a rejection:
`rhook_build_plan()` now checks every pair of entries in the resolved
`RHOOK_ROUTES` list (`SPLIT_INCLUDE_CIDR` unioned with DNS-server host
routes) and logs `overlapping split ranges received from gateway: <a> and
<b>` at `warn` level for any pair that shares an address, while still
planning and routing both exactly as offered -- overlapping ranges are
redundant, not unsafe. New helper `rhook_cidr_overlaps()` compares octet by
octet rather than building one 32-bit integer per address (documented
in-code why: `192.168.x.x`'s first octet alone, `192 * 16777216`, already
exceeds a 32-bit signed integer's range on an unconfirmed-width shell).

### 29c -- IDN/Punycode domain handling

Checked first, rather than assumed: a raw Unicode homoglyph domain is
already rejected as a side effect of `rhook_valid_domain()`'s
`[A-Za-z0-9.-]` character-class check (confirmed with a direct test using
a UTF-8-encoded label, not just reasoned about). Its Punycode-encoded
(`xn--...`) equivalent is plain ASCII and passes that same check -- that is
the actual residual gap, and it is a visibility gap, not a validation gap:
syntactically an ACE-encoded domain is a perfectly valid string.

`rhook_validate_domain_list()` now logs a `warn`-level line for any domain
with a label starting with the `xn--` ACE prefix (case-insensitive,
matching how DNS labels and ACE-prefix comparison are both defined),
without rejecting it. No homoglyph/confusables-table detection was
attempted -- out of proportion for this project's threat model here (a
malicious or compromised gateway sending Mode Config attributes, not a
sophisticated phishing scenario); surfacing the raw Punycode form to a
human reviewing the report is the proportionate fix.

Full suite after all three sub-items: `make check` (1/1) plus all 8 hook
fixture files (476 checks total) pass; `shellcheck` clean.
