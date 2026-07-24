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
