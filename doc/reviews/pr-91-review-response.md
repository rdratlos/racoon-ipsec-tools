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
