# Security / availability advisory: IKE fragment reassembly regression (CVE-2016-10396 follow-up)

- **Component:** `racoon` — IKE phase 1 fragment reassembly (`src/racoon/isakmp_frag.c`)
- **Affected:** `racoon-ipsec-tools` 0.9.0 (and every earlier build that inherited the original CVE-2016-10396 patch) **with `ike_frag on` or `ike_frag force`**
- **Type:** Availability / denial of connectivity (not memory corruption, not remotely exploitable code execution)
- **Fix:** this branch; see the commit touching `isakmp_frag.c`, `handler.h`, and `test/test_isakmp_frag.c`
- **Recommended action:** ship a hotfix release (**0.9.1**)

---

## 1. Summary

The NetBSD fix for **CVE-2016-10396** (remote DoS via out-of-order IKE
fragments) introduced a `frag_last_index` field plus a reassembly-completion
check. This fork inherited that patch and later applied a *partial* follow-up
(commit `7fc4152`) that repaired the completeness walk but left the core
defect in place. As a result, with IKE fragmentation enabled and a payload
large enough to fragment, **a legitimate retransmission of the last fragment —
or any fragment that arrives after the tail fragment — aborts reassembly**, and
phase 1 fails with:

```
ERROR: Repeated last fragment index mismatch
ERROR: phase1 negotiation failed due to time up.
```

The operational impact is that any peer whose IKE payload is large enough to
fragment (modern DH groups, certificate chains) and whose network drops or
reorders a single fragment can no longer establish a tunnel. The known
workaround, `ike_frag off`, disables a legitimate and often necessary feature
(working around broken UDP fragmentation on consumer routers / firewalls) and
is therefore **not** an acceptable production fix.

## 2. Root cause

Three distinct defects in `isakmp_frag_extract()` / `isakmp_frag_reassembly()`:

1. **Flag-vs-index comparison.** `iph1->frag_last_index` stores the fragment
   *number* of the tail fragment, but the check compared it against
   `item->frag_last`, which is the boolean `ISAKMP_FRAG_LAST` *flag* (always
   `1` for a tail fragment):

   ```c
   if (iph1->frag_last_index != 0 &&
       item->frag_last != iph1->frag_last_index)   /* 1 != <index>  */
           ... "Repeated last fragment index mismatch" ...
   ```

   For any real fragmentation the tail index is `> 1`, so the condition is
   always true on the second sighting of the tail — every retransmitted last
   fragment is misclassified as a replay attack and dropped.

2. **Completion only detected in the tail's own call.** Completeness was
   gated on a function-local `last_frag`, set only when *the fragment being
   processed right now* is the tail. If a non-tail fragment arrives **after**
   the tail (reordering, or a retransmission that refills a gap), the
   now-complete chain is never recognised and phase 1 stalls until timeout.

3. **`frag_last_index` never reset.** `isakmp_frag_reassembly()` freed the
   chain but left `frag_last_index` stale, so a second fragmented message on
   the same `ph1handle` (e.g. a full phase-1 retransmission) inherited the old
   tail index and tripped defect #1.

## 3. The fix

`isakmp_frag_extract()` is rewritten to match the corrected upstream NetBSD
logic (rev. `1.12`), adapted to this fork:

- Tail-fragment consistency is enforced against `iph1->frag_last_index` with
  the correct semantics: a **second, differing tail fragment** is rejected
  (`Message has multiple tail fragments`), and a **fragment number greater
  than the tail index** is rejected (`Fragment number greater than tail
  fragment number`). A duplicate of the already-seen tail is caught by the
  existing duplicate-fragment-number check in `isakmp_frag_insert()`.
- `frag_last_index` is recorded **after** a successful insertion, so a rejected
  duplicate can never corrupt reassembly state.
- Completion is evaluated against `iph1->frag_last_index` on **every** call, so
  it is detected regardless of arrival order.
- `isakmp_frag_reassembly()` resets `frag_last_index = 0` when it frees the
  chain.

The CVE-2016-10396 protection is preserved and in fact **strengthened**: the
pre-fix code did not reject a fragment whose index exceeded the tail index; the
fix does. See `test/test_isakmp_frag.c`, Scenario 4.

`handler.h` gains a comment documenting that `frag_last_index` is an index, not
a flag — no structural change is required; the field already exists and matches
upstream.

## 4. Regression test

`test/test_isakmp_frag.c` drives the real reassembly functions with crafted
fragment sequences. Measured result:

| | Pre-fix (`git HEAD`) | Fixed |
| --- | --- | --- |
| Scenario 1 — in-order 1,2,3 | tail index not reset ✗ | ✓ |
| Scenario 2 — out-of-order 1,3,2 (primary) | completion never detected ✗ | ✓ |
| Scenario 3 — full retransmission | false "mismatch", 2nd pass fails ✗ | ✓ |
| Scenario 4 — CVE protections | over-index fragment **accepted** ✗ | rejected ✓ |
| **Total** | **5 checks fail (exit 1)** | **21/21 pass (exit 0)** |

An end-to-end itlab scenario descriptor for the same case (with a `dh_group 14`
vs `dh_group 16` matrix and single-fault fragment-drop injection) is provided
at `test/itlab/scenarios/ike-frag-retransmit-reassembly/`, ready to execute
once the RFC-0001 framework reaches Milestone 1–2.

### Why it stayed invisible — DH group / fragmentation threshold

`ISAKMP_FRAG_MAXLEN = 552` bytes. Fragmentation only happens once a message
exceeds it:

| DH group | KE payload | Fragments on KE alone? |
| --- | --- | --- |
| 14 (MODP-2048) | 256 B | No (PSK) — needs a large payload such as a certificate chain |
| 16 (MODP-4096) | 512 B | Yes — the KE-bearing message alone exceeds 552 B |

PSK setups with small DH groups never fragmented, so never hit the bug. Raising
the DH group for stronger forward secrecy is exactly what began exposing it.

## 5. CVE audit — historically inherited fixes

All racoon CVE patches carried by this fork were reviewed for completeness and
for known documented follow-ups. Confidence is stated explicitly.

| CVE | Affected file | Patch present | Follow-up needed | Action |
| --- | --- | --- | --- | --- |
| **CVE-2016-10396** (out-of-order fragment DoS) | `src/racoon/isakmp_frag.c`, `handler.h` | Yes (orig. + partial `7fc4152`) | **Yes — this advisory.** Original patch had a documented NetBSD follow-up (PR bin/53646) that was only partly applied | **Fixed here.** Full follow-up ported; regression test added |
| **CVE-2015-4047** (NULL deref, missing rmconf check) | `src/racoon/gssapi.c` | Yes (`23a56f8`, Debian `bug785778`) | None known | Verified complete |
| Debian #527634 (fragment with all-zero item lengths → NULL deref) | `src/racoon/isakmp_frag.c` | Yes — `Fragment too short` / `Message too short` length guards (`frag->len < sizeof(*frag)+1`) | None known | Verified present |
| **CVE-2009-1632** (memory leaks in NAT-T + RSA auth → DoS) | `src/racoon/nattraversal.c`, `rsalist.c` | Inherited via 0.7.1+ baseline | None known | Recommend formal re-verification (see §6) |
| **CVE-2008-3652** (orphaned phase-1 handles from invalid first exchange → DoS) | `src/racoon/isakmp.c` / `handler.c` | Inherited via baseline | None known | Recommend formal re-verification |
| **CVE-2007-1841** (crafted packet crashes a tunnel) | `src/racoon` | Inherited via baseline | None known | Recommend formal re-verification |
| **CVE-2005-3732** (malformed ISAKMP / cert handling) | `src/racoon` (X.509) | Inherited via upstream release ≥ 0.6 | None known | Recommend formal re-verification |

**Key finding:** CVE-2016-10396 is the one inherited fix that carried a
*known, documented* upstream correction the fork had not fully applied. The
pre-2010 fixes are baseline-inherited with no known follow-up, but they were
adopted as opaque backports and have **not** been re-verified line-by-line
against every distribution's subsequent patch history — which is the gap §6
addresses.

## 6. Process post-mortem

**Why the existing audit missed it.** The security process leaned on Valgrind
Memcheck over pre-auth code paths. This is a **pure logic error** — a wrong
comparison and missing state reset — with no memory corruption, no leak, and no
invalid access, so Memcheck had nothing to flag. It only manifests under
specific *runtime* conditions (fragmentation actually triggered by payload size,
plus real fragment loss/reordering), none of which Memcheck or memory-safety
fuzzing reproduces. "The CVE patch is applied" was treated as "the CVE class is
closed," when the applied patch itself carried a documented, unshipped
follow-up.

**Concrete proposal.** Add two standing steps to the security review, so that
"we imported the CVE fix" is not automatically "done":

1. **Historical-advisory replay as tests.** For every inherited security patch,
   add a deterministic regression test that reproduces the *original* attack
   *and* the legitimate traffic the patch must not break — as done here in
   `test/test_isakmp_frag.c`. Track, per CVE, the upstream revision the patch
   was taken from and diff against the *current* upstream to catch follow-ups
   (this is exactly what surfaced the CVE-2016-10396 gap).
2. **Interop tests with artificial impairment.** Wire the itlab
   single-fault capability (RFC-0001 §5/§9: fragment drop/delay/reorder) into
   the standard review for any change touching IKE message handling, and run it
   across a DH-group / payload-size matrix so protocol-logic regressions that
   only appear under real network conditions are caught before release. Pair
   with protocol-structure fuzzing (RFC-0001 Appendix A.5) for the pre-auth
   parsers, complementing — not replacing — the existing Memcheck runs.

## 7. Release recommendation

Ship **racoon-ipsec-tools 0.9.1** as a security/availability hotfix.

- `ike_frag` **default is `off`** (`remoteconf.c:513`, `new->ike_frag = FALSE`),
  so a default-configured 0.9.0 is not affected. However, the responder still
  reassembles peer fragments whenever fragmentation is negotiated, and
  `ike_frag on`/`force` is the *recommended* configuration for road-warrior and
  broken-MTU deployments — precisely where this bug bites. The advisory must
  state the default clearly and not overclaim.
- Cut `0.9.1` from `develop` after this fix lands, then cherry-pick to the
  Debian and Ubuntu hotfix branches.

### Draft advisory text

> **racoon-ipsec-tools 0.9.1 — security/availability fix**
>
> Versions up to and including 0.9.0, when configured with `ike_frag on` or
> `ike_frag force`, could fail to complete IKE phase 1 with peers whose IKE
> payload is large enough to be fragmented (modern DH groups, certificate
> chains) whenever a fragment was lost or reordered on the wire. The daemon
> logged `Repeated last fragment index mismatch` and the negotiation timed out,
> locking affected clients out of the VPN. The root cause is a follow-up defect
> in the inherited CVE-2016-10396 fix: the reassembly logic misclassified a
> legitimate retransmission of the last fragment as a replay attack.
>
> 0.9.1 ports the corrected upstream reassembly logic. The DoS protection of
> CVE-2016-10396 is retained and strengthened. Deployments that adopted
> `ike_frag off` as a workaround can and should re-enable IKE fragmentation
> after upgrading. Setups using pre-shared keys with DH group 14 or lower are
> unlikely to have been affected, as their exchanges did not fragment.
