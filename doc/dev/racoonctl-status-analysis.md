# `racoonctl status` — Phase 1 Analysis &amp; Phase 2 Report

**Status:** D1–D4 ratified (§5). Phase 3 done — consolidated issue:
[rdratlos/racoon-ipsec-tools#139](https://github.com/rdratlos/racoon-ipsec-tools/issues/139).
⏸ before Phase 4 (code).
**Branch:** `claude/racoonctl-status-rewrite` (based on `develop`, not the discarded
`feature/racoonctl-status`/first-draft history).
**Scope:** analysis + recommendations only. No code in this commit.

---

## 1. Verified touchpoints

Every name below was checked against this tree (commit `56300f2`, `develop`), not
assumed from memory of the ipsec-tools lineage. Corrections to the task prompt's
assumptions are called out explicitly.

| Prompt's assumption | Verified reality |
|---|---|
| `admin.c`/`admin.h`: dispatch, `ADMIN_*`, `struct admin_com` | Confirmed as described. Command space: `0x01xx` = no-index/proto-bearing, `0x02xx` = indexed. `0x0103`/`0x0104` are free (matches the already-decided `ADMIN_STATUS`/`ADMIN_STATUS_VERBOSE`). |
| `racoonctl.c`: subcommand parsing, `show-sa` | Confirmed. `cmdtab[]` (racoonctl.c:107) maps command strings to `f_*()` handlers; global `getopt(ac, av, "lds:")` (racoonctl.c:270) has no `-v`, so a per-subcommand `-v` (parsed inside `f_status()`'s own `getopt()`, same pattern `f_exchangesa()` already uses for `-u`/`-n`/`-w`) is conflict-free. |
| `handler.h`: `struct ph1handle`, `struct ph2handle`, `PHASE1ST_*`/`PHASE2ST_*` | Confirmed, all present and spelled as expected (handler.h:93-105, :253-264, :120, :266). |
| Identity helper `ipsecdoi_id2str()` | **Confirmed to exist** (`ipsec_doi.c:4235`, declared `ipsec_doi.h:232`) and confirmed to return an already caller-owned `racoon_malloc()`'d pointer, not a pointer into its internal scratch buffer — see Finding H-2 (**corrected** after this document's original guidance caused the opposite mistake in `status.c`). |
| `struct isakmpsa`, reached via `iph1->approval` | Confirmed (`remoteconf.h:55`). **Does not have a `pfs_group` field** — see Finding H-1. |
| `iph1->mode_cfg` → `struct isakmp_cfg_state`, XAuth substate | Confirmed (`isakmp_cfg.h:181`, nested `struct xauth_state xauth` at `isakmp_xauth.h:76`). **Carries a cleartext password field** — see Finding H-3. |
| Man page location "`racoonctl.8`" (Phase 5) | **Off by one section**: the file is `src/racoon/racoonctl.1.in` → generates `racoonctl.1` (mdoc, section 1, confirmed `.Dt RACOONCTL 1`), not section 8. Trivial correction, noted for Phase 5. |

---

## 2. Analysis questions

### 2.1 Retained vs. transient state — and why the headline use case doesn't work today

**No phase1 or phase2 handle carries any error/failure-reason field.** I read
`struct ph1handle` (handler.h:120–229) and `struct ph2handle` (handler.h:266+)
field-by-field: there is no `errno`, `last_error`, `fail_reason`, or anything
resembling one. The only per-handle signal of trouble is the state enum itself
(`PHASE1ST_DYING`/`EXPIRED`) or the handle's absence.

More importantly, for the **specific headline scenario in the problem statement**
(XAuth/LDAP rejection), the handle does not survive long enough to be polled even
if such a field existed — and this is not a "the window is impractically short"
argument, it is a "there is categorically no window" argument. Traced the exact
call chain, one direct synchronous function call per arrow, no scheduler or
event-loop round-trip anywhere in it:

```
session.c: select()/poll() → monitor_fd() dispatch
  → isakmp_handler(ctx, so_isakmp)         isakmp.c:219   [fd-ready callback,
                                                            registered via
                                                            monitor_fd(), isakmp.c:1723]
    → isakmp_main(msg, remote, local)       isakmp.c:410
      → case ISAKMP_ETYPE_CFG:              isakmp.c:754-768
        → isakmp_cfg_r(iph1, msg)           isakmp.c:768 → isakmp_cfg.c:139
          → isakmp_cfg_attr_r(...)          isakmp_cfg.c:249 → isakmp_cfg.c:272
            → case ISAKMP_CFG_SET:
              → isakmp_cfg_set(iph1, attrpl)  isakmp_cfg.c:297 → isakmp_cfg.c:677
                ├─ while (tlen > 0) { case XAUTH_STATUS:
                │    → isakmp_xauth_set(iph1, attr)   isakmp_cfg.c:714 → isakmp_xauth.c:1644
                │        on failure: evt_phase1(iph1, EVT_PHASE1_XAUTH_FAILED, NULL);
                │                    iph1->mode_cfg->flags |= ISAKMP_CFG_DELETE_PH1;
                │        (isakmp_xauth.c:1692/1694) — then returns normally to its caller
                │  }
                ├─ isakmp_cfg_send(...)                isakmp_cfg.c:752-753  (send CFG-ACK)
                └─ if (flags & ISAKMP_CFG_DELETE_PH1)   isakmp_cfg.c:755-761
                       remph1(iph1); delph1(iph1); iph1 = NULL;
```

Two things this chain establishes precisely, correcting an earlier looser
description of the same finding:

- The function that detects the failure and sets the flag, `isakmp_xauth_set()`
  (`isakmp_xauth.c:1644`), **returns normally** — it does not delete anything
  itself. It is the *caller*, `isakmp_cfg_set()` (`isakmp_cfg.c:677`), that checks
  the flag ~40 lines later **in that same function invocation** and deletes the
  handle. Not merely "same call stack" — same function, same activation record.
- There is no `sched_new()`/timer indirection and no return to the event loop
  anywhere between the flag being set (`isakmp_cfg.c:1694`) and the handle being
  freed (`isakmp_cfg.c:759-760`). Both happen inside the one synchronous call
  chain triggered by `isakmp_handler()`, the fd-ready callback for a single
  inbound UDP packet.
- **racoon is single-threaded** — `isakmp_handler()` is registered the same way
  as every other socket callback (`monitor_fd()`, the mechanism `admin_handler()`
  itself also uses for the admin socket), and `session.c`'s event loop dispatches
  one ready fd at a time, strictly serially. There is structurally no way for
  `admin_process()` (the future `status` handler) to run concurrently with, or
  interleave into, this chain — not "the odds are low," but "the runtime has no
  mechanism that could produce that interleaving." So even the most generous
  reading of "window" — a hypothetical concurrent admin-socket read landing
  between flag-set and delete — is not just rare, it is impossible in this
  architecture.

**Conclusion: a `last_error` field on `struct ph1handle` would not make the
headline use case real**, categorically, not as a matter of timing odds. It
would only help for failure modes where the handle lingers (e.g. plain
`EVT_PHASE1_AUTH_FAILED` from `isakmp_base.c`/`isakmp_agg.c`/`isakmp_ident.c`,
which just `goto end` and return an error code to their caller — I did not trace
how long that caller keeps the handle alive, but it is not deleted in the same
call frame the way the XAuth path is). This materially reshapes D2 — see §3.

**What does outlive a failed handle:** `evt.c` maintains a bounded ring buffer
(`evtlist`, `EVTLIST_MAX` = 32, `evt.c:74-80`) of past events, independent of any
`ph1handle`/`ph2handle` lifetime, already exposed via `racoonctl show-event`.
`evt_phase1()`/`evt_phase2()` (evt.c:299+) record the peer's `src`/`dst` address
and an `optdata` payload alongside the event type. **At every current call site**
(`isakmp_agg.c`, `isakmp_base.c`, `isakmp_ident.c`, `isakmp_xauth.c` — 7 sites
total) **`optdata` is passed as `NULL`.** The plumbing to carry a reason string
already exists end-to-end; nothing currently populates it.

### 2.2 Integration seam

`show-sa`'s ISAKMP path is a useful precedent, and it answers the "does the
daemon pre-format text?" question directly: **no.** `dumpph1()` (`handler.c:314-348`)
copies a handful of scalar fields (`index`, `status`, `side`, `remote`, `local`,
`version`, `etype`, `created`, `ph2cnt`) into a fixed-size C struct,
`struct ph1dump` (`handler.h:455-465`), and ships an array of those raw structs
over the admin socket. **All formatting — the column headers, address rendering,
state names — happens client-side**, in `dump_isakmp_sa()` (`racoonctl.c:1032+`).

Two consequences:

1. `struct ph1dump` is **far too thin** for `status` regardless of format —
   it has no algorithm, XAuth, or mode-config fields at all. A new admin command
   (or at minimum a new, richer wire payload) is required either way; extending
   `show-sa` in place is not realistically an option once you look at what
   `struct ph1dump` actually carries. This effectively answers half of D4 already.
2. The existing precedent is "server sends raw scalars, client formats text."
   That precedent does not by itself resolve *where JSON gets serialized* — see
   D1 in §3, which weighs this precedent against the JSON-schema-stability
   requirement.

### 2.3 Enum → name mapping

Verified against source, with provenance corrected where the problem statement's
categorization was imprecise:

| Concept | Source | Provenance |
|---|---|---|
| ID types (`IPSECDOI_ID_*`) | `ipsec_doi.h` | RFC 2407 §4.6.2.1 (DOI) — confirmed real values (`IPSECDOI_ID_IPV4_ADDR` etc., `ipsec_doi.c:4246+`). |
| Encryption/hash/DH-group/auth-method (`OAKLEY_ATTR_*`) | `oakley.h` | RFC 2409 Appendix A (IKE) / IANA IKEv1 registry. |
| Phase-1/2 states | `handler.h` | Internal to this implementation, not a standards concept. |
| XAuth (`XAUTH_*`, `struct xauth_state`) | `isakmp_xauth.h` | **IETF draft** (`draft-ietf-ipsec-isakmp-xauth`), expired, never an RFC. Confirmed no RFC number appears anywhere in the header. |
| Mode-config (`ISAKMP_CFG_*`, `struct isakmp_cfg_state`) | `isakmp_cfg.h` | **IETF draft** (`draft-ietf-ipsec-isakmp-mode-cfg`), expired, never an RFC. |
| Cisco Unity split-tunnel (`split_include`, `split_local`) | `isakmp_cfg.h:192-197`, `isakmp_unity.h` | **Vendor extension**, not an IETF document at all — one level less standard than mode-config itself. The skeleton's `split_include` field is real (verified field name matches `isakmp_cfg.h`) but its provenance label needs to say "Cisco Unity vendor extension," not just "draft." |
| NAT-T, DPD | `nattraversal.h`, `handler.h` (`ENABLE_DPD` block: `dpd_support`, `dpd_seq`, `dpd_fails`, `dpd_last_ack`) | RFC 3947/3948, RFC 3706 respectively — confirmed real fields exist on `struct ph1handle` (handler.h:212-218) but **neither appears in the current JSON skeleton at all.** Flagged as Finding M-1. |

### 2.4 Scope boundary

Given §2.1's finding, the boundary the problem statement proposes ("`status`
introspects current SAs; explaining a *past* failure is an event-log concern") is
not just a reasonable line to draw — it is the *only* technically coherent line
for the XAuth/LDAP scenario specifically, because no per-handle mechanism can
reach past that handle's synchronous deletion. See D2 recommendation.

---

## 3. Decision points

### D1 — JSON rendering location

**Recommendation: server-side, using the existing `ac_proto` wire field to select
`text` vs `json` — not a new wire verb, not client-side JSON parsing.**

Reasoning:

- The `show-sa` precedent (§2.2) is "server sends scalars, client formats," but
  that precedent exists because `struct ph1dump` predates any need for a stable,
  versioned, machine-readable contract. `status` has a different constraint the
  precedent doesn't: **the task explicitly weighs test-harness schema stability
  heaviest**, and a stable schema is easiest to guarantee when it is authored in
  exactly one place.
- A raw-struct-over-the-wire approach (mirroring `ph1dump`) would need the
  *client* (racoonctl) to independently derive JSON keys from an internal C
  struct it receives from a potentially different `racoon` build. That directly
  reintroduces the "racoonctl/racoon version pairing" risk D4 already worries
  about, except now it also risks the JSON contract silently drifting from
  whatever struct layout shipped — worse for schema stability, not better.
- Rendering JSON server-side means racoonctl never needs to *parse* JSON — only
  print bytes it received (exactly what today's `case ADMIN_STATUS: fwrite(buf,
  len, 1, stdout);` already does). Writing JSON is comparatively low-risk (linear,
  append-only); the discarded first draft's JSON bugs (Finding-class issues,
  below) were all in the *writer*, and are fixable without needing a parser
  anywhere. Avoiding a hand-rolled JSON *parser* client-side removes an entire,
  harder-to-get-right code path from scope — consistent with "lightweight task,
  not RFC."
- Mechanically: `ADMIN_STATUS`'s `ac_proto` field is unused today (unlike
  `ADMIN_SHOW_SA`, which already branches on it for ISAKMP/AH/ESP/internal). Using
  it as a two-value format selector (`text` / `json`) needs no new `ADMIN_*`
  command beyond the two already decided, and mirrors an existing pattern instead
  of inventing one.
- Net shape: one server-side extraction pass over `ph1tree`/`ph2tree` per
  `status_dump()` call, feeding **two** independent render functions (`to_text()`,
  `to_json()`) that both already-existing conventions in `admin.c` can dispatch
  to by `ac_proto`. Neither renderer needs to be shared code with the other —
  keeping them separate avoids the previous draft's mistake of interleaving JSON
  string-building with the tree walk itself.
- **Bonus from the §2.1 single-thread finding: the extraction pass needs no
  locking.** `admin_process()` runs on the same single-threaded event loop as
  `isakmp_handler()` (both dispatched via `monitor_fd()`, one fd at a time,
  strictly serial). Nothing can mutate `ph1tree`/`ph2tree` or any handle
  `status_dump()` is reading *while* it's reading it — a negotiation cannot
  advance, and a handle cannot be freed, in the middle of a `status` call. Every
  poll either sees a fully consistent snapshot of a handle, or that handle
  simply isn't in the tree yet/anymore. See Finding M-4 — this needs to become
  an inline comment at the extraction site in Phase 4, not just live in this
  report.

**Ratified.** Approved as-is, plus a follow-up check requested on whether the
admin socket's wire framing actually carries a large, variable-size reply
cleanly (a `status` reply with several SAs' full XAuth/mode-config JSON is
categorically bigger than anything `ph1dump`'s scalar array ever produced).
Checked both directions:

- **Client read side (`com_recv()`, `kmpstat.c:163-219`) is already correct**
  for arbitrary sizes: it `MSG_PEEK`s the fixed-size header first, computes the
  real length from `ac_len`/`ac_len_high` (handling `ADMIN_FLAG_LONG_REPLY`),
  then loops — `while (l < rlen) { recv(...); l += len; p += len; }` — until the
  full payload is in. No change needed here regardless of reply size.
- **Server write side (`admin_reply()`, `admin.c:875`) is not.** It's a single
  `tlen = send(so, retbuf, tlen, 0);` with the result only checked for `< 0`
  (a hard error) — **a legitimate partial send (POSIX explicitly permits this
  for `SOCK_STREAM`, confirmed `AF_UNIX`/`SOCK_STREAM` at `admin.c:982`) is
  silently treated as success, and the unsent remainder of the buffer is never
  retried.** Every existing admin command shares this code path and has this
  latent bug already, but none of them produce a reply large enough to
  plausibly trigger it in practice. `status` (verbose, multiple SAs, full JSON)
  is the first command likely to exceed a single `send()` call's capacity on a
  busy gateway — and a truncated send produces truncated, syntactically invalid
  JSON on the wire, which directly breaks the "exactly one self-contained JSON
  document per invocation" requirement. **Promoted to Finding H-4** (below);
  fixing `admin_reply()` to loop on `send()` the same way `com_recv()` already
  loops on `recv()` is a small, self-contained fix and should land as part of
  this feature's Phase 4 work, not deferred — added to the issue's acceptance
  criteria rather than blocking Phase 3.

### D2 — XAuth/LDAP last-error

**Recommendation: do not add `last_error` to `struct ph1handle` for `status`.
Keep `status` strictly to currently-retained live SA state, matching the
problem statement's own proposed scope boundary.**

§2.1 shows a `ph1handle`-resident field would not serve the headline scenario —
not because the window is impractically short, but because there categorically
is no window: `isakmp_xauth_set()` returns normally to `isakmp_cfg_set()`, and
that same function, same activation record, deletes the handle before returning
to *any* caller, with no scheduler round-trip in between and no possibility of
`admin_process()` interleaving in a single-threaded event loop. Adding a
`last_error` field anyway would be dead weight that quietly fails to deliver
what it's named for, exactly the kind of "aspirational field" Phase 5's own
guidance warns against for the man page.

> **For the frozen issue:** carry the §2.1 call-chain block (the
> `isakmp_handler()` → … → `delph1()` diagram with file:line references) into
> this section's justification verbatim, or lightly trimmed. It's the actual
> argument for why D2 isn't "keep it simple for now" but "this specific field
> cannot work here" — worth being retrievable without redoing this trace six
> months from now when someone asks "why didn't we just add `last_error`?".

The mechanism that *would* work — populating `optdata` at the ~7 existing
`evt_phase1()`/`evt_phase2()` call sites that currently pass `NULL`, and
surfacing it through `evt_dump()`/`show-event` — is real, small, and read-path-safe,
but it is squarely an `evt.c` change, not a `status` change, and touches a
different admin command (`ADMIN_SHOW_EVT`) with its own existing consumers. Given
the "one issue, no scatter" instruction, I'd rather flag it explicitly as a
**separate, tightly-scoped follow-up** than fold it into this issue's frozen
schema. Your call whether to file that follow-up now or later — it doesn't block
`status`.

**Ratified.** No `last_error` field; `status` stays scoped to live state. The
`evt.c` optdata-enrichment follow-up is noted as future, out-of-scope work in
the issue, not filed separately yet.

### D3 — JSON schema

Not re-litigating the pieces already decided (ISO 8601 timestamps, SPI masking,
CIDR selectors, `-v` for the phase2 array, `ADMIN_STATUS_VERBOSE` = `0x0104`).
Three concrete corrections surfaced by verification, plus the cfparse.y alignment
the prompt asked for:

- **`"version": "1.0"` (top level) collides in meaning with `phase1[].version`
  (which is the raw ISAKMP header version byte — confirmed `iph1->version =
  isakmp->v` at `isakmp.c:1061`/`1169`).** Two same-named-in-spirit keys meaning
  different things is a schema footgun. Recommend the prompt's own prose name,
  `schema_version`, for the top-level key, and rendering `phase1[].version` as
  the decoded `"major.minor"` string (e.g. `"1.0"`) rather than a raw byte value
  — `0x10` printed as decimal is `16`, not the `10` the skeleton's example shows,
  which suggests the skeleton's example value was illustrative rather than a
  real captured value.
- **Drop `phase1[].proposal.pfs_group`.** Verified: `struct isakmpsa` (phase1's
  approved-proposal struct, `remoteconf.h:55`) has no `pfs_group` field at all —
  PFS is a Phase-2-only concept in this codebase (`struct saprop.pfs_group`,
  `proposal.h:62`, correctly present under `phase2[].proposal` in the skeleton
  already). The only "pfs_group" reachable from a `struct ph1handle` is
  `isakmp_cfg_config.pfs_group` — a **global daemon config value**, not a
  per-SA negotiated attribute — which is what the discarded first draft
  incorrectly wired into this exact field. Recommend removing it from phase1
  entirely rather than repeating that mistake.
- **cfparse.y alignment (as requested) — mostly already true, one real tension.**
  `cftoken.l` uses `encryption_algorithm`/`hash_algorithm`/`authentication_method`/
  `dh_group`/`pfs_group`/`lifetime` as literal config keywords in both the
  `remote { proposal { ... } }` block (`cftoken.l:388-391`) and the `sainfo { ... }`
  block (`cftoken.l:303-311`, which also has `authentication_algorithm` and
  `compression_algorithm` for phase2) — **these match the skeleton's field names
  exactly already**, good sign the original author did look at the grammar. The
  one place it doesn't line up: config vocabulary calls identities
  `my_identifier`/`peers_identifier` (`cftoken.l:334-336`), but the skeleton uses
  `remote_id`/`local_id`. Recommend keeping `remote_id`/`local_id` — they match
  `struct ph1handle`'s own field names (`local`/`remote`) and existing
  `show-sa` output header ("Source"/"Destination"), and "my/peers" reads oddly
  from a third-person status report — but flagging the inconsistency for your
  call rather than silently picking one.
- **Missing from the skeleton, present on the struct, worth a decision:**
  `phase2[].proposal.compression_algorithm` (IPComp — `cftoken.l:311`, real
  keyword, real `struct saprop`/`struct saproto` field via `IPSECDOI_PROTO_IPCOMP`);
  DPD state (`dpd_support`/`dpd_fails`, RFC 3706, `struct ph1handle` `ENABLE_DPD`
  block); NAT-T state (`natt_options`/`natt_flags`, RFC 3947/3948, `ENABLE_NATT`
  block). None of these block a first cut; listing them so the "frozen" schema is
  frozen on purpose, not by omission.
- **Drop `phase1[].xauth.error` — same root cause as `pfs_group`, not raised
  explicitly until now.** `XAUTHST_*` (`isakmp_xauth.h:104-106`) has exactly
  three values: `NOTYET`, `REQSENT`, `OK` — no `FAILED` state. §2.1 explains why:
  a failure doesn't transition `xauth.status`, it deletes the handle
  synchronously instead. So there is no code path that ever leaves a live
  `ph1handle` sitting with an "xauth failed" status for `status` to read — the
  field would always read as whatever placeholder value was chosen (most likely
  always `0`), never anything meaningful. Same fix as `pfs_group`: drop it
  rather than ship a field that looks like a real signal but structurally never
  fires.

**Ratified, all four:**
1. `schema_version` rename (top level) — done, avoids the collision with
   `phase1[].version`.
2. Drop `phase1[].proposal.pfs_group` — confirmed bug in the discarded draft.
3. Keep `remote_id`/`local_id` over `my_identifier`/`peers_identifier` —
   consistent with `struct ph1handle` and existing `show-sa` output.
4. NAT-T and DPD **in** for v1 (both explicitly named as in-scope RFC concepts
   in the original problem statement, and the marginal extraction cost is the
   same pass either way). IPComp (`compression_algorithm`) is the one field of
   the three explicitly allowed to slip to a follow-up if Phase 4 scope runs
   long — noted as the one flexible item, not a hard commitment.

Plus the `xauth.error` drop above, decided by the same reasoning as `pfs_group`
without needing a separate round.

### D4 — Admin command

§2.2 already establishes `show-sa` extension isn't realistically viable
(`struct ph1dump` is too thin). Recommend the already-decided path: new commands
(`ADMIN_STATUS` / `ADMIN_STATUS_VERBOSE`), format carried on `ac_proto`
per D1 — no separate decision needed here beyond confirming D1's mechanism, since
it was going to require a new `ADMIN_*` pair regardless of the JSON question.

**Version pairing**, the part of D4 not yet addressed: since JSON is generated
server-side (D1), an older `racoonctl` talking to a newer `racoon` gets a
schema it may not expect, and vice versa. Recommend `schema_version` (D3) be
checked by nothing at parse time (JSON is meant to be consumed by external
tooling, not racoonctl itself) but that `racoonctl`'s own `text` renderer — which
under D1 is also server-side — needs no version check either, since server and
renderer always ship together. The only real skew risk is a **future external
JSON consumer** pinned to an old `schema_version` talking to a newer daemon —
a concrete candidate would be the external Paws gateway discussed later in
this doc, or a future itlab Verification-layer check validating
`racoonctl status` output against `share/schema/`; neither exists today (see
the corrected RFC-0001 note below), so this is a design goal to keep the
contract compatible with, not an enforced integration; that's a
contract-versioning policy question (additive-only minor bumps vs. breaking
major bumps) worth one sentence in the frozen issue, not more.

**Ratified.** `schema_version` is `"major.minor"`. Additive changes (new
optional field) bump minor only; breaking changes (rename/remove/retype an
existing field) bump major. Any future JSON consumer needs only
major-version awareness to stay compatible across minor bumps — no consumer
enforcing this exists today; see the corrected RFC-0001 note immediately
below.

**Correction (added during #140's PR pass):** the two paragraphs above
originally named "the RFC-0001 harness" as an existing consumer that pinned
to `schema_version`'s major component. That was never correct — an
unverified assumption introduced during scoping and never checked against
the actual document. The real RFC-0001
(`docs/rfcs/0001-incus-integration-testing-framework.md`, `main` branch) is
an Incus-based network-topology integration framework ("itlab") covering
IKE negotiation, PF_KEY/XFRM, package lifecycle, and DNS-hook coverage — it
has no relationship to JSON schema validation of `racoonctl status` output
and no such harness exists. The honest connection is RFC-0001 §8
("Extension Points"), which lists a **Verification backend** — "how
outcomes are asserted against observations" — as a stable extension point
for future itlab scenarios: schema validation of `racoonctl status` JSON
(`share/schema/racoonctl-status.schema.json`, issue #140) is a plausible
*future* Verification-layer assertion inside an itlab scenario, not
something that exists today. Formally adding it as one of RFC-0001's
extension points is a separate, `main`-branch effort, not part of this
work. This mirrors how Finding H-2 elsewhere in this document records its
own correction in place rather than silently rewriting the earlier text.

### D5 — Racoon operation mode (roadwarrior gateway vs. fixed peer)

Raised as a review comment on issue #139, not in the original scoping prompt.
Verified all three cited fields and both grammar-mapping claims in the
addendum against source — every citation checks out (one harmless
line-number drift, noted below):

- **`rmconf->remote->sa_family == AF_UNSPEC`** — confirmed load-bearing at
  `remoteconf.c:199-204` (`rmconf_match_type()`, comment literally says
  `/* No match at all: unwanted anonymous */`), not just documented. Grammar:
  `remote anonymous { … }` sets exactly this — `remote_index: ANONYMOUS ike_port
  { ...->sa_family = AF_UNSPEC; }` (`cfparse.y:1840-1846`).
- **`rmconf->passive`** ("never initiate", `remoteconf.h:117` — cited as `:113`
  in the review comment, off by 4 lines in this checkout, immaterial) —
  confirmed load-bearing at `isakmp.c:2164`, `pfkey.c:2859`, `pfkey.c:3027`
  (exact line matches), and *also* in `rmconf_match_type()` right next to the
  anonymous check (`remoteconf.c:207`). Grammar: `passive on|off;`
  (`cfparse.y:2057`, `PASSIVE SWITCH`).
- **`rmconf->gen_policy`** (`GENERATE_POLICY_NONE`=0/`REQUIRE`=1/`UNIQUE`=2,
  `remoteconf.h:122-125`) — confirmed load-bearing at `isakmp_quick.c:2425`,
  `isakmp_quick.c:2445`, `proposal.c:1237` (exact line matches).
  **Addendum answered:** the grammar (`cfparse.y:2095-2096`,
  `cftoken.l:350-352`) accepts *two* forms — `generate_policy on|off;` (the
  boolean `SWITCH` token, `on`→`TRUE`=1, `off`→`FALSE`=0) **or**
  `generate_policy require|unique;` (the `GENERATE_LEVEL` token,
  `require`→`GENERATE_POLICY_REQUIRE`=1, `unique`→`GENERATE_POLICY_UNIQUE`=2).
  Numerically, `on` and `require` produce the *identical* stored value (`1`) —
  there is no `none` keyword, only `off`, which stores `0`. So the JSON string
  values `"none"`/`"require"`/`"unique"` (matching the `#define` suffixes,
  same convention as every other enum-to-string mapping in this schema) are a
  clean, honest rendering, even though `"none"` isn't itself a literal
  config keyword — `off` is.

**On the recommendation to add a derived `client`/`gateway` role field:**
agree with the review comment's own reasoning for declining it, and would
apply it just as strongly here as it was applied to `pfs_group` (H-1) and
`xauth.error`: racoon can positively assert "this Phase-1 accepts any peer"
(the anonymous/passive/gen_policy combination above), but has no structural
way to distinguish a fixed, non-anonymous peer that's a site-to-site gateway
from one that's *this* racoon acting as a roadwarrior client dialing a known
gateway — both produce an identical `struct remoteconf` shape. A two-value
role enum would assert precision the source doesn't have.

Recommend adding the three raw fields only:

```json
"remote_config": {
  "anonymous": true,
  "passive": true,
  "generate_policy": "unique"
}
```

**Recommend against** the optional `config_pattern_hint` convenience string
the review comment offered as a "if you want" alternative — not because it's
technically wrong, but because it's precisely the shape of field this
document has twice already flagged as a mistake (H-1, `xauth.error`): a
single label that *looks* like something racoon asserts, backed by a
heuristic combination of unrelated fields, that someone six months from now
will read as ground truth rather than a guess. The three raw fields already
let any consumer compute the same heuristic client-side if they want it,
without racoon vouching for it. Your call if you'd rather have it anyway —
flagging the asymmetry (declined here, but offered as optional in the review
comment) rather than silently picking one.

### D6 — Phase1↔Phase2 association + `effective_group` (issue #140)

Raised during live sign-off of issue #139 (a BSI TR-02102 compliance
question): `phase2[].proposal.pfs_group` correctly renders `null` when no
PFS was negotiated, but per RFC 2409 §5.5 that doesn't mean "no DH group
protects this tunnel" — without a PFS exchange of its own, Phase 2 KEYMAT is
`prf(SKEYID_d, protocol | SPI | Ni_b | Nr_b)`, and `SKEYID_d` is derived from
the *parent Phase 1's* DH exchange. So the group actually backing the
tunnel's key entropy, when `pfs_group` is `null`, is the parent Phase 1's
`dh_group` — and the frozen v1.0 schema gave no way to find that parent from
a `phase2[]` entry.

**Ratified, additive (schema_version 1.0 → 1.1):**

```json
{
  "phase2": [
    {
      "phase1_index": "0xb16602f936e48393bff00320f00f8cf0",
      "proposal": {
        "pfs_group": null,
        "effective_group": 14
      }
    }
  ]
}
```

- `phase2[].phase1_index` — the parent Phase 1's cookie-pair string, same
  format as `phase1[].index` (both produced by `cookie_pair_hex()`,
  `status.c`), letting a consumer join the two arrays. Sourced from
  `iph2->ph1` (`struct ph2handle`, `handler.h`), a direct back-pointer set by
  `bindph12()`.
- `phase2[].proposal.effective_group` — equals `pfs_group` when PFS was
  negotiated, otherwise the parent Phase 1's `dh_group`; a single field a
  compliance checker can read without knowing the RFC 2409 fallback rule.

**Type-consistency rule (the actual reason this needed a decision, not just
an addition):** `phase1[].proposal.dh_group` is a **string** — populated via
`dupstr(s_attr_isakmp_group(iph1->approval->dh_group))`, a name-table
lookup, same convention as `enc_alg`/`hash_alg`/`auth_method`.
`phase2[].proposal.pfs_group` is a **number** (or `null`) — the raw
`iph2->approval->pfs_group` int. `effective_group` bridges both sources, and
naively inheriting whichever type its source happened to have would produce
a field whose JSON type depends on tunnel state (string when falling back to
Phase 1, number when equal to `pfs_group`) — worse than the gap this issue
closes. **Resolved by defining `effective_group`'s own type from scratch:
always a JSON number.** The fallback path reads `iph1->approval->dh_group`
directly (already an `int` in `struct isakmpsa`, `remoteconf.h`) rather than
parsing back out of the already-stringified `dh_group` field — no string
round-trip, and `phase1[].proposal.dh_group`'s existing string type is left
untouched (retyping it would be a breaking, major-bump change and is out of
scope here).

**Edge case, verified not hypothetical:** `iph2->ph1` can genuinely be
`NULL` — `unbindph12()` (`handler.c`) clears it, and is called from
`initph2()` and during phase2 teardown, both of which can run while the
`ph2handle` is still briefly enumerable. `collect_ph2()` guards this: when
`iph2->ph1` is `NULL`, `phase1_index` renders `null` and `effective_group`
renders `0` (not a valid real DH group id, so it doubles as "indeterminate"
without a separate null branch for a field required to always be a number).

---

### D7 — Phase 2 algorithm-name completeness (`AES-CBC`, `hmac-sha1`)

Found during live sign-off of #139/#140 and deliberately kept out of #140's
scope (its "Scope boundary" names this gap and defers it). Comparing
`racoonctl status -v -f json` against `setkey -DN` for the same established
SA (iOS roadwarrior, gateway side): the kernel reported `E: aes-cbc` with a
32-byte key and `A: hmac-sha1` with a 20-byte one, while `status` rendered
`"AES"` and `"hmac-sha"`.

The two phases render their proposals through different name tables, so the
same document described the same cipher family two ways:

| Field | Render source | Value |
|---|---|---|
| `phase1[].proposal.encryption_algorithm` | `s_attr_isakmp_enc()`, `name_attr_isakmp_enc[]` | `AES-CBC` |
| `phase2[].proposal.encryption_algorithm` | `s_ipsecdoi_trns_esp()`, `name_ipsecdoi_trns_esp[]` | `AES` |

**Direction chosen — derive in `status.c`, don't retarget the tables.**
Both alternatives were checked against source first:

- *Sibling table with fuller names?* No. `algorithm.c`'s `ipsec_encdef[]` /
  `ipsec_hmacdef[]` hold **config-grammar keywords** (`"aes"`, `"sha1"`),
  not display names; they carry no mode either, are file-static, and
  several entries are `#ifdef`'d out depending on the OpenSSL build. Not a
  usable substitute.
- *Fix `strnames.c` in place?* Rejected. Those tables are also the render
  path for racoon's `-dddd` proposal logging and are pinned by
  `test/test_strnames.c`, so editing them changes unrelated output for
  every existing consumer — a much wider blast radius than this fix earns.

**Mode is derivable from the transform ID alone**, so no key material or
key length is consulted: `crypto_openssl.c` implements exactly one mode per
cipher (`EVP_aes_{128,192,256}_cbc()`, `EVP_camellia_*_cbc()`,
`EVP_des_ede3_cbc()`, `EVP_bf_cbc()`, `EVP_cast5_cbc()`, `EVP_idea_cbc()`),
and the tree has **no CTR or GCM support at all**. `esp_trns_is_cbc()`
(`status.c`) enumerates the CBC transform IDs; `IPSECDOI_ESP_NULL` (not a
cipher) and `IPSECDOI_ESP_RC4` (a stream cipher) are excluded, as is an
unrecognized ID falling through to `num2str()`.

For authentication the gap was a **single truncated table entry**:
`name_attr_ipsec_auth[]` already names the variant for every SHA-2 entry
(`hmac-sha256`/`-sha384`/`-sha512`) and only renders
`IPSECDOI_ATTR_AUTH_HMAC_SHA1` as `hmac-sha`. `esp_auth_alg_name()`
restores that one entry to the table's own convention and defers to
`s_ipsecdoi_auth()` for everything else.

**No `schema_version` bump.** Both fields keep their type (string) and
their meaning ("the negotiated encryption/authentication algorithm"); only
the value's precision improves. Per D4 the bump ladder covers additive
fields (minor) and rename/remove/retype (major) — a content-quality fix in
an existing field is neither. A consumer matching on the old exact strings
would notice, but no such consumer can have been correct: `"AES"` never
distinguished a mode racoon could actually negotiate two of.

The schema's `x-source-render` citations for both fields were repointed at
`status.c`'s new helpers, keeping `tools/schema_cross_check.py` green. Each
citation stays a **single** `path:line (identifier)` pair — the checker's
regex only validates the first one in the string, so a second appended
citation would be unverified prose free to drift.

---

### D8 — Post-merge defect sweep (issue #143 F1–F4)

Four correctness defects found by reviewing the whole `1dc9149..9594445` arc
after it merged; none had been caught by the live four-machine test passes.
Recorded here because two of them changed a documented contract and the
reasons should not have to be re-derived.

**F1 — `admin_reply()` lost the entire reply on `EINTR`.** The `send()` loop
added for Finding H-4 used `sent += (size_t)n` as a `for` loop's increment
expression, and retried `EINTR` with `continue` — which *runs* that
increment, applying `sent += (size_t)-1`. From `sent == 0` the counter
wrapped to `SIZE_MAX`, the loop test failed at once, and the function
returned `0` for success having written nothing. Rewritten as a `while` loop
that advances `sent` only after a transfer. The `n == 0` case now returns an
error too: silently `break`ing out reported success on a short write, the
exact failure the loop exists to prevent. Signal handlers are installed
without `SA_RESTART` (`session.c`), so `EINTR` here is a real path.

**F2 — text renderer omitted numeric selector proto/ports.** The non-`any`
branch of three ternaries yielded `""`, so a real selector rendered as
`proto= sport= dport=`. This violated D5/#139's mandatory-interface rule
directly (text may differ from JSON in layout only, never in what data is
shown), and it was invisible to the tests because every text fixture used the
all-`any` path. Fixed via `selector_field_str()`.

**F3 — `dpd` block was gated on `ENABLE_HYBRID`.** `collect_dpd()` was
defined *and* called inside `#ifdef ENABLE_HYBRID`, though DPD (RFC 3706) has
no hybrid dependency and `--enable-hybrid`/`--enable-dpd` are independent
`configure` options. A `--disable-hybrid --enable-dpd` build ran DPD but
never emitted the schema-documented block. Moved out to sit beside
`collect_natt()`, which already had the right shape (defined unconditionally,
body guarded by its own `#ifdef`). **Generalizable rule: a collector's
`#ifdef` guard belongs on its own feature, in its own body — never inherited
from the block it happens to be declared in.**

**F4 — SPI placeholder contradicted the published schema, and the fix is a
minor bump (1.1 → 1.2).** `collect_ph2()` pre-seeded `spi_in`/`spi_out` with
`"0x00000000****"` — 8 hex digits where `mask_spi()` and the schema pattern
`^(0x[0-9a-f]{4}\*\*\*\*|\?)$` both specify 4. That placeholder is what
actually rendered for any Phase 2 handle enumerated before its proposal was
approved (`PHASE2ST_START`, `PHASE2ST_GETSPISENT`, …), so a `status -v -f
json` taken during any in-flight negotiation emitted a document failing the
project's own schema.

Two fixes were possible and the choice was deliberate, not incidental:
padding the placeholder to 4 digits would have kept the type stable but kept
*asserting an all-zero SPI that was never on the wire*. Rendering `null`
instead says "not negotiated yet" honestly. Chosen: `null`, with the schema
type widened to `["string", "null"]`.

**Why that is a minor bump under D4, not major:** D4 reserves major for
rename/remove/**retype** of an existing field. Widening a type *union* is
additive — every document valid under 1.1 remains valid under 1.2, because
the string branch is unchanged and only a new permitted value was added. The
direction of the change is what matters: narrowing a union would break
existing consumers and would be major. Consumers that assumed `spi_in` was
always a string need a `// "pending"`-style fallback, which is the normal
cost of a minor bump and why the version moved at all rather than the fix
shipping silently. The RFC-0001 harness pins on major and is unaffected.

Note also that JSON Schema applies `pattern` only to string instances, so
keeping the pattern alongside the widened type constrains the string branch
and ignores `null` — the intended reading, and the reason the pattern did not
need loosening.

**Not fixed, deliberately** — the same review's two low-severity findings
(#143 L1, an unreachable-today leak-by-construction in the transform loop,
and L2, AH's authentication algorithm being reported in
`encryption_algorithm`) remain open. L2 in particular is a *field-meaning*
change for AH SAs and would be a **major** bump under D4, which is why it is
a standalone decision rather than something folded into this sweep.

---

### D9 — AH reports an authentication algorithm, not an encryption one (#143 L2), and L1

Closes the two low-severity findings D8 deliberately left open, at the
maintainer's request after the F1–F4 fixes were live-verified.

**L1 — the transform loop.** `collect_ph2()` walked `proto->head`'s `satrns`
list assigning over `p->enc_alg`/`auth_alg`/`comp_alg` on each pass without
freeing the previous pointer. Unreachable today, and now verified why rather
than assumed: `cmpsaprop_alloc()` (`proposal.c`), which builds
`iph2->approval`, calls `newsatrns()`/`inssatrns()` exactly once per matched
`saproto`, so an approved proposal carries one transform per protocol by
construction. The loop is replaced by a single `proto->head` read — what the
code always meant, and structurally incapable of leaking. (Note the old loop
kept the *last* transform; reading `->head` keeps the first. Identical while
the invariant holds, which is the point.)

**L2 — AH's transform moved to `authentication_algorithm`.** AH provides
integrity only and encrypts nothing, so reporting its transform name in
`encryption_algorithm` answered "what cipher protects this SA" with a hash
name. It now populates `authentication_algorithm`, and
`encryption_algorithm` renders `null` for AH.

**Two pre-existing defects surfaced while doing it, both fixed here:**

1. `authentication_algorithm` was declared `"type": "string"` in the schema
   but *already* rendered `null` — for AH SAs, and for any ESP transform
   negotiated with `IPSECDOI_ATTR_AUTH_NONE`. Both cases therefore emitted a
   document that failed the project's own schema, exactly the F4 defect class
   in the very field L2 moves. Confirmed by validating a reproduction of the
   1.2 AH rendering against the 1.2 schema: `None is not of type 'string'`.
   Both algorithm fields are now `["string", "null"]`.
2. The text renderer passed `p->enc_alg`/`p->auth_alg` straight to a `%s`
   conversion. `auth_alg` was **already** `NULL` for AH and null-auth ESP
   before this change, so text rendering of those SAs was undefined
   behaviour. glibc prints `(null)` and hid it; this tree also targets
   NetBSD. Both now substitute `(none)` explicitly.

**Version: 1.3, a minor bump — and this one is a judgement call, recorded
with its counter-argument rather than presented as obvious.**

The argument for **major** is straightforward and was raised before the
change: D4 reserves major for "rename/remove/retype an existing field", and
for an AH SA a value moved out of `encryption_algorithm` (now `null`) into a
different field. A consumer reading `encryption_algorithm` to inventory AH
SAs sees a behavioural break, which is what major exists to signal.

The argument for **minor**, which is what was chosen:

- The schema-level change is purely a *widening* of two type unions, the
  same additive direction as F4's 1.1 → 1.2. Every document that validated
  under 1.2 still validates under 1.3.
- No consumer can have been *correctly* depending on the old behaviour.
  `encryption_algorithm` is documented as the negotiated cipher; AH has no
  cipher. The old value was a defect, not a contract — and per (1) above, an
  AH document did not even conform to the published schema, so there was no
  valid 1.2 AH contract to break.
- D4's own stated purpose for major is the RFC-0001 harness, which pins on
  major. Forcing a harness change for a fix affecting only AH SAs would
  spend the major bump on the least-used protocol path.

This is the same reasoning that let #142's `AES` → `AES-CBC` precision fix
ship without any bump, extended one step: there the field's value became
more precise, here a value that was never a valid answer for that field
moved to the field it actually answers. Anyone who disagrees should read the
break as real and treat 1.3 as a major bump in effect — the substantive
change is documented above either way, which matters more than the number.

**AH SAs remain reported by `protocol: "AH"`**, so a consumer that wants to
branch on protocol rather than sniff algorithm fields always could, and
still can.

---

## 4. Findings

### High

- **H-1 — `phase1[].proposal.pfs_group` has no backing field.** Covered in D3.
  Concrete failure mode if implemented as the discarded first draft did it: reads
  a *global* `isakmp_cfg_config.pfs_group` and reports it as if it were this
  specific SA's negotiated PFS group — wrong for any daemon proxying multiple
  peers with different configs. *Remedy:* drop the field from phase1. *Effort:*
  none (it's a subtraction). *In scope:* Y.

- **H-2 — CORRECTED post-implementation, see below. Original text (struck
  through, kept for the record):**
  ~~`ipsecdoi_id2str()` returns a pointer into a `static char buf[512]`
  (`ipsec_doi.c:4241`), not a heap allocation. Not reentrant, not stable
  across a second call. ... *Remedy:* `strdup()` (or copy into the JSON/text
  buffer) immediately after each call, before calling it again for anything
  else.~~
  **This was half right and half wrong, and the wrong half caused a real bug.**
  `ipsecdoi_id2str()` does use `static char buf[BUFLEN]` (`ipsec_doi.c:4241`)
  — but purely as scratch space while building the string. Before it
  returns, it unconditionally allocates a fresh, exact-sized copy
  (`ipsec_doi.c:4429-4435`: `ret = racoon_malloc(len+1); memcpy(ret, buf,
  len); ret[len] = 0; return ret;`) and hands that back — **the caller
  already owns a clean heap pointer, not a pointer into the static buffer.**
  The reentrancy hazard is real for the function's *internal* construction
  (and moot anyway per D2's single-threaded event-loop proof — nothing else
  can run mid-construction), but it does not apply to the *returned* value
  at all. `status.c`'s `collect_ph1()` followed this finding's original
  remedy literally — `dupstr(ipsecdoi_id2str(...))`, i.e. an
  already-heap-owned pointer wrapped in a second `racoon_strdup()` — which
  is a double allocation: the `ipsecdoi_id2str()` result itself was never
  referenced again and leaked on every `status` call that rendered an SA
  with a non-address identity. Confirmed by Valgrind on a live gateway and
  roadwarrior client (two loss records, growing linearly with the number of
  `status` polls) and fixed by taking direct ownership of the return value
  instead of wrapping it. *Corrected remedy:* only wrap a call in
  `dupstr()`/`racoon_strdup()` after confirming the callee actually returns
  a pointer into a shared/static buffer (e.g. `saddr2str()`, which genuinely
  does) — check the callee's own source, don't assume from a `static`
  keyword's mere presence in the function body. *In scope:* Y (the guidance
  itself needed the fix, not just the code that followed it).

- **H-3 — `struct xauth_state` (`isakmp_xauth.h:76-89`) holds the XAuth password
  in cleartext** (`authdata.generic.pwd`) **and the LDAP user DN**
  (`udn`, `#ifdef HAVE_LIBLDAP`) **directly on the live `ph1handle`.** Any code
  walking `iph1->mode_cfg->xauth` for `status` must explicitly avoid these two
  fields — there's no structural barrier stopping a future contributor from
  reading `xauth.authdata.generic.pwd` "just to double check the username field is
  right" and it ending up in a debug print or, worse, a schema field. Given the
  "no secrets in any output" requirement is already explicit in the prompt, this
  is the concrete field to name in a code comment at the point of use. *In scope:*
  Y (implementation guardrail).

- **H-4 — `admin_reply()` (`admin.c:875`) does not loop on `send()`.** A single
  `send(so, retbuf, tlen, 0)` call, return value only checked for `< 0`. POSIX
  permits a partial write on a `SOCK_STREAM` socket (confirmed `AF_UNIX`/
  `SOCK_STREAM`, `admin.c:982`) for any payload exceeding the kernel's per-call
  transfer capacity; a partial send here is silently treated as success and the
  unsent remainder is dropped. Pre-existing across every admin command, but
  `status` is the first reply large enough (multiple SAs, full XAuth/mode-config
  JSON, `-v` phase2 array) to plausibly hit it on a busy gateway — and a
  truncated send produces truncated, invalid JSON, breaking the "one
  self-contained JSON document per invocation" contract outright. The client
  side (`com_recv()`, `kmpstat.c:200-213`) already loops correctly on `recv()`;
  fixing `admin_reply()` to do the mirror-image loop on `send()` is small and
  self-contained. *Remedy:* wrap the `send()` in a `while (sent < tlen)` loop.
  *Effort:* small. *In scope:* Y — acceptance criterion for Phase 4, not a
  Phase 3 blocker.

### Medium

- **M-1 — Skeleton omits NAT-T and DPD state** despite the problem statement
  naming both as in-scope RFC concepts and both being real, already-populated
  fields on `struct ph1handle` (`dpd_support`/`dpd_fails`/`dpd_last_ack` under
  `ENABLE_DPD`; `natt_options`/`natt_flags` under `ENABLE_NATT`). *Remedy:*
  decide in/out for v1 of the schema (D3). *Effort:* small if in — same
  extraction pass, a few more JSON keys. *In scope:* your call.

- **M-2 — `dns4` is `struct in_addr dns4[MAXNS]`, not a `sockaddr`**
  (`isakmp_cfg.h:187`). The discarded first draft cast a `struct in_addr*` to
  `struct sockaddr*` and called `getnameinfo()` on it with `salen =
  sizeof(struct in_addr)` — invalid, return value unchecked, and (worse) fed an
  uninitialized stack buffer into `strdup()` on the implied failure path. Correct
  approach is `inet_ntop(AF_INET, &dns4[i], buf, sizeof(buf))` directly, no
  `sockaddr` involved. Naming this explicitly so Phase 4 doesn't reintroduce the
  same bug under a different implementation. *In scope:* Y (implementation
  guardrail).

- **M-3 — Man page target is `racoonctl.1`, not `racoonctl.8`** (§1 table).
  Trivial, but worth fixing in the Phase 3 issue text so Phase 5 doesn't chase
  the wrong filename. *In scope:* Y.

- **M-4 — `status_dump()`'s `ph1tree`/`ph2tree` extraction pass needs no locking,
  and this needs to be written down where the next reader will actually see it.**
  §2.1's call-chain trace establishes racoon's event loop is strictly
  single-threaded (`monitor_fd()`-dispatched, one fd at a time) — `admin_process()`
  cannot run concurrently with, or interleave into, whatever is mutating a
  `ph1handle`/`ph2handle` at the time of a `status` poll. This is a genuine
  implementation simplification (no mutex, no copy-then-release-lock dance, no
  "handle could vanish mid-read" defensive coding beyond the ordinary NULL/list
  checks), but it's exactly the kind of non-obvious invariant that gets silently
  "fixed" by someone who didn't do this trace and adds defensive locking that
  isn't needed — or worse, doesn't add it in the one place it's genuinely
  needed elsewhere. *Remedy:* a short comment at the top of `status_dump()`'s
  extraction loop in Phase 4, stating the single-threaded-event-loop invariant
  and pointing at this document (or the frozen issue) rather than re-deriving it.
  *Effort:* one comment block. *In scope:* Y (implementation guardrail,
  mandatory per your instruction, not optional like M-1/L-1).

### Low

- **L-1 — `compression_algorithm` (IPComp) has a real config keyword and struct
  field** (`cftoken.l:311`, `struct saproto`) **but isn't in the skeleton.**
  Covered under D3/M-1-adjacent; listed separately since it's cheaper than DPD/
  NAT-T (one more transform-table lookup, same shape as encryption/auth) if you
  want it. *In scope:* your call.

- **L-2 — No JSON library anywhere in this tree** (`configure.ac` has no
  jansson/json-c/cjson `PKG_CHECK_MODULES`). Confirms hand-rolling a small JSON
  writer server-side (per D1) is the only option that doesn't add a new build
  dependency — noting it as a confirmed constraint, not a proposal to add one.
  *In scope:* N (informational only).

---

## 5. Ratified decisions

All four decision points closed. Status: **Approved — proceeding to Phase 3.**

1. **D1** — server-side JSON + text rendering, format selected via `ac_proto`.
   `admin_reply()`'s missing `send()` loop promoted to Finding H-4, added as a
   Phase 4 acceptance criterion (not a Phase 3 blocker).
2. **D2** — `status` stays scoped to live state only; no `last_error` field.
   The `evt.c` optdata-enrichment mechanism that *would* actually serve the
   headline use case is noted as explicit future/out-of-scope work in the issue,
   not filed as its own issue yet.
3. **D3** — `schema_version` rename, drop `phase1[].proposal.pfs_group`, keep
   `remote_id`/`local_id`, NAT-T + DPD in for v1 (IPComp/`compression_algorithm`
   may slip to a follow-up if Phase 4 scope runs long), and drop
   `phase1[].xauth.error` (no backing `XAUTHST_FAILED` state exists — same root
   cause as `pfs_group`, surfaced during the freeze pass).
4. **D4** — `schema_version` is `"major.minor"`; additive fields bump minor,
   breaking changes bump major; any future JSON consumer needs only
   major-version awareness to stay compatible across minor bumps (see the
   corrected RFC-0001 note under D4 above — no such consumer exists today).
5. **D5** (added via issue #139 review comment) — `phase1[].remote_config`
   (`anonymous`/`passive`/`generate_policy`, all three source-verified against
   `remoteconf.c`/`isakmp.c`/`pfkey.c`/`isakmp_quick.c`/`proposal.c`) added to
   the schema. A derived `client`/`gateway` role label was proposed and
   declined — no struct-backed way to distinguish a fixed-peer site-to-site
   config from a roadwarrior client's own config, both look identical. The
   **JSON field set is now the mandatory interface**: `text` output must
   present the same fields, differing only in layout — tightens the earlier,
   looser "text and json may diverge stylistically" note.

### Frozen JSON schema v1

Reflects every ratified correction above (§3 has the reasoning for each).

```json
{
  "schema_version": "1.0",
  "timestamp": "2025-01-15T10:30:00Z",
  "phase1": [
    {
      "index": "0x12345678",
      "state": "ESTABLISHED",
      "remote_id": "192.168.1.1",
      "local_id": "10.0.0.1",
      "version": "1.0",
      "exchange_mode": "MAIN",
      "proposal": {
        "encryption_algorithm": "AES256",
        "hash_algorithm": "SHA256",
        "authentication_method": "PRE_SHARED_KEY",
        "dh_group": 14,
        "lifetime_time": 28800
      },
      "xauth": {
        "state": "OK",
        "auth_type": "GENERIC",
        "username": "user1"
      },
      "mode_cfg": {
        "addr4": "10.0.0.50",
        "dns4": ["10.0.0.1"],
        "split_include": ["10.0.1.0/24"]
      },
      "dpd": { "supported": true, "fails": 0 },
      "natt": { "enabled": true },
      "remote_config": {
        "anonymous": true,
        "passive": true,
        "generate_policy": "unique"
      }
    }
  ],
  "phase2": [
    {
      "index": "0x87654321",
      "state": "ESTABLISHED",
      "spi_in": "0x1234****",
      "spi_out": "0x8765****",
      "protocol": "ESP",
      "encmode": "TUNNEL",
      "selectors": {
        "src": "10.0.0.0/24",
        "dst": "192.168.1.0/24",
        "protocol": "any",
        "src_port": "any",
        "dst_port": "any"
      },
      "proposal": {
        "encryption_algorithm": "AES256",
        "authentication_algorithm": "HMAC_SHA2_256",
        "pfs_group": 14,
        "lifetime_time": 3600,
        "lifetime_bytes": 0
      },
      "reqid_in": 1,
      "reqid_out": 2,
      "ok": true
    }
  ]
}
```

Changes from the original skeleton, at a glance: `version` → `schema_version`
(top level, renamed); `phase1[].version` now `"major.minor"` string, not a raw
byte; `phase1[].proposal.pfs_group` removed; `phase1[].xauth.error` removed;
`mode_cfg.flags`/`mode_cfg.pfs_group` removed (both were either raw internal
bitmasks or the same non-per-SA global value `pfs_group` was, never verified as
real per-SA data); `dpd`/`natt` blocks added (new, v1-in per D3); `phase2[].proposal.pfs_group` value must come from `iph2->approval` (the
matched/negotiated result), not `iph2->proposal` or local `sainfo` config — see
the DH-group-vs-PFS-group discussion earlier in this review. `phase2[].pfs_group == 0`
must render as PFS genuinely absent (e.g. omit the key or `null`), never as a
bogus group number. `compression_algorithm` intentionally held back per D3
pending a Phase 4 scope check. `phase1[].remote_config` added per D5.

**Phase 3 done:** [issue #139](https://github.com/rdratlos/racoon-ipsec-tools/issues/139)
consolidates this schema, the D1–D4 rationale (including the §2.1 call-chain
block verbatim), and the acceptance criteria (including H-4's `send()` loop fix
and the live-test matrix). A review comment on the issue added D5
(`remote_config`) and tightened the text/JSON relationship (§ D5 above,
issue comment incorporated and replied to). **⏸ Waiting for the go before any
Phase 4 code**, on `feature/racoonctl-status` fresh off `develop`.

## 6. Sign-off (issues #139, #140)

**✔ Closed.** Both issues are fully live-verified, not just unit-tested:

- **Live platform matrix:** gateway, Ubuntu Bionic (i386), Arch Linux, and
  Ubuntu Noble roadwarrior clients — `-v`/`-f json` parsing (Bug 1),
  `ipsecdoi_id2str()` leak fix (Bug 2, live pre/post Valgrind capture on the
  gateway), the `pfs_group` null/nonzero render split (Bug 3, both branches
  seen live), and D6's `phase1_index`/`effective_group` addition (issue
  #140, both PFS branches) all confirmed against real hardware, cross-checked
  against each platform's own `setkey -DN` output where applicable — not
  simulated or asserted from this sandbox alone (which has no PF_KEY-capable
  kernel and cannot run a live daemon; see the repeated sandbox-limitation
  notes throughout this document).
- **`make check`:** 77/77 passing, including every `status`/`racoonctl`
  suite added or touched across both issues.
- **`check-valgrind`:** clean (0 errors, 0 leaks) across the full
  `check_PROGRAMS` suite, reproduced independently during review on top of
  the maintainer's own live gateway run — both `test_status_dump` and
  `test_racoonctl_status_cli` included, the latter covering the isolated
  `-v` case specifically (the exact case Bug 1's `getopt()` defect had
  silently broken).
- **`make distcheck`:** green, both build passes, `# FAIL: 0` / `# ERROR: 0`.

No further `status.c` changes are in scope from this point — the feature
arc these two issues opened is closed. The one new artifact to come out of
closing them is `share/schema/racoonctl-status.schema.json` (D6 already
documented above; the schema file itself, its provenance-annotation
convention, and its CI wiring are tracked as their own deliverable, not
re-litigated here).

---

## 7. Working with the JSON output (`jq` recipes)

Every command below was run against **real** `status_dump()` output captured
from the render path (schema_version 1.3), not hand-written examples.

`racoonctl status` needs read access to the admin socket, so these normally
run as root; `-v` is required for any `phase2[]` query, since a non-verbose
reply omits the key entirely (D3).

### Validity gate

The one to reach for first, and the one worth putting in a CI or monitoring
job. `jq -e` exits non-zero on malformed input, so this fails loudly on a
truncated or corrupted reply rather than printing something that merely looks
odd:

```sh
racoonctl status -v -f json | jq -e . > /dev/null \
    && echo "status output is valid JSON" \
    || echo "status output is NOT valid JSON" >&2
```

This is exactly the check that would have caught the `admin_reply()`
truncation class of bug (Finding H-4, and issue #143 F1's `EINTR`
regression) from the outside, without reading any C.

To read it as a human, pipe it through unfiltered:

```sh
racoonctl status -v -f json | jq .
```

### Validating against the published schema

`jq` checks syntax, not conformance. For the real thing, validate the
document against `share/schema/racoonctl-status.schema.json` — this is what
catches a field whose *shape* drifted from the contract (issue #143 F4 was
precisely that: an 8-hex-digit SPI placeholder against a 4-digit pattern):

```sh
# pipx install check-jsonschema, or pip install check-jsonschema
racoonctl status -v -f json > /tmp/status.json
check-jsonschema --schemafile share/schema/racoonctl-status.schema.json \
    /tmp/status.json
```

Equivalent with the `jsonschema` Python module, if that is what is already
installed:

```sh
racoonctl status -v -f json \
  | python3 -c 'import json,sys,jsonschema; \
      jsonschema.validate(json.load(sys.stdin), \
        json.load(open("share/schema/racoonctl-status.schema.json"))); \
      print("conforms")'
```

### One line per Phase 2 SA

`// "pending"` supplies the fallback for a `null` SPI — a Phase 2 handle
enumerated before its proposal was approved (issue #143 F4):

```sh
racoonctl status -v -f json | jq -r '
  .phase2[]?
  | [ .index, .protocol, .encmode,
      .proposal.encryption_algorithm,
      .proposal.authentication_algorithm,
      (.spi_in // "pending") ]
  | @tsv'
```

```
0x87654321	ESP	Tunnel	AES-CBC	hmac-sha256	0x1234****
```

### BSI TR-02102 minimum-group audit

The motivating query behind D6. Reads `effective_group`, **not**
`pfs_group`: a `null` `pfs_group` does not mean the tunnel is unprotected, it
means the parent Phase 1's group is what backs its key material (RFC 2409
§5.5). Prints nothing when every SA is compliant, so it composes into a
cron/monitoring check:

```sh
racoonctl status -v -f json | jq -r '
  .phase2[]?
  | select(.proposal.effective_group < 14)
  | "WEAK \(.index) group=\(.proposal.effective_group)"'
```

```
WEAK 0x11112222 group=2
```

### Joining Phase 2 back to its parent Phase 1

What `phase1_index` (D6) exists for. `// "unbound"` covers the window where
`iph2->ph1` is momentarily `NULL` and `phase1_index` renders `null`:

```sh
racoonctl status -v -f json | jq -r '
  . as $d
  | $d.phase2[]?
  | . as $p2
  | "\($p2.index) -> \(($d.phase1[]?
        | select(.index == $p2.phase1_index)
        | .index) // "unbound")"'
```

```
0x87654321 -> 0xaabb
0x11112222 -> 0xaabb
```

### Phase 2 SAs still negotiating

SAs that have no SPIs yet — useful for spotting a Quick Mode that is stuck
rather than established:

```sh
racoonctl status -v -f json | jq -r '
  .phase2[]? | select(.spi_in == null) | "\(.index) \(.state)"'
```

```
0x11112222 getspisent
```

Note this is a schema_version 1.2-and-later idiom. Under 1.1 the same handle rendered
a bogus `"0x00000000****"` string, so `select(.spi_in == null)` matched
nothing and there was no reliable way to ask this question.
