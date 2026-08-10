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
| Identity helper `ipsecdoi_id2str()` | **Confirmed to exist** (`ipsec_doi.c:4235`, declared `ipsec_doi.h:232`) — **but see Finding H-2**, it is not safe to call the way the prompt implies. |
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
renderer always ship together. The only real skew risk is an **external JSON
consumer** (the RFC-0001 harness) pinned to an old `schema_version` talking to a
newer daemon; that's a contract-versioning policy question (additive-only minor
bumps vs. breaking major bumps) worth one sentence in the frozen issue, not more.

**Ratified.** `schema_version` is `"major.minor"`. Additive changes (new
optional field) bump minor only; breaking changes (rename/remove/retype an
existing field) bump major. The RFC-0001 harness pins on major only, so it
keeps working across minor bumps without a harness change.

---

## 4. Findings

### High

- **H-1 — `phase1[].proposal.pfs_group` has no backing field.** Covered in D3.
  Concrete failure mode if implemented as the discarded first draft did it: reads
  a *global* `isakmp_cfg_config.pfs_group` and reports it as if it were this
  specific SA's negotiated PFS group — wrong for any daemon proxying multiple
  peers with different configs. *Remedy:* drop the field from phase1. *Effort:*
  none (it's a subtraction). *In scope:* Y.

- **H-2 — `ipsecdoi_id2str()` returns a pointer into a `static char buf[512]`**
  (`ipsec_doi.c:4241`), **not a heap allocation.** Not reentrant, not stable across
  a second call. A `status_dump()`-style function that calls it once per SA in a
  loop, or calls it twice for the same entry (once for `local_id`, once for
  `remote_id`), will silently clobber the first string with the second before
  either is copied out — this is a real, easy-to-hit landmine for whoever
  implements Phase 4, and it's the kind of bug that only shows up with ≥2 active
  SAs, so a single-tunnel smoke test won't catch it. *Remedy:* `strdup()` (or copy
  into the JSON/text buffer) immediately after each call, before calling it
  again for anything else. *Effort:* trivial, but must be called out in the issue
  since it's exactly the shape of bug the review of the first draft was full of
  (leaked/dangling short-lived pointers). *In scope:* Y (implementation guardrail,
  not a design decision).

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
   breaking changes bump major; the RFC-0001 harness pins on major only.

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
      "natt": { "enabled": true }
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
pending a Phase 4 scope check.

**Phase 3 done:** [issue #139](https://github.com/rdratlos/racoon-ipsec-tools/issues/139)
consolidates this schema, the D1–D4 rationale (including the §2.1 call-chain
block verbatim), and the acceptance criteria (including H-4's `send()` loop fix
and the live-test matrix). **⏸ Waiting for the go before any Phase 4 code**,
on `feature/racoonctl-status` fresh off `develop`.
