> **Archived.** Superseded by [doc/dev/v0.9.1-hardening-spec.md](../dev/v0.9.1-hardening-spec.md)#61-pr-65--netbsd-portability-review as of 2026-08-04; retained for provenance. See also git tag `archive/pre-doc-consolidation`.

# Security & Correctness Review: NetBSD Portability Branch (PR #65 / Issue #64)

**Status: FINAL — PR #65 merged into `develop`, all tracked issues closed**

| | |
|---|---|
| Review scope | `224b99f` (v0.9.0 tag) → `develop` @ `8e3cb79` (PR #65 merge commit) |
| Branch reviewed | `64-fix-all-portability-regressions` (history rewritten post-review to align commit trailers with Linux kernel conventions; final head `784cc68`) |
| Parent issue | [#64 — Fix all portability regressions exposed by NetBSD 10 build](https://github.com/rdratlos/racoon-ipsec-tools/issues/64) (closed, `completed`) |
| Pull request | [#65](https://github.com/rdratlos/racoon-ipsec-tools/pull/65) — merged 2026-07-12T23:05:02Z into `develop` @ `5e6abba` → `8e3cb79`, 23 commits, +1129/-71, 29 files |
| Sub-issues discovered during this review | [#68](https://github.com/rdratlos/racoon-ipsec-tools/issues/68), [#69](https://github.com/rdratlos/racoon-ipsec-tools/issues/69), [#70](https://github.com/rdratlos/racoon-ipsec-tools/issues/70), [#71](https://github.com/rdratlos/racoon-ipsec-tools/issues/71) — all closed, `completed` |
| Anchor commits (stable across the branch rewrite) | `224b99f`, `5e6abba`, `a2eb664` — all three still resolve on `develop` |

This document supersedes the review delivered inline in chat prior to PR #65's merge. It reflects the final, merged, closed state of every item tracked below.

---

## 1. Two datasets under review

Two independent bodies of work are compared:

- **Dataset A — Post-v0.9.0 security-hardening audits.** Everything found and fixed on `develop` between the `v0.9.0` tag (`224b99f`) and the pre-portability baseline (`5e6abba`, PR #63's merge point) — 47 commits.
- **Dataset B — NetBSD portability branch.** Everything found and fixed on `64-fix-all-portability-regressions`, starting at `a2eb664` and landing via PR #65 — 23 commits (merge included), now fully in `develop` as of `8e3cb79`.

`224b99f..develop` (current `HEAD`) spans **71 commits** total (47 from Dataset A + the 23 that came in with PR #65 + `8e3cb79` itself).

---

## 2. Dataset A — Post-v0.9.0 security audits (`224b99f..5e6abba`)

12 issues carrying the `security` label were opened and closed within this range:

| Issue | Title | Labels | Severity |
|---|---|---|---|
| #26 | `xauth_ldap_init_conf()` off-by-one — `vmalloc` without NUL terminator | bug, security | — |
| #32 | Audit findings: latent buffer overflow, timing side-channel, EVP shim issues (OpenSSL 3.x) | bug, openssl-migration, security | — |
| #34 | Hardening: replace `memcmp` over crypto material with `CRYPTO_memcmp` | bug, security | — |
| #35 | 7 audit findings: private key leak, error queue, compat wrapper, alignment, unchecked malloc, silent DH failure, ownership docs | bug, openssl-migration, security | — |
| #37 | Pre-auth OOB read in `t2isakmpsa()` — unchecked SA transform attribute length | bug, memory, security, pre-auth | **high** |
| #38 | Pre-auth OOB read in `vendorid_frag_cap()` — missing FRAGMENTATION VID length check | bug, fragmentation, security, pre-auth | low |
| #39 | Pre-auth OOB read in `check_vendorid()`/`lookup_vendor_id_by_hash()` on short Vendor ID | bug, security, pre-auth | low |
| #40 | NULL deref in `isakmp_frag_reassembly()` cleanup on empty chain | bug, fragmentation, security | low |
| #41 | Off-by-header attribute bound in `isakmp_cfg_reply()` — OOB read (XAuth/mode-config) | bug, security | low |
| #50 | Add OpenSSL 1.1/3.x compatible X.509 test CA framework | enhancement, security, testing, infrastructure | — |
| #52 | Unit tests for X.509 cert functions using cert-framework fixtures | security, testing | — |
| #57 | Weak unit test coverage in `plog.c` / `rsalist.c` | security, testing | — |

All 12 are closed. This is the codebase state PR #65 was rebased onto — i.e., Dataset B assumes all of the above is already fixed.

Four of these (#37–#41, minus #37) reappear as **upstream** tracking issues against NetBSD's own `racoon` fork (#44, #45, #46, #47, all still `open`, labeled `upstream`) — filed so the fixes developed in this repository can be offered back upstream. They are informational cross-references, not separate findings against this codebase.

---

## 3. Dataset B — NetBSD portability branch (PR #65)

### 3.1 As documented in issue #64 / PR #65

Issue #64's own tracking tables enumerate **34 numbered items** (items 1–23, 25–35; item 24 is a deliberate gap — see §4) across seven categories:

| Category | Items | Count |
|---|---|---|
| Header Portability | 1–9 | 9 |
| Yacc/Bison Portability | 10–11 | 2 |
| String Handling (`strncpy`→`strlcpy`) | 12–18 | 7 |
| Socket/BSD Portability | 19–21 | 3 |
| Buffer Over-Read Fixes | 22, 23 | 2 |
| Test Fixes | 25–31 | 7 |
| Build System | 32–34 | 3 |
| Memory Leak | 35 | 1 |
| **Total** | | **34** |

Of these, the two with direct security relevance beyond "portability build fix" are:

- **Item 22** — `isakmp_frag.c`: `vendorid_frag_cap()` read past a truncated FRAGMENTATION VID (mirrors upstream issue #44 / CWE-125).
- **Item 23** — `vendorid.c`: `check_vendorid()`/`lookup_vendor_id_by_hash()` read past a short Vendor ID payload (mirrors upstream issue #45 / CWE-125).
- **Item 35** — `crypto_openssl.c`: `eay_get_pkcs1pubkey()` leaked an `X509` object (resource exhaustion under repeated invocation, not memory-corruption).

### 3.2 Findings discovered independently during this review (B1–B4)

None of the 34 documented items above were mis-scoped — but four **additional, undocumented** defects were found while auditing the branch's `strncpy`→`strlcpy` conversion work (category "String Handling", items 12–18) and its `f_logoutusr()` fix specifically. All four are now filed, fixed, and closed:

| ID | Issue | CWE | Severity | Fixing commit | Fixed in |
|---|---|---|---|---|---|
| B1 | [#68](https://github.com/rdratlos/racoon-ipsec-tools/issues/68) — `f_logoutusr()` writes 1 byte past its `vmalloc`'d buffer | CWE-787 | low | `3209d22` | PR #65 |
| B2 | [#69](https://github.com/rdratlos/racoon-ipsec-tools/issues/69) — `strlcat()` fallback macro underflows its bound (`size_t` wraparound) | CWE-191 → CWE-787 | low | `3ab5c2a` | PR #65 |
| B3 | [#70](https://github.com/rdratlos/racoon-ipsec-tools/issues/70) — `strlcpy()` fallback has wrong return value, violates `siz==0` no-write contract | contract/logic (no direct CWE claimed) | low | `1702337` | PR #65 |
| B4 | [#71](https://github.com/rdratlos/racoon-ipsec-tools/issues/71) — `f_logoutusr()` silently truncates username by 1 char (**regression introduced by B1's own fix**) | CWE-704 | low | `784cc68` | follow-up, `claude/issue-68-regression-test` → `develop` |

B1–B3 were found by tracing which `strncpy`→`strlcpy` conversions in the branch were purely mechanical renames versus actual bound-fixing changes; all three were confirmed to be real, already-fixed defects in the branch's own diff (not merely pre-existing issues left untouched). B4 is notable as a case of **the fix for a filed security bug (B1) introducing a new, 100%-reproducible correctness bug**, caught only because a regression test was subsequently written per the reviewer's own suggestion (see §5).

B1 and B4 form a single before/after pair on the same three lines of `f_logoutusr()`:

```c
/* pre-B1: strncpy(dst, user, userlen+1) into a userlen-byte buffer  → 1-byte heap overflow, every call */
/* B1 fix: strlcpy(dst, user, buf->l - sizeof(admin_com))            → safe, but truncates by 1 char, every call (B4) */
/* B4 fix: make_request(ADMIN_LOGOUT_USER, 0, userlen + 1)           → buffer sized correctly for strlcpy's NUL byte */
```

All four now carry the `bug`/`security` (B1, B2, B4) or `bug` (B3, filed without `security` pending independent confirmation of its write-on-`siz==0` claim) labels plus `severity: low`, consistent with this project's existing high/low calibration — reserved `severity: high` for remotely-reachable, pre-authentication classes (cf. Dataset A's #37), all of Dataset B's findings being local-admin-socket-only or build-time-only.

---

## 4. Audit-integrity finding: fabricated entries in the original PR #65 description

During the initial review, PR #65's (and issue #64's, at the time) "Buffer Over-Read Fixes" table carried two additional bullets beyond the two genuine ones (items 22–23):

- `isakmp_inf.c` — "Guard XAuth info read against truncated payload"
- `isakmp_ike.c` — "Guard proxy ID read against truncated payload"

Neither is real. `src/racoon/isakmp_ike.c` **does not exist anywhere in this repository's git history** (verified via exhaustive `git grep`/`git log --all -- '**/isakmp_ike.c'`), and `isakmp_inf.c`'s actual `read_info_type_xauth`-adjacent code carries no such guard in any commit on the branch. These were hallucinated entries, most likely produced by an AI-assisted drafting pass over the branch's genuine `isakmp_frag.c`/`vendorid.c` fixes, extrapolating two additional, plausible-sounding but nonexistent fixes in the same category.

**Resolution status:**
- **Issue #64**: corrected. Its "Buffer Over-Read Fixes" table now lists only the two genuine items (22, 23); the numbering gap at item 24 is the visible trace of the removal.
- **PR #65**: as merged, its description **still contains both fabricated bullets**, unlike issue #64. The PR body was not edited before merge. This is now a permanent part of the merged PR's historical record on GitHub (PR descriptions are not part of the git history/diff itself, so this does not affect the merged code — `isakmp_ike.c` was never created, and `isakmp_inf.c` was not modified beyond its genuine, already-audited state from Dataset A). No corrective action is required against the codebase; noting it here for the record, since the discrepancy between issue #64's corrected body and PR #65's uncorrected body was not otherwise flagged before merge.

---

## 5. Quantitative comparison

| | Dataset A (post-v0.9.0 audits) | Dataset B (portability branch, PR #65) |
|---|---|---|
| Commit range | `224b99f..5e6abba` | `a2eb664..8e3cb79` |
| Commits | 47 | 23 |
| Tracking issues (all closed) | 12 (`security`-labeled) | 5 (#64 parent + #68, #69, #70, #71) |
| Documented fix items | 12 issues (finding counts vary per issue; #35 alone bundles 7) | 34 (issue #64's own table) + 4 independently discovered (B1–B4) = **38** |
| `severity: high` findings | 1 (#37, pre-auth remote OOB read) | 0 |
| `severity: low` findings | 11 | 38 (all) |
| Fabricated/hallucinated entries | 0 | 2 (§4) |
| Regression introduced by the review's own fix, later caught by a written test | 0 | 1 (B4, from B1) |
| Files touched | not re-tallied for this document (out of scope — Dataset A predates this review) | 29 |
| Lines changed | not re-tallied | +1129 / −71 |

---

## 6. Qualitative comparison

**Dataset A** skews toward genuinely severe, remotely-reachable defects: #37 is the one `severity: high` item across both datasets — a pre-authentication OOB read reachable by any peer that can send an ISAKMP packet to UDP/500. The bundled multi-finding issues (#32, #35) came from focused cryptography-adjacent audits (OpenSSL 3.x migration, timing side-channels, key material handling) rather than general code-quality sweeps, which is reflected in their higher per-issue finding density.

**Dataset B** is dominated by portability-driven mechanical changes (header guards, yacc syntax, `AC_CHECK_HEADERS` cache semantics) that carry no security weight on their own — of the 34 documented items, only 3 (items 22, 23, 35) have direct security/memory-safety content, and none reach `severity: high` (all are local-only or build-time). The security-relevant signal in this branch came almost entirely from a byproduct of its own `strncpy`→`strlcpy` centralization work (items 12–18): auditing *why* each conversion was made, rather than trusting the "portability fix" label, surfaced three real defects (B1–B3) the original categorization didn't call out as security fixes in their own right, plus one defect (B4) that the review process itself induced by prompting a fix for B1 without an accompanying regression test.

The single most notable process finding of this review is not a code defect at all: **B4 demonstrates the value of pairing every security fix with a regression test before considering it closed.** B1's fix was correct in intent and eliminated a real CWE-787 overflow, but the absence of a test for `f_logoutusr()`'s buffer sizing allowed a 100%-reproducible correctness regression to sit in the merged branch until this review's own follow-up (`test/test_racoonctl_logoutusr.c`, issue #68's suggested verification) caught it. This is now the only test in the tree exercising that function's request-buffer construction, and it pins down both the CWE-787 boundary (via `valgrind --leak-check=full`, the project's standard memory-safety gate) and the round-trip content-correctness boundary (via plain `strcmp`, which `valgrind` does not check) in the same harness.

The audit-integrity issue (§4) is a secondary process finding: content in issue/PR descriptions describing security fixes should be verified against the actual diff before being treated as ground truth, independent of how well-formatted or plausible it reads. This review caught it by requiring every claimed fix to be traced to a specific file, function, and commit rather than accepted from the summary table at face value — the same discipline that surfaced B1–B4.

---

## 7. Final status snapshot

| Item | State |
|---|---|
| Issue #64 (parent) | Closed, `completed` |
| Issue #68 (B1) | Closed, `completed`, fixed by `3209d22` |
| Issue #69 (B2) | Closed, `completed`, fixed by `3ab5c2a` |
| Issue #70 (B3) | Closed, `completed`, fixed by `1702337` |
| Issue #71 (B4) | Closed, `completed`, fixed by `784cc68` |
| PR #65 | Merged into `develop` @ `8e3cb79`, 2026-07-12T23:05:02Z |
| Regression test coverage added | `test/test_racoonctl_logoutusr.c` (issues #68 and #71) |
| Branch `64-fix-all-portability-regressions` | History rewritten post-review (commit trailers aligned to Linux kernel convention); final head `784cc68` before merge |
| Anchor commit integrity | `224b99f`, `5e6abba`, `a2eb664` all confirmed resolvable on `develop` after the rewrite |
