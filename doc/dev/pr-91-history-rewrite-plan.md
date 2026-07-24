# PR #91 history rewrite: analysis and plan

**Status: plan only. No commit has been modified, squashed, or dropped. Nothing in
this document has been executed.** Produced per the maintainer's brief
(`pr-91-history-rewrite-plan-prompt`); the maintainer runs the actual
`git rebase -i` by hand.

- **Merge-base with `develop`:** `69d1129f690d505f14054170afa026c7d45d0628`,
  confirmed via `git merge-base origin/develop HEAD` (unchanged whether `develop`
  is taken at its old tip `69d1129` or its current tip `9f60275` — the branch
  diverged before either).
- **Range:** `69d1129..HEAD` (`HEAD` = `84990be`), **79 commits**.
- **Companion files:** `doc/dev/pr-91-rebase-todo.txt` (the `git rebase -i`
  todo-list to paste in), `doc/dev/pr-91-rebase-messages.md` (replacement commit
  messages, one per surviving `pick`/`edit`, labeled by which target commit they
  belong to).

---

## Step 1: full commit inventory and classification

Table columns: **#** (topological position, 1 = oldest), **hash**, **author**,
**date**, **what it actually changed** (from the diff, not the message alone),
**class**. BOUNDARY/FOLD/DROP/DROP-UNRELATED per the brief's definitions.
Evidence for every DROP/DROP-UNRELATED follows the table.

| # | hash | author | date | what it actually changed | class |
|---|------|--------|------|---------------------------|-------|
| 1 | `516e03a` | Thomas Reim `<reimth@gmail.com>` | 2026-06-30 | `debian/rules`: drops `--no-trim` from `dh_installchangelogs`. Cherry-picked (`cherry picked from commit c5b917108b310130cdefdde1acab9846bfedb34b`) from `origin/branches/ubuntu-jammy`, a distro-packaging branch — not an ancestor of `develop` or this branch's merge-base. | **DROP-UNRELATED** |
| 2 | `65db17b` | Thomas Reim `<thomas.reim@airbus.com>` | 2026-07-16 | Two unrelated halves: (a) **survives** — `isakmp_cfg.c`/`.h`, `isakmp_unity.c`: adds `UNITY_SPLITDNS_NAME` parsing and `INTERNAL_SPLITDNS_DOMAINS` env export; `test/test_splitdns.c` + `test/Makefile.am`: new C unit test. (b) **false start, reverted** — rewrites `src/racoon/samples/roadwarrior/client/phase1-{up,down}.sh` in place; net effect on those two files across the whole branch is a byte-for-byte no-op (confirmed below). | **BOUNDARY** (half (a) only — see manual step in the plan) |
| 3 | `a406293` | Thomas Reim | 2026-07-16 | `client/phase1-{up,down}.sh` only: "merge split-route/SPD/DNS/syslog into unified scripts." Part of the reverted false-start chain. | **DROP** |
| 4 | `90bd018` | Thomas Reim | 2026-07-16 | `server/racoon.conf`: modernizes the roadwarrior server sample (155/31 lines). Survives (confirmed: final tree differs from merge-base on this file). | **BOUNDARY** |
| 5 | `034baf8` | Thomas Reim | 2026-07-16 | `server/racoon.conf`: adds admin guidance (91/14 lines), continuation of #4. | **FOLD** → #4 |
| 6 | `cfdc769` | Thomas Reim | 2026-07-16 | Deletes `server/racoon.conf-radius` (unmaintained sample). | **FOLD** → #4 |
| 7 | `d465e89` | Thomas Reim | 2026-07-16 | `client/racoon.conf`: modernizes the roadwarrior client sample (158/24 lines). Survives. | **FOLD** → #4 |
| 8 | `c448451` | Thomas Reim | 2026-07-16 | **Mixed**: `client/racoon.conf` (adminsock group `operator`→`racoon`, add `sainfo anonymous`) + `server/racoon.conf` (cert path, explicit `listen`) — both survive — **and** `client/phase1-{up,down}.sh` (hardcoded `NETWORKS` fallback address change) — part of the reverted false-start chain, does not survive. | **BOUNDARY**, mixed — manual split required (see below) |
| 9 | `a3679dd` | Thomas Reim | 2026-07-16 | `client/phase1-{up,down}.sh` only. False-start chain. | **DROP** |
| 10 | `1c2ea12` | Thomas Reim | 2026-07-16 | `client/racoon.conf`: removes a wrong adminsock path. Survives. | **FOLD** → #4 |
| 11 | `df73fd2` | Thomas Reim | 2026-07-16 | `client/phase1-up.sh` only. False-start chain. | **DROP** |
| 12 | `7e8b118` | Thomas Reim | 2026-07-16 | `client/phase1-up.sh` only. False-start chain. | **DROP** |
| 13 | `67defd1` | Thomas Reim | 2026-07-16 | `client/phase1-up.sh` only. False-start chain. | **DROP** |
| 14 | `61f8303` | Thomas Reim | 2026-07-16 | `client/phase1-{up,down}.sh` only. False-start chain. | **DROP** |
| 15 | `e3bff59` | Thomas Reim | 2026-07-16 | `client/phase1-up.sh` only. False-start chain. | **DROP** |
| 16 | `2786534` | Claude | 2026-07-16 | **Mixed**: `client/racoon.conf` (+10-line comment on the NetworkManager `dns=` split-DNS caveat — **survives verbatim in the current tree**, confirmed by grep) + `client/phase1-{up,down}.sh` (DNS routing gap fix, NM dummy-interface rework) — false-start chain, does not survive. | **BOUNDARY**, mixed — manual split required |
| 17 | `4c7d0cc` | Claude | 2026-07-16 | `client/phase1-{up,down}.sh` only. False-start chain. | **DROP** |
| 18 | `d6c0d0a` | Claude | 2026-07-16 | `client/phase1-{up,down}.sh` only. False-start chain. | **DROP** |
| 19 | `4632dd3` | Claude | 2026-07-16 | `client/phase1-up.sh` only. False-start chain. | **DROP** |
| 20 | `07d4e13` | Claude | 2026-07-16 | `client/phase1-up.sh` only. False-start chain. | **DROP** |
| 21 | `9759847` | Claude | 2026-07-17 | `debian/racoon.conf` + `debian/rules` (glob fix for `dh_installexamples`, unrelated to #1's `--no-trim` line). Survives. | **FOLD** → #4 |
| 22 | `d75eb8f` | Claude | 2026-07-17 | `debian/racoon.conf` + `client/racoon.conf`: drop `racoon-tool` reference, ship client sample inert by default. Survives. | **FOLD** → #4 |
| 23 | `766faa9` | Claude | 2026-07-17 | `client/phase1-{up,down}.sh` only. False-start chain. | **DROP** |
| 24 | `0db2023` | Claude | 2026-07-18 | `client/phase1-{up,down}.sh` only ("fix nm_dbus_prop() crashing under set -e"). False-start chain. | **DROP** |
| 25 | `1778093` | Thomas Reim `<reimth@etik.com>` | 2026-07-18 | Reverts `client/phase1-{up,down}.sh` back to their **pristine original stub content** (confirmed byte-identical to the tiny upstream `sa-up.sh`-style stub) and creates `src/scripts/phase1-{up,down}.sh` (the moved, 485/283-line evolved content) — **the false-start recovery point**, see Step 2. | **FOLD** → #26 (its moved content is itself fully superseded by #29/#30 below; folding avoids ever landing the doomed intermediate content as its own commit) |
| 26 | `0591684` | Claude | 2026-07-18 | New `src/scripts/racoon-hook-lib.sh` skeleton (logging, `run_step`, state I/O) + `test-lib-smoke.sh`. First commit of the actual rewrite (Brief 1). | **BOUNDARY** |
| 27 | `dafd2cf` | Claude | 2026-07-18 | §4 input validation + injection-vector regression tests. | **BOUNDARY** |
| 28 | `4b0ad39` | Claude | 2026-07-18 | §7 resolv.conf landscape survey + 10 fixture tests. | **BOUNDARY** |
| 29 | `2d0488e` | Claude | 2026-07-18 | §6 capability matrix + resolvectl/systemd-resolve emitters. | **BOUNDARY** |
| 30 | `53cbcb0` | Claude | 2026-07-18 | §3.2 plan builder, §7.4 postconditions, `racoon-dns-detect` CLI. | **BOUNDARY** |
| 31 | `72e307b` | Claude | 2026-07-18 | Replaces `phase1-up.sh` with the thin wrapper (final design). | **BOUNDARY** |
| 32 | `5e407f3` | Claude | 2026-07-18 | Replaces `phase1-down.sh` with pure undo-replay (final design). | **BOUNDARY** |
| 33 | `15c5bdb` | Claude | 2026-07-18 | `hooks.conf.sample`, Admin Guide, CI workflow, shellcheck-clean. | **BOUNDARY** |
| 34 | `cf6fd4b` | Claude | 2026-07-18 | §12 final implementation report (→ `doc/admin/split-dns-implementation-report.md`). | **FOLD** → #33 |
| 35 | `1fb4079` | Claude | 2026-07-19 | Fixes the resolved-backend DNS effectiveness check; reorders/rolls back DNS steps. | **BOUNDARY** |
| 36 | `436d6fb` | Claude | 2026-07-19 | Port 53 ownership survey as an equal-weight §7 input (brief 3 §C) + 5 new fixtures. | **BOUNDARY** |
| 37 | `6158721` | Claude | 2026-07-19 | FIFO generation-numbered state matching, supersedes stale-archival (brief 3 §D). | **BOUNDARY** |
| 38 | `e3fd36c` | Claude | 2026-07-19 | Installs and owns SPD entries for the tunnel (brief 3 §E, R2'). | **BOUNDARY** |
| 39 | `e2be159` | Claude | 2026-07-19 | Files `doc/dev/daemon-issues.md`, records §F/§G investigation status. | **BOUNDARY** |
| 40 | `6c07e8a` | Claude | 2026-07-19 | `on_dns_failure=report\|rollback` replaces "abort" (brief 3 §H). | **BOUNDARY** |
| 41 | `bbb8619` | Claude | 2026-07-19 | Gates the resolv.conf-overwrite fallback behind `allow_resolv_conf_overwrite` (brief 3 §I). | **BOUNDARY** |
| 42 | `76f5572` | Claude | 2026-07-19 | Asserts stderr cleanliness on every real subprocess invocation (brief 3 §J). | **BOUNDARY** |
| 43 | `8ed9fea` | Claude | 2026-07-19 | Detects NetworkManager ownership before deleting the dummy interface (brief 3 §K). | **BOUNDARY** |
| 44 | `78ccd01` | Claude | 2026-07-19 | Installs the split-DNS hooks as a real package component (brief 3 §L): `Makefile.am`, `debian/racoon.install`, `packaging/arch/PKGBUILD`, moves `src/scripts/` → `src/racoon/scripts/`. | **BOUNDARY** |
| 45 | `5b22a40` | Claude | 2026-07-19 | Adds split-DNS hooks section to the (different, pre-existing) real Admin Guide `docs/admin-guide/racoon-admin-guide.html` (brief 3 §M). | **BOUNDARY** |
| 46 | `babaad2` | Claude | 2026-07-19 | Extends the implementation report with Brief 3's own §12-style summary. | **FOLD** → #45 |
| 47 | `ec38f74` | Claude | 2026-07-20 | Live bug: idempotent dummy-interface creation (racoon0 hangs after non-clean stop). | **BOUNDARY** |
| 48 | `2630265` | Claude | 2026-07-20 | Live bug: invalid systemd-resolve clear commands, use `--revert`. | **FOLD** → #47 |
| 49 | `163fbdd` | Claude | 2026-07-20 | Live bug: plan the NM DNS profile before routes (Invalid prefsrc address). | **FOLD** → #47 |
| 50 | `64ef546` | Claude | 2026-07-20 | Live bug: `ipv6.method ignore` instead of `disabled` for the NM DNS profile. | **FOLD** → #47 |
| 51 | `7ec2ec6` | Claude | 2026-07-20 | Adds `doc/dev/ARCHITECTURE.md` (609 lines). | **BOUNDARY** |
| 52 | `472f77e` | Claude | 2026-07-21 | Fixes ARCHITECTURE.md numbering collision/undercount/unflagged version claim. | **FOLD** → #51 |
| 53 | `d3b22d1` | Claude | 2026-07-21 | Installs `racoon-hook-lib.sh` non-executable (lintian fix). | **FOLD** → #44 |
| 54 | `bfbfff5` | Claude | 2026-07-21 | Rechecks systemd-version comments against the full NEWS file. | **FOLD** → #51 |
| 55 | `e517623` | Claude | 2026-07-21 | Renames the implementation report to its `1d1-` prefix (first-draft marker). | **FOLD** → #45 |
| 56 | `debdc77` | Claude | 2026-07-21 | Adds an Arch Linux note to ARCHITECTURE.md's decision tree. | **FOLD** → #51 |
| 57 | `a40fef6` | Claude | 2026-07-22 | Closes out the Task F ACQUIRE-provenance investigation (Branch B): `ARCHITECTURE.md`, `daemon-issues.md`, `teardown-investigation.md`. | **BOUNDARY** |
| 58 | `1bf0d9e` | Claude | 2026-07-22 | Softens the Task F original-ACQUIRE causal claim to what the evidence supports. | **FOLD** → #57 |
| 59 | `9dfd5b8` | Claude | 2026-07-22 | **Issue #90 fix**: `phase1-down.sh` matches by `IKE_COOKIE`, not FIFO order. `isakmp.c` export, `racoon-hook-lib.sh`, C unit test, fixture tests. | **BOUNDARY** |
| 60 | `b3caa65` | Claude | 2026-07-23 | `tools/task-f-acquire-investigation.sh` v1 (455 lines, new). | **BOUNDARY** (kept separate per the maintainer's own earlier explicit request to check these in as sequential versions) |
| 61 | `09b3a15` | Claude | 2026-07-23 | v2: hardens against two contamination sources. | **BOUNDARY** (same reason) |
| 62 | `5f92c69` | Claude | 2026-07-23 | v3: filters per-socket SPD noise, terminates racoon by default. | **BOUNDARY** (same reason) |
| 63 | `40c33ad` | Claude | 2026-07-23 | v4: adds issue #90 live checks, renames to `racoon-hook-integration-test.sh`. | **BOUNDARY** (same reason) |
| 64 | `52aa366` | Claude | 2026-07-23 | Records issue #90's live confirmation across three distros (`ARCHITECTURE.md`, `teardown-investigation.md`). | **FOLD** → #59 |
| 65 | `6c3870f` | Thomas Reim `<thomas.reim@airbus.com>` | 2026-07-23 | Adds `doc/dev/1d1-split-dns-implementation-report.md` (Thomas's own original prototype report — the dummy-interface `racoon-vpn0` design) and renames Claude's existing `1d1-` report to `1d2-`. | **BOUNDARY** |
| 66 | `8e946d2` | Claude | 2026-07-24 | Isolates `RACOON_HOOK_RESOLVECTL` in the systemd-resolve-only test scenario — fixes a real, live CI failure. | **BOUNDARY** |
| 67 | `2cb972a` | Claude | 2026-07-24 | Falls back to `sh` when `dash` isn't installed — fixes the NetBSD CI job. | **FOLD** → #66 |
| 68 | `8d11d6c` | Claude | 2026-07-24 | PR #91 review #4/#8: surfaces state-dir creation / unreadable-state-file failures. | **BOUNDARY** |
| 69 | `69a6659` | Claude | 2026-07-24 | PR #91 review #11-16/#30: `PARALLEL_UNLINKED` definition, capability matrix, rollback/orphan tradeoffs. | **FOLD** → #68 |
| 70 | `53a8f53` | Claude | 2026-07-24 | PR #91 review #38: `racoon-dns-detect.8`, `hooks.conf` documented in `racoon.conf.5`/`racoon.8`. | **FOLD** → #68 |
| 71 | `7c16c4f` | Claude | 2026-07-24 | PR #91 review #36: 3 preflight assumption checks in the integration test. | **FOLD** → #68 |
| 72 | `5d7efe9` | Claude | 2026-07-24 | PR #91 review #23: crashed-`phase1-up.sh` state-file coverage + response doc. | **BOUNDARY** |
| 73 | `655caf5` | Claude | 2026-07-24 | PR #91 review #24: closes the dummy-interface check-then-create race. | **BOUNDARY** |
| 74 | `a4b0f4e` | Claude | 2026-07-24 | PR #91 review #24: response-doc entry only. | **FOLD** → #73 |
| 75 | `de83380` | Claude | 2026-07-24 | PR #91 review #29a: bogon DNS server range rejection. | **BOUNDARY** |
| 76 | `fde49e9` | Claude | 2026-07-24 | PR #91 review #29b: CIDR-overlap warning. | **FOLD** → #75 |
| 77 | `9731af3` | Claude | 2026-07-24 | PR #91 review #29c: Punycode domain warning. | **FOLD** → #75 |
| 78 | `16fc058` | Claude | 2026-07-24 | PR #91 review #29: response-doc entry only. | **FOLD** → #75 |
| 79 | `84990be` | Claude | 2026-07-24 | PR #91 review #41: terminology pass. | **BOUNDARY** |

*(79 commits total, verified against `git log --reverse --format='%h' 69d1129..HEAD | wc -l` = 79.)*

### Evidence for every DROP / DROP-UNRELATED

- **`516e03a` (DROP-UNRELATED).** `git show 516e03a` shows a one-line change to
  `debian/rules` with `(cherry picked from commit c5b917108b3...)` in its own
  message. That source commit is `git cat-file -t`-confirmed to exist, but
  `git branch -a --contains` shows it only on `origin/branches/ubuntu-jammy` — a
  distro-packaging branch. `git merge-base --is-ancestor c5b917108b3... origin/develop`
  and `...69d1129` both return false: it is not an ancestor of `develop` or of
  this branch's own merge-base. Dated 2026-06-30, three weeks before the earliest
  split-DNS commit (2026-07-16). It touches `debian/rules` for a reason (Debian
  changelog trimming) that has nothing to do with split-DNS/routing hooks.
- **The false-start chain (`a406293`, `a3679dd`, `df73fd2`, `7e8b118`, `67defd1`,
  `61f8303`, `e3bff59`, `4c7d0cc`, `d6c0d0a`, `4632dd3`, `07d4e13`, `766faa9`,
  `0db2023` — all DROP; `65db17b`/`c448451`/`2786534`'s *script* portions
  likewise).** Every one of these touches only
  `src/racoon/samples/roadwarrior/client/phase1-up.sh` and/or `phase1-down.sh`.
  Proof of zero surviving contribution:
  ```
  $ git diff --stat 69d1129 HEAD -- \
      src/racoon/samples/roadwarrior/client/phase1-up.sh \
      src/racoon/samples/roadwarrior/client/phase1-down.sh
  (no output)
  $ git diff 69d1129 HEAD -- <same two paths> | wc -l
  0
  ```
  The files are **byte-identical** between the merge-base and `HEAD` — every
  edit made to them across the whole branch, however many commits, cancels out
  exactly. `1778093` is the commit that performs the cancellation (see Step 2):
  its diff on these two paths reverts them to precisely their original,
  pre-existing upstream stub content (verified: `git show 1778093 -- <path>`
  shows a `-533/+80`-style diff whose "after" side is what `git show HEAD:<path>`
  still reads today).

---

## Step 2: the false-start recovery, precisely

**Commits `65db17b` through `1778093`** (positions 2–25 above, 24 commits,
2026-07-16 through 2026-07-18) **are the false start.** They built a large,
monolithic `phase1-up.sh`/`phase1-down.sh` pair directly in
`src/racoon/samples/roadwarrior/client/`, adding NetworkManager dummy-device
integration, DNS backend detection, and split-routing logic incrementally —
first by Thomas (`thomas.reim@airbus.com`, with `Assisted-by: OpenCode:Qwen/...`
and `OpenCode:KITCH-Coder` trailers), then continued by Claude in the same
files, same design.

**The recovery point is `1778093`** ("scripts: manage phase1 up/down shell
scripts in src folder", Thomas, `reimth@etik.com`). Its diff does two things at
once: it reverts `client/phase1-up.sh`/`phase1-down.sh` back to their original,
pristine stub content, and it copies the just-reverted (533/329-line) evolved
version into two *new* files at `src/scripts/phase1-up.sh`/`phase1-down.sh`.
The very next commit, `0591684` ("hooks: add racoon-hook-lib.sh skeleton"),
starts an **entirely different architecture**: a shared library
(`racoon-hook-lib.sh`) that owns detection, planning, execution and state I/O,
with `phase1-up.sh`/`phase1-down.sh` reduced to thin wrappers over it — the
design that ships today. `72e307b`/`5e407f3` (four commits later) replace the
copied-forward 533/329-line scripts with those thin wrappers, so none of the
false start's script *content* survives even at the new path — only the
*directory* survived, and even that gets renamed again (`src/scripts/` →
`src/racoon/scripts/`) by `78ccd01` a day later.

**What changed at the pivot, specifically:** the false start put all detection/
DNS-backend/routing logic inline in `phase1-up.sh` itself, called once per VPN
connect/disconnect with no shared state format between the two scripts beyond
a hand-rolled `NETWORKS` variable convention. The rewrite introduced: a
survey → classify → plan → apply pipeline (`racoon-hook-lib.sh`'s own
vocabulary, still visible today in every `rhook_*` function name and the
`§`-numbered section comments); a numbered state-file journal that
`phase1-down.sh` replays rather than re-deriving; and the R1–R8 design rules
(no persistent system reconfiguration, SPD ownership, untrusted-input
validation, etc.) that "Brief 1" formalized and every later "Brief 3 §X"
commit continued to build against.

**Is this already narrated in the project's docs?** Partially, not fully.
`doc/dev/1d2-split-dns-implementation-report.md` (§2, "Dummy interface identity
vs. the old prototype") mentions the prior prototype exists and explains one
specific design divergence from it (interface identity/address), but never
states that it was abandoned, when, or why in a dedicated passage.
`doc/dev/1d1-split-dns-implementation-report.md` (Thomas's own report, added by
`6c3870f`, describing base commit `89efb95`/HEAD `095a142` — commits that
predate even `65db17b` and aren't in this branch at all, a separate,
earlier iteration of the same prototype line) documents the original design in
detail but, being a report *of* the prototype, naturally says nothing about
its own supersession. **Neither document currently states outright "here is
the false start, here is why it was abandoned, here is what changed."** The
paragraph above (this section) is that missing narrative; the maintainer may
want to fold a version of it into `1d2-split-dns-implementation-report.md`
(e.g., a new short "§0. Prior prototype and why this is a rewrite, not an
iteration" section) as part of executing target commit #26 in Step 3 below,
which already touches `6c3870f`'s file — this plan does not make that edit
itself.

---

## Step 3: target commit grouping

36 target sections below, yielding **38 physical commits** after the rebase
(Target 2 mechanically produces 3 commits rather than 1 — see its own section)
— not 12–18, see note below. Grouped by: pre-existing foundational work
(targets 1–2), Brief 1's rewrite arc (3–10), the resolved-backend DNS fix plus
Brief 3's lettered items §C–§M in order (11–21), live-bug fixes and docs
(22–24), the issue #90 fix (25), Task F tooling (26–29), Thomas's prototype
report (30), and the PR #91 review-response tail (31–36).

> **Why more than "roughly 12–18":** Brief 1's R1–R8 arc and Brief 3's §C–§M
> items are, individually, already well-scoped, independently meaningful units
> — that granularity is what the brief itself asks to preserve ("Brief 1's
> R1–R8 as foundational commits; Brief 3's A–M as the bulk of the grouping").
> Forcing them into fewer, larger commits would trade away exactly the
> bisect-granularity the brief separately asks for. If the maintainer wants a
> flatter history, the natural places to merge further are noted inline below
> (marked *"mergeable with →"*) — none of the FOLD assignments below need to
> change to do that, only which target commit a FOLD lands in.

### Target 1 — `racoon: parse UNITY_SPLITDNS_NAME, export INTERNAL_SPLITDNS_DOMAINS`
- **Source:** `65db17b` — **C-side hunks only** (`isakmp_cfg.c`, `isakmp_cfg.h`,
  `isakmp_unity.c`, `test/test_splitdns.c`, `test/Makefile.am`).
- **Manual step required:** `edit` here, then
  `git checkout HEAD^ -- src/racoon/samples/roadwarrior/client/phase1-up.sh src/racoon/samples/roadwarrior/client/phase1-down.sh && git commit --amend --no-edit`
  before continuing — strips this commit's false-start script hunks, keeps
  everything else.
- **Author:** Thomas Reim `<thomas.reim@airbus.com>` (unchanged — this is
  entirely his original work).
- **Independently buildable:** yes (`make check` exercises `test_splitdns.c`
  directly).

### Target 2 — `samples,debian: modernize roadwarrior sample configs and default racoon.conf`
- **Source (in this order):** `90bd018` → `034baf8` → `cfdc769` → `d465e89` →
  `c448451` (**edit**: strip the `phase1-{up,down}.sh` `NETWORKS`-fallback
  hunks, keep the `racoon.conf` hunks) → `1c2ea12` → `2786534` (**edit**: strip
  the `phase1-{up,down}.sh` hunks, keep the `client/racoon.conf` NetworkManager
  `dns=` comment addition — confirmed this paragraph is still present,
  verbatim, in the current tree) → `9759847` → `d75eb8f`.
- **Mechanically, this produces 3 adjacent commits, not 1** — `squash` can
  combine messages but cannot strip hunks, and `edit` starts a fresh commit
  boundary it cannot itself squash backwards into. The natural result of the
  sequence above (`pick`→`squash`→`squash`→`squash`, then `edit`→`squash`,
  then `edit`→`squash`→`squash`) is three commits:
  - **2a** `90bd018`+`034baf8`+`cfdc769`+`d465e89` — server/client `racoon.conf`
    modernization proper.
  - **2b** `c448451` (edited) + `1c2ea12` — small client-config fixes on top,
    made after the modernization above.
  - **2c** `2786534` (edited) + `9759847` + `d75eb8f` — the NetworkManager
    `dns=` documentation note, default `debian/racoon.conf` rewrite, and
    dropping the `racoon-tool` reference.
  This is arguably better-scoped than a single commit and is what this plan
  recommends; see `pr-91-rebase-todo.txt`/`pr-91-rebase-messages.md` for the
  exact mechanics and 2a/2b/2c's three separate messages. If the maintainer
  wants these fully merged into one commit instead, that is a trivial
  additional `squash`-only pass afterward (no more hunk-editing needed once
  2a/2b/2c already exist cleanly).
- **No reordering needed.** `c448451`/`1c2ea12` and `2786534`/`9759847`/
  `d75eb8f` are already adjacent to each other in the original history once
  the false-start commits interspersed between them (all DROP) are removed —
  confirmed against the position table in Step 1 (only DROP-classified
  commits sit between them). `c448451` naturally lands after `d465e89` was
  already applied, which is what its `client/racoon.conf` hunk expects.
- **Author:** mixed — `90bd018`/`034baf8`/`cfdc769`/`d465e89`/`c448451`/
  `1c2ea12` (2a/2b) are Thomas Reim (`thomas.reim@airbus.com`); `2786534`/
  `9759847`/`d75eb8f` (2c) are Claude. **Flagging per Step 4: 2c in particular
  is a genuine mix and needs the maintainer's own attribution call** — see
  Step 4. 2a and 2b are unambiguously Thomas's.
- **Independently buildable:** yes for all three (no code compiled from these
  files; no test suite exercises sample `racoon.conf`s directly, so
  "buildable" here means "the files parse/are internally consistent," not
  test-covered).

### Target 3 — `hooks: add racoon-hook-lib.sh skeleton (logging, run_step, state I/O)`
- **Source:** `1778093` (**folded, not separately reviewable** — see Step 2;
  its moved 485/283-line content is fully superseded within this same target
  by the time Target 8/9 land, so it is folded here rather than kept as an
  independently-reviewable step with no lasting value) → `0591684`.
- **Author:** Claude (both; `1778093`'s surviving contribution — establishing
  the `src/scripts/` directory — is structural, not substantive, and `0591684`
  is where the real content is).
- **Independently buildable:** yes.

### Target 4 — `hooks: add §4 input validation with injection-vector regression tests`
- **Source:** `dafd2cf`. **Author:** Claude. **Buildable:** yes.

### Target 5 — `hooks: add §7 resolv.conf landscape survey with 10 fixture tests`
- **Source:** `4b0ad39`. **Author:** Claude. **Buildable:** yes.

### Target 6 — `hooks: add §6 capability matrix and resolvectl/systemd-resolve emitters`
- **Source:** `2d0488e`. **Author:** Claude. **Buildable:** yes.
- *Mergeable with →* Target 5 or 7 if the maintainer wants fewer commits.

### Target 7 — `hooks: add §3.2 plan builder, §7.4 postconditions, and racoon-dns-detect CLI`
- **Source:** `53cbcb0`. **Author:** Claude. **Buildable:** yes.

### Target 8 — `hooks: replace phase1-up.sh with a thin wrapper over the plan/apply library`
- **Source:** `72e307b`. **Author:** Claude. **Buildable:** yes.

### Target 9 — `hooks: replace phase1-down.sh with a pure undo replay of the state file`
- **Source:** `5e407f3`. **Author:** Claude. **Buildable:** yes.

### Target 10 — `docs/ci: add hooks.conf.sample, admin guide, CI workflow, shellcheck-clean`
- **Source:** `15c5bdb` → `cf6fd4b` (FOLD: §12 implementation report).
- **Author:** Claude. **Buildable:** yes (this is the commit where the CI
  workflow itself first appears).

### Target 11 — `hooks: fix resolved-backend DNS effectiveness check + rollback/reorder DNS steps`
- **Source:** `1fb4079`. **Author:** Claude. **Buildable:** yes.

### Target 12 — `hooks: add port 53 ownership survey as an equal-weight §7 input (brief 3 §C)`
- **Source:** `436d6fb`. **Author:** Claude. **Buildable:** yes.

### Target 13 — `hooks: FIFO generation-numbered state matching, supersedes stale-archival (brief 3 §D)`
- **Source:** `6158721`. **Author:** Claude. **Buildable:** yes.

### Target 14 — `hooks: install and own SPD entries for the tunnel (brief 3 §E, R2')`
- **Source:** `e3fd36c`. **Author:** Claude. **Buildable:** yes.

### Target 15 — `docs: file daemon-side issues from live testing, record §F investigation status (brief 3 §F/§G)`
- **Source:** `e2be159`. **Author:** Claude. **Buildable:** yes (docs-only).

### Target 16 — `hooks: on_dns_failure=report|rollback replaces the overpromising "abort" (brief 3 §H)`
- **Source:** `6c07e8a`. **Author:** Claude. **Buildable:** yes.

### Target 17 — `hooks: gate the resolv.conf-overwrite fallback behind allow_resolv_conf_overwrite (brief 3 §I)`
- **Source:** `bbb8619`. **Author:** Claude. **Buildable:** yes.

### Target 18 — `tests: assert stderr cleanliness on every real subprocess invocation (brief 3 §J)`
- **Source:** `76f5572`. **Author:** Claude. **Buildable:** yes.

### Target 19 — `hooks: detect NetworkManager ownership before deleting the dummy interface (brief 3 §K)`
- **Source:** `8ed9fea`. **Author:** Claude. **Buildable:** yes.

### Target 20 — `build: install the split-DNS hooks as a real package component (brief 3 §L)`
- **Source:** `78ccd01` → `d3b22d1` (FOLD: non-executable `racoon-hook-lib.sh`
  install fix, lintian).
- **Author:** Claude. **Buildable:** yes.

### Target 21 — `docs: add split-DNS hooks section to the real Admin Guide (brief 3 §M)`
- **Source:** `5b22a40` → `babaad2` (FOLD: §12-style summary extension) →
  `e517623` (FOLD: renames the report to its `1d1-` prefix — purely a rename,
  folds here rather than standing alone).
- **Author:** Claude. **Buildable:** yes (docs-only).

### Target 22 — `hooks: 3 live bugs found in real-world testing (idempotent dummy iface, systemd-resolve --revert, NM DNS profile ordering, ipv6.method)`
- **Source:** `ec38f74` → `2630265` (FOLD) → `163fbdd` (FOLD) → `64ef546` (FOLD).
- **Author:** Claude. **Buildable:** yes.
- *Mergeable with →* could stay as 4 separate commits instead if the maintainer
  prefers one-bug-per-commit; each is independently coherent.

### Target 23 — `docs: add doc/dev/ARCHITECTURE.md, a tutorial for the split-DNS/routing hooks`
- **Source:** `7ec2ec6` → `472f77e` (FOLD) → `bfbfff5` (FOLD) → `debdc77` (FOLD).
- **Author:** Claude. **Buildable:** yes (docs-only).

### Target 24 — `docs: close out Task F ACQUIRE-provenance investigation`
- **Source:** `a40fef6` → `1bf0d9e` (FOLD).
- **Author:** Claude. **Buildable:** yes (docs-only).

### Target 25 — `hooks: match phase1-down.sh's own generation by IKE_COOKIE, not FIFO order (issue #90)`
- **Source:** `9dfd5b8` → `52aa366` (FOLD: live confirmation across 3 distros).
- **Author:** Claude. **Buildable:** yes — this is the issue #90 fix itself,
  the branch's headline change.

### Targets 26–29 — Task F tooling, kept as 4 separate commits
- **Source:** `b3caa65` (v1) → `09b3a15` (v2) → `5f92c69` (v3) → `40c33ad` (v4,
  renamed to `racoon-hook-integration-test.sh`). **Not squashed together** —
  the maintainer explicitly asked, earlier in this same PR's development
  (when first checking this tool into version control), to commit each logged
  version as its own step-by-step commit; this plan preserves that stated
  intent rather than overriding it during cleanup. Flagged here in case the
  maintainer wants to reconsider now that the branch as a whole is being
  cleaned up — but the default recommendation is to leave these four as-is.
- **Author:** Claude (all four). **Buildable:** yes (shell syntax only, no
  test suite covers this tool itself).

### Target 30 — `doc: add split DNS NM integration development report 1d1`
- **Source:** `6c3870f`. **Author:** Thomas Reim `<thomas.reim@airbus.com>`
  (his own report about his own original prototype — unambiguous, no
  attribution question). **Buildable:** yes (docs-only).

### Target 31 — `tests: fix 2 CI failures found in PR #91 review (resolvectl leak, dash-not-found)`
- **Source:** `8e946d2` → `2cb972a` (FOLD).
- **Author:** Claude. **Buildable:** yes.

### Target 32 — `docs+hooks: apply PR #91 review items #4/#8, #11-16/#30, #36, #38`
- **Source:** `8d11d6c` → `69a6659` (FOLD) → `53a8f53` (FOLD) → `7c16c4f` (FOLD).
- **Author:** Claude. **Buildable:** yes.

### Target 33 — `tests: cover a crashed phase1-up.sh's incomplete state file (PR #91 row 23)`
- **Source:** `5d7efe9`. **Author:** Claude. **Buildable:** yes.

### Target 34 — `hooks: close the dummy-interface check-then-create race (PR #91 row 24)`
- **Source:** `655caf5` → `a4b0f4e` (FOLD: response-doc entry).
- **Author:** Claude. **Buildable:** yes.

### Target 35 — `hooks: validation gaps from PR #91 row 29 (bogon/RFC1918, CIDR overlap, Punycode)`
- **Source:** `de83380` → `fde49e9` (FOLD) → `9731af3` (FOLD) → `16fc058` (FOLD).
- **Author:** Claude. **Buildable:** yes.

### Target 36 — `docs: lead user-facing prose with "phase1-up/phase1-down scripts" (PR #91 row 41)`
- **Source:** `84990be`. **Author:** Claude. **Buildable:** yes.

### Reordering: only 3 commits in the whole 79 actually need to move

Every FOLD above lands next to its target BOUNDARY commit for free once the
DROP commits between them vanish — checked against the Step 1 position table
for every fold, not assumed. Exactly three commits are not naturally adjacent
to where they fold to and must be moved out of their chronological position:

- **`d3b22d1`** (position 53, "install `racoon-hook-lib.sh` non-executable")
  must move to sit immediately after Target 20's `78ccd01` (position 44) — it
  only touches `src/racoon/scripts/Makefile.am`; none of the 8 commits it
  jumps back over (positions 45–52) touch that file, so this reorder is
  expected to apply without conflict.
- **`e517623`** (position 55, renames the implementation report to its `1d1-`
  prefix) must move to sit immediately after Target 21's `5b22a40`+`babaad2`
  (positions 45–46) — it touches the renamed report path plus a single
  cross-reference line in `ARCHITECTURE.md` (line ~598, "See
  `doc/admin/split-dns-implementation-report.md`..."). Of the 8 commits it
  jumps back over (positions 47–54), three (`7ec2ec6`@51, `472f77e`@52,
  `bfbfff5`@54) also touch `ARCHITECTURE.md` — **this is the one reorder
  where a real line-adjacency conflict is plausible** (if `bfbfff5`'s NEWS-file
  recheck happens to touch the same paragraph). Flagged for extra attention;
  resolve by hand if it conflicts (keep both changes — the cross-reference
  update and whatever `bfbfff5` changed nearby — they're not mutually
  exclusive).
- **`52aa366`** (position 64, "record issue #90's live confirmation") must move
  to sit immediately after Target 25's `9dfd5b8` (position 59) — it touches
  `ARCHITECTURE.md` and `teardown-investigation.md`; the 4 commits it jumps
  back over (positions 60–63, the Task F tool script v1–v4) touch only
  `tools/task-f-acquire-investigation.sh`, so this reorder is expected to
  apply without conflict.

`pr-91-rebase-todo.txt` already places these three lines in their moved
position — this section exists so the maintainer isn't surprised by a `pick`
line that appears out of chronological order in the todo file.

**Everything above is expected to build and pass `make check`/`shellcheck`/the
fixture suite independently**, with the exception of Target 2
(`samples,debian: modernize...`), which touches only sample config files and
`debian/` packaging — nothing there is exercised by this project's test suite
at all (buildable in the sense of "internally consistent," not "test-green").
This is not a new gap introduced by the rewrite; the current merged history
has the same property for these files.

---

## Step 4: authorship

- **Target 1** (`65db17b`'s C-side hunks): keep `--author="Thomas Reim <thomas.reim@airbus.com>"`
  — entirely his original C work.
- **Target 2** (samples/debian modernization): **genuine mix, maintainer's call.**
  6 of 9 folded-in commits are Thomas's (`thomas.reim@airbus.com`); 3
  (`2786534`, `9759847`, `d75eb8f`) are Claude's, each independently a smaller
  share of the total diff than Thomas's contribution. Two reasonable options:
  1. `--author="Thomas Reim <thomas.reim@airbus.com>"`, since his commits are
     both the majority of the work and the ones establishing the pattern the
     Claude commits continue — with an `Assisted-by:`/`Co-Authored-By:` trailer
     (per Step 3's trailer discussion below) noting Claude's contribution.
  2. Keep Claude authorship (matching every other target commit in this
     rewrite) since squashing changes the commit's identity anyway and Thomas
     already has a separate, unambiguous commit (Target 1) for his most
     substantial original contribution in this range.
  This plan does not pick for the maintainer — see the rebase-todo/messages
  files, which use option 2 as the default with a comment flagging where to
  change it to option 1 if preferred.
- **Target 30** (`6c3870f`): keep `--author="Thomas Reim <thomas.reim@airbus.com>"`
  — his own report about his own prototype, no ambiguity.
- **Every other target:** Claude (`noreply@anthropic.com`) — these are
  substantially or entirely Claude's own drafting against the maintainer's
  briefs, matching the existing commits' authorship.
- **Thomas's committer emails seen in this range** (for reference):
  `thomas.reim@airbus.com` (the large majority — 15 of 17 Thomas-authored
  commits), `reimth@etik.com` (`1778093` only), `reimth@gmail.com` (`516e03a`
  only, and that commit is being dropped as unrelated). Recommend
  `thomas.reim@airbus.com` for both Target 1 and Target 30 above, matching the
  email actually used on the substantive originals.

### Trailer format — no policy is actually documented; flagging rather than guessing

`CONTRIBUTING.md`'s "AI-Assisted Development" section (the only place this
project documents anything about AI attribution) states only that the project
"is maintained by a single maintainer" with AI-tooling support — **it specifies
no trailer format at all.** The ~29 commits in this branch that already carry
a trailer are inconsistent with each other: some use
`Assisted-by: Claude Sonnet 5 <noreply@anthropic.com>` + a `Claude-Session:`
URL line, some use `Co-Authored-By:` instead of `Assisted-by:` for the
identical situation, and the Thomas-authored false-start commits use
`Assisted-by: OpenCode:KITCH-Coder` / `Assisted-by: OpenCode:Qwen/Qwen3-Coder-480B-A35B-Instruct`
(a different AI tool entirely, since dropped along with those commits).

The one actual **precedent with review backing** found in this repository's
history is PR #65 (`docs/security-review-pr65-portability.md`: "history
rewritten post-review to align commit trailers with Linux kernel
conventions"). Checking that branch's actual merged commits
(`5e6abba..8e3cb79` on `develop`) shows the format used there is:

```
Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <reimth@etik.com>
```

— i.e. the Linux-kernel `Signed-off-by:` DCO trailer (Thomas, as maintainer,
certifying the commit) plus a plain `Assisted-by:` line, no session URL. This
is a materially different shape from what most of PR #91's own commits
currently carry. **This plan uses that PR #65 format as its default** in
`pr-91-rebase-messages.md` below, since it's the only one with actual
maintainer review behind it — but flags this explicitly as a decision point:
confirm before pasting, since neither format is written down as a hard
requirement anywhere.

---

## Step 5: executable plan artifacts

Two files, not run by this task:

- **`doc/dev/pr-91-rebase-todo.txt`** — paste into
  `git rebase -i 69d1129` (replacing its auto-generated content entirely).
- **`doc/dev/pr-91-rebase-messages.md`** — the 38 replacement commit messages
  (36 target sections; Target 2 is 3 messages, 2a/2b/2c), labeled by which
  `pick`/`edit` line in the todo file they belong to, in the order the
  interactive rebase will actually stop and ask for them.

---

## Checklist for the maintainer

1. **Before starting:** confirm no other branch or open PR is based on
   `claude/issue-90-session-token-qsn6pr` (`git branch --all --contains
   claude/issue-90-session-token-qsn6pr` / check open PRs against it on
   GitHub) — rewriting this branch's history will orphan any such branch.
2. Push a backup ref first: `git branch pr-91-pre-rewrite-backup claude/issue-90-session-token-qsn6pr`.
3. Decide the two open questions before running anything:
   - Target 2's authorship (Thomas vs. Claude — Step 4).
   - The trailer format to paste at each stop (Step 4's trailer section).
4. Run `git rebase -i 69d1129`, replace the editor buffer with
   `pr-91-rebase-todo.txt`'s contents, save/quit.
5. **Expected manual-intervention stops** (in order encountered): the `edit`
   at `65db17b` (Target 1 — strip the two false-start script hunks), the
   `edit` at `c448451` (Target 2b — strip the `NETWORKS`-fallback hunks), the
   `edit` at `2786534` (Target 2c — strip the DNS-routing/NM-rework hunks,
   keep the racoon.conf comment). None of these three are expected to produce
   textual conflict markers (each strips a cleanly-separable hunk from an
   otherwise-clean commit) but each needs the manual `git checkout <parent> --
   <path>` step described in Step 3 before `git rebase --continue`. Separately,
   the reordered pick at `e517623` (folding into Target 21) is the one point
   in the whole plan most likely to show a genuine line-adjacency conflict in
   `ARCHITECTURE.md` against `bfbfff5` — see the reordering note at the end of
   Step 3 for what to do if it does.
6. At every other stop, paste the message from `pr-91-rebase-messages.md`
   labeled for that target, run `make check && (cd tests/hooks && for f in
   test-*.sh; do sh "$f"; done) && shellcheck --shell=sh src/racoon/scripts/*.sh
   tests/hooks/*.sh`, confirm green, **then** continue — don't batch multiple
   stops before testing, since that's what turns a clean bisect history back
   into a black box.
7. If a stop shows an actual conflict beyond the three flagged above, resolve
   it by hand referring to `git show <original-hash>` for what that specific
   source commit intended, re-run the test command from step 6, then continue.
8. After the rebase completes cleanly and every stop's tests passed: diff the
   final tree against the branch's current tip
   (`git diff claude/issue-90-session-token-qsn6pr <new-head>`) and confirm it
   is empty — the rewrite must not change the final code, only its history.
9. Only once step 8 confirms an empty diff: force-push
   (`git push --force-with-lease origin claude/issue-90-session-token-qsn6pr`),
   never a bare `--force`.
10. Leave `pr-91-pre-rewrite-backup` in place until PR #91 is merged, then
    delete it.
