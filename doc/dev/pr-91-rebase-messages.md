# PR #91 rebase — replacement commit messages

One section per `pick`/`edit` line in `pr-91-rebase-todo.txt` that ends a
squash chain (i.e., one per final target commit), in the order the rebase
will actually stop and ask for a message. Paste each into the editor when
`git rebase -i` stops there (for a `squash` chain, git pre-fills the combined
original messages — replace the whole buffer with the text shown here).

**Trailer used below:** `Assisted-by: Claude <noreply@anthropic.com>` +
`Signed-off-by: <author>` — the PR #65 precedent (see plan Step 4). Swap for
whatever the maintainer decides instead; every message below has the trailer
on its own clearly-marked last lines so it's a mechanical find/replace either
way.

---

## Target 1 — `65db17b` (after stripping the false-start script hunks)

```
racoon: parse UNITY_SPLITDNS_NAME, export INTERNAL_SPLITDNS_DOMAINS

isakmp_cfg.h: add split_dns to isakmp_cfg_state and the
ISAKMP_CFG_GOT_SPLIT_DNS flag (0x8000) to config_flags.
isakmp_unity.c: parse the UNITY_SPLITDNS_NAME (28675) attribute in
isakmp_unity_reply() for client-side roadwarrior connections.
isakmp_cfg.c: export INTERNAL_SPLITDNS_DOMAINS to phase1 scripts; free
split_dns in isakmp_cfg_rmstate(). test/test_splitdns.c: 12 unit tests
covering flag value, flag overlap, domain parsing, edge cases, and
resolver format conversion.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 2a — `90bd018`+`034baf8`+`cfdc769`+`d465e89`

```
samples: modernize roadwarrior server and client racoon.conf

Replace the outdated aggressive-mode samples with production-ready
configurations aligned with BSI TR-02102-3 cipher recommendations and
the phase1-up/phase1-down helper scripts: main mode instead of
aggressive, aes256/sha256/dh_group 15 (3072-bit) instead of
aes128/sha1/dh_group 2 (1024-bit), generate_policy unique instead of
on, verify_cert/verify_identifier/peers_identifier, split_network and
split_dns directives wired to phase1-up.sh's SPLIT_INCLUDE_CIDR and
INTERNAL_SPLITDNS_DOMAINS, and comprehensive inline comments.

Also removes the unmaintained racoon.conf-radius sample.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 2b — `c448451` (after stripping the false-start script hunks) + `1c2ea12`

```
samples: fix server cert path, listen binding, client sainfo/adminsock

Server: path certificate /etc/openssl/certs -> /etc/racoon/certs to
keep unprotected private keys out of /etc/ssl and /etc/openssl. Add
explicit listen isakmp/isakmp_natt directives so racoon only binds
the public-facing interface, not WireGuard/Docker/other virtual
interfaces.

Client: adminsock group operator -> racoon (operator does not exist
on modern Ubuntu/Debian; the racoon package creates a system racoon
user/group) and remove a second, wrong adminsock path left over from
an earlier edit. Add the missing 'sainfo anonymous' keyword (a bare
'{' is invalid syntax).

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 2c — `2786534` (after stripping the false-start script hunks) + `9759847` + `d75eb8f`

```
samples,debian: NetworkManager dns= note, onboarding stub, drop racoon-tool

client/racoon.conf: document that real per-domain split-DNS routing
needs NetworkManager running with dns=systemd-resolved or
dns=dnsmasq in NetworkManager.conf -- with the default dns=default,
phase1-up.sh falls back to redirecting all DNS lookups through the
tunnel and logs a warning saying so.

debian/racoon.conf: replace the shipped site-to-site PSK example
(deprecated 3DES/SHA1/aggressive-mode/modp1024) with direct guidance
for the two scenarios this project actually supports well --
connecting as a roadwarrior client, and running the gateway side --
referencing racoon.conf(5)/README.Debian instead of a stale external
HOWTO link. debian/rules: install examples by globbing
src/racoon/samples/* so paths match what the rewritten racoon.conf
references.

samples,debian: drop the racoon-tool reference and ship the client
sample inert by default, so a fresh install doesn't try to dial an
example.com gateway on boot.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

*(Attribution note: this specific target is a genuine mix -- the
NetworkManager dns= paragraph and the onboarding-stub/racoon-tool commits are
Claude's own drafting, folded here because they land on the same files as
Thomas's surrounding work. If the maintainer prefers Claude authorship for
this one target instead, use `Assisted-by: Thomas Reim <thomas.reim@airbus.com>`
+ `Signed-off-by: Claude <noreply@anthropic.com>` or whatever the trailer
policy decision settles on -- see plan Step 4.)*

---

## Target 3 — `1778093`+`0591684`

```
hooks: add racoon-hook-lib.sh skeleton (logging, run_step, state I/O)

First commit of the library-based rewrite: a shared
src/racoon/scripts/racoon-hook-lib.sh owning logging, run_step
(the single place that executes an external state-changing command),
and state-file I/O, with phase1-up.sh/phase1-down.sh reduced to thin
wrappers over it in later commits rather than each re-deriving
detection and planning logic inline.

This supersedes the exploratory phase1-up.sh/phase1-down.sh built
directly in src/racoon/samples/roadwarrior/client/ -- none of that
version's content survives; only the directory this establishes
(later renamed src/racoon/scripts/) carries forward.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

*(Kept Thomas's Signed-off-by since `1778093` -- the commit establishing this
target's directory move -- is his. If the maintainer would rather this read
as a Claude commit since essentially all of the surviving content is
`0591684`'s, that's a reasonable alternative -- see plan Step 4.)*

---

## Targets 4–9, 11–21 (single-source or already-adjacent-fold targets)

These reuse their original commit's subject line verbatim (already accurate
and in this project's own style) with the trailer normalized to the policy
decision from Step 4. Only the trailer line changes; the rest of each
message is unchanged from `git show <hash>`.

- **Target 4** `dafd2cf`: *hooks: add §4 input validation with injection-vector regression tests*
- **Target 5** `4b0ad39`: *hooks: add §7 resolv.conf landscape survey with 10 fixture tests*
- **Target 6** `2d0488e`: *hooks: add §6 capability matrix and resolvectl/systemd-resolve emitters*
- **Target 7** `53cbcb0`: *hooks: add §3.2 plan builder, §7.4 postconditions, and racoon-dns-detect CLI*
- **Target 8** `72e307b`: *hooks: replace phase1-up.sh with a thin wrapper over the plan/apply library*
- **Target 9** `5e407f3`: *hooks: replace phase1-down.sh with a pure undo replay of the state file*
- **Target 11** `1fb4079`: *hooks: fix resolved-backend DNS effectiveness check + rollback/reorder DNS steps*
- **Target 12** `436d6fb`: *hooks: add port 53 ownership survey as an equal-weight §7 input (brief 3 §C)*
- **Target 13** `6158721`: *hooks: FIFO generation-numbered state matching, supersedes stale-archival (brief 3 §D)*
- **Target 14** `e3fd36c`: *hooks: install and own SPD entries for the tunnel (brief 3 §E, R2')*
- **Target 15** `e2be159`: *docs: file daemon-side issues from live testing, record §F investigation status (brief 3 §F/§G)*
- **Target 16** `6c07e8a`: *hooks: on_dns_failure=report\|rollback replaces the overpromising "abort" (brief 3 §H)*
- **Target 17** `bbb8619`: *hooks: gate the resolv.conf-overwrite fallback behind allow_resolv_conf_overwrite (brief 3 §I)*
- **Target 18** `76f5572`: *tests: assert stderr cleanliness on every real subprocess invocation (brief 3 §J)*
- **Target 19** `8ed9fea`: *hooks: detect NetworkManager ownership before deleting the dummy interface (brief 3 §K)*

For each: keep the full original body from `git show <hash>` (already
well-written, self-contained, and matches this project's voice), append/
replace only the trailer with:
```
Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```
(or the maintainer's chosen alternative from Step 4 — these are all
unambiguously Claude's drafting against the maintainer's own briefs, so
`Signed-off-by: Thomas Reim` here means "maintainer reviewed and takes
responsibility for," the normal DCO meaning, not an authorship claim).

---

## Target 10 — `15c5bdb`+`cf6fd4b`

```
docs/ci: add hooks.conf.sample, admin guide, CI workflow, shellcheck-clean

etc/racoon/hooks.conf.sample, doc/admin/split-dns.html, and
.github/workflows/racoon-hooks.yml (shellcheck + a dash/bash Linux
matrix). All shipped scripts pass shellcheck clean.

Also adds the §12 final implementation report
(doc/admin/split-dns-implementation-report.md) required by the
rewrite's own brief: every remaining UNVERIFIED marker and what would
settle it, every open design question and the choice made, and the
fixture/test pass list.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 20 — `78ccd01`+`d3b22d1`

```
build: install the split-DNS hooks as a real package component (brief 3 §L)

Wires the hook set into the actual build/package outputs rather than
leaving it as in-tree-only example material: src/racoon/scripts/
Makefile.am, debian/racoon.install, packaging/arch/PKGBUILD, and
moves src/scripts/ -> src/racoon/scripts/ to sit alongside the rest
of racoon's own sources.

racoon-hook-lib.sh installs non-executable (INSTALL_DATA, 0644): it
has no shebang and is only ever sourced, never executed directly --
marking it executable is exactly what lintian's
executable-not-elf-or-script check flags.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 21 — `5b22a40`+`babaad2`+`e517623`

```
docs: add split-DNS hooks section to the real Admin Guide (brief 3 §M)

docs/admin-guide/racoon-admin-guide.html gets a new section pointing
at doc/admin/split-dns.html for the split-DNS/routing hook set, and
the implementation report is extended with Brief 3's own §12-style
summary.

Renames the report to its 1d1- prefix (first draft, not kept in sync
with later fixes -- its own UNVERIFIED-marker notes are narrower than
the current code comments) and updates the one cross-reference to it
in ARCHITECTURE.md.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 22 — `ec38f74`+`2630265`+`163fbdd`+`64ef546`

```
hooks: 3 live bugs found in real-world testing

- Idempotent dummy-interface creation: racoon0 could be left over
  from a non-clean prior stop; reuse it (bring it up) instead of
  failing outright on "File exists" from a bare `ip link add`.
- systemd-resolve's DNS/domain-clearing commands were invalid; use
  --revert instead, matching resolvectl's own equivalent.
- Plan the NetworkManager DNS profile (which owns the dummy
  interface/address for that backend) before routes -- routes need
  `src=` to already be assigned somewhere, and NM's own profile step
  used to run after them, producing "Invalid prefsrc address."
- ipv6.method ignore instead of disabled for the NM DNS profile:
  disabled additionally turns IPv6 off at the kernel level and isn't
  accepted by the NetworkManager version found in the field; ignore
  is accepted everywhere and is sufficient since this hook set never
  routes IPv6 traffic through the dummy interface anyway.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 23 — `7ec2ec6`+`472f77e`+`bfbfff5`+`debdc77`

```
docs: add doc/dev/ARCHITECTURE.md, a tutorial for the split-DNS/routing hooks

Developer-facing walkthrough of the survey -> classify -> plan ->
apply pipeline, the R1-R8 design rules, and the brief 3 §A-§M
decisions, with corrections folded in: a numbering collision and an
undercount in the original draft, systemd-version comments rechecked
against the full NEWS file (two updated), and an Arch Linux note on
NetworkManager's RcManager compiled default.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 24 — `a40fef6`+`1bf0d9e`

```
docs: close out Task F ACQUIRE-provenance investigation (Branch B)

Records the investigation's findings across ARCHITECTURE.md,
daemon-issues.md, and teardown-investigation.md, then softens the
original-ACQUIRE causal claim to what the live evidence actually
supports rather than what seemed likely going in.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 25 — `9dfd5b8`+`52aa366`

```
hooks: match phase1-down.sh's own generation by IKE_COOKIE, not FIFO order (issue #90)

phase1-down.sh picked the oldest live state-file generation for a
peer address, which can consume an orphaned session's state instead
of its own when two generations for the same peer are live at once
(a teardown for an old session and the setup of its replacement
landing within the same second, or an earlier session's state never
cleanly torn down). script_hook() (src/racoon/isakmp.c) now exports
IKE_COOKIE, racoon's own per-negotiation session token -- fixed for
the life of a Phase 1 negotiation, from the isakmp_index in the iph1
handle. racoon-hook-lib.sh records each generation's cookie in a
sidecar file; phase1-down.sh matches on it exactly instead of
oldest-first.

Confirmed live across three distributions (Ubuntu Noble, Ubuntu
Bionic i386, Arch) using tools/racoon-hook-integration-test.sh.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Targets 26–29 — Task F tooling (unchanged, kept separate)

Reuse each original message verbatim except the trailer:

- **Target 26** `b3caa65`: *tools: add task-f-acquire-investigation.sh (v1)*
- **Target 27** `09b3a15`: *tools: harden task-f-acquire-investigation.sh against two contamination sources (v2)*
- **Target 28** `5f92c69`: *tools: filter per-socket SPD noise, terminate racoon by default (v3)*
- **Target 29** `40c33ad`: *tools: add issue #90 live checks, rename to racoon-hook-integration-test.sh*

Trailer for all four:
```
Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 30 — `6c3870f` (unchanged)

```
doc: add split DNS NM integration development report 1d1

Records Thomas's own original prototype report (base commit 89efb95,
HEAD 095a142 on feature/dns-nm-integration -- a separate, earlier
iteration of the dummy-interface design, predating this branch's own
false start) as doc/dev/1d1-split-dns-implementation-report.md, and
renames the existing 1d1- report (Claude's rewrite report) to 1d2-.

Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

*(No `Assisted-by` line here — this is Thomas's own report about his own
work, no AI drafting involved in the reported content itself.)*

---

## Target 31 — `8e946d2`+`2cb972a`

```
tests: fix 2 CI failures found in PR #91 review

test-dns-emitters.sh's "falls back to systemd-resolve (Bionic case)"
scenario leaked the real resolvectl from the runner's own PATH,
passing for the wrong reason; pin RACOON_HOOK_RESOLVECTL to a
nonexistent path for that scenario specifically.

test-phase1-roundtrip.sh/test-phase1-up.sh hardcoded `dash` for real
hook invocations; the NetBSD CI job has no dash package at all,
failing every one of them outright with "dash: not found" rather than
actually exercising the hooks. Falls back to `sh` when dash isn't on
PATH.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 32 — `8d11d6c`+`69a6659`+`53a8f53`+`7c16c4f`

```
docs+hooks: apply PR #91 review items #4/#8, #11-16/#30, #36, #38

- rhook_ensure_state_dir(): warn (not silently swallow) a failed
  mkdir -p; rhook_undo_replay(): distinguish "no state file" from
  "state file exists but unreadable" (#4/#8).
- Admin Guide: precise PARALLEL_UNLINKED definition, a
  resolvectl/systemd-resolve capability matrix scoped to where they
  actually differ, the SPD/route rollback tradeoff, and the
  orphan/heuristic teardown caveat (#11-16/#30).
- racoon-dns-detect.8: new man page; hooks.conf documented in
  racoon.conf.5/racoon.8 (#38).
- tools/racoon-hook-integration-test.sh: 3 preflight assumption
  checks (live hook-state generations, a competing IKE daemon, DNS
  resolution of the gateway) (#36).

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 33 — `5d7efe9` (unchanged)

```
tests: cover a crashed phase1-up.sh's incomplete state file (PR #91 #23)

test-phase1-roundtrip.sh's existing overlap/lifo scenarios both let
phase1-up.sh run to completion; neither covers the actual issue #90
scenario of a hard-killed phase1-up.sh leaving a genuinely incomplete
state file behind. Added a "crash" scenario that SIGKILLs
phase1-up.sh mid-run and verifies the exact-IKE_COOKIE-match fix
still finds and correctly replays the orphan's one completed step,
without affecting a concurrent fresh session for the same peer.

Also documents, at rhook_conn_cookie(), why the review's claimed
mechanism for this row (NAT-T rebind causing IKE_COOKIE reuse) does
not hold: the cookie pair is fixed at Phase 1 handle creation and is
tracked independently of the NAT-T port-float flag in isakmp.c.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 34 — `655caf5`+`a4b0f4e`

```
hooks: close the dummy-interface check-then-create race (PR #91 #24)

rhook_ensure_dummy_iface()'s "does it exist" check and its "ip link
add" were not atomic: two genuinely concurrent phase1-up.sh runs --
for the same peer, or for two different peers, since the dummy
interface name is one fixed hooks.conf value shared by every session
on the host -- could both pass the check before either created the
interface.

Serializes the whole check-then-create section with flock(1)'s
file-descriptor form when available, falling back to the same
mkdir-based retry-and-cap lock rhook_state_reset() already uses when
it isn't -- this project has no confirmation flock(1) ships in
NetBSD's base install, so the fallback lets that CI job exercise
whichever path actually applies there.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 35 — `de83380`+`fde49e9`+`9731af3`+`16fc058`

```
hooks: validation gaps from PR #91 row 29 (bogon/RFC1918, CIDR overlap, Punycode)

- rhook_validate_dns_list(): extend bogon rejection to link-local
  (169.254.0.0/16) and reserved/Class E plus broadcast
  (240.0.0.0/4), on top of the pre-existing 0.0.0.0/loopback/
  multicast checks. RFC1918 ranges remain, and must remain,
  unconditionally allowed -- they're the address family this
  project's own live-tested internal DNS servers actually use (29a).
- rhook_build_plan(): warn (never reject) on overlapping
  split-include CIDRs -- redundant, not unsafe. 0.0.0.0/0 is not
  specially rejected either: full-tunnel support is a product-scope
  question this fix does not decide (29b).
- rhook_validate_domain_list(): warn on Punycode-encoded (xn--)
  domains after confirming raw Unicode homoglyphs are already
  rejected by the existing character-class check (29c).

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```

---

## Target 36 — `84990be` (unchanged)

```
docs: lead user-facing prose with "phase1-up/phase1-down scripts" (PR #91 #41)

Terminology pass across the Admin Guide, racoon-dns-detect.8, and
racoon.8: an operator/sysadmin reading these has no reason to already
know "hook" the way a developer would, while "phase1-up/phase1-down
scripts" is what racoon.conf's own `script` directive already shows
them, verbatim. Each document introduces "(also called hooks)" once,
at first mention, then leads with "the scripts" or names the
specific script directly for the rest of that document. Code
identifiers, file names, and developer-facing docs are unchanged.

Assisted-by: Claude <noreply@anthropic.com>
Signed-off-by: Thomas Reim <thomas.reim@airbus.com>
```
