# RFC 0005: AI Provenance in Git ("provpaws")

## Status

Draft

## Authors

- Thomas Reim (@rdratlos)

## Reviewers

- @rdratlos (decision)
- (open — reviewers welcome)

## Motivation

AI-assisted development is now the normal way this project is built, and
the commit history should be able to answer one question reliably:
**which model produced code that is still in the tree, and where?** That is
the question a maintainer has to answer when a model is found to have a
systematic bug pattern, a licensing problem, or a security weakness — the
same reason DO-330 asks which tool, in which version, produced an
unverified artefact.

Today the history cannot answer it. On `develop`, 251 of 422 non-merge
commits carry AI attribution, written by hand or by a post-commit hook that
rewrites Claude Code's default `Co-Authored-By:` into `Assisted-by:`
(`.claude/settings.json`). The result:

- two key spellings (`Assisted-by` ×211, `Assisted-By` ×37) and three
  leftover `Co-Authored-By:` lines naming an AI;
- free-text values in incompatible shapes — `Claude Sonnet 5 <noreply@…>`,
  `OpenCode:KITCH-Coder`, `OpenCode:Qwen/Qwen3-Coder-480B-A35B-Instruct`,
  `Claude:claude-opus-4-6`, and a `Sonet` typo;
- **41 commits whose model is unknowable**: 36 say only `Claude`, 5 say
  only `OpenCode:`;
- no file-level information at all: a trailer covers the whole commit,
  including the lines the human wrote;
- no record of multi-agent work (orchestrator, implementer, reviewer on
  different models), which is how OpenCode sessions increasingly run.

Meanwhile the industry has not converged. The Linux kernel introduced
`Assisted-by: AGENT_NAME:MODEL_VERSION` for 7.0 and in July 2026 reduced it
to `Assisted-by: LLM`, dropping the model on the grounds that naming
vendors in the history is advertising with little information value.
Fedora recommends a free-form `Assisted-by:`; QEMU (May 2026) requires an
`AI-used-for:` scope tag; Kubernetes forbids any such trailer; Claude Code
and VS Code default to `Co-Authored-By:`, which GitHub renders as a
co-author.

This project takes a different position from the kernel: the model **is**
the important information, but it belongs in a structured record that the
project controls, not in vendor-shaped free text. And whatever tools we use
in six months, the Git repository will still be here — so the record lives
in Git.

## Goals

- **G1 Answer the recall question.** Given a model (or model family, or
  setup), list the commits and files it contributed to and how many of its
  lines survive at a given revision — the *recall drill*.
- **G2 Human accountability.** Only humans sign off or co-author; an AI
  agent can prepare a provenance record but cannot complete the human
  attestation.
- **G3 Tool neutrality.** The format is defined by this repository, not by
  Claude Code, OpenCode or any successor. Harness integrations are
  replaceable adapters.
- **G4 Survive the PR workflow.** Records survive rebase, squash and
  cherry-pick, and can be contributed from forks without extra refs or
  permissions.
- **G5 Multi-model sessions.** Record several models in several roles per
  session without growing the commit message.
- **G6 Neutral references.** A contributor's organisation can keep a model
  confidential behind a neutral identifier it resolves internally.
- **G7 Verification independence.** AI-written changes to attack-surface
  code are reviewed by a model from a different family (dissimilarity), in
  addition to human review.
- **G8 Machine-checked.** CI verifies every rule; nothing depends on a
  reviewer remembering it.
- **G9 Scale to ~20 contributors** using only Git, Python and GitHub
  Actions.

## Non-goals

- **Detecting undeclared AI use.** This is a contract between
  contributors, not surveillance. Declarations are self-reported; the
  format states how trustworthy each field is (`model_reported_by`), and
  nothing more is claimed.
- **Storing prompts or transcripts** in the repository (size,
  confidentiality, secrets). A digest of a privately kept log is optional.
- **Legal questions** about copyright of model output or DCO validity.
  The DCO is unchanged: the human who signs off certifies it.
- **Rewriting history.** Commits before the enforcement baseline keep
  their trailers; they are made queryable, not corrected.
- **Signing manifests.** Commit signing binds the human sign-off; manifest
  signatures can be added in a later revision if the threat model needs
  them.

## Current design

- `CONTRIBUTING.md` ("AI-Assisted Development") states that AI tooling is
  used but defines no trailer format.
- `.claude/settings.json` on `develop` has a `PostToolUse` hook that, after
  a `git commit` by Claude Code, rewrites `Co-Authored-By:` into
  `Assisted-by:` and amends the commit with `--no-verify`. Model names are
  whatever the harness emitted, including the e-mail address.
- OpenCode sessions are attributed by asking the agent to add a trailer, or
  by hand.
- No CI job looks at trailers. The tree-separation guards
  (`guard-branch-purity.yml`, `guard-tree-purity.yml`) are the only
  workflows that inspect commit content beyond building and testing.

## Proposed design

### 1. Overview

```
commit message            .provenance/ (in the tree)
──────────────            ──────────────────────────────────────────────
Assisted-by: P@rN  ─────▶ profiles/P/rN.toml      which model per role
AI-Scope: code            policy.toml             rules
Provenance-Id: X   ─────▶ manifests/YYYY/X.json   what each role wrote
Signed-off-by: human ◀─── attestations/YYYY/X/T.json  human approval,
                          (signed approval commit)    bound by patch-id
```

The commit message carries three short, stable trailers. Everything
detailed lives in versioned files in the tree, keyed by IDs rather than
commit SHAs, so it survives every Git operation that rewrites SHAs. The
human approval is a separate, signed commit written by `prov attest` (§4a).

### 2. Trailers

| Trailer | Cardinality | Value |
| --- | --- | --- |
| `Assisted-by:` | one per profile used | `<profile-id>@r<N> [tool …]` |
| `AI-Scope:` | exactly one if assisted | comma list from `docs, tests, build, ci, packaging, refactor, code` |
| `Provenance-Id:` | exactly one if assisted | `YYYYMMDDTHHMMSSZ-<8 hex>` |
| `Signed-off-by:` | ≥ 1 human if assisted | unchanged DCO meaning; added by `prov attest` (§4a) |

- The key `Assisted-by` and the optional trailing analysis tools
  (`coccinelle`, `sparse`, …) follow the kernel's syntax, so kernel-style
  tooling can still parse the line. The first token is a **profile
  reference** instead of a vendor model name or the literal `LLM`.
- Spellings are canonical; `Assisted-By` fails.
- `Signed-off-by:` and `Co-Authored-By:` whose value matches an AI
  identity pattern (`policy.toml`) fail.
- `AI-Scope` is QEMU's idea: what kind of change the AI output is. It
  drives policy (§6) and makes review triage cheap.
- Other trailers (e.g. `Claude-Session:`) are allowed and ignored.
- A free-text `Assisted-by:` (no profile reference) is accepted only on a
  guest's fork pull request, until the maintainer's intake replaces it
  (§11). On branches in this repository it fails.

**Commit identities — the pair in Git's two fields.** The human of the
pair is the **author** of record; the agent may appear as **committer**:

| Field | Value | Meaning |
| --- | --- | --- |
| Author | the accountable human | author of record, as in kernel and Fedora practice |
| Committer | the agent (e.g. `Claude Code <agent@…>`) | mechanical fact: who created the commit object |
| `Assisted-by:` + manifest | profile, model, files | what the AI contributed |
| `Signed-off-by:` | the human, added by `prov attest` | DCO certification |

An agent therefore commits with the human's name as author. That is not
misrepresentation: the trailers and manifest disclose the assistance, and
authorship here means accountability, not keystrokes. An agent never adds
`Signed-off-by:` and never has access to the human's signing key.
`verify` fails an AI-assisted commit whose **author** matches an AI
identity pattern; the committer is not restricted.

### 3. Profiles — the neutral reference

`.provenance/profiles/<id>/r<N>.toml` describes a setup: harness, owner,
and one model per role.

```toml
schema_version = "1.0"
id = "opencode-pair"
revision = 1
harness = "opencode"
owner = "rdratlos"
status = "active"

[[roles]]
name = "implementer"
model_family = "alibaba-qwen"
model_id = "Qwen/Qwen3-Coder-480B-A35B-Instruct"
disclosure = "public"

[[roles]]
name = "reviewer"
model_family = "anthropic-claude"
model_id = "claude-sonnet-5"
disclosure = "public"
```

- **Immutable.** Once merged, a revision file never changes; any change
  (new model, new role) is `r<N+1>`. CI rejects modification or deletion.
  A trailer therefore resolves to exactly one setup forever, with no Git
  archaeology.
- **`model_family`** is what the dissimilarity rule compares.
- **`disclosure = "withheld"`** implements G6: `model_id` is a neutral
  reference (e.g. `acme-coder-2`) that only the profile `owner` resolves.
  The public history carries no vendor name; the organisation keeps
  internal traceability.
- Profiles are the natural home for harness configuration cross-checks
  (§7): an OpenCode agent definition or Claude Code setting is expected to
  agree with the profile it claims.

### 4. Manifests — the forensic record

`.provenance/manifests/<YYYY>/<Provenance-Id>.json`, one per AI-assisted
session. A session may span several commits; each references the same ID.

```json
{
  "schema_version": "1.0",
  "provenance_id": "20261012T081500Z-3f9a1c2e",
  "created": "2026-10-12T08:15:00Z",
  "contributions": [
    { "profile": "opencode-pair@r1", "role": "implementer",
      "model": { "family": "alibaba-qwen",
                 "id": "Qwen/Qwen3-Coder-480B-A35B-Instruct" },
      "model_reported_by": "api",
      "files": ["src/racoon/isakmp_frag.c", "test/test_isakmp_frag.c"] },
    { "profile": "opencode-pair@r1", "role": "reviewer",
      "model": { "family": "anthropic-claude", "id": "claude-sonnet-5" },
      "model_reported_by": "config", "files": [] }
  ],
  "human_review": { "reviewer": "jane@example.org",
                    "statement": "reviewed-and-tested" },
  "session": { "digest": "sha256:…" }
}
```

Rules:

- **Record what entered the diff.** `files` lists paths whose committed
  content contains output of that contribution. Models used only for
  search or explanation need not appear. Review-only roles have `files: []`.
- **`model_reported_by`** — `api` (the provider said so), `config` (the
  harness was configured so), `manual` (declared by hand). This makes the
  self-reporting weakness explicit rather than hiding it.
- **Silent substitution.** If an `api`-reported model differs from the
  profile role's model, a provider, router or moving alias swapped it.
  `verify` warns; `config`/`manual` mismatches fail —
  change the profile instead.
- **`human_review.statement = "pending"`** is what an agent writes when it
  runs `declare`. The manifest stays as the agent wrote it; approval is the
  separate attestation (§4a).
- Manifests are **immutable** once merged, like profiles.
- Schema: `.provenance/schema/manifest-v1.schema.json` (JSON Schema
  Draft 2020-12). `schema_version` is frozen per major version, the same
  discipline as `RACOONCTL_STATUS_SCHEMA_VERSION`: a breaking change is a
  new `manifest-v2` file, and v1 records stay valid forever.

### 4a. Attestation — the human approval (`prov attest`)

Approval used to mean editing the manifest, amending commits and signing
off by hand. That rewrote what the agent produced, needed a rebase for
multi-commit sessions, and bound the approval to nothing: the content could
change after review. `prov attest` replaces it with one deliberate act:

1. **Checks** that it runs in the human's own terminal (it refuses when an
   agent marker such as `CLAUDECODE` is set), on a clean, linear range
   ending at `HEAD`, with a git identity that is not an AI identity.
2. **Runs the tests** given with `--test` on the tree being approved.
   Exit 0 is required for `reviewed-and-tested`; the command, exit status,
   duration and a SHA-256 digest of the output are recorded (the log itself
   stays local, `--test-log`). Without `--test` the statement is `reviewed`.
3. **Shows** the sessions, commits and diffstat, and asks for confirmation.
4. **DCO** — adds the human's `Signed-off-by:` to every commit in the
   range by a message-only rewrite: trees, author and committer (names,
   e-mails, dates) are kept, so the agent stays recorded as committer and
   diffs are unchanged. Leading commits that already carry the sign-off are
   left untouched; a signed commit that must be rewritten is re-signed by
   the attester. (An earlier draft also offered an `approval-commit` mode
   without rewrite; no one used it, and it was dropped, §11.6.)
5. **Writes** `.provenance/attestations/<YYYY>/<Provenance-Id>/<time>.json`
   and commits it **signed** (`git commit -S`):

```json
{
  "schema_version": "1.0",
  "provenance_id": "20261017T094500Z-3f9a1c2e",
  "reviewer": "reimth@etik.com",
  "statement": "reviewed-and-tested",
  "attested": "20261017T115000Z",
  "commits": [
    { "patch_id": "9b1c…", "subject": "isakmp: bound-check …" },
    { "patch_id": "41de…", "subject": "test: cover …" }
  ],
  "tests": { "command": "make check", "exit": 0,
             "log_digest": "sha256:…", "duration_s": 412.7 }
}
```

**Binding by `git patch-id --stable`.** A patch-id identifies a commit by
its diff, not its SHA. The approval therefore survives rebase and
cherry-pick (G4), but any change to a reviewed diff, even one line,
invalidates it: `verify` recomputes the patch-ids and fails with "diff
changed after approval". Further commits of the same session need a further
attestation; attestation files are immutable once merged, like manifests.

**Signature, not tooling, is the control.** The approval commit must be
SSH-signed by a key listed in `.provenance/allowed_signers`
(`gpg.ssh.allowedSignersFile` format), and the signing principal must equal
`reviewer`. `verify` reads the allowed signers from the **base** of the
range, so a change cannot admit its own key. (While the base had no
signers at all, the change's own file was used with a warning; this
bootstrap rule served once, for the pull request that added the first
maintainer key, and is replaced by a plain "no signers at base" error,
§11.6.) A key on a hardware
token — FIDO2 `sk-` keys, or an OpenPGP card serving SSH through gpg-agent
— with touch required proves human presence; the agent never holds the
key. The agent-environment check in step 1 is only a speed bump.

**Maintainer workstation.** Signing and verifying approvals needs Git
≥ 2.34 (SSH signing; `user.signingkey` as a path to a `.pub` file, since
the inline `key::` form needs Git ≥ 2.35), OpenSSH ≥ 8.2 (`ssh-keygen -Y`
including `find-principals`), Python ≥ 3.11 (`tomllib`) and, for an
OpenPGP key served through gpg-agent, GnuPG ≥ 2.2. These are requirements
of the workstation that attests, not of racoon's target platforms: racoon
still builds and runs down to Ubuntu Bionic (Git 2.17, OpenSSH 7.6,
Python 3.6), which simply cannot attest.

**Rebasing and merging.** A rebase creates new commit objects and drops
signatures. Patch-ids are unchanged, so the human re-signs while rebasing
(`git rebase --gpg-sign`, or `commit.gpgsign = true`) and the attestation
stays valid without re-attesting — re-signing is the re-confirmation.
GitHub's rebase-merge and squash-merge recreate commits without the
human's signature; merges into `develop` therefore use merge commits.

**Manifest vs. attestation.** The manifest says what the AI did, written by
the agent; the attestation says what the human approved, signed by the
human. Neither edits the other. For DO-178C-style projects the attestation
is the review record: reviewer identity bound by signature, reviewed
content bound by patch-id, test evidence by digest.

### 5. Why in-tree files, not git notes or a side branch

| Option | Survives rebase/squash/cherry-pick | Forks can contribute | Visible in review |
| --- | --- | --- | --- |
| git notes (`refs/notes/…`) | no — keyed by SHA | needs extra refspec/push rights | no (GitHub does not show notes) |
| orphan `provenance` branch | yes | needs push rights to that branch | separate PR |
| **in-tree, keyed by ID** | **yes** | **yes, ordinary PR** | **yes, in the same diff** |

The cost is a small JSON file per session in the tree, which is acceptable
and makes the record reviewable alongside the code it describes.

### 6. Policy (`.provenance/policy.toml`)

- **`enforcement.baseline`** — commits at or before this commit are exempt;
  Phase 0 sets it to `develop`'s tip, so no existing commit is touched.
- **`critical.paths`** — attack-surface and privilege-boundary code: IKE
  parsing (`isakmp*.c`, `ipsec_doi.c`, `oakley.c`), crypto
  (`crypto_openssl.c`, `openssl_compat.c`), `privsep.c`, `admin.c`,
  `pfkey.c`, `nattraversal.c`, `dnssec.c`, `kernelpaws*`, `resolvpaws*`,
  `libipsec`.
- **Dissimilar review (G7).** If a session's scope includes `code` or
  `refactor` and any contribution wrote a critical file, the manifest must
  contain a `reviewer` contribution whose model family differs from every
  family that wrote critical files. Same-model review shares the same blind
  spots — the AI analogue of the verification independence DO-178C
  requires at higher DALs. Human review is required in addition, never
  instead.
- **Withheld models stay out of critical paths.** Nobody outside the
  owning organisation could act on a recall of a model they cannot name.
- **AI-assisted commits need a human `Signed-off-by:`**, added by
  `prov attest` (§4a).
- **`[attestation]`** — `allowed_signers`, `agent_env` (§4a). Attestation
  and its signature are always required; there is no switch to turn either
  off (§11.6).

### 7. Capture: adapters per harness

`tools/prov.py declare` is the single, tool-neutral entry point: it writes
the manifest, stages it, and prints the trailers. Every adapter's only job
is to call it (or produce identical output):

- **Manual** (Phase 1): the contributor runs `declare`. Works for any tool,
  including browser chats and copy-paste — the path that keeps the
  framework honest for contributors using neither harness.
- **Claude Code** (Phase 2): project settings to stop emitting
  `Co-Authored-By:` (replacing today's rewrite hook), plus a hook that
  records the session's model and edited files into a local session log
  for `declare`. *The exact setting keys and hook input fields must be
  verified against current Claude Code documentation when Phase 2 starts;
  third-party descriptions of the `attribution` setting disagree.*
- **OpenCode** (Phase 3): the equivalent through OpenCode's agent
  configuration (per-agent model pinning maps directly onto profile roles)
  and its plugin/event mechanism. *Hook points to be verified when Phase 3
  starts.*
- **Config cross-check** (Phase 3): CI compares harness configuration in
  the repository (`.opencode/`, `.claude/`) against the profiles it claims,
  so a pinned model cannot drift silently from the record.

Adapters are expected to be rewritten as tools change. The schema,
`policy.toml` and `prov` are what stays.

### 8. `tools/prov.py`

Single-file Python ≥ 3.11 (stdlib `tomllib`; `jsonschema` for `verify`),
reporting in `schema_cross_check.py`'s `[OK  ]`/`[WARN]`/`[FAIL]` style.

- `prov verify --range A..B` — schemas and path/ID consistency of all
  profiles and manifests; immutability against `A`; for each commit in the
  range after the baseline: trailer spelling, AI identities, profile
  resolution in the commit's own tree, scope, sign-off, manifest presence;
  per session: role/model/family match against the profile, substitution,
  `files` ⊆ files changed by the session's commits, dissimilarity,
  withheld-in-critical; with attestation required: every commit's patch-id
  covered by an attestation whose approval commit is signed by an allowed
  key of the reviewer (allowed signers read at `A`).
- `prov declare --contrib <id>@r<N>:<role>[=file,…] … --scope …` — writes
  and stages a manifest, prints trailers. `--statement pending` for agents.
- `prov attest [--range BASE..HEAD] [--test CMD] [--test-log FILE]` —
  the human approval (§4a): tests, sign-off, signed approval commit.
- `prov intake --pr <N>` — the maintainer's intake of a guest pull request
  (§11.3): fetches it onto a branch in this repository, creates or reuses a
  maintainer-owned profile mirroring the guest's statement, rewrites commit
  messages (and an AI author) into canonical form, writes the manifest.
- `prov query --model RE | --family F | --profile ID [--blame]
  [--include-legacy]` — the recall drill. `--blame` counts surviving lines
  per commit and file at a revision. `--include-legacy` maps pre-baseline
  free text through `.provenance/legacy-map.toml`; values it cannot map
  (bare `Claude`, bare `OpenCode:`) are reported as unmapped and **not**
  guessed. Legacy hits cover whole commits (no file-level data), so their
  line counts are upper bounds.

### 9. CI

`develop-provenance.yml` (develop-owned, named per the tree-separation
policy):

- `self-test` — `python3 -m unittest tools/test_prov.py`: 35 tests in
  throw-away repositories covering every pass/fail rule, including signed
  approval commits with throw-away SSH keys. Always blocking: a broken
  checker must never silently pass everything.
- `verify` — `prov verify` over the PR's merge-base..head or the push range.
  Non-blocking (`continue-on-error`) in Phase 0, blocking from Phase 1 —
  except on guest fork pull requests, where it is advisory (§11.4).

Merges into `develop` use **merge commits only**. GitHub's squash-merge
concatenates commit messages and can mangle trailers; both squash- and
rebase-merge recreate commits without the human's signature (§4a). Disable
both for `develop` in the repository settings once `verify` blocks.

### 10. Rollout

| Phase | Content | Exit criterion |
| --- | --- | --- |
| 0 | RFC, schemas, policy, seed profiles, `prov`, CI (verify non-blocking) | self-tests green; recall drill runs on real history |
| 1 | `CONTRIBUTING.md` section (Appendix A); maintainer key in `allowed_signers`; `verify` blocking; remove `.claude` rewrite hook; agent git identity (author = human, committer = agent); merge commits only; guest intake and advisory fork mode (§11.3, §11.4); simplification (§11.6) | one month of maintainer sessions attested and passing |
| 2 | Claude Code adapter | `declare` output produced without manual steps |
| 3 | OpenCode adapter; harness-config cross-check | multi-agent session recorded with roles |
| 4 | First formal recall drill (Acceptance criteria) before actively inviting outside contributors; single guest PRs taken via intake (§11.3) do not wait for it | drill report filed as an Issue |

### 11. Guest contributions

#### 11.1 Principle

**Strict where the maintainer works, light where guests work.** The
accountability that matters is at merge time, and the merger is the
maintainer. A guest therefore owes one honest statement; the maintainer
turns it into the structured record and attests it. Every merge into
`develop` still passes the full `verify`.

The kernel goes further in the same direction: since July 2026 it asks
contributors only for `Assisted-by: LLM` and drops the model altogether.
This project keeps the model, but lets a guest name it in free text and
does the structuring itself.

#### 11.2 What a guest provides

Human-only contribution: nothing. No trailer, no profile, no manifest.

AI-assisted contribution: one free-text sentence, in the pull request
description or as a trailer, naming tools, models and what they were used
for:

```
Assisted-by: Claude Code (Opus), review by GPT-5
```

plus the guest's own `Signed-off-by:` (DCO for their provenance). A guest
never creates profiles, manifests or attestations and never runs `declare`
or `attest`. A guest's statement is `model_reported_by = "manual"` by
definition; formalising it would not make it more trustworthy.

The same rule as for everyone applies: **retyped is still assisted**. Text
an agent wrote counts even if the guest copied or reworked it by hand.

#### 11.3 Intake (maintainer side)

An AI-assisted guest pull request is **never merged with the merge
button**. The maintainer takes it in through a pull request from a branch
in this repository, which supersedes the guest's ("supersedes #N"), so that
it passes the blocking `verify` (§11.4). `prov intake` (§8):

1. fetches the guest's commits onto a branch in this repository;
2. creates a profile with `owner = <maintainer>` that mirrors the guest's
   statement, or reuses an existing one (for example the contributor kit's
   profile, Appendix C);
3. rewrites the commit messages into canonical form (profile reference,
   `AI-Scope`, `Provenance-Id`). Trees, the committer and the guest's
   `Signed-off-by:` are kept. If the guest's agent recorded itself as
   **author**, intake sets the guest as author: §2 makes the accountable
   human the author of record, so this corrects the record rather than
   altering it;
4. writes the manifest with `model_reported_by = "manual"`. Where the guest
   gave no per-file detail, `files` lists every file the guest's commits
   change: an upper bound, like legacy attribution, and stated as such.

The maintainer then reviews, runs `prov attest` and merges the intake pull
request with a merge commit. The guest stays author of every commit.

The free-text trailer of §11.2 is therefore **not** valid on branches in
this repository: `verify` rejects it there (§2). The recall drill loses
per-file precision for such commits; `manual` says so honestly.

Critical paths (§6) are unchanged: guest AI `code` in a critical path needs
a `reviewer` contribution from a different model family. If the guest's
statement does not include one, the maintainer runs the dissimilar review
before attesting. That review is a contribution under the **maintainer's**
profile in the same manifest (each contribution carries its own `profile`),
so the commits carry two `Assisted-by:` lines, one per profile (§2).
`withheld` is not available to guests: the owner resolving the reference
would be the maintainer.

Human-only guest pull requests carry no trailers; `verify` passes them, and
they may be merged directly.

#### 11.4 CI behaviour

| Context | `verify` |
| --- | --- |
| Branch in this repository, PR to `develop` | blocking, full rules |
| Fork PR (`head.repo != github.repository`) | advisory: always green; the job summary thanks the guest, says the maintainer completes the record at intake, and lists the findings without enforcing them |
| Push to `develop` | blocking over the pushed range: detects a guest PR merged without intake |

- Findings on forks that would be hard failures in this repository (for
  example an AI identity in `Signed-off-by:`) stay warnings there and are
  corrected at intake.
- The `self-test` job stays blocking for everyone.
- No labels or other write operations from fork pull requests: those would
  need `pull_request_target`, which runs with write access in the base
  repository's context and must never be combined with checking out or
  executing a fork's code. The rule in §11.3 (no merge button for
  AI-assisted guest PRs) and the blocking push check replace a label.

#### 11.5 Profile references for guest contributions

Two options were considered.

| | A. `prov intake` creates a maintainer-owned profile | B. `profile` optional when `model_reported_by = "manual"` |
| --- | --- | --- |
| Manifest schema v1 | unchanged | change: `profile` is required per contribution today |
| Trailer grammar (§2) | unchanged | needs a profile-less form |
| Substitution check, dissimilarity (G7) | unchanged | substitution skipped; family must be required in the manifest `model` block |
| `withheld` | n/a for guests | undefined without a profile |
| Immutable files | more profile revisions | fewer |
| Special cases in `verify` | none | several |

**Adopted: A.** `manifest-v1.schema.json` requires `profile` for every
contribution and `verify` enforces the `<id>@r<N>` form in the trailer, so
B would be a schema change plus new special cases. A keeps every invariant;
the cost is more profile files, which is cheaper than more rules.

#### 11.6 Simplification

Options that no one uses are removed from `policy.toml`, `prov.py`, the
tests and the documentation, in the implementation pull request for this
section (not in the Phase 1 groundwork):

| Option | Reason |
| --- | --- |
| `attestation.dco = "approval-commit"` (former policy a) | racoon uses the rebase sign-off |
| `attestation.required = false` and its "pending fails" path | not used |
| `attestation.require_signature = false` | the signature is the control |
| `substitution = "fail"` | fixed to `warn`; reintroduce on demand |

The bootstrap rule for `allowed_signers` (§4a) is replaced by a plain
error "no signers at base" once the first maintainer key is on `develop`.

#### 11.7 Documentation

`.provenance/README.md` gains the guest and intake procedure and the
maintainer workstation setup (SSH signing, including an OpenPGP key served
through gpg-agent, minimum versions, and a table of common signing errors);
`CONTRIBUTING.md` carries the short form (Appendix A).

## Alternatives considered

- **Do nothing / free text.** The current state: 41 commits already have no
  usable model, and spellings drift. Rejected.
- **Kernel style `Assisted-by: LLM`.** Vendor-neutral and simple, but gives
  up exactly the recall capability that motivates this RFC; for a security
  daemon handling untrusted IKE input that trade is wrong. The profile
  reference keeps the history vendor-neutral *and* keeps traceability.
- **Old kernel style `AGENT:MODEL_VERSION` in the trailer.** Traceable but
  unstructured, single-model, whole-commit only, and leaks confidential
  model names. Superseded by profile + manifest.
- **`Co-Authored-By:` (vendor default).** Makes the AI a co-author on
  GitHub and contradicts the "human is the author" principle shared by the
  kernel, Fedora and this project. Rejected and actively rejected by CI.
- **git notes / orphan branch.** See §5.
- **External database or attestation service** (e.g. session-capture
  tools writing to a separate store). Adds a dependency that may not exist
  in six months; Git will. Could later be fed *from* the manifests.
- **A controlling agent as the source of truth.** A pinned orchestrator
  gives process stability, but its record of what subagents wrote is still
  self-reported by a model. The orchestrator is recorded as a role like any
  other; accountability stays with the human.

## Compatibility

- No effect on racoon's on-wire behaviour, `racoon.conf`, `libipsec` API,
  CLI, platforms or OpenSSL support. Not a breaking change.
- Development process only. Kernel-style tooling that reads `Assisted-by:`
  keeps working; the value is just a different token.
- Branch layout: `.provenance/` and `tools/prov.py` are shared paths that
  travel with the code they describe; `develop-provenance.yml` is
  develop-owned. A `main`-owned counterpart is an open question.

## Migration

- Existing commits: untouched, exempt by baseline, queryable via
  `legacy-map.toml`.
- Seed profiles (`claude-opus`, `claude-sonnet`, `opencode-kitch`,
  `opencode-qwen3-coder`, `opencode-pair`) are derived from the trailer
  variants in history and must be confirmed before Phase 1, because they
  become immutable on merge.
- Contributors: one command (`prov declare`) per AI-assisted session until
  adapters exist.

## Risks

- **False confidence from self-reporting.** Mitigation: `model_reported_by`,
  the Non-goals statement, and a recall drill that measures what the
  records actually deliver.
- **Contributor friction** deters occasional contributors, or makes them
  hide AI use. Mitigation: human-only commits need nothing; a guest gives
  one sentence and the maintainer carries the structure (§11); for
  maintainers, `declare` prints everything and adapters remove the manual
  step.
- **Profile sprawl** with twenty contributors. Mitigation: profiles describe
  setups, not sessions; owners retire old ones with a `status = "retired"`
  revision.
- **Confidentiality leaks by correlation** (a withheld ID used alongside
  public profiles). Withheld IDs give vendor neutrality, not secrecy; stated
  in the contributor guide.
- **Over-matching AI identity patterns** (a human called Claude). Patterns
  live in `policy.toml` and are adjusted by normal review.
- **Tool APIs change** (hooks, settings). Confined to adapters by design.
- **An agent attests its own work.** It can prepare everything, but the
  approval commit needs a signature from an allowed key. Mitigation: keys on
  hardware tokens with touch required, never in reach of the agent; allowed
  signers read from the base; the agent-environment refusal as a speed bump.
- **Signatures lost on merge.** Rebase- and squash-merge recreate commits.
  Mitigation: merge commits only; re-sign on local rebase (§4a).

## Open questions

- Should `main` carry its own `provenance` workflow (mirror of
  `develop-provenance.yml`), or is `develop` the only enforcement point?
- Disclosure of `KITCH-Coder`: keep `withheld` with an owner-resolved
  reference, or publish the model?
- Should `docs` and `tests` scopes in critical paths also require
  dissimilar review? (Currently: no — only `code` and `refactor`.)
- Substitution is fixed to `warn` (§11.6). Reintroduce `fail` once
  adapters report `api` models reliably?
- Is a per-file `files` list enough, or do we want line ranges for the
  first few sessions to measure how often AI and human edits interleave?
- OpenCode's environment marker for `attestation.agent_env` (to be verified;
  `CLAUDECODE` and `AI_AGENT` are listed today).
- `prov intake`: how much of the guest's free text can be mapped
  automatically to an existing profile, and how much stays a manual
  decision at intake?
- OpenPGP (`gpg.format = openpgp`) approval signatures in addition to SSH,
  with a keyring in the repository? SSH keys served by an OpenPGP card via
  gpg-agent already work.

## Acceptance criteria

- [ ] `.provenance/` schemas, policy and profiles present; `prov verify`
      passes on `develop` with baseline at the Phase 0 merge point.
- [ ] `tools/test_prov.py` covers every rule in §2, §4 and §6 with a passing
      and a failing case; `self-test` job blocking in CI.
- [ ] A commit with `Co-Authored-By: <AI>`, an AI `Signed-off-by:`, a
      non-canonical trailer key, a free-text `Assisted-by:` on a branch in
      this repository, a missing manifest, or a missing attestation fails
      `verify`.
- [ ] AI `code` in a critical path without a dissimilar-family reviewer
      fails; with one, passes.
- [ ] Modifying or deleting a merged profile revision, manifest or
      attestation fails.
- [ ] `prov attest` adds the sign-off without changing trees,
      author or committer; a signed approval commit by an allowed key
      passes `verify`; an unsigned approval, a key added by the change
      itself, a diff changed after approval, an unattested follow-up
      commit, or an AI author fails.
- [ ] **Recall drill:** for a chosen model, `prov query --blame` lists every
      affected commit and file and the surviving line counts, cross-checked
      by hand against `git blame` for at least three files; result and
      duration recorded in an Issue.
- [ ] `CONTRIBUTING.md` defines the trailers (Appendix A) and points to
      `.provenance/README.md`.
- [ ] A guest fork pull request with a free-text `Assisted-by:` gets a
      green, advisory `verify` with a job summary of what intake will add;
      the same trailer on a branch in this repository fails.
- [ ] `prov intake` turns a guest pull request into an in-repository
      branch that passes `verify` after `prov attest`, keeping the guest
      as author and their `Signed-off-by:`.
- [ ] A push to `develop` that contains a guest's AI-assisted commits
      without intake fails `verify`.

---

## Appendix A: proposed `CONTRIBUTING.md` section (Phase 1)

> ## AI-Assisted Development
>
> AI tools are welcome. You remain the author and are accountable for every
> line. An AI agent may commit for you, with you as author and itself as
> committer, but never adds `Signed-off-by:` or `Co-Authored-By:`.
>
> **Retyped is still assisted:** provenance follows the text, not the
> keyboard. Before each commit ask: *would these lines look like this if
> the agent had never answered?* If not, say so.
>
> ### Guest contributions (pull requests from a fork)
>
> If an AI tool helped, write one sentence in the pull request (or as a
> trailer) naming the tools, the models and what they did, e.g.
> `Assisted-by: Claude Code (Opus), review by GPT-5`, and sign off your
> commits as usual (`git commit -s`). That is all: the maintainer turns it
> into the project's provenance record when taking your pull request in.
> The provenance check on your pull request is advisory and stays green.
>
> ### Maintainers and regular contributors
>
> If AI output is part of a commit, it is recorded (RFC 0005):
>
> ```
> Assisted-by: <profile>@r<N> [analysis tools]
> AI-Scope: <docs|tests|build|ci|packaging|refactor|code>[, …]
> Provenance-Id: <id>
> ```
>
> `python3 tools/prov.py declare` writes the matching manifest under
> `.provenance/manifests/` and prints these lines. Before merge, approve the
> work in your own terminal with `python3 tools/prov.py attest --test "make
> check"`: it adds your `Signed-off-by:` and writes an approval commit
> signed with your SSH key (listed in `.provenance/allowed_signers`).
> `python3 tools/prov.py verify` runs the same check as CI. See
> `.provenance/README.md` for profiles, confidential models, signing setup,
> and the extra rules for security-critical paths.

## Appendix B: initial recall drill on legacy history

Run during Phase 0 on `develop` (`prov query --include-legacy`), before any
manifest exists:

- 206 legacy commits mapped to a model; 41 unmapped (36 `Claude`,
  5 `OpenCode:`).
- `--family kitch --blame`: 15 commits, 2,153 lines still attributed at
  `HEAD` (whole-commit attribution, so an upper bound).

This is the baseline the manifests must improve on: file-level scope,
every model known, no unmapped entries.

## Appendix C: contributor kit (informative)

> Informative, not normative. The kit is an adapter in the sense of §7: it
> may be rewritten whenever the harness changes. The normative parts are
> the profile format (§3), the manifest (§4) and the guest rules (§11).

### C.1 Purpose

A contributor who works with an AI harness and has little C experience
cannot judge the code the agent produces, yet as its author (§2) is
accountable for it. The kit addresses that quality gap first. Provenance
data is a by-product of using it, so the honest path is also the cheapest
one (§11.1).

### C.2 Contents

| Part | Role |
| --- | --- |
| Agent definitions: implementer and reviewer, models pinned, reviewer from a different family than the implementer | Maps directly onto profile roles (§3, §7); gives the contributor an independent review they cannot perform themselves |
| Project rules file | Build and test commands, conventions, the `critical.paths` with the instruction to stop and warn before changing them |
| Pre-PR check | Runs `make check` (and sanitizer builds where available), keeps the log locally |
| PR text generator | Produces the pull request description from the session: the one-sentence statement (§11.2), scope, changed files, test result, and a marker if a critical path was touched |
| PR template | Fixed headings for the above, so the maintainer's intake (§11.3) starts from structured input |

Two placement constraints follow from the tree-separation policy:

- **One rules file.** `.claude/CLAUDE.md` already holds the agent rules on
  `develop`. A second file (for example a root `AGENTS.md`, which would be
  a shared path and travel to `main`) must not duplicate it: one file is
  the source, the other only points to it.
- **PR template on `main`.** GitHub reads `.github/PULL_REQUEST_TEMPLATE.md`
  from the default branch, which is `main`. The guest statement belongs in
  that file, changed on `main`.

### C.3 The kit is itself a profile

The kit's setup is described once, in this repository, as a maintained
profile (for example `opencode-pair@r1`). A contributor who uses the kit
unchanged references that profile in the pull request text; at intake the
maintainer reuses it and creates no new profile (§11.3, step 2). A
contributor who deviates from the kit gives the free-text statement of
§11.2 instead. Whether the contributor really ran the kit's models remains
self-reported (`config` or `manual`, §4).

### C.4 Limits and benefits

- **Self-reporting.** The kit cannot prove which model ran locally. It
  makes accurate reporting easy; it does not verify it.
- **Critical paths.** The kit cannot make up for missing C experience in
  attack-surface code. It flags such changes early; the maintainer's intake
  review (§6, §11.3) is the control, and is stricter for such pull requests
  than for `docs` or `tests`.
- **Dissimilar review built in.** Because the kit's reviewer is from a
  different model family than its implementer, a kit session already
  satisfies G7 for critical paths, and the maintainer's intake shrinks
  accordingly.
- **Access.** A kit that needs a commercial API excludes some contributors.
  A variant with locally runnable open-weights models is needed, with its
  own profile and an honest note on reduced review quality.
- **Verification of harness hooks.** Hook and plugin points of the harness
  must be checked against its current documentation before the kit relies
  on them (§7). Nothing in this appendix fixes them.

### C.5 Staged introduction

1. After §11 is implemented: the project rules file and the guest
   statement in the PR template. No tooling.
2. Phase 3: agent definitions, pre-PR check, PR text generator, kit
   profile.
3. Observe at least a few guest pull requests before extending the kit. If
   guests do not adopt step 1, more tooling will not help.

### C.6 Reuse

The structure is deliberately not racoon-specific: agent roles, project
rules file, pre-PR checks and a generated pull request text. The same
layout can serve as a template for in-house harness setups; only the
profile content, critical-path list and checks change.
