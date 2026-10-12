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
Signed-off-by: human                              + human review statement
```

The commit message carries three short, stable trailers. Everything
detailed lives in versioned files in the tree, keyed by IDs rather than
commit SHAs, so it survives every Git operation that rewrites SHAs.

### 2. Trailers

| Trailer | Cardinality | Value |
| --- | --- | --- |
| `Assisted-by:` | one per profile used | `<profile-id>@r<N> [tool …]` |
| `AI-Scope:` | exactly one if assisted | comma list from `docs, tests, build, ci, packaging, refactor, code` |
| `Provenance-Id:` | exactly one if assisted | `YYYYMMDDTHHMMSSZ-<8 hex>` |
| `Signed-off-by:` | ≥ 1 human if assisted | unchanged DCO meaning |

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
  `verify` warns (or fails, per policy); `config`/`manual` mismatches fail —
  change the profile instead.
- **`human_review.statement = "pending"`** is what an agent writes when it
  runs `declare`. `verify` fails on `pending`, so a record prepared by an AI
  cannot merge until the accountable human changes it and signs off (G2).
- Manifests are **immutable** once merged, like profiles.
- Schema: `.provenance/schema/manifest-v1.schema.json` (JSON Schema
  Draft 2020-12). `schema_version` is frozen per major version, the same
  discipline as `RACOONCTL_STATUS_SCHEMA_VERSION`: a breaking change is a
  new `manifest-v2` file, and v1 records stay valid forever.

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
- **AI-assisted commits need a human `Signed-off-by:`.**

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
  `files` ⊆ files changed by the session's commits, `pending` review,
  dissimilarity, withheld-in-critical.
- `prov declare --contrib <id>@r<N>:<role>[=file,…] … --scope …` — writes
  and stages a manifest, prints trailers. `--statement pending` for agents.
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

- `self-test` — `python3 -m unittest tools/test_prov.py`: 23 tests in
  throw-away repositories covering every pass/fail rule. Always blocking: a
  broken checker must never silently pass everything.
- `verify` — `prov verify` over the PR's merge-base..head or the push range.
  Non-blocking (`continue-on-error`) in Phase 0, blocking from Phase 1.

Merges into `develop` use merge commits or rebase-merge. GitHub's
squash-merge concatenates commit messages and can mangle trailers; it should
be disabled for `develop` in the repository settings once `verify` blocks.

### 10. Rollout

| Phase | Content | Exit criterion |
| --- | --- | --- |
| 0 | RFC, schemas, policy, seed profiles, `prov`, CI (verify non-blocking) | self-tests green; recall drill runs on real history |
| 1 | `CONTRIBUTING.md` section (Appendix A); `verify` blocking; remove `.claude` rewrite hook; disable squash-merge | one month of maintainer commits passing |
| 2 | Claude Code adapter | `declare` output produced without manual steps |
| 3 | OpenCode adapter; harness-config cross-check | multi-agent session recorded with roles |
| 4 | First formal recall drill (Acceptance criteria) before inviting outside contributors | drill report filed as an Issue |

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
- **Contributor friction** deters occasional contributors. Mitigation:
  human-only commits need nothing; `declare` prints everything; adapters
  remove the manual step.
- **Profile sprawl** with twenty contributors. Mitigation: profiles describe
  setups, not sessions; owners retire old ones with a `status = "retired"`
  revision.
- **Confidentiality leaks by correlation** (a withheld ID used alongside
  public profiles). Withheld IDs give vendor neutrality, not secrecy; stated
  in the contributor guide.
- **Over-matching AI identity patterns** (a human called Claude). Patterns
  live in `policy.toml` and are adjusted by normal review.
- **Tool APIs change** (hooks, settings). Confined to adapters by design.

## Open questions

- Should `main` carry its own `provenance` workflow (mirror of
  `develop-provenance.yml`), or is `develop` the only enforcement point?
- Disclosure of `KITCH-Coder`: keep `withheld` with an owner-resolved
  reference, or publish the model?
- Should `docs` and `tests` scopes in critical paths also require
  dissimilar review? (Currently: no — only `code` and `refactor`.)
- Substitution: keep `warn`, or `fail` once adapters report `api` models
  reliably?
- Is a per-file `files` list enough, or do we want line ranges for the
  first few sessions to measure how often AI and human edits interleave?

## Acceptance criteria

- [ ] `.provenance/` schemas, policy and profiles present; `prov verify`
      passes on `develop` with baseline at the Phase 0 merge point.
- [ ] `tools/test_prov.py` covers every rule in §2, §4 and §6 with a passing
      and a failing case; `self-test` job blocking in CI.
- [ ] A commit with `Co-Authored-By: <AI>`, an AI `Signed-off-by:`, a
      non-canonical trailer key, a free-text `Assisted-by:`, a missing
      manifest, or a `pending` review fails `verify`.
- [ ] AI `code` in a critical path without a dissimilar-family reviewer
      fails; with one, passes.
- [ ] Modifying or deleting a merged profile revision or manifest fails.
- [ ] **Recall drill:** for a chosen model, `prov query --blame` lists every
      affected commit and file and the surviving line counts, cross-checked
      by hand against `git blame` for at least three files; result and
      duration recorded in an Issue.
- [ ] `CONTRIBUTING.md` defines the trailers (Appendix A) and points to
      `.provenance/README.md`.

---

## Appendix A: proposed `CONTRIBUTING.md` section (Phase 1)

> ## AI-Assisted Development
>
> AI tools are welcome. You remain the author and are accountable for every
> line: review, test, and sign off your work as usual. AI agents never add
> `Signed-off-by:` or `Co-Authored-By:`.
>
> If AI output is part of your commit, record it (RFC 0005):
>
> ```
> Assisted-by: <profile>@r<N> [analysis tools]
> AI-Scope: <docs|tests|build|ci|packaging|refactor|code>[, …]
> Provenance-Id: <id>
> Signed-off-by: Your Name <you@example.org>
> ```
>
> `python3 tools/prov.py declare` writes the matching manifest under
> `.provenance/manifests/` and prints these lines; `python3 tools/prov.py
> verify` runs the same check as CI. See `.provenance/README.md` for
> profiles, confidential models, and the extra rules for security-critical
> paths.

## Appendix B: initial recall drill on legacy history

Run during Phase 0 on `develop` (`prov query --include-legacy`), before any
manifest exists:

- 206 legacy commits mapped to a model; 41 unmapped (36 `Claude`,
  5 `OpenCode:`).
- `--family kitch --blame`: 15 commits, 2,153 lines still attributed at
  `HEAD` (whole-commit attribution, so an upper bound).

This is the baseline the manifests must improve on: file-level scope,
every model known, no unmapped entries.
