# AI provenance in racoon-ipsec-tools: a guide for newcomers and QA

Status: draft by an AI agent (a self-assessment, input for QA, not QA).
Basis: `develop` at c7b669a plus the open PR #192. Date: 2026-11-24.
Everything marked "run" was executed while preparing this guide; everything
marked "from code" was read but not run; "unchecked" means neither.

This guide has three parts:

1. a one-page summary by project class (public, internal, confidential);
2. the big picture: which part of the tooling answers which question;
3. a step-by-step walk-through that QA can follow to assess the tooling.

Tags used in the tables:

| Tag | Meaning |
| --- | --- |
| **E** | enforced by the tooling: a violation makes `prov verify` fail or warn |
| **C** | convention: written down, not checked by any tool |
| **N** | not supported yet |

---

## 1. Summary by project class

The tooling has no field called "project class". A class is the combination
of three things: who can read the repository, which profiles it uses, and its
`policy.toml`. Three decisions drive everything else:

- **disclosure** (one flag per profile role: `public` or `withheld`),
- **policy** (one file per repository: critical paths, allowed scopes, rules),
- **evidence handling** (a human procedure for the capture proxy log).

Decide the class **before the first merge**: manifests, profiles and
attestations are immutable once merged (E), and history is not rewritten.
Published names cannot be taken back.

| Question | Public project | Internal project | Confidential project |
| --- | --- | --- | --- |
| Who can read the repository, now or later? | anyone | the company only | the company plus outsiders (customers, suppliers, auditors), or it may be shared later |
| What may the history say about models and providers? | real deployment names and ids | real ids, inside the company only | nothing that names a model, vendor or provider; neutral references only |
| Profile `disclosure` | `public` (E) | `public` (E). It means "public to everyone who can read this repository" | `withheld` (E) |
| `model_id` in the profile | the real id the gateway reports (C) | the real id (C) | a neutral reference, for example `x-acme-coder-2026a` (C: the scheme is not checked) |
| `model_family` in the profile | vendor family, lowercase, for example `alibaba-qwen` (C); compared as a literal string (E) | same | same. The family is never hidden by the tool: it is always in the file (E). Decide once whether it may be published |
| May the model write critical paths? | yes, with a dissimilar-family reviewer for `code` and `refactor` (E) and a human attestation (E) | same as public | **no**: a withheld model that writes a critical file fails `verify` (E) |
| Capture proxy log | stays outside the repository (C). Its digest, the observed deployments and the endpoints go into the manifest (E) | same. Internal host names in the manifest are acceptable inside the company | do **not** run `declare --evidence` (N: nothing removes names or endpoints). Keep the log private and declare by hand |
| Highest evidence level reachable | `router` or `api` through the capture proxy | same | `manual` today |
| Human approval | signed attestation, always (E) | same | same |
| Examples | racoon-ipsec-tools itself | a company tooling repository | code delivered to a customer or shared with a supplier |

How to choose, in one question: *if this repository were read by someone
outside our organisation tomorrow, would the model name or provider matter?*
No: public or internal. Yes: confidential.

---

## 2. The big picture

### 2.1 What provenance is for, and what it is not

The recall question: **which model produced code that is still in the tree,
and where?** When a model turns out to have a systematic fault, the project
must be able to list every commit and file it touched
(`.provenance/PRINCIPLES.md`, RFC 0005 §Motivation).

It does **not** verify that code is correct (principle 7), and it does not
prove which model ran (principle 8): it records what was declared and what
tools observed, and says how strong each statement is (principle 12).

### 2.2 The five layers

```
RULES    .provenance/policy.toml, schema/*.json, allowed_signers
         read from the BASE of a change: a change cannot loosen its own rules

SETUPS   .provenance/profiles/<id>/r<N>.toml      immutable once merged
         harness, owner, and per role: family, model_id, disclosure

SESSIONS commit trailers  Assisted-by: <id>@r<N>
                          AI-Scope: code, tests
                          Provenance-Id: <time>-<8 hex>
              |                      \
              +--> .provenance/manifests/<year>/<Provenance-Id>.json
                   what each role wrote (file list), how the model was
                   reported (manual | config | router | api)
                   optional: observed deployments + digest of the capture log
                                           ^
                                           | private, local, not committed
                                    capture proxy log (provcap.jsonl)

APPROVAL .provenance/attestations/<year>/<Provenance-Id>/<time>.json
         human sign-off + signed approval commit, bound to the diffs by
         `git patch-id --stable`; key listed in allowed_signers

CHECKS   prov verify (CI, blocking)   prov query (recall)   self-tests
```

### 2.3 The five concerns of "G6", separated

RFC 0005 goal G6 is only the first row. The others are separate mechanisms
that happen to meet in the profile.

| # | Concern | Mechanism | Where it lives | Enforced? |
| --- | --- | --- | --- | --- |
| 1 | Do not publish internal model or provider information | `disclosure = "withheld"`, neutral `model_id`, private mapping kept by the profile owner | profile (flag); owner's own systems (mapping) | the flag is E; the mapping and the id scheme are C |
| 2 | Who may touch critical paths | `[critical] paths`, `forbid_withheld_in_critical`, dissimilar-family review, human attestation | `policy.toml` | E |
| 3 | Public versus internal versus confidential projects | the combination of repository visibility, profile set and `policy.toml` | the repository | C (no class field) |
| 4 | Identifier scheme | see 2.4 | several | partly E (patterns), partly C |
| 5 | Proxy log management | capture proxy, `declare --evidence`, log kept outside git | local machine; manifest holds digest and observations | digest and observations E; handling C |

Why withheld models are barred from critical paths: nobody outside the owning
organisation could act on a recall of a model they cannot name (RFC §6).

### 2.4 The identifiers

| Identifier | Example | Minted by | Immutable | Checked by |
| --- | --- | --- | --- | --- |
| Profile id | `kitch-qwen3-8` | profile owner | yes (directory name) | schema pattern, must equal the directory |
| Profile revision | `r1` | profile owner | yes. Any change is `r<N+1>` | file name must equal `revision` |
| `model_family` | `alibaba-qwen` | profile owner | with the revision | schema pattern; **compared as a literal string** for G7 and for `query --family` |
| `model_id` | `hosted_vllm/Qwen3.8-Flash-Next-FP8` or `x-acme-coder-2026a` | profile owner | with the revision | matched exactly (case-insensitive) against observed deployments |
| Route alias | `Qwen3.8-Flash-Next-HighReasoning` | the gateway operator | no | not a model (principle 8); recorded as the requested alias only |
| Deployment name | header `x-litellm-model-name`, body `router_model_name` | the gateway | no | recorded verbatim by the capture reader; header and body spellings can differ by a prefix (#177) |
| Provenance-Id | `20261120T065634Z-bd9beb9d` | `prov declare` | yes | exactly one per assisted commit; links trailer, manifest, attestation |
| patch-id | `git patch-id --stable` of a commit | git | derived | attestation binds approval to it; a changed diff fails `verify` |

### 2.5 Who decides what

| Role | Decides or does | Never does |
| --- | --- | --- |
| Maintainer / profile owner | profiles, policy, the class of the project, disclosure | |
| AI agent | writes code, runs `declare` with `--statement pending`, commits with trailers | adds `Signed-off-by`, attests, signs, picks its own profile (principle 11) |
| Human accountable author | author of every commit, reviews, runs `prov attest` in their own terminal with a signing key | |
| CI | runs self-tests and `verify` | decides correctness |
| QA | assesses the whole record, repeats a sample of the checks | |

### 2.6 One session, start to finish

1. The human names the profile and role. The agent runs
   `prov declare --statement pending --contrib <id>@r<N>:<role>=<files> --scope <scopes>`.
   This writes and stages the manifest and prints the three trailers.
2. Every commit of the session carries the trailers. The human is author, the
   agent is committer (`agent@agents.invalid` or an app bot).
3. The agent pushes its own branch and opens a pull request. It never pushes
   to `develop` or `main`.
4. The human runs `prov attest --test "<command>"`. It runs the tests, adds the
   human's `Signed-off-by` to each commit (message-only rewrite) and writes a
   signed approval commit with the patch-ids.
5. CI runs `prov verify`. The merge is a merge commit.
6. Later: `prov query` answers recall questions.

---

## 3. QA walk-through

Plan about a day. Record every step in the worksheet in section 5.

### Step 0: set up

- Python >= 3.11, git >= 2.34, `ssh-keygen`, and `pip install jsonschema`.
- `git clone https://github.com/rdratlos/racoon-ipsec-tools && cd racoon-ipsec-tools && git checkout develop`
- Read, in this order: `.provenance/PRINCIPLES.md`, `.provenance/README.md`,
  `.provenance/policy.toml`, RFC 0005 (`docs/rfcs/0005-provpaws-ai-provenance.md`
  on `main`, sections 2 to 6 and the acceptance criteria).

### Step 1: does the checker check itself?

```sh
python3 -m unittest tools/test_prov.py
```

Expected: `OK` (88 tests at c7b669a). The tests run in throw-away
repositories and cover each rule with a passing and a failing case, including
signed approval commits with throw-away keys. Note what it needs: if
`ssh-keygen` is missing, most tests error out. That is an environment problem,
not a rule failure. Principle 15: tests derive from requirements, not from the
implementation.

### Step 2: follow one commit through the record

Pick a merged pull request from `git log --first-parent --merges`.

```sh
git log -1 --format=%B <commit>                 # trailers
ls .provenance/manifests/2026 | grep <Provenance-Id>
cat .provenance/manifests/2026/<Provenance-Id>.json
cat .provenance/profiles/<id>/r<N>.toml          # the profile named in the trailer
cat .provenance/attestations/2026/<Provenance-Id>/*.json
```

Check each link:

| Question | Where to look |
| --- | --- |
| Does the trailer name an existing profile revision? | `profiles/<id>/r<N>.toml` |
| Does the manifest list only files the session's commits changed? | `files` against `git show --stat` |
| Is the model in the manifest the one the profile names for that role? | `model` against the profile role |
| How was the model reported? | `model_reported_by`: `manual` (declared), `config` (read from harness config), `router` (gateway evidence), `api` (provider named it) |
| Who approved, and how? | attestation `reviewer`, `statement`, `tests`; approval commit signature |
| Is the approval bound to this diff? | attestation `patch_id` equals `git show <sha> \| git patch-id --stable` (use the commit as it is on `develop`) |

Reading hint: the manifest's `human_review.statement` stays `pending` in most
manifests on purpose. The approval is the attestation, never an edit of the
manifest.

### Step 3: replay what CI does

```sh
m=<merge commit of a pull request>
python3 tools/prov.py verify --range "$(git merge-base $m^1 $m^2)..$m^2"
```

Expected: `0 failure(s)`. A range that starts at the old baseline commit
fails with "no signers at the base": the first range that adds the signers
cannot be verified by rules that do not exist yet. That is the bootstrap case,
not a defect.

### Step 4: break it on purpose

Work in a scratch branch that is never pushed. Agent commits use author = you,
committer = the agent:

```sh
git checkout -b qa/break origin/develop
export GIT_COMMITTER_NAME="Claude Code" GIT_COMMITTER_EMAIL=agent@agents.invalid
```

For each exercise make the change, commit, then run
`python3 tools/prov.py verify --range origin/develop..HEAD`. Ignore the two
failures that every unattested AI commit shows ("without a human
Signed-off-by", "not covered by a valid attestation"). The messages below
were run on a scratch repository with the real profiles.

| # | Exercise | Expected message |
| --- | --- | --- |
| E1 | Declare `opencode-kitch@r1:implementer` (a withheld profile) with scope `code` for `src/racoon/isakmp.c`, then commit | `withheld model wrote critical file(s) src/racoon/isakmp.c`; also `requires a 'reviewer' contribution from a model family other than kitch` |
| E2 | Declare `claude-opus@r1:implementer`, scope `code`, same file | `AI output in critical paths (scope code) requires a 'reviewer' contribution from a model family other than anthropic-claude` |
| E3 | Edit `.provenance/profiles/claude-opus/r1.toml` | `modified (create a new revision instead)` |
| E4 | Commit with the trailer `Assisted-by: Claude Opus 5` | `first token must be a profile reference <id>@r<N>`; also missing `AI-Scope` and `Provenance-Id` |
| E5 | Commit with `Co-Authored-By: Claude <noreply@anthropic.com>` | `names an AI; use Assisted-by (RFC 0005) -- only humans sign off or co-author` |
| E6 | Change a file with the agent as committer and no trailers | `committed by an agent (...) but has no Assisted-by trailer -- declare it` |

More failure cases are covered by tests, not run here: a diff changed after
attestation (`test_diff_changed_after_attestation_fails`), an unsigned
approval (`test_unsigned_approval_fails`), a change that adds its own signer
key (`test_change_cannot_admit_its_own_key`), an AI author
(`test_ai_author_fails`), a rule loosened inside the range
(`test_policy_loosened_inside_range_is_not_applied`). QA should pick two and
repeat them by hand.

Map each exercise to an RFC acceptance criterion (RFC 0005, section
"Acceptance criteria") and note any criterion no exercise reaches.

### Step 5: the approval chain

1. `.provenance/allowed_signers` lists who may sign approvals. It is read from
   the base of a change, so a change cannot add its own key.
2. `git log --show-signature -1 <approval commit>` shows who signed. The
   signer must be listed and must equal the attestation's `reviewer`.
3. `prov attest` refuses to run when an agent marker is set (`CLAUDECODE`,
   `AI_AGENT`, `OPENCODE`). That is a speed bump; the control is that the key
   is out of the agent's reach (principle 14). Ask the maintainer how the key
   is held (hardware token with touch is the intended setup).
4. Check the test evidence: what `tests.command` did the human run? On
   changes that touch only provenance tooling it is the checker's own test
   suite. State in your report what the approval evidences for each change.

### Step 6: recall drill

```sh
python3 tools/prov.py query --family anthropic-claude --blame --include-legacy
python3 tools/prov.py query --profile claude-opus --blame
python3 tools/prov.py query --model 'Qwen3' --blame --include-legacy
```

Pick three files from the output and compare the surviving line counts with
`git blame` by hand. Record the duration. `--include-legacy` maps free-text
trailers from before the baseline; values it cannot map are reported as
unmapped and are not guessed. RFC acceptance criterion: the drill and the
manual cross-check are recorded in an Issue.

### Step 7: evidence from the capture proxy

What it is: `tools/provcap-proxy.py` sits between the harness and the model
endpoint. It logs one line per request: the requested model, the model named in
the response, deployment headers or body fields, the status, and the endpoint
reached. It does not log prompts unless started with `--log-bodies`.

What `prov declare --evidence capture-log:FILE` does with the log:

- reads it with the same reader `verify` uses;
- if a gateway signal is present, sets `model_reported_by = router` itself;
- writes `observed[]` (id, deployment, request counts) into the manifest
  (schema 2.0), and `session.capture` with the digest of the log file, request
  count, time window and endpoints.

QA checks:

1. `sha256sum <log>` equals `session.capture.log_digest` (without the prefix).
2. The count of non-skipped requests in the log equals `requests`.
3. Every observed deployment is explained by the profile
   (`verify` warns "match no disclosed model in this profile").
4. Empty log: nothing reached the proxy. Every request that reaches it is
   logged, including errors.
5. Where the log lives: it must not be inside the repository.

What the evidence does **not** prove: which model ran. A gateway reports a
deployment name; the record says "reported by a gateway", nothing stronger
(principle 8).

### Step 8: assess a project class

For the project under review, fill the class checklist:

| Check | How |
| --- | --- |
| Who can read the repository, and may that change? | repository settings |
| Does each profile's `disclosure` match the class table in section 1? | `grep disclosure .provenance/profiles/*/r*.toml` |
| For withheld profiles: are `model_id` values neutral references, and where is the mapping kept? | profile owner |
| Do any manifests of a withheld profile contain `observed` or `endpoints`? | `grep -l '"observed"\|"endpoints"' .provenance/manifests/*/*.json` |
| Are capture logs excluded from git? | `git check-ignore -v provcap.jsonl` |
| Which paths are critical, and does the list match the attack surface? | `[critical] paths` in `policy.toml` |
| Which profiles have written critical files? | `prov query --profile <id> --blame` |
| Is the family string the same for models of one real family, and different for different ones? | profile owner, against the operator's statement |

### Step 9: what not to conclude

- Passing `verify` means the record is consistent and approved. It does not
  mean the code is correct.
- A `router` or `api` entry is evidence of what a gateway or provider
  reported, not proof of the backend.
- The absence of a manifest is not proof of human authorship: undeclared use
  is not detected (RFC non-goals).

---

## 4. Known limits (facts, as observed)

| # | Fact | How known |
| --- | --- | --- |
| 1 | Family is compared as a literal string, so a different spelling for the same real family counts as "dissimilar" | code (`verify_session`); messages in E1 and E2 |
| 2 | With a withheld profile, `declare --evidence` still writes real deployment names into `observed[]` and the gateway origin into `session.capture.endpoints` | run on a scratch repository with a mock log |
| 3 | `.gitignore` has no entry for `provcap.jsonl` or `.provpaws/`, although `doc/dev/agent-rules.md` says they are ignored | `grep` on `develop` |
| 4 | `status = "retired"` in a profile is documentation; no check uses it | `grep` in `tools/prov.py` |
| 5 | In a session with several contributions, every contribution receives all observations of the log | code (`cmd_declare`), not run |
| 6 | Header and body deployment names can differ by a `hosted_vllm/` prefix; the profile must pick one spelling | #177, comments |
| 7 | Reviewer roles and critical-path files do not occur in the 33 manifests on `develop`; the dissimilar-review rule is covered by tests only | manifests read |
| 8 | Attestation test evidence so far is the checker's own test suite | attestations read |

---

## 5. Worksheet

| Step | What was checked | Expected | Observed | Pass / Fail / Unable | Evidence (command output, file) |
| --- | --- | --- | --- | --- | --- |
| 1 | self-tests | OK | | | |
| 2 | one commit traced | all links resolve | | | |
| 3 | PR replay | 0 failures | | | |
| 4 | E1 to E6 | messages as listed | | | |
| 5 | approval chain | signer in allowed_signers | | | |
| 6 | recall drill, 3 files | counts match `git blame` | | | |
| 7 | capture digest | digest matches | | | |
| 8 | class checklist | per section 1 | | | |

---

## 6. Glossary

| Term | Meaning |
| --- | --- |
| Profile | a named setup: harness, owner, and one model per role |
| Role | implementer, reviewer or orchestrator within a profile |
| Manifest | per-session record of what each role wrote |
| Attestation | the human's signed approval, bound to diffs by patch-id |
| Baseline | the commit before which provenance rules are not applied |
| Critical path | attack-surface or privilege-boundary code listed in `policy.toml` |
| G7 / dissimilar review | AI code in a critical path needs a reviewer from another model family |
| Gateway / router | an intermediary between harness and model that may alias or switch deployments |
| Route alias | the name a harness requests; not a model |
| Deployment | what a gateway reports as having served the request |
| Capture proxy | local pass-through proxy that records response metadata |
| Withheld | the profile's model id is a neutral reference only its owner resolves |
