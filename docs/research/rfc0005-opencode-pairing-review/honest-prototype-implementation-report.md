# Honest Prototype Implementation Report — RFC 0005 OpenCode Pairing Provenance

Status: honest self-assessment for the first QA review. Date: 2026-10-23.
This report states what the prototype actually proves, what it merely observes,
and what it does not prove at all. It is deliberately pessimistic about trust:
a claim is graded by the weakest source that supports it.

## 1. What this prototype is

A capture layer for AI-assisted pair programming through a model router whose
public label (`KITCH-Coder`) does **not** identify the backend that answered a
request. The prototype's job is to record the strongest honest evidence the
runtime can produce, bind it to the canonical `prov declare` manifest, and leave
everything unprovable explicitly unknown. It is a **prototype** for a multi-month
observation period, not a production adapter.

The one finding that drives the whole design: the configured/route label and the
actual serving deployment diverge. In the first real session the label
`KITCH-Coder` was served by at least three different deployments
(`hosted_vllm/Qwen3.8-Flash-Next-FP8`, `Qwen3.8-Flash-Next-NoReasoning`,
`Qwen3.8-Flash-Next`). Any provenance record that equated the route label with a
model would be false.

## 2. Short design description

Two observation sources feed one digest-bound log, which feeds `prov declare`:

```
OpenCode (configured model)
        │  plugin: .opencode/plugin/provpaws-capture.ts
        ▼
 harness-log observation  ──┐
                            │   prov declare --evidence ...
loopback capture proxy      │        │
tools/provcap-proxy.py ─────┘        ▼
 (model + deployment +        schema 2.0 manifest
  endpoint on the wire)        session.capture{...}
        │                            │
        ▼                            ▼
 provcap.jsonl (git-ignored)   signed commit + human attestation
```

- **Plugin** captures what OpenCode *knows*: the configured model id for the
  session. This is config-relayed, nothing more.
- **Capture proxy** is a loopback HTTP forward proxy placed in front of the
  router. It changes nothing on the wire; it records, per request, the response
  `model`, the gateway deployment header, the serving `endpoint` (the origin the
  upstream hop actually reached — an environment proxy may rewrite it, so the
  proxy records what it reached, not what was configured), and the status.
- **`prov declare`** merges both, computes `session.capture.log_digest` (sha256
  over sorted per-file digests), and writes the additive v2 manifest. It never
  fills a field the log did not record.
- **Honesty rules** are enforced by `declare`/`verify`, not by convention:
  a `router` report without evidence fails; a requested-only observation fails;
  absent endpoints stay absent.

Why a proxy and not only a plugin: OpenCode 1.19.3 receives the returned model id
and response headers but drops them when building its step record, and no plugin
hook sees them (verified in the Phase 3 sibling investigation). A capture proxy in
front of the router, or the router's own logs, is the only way to see which
deployment answered.

## 3. Extended manifest format (schema 2.0, additive)

Additions over v1, all optional so v1 manifests stay valid:

- `model_reported_by` gains **`router`** (a gateway answered; the id is the
  router's label or deployment name; only deployment headers say what answered).
  Existing values retained: `api`, `config`, `manual`.
- `contributions[].observed[]` — model identities a capture/harness log saw:
  - `id` — model id seen on the wire (response body, header, or harness log).
  - `deployment` — deployment name/id from a router header, when a gateway sat in
    between.
  - `source` — `capture-proxy` | `harness-log`.
  - `requests` — observation count.
- `session.capture` — binding to the private observation log:
  - `log_digest` — sha256 over the sorted per-file evidence digests.
  - `requests` — total captured requests.
  - `window` — first/last entry timestamp the proxy wrote.
  - `endpoints` — deduplicated origins that served responses; absent when the
    proxy never reached an origin (connection failure / older proxy build) — then
    `declare` records nothing, never a guess.

A route label is never placed in a field that asserts a concrete backend model;
the label lives in `id`, the real deployment lives in `deployment`/`observed`.

## 4. Provenance summary a QA reviewer can read

For any manifest, read it as three separate questions:

1. **Who is accountable?** `human_review.reviewer` + a signed human attestation
   (SSH key in `.provenance/allowed_signers`). An agent never signs or attests;
   `prov attest` refuses in an agent session.
2. **What is claimed vs what is observed?** `contributions[].model` +
   `model_reported_by` is the *claim* and its basis; `observed[]` is *raw
   observation*; `session.capture` links to the private log via a digest.
3. **How strong is each identity statement?** Graded by `model_reported_by` and
   `observed[].source` using the three classes below. The record's overall trust
   equals the **weakest** source that supports the claim being relied on.

The manifest is a claim about a **declared setup**, corroborated by observations.
It is not proof of which model generated a given line, and the digest does not
prove the log is complete or truthful — only that these bytes hashed to it.

## 5. Three-class self-assessment per evidence

Trust classes used (aligned with the schema's `model_reported_by` and
`observed[].source`):

- **C1 — Verified**: supported by a documented, trusted verification mechanism
  (a signature a trusted key made over the fact).
- **C2 — API/Router-observed**: a value seen on the wire from the provider or a
  gateway (response body `model`, deployment header, served endpoint).
- **C3 — Config/Declared**: relayed by configuration or by the harness telling
  the model its own id; or a value a human/agent typed.

| Evidence in the manifest | Source | Class | What it does / does not prove |
| --- | --- | --- | --- |
| Human reviewer identity | SSH signature over attestation, key in `allowed_signers`, checked by `prov verify` | **C1** | Proves a trusted human key approved this manifest/diff. Proves nothing about the backend model. |
| Manifest integrity / diff binding | `prov verify` re-hashes manifest vs commit diff; rebase keeps attestation but needs resign | **C1** | Proves the record was not silently edited after approval. |
| `model_reported_by = "api"` on an observation | response body `model` captured by `provcap-proxy.py` | **C2** | The provider/gateway *returned* this id. Not cryptographically verified; the router can still substitute. |
| `observed[].deployment` (gateway header) | router deployment header seen by the proxy | **C2** | Which deployment the gateway reported serving. Depends on the gateway telling the truth. |
| `session.capture.endpoints` | origin the proxy's upstream hop reached (`resp.geturl()`) | **C2** | Which origin answered. A rewritten env-proxy path is recorded as reached, not as configured. |
| `session.capture.log_digest` + `requests` + `window` | sha256 over the sorted per-file evidence | **C2** | Binds the manifest to specific captured bytes. A relationship, **not** proof of completeness/truthfulness of the log. |
| `model_reported_by = "router"` label (`KITCH-Coder`) | gateway label | **C2→C3** | A router label only, **not** a model/family. Downgraded toward C3 the more it is read as an identity; must never be read as backend identity. |
| `model_reported_by = "config"` / OpenCode configured model | plugin harness-log, i.e. OpenCode's configured id relayed to the model | **C3** | Only proves the setup named this model. Explicitly not evidence of what answered. |
| `model_reported_by = "manual"` | typed value | **C3** | Declared, unverified. |
| `contributions[].files` (file attribution) | correlated session diff to changed files | **C3** | File-level only. **No** line-level attribution; reads ≠ contribution; multi-model not collapsed but not resolved to lines either. |
| Verified backend identity | — | **absent** | Deliberately empty: no trusted source asserts the backend, so it stays unknown rather than guessed. |

Reading rule for QA: if a downstream decision depends on *which backend answered*,
only C2 wire observations speak to it and they are self-reported by the gateway;
C1 never certifies a backend. If a decision depends on *who approved the record*,
that is the C1 layer (human signature + verify), independent of model identity.

## 6. Findings on routing / proxying / reporting

- The route label is stable and shared; the backend deployment is not. One label
  mapped to several real deployments within a single session.
- OpenCode does not expose the returned model id or gateway headers to plugins
  (1.19.3), so plugin-only capture is capped at config trust (C3).
- The capture proxy reliably recovers C2 evidence: response `model`, deployment
  header, and the reached endpoint. This is the difference between "configured to
  use X" and "Y answered".
- The environment proxy rewrites the upstream path; recording `resp.geturl()`
  (what was reached) instead of the configured `--upstream` is what keeps the
  endpoint honest.
- Substitution policy stays non-blocking by design: a router substitution
  **warns**, matching the existing RFC policy, because the router legitimately
  does not pre-announce backends.

## 7. What this prototype does NOT prove (stated plainly)

- It never proves the true backend model cryptographically; there is no such
  source, so `verified` is intentionally empty.
- The digest proves a hash relationship, not log completeness or truthfulness.
- Attribution is file-level; no line-level or human-vs-agent split within a file
  is claimed.
- Tests run against fixtures modeling the router limitation, not the corporate
  router (a task requirement), so live retry/fallback/subagent correlation is
  structurally supported but not exercised.
- Secret redaction is asserted (only response metadata logged) but not yet backed
  by a tested scrubber.
- A `git rebase` silently breaks the manifest↔commit SHA binding (see §9).
- Nothing is pushed yet; branch/SHA state is being reconciled separately.

## 8. Observed weakness: rebase silently orphans the manifest SHA binding

Found while reconciling branches after a `git rebase --gpg-sign` of the feature
branch onto `develop` (and the docs branch onto `main`). The branch hygiene and
the SSH re-signing are correct — every feature commit verifies as `G`, the old
duplicate commits are now unreferenced, `develop`/`main` are proper parents.
But the rebase exposed a real gap:

- Each manifest is named `...-<sha>`, where `<sha>` is the **short SHA of the
  commit it was declared for**. A rebase rewrites those commits, so the embedded
  SHA no longer exists on the branch. Observed on this branch: `1639e641` and
  `e0b90554` are both **gone**, rewritten to `49c74a3` / `fce37ab`.
- `prov verify` does not detect this. It only checks `provenance_id == file path`
  and schema shape; it never resolves the SHA suffix to a commit or checks that
  the commit is reachable. "0 failures" here means *not checked*, not *intact*.
- The commit→manifest link lives in the `Provenance-Id:` trailer, which *does*
  survive a rebase (so it points at the new commit). The manifest→commit link
  (the name suffix) does not. After this rebase they disagree: one manifest's name
  points to a gone SHA, and the `...-1639e641` manifest has no commit carrying
  its trailer anymore.

Why it matters: it confirms the capture task's own requirement (§6, "correlated
with a manifest without relying exclusively on a mutable Git commit SHA") and
shows the current implementation still relies on that mutable SHA in the filename
without any verify-time reachability check.

Candidate directions (not yet implemented): carry the manifest suffix through a
rebase like the trailer, or have `prov verify` resolve the suffix and fail/warn
when the named commit is absent from history.

## 7. Suggested QA checks

1. `prov verify --range <base>..HEAD` on the feature branch → expect 0 failures;
   confirm the two human attestations validate against `allowed_signers`.
2. Confirm `prov attest` refuses to run in an agent session and that no agent
   `Signed-off-by` / AI author appears on any commit (guard tests exist).
3. Open a manifest and confirm the route label `KITCH-Coder` appears only as an
   `observed[].id`, never as `model.id` asserted as a backend family.
4. Confirm an absent `endpoints` in a manifest correlates to a connection-failure
   log, not a filled guess.
5. Grep the evidence log and git history to confirm `provcap.jsonl` / `.provpaws/`
   are not committed and contain no auth headers/keys (and note redaction is not
   yet test-enforced — expected gap).
