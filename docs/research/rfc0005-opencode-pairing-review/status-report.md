# Status Report — RFC 0005 Phase 1 OpenCode Pairing Provenance Capture

Status: internal progress report for the first QA review. Date: 2026-10-23.
Scope source: [`rfc0005-opencode-pairing-provenance-capture.md`](./rfc0005-opencode-pairing-provenance-capture.md).
Implementation lives on [`feature/opencode-pairing-provenance`](https://github.com/rdratlos/racoon-ipsec-tools/tree/feature/opencode-pairing-provenance)
(tip `65fe1b9`); RFC spec read from `main`; RFC schema prose diff on
[`docs/rfc-0005-api-trust`](https://github.com/rdratlos/racoon-ipsec-tools/tree/docs/rfc-0005-api-trust)
(tip `70c98e0`). This report
describes a **prototype** intended for a multi-month observation period; it is
not a Phase 3 completion report.

## Summary

The capture task asked for the smallest reliable OpenCode capture mechanism that
feeds the canonical `prov declare` workflow, keeps a configured model distinct
from the model that actually answered, and never fabricates a backend identity.
The prototype does this with two evidence sources that share one digest-bound
observation log:

- an OpenCode plugin (`.opencode/plugin/provpaws-capture.ts`) that records the
  **configured** model per session (config trust), and
- a loopback capture proxy (`tools/provcap-proxy.py`) that records the **model
  id and deployment actually seen on the wire** plus the serving endpoint (api /
  router trust).

`prov declare --evidence ...` merges both into an additive `session.capture`
block in a schema **2.0** manifest. Existing v1 manifests and `prov verify`
remain valid. A first real session (`20261022T065938Z-1639e641`) captured 207
requests and is signed and human-attested; `prov verify` runs at 0 failures.

The single most important honest finding: the OpenCode route label `KITCH-Coder`
is **not** a backend model. The capture log shows the same `KITCH-Coder` route
being served by different real deployments (`hosted_vllm/Qwen3.8-Flash-Next-FP8`,
`Qwen3.8-Flash-Next-NoReasoning`, `Qwen3.8-Flash-Next`). This is exactly the
configured-vs-actual distinction the task demanded, now backed by observations.

## Request coverage vs the capture task

Each row states the request, whether it is implemented, and why a request is
deferred. "Partial" means the mechanism exists but is exercised only through
documented fixtures, not a live runtime, or covers a subset. "Deferred" means a
later-phase or environment-boundary item deliberately not built now.

| # | Task section | Request | Status | Reason for partial / skip |
| --- | --- | --- | --- | --- |
| 1 | §2 | Distinguish configured / requested / route / reported / verified model | **Implemented** | Five-way distinction is schema-expressible (`model_reported_by`, `observed`); verified identity intentionally left unproven (no crypto source exists). |
| 2 | §2 | Never infer backend from config/route/style; keep unknown as unknown | **Implemented** | Absent fields stay absent (tested: `..._without_endpoints_stays_honest`); no guess fills a gap. |
| 3 | §2 | Never present `KITCH-Coder` as a concrete model/family | **Implemented** | Route label kept only as `id`; backend deployment recorded separately in `observed`. |
| 4 | §3 | Reuse canonical `prov declare`, no competing generator | **Implemented** | Evidence flows into `declare`; no second manifest writer or policy copy. |
| 5 | §3 | Verify installed OpenCode version and real event/hook interfaces | **Done (investigated)** | Recorded in the Phase 3 sibling report: OpenCode 1.19.3 stores only the configured id; no hook exposes the returned id — this is *why* a capture proxy is needed. |
| 6 | §3 | Record verified interface and its limitations in docs | **Implemented** | `.provenance/README.md` "Running a captured session" + schema descriptions. |
| 7 | §4.1 | Session id, timestamps, version, branch, revision, agent/role, resume | **Partial** | Plugin writes session id + configured model; declare binds a window + request count via the log. Version/resume/branch are available to the harness but not all persisted per session yet — deferred to the adapter hardening step. |
| 8 | §4.1 | One session ≠ one commit (multi-commit, multi-session) | **Implemented** | Session spans commits supported (tested `test_session_spanning_two_commits_passes`). |
| 9 | §4.2 | Per-request model/provider/route/deployment/request-id/outcome/trust | **Partial** | Response `model` + deployment header + endpoint + status captured; provider request-id capture and full retry/fallback metadata deferred (corporate router not exercised by tests by design). |
| 10 | §4.2 | Structured local request-observation log for router-side correlation | **Implemented** | JSONL evidence log, git-ignored; endpoints deduplicated for correlation. |
| 11 | §4.2 | No credentials / auth headers / keys collected | **Partial** | Proxy forwards the wire unchanged and logs response metadata only; an explicit tested redaction policy is deferred (tracked, see Honest Report). |
| 12 | §4.3 | File-level contribution records, strongest evidence, no over-attribution | **Implemented (file-level)** | `contributions[].files` at file level only; line-level attribution explicitly not claimed. |
| 13 | §4.3 | Distinguish human edits / interleaving | **Partial** | Human review + separate agent contributions modelled; automatic human-vs-agent file split within one session deferred. |
| 14 | §4.4 | Preserve roles (implementer/reviewer/orchestrator); reviewer-only reads ≠ authoring | **Implemented** | Role per contribution; manifest separates contributions, does not collapse roles. |
| 15 | §4.4 | Keep multiple models/roles separate, no single session model | **Implemented** | `observed` keeps per-observation entries; config-trust vs api/router-trust kept apart. |
| 16 | §5 | Additive schema extension; keep v1 valid; migration/compat tests | **Implemented** | `manifest-v2.schema.json` additive; v1 stays valid (tested `test_router_in_v1_doc_fails_validation` guards misuse, v1 verify still passes). |
| 17 | §5 | Optional digest linking manifest to private observations | **Implemented** | `session.capture.log_digest` (sha256 over sorted per-file digests). |
| 18 | §6 | Keep raw prompts/transcripts out of git; configurable location | **Implemented** | `.gitignore` now covers `.provpaws/` and `provcap.jsonl`; manifest stores digest only. |
| 19 | §6 | Document retention / deletion / secret-redaction | **Partial** | Privacy/ignore behavior documented; retention+redaction policy text deferred (pending redaction impl). |
| 20 | §6 | Manifest stays valid if raw logs deleted | **Implemented** | Digest is a relationship, not proof; missing log keeps manifest valid with capture gap noted. |
| 21 | §7 | Canonical trailers `Assisted-by` / `AI-Scope` / `Provenance-Id` | **Implemented** | Existing `declare` trailers reused; no new trailer grammar. |
| 22 | §7 | Never create human `Signed-off-by`, never access key, never attest for human | **Implemented** | `prov attest` refuses in an agent session (tested `test_attest_refused_in_agent_session`); human signs themselves. |
| 23 | §7 | No automatic commit amend/rewrite for enrichment | **Implemented** | Enrichment needs a human re-declare; no silent rewrite. |
| 24 | §8 | Explicit failure handling (no backend id, mismatch, retry, resume, malformed event, uncorrelated subagent, human edit, version change, missing log) | **Partial** | Covered by fixtures: no-backend, mismatch, api/router merge, requested-only fail, bad-format fail, missing endpoints honest-absent. Live retry/subagent-correlation fixtures deferred. |
| 25 | §8 | Report substitution per existing policy, no new blocking | **Implemented** | Router substitution **warns** (tested `test_evidence_capture_log_router_substitution_warns`), never blocks. |
| 26 | §9 | Analysis command/report summarizing coverage & missingness, no secrets | **Partial** | `harness_cross_check.py` checks config-vs-profile drift; a dedicated coverage/missingness report is deferred to the observation-analysis step. |
| 27 | §9 | No external DB / mandatory network dependency | **Implemented** | Git-based + local JSONL only. |
| 28 | §10 | Automated tests for router failure modes | **Implemented** | 50+ tests incl. capture-evidence, api/router trust, honesty, trust-level guards. |
| 29 | §10 | No dependency on corporate router / live API | **Implemented** | Fixtures model the router limitation; no live calls in the suite. |
| 30 | §10 | Integration/manual verification on the real runtime | **Partial** | A real captured session exists (provcap-live); a scripted, repeatable manual procedure doc is deferred. |
| 31 | §11 | Docs: install/enable, versions, fields+sources, route/config/reported/verified, incomplete capture, correlation, coverage diagnosis, retention, limits | **Partial** | Core documented; coverage-diagnosis + retention subsections pending the deferred report/redaction pieces. |
| 32 | §12 | Small reviewable steps + final implementation report | **In progress** | This review + the Honest Prototype Implementation Report satisfy §12.8. |

Counts: **Implemented 18**, **Partial 9**, **Deferred/boundary 0 standalone**
(deferrals are the parenthetical reasons above), **Done(investigated) 1**,
**In progress 1**.

## Work completed

- **Capture proxy** `tools/provcap-proxy.py`: loopback HTTP forward proxy; logs
  per-request response `model`, deployment header, serving `endpoint` (origin the
  upstream hop finally reached via `resp.geturl()`), status; multi-file evidence
  log; env-proxy aware.
- **OpenCode plugin** `.opencode/plugin/provpaws-capture.ts`: records the
  configured model per session id (config-trust observation source).
- **`prov declare` evidence wiring** `tools/prov.py`: `_load_evidence` reads the
  capture log, merges api+router evidence, writes `session.capture`
  (`log_digest`, `requests`, `window`, `endpoints`); refuses to invent endpoints
  or models.
- **Schema** `manifest-v2.schema.json`: additive `session.capture` block and
  `observed[]` with `source ∈ {capture-proxy, harness-log}`; `model_reported_by`
  gains `router`. v1 preserved.
- **Cross-check** `tools/harness_cross_check.py`: harness `model:` pins vs
  provenance profiles, so a pinned model cannot drift from the record.
- **Git hygiene**: `.gitignore` added `.provpaws/` + `provcap.jsonl` (previously
  the plugin documented them as "git-ignored" with no rule — capture logs with
  configured models and session ids were committable).
- **Docs**: `.provenance/README.md` "Running a captured session" + Layout table
  row for `session.capture.log_digest`.
- **Tests**: `tools/test_prov.py` extended (capture evidence binding, honesty on
  absent endpoints, api rewrite, router trust, api+router merge, router
  substitution warn, requested-only fail, opencode config-trust, bad-format fail,
  router-without-evidence guards, v1/v2 guards).
- **Real run + attestation**: session `20261022T065938Z-1639e641` (207 requests)
  declared, signed (SSH), and human-attested; `prov verify` = 0 failures.

## Activities brought forward from later phases

These were pulled into this prototype although the task framed them as later
work — noted so QA does not read them as a full Phase 3 delivery:

- **Router-trust identity (`model_reported_by = "router"`)** — normally a router-
  integration phase. Needed now because the whole point is `KITCH-Coder` ≠ backend.
- **Deployment-name capture from gateway headers** — a Phase 3 correlation feature,
  built early to make the honest config-vs-actual gap visible.
- **Cross-harness identity investigation** (Phase 3 sibling `rfc0005-phase3/`) —
  run first to justify the proxy approach instead of a plugin-only one.
- **SSH signing + human-attestation separation** hardening — pulled forward to
  produce a verifiable real manifest during observation, including the rule that
  the agent never signs or attests.

## Planned subsequent steps

1. Implement and test an explicit **secret-redaction** policy in the capture log
   (§4.2 / §6), then finalize retention/deletion documentation (§6).
2. Persist the remaining session-lifecycle fields per session (§4.1: version,
   resume, branch/initial revision) once the adapter contract is fixed.
3. Add a **coverage & missingness analysis report** (§9) that summarizes
   capture completeness without exposing prompts/secrets.
4. Capture provider request-ids and retry/fallback metadata; add live-runtime
   retry/subagent-correlation fixtures (§4.2, §8).
5. Write the repeatable **manual verification procedure** for the real runtime
   (§10) and complete the docs subsections deferred above (§11).
6. Run the multi-month observation window and answer the ten §9 evaluation
   questions with real coverage numbers.
6. Run the multi-month observation window and answer the ten §9 evaluation
   questions with real coverage numbers.
7. ~~Reconcile the branch/SHA state, then push~~ **done** — `develop` was made
   the feature parent and `main` the docs parent, the old duplicates are
   unreferenced, and `git rebase --gpg-sign` re-signed all commits to `G`. Both
   branches are now pushed and visible to everyone:
   [`feature/opencode-pairing-provenance`](https://github.com/rdratlos/racoon-ipsec-tools/tree/feature/opencode-pairing-provenance)
   (`65fe1b9`; 8 commits in `origin/develop..origin/feature/opencode-pairing-provenance`)
   and
   [`docs/rfc-0005-api-trust`](https://github.com/rdratlos/racoon-ipsec-tools/tree/docs/rfc-0005-api-trust)
   (`70c98e0`; 1 commit in `origin/main..origin/docs/rfc-0005-api-trust`).
   That push surfaced a real gap: rebasing **orphans the manifest↔commit SHA
   binding** — the `...-<sha>` manifest name still points at pre-rebase SHAs
   (`1639e641`, `e0b90554`, both now gone), and `prov verify` does not catch it
   because it never resolves that SHA suffix. Details in the Honest Report §8.
   Fixing this (carry the suffix through rebase, or verify suffix reachability)
   is now a tracked follow-up.

## Known limitations

- Backend identity is **observed, never cryptographically verified**; no trusted
  source asserts it, so `verified` stays empty by design.
- Tests exercise documented fixtures, not the corporate router (a task
  requirement to avoid a live dependency), so real retry/fallback/subagent
  correlation is only structurally supported.
- Redaction is asserted by "log response metadata only", not yet enforced by a
  tested scrubber.
- `prov verify` does not check that a manifest's `...-<sha>` name suffix resolves
  to a reachable commit, so a rebase silently breaks that binding (Honest §8).
- The **prototype code** lives only on the two branches above and is not on
  `develop` yet; this review pack on `develop` documents and references it.
