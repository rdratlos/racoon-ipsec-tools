# Implementation Task: RFC 0005 — Phase 1 OpenCode Pairing Provenance Capture

Status: task brief (source of requests), reproduced verbatim for the QA review.
Review reports live in `docs/research/rfc0005-opencode-pairing-review/`.
RFC 0005 read from `main`; implementation on `feature/opencode-pairing-provenance`;
RFC schema diff on `docs/rfc-0005-api-trust`.

> **Execution status (2026-10-23).** The prototype was implemented on the two
> branches referenced above, both since pushed and visible to everyone:
> [`feature/opencode-pairing-provenance`](https://github.com/rdratlos/racoon-ipsec-tools/tree/feature/opencode-pairing-provenance)
> (tip `65fe1b9`) and
> [`docs/rfc-0005-api-trust`](https://github.com/rdratlos/racoon-ipsec-tools/tree/docs/rfc-0005-api-trust)
> (tip `70c98e0`). The "Non-Goals" below are deliberate scope choices, not
> oversights. The `Further Proceeding` items are **done**: both branches are
> pushed; PR creation was deferred until after this `develop` review commit.
> What this phase honestly proves is the capture *and* its gaps — see the review
> pack for which requests are still open.

## 1. Objective

Extend the Phase 1 implementation of RFC 0005 (`provpaws`) with an OpenCode-specific provenance capture capability for AI-assisted pair programming.

The primary objective is to collect consistent, machine-readable provenance data over several months, enabling an evidence-based decision on the appropriate long-term OpenCode integration and model-router architecture.

The implementation must remain compatible with the existing `provpaws` design, schemas, CLI, repository conventions, branch-separation rules, and RFC rollout plan.

Read and follow the current authoritative specification:

- `docs/rfcs/0005-provpaws-ai-provenance.md`
- `.provenance/README.md`
- `.provenance/schema/`
- `.provenance/policy.toml`
- `tools/prov.py`
- `tools/test_prov.py`
- Existing OpenCode configuration, agent definitions, plugins, project instructions, and Git hooks, if present.

Inspect the current repository state before making changes. Do not assume that the RFC, schemas, or implementation match an earlier revision of the design.

## 2. Central design constraint: dynamic model routing

The development environment uses OpenCode for pair programming through an organizational model router.

The router exposes the route label `KITCH-Coder`, but does not currently expose a reliable, verifiable identity for the backend model that actually processed an individual request.

The router may dynamically select different models or substitute a backend for capacity or availability reasons. A model configured in OpenCode is therefore not necessarily the model that processed a request.

The implementation MUST distinguish these concepts:

1. **Configured model:** the model declared in the OpenCode configuration.
2. **Requested model:** the model identifier sent by the client, if available.
3. **Selected route:** the router endpoint or logical route, such as `KITCH-Coder`.
4. **Reported backend model:** the model identifier returned by the router or provider for a specific request, if available.
5. **Verified backend identity:** an identity supported by an explicitly documented, trusted source and verification mechanism.

Never infer the actual backend model from the configured model, route label, response style, or generated content.

Never represent `KITCH-Coder` as a concrete model or model family merely to satisfy the existing manifest schema.

An unavailable backend identity must remain explicitly unknown. Preserve the distinction between a missing value, a configured value, a router-reported value, and a verified value.

## 3. Scope and rollout boundaries

This is a targeted Phase 1 enhancement, not a wholesale implementation of all planned Phase 3 features.

Implement the smallest reliable OpenCode capture mechanism that allows real sessions to produce useful provenance records during the observation period.

The existing tool-neutral command `python3 tools/prov.py declare` remains the canonical manifest-generation interface.

The OpenCode integration should collect session observations and supply them to `declare`, or to a narrowly scoped, documented extension of that interface. Do not create a competing manifest generator or duplicate policy logic.

Before selecting the integration mechanism:

- Determine the installed and supported OpenCode version.
- Verify the current official OpenCode documentation and actual available plugin, event, or hook interfaces.
- Inspect the event payloads and their documented semantics.
- Determine whether the relevant events expose session IDs, agent names, model identifiers, tool calls, file changes, request IDs, response metadata, or usage information.
- Test whether events are emitted for every relevant request and whether failures, retries, fallbacks, and subagent activity are observable.
- Record the verified interface and its limitations in the project documentation.

Do not invent event names, payload fields, environment variables, or API guarantees. If the available interface cannot expose a required observation, document the gap instead of simulating it.

## 4. Capture requirements

Capture the following information wherever the runtime makes it available.

### 4.1 Session identity and lifecycle

- A stable OpenCode session identifier, if available.
- Session start and end timestamps in UTC.
- OpenCode version.
- Repository identity, branch, and initial Git revision.
- Relevant agent and role identifiers.
- Session completion status and capture completeness.
- Whether the session was resumed or continued from an earlier session.
- The provenance ID associated with the session.

Do not assume that one OpenCode session corresponds to one Git commit. A session may produce multiple commits, and a commit may include contributions from multiple sessions.

### 4.2 Model and router observations

For each model request or independently identifiable model invocation, capture available information about:

- Configured model identifier and provider.
- Requested model identifier and provider.
- Logical route, including `KITCH-Coder`.
- Backend model identifier and provider reported by the response, if any.
- Provider or router request ID.
- Any documented routing, fallback, retry, or substitution metadata.
- Agent and role associated with the request.
- Timestamp and request outcome.
- Source of each observation and its trust level.

Record which fields were observed and which were unavailable. Distinguish explicitly between configuration-derived values and values reported by the actual request or response.

Where practical, maintain a structured local request-observation log so that future integration with router-side logs is possible.

Do not claim that a provider-reported model identity is cryptographically verified unless an actual verification mechanism exists.

Do not collect credentials, authorization headers, API keys, or other secrets.

### 4.3 Contribution and file attribution

Capture the files modified by each agent or role, including subagents where the runtime exposes them.

Correlate runtime observations with Git changes to determine which files were affected during the session.

Use the strongest attribution evidence available and document its limitations.

In particular:

- Do not attribute every file in a session's final diff to every model used during that session.
- Do not assume that a tool invocation which merely reads a file means the model contributed to it.
- Do not silently claim line-level attribution when only file-level evidence is available.
- Account for human edits and interleaved contributions where they can be distinguished.
- Record ambiguous or incomplete attribution explicitly.

The resulting records must support later refinement of the attribution method without requiring the original session to be repeated.

### 4.4 Multi-agent sessions

Preserve distinct roles such as `implementer`, `reviewer`, and `orchestrator` when these roles exist.

A reviewer that only examines code should not be recorded as having authored that code. A reviewer that subsequently edits a file should be recorded as a contributor to that file.

If multiple models are used within a session, retain their separate observations and contribution records. Do not collapse them into a single session-wide model identity.

## 5. Manifest and schema design

The existing `provpaws` manifest remains the authoritative, version-controlled provenance record.

Inspect `manifest-v1.schema.json` and the current `prov declare` implementation before designing the capture output.

The resulting design must preserve the following semantic distinctions:

- Declared profile and role.
- Actual observations collected during the session.
- Configured or requested model, where known.
- Router route and request identifiers, where available.
- Reported backend model, where available.
- Source and confidence of each identity claim.
- A clear representation of unavailable information.
- Capture completeness and attribution limitations.
- File-level contribution records.
- An optional digest linking a manifest to privately retained session observations.

Do not place a route label in a field that semantically asserts a concrete backend model.

If the current schema cannot represent these distinctions, propose the smallest appropriate schema change. Follow the RFC's schema immutability rules: do not silently change an already-established schema contract or invalidate existing manifests. If a breaking change is required, introduce a new schema version with migration and compatibility tests.

Prefer an additive extension that keeps existing consumers working.

The manifest must remain useful even when the router never reveals the actual backend model.

The implementation must also preserve the RFC's profile semantics. A profile describes a declared development setup; it must not be treated as proof of the model that processed an individual request.

## 6. Local observation log and privacy

The raw capture log is an observation source, not a substitute for the canonical manifest.

Keep raw prompts, transcripts, and potentially sensitive session content out of the Git repository by default.

Store local observations in a documented, configurable location with appropriate access restrictions. Ensure that they can be correlated with a manifest without relying exclusively on a mutable Git commit SHA.

Use a stable session identifier and, where useful, a digest of a well-defined, canonically serialized observation record.

A digest establishes a relationship to the recorded bytes; it does not independently prove that the underlying observations are complete or truthful.

Document retention, deletion, and secret-redaction behavior. Avoid retaining more sensitive information than is needed for the provenance objective.

If raw logs are unavailable or have been deleted, the manifest must remain valid and indicate the loss of the underlying evidence where appropriate.

## 7. Git integration and canonical trailers

Preserve the RFC's canonical commit-message format:

- `Assisted-by:`
- `AI-Scope:`
- `Provenance-Id:`

Use the existing `prov declare` implementation to generate the canonical trailers and manifest.

Do not introduce alternative spellings, free-text model names, or a separate OpenCode-only trailer grammar.

Keep the human as the accountable author of record and preserve the RFC's separation between agent-generated provenance and human attestation.

The OpenCode integration must never create a human `Signed-off-by:` trailer, access a human signing key, or execute the human attestation on the user's behalf.

Do not automatically amend or rewrite existing commits merely to enrich provenance data.

The existing Phase 1 rules for manifests, profiles, signatures, attestations, verification, and CI remain authoritative.

## 8. Failure handling and graceful degradation

Provenance capture must not fabricate missing information.

Handle at least these cases explicitly:

- The router returns no backend model identifier.
- The configured model differs from the reported model.
- A request fails or is retried.
- A session ends unexpectedly.
- A plugin event is missing or malformed.
- A subagent cannot be correlated with its parent session.
- A file was edited manually during an AI-assisted session.
- The runtime or router version changes.
- Local observation data is unavailable when the manifest is generated.

Capture errors and incomplete observations in a structured, diagnosable way.

Do not silently discard observations or turn unknown model identities into guessed values.

Follow the existing RFC's substitution policy. Report discrepancies according to the current policy; do not introduce a new blocking policy merely because the router does not reveal its backend.

A temporary capture failure must not result in a misleading manifest that claims complete attribution. Where a session cannot be represented honestly under the existing schema, provide a clear diagnostic and document the appropriate recovery path.

## 9. Data collection and future evaluation

The observation mechanism must support a multi-month data collection period without requiring a later redesign of the capture format.

The data should help answer:

1. What percentage of requests expose a concrete backend model identity?
2. How often do configured and reported model identifiers differ?
3. Does the router expose stable request IDs suitable for correlation with administrative logs?
4. How frequently are retries, fallbacks, or backend substitutions observable?
5. What percentage of sessions have complete file attribution?
6. How frequently are multiple models or roles used in a session?
7. How often do human and AI contributions interleave in the same files?
8. Which fields are consistently missing, and which missing fields materially limit later recall queries?
9. Can recorded provenance support a meaningful model- or family-based recall drill?
10. What additional router-side interface would deliver the greatest improvement in evidence quality?

Where practical, provide a small analysis command or report that summarizes coverage and missingness without exposing prompts, transcripts, or secrets.

Do not introduce an external database or mandatory network dependency. The existing Git-based design remains authoritative, and local capture data should be sufficient for the initial observation period.

## 10. Testing requirements

Add automated tests using the repository's existing testing conventions.

Cover at least:

- A request with a known configured model and no reported backend identity.
- A request with a reported backend identity.
- A configured/requested/reported model mismatch.
- A route-only observation such as `KITCH-Coder`.
- Missing request IDs and incomplete event payloads.
- Multiple model requests in one session.
- Multiple agents or roles.
- Session resume and multiple commits from one session.
- Human edits mixed with agent-generated changes.
- Missing or malformed local capture data.
- Secret redaction.
- Manifest generation and schema validation.
- Backward compatibility with existing manifests and `prov verify`.
- Correct canonical trailer generation.
- No accidental creation of human sign-offs or automatic commit rewrites.

Use fixtures that model the known router limitation. Do not make the test suite depend on the corporate router or a live model API.

Where the current OpenCode API cannot be exercised directly in unit tests, use documented, representative event fixtures and add an integration test or reproducible manual verification procedure for the actual installed runtime.

All existing provenance self-tests and relevant CI checks must remain passing.

## 11. Documentation

Update the appropriate provenance documentation to describe:

- How OpenCode capture is installed and enabled.
- Which runtime version and interface were verified.
- Which fields are collected and their sources.
- The distinction between route, configured model, reported backend, and verified identity.
- How incomplete capture is represented.
- How manifests and local observation logs are correlated.
- How to inspect capture coverage and diagnose failures.
- How to preserve the observation data for later analysis.
- Known limitations and the conditions under which a future router integration would improve provenance quality.

Keep the RFC authoritative. If this enhancement changes the agreed phase boundaries or normative behavior, update the RFC through the project's normal design process instead of silently diverging from it.

## 12. Implementation approach

Proceed in small, reviewable steps:

1. Inspect the current RFC, schemas, CLI, tests, OpenCode configuration, and repository status.
2. Report the existing capabilities, missing fields, and verified OpenCode integration points.
3. Propose the smallest implementation design, including any necessary schema changes.
4. Implement the capture mechanism and integrate it with `prov declare`.
5. Add tests and documentation.
6. Run the relevant test suite, schema validation, and `prov verify`.
7. Inspect the final diff for privacy issues, accidental commit rewriting, schema incompatibilities, and incorrect model attribution.
8. Provide a concise implementation report listing changed files, tests executed, observed limitations, and remaining questions.

Do not stop after producing a design proposal if the repository provides enough information to implement the enhancement safely. If a necessary interface or schema assumption cannot be verified, isolate that uncertainty and implement the remaining parts without inventing the missing behavior.

## 13. Acceptance criteria

The work is complete when:

- OpenCode sessions can produce provenance manifests through the canonical `prov declare` workflow with minimal manual effort.
- The manifest records the available route and model observations without misrepresenting the actual backend identity.
- Missing backend identities remain explicitly unknown.
- Request-level observations can be correlated with sessions and, where possible, file contributions.
- Multi-model and multi-agent sessions are not collapsed into a single model attribution.
- Existing manifests and Phase 1 verification rules remain compatible.
- Automated tests cover the dynamic-router failure modes.
- The capture mechanism can run throughout a multi-month observation period.
- The resulting data supports a later, evidence-based decision about router integration and the full OpenCode adapter.

The objective is not to prove which model generated every line when the router does not expose that information. The objective is to collect the strongest honest evidence currently available, preserve its provenance, quantify its limitations, and make future improvements possible without losing the accumulated history.
