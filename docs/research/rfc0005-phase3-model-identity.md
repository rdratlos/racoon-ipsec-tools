# How model identity reaches a commit (RFC 0005, Phase 3 investigation)

Status: research report, not normative. Date: 2026-10-20. Branch base:
`develop` at `ade7ced`; RFC 0005 read from `main` at `0ef7737`
(`docs/rfcs/0005-provpaws-ai-provenance.md`).

## Summary

No commit on `develop` today records a model identity that came from the
model provider. All 250 legacy AI trailers carry a name that the harness
(Claude Code) wrote into its default trailer, or that an agent or a human
typed in. The 8 Phase 1 manifests say `model_reported_by = "config"`. In
fact the agent picked the profile from what its system prompt told it.
Both harnesses tell the model its configured model id in the system
prompt: Claude Code does it in this cloud session, OpenCode always does
it. That is configuration relayed by the model, not provider evidence.
`api`-level identity exists in one place only: **Claude Code's local
session transcript**. It records, per assistant message, the `model` field
of the API response body next to the `requestedModel`. Against a router
mock, Claude Code recorded `KITCH-Coder` (returned) next to
`claude-opus-5-5` (requested). No hook input carries a model.
**OpenCode 1.19.3 stores only the configured model id.** It receives the
returned model id and the response headers from the AI SDK, but drops
them when it builds the step record, and no plugin hook sees them. Behind
a router, neither harness keeps the deployment headers (LiteLLM
`x-litellm-model-id` and related). Only a capture proxy in front of the
router, or the router's own logs, can show which deployment answered.
The legacy history also has one recall miss: `prov query --include-legacy`
drops `Assisted-by: OpenCode:<KITCH-Coder>` (`f757084`), because the
e-mail filter removes the bracketed model name. That commit changes the
critical paths `crypto_openssl.c` and `isakmp_quick.c`.

## Method, versions, sources

| Item | Value |
| --- | --- |
| Claude Code | CLI `2.1.304` (`claude --version`; transcript `version` field). The environment variable `CLAUDE_CODE_VERSION` in this container says `2.1.42` and contradicts the binary. The binary was trusted. |
| Claude Code docs | `https://code.claude.com/docs/en/<page>.md`, fetched 2026-10-20 20:35 UTC: `hooks`, `statusline`, `settings-reference`, `env-vars`, `model-config`, `monitoring-usage`, `llm-gateway`, `llm-gateway-protocol`. Line numbers below refer to these fetched files. |
| OpenCode | `opencode-ai@1.19.3`, `@opencode-ai/sdk@1.19.3`, `@opencode-ai/plugin@1.19.3` (npm, published 2026-10-16), installed with `npm install` into a throw-away directory. Binary `opencode-linux-x64/bin/opencode`, sha256 `179ca421d61eefeadfa0c50e084a6e79c1623734732f0f4593f81ccfd3ab7ee9`. |
| OpenCode source | The network policy of this sandbox blocks github.com (403) and opencode.ai. So the TypeScript source **could not be read at a commit**. Evidence comes from the published type definitions (`.d.ts`) and from the JavaScript bundle embedded in the compiled binary, cited by byte offset (`grep -abo`). The cited OpenCode lines still need checking against the repository at the `v1.19.3` tag. |
| LiteLLM (router reference) | `litellm==1.106.1` wheel from PyPI: `litellm/proxy/common_request_processing.py:1824-1833` (`x-litellm-model-id`, `x-litellm-model-name`, `x-litellm-model-api-base`, `x-litellm-version`, `x-litellm-model-region`), `litellm/router.py:11798` (`x-litellm-model-group`). |
| Experiments | Throw-away directories only, with `env -i` and redirected `HOME`, `CLAUDE_CONFIG_DIR` and `XDG_*`. Dummy API key, base URL `127.0.0.1`. No credentials and no paid calls were used. The user's `~/.claude` and `~/.config/opencode` were not read or written. |

Labels: **Verified** (cited), **Observed** (own experiment, command and
output under Q4), **Inferred** (premises stated), **Unknown** (what was
searched).

## Findings

| Q | Hypothesis / question | Verdict | Evidence | Label |
| --- | --- | --- | --- | --- |
| Q2 | H1: the model learns its name from the harness system prompt (config-level) | **Confirmed** for this cloud session. The system prompt states "You are powered by the model named Opus 5.5. The exact model ID is claude-opus-5-5", and a system reminder gives the commit attribution line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. In `claude -p` against a custom `ANTHROPIC_BASE_URL`, the system prompt had **no** such line, only the generic list of Claude model ids. | This session's context. The Q4 router log field `system_identity_lines`. | Observed |
| Q2 | H2: hook input contains the model | **Refuted** for all events except `SessionStart`, where `model` is optional and "not always included". `PreModelSwitch` and `PostModelSwitch` get `from_model`/`to_model` (the session's configured model). Every hook gets `transcript_path`. | `hooks.md:732-734` ("Only SessionStart hooks can receive a model field"; "There is no $CLAUDE_MODEL"), `hooks.md:1230-1235`, `hooks.md:3381-3386`. Q4: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Stop` and `SessionEnd` had no model key; `SessionStart` had no `model` in `-p` mode, either on startup or on resume. | Verified + Observed |
| Q2 | H3: statusline input contains the model identifier | **Confirmed, config-level**: `model.id` and `model.display_name` give the "current model", which is the session setting, not a per-response value. | `statusline.md:174`, `statusline.md:226-229`. Not observed: the statusline does not run in `-p` mode, and the Q4 run recorded nothing. | Verified (field); Inferred (level) |
| Q2 | H4: the transcript records the API-returned model per assistant message | **Confirmed.** `message.model` is the `model` of the response body, and the entry also carries `requestedModel` and `requestId`. The mock returned `KITCH-Coder` for a request for `claude-opus-5-5`, and the transcript recorded both. Response headers are not recorded. | Q4 Claude Code run. This session's transcript has 43/43 assistant entries with `message.model = claude-opus-5-5`, `requestedModel = claude-opus-5-5` and `version = 2.1.304`. `monitoring-usage.md:766` documents `requestId` in the transcript. The transcript format itself is undocumented. | Observed |
| Q2 | Mid-session model switch | Transcript: `requestedModel` changes per message (Observed with `--resume <id> --model claude-sonnet-5-5`). `PostModelSwitch` runs on `/model`, automatic fallback and resume. It does **not** run when a fallback-chain model serves one turn, and it did not fire on `--resume --model` in `-p`. `claude -p --output-format json` keys `modelUsage` by the **requested** model, so it hides substitution. | `hooks.md:3448-3459`, `model-config.md:483-487`. Q4 resume run. | Verified + Observed |
| Q3 | Model selection in OpenCode | Configured in `opencode.json` (`model`, `provider.<id>.models`) and per agent. The configured id is what OpenCode sends, stores, and tells the model ("You are powered by the model named ${api.id}. The exact model ID is ${providerID}/${api.id}"). | Binary offset 96721636. Q4: the system prompt said "You are powered by the model named kitch-coder-latest". | Verified (bundle) + Observed |
| Q3 | H5: OpenCode stores provider and model per message | **Confirmed, but it is the requested model.** It is SQLite (`$XDG_DATA_HOME/opencode/opencode.db`, tables `message`, `part`, `session`, `event`). `UserMessage.model{providerID,modelID}` and `AssistantMessage.modelID/providerID` hold `kitch-coder-latest` (configured). The returned `KITCH-Coder` appears nowhere (case-sensitive search over `message`, `part`, `session`, `event`: 0 hits). `step-finish` parts contain only `cost`, `reason`, `snapshot` and `tokens`. | `@opencode-ai/sdk` `dist/v2/gen/types.gen.d.ts:128-151, 213-246`. Q4 OpenCode run and DB query. | Verified + Observed |
| Q3 | H6: a plugin can observe each LLM request and response | **Partly refuted.** Hooks: `chat.message`, `chat.params`, `chat.headers` (request headers the plugin may add), `event` (bus events such as `message.updated`), `tool.execute.before/after`, `shell.env` and others. Each one receives the configured `Model`. **No hook receives the response body, the returned model id or the response headers.** | `@opencode-ai/plugin` `dist/index.d.ts:173-330`. Q4 `provprobe.jsonl`. | Verified + Observed |
| Q3 | H7: the provider layer receives the returned model and headers but does not expose them | **Confirmed.** The AI SDK's `finish-step` stream part carries `response:{...modelId, headers}` (offset 99410893). The openai-compatible provider emits `response-metadata` from the response body. OpenCode's handler for `case"finish-step"` (offset 96591969) builds `stepFinish({index, reason, usage, providerMetadata})` and **ignores `response`**. That is where the returned model and the headers are dropped. | Bundle offsets in the 1.19.3 binary. Q4: nothing is stored. To verify against the source tag. | Verified (bundle) + Observed |
| Q3 | Environment marker | OpenCode sets `AGENT=1`, `OPENCODE=1` and `OPENCODE_PID=<pid>` at CLI start. Child shells see `AGENT=1` and `OPENCODE=1`. | Offset 96083125 (`process.env.AGENT="1",process.env.OPENCODE="1",process.env.OPENCODE_PID=...`). Q4 bash tool output `AGENT=1 OPENCODE=1`. | Verified + Observed |
| Q4 | Behind a router | Claude Code keeps the body's alias (`KITCH-Coder`) and loses the deployment headers. OpenCode keeps neither: it stores the configured id only. A model's answer to "which model are you" can only repeat the system prompt. | Q4 below. | Observed |
| Q1 | How the legacy trailers were made | 176 of 250 legacy trailer lines are Claude Code's default `Co-Authored-By` trailer rewritten by the hook. Their model name was generated by the harness, not stated by the model. | Q1 below. | Verified (rules) / Inferred (per group) |

## Q1. History of the existing trailers

Script: `docs/research/rfc0005-phase3/q1_trailer_history.py`. Run it
after `git fetch --unshallow` with
`python3 docs/research/rfc0005-phase3/q1_trailer_history.py --rules`;
`--json` gives one line per trailer. The repository facts it relies on:

- **Hook.** `.claude/settings.json` was added in `2cd3a84` on 2026-07-02
  with a `PostToolUse` hook. After a `git commit` command that does not
  contain `amend`, the hook replaces `Co-Authored-By:` with `Assisted-by:`
  and amends the commit with `--no-verify`. `4b23cfe` (2026-10-17) replaced
  the hook with `attribution: {commit: "", pr: ""}` and the agent committer
  identity. No version of the file ever pinned a model. **Verified** (`git log --full-history -- .claude/settings.json`).
- **Harness name.** Claude Code's default trailer is
  `Co-Authored-By: <name> <noreply@anthropic.com>`. The name is "the model
  in use when the commit is made, such as `Claude Sonnet 5`". It is
  `Claude` alone when the harness "recognizes the model as a Claude model
  but can't confirm its exact version", and `Claude Code` for a model it
  cannot match. **Verified**: `settings-reference.md:3369-3371`.
- **No OpenCode configuration** (`opencode.json`, `.opencode/`,
  `AGENTS.md` before 2026-10-19) and no `<model-name>` template appear
  anywhere in the history (`git log --all -S'<model-name>'`: no result).
  **Verified** (searched).

`origin/develop`: 440 non-merge commits, 261 with AI trailers (250
legacy, 11 under the policy), one AI trailer line per commit.

| Mechanism | Trailer | Committer | Claude-Session | Hook at parent | Commits | Author dates | Examples | Confidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| hook-rewrite | `Assisted-by: Claude Sonnet 5 <email>` | human | no | yes | 82 | 2026-07-25 .. 08-10 | daaa591, 2e81f7c | high |
| hook-rewrite | `Assisted-by: Claude Sonnet 5 <email>` | human | yes | yes | 30 | 2026-07-22 .. 08-05 | 49c1086, e65c450 | high |
| hook-rewrite | `Assisted-by: Claude Sonnet 5 <email>` | Claude | yes | yes | 3 | 2026-07-12 .. 07-25 | 077a629, 735f2ff | high |
| hook-rewrite | `Assisted-by: Claude <email>` | human | no | yes | 33 | 2026-07-09 .. 08-04 | 8a4aff0, adb1de2 | high |
| hook-rewrite | `Assisted-by: Claude <email>` | Claude | no | yes | 3 | 2026-07-11 .. 08-03 | 33c17d1, 24ae6b3 | high |
| hook-rewrite | `Assisted-by: Claude Opus 5 <email>` | human | no | yes | 11 | 2026-08-10 .. 08-11 | 226e27e, 6bb9bba | high |
| hook-rewrite | `Assisted-by: Claude Opus 5 <email>` | human | yes | yes | 10 | 2026-07-28 | b8ece23, a161d10 | high |
| hook-rewrite | `Assisted-by: Claude Opus 4.8 <email>` | human / Claude | yes | yes | 1 + 3 | 2026-07-04 .. 07-06 | aa01a33, f92c55c | high |
| harness-copy | `Assisted-By: Claude Sonnet 5 <email>` | human | yes: 19, no: 9 | yes | 28 | 2026-07-07 .. 08-11 | 2813d18, 6c2891c | medium |
| harness-copy | `Assisted-By: Claude Opus 4.8 <email>` | human | yes: 5, no: 2 | yes | 7 | 2026-07-06 .. 07-15 | 42c06c2, 775b4f7 | medium |
| harness-copy | `Assisted-By: Claude Opus 5 <email>` | human | yes | yes | 2 | 2026-07-28 | bd2bcd0, b39f5d8 | medium |
| harness-raw | `Co-Authored-By: Claude Opus 4.8 / Sonnet 5 <email>` | Claude | yes | yes | 3 | 2026-07-04 | babf1bd, bceaf1c, 64c2bde | high (origin), unknown (why the hook did not run) |
| edited | `Assisted-by: Claude Sonet 5 <email>` | human | no | yes | 9 | 2026-07-09 | 7fd21ef, 4fdf330 | medium |
| agent-self | `Assisted-by: OpenCode:KITCH-Coder` | human | no | (n/a) | 15 | 2026-07-06 .. 07-25 | b48df51, 0a3d79e | low |
| agent-self | `Assisted-by: OpenCode:Qwen/Qwen3-Coder-480B-A35B-Instruct` | human | no | (n/a) | 5 | 2026-07-03 .. 07-25 | c648cd4, 03e4fa4 | low |
| agent-template | `Assisted-by: OpenCode:<model-name>` (literal) | human | no | (n/a) | 4 | 2026-07-10 | 3209d22, 9d82461 | medium |
| agent-template | `Assisted-by: OpenCode:<KITCH-Coder>` | human | no | (n/a) | 1 | 2026-07-03 | f757084 | medium |
| declare | `Assisted-by: claude-opus@r1` | agent id / human | mostly yes | mixed | 11 | 2026-10-12 .. 10-20 | 360a89b, ade7ced | high |

Notes on the table:

- **Committer is weak evidence.** `rebase`, `cherry-pick`, `amend` and
  `prov attest` set the committer to whoever runs them. "human" therefore
  does not mean "a human typed the trailer". **Inferred** from git
  semantics.
- **hook-rewrite**: the key is exactly `Assisted-by`, which is the hook's
  output spelling, and the hook was present at the parent. The name is the
  documented harness name. So the model name was **chosen by Claude Code
  from its configured model**. That is config-level, and neither the model
  nor the human typed it. **Inferred** from the two Verified facts above.
- **harness-copy** (`Assisted-By`): the hook never writes a capital B, but
  the value has the exact harness format. In 8 `Claude-Session`s,
  `Assisted-by` and `Assisted-By` commits appear side by side with the
  same model name. Possible causes: the agent wrote the trailer itself,
  copying the history's style, so the hook had nothing to rewrite; or a
  human retyped it. Which one is **Unknown**. Either way the model name
  still comes from the harness string.
- **harness-raw** (3 commits, session `015h82WGHm3NZfq8rdhfkR91`): the
  same session has 3 rewritten commits. The hook was present but did not
  rewrite these. The cause is **Unknown**. Candidates: the commit command
  contained `amend`, `jq` was missing at that moment, or the commit ran
  outside the `Bash` tool.
- **Bare `Claude`** (36): the harness writes it when it cannot confirm the
  exact version (Verified rule). These are mostly local sessions (33
  without `Claude-Session`). **The model is unknowable from the
  repository.** Correctly left unmapped.
- **`Sonet`** (9, one day): the harness cannot produce a misspelling. So
  it was typed by a human, or by an agent following a misspelled
  instruction. **Inferred**.
- **`OpenCode:`** (25): nothing in the repository produced these. The
  literal `<model-name>` shows that an instruction template outside the
  repository (a prompt or a global OpenCode rules file) was copied without
  filling in the model. In `f757084` the placeholder was filled but the
  brackets were kept. `KITCH-Coder` and `Qwen/...` are model names that
  the agent or the human wrote. The OpenCode system prompt states the
  configured id (Verified, Q3), so the agent *could* copy it. **Low
  confidence** that the values match what ran. **Inferred**.
- **The RFC's "5 bare `OpenCode:`" is wrong.** It is 4 literal
  `<model-name>` and 1 `<KITCH-Coder>`. `prov query` strips `<...>` with
  `EMAIL_RE = r"\s*<[^>]*>\s*"` (`tools/prov.py:61`) before matching
  `legacy-map.toml`, so `f757084` is reported as unmapped `OpenCode:`.
  `f757084` changes `src/racoon/crypto_openssl.c` and
  `src/racoon/isakmp_quick.c`, which are critical paths. That is a **recall
  miss for a withheld model in critical code**. **Observed**
  (`prov query --model KITCH --include-legacy`: 15 hits, `f757084`
  missing; Appendix B says 15 and should say 16).

**Q1.3 Stated model vs. configuration.** No `.claude/settings.json`
version and no OpenCode configuration in the repository ever selected a
model. Model selection lived in the users' local or cloud settings. The
repository therefore has nothing to compare against, and the result is
**Unknown** for all 250 legacy lines. Internal consistency (Observed):
none of the 18 `Claude-Session`s shows two different model names. The
platform keeps a server-side record per cloud session: for this session,
`get_session` returns `configured_model`, `session_context.model` and
`last_served_model`, all `claude-opus-5-5`. The `Claude-Session` URLs in
the 18 legacy sessions and the 8 manifests could be checked the same way.
That needs access to your account's other sessions, outside this task's
rules, so it **was not done**. It is listed under remaining unknowns.

**Q1.4 Defects by probable cause.**

| Defect | Count | Probable cause | Label |
| --- | --- | --- | --- |
| bare `Claude` | 36 | harness default name when the version is not confirmed, then hook rewrite | Verified (rule) / Inferred |
| bare `OpenCode:` | 4 (+1) | unfilled instruction template `<model-name>` (+1 filled but bracketed) | Observed (values) / Inferred (cause) |
| `Sonet` | 9 | human typing, or a misspelled instruction | Inferred |
| `Assisted-By` | 37 | not the hook; the agent wrote the trailer itself, or a human retyped it | Inferred / Unknown |
| e-mail in value | 225 | the harness value is `<name> <noreply@anthropic.com>`; the hook changes only the key (176), and copies and edits keep it (49) | Verified (hook code, harness default) |
| `Co-Authored-By` leftovers | 3 | the hook did not run on those commits | Unknown cause |

**Q1.5 Seed profiles vs. history.**

| Profile | In history? | Model evidence in that period | Remark |
| --- | --- | --- | --- |
| `claude-opus@r1` (`claude-opus-5-5`) | 11 commits / 8 manifests since 2026-10-12 | Agent self-selection from the system prompt (config-level). Platform record available, not checked. | The legacy `Claude Opus 5` (21) may be Opus 5 rather than 5.5: today the harness writes `Claude Opus 5.5` (this session's attribution line). The legacy map joins them. **Inferred** |
| `claude-sonnet@r1` (`claude-sonnet-5`) | 143 legacy lines (`Sonnet 5`, `Sonet 5`); not used under the policy | harness name only | consistent with the harness name |
| `opencode-kitch@r1` | 16 legacy (15 + `f757084`) | agent/human free text | no repository config backs it; disclosure is `withheld`, and one commit is in a critical path |
| `opencode-qwen3-coder@r1` | 5 legacy | agent/human free text | consistent, low confidence |
| `opencode-pair@r1` | **none** | none | The multi-agent setup it describes does not appear in the history. It is an example profile marked `active`. |

## Q2. Claude Code (2.1.304)

Capture points, most to least trustworthy:

1. **Session transcript** `~/.claude/projects/<cwd-slug>/<session-id>.jsonl`
   (`CLAUDE_CONFIG_DIR` relocates it). Per assistant entry: `message.model`
   (the response body), `requestedModel`, `message.id`, `requestId`,
   `version`, `timestamp`, `isSidechain`, plus `tool_use` blocks that carry
   their file paths. **Observed.** Hooks receive the path as
   `transcript_path`, and Bash/hook subprocesses get
   `CLAUDE_CODE_SESSION_ID` (`env-vars.md:375`). The transcript "is written
   asynchronously and may lag" (`hooks.md`, common input fields).
   Retention: `cleanupPeriodDays`, default 30 (`settings-reference.md`).
   The format is not documented as a stable interface. **Verified.**
2. **OpenTelemetry**: `claude_code.llm_request` carries `model` /
   `gen_ai.request.model`, which is the *request* (`monitoring-usage.md:227-229`).
   `api_response_body` (gated by `OTEL_LOG_RAW_API_BODIES`) carries the
   full response body, and therefore the returned `model`
   (`monitoring-usage.md:934-950`). Response headers are not documented.
   **Verified.**
3. **Cloud platform record** (cloud sessions only): `configured_model`,
   `session_context.model` and `last_served_model` per session, reachable
   through the `Claude-Session` URL. **Observed** for this session.
   Retention and access by third parties: **Unknown**.
4. **Hooks**: `SessionStart.model` (optional), `Pre/PostModelSwitch`
   (`from_model`/`to_model`), all config-level. **Verified.**
5. **Statusline** `model.id`: config-level. **Verified/Inferred.**
6. **System prompt / attribution line** → what the agent writes: config
   relayed by the model. **Observed.**

Model switches show up in the transcript per message. `PostModelSwitch`
misses fallback-chain turns. The `-p` JSON `modelUsage` reports requested
models only.

## Q3. OpenCode (1.19.3)

- **Selection.** `opencode.json` `model` and `provider.<id>.models.<key>`,
  per-agent `model`. The stored and announced id is
  `providerID/modelID` from the configuration. **Verified/Observed.**
- **Store.** SQLite `opencode.db` with JSON in `message.data` and
  `part.data`. User messages hold `model{providerID, modelID}`; assistant
  messages hold `modelID` and `providerID`. All of these are the
  **configured** id. **Observed.**
- **Plugins.** No hook receives response data. `event` gives
  `message.updated` with the same configured `modelID`. **Verified/Observed.**
- **Drop point.** The `finish-step` handler ignores `response.modelId` and
  `response.headers`, which the AI SDK provides (bundle offsets 96591969
  and 99410893). **Verified (bundle); verification against the source tag is pending.**
- **Marker.** `OPENCODE=1`, `AGENT=1`, `OPENCODE_PID`. **Verified/Observed.**
- **Untested (Unknown):** whether a plugin's `config` hook can inject a
  custom `fetch` into `provider.options`. That would make in-process
  response capture possible without patching OpenCode. Searched: the
  plugin typings (no `fetch` field in `ProviderContext.options`, which is
  `Record<string, any>`).

## Q4. Behind a router: observations

Mock: `docs/research/rfc0005-phase3/router_mock.py`, with alias
`KITCH-Coder`, LiteLLM-style deployment headers and a deployment switch
on every request. Runners: `q4_claude_code.sh` and `q4_opencode.sh`,
plus the plugin `provprobe-plugin.js`.

**Claude Code**, from `sh q4_claude_code.sh <dir> claude-opus-5-5`:

```
== router log (ground truth)
{"n":0,"path":"/v1/messages","requested_model":"claude-opus-5-5","deployment":"deploy-a-7f3c","response_model":"KITCH-Coder"}
{"n":1,"path":"/v1/messages","requested_model":"claude-opus-5-5","deployment":"deploy-b-91e2","response_model":"KITCH-Coder"}
== -p result  modelUsage keys: ["claude-opus-5-5"]
== hook events: SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop, SessionEnd -- no model field in any
== transcript: per assistant message
{"model":"KITCH-Coder","requestedModel":"claude-opus-5-5","id":"msg_mock354e...","version":"2.1.304"}
{"model":"KITCH-Coder","requestedModel":"claude-opus-5-5","id":"msg_mockfa1c...","version":"2.1.304"}
resume with --model claude-sonnet-5-5:
{"model":"KITCH-Coder","requestedModel":"claude-sonnet-5-5", ...}   PostModelSwitch: not fired
```

**OpenCode**, from `sh q4_opencode.sh <dir> <opencode>` (requested
`kitch/kitch-coder-latest`):

```
== router log: requested_model "kitch-coder-latest", deployments a, b, a; response_model "KITCH-Coder"
== plugin init env: AGENT=1 OPENCODE=1 OPENCODE_PID=1543
== chat.params  model {"id":"kitch-coder-latest","providerID":"kitch"} provider.source "config"  (agents "title" and "build")
== chat.headers requestHeaders []
== tool.execute.after bash output "AGENT=1\nOPENCODE=1\n"
== message.updated assistant modelID "kitch-coder-latest" (each step)
== system prompt: "You are powered by the model named kitch-coder-latest. The exact model ID is kitch/kitch-coder-latest"
== opencode.db: case-sensitive "KITCH-Coder" 0 hits; "deploy-" 0 hits
```

| | Claude Code | OpenCode |
| --- | --- | --- |
| What the model can say about itself | only what the system prompt says (here: nothing specific; in cloud sessions: the configured id) | the configured id |
| Transcript or store | requested + **returned** model per message | configured model only |
| Hook or plugin | no model; `transcript_path` | configured model only |
| Router header (deployment) | lost | lost |
| Deployment switch | invisible (same alias in the body) | invisible |

Not tested: Claude Code against a non-Claude model through a router. The
documentation says Anthropic "doesn't support routing Claude Code to
non-Claude models through any gateway" (`llm-gateway.md`). The realistic
router case for KITCH is therefore OpenCode.

## Q5. Consequences for the design

### Q5.1 Best capture point per harness and setup

| Harness | Setup | Best capture point | `model_reported_by` |
| --- | --- | --- | --- |
| Claude Code | direct (Anthropic API, cloud) | transcript `message.model` per assistant entry, mapped to files through the `tool_use` paths. Cross-check: the platform session record. | `api` |
| Claude Code | gateway/router | transcript `message.model` (the router's claim) + capture proxy for deployment headers | `router` (new) or `api` + `endpoint` (see below) |
| OpenCode | direct | today the store gives only `config`. For `api`: a capture proxy (`baseURL` → local proxy → provider), or an upstream patch that keeps `response.modelId` in `step-finish` | `config` today; `api` with a proxy or patch |
| OpenCode | router | capture proxy (body alias + `x-litellm-*` headers + `x-litellm-call-id`), cross-referenced with the router's logs | `router` |
| any | browser chat, copy-paste | manual | `manual` |

**Proposal: a new value `router`.** It would mean: model id as returned
by an intermediary that may alias or switch deployments, plus the
deployment reference if the router exposes one. `api` should be reserved
for a body that comes from the provider that ran the model. A router's
alias is not equivalent: the profile check (substitution warning) would
pass while the deployment changed underneath. **Inferred** from the Q4
observations. Also: the 8 Phase 1 manifests labelled `config` are really
**agent-relayed** values. The agent ran `declare` with the default
`--reported-by config` and chose the profile from its system prompt, as
`.claude/CLAUDE.md` instructs ("Use the profile whose model matches the
one you run on"). They are immutable. The RFC should define `config` as
"read by a tool from harness configuration", and treat a value the agent
passes on as `manual`, or as a new value `agent`.

### Q5.2 What the agent may write

- **Commit message:** only what `prov declare` prints (profile reference,
  `AI-Scope`, `Provenance-Id`). This confirms your expectation. The agent
  never writes a model id into a commit.
- **Manifest model fields:** only from `declare` reading evidence
  (`--evidence claude-transcript:<path>`, `--evidence capture-log:<path>`).
  An agent-supplied `--model ROLE=ID` must not produce `api`. Today it
  does (`tools/prov.py:763-766`). **Verified.**
- `session.digest` should hash the evidence file actually used, so a
  later check can tie the manifest to it without publishing it.

### Q5.3 A session with a deployment switch

Keep one contribution per role (the profile role is the unit of recall)
and add the observed identities. The proposed v2 shape, not applied:

```json
{ "profile": "opencode-kitch@r2", "role": "implementer",
  "model": { "family": "kitch", "id": "KITCH-Coder" },
  "model_reported_by": "router",
  "observed": [
    { "id": "KITCH-Coder", "deployment": "deploy-a-7f3c", "requests": 2,
      "first": "2026-10-20T20:38:37Z", "last": "2026-10-20T20:38:39Z" },
    { "id": "KITCH-Coder", "deployment": "deploy-b-91e2", "requests": 1, "...": "..." }
  ],
  "files": ["..."] }
```

`verify` would warn when an `observed` id or deployment is not mapped to
the profile's model. For withheld models, the deployment → model mapping
stays with the owner (G6).

### Q5.4 Proposed changes to RFC 0005 (diff proposal, not applied)

```diff
 ### 4. Manifests
-- **`model_reported_by`** — `api` (the provider said so), `config` (the
-  harness was configured so), `manual` (declared by hand).
+- **`model_reported_by`** — `api` (model id in the response body of the
+  provider that ran the model, read by a tool from a harness record or a
+  capture log), `router` (id returned by an intermediary that may alias or
+  switch deployments; deployment reference in `observed`), `config` (read
+  by a tool from harness configuration), `manual` (declared by a human, or
+  relayed by the agent from its system prompt).
+  A model id the agent states about itself is never `api` or `config`.
+- **`observed`** (manifest v2): distinct (id, deployment) pairs seen in
+  the session with request counts; required for `router`.
```

```diff
 ### 7. Capture: adapters per harness
-- **Claude Code** (Phase 2): ... a hook that records the session's model
-  and edited files into a local session log for `declare`.
+- **Claude Code** (Phase 2): `declare --evidence claude-transcript:PATH`
+  reads the session transcript (path from `transcript_path` or
+  `CLAUDE_CODE_SESSION_ID`): per assistant message `message.model`
+  (returned) and `requestedModel`, and the file paths of its `tool_use`
+  blocks. Hooks carry no model; they are only a trigger. The transcript
+  format is undocumented: pin the tested CLI version.
-- **OpenCode** (Phase 3): ... plugin/event mechanism.
+- **OpenCode** (Phase 3): the plugin API and the session store see only the
+  configured model (1.19.3). `api`/`router` evidence needs either a capture
+  proxy between OpenCode and the endpoint, or an upstream change that
+  keeps the AI SDK's `response.modelId`/`headers`. Until then OpenCode
+  sessions are `config`.
+- **Capture proxy** (tool-neutral, Phase 3): a local pass-through that
+  logs, per request, the requested model, the response `model`, router
+  deployment headers and the call id. It works for any harness with a
+  configurable base URL.
```

```diff
 ### 10. Rollout
-| 2 | Claude Code adapter | `declare` output produced without manual steps |
+| 2 | Claude Code adapter | `declare` output produced without manual steps, with
+    `model_reported_by = api` from the transcript; a mock substitution
+    (requested ≠ returned) is detected and warned |
-| 3 | OpenCode adapter; harness-config cross-check | multi-agent session recorded with roles |
+| 3 | OpenCode adapter; capture proxy; harness-config cross-check | multi-agent
+    session recorded with roles; behind a router, a deployment switch
+    appears in `observed`; without proxy/patch the record says `config` |
```

```diff
 ## Open questions
-- OpenCode's environment marker for `attestation.agent_env` (to be verified; ...).
+- OpenCode sets `OPENCODE=1` (and `AGENT=1`): add `OPENCODE` to
+  `agent_env` (verified for 1.19.3).
+- `router` value and `observed` list: manifest v2, or an additive v1.1?
+- Which router owners will expose and retain deployment identity
+  (`x-litellm-model-id`/`-name`, call-id logs), and for how long?
+- Transcript retention (30 days by default) vs. when `declare` runs.
```

Also proposed, outside the RFC text:

- `legacy-map.toml` and `tools/prov.py:61`: do not strip a `<...>` that
  contains no `@`, so that `f757084` maps to KITCH.
- Correct Appendix B to 16 KITCH commits and "4 unfilled
  `OpenCode:<model-name>`".

### Cost and benefit, and who must act

| Evidence level | What it proves | Cost | Who |
| --- | --- | --- | --- |
| `manual` / agent-relayed (Phase 1 today) | what the contributor or agent believed | none | contributor |
| `config` by tool | what the harness was configured to request | small adapter | project |
| `api` from the Claude Code transcript | what the provider said answered, per message | adapter + version pinning (undocumented format) | project |
| `api` for OpenCode | same | capture proxy, or an upstream patch to OpenCode | project / OpenCode maintainers |
| `router` with deployment | which deployment answered | the router must emit deployment headers and keep call-id logs; the owner maps deployment → model | **LLM/router admin team** |
| independent confirmation | that the record was not edited | server-side log (platform session record, router log), retained and accessible | provider / admin team |

This confirms your expectation: beyond `api` for Claude Code, trustworthy
identity needs the party that runs the endpoint.

## Remaining unknowns

- OpenCode TypeScript source at the `v1.19.3` tag (github.com blocked
  here). The bundle offsets need re-checking against the source.
- Whether an OpenCode plugin can inject a `fetch` wrapper (in-process
  capture without a proxy).
- The statusline input, not observed (`-p` mode).
- Why the hook missed 3 commits on 2026-07-04, and who wrote the 37
  `Assisted-By`.
- The model each legacy `Claude-Session` and each Phase 1 manifest
  session really ran on. The platform session records could answer this,
  but reading them needs your OK (outside the repository).
- The model behind the 36 bare `Claude` lines and behind all `OpenCode:`
  lines: no record in the repository.
- Whether Claude Code subagent transcripts (`isSidechain`) carry the same
  fields. Not exercised.
- The `x-litellm-*` headers of a *real* LiteLLM deployment under load.
  The mock uses the names from the 1.106.1 source.

## Reproduce

```sh
git fetch --unshallow                       # Q1 needs full history
python3 docs/research/rfc0005-phase3/q1_trailer_history.py --rules
# Q4 (throw-away dirs; no credentials; Claude Code CLI on PATH)
sh docs/research/rfc0005-phase3/q4_claude_code.sh "$(mktemp -d)"
d=$(mktemp -d); npm install --prefix "$d/npm" opencode-ai@1.19.3
sh docs/research/rfc0005-phase3/q4_opencode.sh "$d" "$d/npm/node_modules/.bin/opencode"
```
