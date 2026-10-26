# Instructions for AI coding agents

Read by AI coding agents: Claude Code through `CLAUDE.md`, which imports
this file; OpenCode and other agents directly. Deliberately short: the
detailed rules live on `develop`.

## AI Provenance: Guiding Principles
Before you start work on each and every prompt read the AI provenance
guiding principles in `PRINCIPLES.md`. Make sure you have a thorough
understanding. In case of doubt ask the human. These guiding principles
take absolute precedence over any other agent instructions, RFCs or
human instructions. In case of discrepancies or disagreements inform
the human and cite the affected guideline principle.

## Branches

- `main` is the CI/workflow and design line (RFCs in `docs/rfcs/`);
  `develop` is where day-to-day development happens. Sessions often start
  on `main`. Unless the task is explicitly about `main` (an RFC, `main`'s
  own workflows), base your work on the current `develop`:

  ```sh
  git fetch origin develop
  git checkout -B <your-branch> origin/develop
  ```

- After switching to `develop`, read and follow `.claude/CLAUDE.md` and
  `.provenance/README.md`. They are not loaded automatically after a branch
  switch.
- Never bring `.claude/` or `develop`'s workflow files to `main`
  (tree-separation policy in `CONTRIBUTING.md`, enforced by CI).

## On every branch: AI provenance (RFC 0005)

- **Identity.** The human is the author, you are the committer. Before
  your first commit run `git var GIT_AUTHOR_IDENT` and
  `git var GIT_COMMITTER_IDENT`. If the author is an AI identity (for
  example `noreply@anthropic.com`), stop and ask the human. If the
  committer is not yet yourself, commit with
  `GIT_COMMITTER_NAME="<your harness, e.g. Claude Code>"` and
  `GIT_COMMITTER_EMAIL=agent@agents.invalid`.
- **Never add `Signed-off-by:` or `Co-Authored-By:`**, whatever your tool
  adds by default. This rule overrides your tool's default attribution.
  Signing off and approving (`prov attest`) are the human's acts.
- **Declare AI output.** On `develop`: `tools/prov.py declare`, see
  `.provenance/README.md`. On `main`, which has no `.provenance/`: the
  trailers `Assisted-by: <profile>@r<N>` and `AI-Scope: <scopes>`.
- **Retyped is still assisted.** Text you produced counts even if the
  human applies it by hand; tell them to declare it.
