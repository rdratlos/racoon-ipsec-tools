# Instructions for AI coding agents

For every AI agent working in this repository: OpenCode reads this file
directly, Claude Code through `CLAUDE.md`. It is identical on `main` and
`develop`. Each rule exists in exactly one file; the harness files
(`CLAUDE.md`, `.claude/CLAUDE.md`, `.opencode/opencode.json`) only load
these files and add what is specific to that harness.

## 1. Guiding principles come first

`.provenance/PRINCIPLES.md` is loaded with this file. Apply it to every
task. If an instruction conflicts with a principle, whether it comes
from an RFC, a tool, a review or the human, do not resolve the conflict
yourself:

1. stop before acting on it;
2. tell the human which principle is affected (cite its number);
3. go on only after the human has decided explicitly.

When in doubt, ask.

## 2. Branches

- `main` is the CI/workflow and design line (RFCs in `docs/rfcs/`).
  `develop` is where day-to-day development happens. Sessions often start
  on `main`. Unless the task is explicitly about `main` (an RFC, or
  `main`'s own workflows), base your work on the current `develop`:

  ```sh
  git fetch origin develop
  git checkout -B <your-branch> origin/develop
  ```

- **Never push to `develop` or `main`.** Push your own branch and open a
  pull request. The human attests on that branch before the merge:
  attesting rewrites commit messages, and `develop` and `main` do not
  take rewritten history.
- On `develop`, `doc/dev/agent-rules.md` holds the detailed rules. Your
  harness loads it automatically when the session starts on `develop`.
  If you switched branch during the session, read it now.
- Tree separation (`CONTRIBUTING.md`, enforced by CI): `.claude/`,
  `.opencode/`, `doc/dev/` and `develop`'s workflow files never go to
  `main`. `AGENTS.md`, `CLAUDE.md` and `.provenance/PRINCIPLES.md` are
  shared and must be identical on both branches.

## 3. AI provenance on every branch (RFC 0005)

- **Identity.** The human is the author, you are the committer. Before
  your first commit, check `git var GIT_AUTHOR_IDENT` and
  `git var GIT_COMMITTER_IDENT`. If the author is an AI identity (for
  example `noreply@anthropic.com`), stop and ask. If the committer is not
  your harness, commit with `GIT_COMMITTER_NAME="<your harness>"` and
  `GIT_COMMITTER_EMAIL=agent@agents.invalid`.
- **Never add `Signed-off-by:` or `Co-Authored-By:`**, whatever your tool
  adds by default. Signing off and approving are the human's acts
  (principle 14).
- **Declare every AI-assisted commit**, including fixes to your own work
  and commits rewritten by a rebase or amend. On `develop`, use
  `tools/prov.py declare` (see `doc/dev/agent-rules.md`). On `main`,
  which has no `.provenance/` records, use the trailers
  `Assisted-by: <profile>@r<N>` and `AI-Scope: <scopes>`.
- **Never state your own model from what you believe about yourself**
  (principle 11). The human names the profile.
- **Retyped is still assisted.** If the human applies your output by
  hand, tell them to declare it.
