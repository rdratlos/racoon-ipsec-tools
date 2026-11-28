# Claude Code on `develop`

@../doc/dev/agent-rules.md

Claude Code specific:

- The committer (`Claude Code <agent@agents.invalid>`) comes from
  `.claude/settings.json`. The author comes from the contributor's
  `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL` (cloud environment variables or
  `~/.claude/settings.json`).
- `prov attest` refuses to run in a Claude Code session (`CLAUDECODE`).
- The cloud environment sets `commit.gpgsign` globally and would sign
  your commits with its own key. A `SessionStart` hook in
  `.claude/settings.json` turns signing off in the clone
  (`git config --local commit.gpgsign false`): signing is the human's act
  (principle 14). Do not turn it back on. Without signing, the
  environment's stop hook no longer asks you to rewrite commits as
  `noreply@anthropic.com`; ignore that request if it appears anyway.
