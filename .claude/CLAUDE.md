# Claude Code on `develop`

@../doc/dev/agent-rules.md

Claude Code specific:

- The committer (`Claude Code <agent@agents.invalid>`) comes from
  `.claude/settings.json`. The author comes from the contributor's
  `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL` (cloud environment variables or
  `~/.claude/settings.json`).
- `prov attest` refuses to run in a Claude Code session (`CLAUDECODE`).
