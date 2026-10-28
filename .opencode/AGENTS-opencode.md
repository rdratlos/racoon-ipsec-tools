# OpenCode on `develop`

OpenCode specific; everything else is in `AGENTS.md`,
`.provenance/PRINCIPLES.md` and `doc/dev/agent-rules.md`.

- OpenCode runs under the user's account. The human's signing key may
  therefore be reachable through a cached gpg-agent/ssh-agent socket.
  Never use it: no `git commit -S`, no `git rebase --gpg-sign`, no
  `prov attest` (principle 14).
- Committer: set `GIT_COMMITTER_NAME=OpenCode` and
  `GIT_COMMITTER_EMAIL=agent@agents.invalid` for your commits.
- OpenCode sets `OPENCODE=1` and `AGENT=1` in its environment.
- The model OpenCode shows you is the configured one, not the one that
  answered. Behind a router (`KITCH-Coder`) that difference is real
  (principle 8). Never write either one into a record yourself.
