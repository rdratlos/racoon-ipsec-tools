# Agent identity: a GitHub App per harness

Why: an agent that works with the maintainer's GitHub credentials acts as
the maintainer. GitHub then cannot tell who pushed, commented or edited,
and the maintainer's SSH key is in the agent's reach. An agent with its
own GitHub App works as `<app>[bot]`: pushes, pull requests and comments
are attributed to it, and its commits name it as committer (`AGENTS.md`
§3). The human stays the author and the only one who attests
(principle 14).

This page sets up a harness with its app. The apps so far:

| Harness | App | OS user | Configuration |
| --- | --- | --- | --- |
| OpenCode | `racoon-opencode` | `opencode` | `/etc/racoon-opencode/app.json` |
| Claude Code (local) | `racoon-claude` | `claude` | `/etc/racoon-claude/app.json` |

Below, `<app>` and `<user>` stand for one row. The scripts in
`agent-identity/` are a first version: checked offline (the JWT signature
verifies against a throw-away key), not yet against GitHub. The
acceptance test below is the first real check.

## How it works

- The apps' private keys belong to a separate OS user, `ghapp`. The
  agents' OS users cannot read them.
- `mint-token /etc/<app>/app.json`, run as `ghapp`, signs a JWT with that
  app's key and exchanges it for an installation token: valid for 1 hour, limited to this
  repository and to the permissions below. It reuses the token until 5
  minutes before it expires, one cache per app.
- Each agent's OS user may run exactly that command, with its own app's
  `app.json` as the only argument, through `sudo`. sudoers pins the
  argument, so OpenCode cannot mint a `racoon-claude` token or the other
  way round. Git gets the token from `git-credential-racoon`, `gh` from
  the `gh` wrapper; both pass `RACOON_APP_CONF` from the agent's
  environment to `mint-token`.

The agent can always act as the bot while it runs; that is the point. It
cannot take the key with it, widen the token, or keep using it once the
key or the installation is removed.

## 1. The app (GitHub, once per app)

In the app's settings:

- Repository permissions: Contents, Pull requests and Issues read and
  write; Metadata read. Everything else, Administration and Workflows in
  particular, no access.
- Webhook off.
- Install it on `racoon-ipsec-tools` only.
- Generate a private key (downloads a `.pem`).
- Note the Client ID (`Iv23...`, top of the app's settings) and the
  installation ID (the number at the end of the URL of the installation's
  Configure page).

The bot's user ID is the `id` in
`https://api.github.com/users/<app>%5Bbot%5D` (no token needed).
Its commit address is `<id>+<app>[bot]@users.noreply.github.com`;
GitHub links commits with that address to the bot.

## 2. The machine (as root)

Each harness runs as its own OS user (`<user>`), never as the human.

Once per machine:

```sh
useradd --system --create-home ghapp
install -D -m 755 doc/dev/agent-identity/mint-token /usr/local/libexec/mint-token
install -m 755 doc/dev/agent-identity/git-credential-racoon /usr/local/bin/
```

Install `agent-identity/gh` in a directory that comes before `/usr/bin`
in the agents' `PATH`, and adjust the path of the real `gh` in it if
needed.

Once per app:

```sh
install -d -o ghapp -m 700 /etc/<app>
install -o ghapp -m 600 <app>.*.pem /etc/<app>/app.pem
cat > /etc/<app>/app.json <<'EOF'
{"client_id": "Iv23...", "installation_id": 12345678,
 "key": "/etc/<app>/app.pem", "repo": "racoon-ipsec-tools"}
EOF
chown ghapp /etc/<app>/app.json
echo '<user> ALL=(ghapp) NOPASSWD: /usr/local/libexec/mint-token /etc/<app>/app.json' \
    > /etc/sudoers.d/<app>
chmod 440 /etc/sudoers.d/<app>
visudo -c
```

Keep the argument in the sudoers line: without it, the user may run
`mint-token` with any app's configuration. Delete the downloaded `.pem`.

## 3. The agent's clone and environment (as `<user>`)

```sh
git remote set-url origin https://github.com/rdratlos/racoon-ipsec-tools.git
git config --local credential.https://github.com.helper ''
git config --local --add credential.https://github.com.helper \
    /usr/local/bin/git-credential-racoon
```

In the environment the harness starts with (for example the `<user>`
user's profile):

```sh
export RACOON_APP_CONF=/etc/<app>/app.json
export GIT_AUTHOR_NAME="Your Name" GIT_AUTHOR_EMAIL="you@example.org"
export GIT_COMMITTER_NAME="<app>[bot]"
export GIT_COMMITTER_EMAIL="<id>+<app>[bot]@users.noreply.github.com"
unset SSH_AUTH_SOCK GPG_AGENT_INFO
```

Claude Code sets the committer from `env` in `.claude/settings.json`
(`Claude Code <agent@agents.invalid>`), which wins over the profile. For
`racoon-claude`, set the bot's `GIT_COMMITTER_NAME` and
`GIT_COMMITTER_EMAIL` in `env` of `.claude/settings.local.json` in the
clone instead; it takes precedence over the project settings and is not
committed.

Set the author explicitly. Do not set `user.name`/`user.email` to the
bot: a commit with the bot as author fails `verify` (AI author).

## 4. Acceptance test (as `<user>`)

| Command | Expected |
| --- | --- |
| `cat /etc/<app>/app.pem` | Permission denied |
| `sudo -n -u ghapp /usr/local/libexec/mint-token /etc/<other-app>/app.json` | fails: a password is required |
| `gh pr list` | works |
| `gh api user` | fails: an installation token has no user |
| `git push origin HEAD:develop` | rejected by branch protection |
| `git push -u origin <own-branch>` | works; GitHub shows `<app>[bot]` as pusher |
| a commit on that branch | committer `<app>[bot]`, author the human |
| `python3 tools/prov.py verify` on it without trailers | fails: committed by an agent |

Record the results in the pull request that first uses the app.

## Limits

- With Contents and Pull requests write, the bot can technically merge.
  What stops an unattested merge is a required status check that fails
  without an attestation, not the identity.
- With Issues write, the bot can probably edit other people's comments
  (unchecked). GitHub then shows the bot as editor, so the record names
  who did it; the rule in `AGENTS.md` §2 still applies.
- `ghapp` can read every app's key. The separation between the agents
  rests on the sudoers argument, not on file permissions.
- Only `git` and `gh` are covered. If a harness reaches GitHub another way
  (an MCP server, its own API client), that client needs the same token
  source.
- Emergency stop: delete the key in the app's settings or remove the
  installation. Tokens already issued expire within the hour.
