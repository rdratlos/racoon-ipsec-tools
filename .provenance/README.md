# AI provenance (RFC 0005 "provpaws")

This directory records **which AI models produced output that entered the
repository**, in a tool-neutral format that lives with the code. The design
and its rationale are in `docs/rfcs/0005-provpaws-ai-provenance.md` (on
`main`). This file is the short version for contributors.

## The rule in one paragraph

A human is always the author and the only one who signs off; the agent may
appear as **committer**. If AI output ends up in a commit, it carries three
trailers and a manifest (`tools/prov.py declare` writes both). Before merge,
the accountable human runs `tools/prov.py attest`, which adds their
Signed-off-by and writes a **signed approval commit** that binds the
approval to the reviewed diffs. CI (`develop-provenance.yml`) checks all of
it.

```
Assisted-by: <profile>@r<N> [analysis tools]
AI-Scope: code, tests
Provenance-Id: 20261012T081500Z-3f9a1c2e
Signed-off-by: Your Name <you@example.org>
```

Never put an AI in `Signed-off-by:` or `Co-Authored-By:`.

## Typical session

The agent (Claude Code, OpenCode, ...) commits with **you as author** and
itself as committer, and records the session with `--statement pending`:

Git identity for agent commits -- author = you, committer = the agent:

- **Committer** is the same for everyone and comes with the repository for
  Claude Code (`.claude/settings.json`, `env`). Other harnesses set
  `GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL` the same way.
- **Author** is yours and never in the repository: set
  `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL` in your own configuration -- the
  environment variables of your Claude Code cloud environment, or `env` in
  `~/.claude/settings.json` for local sessions. If you forget, git uses
  `user.name`/`user.email`; in a cloud session that is the agent's own
  identity, and `verify` fails the commit for an AI author.

```sh
# what an agent session looks like (Claude Code sets these for you)
export GIT_AUTHOR_NAME="Your Name" GIT_AUTHOR_EMAIL="you@example.org"
export GIT_COMMITTER_NAME="Claude Code" GIT_COMMITTER_EMAIL="agent@agents.invalid"

python3 tools/prov.py declare --statement pending \
    --contrib opencode-pair@r1:implementer=src/racoon/isakmp.c,test/test_isakmp.c \
    --contrib opencode-pair@r1:reviewer \
    --scope code,tests  > /tmp/trailers
git commit -t /tmp/trailers        # no Signed-off-by: that is yours to add
```

Then you review the branch and approve it, in your own terminal (attest
refuses to run inside a Claude Code session):

```sh
python3 tools/prov.py attest --range origin/develop..HEAD --test "make check"
python3 tools/prov.py verify --range origin/develop..HEAD    # what CI runs
```

`attest` runs the tests (exit 0 required for `reviewed-and-tested`), shows
what you approve, adds your Signed-off-by to every commit in the range
(message-only rewrite; trees, author and committer unchanged), and commits
`.provenance/attestations/<YYYY>/<id>/<time>.json` **signed with your SSH
key**. The attestation lists each commit by `git patch-id --stable`:

- a later rebase keeps the approval valid, if you re-sign while rebasing
  (`git rebase --gpg-sign`, or `commit.gpgsign = true`);
- any change to a reviewed diff invalidates it: attest again;
- further commits of the same session need a further `attest`.

One-time setup: an SSH signing key (preferably on a hardware token) and its
public key in `.provenance/allowed_signers` -- see "Maintainer workstation"
below, including how to use an existing OpenPGP key.

CI reads `allowed_signers` from the **base** of a change, so a pull request
cannot admit its own key; a base without signers fails. Merge into
`develop` with merge commits: GitHub's rebase- and squash-merge recreate
commits without your signature.

## Retyped is still assisted

**Provenance follows the text, not the keyboard.** Whether the agent
committed its output, or you copied, retyped, pasted or edited it yourself,
makes no difference: if the agent's output is in the lines you commit, the
commit is assisted and carries the trailers. Your name as author and your
`Signed-off-by:` stay exactly where they are -- you are still the
accountable author; the trailers only say where the text came from.

The one-question test, before every commit:

> **Would these lines look like this if the agent had never answered?**
> No → declare it.

| Situation | Assisted? |
| --- | --- |
| The agent commits its own output | yes -- the agent declares it |
| You apply a file, snippet or patch the agent proposed, by hand | **yes** -- same `Provenance-Id` as the session, or `declare --reported-by manual` |
| You take the agent's draft and rework it | **yes**, as long as any of its output survives in the file |
| You start from the agent's draft and end up rewriting every line | no -- the final text is yours |
| The agent only searched, explained or reviewed; you wrote the lines | no -- need not be declared |
| A colleague's suggestion, a Stack Overflow snippet | not RFC 0005 -- license and attribution rules apply as before |

Why AI output is treated differently from a colleague or Stack Overflow:
a model repeats its mistakes. When one model is found to have a systematic
bug pattern, the recall drill (`prov query`) has to find **every** place its
output landed, across all contributors -- and an undeclared line is exactly
the line it cannot find.

Declaring is not a confession. There is no quota and no penalty for a high
AI share; the only commit that harms the project is the one that hides its
origin. List in the manifest only files whose committed content still
contains AI output.

## Guest contributions (pull requests from a fork)

**Strict where the maintainer works, light where guests work** (RFC 0005
§11). A guest whose pull request contains AI output writes one sentence in
the pull request, or as a trailer, naming tools, models and what they did --
for example `Assisted-by: Claude Code (Opus), review by GPT-5` -- and signs
off their own commits. Nothing else: no profile, manifest, `declare` or
`attest`. On fork pull requests `verify` is advisory: it stays green and
lists in the job summary what the maintainer will complete. Human-only
guest pull requests need nothing and may be merged directly.

### Intake (maintainer)

An AI-assisted guest pull request is never merged with the merge button.
Take it in through a branch in this repository instead:

```sh
python3 tools/prov.py intake --pr 151 \
    --guest-statement "Claude Code (Opus) wrote the fix, review by GPT-5" \
    --scope code,tests \
    --new-profile guest-jdoe --owner rdratlos \
    --role implementer=anthropic-claude:claude-opus-5-5 \
    --author "J. Doe <jdoe@example.org>"        # only if an agent was author
```

`intake` fetches the pull request into `intake/pr-<N>`, then

1. writes an **intake commit** on the base: a maintainer-owned profile
   mirroring the statement (`--new-profile`; or reuse one with
   `--profile ID@rN`, e.g. a contributor-kit profile) and a manifest with
   `model_reported_by = "manual"` listing every file the guest changed (an
   upper bound, stated as such);
2. rebuilds the guest's commits on it: original trees plus those files, so
   every diff and patch-id is unchanged; free-text `Assisted-by:`,
   `AI-Scope:`, `Provenance-Id:` and AI `Co-Authored-By:`/`Signed-off-by:`
   lines are replaced by canonical trailers; the guest's own
   `Signed-off-by:` stays; a commit whose author is an AI gets the guest
   (`--author`) as author of record.

For guest `code` in a critical path, run a review with a model from another
family yourself and add it with `--reviewed-by <profile>@rN` (the commits
then carry one `Assisted-by:` per profile). Then review, `prov attest`, push
the branch, open a pull request that says "supersedes #N", and merge it with
a merge commit. `intake` refuses guest commits that change `.provenance/`.

## Maintainer workstation

Attesting needs Git >= 2.34, OpenSSH >= 8.2, Python >= 3.11 (and GnuPG >= 2.2
for an OpenPGP key). That is the workstation that signs approvals, not a
platform racoon supports: racoon still builds and runs down to Ubuntu Bionic,
which cannot attest.

### SSH signing with an existing OpenPGP key (gpg-agent)

gpg-agent can serve your OpenPGP signing (sub)key as an SSH key, so you keep
one key. Tested with Git 2.34 and later.

```sh
# 1. signing (sub)key [S]: fingerprint and keygrip
gpg -K --with-subkey-fingerprint --with-keygrip <you@example.org>
FPR=<fingerprint of the [S] key>; KEYGRIP=<its keygrip>

# 2. public key as an SSH file ("!" = exactly this subkey, even without [A])
mkdir -p ~/.ssh && chmod 700 ~/.ssh
gpg --export-ssh-key "${FPR}"'!' > ~/.ssh/git-signing.pub

# 3. gpg-agent as ssh-agent for this key
echo enable-ssh-support >> ~/.gnupg/gpg-agent.conf
echo "$KEYGRIP" >> ~/.gnupg/sshcontrol
gpgconf --kill gpg-agent
cat >> ~/.bashrc <<'EOF'
export GPG_TTY=$(tty)
export SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"
gpg-connect-agent updatestartuptty /bye >/dev/null
EOF
. ~/.bashrc; ssh-add -L          # must show the key from step 2

# 4. git, in this repository only (OpenPGP signing elsewhere is unaffected)
git config gpg.format ssh
git config user.signingkey ~/.ssh/git-signing.pub   # a path: works from Git 2.34
git config gpg.ssh.allowedSignersFile "$(git rev-parse --show-toplevel)/.provenance/allowed_signers"

# 5. the allowed_signers line, added by a reviewed commit on develop
printf '%s %s %s\n' <you@example.org> "$(cut -d' ' -f1,2 ~/.ssh/git-signing.pub)" \
    "openpgp:0x${FPR: -16}"

# 6. test
git commit --allow-empty -S -m "signing test" && git log -1 --format='%G? %GS'
git reset --hard HEAD~1          # expected above: "G <you@example.org>"
```

Use a path for `user.signingkey`: the inline `key::ssh-ed25519 ...` form
needs Git >= 2.35, and Git 2.34 reads it as a file name.

| Message | Cause |
| --- | --- |
| `Couldn't get agent socket?` | `SSH_AUTH_SOCK` not set in this shell (step 3) |
| `Couldn't find key in agent?` | keygrip missing from `sshcontrol`, or another subkey's |
| `agent refused operation?` | gpg-agent cannot show pinentry here: `gpg-connect-agent updatestartuptty /bye`; on a headless machine install `pinentry-curses` |
| `Couldn't load public key ...` followed by the key text | `user.signingkey` is not read as a key: quotes in the stored value, or `key::` on Git 2.34 -- use the path form |
| `%G?` is `U` | e-mail in `allowed_signers` does not match the key |
| `%G?` is `N`, or an `allowedSignersFile` error | the path from step 4 is wrong, or the file has no line for the key yet |

`prov verify` always checks signatures with plain `ssh-keygen`, whatever
`gpg.ssh.program` you configured for signing.

## Layout

| Path | What | Mutability |
| --- | --- | --- |
| `policy.toml` | baseline, allowed scopes, critical paths, rules | reviewed like code |
| `schema/*.schema.json` | manifest and profile schemas (v1, frozen) | new major = new file |
| `profiles/<id>/r<N>.toml` | which model per role in a setup | **immutable**; change = `r<N+1>` |
| `manifests/<YYYY>/<id>.json` | one per AI-assisted session; may bind a capture log by `session.capture.log_digest` | **immutable** |
| `attestations/<YYYY>/<id>/<time>.json` | human approval, in a signed commit | **immutable** |
| `allowed_signers` | SSH keys allowed to sign approvals | reviewed like code |
| `legacy-map.toml` | maps pre-policy free-text trailers for `query` | editable |

## Profiles and confidential models

A profile names a setup, not a vendor in your commit message. If your
organisation does not disclose a model, use `disclosure = "withheld"` with a
neutral `model_id` that your organisation resolves internally. Withheld
models may not write files under the critical paths in `policy.toml`,
because nobody outside your organisation could act on a recall.

## Recall drill

```sh
python3 tools/prov.py query --model 'qwen3-coder' --blame --include-legacy
```

lists every commit and file a model contributed to and how many of its lines
survive at `HEAD`.

## Running a captured session

A *captured session* is a normal AI-assisted session that additionally
records **what the API and router actually answered** -- so the manifest can
say what was *observed*, not only what was *configured*. Two independent
capture sources feed `prov declare --evidence`; each proves a different
trust level (`model_reported_by`). Use the capture proxy for the strong
`api` / `router` evidence; the OpenCode plugin alone only ever sees the
configured model and so yields `config`.

**1. Capture proxy (strongest evidence -- what answered behind the router).**

```sh
# start the loopback proxy; TLS verification stays ON by default
python3 tools/provcap-proxy.py \
    --listen localhost:8787 \
    --upstream https://router.example.org/v1 \
    --log capture.jsonl
```

Point the harness at `http://localhost:8787/v1` -- **`localhost`, never
`127.0.0.1`**: corporate `no_proxy` lists carry `localhost` verbatim but
often only the CIDR `127.0.0.0/8`, which many env-proxy matchers do not
expand, so the harness would otherwise send loopback to the web proxy
(`503`/`403`). Each completion is appended to `capture.jsonl` as one JSON
object with the requested model, the response-claimed model, any router
deployment headers, and the `endpoint` origin the upstream hop finally
reached (observed, not configured; absent when the connection failed --
declare then records no endpoint, never a guess).

**2. OpenCode plugin (harness side -- configured model and edited files).**

`.opencode/plugin/provpaws-capture.ts` writes one JSON-lines log per session
under `.provpaws/sessions/` (git-ignored working data). It only ever sees the
*configured* model, so it is `config` evidence: good for the file-touch list,
never on its own proof of what answered.

**3. Declare, binding the evidence into the manifest (schema v2):**

```sh
python3 tools/prov.py declare --schema-version 2.0 --statement pending \
    --session-ref opencode:provcap-live-20261022 \
    --evidence capture-log:capture.jsonl \
    --evidence opencode-session:.provpaws/sessions/opencode-<id>.jsonl \
    --contrib <profile>@r<N>:implementer=src/racoon/isakmp.c \
    --scope code > /tmp/trailers
git commit -t /tmp/trailers
```

`capture-log:` raises `model_reported_by` to `api` (plain provider) or, when
deployment headers were seen, `router` (which needs schema v2). The manifest
then carries a `session.capture` block recording the log's `log_digest`, the
request count, the observed window and endpoints -- a **digest**, never the
log itself. Capture logs stay local working data: `verify` re-checks a
manifest against the digest, so the full log does not have to be committed or
kept; the raw capture may live in your scratch directory and be discarded
once declared.

