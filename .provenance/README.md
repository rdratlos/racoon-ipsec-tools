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
public key in `.provenance/allowed_signers`:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519_sk.pub
```

CI reads `allowed_signers` from the **base** of a change, so a pull request
cannot admit its own key. Merge into `develop` with merge commits: GitHub's
rebase- and squash-merge recreate commits without your signature.

List only files whose committed content still contains AI output. Models you
only used for searching or explaining need not be declared.

## Layout

| Path | What | Mutability |
| --- | --- | --- |
| `policy.toml` | baseline, allowed scopes, critical paths, rules | reviewed like code |
| `schema/*.schema.json` | manifest and profile schemas (v1, frozen) | new major = new file |
| `profiles/<id>/r<N>.toml` | which model per role in a setup | **immutable**; change = `r<N+1>` |
| `manifests/<YYYY>/<id>.json` | one per AI-assisted session | **immutable** |
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
