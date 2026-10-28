# Agent rules on `develop`

For every AI agent, whichever harness it runs in. Loaded together with
`AGENTS.md` and `.provenance/PRINCIPLES.md`: Claude Code loads it through
`.claude/CLAUDE.md`, OpenCode through `.opencode/opencode.json`. The
procedure in detail is in `.provenance/README.md`. When this file and
the principles disagree, the principles win (`AGENTS.md` §1).

## Before you start

- Know the principles. For provenance work in particular, the section
  "Rules for Agents Working on Provenance" in `.provenance/PRINCIPLES.md`
  applies.
- Check your identity (`AGENTS.md` §3). If the author is unset or is an
  AI identity, stop and ask: an AI author fails `verify`.
- **Profile.** Ask the human which profile (`<id>@r<N>`) and role apply
  to this session, unless the task already names them. Do not choose a
  profile from what you believe your model is (principle 11). If no
  profile fits, ask. Profiles are immutable once merged, so a change
  means a new revision `r<N+1>`.

## Once per session, before the first commit

```sh
python3 tools/prov.py declare --statement pending --reported-by manual \
    --contrib <profile>@r<N>:<role>=<file>,<file> --scope <scopes>
```

- `declare` writes and stages the manifest and prints the trailers. Put
  them in **every** commit of the session, before any other trailers, in
  this order: `Assisted-by:`, `AI-Scope:`, `Provenance-Id:`.
- `--reported-by manual` says that the model comes from a declaration,
  not from a tool. Use `config` only where a tool has read the model from
  the harness configuration, and `api` or `router` only with
  `--evidence` (principles 11, 12).
- `files` lists every file whose committed content contains your output,
  including docs. Keep the list up to date with later commits of the
  session. Do not list files you only read.
- `--statement pending`, always. `reviewed` and `reviewed-and-tested` are
  for the human alone.

## During the session

- Every commit that contains your output carries the trailers, including
  fixes to your own work. After a rebase or an amend, check that the
  trailers are still there (`git log --format=%B`).
- Do not commit capture logs, transcripts or prompts (`.provpaws/`,
  `provcap.jsonl` are git-ignored).

## Before you push

```sh
python3 -m unittest tools/test_prov.py
python3 tools/prov.py verify --range "$(git merge-base origin/develop HEAD)..HEAD"
```

Until the human has attested, the only expected failures are the missing
human `Signed-off-by:` and "not covered by a valid attestation". Report
anything else, or any check you could not run (for example, no
`ssh-keygen`), as such. Do not present it as passed.

## Never

- Run `prov attest`, sign commits (`git commit -S`, `rebase --gpg-sign`)
  or use the human's signing key, even when the key is technically
  reachable, for example through a cached agent socket (principle 14).
- Write a model identity from what you believe about yourself into a
  commit, manifest, profile or report (principle 11).
- Describe weaknesses, commits or behaviour that you have not observed.
  Cite file and line, commit or command output, and mark anything
  unchecked as unchecked.
- Call your own reports QA. Label them as self-assessments.

## After the human has attested

The human force-pushes your branch. Before you do anything else:

```sh
git fetch && git reset --hard origin/<branch>
```

Do not push while the human is attesting.
