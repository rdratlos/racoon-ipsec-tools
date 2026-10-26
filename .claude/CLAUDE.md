# Agent rules for this repository

## AI provenance (RFC 0005, `.provenance/README.md`)

Every commit that contains your output is recorded; CI (`develop-provenance.yml`)
checks it.

- **Guiding Principles.** Read provenance principles in file .provenance/PRINCIPLES.md.
  Especially section Rules for Agents. Make sure that you have a thorough understanding
  of the principles and their strategic rationale.
- **Identity.** Commit with the human as author and yourself as committer.
  The committer comes from `.claude/settings.json`; the author from the
  contributor's own `GIT_AUTHOR_NAME`/`GIT_AUTHOR_EMAIL` (cloud environment
  variables or `~/.claude/settings.json`). If those are unset, stop and ask:
  an AI author fails `verify`.
- **Never** add `Signed-off-by:` or `Co-Authored-By:`, and never run
  `prov attest`: approval is the human's signed act.
- **Per session**, before the first commit:
  `python3 tools/prov.py declare --statement pending --contrib <profile>@r<N>:<role>=<files> --scope <scopes>`.
  It writes and stages the manifest and prints the trailers. Put them in every
  commit of the session, before any other trailers:
  `Assisted-by:`, `AI-Scope:`, `Provenance-Id:`.
  Keep the manifest's `files` list in step with later commits of the session.
- **Profile.** Use the profile whose model matches the one you run on. If none
  matches, ask; profiles are immutable once merged, so changes are a new `r<N+1>`.
- **Before pushing**: `python3 -m unittest tools/test_prov.py` and
  `python3 tools/prov.py verify --range origin/develop..HEAD`. Until the human
  attests, the only expected failures are the missing human `Signed-off-by:`
  and "not covered by a valid attestation".
- **After the human attests**, they force-push your branch. Resync with
  `git fetch && git reset --hard origin/<branch>` before doing anything else,
  and don't push while they are attesting.
