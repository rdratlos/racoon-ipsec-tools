# AI provenance (RFC 0005 "provpaws")

This directory records **which AI models produced output that entered the
repository**, in a tool-neutral format that lives with the code. The design
and its rationale are in `docs/rfcs/0005-provpaws-ai-provenance.md` (on
`main`). This file is the short version for contributors.

## The rule in one paragraph

A human is always the author and the only one who signs off. If AI output
ends up in your commit, add three trailers and a manifest. `tools/prov.py
declare` writes the manifest and prints the trailers for you; CI
(`develop-provenance.yml`) checks the result.

```
Assisted-by: <profile>@r<N> [analysis tools]
AI-Scope: code, tests
Provenance-Id: 20261012T081500Z-3f9a1c2e
Signed-off-by: Your Name <you@example.org>
```

Never put an AI in `Signed-off-by:` or `Co-Authored-By:`.

## Typical session

```sh
# after the AI session, before committing:
python3 tools/prov.py declare \
    --contrib opencode-pair@r1:implementer=src/racoon/isakmp.c,test/test_isakmp.c \
    --contrib opencode-pair@r1:reviewer \
    --scope code,tests  > /tmp/trailers
git commit -s -t /tmp/trailers     # or paste the printed lines
python3 tools/prov.py verify       # same check CI runs
```

List only files whose committed content still contains AI output. Models you
only used for searching or explaining need not be declared.

## Layout

| Path | What | Mutability |
| --- | --- | --- |
| `policy.toml` | baseline, allowed scopes, critical paths, rules | reviewed like code |
| `schema/*.schema.json` | manifest and profile schemas (v1, frozen) | new major = new file |
| `profiles/<id>/r<N>.toml` | which model per role in a setup | **immutable**; change = `r<N+1>` |
| `manifests/<YYYY>/<id>.json` | one per AI-assisted session | **immutable** |
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
