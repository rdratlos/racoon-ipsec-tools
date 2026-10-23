# RFC 0005 — OpenCode Pairing Provenance: QA Review pack

First QA review of the OpenCode + KITCH provenance prototype (RFC 0005 Phase 1).
Review prepared 2026-10-23. **Committed to `develop` via the RFC 0005 workflow.**

Intended repository layout once accepted:

```
docs/research/
  rfc0005-opencode-pairing-provenance-capture.md   # source task brief (verbatim)
  rfc0005-opencode-pairing-review/
    README.md                                       # this file
    status-report.md                                # progress vs the task's requests
    honest-prototype-implementation-report.md       # design + provenance + trust grades
```

## Contents

- [`rfc0005-opencode-pairing-provenance-capture.md`](./rfc0005-opencode-pairing-provenance-capture.md)
  — the capture task, reproduced verbatim (lives one level up in `docs/research/`).
- [`status-report.md`](./status-report.md) — request-by-request coverage table
  (implemented / partial / deferred with reasons), completed work, activities
  pulled forward from later phases, planned next steps, limitations.
- [`honest-prototype-implementation-report.md`](./honest-prototype-implementation-report.md)
  — design, extended manifest format, QA-readable provenance summary, and a
  three-class (Verified / API-Router-observed / Config-Declared) trust grade for
  every manifest evidence with source and purpose.

## Headline

The router label `KITCH-Coder` is **not** a backend model: the first real
captured session shows one label served by several real deployments. The
prototype's value is capturing that configured-vs-actual gap honestly, with a
digest-bound evidence log, an additive schema 2.0, and human SSH attestation —
while leaving the true backend identity explicitly unknown because no trusted
source asserts it.

## Branch references

The prototype this review describes is **not** on `develop`; it lives on two
pushed branches, visible to everyone:

- [`feature/opencode-pairing-provenance`](https://github.com/rdratlos/racoon-ipsec-tools/tree/feature/opencode-pairing-provenance)
  — prototype code (plugin, `provcap-proxy.py`, `prov.py` evidence wiring,
  schema v2, `harness_cross_check.py`). Tip `65fe1b9`; 8 commits in
  `origin/develop..origin/feature/opencode-pairing-provenance`.
- [`docs/rfc-0005-api-trust`](https://github.com/rdratlos/racoon-ipsec-tools/tree/docs/rfc-0005-api-trust)
  — the RFC 0005 schema-2.0 prose diff, based on `main`. Tip `70c98e0`; 1 commit
  in `origin/main..origin/docs/rfc-0005-api-trust`.

## Status caveat

Branch/SHA hygiene is reconciled and **both prototype branches are now pushed**:
`develop` is the feature parent, `main` the docs parent, the old duplicates are
unreferenced, and `git rebase --gpg-sign` re-signed every commit to `G`. One
honest caveat remains and is documented, not yet fixed: rebasing **orphans the
manifest↔commit SHA binding** (the `...-<sha>` name still names now-gone pre-
rebase SHAs, and `prov verify` does not catch it) — see Honest Report §8.
