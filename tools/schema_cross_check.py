#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors

"""Verify share/schema/racoonctl-status.schema.json's x-source-config/
x-source-render provenance annotations against the actual source they cite
(src/racoon/cftoken.l, src/racoon/strnames.c).

Each annotated schema property carries a free-text citation of the form
"path:line (identifier[, extra])", e.g.:

    "x-source-config": "src/racoon/cftoken.l:388 (encryption_algorithm, S_RMTP)"
    "x-source-render": "src/racoon/strnames.c:659 (s_attr_isakmp_enc)"

This script parses every such citation, reads the cited file at (a window
around) the cited line, and confirms the named identifier actually appears
there. It exists to catch citation drift -- a future edit to cftoken.l or
strnames.c that shifts line numbers or renames/removes the cited symbol,
silently making the schema's provenance claims wrong, exactly the kind of
drift doc/dev/racoonctl-status-analysis.md's D5 entry already found once by
hand ("off by 4 lines... immaterial", a citation that happened to still be
close enough to spot manually; nothing guarantees the next one will be).

Deliberately scoped to citation freshness, not full semantic enum-value
parity between racoon's config-accepted algorithm keywords (cftoken.l) and
its rendered display strings (strnames.c). Config tokens are the argument
grammar (snake_case, e.g. "hmac_sha2_256"); render strings are display
output (e.g. "SHA256") -- the two are never expected to match textually,
and building a real correspondence check would mean tracing every
algtype_* config keyword through algorithm.c's algtype2doi() to the DOI
constant strnames.c actually keys its tables on. That is a larger, useful
follow-up in its own right (and the natural place to actually catch a gap
like the AES/AES-CBC or hmac-sha/hmac-sha1 naming looseness noted during
issue #139/#140's live testing, tracked separately) -- not something to
fake here with a shallow, either-always-fails or never-checks-anything
comparison that would create false confidence rather than real coverage.
"""

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "share" / "schema" / "racoonctl-status.schema.json"

CITATION_RE = re.compile(r"^(?P<path>\S+):(?P<line>\d+)\s+\((?P<ident>[^,)]+)")

# How many lines around the cited one to tolerate -- generous enough to
# survive minor drift (an intervening comment, a nearby edit) without
# masking a citation that's actually gone stale.
WINDOW = 5


def iter_annotations(node, pointer=""):
    """Yield (json_pointer, keyword, citation) for every x-source-* key
    found anywhere in the schema document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("x-source-config", "x-source-render"):
                yield pointer, key, value
            else:
                yield from iter_annotations(value, f"{pointer}/{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from iter_annotations(value, f"{pointer}/{i}")


def check_citation(pointer, keyword, citation):
    m = CITATION_RE.match(citation)
    if not m:
        return False, f"citation does not match 'path:line (identifier)': {citation!r}"

    path = REPO_ROOT / m.group("path")
    line_no = int(m.group("line"))
    ident = m.group("ident").strip()

    if not path.is_file():
        return False, f"cited file does not exist: {m.group('path')}"

    lines = path.read_text().splitlines()
    lo = max(0, line_no - 1 - WINDOW)
    hi = min(len(lines), line_no - 1 + WINDOW + 1)
    window_text = "\n".join(lines[lo:hi])

    if ident not in window_text:
        return False, (
            f"{m.group('path')}:{line_no}: identifier {ident!r} not found "
            f"within {WINDOW} lines of the cited line -- citation has drifted"
        )
    return True, f"{m.group('path')}:{line_no}: {ident!r} confirmed"


def main():
    if not SCHEMA_PATH.is_file():
        print(f"error: schema not found at {SCHEMA_PATH}", file=sys.stderr)
        return 1

    schema = json.loads(SCHEMA_PATH.read_text())

    annotations = list(iter_annotations(schema))
    if not annotations:
        print("error: no x-source-config/x-source-render annotations found "
              "-- expected at least one", file=sys.stderr)
        return 1

    failures = 0
    for pointer, keyword, citation in annotations:
        ok, message = check_citation(pointer, keyword, citation)
        status = "OK  " if ok else "FAIL"
        print(f"[{status}] {pointer} {keyword}: {message}")
        if not ok:
            failures += 1

    print(f"\n{len(annotations)} citations checked, {failures} failed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
