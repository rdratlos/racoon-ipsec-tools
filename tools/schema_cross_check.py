#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors

"""Guard share/schema/racoonctl-status.schema.json against drifting away
from the source it describes. Two independent checks:

1. The x-source-config/x-source-render provenance annotations, verified
   against the actual source they cite (src/racoon/cftoken.l,
   src/racoon/strnames.c, src/racoon/status.c) -- see below.

2. schema_version consistency. That value is authored once, as
   RACOONCTL_STATUS_SCHEMA_VERSION in src/racoon/status.h; status.c's
   renderer and test/test_status_dump.c both build their strings from that
   macro, so those two cannot drift. The remaining two copies are not C and
   cannot include the header -- this file's own
   properties.schema_version.const, and the worked JSON example in
   src/racoon/racoonctl.1.in -- so they are compared against the macro
   here. A bump that moves some copies but not all fails this script rather
   than shipping a daemon and a published schema that disagree about what
   they speak.

Both checks report in the same [OK  ]/[FAIL] style and either failing makes
the script exit non-zero.

--- provenance annotations ---

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
HEADER_PATH = REPO_ROOT / "src" / "racoon" / "status.h"
MANPAGE_PATH = REPO_ROOT / "src" / "racoon" / "racoonctl.1.in"

CITATION_RE = re.compile(r"^(?P<path>\S+):(?P<line>\d+)\s+\((?P<ident>[^,)]+)")

# status.h's single C-side source of truth for schema_version. status.c's
# renderer and test_status_dump.c's assertion both build their strings from
# this macro, so those two copies cannot drift; the schema file's "const"
# and the man page's worked example are JSON and mdoc, cannot include a C
# header, and are held to it here instead.
VERSION_DEFINE_RE = re.compile(
    r'^[ \t]*#[ \t]*define[ \t]+RACOONCTL_STATUS_SCHEMA_VERSION[ \t]+"([^"]*)"',
    re.MULTILINE,
)
# The worked JSON example in racoonctl.1.in, e.g. '  "schema_version": "2.0",'
MANPAGE_VERSION_RE = re.compile(r'"schema_version"[ \t]*:[ \t]*"([^"]*)"')

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


def read_header_version():
    """The value of RACOONCTL_STATUS_SCHEMA_VERSION in status.h, or None."""
    if not HEADER_PATH.is_file():
        return None, f"header not found at src/racoon/status.h"
    m = VERSION_DEFINE_RE.search(HEADER_PATH.read_text())
    if m is None:
        return None, ("src/racoon/status.h: no "
                      "'#define RACOONCTL_STATUS_SCHEMA_VERSION \"...\"' found "
                      "-- the C-side source of truth is missing or was renamed")
    return m.group(1), None


def read_manpage_versions():
    """Every schema_version string in racoonctl.1.in's worked example.

    Returned as a list so a page carrying two different values (an example
    updated in one place but not another) is reported rather than silently
    passing on whichever happened to be found first."""
    if not MANPAGE_PATH.is_file():
        return None, "man page not found at src/racoon/racoonctl.1.in"
    found = MANPAGE_VERSION_RE.findall(MANPAGE_PATH.read_text())
    if not found:
        return None, ("src/racoon/racoonctl.1.in: no \"schema_version\": \"...\" "
                      "in the worked JSON example -- expected one")
    return found, None


def check_schema_version(schema):
    """Confirm status.h, the schema's const, and the man page example all
    name the same schema_version.

    Returns (checks_run, failures) and prints one line per check in the
    same [OK  ]/[FAIL] style as the citation checks above."""
    checks = 0
    failures = 0

    header_version, err = read_header_version()
    if err is not None:
        print(f"[FAIL] schema_version source: {err}")
        return 1, 1
    print(f"[OK  ] schema_version source: src/racoon/status.h defines "
          f"{header_version!r}")
    checks += 1

    const = schema.get("properties", {}).get("schema_version", {}).get("const")
    checks += 1
    if const is None:
        print("[FAIL] schema_version const: "
              "share/schema/racoonctl-status.schema.json has no "
              "properties.schema_version.const to compare against")
        failures += 1
    elif const != header_version:
        print(f"[FAIL] schema_version const: schema file says {const!r} but "
              f"src/racoon/status.h defines {header_version!r} -- the daemon "
              f"and its published schema would disagree on the wire")
        failures += 1
    else:
        print(f"[OK  ] schema_version const: schema file agrees ({const!r})")

    versions, err = read_manpage_versions()
    checks += 1
    if err is not None:
        print(f"[FAIL] schema_version manpage: {err}")
        failures += 1
    else:
        distinct = sorted(set(versions))
        if len(distinct) > 1:
            print(f"[FAIL] schema_version manpage: racoonctl.1.in names more "
                  f"than one version in its example(s): {distinct} -- expected "
                  f"all to be {header_version!r}")
            failures += 1
        elif distinct[0] != header_version:
            print(f"[FAIL] schema_version manpage: racoonctl.1.in's example "
                  f"says {distinct[0]!r} but src/racoon/status.h defines "
                  f"{header_version!r} -- the documented example would not "
                  f"match what the daemon emits")
            failures += 1
        else:
            print(f"[OK  ] schema_version manpage: racoonctl.1.in agrees "
                  f"({distinct[0]!r})")

    return checks, failures


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

    print()
    version_checks, version_failures = check_schema_version(schema)
    print(f"\n{version_checks} schema_version copies checked, "
          f"{version_failures} failed.")

    return 1 if (failures or version_failures) else 0


if __name__ == "__main__":
    sys.exit(main())
