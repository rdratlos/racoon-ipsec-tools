#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors

"""Emit GitHub Actions annotations from GCC/SARIF deprecation diagnostics.

Deliberately not a second diagnostics parser: this reuses parse_gcc_json()
and parse_sarif() from gen_deprecation_report.py -- the same functions
that already turn merge_gcc_json.py's merged JSON (or a GCC >= 13 SARIF
file) into {file, line, col, message, hint} records for the HTML report --
and just formats those records as `::warning file=...::` workflow commands
instead of HTML rows. If the parsing logic ever changes (a new GCC
diagnostic field, a SARIF schema bump), there is exactly one place to fix
it.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_deprecation_report import parse_gcc_json, parse_sarif  # noqa: E402


def escape(text):
    # GitHub workflow-command property/message escaping.
    return (text.replace("%", "%25")
                .replace("\r", "%0D")
                .replace("\n", "%0A"))


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*",
                         help="diagnostic files (.gcc.json or .sarif)")
    parser.add_argument("--format", required=True, choices=["sarif", "gcc.json"])
    parser.add_argument("--source-root", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    parser_fn = parse_sarif if args.format == "sarif" else parse_gcc_json

    warnings = []
    for path in args.files:
        warnings.extend(parser_fn(path, args.source_root))

    for w in warnings:
        message = w["message"]
        if w["hint"] and w["hint"] != "—":
            message += " [hint: %s]" % w["hint"]
        print("::warning file=%s,line=%s,col=%s,title=Deprecated OpenSSL API::%s" %
              (w["file"], w["line"], w["col"], escape(message)))

    print("Emitted %d annotation(s)." % len(warnings), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
