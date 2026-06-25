#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors

"""Generate a deprecation-warning report from GCC diagnostics.

Supports two diagnostic formats:
  - 'gcc.json' : GCC's native JSON diagnostic format (GCC 9-12)
  - 'sarif'    : SARIF 2.1.0, emitted by -fdiagnostics-format=sarif-file (GCC >= 13)
"""

import argparse
import datetime
import html
import json
import os
import re
import sys
from collections import defaultdict
from urllib.parse import urlparse, unquote


RULE_ID = "-Wdeprecated-declarations"

SYMBOL_RE = re.compile(r"^'([^']+)' is deprecated(?::\s*use '([^']+)' instead)?")


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*",
                         help="diagnostic files (.gcc.json or .sarif)")
    parser.add_argument("--format", required=True, choices=["sarif", "gcc.json"])
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--source-root", required=True)
    return parser.parse_args()


def to_relpath(path, source_root):
    try:
        return os.path.relpath(path, source_root)
    except ValueError:
        return path


def extract_hint(message):
    m = SYMBOL_RE.match(message)
    if m:
        return m.group(1), m.group(2) or ""
    return "", ""


def parse_gcc_json(path, source_root):
    warnings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        print("warning: skipping unparseable file %s: %s" % (path, exc), file=sys.stderr)
        return warnings

    if isinstance(data, dict):
        data = [data]

    for diag in data:
        if diag.get("kind") != "warning":
            continue
        if diag.get("option") != RULE_ID:
            continue
        locations = diag.get("locations") or []
        if not locations:
            continue
        caret = locations[0].get("caret", {})
        file_path = caret.get("file")
        if file_path is None:
            continue
        line = caret.get("line", 0)
        col = caret.get("column", 0)
        message = diag.get("message", "")

        hint = "—"
        for child in diag.get("children", []) or []:
            if child.get("kind") == "note":
                hint = child.get("message", "—")
                break

        warnings.append({
            "file": to_relpath(file_path, source_root),
            "line": line,
            "col": col,
            "message": message,
            "hint": hint,
        })
    return warnings


def parse_sarif(path, source_root):
    warnings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        print("warning: skipping unparseable file %s: %s" % (path, exc), file=sys.stderr)
        return warnings

    for run in data.get("runs", []) or []:
        for result in run.get("results", []) or []:
            if result.get("ruleId") != RULE_ID:
                continue
            if result.get("level") != "warning":
                continue
            locations = result.get("locations") or []
            if not locations:
                continue
            phys = locations[0].get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            uri = artifact.get("uri", "")
            if uri.startswith("file://"):
                file_path = unquote(urlparse(uri).path)
            else:
                file_path = uri
            region = phys.get("region", {})
            line = region.get("startLine", 0)
            col = region.get("startColumn", 0)
            message = result.get("message", {}).get("text", "")

            hint = "—"
            related = result.get("relatedLocations") or []
            if related:
                rel_msg = related[0].get("message", {}).get("text")
                if rel_msg:
                    hint = rel_msg

            warnings.append({
                "file": to_relpath(file_path, source_root),
                "line": line,
                "col": col,
                "message": message,
                "hint": hint,
            })
    return warnings


def dedup_and_group(warnings):
    seen = set()
    groups = defaultdict(list)
    for w in warnings:
        key = (w["file"], w["line"], w["col"], w["message"])
        if key in seen:
            continue
        seen.add(key)
        groups[w["file"]].append(w)

    for items in groups.values():
        items.sort(key=lambda w: (w["line"], w["col"]))

    return dict(sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True))


def write_text_report(path, groups):
    total = sum(len(w) for w in groups.values())
    with open(path, "w") as f:
        if not groups:
            f.write("No -Wdeprecated-declarations warnings found.\n")
            return
        for file_name, warnings in groups.items():
            for w in warnings:
                hint_suffix = ""
                if w["hint"] and w["hint"] != "—":
                    hint_suffix = " [hint: %s]" % w["hint"]
                f.write("%s:%s:%s: deprecated: %s%s\n" %
                        (file_name, w["line"], w["col"], w["message"], hint_suffix))
        f.write("\n── Total: %d warnings across %d files ──\n" %
                (total, len(groups)))


def write_html_report(path, groups, fmt):
    total = sum(len(w) for w in groups.values())
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    style = """
    body { font-family: sans-serif; margin: 2em; background: #f8f8f8; color: #222; }
    h1 { border-bottom: 2px solid #444; padding-bottom: 0.3em; }
    h2 { margin-top: 2em; border-bottom: 1px solid #ccc; padding-bottom: 0.2em; }
    .summary { color: #555; margin-bottom: 1.5em; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 1em; background: #fff; }
    th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top; }
    th { background: #444; color: #fff; }
    tr:nth-child(even) { background: #f2f2f2; }
    code { background: #eee; padding: 1px 4px; border-radius: 3px; }
    footer { margin-top: 2em; color: #888; font-size: 0.85em; }
    a { color: #06c; text-decoration: none; }
    """

    parts = []
    parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    parts.append("<title>OpenSSL Deprecation Report</title>")
    parts.append("<style>%s</style></head><body>" % style)
    parts.append("<h1>OpenSSL Deprecation Report</h1>")
    parts.append("<div class='summary'>Total warnings: <b>%d</b> across <b>%d</b> files"
                  " &mdash; Generated: %s</div>" % (total, len(groups), html.escape(timestamp)))

    if not groups:
        parts.append("<p>No -Wdeprecated-declarations warnings found.</p>")
    else:
        parts.append("<table><tr><th>File</th><th>Warning Count</th><th>% of Total</th></tr>")
        for idx, (file_name, warnings) in enumerate(groups.items()):
            pct = 100.0 * len(warnings) / total if total else 0
            anchor = "file-%d" % idx
            parts.append("<tr><td><a href='#%s'>%s</a></td><td>%d</td><td>%.1f%%</td></tr>" %
                          (anchor, html.escape(file_name), len(warnings), pct))
        parts.append("</table>")

        for idx, (file_name, warnings) in enumerate(groups.items()):
            anchor = "file-%d" % idx
            parts.append("<h2 id='%s'>%s</h2>" % (anchor, html.escape(file_name)))
            parts.append("<table><tr><th>Line</th><th>Col</th><th>Deprecated Symbol</th>"
                          "<th>Message</th><th>Replacement Hint</th></tr>")
            for w in warnings:
                symbol, replacement = extract_hint(w["message"])
                hint = w["hint"] if w["hint"] and w["hint"] != "—" else "—"
                if replacement:
                    hint = replacement
                parts.append(
                    "<tr><td>%s</td><td>%s</td><td><code>%s</code></td>"
                    "<td>%s</td><td><code>%s</code></td></tr>" %
                    (w["line"], w["col"],
                     html.escape(symbol) if symbol else "—",
                     html.escape(w["message"]),
                     html.escape(hint)))
            parts.append("</table>")

    parts.append("<footer>Generated by tools/gen_deprecation_report.py "
                  "(diagnostic format: %s)</footer>" % html.escape(fmt))
    parts.append("</body></html>")

    with open(path, "w") as f:
        f.write("\n".join(parts))


def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    if not args.files:
        print("No diagnostic files given; nothing to report.")
        write_text_report(os.path.join(args.output_dir, "deprecation-report.txt"), {})
        write_html_report(os.path.join(args.output_dir, "index.html"), {}, args.format)
        return 0

    parser_fn = parse_sarif if args.format == "sarif" else parse_gcc_json

    warnings = []
    for path in args.files:
        warnings.extend(parser_fn(path, args.source_root))

    groups = dedup_and_group(warnings)

    write_text_report(os.path.join(args.output_dir, "deprecation-report.txt"), groups)
    write_html_report(os.path.join(args.output_dir, "index.html"), groups, args.format)

    print("Found %d deprecation warning(s) across %d file(s)." %
          (sum(len(w) for w in groups.values()), len(groups)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
