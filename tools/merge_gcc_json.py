#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors

"""Merge GCC JSON diagnostics captured from stderr into a single JSON array.

GCC 9-11 emit -fdiagnostics-format=json to stderr, one JSON array per
compilation unit.  This script filters the JSON lines from mixed stderr
output (which also contains libtool messages) and merges them into a
single consolidated array."""

import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True,
                        help="raw stderr log file")
    parser.add_argument("--output", required=True,
                        help="output consolidated JSON file")
    args = parser.parse_args()

    merged = []
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("["):
                continue
            try:
                arr = json.loads(line)
                merged.extend(arr)
            except (json.JSONDecodeError, ValueError):
                continue

    with open(args.output, "w") as f:
        json.dump(merged, f)

    print("Merged %d diagnostic(s) from stderr into %s" % (len(merged), args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
