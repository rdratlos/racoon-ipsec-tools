#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors

"""Parse a `make check-valgrind` log into JSON findings for annotations.

Reads test/Makefile.am's check-valgrind output (valgrind run with
--leak-check=full --show-leak-kinds=all --track-origins=yes
--error-exitcode=1 per test binary, wrapped in "Testing <binary>..."
markers) from stdin, and writes a JSON array of
{binary, message, file, line} to stdout -- one entry per block that would
have tripped valgrind's own --error-exitcode (definitely/indirectly lost
blocks, invalid read/write, use of uninitialised value, mismatched
free/delete). "Still reachable"/"possibly lost" blocks are informational
under --show-leak-kinds=all and don't fail the build on their own, so
they're deliberately not reported here -- annotating them would just be
noise disconnected from what actually made the job fail.

`file`/`line` come from the first stack frame in the block that has
source location info (valgrind only has that for frames in code built
with -g, i.e. this project's own binaries, not system libraries) --
`None` if no such frame exists, meaning the caller should fall back to a
plain (non-annotation) mention rather than guessing a location.
"""

import json
import re
import sys

CURRENT_TEST_RE = re.compile(r'^Testing (\S+)\.\.\.$')
PID_LINE_RE = re.compile(r'^==\d+==\s?(.*)$')
BLOCK_HEADER_RE = re.compile(
    r'^\d[\d,]* bytes? in \d+ blocks? are (definitely|indirectly) lost'
    r'|^Invalid (read|write) of size \d+'
    r'|^Conditional jump or move depends on uninitialised value'
    r'|^Use of uninitialised value'
    r"|^Mismatched free\(\)"
    r'|^Syscall param .* points to (unaddressable|uninitialised) byte'
)
FRAME_FILE_RE = re.compile(r'\(([^()]+\.c):(\d+)\)')


def parse(text):
    findings = []
    current_test = None
    block_header = None
    block_file = None
    block_line = None

    def flush():
        if block_header is not None:
            findings.append({
                "binary": current_test,
                "message": block_header,
                "file": block_file,
                "line": block_line,
            })

    for raw in text.splitlines():
        m = CURRENT_TEST_RE.match(raw)
        if m:
            flush()
            current_test = m.group(1)
            block_header = None
            block_file = None
            block_line = None
            continue

        m = PID_LINE_RE.match(raw)
        if not m:
            continue
        content = m.group(1)

        if content == "":
            flush()
            block_header = None
            block_file = None
            block_line = None
            continue

        if BLOCK_HEADER_RE.search(content):
            flush()
            block_header = content
            block_file = None
            block_line = None
            continue

        if block_header is not None and block_file is None:
            fm = FRAME_FILE_RE.search(content)
            if fm:
                block_file = fm.group(1)
                block_line = int(fm.group(2))

    flush()
    return findings


def main():
    text = sys.stdin.read()
    findings = parse(text)
    json.dump(findings, sys.stdout)
    sys.stdout.write("\n")
    print("Parsed %d valgrind finding(s)." % len(findings), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
