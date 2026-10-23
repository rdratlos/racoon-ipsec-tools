#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2026 Thomas Reim and the racoon-ipsec-tools contributors

"""harness_cross_check: harness config vs .provenance profiles (RFC 0005 §7).

Compares the AI harness configuration committed in the repository with the
provenance profiles it claims to use, so a pinned model cannot drift
silently from the record:

  - every `.opencode/agent/*.md` `model:` pin must be the `model_id` of a
    role in a profile with `harness = "opencode"`;
  - every `provider.<p>.models.<m>` id in `.opencode/opencode.json` must
    appear as some opencode profile's `model_id`;
  - the same for `.claude/settings.json` `model` keys, matched against
    profiles with `harness = "claude-code"`.

Profile fields are read with a small regex over `key = "value"` lines: a
profile is simple TOML and this keeps the checker runnable on python3.6,
including the Ubuntu Bionic build hosts. Harness config files are
optional; absent files are skipped. Exit 0 with only notes, 1 on any
mismatch. Stdlib only.

Usage: python3 tools/harness_cross_check.py [--rev REV]
"""

import argparse
import json
import os
import re
import subprocess
import sys

PROFILES = ".provenance/profiles"
HARNESS_KEYS = {"opencode": "opencode", "claude": "claude-code",
                "claude-code": "claude-code"}


def git_show(rev, path):
    r = subprocess.run(["git", "show", f"{rev}:{path}"],
                       capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def git_ls(rev, prefix):
    r = subprocess.run(["git", "ls-tree", "--name-only", "-r",
                        f"{rev}", "--", prefix], capture_output=True,
                       text=True)
    return r.stdout.split() if r.returncode == 0 else []


def toml_str(text, key):
    m = re.search(rf'^{key}\s*=\s*"([^"]*)"', text, re.M)
    return m.group(1) if m else None


def role_models(text):
    """[(role_name, model_id)] from a profile TOML, regex-based."""
    out = []
    for block in re.findall(r"\[\[roles\]\](.*?)(?=\[\[|\Z)", text, re.S):
        name, mid = toml_str(block, "name"), toml_str(block, "model_id")
        if mid:
            out.append((name or "?", mid))
    return out


def all_profiles(rev):
    """[(ref, harness, [(role, model_id)])] for harness profiles at rev."""
    out = []
    for path in git_ls(rev, PROFILES):
        m = re.match(r"^(.+)/([^/]+)/r([0-9]+)\.toml$", path)
        text = git_show(rev, path) if m else None
        if text is None:
            continue
        harness = (toml_str(text, "harness") or "").lower()
        if harness not in HARNESS_KEYS.values():
            continue
        ref = f"{m.group(2)}@r{m.group(3)}"
        out.append((ref, harness, role_models(text)))
    return out


def load_json(rev, path):
    text = git_show(rev, path)
    if text is None and os.path.exists(path):
        text = open(path, encoding="utf-8").read()
    if text is None:
        return None
    try:
        text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
        return json.loads(text)
    except json.JSONDecodeError as e:
        return {"_error": str(e)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", default="HEAD")
    args = ap.parse_args(argv)

    profiles_at = all_profiles(args.rev)
    ids, by_ref = {}, {}
    for ref, harness, roles in profiles_at:
        for role, mid in roles:
            ids.setdefault(harness, set()).add(mid)
            by_ref.setdefault(harness, set()).add(ref)

    fails, notes = [], []

    def check(what, model, harness):
        known = ids.get(harness, set())
        if not known:
            notes.append(f"{what}: no {harness} profiles; skipped")
        elif model not in known:
            where = ", ".join(sorted(by_ref.get(harness, []))) or "none"
            fails.append(f"{what}: model '{model}' is not the model_id of "
                         f"any role in {harness} profiles ({where})")
        else:
            notes.append(f"{what}: '{model}' matches a role in "
                         f"{', '.join(sorted(by_ref.get(harness, [])))}")

    for path in git_ls(args.rev, ".opencode/agent"):
        if not path.endswith(".md"):
            continue
        text = git_show(args.rev, path) or ""
        m = re.search(r"^model:\s*(\S+)\s*$", text, re.M)
        if m:
            check(path, m.group(1), "opencode")

    cfg = load_json(args.rev, ".opencode/opencode.json")
    if cfg is not None:
        if "_error" in (cfg or {}):
            fails.append(f".opencode/opencode.json: invalid JSON: "
                         f"{cfg['_error']}")
        else:
            for prov in (cfg.get("provider") or {}).values():
                for mid in (prov.get("models") or {}):
                    check(".opencode/opencode.json provider model",
                          mid, "opencode")

    cfg = load_json(args.rev, ".claude/settings.json")
    if cfg is not None and "_error" not in cfg:
        if cfg.get("model"):
            check(".claude/settings.json", cfg["model"], "claude-code")

    for n in notes:
        print(f"[OK  ] {n}")
    for f in fails:
        print(f"[FAIL] {f}")
    print(f"harness cross-check: {len(notes)} match(es), {len(fails)} "
          f"failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
