#!/usr/bin/env python3
"""Q1 of the RFC 0005 Phase 3 investigation: how were the AI trailers on a
branch produced?

Reads every non-merge commit reachable from REV (default origin/develop)
that carries an AI attribution trailer, groups the commits by trailer
variant, committer and companion trailers, and classifies the probable
production mechanism from the repository state at the commit's first
parent (the configuration the session ran with):

  hook      .claude/settings.json at the parent contains the PostToolUse
            hook that rewrites "Co-Authored-By:" into "Assisted-by:"
  declare   canonical profile reference (tools/prov.py declare)

The rules are printed with the result (--rules). Needs a full clone
(`git fetch --unshallow`), Python >= 3.8, git. Read-only.

usage: q1_trailer_history.py [--rev origin/develop] [--json] [--rules]
"""
import argparse
import collections
import json
import re
import subprocess
import sys

AI_KEYS = re.compile(r"^(assisted-by|co-authored-by)$", re.I)
AI_VALUE = re.compile(r"claude|opencode|anthropic|qwen|kitch|gpt|gemini|@r\d+\b",
                      re.I)
HOOK_MARK = "s/Co-Authored-By:/Assisted-by:/"
HARNESS_NAME = re.compile(r"^Claude(?: (?:Opus|Sonnet|Haiku|Fable) [0-9.]+)?$")

RULES = """\
Mechanism rules (first match wins), evaluated per trailer:
  declare        value is a profile reference <id>@r<N>                  -> prov declare (Phase 1)
  harness-raw    key Co-Authored-By, value '<harness name> <noreply@...>' -> Claude Code default trailer, not rewritten
                 (hook-active=no: no hook in that checkout; yes: hook did not run, e.g. --amend or cloud quirks)
  hook-rewrite   key 'Assisted-by', value '<harness name> <noreply@...>',
                 hook active at parent                                    -> Claude Code default trailer rewritten by the hook
  harness-copy   key not canonical ('Assisted-By') or hook not active,
                 value '<harness name> <noreply@...>'                    -> harness attribution text copied/retyped (agent or human)
  edited         value 'Claude <family> <n>' that the harness cannot emit
                 (e.g. 'Sonet')                                           -> typed or edited by a human
  agent-template value 'OpenCode:<...>' with a literal '<placeholder>'   -> agent filled an instruction template, placeholder left
  agent-self     value 'OpenCode:<model>'                                -> model name written by the agent/human; no repo config backs it
  unknown        anything else
"Harness name" is the set Claude Code documents for its default trailer:
'Claude' alone, or 'Claude <Family> <version>' (settings-reference, attribution.commit).
"""


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True,
                          text=True).stdout


def trailers(sha):
    out = git("log", "-1", "--format=%(trailers:only,unfold)", sha)
    res = []
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            res.append((k.strip(), v.strip()))
    return res


def file_at(rev, path):
    r = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True,
                       text=True)
    return r.stdout if r.returncode == 0 else None


def classify(key, value, hook_active):
    bare = re.sub(r"\s*<[^>]*@[^>]*>\s*$", "", value).strip()
    has_mail = bare != value.strip()
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*@r[1-9][0-9]*(\s.*)?", value):
        return "declare"
    if HARNESS_NAME.match(bare) and has_mail:
        if key.lower() == "co-authored-by":
            return "harness-raw"
        if key == "Assisted-by" and hook_active:
            return "hook-rewrite"
        return "harness-copy"
    if re.match(r"^Claude\b", bare):
        return "edited"
    if re.match(r"^OpenCode:", bare):
        return "agent-template" if re.search(r"<[^>@]*>", value) else "agent-self"
    return "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", default="origin/develop")
    ap.add_argument("--json", action="store_true", help="per-commit JSON lines")
    ap.add_argument("--rules", action="store_true")
    args = ap.parse_args()
    if git("rev-parse", "--is-shallow-repository").strip() == "true":
        sys.exit("shallow clone: run `git fetch --unshallow` first")
    if args.rules:
        print(RULES)

    main_tip = git("rev-parse", "--verify", "-q", "origin/main").strip()
    on_main = set(git("rev-list", main_tip).split()) if main_tip else set()
    hook_cache = {}
    rows = []
    fmt = "%H%x1f%h%x1f%as%x1f%cs%x1f%an <%ae>%x1f%cn <%ce>%x1f%P%x1f%s"
    for line in git("log", "--no-merges", f"--format={fmt}", args.rev).splitlines():
        sha, short, adate, cdate, author, committer, parents, subject = \
            line.split("\x1f")
        trs = trailers(sha)
        ai = [(k, v) for k, v in trs if AI_KEYS.match(k) and AI_VALUE.search(v)]
        if not ai:
            continue
        parent = parents.split()[0] if parents else None
        if parent not in hook_cache:
            s = file_at(parent, ".claude/settings.json") if parent else None
            hook_cache[parent] = {
                "hook": bool(s and HOOK_MARK in s),
                "attribution": bool(s and '"attribution"' in s),
            }
        cfg = hook_cache[parent]
        keys = {k for k, _ in trs}
        for k, v in ai:
            rows.append({
                "commit": short, "author_date": adate, "commit_date": cdate,
                "author": author, "committer": committer, "subject": subject,
                "key": k, "value": re.sub(r"<[^>]*@[^>]*>", "<email>", v),
                "claude_session": "Claude-Session" in keys,
                "provenance_id": "Provenance-Id" in keys,
                "signed_off": "Signed-off-by" in keys,
                "hook_active": cfg["hook"],
                "attribution_setting": cfg["attribution"],
                "also_on_main": sha in on_main,
                "mechanism": classify(k, v, cfg["hook"]),
            })

    if args.json:
        for r in rows:
            print(json.dumps(r))
        return

    commits = {r["commit"] for r in rows}
    total = int(git("rev-list", "--no-merges", "--count", args.rev))
    print(f"# {args.rev}: {total} non-merge commits, {len(commits)} with AI "
          f"trailers, {len(rows)} AI trailer lines\n")

    def committer_class(c):
        if "agents.invalid" in c:
            return "agent-id"
        if "anthropic" in c.lower():
            return "Claude"
        return "human"

    groups = collections.OrderedDict()
    for r in sorted(rows, key=lambda r: (r["mechanism"], r["key"], r["value"])):
        g = (r["mechanism"], f'{r["key"]}: {r["value"]}',
             committer_class(r["committer"]), r["claude_session"],
             r["hook_active"])
        groups.setdefault(g, []).append(r)
    print("| mechanism | trailer | committer | Claude-Session | hook at parent | "
          "commits | author-date range | examples |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for (mech, tr, comm, sess, hook), rs in groups.items():
        dates = sorted(r["author_date"] for r in rs)
        ex = ", ".join(r["commit"] for r in rs[:3])
        print(f"| {mech} | `{tr}` | {comm} | {'yes' if sess else 'no'} | "
              f"{'yes' if hook else 'no'} | {len(rs)} | {dates[0]} .. {dates[-1]} "
              f"| {ex} |")

    print("\n## By mechanism")
    by = collections.Counter(r["mechanism"] for r in rows)
    for m, n in by.most_common():
        print(f"- {m}: {n}")
    print("\n## Hook active at parent vs. trailer key")
    c = collections.Counter((r["hook_active"], r["key"]) for r in rows)
    for (h, k), n in sorted(c.items()):
        print(f"- hook={'yes' if h else 'no'}, key={k}: {n}")


if __name__ == "__main__":
    main()
