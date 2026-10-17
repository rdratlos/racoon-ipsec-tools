#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2026 Thomas Reim and the racoon-ipsec-tools contributors

"""AI provenance tooling for RFC 0005 ("provpaws").

Everything this tool knows lives in the Git repository:

  .provenance/policy.toml               rules (baseline, scopes, critical paths)
  .provenance/schema/*.schema.json      manifest and profile schemas
  .provenance/profiles/<id>/r<N>.toml   immutable agent profiles
  .provenance/manifests/<YYYY>/<id>.json  one manifest per AI-assisted session
  .provenance/attestations/<YYYY>/<id>/<time>.json  human approval (signed)
  .provenance/allowed_signers           SSH keys allowed to sign approvals
  .provenance/legacy-map.toml           free-text trailers before the baseline

and in commit trailers:

  Assisted-by: <profile>@r<N> [tool ...]
  AI-Scope: <scope>[, <scope> ...]
  Provenance-Id: <id>
  Signed-off-by: <human>

Subcommands:

  verify   check trailers, manifests, profiles and policy over a commit range
  declare  write a manifest for the current work and print the trailers
  attest   human approval: sign-off, test evidence, signed approval commit
  query    find commits/files a model or profile contributed to (recall drill)

Tool-neutral by design: no subcommand depends on Claude Code, OpenCode or any
other harness. Adapters for those tools only have to produce what `declare`
produces. Output follows tools/schema_cross_check.py: [OK  ] / [WARN] / [FAIL]
lines, non-zero exit on any FAIL.

Requires Python >= 3.11 (tomllib) and, for `verify`, the jsonschema package.
"""

import argparse
import datetime
import fnmatch
import json
import os
import re
import secrets
import subprocess
import sys
import tomllib

PROV_DIR = ".provenance"
PROFILE_RE = re.compile(r"^([a-z0-9][a-z0-9-]*)@r([1-9][0-9]*)$")
PROFILE_PATH_RE = re.compile(
    r"^\.provenance/profiles/([a-z0-9][a-z0-9-]*)/r([1-9][0-9]*)\.toml$")
MANIFEST_PATH_RE = re.compile(
    r"^\.provenance/manifests/([0-9]{4})/([0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})\.json$")
PROVID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
ATTEST_PATH_RE = re.compile(
    r"^\.provenance/attestations/([0-9]{4})/([0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})/"
    r"([0-9]{8}T[0-9]{6}Z)\.json$")
EMAIL_RE = re.compile(r"\s*<[^>]*>\s*")


# --------------------------------------------------------------------------
# reporting

class Report:
    def __init__(self, quiet=False):
        self.fails = 0
        self.warns = 0
        self.quiet = quiet

    def ok(self, msg):
        if not self.quiet:
            print(f"[OK  ] {msg}")

    def warn(self, msg):
        self.warns += 1
        print(f"[WARN] {msg}")

    def fail(self, msg):
        self.fails += 1
        print(f"[FAIL] {msg}")


# --------------------------------------------------------------------------
# git helpers

class Git:
    def __init__(self, root=None):
        if root is None:
            root = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"], check=True,
                capture_output=True, text=True).stdout.strip()
        self.root = root

    def run(self, *args, check=True, stdin=None, env=None):
        p = subprocess.run(["git", "-C", self.root, *args], input=stdin,
                           capture_output=True, text=True, env=env)
        if check and p.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)}: {p.stderr.strip()}")
        return p

    def out(self, *args, **kw):
        return self.run(*args, **kw).stdout

    def exists(self, rev):
        return self.run("cat-file", "-e", rev, check=False).returncode == 0

    def show(self, rev, path):
        p = self.run("show", f"{rev}:{path}", check=False)
        return p.stdout if p.returncode == 0 else None

    def ls_tree(self, rev, path):
        p = self.run("ls-tree", "-r", rev, "--", path, check=False)
        result = {}
        if p.returncode != 0:
            return result
        for line in p.stdout.splitlines():
            meta, name = line.split("\t", 1)
            result[name] = meta.split()[2]
        return result

    def is_ancestor(self, a, b):
        return self.run("merge-base", "--is-ancestor", a, b,
                        check=False).returncode == 0

    def commits(self, rev_range):
        args = ["rev-list", "--no-merges", "--reverse"]
        args += rev_range.split() if " " in rev_range else [rev_range]
        return self.out(*args).split()

    def message(self, c):
        return self.out("show", "-s", "--format=%B", c)

    def subject(self, c):
        return self.out("show", "-s", "--format=%s", c).strip()

    def changed_files(self, c):
        return set(self.out("diff-tree", "--no-commit-id", "--name-only",
                            "-r", "--root", c).split("\n")) - {""}

    def patch_id(self, c):
        """git patch-id --stable: identifies a commit by its diff, so it
        survives rebase and cherry-pick but not a change to the diff."""
        cache = self.__dict__.setdefault("_pid_cache", {})
        if c not in cache:
            diff = self.out("show", "--no-color", "--binary",
                            "--pretty=format:commit %H", c)
            out = self.out("patch-id", "--stable", stdin=diff).split()
            cache[c] = out[0] if out else "empty"
        return cache[c]

    def ident(self, c):
        f = self.out("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce", c)
        an, ae, cn, ce = f.rstrip("\n").split("\x00")
        return {"author": (an, ae), "committer": (cn, ce)}

    def trailers(self, c):
        """Return [(key, value)] exactly as written (case preserved)."""
        text = self.out("interpret-trailers", "--parse", "--unfold",
                        stdin=self.message(c))
        result = []
        for line in text.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                result.append((k.strip(), v.strip()))
        return result


# --------------------------------------------------------------------------
# loading repository data

def load_toml_text(text, what, report):
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        report.fail(f"{what}: invalid TOML: {e}")
        return None


def load_policy(git, report, rev=None):
    path = f"{PROV_DIR}/policy.toml"
    text = git.show(rev, path) if rev else _read(git, path)
    if text is None:
        report.fail(f"{path}: missing")
        return None
    return load_toml_text(text, path, report)


def _read(git, rel):
    try:
        with open(os.path.join(git.root, rel), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def load_schema(git, name):
    text = _read(git, f"{PROV_DIR}/schema/{name}")
    return json.loads(text) if text else None


def validator_for(schema):
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return None
    return Draft202012Validator(schema)


def schema_errors(validator, doc):
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in sorted(validator.iter_errors(doc), key=str)]


def profile_path(ref):
    m = PROFILE_RE.match(ref)
    return f"{PROV_DIR}/profiles/{m.group(1)}/r{m.group(2)}.toml" if m else None


def manifest_path(provid):
    return f"{PROV_DIR}/manifests/{provid[:4]}/{provid}.json"


def profile_role(profile, role_name):
    for r in profile.get("roles", []):
        if r.get("name") == role_name:
            return r
    return None


def is_critical(path, policy):
    return any(fnmatch.fnmatch(path, g)
               for g in policy.get("critical", {}).get("paths", []))


# --------------------------------------------------------------------------
# verify

def verify_tree(git, report, policy, head):
    """Profiles, manifests and legacy map as they exist at `head`."""
    pschema = load_schema(git, "profile-v1.schema.json")
    mschema = load_schema(git, "manifest-v1.schema.json")
    if pschema is None or mschema is None:
        report.fail(f"{PROV_DIR}/schema: profile/manifest schema missing")
        return
    aschema = load_schema(git, "attestation-v1.schema.json")
    pv, mv = validator_for(pschema), validator_for(mschema)
    av = validator_for(aschema) if aschema else None
    if pv is None:
        report.fail("jsonschema not installed (pip install jsonschema, or "
                    "apt install python3-jsonschema)")
        return

    tree = git.ls_tree(head, f"{PROV_DIR}/")
    n_prof = n_man = n_att = 0
    for path in sorted(tree):
        if path.startswith(f"{PROV_DIR}/profiles/"):
            m = PROFILE_PATH_RE.match(path)
            if not m:
                report.fail(f"{path}: not of the form profiles/<id>/r<N>.toml")
                continue
            doc = load_toml_text(git.show(head, path), path, report)
            if doc is None:
                continue
            errs = schema_errors(pv, doc)
            for e in errs:
                report.fail(f"{path}: {e}")
            if errs:
                continue
            if doc["id"] != m.group(1) or doc["revision"] != int(m.group(2)):
                report.fail(f"{path}: id/revision do not match the file path")
                continue
            names = [r["name"] for r in doc["roles"]]
            if len(names) != len(set(names)):
                report.fail(f"{path}: duplicate role names")
                continue
            n_prof += 1
        elif path.startswith(f"{PROV_DIR}/manifests/"):
            if path.endswith("/.gitkeep"):
                continue
            m = MANIFEST_PATH_RE.match(path)
            if not m:
                report.fail(f"{path}: not of the form manifests/<YYYY>/<id>.json")
                continue
            try:
                doc = json.loads(git.show(head, path))
            except json.JSONDecodeError as e:
                report.fail(f"{path}: invalid JSON: {e}")
                continue
            errs = schema_errors(mv, doc)
            for e in errs:
                report.fail(f"{path}: {e}")
            if errs:
                continue
            if doc["provenance_id"] != m.group(2) or m.group(1) != m.group(2)[:4]:
                report.fail(f"{path}: provenance_id does not match the file path")
                continue
            n_man += 1
        elif path.startswith(f"{PROV_DIR}/attestations/"):
            m = ATTEST_PATH_RE.match(path)
            if not m:
                report.fail(f"{path}: not of the form "
                            f"attestations/<YYYY>/<id>/<time>.json")
                continue
            if av is None:
                report.fail(f"{path}: attestation schema missing")
                continue
            try:
                doc = json.loads(git.show(head, path))
            except json.JSONDecodeError as e:
                report.fail(f"{path}: invalid JSON: {e}")
                continue
            errs = schema_errors(av, doc)
            for e in errs:
                report.fail(f"{path}: {e}")
            if errs:
                continue
            if (doc["provenance_id"] != m.group(2) or doc["attested"] != m.group(3)
                    or m.group(1) != m.group(2)[:4]):
                report.fail(f"{path}: provenance_id/attested do not match the "
                            f"file path")
                continue
            n_att += 1
    report.ok(f"{n_prof} profile revision(s), {n_man} manifest(s), "
              f"{n_att} attestation(s) valid against schema v1")

    legacy = git.show(head, f"{PROV_DIR}/legacy-map.toml")
    if legacy is not None:
        doc = load_toml_text(legacy, "legacy-map.toml", report)
        if doc is not None:
            for entry in doc.get("map", []):
                try:
                    re.compile(entry["pattern"])
                except (KeyError, re.error) as e:
                    report.fail(f"legacy-map.toml: bad entry {entry}: {e}")


def verify_immutability(git, report, base, head):
    """Profile revisions and manifests are append-only records."""
    if base is None:
        report.ok("no base revision: immutability check skipped")
        return
    before = git.ls_tree(base, f"{PROV_DIR}/profiles/")
    for sub in ("manifests", "attestations"):
        before.update({k: v for k, v in git.ls_tree(base, f"{PROV_DIR}/{sub}/").items()
                       if not k.endswith(".gitkeep")})
    after = git.ls_tree(head, f"{PROV_DIR}/")
    bad = 0
    for path, blob in sorted(before.items()):
        if path not in after:
            report.fail(f"{path}: deleted (profile revisions and manifests are "
                        f"immutable; retire a profile with a new revision)")
            bad += 1
        elif after[path] != blob:
            report.fail(f"{path}: modified (create a new revision instead)")
            bad += 1
    if not bad:
        report.ok(f"{len(before)} existing profile/manifest/attestation "
                  f"file(s) unchanged")


def verify_commits(git, report, policy, commits, base=None, head="HEAD"):
    tcfg = policy.get("trailers", {})
    k_ass = tcfg.get("assisted", "Assisted-by")
    k_scope = tcfg.get("scope", "AI-Scope")
    k_prov = tcfg.get("provenance", "Provenance-Id")
    scopes_ok = set(tcfg.get("allowed_scopes", []))
    ai_res = [re.compile(p, re.I) for p in tcfg.get("ai_identity_patterns", [])]
    baseline = policy.get("enforcement", {}).get("baseline")
    if baseline and not git.exists(f"{baseline}^{{commit}}"):
        report.warn(f"baseline {baseline[:12]} not present in this clone "
                    f"(shallow?); all commits in range are checked")
        baseline = None
    need_signoff = policy.get("enforcement", {}).get(
        "require_signoff_on_assisted", True)
    acfg = policy.get("attestation", {})
    if acfg.get("required") and acfg.get("dco") == "approval-commit":
        need_signoff = False    # policy (a): the approval commit carries it

    sessions = {}   # provid -> {"commits": [...], "files": set(), "scopes": set()}
    checked = exempt = assisted = 0

    for c in commits:
        short = c[:12]
        if baseline and git.is_ancestor(c, baseline):
            exempt += 1
            continue
        checked += 1
        trailers = git.trailers(c)
        lower = {}
        for k, v in trailers:
            lower.setdefault(k.lower(), []).append((k, v))

        # canonical spelling of our own keys
        for canon in (k_ass, k_scope, k_prov):
            for k, _ in lower.get(canon.lower(), []):
                if k != canon:
                    report.fail(f"{short}: trailer key '{k}' must be spelled '{canon}'")

        # AI identities where only humans belong
        for key in ("signed-off-by", "co-authored-by"):
            for k, v in lower.get(key, []):
                if any(r.search(v) for r in ai_res):
                    report.fail(f"{short}: '{k}: {v}' names an AI; use "
                                f"{k_ass} (RFC 0005) -- only humans sign off "
                                f"or co-author")

        ass = [v for _, v in lower.get(k_ass.lower(), [])]
        scope = [v for _, v in lower.get(k_scope.lower(), [])]
        prov = [v for _, v in lower.get(k_prov.lower(), [])]

        if not ass:
            if scope or prov:
                report.fail(f"{short}: {k_scope}/{k_prov} without {k_ass}")
            continue
        assisted += 1

        an, ae = git.ident(c)["author"]
        if any(r.search(f"{an} <{ae}>") for r in ai_res):
            report.fail(f"{short}: author '{an} <{ae}>' is an AI identity -- "
                        f"the author of record is the accountable human; the "
                        f"agent may appear as committer")

        refs = []
        for v in ass:
            ref = v.split()[0] if v.split() else ""
            if not PROFILE_RE.match(ref):
                report.fail(f"{short}: '{k_ass}: {v}' -- first token must be "
                            f"a profile reference <id>@r<N>")
                continue
            if git.show(c, profile_path(ref)) is None:
                report.fail(f"{short}: profile {ref} not found in the commit's "
                            f"tree ({profile_path(ref)})")
                continue
            refs.append(ref)

        if len(scope) != 1:
            report.fail(f"{short}: exactly one {k_scope} trailer required "
                        f"(found {len(scope)})")
            cscopes = set()
        else:
            cscopes = {s.strip() for s in scope[0].split(",") if s.strip()}
            unknown = cscopes - scopes_ok
            if unknown or not cscopes:
                report.fail(f"{short}: {k_scope} '{scope[0]}' -- allowed: "
                            f"{', '.join(sorted(scopes_ok))}")

        if need_signoff:
            humans = [v for _, v in lower.get("signed-off-by", [])
                      if not any(r.search(v) for r in ai_res)]
            if not humans:
                report.fail(f"{short}: AI-assisted commit without a human "
                            f"Signed-off-by")

        if len(prov) != 1 or not PROVID_RE.match(prov[0]):
            report.fail(f"{short}: exactly one well-formed {k_prov} trailer "
                        f"required (found {prov or 'none'})")
            continue
        pid = prov[0]
        mtext = git.show(c, manifest_path(pid))
        if mtext is None:
            report.fail(f"{short}: manifest {manifest_path(pid)} not in the "
                        f"commit's tree")
            continue
        s = sessions.setdefault(pid, {"commits": [], "files": set(),
                                      "scopes": set(), "manifest": mtext,
                                      "rev": c})
        s["commits"].append(c)
        s["files"] |= git.changed_files(c)
        s["scopes"] |= cscopes
        try:
            mdoc = json.loads(mtext)
        except json.JSONDecodeError:
            report.fail(f"{short}: manifest {pid} is not valid JSON")
            continue
        mprofiles = {x.get("profile") for x in mdoc.get("contributions", [])}
        for ref in refs:
            if ref not in mprofiles:
                report.fail(f"{short}: {k_ass} {ref} has no contribution in "
                            f"manifest {pid}")

    report.ok(f"{checked} commit(s) checked, {assisted} AI-assisted, "
              f"{exempt} exempt (at or before baseline)")

    signers = None
    if acfg.get("required") and sessions:
        signers = allowed_signers_text(git, report, policy, base, head)
    for pid, s in sorted(sessions.items()):
        verify_session(git, report, policy, pid, s)
        if acfg.get("required"):
            verify_attestation(git, report, policy, pid, s, head, signers)


def verify_session(git, report, policy, pid, s):
    try:
        mdoc = json.loads(s["manifest"])
    except json.JSONDecodeError:
        return
    before = report.fails
    sub_mode = policy.get("enforcement", {}).get("substitution", "warn")
    if (mdoc.get("human_review", {}).get("statement") == "pending"
            and not policy.get("attestation", {}).get("required")):
        report.fail(f"manifest {pid}: human_review.statement is 'pending' -- "
                    f"the accountable human must review and set it to "
                    f"'reviewed' or 'reviewed-and-tested' before merge")
    crit = policy.get("critical", {})
    writers_critical = []   # (contribution, family)
    reviewers = []

    for i, contrib in enumerate(mdoc.get("contributions", [])):
        where = f"manifest {pid} contribution[{i}]"
        ref = contrib.get("profile", "")
        ptext = git.show(s["rev"], profile_path(ref) or "")
        if ptext is None:
            report.fail(f"{where}: profile {ref} not found")
            continue
        try:
            profile = tomllib.loads(ptext)
        except tomllib.TOMLDecodeError:
            report.fail(f"{where}: profile {ref} is invalid TOML")
            continue
        role = profile_role(profile, contrib.get("role"))
        if role is None:
            report.fail(f"{where}: role '{contrib.get('role')}' not defined "
                        f"in profile {ref}")
            continue
        model = contrib.get("model", {})
        if model.get("family") != role["model_family"]:
            report.fail(f"{where}: model family '{model.get('family')}' != "
                        f"profile {ref} role '{role['name']}' family "
                        f"'{role['model_family']}'")
        if model.get("id") != role["model_id"]:
            msg = (f"{where}: model '{model.get('id')}' differs from profile "
                   f"{ref} role '{role['name']}' ('{role['model_id']}')")
            if contrib.get("model_reported_by") == "api":
                (report.fail if sub_mode == "fail" else report.warn)(
                    msg + " -- provider substitution?")
            else:
                report.fail(msg + " -- configured/declared model must match "
                            "the profile; create a new profile revision")

        files = contrib.get("files", [])
        missing = sorted(set(files) - s["files"])
        if missing:
            report.fail(f"{where}: claims files not changed by any commit "
                        f"referencing {pid}: {', '.join(missing)}")
        crit_files = [f for f in files if is_critical(f, policy)]
        if crit_files:
            if role["disclosure"] == "withheld" and crit.get(
                    "forbid_withheld_in_critical", True):
                report.fail(f"{where}: withheld model wrote critical file(s) "
                            f"{', '.join(crit_files)}")
            writers_critical.append(role["model_family"])
        if contrib.get("role") == "reviewer":
            reviewers.append(role["model_family"])

    needs = set(crit.get("require_dissimilar_review_for_scopes", []))
    if writers_critical and (s["scopes"] & needs):
        ok = [f for f in reviewers if f not in set(writers_critical)]
        if not ok:
            report.fail(f"manifest {pid}: AI output in critical paths "
                        f"(scope {', '.join(sorted(s['scopes'] & needs))}) "
                        f"requires a 'reviewer' contribution from a model "
                        f"family other than {', '.join(sorted(set(writers_critical)))}")
    if report.fails == before:
        report.ok(f"manifest {pid}: consistent with {len(s['commits'])} "
                  f"commit(s) and policy")


def attestation_path(pid, attested):
    return f"{PROV_DIR}/attestations/{pid[:4]}/{pid}/{attested}.json"


def allowed_signers_text(git, report, policy, base, head):
    """Allowed signers come from the BASE of the range, so a change cannot
    admit its own key. Bootstrap: no file at base -> the change's own file,
    with a warning."""
    path = policy.get("attestation", {}).get(
        "allowed_signers", f"{PROV_DIR}/allowed_signers")
    text = git.show(base, path) if base else None
    if text is None or not _signer_lines(text):
        text = git.show(head, path)
        if text is not None and _signer_lines(text):
            report.warn(f"{path}: not present (or empty) at the base of the "
                        f"range -- bootstrap: using the change's own file")
    return text if text and _signer_lines(text) else None


def _signer_lines(text):
    return [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]


def commit_signature(git, sha, signers_text):
    """(status, principal) of a commit signature, checked against an
    allowed-signers text. Status letters as git's %G? ('G' = good)."""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".allowed_signers",
                                     delete=False) as f:
        f.write(signers_text or "")
        tmp = f.name
    try:
        out = git.out("-c", f"gpg.ssh.allowedSignersFile={tmp}", "log", "-1",
                      "--format=%G?%x00%GS", sha, check=False)
    finally:
        os.unlink(tmp)
    status, _, principal = out.strip().partition("\x00")
    return status or "N", principal


def session_attestations(git, head, pid):
    """[(path, doc, adding_commit)] for all attestations of pid at head."""
    prefix = f"{PROV_DIR}/attestations/{pid[:4]}/{pid}/"
    result = []
    for path in sorted(git.ls_tree(head, prefix)):
        if not ATTEST_PATH_RE.match(path):
            continue
        try:
            doc = json.loads(git.show(head, path))
        except (json.JSONDecodeError, TypeError):
            continue
        added = git.out("log", "--diff-filter=A", "--format=%H", head, "--",
                        path).split()
        result.append((path, doc, added[-1] if added else None))
    return result


def verify_attestation(git, report, policy, pid, s, head, signers):
    acfg = policy.get("attestation", {})
    tcfg = policy.get("trailers", {})
    ai_res = [re.compile(p, re.I) for p in tcfg.get("ai_identity_patterns", [])]
    before = report.fails
    approved = {}
    for path, doc, sha in session_attestations(git, head, pid):
        if sha is None:
            report.fail(f"{path}: cannot find the commit that added it")
            continue
        where = f"attestation {path.rsplit('/', 1)[-1]} ({sha[:12]})"
        if any(r.search(doc.get("reviewer", "")) for r in ai_res):
            report.fail(f"{where}: reviewer '{doc.get('reviewer')}' is an AI identity")
            continue
        if acfg.get("require_signature", True):
            if signers is None:
                report.fail(f"{where}: no allowed signers configured "
                            f"({acfg.get('allowed_signers', '.provenance/allowed_signers')})")
                continue
            status, principal = commit_signature(git, sha, signers)
            if status != "G":
                report.fail(f"{where}: approval commit is not signed by an "
                            f"allowed key (signature status '{status}')")
                continue
            if principal != doc.get("reviewer"):
                report.fail(f"{where}: signed by '{principal}', but reviewer is "
                            f"'{doc.get('reviewer')}'")
                continue
        if acfg.get("dco") == "approval-commit":
            sobs = [v for k, v in git.trailers(sha) if k.lower() == "signed-off-by"]
            if not any(doc.get("reviewer", "") in v for v in sobs):
                report.fail(f"{where}: dco = approval-commit requires the "
                            f"reviewer's Signed-off-by on the approval commit")
                continue
        for entry in doc.get("commits", []):
            approved[entry["patch_id"]] = doc.get("statement")

    for c in s["commits"]:
        pid_c = git.patch_id(c)
        if pid_c not in approved:
            report.fail(f"{c[:12]}: not covered by a valid attestation of {pid} "
                        f"(never attested, or its diff changed after approval) "
                        f"-- run `prov attest`")
    if report.fails == before:
        report.ok(f"attestation {pid}: {len(s['commits'])} commit(s) approved "
                  f"by a signed human attestation")


def default_range(git, policy):
    p = git.run("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}",
                check=False)
    if p.returncode == 0:
        return f"{p.stdout.strip()}..HEAD"
    base = policy.get("enforcement", {}).get("baseline")
    return f"{base}..HEAD" if base else "HEAD"


def cmd_verify(args):
    git = Git(args.repo)
    report = Report(args.quiet)
    policy = load_policy(git, report)
    if policy is None:
        return 1
    rng = args.range or default_range(git, policy)
    head = rng.split("..")[-1].lstrip(".") if ".." in rng else rng
    head = head or "HEAD"
    base = rng.split("..")[0] if ".." in rng else None
    if base and not git.exists(f"{base}^{{commit}}"):
        report.warn(f"base {base} not found; immutability check skipped")
        base = None
    print(f"prov verify: range {rng}")
    verify_tree(git, report, policy, head)
    verify_immutability(git, report, base, head)
    verify_commits(git, report, policy, git.commits(rng), base=base, head=head)
    print(f"prov verify: {report.fails} failure(s), {report.warns} warning(s)")
    return 1 if report.fails else 0


# --------------------------------------------------------------------------
# declare

def cmd_declare(args):
    git = Git(args.repo)
    report = Report()
    policy = load_policy(git, report)
    if policy is None:
        return 1
    scopes = [s.strip() for s in args.scope.split(",") if s.strip()]
    bad = set(scopes) - set(policy["trailers"]["allowed_scopes"])
    if bad:
        print(f"prov declare: unknown scope(s) {', '.join(sorted(bad))}",
              file=sys.stderr)
        return 2

    contributions, refs = [], []
    for spec in args.contrib:
        # <profile>@r<N>:<role>[=file,file,...]
        m = re.match(r"^([^:]+):([a-z][a-z0-9-]*)(?:=(.*))?$", spec)
        if not m or not PROFILE_RE.match(m.group(1)):
            print(f"prov declare: bad --contrib '{spec}' "
                  f"(want <id>@r<N>:<role>[=file,...])", file=sys.stderr)
            return 2
        ref, role_name, files = m.group(1), m.group(2), m.group(3)
        text = _read(git, profile_path(ref))
        if text is None:
            print(f"prov declare: profile {ref} not found", file=sys.stderr)
            return 2
        role = profile_role(tomllib.loads(text), role_name)
        if role is None:
            print(f"prov declare: role '{role_name}' not in {ref}", file=sys.stderr)
            return 2
        model = {"family": role["model_family"], "id": role["model_id"]}
        reported = args.reported_by
        if args.model and role_name in dict(x.split("=", 1) for x in args.model):
            model["id"] = dict(x.split("=", 1) for x in args.model)[role_name]
            reported = "api"
        contributions.append({
            "profile": ref, "role": role_name, "model": model,
            "model_reported_by": reported,
            "files": sorted({f for f in (files or "").split(",") if f}),
        })
        if ref not in refs:
            refs.append(ref)

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    pid = args.id or f"{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
    reviewer = args.reviewer or git.out("config", "user.email",
                                        check=False).strip()
    if not reviewer:
        print("prov declare: --reviewer required (no git user.email)",
              file=sys.stderr)
        return 2
    doc = {
        "schema_version": "1.0",
        "provenance_id": pid,
        "created": now.isoformat().replace("+00:00", "Z"),
        "contributions": contributions,
        "human_review": {"reviewer": reviewer, "statement": args.statement},
    }
    if args.session_ref:
        doc["session"] = {"ref": args.session_ref}
    path = manifest_path(pid)
    full = os.path.join(git.root, path)
    if os.path.exists(full):
        print(f"prov declare: {path} already exists", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    if not args.no_stage:
        git.run("add", path)

    tools = (" " + " ".join(args.tool)) if args.tool else ""
    lines = [f"Assisted-by: {r}{tools}" for r in refs]
    lines += [f"AI-Scope: {', '.join(scopes)}", f"Provenance-Id: {pid}"]
    print(f"wrote {path}" + ("" if args.no_stage else " (staged)"),
          file=sys.stderr)
    print("\n".join(lines))
    return 0


# --------------------------------------------------------------------------
# attest

def _err(msg):
    print(f"prov attest: {msg}", file=sys.stderr)


def add_signoff(git, commits, trailer):
    """Append `trailer` to every commit message in the linear series
    `commits` (oldest first) and move HEAD to the rewritten tip.

    Message-only rewrite: each new commit reuses the original tree, author
    and committer (name, e-mail, date), so the agent stays recorded as
    committer and diffs -- and therefore patch-ids -- are unchanged. Existing
    commit signatures on the rewritten commits are not carried over."""
    def has(c):
        return any(f"{k}: {v}" == trailer for k, v in git.trailers(c))
    # commits that already carry the trailer at the start stay untouched
    # (signatures included); rewriting starts at the first one without it
    first = next((i for i, c in enumerate(commits) if not has(c)), None)
    if first is None:
        return git.out("rev-parse", "HEAD").strip()
    commits = commits[first:]
    parent = git.out("rev-parse", f"{commits[0]}^").strip()
    for c in commits:
        msg = git.message(c)
        new_msg = git.out("interpret-trailers", "--if-exists", "addIfDifferent",
                          "--trailer", trailer, stdin=msg)
        # a commit that was signed (e.g. an earlier approval commit) is
        # re-signed by the attesting human; others stay unsigned
        signed = "\ngpgsig " in git.out("cat-file", "commit", c)
        f = git.out("show", "-s", "--date=raw",
                    "--format=%an%x00%ae%x00%ad%x00%cn%x00%ce%x00%cd", c)
        an, ae, ad, cn, ce, cd = f.rstrip("\n").split("\x00")
        env = dict(os.environ, GIT_AUTHOR_NAME=an, GIT_AUTHOR_EMAIL=ae,
                   GIT_AUTHOR_DATE=ad, GIT_COMMITTER_NAME=cn,
                   GIT_COMMITTER_EMAIL=ce, GIT_COMMITTER_DATE=cd)
        tree = git.out("rev-parse", f"{c}^{{tree}}").strip()
        parent = git.out("commit-tree", *(["-S"] if signed else []), tree,
                         "-p", parent, stdin=new_msg, env=env).strip()
    git.run("update-ref", "-m", "prov attest: add Signed-off-by", "HEAD", parent)
    return parent


def run_tests(git, command):
    import hashlib
    import time
    t0 = time.monotonic()
    p = subprocess.run(command, shell=True, cwd=git.root, capture_output=True)
    log = p.stdout + p.stderr
    return {"command": command, "exit": p.returncode,
            "log_digest": "sha256:" + hashlib.sha256(log).hexdigest(),
            "duration_s": round(time.monotonic() - t0, 3)}, log


def cmd_attest(args):
    git = Git(args.repo)
    report = Report()
    policy = load_policy(git, report)
    if policy is None:
        return 1
    acfg = policy.get("attestation", {})
    k_prov = policy.get("trailers", {}).get("provenance", "Provenance-Id").lower()
    ai_res = [re.compile(p, re.I)
              for p in policy.get("trailers", {}).get("ai_identity_patterns", [])]

    # 1. a human, not an agent session (speed bump; the signature is the control)
    for var in acfg.get("agent_env", []):
        if os.environ.get(var):
            _err(f"refusing to run inside an agent session ({var} is set). "
                 f"Attestation is the accountable human's act: run it in your "
                 f"own terminal.")
            return 2
    name = git.out("config", "user.name", check=False).strip()
    email = git.out("config", "user.email", check=False).strip()
    if not name or not email:
        _err("git user.name and user.email must be set")
        return 2
    if any(r.search(f"{name} <{email}>") for r in ai_res):
        _err(f"git identity '{name} <{email}>' is an AI identity")
        return 2

    # 2. a clean, linear range ending at HEAD
    if git.out("status", "--porcelain", "--untracked-files=no").strip():
        _err("working tree has uncommitted changes")
        return 2
    rng = args.range or default_range(git, policy)
    if ".." not in rng:
        _err(f"need a range BASE..HEAD (got '{rng}'); use --range")
        return 2
    base, head = rng.split("..", 1)
    head = head.lstrip(".") or "HEAD"
    if git.out("rev-parse", head).strip() != git.out("rev-parse", "HEAD").strip():
        _err("the range must end at HEAD (attest rewrites and extends HEAD)")
        return 2
    if git.out("rev-list", "--merges", rng).strip():
        _err("the range contains merge commits; attest needs a linear series")
        return 2
    commits = git.commits(rng)
    if not commits:
        _err(f"no commits in {rng}")
        return 2

    # 3. what still needs approval
    sessions = {}
    for c in commits:
        for k, v in git.trailers(c):
            if k.lower() == k_prov:
                sessions.setdefault(v, []).append(c)
    todo = {}
    for pid, cs in sessions.items():
        done = {e["patch_id"] for _, d, _ in session_attestations(git, "HEAD", pid)
                for e in d.get("commits", [])}
        left = [c for c in cs if git.patch_id(c) not in done]
        if left:
            todo[pid] = left
    if not todo:
        print("prov attest: nothing to attest -- every AI-assisted commit in "
              f"{rng} is already covered")
        return 0

    # 4. test evidence on the tree being approved
    tests = None
    if args.test:
        print(f"prov attest: running tests: {args.test}")
        tests, log = run_tests(git, args.test)
        if args.test_log:
            with open(args.test_log, "wb") as f:
                f.write(log)
        if tests["exit"] != 0:
            sys.stdout.write(log.decode(errors="replace")[-4000:])
            _err(f"tests failed (exit {tests['exit']}); nothing attested")
            return 1
        statement = "reviewed-and-tested"
    else:
        statement = "reviewed"

    # 5. show what is being approved, and ask
    print(f"\nprov attest: {name} <{email}> approves as '{statement}':")
    for pid, cs in sorted(todo.items()):
        print(f"  {pid}")
        for c in cs:
            print(f"    {c[:12]} {git.subject(c)}")
    print(git.out("diff", "--stat", f"{commits[0]}^", "HEAD"))
    dco = acfg.get("dco", "rebase-signoff")
    if dco == "rebase-signoff":
        print(f"Your Signed-off-by will be added to {len(commits)} commit(s) "
              f"in {rng} (message-only rewrite).")
    if sys.stdin.isatty() and not args.yes:
        if input("Type 'attest' to sign this approval: ").strip() != "attest":
            _err("not confirmed; nothing changed")
            return 1
    elif not args.yes:
        _err("no terminal for confirmation; pass --yes to confirm explicitly")
        return 2

    # 6. DCO, then the signed approval commit
    signoff = f"Signed-off-by: {name} <{email}>"
    if dco == "rebase-signoff":
        add_signoff(git, commits, signoff)
    import time
    while True:   # one attestation per session and second: wait out a clash
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        if not any(os.path.exists(os.path.join(git.root, attestation_path(p, now)))
                   for p in todo):
            break
        time.sleep(0.25)
    written = []
    for pid, cs in sorted(todo.items()):
        doc = {"schema_version": "1.0", "provenance_id": pid,
               "reviewer": email, "statement": statement, "attested": now,
               "commits": [{"patch_id": git.patch_id(c), "subject": git.subject(c)}
                           for c in cs]}
        if tests:
            doc["tests"] = tests
        path = attestation_path(pid, now)
        full = os.path.join(git.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        git.run("add", path)
        written.append(path)

    msg = (f"provenance: attest {', '.join(sorted(todo))}\n\n"
           f"Human approval ({statement}) of "
           f"{sum(len(v) for v in todo.values())} AI-assisted commit(s), "
           f"bound by git patch-id (RFC 0005).\n"
           + (f"Tests: {tests['command']} (exit 0)\n" if tests else "")
           + f"\n{signoff}\n")
    sign = ["-S"] if acfg.get("require_signature", True) else []
    p = git.run("commit", "-q", *sign, "-F", "-", stdin=msg, check=False)
    if p.returncode != 0:
        git.run("reset", "-q", "--", *written, check=False)
        for w in written:
            os.unlink(os.path.join(git.root, w))
        _err("signing the approval commit failed -- configure commit signing "
             "(git config gpg.format ssh; git config user.signingkey <key>) "
             f"and retry.\n{p.stderr.strip()}")
        if dco == "rebase-signoff":
            _err("note: Signed-off-by was already added; `git reflog` shows "
                 "the previous HEAD if you want to undo that")
        return 1
    print(f"prov attest: signed approval commit "
          f"{git.out('rev-parse', '--short', 'HEAD').strip()} written "
          f"({', '.join(written)})")
    return 0


# --------------------------------------------------------------------------
# query

def load_legacy_map(git):
    text = _read(git, f"{PROV_DIR}/legacy-map.toml")
    if not text:
        return []
    return [(re.compile(rf"^(?:{e['pattern']})$", re.I), e)
            for e in tomllib.loads(text).get("map", [])]


def cmd_query(args):
    git = Git(args.repo)
    report = Report(quiet=True)
    policy = load_policy(git, report) or {}
    k_ass = policy.get("trailers", {}).get("assisted", "Assisted-by").lower()
    k_prov = policy.get("trailers", {}).get("provenance", "Provenance-Id").lower()
    model_re = re.compile(args.model, re.I) if args.model else None
    legacy = load_legacy_map(git) if args.include_legacy else []

    def matches(family, model_id, profile=None):
        if args.family and family != args.family:
            return False
        if model_re and not model_re.search(model_id or ""):
            return False
        if args.profile and (profile or "").split("@")[0] != args.profile:
            return False
        return True

    hits, unmapped = [], {}
    for c in git.commits(args.range):
        tr = {}
        for k, v in git.trailers(c):
            tr.setdefault(k.lower(), []).append(v)
        pids = tr.get(k_prov, [])
        if pids:
            mtext = git.show(c, manifest_path(pids[0]))
            if mtext is None:
                continue
            changed = git.changed_files(c)
            for contrib in json.loads(mtext).get("contributions", []):
                m = contrib.get("model", {})
                if matches(m.get("family"), m.get("id"), contrib.get("profile")):
                    files = sorted(set(contrib.get("files", [])) & changed)
                    if files:
                        hits.append({"commit": c, "kind": "manifest",
                                     "profile": contrib["profile"],
                                     "role": contrib["role"],
                                     "model": m.get("id"), "files": files})
        elif legacy and tr.get(k_ass):
            for v in tr[k_ass]:
                value = EMAIL_RE.sub(" ", v).strip()
                if PROFILE_RE.match(value.split()[0] if value.split() else ""):
                    continue
                entry = next((e for r, e in legacy if r.match(value)), None)
                if entry is None:
                    unmapped[value] = unmapped.get(value, 0) + 1
                    continue
                if args.profile:
                    continue
                if matches(entry["family"], entry["model_id"]):
                    hits.append({"commit": c, "kind": "legacy",
                                 "profile": None, "role": None,
                                 "model": entry["model_id"],
                                 "files": sorted(git.changed_files(c))})

    if args.blame:
        survivors = blame_survivors(git, hits, args.blame_rev)
        for h in hits:
            h["surviving_lines"] = {f: survivors.get((h["commit"], f), 0)
                                    for f in h["files"]}

    if args.json:
        print(json.dumps({"hits": hits, "unmapped_legacy": unmapped}, indent=2))
        return 0
    for h in hits:
        label = h["profile"] or "legacy"
        print(f"{h['commit'][:12]} {label:<24} {h['model']}  "
              f"{git.subject(h['commit'])}")
        for f in h["files"]:
            extra = ""
            if args.blame:
                extra = f"  ({h['surviving_lines'][f]} line(s) at {args.blame_rev})"
            print(f"    {f}{extra}")
    total = sum(sum(h.get("surviving_lines", {}).values()) for h in hits)
    print(f"prov query: {len(hits)} hit(s)"
          + (f", {total} surviving line(s)" if args.blame else ""))
    if unmapped:
        print("prov query: unmapped legacy trailers (model unknown, NOT included):")
        for v, n in sorted(unmapped.items(), key=lambda x: -x[1]):
            print(f"    {n:4d}  {v}")
    return 0


def blame_survivors(git, hits, rev):
    """(commit, file) -> number of lines in `rev` still attributed to commit."""
    wanted = {}
    for h in hits:
        for f in h["files"]:
            wanted.setdefault(f, set()).add(h["commit"])
    result = {}
    for f, commits in wanted.items():
        p = git.run("blame", "--line-porcelain", rev, "--", f, check=False)
        if p.returncode != 0:
            continue    # file no longer exists at rev: zero survivors
        for line in p.stdout.splitlines():
            if re.match(r"^[0-9a-f]{40} ", line):
                sha = line[:40]
                if sha in commits:
                    result[(sha, f)] = result.get((sha, f), 0) + 1
    return result


# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="prov", description=__doc__.split("\n")[0])
    ap.add_argument("-C", dest="repo", default=None,
                    help="repository root (default: current repository)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="check provenance over a commit range")
    v.add_argument("--range", help="git revision range, e.g. origin/develop..HEAD")
    v.add_argument("-q", "--quiet", action="store_true", help="only WARN/FAIL")
    v.set_defaults(func=cmd_verify)

    d = sub.add_parser("declare", help="write a manifest, print trailers")
    d.add_argument("--contrib", action="append", required=True,
                   metavar="ID@rN:ROLE[=FILE,...]",
                   help="one contribution; repeat for each role/profile")
    d.add_argument("--scope", required=True, help="comma-separated AI-Scope")
    d.add_argument("--reviewer", help="accountable human (default: git user.email)")
    d.add_argument("--statement", default="reviewed-and-tested",
                   choices=["pending", "reviewed", "reviewed-and-tested"],
                   help="use pending when an agent runs declare")
    d.add_argument("--reported-by", default="config",
                   choices=["config", "manual"],
                   help="how the profile models were established")
    d.add_argument("--model", action="append", metavar="ROLE=MODEL_ID",
                   help="api-reported model for a role (records substitution)")
    d.add_argument("--tool", action="append", default=[],
                   help="analysis tool for the Assisted-by line (coccinelle, ...)")
    d.add_argument("--session-ref", help="opaque session reference")
    d.add_argument("--id", help=argparse.SUPPRESS)
    d.add_argument("--no-stage", action="store_true", help="do not git add")
    d.set_defaults(func=cmd_declare)

    a = sub.add_parser("attest", help="human approval: sign-off, tests, "
                       "signed approval commit")
    a.add_argument("--range", help="BASE..HEAD to approve (default: upstream..HEAD)")
    a.add_argument("--test", metavar="CMD",
                   help="run CMD on the approved tree; exit 0 required, "
                        "recorded as reviewed-and-tested evidence")
    a.add_argument("--test-log", metavar="FILE",
                   help="keep the test output locally (only its digest is recorded)")
    a.add_argument("--yes", action="store_true",
                   help="confirm without a terminal prompt")
    a.set_defaults(func=cmd_attest)

    q = sub.add_parser("query", help="find what a model/profile contributed")
    g = q.add_argument_group("selector (at least one)")
    g.add_argument("--model", help="regular expression on model id")
    g.add_argument("--family", help="exact model family")
    g.add_argument("--profile", help="profile id (without @rN)")
    q.add_argument("--range", default="HEAD", help="revision range (default HEAD)")
    q.add_argument("--include-legacy", action="store_true",
                   help="also map pre-policy free-text trailers via legacy-map.toml")
    q.add_argument("--blame", action="store_true",
                   help="count lines still attributed to each hit")
    q.add_argument("--blame-rev", default="HEAD")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_query)

    args = ap.parse_args(argv)
    if args.cmd == "query" and not (args.model or args.family or args.profile):
        ap.error("query needs --model, --family or --profile")
    try:
        return args.func(args)
    except RuntimeError as e:
        print(f"prov: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
