#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2026 Thomas Reim and the racoon-ipsec-tools contributors

"""Self-tests for tools/prov.py (RFC 0005 "provpaws").

Each test builds a throw-away Git repository containing this repository's
real .provenance/ directory (policy, schemas, profiles) with the baseline
cleared, makes commits, and checks that `prov verify` accepts or rejects
them for the right reason. No network, no fixtures outside this file.

Run:  python3 -m unittest -v tools/test_prov.py
"""

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prov  # noqa: E402

SRC_PROV = os.path.join(os.path.dirname(HERE), ".provenance")
HUMAN = "Signed-off-by: Jane Doe <jane@example.org>"


class Repo:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="prov-test-")
        self.git("init", "-q", "-b", "develop")
        self.git("config", "user.name", "Jane Doe")
        self.git("config", "user.email", "jane@example.org")
        self.git("config", "commit.gpgsign", "false")
        shutil.copytree(SRC_PROV, os.path.join(self.dir, ".provenance"),
                        ignore=shutil.ignore_patterns("[0-9][0-9][0-9][0-9]"))
        pol = os.path.join(self.dir, ".provenance", "policy.toml")
        with open(pol) as f:
            text = f.read()
        text = re.sub(r'^baseline = ".*"$', 'baseline = ""', text, flags=re.M)
        with open(pol, "w") as f:
            f.write(text)
        self.git("add", "-A")
        self.write("README", "base\n")
        self.commit("initial", trailers=[HUMAN])
        self.base = self.head()

    def git(self, *args, stdin=None):
        return subprocess.run(["git", "-C", self.dir, *args], input=stdin,
                              check=True, capture_output=True, text=True).stdout

    def head(self):
        return self.git("rev-parse", "HEAD").strip()

    def write(self, path, text):
        full = os.path.join(self.dir, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "a") as f:
            f.write(text)
        self.git("add", path)

    def declare(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = prov.main(["-C", self.dir, "declare", *argv])
        assert rc == 0, buf.getvalue()
        return buf.getvalue().strip().splitlines()

    def commit(self, subject, trailers=()):
        msg = subject + "\n\nbody\n\n" + "\n".join(trailers) + "\n"
        self.git("commit", "-q", "-F", "-", stdin=msg)

    def verify(self, rng=None):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = prov.main(["-C", self.dir, "verify",
                            "--range", rng or f"{self.base}..HEAD"])
        return rc, buf.getvalue()

    def query(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            prov.main(["-C", self.dir, "query", "--json", *argv])
        return json.loads(buf.getvalue())

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class ProvTests(unittest.TestCase):
    def setUp(self):
        self.r = Repo()

    def tearDown(self):
        self.r.cleanup()

    def assertPass(self):
        rc, out = self.r.verify()
        self.assertEqual(rc, 0, out)
        return out

    def assertFail(self, needle):
        rc, out = self.r.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn(needle, out)
        return out

    # -- baseline behaviour ---------------------------------------------

    def test_human_only_commit_passes(self):
        self.r.write("src/x.c", "int x;\n")
        self.r.commit("human change", [HUMAN])
        self.assertPass()

    def test_assisted_commit_passes(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code")
        self.r.commit("assisted change", tr + [HUMAN])
        out = self.assertPass()
        self.assertIn("1 AI-assisted", out)

    # -- trailer rules --------------------------------------------------

    def test_co_authored_by_ai_fails(self):
        self.r.write("src/x.c", "int x;\n")
        self.r.commit("vendor default", [
            "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>", HUMAN])
        self.assertFail("names an AI")

    def test_ai_signed_off_by_fails(self):
        self.r.write("src/x.c", "int x;\n")
        self.r.commit("bad signoff", ["Signed-off-by: Claude <noreply@anthropic.com>"])
        self.assertFail("names an AI")

    def test_noncanonical_casing_fails(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code")
        tr = [t.replace("Assisted-by", "Assisted-By") for t in tr]
        self.r.commit("casing", tr + [HUMAN])
        self.assertFail("must be spelled 'Assisted-by'")

    def test_free_text_assisted_by_fails_after_baseline(self):
        self.r.write("src/x.c", "int x;\n")
        self.r.commit("legacy style", ["Assisted-by: Claude Sonnet 5", HUMAN])
        self.assertFail("must be a profile reference")

    def test_missing_signoff_fails(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code")
        self.r.commit("no signoff", tr)
        self.assertFail("without a human Signed-off-by")

    def test_unknown_scope_fails(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code")
        tr = [("AI-Scope: vibes" if t.startswith("AI-Scope") else t) for t in tr]
        self.r.commit("scope", tr + [HUMAN])
        self.assertFail("AI-Scope 'vibes'")

    def test_unknown_profile_fails(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code")
        tr = [t.replace("claude-opus@r1", "claude-opus@r9") for t in tr]
        self.r.commit("ghost profile", tr + [HUMAN])
        self.assertFail("profile claude-opus@r9 not found")

    def test_missing_manifest_fails(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code")
        self.r.git("rm", "-q", "--cached", "-r", ".provenance/manifests")
        self.r.commit("manifest forgotten", tr + [HUMAN])
        self.assertFail("not in the commit's tree")

    # -- manifest consistency -------------------------------------------

    def test_manifest_claiming_untouched_file_fails(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib",
                            "claude-opus@r1:implementer=src/x.c,src/other.c",
                            "--scope", "code")
        self.r.commit("overclaim", tr + [HUMAN])
        self.assertFail("claims files not changed")

    def test_session_spanning_two_commits_passes(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib",
                            "claude-opus@r1:implementer=src/x.c,tests/t.c",
                            "--scope", "code, tests")
        self.r.commit("part 1", tr + [HUMAN])
        self.r.write("tests/t.c", "int t;\n")
        self.r.commit("part 2", tr + [HUMAN])
        self.assertPass()

    def test_api_reported_substitution_warns(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code",
                            "--model", "implementer=claude-sonnet-5")
        self.r.commit("substituted", tr + [HUMAN])
        out = self.assertPass()
        self.assertIn("[WARN]", out)
        self.assertIn("provider substitution?", out)

    def test_pending_review_fails(self):
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code", "--statement", "pending")
        self.r.commit("agent-prepared", tr + [HUMAN])
        self.assertFail("statement is 'pending'")

    # -- critical paths -------------------------------------------------

    def test_critical_code_without_dissimilar_review_fails(self):
        self.r.write("src/racoon/isakmp.c", "/* fix */\n")
        tr = self.r.declare(
            "--contrib", "opencode-qwen3-coder@r1:implementer=src/racoon/isakmp.c",
            "--scope", "code")
        self.r.commit("critical, unreviewed", tr + [HUMAN])
        self.assertFail("requires a 'reviewer' contribution")

    def test_critical_code_with_same_family_review_fails(self):
        self.r.write(".provenance/profiles/qwen-selfreview/r1.toml",
                     'schema_version = "1.0"\nid = "qwen-selfreview"\n'
                     'revision = 1\nharness = "opencode"\nowner = "test"\n'
                     'status = "active"\n'
                     '[[roles]]\nname = "implementer"\n'
                     'model_family = "alibaba-qwen"\nmodel_id = "q1"\n'
                     'disclosure = "public"\n'
                     '[[roles]]\nname = "reviewer"\n'
                     'model_family = "alibaba-qwen"\nmodel_id = "q2"\n'
                     'disclosure = "public"\n')
        self.r.write("src/racoon/isakmp.c", "/* fix */\n")
        tr = self.r.declare(
            "--contrib", "qwen-selfreview@r1:implementer=src/racoon/isakmp.c",
            "--contrib", "qwen-selfreview@r1:reviewer",
            "--scope", "code")
        self.r.commit("critical, same family", tr + [HUMAN])
        self.assertFail("requires a 'reviewer' contribution")

    def test_critical_code_with_dissimilar_review_passes(self):
        self.r.write("src/racoon/isakmp.c", "/* fix */\n")
        tr = self.r.declare(
            "--contrib", "opencode-pair@r1:implementer=src/racoon/isakmp.c",
            "--contrib", "opencode-pair@r1:reviewer",
            "--scope", "code")
        self.r.commit("critical, reviewed", tr + [HUMAN])
        self.assertPass()

    def test_critical_tests_scope_needs_no_review(self):
        self.r.write("src/racoon/isakmp.c", "/* test hook */\n")
        tr = self.r.declare(
            "--contrib", "claude-opus@r1:implementer=src/racoon/isakmp.c",
            "--scope", "tests")
        self.r.commit("critical, tests only", tr + [HUMAN])
        self.assertPass()

    def test_withheld_model_in_critical_path_fails(self):
        self.r.write("src/racoon/privsep.c", "/* change */\n")
        tr = self.r.declare(
            "--contrib", "opencode-kitch@r1:implementer=src/racoon/privsep.c",
            "--contrib", "opencode-pair@r1:reviewer",
            "--scope", "tests")
        self.r.commit("withheld", tr + [HUMAN])
        self.assertFail("withheld model wrote critical file")

    # -- immutability ---------------------------------------------------

    def test_modified_profile_revision_fails(self):
        p = ".provenance/profiles/claude-opus/r1.toml"
        self.r.write(p, "# sneaky edit\n")
        self.r.commit("edit profile", [HUMAN])
        self.assertFail("modified (create a new revision instead)")

    def test_new_profile_revision_passes(self):
        src = os.path.join(self.r.dir, ".provenance/profiles/claude-opus/r1.toml")
        text = open(src).read().replace("revision = 1", "revision = 2")
        self.r.write(".provenance/profiles/claude-opus/r2.toml", text)
        self.r.commit("new revision", [HUMAN])
        self.assertPass()

    # -- query ----------------------------------------------------------

    def test_query_finds_model_and_surviving_lines(self):
        self.r.write("src/x.c", "a\nb\nc\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code")
        self.r.commit("assisted", tr + [HUMAN])
        self.r.write("src/x.c", "human\n")
        self.r.commit("human follow-up", [HUMAN])
        res = self.r.query("--model", "opus", "--blame")
        self.assertEqual(len(res["hits"]), 1)
        self.assertEqual(res["hits"][0]["surviving_lines"], {"src/x.c": 3})

    def test_query_legacy_mapping_and_unmapped(self):
        self.r.write("src/x.c", "a\n")
        self.r.commit("old", ["Assisted-By: Claude Sonet 5 <noreply@anthropic.com>", HUMAN])
        self.r.write("src/y.c", "b\n")
        self.r.commit("old vague", ["Assisted-by: Claude", HUMAN])
        res = self.r.query("--model", "sonnet", "--include-legacy")
        self.assertEqual([h["kind"] for h in res["hits"]], ["legacy"])
        self.assertEqual(res["unmapped_legacy"], {"Claude": 1})


if __name__ == "__main__":
    unittest.main()
