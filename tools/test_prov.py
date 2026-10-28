#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2026 Thomas Reim and the racoon-ipsec-tools contributors

"""Self-tests for tools/prov.py (RFC 0005 "provpaws").

Each test builds a throw-away Git repository containing this repository's
real .provenance/ directory (policy, schemas, profiles) with the baseline
cleared, makes commits, and checks that `prov verify` accepts or rejects
them for the right reason. No network, no fixtures outside this file.

Attestation is always required, so every repository signs approval commits
with throw-away SSH keys (needs ssh-keygen, as git's SSH signing does).
ProvTests covers trailers, manifests and policy: a case that should pass is
attested first, a case that should fail is checked for its own reason.
AttestTests covers `prov attest` and the signature rules, GuestTests the
advisory mode for fork pull requests and `prov intake` (RFC 0005 §11).

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
import tomllib
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prov  # noqa: E402

SRC_PROV = os.path.join(os.path.dirname(HERE), ".provenance")
HUMAN = "Signed-off-by: Jane Doe <jane@example.org>"
# attest refuses to run while any of the policy's agent markers is set; the
# tests run attest as the human, so they clear all of them.
with open(os.path.join(SRC_PROV, "policy.toml"), "rb") as _f:
    AGENT_MARKERS = set(tomllib.load(_f)["attestation"]["agent_env"])
# Throw-away repositories get their identities from their own config or from
# the test itself, never from the caller: a maintainer whose environment sets
# GIT_AUTHOR_*/GIT_COMMITTER_* (as .provenance/README.md recommends) must see
# the same results as CI.
for _var in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE",
             "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE"):
    os.environ.pop(_var, None)
AGENT_ENV = {"GIT_COMMITTER_NAME": "Claude Code",
             "GIT_COMMITTER_EMAIL": "agent@agents.invalid"}


class Repo:
    def __init__(self, signers=True):
        self.dir = tempfile.mkdtemp(prefix="prov-test-")
        self.git("init", "-q", "-b", "develop")
        self.git("config", "user.name", "Jane Doe")
        self.git("config", "user.email", "jane@example.org")
        self.git("config", "commit.gpgsign", "false")
        shutil.copytree(SRC_PROV, os.path.join(self.dir, ".provenance"),
                        ignore=shutil.ignore_patterns("[0-9][0-9][0-9][0-9]"))
        # start from no allowed signers, whatever the real repository lists
        with open(os.path.join(self.dir, ".provenance", "allowed_signers"), "w") as f:
            f.write("# test repository\n")
        pol = os.path.join(self.dir, ".provenance", "policy.toml")
        with open(pol) as f:
            text = f.read()
        text = re.sub(r'^baseline = ".*"$', 'baseline = ""', text, flags=re.M)
        with open(pol, "w") as f:
            f.write(text)
        self.keys = {}
        self.git("config", "gpg.format", "ssh")
        # a host-wide gpg.ssh.program may point elsewhere; tests sign with
        # plain ssh-keygen, as CI does
        self.git("config", "gpg.ssh.program", "ssh-keygen")
        self.use_key("jane")
        if signers:
            self.allow("jane")
        self.git("add", "-A")
        self.write("README", "base\n")
        self.commit("initial", trailers=[HUMAN])
        self.base = self.head()

    def git(self, *args, stdin=None, env=None):
        return subprocess.run(["git", "-C", self.dir, *args], input=stdin,
                              check=True, capture_output=True, text=True,
                              env=dict(os.environ, **(env or {}))).stdout

    def key(self, name):
        if name not in self.keys:
            path = os.path.join(self.dir + "-keys", name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-C", name, "-f", path], check=True)
            self.keys[name] = path
        return self.keys[name]

    def use_key(self, name):
        self.git("config", "user.signingkey", self.key(name))

    def allow(self, name, email="jane@example.org"):
        pub = open(self.key(name) + ".pub").read().split()
        self.write(".provenance/allowed_signers", f"{email} {pub[0]} {pub[1]}\n")

    def attest(self, *argv, env_extra=None):
        env = {k: v for k, v in os.environ.items() if k not in AGENT_MARKERS}
        env.update(env_extra or {})
        buf = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(buf):
            rc = prov.main(["-C", self.dir, "attest", "--yes",
                            "--range", f"{self.base}..HEAD", *argv])
        return rc, buf.getvalue()

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

    def commit(self, subject, trailers=(), env=None, author=None):
        msg = subject + "\n\nbody\n\n" + "\n".join(trailers) + "\n"
        extra = ["--author", author] if author else []
        self.git("commit", "-q", *extra, "-F", "-", stdin=msg, env=env)

    def verify(self, *argv, rng=None):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = prov.main(["-C", self.dir, "verify",
                            "--range", rng or f"{self.base}..HEAD", *argv])
        return rc, buf.getvalue()

    def intake(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf), mock.patch("sys.stderr", buf):
            rc = prov.main(["-C", self.dir, "intake",
                            "--range", f"{self.base}..HEAD", *argv])
        return rc, buf.getvalue()

    def query(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            prov.main(["-C", self.dir, "query", "--json", *argv])
        return json.loads(buf.getvalue())

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        shutil.rmtree(self.dir + "-keys", ignore_errors=True)


class ProvTests(unittest.TestCase):
    def setUp(self):
        self.r = Repo()

    def tearDown(self):
        self.r.cleanup()

    def assertPass(self):
        rc, out = self.r.attest()
        self.assertEqual(rc, 0, out)
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

    def test_declare_without_reported_by_records_manual(self):
        # PRINCIPLES.md 11 and 12: a model that no tool has read is a
        # declaration, so the record must not claim "config".
        self.r.write("src/x.c", "int x;\n")
        tr = self.r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                            "--scope", "code")
        pid = [t.split(": ", 1)[1] for t in tr if t.startswith("Provenance-Id")][0]
        with open(os.path.join(self.r.dir, ".provenance", "manifests", pid[:4],
                               pid + ".json"), encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual([c["model_reported_by"] for c in doc["contributions"]],
                         ["manual"])

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



class AttestTests(unittest.TestCase):
    """prov attest + verify: sign-off, signed approval, patch-id binding."""

    def setUp(self):
        self.r = None

    def tearDown(self):
        if self.r:
            self.r.cleanup()

    def repo(self, **kw):
        self.r = Repo(**kw)
        return self.r

    def agent_session(self, path="src/x.c", text="int x;\n", subject="agent change"):
        r = self.r
        r.write(path, text)
        tr = r.declare("--contrib", f"claude-opus@r1:implementer={path}",
                       "--scope", "code", "--statement", "pending")
        r.commit(subject, tr, env=AGENT_ENV)
        return tr

    def verify(self):
        return self.r.verify()

    def test_end_to_end_attest_then_verify(self):
        r = self.repo()
        self.agent_session()
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("not covered by a valid attestation", out)
        rc, out = r.attest("--test", "true")
        self.assertEqual(rc, 0, out)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)
        self.assertIn("approved by a signed human attestation", out)
        # sign-off added, agent kept as committer, author is human
        agent = r.git("rev-parse", "HEAD~1").strip()
        self.assertIn(HUMAN, r.git("show", "-s", "--format=%B", agent))
        self.assertEqual(r.git("show", "-s", "--format=%cn", agent).strip(),
                         "Claude Code")
        self.assertEqual(r.git("show", "-s", "--format=%an", agent).strip(),
                         "Jane Doe")
        att = r.git("show", "--name-only", "--format=", "HEAD").split()
        doc = json.loads(r.git("show", f"HEAD:{att[0]}"))
        self.assertEqual(doc["statement"], "reviewed-and-tested")
        self.assertEqual(doc["tests"]["exit"], 0)

    def test_attest_without_tests_is_reviewed_only(self):
        r = self.repo()
        self.agent_session()
        rc, out = r.attest()
        self.assertEqual(rc, 0, out)
        att = r.git("show", "--name-only", "--format=", "HEAD").split()
        self.assertEqual(json.loads(r.git("show", f"HEAD:{att[0]}"))["statement"],
                         "reviewed")
        self.assertEqual(self.verify()[0], 0)

    def test_attest_refused_in_agent_session(self):
        r = self.repo()
        self.agent_session()
        before = r.head()
        rc, _ = r.attest(env_extra={"CLAUDECODE": "1"})
        self.assertEqual(rc, 2)
        self.assertEqual(r.head(), before)

    def test_attest_refused_in_opencode_session(self):
        # PRINCIPLES.md 14: OpenCode sets OPENCODE=1 for its tool processes
        # (OpenCode 1.19.3); attest must refuse there as in Claude Code.
        r = self.repo()
        self.agent_session()
        before = r.head()
        rc, _ = r.attest(env_extra={"OPENCODE": "1"})
        self.assertEqual(rc, 2)
        self.assertEqual(r.head(), before)

    def test_failing_tests_attest_nothing(self):
        r = self.repo()
        self.agent_session()
        before = r.head()
        rc, _ = r.attest("--test", "false")
        self.assertEqual(rc, 1)
        self.assertEqual(r.head(), before)

    def test_diff_changed_after_attestation_fails(self):
        r = self.repo()
        self.agent_session()
        self.assertEqual(r.attest()[0], 0)
        approval = r.head()
        agent = r.git("rev-parse", "HEAD~1").strip()
        # rebuild the series with a modified agent diff, keep the approval
        r.git("reset", "-q", "--hard", r.base)
        r.git("cherry-pick", agent)
        r.write("src/x.c", "/* slipped in after review */\n")
        r.git("commit", "-q", "--amend", "--no-edit")
        r.git("cherry-pick", "-S", approval)
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("diff changed after approval", out)

    def test_rebase_needs_resigning_but_keeps_attestation(self):
        r = self.repo()
        self.agent_session()
        self.assertEqual(r.attest()[0], 0)
        r.git("checkout", "-q", "-b", "upstream", r.base)
        r.write("docs/unrelated.md", "x\n")
        r.commit("unrelated", [HUMAN])
        new_base = r.head()
        r.git("checkout", "-q", "develop")
        r.base = new_base
        # an unsigned rebase drops the approval signature: verify says so
        r.git("rebase", "-q", "--no-gpg-sign", new_base)
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("not signed by an allowed key", out)
        # the human re-signs while rebasing: patch-ids are unchanged, so the
        # attestation still binds and no new attestation is needed
        r.git("rebase", "-q", "--force-rebase", "--gpg-sign", new_base)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)

    def test_unsigned_approval_fails(self):
        r = self.repo()
        self.agent_session()
        agent = r.head()
        pid = [l.split(": ")[1] for l in
               r.git("show", "-s", "--format=%B", agent).splitlines()
               if l.startswith("Provenance-Id")][0]
        doc = {"schema_version": "1.0", "provenance_id": pid,
               "reviewer": "jane@example.org", "statement": "reviewed",
               "attested": "20261017T120000Z",
               "commits": [{"patch_id": prov.Git(r.dir).patch_id(agent),
                            "subject": "agent change"}]}
        r.write(prov.attestation_path(pid, "20261017T120000Z"), json.dumps(doc))
        r.commit("provenance: attest (unsigned)", [HUMAN])
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("not signed by an allowed key", out)

    def test_change_cannot_admit_its_own_key(self):
        r = self.repo()
        self.agent_session()
        r.allow("mallory")           # added in the change, not at the base
        r.commit("add a key", [HUMAN])
        r.use_key("mallory")
        self.assertEqual(r.attest()[0], 0)
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("not signed by an allowed key", out)

    def test_no_signers_at_base_fails(self):
        # the key added by the change itself never counts, not even once
        r = self.repo(signers=False)
        r.allow("jane")
        r.commit("add maintainer key", [HUMAN])
        self.agent_session()
        self.assertEqual(r.attest()[0], 0)
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("no signers at the base", out)

    def test_signature_check_ignores_local_gpg_ssh_program(self):
        r = self.repo()
        self.agent_session()
        self.assertEqual(r.attest()[0], 0)
        # a caller's own verification program must not decide the result
        r.git("config", "gpg.ssh.program", "false")
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)

    def test_ai_author_fails(self):
        r = self.repo()
        r.write("src/x.c", "int x;\n")
        tr = r.declare("--contrib", "claude-opus@r1:implementer=src/x.c",
                       "--scope", "code", "--statement", "pending")
        r.commit("agent as author", tr + [HUMAN],
                 author="Claude <noreply@anthropic.com>")
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("is an AI identity", out)

    def test_new_commit_needs_new_attestation(self):
        r = self.repo()
        tr = self.agent_session()
        self.assertEqual(r.attest()[0], 0)
        r.write("tests/t.c", "int t;\n")
        r.commit("agent follow-up", tr, env=AGENT_ENV)
        rc, out = self.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("not covered by a valid attestation", out)
        rc, out = r.attest()
        self.assertEqual(rc, 0, out)
        rc, out = self.verify()
        self.assertEqual(rc, 0, out)


GUEST = "Signed-off-by: Gus Guest <gus@example.org>"
GUEST_STATEMENT = "Claude Code (Opus) wrote the fix, I reviewed and tested it"


class GuestTests(unittest.TestCase):
    """Guest fork pull requests: advisory verify, maintainer intake."""

    def setUp(self):
        self.r = Repo()

    def tearDown(self):
        self.r.cleanup()

    def guest_commits(self, path="src/x.c"):
        """Two guest commits as they arrive from a fork: free-text statement,
        the guest's agent as author of one, a vendor co-author line."""
        r = self.r
        r.write(path, "int x;\n")
        r.commit("guest: fix", ["Assisted-by: Claude Code (Opus)",
                                "Co-Authored-By: Claude <noreply@anthropic.com>",
                                GUEST], author="Claude <noreply@anthropic.com>")
        r.write("tests/t.c", "int t;\n")
        r.commit("guest: test", [GUEST], author="Gus Guest <gus@example.org>")

    def test_advisory_mode_is_green_and_writes_summary(self):
        self.guest_commits()
        summary = os.path.join(self.r.dir + "-keys", "summary.md")
        rc, out = self.r.verify("--advisory", "--summary", summary)
        self.assertEqual(rc, 0, out)
        self.assertIn("[NOTE]", out)
        self.assertNotIn("[FAIL]", out)
        text = open(summary).read()
        self.assertIn("Thank you", text)
        self.assertIn("profile reference", text)
        # the same commits on a branch in this repository fail
        self.assertEqual(self.r.verify()[0], 1)

    def test_intake_then_attest_passes(self):
        r = self.r
        self.guest_commits()
        originals = r.git("rev-list", "--reverse", f"{r.base}..HEAD").split()
        g = prov.Git(r.dir)
        before = [g.patch_id(c) for c in originals]
        rc, out = r.intake("--guest-statement", GUEST_STATEMENT, "--scope", "code, tests",
                           "--new-profile", "guest-gus", "--owner", "jane",
                           "--role", "implementer=anthropic-claude:claude-opus-5-5",
                           "--author", "Gus Guest <gus@example.org>")
        self.assertEqual(rc, 0, out)
        rc, out = r.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("not covered by a valid attestation", out)
        self.assertEqual(r.attest()[0], 0)
        rc, out = r.verify()
        self.assertEqual(rc, 0, out)

        # intake commit, two rebuilt guest commits, approval commit
        series = r.git("rev-list", "--reverse", f"{r.base}..HEAD").split()
        self.assertEqual(len(series), 4)
        intake, fix, test = series[:3]
        self.assertIn(".provenance/profiles/guest-gus/r1.toml",
                      r.git("show", "--name-only", "--format=", intake))
        self.assertIn(GUEST_STATEMENT, r.git("show", "-s", "--format=%B", intake))
        msg = r.git("show", "-s", "--format=%B", fix)
        self.assertIn("Assisted-by: guest-gus@r1", msg)
        self.assertIn(GUEST, msg)
        self.assertNotIn("Co-Authored-By", msg)
        self.assertNotIn("Claude Code (Opus)", msg)
        for c in (fix, test):
            self.assertEqual(r.git("show", "-s", "--format=%an <%ae>", c).strip(),
                             "Gus Guest <gus@example.org>")
        # the guest's diffs are untouched: same patch-ids
        self.assertEqual([prov.Git(r.dir).patch_id(c) for c in (fix, test)], before)

    def test_intake_reuses_profile(self):
        r = self.r
        self.guest_commits()
        rc, out = r.intake("--guest-statement", GUEST_STATEMENT, "--scope", "code",
                           "--profile", "claude-opus@r1",
                           "--author", "Gus Guest <gus@example.org>")
        self.assertEqual(rc, 0, out)
        intake = r.git("rev-list", "--reverse", f"{r.base}..HEAD").split()[0]
        self.assertNotIn("profiles/", r.git("show", "--name-only", "--format=", intake))
        self.assertEqual(r.attest()[0], 0)
        self.assertEqual(r.verify()[0], 0)

    def test_intake_refuses_ai_author_without_guest(self):
        r = self.r
        self.guest_commits()
        head = r.head()
        rc, out = r.intake("--guest-statement", GUEST_STATEMENT, "--scope", "code",
                           "--profile", "claude-opus@r1")
        self.assertEqual(rc, 2, out)
        self.assertIn("name an AI as author", out)
        self.assertEqual(r.head(), head)

    def test_intake_critical_path_needs_dissimilar_review(self):
        r = self.r
        self.guest_commits(path="src/racoon/isakmp.c")
        args = ["--guest-statement", "Qwen3-Coder via OpenCode", "--scope", "code",
                "--new-profile", "guest-qwen", "--owner", "jane",
                "--role", "implementer=alibaba-qwen:Qwen/Qwen3-Coder-480B-A35B-Instruct",
                "--author", "Gus Guest <gus@example.org>"]
        guest_tip = r.head()
        self.assertEqual(r.intake(*args)[0], 0)
        self.assertEqual(r.attest()[0], 0)
        rc, out = r.verify()
        self.assertEqual(rc, 1, out)
        self.assertIn("requires a 'reviewer' contribution", out)
        # the maintainer runs a review with a model of another family
        r.git("reset", "-q", "--hard", guest_tip)
        rc, out = r.intake(*args, "--reviewed-by", "opencode-pair@r1")
        self.assertEqual(rc, 0, out)
        msg = r.git("show", "-s", "--format=%B", "HEAD")
        self.assertIn("Assisted-by: opencode-pair@r1", msg)
        self.assertEqual(r.attest()[0], 0)
        rc, out = r.verify()
        self.assertEqual(rc, 0, out)

    def test_intake_refuses_guest_provenance_changes(self):
        r = self.r
        r.write(".provenance/profiles/mine/r1.toml", "x = 1\n")
        r.commit("guest adds a profile", [GUEST])
        rc, out = r.intake("--guest-statement", GUEST_STATEMENT, "--scope", "code",
                           "--profile", "claude-opus@r1")
        self.assertEqual(rc, 2, out)
        self.assertIn("change .provenance/", out)


if __name__ == "__main__":
    unittest.main()
