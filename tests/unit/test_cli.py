import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from agentshield import ApprovalStore, AuditLog
from agentshield.cli import main
from tests.helpers import TmpDirTestCase

POLICY = """
version: 1
tools:
  calculator: {risk: low, decision: ALLOW}
  filesystem.read: {risk: medium, decision: ALLOW, allowed_roots: [./workspace]}
  filesystem.write: {risk: high, decision: REQUIRE_APPROVAL, allowed_roots: [./workspace/output]}
"""


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as e:  # argparse errors
            code = int(e.code)
    return code, out.getvalue(), err.getvalue()


class CliTests(TmpDirTestCase):
    def setUp(self):
        super().setUp()
        self.pol = os.path.join(self.tmp, "policy.yaml")
        with open(self.pol, "w") as fh:
            fh.write(POLICY)

    def test_lint_ok_text_and_json(self):
        code, out, _ = run("lint", self.pol)
        self.assertEqual(code, 0)
        self.assertIn("filesystem.write", out)
        code, out, _ = run("lint", self.pol, "--json")
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["policy_hash"]), 64)

    def test_lint_reports_errors_with_exit_2(self):
        bad = os.path.join(self.tmp, "bad.yaml")
        with open(bad, "w") as fh:
            fh.write("version: 1\ntools:\n  calculator: {decision: ALLOW}\n")
        code, out, err = run("lint", bad)
        self.assertEqual(code, 2)
        self.assertIn("risk", err)
        self.assertEqual(run("lint", os.path.join(self.tmp, "missing.yaml"))[0], 2)

    def test_lint_warnings(self):
        w = os.path.join(self.tmp, "w.yaml")
        with open(w, "w") as fh:
            fh.write("version: 1\ntools:\n  http.fetch: {risk: low, decision: ALLOW, allowed_hosts: [a.com], allowed_schemes: [http, https], block_private_addresses: false}\n  my.tool: {risk: high, decision: ALLOW}\n")
        code, out, _ = run("lint", w)
        self.assertEqual(code, 0)
        for needle in ("plain http", "block_private_addresses", "high-risk", "not a built-in"):
            self.assertIn(needle, out)

    def test_evaluate_exit_codes(self):
        self.assertEqual(run("evaluate", self.pol, "--tool", "calculator", "--args", '{"expression":"1+1"}')[0], 0)
        self.assertEqual(run("evaluate", self.pol, "--tool", "filesystem.read", "--args", '{"path":"../x"}')[0], 1)
        self.assertEqual(run("evaluate", self.pol, "--tool", "filesystem.write", "--args", '{"path":"a.txt","content":"x"}')[0], 3)
        self.assertEqual(run("evaluate", self.pol, "--tool", "shell.exec", "--args", "{}")[0], 1)

    def test_evaluate_json_and_explain(self):
        code, out, _ = run("evaluate", self.pol, "--tool", "calculator", "--args", '{"expression":"1+1"}', "--json")
        d = json.loads(out)
        self.assertEqual(d["decision"], "ALLOW")
        self.assertNotIn("trace", d)
        code, out, _ = run("explain", self.pol, "--tool", "filesystem.read", "--args", '{"path":"/etc/passwd"}')
        self.assertEqual(code, 1)
        self.assertIn("PATH_OUTSIDE_ROOT", out)
        self.assertIn("- schema: ok", out)

    def test_evaluate_args_from_file_and_bad_json(self):
        af = os.path.join(self.tmp, "args.json")
        with open(af, "w") as fh:
            fh.write('{"expression": "2+2"}')
        self.assertEqual(run("evaluate", self.pol, "--tool", "calculator", "--args", "@" + af)[0], 0)
        self.assertEqual(run("evaluate", self.pol, "--tool", "calculator", "--args", "{nope")[0], 2)
        self.assertEqual(run("evaluate", self.pol, "--tool", "calculator", "--args", "@/nonexistent.json")[0], 2)

    def test_evaluate_never_creates_approvals_or_executes(self):
        run("evaluate", self.pol, "--tool", "filesystem.write", "--args", '{"path":"a.txt","content":"x"}')
        self.assertFalse(os.path.exists(os.path.join(self.tmp, ".agentshield")))
        self.assertFalse(os.path.exists(os.path.join(self.ws, "output", "a.txt")))

    def test_approvals_flow(self):
        d = os.path.join(self.tmp, "ap")
        store = ApprovalStore(d)
        rec = store.request(action_hash="a" * 64, policy_hash="b" * 64, agent_id="x", tool="filesystem.write", risk="high",
                            summary={"target": "/t", "args": {"path": "p"}}, ttl_seconds=300)
        code, out, _ = run("approvals", "--dir", d, "list")
        self.assertIn(rec.id, out)
        code, out, _ = run("approvals", "--dir", d, "show", rec.id)
        self.assertIn("action_hash", out)
        code, out, _ = run("approvals", "--dir", d, "approve", rec.id, "--yes")
        self.assertEqual(code, 0)
        self.assertEqual(store.get(rec.id).status, "approved")
        self.assertEqual(run("approvals", "--dir", d, "approve", rec.id, "--yes")[0], 2, "cannot approve twice")
        self.assertEqual(run("approvals", "--dir", d, "show", "nope")[0], 2)
        code, out, _ = run("approvals", "--dir", d, "--json", "list", "--status", "approved")
        self.assertEqual(json.loads(out)[0]["id"], rec.id)

    def test_approval_prompt_default_is_no(self):
        d = os.path.join(self.tmp, "ap")
        store = ApprovalStore(d)
        rec = store.request(action_hash="a" * 64, policy_hash="b" * 64, agent_id="x", tool="t", risk=None, summary={}, ttl_seconds=300)
        with mock.patch("builtins.input", return_value=""):
            self.assertEqual(run("approvals", "--dir", d, "approve", rec.id)[0], 1)
        self.assertEqual(store.get(rec.id).status, "pending")
        with mock.patch("builtins.input", return_value="y"):
            self.assertEqual(run("approvals", "--dir", d, "reject", rec.id)[0], 0)
        self.assertEqual(store.get(rec.id).status, "rejected")

    def test_audit_verify(self):
        path = os.path.join(self.tmp, "a.jsonl")
        log = AuditLog(path)
        for i in range(3):
            log.record("decision", i=i)
        log.close()
        code, out, _ = run("audit", "verify", path)
        self.assertEqual(code, 0)
        self.assertIn("3 events", out)
        with open(path, "rb") as fh:
            lines = fh.readlines()
        with open(path, "wb") as fh:
            fh.writelines(lines[:2])
        code, out, _ = run("audit", "verify", path, "--json")
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["ok"])

    def test_module_entrypoint_and_version(self):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        p = subprocess.run([sys.executable, "-m", "agentshield", "--version"], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0)
        self.assertIn("agentshield 0.1.0a1", p.stdout)

    def test_requires_a_subcommand(self):
        self.assertEqual(run()[0], 2)


if __name__ == "__main__":
    unittest.main()
