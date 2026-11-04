import json
import os
import unittest

from agentshield import Decision, Policy, PolicyError
from tests.helpers import TmpDirTestCase

GOOD = """
version: 1
default_decision: DENY
tools:
  calculator: {enabled: true, risk: low, decision: ALLOW}
  filesystem.read: {risk: medium, decision: ALLOW, allowed_roots: [./workspace]}
  http.fetch:
    risk: medium
    decision: ALLOW
    allowed_hosts: [Docs.Example.com.]
  shell.exec: {enabled: false, risk: high, decision: DENY}
"""


class PolicyTests(TmpDirTestCase):
    def load(self, text):
        return Policy.from_text(text, base_dir=self.tmp)

    def err(self, text):
        with self.assertRaises(PolicyError) as cm:
            self.load(text)
        return " | ".join(cm.exception.errors)

    def test_valid_policy(self):
        p = self.load(GOOD)
        self.assertEqual(p.tools["calculator"].decision, Decision.ALLOW)
        self.assertEqual(p.tools["filesystem.read"].constraints["allowed_roots"], (os.path.join(self.tmp, "workspace"),))
        self.assertEqual(p.tools["http.fetch"].constraints["allowed_hosts"], ("docs.example.com",))
        self.assertEqual(p.tools["http.fetch"].constraints["allowed_ports"], (443,))
        self.assertEqual(p.tools["http.fetch"].constraints["block_private_addresses"], True)

    def test_hash_stable_and_sensitive(self):
        a, b = self.load(GOOD), self.load(GOOD)
        self.assertEqual(a.hash, b.hash)
        c = self.load(GOOD.replace("decision: ALLOW}\n  filesystem", "decision: DENY}\n  filesystem"))
        self.assertNotEqual(a.hash, c.hash)

    def test_json_is_accepted(self):
        p = self.load(json.dumps({"version": 1, "tools": {"calculator": {"risk": "low", "decision": "ALLOW"}}}))
        self.assertIn("calculator", p.tools)

    def test_from_file_uses_file_directory_for_relative_roots(self):
        path = os.path.join(self.tmp, "p.yaml")
        with open(path, "w") as fh:
            fh.write(GOOD)
        p = Policy.from_file(path)
        self.assertEqual(p.tools["filesystem.read"].constraints["allowed_roots"], (os.path.join(self.tmp, "workspace"),))

    def test_duplicate_keys_rejected(self):
        self.assertIn("duplicate key", self.err("version: 1\ntools:\n  a: {risk: low, decision: ALLOW}\n  a: {risk: low, decision: DENY}\n"))

    def test_aliases_rejected(self):
        self.assertIn("aliases", self.err("version: 1\ntools:\n  x: &a {risk: low, decision: ALLOW}\n  y: *a\n"))

    def test_yaml_norway_problem_is_caught(self):
        self.assertIn("quote values", self.err("version: 1\ntools:\n  http.fetch: {risk: low, decision: ALLOW, allowed_hosts: [no]}\n"))

    def test_python_tags_are_not_executed(self):
        self.assertIn("YAML error", self.err("version: 1\ntools: !!python/object/apply:os.system ['echo pwned']\n"))

    def test_top_level_and_version_errors(self):
        self.assertIn("mapping", self.err("- a\n- b\n"))
        self.assertIn("version", self.err("tools: {}\n"))
        self.assertIn("version", self.err("version: 2\ntools: {}\n"))
        self.assertIn("unknown top-level key", self.err("version: 1\ntools: {}\nextra: 1\n"))

    def test_default_decision_must_be_deny(self):
        self.assertIn("default_decision", self.err("version: 1\ndefault_decision: ALLOW\ntools: {}\n"))

    def test_rule_errors(self):
        self.assertIn("risk", self.err("version: 1\ntools:\n  a: {decision: ALLOW}\n"))
        self.assertIn("decision", self.err("version: 1\ntools:\n  a: {risk: low, decision: MAYBE}\n"))
        self.assertIn("invalid tool name", self.err("version: 1\ntools:\n  'A B': {risk: low, decision: ALLOW}\n"))
        self.assertIn("approval_ttl_seconds", self.err("version: 1\ntools:\n  a: {risk: low, decision: ALLOW, approval_ttl_seconds: 1}\n"))
        self.assertIn("max_calls", self.err("version: 1\ntools:\n  a: {risk: low, decision: ALLOW, max_calls: 0}\n"))
        self.assertIn("enabled", self.err("version: 1\ntools:\n  a: {risk: low, decision: ALLOW, enabled: 'yes'}\n"))

    def test_builtin_constraint_errors(self):
        self.assertIn("unknown constraint", self.err("version: 1\ntools:\n  calculator: {risk: low, decision: ALLOW, allowd_roots: []}\n"))
        self.assertIn("directory does not exist", self.err("version: 1\ntools:\n  filesystem.read: {risk: low, decision: ALLOW, allowed_roots: [./nope]}\n"))
        self.assertIn("required", self.err("version: 1\ntools:\n  filesystem.read: {risk: low, decision: ALLOW}\n"))
        self.assertIn("wildcards", self.err("version: 1\ntools:\n  http.fetch: {risk: low, decision: ALLOW, allowed_hosts: ['*.example.com']}\n"))
        self.assertIn("one of", self.err("version: 1\ntools:\n  http.fetch: {risk: low, decision: ALLOW, allowed_hosts: [a.com], allowed_schemes: [ftp]}\n"))
        self.assertIn("boolean", self.err("version: 1\ntools:\n  http.fetch: {risk: low, decision: ALLOW, allowed_hosts: [a.com], block_private_addresses: 'false'}\n"))

    def test_arg_constraints_validated(self):
        self.assertIn("unknown argument constraint", self.err("version: 1\ntools:\n  a: {risk: low, decision: ALLOW, arg_constraints: {x: {regex: '.*'}}}\n"))
        self.assertIn("enum", self.err("version: 1\ntools:\n  a: {risk: low, decision: ALLOW, arg_constraints: {x: {enum: []}}}\n"))

    def test_collects_multiple_errors(self):
        msg = self.err("version: 1\ntools:\n  a: {decision: ALLOW}\n  b: {risk: low}\n")
        self.assertIn("tools.a.risk", msg)
        self.assertIn("tools.b.decision", msg)

    def test_size_limit(self):
        with self.assertRaises(PolicyError):
            self.load("version: 1\n#" + "x" * 300_000 + "\ntools: {}\n")

    def test_pathologically_nested_yaml_is_a_policy_error_not_a_crash(self):
        with self.assertRaises(PolicyError):
            self.load("version: 1\ntools: " + "[" * 100_000 + "]" * 100_000)
        with self.assertRaises(PolicyError):
            self.load("version: 1\ntools: " + "{a: " * 50_000 + "1" + "}" * 50_000)

    def test_invalid_utf8_file_is_a_policy_error(self):
        path = os.path.join(self.tmp, "bad.yaml")
        with open(path, "wb") as fh:
            fh.write(b"version: 1\ntools: {}\n# \xff\xfe\n")
        with self.assertRaises(PolicyError):
            Policy.from_file(path)

    def test_missing_file(self):
        with self.assertRaises(PolicyError):
            Policy.from_file(os.path.join(self.tmp, "nope.yaml"))


if __name__ == "__main__":
    unittest.main()
