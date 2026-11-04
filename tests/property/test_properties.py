"""Seeded randomized (property-style) tests using only the standard library.

Override with AGENTSHIELD_FUZZ_SEED / AGENTSHIELD_FUZZ_N. If ``hypothesis`` is installed in CI, these
complement (not replace) any Hypothesis-based tests you add.
"""

import dataclasses
import json
import os
import random
import string
import threading
import time
import unittest

from agentshield import (
    ActionDenied, ApprovalPending, ArgSpec, AuditLog, Decision, ExecutionError, Policy, PolicyError, Shield, Tool,
    ToolExecutionError, verify_chain,
)
from agentshield.adapters import calculator_tool, file_read_tool, file_write_tool, http_fetch_tool
from agentshield.adapters.calculator import calculate
from agentshield.adapters.filesystem import PathProblem, resolve_in_roots
from agentshield.approvals import ApprovalStore
from agentshield.netguard import HostError, parse_url
from agentshield.normalize import NormalizationError, normalize_args
from tests.helpers import TmpDirTestCase

SEED = int(os.environ.get("AGENTSHIELD_FUZZ_SEED", "1337"))
N = int(os.environ.get("AGENTSHIELD_FUZZ_N", "2500"))

NASTY = [
    "", " ", "..", "../..", "/", "//", "/etc/passwd", "a/../b", "\x00", "a\x00b", "\n", "\r\n", "\u202e", "\u200b", "%2e%2e", "..\\..\\x",
    "caf\u00e9", "cafe\u0301", "\ud800", "x" * 5000, "http://169.254.169.254/", "https://docs.example.com/", "https://docs.example.com@evil.com/",
    "file:///etc/passwd", "http://[::1]/", "http://2130706433/", "__import__('os')", "1+1", "9**9**9", "workspace/hello.txt", "output/a.txt",
    "{}", "[]", "null", "true", "\u0000\u0001\u0002", "\U0001f600", "\\\\server\\share", "C:\\Windows", "docs.example.com", "/tmp",
]


def rand_scalar(r: random.Random):
    k = r.randrange(9)
    if k == 0:
        return r.choice(NASTY)
    if k == 1:
        return "".join(r.choice(string.printable + "\u00e9\u202e\u200b") for _ in range(r.randrange(0, 40)))
    if k == 2:
        return r.randrange(-2**70, 2**70)
    if k == 3:
        return r.choice([0.0, -0.0, 1.5, float("nan"), float("inf"), 1e308])
    if k == 4:
        return r.choice([True, False, None])
    if k == 5:
        return bytes(r.randrange(256) for _ in range(r.randrange(8)))
    if k == 6:
        return object()
    if k == 7:
        return r.choice(NASTY) + r.choice(NASTY)
    return r.choice(NASTY)


def rand_value(r: random.Random, depth=0):
    if depth < 4 and r.random() < 0.2:
        if r.random() < 0.5:
            return [rand_value(r, depth + 1) for _ in range(r.randrange(4))]
        return {r.choice(NASTY + ["a", "path", "url"]): rand_value(r, depth + 1) for _ in range(r.randrange(4))}
    return rand_scalar(r)


class NoopCounter:
    def __init__(self):
        self.calls = 0

    def __call__(self, **kw):
        self.calls += 1
        return "ok"


def noop_tool(tool: Tool, counter: NoopCounter) -> Tool:
    return dataclasses.replace(tool, executor_factory=lambda tp: counter)


class DenyMeansNoExecutionProperty(TmpDirTestCase):
    """Property: for ANY input, a non-ALLOW outcome never invokes an executor; ALLOW <=> evaluate said ALLOW."""

    def setUp(self):
        super().setUp()
        os.makedirs(os.path.join(self.ws, "docs"))
        pol = {
            "version": 1,
            "tools": {
                "calculator": {"risk": "low", "decision": "ALLOW"},
                "filesystem.read": {"risk": "medium", "decision": "ALLOW", "allowed_roots": ["./workspace"]},
                "filesystem.write": {"risk": "high", "decision": "REQUIRE_APPROVAL", "allowed_roots": ["./workspace/output"]},
                "http.fetch": {"risk": "medium", "decision": "ALLOW", "allowed_hosts": ["docs.example.com"]},
                "demo.deny": {"risk": "low", "decision": "DENY"},
                "demo.argc": {"risk": "low", "decision": "ALLOW", "max_calls": 50,
                              "arg_constraints": {"n": {"min": 0, "max": 100}, "s": {"max_length": 10, "prefixes": ["ok"]}}},
            },
        }
        self.counter = NoopCounter()
        self.sh = Shield(Policy.from_text(json.dumps(pol), base_dir=self.tmp), agent_id="fuzz",
                         approvals=ApprovalStore(os.path.join(self.tmp, "ap")))
        res = lambda h, p: ["93.184.216.34"]  # noqa: E731
        tools = [calculator_tool(), file_read_tool(), file_write_tool(), http_fetch_tool(resolver=res),
                 Tool.from_callable(None, "demo.deny", {}), Tool.from_callable(None, "demo.argc", {"n": ArgSpec("int", required=False), "s": ArgSpec("str", required=False)})]
        self.fns = {t.name: self.sh.wrap(noop_tool(t, self.counter)) for t in tools}
        self.names = list(self.fns) + ["shell.exec", "", "FILESYSTEM.READ"]

    def test_property(self):
        r = random.Random(SEED)
        allowed = denied = pending = 0
        for i in range(N):
            name = r.choice(self.names)
            if r.random() < 0.15:
                args = rand_value(r)
            else:
                args = {r.choice(["path", "url", "expression", "content", "overwrite", "n", "s", "extra"]): rand_value(r) for _ in range(r.randrange(0, 4))}
            verdict = self.sh.evaluate(name, args)
            fn = self.fns.get(name)
            before = self.counter.calls
            if fn is None or not isinstance(args, dict) or not all(isinstance(k, str) for k in args):
                self.assertEqual(verdict.decision, Decision.DENY, (name, args))
                continue
            try:
                fn(**args)
                outcome = "allow"
                allowed += 1
            except ActionDenied:
                outcome = "deny"
                denied += 1
            except ApprovalPending:
                outcome = "pending"
                pending += 1
            except ToolExecutionError:
                outcome = "allow"
            ran = self.counter.calls - before
            if outcome == "allow":
                self.assertEqual(ran, 1, (name, args))
                self.assertEqual(verdict.decision, Decision.ALLOW, ("executed but evaluate disagreed", name, args))
            else:
                self.assertEqual(ran, 0, ("executor ran despite non-ALLOW", name, args, outcome))
                if outcome == "deny" and name != "demo.argc":  # demo.argc has stateful call limits
                    self.assertNotEqual(verdict.decision, Decision.ALLOW, (name, args))
        self.assertGreater(denied, N // 4)
        self.assertGreater(allowed, 0, "fuzzer should also reach the ALLOW path")

    def test_audit_decision_count_matches_calls(self):
        r = random.Random(SEED + 1)
        calls = 0
        for _ in range(500):
            name = r.choice(list(self.fns))
            try:
                self.fns[name](**{"path": r.choice(NASTY)} if r.random() < 0.5 else {})
            except (ActionDenied, ApprovalPending, ToolExecutionError):
                pass
            calls += 1
        decisions = [e for e in self.sh.audit.events if e["type"] == "decision"]
        self.assertEqual(len(decisions), calls)
        outcomes = [e for e in self.sh.audit.events if e["type"] == "outcome"]
        self.assertEqual(len(outcomes), sum(1 for d in decisions if d["decision"] == "ALLOW"))
        self.assertEqual(self.counter.calls, len(outcomes))


class ComponentFuzz(unittest.TestCase):
    def test_normalizer_only_raises_normalization_error(self):
        r = random.Random(SEED)
        schema = {"a": ArgSpec("str"), "b": ArgSpec("path", required=False), "c": ArgSpec("int", required=False),
                  "d": ArgSpec("json", required=False), "e": ArgSpec("number", required=False), "f": ArgSpec("url", required=False)}
        for _ in range(N):
            raw = rand_value(r) if r.random() < 0.2 else {k: rand_value(r) for k in r.sample(list(schema) + ["zz"], r.randrange(0, 5))}
            try:
                out = normalize_args(schema, raw)
            except NormalizationError:
                continue
            for v in out.values():  # anything that passes is well-formed
                json.dumps(v, allow_nan=False)

    @unittest.skipUnless(os.name == "posix", "uses POSIX path arithmetic")
    def test_path_resolution_never_escapes_root(self):
        r = random.Random(SEED)
        roots = ["/srv/ws", "/srv/other"]
        segs = ["a", "b", "..", ".", "", "c.txt", "\u00e9", "...", " ", "/", "srv", "ws", "other"]
        for _ in range(N * 4):
            p = "".join(r.choice(segs) + r.choice(["/", "/", ""]) for _ in range(r.randrange(1, 8)))
            if r.random() < 0.3:
                p = "/srv/ws/" + p
            try:
                root, parts = resolve_in_roots(p, roots, windows=False)
            except PathProblem:
                continue
            self.assertTrue(parts and all(x not in ("", ".", "..") and "/" not in x for x in parts), (p, parts))
            joined = os.path.normpath(root + "/" + "/".join(parts))
            self.assertEqual(os.path.commonpath([root, joined]), root, p)

    def test_url_parser_only_raises_host_error_and_normalizes(self):
        r = random.Random(SEED)
        pieces = ["http", "https", "://", "@", ":", "/", "?", "#", "docs.example.com", "127.0.0.1", "[::1]", "0x7f", "%2e", "..", "a", "\\", " ", "\u00e9", "80", "99999", ".", "\n"]
        for _ in range(N * 4):
            url = "".join(r.choice(pieces) for _ in range(r.randrange(1, 12)))
            try:
                p = parse_url(url)
            except HostError:
                continue
            self.assertIn(p.scheme, ("http", "https"))
            self.assertEqual(p.host, p.host.lower())
            self.assertTrue(0 < p.port < 65536)
            self.assertFalse(any(c in p.host for c in " @\\%/"), (url, p.host))

    def test_calculator_is_total_and_fast(self):
        r = random.Random(SEED)
        toks = ["1", "2", "3.5", "0", "(", ")", "+", "-", "*", "/", "//", "%", "**", " ", "a", "1e9", "99999999999", "__", ".", "x"]
        start = time.monotonic()
        for _ in range(N * 2):
            expr = "".join(r.choice(toks) for _ in range(r.randrange(1, 30)))
            t0 = time.monotonic()
            try:
                v = calculate(expr)
                self.assertIn(type(v), (int, float), expr)
            except ExecutionError:
                pass
            self.assertLess(time.monotonic() - t0, 0.5, expr)
        self.assertLess(time.monotonic() - start, 20)

    def test_policy_parser_only_raises_policy_error(self):
        r = random.Random(SEED)
        with open(os.path.join(os.path.dirname(__file__), "..", "..", "examples", "policies", "default-deny.yaml"), encoding="utf-8") as fh:
            base = fh.read()
        ok = bad = 0
        for _ in range(min(N, 1500)):
            text = base
            for _ in range(r.randrange(1, 5)):
                if not text:
                    break
                kind = r.randrange(4)
                i = r.randrange(len(text))
                if kind == 0:
                    text = text[:i] + r.choice(["", ":", "- ", "\t", "{", "}", "[", "*a", "&a", "!!python/object:os.system", "\x00", "\u202e", "'"]) + text[i + r.randrange(0, 4):]
                elif kind == 1:
                    text = text[:i]
                elif kind == 2:
                    text = text.replace(r.choice(["ALLOW", "DENY", "true", "false", "443", "low", "high", "REQUIRE_APPROVAL"]), r.choice(NASTY[:12] + ["1", "null", "[]", "{}", "yes", "no"]), 1)
                else:
                    text = text[:i] + "\n" + text[i:]
            try:
                Policy.from_text(text, base_dir=os.path.join(os.path.dirname(__file__), "..", "..", "examples", "policies"))
                ok += 1
            except PolicyError:
                bad += 1
        self.assertGreater(bad, 0)


class ConcurrencyProperty(TmpDirTestCase):
    def test_threads_keep_chain_and_exact_executor_counts(self):
        path = os.path.join(self.tmp, "audit.jsonl")
        pol = {"version": 1, "tools": {"demo.argc": {"risk": "low", "decision": "ALLOW", "arg_constraints": {"n": {"min": 0, "max": 10}}}}}
        sh = Shield(Policy.from_text(json.dumps(pol), base_dir=self.tmp), agent_id="mt", audit=AuditLog(path))
        counter = NoopCounter()
        fn = sh.wrap(Tool.from_callable(counter, "demo.argc", {"n": ArgSpec("int")}))
        allowed = [0] * 6

        def worker(idx):
            r = random.Random(SEED + idx)
            for _ in range(200):
                try:
                    fn(n=r.randrange(0, 20))
                    allowed[idx] += 1
                except ActionDenied:
                    pass

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        sh.audit.close()
        self.assertEqual(counter.calls, sum(allowed))
        res = verify_chain(path)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.events, 6 * 200 + sum(allowed))


if __name__ == "__main__":
    unittest.main()
