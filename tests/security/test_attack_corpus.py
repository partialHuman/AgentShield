import dataclasses
import json
import os
import unittest

from agentshield import ActionDenied, ApprovalPending, ArgSpec, Decision, Policy, Shield, Tool, ToolExecutionError
from agentshield.adapters import calculator_tool, file_read_tool, file_write_tool, http_fetch_tool
from agentshield.approvals import ApprovalStore
from tests.helpers import Counter, TmpDirTestCase
from tests.security import corpus

POSIX = os.name == "posix"


class Spy:
    """Wraps an executor_factory so we can prove whether the real executor ever ran."""

    def __init__(self):
        self.calls = 0

    def wrap(self, tool: Tool) -> Tool:
        inner = tool.executor_factory

        def factory(tp):
            real = inner(tp)

            def spied(**kw):
                self.calls += 1
                return real(**kw)

            return spied

        return dataclasses.replace(tool, executor_factory=factory)


def resolver(host, port):
    if host not in corpus.DNS:
        raise OSError("NXDOMAIN")
    return corpus.DNS[host]


def connector(ip, port, timeout):  # any attempt to connect in the corpus tests is a failure
    raise AssertionError(f"attack scenario attempted a network connection to {ip}:{port}")


class Env(TmpDirTestCase):
    """Shared world: a workspace with hostile things in it, plus a locked-down policy."""

    def build(self):
        self.outside = os.path.join(self.tmp, "outside")
        os.makedirs(self.outside)
        self.secret_path = os.path.join(self.outside, "secret.txt")
        with open(self.secret_path, "w") as fh:
            fh.write(corpus.SECRET)
        os.makedirs(os.path.join(self.ws, "docs", "nested", "deep"))
        os.makedirs(os.path.join(self.ws, "output", "sub", "dir"))
        for rel in ("docs/guide.md", "docs/nested/deep/file.txt", "notes (final).txt", "data-2026_11.csv", "caf\u00e9.txt",
                    "\u65e5\u672c\u8a9e.txt", "file.with.many.dots.txt", ".hidden", "UPPER.TXT", "a b c.txt"):
            with open(os.path.join(self.ws, rel), "w", encoding="utf-8") as fh:
                fh.write("content")
        os.symlink(self.secret_path, os.path.join(self.ws, "link.txt"))
        os.symlink(self.outside, os.path.join(self.ws, "dirlink"))
        os.symlink(os.path.join(self.outside, "nonexistent"), os.path.join(self.ws, "dangling"))
        os.symlink(self.outside, os.path.join(self.ws, "output", "wlink"))
        os.link(self.secret_path, os.path.join(self.ws, "hard.txt"))
        os.mkfifo(os.path.join(self.ws, "pipe"))
        os.makedirs(self.ws + "-evil")
        with open(os.path.join(self.ws + "-evil", "x.txt"), "w") as fh:
            fh.write("evil")
        pol = {
            "version": 1,
            "tools": {
                "calculator": {"risk": "low", "decision": "ALLOW"},
                "filesystem.read": {"risk": "medium", "decision": "ALLOW", "allowed_roots": ["./workspace"], "max_bytes": 1000},
                "filesystem.write": {"risk": "high", "decision": "REQUIRE_APPROVAL", "allowed_roots": ["./workspace/output"], "max_bytes": 1000},
                "http.fetch": {
                    "risk": "medium", "decision": "ALLOW", "allowed_hosts": list(corpus.DNS) + ["169.254.169.254", "93.184.216.34", "::ffff:7f00:1"],
                    "allowed_ports": [443, 8443],
                },
                "demo.delete": {"risk": "high", "decision": "DENY"},
                "demo.disabled": {"enabled": False, "risk": "low", "decision": "ALLOW"},
            },
        }
        self.sh = Shield(Policy.from_text(json.dumps(pol), base_dir=self.tmp), agent_id="attacker",
                         approvals=ApprovalStore(os.path.join(self.tmp, "ap")))
        self.spy = Spy()
        self.fns = {}
        for t in (calculator_tool(), file_read_tool(), file_write_tool(), http_fetch_tool(resolver=resolver, connector=connector)):
            self.fns[t.name] = self.sh.wrap(self.spy.wrap(t))
        for name in ("demo.delete", "demo.disabled", "demo.unlisted"):
            self.fns[name] = self.sh.wrap(self.spy.wrap(Tool.from_callable(Counter(), name, {"target": ArgSpec("str", required=False)})))

    def subst(self, v):
        if isinstance(v, str):
            return v.replace("{ws}", self.ws).replace("{outside}", self.outside)
        if isinstance(v, dict):
            return {k: self.subst(x) for k, x in v.items()}
        return v


@unittest.skipUnless(POSIX, "corpus builds symlinks, hard links and FIFOs")
class AttackCorpusTests(Env):
    def setUp(self):
        super().setUp()
        self.build()

    def snapshot(self):
        names = sorted(os.listdir(self.outside))
        with open(self.secret_path) as fh:
            return names, fh.read()

    def test_corpus_size(self):
        self.assertGreaterEqual(len(corpus.ATTACKS), 30)
        self.assertEqual(len({a.id for a in corpus.ATTACKS}), len(corpus.ATTACKS), "ids must be unique")

    def test_every_attack(self):
        before = self.snapshot()
        for atk in corpus.ATTACKS:
            with self.subTest(atk.id, desc=atk.description):
                args = self.subst(atk.args)
                spy_before = self.spy.calls
                if not isinstance(atk.tool, str) or atk.tool not in self.fns:
                    result = self.sh.evaluate(atk.tool, args)
                    self.assertEqual(result.decision, Decision.DENY)
                    self.assertTrue(set(atk.codes) <= set(result.reason_codes), (atk.codes, result.reason_codes))
                    continue
                fn = self.fns[atk.tool]
                kwargs = args if isinstance(args, dict) else None
                if kwargs is None:  # non-mapping args cannot be passed as **kwargs; exercise the evaluator directly
                    result = self.sh.evaluate(atk.tool, args)
                    self.assertEqual(result.decision, Decision.DENY)
                    self.assertTrue(set(atk.codes) <= set(result.reason_codes), (atk.codes, result.reason_codes))
                    continue
                if atk.expect == "deny":
                    with self.assertRaises(ActionDenied) as cm:
                        fn(**kwargs)
                    self.assertTrue(set(atk.codes) <= set(cm.exception.result.reason_codes), (atk.codes, cm.exception.result.reason_codes))
                    self.assertEqual(self.spy.calls, spy_before, "executor must not run for a denied action")
                elif atk.expect == "approval":
                    with self.assertRaises(ApprovalPending):
                        fn(**kwargs)
                    self.assertEqual(self.spy.calls, spy_before, "executor must not run while approval is pending")
                else:  # safe: may be allowed by policy, but must not succeed in doing harm
                    try:
                        out = fn(**kwargs)
                    except (ActionDenied, ToolExecutionError):
                        pass
                    else:
                        self.assertNotIn(corpus.SECRET, json.dumps(out, default=str))
        self.assertEqual(self.snapshot(), before, "nothing outside the workspace may change")
        self.assertFalse(os.path.exists(os.path.join(self.outside, "pwned.txt")))
        self.assertNotIn(corpus.SECRET, json.dumps(self.sh.audit.events, default=str), "secrets never reach the audit log")

    def test_attack_doc_is_in_sync_with_corpus(self):
        path = os.path.join(os.path.dirname(__file__), "..", "..", "docs", "attack-scenarios.md")
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), corpus.render_markdown(), "run: python -m tests.security.corpus --write docs/attack-scenarios.md")


@unittest.skipUnless(POSIX, "corpus builds symlinks, hard links and FIFOs")
class BenignCorpusTests(Env):
    def setUp(self):
        super().setUp()
        self.build()

    def test_corpus_size(self):
        self.assertGreaterEqual(len(corpus.BENIGN), 50)

    def test_zero_false_blocks_on_benign_corpus(self):
        false_blocks = []
        for tool, args in corpus.BENIGN:
            r = self.sh.evaluate(tool, self.subst(args))
            want = Decision.REQUIRE_APPROVAL if tool == "filesystem.write" else Decision.ALLOW
            if r.decision != want:
                false_blocks.append((tool, args, r.decision.value, r.reason_codes))
        rate = len(false_blocks) / len(corpus.BENIGN)
        self.assertEqual(false_blocks, [], f"false-block rate {rate:.1%}")

    def test_benign_calculator_and_reads_actually_execute(self):
        self.assertEqual(self.fns["calculator"](expression="2 ** 10"), 1024)
        self.assertEqual(self.fns["filesystem.read"](path="docs/guide.md")["content"], "content")
        self.assertEqual(self.fns["filesystem.read"](path="cafe\u0301.txt")["content"], "content")


if __name__ == "__main__":
    unittest.main()
