import json
import statistics
import time
import unittest

from agentshield import ArgSpec, Policy, Shield, Tool
from agentshield.adapters import calculator_tool, http_fetch_tool


class PerfBudgetTests(unittest.TestCase):
    """Loose regression guard for the PRD target (p95 < 10 ms, excluding DNS and file I/O)."""

    def test_policy_evaluation_p95_under_budget(self):
        pol = {"version": 1, "tools": {
            "calculator": {"risk": "low", "decision": "ALLOW"},
            "http.fetch": {"risk": "medium", "decision": "ALLOW", "allowed_hosts": ["docs.example.com"]},
            "demo.t": {"risk": "low", "decision": "ALLOW", "arg_constraints": {"n": {"max": 5}}},
        }}
        sh = Shield(Policy.from_text(json.dumps(pol), base_dir="."), agent_id="perf")
        sh.wrap(calculator_tool())
        sh.wrap(http_fetch_tool(resolver=lambda h, p: ["93.184.216.34"]))
        sh.wrap(Tool.from_callable(lambda n: None, "demo.t", {"n": ArgSpec("int")}))
        cases = [("calculator", {"expression": "1+2*3"}), ("http.fetch", {"url": "https://docs.example.com/x?y=1"}), ("demo.t", {"n": 3}),
                 ("shell.exec", {})]
        for tool, args in cases:
            samples = []
            for _ in range(400):
                t = time.perf_counter()
                sh.evaluate(tool, args)
                samples.append((time.perf_counter() - t) * 1000)
            samples.sort()
            self.assertLess(samples[int(0.95 * len(samples))], 10.0, (tool, statistics.median(samples)))


if __name__ == "__main__":
    unittest.main()
