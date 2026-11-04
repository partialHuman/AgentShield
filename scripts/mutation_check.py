"""Sanity-check the test suite's power: break security-critical code on purpose and confirm tests fail.

Usage: python scripts/mutation_check.py
Each mutation is applied to a throw-away copy of ``src/``; the full suite must FAIL for the mutation to count
as "killed". A surviving mutation means a security property is not actually pinned down by tests.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MUTATIONS = [
    ("DENY no longer blocks execution", "shield.py",
     "        if result.decision is Decision.DENY:\n            raise ActionDenied(result)\n", "        if False:\n            raise ActionDenied(result)\n"),
    ("REQUIRE_APPROVAL no longer blocks execution", "shield.py",
     "        if result.decision is Decision.REQUIRE_APPROVAL:\n            raise ApprovalPending(result)\n", "        if False:\n            raise ApprovalPending(result)\n"),
    ("constraint violations ignored", "evaluator.py", "        if codes:\n            seen: list[str] = []", "        if False:\n            seen: list[str] = []"),
    ("evaluator error becomes ALLOW-path (no fail-closed)", "shield.py",
     "            result = DecisionResult(\n                Decision.DENY, [Reason.EVALUATOR_ERROR], name,", "            raise\n            result = DecisionResult(\n                Decision.DENY, [Reason.EVALUATOR_ERROR], name,"),
    ("filesystem: symlinks followed (no O_NOFOLLOW)", "adapters/filesystem.py", "_O_NOFOLLOW = getattr(os, \"O_NOFOLLOW\", 0)", "_O_NOFOLLOW = 0"),
    ("filesystem: '..' allowed", "adapters/filesystem.py", "        if part == \"..\":\n            raise PathProblem(Reason.PATH_TRAVERSAL", "        if False:\n            raise PathProblem(Reason.PATH_TRAVERSAL"),
    ("filesystem: hard links allowed", "adapters/filesystem.py", "        if st.st_nlink > 1:\n            raise ExecutionError(\"HARDLINK_NOT_ALLOWED\")\n        if st.st_size", "        if False:\n            raise ExecutionError(\"HARDLINK_NOT_ALLOWED\")\n        if st.st_size"),
    ("http: use-time destination revalidation skipped", "adapters/http_fetch.py", "            if codes or parsed is None:", "            if parsed is None:"),
    ("http: redirects not revalidated against allowlist", "adapters/http_fetch.py", "REDIRECT_BLOCKED\" if hops else \"DESTINATION_BLOCKED\"", "DESTINATION_BLOCKED\" if hops else \"DESTINATION_BLOCKED\""),
    ("netguard: IPv4-mapped IPv6 not unwrapped", "netguard.py", "        inner = _embedded_v4(ip)\n        if inner is not None:", "        inner = None\n        if inner is not None:"),
    ("netguard: one private address among several is tolerated", "netguard.py", "            return [Reason.ADDRESS_BLOCKED], []  # one bad address poisons the set", "            continue"),
    ("netguard: non-canonical numeric hosts accepted", "netguard.py", "    if _NUMERIC_HOST.match(h.lower()):\n        raise HostError", "    if False:\n        raise HostError"),
    ("approvals: consumed approvals can be reused", "approvals.py", "if row is not None and row[\"status\"] == \"approved\" and row[\"expires_at\"] > now:", "if row is not None and row[\"expires_at\"] > now:"),
    ("approvals: expiry ignored on consume", "approvals.py", "and row[\"expires_at\"] > now:\n                    expected", "and True:\n                    expected"),
    ("approvals: MAC not verified", "approvals.py", "if hmac.compare_digest(expected, row[\"mac\"] or \"\"):\n                        c.execute(\"UPDATE approvals SET status='consumed'", "if True:\n                        c.execute(\"UPDATE approvals SET status='consumed'"),
    ("approvals: not bound to agent identity", "approvals.py", "WHERE action_hash=? AND policy_hash=? AND agent_id=? \"\n                \"AND status IN", "WHERE action_hash=? AND policy_hash=? AND ?=? \"\n                \"AND status IN"),
    ("audit: event hash ignores contents", "audit.py", "    body = {k: v for k, v in event.items() if k != \"hash\"}", "    body = {\"seq\": event.get(\"seq\")}"),
    ("audit: decision event written AFTER dispatch (ordering)", "shield.py", "        result = self._audit_decision(result, request_id, duration_ms)\n        self._metrics.observe(result, duration_ms)", "        self._metrics.observe(result, duration_ms)"),
    ("policy: duplicate YAML keys allowed", "policy.py", "            if key in seen:", "            if False:"),
    ("policy: YAML aliases allowed", "policy.py", "        if self.check_event(yaml.events.AliasEvent):", "        if False:"),
    ("redaction: URL query strings logged", "adapters/http_fetch.py", "    has_query = \"?\" in p.target\n    return truncate(f\"{p.scheme}://{p.netloc}{path}{'?[redacted]' if has_query else ''}\", 300)", "    return truncate(p.url(), 300)"),
    ("redaction: file contents logged", "adapters/filesystem.py", "            \"content_bytes\": len(a[\"content\"].encode(\"utf-8\")),", "            \"content\": a[\"content\"], \"content_bytes\": 0,"),
    ("normalizer: unknown arguments accepted", "normalize.py", "        if not allow_extra:\n            raise NormalizationError(Reason.SCHEMA_UNEXPECTED_FIELD", "        if False:\n            raise NormalizationError(Reason.SCHEMA_UNEXPECTED_FIELD"),
    ("normalizer: control characters accepted in paths", "normalize.py", "    if _bad_chars(value, allow_space=(kind in (\"path\", \"str\"))):", "    if False:"),
    ("calculator: complex results allowed", "adapters/calculator.py", "    if type(v) not in (int, float):", "    if False:"),
    ("call limit not enforced", "shield.py", "                if self._calls[name] >= tp.max_calls:\n                    result = _with(result, Decision.DENY, [Reason.CALL_LIMIT_EXCEEDED], \"call limit reached\")\n                else:", "                if False:\n                    pass\n                else:"),
]


def main() -> int:
    survivors = []
    for name, rel, old, new in MUTATIONS:
        work = tempfile.mkdtemp(prefix="mut-")
        try:
            shutil.copytree(os.path.join(ROOT, "src"), os.path.join(work, "src"))
            path = os.path.join(work, "src", "agentshield", rel)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            if old not in text:
                print(f"?? PATCH NOT APPLICABLE: {name}")
                survivors.append(name)
                continue
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text.replace(old, new, 1))
            env = dict(os.environ, PYTHONPATH=os.pathsep.join([os.path.join(work, "src"), ROOT]))
            p = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."], cwd=ROOT, env=env,
                               capture_output=True, text=True, timeout=600)
            killed = p.returncode != 0
            print(f"{'killed  ' if killed else 'SURVIVED'}  {name}")
            if not killed:
                survivors.append(name)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    print(f"\n{len(MUTATIONS) - len(survivors)}/{len(MUTATIONS)} mutations killed")
    return 1 if survivors else 0


if __name__ == "__main__":
    raise SystemExit(main())
