"""Command-line interface: lint, evaluate/explain, approvals, audit verification.

Exit codes: 0 ok / ALLOW, 1 DENY or verification failure, 2 invalid input or policy,
3 REQUIRE_APPROVAL (for ``evaluate``/``explain``).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from . import __version__
from .adapters import builtin_tools
from .approvals import ApprovalStore
from .audit import verify_chain
from .constraints import BUILTIN_SCHEMAS
from .models import ApprovalStoreError, Decision, PolicyError
from .policy import Policy
from .shield import Shield

DEFAULT_DIR = ".agentshield"


def _out(obj: Any, as_json: bool, text: str) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True) if as_json else text)


def _load_policy(path: str) -> Policy | None:
    try:
        return Policy.from_file(path)
    except PolicyError as exc:
        for e in exc.errors:
            print(f"error: {e}", file=sys.stderr)
        return None


def _warnings(policy: Policy) -> list[str]:
    out: list[str] = []
    for name, tp in policy.tools.items():
        if tp.decision is Decision.ALLOW and tp.risk == "high":
            out.append(f"{name}: high-risk tool is set to ALLOW; consider REQUIRE_APPROVAL")
        if name not in BUILTIN_SCHEMAS and tp.enabled and tp.decision is not Decision.DENY:
            out.append(f"{name}: not a built-in tool; constraints are validated when the tool is wrapped")
        c = tp.constraints
        if c.get("block_private_addresses") is False:
            out.append(f"{name}: block_private_addresses is false (private/loopback targets are reachable)")
        if "http" in c.get("allowed_schemes", ()):
            out.append(f"{name}: plain http is allowed (no transport encryption)")
        if tp.risk == "low" and name.startswith(("filesystem.", "http.")):
            out.append(f"{name}: risk 'low' is unusual for a resource-touching tool")
    return out


def cmd_lint(a: argparse.Namespace) -> int:
    policy = _load_policy(a.policy)
    if policy is None:
        return 2
    warns = _warnings(policy)
    info = {
        "ok": True, "policy_hash": policy.hash, "version": policy.version,
        "tools": {n: {"decision": t.decision.value, "risk": t.risk, "enabled": t.enabled} for n, t in policy.tools.items()},
        "warnings": warns,
    }
    lines = [f"OK  policy v{policy.version}  hash {policy.hash[:16]}  ({len(policy.tools)} tools)"]
    lines += [f"  {n:<18} {t.decision.value:<17} risk={t.risk}{'' if t.enabled else '  (disabled)'}" for n, t in policy.tools.items()]
    lines += [f"warning: {w}" for w in warns]
    _out(info, a.json, "\n".join(lines))
    return 0


def _shield_for_dry_run(policy: Policy, agent_id: str) -> Shield:
    shield = Shield(policy, agent_id=agent_id)
    for name, tool in builtin_tools().items():
        if name in policy.tools:
            shield.wrap(tool)
    return shield


def cmd_evaluate(a: argparse.Namespace, explain: bool = False) -> int:
    policy = _load_policy(a.policy)
    if policy is None:
        return 2
    try:
        raw = a.args
        if raw.startswith("@"):
            with open(raw[1:], encoding="utf-8") as fh:
                raw = fh.read()
        args = json.loads(raw)
    except (OSError, ValueError) as exc:
        print(f"error: --args must be a JSON object or @file ({exc})", file=sys.stderr)
        return 2
    shield = _shield_for_dry_run(policy, a.agent_id)
    result = shield.evaluate(a.tool, args)
    d = result.to_dict()
    if not explain:
        d.pop("trace")
    text = f"{result.decision.value}  [{', '.join(result.reason_codes)}]"
    if result.target:
        text += f"\n  target: {result.target}"
    if explain:
        text += "\n" + "\n".join(f"  - {t}" for t in result.trace)
    _out(d, a.json, text)
    return {Decision.ALLOW: 0, Decision.DENY: 1, Decision.REQUIRE_APPROVAL: 3}[result.decision]


def _store(a: argparse.Namespace) -> ApprovalStore:
    return ApprovalStore(a.dir)


def _fmt_rec(store: ApprovalStore, r: Any) -> str:
    status = "expired" if r.status in ("pending", "approved") and store.is_expired(r) else r.status
    return f"{r.id}  {status:<9} {r.tool:<18} agent={r.agent_id}  target={r.summary.get('target')}"


def cmd_approvals(a: argparse.Namespace) -> int:
    try:
        store = _store(a)
        if a.action == "list":
            recs = store.list(a.status)
            _out([r.to_dict() for r in recs], a.json, "\n".join(_fmt_rec(store, r) for r in recs) or "(no approvals)")
            return 0
        rec = store.get(a.id)
        if rec is None:
            print("error: no such approval request", file=sys.stderr)
            return 2
        if a.action == "show":
            _out(rec.to_dict(), a.json, _fmt_rec(store, rec) + "\n" + json.dumps(rec.summary, indent=2, sort_keys=True)
                 + f"\n  action_hash: {rec.action_hash}")
            return 0
        approve = a.action == "approve"
        if not a.yes:
            print(_fmt_rec(store, rec))
            print(json.dumps(rec.summary, indent=2, sort_keys=True))
            print(f"action_hash: {rec.action_hash}")
            answer = input(f"{'Approve' if approve else 'Reject'} this exact action? [y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                print("aborted")
                return 1
        done = store.decide(a.id, approve)
        _out(done.to_dict(), a.json, f"{done.status}: {done.id} (by {done.approver})")
        return 0
    except ApprovalStoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def cmd_audit(a: argparse.Namespace) -> int:
    res = verify_chain(a.file, head_path=a.head, expect_hash=a.expect_hash)
    msg = f"OK  {res.events} events, last hash {res.last_hash}" if res.ok else (
        f"FAILED: {res.error}" + (f" (line {res.line})" if res.line else ""))
    _out(res.to_dict(), a.json, msg)
    return 0 if res.ok else 1


def cmd_schema(_: argparse.Namespace) -> int:
    from .schema import render

    print(render(), end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentshield", description="AgentShield: runtime authorization for AI-agent tool calls.")
    p.add_argument("--version", action="version", version=f"agentshield {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("lint", help="validate a policy file")
    s.add_argument("policy"); s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_lint)

    for name, explain in (("evaluate", False), ("explain", True)):
        s = sub.add_parser(name, help="dry-run an action against a policy (never executes tools)")
        s.add_argument("policy"); s.add_argument("--tool", required=True)
        s.add_argument("--args", required=True, help="JSON object, or @file.json")
        s.add_argument("--agent-id", default="cli"); s.add_argument("--json", action="store_true")
        s.set_defaults(fn=(lambda a, e=explain: cmd_evaluate(a, e)))

    s = sub.add_parser("schema", help="print the JSON Schema for policy files")
    s.set_defaults(fn=cmd_schema)

    s = sub.add_parser("approvals", help="manage pending approvals")
    s.add_argument("--dir", default=DEFAULT_DIR, help=f"approval store directory (default {DEFAULT_DIR})")
    s.add_argument("--json", action="store_true")
    asub = s.add_subparsers(dest="action", required=True)
    ls = asub.add_parser("list"); ls.add_argument("--status", choices=["pending", "approved", "rejected", "consumed"])
    for act in ("show", "approve", "reject"):
        x = asub.add_parser(act); x.add_argument("id")
        if act != "show":
            x.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    s.set_defaults(fn=cmd_approvals)

    s = sub.add_parser("audit", help="audit log tools")
    asub = s.add_subparsers(dest="action", required=True)
    v = asub.add_parser("verify", help="verify the hash chain of an audit log")
    v.add_argument("file"); v.add_argument("--head"); v.add_argument("--expect-hash")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_audit)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
