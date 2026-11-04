"""Pure(ish) policy evaluation: no execution, no approvals, no audit."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .models import Decision, DecisionResult, Reason
from .normalize import (
    NormalizationError,
    action_hash,
    bound_summary,
    default_summary,
    normalize_args,
)
from .policy import Policy, ToolPolicy
from .tools import Tool


@dataclass(frozen=True)
class Bound:
    tool: Tool
    policy: ToolPolicy | None


@dataclass
class Evaluation:
    """Evaluator output plus the normalized args (internal; not exposed to agents)."""

    result: DecisionResult
    args: dict[str, Any] | None


def _check_arg_constraints(args: Mapping[str, Any], tp: ToolPolicy) -> list[str]:
    problems: list[str] = []
    for name, c in tp.arg_constraints.items():
        if name not in args:
            continue
        v = args[name]
        if "enum" in c and v not in c["enum"]:
            problems.append(f"{name}: not in enum")
        if "max_length" in c and isinstance(v, str) and len(v) > c["max_length"]:
            problems.append(f"{name}: longer than {c['max_length']}")
        if "prefixes" in c:
            if not isinstance(v, str) or not any(v.startswith(p) for p in c["prefixes"]):
                problems.append(f"{name}: prefix not allowed")
        if ("min" in c or "max" in c) and type(v) in (int, float):
            if "min" in c and v < c["min"]:
                problems.append(f"{name}: below minimum")
            if "max" in c and v > c["max"]:
                problems.append(f"{name}: above maximum")
        elif ("min" in c or "max" in c) and type(v) not in (int, float):
            problems.append(f"{name}: not a number")
    return problems


class Evaluator:
    def __init__(self, policy: Policy, tools: Mapping[str, Bound]):
        self._policy = policy
        self._tools = tools

    def evaluate(self, tool_name: Any, raw_args: Any) -> Evaluation:
        pol = self._policy
        name = tool_name if isinstance(tool_name, str) and len(tool_name) <= 128 else "<invalid>"
        base: dict[str, Any] = {"tool": name, "policy_version": pol.version, "policy_hash": pol.hash}
        trace: list[str] = []

        def deny(codes: list[str], **kw: Any) -> Evaluation:
            trace.append("decision: DENY (" + ", ".join(codes) + ")")
            return Evaluation(DecisionResult(Decision.DENY, codes, trace=trace, **{**base, **kw}), None)

        bound = self._tools.get(name) if isinstance(tool_name, str) else None
        if bound is None:
            trace.append("tool: not registered with this shield")
            return deny([Reason.UNKNOWN_TOOL])
        tool, tp = bound.tool, bound.policy
        trace.append(f"tool: {name} registered")

        try:
            args = normalize_args(tool.args, raw_args, allow_extra=tool.allow_extra_args)
        except NormalizationError as exc:
            trace.append(f"schema: {exc.code} field={exc.field}")
            keys = sorted(k for k in raw_args if isinstance(k, str))[:16] if isinstance(raw_args, Mapping) else []
            return deny([exc.code], args_summary={"_arg_names": keys})
        trace.append("schema: ok")

        summary = bound_summary(tool.summarize(args) if tool.summarize else default_summary(args))
        base["args_summary"] = summary

        if tp is None:
            trace.append("policy: no rule for this tool (default deny)")
            return deny([Reason.NO_POLICY_RULE])
        base["risk"] = tp.risk
        if not tp.enabled:
            trace.append("policy: tool disabled")
            return deny([Reason.TOOL_DISABLED])
        if tp.decision is Decision.DENY:
            trace.append("policy: explicit DENY rule")
            return deny([Reason.EXPLICIT_DENY])

        codes: list[str] = []
        target: str | None = None
        shown: str | None = None
        if tool.checker is not None:
            outcome = tool.checker(args, tp)
            target = outcome.target
            shown = outcome.display_target if outcome.display_target is not None else outcome.target
            trace.extend(f"check: {t}" for t in outcome.trace)
            codes.extend(outcome.deny_codes)
        problems = _check_arg_constraints(args, tp)
        for p in problems:
            trace.append(f"arg_constraint: {p}")
        if problems:
            codes.append(Reason.ARG_CONSTRAINT_VIOLATION)
        if shown is not None:
            base["target"] = shown
        if codes:
            seen: list[str] = []
            for c in codes:
                if c not in seen:
                    seen.append(c)
            return deny(seen)
        trace.append("constraints: all satisfied")

        ahash = action_hash(name, args, target)
        base["action_hash"] = ahash
        if tp.decision is Decision.REQUIRE_APPROVAL:
            trace.append("decision: REQUIRE_APPROVAL (policy rule)")
            return Evaluation(
                DecisionResult(Decision.REQUIRE_APPROVAL, [Reason.APPROVAL_REQUIRED], trace=trace, **base), args
            )
        trace.append("decision: ALLOW (policy rule)")
        return Evaluation(DecisionResult(Decision.ALLOW, [Reason.ALLOWED], trace=trace, **base), args)
