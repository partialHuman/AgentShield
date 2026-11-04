"""The Shield: authorizes every tool call before the real executor can run."""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import logging
import re
import threading
import time
import uuid
from collections import Counter, deque
from collections.abc import Callable, Mapping
from typing import Any

from .approvals import ApprovalStore
from .audit import AuditLog
from .constraints import BUILTIN_SCHEMAS
from .evaluator import Bound, Evaluator
from .models import (
    ActionDenied,
    ApprovalPending,
    ApprovalStoreError,
    AuditWriteError,
    Decision,
    DecisionResult,
    ExecutionError,
    Reason,
    ToolExecutionError,
)
from .policy import Policy
from .tools import Tool

log = logging.getLogger("agentshield")
_AGENT_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


@dataclasses.dataclass
class _Auth:
    """Internal authorization ticket (holds normalized args; never handed to agents)."""

    result: DecisionResult
    args: dict[str, Any]
    request_id: str


class _Metrics:
    """In-process counters (FR-12). No endpoint, no secrets."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.decisions: Counter[str] = Counter()
        self.reasons: Counter[str] = Counter()
        self.counters: Counter[str] = Counter()
        self.latency_ms: deque[float] = deque(maxlen=2048)

    def observe(self, result: DecisionResult, ms: float) -> None:
        with self._lock:
            self.decisions[result.decision.value] += 1
            if result.decision is Decision.DENY:
                for c in result.reason_codes:
                    self.reasons[c] += 1
            self.latency_ms.append(ms)

    def bump(self, name: str) -> None:
        with self._lock:
            self.counters[name] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            lat = sorted(self.latency_ms)

            def pct(p: float) -> float | None:
                return round(lat[min(len(lat) - 1, int(p * len(lat)))], 4) if lat else None

            return {
                "decisions": dict(self.decisions),
                "denials_by_reason": dict(self.reasons),
                "counters": dict(self.counters),
                "decision_latency_ms": {"count": len(lat), "p50": pct(0.5), "p95": pct(0.95), "max": lat[-1] if lat else None},
            }


class Shield:
    """Wraps tools so that only ALLOWed (or approved) calls reach their executors."""

    def __init__(
        self,
        policy: Policy,
        *,
        agent_id: str,
        audit: AuditLog | None = None,
        approvals: ApprovalStore | None = None,
        allow_unaudited_low_risk: bool = False,
    ):
        if not isinstance(agent_id, str) or not _AGENT_ID.match(agent_id):
            raise ValueError("agent_id must match [A-Za-z0-9_.:@-]{1,128}")
        self._policy = policy
        self._agent_id = agent_id
        self._audit = audit if audit is not None else AuditLog()
        self._approvals = approvals
        self._allow_unaudited_low_risk = allow_unaudited_low_risk
        self._bound: dict[str, Bound] = {}
        self._executors: dict[str, Callable[..., Any]] = {}
        self._evaluator = Evaluator(policy, self._bound)
        self._calls: Counter[str] = Counter()
        self._calls_lock = threading.Lock()
        self._metrics = _Metrics()

    # ------------------------------------------------------------ public API
    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def audit(self) -> AuditLog:
        return self._audit

    def metrics(self) -> dict[str, Any]:
        return self._metrics.snapshot()

    def evaluate(self, tool: str, args: Mapping[str, Any]) -> DecisionResult:
        """Dry run: evaluate policy only. No execution, no audit event, no approval created."""
        try:
            return self._evaluator.evaluate(tool, args).result
        except Exception:  # noqa: BLE001
            return DecisionResult(
                Decision.DENY, [Reason.EVALUATOR_ERROR], tool if isinstance(tool, str) else "<invalid>",
                policy_version=self._policy.version, policy_hash=self._policy.hash,
            )

    def call(self, tool: str, args: Mapping[str, Any]) -> Any:
        """Dispatch by tool name (what agent loops receive from a model). Unknown names are denied and audited."""
        return self._run_sync(tool, args)  # type: ignore[arg-type]

    async def acall(self, tool: str, args: Mapping[str, Any]) -> Any:
        """Async variant of :meth:`call`."""
        return await self._run_async(tool, args)  # type: ignore[arg-type]

    def wrap(self, tool: Tool) -> Callable[..., Any]:
        """Return a protected callable. Async executors yield an async callable."""
        executor = self._register(tool)
        if executor is not None and inspect.iscoroutinefunction(executor):
            return self._make_async(tool)
        return self._make_sync(tool)

    def wrap_async(self, tool: Tool) -> Callable[..., Any]:
        """Like ``wrap`` but always returns an async callable (sync executors run in a thread)."""
        self._register(tool)
        return self._make_async(tool)

    # ------------------------------------------------------------ registration
    def _register(self, tool: Tool) -> Callable[..., Any] | None:
        if tool.name in self._bound:
            raise ValueError(f"tool {tool.name!r} is already wrapped by this shield")
        tp = self._policy.tool_policy(tool.name)
        if tp is not None and tool.name not in BUILTIN_SCHEMAS:
            tp = tp.with_schema(tool.constraint_schema or {}, self._policy.base_dir)  # raises PolicyError
        executor: Callable[..., Any] | None = None
        if tp is not None and tp.enabled and tp.decision is not Decision.DENY:
            executor = tool.executor_factory(tp)
            if not callable(executor):
                raise TypeError("executor_factory must return a callable")
        if tp is None:
            log.warning("tool %r has no policy rule; every call will be denied (default deny)", tool.name)
        self._bound[tool.name] = Bound(tool, tp)
        if executor is not None:
            self._executors[tool.name] = executor
        return executor

    def _make_sync(self, tool: Tool) -> Callable[..., Any]:
        name = tool.name

        def protected(*args: Any, **kwargs: Any) -> Any:
            if args:
                raise TypeError("protected tools accept keyword arguments only")
            return self._run_sync(name, kwargs)

        protected.__name__ = name.replace(".", "_")
        protected.__doc__ = f"AgentShield-protected tool {name!r}."
        return protected

    def _make_async(self, tool: Tool) -> Callable[..., Any]:
        name = tool.name

        async def protected(*args: Any, **kwargs: Any) -> Any:
            if args:
                raise TypeError("protected tools accept keyword arguments only")
            return await self._run_async(name, kwargs)

        protected.__name__ = name.replace(".", "_")
        protected.__doc__ = f"AgentShield-protected tool {name!r}."
        return protected

    # ------------------------------------------------------------ execution paths
    def _run_sync(self, name: str, kwargs: Any) -> Any:
        auth = self._authorize(name, kwargs)
        executor = self._executors[name]
        start = time.perf_counter()
        try:
            value = executor(**auth.args)
        except BaseException as exc:
            self._finish_error(auth, exc, start)
            if isinstance(exc, Exception):
                raise ToolExecutionError(name, _error_code(exc), auth.result.event_id) from exc
            raise
        self._finish_ok(auth, value, start)
        return value

    async def _run_async(self, name: str, kwargs: Any) -> Any:
        auth = await asyncio.to_thread(self._authorize, name, kwargs)
        executor = self._executors[name]
        start = time.perf_counter()
        try:
            if inspect.iscoroutinefunction(executor):
                value = await executor(**auth.args)
            else:
                value = await asyncio.to_thread(lambda: executor(**auth.args))
        except BaseException as exc:
            self._finish_error(auth, exc, start)
            if isinstance(exc, Exception):
                raise ToolExecutionError(name, _error_code(exc), auth.result.event_id) from exc
            raise
        self._finish_ok(auth, value, start)
        return value

    # ------------------------------------------------------------ authorization
    def _authorize(self, name: str, kwargs: Any) -> _Auth:
        request_id = uuid.uuid4().hex
        t0 = time.perf_counter()
        args: dict[str, Any] | None
        try:
            ev = self._evaluator.evaluate(name, kwargs)
            result, args = ev.result, ev.args
        except Exception:  # noqa: BLE001 - evaluator failure is a DENY, never an ALLOW
            log.exception("policy evaluation failed for tool %r", name)
            result = DecisionResult(
                Decision.DENY, [Reason.EVALUATOR_ERROR], name, policy_version=self._policy.version,
                policy_hash=self._policy.hash,
            )
            args = None
        bound = self._bound.get(name) if isinstance(name, str) else None
        tp = bound.policy if bound else None

        if tp is not None and tp.max_calls is not None and result.decision is Decision.REQUIRE_APPROVAL:
            # don't queue approval requests for a tool whose budget is already spent (advisory; the
            # authoritative, atomic check-and-reserve happens below for every ALLOW)
            with self._calls_lock:
                exhausted = self._calls[name] >= tp.max_calls
            if exhausted:
                result = _with(result, Decision.DENY, [Reason.CALL_LIMIT_EXCEEDED], "call limit reached")

        if result.decision is Decision.REQUIRE_APPROVAL:
            result = self._resolve_approval(result, tp.approval_ttl_seconds if tp else 300)

        if result.decision is Decision.ALLOW and tp is not None and tp.max_calls is not None:
            with self._calls_lock:
                if self._calls[name] >= tp.max_calls:
                    result = _with(result, Decision.DENY, [Reason.CALL_LIMIT_EXCEEDED], "call limit reached")
                else:
                    self._calls[name] += 1

        duration_ms = (time.perf_counter() - t0) * 1000
        result = self._audit_decision(result, request_id, duration_ms)
        self._metrics.observe(result, duration_ms)

        if result.decision is Decision.DENY:
            raise ActionDenied(result)
        if result.decision is Decision.REQUIRE_APPROVAL:
            raise ApprovalPending(result)
        if args is None:  # pragma: no cover - defensive: ALLOW always carries args
            raise ActionDenied(_with(result, Decision.DENY, [Reason.EVALUATOR_ERROR], "missing args"))
        return _Auth(result, args, request_id)

    def _resolve_approval(self, result: DecisionResult, ttl: int) -> DecisionResult:
        store = self._approvals
        if store is None:
            return _with(result, Decision.DENY, [Reason.APPROVAL_UNAVAILABLE], "no approval store configured")
        assert result.action_hash and result.policy_hash
        try:
            res = store.resolve(result.action_hash, result.policy_hash, self._agent_id)
            if res.state == "approved" and res.record is not None:
                if store.consume(res.record.id):
                    self._metrics.bump("approvals_consumed")
                    out = _with(result, Decision.ALLOW, [Reason.APPROVAL_CONSUMED], "approval consumed (single use)")
                    out.approval_id = res.record.id
                    return out
                return _with(result, Decision.DENY, [Reason.APPROVAL_INVALID], "approval could not be consumed")
            if res.state == "pending" and res.record is not None:
                out = _with(result, Decision.REQUIRE_APPROVAL, [Reason.APPROVAL_PENDING], "approval still pending")
                out.approval_id = res.record.id
                return out
            if res.state == "rejected":
                return _with(result, Decision.DENY, [Reason.APPROVAL_REJECTED], "approval was rejected")
            if res.state == "invalid":
                return _with(result, Decision.DENY, [Reason.APPROVAL_INVALID], "approval record failed authenticity check")
            rec = store.request(
                action_hash=result.action_hash, policy_hash=result.policy_hash, agent_id=self._agent_id,
                tool=result.tool, risk=result.risk, ttl_seconds=ttl,
                summary={"tool": result.tool, "risk": result.risk, "target": result.target,
                         "args": result.args_summary, "action_hash": result.action_hash},
            )
            self._metrics.bump("approvals_requested")
            out = _with(result, Decision.REQUIRE_APPROVAL, [Reason.APPROVAL_REQUIRED], "approval requested")
            out.approval_id = rec.id
            return out
        except ApprovalStoreError as exc:
            code = Reason.APPROVAL_QUEUE_FULL if "full" in str(exc) else Reason.APPROVAL_UNAVAILABLE
            return _with(result, Decision.DENY, [code], "approval store refused")
        except Exception:  # noqa: BLE001
            log.exception("approval store failure")
            return _with(result, Decision.DENY, [Reason.APPROVAL_UNAVAILABLE], "approval store failure")

    def _audit_decision(self, result: DecisionResult, request_id: str, duration_ms: float) -> DecisionResult:
        try:
            ev = self._audit.record(
                "decision",
                request_id=request_id, agent_id=self._agent_id, tool=result.tool, risk=result.risk,
                decision=result.decision.value, reason_codes=result.reason_codes,
                policy_version=result.policy_version, policy_hash=result.policy_hash,
                action_hash=result.action_hash, target=_clip(result.target), args_summary=result.args_summary,
                approval_id=result.approval_id, duration_ms=round(duration_ms, 4),
            )
            result.event_id = ev["event_id"]
            return result
        except AuditWriteError:
            self._metrics.bump("audit_failures")
            if result.decision is Decision.ALLOW and result.risk == "low" and self._allow_unaudited_low_risk:
                log.error("audit unavailable; proceeding (explicit low-risk fallback) for %r", result.tool)
                return result
            if result.decision is Decision.ALLOW:
                return _with(result, Decision.DENY, [Reason.AUDIT_UNAVAILABLE], "decision event could not be written")
            return result  # DENY / REQUIRE_APPROVAL: nothing executes either way

    def _outcome(self, auth: _Auth, status: str, error_code: str | None, start: float, size: int | None) -> None:
        try:
            self._audit.record(
                "outcome",
                request_id=auth.request_id, decision_event_id=auth.result.event_id, agent_id=self._agent_id,
                tool=auth.result.tool, status=status, error_code=error_code,
                duration_ms=round((time.perf_counter() - start) * 1000, 4), result_size=size,
            )
        except AuditWriteError:
            self._metrics.bump("audit_failures")
            log.error("could not write outcome event for tool %r", auth.result.tool)

    def _finish_ok(self, auth: _Auth, value: Any, start: float) -> None:
        size = len(value) if isinstance(value, (str, bytes, list, dict, tuple)) else None
        self._outcome(auth, "ok", None, start, size)

    def _finish_error(self, auth: _Auth, exc: BaseException, start: float) -> None:
        if isinstance(exc, asyncio.CancelledError):
            self._outcome(auth, "cancelled", None, start, None)
        elif isinstance(exc, Exception):
            self._metrics.bump("execution_errors")
            self._outcome(auth, "error", _error_code(exc), start, None)
        else:
            self._outcome(auth, "interrupted", None, start, None)


def _error_code(exc: Exception) -> str:
    return exc.code if isinstance(exc, ExecutionError) else "EXECUTOR_EXCEPTION"


def _clip(s: str | None, n: int = 512) -> str | None:
    return s if s is None or len(s) <= n else s[:n]


def _with(result: DecisionResult, decision: Decision, codes: list[str], note: str) -> DecisionResult:
    trace = [*result.trace, f"shield: {note} -> {decision.value} ({', '.join(codes)})"]
    return dataclasses.replace(result, decision=decision, reason_codes=codes, trace=trace)
