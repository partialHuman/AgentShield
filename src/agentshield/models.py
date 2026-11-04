"""Core data types, reason codes and exceptions."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Decision(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Reason:
    """Stable reason codes. Developers see these; agents do not."""

    ALLOWED = "ALLOWED_BY_POLICY"
    APPROVAL_CONSUMED = "APPROVAL_CONSUMED"
    # request / schema
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    SCHEMA_MISSING_FIELD = "SCHEMA_MISSING_FIELD"
    SCHEMA_UNEXPECTED_FIELD = "SCHEMA_UNEXPECTED_FIELD"
    SCHEMA_INVALID_TYPE = "SCHEMA_INVALID_TYPE"
    SCHEMA_INVALID_VALUE = "SCHEMA_INVALID_VALUE"
    ARG_TOO_LARGE = "ARG_TOO_LARGE"
    ARG_TOO_DEEP = "ARG_TOO_DEEP"
    ARG_INVALID_CHARACTERS = "ARG_INVALID_CHARACTERS"
    # policy
    NO_POLICY_RULE = "NO_POLICY_RULE"
    TOOL_DISABLED = "TOOL_DISABLED"
    EXPLICIT_DENY = "EXPLICIT_DENY"
    ARG_CONSTRAINT_VIOLATION = "ARG_CONSTRAINT_VIOLATION"
    CALL_LIMIT_EXCEEDED = "CALL_LIMIT_EXCEEDED"
    EVALUATOR_ERROR = "EVALUATOR_ERROR"
    # filesystem
    PATH_INVALID = "PATH_INVALID"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    PATH_OUTSIDE_ROOT = "PATH_OUTSIDE_ROOT"
    PATH_SYMLINK = "PATH_SYMLINK"
    CONTENT_TOO_LARGE = "CONTENT_TOO_LARGE"
    # network
    URL_INVALID = "URL_INVALID"
    URL_SCHEME_NOT_ALLOWED = "URL_SCHEME_NOT_ALLOWED"
    URL_USERINFO = "URL_USERINFO"
    HOST_NOT_ALLOWED = "HOST_NOT_ALLOWED"
    HOST_AMBIGUOUS_IP = "HOST_AMBIGUOUS_IP"
    PORT_NOT_ALLOWED = "PORT_NOT_ALLOWED"
    ADDRESS_BLOCKED = "ADDRESS_BLOCKED"
    DNS_FAILURE = "DNS_FAILURE"
    # approvals
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    APPROVAL_UNAVAILABLE = "APPROVAL_UNAVAILABLE"
    APPROVAL_QUEUE_FULL = "APPROVAL_QUEUE_FULL"
    # audit
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"


ALL_REASON_CODES = frozenset(v for k, v in vars(Reason).items() if k.isupper() and isinstance(v, str))


@dataclass
class DecisionResult:
    """Outcome of evaluating one proposed action. Developer-facing."""

    decision: Decision
    reason_codes: list[str]
    tool: str
    risk: str | None = None
    target: str | None = None
    args_summary: dict[str, Any] = field(default_factory=dict)
    action_hash: str | None = None
    policy_version: int | None = None
    policy_hash: str | None = None
    trace: list[str] = field(default_factory=list)
    approval_id: str | None = None
    event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason_codes": list(self.reason_codes),
            "tool": self.tool,
            "risk": self.risk,
            "target": self.target,
            "args_summary": self.args_summary,
            "action_hash": self.action_hash,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "trace": list(self.trace),
            "approval_id": self.approval_id,
            "event_id": self.event_id,
        }


class AgentShieldError(Exception):
    """Base class for all AgentShield errors."""


class PolicyError(AgentShieldError, ValueError):
    def __init__(self, errors: list[str] | str):
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("invalid policy: " + "; ".join(self.errors))


class ActionDenied(AgentShieldError):
    """The action was denied. ``str(e)`` is generic; use ``e.result`` for details."""

    code = "ACTION_DENIED"

    def __init__(self, result: DecisionResult):
        super().__init__("Action denied by security policy.")
        self.result = result
        self.event_id = result.event_id

    def agent_message(self) -> str:
        return "Action denied by security policy."


class ApprovalPending(AgentShieldError):
    """The action needs human approval. Re-submit the identical call after approval."""

    code = "APPROVAL_PENDING"

    def __init__(self, result: DecisionResult):
        super().__init__("Action requires human approval.")
        self.result = result
        self.request_id = result.approval_id
        self.event_id = result.event_id

    def agent_message(self) -> str:
        return f"Action requires human approval (request {self.request_id})."


class ToolExecutionError(AgentShieldError):
    """The tool was authorized but failed while executing."""

    code = "TOOL_EXECUTION_ERROR"

    def __init__(self, tool: str, error_code: str, event_id: str | None = None):
        super().__init__(f"Tool {tool!r} failed ({error_code}).")
        self.tool = tool
        self.error_code = error_code
        self.event_id = event_id

    def agent_message(self) -> str:
        return f"Tool failed ({self.error_code})."


class ExecutionError(Exception):
    """Raised by executors/adapters with a stable, non-sensitive error code."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class AuditWriteError(AgentShieldError):
    pass


class ApprovalStoreError(AgentShieldError):
    pass
