"""AgentShield: runtime authorization firewall for AI-agent tool calls."""

from .approvals import ApprovalRecord, ApprovalStore
from .audit import AuditLog, VerifyResult, verify_chain
from .constraints import C
from .models import (
    ActionDenied,
    AgentShieldError,
    ApprovalPending,
    ApprovalStoreError,
    AuditWriteError,
    Decision,
    DecisionResult,
    ExecutionError,
    PolicyError,
    Reason,
    ToolExecutionError,
)
from .normalize import ArgSpec
from .policy import Policy
from .shield import Shield
from .tools import CheckOutcome, Tool

__version__ = "0.1.0a1"

__all__ = [
    "ActionDenied", "AgentShieldError", "ApprovalPending", "ApprovalRecord", "ApprovalStore",
    "ApprovalStoreError", "ArgSpec", "AuditLog", "AuditWriteError", "C", "CheckOutcome", "Decision",
    "DecisionResult", "ExecutionError", "Policy", "PolicyError", "Reason", "Shield", "Tool",
    "ToolExecutionError", "VerifyResult", "__version__", "verify_chain",
]
