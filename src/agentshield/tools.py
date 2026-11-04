"""Tool definitions: schema + resource checker + executor factory."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .constraints import C
from .normalize import ArgSpec
from .policy import ToolPolicy

_NAME = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")


@dataclass(frozen=True)
class CheckOutcome:
    """Result of a tool's resource check (decision-time, advisory for TOCTOU-sensitive resources)."""

    target: str | None = None  # exact canonical target; bound into the action hash
    deny_codes: tuple[str, ...] = ()
    trace: tuple[str, ...] = ()
    display_target: str | None = None  # redacted form for audit events and approval prompts (defaults to target)


Checker = Callable[[dict[str, Any], ToolPolicy], CheckOutcome]
Summarizer = Callable[[dict[str, Any]], dict[str, Any]]
ExecutorFactory = Callable[[ToolPolicy], Callable[..., Any]]


@dataclass(frozen=True)
class Tool:
    """A protectable tool.

    ``executor_factory`` receives the validated ToolPolicy and returns the callable
    that performs the real action. Shield captures it privately; it is only invoked
    after an ALLOW decision.
    """

    name: str
    args: Mapping[str, ArgSpec]
    executor_factory: ExecutorFactory
    checker: Checker | None = None
    constraint_schema: Mapping[str, C] | None = None
    summarize: Summarizer | None = None
    allow_extra_args: bool = False

    def __post_init__(self) -> None:
        if not _NAME.match(self.name):
            raise ValueError(f"invalid tool name {self.name!r}")

    @staticmethod
    def from_callable(
        fn: Callable[..., Any],
        name: str,
        args: Mapping[str, ArgSpec],
        *,
        checker: Checker | None = None,
        constraint_schema: Mapping[str, C] | None = None,
        summarize: Summarizer | None = None,
    ) -> Tool:
        """Protect an ordinary (sync or async) function."""
        return Tool(
            name=name,
            args=dict(args),
            executor_factory=lambda _tp: fn,
            checker=checker,
            constraint_schema=constraint_schema,
            summarize=summarize,
        )
