"""Policy loading and validation (strict YAML, structured constraints)."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import yaml

from .constraints import BUILTIN_SCHEMAS, C, validate_constraints
from .models import Decision, PolicyError
from .normalize import canonical_json, sha256_hex

MAX_POLICY_BYTES = 256 * 1024
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
_RISKS = ("low", "medium", "high")
_COMMON_KEYS = {"enabled", "risk", "decision", "approval_ttl_seconds", "max_calls", "arg_constraints"}
_ARG_CONSTRAINT_KEYS = {"enum", "max_length", "prefixes", "min", "max"}


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys, non-string keys and aliases."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            mark = self.peek_event().start_mark
            raise yaml.constructor.ConstructorError(None, None, "YAML aliases are not allowed in policies", mark)
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if type(key) is not str:
                raise yaml.constructor.ConstructorError(
                    None, None, f"mapping keys must be strings, got {key!r}", key_node.start_mark
                )
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _depth(obj: Any, limit: int = 12, cur: int = 0) -> bool:
    if cur > limit:
        return False
    if isinstance(obj, dict):
        return all(_depth(v, limit, cur + 1) for v in obj.values())
    if isinstance(obj, list):
        return all(_depth(v, limit, cur + 1) for v in obj)
    return True


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    enabled: bool
    risk: str
    decision: Decision
    approval_ttl_seconds: int = 300
    max_calls: int | None = None
    arg_constraints: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    constraints: Mapping[str, Any] = field(default_factory=dict)  # validated tool-specific
    extra: Mapping[str, Any] = field(default_factory=dict)  # raw, validated at wrap time

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "risk": self.risk,
            "decision": self.decision.value,
            "approval_ttl_seconds": self.approval_ttl_seconds,
            "max_calls": self.max_calls,
            "arg_constraints": {k: dict(v) for k, v in self.arg_constraints.items()},
            "constraints": dict(self.constraints) if self.constraints else dict(self.extra),
        }

    def with_schema(self, schema: Mapping[str, C], base_dir: str) -> ToolPolicy:
        raw = dict(self.extra) if self.extra else dict(self.constraints)
        values, errors = validate_constraints(raw, schema, base_dir=base_dir, where=f"tools.{self.name}")
        if errors:
            raise PolicyError(errors)
        return ToolPolicy(
            self.name, self.enabled, self.risk, self.decision, self.approval_ttl_seconds,
            self.max_calls, self.arg_constraints, values, {},
        )


def _validate_arg_constraints(raw: Any, where: str, errors: list[str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if raw is None:
        return out
    if not isinstance(raw, dict):
        errors.append(f"{where}: must be a mapping of argument name to constraints")
        return out
    for arg, spec in raw.items():
        w = f"{where}.{arg}"
        if not isinstance(spec, dict):
            errors.append(f"{w}: must be a mapping")
            continue
        for k in spec:
            if k not in _ARG_CONSTRAINT_KEYS:
                errors.append(f"{w}.{k}: unknown argument constraint (allowed: {sorted(_ARG_CONSTRAINT_KEYS)})")
        item: dict[str, Any] = {}
        if "enum" in spec:
            v = spec["enum"]
            if type(v) is not list or not v or any(type(x) not in (str, int) for x in v):
                errors.append(f"{w}.enum: must be a non-empty list of strings or integers")
            else:
                item["enum"] = list(v)
        if "prefixes" in spec:
            v = spec["prefixes"]
            if type(v) is not list or not v or any(type(x) is not str or not x for x in v):
                errors.append(f"{w}.prefixes: must be a non-empty list of strings")
            else:
                item["prefixes"] = list(v)
        if "max_length" in spec:
            v = spec["max_length"]
            if type(v) is not int or v < 0:
                errors.append(f"{w}.max_length: must be a non-negative integer")
            else:
                item["max_length"] = v
        for k in ("min", "max"):
            if k in spec:
                v = spec[k]
                if type(v) not in (int, float):
                    errors.append(f"{w}.{k}: must be a number")
                else:
                    item[k] = v
        out[arg] = item
    return out


@dataclass(frozen=True)
class Policy:
    version: int
    default_decision: Decision
    tools: Mapping[str, ToolPolicy]
    hash: str
    base_dir: str

    # ---- constructors ----
    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> Policy:
        p = os.fspath(path)
        try:
            size = os.path.getsize(p)
        except OSError as exc:
            raise PolicyError(f"cannot read policy file: {exc.strerror or exc}") from None
        if size > MAX_POLICY_BYTES:
            raise PolicyError(f"policy file larger than {MAX_POLICY_BYTES} bytes")
        try:
            with open(p, encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            raise PolicyError(f"cannot read policy file: {type(exc).__name__}") from None
        return cls.from_text(text, base_dir=os.path.dirname(os.path.abspath(p)))

    @classmethod
    def from_text(cls, text: str, *, base_dir: str | None = None) -> Policy:
        if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
            raise PolicyError(f"policy larger than {MAX_POLICY_BYTES} bytes")
        try:
            data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - strict SafeLoader subclass
        except yaml.YAMLError as exc:
            raise PolicyError(f"YAML error: {str(exc).splitlines()[0] if str(exc) else exc}") from None
        except (RecursionError, MemoryError):
            raise PolicyError("policy is nested too deeply or too large to parse") from None
        return cls.from_dict(data, base_dir=base_dir)

    @classmethod
    def from_dict(cls, data: Any, *, base_dir: str | None = None) -> Policy:
        base = os.path.abspath(base_dir or os.getcwd())
        errors: list[str] = []
        if not isinstance(data, dict):
            raise PolicyError("policy must be a mapping at the top level")
        if not _depth(data):
            raise PolicyError("policy is nested too deeply")
        for k in data:
            if k not in ("version", "default_decision", "tools"):
                errors.append(f"{k}: unknown top-level key")
        if data.get("version") != 1 or type(data.get("version")) is not int:
            errors.append("version: must be the integer 1")
        dd = data.get("default_decision", "DENY")
        if dd != "DENY":
            errors.append("default_decision: must be DENY (default-deny is mandatory in v0.1)")
        raw_tools = data.get("tools")
        if not isinstance(raw_tools, dict):
            errors.append("tools: must be a mapping of tool name to rule")
            raw_tools = {}
        tools: dict[str, ToolPolicy] = {}
        for name, rule in raw_tools.items():
            where = f"tools.{name}"
            if not _TOOL_NAME.match(name):
                errors.append(f"{where}: invalid tool name (use lower-case dotted names)")
                continue
            if not isinstance(rule, dict):
                errors.append(f"{where}: must be a mapping")
                continue
            enabled = rule.get("enabled", True)
            if type(enabled) is not bool:
                errors.append(f"{where}.enabled: must be a boolean")
            risk = rule.get("risk")
            if risk not in _RISKS:
                errors.append(f"{where}.risk: required, one of {list(_RISKS)}")
            decision_raw = rule.get("decision")
            try:
                decision = Decision(decision_raw)
            except ValueError:
                errors.append(f"{where}.decision: required, one of ALLOW, REQUIRE_APPROVAL, DENY")
                decision = Decision.DENY
            ttl = rule.get("approval_ttl_seconds", 300)
            if type(ttl) is not int or not 10 <= ttl <= 86400:
                errors.append(f"{where}.approval_ttl_seconds: integer between 10 and 86400")
                ttl = 300
            max_calls = rule.get("max_calls")
            if max_calls is not None and (type(max_calls) is not int or max_calls < 1):
                errors.append(f"{where}.max_calls: must be a positive integer")
                max_calls = None
            argc = _validate_arg_constraints(rule.get("arg_constraints"), f"{where}.arg_constraints", errors)
            extra = {k: v for k, v in rule.items() if k not in _COMMON_KEYS}
            tp = ToolPolicy(
                name, bool(enabled), str(risk), decision, ttl, max_calls, argc, {}, extra,
            )
            if name in BUILTIN_SCHEMAS:
                try:
                    tp = tp.with_schema(BUILTIN_SCHEMAS[name], base)
                except PolicyError as exc:
                    errors.extend(exc.errors)
                    continue
            tools[name] = tp
        if errors:
            raise PolicyError(errors)
        canon = {
            "version": 1,
            "default_decision": "DENY",
            "tools": {n: t.to_dict() for n, t in sorted(tools.items())},
        }
        return cls(1, Decision.DENY, tools, sha256_hex(canonical_json(_jsonable(canon))), base)

    def tool_policy(self, name: str) -> ToolPolicy | None:
        return self.tools.get(name)


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return obj
