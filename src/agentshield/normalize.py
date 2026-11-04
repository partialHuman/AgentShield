"""Argument validation and normalization.

All strings that identify resources (paths, URLs, identifiers) are Unicode
NFC-normalized and stripped of control/format characters. Free text is left
byte-for-byte intact (only NUL and unencodable surrogates are rejected).
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .models import Reason


@dataclass(frozen=True)
class Limits:
    max_arg_bytes: int = 2 * 1024 * 1024
    max_depth: int = 8
    max_items: int = 256
    max_str: int = 1024 * 1024
    max_path: int = 4096
    max_url: int = 2048
    max_ident: int = 256


DEFAULT_LIMITS = Limits()
_UNSET: Any = object()
_INT_BOUND = 2**63


class NormalizationError(Exception):
    def __init__(self, code: str, field: str | None = None, detail: str = ""):
        super().__init__(f"{code} ({field}): {detail}" if field else code)
        self.code = code
        self.field = field
        self.detail = detail


@dataclass(frozen=True)
class ArgSpec:
    """Schema for one argument.

    kind: ``str`` (identifier-like), ``text`` (free text), ``path``, ``url``,
    ``int``, ``number``, ``bool`` or ``json`` (bounded nested structure).
    """

    kind: str
    required: bool = True
    max_length: int | None = None
    default: Any = _UNSET


_KINDS = {"str", "text", "path", "url", "int", "number", "bool", "json"}


def _bad_chars(s: str, *, allow_space: bool) -> bool:
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            return True
        if not allow_space and cat == "Zs":
            return True
    return False


def _clean_string(value: str, kind: str, name: str, limits: Limits, max_length: int | None) -> str:
    cap = {
        "path": limits.max_path,
        "url": limits.max_url,
        "str": limits.max_ident,
        "text": limits.max_str,
    }[kind]
    if max_length is not None:
        cap = min(cap, max_length)
    if len(value) > cap:
        raise NormalizationError(Reason.ARG_TOO_LARGE, name, f"longer than {cap} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise NormalizationError(Reason.ARG_INVALID_CHARACTERS, name, "unencodable characters") from None
    if "\x00" in value:
        raise NormalizationError(Reason.ARG_INVALID_CHARACTERS, name, "NUL character")
    if kind == "text":
        return value
    value = unicodedata.normalize("NFC", value)
    if len(value) > cap:
        raise NormalizationError(Reason.ARG_TOO_LARGE, name, "too long after normalization")
    if _bad_chars(value, allow_space=(kind in ("path", "str"))):
        raise NormalizationError(Reason.ARG_INVALID_CHARACTERS, name, "control or format characters")
    if kind == "url" and "\\" in value:
        raise NormalizationError(Reason.ARG_INVALID_CHARACTERS, name, "backslash in URL")
    if kind in ("path", "str", "url") and value == "":
        raise NormalizationError(Reason.SCHEMA_INVALID_VALUE, name, "empty value")
    return value


class _Budget:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.bytes = 0

    def add(self, n: int, name: str) -> None:
        self.bytes += n
        if self.bytes > self.limits.max_arg_bytes:
            raise NormalizationError(Reason.ARG_TOO_LARGE, name, "total arguments too large")


def _json_value(value: Any, name: str, depth: int, budget: _Budget) -> Any:
    lim = budget.limits
    if depth > lim.max_depth:
        raise NormalizationError(Reason.ARG_TOO_DEEP, name, "nesting too deep")
    t = type(value)
    if value is None or t is bool:
        budget.add(5, name)
        return value
    if t is int:
        if not -_INT_BOUND < value < _INT_BOUND:
            raise NormalizationError(Reason.SCHEMA_INVALID_VALUE, name, "integer out of range")
        budget.add(20, name)
        return value
    if t is float:
        if not math.isfinite(value):
            raise NormalizationError(Reason.SCHEMA_INVALID_VALUE, name, "non-finite number")
        budget.add(24, name)
        return value
    if t is str:
        budget.add(len(value) * 4 + 2 if len(value) < 64 else len(value.encode("utf-8", "replace")) + 2, name)
        return _clean_string(value, "text", name, lim, None)
    if t is list:
        if len(value) > lim.max_items:
            raise NormalizationError(Reason.ARG_TOO_LARGE, name, "too many items")
        return [_json_value(v, name, depth + 1, budget) for v in value]
    if t is dict:
        if len(value) > lim.max_items:
            raise NormalizationError(Reason.ARG_TOO_LARGE, name, "too many items")
        out: dict[str, Any] = {}
        for k, v in value.items():
            if type(k) is not str:
                raise NormalizationError(Reason.SCHEMA_INVALID_TYPE, name, "non-string key")
            out[_clean_string(k, "str", name, lim, 128)] = _json_value(v, name, depth + 1, budget)
        return out
    raise NormalizationError(Reason.SCHEMA_INVALID_TYPE, name, f"unsupported type {t.__name__}")


def normalize_args(
    schema: Mapping[str, ArgSpec],
    raw: Any,
    *,
    allow_extra: bool = False,
    limits: Limits = DEFAULT_LIMITS,
) -> dict[str, Any]:
    """Validate ``raw`` against ``schema`` and return a normalized copy."""
    if not isinstance(raw, Mapping):
        raise NormalizationError(Reason.MALFORMED_REQUEST, None, "arguments must be a mapping")
    if len(raw) > limits.max_items:
        raise NormalizationError(Reason.ARG_TOO_LARGE, None, "too many arguments")
    for k in raw:
        if type(k) is not str:
            raise NormalizationError(Reason.MALFORMED_REQUEST, None, "argument names must be strings")
    out: dict[str, Any] = {}
    budget = _Budget(limits)
    for name, spec in schema.items():
        if spec.kind not in _KINDS:
            raise ValueError(f"unknown ArgSpec kind {spec.kind!r}")
        if name not in raw:
            if spec.required:
                raise NormalizationError(Reason.SCHEMA_MISSING_FIELD, name)
            if spec.default is not _UNSET:
                out[name] = spec.default
            continue
        value = raw[name]
        t = type(value)
        if spec.kind in ("str", "text", "path", "url"):
            if t is not str:
                raise NormalizationError(Reason.SCHEMA_INVALID_TYPE, name, "expected string")
            budget.add(len(value) if len(value) < 64 else len(value.encode("utf-8", "replace")), name)
            out[name] = _clean_string(value, spec.kind, name, limits, spec.max_length)
        elif spec.kind == "int":
            if t is not int:
                raise NormalizationError(Reason.SCHEMA_INVALID_TYPE, name, "expected integer")
            if not -_INT_BOUND < value < _INT_BOUND:
                raise NormalizationError(Reason.SCHEMA_INVALID_VALUE, name, "integer out of range")
            out[name] = value
        elif spec.kind == "number":
            if t not in (int, float):
                raise NormalizationError(Reason.SCHEMA_INVALID_TYPE, name, "expected number")
            if t is float and not math.isfinite(value):
                raise NormalizationError(Reason.SCHEMA_INVALID_VALUE, name, "non-finite number")
            if t is int and not -_INT_BOUND < value < _INT_BOUND:
                raise NormalizationError(Reason.SCHEMA_INVALID_VALUE, name, "integer out of range")
            out[name] = value
        elif spec.kind == "bool":
            if t is not bool:
                raise NormalizationError(Reason.SCHEMA_INVALID_TYPE, name, "expected boolean")
            out[name] = value
        else:  # json
            out[name] = _json_value(value, name, 1, budget)
    extras = [k for k in raw if k not in schema]
    if extras:
        if not allow_extra:
            raise NormalizationError(Reason.SCHEMA_UNEXPECTED_FIELD, sorted(extras)[0])
        for k in sorted(extras):
            out[_clean_string(k, "str", k, limits, 128)] = _json_value(raw[k], k, 1, budget)
    return out


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def action_hash(tool: str, args: Mapping[str, Any], target: str | None) -> str:
    """Hash binding an approval to the exact normalized action."""
    return sha256_hex(canonical_json({"v": 1, "tool": tool, "target": target, "args": args}))


# ---- summaries for audit/approval display (allowlist/redaction helpers) ----


def truncate(value: str, n: int = 120) -> str:
    if len(value) <= n:
        return value
    return f"{value[:n]}...(+{len(value) - n} chars)"


def default_summary(args: Mapping[str, Any]) -> dict[str, Any]:
    """Default redaction: argument names with type and size only, never values."""
    out: dict[str, Any] = {}
    for k, v in args.items():
        if isinstance(v, str):
            out[k] = f"<str len={len(v)}>"
        elif isinstance(v, (list, dict)):
            out[k] = f"<{type(v).__name__} len={len(v)}>"
        else:
            out[k] = f"<{type(v).__name__}>"
    return out


def bound_summary(summary: Any, *, max_keys: int = 32, max_str: int = 256, depth: int = 3) -> Any:
    """Bound an args summary so audit events stay small."""
    if depth <= 0:
        return "<elided>"
    if isinstance(summary, dict):
        items = list(summary.items())[:max_keys]
        out = {truncate(str(k), 64): bound_summary(v, max_keys=max_keys, max_str=max_str, depth=depth - 1) for k, v in items}
        if len(summary) > max_keys:
            out["_more_keys"] = len(summary) - max_keys
        return out
    if isinstance(summary, (list, tuple)):
        return [bound_summary(v, max_keys=max_keys, max_str=max_str, depth=depth - 1) for v in list(summary)[:max_keys]]
    if isinstance(summary, str):
        return truncate(summary, max_str)
    if isinstance(summary, (int, float, bool)) or summary is None:
        return summary
    return truncate(str(summary), max_str)
