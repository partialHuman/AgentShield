"""Typed, structured policy constraints (no user-supplied regular expressions)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .netguard import normalize_host

_UNSET: Any = object()


@dataclass(frozen=True)
class C:
    """Constraint spec. kind: str_list | int_list | host_list | dir_list | int | number | bool."""

    kind: str
    default: Any = _UNSET
    min: float | None = None
    max: float | None = None
    choices: tuple[Any, ...] | None = None
    nonempty: bool = False

    @property
    def required(self) -> bool:
        return self.default is _UNSET


def _num(v: Any) -> bool:
    return type(v) in (int, float)


def validate_constraints(
    raw: Mapping[str, Any], schema: Mapping[str, C], *, base_dir: str, where: str
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    out: dict[str, Any] = {}
    for key in raw:
        if key not in schema:
            errors.append(f"{where}.{key}: unknown constraint")
    for key, spec in schema.items():
        path = f"{where}.{key}"
        if key not in raw:
            if spec.required:
                errors.append(f"{path}: required")
            else:
                out[key] = spec.default
            continue
        v = raw[key]
        if spec.kind == "bool":
            if type(v) is not bool:
                errors.append(f"{path}: must be a boolean (true/false)")
            else:
                out[key] = v
        elif spec.kind == "int":
            if type(v) is not int:
                errors.append(f"{path}: must be an integer")
            elif (spec.min is not None and v < spec.min) or (spec.max is not None and v > spec.max):
                errors.append(f"{path}: must be between {spec.min} and {spec.max}")
            else:
                out[key] = v
        elif spec.kind == "number":
            if not _num(v):
                errors.append(f"{path}: must be a number")
            elif (spec.min is not None and v < spec.min) or (spec.max is not None and v > spec.max):
                errors.append(f"{path}: must be between {spec.min} and {spec.max}")
            else:
                out[key] = v
        elif spec.kind in ("str_list", "int_list", "host_list", "dir_list"):
            if type(v) is not list or (spec.nonempty and not v):
                errors.append(f"{path}: must be a {'non-empty ' if spec.nonempty else ''}list")
                continue
            items: list[Any] = []
            ok = True
            for i, item in enumerate(v):
                ip = f"{path}[{i}]"
                if spec.kind == "int_list":
                    if type(item) is not int or not (spec.min or 0) <= item <= (spec.max or 65535):
                        errors.append(f"{ip}: must be an integer in range")
                        ok = False
                    else:
                        items.append(item)
                    continue
                if type(item) is not str or not item:
                    errors.append(f"{ip}: must be a non-empty string (quote values like 'no' or 'yes')")
                    ok = False
                    continue
                if spec.kind == "str_list":
                    if spec.choices is not None and item not in spec.choices:
                        errors.append(f"{ip}: must be one of {list(spec.choices)}")
                        ok = False
                    else:
                        items.append(item)
                elif spec.kind == "host_list":
                    if "*" in item:
                        errors.append(f"{ip}: wildcards are not supported in v0.1")
                        ok = False
                        continue
                    try:
                        items.append(normalize_host(item))
                    except ValueError as exc:
                        errors.append(f"{ip}: {exc}")
                        ok = False
                else:  # dir_list
                    full = item if os.path.isabs(item) else os.path.join(base_dir, item)
                    real = os.path.realpath(full)
                    if not os.path.isdir(real):
                        errors.append(f"{ip}: directory does not exist: {item}")
                        ok = False
                    else:
                        items.append(real)
            if ok:
                out[key] = tuple(items)
        else:  # pragma: no cover
            raise ValueError(f"unknown constraint kind {spec.kind}")
    return out, errors


# ---- built-in tool constraint schemas ----

CALCULATOR_CONSTRAINTS: dict[str, C] = {
    "max_expression_length": C("int", default=200, min=1, max=1000),
}
_MAX_BYTES = C("int", default=1024 * 1024, min=1, max=256 * 1024 * 1024)
FS_READ_CONSTRAINTS: dict[str, C] = {
    "allowed_roots": C("dir_list", nonempty=True),
    "max_bytes": _MAX_BYTES,
}
FS_WRITE_CONSTRAINTS: dict[str, C] = {
    "allowed_roots": C("dir_list", nonempty=True),
    "max_bytes": _MAX_BYTES,
}
HTTP_CONSTRAINTS: dict[str, C] = {
    "allowed_schemes": C("str_list", default=("https",), choices=("http", "https"), nonempty=True),
    "allowed_hosts": C("host_list", nonempty=True),
    "allowed_ports": C("int_list", default=(443,), min=1, max=65535, nonempty=True),
    "block_private_addresses": C("bool", default=True),
    "revalidate_redirects": C("bool", default=True),
    "max_redirects": C("int", default=3, min=0, max=10),
    "max_response_bytes": C("int", default=1024 * 1024, min=1, max=128 * 1024 * 1024),
    "timeout_seconds": C("number", default=10, min=0.5, max=120),
}

BUILTIN_SCHEMAS: dict[str, dict[str, C]] = {
    "calculator": CALCULATOR_CONSTRAINTS,
    "filesystem.read": FS_READ_CONSTRAINTS,
    "filesystem.write": FS_WRITE_CONSTRAINTS,
    "http.fetch": HTTP_CONSTRAINTS,
}
