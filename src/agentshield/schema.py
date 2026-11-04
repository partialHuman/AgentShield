"""JSON Schema for policy files, generated from the same constraint specs the validator uses."""

from __future__ import annotations

import json
from typing import Any

from .constraints import BUILTIN_SCHEMAS, C

_COMMON: dict[str, Any] = {
    "enabled": {"type": "boolean", "default": True},
    "risk": {"enum": ["low", "medium", "high"]},
    "decision": {"enum": ["ALLOW", "REQUIRE_APPROVAL", "DENY"]},
    "approval_ttl_seconds": {"type": "integer", "minimum": 10, "maximum": 86400, "default": 300},
    "max_calls": {"type": "integer", "minimum": 1},
    "arg_constraints": {
        "type": "object",
        "additionalProperties": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "enum": {"type": "array", "minItems": 1, "items": {"type": ["string", "integer"]}},
                "max_length": {"type": "integer", "minimum": 0},
                "prefixes": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
                "min": {"type": "number"},
                "max": {"type": "number"},
            },
        },
    },
}


def _constraint_schema(spec: C) -> dict[str, Any]:
    d: dict[str, Any]
    if spec.kind == "bool":
        d = {"type": "boolean"}
    elif spec.kind == "int":
        d = {"type": "integer"}
    elif spec.kind == "number":
        d = {"type": "number"}
    elif spec.kind == "int_list":
        d = {"type": "array", "items": {"type": "integer", "minimum": 1, "maximum": 65535}}
    elif spec.kind == "str_list":
        items: dict[str, Any] = {"type": "string"}
        if spec.choices:
            items["enum"] = list(spec.choices)
        d = {"type": "array", "items": items}
    elif spec.kind == "host_list":
        d = {"type": "array", "items": {"type": "string", "minLength": 1, "pattern": "^[^*]+$"},
             "description": "Exact hostnames or IP literals; wildcards are not supported in v0.1."}
    else:  # dir_list
        d = {"type": "array", "items": {"type": "string", "minLength": 1},
             "description": "Existing directories; relative paths resolve against the policy file's directory."}
    if spec.kind in ("int", "number"):
        if spec.min is not None:
            d["minimum"] = spec.min
        if spec.max is not None:
            d["maximum"] = spec.max
    if spec.nonempty:
        d["minItems"] = 1
    if not spec.required:
        default = spec.default
        d["default"] = list(default) if isinstance(default, tuple) else default
    return d


def policy_schema() -> dict[str, Any]:
    defs: dict[str, Any] = {}
    for name, constraints in BUILTIN_SCHEMAS.items():
        props = dict(_COMMON)
        props.update({k: _constraint_schema(v) for k, v in constraints.items()})
        defs[name] = {
            "type": "object",
            "additionalProperties": False,
            "required": ["risk", "decision", *[k for k, v in constraints.items() if v.required]],
            "properties": props,
        }
    defs["custom_tool"] = {
        "type": "object",
        "required": ["risk", "decision"],
        "properties": dict(_COMMON),
        "description": "Custom tools may declare extra constraint keys; they are validated when the tool is wrapped.",
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentshield.dev/schemas/policy-v1.json",
        "title": "AgentShield policy (version 1)",
        "type": "object",
        "additionalProperties": False,
        "required": ["version", "tools"],
        "properties": {
            "version": {"const": 1},
            "default_decision": {"const": "DENY", "description": "Default-deny is mandatory in v0.1."},
            "tools": {
                "type": "object",
                "propertyNames": {"pattern": "^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)*$"},
                "properties": {name: {"$ref": f"#/$defs/{name}"} for name in BUILTIN_SCHEMAS},
                "additionalProperties": {"$ref": "#/$defs/custom_tool"},
            },
        },
        "$defs": defs,
    }


def render() -> str:
    return json.dumps(policy_schema(), indent=2, sort_keys=False) + "\n"
