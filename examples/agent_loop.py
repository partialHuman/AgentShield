"""A minimal tool-use agent loop (Anthropic Messages format) protected by AgentShield.

Every ``tool_use`` block the model emits is dispatched through ``shield.call(...)``, so nothing the model
proposes can reach an executor without an ALLOW (or a consumed approval).

* ``ScriptedModel``  - deterministic, offline; used by the demo and CI (no API key needed).
* ``LiveAnthropicModel`` - optional real model (``pip install anthropic``; set ANTHROPIC_API_KEY).
  NOTE: the live path is a thin adapter that is NOT exercised by this repository's test suite.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any

from agentshield import ActionDenied, ApprovalPending, Shield, Tool, ToolExecutionError

_JSON_TYPES = {"str": "string", "text": "string", "path": "string", "url": "string", "int": "integer",
               "number": "number", "bool": "boolean", "json": "object"}


def model_name(tool_name: str) -> str:
    """Provider tool names may not contain dots."""
    return tool_name.replace(".", "_")


def tool_schemas(tools: list[Tool], descriptions: dict[str, str]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    schemas, name_map = [], {}
    for t in tools:
        mn = model_name(t.name)
        name_map[mn] = t.name
        schemas.append({
            "name": mn,
            "description": descriptions.get(t.name, t.name),
            "input_schema": {
                "type": "object",
                "properties": {k: {"type": _JSON_TYPES[v.kind]} for k, v in t.args.items()},
                "required": [k for k, v in t.args.items() if v.required],
            },
        })
    return schemas, name_map


ModelFn = Callable[[list[dict[str, Any]], list[dict[str, Any]]], dict[str, Any]]


def run_agent(
    model: ModelFn,
    shield: Shield,
    tools: list[dict[str, Any]],
    name_map: dict[str, str],
    prompt: str,
    *,
    max_turns: int = 12,
    on_step: Callable[[dict[str, Any], str, Exception | None], None] | None = None,
) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
    for _ in range(max_turns):
        assistant = model(messages, tools)
        messages.append(assistant)
        uses = [b for b in assistant["content"] if b.get("type") == "tool_use"]
        if not uses:
            return messages
        results = []
        for use in uses:
            real_name = name_map.get(use["name"], use["name"])  # unknown names still go through the shield
            error: Exception | None = None
            try:
                out = shield.call(real_name, use["input"])
                content, is_error = json.dumps(out, default=str), False
            except (ActionDenied, ApprovalPending, ToolExecutionError) as exc:
                error, content, is_error = exc, exc.agent_message(), True  # generic text only: never leak policy details
            if on_step:
                on_step(use, real_name, error)
            results.append({"type": "tool_result", "tool_use_id": use["id"], "content": content, "is_error": is_error})
        messages.append({"role": "user", "content": results})
    return messages


class ScriptedModel:
    """Replays prepared assistant turns (the 'malicious model')."""

    def __init__(self, turns: list[list[dict[str, Any]]]):
        self._turns = list(turns)

    def __call__(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        content = self._turns.pop(0) if self._turns else [{"type": "text", "text": "done"}]
        return {"role": "assistant", "content": content}


class LiveAnthropicModel:  # pragma: no cover - requires network + API key; not exercised in CI
    def __init__(self, model: str | None = None):
        import anthropic

        self.client = anthropic.Anthropic()
        self.model = model or os.environ.get("AGENTSHIELD_MODEL", "claude-sonnet-5-5")

    def __call__(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        resp = self.client.messages.create(model=self.model, max_tokens=1024, tools=tools, messages=messages)
        return {"role": "assistant", "content": [b.model_dump() for b in resp.content]}


def tu(i: int, name: str, **input_: Any) -> dict[str, Any]:
    return {"type": "tool_use", "id": f"toolu_{i:02d}", "name": name, "input": input_}
