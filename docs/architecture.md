# Architecture

AgentShield is an in-process Python library. The CLI is a thin layer over the same code.

```
src/agentshield/
├── shield.py        Shield: wrap/call, authorization pipeline, approvals, audit ordering, metrics
├── evaluator.py     Policy evaluation (no side effects): schema → policy rule → constraints → decision
├── normalize.py     Argument schemas (ArgSpec), Unicode/size/depth bounds, canonical JSON, action hash
├── policy.py        Strict YAML loader + validation, ToolPolicy, policy hash
├── constraints.py   Typed constraint specs and the built-in tools' constraint schemas
├── netguard.py      URL/host/IP normalization and classification (no I/O except system_resolver)
├── tools.py         Tool: schema + checker + executor factory
├── approvals.py     SQLite approval store, HMAC authenticity, atomic single-use consume
├── audit.py         Hash-chained JSONL log + verify_chain
├── schema.py        JSON Schema generated from the constraint specs
├── cli.py           lint / evaluate / explain / approvals / audit verify / schema
└── adapters/        calculator, filesystem (read/write), http_fetch
```

## Request flow

```
shield.call(name, args)   (or a function returned by shield.wrap(tool))
   │
   ├─ 1  evaluator.evaluate(name, args)            ── never executes anything
   │       registered tool?  → normalize/validate args (types, NFC, control chars, size, depth)
   │       policy rule? enabled? explicit DENY?
   │       tool checker (path/URL/… resource checks) + arg_constraints  → any violation ⇒ DENY
   │       otherwise the rule's decision: ALLOW | REQUIRE_APPROVAL
   │       any exception anywhere ⇒ DENY (EVALUATOR_ERROR)
   │
   ├─ 2  REQUIRE_APPROVAL → approval store: none → create pending │ pending → still pending
   │                         approved → atomically consume (single use) → ALLOW
   │                         rejected / invalid MAC / queue full / no store → DENY
   │
   ├─ 3  call-limit reservation (atomic) for ALLOW
   │
   ├─ 4  audit: write the DECISION event (hash-chained).  If it cannot be written: ALLOW → DENY
   │
   ├─ 5  DENY → raise ActionDenied │ REQUIRE_APPROVAL → raise ApprovalPending     (executor untouched)
   │
   └─ 6  ALLOW → executor(**normalized_args) → audit OUTCOME event → return result
              (executor errors become ToolExecutionError with a stable code; messages are never logged)
```

The executor is created by `Tool.executor_factory(tool_policy)` at wrap time and stored privately in the `Shield`.
Adapters **re-derive** security-relevant facts at use time (the file adapter re-resolves the path with no-follow opens;
the HTTP adapter re-resolves and re-validates DNS for the request and for every redirect) and never trust the
decision-time check, because the world can change in between.

## Decision order (policy semantics)

1. Request/schema invalid → `DENY` (`SCHEMA_*`, `ARG_*`, `MALFORMED_REQUEST`)
2. Tool not registered with the shield → `DENY` (`UNKNOWN_TOOL`); no rule → `NO_POLICY_RULE`; disabled → `TOOL_DISABLED`; explicit `decision: DENY` → `EXPLICIT_DENY`
3. Any **constraint** violated (roots, hosts, ports, sizes, `arg_constraints`) → `DENY`, regardless of the declared decision
4. All constraints pass → the rule's decision (`ALLOW` or `REQUIRE_APPROVAL`)
5. Anything unexpected → `DENY`

## Action hash and approvals

`action_hash = sha256(canonical_json({v, tool, target, args}))` where `args` are the *normalized* arguments and
`target` is the canonical resource (absolute path, or normalized URL). An approval is keyed by
`(action_hash, policy_hash, agent_id)`, so changing an argument, the target, the policy, or the agent invalidates it.

```
pending ──approve──▶ approved ──consume──▶ consumed        (every state also expires at created_at + ttl)
   └─────reject────▶ rejected
```

After approval the application **re-submits the identical call**; the shield recognizes it and executes it exactly once.
No arguments are stored server-side for later replay, only the hash and a redacted display summary.

## Audit event schema (v1)

`schema, seq, event_id, ts, type (decision|outcome), request_id, agent_id, tool, risk, decision, reason_codes,
policy_version, policy_hash, action_hash, target (redacted), args_summary (allow-listed), approval_id, duration_ms,
prev_hash, hash`. Outcome events add `decision_event_id, status (ok|error|cancelled|interrupted), error_code, result_size`.
`hash = sha256(canonical_json(event without hash))`; `prev_hash` links to the previous event (genesis = 64 zeros).

## Extending: protect your own tool

```python
from agentshield import ArgSpec, C, CheckOutcome, Reason, Tool

def check(args, tp):                      # decision-time resource check
    ok = args["channel"] in tp.constraints["channels"]
    return CheckOutcome(args["channel"], () if ok else (Reason.ARG_CONSTRAINT_VIOLATION,))

send = Tool.from_callable(
    my_send_function, "chat.send",
    {"channel": ArgSpec("str"), "text": ArgSpec("text", max_length=2000)},
    checker=check,
    constraint_schema={"channels": C("str_list", nonempty=True)},          # validated when wrapped
    summarize=lambda a: {"channel": a["channel"], "text_len": len(a["text"])},   # allow-list for audit logs
)
protected_send = shield.wrap(send)        # async functions work too
```

Custom tools must not do their own path/URL resolution in a way that can be raced; prefer the built-in adapters as models.
