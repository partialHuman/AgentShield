**AGENTSHIELD**

AI Agent Runtime Security Firewall

**PRODUCT REQUIREMENTS DOCUMENT**

A policy-enforcement layer that mediates AI-agent tool use, validates actions before execution, and records explainable security decisions.

| **Document field**            | **Value**                                                                                                                                  |
|-------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| Version                       | 1.1 — Revised after design review (see Appendix B)                                                                                         |
| Status                        | Draft for implementation; scope revised for the first release                                                                              |
| Date                          | 3 November 2026                                                                                                                            |
| First release target          | v0.1.0 (alpha / preview). Not labelled 1.0 until independent bypass review is complete.                                                    |
| Product type                  | Open-source security middleware / developer tool                                                                                           |
| Primary users                 | AI application developers, application security engineers, platform/security teams                                                         |
| Relationship to existing work | Complementary to Guardrails-Gateway (SentraGuard Lite); focuses on tool/action authorization rather than primarily prompt/context analysis |

**Product principle**

The model may propose an action; the application remains responsible for deciding whether that action is allowed. AgentShield enforces the decision outside the model.

# 1. Executive Summary

AgentShield is a runtime security firewall for AI agents. It sits between an agent framework and the tools or capabilities the agent can invoke—such as shell commands, file operations, HTTP requests, and database actions. Every supported action must pass through a deterministic policy decision before execution. AgentShield validates the requested tool, arguments, identity, resource scope, and risk; then allows, denies, or requires human approval.

The first release (v0.1.0, alpha) is deliberately narrow: a local-first Python SDK, a small set of reference tool adapters (utility, file, and HTTP), a hash-chained audit log, CLI-based approvals, and a demo that proves blocked actions never reach the executor. It is not an LLM, a general-purpose agent framework, or a replacement for operating-system sandboxing. The optional HTTP service, shell adapter, and web interface are deferred until the enforcement core has been independently reviewed.

# 2. Problem Statement

AI agents can translate natural-language goals into tool calls. A model can be manipulated by prompt injection, mistaken context, over-broad instructions, or its own reasoning errors and then request actions with real-world effects. Application code often gives tools broad permissions and relies on the model to choose safe actions. Prompt filtering alone cannot reliably authorize an action because the critical security decision concerns what the tool call will do, with which arguments, against which resource, and under whose authority.

AgentShield addresses this gap by enforcing least-privilege policies at the tool boundary. The enforcement point must be outside the model and fail closed for protected actions when policy evaluation is unavailable or ambiguous.

# 3. Goals and Non-Goals

## 3.1 Goals

- Intercept every tool call routed through an AgentShield-protected adapter before the underlying tool executes.

- Make allow / deny / require-approval decisions using deterministic, inspectable policies.

- Validate tool names and arguments against schemas and policy constraints.

- Apply least privilege to tool access, file paths, network destinations, and operation types.

- Provide clear decision explanations and a hash-chained audit event structure that is tamper-evident by design (without claiming cryptographic immutability in v0.1).

- Ship runnable examples, security tests, Docker-based development setup, and CI checks.

- Integrate with agent frameworks through a small adapter interface without requiring a particular model provider.

- Support both synchronous and asynchronous tools, since most agent frameworks are asynchronous.

- Give the model only minimal denial information, while giving developers full reason codes through logs and explain mode.

## 3.2 Non-goals for v0.1

- Guaranteeing that an LLM is truthful, unbiased, or immune to prompt injection.

- Replacing OS-level sandboxing, container isolation, network egress controls, IAM, or database permissions.

- Automatically executing arbitrary shell commands with elevated privileges.

- Supporting every agent framework or tool protocol on day one.

- Building a hosted multi-tenant SaaS control plane, billing system, or enterprise identity platform.

- Using a second LLM as the primary authorization engine.

- A FastAPI policy service, web dashboard, or approval web interface (the SDK and CLI are the only interfaces in v0.1).

- A shell command adapter, which is deferred until the file and HTTP adapters have been independently reviewed.

- Per-agent policy branching: agent identity is recorded in events and bound into approvals, but one policy applies per shield instance.

- Framework-specific adapters (LangChain, MCP, and others); one custom tool-use loop is the reference integration.

# 4. Target Users and Use Cases

| **Persona**                         | **Need**                                                                       | **Success outcome**                                       |
|-------------------------------------|--------------------------------------------------------------------------------|-----------------------------------------------------------|
| AI application developer            | Protect agent tools without rewriting the whole agent                          | Can wrap tools with a short, documented integration       |
| Application security engineer       | Review and test tool permissions and dangerous action paths                    | Can write policies and prove denied calls never execute   |
| Platform / security team            | Understand which actions agents requested and why they were allowed or blocked | Can inspect structured events and export audit records    |
| Open-source maintainer / researcher | Reproduce attacks and test policy changes                                      | Can run a local demo and security test suite consistently |

# 5. Core User Journeys

1.  Developer installs AgentShield and wraps an existing tool with a protected adapter.

2.  Developer defines a policy: allowed tools, argument constraints, resource scopes, and approval rules.

3.  Agent requests an action. AgentShield normalizes and validates the request before calling the executor.

4.  AgentShield returns an explicit decision with reason codes. Only an allowed action is dispatched automatically.

5.  For approval-required actions, the request is held pending an authorized human decision made through the CLI; no tool execution occurs before approval.

6.  Security engineer reviews events, runs attack scenarios, adjusts policies, and reruns regression tests.

# 6. Product Scope and Requirements

## 6.1 Functional requirements

| **ID** | **Requirement**                    | **Priority** | **Acceptance criteria**                                                                                                                                                                                                                                                                                                                                               |
|--------|------------------------------------|--------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| FR-01  | Tool-call interception             | P0           | All tool calls through a protected adapter are evaluated before executor invocation; the wrapper holds the executor privately and exposes no handle to it; sync and async callables are supported; tests prove denied calls invoke no executor.                                                                                                                       |
| FR-02  | Policy decision                    | P0           | Return one of ALLOW, DENY, or REQUIRE_APPROVAL with stable reason codes.                                                                                                                                                                                                                                                                                              |
| FR-03  | Schema validation                  | P0           | Reject unknown tools, missing required fields, unexpected fields where configured, and invalid argument types; enforce size and nesting bounds and normalize input before evaluation (Section 7.2).                                                                                                                                                                   |
| FR-04  | Least-privilege tool registry      | P0           | Only explicitly registered tools are callable; each tool has a declared risk tier and capability scope.                                                                                                                                                                                                                                                               |
| FR-05  | File-operation controls            | P0           | Path rules prevent traversal and restrict operations to configured roots; on Linux and macOS, paths resolve relative to a root directory descriptor with no-follow opens; on Windows, reparse points are denied and limits are documented; symlink and canonical-path behavior is tested.                                                                             |
| FR-06  | Network-operation controls         | P0           | HTTP adapter enforces scheme, host, and port allowlists and blocks localhost, private, link-local, and metadata-service targets by default; resolves DNS once, validates every address, and connects to the validated IP; redirects are handled manually and revalidated; proxy environment variables are ignored; numeric and IPv4-mapped IPv6 forms are normalized. |
| FR-07  | Human approval workflow (CLI-only) | P0           | High-risk action is held without execution until the CLI approver approves or rejects it; approval is bound to the action hash, policy hash, and agent identity, is single-use, and expired or replayed requests fail closed. In v0.1 the approver is the local OS user plus a local secret.                                                                          |
| FR-08  | Audit events                       | P0           | Each decision emits structured event data with event ID, timestamp, tool, normalized argument summary, decision, reason codes, policy version, and duration; events are hash-chained; the decision event is written before dispatch and an outcome event after; protected tools fail closed if the decision event cannot be written.                                  |
| FR-09  | Policy configuration               | P0           | Policies load from validated YAML (strict loader, duplicate keys rejected) with a published JSON Schema; constraints are structured with no user-supplied regular expressions; invalid policy prevents startup or protected execution.                                                                                                                                |
| FR-10  | Dry-run / explain mode             | P0           | Developers can evaluate policies without executing tools and see the matched rules and decision rationale, through both the SDK and the CLI.                                                                                                                                                                                                                          |
| FR-11  | CLI                                | P1           | CLI validates a policy file, evaluates and explains supplied sample actions, manages pending approvals, and verifies audit hash chains; output supports human-readable and JSON formats.                                                                                                                                                                              |
| FR-12  | Metrics                            | P2           | In v0.1, in-process counters only: decision counts, denied actions, approval queue counts, and evaluation latency, without logging secrets; no metrics endpoint.                                                                                                                                                                                                      |
| FR-13  | Agent-framework adapter example    | P1           | A documented reference integration demonstrates a real tool-call interception path: a scripted malicious-model loop runs in CI without API keys, and an optional live mode uses a real provider SDK.                                                                                                                                                                  |
| FR-14  | Event export                       | P2           | Export audit events as JSONL for local analysis and CI artifacts.                                                                                                                                                                                                                                                                                                     |
| FR-15  | Sync and async support             | P0           | The wrapper protects synchronous and asynchronous callables with identical enforcement guarantees; tests cover both paths, including concurrent calls.                                                                                                                                                                                                                |
| FR-16  | Minimal denial disclosure          | P0           | Denials returned to the agent contain only a stable error code and a generic message; matched rules and resolved targets appear only in developer-facing events and explain mode.                                                                                                                                                                                     |
| FR-17  | Per-tool call limits               | P2           | Optional per-tool call-count limits per shield instance; exceeding a limit returns DENY with a stable reason code.                                                                                                                                                                                                                                                    |

## 6.2 Initial supported tool types

| **Tool adapter**                     | **Initial behavior**                                  | **Security constraints**                                                                                                                                                                                                                   |
|--------------------------------------|-------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Safe calculator / structured utility | Low-risk example tool                                 | Strict input schema; no dynamic code evaluation                                                                                                                                                                                            |
| File reader / writer                 | Read and write only within configured workspace roots | Canonical-path validation; fd-relative, no-follow opens on Linux and macOS (Windows: reparse points denied, limits documented); traversal defense; operation-specific permissions; size limits                                             |
| HTTP fetch                           | Fetch URLs on the configured allowlist                | Scheme, host, and port allowlists; resolve once, validate every IP, connect to the validated IP with Host and SNI preserved; manual redirect revalidation; proxy environment variables ignored; timeout and streaming response-size limits |
| Shell command runner                 | Not shipped in v0.1 (deferred)                        | If added later: fixed command registry, argument arrays, non-root container, timeout, resource limits, and a separate security review                                                                                                      |

The shell adapter is not part of v0.1. The first release prioritizes file and HTTP controls, where resource boundaries and test cases can be specified clearly. A shell adapter will be considered only after the file and HTTP adapters have passed an independent bypass review, and then only in an isolated, unprivileged environment.

# 7. Decision Model and Policy Semantics

Every action should be represented as a normalized request with at least:

- request_id and timestamp

- agent / application identity (trusted application-supplied identifier, not a model assertion)

- tool name and declared capability

- validated arguments or a safe argument summary

- target resource (canonical file path, hostname/IP, database resource, or other identifier)

- requested operation and policy version

Decision precedence:

| **Condition**                                                               | **Decision**        |
|-----------------------------------------------------------------------------|---------------------|
| Malformed request, unknown tool, schema failure, or policy evaluation error | DENY                |
| Explicit deny rule or target outside an allowed scope                       | DENY                |
| Action matches an approval-required rule                                    | REQUIRE_APPROVAL    |
| Action is explicitly permitted and all constraints pass                     | ALLOW               |
| No matching allow rule for a protected tool                                 | DENY (default-deny) |

The adapter must dispatch to the executor only after ALLOW. REQUIRE_APPROVAL must create a pending record and return control without dispatching. Approval must be bound to the exact normalized action and policy context; changes to arguments or target invalidate the approval.

## 7.1 Policy rule model

Each tool entry in a policy declares an enabled flag, a risk tier, a decision (ALLOW, REQUIRE_APPROVAL, or DENY), and typed constraints. Evaluation proceeds in a fixed order:

1.  Validate the request and schema; any failure or evaluator error returns DENY.

2.  Apply explicit deny rules and reject disabled or unregistered tools; return DENY.

3.  Check every constraint (roots, hosts, ports, size limits, enumerations); any violation returns DENY, regardless of the tool’s declared decision.

4.  If all constraints pass, return the tool’s declared decision (ALLOW or REQUIRE_APPROVAL).

5.  If no rule matches a protected tool, return DENY (default-deny).

- Constraints are hard limits. A filesystem.write entry with decision REQUIRE_APPROVAL and a path outside allowed_roots is denied outright; a path inside allowed_roots is held for approval.

- Constraints are structured only: enumerations, prefixes, maximum lengths and sizes, and allowlists. User-supplied regular expressions are not supported in v0.1, to avoid ReDoS and ambiguous matching.

- Agent identity is recorded in every event and bound into approvals, but v0.1 applies one policy per shield instance; per-agent policies are deferred.

- Denials returned to the agent carry a stable error code and a generic message only. Matched rules, resolved paths, and policy details appear in audit events and explain mode for developers, so the agent cannot probe the policy.

## 7.2 Input normalization

- Enforce maximum argument size, nesting depth, string length, and URL length before any other processing.

- Normalize strings to Unicode NFC; reject NUL and other control characters in paths, hostnames, and identifiers.

- Lower-case hostnames, convert them to IDNA (punycode) form, and strip trailing dots before matching.

- Canonicalize or reject ambiguous IP forms (decimal, octal, hexadecimal, IPv4-mapped IPv6) before address classification.

- Compute the action hash over canonical JSON (sorted keys, normalized values) so equivalent requests hash identically.

## 7.3 Approval semantics

- Approval is CLI-only in v0.1. Pending actions are held in a local SQLite or file-backed queue; the agent receives an ApprovalPending outcome with a request ID, and no executor call is made.

- An approval binds the action hash, the policy hash and version, and the agent identity. Any change to arguments, target, or policy invalidates it.

- Approvals are single-use and expire after a configurable TTL; expired, replayed, or mismatched approvals fail closed.

- The approver is identified by the local OS user plus a local secret. This is a deliberate v0.1 limitation documented in the threat model; stronger approver authentication is deferred.

- The approver sees the exact normalized action and target before deciding.

# 8. Proposed Architecture

Use a modular Python package with a small core that can be embedded in-process. The local SDK is the only enforcement path in v0.1 because it avoids a network round-trip and reduces the risk of bypassing a remote authorization service. An optional FastAPI service for demos and multi-process integrations is deferred beyond v0.1.

| **Component**           | **Responsibility**                                                                                                                                          |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Protected adapter / SDK | Intercepts tool invocation; captures the executor privately and never exposes it; unreachable until ALLOW; supports sync and async callables.               |
| Request normalizer      | Creates a canonical action representation: size and depth bounds, Unicode and IDNA normalization, canonical JSON for hashing (Section 7.2).                 |
| Schema validator        | Validates tool identity and argument shape/types.                                                                                                           |
| Policy engine           | Evaluates allow, deny, scope, risk, and approval rules deterministically.                                                                                   |
| Resource validators     | Canonicalizes file paths (fd-relative, no-follow opens) and validates network destinations at the point of use (resolve once, connect to the validated IP). |
| Approval manager        | Stores pending action, approver identity, expiry, and decision in a local queue; binds approval to the action hash; single-use with TTL.                    |
| Audit event writer      | Emits structured, hash-chained decision and outcome events with redaction and bounded fields; decision event precedes dispatch.                             |
| CLI (HTTP API deferred) | Policy linting, dry-run and explain, approvals, audit inspection and hash-chain verification.                                                               |

## 8.1 Request flow

1.  Agent proposes a tool call.

2.  Protected adapter creates a normalized action request.

3.  Schema and resource validation run.

4.  Policy engine evaluates explicit rules and returns a decision plus reason codes.

5.  DENY: write the decision event, return a safe, generic error to the agent, and do not invoke the executor.

6.  REQUIRE_APPROVAL: write the decision event, persist the exact pending action, return an ApprovalPending outcome, and wait for a separate CLI approval path; do not invoke the executor.

7.  ALLOW: write the decision event before dispatch (protected tools fail closed if it cannot be written), invoke the narrowly scoped executor with timeout and size limits, then write an outcome event.

# 9. API and Developer Interface

v0.1 exposes a Python SDK and a CLI. An optional local HTTP API is deferred beyond v0.1; its routes are listed as provisional for planning only.

| **Interface**                       | **Purpose**                               | **Notes**                                                                                         |
|-------------------------------------|-------------------------------------------|---------------------------------------------------------------------------------------------------|
| Python: shield.wrap(tool, policy)   | Wrap a callable with enforcement          | Core entry point; executor captured privately and invoked only after ALLOW; sync and async        |
| Python: shield.evaluate(action)     | Evaluate without executing                | Useful for tests and dry-run                                                                      |
| CLI: agentshield lint               | Validate a policy file                    | Human-readable and JSON output                                                                    |
| CLI: agentshield evaluate / explain | Dry-run sample actions with matched rules | Never executes tools                                                                              |
| CLI: agentshield approvals          | List, approve, or reject pending actions  | Shows the exact normalized action; single-use, expiring                                           |
| CLI: agentshield audit verify       | Verify the hash chain of an event log     | Detects edits, deletions, and reordering                                                          |
| POST /v1/decisions/evaluate         | Evaluate a normalized action              | Deferred beyond v0.1. Optional API; authenticated or bound to localhost in development            |
| GET /health                         | Health check                              | Deferred beyond v0.1. No secrets or policy contents in response                                   |
| GET /v1/events                      | Query recent events                       | Deferred beyond v0.1. Local demo only; authentication and pagination required if enabled          |
| POST /v1/approvals/{id}/decision    | Approve/reject pending action             | Deferred beyond v0.1. P1; authenticated approver, expiry, replay protection, exact-action binding |

API names are provisional. The final contract should use typed Pydantic models, bounded request sizes, explicit error codes, and versioned routes.

# 10. Security and Privacy Requirements

- Default deny: unknown tools, missing policies, policy parse failures, and evaluator errors must not fall through to execution.

- No model self-authorization: identity, approval status, and policy configuration must come from trusted application/system channels.

- **Executor encapsulation:** the protected wrapper holds the executor privately and exposes no handle to it; tests try to extract or call it around the wrapper. This is a design boundary within a process, not protection against hostile code in the same process, so OS and container isolation remain necessary.

- Least privilege: each adapter receives only the capabilities and resource scope it needs.

- SSRF resistance: validate scheme, host, and port; resolve DNS once and validate every returned address; connect to the validated address with the original Host and SNI; disable automatic redirects and revalidate each hop; handle IPv4-mapped IPv6 and numeric IP forms; reject URL userinfo; ignore proxy environment variables; enforce streaming response-size limits.

- Path safety: use canonical paths and avoid check-then-use gaps. On Linux and macOS, resolve paths relative to a root directory file descriptor with no-follow semantics. On Windows, deny reparse points (junctions and symlinks) and document the remaining limits.

- Secret minimization: do not log raw credentials, access tokens, full document contents, or unrestricted tool arguments by default.

- **Audit integrity:** hash-chain events, write the decision event before dispatch, and fail closed for protected tools if it cannot be written. Chain verification detects edits, deletions, and reordering but does not make logs immutable.

- **Minimal denial disclosure:** return only a stable error code and generic message to the agent; keep matched rules and resolved targets in developer-facing logs and explain mode.

- Bounded execution: enforce timeouts, payload limits, output limits, and cancellation behavior.

- Approval safety: authenticate approvers (local OS user plus local secret in v0.1), expire pending actions, make approvals single-use, prevent replay, and invalidate approvals when action parameters or policy change.

- Service safety: not applicable to v0.1, which ships no network service. If an API is added later, bind it to loopback by default and require authentication and explicit deployment configuration for network exposure.

- Container safety: non-root user, read-only filesystem where practical, dropped capabilities, resource limits, and no privileged mode.

- Supply-chain hygiene: pinned dependencies, vulnerability scanning, secret scanning, and a documented update process.

- Clear limitations: document that AgentShield only protects calls routed through its adapters and is not a substitute for OS/container/network controls.

# 11. Reliability, Performance, and Operational Requirements

| **Area**              | **Requirement / target for MVP**                                                                                                                                                                                                                  |
|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Decision latency      | Target p95 policy evaluation under 10 ms for local, in-process policies on a documented test machine, measured excluding DNS resolution and filesystem I/O; benchmark rather than promise universally.                                            |
| Availability behavior | Protected actions fail closed if policy cannot be evaluated or the decision event cannot be written; a safe low-risk fallback must be explicitly configured, never implicit.                                                                      |
| Input bounds          | Maximum argument size, nesting depth, URL length, file size, HTTP response size, and execution duration are configurable and tested.                                                                                                              |
| Observability         | Structured logs; stable reason codes; decision duration and executor outcome; secrets redacted.                                                                                                                                                   |
| Portability           | Python 3.11+. Linux and macOS are release-blocking for all adapters. On Windows, the core SDK and policy engine are tested in CI; the file adapter denies reparse points and its limits are documented. Container demo primarily tested on Linux. |
| Configuration         | Validated config, explicit defaults, useful startup errors, no secrets committed to repository.                                                                                                                                                   |
| Testing               | Unit, integration, property-based (Hypothesis), negative security, adapter bypass, and policy regression tests in CI; sync and async paths both covered.                                                                                          |

# 12. Success Metrics

| **Metric**              | **MVP target / measurement**                                                                                                                                                                                                                                              |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Enforcement correctness | 100% of test cases marked DENY or REQUIRE_APPROVAL demonstrate zero executor invocations, including Hypothesis property tests over generated inputs and both sync and async paths.                                                                                        |
| Policy test coverage    | Every decision branch and every P0 rule has positive and negative tests.                                                                                                                                                                                                  |
| Attack scenarios        | At least 30 documented scenarios (target 40) covering path traversal, symlink and race cases, unauthorized tools, SSRF variants (redirects, DNS rebinding, numeric IP forms), invalid schemas, approval replay and bypass attempts, and attempts to extract the executor. |
| False blocks            | Track false-positive rate on a labeled corpus of at least 50 benign actions; establish a baseline rather than claiming a universal threshold.                                                                                                                             |
| Latency                 | Publish p50/p95/p99 local decision latency (excluding DNS and file I/O) with hardware, policy size, and test method documented.                                                                                                                                           |
| Integration usability   | One working example can protect a tool with a small, documented wrapper and policy file.                                                                                                                                                                                  |
| Reproducibility         | A new contributor can run lint, tests, and demo from a clean checkout using documented commands.                                                                                                                                                                          |
| Independent review      | At least two external reviewers attempt to bypass the file and HTTP adapters before the 0.1.0 tag; every finding becomes a regression test.                                                                                                                               |

# 13. MVP Acceptance Criteria

- A clean checkout installs and runs using documented instructions.

- A reference agent/tool demo can call a protected utility, read/write only within an allowed directory, and fetch only approved destinations.

- Unknown tools, invalid arguments, disallowed paths, prohibited network destinations, and policy errors are denied before execution.

- Tests instrument executors and assert that every denied or pending action results in zero executor calls.

- Approval-required actions cannot execute before approval and cannot execute after expiry, after replay, or after their arguments, target, or policy change.

- Every decision emits a structured event with stable reason codes and redacted arguments.

- Both synchronous and asynchronous tools are protected and tested.

- The wrapper exposes no handle to the underlying executor, and tests that try to extract or call it around the wrapper through the public API fail.

- Audit logs verify as an unbroken hash chain, and the verification command detects a tampered or truncated log.

- Policy files are schema-validated and include safe example defaults.

- Docker demo runs as non-root and does not require privileged mode.

- CI runs formatting/lint, type checks where configured, unit tests, integration tests, and security regression tests.

- At least two independent reviewers have attempted to bypass the file and HTTP adapters, and all findings are fixed or documented as known limitations.

- README includes architecture, threat model, quickstart, sample policies, demo screenshots or terminal output, known limitations, and responsible disclosure guidance.

- The package is released as v0.1.0 alpha with a CHANGELOG, SECURITY.md, and a README that states limitations prominently.

# 14. Testing Strategy

| **Test layer**                 | **Examples**                                                                                                                                                                          |
|--------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Unit                           | Policy precedence, schema failures, reason codes, argument normalization, policy parsing.                                                                                             |
| Adapter integration            | Executor called only on ALLOW; timeout and output limits; error handling.                                                                                                             |
| Filesystem security            | Traversal, absolute paths, symlink escape, Unicode/path normalization, race-sensitive cases.                                                                                          |
| Network security               | Loopback/private/link-local/metadata targets, redirect to prohibited host, malformed URLs, DNS changes.                                                                               |
| Approval workflow              | No pre-approval execution, expiry, replay, approver authorization, modified action invalidation.                                                                                      |
| Abuse / regression             | Fuzz malformed action inputs; run versioned attack corpus in CI; preserve discovered bypasses as tests.                                                                               |
| Deployment                     | Non-root container, no privileged mode, restricted ports, invalid config startup failure.                                                                                             |
| Property-based and concurrency | Hypothesis-generated actions assert no executor call on any non-ALLOW outcome; sync and async wrappers under concurrent calls; approval races (double approve, approve after expiry). |
| Encapsulation                  | Public API exposes no executor handle; attempts through documented public attributes fail; remaining in-process introspection limits are documented.                                  |
| Audit integrity                | Hash-chain verification, tamper and truncation detection, decision-before-dispatch ordering, fail-closed when the log is unwritable, redaction allowlist.                             |

# 15. Risks and Mitigations

| **Risk**                                                                              | **Impact**  | **Mitigation**                                                                                                                                                                                                                                          |
|---------------------------------------------------------------------------------------|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Developer bypasses the wrapper                                                        | High        | Make protected adapters the only documented executor path; the wrapper holds the executor privately; add integration tests and explicit limitation warnings; state that in-process wrapping is not a boundary against hostile code in the same process. |
| Policy is too broad or misconfigured                                                  | High        | Default-deny, policy linting, explain mode, example least-privilege policies, regression tests.                                                                                                                                                         |
| TOCTOU or canonicalization bugs                                                       | High        | Use fd-relative, no-follow opens on Linux and macOS, revalidate close to use, avoid path-string-only checks, and rely on OS isolation as defense in depth.                                                                                              |
| SSRF bypass via redirects/DNS                                                         | High        | Resolve once, validate all addresses, connect to the validated IP, revalidate each manual redirect; constrain egress at the OS and network layer.                                                                                                       |
| Approval fatigue / insecure approvals                                                 | Medium-High | Only require approval for meaningful risk tiers; show exact action and target; expire and bind approval.                                                                                                                                                |
| Audit logs expose secrets                                                             | High        | Redact by default, allowlist fields, cap event size, test redaction.                                                                                                                                                                                    |
| Overclaiming protection                                                               | High        | Publish threat model and explicit coverage boundaries; never describe tool mediation as complete agent containment.                                                                                                                                     |
| Scope creep across frameworks                                                         | Medium      | Ship one reference integration and a stable adapter contract before expanding.                                                                                                                                                                          |
| Windows path semantics (junctions, 8.3 names, alternate data streams, reserved names) | Medium-High | Deny reparse points; document file-adapter guarantees on Windows as limited; Linux and macOS are release-blocking.                                                                                                                                      |
| Policy probing through denial messages                                                | Medium      | Generic denials to the agent; full reasons only in developer logs and explain mode.                                                                                                                                                                     |
| Scope creep from shell adapter or HTTP service                                        | Medium      | Both deferred beyond v0.1; revisit only after independent bypass review.                                                                                                                                                                                |
| Name or trademark conflict                                                            | Medium      | Check PyPI, GitHub, and trademark databases before first publication; rename before the 0.1.0 tag if needed.                                                                                                                                            |

# 16. Delivery Plan

| **Milestone**                       | **Scope**                                                                                                                                                | **Exit criteria**                                                             |
|-------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| M0 — Design foundation (3–4 days)   | Threat model, action schema, policy grammar and precedence (Section 7), approval semantics, repository skeleton, CI (lint, types, tests), name clearance | Policy semantics reviewed; threat boundaries agreed; name cleared.            |
| M1 — Core enforcement (6–7 days)    | Normalizer, evaluator, SDK wrapper (sync and async), private executor, default-deny, reason codes, explain mode                                          | Hypothesis property tests: zero executor calls on every non-ALLOW outcome.    |
| M2 — Resource adapters (10–12 days) | Calculator, fd-relative file adapter, HTTP adapter with IP pinning and manual redirects                                                                  | 25+ traversal, symlink, and SSRF cases pass; benign corpus baseline recorded. |
| M3 — Audit + approvals (6–7 days)   | Hash-chained JSONL, redaction allowlist, decision-before-dispatch, SQLite or file-backed approval queue, CLI approve/reject                              | Approval binding, expiry, replay, and tamper-detection tests pass.            |
| M4 — Demo + packaging (5–6 days)    | CLI polish, scripted-attacker demo, one real provider tool-use loop, Dockerfile, README, CI                                                              | Fresh-checkout quickstart and full CI pass on Linux.                          |
| M5 — Hardening + release (5–6 days) | Fuzzing, benchmarks, 30–40 attack scenarios, external bypass review, docs freeze, release hygiene                                                        | P0 criteria green; limitations and benchmarks published; v0.1.0 alpha tagged. |

Suggested sequencing: complete M0–M2 before building anything polished. A dashboard is not required for the MVP; correct enforcement and credible security tests are the product’s core proof. The estimates total roughly 35–42 working days for one developer working full time; allow about twice the calendar time if part-time.

## 16.1 Release plan for v0.1.0 (alpha)

- **External review:** ask at least two security-minded reviewers to attempt to bypass the file and HTTP adapters before tagging; convert every bypass into a regression test.

- **Release hygiene:** Apache-2.0 license with DCO sign-off; SECURITY.md with private reporting through GitHub Security Advisories; CHANGELOG; pinned and locked dependencies; vulnerability and secret scanning; signed tags; PyPI Trusted Publishing; SBOM if inexpensive.

- **Documentation gate:** README with threat model, quickstart, and known limitations near the top; policy reference; benchmark methodology. Wording must never imply complete agent containment.

- **Go/no-go:** all P0 criteria pass in CI, zero-executor-call tests are green, the Docker demo runs non-root without privileged mode, and a fresh-clone run succeeds on Linux.

- **Versioning:** publish as 0.1.0 alpha with versioned policy and event schemas; reserve 1.0 for after independent review and real-world feedback.

- **After 0.1:** use 0.2 for hardening and feedback, then add the first extra integration. An MCP policy proxy is the most promising candidate.

# 17. Suggested Repository Structure

> agentshield/  
> ├── pyproject.toml  
> ├── README.md  
> ├── CHANGELOG.md  
> ├── LICENSE  
> ├── SECURITY.md  
> ├── CONTRIBUTING.md  
> ├── .github/workflows/ci.yml  
> ├── docs/  
> │ ├── prd.md  
> │ ├── threat-model.md  
> │ ├── architecture.md  
> │ └── policy-reference.md  
> ├── src/agentshield/  
> │ ├── \_\_init\_\_.py  
> │ ├── models.py  
> │ ├── normalize.py  
> │ ├── policy.py  
> │ ├── evaluator.py  
> │ ├── shield.py  
> │ ├── audit.py  
> │ ├── approvals.py  
> │ ├── cli.py  
> │ └── adapters/  
> │ ├── base.py  
> │ ├── calculator.py  
> │ ├── filesystem.py  
> │ └── http_fetch.py  
> ├── examples/  
> │ ├── basic_agent.py  
> │ ├── scripted_attacker.py  
> │ └── policies/  
> │ └── default-deny.yaml  
> ├── tests/  
> │ ├── unit/  
> │ ├── integration/  
> │ ├── security/  
> │ └── property/  
> ├── Dockerfile  
> └── compose.yaml

# 18. Relationship to Guardrails-Gateway

AgentShield should complement, not duplicate, the existing Guardrails-Gateway / SentraGuard Lite project. The gateway currently focuses on analyzing prompts and context for prompt injection, PII, and RAG-injection signals, applying risk scoring and policy decisions, and sanitizing content. AgentShield's distinct responsibility is authorizing concrete actions at the tool boundary.

| **Concern**      | **Guardrails-Gateway**                           | **AgentShield**                                              |
|------------------|--------------------------------------------------|--------------------------------------------------------------|
| Primary input    | Prompts, context, retrieved text                 | Normalized tool/action requests and resource targets         |
| Primary decision | Content risk and handling policy                 | Whether a specific action may execute now                    |
| Core enforcement | Analyze / score / transform / block content      | Prevent unauthorized tool dispatch                           |
| Key tests        | Detector quality, sanitization, policy decisions | Zero executor calls on deny/pending; resource-boundary tests |
| Integration      | Upstream content guard                           | Downstream tool-call authorization boundary                  |

A later integration can pass gateway risk metadata into AgentShield as an additional signal, but AgentShield must not treat model-generated claims or untrusted text as trusted authorization. Tool authorization remains deterministic and independently enforced.

# 19. Decisions and Open Questions

The questions raised in v1.0 are resolved below. New open questions follow.

- **Decided — First integration:** a minimal custom tool-use loop, with a scripted model in CI and a real provider SDK as optional live mode. LangChain and MCP adapters follow after v0.1.

- **Decided — Optional API:** not in v0.1; the product is SDK-first with a CLI.

- **Decided — Policy format:** YAML only, loaded strictly (safe loader, duplicate keys rejected) with a published JSON Schema.

- **Decided — Approval interface:** CLI-only in v0.1; no web interface.

- **Decided — Platforms:** Linux and macOS are release-blocking; Windows runs core and policy tests in CI and its file-adapter limits are documented.

- **Decided — License:** Apache-2.0 with DCO sign-off.

**Open questions**

- Is the AgentShield name available on PyPI, GitHub, and trademark databases, or is a rename needed before first publication?

- Will per-tool call-count limits (FR-17) make v0.1, or move to 0.2?

- What approver authentication should replace the OS user plus local secret after v0.1?

- Should Windows file-adapter guarantees be upgraded after the bypass review, or remain documented limitations?

# 20. Definition of Done

AgentShield v0.1.0 is done when the core enforcement path is small and understandable, all P0 acceptance criteria pass, security tests (including property-based tests) prove that denied and approval-pending actions do not execute, independent reviewers have attempted to bypass the file and HTTP adapters, the demo works from a clean checkout, and the documentation accurately states the threat model and limitations. The release must prioritize verifiable enforcement over the number of integrations or the polish of the UI.

# Appendix A — Example Policy (Illustrative)

> version: 1  
> default_decision: DENY  
>   
> tools:  
> calculator:  
> enabled: true  
> risk: low  
> decision: ALLOW  
>   
> filesystem.read:  
> enabled: true  
> risk: medium  
> allowed_roots:  
> - ./workspace  
> max_bytes: 1048576  
> decision: ALLOW  
>   
> filesystem.write:  
> enabled: true  
> risk: high  
> allowed_roots:  
> - ./workspace/output  
> max_bytes: 1048576  
> decision: REQUIRE_APPROVAL  
> approval_ttl_seconds: 300  
>   
> http.fetch:  
> enabled: true  
> risk: medium  
> allowed_schemes:  
> - https  
> allowed_hosts:  
> - docs.example.com  
> allowed_ports:  
> - 443  
> block_private_addresses: true  
> revalidate_redirects: true  
> max_redirects: 3  
> max_response_bytes: 2097152  
> timeout_seconds: 10  
> decision: ALLOW  
>   
> shell.exec:  
> enabled: false  
> decision: DENY

This policy is a product illustration, not a complete production policy. Constraint values such as max_bytes and timeouts are examples. Constraints are hard limits: a violation returns DENY even when the tool’s decision is ALLOW or REQUIRE_APPROVAL (Section 7.1). The shell.exec entry only illustrates an explicit deny; no shell adapter ships in v0.1, and unregistered tools are denied by default. Exact schema, path resolution, host validation, and approval behavior must be defined and tested in implementation.

# Appendix B — Revision Summary (v1.0 to v1.1)

Changes made after a design review of v1.0. Section references are to this document.

| **Area**               | **Change in v1.1**                                                                                            | **Reason**                                                                      |
|------------------------|---------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| Release scope          | Re-scoped as v0.1.0 alpha; FastAPI service, shell adapter, and metrics endpoint deferred.                     | Reduces attack surface and scope; a 1.0 label should follow independent review. |
| Policy semantics       | Added the rule model (7.1): hard constraints, fixed evaluation order, no user regex, generic denials.         | Appendix A mixed decisions and constraints without defining how they interact.  |
| Executor encapsulation | Wrapper holds the executor privately; extraction tests added (FR-01, Section 10).                             | "Unreachable until ALLOW" was undefined for an in-process SDK.                  |
| Approvals              | Promoted to P0 (minimal, CLI-only); semantics defined (7.3).                                                  | Acceptance criteria and the sample policy already depended on approvals.        |
| Explain mode           | Promoted to P0 (FR-10).                                                                                       | Needed by tests and nearly free once the evaluator exists.                      |
| Filesystem             | fd-relative, no-follow opens; Windows limits documented (FR-05).                                              | Canonicalize-then-open has a TOCTOU gap; Windows path semantics differ.         |
| HTTP / SSRF            | Resolve once, connect to the validated IP, manual redirects, numeric IP forms, proxy handling (FR-06).        | "Where feasible" was not implementable as written.                              |
| Async and audit order  | Sync and async support (FR-15); decision event before dispatch; fail closed if unwritable (FR-08).            | Most frameworks are async; audit ordering was unspecified.                      |
| Audit integrity        | Hash-chained events with a verify command.                                                                    | Makes tamper-evident-by-design concrete without claiming immutability.          |
| Metrics and limits     | Latency target excludes DNS and I/O; metrics reduced to in-process counters; call limits added as P2 (FR-17). | A latency target that includes network I/O is not meaningful.                   |
| Testing                | Property-based tests, at least 30 attack scenarios, at least 50 benign actions, external bypass review.       | Strengthens the zero-executor-call proof.                                       |
| Platforms              | Linux and macOS release-blocking; Windows limited and documented.                                             | Windows file semantics are a large separate effort.                             |
| Plan and decisions     | Delivery plan with effort estimates, release plan (16.1), open questions resolved (19).                       | Turns the PRD into an executable plan.                                          |
