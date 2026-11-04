# Threat model (v0.1.0 alpha)

AgentShield sits between an AI agent and the tools it can call. Its job is narrow: **make sure an action the
model *proposes* is only executed if your policy says so, and leave an explainable record.** This document says
what that does and does not protect against. Please read the limitations before relying on it.

## 1. What is protected

| Asset | Example |
|---|---|
| Files outside the configured roots | `~/.ssh/id_rsa`, `/etc/passwd`, other projects |
| Internal network services and cloud credentials | `169.254.169.254`, `localhost:8080/admin`, RFC1918 hosts |
| The host's integrity | arbitrary code via a "calculator", shell commands |
| Audit trail accuracy | what was attempted, what was decided, by which policy |

## 2. Adversary and trust boundaries

**The adversary is the model's output.** A model may propose harmful tool calls because a user asked,
because a prompt injection in a web page or document steered it, or because it is simply wrong. AgentShield treats
**every tool name and every argument as untrusted input**.

Trusted: your application code, the policy file, the operating system user running the process, the local
approval-store directory, and the tool implementations you write.

```
 untrusted                      trusted process boundary (your application)
┌────────────┐   tool_use   ┌──────────────────────────────────────────────┐
│   model    │ ───────────▶ │ Shield: normalize → evaluate → (approve) →   │──▶ executor ──▶ file / network
│ (+ content │ ◀─────────── │         audit(decision) → dispatch → audit   │
│  it read)  │ generic text │         (outcome)                            │
└────────────┘              └──────────────────────────────────────────────┘
```

## 3. Security properties and the evidence for each

| # | Property | Mechanism | Evidence in this repository |
|---|---|---|---|
| P1 | A `DENY` or pending-approval action never reaches an executor | The executor is captured privately by the wrapper and invoked only after an `ALLOW` | Executor-spy tests for every deny path; 2,500-case seeded property test; 73-scenario attack corpus asserts zero executor calls; mutation check |
| P2 | Fail closed | Evaluator exception, audit failure (protected tools), missing approval store, unknown tool, no matching rule → `DENY` | `test_shield_flow` (crash, audit-down, no store, unknown/garbage names) |
| P3 | No file access beyond configured roots, no symlink following | `..` rejected lexically; on POSIX every component is opened with `O_NOFOLLOW` relative to the previous directory fd, so there is no check-then-use gap; hard-linked files refused; only regular files | Symlink/hard-link/FIFO tests; a symlink-swap race harness (control experiment: a naive "check then open" leaks 6 times in 20,000 attempts with the same harness; this implementation leaked 0 while blocking ~12,000 mid-swap reads) |
| P4 | SSRF resistance | URL normalized; allowlists for scheme/host/port; DNS resolved **once**, **every** answer validated, then the **validated IP** is connected to (Host header and TLS SNI/cert hostname stay the original); redirects handled manually and revalidated every hop; numeric/mapped/NAT64/6to4/Teredo IP forms handled; metadata and link-local addresses always blocked; proxy environment variables ignored; bounded, never-decompressed responses | Rebinding simulation, redirect tests, real TLS test (cert verified against the original hostname while connecting to the pinned IP), 32 SSRF/URL scenarios in the corpus |
| P5 | Approvals are exact, single-use and expiring | Bound to `(action_hash, policy_hash, agent_id)`; atomic consume in SQLite; HMAC over the approval row; TTL | `test_approvals`, concurrent-resubmission test (10 threads, executes once) |
| P6 | Tamper-**evident** audit | Hash chain + `.head` sidecar; decision event written **before** dispatch, outcome after; secrets never logged (allow-list summaries: file content → size + SHA-256, URL → no userinfo/query) | `test_audit`, credential-leak tests, mutation check |
| P7 | The agent cannot probe the policy | Agents receive a generic message; reason codes and traces are developer-only | `test_denial_message_is_generic...` |

## 4. Out of scope (AgentShield does not try to do this)

- **Prompt-injection prevention or content filtering.** AgentShield authorizes *actions*, not *text*. Data a
  tool returns (a fetched page, a file) goes back to the model unmodified.
- **Sandboxing hostile code in your process.** The wrapper hides the executor from the public API, but Python
  introspection (closures, `gc`, `ctypes`, monkey-patching) can reach it. In-process wrapping is a *design
  boundary*, not a security boundary against code that already runs in your process.
- **Malicious tool implementations**, compromised hosts, malicious dependencies, kernel/container escapes.
- **Operating-system isolation.** Use containers, seccomp, read-only root filesystems, non-root users and network
  egress rules as defense in depth. `compose.yaml` shows one hardened configuration.
- **Multi-tenant authorization, SSO/identity**, remote policy distribution, per-agent policies (v0.1 applies one
  policy per `Shield`; the agent id is recorded and bound into approvals).

## 5. Known limitations (read these)

**Approvals**
- The approver is the local OS user plus possession of `approval.key` (HMAC). Code running as the *same OS user* can
  read the key and approve its own requests. Run the agent and the approver as different users (or on different
  hosts) if that matters; stronger approver authentication is planned.
- The approval prompt shows a bounded, redacted summary. The hash binds the *full* arguments, but a human only sees
  the summary (e.g. a file-write shows path, size and SHA-256, not the content).

**Audit**
- Tamper-evident, not tamper-proof: someone who can rewrite both the log and its `.head` file can forge a consistent
  chain. Anchor `last_hash` externally (`agentshield audit verify FILE --expect-hash H`) if you need stronger guarantees.
- Only *decision* and *outcome* events are written. Allow-list summaries mean some forensic detail is deliberately
  absent. Custom tools that supply their own `summarize` can leak whatever that function returns.
- If the log is unwritable, `ALLOW` becomes `DENY` unless you explicitly opt in to a low-risk fallback.

**Filesystem**
- The POSIX guarantees depend on `openat`-style resolution with `O_NOFOLLOW`. They hold for the paths *beneath* a root;
  the root directories themselves are resolved once at policy load (a symlinked root is followed there, by design).
- Absolute paths must match the root's real path textually (e.g. on macOS `/tmp` vs `/private/tmp` will not match). Relative
  paths resolve against the **first** allowed root.
- Hard-linked files (`st_nlink > 1`) are refused for read and write. Directory listing/deleting tools do not exist in v0.1.
- **Windows is best-effort and was not tested in this release's development environment.** Reparse points are denied and
  alternate data streams, reserved device names, drive/UNC paths and short names are rejected, but a check-then-use
  window remains. Treat Windows file protection as defense-in-depth only.

**HTTP**
- GET only. Response bodies are bounded and returned undecoded; no content inspection.
- DNS is resolved by the system resolver, and you trust it (DNS-over-TLS/DNSSEC are out of scope). Pinning removes the
  rebinding window between check and connect; it cannot protect against a poisoned resolver answering with a public IP.
- TLS verification uses the system trust store. A custom `ssl_context` can be supplied for private CAs.
- Address classification uses Python's `ipaddress` semantics, which differ slightly between Python minor versions; extra
  explicit rules cover metadata, link-local, NAT64, 6to4, Teredo and IPv4-mapped forms.

**General**
- Sync custom tools cannot be forcibly interrupted; give them their own timeouts. Built-in adapters enforce time and size limits.
- `max_calls` counters are per-process and not persisted.
- v0.1 is an **alpha**. It has had tests, a mutation check and a self-written attack corpus, but **no independent security
  review yet** (planned before any 1.0).
- Development and testing happened on Linux with Python 3.12. Python 3.11, macOS and Windows are covered by the CI matrix
  but were not run during development.

## 6. Deployment guidance

1. Run the agent as an unprivileged user, in a container with a read-only root filesystem and `cap_drop: ALL`.
2. Restrict network egress at the OS/firewall level *in addition to* `http.fetch` allowlists.
3. Keep approval keys and audit logs on storage the agent's user cannot write (or run the approver separately).
4. Start with `REQUIRE_APPROVAL` for anything high-risk and review the audit log before loosening a rule.
5. Treat every bypass report as a regression test: add it to `tests/security/corpus.py`.
