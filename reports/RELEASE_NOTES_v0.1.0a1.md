# AgentShield v0.1.0a1 — Public Alpha Release Notes

**Release Tag:** `v0.1.0a1`
**Release Type:** Alpha Preview (Pre-Release)
**Date:** 2026-11-04
**Git Commit:** `5353c61` (Release preparation commit)
**License:** Apache 2.0

---

> [!WARNING]
> **ALPHA PREVIEW NOTICE:** AgentShield v0.1.0a1 is a public pre-release intended for developer experimentation, architectural evaluation, and security research. **It has NOT yet completed an independent third-party application security review.** Do not deploy in mission-critical production environments without understanding the documented threat model and limitations. Stable release v0.1.0 is blocked pending independent security audit (PRD Section 13 Criterion 14).

---

## 1. Release Overview

AgentShield is a lightweight, high-performance in-process runtime authorization firewall and hash-chained audit system for AI agents.

While LLM prompt filters evaluate *text*, AI agents cause real-world impact through *actions*: reading local files, making HTTP network requests, and executing system tools. AgentShield intercepts tool calls at the application boundary, treating all model-proposed tool names and arguments as untrusted inputs. It deterministically enforces default-deny policies, single-use human approvals, and cryptographic audit trails before invoking wrapped tools.

---

## 2. Main Capabilities

- **Deterministic Tool Authorization:** Wraps synchronous and asynchronous tool functions (`shield.wrap(tool)` / `shield.wrap_async(tool)`). Hidden closures guarantee that denied actions never invoke tool executors.
- **Strict YAML Policy Engine:** Policies define allowable tools, risk classifications (`low`, `medium`, `high`), decisions (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`), and hard constraints. Rejects duplicate keys, aliases, and dangerous YAML deserialization.
- **Human-in-the-Loop Approvals:** High-risk actions generate expiring, single-use approval requests cryptographically bound to `(action_hash, policy_hash, agent_id)` and signed with HMAC-SHA256 via SQLite.
- **Tamper-Evident Audit Chains:** Decision events are written to a JSONL log *before* tool execution, and outcome events after. Events are linked via SHA-256 hash chaining with an external `.head` sidecar file for verifiable forensic integrity (`agentshield audit verify`).
- **Secret Redaction:** Argument summaries automatically redact sensitive payloads: file contents are replaced with byte lengths and SHA-256 digests; URLs are stripped of credentials and query strings.
- **Command-Line Interface:** Inspect, validate, and manage policies and approvals with `agentshield lint`, `agentshield evaluate`, `agentshield explain`, `agentshield approvals`, `agentshield audit`, and `agentshield schema`.

---

## 3. Built-In Security Adapters

- **Safe Calculator (`calculator`):** Evaluates mathematical expressions using a strict AST whitelist. Enforces node counts, depth limits, magnitude bounds (`10^60`), exponent bounds, and rejects non-numeric types (`complex`, `bool`, `str`, `None`).
- **Filesystem Tools (`filesystem.read`, `filesystem.write`):**
  - Enforces workspace root confinement and rejects directory traversal (`..`) and absolute path escapes.
  - **POSIX:** Uses fd-relative traversal (`openat`) with `O_NOFOLLOW` and `O_DIRECTORY` to eliminate Time-of-Check to Time-of-Use (TOCTOU) symlink swap races. Rejects FIFOs and hardlinks (`st_nlink > 1`).
  - **Windows:** Inspects reparse points at decision time (`probe_windows`) and pre-open verification (`_win_walk`). Rejects Windows reserved device names (`CON`, `PRN`, `NUL`, `COM1-9`, `LPT1-9`) and alternate data streams (`:stream`).
- **SSRF-Resistant HTTP (`http.fetch`):**
  - Scheme and port allowlisting.
  - **DNS Pinning:** Resolves hostname once, validates every IP in the response, and connects directly to the validated IP while preserving the original `Host` header and TLS certificate verification.
  - **Network Classification:** Blocks RFC1918 private subnets, loopback addresses, cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`), IPv4-mapped IPv6, NAT64 (`64:ff9b::/96`), 6to4, and non-canonical numeric IP formats.
  - **Redirect Protection:** Manually follows HTTP redirects up to 5 hops, re-validating every intermediate destination against policy allowlists.

---

## 4. Platform Support & Compatibility

| Platform | Support Tier | Security Guarantees & Status |
|---|---|---|
| **Linux (x86_64, Debian / Ubuntu)** | **Tier 1 (Reference)** | Full kernel-level race protection via `openat(O_NOFOLLOW)`. 204/204 tests passed. 26/26 mutations killed. |
| **macOS (Darwin 64-bit)** | **Tier 1** | Full POSIX compliance matching Linux (`_IS_POSIX = True`). CI validated on macOS runners. |
| **Windows 11 (NT Hybrid)** | **Tier 2 (Supported)** | Full core SDK, policy evaluation, NetGuard, approvals, and audit support. 193/204 tests passed (11 POSIX-only skipped). Reparse point defense-in-depth. |
| **Hardened Docker Container** | **Recommended** | Non-root runtime (`10001:10001`), read-only rootfs, `network_mode: none`, `cap_drop: [ALL]`. Verified in `compose.yaml`. |

---

## 5. Installation Instructions

> [!NOTE]
> **GitHub-Only Distribution:** Version `v0.1.0a1` is provided exclusively through GitHub (GitHub Releases and GitHub Actions workflow artifacts). Pushing a version tag builds and archives artifacts within GitHub Actions; **it does not publish to PyPI**. Any future publication to PyPI must use a separate, explicit, manually controlled release workflow.

### Requirements
- Python 3.11 or 3.12
- Core runtime dependency: `PyYAML>=6.0,<7` (zero C extensions required for pure Python mode)

### From GitHub Release Assets
Download the wheel from GitHub Release assets:
```bash
pip install agentshield-0.1.0a1-py3-none-any.whl
```

### From Source
```bash
git clone https://github.com/partialHuman/AgentShield.git
cd AgentShield
git checkout v0.1.0a1
pip install -e .
```

---

## 6. Quickstart Example

```python
import os
import tempfile
from agentshield import Shield, Policy, ApprovalStore, AuditLog, ActionDenied, ApprovalPending
from agentshield.adapters import calculator_tool, file_read_tool, file_write_tool

base = tempfile.mkdtemp()
os.makedirs(os.path.join(base, "workspace", "output"))
with open(os.path.join(base, "workspace", "hello.txt"), "w") as fh:
    fh.write("hello world")

policy = Policy.from_text("""
version: 1
tools:
  calculator:       {risk: low,    decision: ALLOW}
  filesystem.read:  {risk: medium, decision: ALLOW, allowed_roots: [./workspace]}
  filesystem.write: {risk: high,   decision: REQUIRE_APPROVAL, allowed_roots: [./workspace/output]}
""", base_dir=base)

shield = Shield(
    policy,
    agent_id="agent-007",
    audit=AuditLog(os.path.join(base, "audit.jsonl")),
    approvals=ApprovalStore(os.path.join(base, ".agentshield")),
)

calc = shield.wrap(calculator_tool())
read = shield.wrap(file_read_tool())

# Allowed action executes normally
print(calc(expression="2 + 2 * 10"))  # 22
print(read(path="hello.txt")["content"])  # hello world

# Path traversal attempt is denied deterministically outside the model
try:
    read(path="../../etc/passwd")
except ActionDenied as denied:
    print("Agent received:", denied.agent_message())  # generic message
    print("Audit reason:", denied.result.reason_codes)  # ['PATH_TRAVERSAL']
```

---

## 7. Known Limitations & Threat Model Boundaries

1. **Independent Security Audit Pending:** Strict compliance with PRD Section 13 Criterion 14 requires a third-party security audit prior to stable release v0.1.0.
2. **Windows Filesystem TOCTOU Window:** Windows NTFS lacks an atomic `openat(O_NOFOLLOW)` primitive. Directory traversal defense is implemented via pre-open checks (`_win_walk` and `probe_windows`). In hostile multi-tenant environments where a local concurrent process swaps directories with junction points, a race condition window remains. Production workloads requiring strict filesystem sandboxing should execute on Linux or inside hardened Linux containers (`compose.yaml`).
3. **Approval Store Local User Trust:** The approval HMAC key (`approval.key`) is stored on the filesystem with permission mode `0o600`. Any process executing under the same OS user account can read this key. Production deployments using human-in-the-loop approvals should run the agent and approver under distinct OS accounts.
4. **In-Process Boundary:** Tool wrapping is a design boundary, not an operating-system sandbox against malicious bytecode running within the same Python process.

---

## 8. Vulnerability Reporting

If you discover a security vulnerability or authorization bypass in AgentShield, please disclose it privately in accordance with our [Security Policy](SECURITY.md). Please do not create public GitHub issues for security vulnerabilities.
