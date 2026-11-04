# AgentShield — External Security Review Package

**Project:** AgentShield  
**Target Version:** 0.1.0a1 (Alpha)  
**Document Purpose:** Independent Application Security Auditor Guide & Testing Package  
**Assessor Context:** Prepared for Third-Party Application Security & AI Runtime Security Reviewers  
**Repository Branch:** `dev/baseline-validation`  
**Compliance Target:** PRD v1.1 Section 13 Criterion 14 (Independent Security Review)  

---

> [!IMPORTANT]
> **Status Notice:** AgentShield v0.1.0a1 has undergone rigorous internal testing, mutation testing (26/26 killed on Linux), and cross-platform verification. However, **it has NOT yet completed an external independent security audit**. Per project release criteria, graduation to v0.1.0 stable general release is blocked until independent external review findings are documented and addressed.

---

## 1. Architecture & Threat Model

AgentShield sits directly between an AI agent (LLM framework / loop) and the tools it can invoke. It acts as an in-process, deterministic runtime authorization firewall and hash-chained audit system.

```
┌────────────────────────┐
│  Untrusted AI Agent    │  (Prompt-injected content, rogue model, untrusted tool call)
└──────────┬─────────────┘
           │ Proposed Action (tool name, untrusted kwargs)
           ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  AgentShield Firewall Boundary (Trusted Application Space)                      │
│                                                                                  │
│   1. Argument Normalization & Strict Schema Validation                           │
│   2. Policy Evaluation (Default Deny, Risk Assessment, Built-in & Custom Bounds) │
│   3. Human Approval Store (HMAC-Bound, Expiring, Single-Use, SQLite)             │
│   4. Decision Audit Event Logging (Recorded BEFORE dispatch)                     │
│   5. Dispatch to Wrapped Tool Executor (Private Closure)                         │
│   6. Outcome Audit Event Logging (Redacted Summaries, Status, Hash Chained)      │
└──────────────────────────────────┬───────────────────────────────────────────────┘
                                   │ Only ALLOWED Actions Dispatched
                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  Host OS & External Resources (Filesystem, Network, Python Runtime)              │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Threat Model Assumptions & Adversary Capabilities
- **The Adversary:** The AI model's output. A model may propose harmful tool calls due to indirect prompt injection, multi-turn jailbreaking, adversarial inputs from retrieved documents, or hallucinations.
- **Untrusted Inputs:** Tool names, string paths, URLs, query parameters, shell commands, and JSON payloads proposed by the agent are treated as hostile.
- **Trusted Computing Base (TCB):** The host operating system kernel, the Python process running AgentShield, the policy definition file, the local file system hosting `approval.key`, and custom tool executors written by the developer.

### 1.2 Security Boundaries & Explicit Non-Goals
1. **In-Process Python Boundary:** AgentShield wraps tool callables using private closures to hide executors. However, inside the same Python process, code execution (e.g. `ctypes`, `gc.get_objects()`, monkey-patching) can bypass wrapper closures. AgentShield is designed to constrain *well-formed agent loops calling tools*, not to contain arbitrary bytecode already running within the interpreter.
2. **Container / OS Hardening:** Operating system sandboxing (containers, cgroups, seccomp, dropped capabilities, non-root users) must be layered beneath AgentShield for defense-in-depth (`compose.yaml`).
3. **Action Authorization vs. Content Inspection:** AgentShield authorizes *actions* proposed by the model. It does not inspect or filter the returned content payload flowing back to the LLM context window.

---

## 2. Attack Surfaces & Relevant Source Locations

| Subsystem | Security Responsibilities | Source Locations |
|---|---|---|
| **Core Firewall & Dispatch** | Default-deny enforcement, evaluator fail-closed behavior, private closure over executor, decision-before-dispatch ordering. | `src/agentshield/shield.py`<br>`src/agentshield/evaluator.py`<br>`src/agentshield/models.py` |
| **Policy Engine** | Safe YAML loading (no arbitrary code execution), duplicate key rejection, YAML alias expansion attack prevention, schema validation. | `src/agentshield/policy.py`<br>`src/agentshield/schema.py`<br>`src/agentshield/constraints.py` |
| **Filesystem Adapter** | Workspace root confinement, directory traversal (`..`) blocking, atomic symlink race (TOCTOU) defense, hardlink & FIFO rejection, Windows reparse point blocking, Windows device name rejection. | `src/agentshield/adapters/filesystem.py`<br>`src/agentshield/normalize.py` |
| **Network & SSRF Guard** | Scheme & port allowlisting, DNS resolution pinning, IP address classification (blocking loopback, private, cloud metadata, IPv4-mapped IPv6, NAT64, 6to4, Teredo), manual redirect revalidation, TLS hostname verification. | `src/agentshield/netguard.py`<br>`src/agentshield/adapters/http_fetch.py` |
| **Human Approvals** | Cryptographic binding `(action_hash, policy_hash, agent_id)`, HMAC-SHA256 signature, expiry enforcement, atomic single-use consume, SQLite transaction isolation. | `src/agentshield/approvals.py` |
| **Audit Logging** | SHA-256 hash chaining, `.head` sidecar anchoring, tamper-evident verification, credential & secret redaction in argument summaries. | `src/agentshield/audit.py` |

---

## 3. Existing Automated Security Test Suite

AgentShield comes with 204 automated tests covering functional, security, property-based, and concurrency behaviors:

1. **Unit Test Suite (`tests/unit/`):**
   - `test_approvals.py`: Approval expiry, MAC binding, SQLite row tampering, concurrent consume.
   - `test_audit.py`: Hash chain calculation, tampering detection, reordering detection, concurrent writers.
   - `test_netguard.py`: IPv4, IPv6, cloud metadata (`169.254.169.254`), non-canonical numeric IP formats, embedded IPv4 addresses.
   - `test_filesystem_paths.py`: Traversal, root escaping, Windows reserved names (`CON`, `NUL`), Windows reparse points.
   - `test_policy.py`: YAML deserialization attacks, duplicate keys, anchor bombs.
2. **Integration Test Suite (`tests/integration/`):**
   - `test_shield_flow.py`: Fail-closed on evaluator error, audit down fallback, call limits under 8-thread concurrency, single-use approval under 10-thread concurrency.
   - `test_filesystem_adapter.py`: Symlink swaps, directory hops, hardlink rejections, FIFO rejections, atomic `O_NOFOLLOW` relative reads.
   - `test_http_adapter.py`: DNS rebinding attacks, redirect chains, TLS SNI vs. pinned IP verification.
3. **Security Attack Corpus (`tests/security/`):**
   - `corpus.py` & `test_attack_corpus.py`: 73 dedicated adversarial attack vectors spanning path traversal, SSRF bypasses, and schema violations.
4. **Property & Fuzzing Tests (`tests/property/`):**
   - `test_properties.py`: Hypothesis property tests covering normalizer invariance, path normalization matching `PurePosixPath`, audit chain integrity under concurrent chaos.
5. **Mutation Testing (`scripts/mutation_check.py`):**
   - 26 deliberate source code mutations targeting security-critical lines; requires full test failure to kill.

---

## 4. Known Limitations & Platform Discrepancies

### 4.1 Windows Filesystem TOCTOU Window (Defense-in-Depth)
- **POSIX Guarantee:** On Linux and macOS, `_read_posix()` uses fd-relative directory traversal with `openat(dir_fd, component, O_NOFOLLOW | O_DIRECTORY)`. This closes the Time-of-Check to Time-of-Use (TOCTOU) gap at the OS kernel level. A concurrent attacker swapping a directory for a symlink between decision and read is trapped atomically.
- **Windows Limitation:** Windows NTFS lacks an atomic `openat(O_NOFOLLOW)` primitive in the Python standard library. AgentShield defends Windows using `probe_windows()` at decision time and `_win_walk()` at use time to inspect reparse points (`stat.FILE_ATTRIBUTE_REPARSE_POINT`). In a hostile multi-threaded environment where a local process swaps directories between validation and open, a race condition window remains.
- **Auditor Guidance:** Reviewers should test whether this window can be exploited on Windows and evaluate whether Win32 `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` should be integrated via `ctypes`.

### 4.2 Audit Hash Chaining vs. System Compromise
- **Tamper-Evident, Not Tamper-Proof:** Audit log events are linked via SHA-256 hash chains (`hash = SHA256(seq || ts || type || prev_hash || body)`). An external observer holding a copy of the latest `.head` hash can immediately detect tampering, modification, or truncation.
- **Attacker with Local Write Access:** An attacker with write access to both the `.jsonl` file and the `.head` file can re-compute a valid synthetic chain from scratch. Auditors should verify the external hash anchoring mechanism (`agentshield audit verify --expect-hash <HASH>`).

### 4.3 Approver Identity & Shared Local User
- Approvals are signed with HMAC-SHA256 using `approval.key` stored on disk with mode `0o600`. Any process running as the **same OS user** can read `approval.key` and generate valid approval signatures.
- Deployments requiring human-in-the-loop authorization should run the agent under a separate dedicated unprivileged OS user account.

---

## 5. Reviewer Reproduction & Execution Commands

### 5.1 Environment Setup (POSIX / Linux / macOS)
```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 5.2 Test Suite Execution
```bash
# Run full unittest discovery
python -m unittest discover -s tests -t . -v

# Run with strict ResourceWarning mode
python -W error::ResourceWarning -m unittest discover -s tests -t .

# Run pytest runner
pytest -q
```

### 5.3 Security Mutation Test Execution
```bash
python scripts/mutation_check.py
# Reference Result on Linux: 26 / 26 mutations killed
# Reference Result on Windows: 24 / 26 mutations killed (2 POSIX-only lines survive)
```

### 5.4 Hardened Container Demo Execution
```bash
docker compose run --rm demo
# Expected Output: 11 denied, 1 held for approval, 3 allowed actions; audit chain OK; secret in audit: False
```

### 5.5 Static Analysis Execution
```bash
# Ruff linter
ruff check src tests examples benchmarks scripts

# Mypy type checker
mypy
```

---

## 6. Specific Bypass Scenarios for Reviewers to Attempt

Independent auditors are requested to specifically attempt the following targeted attack scenarios:

### 6.1 Filesystem Path Traversal & Symlink Escapes
- [ ] **Symlink Swap Race (TOCTOU):** Execute a multi-threaded attacker process continuously swapping an allowed workspace sub-directory with a symlink to `/etc` or `C:\Windows` during rapid tool execution. Verify whether any reads escape the root.
- [ ] **Reparse Point Variations (Windows):** Test Windows directory junctions, volume mount points, AppExecLinks, and Alternate Data Streams (`filename.txt:stream:$DATA`).
- [ ] **Path Normalization Edge Cases:** Attempt Windows 8.3 short name collisions (`PROGRA~1`), reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`), mixed path separators (`/` vs. `\`), and URI-encoded path components (`%2e%2e`).

### 6.2 HTTP SSRF, DNS Rebinding & URL Parsing
- [ ] **DNS Rebinding:** Configure a custom authoritative DNS server that returns an allowed public IP on the first resolution query and a loopback address (`127.0.0.1`) or cloud metadata IP (`169.254.169.254`) on the second. Verify whether AgentShield's DNS pinning (`_pinned_connector`) prevents SSRF.
- [ ] **Redirect Transitions:** Host an allowed endpoint that issues HTTP 301/302 redirects to `http://169.254.169.254/latest/meta-data/` or `http://[::ffff:127.0.0.1]/`. Verify that every redirect hop is independently re-validated against the policy.
- [ ] **SNI & Certificate Validation:** Verify that when connecting to a pinned IP, TLS certificate hostname validation verifies against the original requested domain name, not the numeric IP.
- [ ] **Ambiguous Numeric & Encoded IP Formats:** Test dword integer IPs (`http://2130706433/`), octal IPs (`http://0177.0000.0000.0001/`), dotted hex (`http://0x7f.0x0.0x0.0x1/`), IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`), and NAT64 (`64:ff9b::127.0.0.1`).

### 6.3 Human Approval Workflows & Concurrency
- [ ] **Approval Replay:** Capture a valid approval ID and attempt to execute a second tool call with the same ID after it has been consumed.
- [ ] **Parameter Tampering Under Approved Action:** Approve an action for `filesystem.write(path="report.txt")` and attempt to execute `filesystem.write(path="secret.txt")` using the original approval token.
- [ ] **Cross-Agent Approval Transplant:** Attempt to consume an approval approved for `agent-A` from within a session for `agent-B`.
- [ ] **Approval Signature Forgery:** Inject a forged row into the SQLite `approvals` table with status `approved` without knowing `approval.key`. Verify whether HMAC verification halts consumption.
- [ ] **High-Concurrency Race on Consume:** Spawn 50 concurrent threads attempting to consume a single pending approval simultaneously. Verify that exactly one thread succeeds and 49 fail.

### 6.4 Audit Chain Integrity & Information Leakage
- [ ] **Intermediate Log Event Tampering:** Modify a single character inside an intermediate JSON line of an audit log. Run `agentshield audit verify` and verify that the chain error is flagged with the exact sequence number.
- [ ] **Audit File Truncation:** Remove the last 3 events from an audit log file while leaving the `.head` sidecar file unchanged. Verify that chain verification fails.
- [ ] **Sensitive Data Leakage:** Inspect audit logs generated by `http.fetch` and `filesystem.write`. Verify that authorization headers, URL query parameters, passwords, and file contents are properly redacted.

---

## 7. Independent Reviewer Findings Checklist

Reviewers are invited to record their findings using the template below:

| Target Subsystem | Severity (Critical / High / Medium / Low / Info) | Vulnerability Title | Source Location | Description & Repro Steps | Recommended Remediation |
|---|---|---|---|---|---|
| Core Engine / Dispatch | | | | | |
| Policy Parser / Loader | | | | | |
| Filesystem Adapter | | | | | |
| HTTP / NetGuard Adapter | | | | | |
| Approval Workflow | | | | | |
| Audit Hash Chaining | | | | | |
| Packaging / Configuration | | | | | |

---

## 8. Auditor Sign-Off Template

```markdown
### Independent Security Review Sign-Off

- Reviewing Organization: __________________________________________________
- Lead Auditor Name: ______________________________________________________
- Date of Assessment: ____________________________________________________
- Repository Commit Hash Audited: _________________________________________
- Overall Security Verdict: [ ] PASS  [ ] PASS WITH REMEDIATION  [ ] FAIL
- Justification & Summary:
  _________________________________________________________________________
  _________________________________________________________________________
```
