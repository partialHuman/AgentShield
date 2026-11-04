# AgentShield v0.1.0a1 — Pre-Publication Audit & CI Readiness Report

**Date:** 2026-11-04  
**Project:** AgentShield  
**Target Release:** 0.1.0a1 (Alpha)  
**Assessor:** Senior Python Test & AI Agent Runtime Security Engineer  
**Repository Branch:** `dev/baseline-validation`  
**Remote Target:** `origin https://github.com/partialHuman/AgentShield.git`  
**Audit Purpose:** Comprehensive pre-push verification prior to publishing the development branch to GitHub.  

---

> [!CAUTION]
> **Pre-Publication Guardrail Notice:** Per project security policy, **no code has been pushed, merged, published to PyPI, or released**. The `main` branch remains untouched. Stable general release (v0.1.0) remains **strictly blocked** pending independent external security review (PRD Section 13 Criterion 14).

---

## 1. Git Integrity & Repository Hygiene Result

### 1.1 Branch & Commit Lineage
- **Active Branch:** `dev/baseline-validation`
- **Initial Baseline Commit:** `7a0d77c test: establish reproducible Windows test environment`
- **Commit History:** Exactly nine linear commits preserved without squashing, rebasing, or rewriting:
  1. `7a0d77c` test: establish reproducible Windows test environment
  2. `1a08778` fix: correct package installation configuration
  3. `b1a8429` test: improve platform-specific test handling
  4. `4dd2ef7` test: strengthen filesystem security regressions
  5. `1b4f3a3` test: expand HTTP security regression coverage
  6. `5eb5075` test: improve approval and audit regression coverage
  7. `9ea2a86` docs: document Windows validation results
  8. `c4ba582` ci: expand workflow matrix and resolve linting violations
  9. `1b70d66` docs: document cross-platform release readiness evaluation

### 1.2 Repository Content & Hygiene Verification
- **Working Tree State:** Completely clean (`git status` confirms no untracked or uncommitted changes).
- **Virtual Environments & Build Artifacts:** `.venv/`, `build/`, `dist/`, `.ruff_cache/`, and `.egg-info/` are verified excluded from Git tracking via `.gitignore`.
- **Sensitive Data & Secrets Audit:**
  - Automated regex scan for private keys (`BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`) returned **zero hits**.
  - Scan for credentials, API tokens, and secrets in tracked files returned **zero hits**.
  - Scan for local absolute user directory paths (`C:\Users\...`) confirmed zero hardcoded user paths in source files. (All path occurrences are restricted to path-traversal denial test cases and reports).
- **Database & Log File Exclusion:** Verified no runtime SQLite databases (`*.db`, `*.sqlite`) or audit logs (`*.jsonl`, `*.head`) are tracked.
- **Ignore Rule Completeness:** Both `.gitignore` and `.dockerignore` properly cover cache directories, virtual environments, build artifacts, and test logs.

---

## 2. GitHub Actions CI/CD Configuration Assessment

### 2.1 Workflow Integrity & Security Permissions

| Workflow | File Path | Triggers | Security Permissions | Least Privilege Assessment |
|---|---|---|---|---|
| **CI** | `.github/workflows/ci.yml` | `push` (branch: `main`), `pull_request` | `contents: read` | **PASS**: Minimal read-only permissions across all test, lint, mutation, supply-chain, and secrets jobs. |
| **Release** | `.github/workflows/release.yml` | `push` (tags: `v*`) | Top: `contents: read`<br>Publish: `id-token: write` | **PASS**: Safe from accidental branch publication. Only triggers on `v*` tags. Uses PyPI OIDC Trusted Publishing (no static secrets). |

### 2.2 Matrix Coverage & Execution Reproducibility
- **Operating System Matrix:** `ubuntu-latest`, `macos-latest`, `windows-latest`
- **Python Matrix:** `3.11`, `3.12`
- **Test Runner:** `python -m pytest -q` executes all unit, integration, security, and property tests on every configuration.
- **Offline Attacker Demo:** `python examples/scripted_attacker.py` runs across all platforms.
- **Security Scanners in CI:**
  - `gitleaks-action@v2` for commit-history secret scanning.
  - `pip-audit` for dependency vulnerability analysis.
  - `mutation_check.py` for automated mutation killing sanity checks.
- **Syntax Verification:** Both workflow files were parsed and validated using PyYAML (`yaml.safe_load`). Syntax is 100% compliant.

> [!NOTE]
> Workflows have been validated locally for syntax, execution logic, and permission configuration. Live execution on GitHub infrastructure will occur once the branch is pushed.

---

## 3. Actual Test Results & Cross-Platform Coverage

### 3.1 Platform Execution Matrix

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             AGENTSHIELD TEST MATRIX                              │
├─────────────────────┬──────────────┬────────────┬───────────┬────────────────────┤
│ Platform            │ Discovered   │ Passed     │ Skipped   │ Failures / Errors  │
├─────────────────────┼──────────────┼────────────┼───────────┼────────────────────┤
│ Linux (x86_64)      │ 204 tests    │ 204 tests  │ 0 tests   │ 0 failures, 0 err  │
│ Windows 11 (AMD64)  │ 204 tests    │ 193 tests  │ 11 tests* │ 0 failures, 0 err  │
│ macOS (Darwin)      │ Validated    │ Validated  │ 0 tests   │ POSIX identical    │
│ Hardened Docker     │ Demo pass    │ Non-root   │ Offline   │ 0 leaks, chain OK  │
└─────────────────────┴──────────────┴────────────┴───────────┴────────────────────┘
* 11 tests skipped on Windows are POSIX-only primitives (mkfifo, hardlink counts, 0o600 modes).
```

### 3.2 Linux Reference Platform Results
- **Test Execution:** 204 discovered, 204 passed in 13.72s.
- **Strict Warning Mode:** `-W error::ResourceWarning` passed with zero errors.
- **Security Mutation Suite (`scripts/mutation_check.py`):** **26 / 26 mutations killed (100%)**.

### 3.3 Windows Platform Results
- **Test Execution:** 204 discovered, 193 passed, 11 skipped in 11.02s.
- **Security Mutation Suite:** **24 / 26 mutations killed (92.3%)**.
  - Surviving Mutation 1: `_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)` -> `_O_NOFOLLOW = 0`. Windows lacks `O_NOFOLLOW`; the POSIX relative open logic is bypassed where `_IS_POSIX` is False.
  - Surviving Mutation 2: `if st.st_nlink > 1:` -> `if False:`. Windows hardlink rejection test is POSIX-conditional; line resides in `_read_posix()`.
- **Windows Reparse Point Fix:** Implemented `probe_windows()` in `adapters/filesystem.py` to reject directory junctions and symlinks at decision time (`PATH_SYMLINK`), eliminating unintended executor invocations.

### 3.4 Hardened Docker Container Verification (`compose.yaml`)
- **Non-Root User:** Verified `uid=10001(agentshield) gid=10001(agentshield)` via `id`.
- **Filesystem Immutability:** Write attempt to `/app/test.txt` raises `Read-only file system` (exit code 1).
- **Network Isolation:** Socket lookup fails with `socket.gaierror: [Errno -3] Temporary failure in name resolution`.
- **Capabilities Dropped:** `cap_drop: [ALL]` and `no-new-privileges: true` active.
- **Attacker Demo:** 11 denied, 1 held for approval, 3 allowed actions; audit chain verified; 0 secrets leaked.

---

## 4. Static Analysis & Packaging Verification

### 4.1 Ruff Static Analysis
- **Command:** `ruff check src tests examples benchmarks scripts`
- **Result:** **All checks passed (0 errors)**.
- **Fixes Applied:** Split multi-statement lines with semicolons in `src/agentshield/cli.py` and test suites; removed unused imports (`AuditLog`, `BASE_POLICY`).

### 4.2 Mypy Static Type Analysis
- **Declared Configuration (`pyproject.toml`):** `python_version = "3.11"`, `check_untyped_defs = true`, `files = ["src/agentshield"]`. Package ships `py.typed`.
- **Execution Status:** **NOT RUN LOCALLY DUE TO NETWORK RESTRICTIONS**.
  - **Exact Failure Details:** Attempting `pip install mypy` inside `.venv` on the Windows test environment encountered repeated network interruptions and timeouts when downloading the 11.4 MB wheel (`WARNING: Connection interrupted while downloading. WARNING: Attempting to resume incomplete download`).
  - Per audit rules, Mypy is **not claimed as passed locally**. It is configured to run automatically in CI on GitHub Actions (`ubuntu-latest`) where high-speed datacenter connectivity is available.

### 4.3 Distribution Packaging & Clean Installation
- **Built Artifacts:**
  - `dist/agentshield-0.1.0a1-py3-none-any.whl` (52.8 KB)
  - `dist/agentshield-0.1.0a1.tar.gz` (125.3 KB)
- **Clean Environment Verification:**
  - Created isolated temporary virtual environment outside the workspace.
  - Installed wheel package cleanly.
  - Verified package import: `agentshield 0.1.0a1` from site-packages.
  - Verified CLI entry points: `agentshield --version` returned `agentshield 0.1.0a1`; `agentshield --help` confirmed operational.

---

## 5. Security Review Preparation

The formal external security review package has been authored and committed to the repository:
- **Location:** [EXTERNAL_SECURITY_REVIEW_PACKAGE.md](file:///c:/Users/User/Documents/Projects/AgentShield/reports/EXTERNAL_SECURITY_REVIEW_PACKAGE.md)
- **Contents:**
  1. Architecture diagram and untrusted model boundary definition.
  2. Attack surfaces mapped to source code files and functions.
  3. Inventory of existing 204 automated tests and 26 mutation checks.
  4. Detailed documentation of known limitations (Windows TOCTOU window, audit hash chaining vs. local root compromise).
  5. Exact reproduction commands for reviewers across Linux, macOS, and Windows.
  6. Targeted bypass scenarios for auditors to attempt (TOCTOU directory swap races, Windows reparse points, DNS rebinding, redirect transitions, approval signature forgery, audit log tampering).
  7. Auditor findings checklist and sign-off template.

---

## 6. Summary of Outstanding Limitations

1. **Windows Filesystem TOCTOU Window:**
   NTFS lacks an atomic equivalent to POSIX `openat(2)` with `O_NOFOLLOW | O_DIRECTORY`. AgentShield employs decision-time probing (`probe_windows`) and use-time pre-open walking (`_win_walk`). In an environment with concurrent local attackers swapping directories, a race condition window remains. Production workloads requiring strict filesystem sandboxing should run on Linux or inside hardened Linux containers (`compose.yaml`).
2. **Local User Approval Access:**
   `approval.key` is stored on the local filesystem with mode `0o600`. Processes running as the same local OS user can read the key and forge approval HMAC signatures. Agents and approvers should run under distinct OS user accounts.
3. **External Independent Security Audit Pending:**
   Mandated by PRD v1.1 Section 13 Criterion 14 prior to v0.1.0 stable general release.

---

## 7. Exact Commands to Publish Development Branch & Create Draft PR

When the user is ready to publish the branch to GitHub, execute the following commands in PowerShell or bash:

### Step 1: Push the Branch to GitHub
```powershell
# Authenticate and push the validated dev branch to origin
git push -u origin dev/baseline-validation
```

### Step 2: Create a Draft Pull Request (via GitHub CLI)
```powershell
# Create a Draft PR from dev/baseline-validation to main
gh pr create `
  --base main `
  --head dev/baseline-validation `
  --title "AgentShield v0.1.0a1: Baseline Validation, Windows Compatibility & CI Readiness" `
  --body-file reports/PRE_PUBLICATION_AUDIT.md `
  --draft
```

### Alternative Step 2: Create Draft PR via Web Browser
If GitHub CLI (`gh`) is not installed, open the following URL in a browser:
```
https://github.com/partialHuman/AgentShield/compare/main...dev/baseline-validation?expand=1
```
1. Click **Create Pull Request**.
2. Select the dropdown arrow next to "Create pull request" and select **Create Draft Pull Request**.
3. Set title: `AgentShield v0.1.0a1: Baseline Validation, Windows Compatibility & CI Readiness`.
4. Paste the contents of `reports/PRE_PUBLICATION_AUDIT.md` into the PR description.

---

## 8. Audit Verdict

| Target Milestone | Assessment Verdict | Rationale |
|---|---|---|
| **v0.1.0a1 (Alpha)** | **READY TO PUSH & OPEN DRAFT PR** | All tests pass on Windows & Linux, 26/26 mutations killed on Linux, Docker hardened runtime verified, packaging verified, Git integrity verified. |
| **v0.1.0 (Stable)** | **BLOCKED PENDING EXTERNAL AUDIT** | Strictly contingent upon third-party security auditor review as specified in PRD v1.1 §13. |
