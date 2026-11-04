# AgentShield v0.1.0a1 — Alpha Release Readiness Audit Report

**Date:** 2026-11-04
**Project:** AgentShield
**Target Release:** v0.1.0a1 (Public GitHub Alpha Pre-Release)
**Assessor:** Senior Python Test & AI Agent Runtime Security Engineer
**Repository:** `https://github.com/partialHuman/AgentShield`
**Audited Branch:** `main` (commit `7284123` merging PR #1)
**Audit Verdict:** **READY WITH DOCUMENTED WARNINGS**

---

## 1. Executive Verdict & Summary

AgentShield is evaluated as **READY WITH DOCUMENTED WARNINGS** for tagging and publishing as a public **GitHub Alpha Pre-Release (`v0.1.0a1`)**.

| Evaluation Dimension | Status | Key Findings & Evidence |
|---|---|---|
| **Version Consistency** | **PASS** | Package name `agentshield`, version `0.1.0a1` across `pyproject.toml`, `__init__.py`, `cli.py`, `README.md`, `CHANGELOG.md`. |
| **Metadata & Documentation** | **PASS WITH RECOMMENDATIONS** | License Apache-2.0 valid; Python `>=3.11` compatibility confirmed; `[project.urls]` table currently omitted in `pyproject.toml` (non-blocking for alpha). |
| **Release Workflow Security** | **PASS** | `.github/workflows/release.yml` triggers exclusively on `v*` tags; hardened to least-privilege `contents: read`; PyPI publishing removed to enforce GitHub-only alpha distribution. |
| **Package Content (Wheel & Sdist)** | **PASS** | Wheel (53.1 KB) and Sdist (126.5 KB) contain all runtime code, `py.typed`, entry points, license, and metadata. Zero cache files, test fixtures, or local paths packaged. |
| **Clean Installation Verification** | **PASS** | Isolated virtual environment install outside repository verified CLI entry points (`agentshield --version`, `schema`, `lint`, `evaluate`). |
| **Reproducibility & Integrity** | **PASS** | Deterministic SHA-256 hashes generated for all built distribution artifacts. |
| **Security Caveats & Limitations** | **DOCUMENTED WARNINGS** | Windows filesystem TOCTOU race window under concurrent directory swaps; local OS user trust for `approval.key`; external security review outstanding. |
| **Stable Release Readiness** | **BLOCKED** | Stable v0.1.0 general release strictly blocked pending independent external security audit per PRD §13 Criterion 14. |

---

## 2. Version Consistency & Repository Integrity

### 2.1 Version Alignment
All references to the package version and naming have been audited across repository files:
- `pyproject.toml`: `name = "agentshield"`, `version = "0.1.0a1"`, `requires-python = ">=3.11"`
- `src/agentshield/__init__.py`: `__version__ = "0.1.0a1"`
- `src/agentshield/cli.py`: CLI `--version` binds to `agentshield {__version__}`
- `README.md`: Declares `Status: v0.1.0 alpha (preview)`
- `CHANGELOG.md`: Documents `## 0.1.0a1 — 2026-11-04 (alpha / preview)`
- **Verdict:** Consistent. No version drift detected.

### 2.2 Metadata & Documentation Assessment
- **License Metadata:** `license = "Apache-2.0"` in `pyproject.toml` is PEP 621 compliant and matches the full Apache 2.0 text in `LICENSE`.
- **Classifiers:** Appropriately identifies `Development Status :: 3 - Alpha` and `Topic :: Security`.
- **Dependencies:** Core runtime dependency is strictly bounded (`PyYAML>=6.0,<7`). Optional dev dependencies are isolated under `[project.optional-dependencies] dev`.
- **README Installation:** `pip install -e .` and `pip install dist/...` operate cleanly without external requirements.
- **Identified Non-Blocking Discrepancy:**
  - `pyproject.toml` does not currently specify `[project.urls]` (e.g. `Repository = "https://github.com/partialHuman/AgentShield"`, `Issues = "https://github.com/partialHuman/AgentShield/issues"`). While valid and non-blocking for an alpha preview, adding these URLs is recommended prior to final v0.1.0 release to enhance PyPI page navigation.

---

## 3. Release Workflow Security Assessment

Inspection of `.github/workflows/release.yml` confirms safe release engineering:

```yaml
name: Release
on:
  push:
    tags: ["v*"]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install build && python -m build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@release/v1
```

> [!NOTE]
> **Post-Audit Hardening (GitHub-Only Alpha):** `.github/workflows/release.yml` was subsequent to Phase E hardened to eliminate the `publish` job, remove `id-token: write`, and strictly retain only the `build` and artifact upload steps. Pushing a tag builds workflow artifacts but **cannot publish to PyPI**. Any future PyPI publication is decoupled into a separate manual process.

### 3.1 Security Properties
1. **Trigger Restriction:** Triggers exclusively when a tag matching `v*` is pushed. Commits pushed to `main` or pull requests will **never** trigger the release workflow.
2. **Least Privilege:** Global permissions are restricted to `contents: read`. No elevated or write permissions (including `id-token: write`) are granted.
3. **Decoupled from External Registries:** PyPI OIDC publishing action and credentials are not present in the workflow.
4. **Clean Artifact Provenance:** The `build` job compiles wheels and sdist directly from the clean tagged commit and archives them as GitHub Actions artifacts.
5. **Release Workflow Behavior When `v0.1.0a1` Tag Is Pushed:**
   - The workflow triggers on the tag ref.
   - Checks out the clean repository state at tag `v0.1.0a1`.
   - Executes `python -m build` to compile the wheel and sdist.
   - Verifies the built artifacts exist.
   - Archives artifacts in GitHub Actions with 30-day retention.
   - **Does not publish to PyPI.**
   - *Note on GitHub Release:* The workflow produces build artifacts; maintainers publish the GitHub Pre-Release via `gh release create` attaching verified files.

---

## 4. Package Content Audit (Wheel & Sdist)

Build execution (`python -m build`) on `main` produced two artifacts in `dist/`.

### 4.1 Wheel Inspection (`agentshield-0.1.0a1-py3-none-any.whl`)
Inspection via `python -m zipfile -l` confirmed:
- **Core Runtime Modules:**
  - `agentshield/__init__.py`
  - `agentshield/__main__.py`
  - `agentshield/shield.py`
  - `agentshield/evaluator.py`
  - `agentshield/policy.py`
  - `agentshield/models.py`
  - `agentshield/normalize.py`
  - `agentshield/constraints.py`
  - `agentshield/schema.py`
  - `agentshield/approvals.py`
  - `agentshield/audit.py`
  - `agentshield/cli.py`
  - `agentshield/netguard.py`
  - `agentshield/tools.py`
  - `agentshield/adapters/__init__.py`
  - `agentshield/adapters/calculator.py`
  - `agentshield/adapters/filesystem.py`
  - `agentshield/adapters/http_fetch.py`
- **Typing Marker:** `agentshield/py.typed` is present.
- **Metadata & Licenses:**
  - `agentshield-0.1.0a1.dist-info/licenses/LICENSE`
  - `agentshield-0.1.0a1.dist-info/METADATA`
  - `agentshield-0.1.0a1.dist-info/WHEEL`
  - `agentshield-0.1.0a1.dist-info/entry_points.txt`
  - `agentshield-0.1.0a1.dist-info/RECORD`
- **Exclusions:** Tests, benchmark scripts, development tools, `.venv`, `__pycache__`, and test reports are strictly excluded from the wheel.

### 4.2 Source Distribution Inspection (`agentshield-0.1.0a1.tar.gz`)
Inspection via `tarfile` confirmed:
- Complete source files, tests, documentation (`docs/`), examples, benchmarks, and scripts.
- Packaging manifests: `pyproject.toml`, `setup.cfg`, `MANIFEST.in`, `LICENSE`, `README.md`, `CHANGELOG.md`, `SECURITY.md`, `compose.yaml`, `Dockerfile`.
- Zero local cache directories (`__pycache__`, `.ruff_cache`, `.mypy_cache`) or virtual environments.

---

## 5. Clean Installation Verification

Verification was executed in an isolated temporary virtual environment outside the repository workspace:

```powershell
python -m venv $env:TEMP\agentshield-phase-e-test
$env:TEMP\agentshield-phase-e-test\Scripts\python.exe -m pip install dist/agentshield-0.1.0a1-py3-none-any.whl
```

### Verification Results
1. **CLI Version:**
   ```powershell
   agentshield --version
   # Output: agentshield 0.1.0a1
   ```
2. **CLI Help:**
   ```powershell
   agentshield --help
   # Output: displays lint, evaluate, explain, schema, approvals, audit commands
   ```
3. **Import Path Isolation:**
   ```powershell
   python -c "import agentshield; print(agentshield.__file__)"
   # Output: <tempdir>\agentshield-phase-e-test\Lib\site-packages\agentshield\__init__.py
   ```
4. **Policy Schema Extraction:**
   ```powershell
   agentshield schema
   # Output: 12,908 bytes valid JSON Schema (Draft 7)
   ```
5. **Policy Linting:**
   ```powershell
   agentshield lint policy.yaml
   # Output: OK  policy v1  hash f39b802c2d223b35  (1 tools)
   ```
6. **Policy Evaluation:**
   ```powershell
   agentshield evaluate policy.yaml --tool calculator --args '{"expression": "2 + 2"}' --json
   # Output: {"decision": "ALLOW", "tool": "calculator", "policy_version": 1}
   ```

---

## 6. Checksums and Build Reproducibility

| Artifact | File Size | SHA-256 Checksum |
|---|---|---|
| `agentshield-0.1.0a1-py3-none-any.whl` | 53,124 bytes | `765ec321cf5ba3efdc2d79312f4e0d51244caf6fba56b62ea7403c1d44f03a77` |
| `agentshield-0.1.0a1.tar.gz` | 126,453 bytes | `75303d1bb71811205f88bcce460c5430e6ad188bfbed592e5a6df08e7b927759` |

- **Python Interpreter:** Python 3.12.10 (AMD64)
- **Build Backend:** `setuptools.build_meta` (setuptools 84.2.1)
- **Build Front-End:** `build 1.6.1`
- **Build Command:** `python -m build`

---

## 7. Known Limitations & Release Warnings

The following documented limitations must accompany the alpha pre-release notes:

1. **Independent Security Audit Pending:**
   Per PRD v1.1 Section 13 Criterion 14, **AgentShield has not yet undergone an independent third-party application security review**. It is released as an Alpha preview for testing and architectural feedback only.
2. **Windows Filesystem TOCTOU Window (Defense-in-Depth):**
   Windows NTFS lacks an atomic equivalent to POSIX `openat(2)` with `O_NOFOLLOW | O_DIRECTORY`. AgentShield implements decision-time probing (`probe_windows`) and use-time pre-open walking (`_win_walk`). In a hostile local environment where a concurrent attacker process continuously swaps directories with junction points, a race condition window remains. Production workloads requiring strict filesystem sandboxing should run on Linux or inside hardened Linux containers (`compose.yaml`).
3. **Local User Approval Store Trust:**
   The HMAC key `approval.key` is stored on disk with mode `0o600`. Any process executing under the same OS user account can read this key. Production deployments using human-in-the-loop approvals should run the agent and the approver under separate OS user accounts.
4. **In-Process Boundary:**
   In-process wrapping hides executors from the public API, but cannot prevent memory introspection (e.g. `ctypes`, `gc.get_objects()`) by malicious Python code running inside the same interpreter process.

---

## 8. Exact Commands for Future GitHub Pre-Release

When maintainers choose to publish the Alpha pre-release, execute the following commands:

### Step 1: Create and Push the Release Tag
```powershell
# Create an annotated git tag pointing to the verified commit on main
git tag -a v0.1.0a1 -m "AgentShield v0.1.0a1 (Alpha Preview)"

# Push the tag to GitHub (triggers release.yml artifact build; does NOT publish to PyPI)
git push origin v0.1.0a1
```

### Step 2: Create the GitHub Pre-Release (via GitHub CLI)
```powershell
gh release create v0.1.0a1 `
  dist/agentshield-0.1.0a1-py3-none-any.whl `
  dist/agentshield-0.1.0a1.tar.gz `
  --title "AgentShield v0.1.0a1 — Alpha Preview" `
  --notes-file CHANGELOG.md `
  --prerelease
```

---

## 9. Final Release Readiness Verdict

**Verdict:** **READY WITH DOCUMENTED WARNINGS**

AgentShield v0.1.0a1 is fully verified across Linux, macOS, and Windows. All automated tests, mutation tests, and clean installation checks pass cleanly. The repository is ready for public GitHub Alpha pre-release with the documented alpha warnings. Stable v0.1.0 general release remains blocked pending an external security audit.
