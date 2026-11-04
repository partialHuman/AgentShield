# AgentShield v0.1.0a1 — Final Release Checklist & Sign-Off Guide

**Release Target:** `v0.1.0a1` (Alpha Preview)
**Date:** 2026-11-04
**Target Commit:** `7284123` (on branch `main`)
**Repository:** `https://github.com/partialHuman/AgentShield`
**Purpose:** Pre-publication sign-off checklist and release authorization matrix.

---

## 1. Release Readiness Checklist

| Category | Verification Item | Status | Verification Evidence / Location |
|---|---|---|---|
| **Git Integrity** | `main` branch synchronized with `origin/main` | **VERIFIED** | `git rev-parse HEAD` = `728412300b95763ca7766b26d8ee1c3e3725fe05` matching `origin/main`. |
| **Git Integrity** | Clean working tree; no tracked scratch/temp files | **VERIFIED** | Working tree clean. `scratch/` confirmed outside repository in local appdata. |
| **Git Integrity** | No prior tag `v0.1.0a1` exists locally or remotely | **VERIFIED** | `git tag -l` and `git ls-remote --tags origin` confirm 0 conflicting tags. |
| **Version Alignment** | Package version consistently declared | **VERIFIED** | `0.1.0a1` in `pyproject.toml`, `src/agentshield/__init__.py`, `cli.py`, `README.md`, `CHANGELOG.md`. |
| **CI Validation** | GitHub Actions 6-runner test matrix | **VERIFIED** | Passed: Ubuntu 3.11 & 3.12, macOS 3.11 & 3.12, Windows 3.11 & 3.12. |
| **CI Validation** | CI Security & Sanity Scanners | **VERIFIED** | Passed: `mutation-sanity` (26/26 killed), `supply-chain` (`pip-audit`), `secrets` (`gitleaks`). |
| **CI Validation** | Static Analysis / Linting | **VERIFIED** | Passed: `ruff check` (0 errors), Mypy static analysis resolved in commit `2aa0b9e`. |
| **Artifact Build** | Python wheel built from `main` | **VERIFIED** | `dist/agentshield-0.1.0a1-py3-none-any.whl` (53,124 bytes). SHA-256 confirmed. |
| **Artifact Build** | Source distribution built from `main` | **VERIFIED** | `dist/agentshield-0.1.0a1.tar.gz` (126,453 bytes). SHA-256 confirmed. |
| **Clean Install** | Isolated venv installation & CLI verification | **VERIFIED** | Wheel installed in clean temp venv; `agentshield --version`, `schema`, `lint`, `evaluate` all passed. |
| **Documentation** | Dedicated alpha release notes prepared | **VERIFIED** | Authored in `reports/RELEASE_NOTES_v0.1.0a1.md`. |
| **Documentation** | Audit reports prepared | **VERIFIED** | `reports/ALPHA_RELEASE_AUDIT.md`, `reports/PRE_PUBLICATION_AUDIT.md`, `reports/EXTERNAL_SECURITY_REVIEW_PACKAGE.md`. |
| **Security Caveats** | Threat model & limitations documented | **VERIFIED** | Windows TOCTOU limitations and local user approval trust boundaries clearly stated in notes. |
| **Security Audit** | Independent security audit status noted | **VERIFIED** | Explicitly marked as **NOT PERFORMED**. Stable v0.1.0 release remains blocked. |

---

## 2. Release Workflow Architecture & Behavior (Hardened GitHub-Only)

Inspection of `.github/workflows/release.yml` confirms the hardened GitHub-only release workflow:

```
                  ┌──────────────────────────────────────────────┐
                  │ Maintainer Pushes Git Tag: `git push v0.1.0a1│
                  └──────────────────────┬───────────────────────┘
                                         │ triggers on: push: tags: ["v*"]
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ GitHub Actions: Release Workflow             │
                  │ Permissions: contents: read                  │
                  │                                              │
                  │ `build` Job:                                 │
                  │  - Checks out tagged commit (`v*`)           │
                  │  - Sets up Python 3.12                       │
                  │  - Installs `build` & runs `python -m build` │
                  │  - Verifies presence of wheel & sdist files  │
                  │  - Uploads `dist/` artifacts (30d retention) │
                  │                                              │
                  │ [NO PUBLISH JOB / NO PYPI OIDC INTEGRATION]  │
                  └──────────────────────────────────────────────┘
```

### Key Operational Guarantees:
1. **Zero PyPI Publishing Capability:** Pushing a version tag **CANNOT publish anything to PyPI**. The `publish` job, `pypa/gh-action-pypi-publish` action, and `id-token: write` permission have been entirely removed.
2. **GitHub Actions Artifact Storage:** Build artifacts (wheel and source distribution) are preserved as downloadable GitHub Actions workflow artifacts with a 30-day retention window.
3. **GitHub Pre-Release Creation is Explicit & Controlled:** Maintainers create and publish the GitHub Release via the GitHub CLI (`gh release create`) or Web UI, attaching verified local artifacts or downloaded workflow artifacts.
4. **Future PyPI Publication:** Any future distribution to PyPI is strictly decoupled and will require an explicit, manually triggered workflow or maintainer action with separate authorization.

---

## 3. GitHub-Only Alpha Pre-Release Procedure

The release procedure for `v0.1.0a1` is GitHub-only:

1. **Create and push the release tag (maintainer command):**
   ```powershell
   git tag -a v0.1.0a1 -m "AgentShield v0.1.0a1 (Alpha Preview)"
   git push origin v0.1.0a1
   ```
2. **Workflow Execution:**
   - GitHub Actions executes the `build` job.
   - Wheel and source distribution are compiled and verified in the CI runner.
   - Artifacts are saved to the workflow run as `dist`.
   - **No network calls to PyPI are made.**
3. **Publish the GitHub Pre-Release with attached assets (maintainer command):**
   ```powershell
   gh release create v0.1.0a1 `
     dist/agentshield-0.1.0a1-py3-none-any.whl `
     dist/agentshield-0.1.0a1.tar.gz `
     --title "AgentShield v0.1.0a1 — Alpha Preview" `
     --notes-file reports/RELEASE_NOTES_v0.1.0a1.md `
     --prerelease
   ```

---

## 4. Distinction: Ready Status vs. Required Explicit Authorization

| Item / Action | Current Status | Requires Authorization? |
|---|---|---|
| **Codebase & Tests (`main`)** | **100% READY** | Automated verification complete; no further code changes required. |
| **Packaging Artifacts (`dist/`)** | **100% READY** | Wheel and Sdist built and verified; SHA-256 hashes matched. |
| **Release Workflow Hardening** | **100% READY** | GitHub-only: PyPI publishing job and OIDC token permissions removed. |
| **Release Documentation** | **100% READY** | Release notes, threat model, audit reports complete. |
| **Creating Git Tag `v0.1.0a1`** | **PENDING AUTHORIZATION** | **REQUIRES MAINTAINER COMMAND**: `git tag -a v0.1.0a1` |
| **Pushing Tag to GitHub** | **PENDING AUTHORIZATION** | **REQUIRES MAINTAINER COMMAND**: `git push origin v0.1.0a1` |
| **Publishing GitHub Release** | **PENDING AUTHORIZATION** | **REQUIRES MAINTAINER COMMAND**: `gh release create v0.1.0a1 --prerelease` |
| **Publishing to PyPI** | **DISABLED / DECOUPLED** | **NOT CONFIGURED IN WORKFLOW**: Zero automated PyPI path exists. |
| **Stable v0.1.0 Release** | **BLOCKED** | **BLOCKED**: Requires independent external security audit. |

---

## 5. Artifact Verification Checksums

```
agentshield-0.1.0a1-py3-none-any.whl
Size:   53,124 bytes
SHA256: 765ec321cf5ba3efdc2d79312f4e0d51244caf6fba56b62ea7403c1d44f03a77

agentshield-0.1.0a1.tar.gz
Size:   126,453 bytes
SHA256: 75303d1bb71811205f88bcce460c5430e6ad188bfbed592e5a6df08e7b927759
```
