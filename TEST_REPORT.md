# AgentShield v0.1.0a1: test report

Date: 2026-11-04 · Environment: Linux x86-64 (Intel Xeon @ 2.10 GHz, 1 vCPU), **Python 3.12.3**, PyYAML 6.0.3 · no network.

## Result

| Check | Command | Result |
|---|---|---|
| Full suite from source | `python -m unittest discover -s tests -t .` (also with `-W error::ResourceWarning`) | **199 tests, 0 failures** (≈6 s) |
| Full suite against the **installed wheel** (fresh venv, no `src/` on the path) | same, `PYTHONPATH=.` | **199 tests, 0 failures** |
| Mutation check | `python scripts/mutation_check.py` | **26 / 26** deliberate security bugs caught |
| Offline demo (installed package) | `python examples/scripted_attacker.py` | `RESULT: PASS` (11 denied, 1 held, 3 legitimate executions, audit chain OK) |
| Build | wheel + sdist via setuptools | built; wheel imports with `-W error` |
| Benchmarks | `python benchmarks/run.py` | policy-evaluation p95 0.02–0.09 ms (target < 10 ms) |

Test breakdown (199): **103 unit** (policy 18, audit 16, netguard 14, approvals 13, normalize 13, CLI 12, path logic 7, calculator 5, schema 4, perf guard 1) · **82 integration** (Shield flow 40, HTTP adapter 22 incl. real TLS, filesystem adapter 17, demo + quickstart 3) · **6 corpus runners** (**73 attack scenarios**, **56 benign actions → 0 false blocks**) · **8 seeded property/fuzz tests**.

## What the tests prove (and how)

- **Denied/pending ⇒ executor never ran.** Executor spies on every deny path; a 2,500-case seeded property test (random tool names, types, nasty strings, nested/huge values) asserts `executed ⇔ evaluate said ALLOW`; the 73-scenario corpus asserts zero executor invocations and no changes outside the workspace; the HTTP corpus uses a connector that fails the test if any connection is attempted.
- **Symlink races.** A thread swaps a directory ↔ symlink to an outside location while reads run. Control: a naive check-then-open implementation leaks (6 / 20,000 attempts); this implementation: 0 leaks across ~19,500 reads, ~11,800 of them caught mid-swap and blocked.
- **SSRF.** DNS rebinding simulated (decision-time public answer, use-time loopback answer → blocked before connecting); mixed public/private answers; redirects to disallowed port/host/scheme/metadata; numeric-IP, IPv4-mapped, NAT64, 6to4, Teredo forms; real TLS handshake verifying the certificate against the *original* hostname while connecting to the pinned IP.
- **Approvals.** Bound to action/policy/agent; expiry; single-use under 10 concurrent re-submissions (runs once); forged and transplanted MACs rejected.
- **Audit.** Edit, edit-with-recomputed-hash, deletion, insertion, reorder, tail truncation, wipe, external anchor; two writers and 6 threads keep one valid chain; secrets (file content, URL credentials/queries) never appear.
- **Mutation check** breaks the code in 26 security-critical ways (e.g. DENY not blocking, removing `O_NOFOLLOW`, skipping use-time DNS revalidation, accepting reused approvals, logging query strings) and requires the suite to fail each time.

## Real defects the tests found while building (all fixed)

1. Calculator returned a **complex number** for `(-8) ** 0.5`.
2. IPv6 **zone identifiers** inside brackets were not rejected (`[fe80::1%25eth0]`).
3. URL redaction fallback logged **credentials** for URLs with userinfo (`http://admin:hunter2@…`).
4. The audit event's `target` field logged the **full URL including the query string** (the summary was redacted, the target was not).
5. A non-hashable tool name (e.g. a dict from a malicious model) raised `TypeError` **before it could be audited**.
6. `http.client` closes the socket for `Connection: close` responses, which broke per-read deadline updates (the fetch failed; fixed by using the live socket).
7. Call-limit logic had a redundant non-atomic check that hid the atomic one from the tests (simplified; mutation now killed).
8. Policy loader raised `RecursionError` / `UnicodeDecodeError` for pathological files instead of `PolicyError`.

## PRD v1.1 acceptance criteria (Section 13)

| Criterion | Status |
|---|---|
| Clean checkout installs and runs with documented instructions | ✅ built wheel installed into a fresh venv; tests + demo run. *(Not tested: installing from PyPI. It isn't published.)* |
| Reference demo: protected utility, read/write only in allowed dir, fetch only approved destinations | ✅ Real fetches are covered by integration tests (local server + TLS); the offline demo shows the fetch *decisions* without touching the network |
| Unknown tools, invalid args, disallowed paths/destinations, policy errors denied before execution | ✅ |
| Executors instrumented: denied/pending ⇒ zero calls | ✅ |
| Approvals: not before approval; not after expiry, replay, or arg/target/policy change | ✅ |
| Structured event per decision, stable reason codes, redacted args | ✅ |
| Sync and async tools protected and tested | ✅ |
| Wrapper exposes no executor handle via the public API | ✅ *(Python introspection can still reach it; documented, as the PRD anticipates)* |
| Audit chain verifies; verify detects tampered or truncated log | ✅ |
| Policy files schema-validated, safe example defaults | ✅ validator + generated JSON Schema (kept in sync by a test); the schema is published, **not** enforced by a JSON-Schema library at runtime |
| Docker demo runs non-root, no privileged mode | ⚠️ `Dockerfile`/`compose.yaml` written (UID 10001, read-only fs, `cap_drop: ALL`, no network) but **not built or run: no Docker in the sandbox** |
| CI runs lint, type checks, unit, integration, security regression tests | ⚠️ workflows written (Linux/macOS/Windows × 3.11/3.12, lint, mutation, pip-audit, gitleaks) but **not executed**; `ruff`/`mypy` were not available, so style/type cleanliness is unverified |
| **≥ 2 independent reviewers attempted to bypass the file and HTTP adapters** | ❌ **NOT DONE: cannot be done by the author.** This is the gating item before tagging a non-alpha `0.1.0` / `1.0` |
| README has architecture, threat model, quickstart, sample policies, terminal output, limitations, disclosure guidance | ✅ |
| Released as v0.1.0 alpha with CHANGELOG, SECURITY.md, README limitations | ✅ artifacts prepared (`0.1.0a1`); nothing has been published |

## Deviations from the PRD, and things I could not verify

- **Test tooling:** `pytest`, Hypothesis, ruff, mypy and pip-audit were not installable offline. Tests use stdlib `unittest` (pytest collects them as-is); the property tests are hand-rolled, seeded and stdlib-only rather than Hypothesis. Add Hypothesis tests in CI if you want shrinking.
- **API shape:** `Shield(policy, agent_id=…)` then `shield.wrap(tool)` (the PRD sketched `wrap(tool, policy)`); name-based dispatch added as `shield.call(name, args)`.
- **Approval resume model:** after approval the application re-submits the identical call, which executes exactly once (no arguments are stored for replay).
- **Not run here:** Windows, macOS, Python 3.11 (CI matrix), the Docker image, the optional live-model adapter (`examples/agent_loop.py`, `--live` path), real internet/DNS fetches, PyPI publishing.
- **Windows** file protection is best-effort by design and only its pure path-rule helpers were exercised on Linux.
- v0.1 is an **alpha with no independent review**; the mutation check and attack corpus are self-authored and can't find blind spots the author shares.

## Reproduce

```bash
pip install -e ".[dev]"            # or: PYTHONPATH=src:. python -m unittest discover -s tests -t .
python -m pytest -q
python scripts/mutation_check.py
python examples/scripted_attacker.py
python benchmarks/run.py --write docs/benchmarks.md
```
