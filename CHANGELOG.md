# Changelog

All notable changes are documented here. Versioning follows [SemVer](https://semver.org/); 0.x releases may change
interfaces. Policy files and audit events carry their own schema versions.

## 0.1.0a1 — 2026-11-04 (alpha / preview)

First public preview. **Not independently reviewed.** See `docs/threat-model.md` for guarantees and limitations.

### Added
- In-process enforcement: `Shield.wrap` / `Shield.call` (sync and async), default-deny policy evaluation, executor captured privately and invoked only after `ALLOW`.
- Strict YAML policy loader with structured constraints, JSON Schema (`agentshield schema`), policy hash.
- Built-in tools: `calculator` (AST whitelist), `filesystem.read` / `filesystem.write` (no-follow, fd-relative on POSIX), `http.fetch` (DNS pinning, per-hop redirect revalidation, bounded responses).
- Human approvals: CLI-only, SQLite-backed, bound to action hash + policy hash + agent, single-use, expiring, HMAC-authenticated.
- Hash-chained JSONL audit log with `.head` sidecar, decision-before-dispatch ordering, allow-list redaction, `audit verify`.
- CLI: `lint`, `evaluate`, `explain`, `approvals list|show|approve|reject`, `audit verify`, `schema`.
- Offline scripted-attacker demo, provider-style agent loop, quickstart, Dockerfile/compose, CI, benchmarks, 73 documented attack scenarios.

### Not included (deferred)
FastAPI service, shell adapter, web UI, metrics endpoint, per-agent policies, LangChain/MCP adapters.
