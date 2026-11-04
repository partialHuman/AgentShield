# Security policy

AgentShield is a security tool; we take bypasses seriously. v0.1 is an **alpha without independent review**: please
read `docs/threat-model.md` first, and do not treat it as your only control.

## Reporting a vulnerability

Please **do not open a public issue** for a suspected bypass. Use the repository's *private vulnerability reporting*
(Security tab → "Report a vulnerability") or contact the maintainers privately. Include:

- the policy and tool configuration, the exact action/arguments, and the expected vs. actual decision
- the Python version and operating system
- a failing test if you can write one (see `tests/security/corpus.py`)

We aim to acknowledge reports within 5 working days and to credit reporters who want credit. These targets are intentions, not guarantees.

## What counts as a vulnerability

- Any way for a `DENY` / pending-approval / unregistered action to reach an executor
- File access outside the configured roots, symlink/hard-link/race escapes (POSIX)
- SSRF: reaching a destination the policy forbids (including via DNS, redirects or URL parsing differentials)
- Approval replay, reuse, binding or authenticity failures
- Secrets (file contents, credentials, query strings) appearing in audit logs or approval summaries
- Audit chain forgery that `audit verify` does not detect when the attacker lacks write access to both the log and its `.head` file

Out of scope: items listed under "Out of scope" and "Known limitations" in `docs/threat-model.md`
(e.g. hostile code running inside the same Python process, same-OS-user approvals, Windows file-race windows).

## Supported versions

Only the latest 0.x release receives fixes while the project is in alpha.
