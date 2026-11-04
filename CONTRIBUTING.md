# Contributing

Thanks for helping make agent tool use safer. AgentShield is security-sensitive, so the bar for changes is
"demonstrably enforced and tested", not "looks right".

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q                      # or, with no dev deps:  python -m unittest discover -s tests -t .
python examples/scripted_attacker.py     # offline demo; must print RESULT: PASS
python scripts/mutation_check.py         # breaks security code on purpose; every mutation must be killed
ruff check . && mypy
```

## Rules of the road

1. **Every bypass becomes a test first.** Add an entry to `tests/security/corpus.py`, run
   `python -m tests.security.corpus --write docs/attack-scenarios.md`, watch it fail, then fix.
2. **Denied means not executed.** New code paths must preserve: no executor call unless the decision is ALLOW. Add a test that proves it with a counter, not just an exception check.
3. **Fail closed.** Unexpected errors deny. Never add an implicit fallback that permits.
4. **Never log values by default.** Summaries are allow-lists (sizes, hashes, redacted URLs). Add a leak test for new fields.
5. **Re-validate at use time.** Don't trust a decision-time check for anything that can change (files, DNS).
6. Keep core dependencies minimal (currently only PyYAML).
7. If you change the policy schema or constraint specs, regenerate `docs/policy.schema.json` (`agentshield schema > docs/policy.schema.json`).
8. If you add a security-critical branch, add a mutation to `scripts/mutation_check.py` that your tests kill.

## Sign-off (DCO)

Sign your commits (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).
Contributions are licensed under Apache-2.0.
