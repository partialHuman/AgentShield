# Policy reference (version 1)

Policies are strict YAML (JSON is accepted as a subset). They are validated at load time; an invalid policy never
starts. Validate with `agentshield lint policy.yaml`; the JSON Schema is [`policy.schema.json`](policy.schema.json)
(`agentshield schema`).

Loader rules: duplicate keys, YAML aliases/anchors, non-string keys, unknown keys, and files over 256 KiB are errors.
Quote values like `'no'`/`'yes'`/`'on'` (YAML turns bare ones into booleans, and the validator will tell you).

```yaml
version: 1                  # required, must be 1
default_decision: DENY      # optional; only DENY is accepted in v0.1
tools:
  <tool.name>:              # lower-case dotted name
    enabled: true           # default true
    risk: low|medium|high   # required; recorded in events, drives the audit-failure fallback
    decision: ALLOW | REQUIRE_APPROVAL | DENY   # required
    approval_ttl_seconds: 300   # 10..86400; how long a request/approval stays valid
    max_calls: 100          # optional per-process call budget (decrements on every ALLOW)
    arg_constraints:        # optional, structured (no regular expressions)
      <arg>: { enum: [..], max_length: 10, prefixes: [..], min: 0, max: 5 }
    # ...tool-specific constraints below...
```

**Constraints are hard limits.** If any constraint fails the action is denied even when `decision` is `ALLOW` or
`REQUIRE_APPROVAL`. Example: `filesystem.write` with `REQUIRE_APPROVAL` and a path outside `allowed_roots` is
denied outright; a path inside is held for approval.

## `calculator`
| Key | Default | Meaning |
|---|---|---|
| `max_expression_length` | 200 (1–1000) | Longer expressions are denied |

Arithmetic only (`+ - * / // % **`, unary +/-, numbers). No names, calls, attributes or comparisons. Magnitudes are bounded.

## `filesystem.read` / `filesystem.write`
| Key | Default | Meaning |
|---|---|---|
| `allowed_roots` | **required** | Existing directories. Relative entries resolve against the policy file's directory. Resolved once at load. |
| `max_bytes` | 1 MiB (max 256 MiB) | Read: larger files fail at use time. Write: larger content is denied. |

Arguments: `read(path)`, `write(path, content, overwrite=False)`.
Paths: relative paths resolve against the **first** root; absolute paths must lie under one of the roots (textually,
real paths). `..` is always denied. Symlinks anywhere beneath a root are denied. Hard-linked files are refused. Only
regular files. `write` without `overwrite` fails if the file exists. New files are created `0600`. Parent directories are
never created.

## `http.fetch` (GET only)
| Key | Default | Meaning |
|---|---|---|
| `allowed_hosts` | **required** | Exact hostnames or IP literals (no wildcards). Normalized (lower-case, IDNA, no trailing dot). |
| `allowed_schemes` | `[https]` | `http` and/or `https` |
| `allowed_ports` | `[443]` | Ports permitted (also applied to redirects) |
| `block_private_addresses` | `true` | `false` additionally permits loopback/RFC1918/ULA/CGNAT targets (link-local, multicast, metadata and unspecified addresses stay blocked) |
| `revalidate_redirects` | `true` | `true`: follow redirects, revalidating every hop against this policy. `false`: do not follow redirects (the 3xx response is returned) |
| `max_redirects` | 3 (0–10) | |
| `max_response_bytes` | 1 MiB | Larger responses fail; bodies are never decompressed |
| `timeout_seconds` | 10 (0.5–120) | Total deadline for connect + request + read, across redirects |

Argument: `fetch(url)`. URLs with credentials, non-http(s) schemes, ambiguous numeric hosts (`2130706433`, `0x7f.1`),
percent-encoded hosts, backslashes or control characters are denied before any DNS lookup.

## Custom tools
Any other tool name may appear in a policy with the common keys. Extra constraint keys are accepted at load time and
validated against the `Tool.constraint_schema` when the tool is wrapped (unknown keys then fail with a `PolicyError`).

## Error messages
`agentshield lint` prints every problem with its path, e.g. `tools.http.fetch.allowed_hosts[0]: must be a non-empty string
(quote values like 'no' or 'yes')`.
