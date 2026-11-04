# Attack scenarios (generated)

Generated from `tests/security/corpus.py` by `python -m tests.security.corpus --write docs/attack-scenarios.md`.
A test fails if this file drifts from the corpus. Every scenario is executed against the real enforcement path;
`deny` scenarios must be refused with the listed reason code **and** must not invoke the executor.
`safe` scenarios may be allowed by policy but must fail or return nothing sensitive at use time.

Total: **73** attack scenarios, **56** benign actions used to measure false blocks.

| ID | Category | Scenario | Tool | Expected | Reason code |
|----|----------|----------|------|----------|-------------|
| FS-01 | path traversal | Relative parent traversal to a file outside the workspace | `filesystem.read` | deny | PATH_TRAVERSAL |
| FS-02 | path traversal | Traversal hidden after a legitimate-looking prefix | `filesystem.read` | deny | PATH_TRAVERSAL |
| FS-03 | path traversal | Traversal that would resolve back inside the root is still refused (no ambiguity) | `filesystem.read` | deny | PATH_TRAVERSAL |
| FS-04 | path traversal | Absolute path to a system file | `filesystem.read` | deny | PATH_OUTSIDE_ROOT |
| FS-05 | path traversal | Absolute path in a sibling directory sharing the root's name prefix | `filesystem.read` | deny | PATH_OUTSIDE_ROOT |
| FS-06 | path traversal | Absolute path to the outside secret | `filesystem.read` | deny | PATH_OUTSIDE_ROOT |
| FS-07 | path traversal | Percent-encoded traversal (must be treated as a literal name, never decoded) | `filesystem.read` | safe | - |
| FS-08 | path traversal | Backslash traversal on POSIX (literal filename, never a separator) | `filesystem.read` | safe | - |
| FS-09 | symlink | Symlink inside the workspace pointing at an outside file | `filesystem.read` | deny | PATH_SYMLINK |
| FS-10 | symlink | Symlinked directory component pointing outside | `filesystem.read` | deny | PATH_SYMLINK |
| FS-11 | symlink | Dangling symlink (could be created later to point anywhere) | `filesystem.read` | deny | PATH_SYMLINK |
| FS-12 | symlink | Write through a symlinked directory in the output root | `filesystem.write` | deny | PATH_SYMLINK |
| FS-13 | symlink | Hard link inside the workspace to an outside file (refused at use time) | `filesystem.read` | safe | - |
| FS-14 | device files | Named pipe (would block a naive open forever) | `filesystem.read` | safe | - |
| FS-15 | encoding | NUL byte to truncate the path in C-level APIs | `filesystem.read` | deny | ARG_INVALID_CHARACTERS |
| FS-16 | encoding | Newline injection in a path | `filesystem.read` | deny | ARG_INVALID_CHARACTERS |
| FS-17 | encoding | Right-to-left override to disguise a file name | `filesystem.read` | deny | ARG_INVALID_CHARACTERS |
| FS-18 | encoding | Zero-width character in a path | `filesystem.read` | deny | ARG_INVALID_CHARACTERS |
| FS-19 | schema | Empty path | `filesystem.read` | deny | SCHEMA_INVALID_VALUE |
| FS-20 | schema | Path supplied as an object | `filesystem.read` | deny | SCHEMA_INVALID_TYPE |
| FS-21 | schema | Oversized path | `filesystem.read` | deny | ARG_TOO_LARGE |
| FS-22 | schema | Undeclared extra argument smuggled alongside a valid path | `filesystem.read` | deny | SCHEMA_UNEXPECTED_FIELD |
| FS-23 | schema | Directory path with trailing slash | `filesystem.read` | deny | PATH_INVALID |
| FS-24 | write scope | Write outside the output root via traversal | `filesystem.write` | deny | PATH_TRAVERSAL |
| FS-25 | write scope | Overwrite a workspace file that is outside the (narrower) write root | `filesystem.write` | deny | PATH_OUTSIDE_ROOT |
| FS-26 | write scope | Oversized content | `filesystem.write` | deny | CONTENT_TOO_LARGE |
| FS-27 | approval | In-scope write still requires a human (never auto-executes) | `filesystem.write` | approval | APPROVAL_REQUIRED |
| TL-01 | unauthorized tool | Shell execution tool that was never registered | `shell.exec` | deny | UNKNOWN_TOOL |
| TL-02 | unauthorized tool | Case variant of a real tool name | `Filesystem.Read` | deny | UNKNOWN_TOOL |
| TL-03 | unauthorized tool | Tool name with an invisible suffix | `filesystem.read​` | deny | UNKNOWN_TOOL |
| TL-04 | unauthorized tool | Explicit DENY rule in policy | `demo.delete` | deny | EXPLICIT_DENY |
| TL-05 | unauthorized tool | Tool disabled in policy | `demo.disabled` | deny | TOOL_DISABLED |
| TL-06 | unauthorized tool | Registered tool with no policy rule (default deny) | `demo.unlisted` | deny | NO_POLICY_RULE |
| TL-07 | schema | Arguments supplied as a list | `filesystem.read` | deny | MALFORMED_REQUEST |
| TL-08 | schema | Arguments supplied as null | `filesystem.read` | deny | MALFORMED_REQUEST |
| TL-09 | schema | Tool name supplied as an object | `(non-string)` | deny | UNKNOWN_TOOL |
| CA-01 | code injection | Python import/exec via the calculator | `calculator` | deny | SCHEMA_INVALID_VALUE |
| CA-02 | code injection | Attribute walk to reach builtins | `calculator` | deny | SCHEMA_INVALID_VALUE |
| CA-03 | code injection | Walrus / lambda syntax | `calculator` | deny | SCHEMA_INVALID_VALUE |
| CA-04 | resource exhaustion | Exponent tower to burn CPU/memory (valid syntax, refused at execution) | `calculator` | safe | - |
| CA-05 | resource exhaustion | Oversized expression | `calculator` | deny | ARG_TOO_LARGE |
| HT-01 | ssrf | Alibaba-style cloud metadata IP (not allowlisted) | `http.fetch` | deny | HOST_NOT_ALLOWED |
| HT-02 | ssrf | AWS/GCP metadata IP explicitly allowlisted by a careless operator: still blocked | `http.fetch` | deny | ADDRESS_BLOCKED |
| HT-03 | ssrf | Loopback by name | `http.fetch` | deny | HOST_NOT_ALLOWED |
| HT-04 | ssrf | Loopback as a decimal integer host | `http.fetch` | deny | HOST_AMBIGUOUS_IP |
| HT-05 | ssrf | Loopback in hexadecimal | `http.fetch` | deny | HOST_AMBIGUOUS_IP |
| HT-06 | ssrf | Loopback in octal dotted form | `http.fetch` | deny | HOST_AMBIGUOUS_IP |
| HT-07 | ssrf | Short dotted form 127.1 | `http.fetch` | deny | HOST_AMBIGUOUS_IP |
| HT-08 | ssrf | IPv6 loopback literal | `http.fetch` | deny | HOST_NOT_ALLOWED |
| HT-09 | ssrf | IPv4-mapped IPv6 RFC1918 literal (not allowlisted) | `http.fetch` | deny | HOST_NOT_ALLOWED |
| HT-09b | ssrf | IPv4-mapped IPv6 loopback literal that a careless operator allowlisted: still blocked | `http.fetch` | deny | ADDRESS_BLOCKED |
| HT-10 | ssrf | Allowlisted name whose DNS answer is loopback (DNS pointing inward) | `http.fetch` | deny | ADDRESS_BLOCKED |
| HT-11 | ssrf | Allowlisted name with one public and one private answer | `http.fetch` | deny | ADDRESS_BLOCKED |
| HT-12 | ssrf | Allowlisted name resolving to the metadata address | `http.fetch` | deny | ADDRESS_BLOCKED |
| HT-13 | ssrf | Allowlisted name resolving to an IPv4-mapped IPv6 loopback | `http.fetch` | deny | ADDRESS_BLOCKED |
| HT-14 | ssrf | Allowlisted name resolving to a NAT64-embedded loopback | `http.fetch` | deny | ADDRESS_BLOCKED |
| HT-15 | ssrf | Allowlisted name resolving to an RFC1918 address | `http.fetch` | deny | ADDRESS_BLOCKED |
| HT-16 | url confusion | Userinfo trick: allowed host before the @ | `http.fetch` | deny | URL_USERINFO |
| HT-17 | url confusion | Backslash-as-separator confusion | `http.fetch` | deny | ARG_INVALID_CHARACTERS |
| HT-18 | url confusion | Suffix trick: allowed name as a prefix of an attacker domain | `http.fetch` | deny | HOST_NOT_ALLOWED |
| HT-19 | url confusion | Prefix trick: attacker label before the allowed domain | `http.fetch` | deny | HOST_NOT_ALLOWED |
| HT-20 | url confusion | Cyrillic homograph of an allowed host (IDNA exposes it) | `http.fetch` | deny | HOST_NOT_ALLOWED |
| HT-21 | url confusion | Percent-encoded characters in the host | `http.fetch` | deny | URL_INVALID |
| HT-22 | url confusion | CRLF injection to smuggle headers | `http.fetch` | deny | ARG_INVALID_CHARACTERS |
| HT-23 | url confusion | Whitespace-padded URL | `http.fetch` | deny | ARG_INVALID_CHARACTERS |
| HT-24 | scheme | file:// scheme | `http.fetch` | deny | URL_SCHEME_NOT_ALLOWED |
| HT-25 | scheme | gopher:// scheme | `http.fetch` | deny | URL_SCHEME_NOT_ALLOWED |
| HT-26 | scheme | Plain http when only https is allowed (downgrade) | `http.fetch` | deny | URL_SCHEME_NOT_ALLOWED |
| HT-27 | scheme | Scheme-relative URL | `http.fetch` | deny | URL_SCHEME_NOT_ALLOWED |
| HT-28 | ports | Allowed host on an unapproved port (internal admin port) | `http.fetch` | deny | PORT_NOT_ALLOWED |
| HT-29 | ports | Port out of range | `http.fetch` | deny | URL_INVALID |
| HT-30 | schema | URL supplied as a list | `http.fetch` | deny | SCHEMA_INVALID_TYPE |
| HT-31 | schema | Header injection through an undeclared argument | `http.fetch` | deny | SCHEMA_UNEXPECTED_FIELD |
