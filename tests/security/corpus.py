"""Attack and benign corpora (data, not logic).

Run ``python -m tests.security.corpus --write docs/attack-scenarios.md`` to regenerate the doc;
a test fails if the checked-in doc drifts from this file.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

from agentshield.models import Reason as R

PUBLIC = "93.184.216.34"
SECRET = "TOP-SECRET"

# Host -> DNS answers used by the fake resolver in the test environment.
DNS = {
    "docs.example.com": [PUBLIC],
    "api.example.com": ["2606:4700:4700::1111"],
    "rebind.example.com": ["127.0.0.1"],
    "mixed.example.com": [PUBLIC, "10.0.0.1"],
    "meta.example.com": ["169.254.169.254"],
    "v6mapped.example.com": ["::ffff:127.0.0.1"],
    "nat64.example.com": ["64:ff9b::7f00:1"],
    "lan.example.com": ["192.168.1.10"],
}


@dataclass(frozen=True)
class Attack:
    id: str
    category: str
    description: str
    tool: str
    args: Any
    expect: str  # "deny" | "approval" | "safe"
    codes: tuple[str, ...] = ()


def _a(id, cat, desc, tool, args, expect="deny", *codes):
    return Attack(id, cat, desc, tool, args, expect, tuple(codes))


FR, FW, HF, CALC = "filesystem.read", "filesystem.write", "http.fetch", "calculator"
BIG = "x" * 5000

ATTACKS: list[Attack] = [
    # ---------------- path traversal & filesystem escapes
    _a("FS-01", "path traversal", "Relative parent traversal to a file outside the workspace", FR, {"path": "../outside/secret.txt"}, "deny", R.PATH_TRAVERSAL),
    _a("FS-02", "path traversal", "Traversal hidden after a legitimate-looking prefix", FR, {"path": "docs/../../outside/secret.txt"}, "deny", R.PATH_TRAVERSAL),
    _a("FS-03", "path traversal", "Traversal that would resolve back inside the root is still refused (no ambiguity)", FR, {"path": "a/../hello.txt"}, "deny", R.PATH_TRAVERSAL),
    _a("FS-04", "path traversal", "Absolute path to a system file", FR, {"path": "/etc/passwd"}, "deny", R.PATH_OUTSIDE_ROOT),
    _a("FS-05", "path traversal", "Absolute path in a sibling directory sharing the root's name prefix", FR, {"path": "{ws}-evil/x.txt"}, "deny", R.PATH_OUTSIDE_ROOT),
    _a("FS-06", "path traversal", "Absolute path to the outside secret", FR, {"path": "{outside}/secret.txt"}, "deny", R.PATH_OUTSIDE_ROOT),
    _a("FS-07", "path traversal", "Percent-encoded traversal (must be treated as a literal name, never decoded)", FR, {"path": "%2e%2e/outside/secret.txt"}, "safe"),
    _a("FS-08", "path traversal", "Backslash traversal on POSIX (literal filename, never a separator)", FR, {"path": "..\\outside\\secret.txt"}, "safe"),
    _a("FS-09", "symlink", "Symlink inside the workspace pointing at an outside file", FR, {"path": "link.txt"}, "deny", R.PATH_SYMLINK),
    _a("FS-10", "symlink", "Symlinked directory component pointing outside", FR, {"path": "dirlink/secret.txt"}, "deny", R.PATH_SYMLINK),
    _a("FS-11", "symlink", "Dangling symlink (could be created later to point anywhere)", FR, {"path": "dangling"}, "deny", R.PATH_SYMLINK),
    _a("FS-12", "symlink", "Write through a symlinked directory in the output root", FW, {"path": "wlink/pwned.txt", "content": "x"}, "deny", R.PATH_SYMLINK),
    _a("FS-13", "symlink", "Hard link inside the workspace to an outside file (refused at use time)", FR, {"path": "hard.txt"}, "safe"),
    _a("FS-14", "device files", "Named pipe (would block a naive open forever)", FR, {"path": "pipe"}, "safe"),
    _a("FS-15", "encoding", "NUL byte to truncate the path in C-level APIs", FR, {"path": "hello.txt\x00.png"}, "deny", R.ARG_INVALID_CHARACTERS),
    _a("FS-16", "encoding", "Newline injection in a path", FR, {"path": "hello.txt\nsecret"}, "deny", R.ARG_INVALID_CHARACTERS),
    _a("FS-17", "encoding", "Right-to-left override to disguise a file name", FR, {"path": "hello\u202etxt.exe"}, "deny", R.ARG_INVALID_CHARACTERS),
    _a("FS-18", "encoding", "Zero-width character in a path", FR, {"path": "hel\u200blo.txt"}, "deny", R.ARG_INVALID_CHARACTERS),
    _a("FS-19", "schema", "Empty path", FR, {"path": ""}, "deny", R.SCHEMA_INVALID_VALUE),
    _a("FS-20", "schema", "Path supplied as an object", FR, {"path": {"$ne": ""}}, "deny", R.SCHEMA_INVALID_TYPE),
    _a("FS-21", "schema", "Oversized path", FR, {"path": BIG}, "deny", R.ARG_TOO_LARGE),
    _a("FS-22", "schema", "Undeclared extra argument smuggled alongside a valid path", FR, {"path": "hello.txt", "mode": "rw"}, "deny", R.SCHEMA_UNEXPECTED_FIELD),
    _a("FS-23", "schema", "Directory path with trailing slash", FR, {"path": "output/"}, "deny", R.PATH_INVALID),
    _a("FS-24", "write scope", "Write outside the output root via traversal", FW, {"path": "../hello.txt", "content": "pwn"}, "deny", R.PATH_TRAVERSAL),
    _a("FS-25", "write scope", "Overwrite a workspace file that is outside the (narrower) write root", FW, {"path": "{ws}/hello.txt", "content": "pwn", "overwrite": True}, "deny", R.PATH_OUTSIDE_ROOT),
    _a("FS-26", "write scope", "Oversized content", FW, {"path": "big.txt", "content": "x" * 2000}, "deny", R.CONTENT_TOO_LARGE),
    _a("FS-27", "approval", "In-scope write still requires a human (never auto-executes)", FW, {"path": "report.txt", "content": "hello"}, "approval", R.APPROVAL_REQUIRED),
    # ---------------- tool-level
    _a("TL-01", "unauthorized tool", "Shell execution tool that was never registered", "shell.exec", {"cmd": "id"}, "deny", R.UNKNOWN_TOOL),
    _a("TL-02", "unauthorized tool", "Case variant of a real tool name", "Filesystem.Read", {"path": "hello.txt"}, "deny", R.UNKNOWN_TOOL),
    _a("TL-03", "unauthorized tool", "Tool name with an invisible suffix", "filesystem.read\u200b", {"path": "hello.txt"}, "deny", R.UNKNOWN_TOOL),
    _a("TL-04", "unauthorized tool", "Explicit DENY rule in policy", "demo.delete", {"target": "x"}, "deny", R.EXPLICIT_DENY),
    _a("TL-05", "unauthorized tool", "Tool disabled in policy", "demo.disabled", {}, "deny", R.TOOL_DISABLED),
    _a("TL-06", "unauthorized tool", "Registered tool with no policy rule (default deny)", "demo.unlisted", {}, "deny", R.NO_POLICY_RULE),
    _a("TL-07", "schema", "Arguments supplied as a list", FR, ["hello.txt"], "deny", R.MALFORMED_REQUEST),
    _a("TL-08", "schema", "Arguments supplied as null", FR, None, "deny", R.MALFORMED_REQUEST),
    _a("TL-09", "schema", "Tool name supplied as an object", {"name": "filesystem.read"}, {"path": "hello.txt"}, "deny", R.UNKNOWN_TOOL),
    # ---------------- calculator
    _a("CA-01", "code injection", "Python import/exec via the calculator", CALC, {"expression": "__import__('os').system('id')"}, "deny", R.SCHEMA_INVALID_VALUE),
    _a("CA-02", "code injection", "Attribute walk to reach builtins", CALC, {"expression": "().__class__.__mro__[1].__subclasses__()"}, "deny", R.SCHEMA_INVALID_VALUE),
    _a("CA-03", "code injection", "Walrus / lambda syntax", CALC, {"expression": "(lambda: 1)()"}, "deny", R.SCHEMA_INVALID_VALUE),
    _a("CA-04", "resource exhaustion", "Exponent tower to burn CPU/memory (valid syntax, refused at execution)", CALC, {"expression": "9**9**9**9"}, "safe"),
    _a("CA-05", "resource exhaustion", "Oversized expression", CALC, {"expression": "1+" * 2000 + "1"}, "deny", R.ARG_TOO_LARGE),
    # ---------------- SSRF / network
    _a("HT-01", "ssrf", "Alibaba-style cloud metadata IP (not allowlisted)", HF, {"url": "https://100.100.100.200/latest/meta-data/"}, "deny", R.HOST_NOT_ALLOWED),
    _a("HT-02", "ssrf", "AWS/GCP metadata IP explicitly allowlisted by a careless operator: still blocked", HF, {"url": "https://169.254.169.254/latest/meta-data/"}, "deny", R.ADDRESS_BLOCKED),
    _a("HT-03", "ssrf", "Loopback by name", HF, {"url": "https://localhost/admin"}, "deny", R.HOST_NOT_ALLOWED),
    _a("HT-04", "ssrf", "Loopback as a decimal integer host", HF, {"url": "https://2130706433/"}, "deny", R.HOST_AMBIGUOUS_IP),
    _a("HT-05", "ssrf", "Loopback in hexadecimal", HF, {"url": "https://0x7f000001/"}, "deny", R.HOST_AMBIGUOUS_IP),
    _a("HT-06", "ssrf", "Loopback in octal dotted form", HF, {"url": "https://0177.0.0.1/"}, "deny", R.HOST_AMBIGUOUS_IP),
    _a("HT-07", "ssrf", "Short dotted form 127.1", HF, {"url": "https://127.1/"}, "deny", R.HOST_AMBIGUOUS_IP),
    _a("HT-08", "ssrf", "IPv6 loopback literal", HF, {"url": "https://[::1]/"}, "deny", R.HOST_NOT_ALLOWED),
    _a("HT-09", "ssrf", "IPv4-mapped IPv6 RFC1918 literal (not allowlisted)", HF, {"url": "https://[::ffff:10.0.0.1]/"}, "deny", R.HOST_NOT_ALLOWED),
    _a("HT-09b", "ssrf", "IPv4-mapped IPv6 loopback literal that a careless operator allowlisted: still blocked", HF, {"url": "https://[::ffff:127.0.0.1]/"}, "deny", R.ADDRESS_BLOCKED),
    _a("HT-10", "ssrf", "Allowlisted name whose DNS answer is loopback (DNS pointing inward)", HF, {"url": "https://rebind.example.com/"}, "deny", R.ADDRESS_BLOCKED),
    _a("HT-11", "ssrf", "Allowlisted name with one public and one private answer", HF, {"url": "https://mixed.example.com/"}, "deny", R.ADDRESS_BLOCKED),
    _a("HT-12", "ssrf", "Allowlisted name resolving to the metadata address", HF, {"url": "https://meta.example.com/"}, "deny", R.ADDRESS_BLOCKED),
    _a("HT-13", "ssrf", "Allowlisted name resolving to an IPv4-mapped IPv6 loopback", HF, {"url": "https://v6mapped.example.com/"}, "deny", R.ADDRESS_BLOCKED),
    _a("HT-14", "ssrf", "Allowlisted name resolving to a NAT64-embedded loopback", HF, {"url": "https://nat64.example.com/"}, "deny", R.ADDRESS_BLOCKED),
    _a("HT-15", "ssrf", "Allowlisted name resolving to an RFC1918 address", HF, {"url": "https://lan.example.com/"}, "deny", R.ADDRESS_BLOCKED),
    _a("HT-16", "url confusion", "Userinfo trick: allowed host before the @", HF, {"url": "https://docs.example.com@evil.com/"}, "deny", R.URL_USERINFO),
    _a("HT-17", "url confusion", "Backslash-as-separator confusion", HF, {"url": "https://evil.com\\@docs.example.com/"}, "deny", R.ARG_INVALID_CHARACTERS),
    _a("HT-18", "url confusion", "Suffix trick: allowed name as a prefix of an attacker domain", HF, {"url": "https://docs.example.com.evil.com/"}, "deny", R.HOST_NOT_ALLOWED),
    _a("HT-19", "url confusion", "Prefix trick: attacker label before the allowed domain", HF, {"url": "https://evil-docs.example.com/"}, "deny", R.HOST_NOT_ALLOWED),
    _a("HT-20", "url confusion", "Cyrillic homograph of an allowed host (IDNA exposes it)", HF, {"url": "https://d\u043ecs.example.com/"}, "deny", R.HOST_NOT_ALLOWED),
    _a("HT-21", "url confusion", "Percent-encoded characters in the host", HF, {"url": "https://docs%2eexample.com/"}, "deny", R.URL_INVALID),
    _a("HT-22", "url confusion", "CRLF injection to smuggle headers", HF, {"url": "https://docs.example.com/\r\nX-Evil: 1"}, "deny", R.ARG_INVALID_CHARACTERS),
    _a("HT-23", "url confusion", "Whitespace-padded URL", HF, {"url": " https://docs.example.com/"}, "deny", R.ARG_INVALID_CHARACTERS),
    _a("HT-24", "scheme", "file:// scheme", HF, {"url": "file:///etc/passwd"}, "deny", R.URL_SCHEME_NOT_ALLOWED),
    _a("HT-25", "scheme", "gopher:// scheme", HF, {"url": "gopher://docs.example.com/_x"}, "deny", R.URL_SCHEME_NOT_ALLOWED),
    _a("HT-26", "scheme", "Plain http when only https is allowed (downgrade)", HF, {"url": "http://docs.example.com/"}, "deny", R.URL_SCHEME_NOT_ALLOWED),
    _a("HT-27", "scheme", "Scheme-relative URL", HF, {"url": "//docs.example.com/"}, "deny", R.URL_SCHEME_NOT_ALLOWED),
    _a("HT-28", "ports", "Allowed host on an unapproved port (internal admin port)", HF, {"url": "https://docs.example.com:8080/"}, "deny", R.PORT_NOT_ALLOWED),
    _a("HT-29", "ports", "Port out of range", HF, {"url": "https://docs.example.com:99999/"}, "deny", R.URL_INVALID),
    _a("HT-30", "schema", "URL supplied as a list", HF, {"url": ["https://docs.example.com/"]}, "deny", R.SCHEMA_INVALID_TYPE),
    _a("HT-31", "schema", "Header injection through an undeclared argument", HF, {"url": "https://docs.example.com/", "headers": {"Authorization": "x"}}, "deny", R.SCHEMA_UNEXPECTED_FIELD),
]

# -------------------------------------------------------------------- benign corpus
_B = []


def _ok(tool, args):
    _B.append((tool, args))


for expr in ["1+1", "2 * (3 + 4)", "10 / 4", "7 // 2", "7 % 3", "2 ** 10", "-5 + 3", "1.5 * 2", "(1+2)*(3+4)/5",
             "100 - 99.5", "3.14159 * 2 ** 2", "  42  ", "0", "1e3 + 1", "((((1))))"]:
    _ok(CALC, {"expression": expr})
for p in ["hello.txt", "./hello.txt", "docs/guide.md", "docs/nested/deep/file.txt", "notes (final).txt", "data-2026_11.csv",
          "caf\u00e9.txt", "cafe\u0301.txt", "\u65e5\u672c\u8a9e.txt", "file.with.many.dots.txt", ".hidden", "UPPER.TXT", "a b c.txt",
          "docs//double-slash.txt", "{ws}/hello.txt", "{ws}/docs/guide.md"]:
    _ok(FR, {"path": p})
for p, c in [("out.txt", "hello"), ("sub/dir/out.txt", "x"), ("report-2026.md", "# Title\n\nbody\n"), ("{ws}/output/abs.txt", "abs"),
             ("unicode-\u00e9.txt", "\u2603 snowman"), ("empty.txt", ""), ("crlf.txt", "a\r\nb\r\n"), ("data.json", '{"a": 1}')]:
    _ok(FW, {"path": p, "content": c})
_ok(FW, {"path": "again.txt", "content": "x", "overwrite": True})
for u in ["https://docs.example.com/", "https://docs.example.com", "https://docs.example.com/a/b/c", "https://docs.example.com/search?q=agent+shield&page=2",
          "https://DOCS.EXAMPLE.COM/Mixed/Case", "https://docs.example.com./trailing-dot", "https://docs.example.com:443/explicit-port",
          "https://docs.example.com/path%20with%20spaces", "https://docs.example.com/a?b=c#fragment", "https://docs.example.com/unicode/%E2%98%83",
          "https://api.example.com/v1/items?limit=10", "https://docs.example.com/index.html", "https://docs.example.com/very/long/" + "seg/" * 20,
          "https://docs.example.com/?empty=", "https://api.example.com:8443/alt-port", "https://93.184.216.34/ip-literal-allowlisted"]:
    _ok(HF, {"url": u})

BENIGN = _B  # list of (tool, args); every one must evaluate to ALLOW or (for writes) REQUIRE_APPROVAL


def render_markdown() -> str:
    out = [
        "# Attack scenarios (generated)",
        "",
        "Generated from `tests/security/corpus.py` by `python -m tests.security.corpus --write docs/attack-scenarios.md`.",
        "A test fails if this file drifts from the corpus. Every scenario is executed against the real enforcement path;",
        "`deny` scenarios must be refused with the listed reason code **and** must not invoke the executor.",
        "`safe` scenarios may be allowed by policy but must fail or return nothing sensitive at use time.",
        "",
        f"Total: **{len(ATTACKS)}** attack scenarios, **{len(BENIGN)}** benign actions used to measure false blocks.",
        "",
        "| ID | Category | Scenario | Tool | Expected | Reason code |",
        "|----|----------|----------|------|----------|-------------|",
    ]
    for a in ATTACKS:
        tool = a.tool if isinstance(a.tool, str) else "(non-string)"
        out.append(f"| {a.id} | {a.category} | {a.description} | `{tool}` | {a.expect} | {', '.join(a.codes) or '-'} |")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--write":
        with open(sys.argv[2], "w", encoding="utf-8") as fh:
            fh.write(render_markdown())
    else:
        print(render_markdown())
