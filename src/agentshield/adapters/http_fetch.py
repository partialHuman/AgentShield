"""SSRF-resistant HTTP fetch tool (standard library only).

Per request (and again for every redirect hop):
  1. parse + normalize the URL (userinfo, numeric IP forms, IDNA, ports)
  2. check scheme / host / port allowlists
  3. resolve DNS ONCE and validate EVERY returned address
  4. connect to the validated IP address (never re-resolve), preserving the
     original Host header and TLS SNI/certificate hostname
Redirects are never followed automatically; proxies in the environment are
ignored (this module does not use urllib/requests). Response bodies are read
in bounded chunks and never decompressed.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import urljoin

from ..constraints import HTTP_CONSTRAINTS
from ..models import ExecutionError
from ..netguard import HostError, ParsedURL, Resolver, check_destination, parse_url, system_resolver
from ..normalize import ArgSpec, truncate
from ..policy import ToolPolicy
from ..tools import CheckOutcome, Tool

Connector = Callable[[str, int, float], socket.socket]
_REDIRECT = {301, 302, 303, 307, 308}


def default_connector(ip: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((ip, port), timeout=timeout)


_USERINFO = re.compile(r"(?<=//)[^/?#]*@")


def redact_url(url: str) -> str:
    """Audit-safe URL: scheme://host:port/path with credentials and query string removed."""
    try:
        p = parse_url(url)
    except HostError:
        # unparseable (possibly hostile) input: strip anything that could hold secrets
        s = _USERINFO.sub("[redacted]@", url)
        return truncate(s.split("?", 1)[0].split("#", 1)[0], 200)
    path = p.target.split("?", 1)[0]
    has_query = "?" in p.target
    return truncate(f"{p.scheme}://{p.netloc}{path}{'?[redacted]' if has_query else ''}", 300)


def _constraints(tp: ToolPolicy) -> dict[str, Any]:
    c = tp.constraints
    return {
        "allowed_schemes": c["allowed_schemes"], "allowed_hosts": c["allowed_hosts"],
        "allowed_ports": c["allowed_ports"], "block_private": bool(c["block_private_addresses"]),
    }


def _check(url: str, tp: ToolPolicy, resolver: Resolver) -> tuple[ParsedURL | None, list[str], list[str]]:
    try:
        parsed = parse_url(url)
    except HostError as exc:
        return None, [exc.code], []
    codes, ips = check_destination(parsed, resolver=resolver, **_constraints(tp))
    return parsed, codes, ips


def make_executor(
    tp: ToolPolicy,
    resolver: Resolver = system_resolver,
    connector: Connector = default_connector,
    ssl_context: ssl.SSLContext | None = None,
) -> Callable[..., dict[str, Any]]:
    c = tp.constraints
    max_bytes = int(c["max_response_bytes"])
    timeout = float(c["timeout_seconds"])
    max_redirects = int(c["max_redirects"])
    follow = bool(c["revalidate_redirects"])

    def fetch(url: str) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        current = url
        hops = 0
        while True:
            parsed, codes, ips = _check(current, tp, resolver)  # authoritative, use-time validation
            if codes or parsed is None:
                raise ExecutionError("REDIRECT_BLOCKED" if hops else "DESTINATION_BLOCKED", ",".join(codes))
            status, headers, body = _request_once(parsed, ips, deadline, max_bytes, connector, ssl_context)
            location = headers.get("location")
            if status in _REDIRECT and location and follow:
                hops += 1
                if hops > max_redirects:
                    raise ExecutionError("TOO_MANY_REDIRECTS")
                current = urljoin(parsed.url(), location)
                continue
            text = body.decode("utf-8", errors="replace")
            return {
                "status": status,
                "url": parsed.url(),
                "content_type": headers.get("content-type"),
                "body": text,
                "redirected": hops,
            }

    return fetch


def _request_once(
    parsed: ParsedURL,
    ips: Sequence[str],
    deadline: float,
    max_bytes: int,
    connector: Connector,
    ssl_context: ssl.SSLContext | None,
) -> tuple[int, dict[str, str], bytes]:
    sock: socket.socket | None = None
    last_err: Exception | None = None
    for ip in ips:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ExecutionError("TIMEOUT")
        try:
            sock = connector(ip, parsed.port, remaining)  # connect to the VALIDATED address
            break
        except OSError as exc:
            last_err = exc
    if sock is None:
        raise ExecutionError("CONNECT_FAILED", type(last_err).__name__ if last_err else "")
    conn: http.client.HTTPConnection | None = None
    try:
        if parsed.scheme == "https":
            ctx = ssl_context or ssl.create_default_context()
            try:
                sock = ctx.wrap_socket(sock, server_hostname=parsed.host)  # SNI + cert check use the ORIGINAL host
            except (ssl.SSLError, OSError) as exc:
                raise ExecutionError("TLS_ERROR", type(exc).__name__) from None
            conn = http.client.HTTPSConnection(parsed.host, parsed.port, timeout=max(0.1, deadline - time.monotonic()))
        else:
            conn = http.client.HTTPConnection(parsed.host, parsed.port, timeout=max(0.1, deadline - time.monotonic()))
        conn.sock = sock
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            conn.request(
                "GET", parsed.target,
                headers={"Accept-Encoding": "identity", "User-Agent": "agentshield/0.1", "Connection": "close"},
            )
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            raise ExecutionError("REQUEST_FAILED", type(exc).__name__) from exc
        clen = resp.getheader("Content-Length")
        if clen is not None and clen.isdigit() and int(clen) > max_bytes:
            raise ExecutionError("RESPONSE_TOO_LARGE")
        chunks: list[bytes] = []
        total = 0
        # http.client closes ``sock`` for "Connection: close" responses; the live socket is behind resp.fp
        live = getattr(getattr(getattr(resp, "fp", None), "raw", None), "_sock", sock)
        try:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise ExecutionError("TIMEOUT")
                try:
                    live.settimeout(left)  # keeps the TOTAL deadline binding against slow-drip servers
                except OSError:
                    pass
                chunk = resp.read(min(16384, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ExecutionError("RESPONSE_TOO_LARGE")
                chunks.append(chunk)
        except (OSError, http.client.HTTPException) as exc:
            if isinstance(exc, socket.timeout):
                raise ExecutionError("TIMEOUT") from None
            raise ExecutionError("REQUEST_FAILED", type(exc).__name__) from exc
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, b"".join(chunks)
    finally:
        if conn is not None:
            conn.close()
        else:
            sock.close()


def http_fetch_tool(
    *,
    resolver: Resolver = system_resolver,
    connector: Connector = default_connector,
    ssl_context: ssl.SSLContext | None = None,
) -> Tool:
    """GET-only fetch tool. ``resolver``/``connector``/``ssl_context`` are injectable for tests."""

    def checker(args: dict[str, Any], tp: ToolPolicy) -> CheckOutcome:
        parsed, codes, ips = _check(args["url"], tp, resolver)
        trace = [f"url parsed: {parsed.scheme}://{parsed.netloc}" if parsed else "url rejected"]
        if ips:
            trace.append(f"destination validated ({len(ips)} address(es))")
        target = parsed.url() if parsed else None
        shown = redact_url(target) if target else None  # never put query strings / secrets in audit targets
        return CheckOutcome(target, tuple(codes), tuple(trace), display_target=shown)

    return Tool(
        name="http.fetch",
        args={"url": ArgSpec("url")},
        executor_factory=lambda tp: make_executor(tp, resolver, connector, ssl_context),
        checker=checker,
        constraint_schema=HTTP_CONSTRAINTS,
        summarize=lambda a: {"url": redact_url(a["url"])},
    )
