"""Shared test helpers (stdlib only so the suite runs without pytest)."""

from __future__ import annotations

import gzip
import http.server
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from typing import Any

from agentshield import AuditLog, Policy, Shield
from agentshield.approvals import ApprovalStore

PUBLIC_IP = "93.184.216.34"


class TmpDirTestCase(unittest.TestCase):
    """Provides self.tmp (a real, realpath'd temporary directory) cleaned up after each test."""

    def setUp(self) -> None:
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="agentshield-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.ws = os.path.join(self.tmp, "workspace")
        os.makedirs(os.path.join(self.ws, "output"))
        with open(os.path.join(self.ws, "hello.txt"), "w", encoding="utf-8") as fh:
            fh.write("hello")

    def policy(self, text: str) -> Policy:
        return Policy.from_text(text, base_dir=self.tmp)

    def shield(self, policy_text: str, *, approvals: bool = False, clock: Any = None, **kw: Any) -> Shield:
        store = ApprovalStore(os.path.join(self.tmp, ".agentshield"), **({"clock": clock} if clock else {})) if approvals else None
        return Shield(self.policy(policy_text), agent_id=kw.pop("agent_id", "test-agent"), approvals=store, **kw)


class FakeClock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


class Counter:
    """Callable that counts invocations: proves whether an executor ran."""

    def __init__(self, result: Any = "ran"):
        self.calls: list[dict[str, Any]] = []
        self.result = result

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.result

    @property
    def count(self) -> int:
        return len(self.calls)


BASE_POLICY = """
version: 1
tools:
  calculator: {risk: low, decision: ALLOW}
  filesystem.read: {risk: medium, decision: ALLOW, allowed_roots: [./workspace]}
  filesystem.write:
    risk: high
    decision: REQUIRE_APPROVAL
    allowed_roots: [./workspace/output]
    max_bytes: 1000
"""


# ------------------------------------------------------------------ local HTTP server
class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: Any

    def log_message(self, *a: Any) -> None:  # silence
        pass

    def _send(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        s = self.server
        s.requests.append((self.path, self.headers.get("Host")))
        port = s.server_address[1]
        p = self.path.split("?")[0]
        if p == "/ok":
            self._send(200, b"ok", {"Content-Type": "text/plain"})
        elif p == "/host":
            self._send(200, (self.headers.get("Host") or "").encode())
        elif p == "/big":
            self._send(200, b"x" * 5000)
        elif p == "/gzip":
            self._send(200, gzip.compress(b"A" * 1000), {"Content-Encoding": "gzip"})
        elif p == "/slow":
            time.sleep(2.0)
            self._send(200, b"late")
        elif p == "/redir-ok":
            self._send(302, headers={"Location": "/ok"})
        elif p == "/redir-loop":
            self._send(302, headers={"Location": "/redir-loop"})
        elif p == "/redir-port":
            self._send(302, headers={"Location": f"http://127.0.0.1:{port + 1}/ok"})
        elif p == "/redir-host":
            self._send(302, headers={"Location": f"http://localhost:{port}/ok"})
        elif p == "/redir-meta":
            self._send(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        elif p == "/redir-scheme":
            self._send(302, headers={"Location": "file:///etc/passwd"})
        else:
            self._send(404, b"nope")


class LocalServer:
    def __init__(self, tls_cert: tuple[str, str] | None = None):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.requests = []  # type: ignore[attr-defined]
        self.httpd.handle_error = lambda *a: None  # type: ignore[method-assign]  # clients may hang up (timeout tests)
        if tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls_cert)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.requests: list[tuple[str, str | None]] = self.httpd.requests  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True)

    def __enter__(self) -> LocalServer:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def make_cert(directory: str, hostname: str) -> tuple[str, str] | None:
    """Self-signed cert via the openssl CLI; None if openssl is unavailable."""
    openssl_cmd = shutil.which("openssl")
    if openssl_cmd is None and os.name == "nt":
        candidate = r"C:\Program Files\Git\usr\bin\openssl.exe"
        if os.path.exists(candidate):
            openssl_cmd = candidate
    if openssl_cmd is None:
        return None
    key, crt = os.path.join(directory, "k.pem"), os.path.join(directory, "c.pem")
    try:
        subprocess.run(
            [openssl_cmd, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
             "-days", "2", "-subj", f"/CN={hostname}", "-addext", f"subjectAltName=DNS:{hostname}"],
            check=True, capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    return crt, key
