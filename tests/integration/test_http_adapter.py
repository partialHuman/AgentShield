import json
import os
import socket
import ssl
import unittest

from agentshield import ActionDenied, Reason, ToolExecutionError
from agentshield.adapters import http_fetch_tool
from tests.helpers import PUBLIC_IP, LocalServer, TmpDirTestCase, make_cert


def policy(port, **over):
    rule = {
        "risk": "medium", "decision": "ALLOW", "allowed_schemes": ["http"], "allowed_hosts": ["docs.example.com"],
        "allowed_ports": [port], "timeout_seconds": 1, "max_response_bytes": 1000,
    }
    rule.update(over)
    return json.dumps({"version": 1, "tools": {"http.fetch": rule}})


class Net:
    """Fake DNS + connector: resolves to a PUBLIC ip, but really connects to the local test server."""

    def __init__(self, server_port, resolve=lambda n: [PUBLIC_IP]):
        self.server_port, self.resolve_fn = server_port, resolve
        self.resolutions, self.connections = [], []

    def resolver(self, host, port):
        self.resolutions.append(host)
        return self.resolve_fn(len(self.resolutions))

    def connector(self, ip, port, timeout):
        self.connections.append(ip)
        return socket.create_connection(("127.0.0.1", self.server_port), timeout=timeout)


class HttpAdapterTests(TmpDirTestCase):
    def setUp(self):
        super().setUp()
        self.server = LocalServer().__enter__()
        self.addCleanup(self.server.__exit__)
        self.port = self.server.port

    def build(self, net=None, **over):
        self.net = net or Net(self.port)
        sh = self.shield(policy(self.port, **over))
        self.sh = sh
        return sh.wrap(http_fetch_tool(resolver=self.net.resolver, connector=self.net.connector))

    def url(self, path, host="docs.example.com"):
        return f"http://{host}:{self.port}{path}"

    def denied(self, fetch, url):
        with self.assertRaises(ActionDenied) as cm:
            fetch(url=url)
        return cm.exception.result.reason_codes

    def err(self, fetch, url):
        with self.assertRaises(ToolExecutionError) as cm:
            fetch(url=url)
        return cm.exception.error_code

    # ---- happy path & pinning
    def test_fetch_connects_to_validated_ip_and_preserves_host_header(self):
        fetch = self.build()
        out = fetch(url=self.url("/host"))
        self.assertEqual(out["status"], 200)
        self.assertEqual(out["body"], f"docs.example.com:{self.port}")  # original Host, not the IP
        self.assertEqual(self.net.connections, [PUBLIC_IP])  # connected to the VALIDATED address
        self.assertEqual(out["url"], f"http://docs.example.com:{self.port}/host")

    def test_fetch_ok_content_type(self):
        out = self.build()(url=self.url("/ok"))
        self.assertEqual((out["body"], out["content_type"], out["redirected"]), ("ok", "text/plain", 0))

    # ---- allowlist / syntax denials (no connection attempted)
    def test_denials_make_no_connection(self):
        fetch = self.build()
        cases = {
            self.url("/ok", "evil.com"): Reason.HOST_NOT_ALLOWED,
            f"http://docs.example.com:{self.port + 1}/": Reason.PORT_NOT_ALLOWED,
            "https://docs.example.com/": Reason.URL_SCHEME_NOT_ALLOWED,
            "file:///etc/passwd": Reason.URL_SCHEME_NOT_ALLOWED,
            f"http://user:pw@docs.example.com:{self.port}/": Reason.URL_USERINFO,
            f"http://2130706433:{self.port}/": Reason.HOST_AMBIGUOUS_IP,
            f"http://127.0.0.1:{self.port}/": Reason.HOST_NOT_ALLOWED,
            f"http://docs.example.com.evil.com:{self.port}/": Reason.HOST_NOT_ALLOWED,
        }
        for url, code in cases.items():
            self.assertIn(code, self.denied(fetch, url), url)
        self.assertEqual(self.net.connections, [])
        self.assertEqual(self.server.requests, [])

    def test_decision_time_private_resolution_is_denied(self):
        fetch = self.build(net=Net(self.port, lambda n: ["127.0.0.1"]))
        self.assertEqual(self.denied(fetch, self.url("/ok")), [Reason.ADDRESS_BLOCKED])
        fetch = self.build(net=Net(self.port, lambda n: ["10.0.0.5", PUBLIC_IP]))
        self.assertEqual(self.denied(fetch, self.url("/ok")), [Reason.ADDRESS_BLOCKED])
        fetch = self.build(net=Net(self.port, lambda n: ["169.254.169.254"]))
        self.assertEqual(self.denied(fetch, self.url("/ok")), [Reason.ADDRESS_BLOCKED])
        self.assertEqual(self.server.requests, [])

    def test_dns_failure_is_denied(self):
        def boom(n):
            raise OSError("NXDOMAIN")

        self.assertEqual(self.denied(self.build(net=Net(self.port, boom)), self.url("/ok")), [Reason.DNS_FAILURE])

    # ---- DNS rebinding: the answer changes between decision-time and use-time ----
    def test_dns_rebinding_to_private_between_check_and_use_is_blocked(self):
        # 1st resolution (decision) -> public; 2nd (use-time, authoritative) -> loopback
        net = Net(self.port, lambda n: [PUBLIC_IP] if n == 1 else ["127.0.0.1"])
        fetch = self.build(net=net)
        self.assertEqual(self.err(fetch, self.url("/ok")), "DESTINATION_BLOCKED")
        self.assertEqual(net.connections, [], "must never connect to the rebound address")
        self.assertEqual(self.server.requests, [])

    def test_connection_always_uses_the_use_time_validated_address_not_the_decision_one(self):
        net = Net(self.port, lambda n: ["93.184.216.34"] if n == 1 else ["93.184.216.35"])
        fetch = self.build(net=net)
        fetch(url=self.url("/ok"))
        self.assertEqual(net.connections, ["93.184.216.35"])

    # ---- redirects ----
    def test_safe_redirect_is_followed_and_revalidated(self):
        fetch = self.build()
        out = fetch(url=self.url("/redir-ok"))
        self.assertEqual((out["body"], out["redirected"]), ("ok", 1))
        # decision-time check of the first URL, then an authoritative use-time check per hop
        self.assertEqual(len(self.net.resolutions), 3)

    def test_redirect_to_disallowed_destinations_is_blocked(self):
        fetch = self.build()
        for path in ["/redir-port", "/redir-host", "/redir-meta", "/redir-scheme"]:
            self.assertEqual(self.err(fetch, self.url(path)), "REDIRECT_BLOCKED", path)
        paths = [p for p, _ in self.server.requests]
        self.assertEqual(sorted(set(paths)), ["/redir-host", "/redir-meta", "/redir-port", "/redir-scheme"], "only the redirecting hop was contacted")

    def test_redirect_to_metadata_blocked_even_if_host_is_allowlisted_and_private_allowed(self):
        fetch = self.build(allowed_hosts=["docs.example.com", "169.254.169.254"], allowed_ports=[self.port, 80],
                           block_private_addresses=False)
        self.assertEqual(self.err(fetch, self.url("/redir-meta")), "REDIRECT_BLOCKED")

    def test_redirect_loop_is_bounded(self):
        fetch = self.build(max_redirects=2)
        self.assertEqual(self.err(fetch, self.url("/redir-loop")), "TOO_MANY_REDIRECTS")
        self.assertEqual(len(self.server.requests), 3)

    def test_redirects_not_followed_when_revalidation_disabled(self):
        fetch = self.build(revalidate_redirects=False)
        out = fetch(url=self.url("/redir-ok"))
        self.assertEqual((out["status"], out["redirected"]), (302, 0))
        self.assertEqual([p for p, _ in self.server.requests], ["/redir-ok"])

    # ---- response handling ----
    def test_response_size_limit(self):
        fetch = self.build()
        self.assertEqual(self.err(fetch, self.url("/big")), "RESPONSE_TOO_LARGE")

    def test_content_encoding_is_never_decoded(self):
        out = self.build(max_response_bytes=5000)(url=self.url("/gzip"))
        self.assertTrue(out["body"].startswith("\ufffd") or "\x1f" in out["body"] or len(out["body"]) < 1000)
        self.assertNotEqual(out["body"], "A" * 1000, "decompression would allow zip-bomb amplification")

    def test_total_timeout(self):
        fetch = self.build(timeout_seconds=0.5)
        self.assertIn(self.err(fetch, self.url("/slow")), ("TIMEOUT", "REQUEST_FAILED"))

    def test_http_error_status_is_returned_not_raised(self):
        self.assertEqual(self.build()(url=self.url("/missing"))["status"], 404)

    def test_connect_failure(self):
        net = Net(self.port)
        net.connector = lambda ip, port, timeout: (_ for _ in ()).throw(ConnectionRefusedError())
        self.assertEqual(self.err(self.build(net=net), self.url("/ok")), "CONNECT_FAILED")

    def test_proxy_environment_variables_are_ignored(self):
        old = {k: os.environ.get(k) for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY")}
        try:
            for k in old:
                os.environ[k] = "http://127.0.0.1:9"  # a dead proxy; honoring it would break the fetch
            out = self.build()(url=self.url("/ok"))
            self.assertEqual(out["body"], "ok")
        finally:
            for k, v in old.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v

    def test_query_string_is_redacted_in_audit(self):
        self.build()(url=self.url("/ok?token=SECRET123&x=1"))
        dump = str(self.sh.audit.events)
        self.assertNotIn("SECRET123", dump)
        self.assertIn("?[redacted]", dump)

    def test_credentials_in_urls_never_reach_the_audit_log(self):
        fetch = self.build()
        for bad in (f"http://admin:hunter2@docs.example.com:{self.port}/", "http://u:hunter2@[::1/x", "http://a.com\\hunter2@x/",
                    f"http://docs.example.com:{self.port}/p?password=hunter2#hunter2", "ftp://root:hunter2@h/"):
            try:
                fetch(url=bad)
            except ActionDenied:
                pass
        self.assertNotIn("hunter2", str(self.sh.audit.events))


class TlsTests(TmpDirTestCase):
    def setUp(self):
        super().setUp()
        self.cert = make_cert(self.tmp, "docs.example.com")
        if self.cert is None:
            self.skipTest("openssl CLI not available")
        self.server = LocalServer(tls_cert=self.cert).__enter__()
        self.addCleanup(self.server.__exit__)
        self.ctx = ssl.create_default_context(cafile=self.cert[0])

    def fetch_for(self, host, net_host="docs.example.com"):
        port = self.server.port
        net = Net(port)
        sh = self.shield(policy(port, allowed_schemes=["https"], allowed_hosts=[host], timeout_seconds=5))
        return sh.wrap(http_fetch_tool(resolver=net.resolver, connector=net.connector, ssl_context=self.ctx)), net

    def test_tls_verifies_certificate_against_the_original_hostname_while_connecting_to_pinned_ip(self):
        fetch, net = self.fetch_for("docs.example.com")
        out = fetch(url=f"https://docs.example.com:{self.server.port}/host")
        self.assertEqual(out["status"], 200)
        self.assertEqual(net.connections, [PUBLIC_IP])
        self.assertEqual(out["body"], f"docs.example.com:{self.server.port}")

    def test_tls_hostname_mismatch_fails(self):
        fetch, net = self.fetch_for("other.example.com")  # cert is only valid for docs.example.com
        with self.assertRaises(ToolExecutionError) as cm:
            fetch(url=f"https://other.example.com:{self.server.port}/ok")
        self.assertEqual(cm.exception.error_code, "TLS_ERROR")


if __name__ == "__main__":
    unittest.main()
