import ipaddress
import unittest

from agentshield.models import Reason
from agentshield.netguard import HostError, address_block_reason, check_destination, normalize_host, parse_url


def perr(url):
    try:
        parse_url(url)
    except HostError as e:
        return e.code
    return None


class ParseUrlTests(unittest.TestCase):
    def test_normalization(self):
        p = parse_url("HTTPS://Docs.Example.COM./a/b?x=1#frag")
        self.assertEqual((p.scheme, p.host, p.port, p.target), ("https", "docs.example.com", 443, "/a/b?x=1"))
        self.assertEqual(parse_url("http://a.com").target, "/")
        self.assertEqual(parse_url("http://a.com:8080/x").port, 8080)
        self.assertEqual(parse_url("http://[::1]:81/").host, "::1")

    def test_idna(self):
        self.assertEqual(normalize_host("b\u00fccher.example"), "xn--bcher-kva.example")

    def test_rejections(self):
        cases = {
            "ftp://a.com": Reason.URL_SCHEME_NOT_ALLOWED,
            "file:///etc/passwd": Reason.URL_SCHEME_NOT_ALLOWED,
            "javascript:alert(1)": Reason.URL_SCHEME_NOT_ALLOWED,
            "//a.com/x": Reason.URL_SCHEME_NOT_ALLOWED,
            "https://user:pw@a.com/": Reason.URL_USERINFO,
            "https://a.com@evil.com/": Reason.URL_USERINFO,
            "http://a.com:99999/": Reason.URL_INVALID,
            "http://a.com:abc/": Reason.URL_INVALID,
            "http:///x": Reason.URL_INVALID,
            "http://exa%6dple.com/": Reason.URL_INVALID,
            "http://a.com\\@evil.com/": Reason.URL_INVALID,
            "http://a .com/": Reason.URL_INVALID,
            "http://-bad-.com/": Reason.URL_INVALID,
            "http://a..com/": Reason.URL_INVALID,
        }
        for url, expected in cases.items():
            self.assertEqual(perr(url), expected, url)

    def test_ambiguous_numeric_hosts(self):
        for url in ["http://2130706433/", "http://0x7f000001/", "http://0x7f.0.0.1/", "http://127.1/", "http://017700000001/", "http://0177.0.0.1/", "http://1.1.1/"]:
            self.assertEqual(perr(url), Reason.HOST_AMBIGUOUS_IP, url)

    def test_ip_literals(self):
        self.assertTrue(parse_url("http://93.184.216.34/").is_ip)
        self.assertTrue(parse_url("http://[2001:db8::1]/").is_ip)
        self.assertEqual(perr("http://[fe80::1%25eth0]/"), Reason.HOST_AMBIGUOUS_IP)


class AddressTests(unittest.TestCase):
    def blocked(self, a, allow_private=False):
        return address_block_reason(ipaddress.ip_address(a), allow_private=allow_private) is not None

    def test_always_blocked_even_when_private_allowed(self):
        for a in ["169.254.169.254", "169.254.0.1", "fe80::1", "224.0.0.1", "0.0.0.0", "::", "fd00:ec2::254", "100.100.100.200", "ff02::1"]:
            self.assertTrue(self.blocked(a, True), a)

    def test_private_blocked_by_default(self):
        for a in ["127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "100.64.0.1", "::1", "fc00::1", "192.0.0.1", "198.18.0.1"]:
            self.assertTrue(self.blocked(a), a)
            self.assertFalse(self.blocked(a, True) and a in ("127.0.0.1", "10.0.0.1"), a)

    def test_public_allowed(self):
        for a in ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"]:
            self.assertFalse(self.blocked(a), a)

    def test_embedded_ipv4_forms_are_unwrapped(self):
        self.assertTrue(self.blocked("::ffff:127.0.0.1"))
        self.assertTrue(self.blocked("::ffff:10.0.0.1"))
        self.assertTrue(self.blocked("::ffff:169.254.169.254", True))
        self.assertTrue(self.blocked("64:ff9b::7f00:1"))  # NAT64 -> 127.0.0.1
        self.assertTrue(self.blocked("64:ff9b::a9fe:a9fe", True))  # NAT64 -> metadata
        self.assertTrue(self.blocked("2002:7f00:1::1"))  # 6to4 -> 127.0.0.1
        self.assertTrue(self.blocked("2001:0:4136:e378:8000:63bf:3fff:fdd2"))  # Teredo
        self.assertTrue(self.blocked("::7f00:1"))  # IPv4-compatible
        self.assertFalse(self.blocked("::ffff:8.8.8.8"))


class DestinationTests(unittest.TestCase):
    KW = dict(allowed_schemes=("https",), allowed_hosts=("docs.example.com",), allowed_ports=(443,), block_private=True)

    def chk(self, url, resolver):
        return check_destination(parse_url(url), resolver=resolver, **self.KW)

    def test_ok_and_pinned(self):
        codes, ips = self.chk("https://docs.example.com/x", lambda h, p: ["93.184.216.34"])
        self.assertEqual((codes, ips), ([], ["93.184.216.34"]))

    def test_allowlists(self):
        r = lambda h, p: ["93.184.216.34"]  # noqa: E731
        self.assertEqual(self.chk("https://evil.com/", r)[0], [Reason.HOST_NOT_ALLOWED])
        self.assertEqual(self.chk("http://docs.example.com/", r)[0], [Reason.URL_SCHEME_NOT_ALLOWED, Reason.PORT_NOT_ALLOWED])
        self.assertEqual(self.chk("https://docs.example.com:8443/", r)[0], [Reason.PORT_NOT_ALLOWED])
        self.assertEqual(self.chk("https://sub.docs.example.com/", r)[0], [Reason.HOST_NOT_ALLOWED])
        self.assertEqual(self.chk("https://docs.example.com.evil.com/", r)[0], [Reason.HOST_NOT_ALLOWED])

    def test_dns_to_private_or_mixed_is_blocked(self):
        self.assertEqual(self.chk("https://docs.example.com/", lambda h, p: ["127.0.0.1"])[0], [Reason.ADDRESS_BLOCKED])
        self.assertEqual(self.chk("https://docs.example.com/", lambda h, p: ["93.184.216.34", "10.0.0.5"])[0], [Reason.ADDRESS_BLOCKED])
        self.assertEqual(self.chk("https://docs.example.com/", lambda h, p: ["::ffff:7f00:1"])[0], [Reason.ADDRESS_BLOCKED])

    def test_dns_failure_modes_fail_closed(self):
        def boom(h, p):
            raise OSError("no dns")

        self.assertEqual(self.chk("https://docs.example.com/", boom)[0], [Reason.DNS_FAILURE])
        self.assertEqual(self.chk("https://docs.example.com/", lambda h, p: [])[0], [Reason.DNS_FAILURE])
        self.assertEqual(self.chk("https://docs.example.com/", lambda h, p: ["not-an-ip"])[0], [Reason.DNS_FAILURE])

    def test_ip_literal_host_needs_allowlist_and_public(self):
        kw = dict(self.KW, allowed_hosts=("127.0.0.1", "93.184.216.34"))
        no_dns = lambda h, p: self.fail("must not resolve IP literals")  # noqa: E731
        self.assertEqual(check_destination(parse_url("https://127.0.0.1/"), resolver=no_dns, **kw)[0], [Reason.ADDRESS_BLOCKED])
        self.assertEqual(check_destination(parse_url("https://93.184.216.34/"), resolver=no_dns, **kw), ([], ["93.184.216.34"]))
        self.assertEqual(check_destination(parse_url("https://8.8.8.8/"), resolver=no_dns, **kw)[0], [Reason.HOST_NOT_ALLOWED])


class RedactUrlTests(unittest.TestCase):
    def test_redact_url_strips_credentials_and_query(self):
        from agentshield.adapters.http_fetch import redact_url
        self.assertEqual(redact_url("https://example.com/path?token=secret#frag"), "https://example.com/path?[redacted]")
        self.assertEqual(redact_url("https://user:pass@example.com/path?token=secret#frag"), "https://[redacted]@example.com/path")
        self.assertNotIn("secret", redact_url("https://user:pass@example.com/path?token=secret#frag"))
        self.assertEqual(redact_url("http://example.com/clean"), "http://example.com/clean")


if __name__ == "__main__":
    unittest.main()
