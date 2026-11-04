"""Hostname, IP and URL validation helpers for SSRF-resistant fetching.

Nothing here performs network I/O except ``system_resolver``.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Reason

Resolver = Callable[[str, int], Sequence[str]]

_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
# decimal / octal / hex / short forms that OS resolvers (inet_aton) accept but ipaddress rejects
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$")

_METADATA = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}
_PRIVATE_OK = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "::1/128", "fc00::/7")
]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")
_V4_COMPAT = ipaddress.ip_network("::/96")


class HostError(ValueError):
    """Raised with a Reason code in ``.code``."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


def parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return an address for canonical IP literals; raise on ambiguous numeric forms."""
    h = host
    if "%" in h:
        raise HostError(Reason.HOST_AMBIGUOUS_IP, "IPv6 zone identifiers are not allowed")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
        try:
            return ipaddress.IPv6Address(h)
        except ValueError:
            raise HostError(Reason.URL_INVALID, "invalid IPv6 literal") from None
    if ":" in h:
        try:
            return ipaddress.IPv6Address(h)
        except ValueError:
            raise HostError(Reason.URL_INVALID, "invalid host") from None
    try:
        return ipaddress.IPv4Address(h)
    except ValueError:
        pass
    if _NUMERIC_HOST.match(h.lower()):
        raise HostError(Reason.HOST_AMBIGUOUS_IP, "non-canonical numeric host")
    return None


def normalize_host(host: str) -> str:
    """Normalize a hostname or IP literal: lower-case, IDNA, no trailing dot.

    Raises ValueError for invalid or ambiguous hosts.
    """
    if not isinstance(host, str) or not host:
        raise ValueError("empty host")
    h = host.strip()
    if h != host or any(c.isspace() for c in h):
        raise ValueError("whitespace in host")
    try:
        ip = parse_ip_literal(h)
    except HostError as exc:
        raise ValueError(str(exc)) from None
    if ip is not None:
        return str(ip)
    h = h.rstrip(".") if h.endswith(".") and not h.endswith("..") else h
    try:
        h = h.encode("idna").decode("ascii") if not h.isascii() else h
    except UnicodeError:
        raise ValueError("invalid internationalized hostname") from None
    h = h.lower()
    if len(h) > 253 or not h:
        raise ValueError("invalid hostname length")
    for label in h.split("."):
        if not _LABEL.match(label):
            raise ValueError(f"invalid hostname label {label!r}")
    return h


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _SIXTOFOUR:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return None


def address_block_reason(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool = False
) -> str | None:
    """Return Reason.ADDRESS_BLOCKED if ``ip`` must not be contacted, else None."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in _TEREDO or (ip in _V4_COMPAT and int(ip) > 1):
            return Reason.ADDRESS_BLOCKED
        inner = _embedded_v4(ip)
        if inner is not None:
            return address_block_reason(inner, allow_private=allow_private)
    if ip in _METADATA or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return Reason.ADDRESS_BLOCKED
    if ip.is_global:
        return None
    if allow_private and any(ip in net for net in _PRIVATE_OK if net.version == ip.version):
        return None
    return Reason.ADDRESS_BLOCKED


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


@dataclass(frozen=True)
class ParsedURL:
    scheme: str
    host: str  # normalized, no brackets
    port: int
    target: str  # path + query as sent on the wire
    is_ip: bool

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        default = 443 if self.scheme == "https" else 80
        return host if self.port == default else f"{host}:{self.port}"

    def url(self) -> str:
        return f"{self.scheme}://{self.netloc}{self.target}"


def parse_url(url: str) -> ParsedURL:
    """Parse and normalize an http(s) URL. Raises HostError(code)."""
    if any(c.isspace() for c in url) or "\\" in url:
        raise HostError(Reason.URL_INVALID, "whitespace or backslash in URL")
    try:
        parts = urlsplit(url)
    except ValueError:
        raise HostError(Reason.URL_INVALID, "unparseable URL") from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise HostError(Reason.URL_SCHEME_NOT_ALLOWED, f"scheme {scheme!r}")
    if "@" in parts.netloc:
        raise HostError(Reason.URL_USERINFO, "credentials in URL")
    try:
        port = parts.port
        raw_host = parts.hostname
    except ValueError:
        raise HostError(Reason.URL_INVALID, "invalid port") from None
    if not raw_host:
        raise HostError(Reason.URL_INVALID, "missing host")
    if "%" in raw_host and ":" not in raw_host:
        raise HostError(Reason.URL_INVALID, "percent-encoding in host")
    try:
        host = normalize_host(f"[{raw_host}]" if ":" in raw_host else raw_host)
    except ValueError as exc:
        msg = str(exc)
        code = Reason.HOST_AMBIGUOUS_IP if "numeric" in msg or "zone" in msg else Reason.URL_INVALID
        raise HostError(code, msg) from None
    is_ip = parse_ip_literal(f"[{host}]" if ":" in host else host) is not None
    if port is None:
        port = 443 if scheme == "https" else 80
    path = parts.path or "/"
    target = path + (f"?{parts.query}" if parts.query else "")
    return ParsedURL(scheme, host, port, target, is_ip)


def check_destination(
    parsed: ParsedURL,
    *,
    allowed_schemes: Sequence[str],
    allowed_hosts: Sequence[str],
    allowed_ports: Sequence[int],
    block_private: bool,
    resolver: Resolver,
) -> tuple[list[str], list[str]]:
    """Validate a parsed URL against constraints.

    Returns ``(deny_codes, pinned_ips)``. ``pinned_ips`` are validated addresses
    the caller must connect to (never re-resolve the hostname afterwards).
    """
    codes: list[str] = []
    if parsed.scheme not in allowed_schemes:
        codes.append(Reason.URL_SCHEME_NOT_ALLOWED)
    if parsed.port not in allowed_ports:
        codes.append(Reason.PORT_NOT_ALLOWED)
    if parsed.host not in allowed_hosts:
        codes.append(Reason.HOST_NOT_ALLOWED)
    if codes:
        return codes, []
    if parsed.is_ip:
        ip = ipaddress.ip_address(parsed.host)
        if address_block_reason(ip, allow_private=not block_private):
            return [Reason.ADDRESS_BLOCKED], []
        return [], [str(ip)]
    try:
        addrs = list(resolver(parsed.host, parsed.port))
    except Exception:  # noqa: BLE001 - any resolver failure fails closed
        return [Reason.DNS_FAILURE], []
    if not addrs:
        return [Reason.DNS_FAILURE], []
    pinned: list[str] = []
    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return [Reason.DNS_FAILURE], []
        if address_block_reason(ip, allow_private=not block_private):
            return [Reason.ADDRESS_BLOCKED], []  # one bad address poisons the set
        pinned.append(str(ip))
    return [], pinned
