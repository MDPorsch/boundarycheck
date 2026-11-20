"""Loopback-only address rules (docs/contract.md s5), shared by the config loader and the live
transport so the two cannot disagree."""

from __future__ import annotations

import ipaddress
from urllib.parse import SplitResult, urlsplit

LOOPBACK_NAME = "localhost"
V0_2_HINT = (
    "v0.1 only talks to loopback (127.0.0.0/8, ::1 or the name 'localhost'); remote hosts arrive in "
    "v0.2 with an allowlist, an attestation and DNS-rebinding checks"
)


class NotLoopback(ValueError):
    """The URL or address is not acceptable for v0.1."""


def is_loopback_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return False  # an IPv4-mapped IPv6 address is never treated as loopback: refuse the trick
    return address.is_loopback


def parse_loopback_base_url(url: str) -> tuple[str, int]:
    """Return (host, port). Raises NotLoopback with a message that names the rule."""
    try:
        parts: SplitResult = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise NotLoopback(f"base_url is not a valid URL ({type(exc).__name__}); {V0_2_HINT}") from None
    if parts.scheme != "http":
        raise NotLoopback(f"base_url must use http:// on loopback; {V0_2_HINT}")
    if parts.username is not None or parts.password is not None:
        raise NotLoopback("base_url must not contain credentials")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise NotLoopback("base_url must be only scheme, host and optional port")
    host = parts.hostname
    if not host:
        raise NotLoopback(f"base_url has no host; {V0_2_HINT}")
    if not (is_loopback_ip(host) or host == LOOPBACK_NAME):
        raise NotLoopback(f"base_url host is not loopback; {V0_2_HINT}")
    return host, port if port is not None else 80
