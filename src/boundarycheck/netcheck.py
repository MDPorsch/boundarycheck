"""Address rules shared by the config loader and the live transport, so the two cannot disagree.

Two modes (docs/contract.md s5, docs/remote-live-design.md s4):

* **loopback** (v0.1): `http://` on 127.0.0.0/8, ::1 or `localhost`; every address must be loopback.
* **remote**: `https://` to the ONE declared host; every address it resolves to must be acceptable:
  public by default, private ranges only if the operator wrote them down, and a few ranges never.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import SplitResult, urlsplit

LOOPBACK_NAME = "localhost"
MAX_NETWORKS: Final = 32
MAX_ADDRESS_TEXT: Final = 64
V0_2_HINT = (
    "to reach a host other than loopback declare it twice (base_url and allowed_hosts), add an "
    "authorization block, and use https (docs/remote-live-design.md)"
)

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network

# Never acceptable, whatever the operator lists. Each entry says why, for the refusal message.
_NEVER: Final[tuple[tuple[_Net, str], ...]] = tuple(
    (ipaddress.ip_network(net), why)
    for net, why in (
        ("0.0.0.0/8", "the 'this network' range"),
        ("169.254.0.0/16", "link-local, where cloud metadata services live"),
        ("224.0.0.0/4", "multicast"),
        ("240.0.0.0/4", "reserved or broadcast"),
        ("fe80::/10", "link-local"),
        ("ff00::/8", "multicast"),
        ("::ffff:0:0/96", "an IPv4-mapped IPv6 address (it exists to reach an IPv4 host)"),
        ("64:ff9b::/96", "a NAT64 address (it exists to reach an IPv4 host through a gateway)"),
        ("64:ff9b:1::/48", "a NAT64 address (it exists to reach an IPv4 host through a gateway)"),
        ("2002::/16", "a 6to4 address (it embeds an IPv4 address)"),
        ("2001::/32", "a Teredo address (it embeds an IPv4 address)"),
        ("::/96", "an IPv4-compatible or unspecified IPv6 address"),
    )
)
_IPV6_LOOPBACK: Final = ipaddress.IPv6Address("::1")


class NotLoopback(ValueError):
    """The URL or address is not acceptable."""


class AddressRefused(ValueError):
    """An address may not be connected to. The message names the rule and is safe to show."""


def is_loopback_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return False  # an IPv4-mapped IPv6 address is never treated as loopback: refuse the trick
    return address.is_loopback


def _never_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if address == _IPV6_LOOPBACK:
        return None  # ::1 sits inside ::/96 but is ordinary loopback: it needs listing like 127.0.0.1
    for network, why in _NEVER:
        if address.version == network.version and address in network:
            return why
    return None


def parse_address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(text, str) or not text or len(text) > MAX_ADDRESS_TEXT:
        raise AddressRefused("not an IP address literal")
    if "%" in text:
        raise AddressRefused("an IP address with a zone id is never accepted")
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise AddressRefused("not an IP address literal") from None


def check_address(text: str, allowed_networks: Iterable[str] = ()) -> None:
    """Raise AddressRefused unless `text` may be connected to (docs/remote-live-design.md s4.3)."""
    address = parse_address(text)
    why = _never_reason(address)
    if why is not None:
        raise AddressRefused(f"{address} is never allowed: {why}")
    if address.is_global:
        return
    for network in allowed_networks:
        net = ipaddress.ip_network(network, strict=False)
        if address.version == net.version and address in net:
            return
    raise AddressRefused(
        f"{address} is not a public address; add its range to allowed_networks if it is your target's network"
    )


def validate_networks(networks: Sequence[str]) -> list[str]:
    """Check the operator's `allowed_networks` list at load time. Returns it unchanged if valid."""
    if len(networks) > MAX_NETWORKS:
        raise ValueError(f"at most {MAX_NETWORKS} ranges may be listed")
    for text in networks:
        if "/" not in text or "%" in text:
            raise ValueError("write each range with its prefix length, for example 10.20.0.0/16")
        try:
            net = ipaddress.ip_network(text, strict=True)
        except ValueError:
            raise ValueError("a listed range is not a valid network (host bits set, or a bad prefix)") from None
        for never, why in _NEVER:
            if net.version == never.version and net.overlaps(never):
                raise ValueError(f"a listed range includes addresses that are never allowed ({why})")
    return list(networks)


@dataclass(frozen=True)
class EgressPolicy:
    """Which addresses a run may connect to, and how (loopback or remote)."""

    is_remote: bool
    host: str
    port: int
    allowed_networks: tuple[str, ...] = ()
    ca_bundle: Path | None = None

    @classmethod
    def loopback(cls, host: str, port: int) -> EgressPolicy:
        return cls(is_remote=False, host=host, port=port)

    @classmethod
    def remote(
        cls, *, host: str, port: int, allowed_networks: Iterable[str] = (), ca_bundle: Path | None = None
    ) -> EgressPolicy:
        return cls(is_remote=True, host=host, port=port, allowed_networks=tuple(allowed_networks), ca_bundle=ca_bundle)

    @property
    def scheme(self) -> str:
        return "https" if self.is_remote else "http"

    def check(self, address: str) -> None:
        if not self.is_remote:
            if not is_loopback_ip(address):
                raise AddressRefused("not a loopback address")
            return
        check_address(address, self.allowed_networks)


def _split(url: str) -> tuple[SplitResult, int | None]:
    try:
        parts = urlsplit(url)
        return parts, parts.port
    except ValueError as exc:
        raise NotLoopback(f"base_url is not a valid URL ({type(exc).__name__})") from None


def _plain(parts: SplitResult) -> str:
    """The parts of a base_url every mode refuses; returns the host."""
    if parts.username is not None or parts.password is not None:
        raise NotLoopback("base_url must not contain credentials")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise NotLoopback("base_url must be only scheme, host and optional port")
    if not parts.hostname:
        raise NotLoopback("base_url has no host")
    return parts.hostname


def is_loopback_host(host: str) -> bool:
    return is_loopback_ip(host) or host == LOOPBACK_NAME


def parse_target_url(url: str) -> tuple[str, str, int, bool]:
    """(scheme, host, port, is_remote) for a base_url, or NotLoopback naming the rule it breaks."""
    parts, port = _split(url)
    host = _plain(parts)
    if is_loopback_host(host):
        if parts.scheme != "http":
            raise NotLoopback("a loopback base_url must use http://")
        return "http", host, port if port is not None else 80, False
    if parts.scheme != "https":
        raise NotLoopback(f"base_url must use https:// for any host that is not loopback; {V0_2_HINT}")
    return "https", host, port if port is not None else 443, True


def parse_loopback_base_url(url: str) -> tuple[str, int]:
    """(host, port) for a LOOPBACK base_url (the v0.1 rule). NotLoopback if it is anything else."""
    parts, port = _split(url)
    if parts.scheme != "http":
        raise NotLoopback(f"base_url must use http:// on loopback; {V0_2_HINT}")
    host = _plain(parts)
    if not is_loopback_host(host):
        raise NotLoopback(f"base_url host is not loopback; {V0_2_HINT}")
    return host, port if port is not None else 80
