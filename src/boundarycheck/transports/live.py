"""The live transport (docs/contract.md s5, docs/remote-live-design.md): loopback over http, or ONE
declared remote host over verified https.

Every rule here is a property of THIS tool. None of it replaces network controls the operator must
provide; a container or network ACL outside the process is the supported containment.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
import time
import zlib
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any, Final

import httpx

from boundarycheck import __version__
from boundarycheck.config import Config
from boundarycheck.model import EgressViolation, Observation, PolicyRefusal, TransportUnavailable
from boundarycheck.netcheck import (
    AddressRefused,
    EgressPolicy,
    NotLoopback,
    parse_address,
    parse_loopback_base_url,
    parse_target_url,
)

READ_METHODS: Final = frozenset({"GET", "HEAD"})
_TOKEN = re.compile(r"^[\x21-\x7e]{8,4096}$")
_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{0,255}$")


def _system_resolver(host: str) -> list[str]:
    return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})


def valid_path(path: str) -> bool:
    return bool(_PATH.fullmatch(path)) and "//" not in path and not any(p in {".", ".."} for p in path.split("/"))


def verify_peer(response: Any, expected_ip: str, policy: EgressPolicy | None = None) -> None:
    """The address we actually connected to must be the address that was checked, and must still pass
    the policy (loopback for a loopback run, the remote address policy otherwise)."""
    stream = response.extensions.get("network_stream")
    info = stream.get_extra_info("server_addr") if stream is not None else None
    peer = info[0] if info else None
    remote = policy is not None and policy.is_remote
    if not isinstance(peer, str):
        raise EgressViolation("the connected peer could not be verified")
    try:
        (policy or EgressPolicy.loopback("", 0)).check(peer)
    except AddressRefused:
        raise EgressViolation(
            "the connected peer is not acceptable" if remote else "the connected peer could not be verified as loopback"
        ) from None
    if ipaddress.ip_address(peer) != ipaddress.ip_address(expected_ip):
        raise EgressViolation("the connected peer is not the address that was checked")


def tls_context(ca_bundle: Path | None) -> ssl.SSLContext:
    """TLS 1.2 or newer, certificate and host name ALWAYS verified. A `ca_bundle` ADDS trust for a
    private authority; nothing here can turn verification off."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca_bundle is not None:
        try:
            context.load_verify_locations(cafile=str(ca_bundle))
        except (OSError, ssl.SSLError):
            raise TransportUnavailable("ca_bundle could not be read as a PEM certificate file") from None
    return context


class _TooLarge(Exception):
    pass


class _Unreadable(Exception):
    pass


async def _read_bounded(response: httpx.Response, cap: int) -> bytes:
    """Read the DECODED body, never more than `cap` bytes, whatever the encoding claims."""
    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if encoding in ("", "identity"):
        decoder = None
    elif encoding in ("gzip", "x-gzip"):
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        decoder = zlib.decompressobj()
    else:
        raise _Unreadable
    out = bytearray()
    raw_total = 0
    async for chunk in response.aiter_raw():
        raw_total += len(chunk)
        if raw_total > cap:
            raise _TooLarge
        if decoder is None:
            out += chunk
        else:
            try:
                data = decoder.decompress(chunk, cap - len(out) + 1)
                while decoder.unconsumed_tail and len(out) + len(data) <= cap:
                    out += data
                    data = decoder.decompress(decoder.unconsumed_tail, cap - len(out) + 1)
                out += data
            except zlib.error:
                raise _Unreadable from None
        if len(out) > cap:
            raise _TooLarge
    return bytes(out)


class LiveTransport:
    def __init__(  # noqa: PLR0913 - keyword-only limits, an injected clock, resolver and policy
        self,
        base_url: str,
        *,
        credentials: Mapping[str, str],
        environ: Mapping[str, str],
        rate_limit_rps: float = 10.0,
        timeout: float = 10.0,
        max_response_bytes: int = 1_048_576,
        resolver: Callable[[str], list[str]] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        egress: EgressPolicy | None = None,
    ) -> None:
        if egress is None:
            try:
                host, port = parse_loopback_base_url(base_url)
            except NotLoopback as exc:
                raise EgressViolation(str(exc)) from None
            egress = EgressPolicy.loopback(host, port)
        else:
            try:
                scheme, host, port, _remote = parse_target_url(base_url)
            except NotLoopback as exc:
                raise EgressViolation(str(exc)) from None
            if (scheme, host, port) != (egress.scheme, egress.host, egress.port):
                raise EgressViolation("the base_url is not the host the egress policy was built for")
        self._policy = egress
        self._host = host
        self._port = port
        self.name = "live:remote" if egress.is_remote else "live:loopback"
        # always a real, verifying context (a loopback run is plain http and never uses it)
        context = tls_context(egress.ca_bundle if egress.is_remote else None)
        self._ip = self._pin(egress, host, resolver or _system_resolver)
        if egress.is_remote:
            self.name = f"live:remote:{host}:{port}@{self._ip}"
        bracket = f"[{self._ip}]" if ":" in self._ip else self._ip
        self._origin = f"{egress.scheme}://{bracket}:{port}"
        shown = f"[{host}]" if ":" in host else host
        self._host_header = shown if (egress.is_remote and port == 443) else f"{shown}:{port}"
        self._tokens = {p: environ[v] for p, v in credentials.items() if v in environ and _TOKEN.fullmatch(environ[v])}
        self._interval = 1.0 / rate_limit_rps
        self._timeout = timeout
        self._cap = max_response_bytes
        self._monotonic = monotonic
        self._sleep = sleep
        self._next_slot = 0.0
        self._client = httpx.AsyncClient(
            trust_env=False,  # no proxy variables, no netrc, no ambient configuration
            follow_redirects=False,
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
            verify=context,  # ALWAYS verified: see tls_context; there is no way to pass False
        )

    @staticmethod
    def _pin(policy: EgressPolicy, host: str, resolver: Callable[[str], list[str]]) -> str:
        """The one address we will connect to. A name is resolved ONCE, here, and EVERY address it
        resolves to must pass the policy; the connection then goes to the checked literal, so there is
        no second lookup to rebind."""
        try:
            parse_address(host)
        except AddressRefused:
            literal = False
        else:
            literal = True
        if literal:
            try:
                policy.check(host)
            except AddressRefused as exc:
                raise EgressViolation(str(exc)) from None
            return host
        try:
            addresses = resolver(host)
        except OSError:
            raise EgressViolation("the host name could not be resolved") from None
        if not addresses:
            raise EgressViolation("the host name did not resolve to any address")
        for address in addresses:
            try:
                policy.check(address)
            except AddressRefused as exc:
                if policy.is_remote:
                    raise EgressViolation(f"the host name resolves to an address that may not be used: {exc}") from None
                raise EgressViolation("the host name does not resolve only to loopback addresses") from None
        return sorted(addresses, key=lambda a: ":" in a)[0]

    @property
    def pinned_address(self) -> str:
        return self._ip

    def describe(self) -> str:
        """One line saying exactly where requests will go, for the operator to read first."""
        shown = f"{self._policy.scheme}://{self._host}:{self._port}"
        if self._policy.is_remote:
            return f"{shown} -> {self._ip} (the name was resolved once; connections go to this address)"
        return f"{shown} (loopback, address {self._ip})"

    def __repr__(self) -> str:
        return f"LiveTransport(origin={self._origin!r})"

    @classmethod
    def from_config(
        cls, config: Config, environ: Mapping[str, str], *, resolver: Callable[[str], list[str]] | None = None
    ) -> LiveTransport:
        target = config.scope.target
        if target.base_url is None:
            raise TransportUnavailable("the config has no scope.target.base_url, which the live transport needs")
        credentials = {k: p.credential.env for k, p in config.principals.items() if p.credential and p.credential.env}
        egress: EgressPolicy | None = None
        if target.is_remote:
            _scheme, host, port, _remote = parse_target_url(target.base_url)
            egress = EgressPolicy.remote(
                host=host, port=port, allowed_networks=target.allowed_networks,
                ca_bundle=Path(target.ca_bundle) if target.ca_bundle else None,
            )  # fmt: skip
        return cls(
            target.base_url, credentials=credentials, environ=environ, rate_limit_rps=target.effective_rate_limit_rps,
            timeout=target.timeout_seconds, max_response_bytes=target.max_response_bytes, resolver=resolver,
            egress=egress,
        )  # fmt: skip

    def has_credential(self, principal: str | None) -> bool:
        return principal is None or principal in self._tokens

    def secrets(self) -> list[str]:
        return list(self._tokens.values())

    async def _pace(self) -> None:
        now = self._monotonic()
        slot = max(now, self._next_slot)
        self._next_slot = slot + self._interval
        if slot > now:
            await self._sleep(slot - now)

    #: The live transport cannot report or restore the target's state, so it is never sent a write.
    state_aware = False

    async def send(self, method: str, path: str, principal: str | None, body: bytes | None = None) -> Observation:
        if method not in READ_METHODS:
            raise PolicyRefusal(f"method {method[:10]!r} is not allowed: the live transport sends GET and HEAD only")
        if body is not None:
            raise PolicyRefusal("the live transport never sends a request body")
        if not valid_path(path):
            raise PolicyRefusal("the request path is not acceptable")
        if principal is not None and principal not in self._tokens:
            raise PolicyRefusal(f"no usable credential for principal '{principal[:40]}'")
        await self._pace()
        headers = {
            "Host": self._host_header, "Accept": "application/json", "Accept-Encoding": "identity",
            "User-Agent": f"boundarycheck/{__version__}",
        }  # fmt: skip
        if principal is not None:
            headers["Authorization"] = f"Bearer {self._tokens[principal]}"
        try:
            async with asyncio.timeout(self._timeout):
                return await self._exchange(method, self._origin + path, headers)
        except (TimeoutError, httpx.TimeoutException):
            return Observation(status=None, error="timeout")
        except httpx.TransportError:
            return Observation(status=None, error="connection")
        finally:
            self._client.cookies.clear()  # never replay a cookie the target set

    async def _exchange(self, method: str, url: str, headers: dict[str, str]) -> Observation:
        extensions: dict[str, Any] = {}
        if self._policy.is_remote and not self._is_literal_host():
            extensions["sni_hostname"] = self._host  # the certificate is checked against THIS name
        async with self._client.stream(method, url, headers=headers, extensions=extensions) as response:
            if self._policy.is_remote:
                verify_peer(response, self._ip, self._policy)
            else:
                verify_peer(response, self._ip)
            if response.is_redirect:
                return Observation(status=None, error="redirect")
            seen = {k.lower(): v for k, v in response.headers.items()}
            try:
                body = await _read_bounded(response, self._cap)
            except _TooLarge:
                return Observation(status=response.status_code, headers=seen, error="body_too_large")
            except _Unreadable:
                return Observation(status=response.status_code, headers=seen, error="unreadable")
            return Observation(status=response.status_code, headers=seen, body=body)

    def _is_literal_host(self) -> bool:
        try:
            parse_address(self._host)
        except AddressRefused:
            return False
        return True

    async def aclose(self) -> None:
        await self._client.aclose()
