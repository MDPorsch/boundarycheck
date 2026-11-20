"""The loopback-only live transport (docs/contract.md s5).

Every rule here is a property of THIS tool. None of it replaces network controls the operator must
provide; a container or network ACL outside the process is the supported containment.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
import zlib
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Final

import httpx

from boundarycheck import __version__
from boundarycheck.config import Config
from boundarycheck.model import EgressViolation, Observation, PolicyRefusal, TransportUnavailable
from boundarycheck.netcheck import NotLoopback, is_loopback_ip, parse_loopback_base_url

READ_METHODS: Final = frozenset({"GET", "HEAD"})
_TOKEN = re.compile(r"^[\x21-\x7e]{8,4096}$")
_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{0,255}$")


def _system_resolver(host: str) -> list[str]:
    return sorted({str(info[4][0]) for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})


def valid_path(path: str) -> bool:
    return bool(_PATH.fullmatch(path)) and "//" not in path and not any(p in {".", ".."} for p in path.split("/"))


def verify_peer(response: Any, expected_ip: str) -> None:
    """The address we actually connected to must be the loopback address that was checked."""
    stream = response.extensions.get("network_stream")
    info = stream.get_extra_info("server_addr") if stream is not None else None
    peer = info[0] if info else None
    if not isinstance(peer, str) or not is_loopback_ip(peer):
        raise EgressViolation("the connected peer could not be verified as loopback")
    if ipaddress.ip_address(peer) != ipaddress.ip_address(expected_ip):
        raise EgressViolation("the connected peer is not the address that was checked")


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
    name = "live:loopback"

    def __init__(  # noqa: PLR0913 - keyword-only limits and injected clock/resolver
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
    ) -> None:
        try:
            host, port = parse_loopback_base_url(base_url)
        except NotLoopback as exc:
            raise EgressViolation(str(exc)) from None
        self._ip = self._pin(host, resolver or _system_resolver)
        bracket = f"[{self._ip}]" if ":" in self._ip else self._ip
        self._origin = f"http://{bracket}:{port}"
        self._host_header = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
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
        )

    @staticmethod
    def _pin(host: str, resolver: Callable[[str], list[str]]) -> str:
        """The one address we will connect to. A name is resolved ONCE, here, and every address it
        resolves to must be loopback; the connection then goes to the checked literal."""
        if is_loopback_ip(host):
            return host
        try:
            addresses = resolver(host)
        except OSError:
            raise EgressViolation("the host name could not be resolved") from None
        if not addresses or not all(is_loopback_ip(a) for a in addresses):
            raise EgressViolation("the host name does not resolve only to loopback addresses")
        return sorted(addresses, key=lambda a: ":" in a)[0]

    def __repr__(self) -> str:
        return f"LiveTransport(origin={self._origin!r})"

    @classmethod
    def from_config(cls, config: Config, environ: Mapping[str, str]) -> LiveTransport:
        target = config.scope.target
        if target.base_url is None:
            raise TransportUnavailable("the config has no scope.target.base_url, which the live transport needs")
        credentials = {k: p.credential.env for k, p in config.principals.items() if p.credential and p.credential.env}
        return cls(
            target.base_url, credentials=credentials, environ=environ, rate_limit_rps=target.rate_limit_rps,
            timeout=target.timeout_seconds, max_response_bytes=target.max_response_bytes,
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

    async def send(self, method: str, path: str, principal: str | None) -> Observation:
        if method not in READ_METHODS:
            raise PolicyRefusal(f"method {method[:10]!r} is not allowed: v0.1 sends GET and HEAD only")
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
        async with self._client.stream(method, url, headers=headers) as response:
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

    async def aclose(self) -> None:
        await self._client.aclose()
