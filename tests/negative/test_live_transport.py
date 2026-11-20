"""The loopback-only live transport against a real (and hostile) HTTP server (docs/contract.md s5).

Every claim has a test that fails if the claim is false: the server records what it receives, so
"never sent" is observed, not assumed."""

from __future__ import annotations

import socket
import types
from typing import Any

import pytest

from tests.support import FakeServer, fake_server, gzip_bomb, slow

pytestmark = pytest.mark.milestone("S1")

TOKEN = "tok-" + "Zq81xKd02LmPq77AbCd"


def _make(base_url: str, **kw: Any) -> Any:
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    kw.setdefault("credentials", {"alice": "BC_A"})
    kw.setdefault("environ", {"BC_A": TOKEN})
    kw.setdefault("resolver", lambda host: ["127.0.0.1"])
    return LiveTransport(base_url, **kw)


async def _send(server: FakeServer, path: str = "/v1/x", method: str = "GET", principal: str | None = "alice", **kw: Any) -> Any:
    transport = _make(server.base_url, **kw)
    try:
        return await transport.send(method, path, principal)
    finally:
        await transport.aclose()


async def test_a_get_carries_the_bearer_token_identity_encoding_and_nothing_else_ambient() -> None:
    with fake_server() as server:
        server.json("/v1/x", {"ok": 1})
        obs = await _send(server)
        assert obs.status == 200 and obs.error is None and b'"ok"' in obs.body
        headers = {k.lower(): v for k, v in server.requests[0]["headers"].items()}
        assert headers["authorization"] == f"Bearer {TOKEN}"
        assert headers["accept-encoding"] == "identity"
        assert "cookie" not in headers and "proxy-authorization" not in headers
        assert headers["user-agent"].startswith("boundarycheck/")


async def test_the_anonymous_principal_sends_no_authorization_header() -> None:
    with fake_server() as server:
        server.json("/v1/x", {})
        await _send(server, principal=None)
        assert "authorization" not in {k.lower() for k in server.requests[0]["headers"]}


async def test_head_is_allowed() -> None:
    with fake_server() as server:
        server.json("/v1/x", {})
        assert (await _send(server, method="HEAD")).status == 200


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT", "get"])
async def test_a_non_read_method_is_refused_before_a_socket_is_opened(method: str) -> None:
    from boundarycheck.model import PolicyRefusal  # noqa: PLC0415

    with fake_server() as server, pytest.raises(PolicyRefusal):
        await _send(server, method=method)
    assert server.requests == []


@pytest.mark.parametrize(
    "path",
    ["//evil.invalid/x", "/../x", "/a/../b", "/a b", "http://evil.invalid/", "x", "", "/a?b=1", "/a#f", "/a\\b", "/%2e%2e/x", "/a\n/b", "/a\r\nHost: evil", "/" + "a" * 300, "/é"],
)
async def test_a_path_that_could_smuggle_an_authority_traversal_or_header_is_refused(path: str) -> None:
    from boundarycheck.model import PolicyRefusal  # noqa: PLC0415

    with fake_server() as server, pytest.raises(PolicyRefusal):
        await _send(server, path=path)
    assert server.requests == []


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_a_redirect_is_never_followed(status: int) -> None:
    with fake_server() as server:
        server.routes["/r"] = (status, {"location": f"{server.base_url}/target", "content-type": "text/plain"}, b"")
        server.json("/target", {"followed": True})
        obs = await _send(server, path="/r")
        assert obs.error == "redirect"
        assert [r["path"] for r in server.requests] == ["/r"]


async def test_a_redirect_to_another_host_is_not_followed_either() -> None:
    with fake_server() as server:
        server.routes["/r"] = (302, {"location": "http://203.0.113.9/steal", "content-type": "text/plain"}, b"")
        obs = await _send(server, path="/r")
        assert obs.error == "redirect"


async def test_a_response_over_the_size_cap_is_incomplete_not_read_to_the_end() -> None:
    with fake_server() as server:
        server.routes["/big"] = (200, {"content-type": "application/json"}, b"0" * (3 * 1024 * 1024))
        obs = await _send(server, path="/big", max_response_bytes=100_000)
        assert obs.error == "body_too_large" and len(obs.body) <= 100_000


async def test_a_decompression_bomb_is_capped_on_the_decoded_size() -> None:
    with fake_server() as server:
        server.routes["/bomb"] = gzip_bomb(40 * 1024 * 1024)
        obs = await _send(server, path="/bomb", max_response_bytes=100_000)
        assert obs.error == "body_too_large" and len(obs.body) <= 100_000


async def test_a_slow_server_is_a_timeout_never_a_pass() -> None:
    with fake_server() as server:
        server.routes["/slow"] = slow(2.0)
        obs = await _send(server, path="/slow", timeout=0.3)
        assert obs.error == "timeout" and obs.status is None


async def test_a_refused_connection_is_reported_as_a_connection_error() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    transport = _make(f"http://127.0.0.1:{port}")
    obs = await transport.send("GET", "/v1/x", "alice")
    assert obs.error == "connection" and obs.status is None
    await transport.aclose()


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
async def test_ordinary_statuses_are_returned_as_observed(status: int) -> None:
    with fake_server() as server:
        server.json("/v1/x", {"code": "c"}, status=status)
        obs = await _send(server)
        assert obs.status == status and obs.error is None


async def test_proxy_environment_variables_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_server() as target, fake_server() as proxy:
        target.json("/v1/x", {"direct": True})
        for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy"):
            monkeypatch.setenv(name, proxy.base_url)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        obs = await _send(target)
        assert obs.status == 200 and len(target.requests) == 1 and proxy.requests == []


# ------------------------------------------------------------------------ the target ----
@pytest.mark.parametrize(
    "url",
    ["http://192.0.2.7:80", "http://10.1.2.3", "http://0.0.0.0:80", "http://[2001:db8::1]", "https://127.0.0.1:1", "http://example.com", "http://169.254.169.254", "http://[::ffff:10.0.0.1]"],
)
def test_a_non_loopback_target_is_refused_at_construction(url: str) -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415

    with pytest.raises(EgressViolation):
        _make(url, resolver=lambda host: ["192.0.2.7"])


@pytest.mark.parametrize("addresses", [["192.0.2.7"], ["127.0.0.1", "192.0.2.7"], ["192.0.2.7", "127.0.0.1"], [], ["::ffff:192.0.2.7"], ["169.254.169.254"]])
def test_a_name_must_resolve_only_to_loopback(addresses: list[str]) -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415

    with pytest.raises(EgressViolation):
        _make("http://localhost:8000", resolver=lambda host: addresses)


async def test_a_name_is_resolved_once_and_the_connection_goes_to_the_checked_literal() -> None:
    calls: list[str] = []

    def resolver(host: str) -> list[str]:
        calls.append(host)
        return ["127.0.0.1"] if len(calls) == 1 else ["192.0.2.7"]  # a rebinding resolver

    with fake_server() as server:
        server.json("/v1/x", {})
        transport = _make(f"http://localhost:{server.port}", resolver=resolver)
        for _ in range(3):
            assert (await transport.send("GET", "/v1/x", "alice")).status == 200
        await transport.aclose()
        assert calls == ["localhost"]
        assert {r["headers"]["Host"] for r in server.requests} == {f"localhost:{server.port}"}


# ------------------------------------------------------------------------ the peer ----
def test_the_connected_peer_must_be_the_address_that_was_checked() -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415
    from boundarycheck.transports.live import verify_peer  # noqa: PLC0415

    def response(addr: Any) -> Any:
        stream = types.SimpleNamespace(get_extra_info=lambda name: addr if name == "server_addr" else None)
        return types.SimpleNamespace(extensions={"network_stream": stream})

    verify_peer(response(("127.0.0.1", 80)), "127.0.0.1")
    for bad in (("192.0.2.1", 80), ("10.0.0.1", 80), None, ("::ffff:10.0.0.1", 80, 0, 0)):
        with pytest.raises(EgressViolation):
            verify_peer(response(bad), "127.0.0.1")
    with pytest.raises(EgressViolation):
        verify_peer(types.SimpleNamespace(extensions={}), "127.0.0.1")


async def test_every_request_is_peer_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415
    from boundarycheck.transports import live  # noqa: PLC0415

    seen: list[str] = []

    def spy(response: Any, expected: str) -> None:
        seen.append(expected)
        raise EgressViolation("peer mismatch")

    monkeypatch.setattr(live, "verify_peer", spy)
    with fake_server() as server:
        server.json("/v1/x", {})
        with pytest.raises(EgressViolation):
            await _send(server)
    assert seen == ["127.0.0.1"]


# ------------------------------------------------------------------- credentials ----
async def test_credentials_come_from_the_environment_only_and_are_never_printed() -> None:
    with fake_server() as server:
        transport = _make(server.base_url)
        assert transport.has_credential("alice") is True and transport.has_credential(None) is True
        assert transport.has_credential("bob") is False
        assert TOKEN not in repr(transport) and TOKEN not in str(transport) and TOKEN not in repr(vars(transport).keys())
        assert transport.secrets() == [TOKEN]
        await transport.aclose()


@pytest.mark.parametrize("value", ["", " ", "short", "tok with space 12345678", "tok-12345678\r\nX-Evil: 1", "tok-12345678\n", "é" * 12, "x" * 5000])
def test_an_unusable_credential_value_counts_as_no_credential(value: str) -> None:
    with fake_server() as server:
        transport = _make(server.base_url, environ={"BC_A": value})
        assert transport.has_credential("alice") is False and transport.secrets() == []


async def test_sending_as_a_principal_without_a_credential_is_refused() -> None:
    from boundarycheck.model import PolicyRefusal  # noqa: PLC0415

    with fake_server() as server, pytest.raises(PolicyRefusal):
        await _send(server, principal="bob")
    assert server.requests == []


# ------------------------------------------------------------------------- pacing ----
async def test_requests_are_paced_by_the_rate_limit() -> None:
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    with fake_server() as server:
        server.json("/v1/x", {})
        transport = _make(server.base_url, rate_limit_rps=5.0, monotonic=lambda: 100.0, sleep=fake_sleep)
        for _ in range(3):
            await transport.send("GET", "/v1/x", "alice")
        await transport.aclose()
    assert sleeps == pytest.approx([0.2, 0.4])
