"""Remote live mode, the transport (docs/remote-live-design.md s4.3 to 4.6).

Real TLS servers on 127.0.0.1 with throwaway certificates; a name such as api.test.example is mapped
to 127.0.0.1 by an injected resolver, never by the operating system. The recurring assertion is the
important one: when anything about the connection is wrong, `server.requests == []`, which means the
bearer token was never sent."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.support import FakeServer, fake_server, fake_token
from tests.support_tls import HOST, Authority, TlsServer, issue, make_authority

pytestmark = pytest.mark.milestone("R2")

TOKEN = fake_token("remote")
LOOPBACK_NET = ("127.0.0.0/8",)


def _resolver(*answers: list[str]) -> Any:
    """A resolver that records its calls and answers from `answers`, repeating the last one."""
    calls: list[str] = []

    def resolve(host: str) -> list[str]:
        calls.append(host)
        return answers[min(len(calls), len(answers)) - 1]

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


def _transport(
    base_url: str,
    *,
    ca: Path | None,
    networks: tuple[str, ...] = LOOPBACK_NET,
    resolver: Any = None,
    host: str = HOST,
    **kw: Any,
) -> Any:
    from boundarycheck.netcheck import EgressPolicy  # noqa: PLC0415
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    port = int(base_url.rsplit(":", 1)[1])
    policy = EgressPolicy.remote(host=host, port=port, allowed_networks=networks, ca_bundle=ca)
    return LiveTransport(
        base_url,
        credentials={"alice": "BC_A"},
        environ={"BC_A": TOKEN},
        resolver=resolver or _resolver(["127.0.0.1"]),
        egress=policy,
        rate_limit_rps=kw.pop("rate_limit_rps", 1000.0),
        **kw,
    )


@pytest.fixture
def pki(tmp_path: Path) -> Authority:
    return make_authority(tmp_path)


@pytest.fixture
def good_server(tmp_path: Path, pki: Authority) -> Any:
    cert, key = issue(pki, tmp_path, [HOST])
    server = TlsServer(cert, key)
    server.start()
    server.json("/v1/x", {"ok": 1})
    yield server
    server.stop()


# ----------------------------------------------------------------------- the good path ----
async def test_a_verified_https_request_carries_the_token_and_the_declared_name(
    good_server: Any, pki: Authority
) -> None:
    transport = _transport(good_server.base_url, ca=pki.pem_path)
    try:
        obs = await transport.send("GET", "/v1/x", "alice")
    finally:
        await transport.aclose()
    assert obs.status == 200 and obs.error is None and b'"ok"' in obs.body
    headers = {k.lower(): v for k, v in good_server.requests[0]["headers"].items()}
    assert headers["authorization"] == f"Bearer {TOKEN}"
    assert headers["host"] == f"{HOST}:{good_server.port}"
    assert good_server.sni == [HOST], "the TLS server name must be the declared one, not the pinned address"
    assert headers["accept-encoding"] == "identity" and "cookie" not in headers


async def test_the_name_is_resolved_once_whatever_the_second_answer_would_be(good_server: Any, pki: Authority) -> None:
    resolver = _resolver(["127.0.0.1"], ["169.254.169.254"])
    transport = _transport(good_server.base_url, ca=pki.pem_path, resolver=resolver)
    try:
        for _ in range(3):
            assert (await transport.send("GET", "/v1/x", "alice")).status == 200
    finally:
        await transport.aclose()
    assert resolver.calls == [HOST], "a second lookup is a rebinding window"


def test_an_ip_literal_target_is_pinned_without_any_lookup_and_judged_by_the_same_policy() -> None:
    """A loopback literal can only be http (the v0.1 rule), so a TLS server here cannot be reached by
    literal; the literal path is checked without a connection."""
    from boundarycheck.model import EgressViolation  # noqa: PLC0415

    def never(_host: str) -> list[str]:
        raise AssertionError("an IP literal must not be looked up")

    public = _transport("https://93.184.216.34:443", ca=None, networks=(), resolver=never, host="93.184.216.34")
    assert public.pinned_address == "93.184.216.34"
    with pytest.raises(EgressViolation):
        _transport("https://10.20.0.5:443", ca=None, networks=(), resolver=never, host="10.20.0.5")
    listed = _transport("https://10.20.0.5:443", ca=None, networks=("10.20.0.0/16",), resolver=never, host="10.20.0.5")
    assert listed.pinned_address == "10.20.0.5"
    with pytest.raises(EgressViolation):
        _transport(
            "https://169.254.169.254:443", ca=None, networks=("10.0.0.0/8",), resolver=never, host="169.254.169.254"
        )


# --------------------------------------------------------------- addresses, before a byte ----
@pytest.mark.parametrize(
    "answers",
    [
        ["169.254.169.254"],
        ["127.0.0.1", "10.0.0.1"],
        ["8.8.8.8", "169.254.169.254"],
        ["8.8.8.8", "192.168.1.5"],
        ["::ffff:8.8.8.8"],
        ["64:ff9b::808:808"],
        ["0.0.0.0"],
        ["fe80::1"],
        ["224.0.0.1"],
        [],
    ],
)
def test_a_name_with_any_unacceptable_address_is_refused_before_anything_is_sent(
    answers: list[str], good_server: Any, pki: Authority
) -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415

    networks = ("127.0.0.0/8",)  # listing loopback must not admit the private or never-allowed answers
    with pytest.raises(EgressViolation):
        _transport(good_server.base_url, ca=pki.pem_path, networks=networks, resolver=_resolver(answers))
    assert good_server.requests == []


def test_a_resolution_error_is_a_clear_refusal() -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415

    def failing(_host: str) -> list[str]:
        raise OSError("no such host")

    with pytest.raises(EgressViolation, match="resolved"):
        _transport(f"https://{HOST}:443", ca=None, resolver=failing)


def test_public_addresses_need_no_listing_and_the_pinned_one_is_exposed() -> None:
    transport = _transport(
        f"https://{HOST}:443",
        ca=None,
        networks=(),
        resolver=_resolver(["93.184.216.34", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"]),
    )
    assert transport.pinned_address == "93.184.216.34"  # IPv4 first, as before
    assert "93.184.216.34" in transport.describe() and HOST in transport.describe()


def test_a_transport_refuses_a_base_url_that_is_not_its_declared_host() -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415

    with pytest.raises(EgressViolation):
        _transport("https://other.test.example:443", ca=None, host=HOST)


# ----------------------------------------------------------------------------- TLS, always ----
async def test_an_untrusted_certificate_authority_ends_the_request_and_no_token_is_sent(good_server: Any) -> None:
    transport = _transport(good_server.base_url, ca=None)  # the test CA is not in any trust store
    try:
        obs = await transport.send("GET", "/v1/x", "alice")
    finally:
        await transport.aclose()
    assert obs.status is None and obs.error == "connection"
    assert good_server.requests == []


async def test_a_certificate_for_another_name_is_refused(tmp_path: Path, pki: Authority) -> None:
    cert, key = issue(pki, tmp_path, ["other.test.example"])
    server = TlsServer(cert, key)
    server.start()
    server.json("/v1/x", {})
    try:
        transport = _transport(server.base_url, ca=pki.pem_path)
        try:
            obs = await transport.send("GET", "/v1/x", "alice")
        finally:
            await transport.aclose()
        assert obs.error == "connection" and server.requests == []
    finally:
        server.stop()


async def test_an_expired_certificate_is_refused(tmp_path: Path, pki: Authority) -> None:
    cert, key = issue(pki, tmp_path, [HOST], not_before_days=-30, not_after_days=-1)
    server = TlsServer(cert, key)
    server.start()
    server.json("/v1/x", {})
    try:
        transport = _transport(server.base_url, ca=pki.pem_path)
        try:
            obs = await transport.send("GET", "/v1/x", "alice")
        finally:
            await transport.aclose()
        assert obs.error == "connection" and server.requests == []
    finally:
        server.stop()


async def test_a_plaintext_server_behind_an_https_url_is_refused_and_sees_no_token(pki: Authority) -> None:
    with fake_server() as plain:
        plain.json("/v1/x", {})
        transport = _transport(f"https://{HOST}:{plain.port}", ca=pki.pem_path)
        try:
            obs = await transport.send("GET", "/v1/x", "alice")
        finally:
            await transport.aclose()
        assert obs.error == "connection"
        assert not any("authorization" in {k.lower() for k in r["headers"]} for r in plain.requests)


async def test_the_ca_bundle_adds_exactly_its_own_authority(tmp_path: Path, pki: Authority, good_server: Any) -> None:
    other_ca = make_authority(tmp_path, "some other CA")
    transport = _transport(good_server.base_url, ca=other_ca.pem_path)  # trusts the OTHER authority only
    try:
        obs = await transport.send("GET", "/v1/x", "alice")
    finally:
        await transport.aclose()
    assert obs.error == "connection" and good_server.requests == []


def test_a_missing_ca_bundle_file_is_a_clear_refusal(tmp_path: Path) -> None:
    from boundarycheck.model import TransportUnavailable  # noqa: PLC0415

    with pytest.raises(TransportUnavailable, match="ca_bundle"):
        _transport(
            f"https://{HOST}:443", ca=tmp_path / "missing.pem", networks=(), resolver=_resolver(["93.184.216.34"])
        )


# --------------------------------------------------------------------- redirects, proxies ----
async def test_a_redirect_to_another_host_is_refused_and_the_token_goes_nowhere_else(
    good_server: Any, pki: Authority
) -> None:
    with fake_server() as elsewhere:
        elsewhere.json("/v1/x", {"leak": True})
        good_server.routes["/v1/x"] = (302, {"Location": f"{elsewhere.base_url}/v1/x"}, b"")
        transport = _transport(good_server.base_url, ca=pki.pem_path)
        try:
            obs = await transport.send("GET", "/v1/x", "alice")
        finally:
            await transport.aclose()
        assert obs.error == "redirect" and elsewhere.requests == []


async def test_proxy_variables_are_ignored(good_server: Any, pki: Authority, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    transport = _transport(good_server.base_url, ca=pki.pem_path)
    try:
        assert (await transport.send("GET", "/v1/x", "alice")).status == 200
    finally:
        await transport.aclose()


# ---------------------------------------------------------------------------- the peer ----
class _Stream:
    def __init__(self, ip: str | None) -> None:
        self._ip = ip

    def get_extra_info(self, name: str) -> Any:
        return (self._ip, 443) if name == "server_addr" and self._ip else None


class _Response:
    def __init__(self, ip: str | None) -> None:
        self.extensions = {"network_stream": _Stream(ip)}


def test_the_connected_peer_must_be_the_pinned_address_and_pass_the_same_policy() -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415
    from boundarycheck.netcheck import EgressPolicy  # noqa: PLC0415
    from boundarycheck.transports.live import verify_peer  # noqa: PLC0415

    policy = EgressPolicy.remote(host=HOST, port=443, allowed_networks=(), ca_bundle=None)
    verify_peer(_Response("93.184.216.34"), "93.184.216.34", policy)
    with pytest.raises(EgressViolation):
        verify_peer(_Response("93.184.216.35"), "93.184.216.34", policy)  # not the pinned one
    with pytest.raises(EgressViolation):
        verify_peer(_Response("10.0.0.1"), "10.0.0.1", policy)  # the pinned one would be unacceptable
    with pytest.raises(EgressViolation):
        verify_peer(_Response(None), "93.184.216.34", policy)  # unknowable


def test_the_loopback_peer_rule_is_unchanged() -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415
    from boundarycheck.transports.live import verify_peer  # noqa: PLC0415

    verify_peer(_Response("127.0.0.1"), "127.0.0.1")  # the v0.1 call, no policy
    with pytest.raises(EgressViolation):
        verify_peer(_Response("8.8.8.8"), "127.0.0.1")


# ----------------------------------------------------------------------------- from_config ----
def _config(tmp_path: Path, url: str, **target: Any) -> Any:
    from tests.support import mini, parse  # noqa: PLC0415

    data = mini()
    host = url.split("//", 1)[1].rsplit(":", 1)[0]
    port = url.rsplit(":", 1)[1]
    data["scope"]["target"].update({"base_url": url, "allowed_hosts": [f"{host}:{port}"], **target})
    data["scope"]["authorization"] = {"engagement": "TEST-1", "not_after": "2099-01-01T00:00:00Z"}
    return parse(data)


async def test_from_config_builds_the_remote_policy_and_the_lower_default_rate(
    good_server: Any, pki: Authority, tmp_path: Path
) -> None:
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    cfg = _config(tmp_path, good_server.base_url, allowed_networks=["127.0.0.0/8"], ca_bundle=str(pki.pem_path))
    transport = LiveTransport.from_config(cfg, {"BC_T_ALICE": TOKEN}, resolver=_resolver(["127.0.0.1"]))
    try:
        assert transport._interval == pytest.approx(0.5)  # 2 requests per second by default for a remote host
        assert (await transport.send("GET", "/v1/projects/pa1", "alice")).status in {200, 404}
    finally:
        await transport.aclose()


def test_from_config_for_a_remote_target_still_refuses_an_unlisted_private_answer(
    good_server: Any, pki: Authority, tmp_path: Path
) -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    cfg = _config(tmp_path, good_server.base_url, ca_bundle=str(pki.pem_path))  # no allowed_networks
    with pytest.raises(EgressViolation):
        LiveTransport.from_config(cfg, {"BC_T_ALICE": TOKEN}, resolver=_resolver(["127.0.0.1"]))


def test_a_loopback_config_is_unchanged(tmp_path: Path) -> None:
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415
    from tests.support import mini, parse  # noqa: PLC0415

    transport = LiveTransport.from_config(parse(mini()), {"BC_T_ALICE": TOKEN})
    assert transport.name == "live:loopback" and "127.0.0.1" in transport.describe()


async def _unused(_s: FakeServer) -> None:  # keeps the FakeServer import honest for type checkers
    return None


def test_the_host_header_omits_the_default_https_port_and_keeps_any_other() -> None:
    default = _transport(f"https://{HOST}:443", ca=None, networks=(), resolver=_resolver(["93.184.216.34"]))
    assert default._host_header == HOST
    other = _transport(f"https://{HOST}:8443", ca=None, networks=(), resolver=_resolver(["93.184.216.34"]))
    assert other._host_header == f"{HOST}:8443"
    v6 = _transport("https://[2606:4700:4700::1111]:443", ca=None, networks=(), host="2606:4700:4700::1111")
    assert v6._host_header == "[2606:4700:4700::1111]"


def test_a_remote_transport_is_named_after_its_host_and_pinned_address() -> None:
    transport = _transport(f"https://{HOST}:443", ca=None, networks=(), resolver=_resolver(["93.184.216.34"]))
    assert transport.name == f"live:remote:{HOST}:443@93.184.216.34"
    assert "describe" in dir(transport) and HOST in transport.describe()
