"""v0.3 (docs/design-v0.3.md s2): a credential has a scheme: a bearer token (as before), an API key in a
named header, or a named session cookie. The value is never in the config and never in a report."""

from __future__ import annotations

from typing import Any

import pytest

from tests.support import dump, fake_server, fake_token, mini, parse

pytestmark = pytest.mark.milestone("V3")


def _with_credential(credential: dict[str, Any]) -> dict[str, Any]:
    data = mini()
    data["principals"]["alice"] = {"credential": credential}
    return data


def _bad(data: dict[str, Any], needle: str | None = None) -> None:
    from boundarycheck.config import ConfigError, parse_config  # noqa: PLC0415

    with pytest.raises(ConfigError) as caught:
        parse_config(dump(data))
    if needle is not None:
        assert needle.lower() in str(caught.value).lower(), str(caught.value)


# --------------------------------------------------------------------------------- the config ----
def test_a_bearer_credential_is_the_default_and_unchanged() -> None:
    cred = parse(_with_credential({"env": "BC_X"})).principals["alice"].credential
    assert cred is not None and cred.scheme == "bearer" and cred.name is None and cred.prefix is None


def test_an_api_key_header_and_a_cookie_are_accepted() -> None:
    header = (
        parse(_with_credential({"env": "BC_X", "in": "header", "name": "X-API-Key"})).principals["alice"].credential
    )
    cookie = parse(_with_credential({"env": "BC_X", "in": "cookie", "name": "session"})).principals["alice"].credential
    assert header is not None and (header.scheme, header.name) == ("header", "X-API-Key")
    assert cookie is not None and (cookie.scheme, cookie.name) == ("cookie", "session")


def test_a_header_credential_may_carry_a_prefix_such_as_token() -> None:
    cred = (
        parse(_with_credential({"env": "BC_X", "in": "header", "name": "Authorization", "prefix": "Token "}))
        .principals["alice"]
        .credential
    )
    assert cred is not None and cred.prefix == "Token "


@pytest.mark.parametrize("scheme", ["query", "body", "basic", "Header", "COOKIE", "", "bearer-ish"])
def test_an_unknown_scheme_is_refused(scheme: str) -> None:
    _bad(_with_credential({"env": "BC_X", "in": scheme, "name": "k"}))


@pytest.mark.parametrize("scheme", ["header", "cookie"])
def test_header_and_cookie_credentials_need_a_name(scheme: str) -> None:
    _bad(_with_credential({"env": "BC_X", "in": scheme}), "name")


def test_a_bearer_credential_takes_no_name_or_prefix() -> None:
    _bad(_with_credential({"env": "BC_X", "name": "X-API-Key"}), "name")
    _bad(_with_credential({"env": "BC_X", "prefix": "Token "}), "prefix")


def test_a_cookie_takes_no_prefix() -> None:
    _bad(_with_credential({"env": "BC_X", "in": "cookie", "name": "session", "prefix": "Token "}), "prefix")


@pytest.mark.parametrize(
    "name",
    [
        "Host",
        "host",
        "HOST",
        "Content-Length",
        "Content-Type",
        "Transfer-Encoding",
        "Connection",
        "Upgrade",
        "TE",
        "Trailer",
        "Accept",
        "Accept-Encoding",
        "User-Agent",
        "Proxy-Authorization",
        "Cookie",
        "Set-Cookie",
        "cookie",
    ],
)
def test_a_header_name_that_would_change_how_the_request_is_framed_is_refused(name: str) -> None:
    _bad(_with_credential({"env": "BC_X", "in": "header", "name": name}), "header")


@pytest.mark.parametrize("name", ["", "X API", "X-API-Key:", "X_API\nKey", "Clé", "x" * 65, "a b", "a;b", "a=b", "a/b"])
def test_a_header_name_is_a_plain_token(name: str) -> None:
    _bad(_with_credential({"env": "BC_X", "in": "header", "name": name}))


@pytest.mark.parametrize("name", ["", "a b", "a=b", "a;b", "a,b", "a\nb", "é", "x" * 65, "a/b", 'a"b'])
def test_a_cookie_name_is_a_plain_token(name: str) -> None:
    _bad(_with_credential({"env": "BC_X", "in": "cookie", "name": name}))


@pytest.mark.parametrize("name", ["X-API-Key", "Authorization", "Api-Key", "x-token", "X-Auth-Token"])
def test_ordinary_api_key_header_names_are_accepted(name: str) -> None:
    parse(_with_credential({"env": "BC_X", "in": "header", "name": name}))


@pytest.mark.parametrize("name", ["session", "sid", "__Host-sid", "JSESSIONID", "auth.token", "a_b-c"])
def test_ordinary_cookie_names_are_accepted(name: str) -> None:
    parse(_with_credential({"env": "BC_X", "in": "cookie", "name": name}))


@pytest.mark.parametrize("prefix", ["\r\n", "a\nb", "x" * 33, "é", "\x00", "a\x7f"])
def test_a_prefix_is_short_printable_ascii(prefix: str) -> None:
    _bad(_with_credential({"env": "BC_X", "in": "header", "name": "Authorization", "prefix": prefix}))


def test_a_fixture_only_credential_cannot_choose_a_scheme() -> None:
    _bad(_with_credential({"fixture": "alice", "in": "header", "name": "X-API-Key"}), "env")


# ------------------------------------------------------------------------------- the material ----
def _materials(config: dict[str, Any], environ: dict[str, str]) -> Any:
    from boundarycheck.credentials import resolve_materials  # noqa: PLC0415

    return resolve_materials(parse(config), environ)


def test_materials_are_resolved_per_principal_with_their_scheme() -> None:
    data = mini()
    data["principals"]["alice"] = {"credential": {"env": "BC_A"}}
    data["principals"]["bob"] = {"credential": {"env": "BC_B", "in": "header", "name": "X-API-Key"}}
    data["principals"]["carol"] = {"credential": {"env": "BC_C", "in": "cookie", "name": "session"}}
    env = {"BC_A": fake_token("a"), "BC_B": fake_token("b"), "BC_C": fake_token("c")}
    got = _materials(data, env)
    assert (got["alice"].scheme, got["bob"].scheme, got["carol"].scheme) == ("bearer", "header", "cookie")
    assert got["bob"].name == "X-API-Key" and got["carol"].name == "session"
    assert "gina" not in got  # no credential declared


def test_a_missing_or_unusable_value_is_left_out_so_the_case_is_not_run() -> None:
    data = mini()
    data["principals"]["bob"] = {"credential": {"env": "BC_B", "in": "cookie", "name": "session"}}
    data["principals"]["carol"] = {"credential": {"env": "BC_C", "in": "cookie", "name": "session"}}
    data["principals"]["alice"] = {"credential": {"env": "BC_A"}}
    env = {"BC_B": "abc; admin=1; x=yyyyyyyy", "BC_A": "short"}  # a cookie with ';' and a too-short token; carol unset
    assert _materials(data, env) == {}


@pytest.mark.parametrize("value", ["has space 1234", "tab\tinside1234", "new\nline1234", "é" * 12, "x" * 4097])
def test_a_value_that_is_not_printable_ascii_without_spaces_is_unusable(value: str) -> None:
    data = _with_credential({"env": "BC_X", "in": "header", "name": "X-API-Key"})
    assert _materials(data, {"BC_X": value}) == {}


@pytest.mark.parametrize("value", ["a;bcdefghij", "a,bcdefghij", 'a"bcdefghij', "a\\bcdefghij", "a bcdefghij"])
def test_a_cookie_value_may_not_smuggle_another_cookie(value: str) -> None:
    data = _with_credential({"env": "BC_X", "in": "cookie", "name": "session"})
    assert _materials(data, {"BC_X": value}) == {}


def test_a_material_never_shows_its_value() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415

    secret = fake_token("never-shown")
    material = Material(value=secret, scheme="header", name="X-API-Key")
    assert secret not in repr(material) and secret not in str(material)


def test_the_header_each_scheme_sends() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415

    assert Material(value="v" * 12).header() == ("Authorization", "Bearer " + "v" * 12)
    assert Material(value="v" * 12, scheme="header", name="X-API-Key").header() == ("X-API-Key", "v" * 12)
    assert Material(value="v" * 12, scheme="header", name="Authorization", prefix="Token ").header() == (
        "Authorization",
        "Token " + "v" * 12,
    )
    assert Material(value="v" * 12, scheme="cookie", name="session").header() == ("Cookie", "session=" + "v" * 12)


# -------------------------------------------------------------------------------- transport ----
async def _send(
    materials: dict[str, Any], principal: str | None, server: Any, *, extra: dict[str, Any] | None = None
) -> Any:
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    transport = LiveTransport(
        server.base_url,
        credentials={},
        environ={},
        materials=materials,
        resolver=lambda _h: ["127.0.0.1"],
        **(extra or {}),
    )
    try:
        return await transport.send("GET", "/v1/x", principal), transport
    finally:
        await transport.aclose()


async def test_an_api_key_goes_in_its_named_header_and_nothing_else_authenticates() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415

    key = fake_token("key")
    with fake_server() as server:
        server.json("/v1/x", {})
        await _send({"bob": Material(value=key, scheme="header", name="X-API-Key")}, "bob", server)
        headers = {k.lower(): v for k, v in server.requests[0]["headers"].items()}
        assert headers["x-api-key"] == key and "authorization" not in headers and "cookie" not in headers


async def test_a_prefixed_header_credential_sends_the_prefix_and_the_value() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415

    key = fake_token("drf")
    with fake_server() as server:
        server.json("/v1/x", {})
        await _send({"bob": Material(value=key, scheme="header", name="Authorization", prefix="Token ")}, "bob", server)
        assert {k.lower(): v for k, v in server.requests[0]["headers"].items()}["authorization"] == f"Token {key}"


async def test_a_session_cookie_goes_in_the_cookie_header_and_nothing_else_authenticates() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415

    sid = fake_token("sid")
    with fake_server() as server:
        server.json("/v1/x", {})
        await _send({"carol": Material(value=sid, scheme="cookie", name="session")}, "carol", server)
        headers = {k.lower(): v for k, v in server.requests[0]["headers"].items()}
        assert headers["cookie"] == f"session={sid}" and "authorization" not in headers


async def test_a_bearer_material_is_the_authorization_header_as_before() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415

    token = fake_token()
    with fake_server() as server:
        server.json("/v1/x", {})
        await _send({"alice": Material(value=token)}, "alice", server)
        assert {k.lower(): v for k, v in server.requests[0]["headers"].items()}["authorization"] == f"Bearer {token}"


async def test_the_anonymous_principal_sends_no_credential_of_any_scheme() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415

    with fake_server() as server:
        server.json("/v1/x", {})
        await _send({"bob": Material(value=fake_token(), scheme="header", name="X-API-Key")}, None, server)
        names = {k.lower() for k in server.requests[0]["headers"]}
        assert not names & {"authorization", "x-api-key", "cookie"}


async def test_a_cookie_the_target_sets_is_never_replayed_next_to_ours() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    sid = fake_token("sid")
    with fake_server() as server:
        server.routes["/v1/x"] = (
            200,
            {"content-type": "application/json", "set-cookie": "tracker=evil; Path=/"},
            b"{}",
        )
        transport = LiveTransport(
            server.base_url,
            credentials={},
            environ={},
            materials={"carol": Material(value=sid, scheme="cookie", name="session")},
            resolver=lambda _h: ["127.0.0.1"],
        )
        try:
            await transport.send("GET", "/v1/x", "carol")
            await transport.send("GET", "/v1/x", "carol")
        finally:
            await transport.aclose()
        assert [r["headers"].get("Cookie") for r in server.requests] == [f"session={sid}"] * 2


async def test_the_transport_exposes_every_scheme_value_as_a_secret_and_has_credentials_for_them() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    a, b = fake_token("a"), fake_token("b")
    with fake_server() as server:
        transport = LiveTransport(
            server.base_url,
            credentials={},
            environ={},
            resolver=lambda _h: ["127.0.0.1"],
            materials={
                "x": Material(value=a, scheme="header", name="K"),
                "y": Material(value=b, scheme="cookie", name="s"),
            },
        )
        try:
            assert sorted(transport.secrets()) == sorted([a, b])
            assert transport.has_credential("x") and transport.has_credential("y") and not transport.has_credential("z")
        finally:
            await transport.aclose()


async def test_legacy_bearer_credentials_still_work_alongside_materials() -> None:
    from boundarycheck.credentials import Material  # noqa: PLC0415
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    tok, key = fake_token("tok"), fake_token("key")
    with fake_server() as server:
        server.json("/v1/x", {})
        transport = LiveTransport(
            server.base_url,
            credentials={"alice": "BC_A"},
            environ={"BC_A": tok},
            materials={"bob": Material(value=key, scheme="header", name="K")},
            resolver=lambda _h: ["127.0.0.1"],
        )
        try:
            await transport.send("GET", "/v1/x", "alice")
            await transport.send("GET", "/v1/x", "bob")
        finally:
            await transport.aclose()
        first, second = ({k.lower(): v for k, v in r["headers"].items()} for r in server.requests)
        assert first["authorization"] == f"Bearer {tok}" and second["k"] == key


# -------------------------------------------------------------------------- the whole run ----
def test_a_cli_run_with_an_api_key_principal_sends_the_key_in_its_header_and_stores_it_nowhere(tmp_path: Any) -> None:
    from typer.testing import CliRunner  # noqa: PLC0415

    from boundarycheck.cli import app  # noqa: PLC0415

    key = fake_token("apikey")
    data = mini()
    data["principals"] = {"alice": {"credential": {"env": "BC_KEY", "in": "header", "name": "X-API-Key"}}}
    data["memberships"] = [{"principal": "alice", "tenant": "A", "role": "owner", "status": "active"}]
    with fake_server() as server:
        # a hostile target that ECHOES the key back in a body and a header
        server.default = lambda h: h._send(
            200,
            {"content-type": "application/json", "x-echo": h.headers.get("X-API-Key", "")},
            ('{"echo":"' + h.headers.get("X-API-Key", "") + '"}').encode(),
        )
        data["scope"]["target"]["base_url"] = server.base_url
        path = tmp_path / "c.yaml"
        path.write_text(dump(data))
        out = CliRunner().invoke(
            app,
            ["test", "--config", str(path), "--transport", "live", "--runs-dir", str(tmp_path / "r")],
            env={"BC_KEY": key},
            catch_exceptions=False,
        )
        assert any(r["headers"].get("X-API-Key") == key for r in server.requests)
        assert not any("authorization" in {k.lower() for k in r["headers"]} for r in server.requests)
    assert key not in out.output
    for file in (tmp_path / "r").rglob("*"):
        if file.is_file():
            assert key.encode() not in file.read_bytes(), file
