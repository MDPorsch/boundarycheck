"""Remote live mode, the command line and the report (docs/remote-live-design.md s4.2, s5).

A remote run needs the declared authorization AND `--ack-authorization`, runs only inside its window,
says what it is about to do before it does it, and is never silent about the fact that the authorization
is the operator's word, not something the tool checked."""

from __future__ import annotations

import datetime as dt
import json
import socket
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tests.support import DELETE, dump, fake_token, remote_mini
from tests.support_tls import HOST, Authority, TlsServer, issue, make_authority

pytestmark = pytest.mark.milestone("R3")

runner = CliRunner()
TOKEN = fake_token("cli")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _stamp(delta_days: float) -> str:
    return (_now() + dt.timedelta(days=delta_days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _invoke(*args: str, env: dict[str, str] | None = None) -> Any:
    from boundarycheck.cli import app  # noqa: PLC0415

    return runner.invoke(app, list(args), env=env, catch_exceptions=False)


@pytest.fixture
def pki(tmp_path: Path) -> Authority:
    return make_authority(tmp_path)


@pytest.fixture
def server(tmp_path: Path, pki: Authority) -> Any:
    cert, key = issue(pki, tmp_path, [HOST])
    srv = TlsServer(cert, key)
    srv.start()
    yield srv
    srv.stop()


def _config(tmp_path: Path, server: Any, pki: Authority, **changes: Any) -> Path:
    base = {
        "scope__target__base_url": server.base_url,
        "scope__target__allowed_hosts": [f"{HOST}:{server.port}"],
        "scope__target__allowed_networks": ["127.0.0.0/8"],
        "scope__target__ca_bundle": str(pki.pem_path),
        "scope__target__request_budget": 6,
        "scope__authorization": {"engagement": "TEST-ENG-7", "not_after": _stamp(7)},
    }
    path = tmp_path / "remote.yaml"
    path.write_text(dump(remote_mini(**{**base, **changes})))
    return path


@pytest.fixture(autouse=True)
def resolve_to_loopback(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The operating system's resolver is never used: the test name maps to 127.0.0.1."""
    calls: list[str] = []

    def fake(host: str) -> list[str]:
        calls.append(host)
        return ["127.0.0.1"]

    monkeypatch.setattr("boundarycheck.transports.live._system_resolver", fake)
    return calls


def _args(config: Path, tmp_path: Path, *extra: str) -> list[str]:
    return ["test", "--config", str(config), "--transport", "live", "--runs-dir", str(tmp_path / "runs"), *extra]


# ------------------------------------------------------------------ the acknowledgement ----
def test_a_remote_run_without_the_acknowledgement_is_refused_before_any_lookup(
    tmp_path: Path, server: Any, pki: Authority, resolve_to_loopback: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_network(*_a: Any, **_k: Any) -> None:
        raise AssertionError("nothing may touch the network before the acknowledgement")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    out = _invoke(*_args(_config(tmp_path, server, pki), tmp_path), env={"BC_T_ALICE": TOKEN})
    assert out.exit_code == 2 and "--ack-authorization" in out.output
    assert resolve_to_loopback == [] and server.requests == []


def test_a_remote_run_with_the_acknowledgement_says_where_it_goes_before_it_goes(
    tmp_path: Path, server: Any, pki: Authority
) -> None:
    out = _invoke(*_args(_config(tmp_path, server, pki), tmp_path, "--ack-authorization"), env={"BC_T_ALICE": TOKEN})
    text = out.output
    assert f"{HOST}:{server.port}" in text and "127.0.0.1" in text and "TEST-ENG-7" in text
    assert text.index("TEST-ENG-7") < text.index("cases:"), "the target is announced before the results"
    assert server.requests and all(r["method"] == "GET" for r in server.requests)
    assert all(
        r["headers"].get("Authorization") == f"Bearer {TOKEN}"
        for r in server.requests
        if "Authorization" in r["headers"]
    )


def test_the_acknowledgement_flag_is_not_needed_on_loopback(tmp_path: Path) -> None:
    from tests.support import fake_server, mini  # noqa: PLC0415

    with fake_server() as srv:
        data = mini()
        data["scope"]["target"]["base_url"] = srv.base_url
        path = tmp_path / "loop.yaml"
        path.write_text(dump(data))
        out = _invoke(*_args(path, tmp_path), env={"BC_T_ALICE": TOKEN})
        assert "--ack-authorization" not in out.output


# ---------------------------------------------------------------------------- the window ----
@pytest.mark.parametrize(
    ("changes", "needle"),
    [
        ({"scope__authorization": {"engagement": "E", "not_after": _stamp(-1)}}, "expired"),
        ({"scope__authorization": {"engagement": "E", "not_before": _stamp(1), "not_after": _stamp(7)}}, "not yet"),
        ({"scope__authorization": {"engagement": "E", "not_after": _stamp(500)}}, "too long"),
    ],
    ids=["expired", "not-yet-valid", "more-than-a-year-away"],
)
def test_a_run_outside_the_authorization_window_is_refused_and_sends_nothing(
    tmp_path: Path, server: Any, pki: Authority, changes: dict[str, Any], needle: str
) -> None:
    out = _invoke(
        *_args(_config(tmp_path, server, pki, **changes), tmp_path, "--ack-authorization"), env={"BC_T_ALICE": TOKEN}
    )
    assert out.exit_code == 2 and needle in out.output.lower()
    assert server.requests == []


# ------------------------------------------------------------------------ the report ----
def test_the_report_says_the_authorization_is_the_operators_word(tmp_path: Path, server: Any, pki: Authority) -> None:
    out = _invoke(*_args(_config(tmp_path, server, pki), tmp_path, "--ack-authorization"), env={"BC_T_ALICE": TOKEN})
    run = next((tmp_path / "runs").iterdir())
    doc = json.loads((run / "report.json").read_text())
    text = doc["attestation"].lower()
    assert "remote run" in text and "test-eng-7" in text
    assert "not verified" in text or "cannot verify" in text
    assert HOST in doc["transport"] and "127.0.0.1" in doc["transport"]
    md = (run / "report.md").read_text().lower()
    assert "test-eng-7" in md
    assert TOKEN not in json.dumps(doc) and TOKEN not in (run / "report.md").read_text() and TOKEN not in out.output


def test_the_report_of_a_remote_run_never_holds_the_token_anywhere_on_disk(
    tmp_path: Path, server: Any, pki: Authority
) -> None:
    _invoke(*_args(_config(tmp_path, server, pki), tmp_path, "--ack-authorization"), env={"BC_T_ALICE": TOKEN})
    for path in (tmp_path / "runs").rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes(), path


# ---------------------------------------------------------------------------- preflight ----
def test_preflight_resolves_checks_and_sends_nothing(
    tmp_path: Path, server: Any, pki: Authority, resolve_to_loopback: list[str]
) -> None:
    out = _invoke("preflight", "--config", str(_config(tmp_path, server, pki)))
    assert out.exit_code == 0, out.output
    assert HOST in out.output and "127.0.0.1" in out.output and "acceptable" in out.output.lower()
    assert "TEST-ENG-7" in out.output and "window" in out.output.lower()
    assert server.requests == [], "preflight must send no request"
    assert resolve_to_loopback == [HOST]


def test_preflight_shows_a_refusal_for_each_unacceptable_address(
    tmp_path: Path, server: Any, pki: Authority, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "boundarycheck.transports.live._system_resolver", lambda _h: ["8.8.8.8", "169.254.169.254", "10.0.0.9"]
    )
    out = _invoke("preflight", "--config", str(_config(tmp_path, server, pki)))
    assert out.exit_code == 2
    assert "169.254.169.254" in out.output and "refused" in out.output.lower() and "10.0.0.9" in out.output
    assert server.requests == []


def test_preflight_reports_a_closed_window_without_resolving(
    tmp_path: Path, server: Any, pki: Authority, resolve_to_loopback: list[str]
) -> None:
    cfg = _config(tmp_path, server, pki, scope__authorization={"engagement": "E", "not_after": _stamp(-2)})
    out = _invoke("preflight", "--config", str(cfg))
    assert out.exit_code == 2 and "expired" in out.output.lower()
    assert resolve_to_loopback == []


def test_preflight_on_a_loopback_config_says_there_is_nothing_remote_to_check(tmp_path: Path) -> None:
    from tests.support import mini  # noqa: PLC0415

    path = tmp_path / "loop.yaml"
    path.write_text(dump(mini()))
    out = _invoke("preflight", "--config", str(path))
    assert out.exit_code == 0 and "loopback" in out.output.lower()


def test_preflight_rejects_a_config_that_is_not_valid(tmp_path: Path, server: Any, pki: Authority) -> None:
    path = _config(tmp_path, server, pki, scope__authorization=DELETE)
    out = _invoke("preflight", "--config", str(path))
    assert out.exit_code == 2 and "authorization" in out.output.lower()


# ------------------------------------------------------------------------------- init ----
def test_init_remote_writes_a_template_that_validates_but_cannot_run_until_edited(tmp_path: Path) -> None:
    target = tmp_path / "remote.yaml"
    out = _invoke("init", "--remote", "--output", str(target))
    assert out.exit_code == 0 and target.is_file()
    text = target.read_text()
    assert "allowed_hosts" in text and "authorization" in text and "not_after" in text and "EDIT" in text
    assert _invoke("validate", "--config", str(target)).exit_code == 0
    # a template must never be a working authorization: its window has already closed
    run = _invoke("preflight", "--config", str(target))
    assert run.exit_code == 2 and "expired" in run.output.lower()
    assert "token" not in text.lower() or "BC_TOKEN" in text  # credentials are named by variable only


def test_plain_init_is_unchanged(tmp_path: Path) -> None:
    target = tmp_path / "plain.yaml"
    assert _invoke("init", "--output", str(target)).exit_code == 0
    assert "allowed_hosts" not in target.read_text()
