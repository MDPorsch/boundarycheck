"""The command line: a thin layer over the library (docs/contract.md s2, s5, s7)."""

from __future__ import annotations

import socket
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tests.support import EXAMPLE, FakeServer, fake_server

pytestmark = pytest.mark.milestone("S1")

runner = CliRunner()
CANARIES = {f"BC_TOKEN_{n}": f"canary-{n}-" + "Zq81xKd02LmPq77AbCd" for n in ("ALICE", "BOB", "CARLA", "DAVE", "ERIN", "FRANK", "GINA")}


def _app() -> Any:
    from boundarycheck.cli import app  # noqa: PLC0415

    return app


def _invoke(*args: str, env: dict[str, str] | None = None) -> Any:
    return runner.invoke(_app(), list(args), env=env, catch_exceptions=False)


def test_help_lists_every_command_and_version_works() -> None:
    out = _invoke("--help")
    assert out.exit_code == 0
    for command in ("init", "validate", "plan", "test", "report", "list-runs", "purge"):
        assert command in out.output
    version = _invoke("--version")
    assert version.exit_code == 0 and "boundarycheck" in version.output


def test_init_writes_a_template_that_validates_and_will_not_overwrite(tmp_path: Path) -> None:
    from boundarycheck.config import load_config  # noqa: PLC0415

    target = tmp_path / "bc.yaml"
    out = _invoke("init", "--output", str(target))
    assert out.exit_code == 0 and target.is_file()
    load_config(target)
    assert "token" not in target.read_text().lower().replace("env var", "")  # no secret-looking placeholders
    before = target.read_text()
    again = _invoke("init", "--output", str(target))
    assert again.exit_code == 2 and "exists" in again.output.lower() and target.read_text() == before
    assert _invoke("init", "--output", str(target), "--force").exit_code == 0


def test_validate_accepts_the_example_and_reports_what_it_will_do() -> None:
    out = _invoke("validate", "--config", str(EXAMPLE))
    assert out.exit_code == 0 and "lab-demo" in out.output and "cases" in out.output.lower()


@pytest.mark.parametrize("content", ["version: 2\n", "not: [valid", "version: 1\nversion: 1\n", "a: &x 1\nb: *x\n"])
def test_a_bad_config_exits_two_with_a_message_and_no_traceback(tmp_path: Path, content: str) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(content)
    out = _invoke("validate", "--config", str(bad))
    assert out.exit_code == 2 and "Traceback" not in out.output and "error" in out.output.lower()


def test_a_missing_config_exits_two(tmp_path: Path) -> None:
    out = _invoke("validate", "--config", str(tmp_path / "nope.yaml"))
    assert out.exit_code == 2 and "Traceback" not in out.output


def test_plan_prints_every_request_and_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_sockets(*_a: Any, **_k: Any) -> None:
        raise AssertionError("plan must not open a socket")

    monkeypatch.setattr(socket, "socket", no_sockets)
    out = _invoke("plan", "--config", str(EXAMPLE))
    assert out.exit_code == 0
    lines = [ln for ln in out.output.splitlines() if ln.startswith("BC-")]
    assert len(lines) >= 240 and "GET /v1/projects/50000000-0000-4000-8000-000000000001" in out.output
    assert "Bearer" not in out.output and "eyJ" not in out.output


def test_a_fixture_run_against_the_patched_lab_exits_zero_and_saves_a_private_run(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    out = _invoke("test", "--config", str(EXAMPLE), "--transport", "fixture", "--runs-dir", str(runs))
    assert out.exit_code == 0, out.output
    assert "no_issue_observed" in out.output and "does not mean" in out.output.lower()
    saved = [p for p in runs.iterdir() if p.is_dir()]
    assert len(saved) == 1 and (saved[0] / "report.json").is_file() and (saved[0] / "report.md").is_file()
    assert saved[0].name in out.output


def test_a_vulnerable_variant_is_detected_and_exits_one(tmp_path: Path) -> None:
    out = _invoke("test", "--config", str(EXAMPLE), "--transport", "fixture", "--fixture-variant", "vulnerable", "--fixture-flaws", "ROLE_CHECK_MISSING", "--runs-dir", str(tmp_path / "r"))
    assert out.exit_code == 1 and "finding_candidate" in out.output and "bob:contact.private.read:PA1" in out.output


def test_no_save_writes_nothing(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    out = _invoke("test", "--config", str(EXAMPLE), "--transport", "fixture", "--runs-dir", str(runs), "--no-save")
    assert out.exit_code == 0 and not runs.exists()


@pytest.mark.parametrize("extra", [["--transport", "bogus"], ["--transport", "fixture", "--fixture-flaws", "NOT_A_FLAW", "--fixture-variant", "vulnerable"], ["--transport", "fixture", "--fixture-variant", "nope"], ["--transport", "fixture", "--fixture-flaws", "ROLE_CHECK_MISSING"]])
def test_usage_errors_exit_two_before_anything_runs(tmp_path: Path, extra: list[str]) -> None:
    out = _invoke("test", "--config", str(EXAMPLE), "--runs-dir", str(tmp_path / "r"), *extra)
    assert out.exit_code == 2 and not (tmp_path / "r").exists()


def test_a_missing_lab_is_a_clear_message_not_a_traceback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setitem(sys.modules, "tenantlab", None)
    out = _invoke("test", "--config", str(EXAMPLE), "--transport", "fixture", "--runs-dir", str(tmp_path / "r"))
    assert out.exit_code == 2 and "tenant-boundary-lab" in out.output and "Traceback" not in out.output


def test_a_world_writable_runs_directory_is_refused(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    out = _invoke("test", "--config", str(EXAMPLE), "--transport", "fixture", "--runs-dir", str(shared))
    assert out.exit_code == 2 and "writable" in out.output.lower()


def _live_config(tmp_path: Path, base_url: str) -> Path:
    text = EXAMPLE.read_text().replace("http://127.0.0.1:8099", base_url)
    path = tmp_path / "live.yaml"
    path.write_text(text)
    return path


def test_live_without_credentials_cannot_be_clean(tmp_path: Path) -> None:
    with fake_server() as server:
        out = _invoke("test", "--config", str(_live_config(tmp_path, server.base_url)), "--transport", "live", "--runs-dir", str(tmp_path / "r"))
    assert out.exit_code == 2 and "not_run" in out.output


def test_a_target_that_echoes_every_token_leaves_no_token_anywhere(tmp_path: Path) -> None:
    """The canary test (docs/contract.md s7): hostile target echoes the Authorization header in every
    response body and header. No credential may appear in stdout, stderr, the report or any blob."""

    def echo(handler: Any) -> None:
        import json as _json  # noqa: PLC0415

        auth = handler.headers.get("Authorization", "")
        body = _json.dumps({"id": "x", "echo": auth, "title": auth}).encode()
        handler._send(200, {"content-type": "application/json", "x-echo": auth}, body)  # noqa: SLF001

    runs = tmp_path / "runs"
    with fake_server() as server:
        server.default = echo
        out = _invoke("test", "--config", str(_live_config(tmp_path, server.base_url)), "--transport", "live", "--runs-dir", str(runs), env=CANARIES)
    assert out.exit_code == 1, out.output
    haystacks = [out.output] + [p.read_text(errors="replace") for p in runs.rglob("*") if p.is_file()]
    assert len(haystacks) > 10
    for token in CANARIES.values():
        assert not [h for h in haystacks if token in h], token
        assert not [h for h in haystacks if token.removeprefix("canary-") in h]
    assert any("[credential]" in h for h in haystacks)


def test_report_list_runs_and_purge(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    assert _invoke("list-runs", "--runs-dir", str(runs)).exit_code == 0
    first = _invoke("test", "--config", str(EXAMPLE), "--transport", "fixture", "--runs-dir", str(runs))
    run_id = next(p.name for p in runs.iterdir())
    listing = _invoke("list-runs", "--runs-dir", str(runs))
    assert listing.exit_code == 0 and run_id in listing.output and first.exit_code == 0
    as_json = _invoke("report", "--run", run_id, "--format", "json", "--runs-dir", str(runs))
    assert as_json.exit_code == 0 and '"schema_version"' in as_json.output
    as_md = _invoke("report", "--run", run_id, "--format", "md", "--runs-dir", str(runs))
    assert as_md.exit_code == 0 and as_md.output.startswith("# boundarycheck report")
    assert _invoke("report", "--run", "../etc", "--format", "json", "--runs-dir", str(runs)).exit_code == 2
    assert _invoke("report", "--run", run_id, "--format", "xml", "--runs-dir", str(runs)).exit_code == 2
    assert _invoke("report", "--run", "20200101T000000Z-00000000", "--format", "json", "--runs-dir", str(runs)).exit_code == 2
    kept = _invoke("purge", "--older-than", "30d", "--runs-dir", str(runs))
    assert kept.exit_code == 0 and (runs / run_id).exists()
    assert _invoke("purge", "--older-than", "banana", "--runs-dir", str(runs)).exit_code == 2


def test_purge_removes_an_old_run(tmp_path: Path) -> None:
    import asyncio  # noqa: PLC0415

    from boundarycheck.config import load_config  # noqa: PLC0415
    from boundarycheck.engine import run  # noqa: PLC0415
    from boundarycheck.evidence import RunStore  # noqa: PLC0415
    from boundarycheck.report import to_json, to_markdown  # noqa: PLC0415
    from tests.support import FakeTransport, compliant  # noqa: PLC0415

    cfg = load_config(EXAMPLE)
    old = datetime.now(UTC) - timedelta(days=60)
    result = asyncio.run(run(cfg, FakeTransport(compliant(cfg)), now=old))
    RunStore(tmp_path / "runs").save(result, to_json(result), to_markdown(result), [])
    out = _invoke("purge", "--older-than", "30d", "--runs-dir", str(tmp_path / "runs"))
    assert out.exit_code == 0 and result.run_id in out.output and not (tmp_path / "runs" / result.run_id).exists()
