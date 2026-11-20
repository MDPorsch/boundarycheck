"""v0.3: `boundarycheck import-openapi` (docs/design-v0.3.md s5)."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from tests.unit.test_openapi import spec

pytestmark = pytest.mark.milestone("V3")

runner = CliRunner()


def _invoke(*args: str) -> Any:
    from boundarycheck.cli import app  # noqa: PLC0415

    return runner.invoke(app, list(args), catch_exceptions=False)


def _write_spec(tmp_path: Path, as_yaml: bool = False) -> Path:
    path = tmp_path / ("api.yaml" if as_yaml else "api.json")
    path.write_text(yaml.safe_dump(spec(), sort_keys=False) if as_yaml else json.dumps(spec()))
    return path


def test_import_writes_a_skeleton_that_validates_and_plans_and_tells_the_operator_what_to_edit(tmp_path: Path) -> None:
    out_path = tmp_path / "boundarycheck.yaml"
    out = _invoke("import-openapi", str(_write_spec(tmp_path)), "--output", str(out_path))
    assert out.exit_code == 0 and out_path.is_file()
    text = out.output.lower()
    assert "5 action" in text and "3 write" in text and "edit" in text and "policy" in text
    assert _invoke("validate", "--config", str(out_path)).exit_code == 0
    assert "requests planned" in _invoke("plan", "--config", str(out_path)).output


def test_a_yaml_spec_works_the_same(tmp_path: Path) -> None:
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    assert _invoke("import-openapi", str(_write_spec(tmp_path)), "-o", str(a)).exit_code == 0
    assert _invoke("import-openapi", str(_write_spec(tmp_path, as_yaml=True)), "-o", str(b)).exit_code == 0
    assert a.read_text() == b.read_text()


def test_import_will_not_overwrite_without_force(tmp_path: Path) -> None:
    out_path = tmp_path / "boundarycheck.yaml"
    out_path.write_text("keep me")
    spec_path = _write_spec(tmp_path)
    refused = _invoke("import-openapi", str(spec_path), "--output", str(out_path))
    assert refused.exit_code == 2 and "--force" in refused.output and out_path.read_text() == "keep me"
    assert _invoke("import-openapi", str(spec_path), "--output", str(out_path), "--force").exit_code == 0
    assert out_path.read_text() != "keep me"


@pytest.mark.parametrize("url", ["http://example.com/openapi.json", "https://example.com/openapi.yaml", "HTTPS://example.com/x"])
def test_a_url_is_refused_because_the_importer_never_fetches_anything(tmp_path: Path, url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_network(*_a: Any, **_k: Any) -> None:
        raise AssertionError("no network")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    out = _invoke("import-openapi", url, "--output", str(tmp_path / "o.yaml"))
    assert out.exit_code == 2 and "file" in out.output.lower() and not (tmp_path / "o.yaml").exists()


def test_a_missing_file_a_directory_and_an_invalid_document_are_clear_errors_that_write_nothing(tmp_path: Path) -> None:
    target = tmp_path / "o.yaml"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    for argument in (str(tmp_path / "nope.json"), str(tmp_path), str(bad)):
        out = _invoke("import-openapi", argument, "--output", str(target))
        assert out.exit_code == 2 and "Traceback" not in out.output and not target.exists()


def test_an_oversized_file_is_refused_without_being_read(tmp_path: Path) -> None:
    from boundarycheck.openapi import MAX_SPEC_BYTES  # noqa: PLC0415

    big = tmp_path / "big.json"
    with big.open("wb") as handle:
        handle.truncate(MAX_SPEC_BYTES + 1)  # a sparse file: nothing is allocated
    out = _invoke("import-openapi", str(big), "--output", str(tmp_path / "o.yaml"))
    assert out.exit_code == 2 and "too large" in out.output.lower()


def test_a_swagger_2_document_says_what_to_do(tmp_path: Path) -> None:
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"swagger": "2.0", "paths": {}}))
    out = _invoke("import-openapi", str(path), "--output", str(tmp_path / "o.yaml"))
    assert out.exit_code == 2 and "openapi 3" in out.output.lower()


def test_a_skeleton_run_before_editing_reports_findings_not_a_false_clean(tmp_path: Path) -> None:
    """The placeholders fail loud: nobody may do anything, so an API that answers anyone is a finding."""
    from tests.support import fake_server  # noqa: PLC0415

    out_path = tmp_path / "b.yaml"
    _invoke("import-openapi", str(_write_spec(tmp_path)), "--output", str(out_path))
    config = yaml.safe_load(out_path.read_text())
    with fake_server() as server:
        server.default = lambda h: h._send(200, {"content-type": "application/json"}, b'{"id":"x","title":"t"}')
        config["scope"]["target"]["base_url"] = server.base_url
        for resource in config["resources"]:
            for key in resource["ids"]:
                resource["ids"][key] = resource["ids"][key].replace("REPLACE-WITH-", "ID-").lower()
        out_path.write_text(yaml.safe_dump(config, sort_keys=False))
        out = runner.invoke(
            __import__("boundarycheck.cli", fromlist=["app"]).app,
            ["test", "--config", str(out_path), "--transport", "live", "--runs-dir", str(tmp_path / "r")],
            env={"BC_TOKEN_ALICE": "tok-" + "a" * 20, "BC_TOKEN_BOB": "tok-" + "b" * 20, "BC_TOKEN_CAROL": "tok-" + "c" * 20},
            catch_exceptions=False,
        )
    assert out.exit_code == 1 and "finding_candidate" in out.output
