"""v0.3: the CLI writes and prints SARIF (docs/design-v0.3.md s4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tests.support import EXAMPLE, VULN_EXAMPLE

pytestmark = pytest.mark.milestone("V3")

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "data" / "sarif-schema-2.1.0.json").read_text())
runner = CliRunner()


def _invoke(*args: str) -> Any:
    from boundarycheck.cli import app  # noqa: PLC0415

    return runner.invoke(app, list(args), catch_exceptions=False)


def _validate(text: str) -> dict[str, Any]:
    import jsonschema  # noqa: PLC0415

    doc = json.loads(text)
    jsonschema.Draft4Validator(SCHEMA).validate(doc)
    return doc  # type: ignore[no-any-return]


def _flawed(tmp_path: Path, *extra: str) -> Path:
    out = _invoke(
        "test",
        "--config",
        str(VULN_EXAMPLE),
        "--transport",
        "fixture",
        "--fixture-flaws",
        "ROLE_CHECK_MISSING",
        "--runs-dir",
        str(tmp_path / "runs"),
        *extra,
    )
    assert out.exit_code == 1, out.output
    return next((tmp_path / "runs").iterdir())


def _line_of(path: Path, action: str) -> int:
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if f"id: {action}," in line or line.strip() == f"- id: {action}":
            return number
    raise AssertionError(action)


def test_a_run_saves_a_valid_sarif_file_next_to_the_other_reports(tmp_path: Path) -> None:
    run = _flawed(tmp_path)
    doc = _validate((run / "report.sarif").read_text())
    results = doc["runs"][0]["results"]
    assert {r["ruleId"] for r in results} == {"BC-ROLE-01"} and len(results) == 5
    assert (run / "report.sarif").stat().st_mode & 0o777 == 0o600 and (run / "report.json").is_file()


def test_each_result_points_at_the_line_of_its_action_in_the_config_file(tmp_path: Path) -> None:
    doc = _validate((_flawed(tmp_path) / "report.sarif").read_text())
    for item in doc["runs"][0]["results"]:
        action = item["properties"]["action"]
        assert item["locations"][0]["physicalLocation"]["region"]["startLine"] == _line_of(VULN_EXAMPLE, action)


def test_report_prints_the_stored_sarif(tmp_path: Path) -> None:
    run = _flawed(tmp_path)
    out = _invoke("report", "--run", run.name, "--format", "sarif", "--runs-dir", str(tmp_path / "runs"))
    assert out.exit_code == 0 and out.output == (run / "report.sarif").read_text()


def test_an_unknown_report_format_names_sarif_among_the_choices(tmp_path: Path) -> None:
    run = _flawed(tmp_path)
    out = _invoke("report", "--run", run.name, "--format", "html", "--runs-dir", str(tmp_path / "runs"))
    assert out.exit_code == 2 and "sarif" in out.output


def test_the_config_path_in_the_file_is_the_file_name_for_an_absolute_path_and_sarif_uri_overrides_it(
    tmp_path: Path,
) -> None:
    default = _validate((_flawed(tmp_path) / "report.sarif").read_text())
    assert default["runs"][0]["artifacts"][0]["location"]["uri"] == "lab-vulnerable.yaml"
    second = tmp_path / "again"
    second.mkdir()
    chosen = _validate((_flawed(second, "--sarif-uri", "ci/boundarycheck.yaml") / "report.sarif").read_text())
    assert chosen["runs"][0]["artifacts"][0]["location"]["uri"] == "ci/boundarycheck.yaml"


def test_an_unsafe_sarif_uri_is_not_written_into_the_file(tmp_path: Path) -> None:
    doc = _validate((_flawed(tmp_path, "--sarif-uri", "../../etc/passwd") / "report.sarif").read_text())
    uri = doc["runs"][0]["artifacts"][0]["location"]["uri"]
    assert ".." not in uri and not uri.startswith("/")


def test_a_clean_run_is_valid_sarif_with_no_results_and_the_notice(tmp_path: Path) -> None:
    out = _invoke("test", "--config", str(EXAMPLE), "--transport", "fixture", "--runs-dir", str(tmp_path / "runs"))
    assert out.exit_code == 0
    doc = _validate((next((tmp_path / "runs").iterdir()) / "report.sarif").read_text())
    assert doc["runs"][0]["results"] == [] and "public" in doc["runs"][0]["properties"]["notice"].lower()


def test_no_save_writes_no_sarif(tmp_path: Path) -> None:
    _invoke(
        "test", "--config", str(EXAMPLE), "--transport", "fixture", "--no-save", "--runs-dir", str(tmp_path / "runs")
    )
    assert not (tmp_path / "runs").exists()
