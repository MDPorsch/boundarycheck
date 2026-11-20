"""v0.3 (docs/design-v0.3.md s4): SARIF 2.1.0 output. Findings are results, everything else that was not
clean is a notification, nothing carries a response body or a credential, and the file is schema-valid."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.support import FakeTransport, StatefulFake, compliant, fake_token, mini, parse, write_config

pytestmark = pytest.mark.milestone("V3")

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "data" / "sarif-schema-2.1.0.json").read_text())


def _valid(text: str) -> dict[str, Any]:
    import jsonschema  # noqa: PLC0415

    doc = json.loads(text)
    jsonschema.Draft4Validator(SCHEMA).validate(doc)
    assert isinstance(doc, dict)
    return doc


async def _run(config: Any, transport: Any, **kwargs: Any) -> Any:
    from boundarycheck.engine import run  # noqa: PLC0415

    return await run(config, transport, **kwargs)


def _sarif(result: Any, **kwargs: Any) -> str:
    from boundarycheck.sarif import to_sarif  # noqa: PLC0415

    return to_sarif(result, **kwargs)


def _tweak_to(status: int, key: str) -> Any:
    from boundarycheck.model import Observation  # noqa: PLC0415

    def tweak(case: Any, obs: Any) -> Any:
        return Observation(status=status, headers=obs.headers, body=b'{"id":"x"}') if case.key == key else obs

    return tweak


# --------------------------------------------------------------------------------- validity ----
async def test_a_clean_run_is_valid_sarif_with_no_results_and_a_successful_invocation() -> None:
    cfg = parse(mini())
    doc = _valid(_sarif(await _run(cfg, FakeTransport(compliant(cfg)))))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is True and run["invocations"][0]["exitCode"] == 0
    assert run["tool"]["driver"]["name"] == "boundarycheck" and run["tool"]["driver"]["version"]


async def test_findings_are_results_with_rule_level_message_and_fingerprint() -> None:
    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg, tweak=_tweak_to(200, "bob:contact.private.read:PA1"))))
    doc = _valid(_sarif(result))
    run = doc["runs"][0]
    assert len(run["results"]) == 1
    item = run["results"][0]
    assert item["ruleId"] == "BC-ROLE-01" and item["level"] == "error" and item["kind"] == "fail"
    assert run["tool"]["driver"]["rules"][item["ruleIndex"]]["id"] == item["ruleId"]
    assert "deny_forbidden" in item["message"]["text"] and "allow" in item["message"]["text"]
    assert len(item["partialFingerprints"]["boundarycheck/case/v1"]) == 32
    assert item["properties"]["principal"] == "bob" and item["properties"]["review_state"] == "needs_review"
    assert doc["runs"][0]["invocations"][0]["exitCode"] == 1 and run["invocations"][0]["executionSuccessful"] is True


@pytest.mark.parametrize(
    ("severity", "level"), [("high", "error"), ("medium", "warning"), ("low", "note"), (None, "warning")]
)
def test_severity_maps_to_a_sarif_level(severity: str | None, level: str) -> None:
    from boundarycheck.sarif import level_for  # noqa: PLC0415

    assert level_for(severity) == level


async def test_every_rule_the_tool_can_emit_is_defined_once_and_findable() -> None:
    from boundarycheck.comparator import MUTATION_RULE  # noqa: PLC0415
    from boundarycheck.engine import CONCEAL_RULE  # noqa: PLC0415
    from boundarycheck.oracle import RULE_BY_REASON  # noqa: PLC0415

    cfg = parse(mini())
    doc = _valid(_sarif(await _run(cfg, FakeTransport(compliant(cfg)))))
    defined = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(defined) == len(set(defined))
    emitted = {*RULE_BY_REASON.values(), CONCEAL_RULE, MUTATION_RULE, "BC-FIELDS-01", "BC-LIST-01"}
    assert emitted <= set(defined)
    for rule in doc["runs"][0]["tool"]["driver"]["rules"]:
        assert rule["shortDescription"]["text"] and rule["help"]["text"] and rule["defaultConfiguration"]["level"]


async def test_a_state_diff_finding_carries_its_changed_rows_by_name_only() -> None:
    cfg = parse(write_config())
    transport = StatefulFake(
        compliant(cfg), mutates=lambda m, p, who: who == "bob" and p.endswith("pa1") and m == "PATCH"
    )
    doc = _valid(_sarif(await _run(cfg, transport)))
    item = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "BC-MUTATION-01")
    assert item["properties"]["state_changes"] == [{"table": "projects", "key": "p-1", "kind": "modified"}]
    assert "CHANGED SECRET TITLE" not in json.dumps(doc)


# ------------------------------------------------------------- nothing silently disappears ----
async def test_a_run_that_was_not_clean_is_not_a_clean_sarif() -> None:
    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg), creds={"alice"}))  # nobody else has a credential
    doc = _valid(_sarif(result))
    invocation = doc["runs"][0]["invocations"][0]
    assert (
        doc["runs"][0]["results"] == [] and invocation["exitCode"] == 2 and invocation["executionSuccessful"] is False
    )
    notes = invocation["toolExecutionNotifications"]
    assert notes and all(n["level"] in {"warning", "error"} for n in notes)
    assert any("not_run" in n["message"]["text"] and "no credential" in n["message"]["text"] for n in notes)


async def test_notifications_are_capped_and_the_cap_is_announced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("boundarycheck.sarif.MAX_NOTIFICATIONS", 20)
    from boundarycheck.sarif import MAX_NOTIFICATIONS  # noqa: PLC0415

    assert MAX_NOTIFICATIONS == 20
    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg), creds=set()))  # every credentialed case is not_run
    notes = _valid(_sarif(result))["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert len(notes) <= MAX_NOTIFICATIONS + 1
    not_run = sum(1 for c in result.cases if c.status.value != "no_issue_observed")
    assert (
        not_run > MAX_NOTIFICATIONS
        and "more" in notes[-1]["message"]["text"]
        and str(not_run - MAX_NOTIFICATIONS) in notes[-1]["message"]["text"]
    )


async def test_an_error_case_is_an_error_level_notification() -> None:
    cfg = parse(mini())

    def respond(method: str, path: str, who: str | None) -> Any:
        if who == "bob" and path.endswith("pa1"):
            return RuntimeError("boom")
        return compliant(cfg)(method, path, who)

    doc = _valid(_sarif(await _run(cfg, FakeTransport(respond))))
    notes = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert any(n["level"] == "error" and "error" in n["message"]["text"] for n in notes)


# ------------------------------------------------------------------------------- locations ----
async def test_a_result_points_at_the_actions_declaration_in_the_config() -> None:
    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg, tweak=_tweak_to(200, "bob:contact.private.read:PA1"))))
    doc = _valid(_sarif(result, config_uri="ci/boundarycheck.yaml", lines={"contact.private.read": 42}))
    location = doc["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "ci/boundarycheck.yaml"
    assert location["physicalLocation"]["region"]["startLine"] == 42
    assert location["logicalLocations"][0]["fullyQualifiedName"] == "bob:contact.private.read:PA1"
    assert doc["runs"][0]["artifacts"][0]["location"]["uri"] == "ci/boundarycheck.yaml"


async def test_an_unknown_action_line_falls_back_to_line_one() -> None:
    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg, tweak=_tweak_to(200, "bob:contact.private.read:PA1"))))
    doc = _valid(_sarif(result))
    assert doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


@pytest.mark.parametrize(
    "bad",
    [
        "/etc/passwd",
        "../x.yaml",
        "a/../b.yaml",
        "C:\\x.yaml",
        "file:///x",
        "https://evil/x",
        "x\ny.yaml",
        "",
        "a b\x00.yaml",
    ],
)
def test_a_config_uri_is_a_safe_relative_path_or_it_becomes_the_file_name(bad: str) -> None:
    from boundarycheck.sarif import safe_uri  # noqa: PLC0415

    got = safe_uri(bad)
    assert (
        not got.startswith(("/", "file:", "http"))
        and ".." not in got
        and "\n" not in got
        and "\x00" not in got
        and "\\" not in got
    )


def test_a_plain_relative_config_path_is_kept() -> None:
    from boundarycheck.sarif import safe_uri  # noqa: PLC0415

    assert (
        safe_uri("ci/boundarycheck.yaml") == "ci/boundarycheck.yaml"
        and safe_uri("boundarycheck.yaml") == "boundarycheck.yaml"
    )


def test_action_lines_reads_the_line_of_each_declaration_in_block_and_flow_style() -> None:
    from boundarycheck.sarif import action_lines  # noqa: PLC0415

    text = "version: 1\nscope:\n  id: demo\nactions:\n  - id: a.read\n    method: GET\n  - {id: b.read, method: GET}\n  - id: c.read\n    method: GET\n"
    assert action_lines(text) == {"a.read": 5, "b.read": 7, "c.read": 8}


@pytest.mark.parametrize("text", ["", "not: [valid", "actions: 5", "actions:\n  - 3\n  - {x: 1}\n", "\x00\x01"])
def test_action_lines_never_raises_on_odd_input(text: str) -> None:
    from boundarycheck.sarif import action_lines  # noqa: PLC0415

    assert action_lines(text) == {}


# ------------------------------------------------------------------------ privacy and shape ----
async def test_a_sarif_file_holds_no_credential_and_no_response_body() -> None:
    from boundarycheck.model import Observation  # noqa: PLC0415

    cfg = parse(mini())
    secret = fake_token("tok")

    def tweak(case: Any, obs: Any) -> Any:
        body = json.dumps({"id": "x", "email_private": "SENTINEL-BODY", "echo": secret}).encode()
        return (
            Observation(status=200, headers=obs.headers, body=body)
            if case.key == "bob:contact.private.read:PA1"
            else obs
        )

    result = await _run(cfg, FakeTransport(compliant(cfg, tweak=tweak), secrets=[secret]))
    text = _sarif(result)
    assert secret not in text and "SENTINEL-BODY" not in text


def test_control_characters_in_a_detail_cannot_reach_the_file() -> None:
    from boundarycheck.engine import CaseResult, RunResult  # noqa: PLC0415
    from boundarycheck.model import Status  # noqa: PLC0415

    nasty = "line1\nline2\x1b[31m\u2028end"
    case = CaseResult(id="BC-0001", key="a:b:c", rule_id="BC-ROLE-01", status=Status.FINDING_CANDIDATE, principal="a", action="b", resource="c",
                      expected="deny_forbidden", observed="allow", reason="role_denied", detail=nasty, severity="high", confidence="medium")  # fmt: skip
    result = RunResult(run_id="r", tool_version="0", scope_id="s", target_label="t", transport="x", started_at="2026-01-01T00:00:00Z",
                       finished_at="2026-01-01T00:00:01Z", attestation="a", cases=[case], limitations=[], evidence={})  # fmt: skip
    doc = _valid(_sarif(result))
    message = doc["runs"][0]["results"][0]["message"]["text"]
    assert "\n" not in message and "\x1b" not in message and "\u2028" not in message and "line1" in message


async def test_the_privacy_notice_travels_inside_the_file() -> None:
    cfg = parse(mini())
    doc = _valid(_sarif(await _run(cfg, FakeTransport(compliant(cfg)))))
    notice = doc["runs"][0]["properties"]["notice"].lower()
    assert "names" in notice and "public" in notice and "tenant" in notice


async def test_the_output_is_deterministic_and_fingerprints_follow_the_scope() -> None:
    cfg = parse(mini())
    result = await _run(
        cfg, FakeTransport(compliant(cfg, tweak=_tweak_to(200, "bob:contact.private.read:PA1"))), run_id="r1"
    )
    assert _sarif(result) == _sarif(result)
    first = _valid(_sarif(result))["runs"][0]["results"][0]["partialFingerprints"]["boundarycheck/case/v1"]
    other = parse({**mini(), "scope": {**mini()["scope"], "id": "another"}})
    result2 = await _run(
        other, FakeTransport(compliant(other, tweak=_tweak_to(200, "bob:contact.private.read:PA1"))), run_id="r2"
    )
    second = _valid(_sarif(result2))["runs"][0]["results"][0]["partialFingerprints"]["boundarycheck/case/v1"]
    again = _valid(
        _sarif(
            await _run(
                cfg, FakeTransport(compliant(cfg, tweak=_tweak_to(200, "bob:contact.private.read:PA1"))), run_id="r3"
            )
        )
    )["runs"][0]["results"][0]["partialFingerprints"]["boundarycheck/case/v1"]
    assert first == again and first != second


# ---------------------------------------------------------------------------- store and CLI ----
async def test_the_run_store_keeps_report_sarif_privately_and_prints_it_back(tmp_path: Path) -> None:
    from boundarycheck.evidence import RunStore  # noqa: PLC0415
    from boundarycheck.report import to_json, to_markdown  # noqa: PLC0415

    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg)))
    store = RunStore(tmp_path / "runs")
    run_dir = store.save(result, to_json(result), to_markdown(result), [], sarif=_sarif(result))
    assert (run_dir / "report.sarif").stat().st_mode & 0o777 == 0o600
    assert json.loads(store.read_report(result.run_id, "sarif"))["version"] == "2.1.0"


async def test_the_leak_guard_covers_the_sarif_file(tmp_path: Path) -> None:
    from boundarycheck.evidence import RunStore  # noqa: PLC0415
    from boundarycheck.redact import SecretLeakError  # noqa: PLC0415
    from boundarycheck.report import to_json, to_markdown  # noqa: PLC0415

    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg)))
    secret = fake_token("leak")
    with pytest.raises(SecretLeakError):
        RunStore(tmp_path / "runs").save(
            result, to_json(result), to_markdown(result), [secret], sarif=_sarif(result) + secret
        )
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").iterdir())


def test_a_report_in_sarif_that_was_never_written_is_a_clear_error(tmp_path: Path) -> None:
    from boundarycheck.evidence import RunStore, StoreError  # noqa: PLC0415

    with pytest.raises(StoreError):
        RunStore(tmp_path / "runs").read_report("20200101T000000Z-00000000", "sarif")
