"""JSON is the source of truth; Markdown renders the same data (docs/contract.md s8)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.support import FakeTransport, compliant, mini, parse

pytestmark = pytest.mark.milestone("S1")

CASE_KEYS = {
    "id",
    "key",
    "rule_id",
    "status",
    "severity",
    "confidence",
    "principal",
    "action",
    "resource",
    "expected",
    "observed",
    "reason",
    "detail",
    "redacted_evidence_refs",
    "limitations",
    "review_state",
    "observed_at",
}


async def _result(tweak: Any = None, data: dict[str, Any] | None = None) -> Any:
    from boundarycheck.engine import run  # noqa: PLC0415

    cfg = parse(data or mini())
    return cfg, await run(cfg, FakeTransport(compliant(cfg, tweak=tweak)))


async def test_the_json_report_has_the_documented_shape() -> None:
    from boundarycheck.report import to_json  # noqa: PLC0415

    _cfg, result = await _result()
    doc = json.loads(to_json(result))
    assert doc["schema_version"] == "1" and doc["tool"]["name"] == "boundarycheck" and doc["tool"]["version"]
    assert doc["scope"] == {"id": "unit", "target_label": "unit-target"} and doc["transport"] == "fake"
    assert "attested" in doc["attestation"].lower() or "not required" in doc["attestation"].lower()
    assert doc["summary"]["exit_code"] == 0 and doc["summary"]["total"] == len(doc["cases"])
    assert sum(doc["summary"]["by_status"].values()) == len(doc["cases"])
    assert all(set(c) >= CASE_KEYS for c in doc["cases"])
    assert any("secure" in lim for lim in doc["limitations"])
    assert any("write" in lim.lower() for lim in doc["limitations"])
    assert any("policy" in lim.lower() for lim in doc["limitations"])


async def test_findings_carry_severity_confidence_and_a_review_state() -> None:
    from boundarycheck.model import Observation  # noqa: PLC0415
    from boundarycheck.report import to_json  # noqa: PLC0415

    def leak(case: Any, obs: Any) -> Any:
        if case.key == "bob:project.read:PB1":
            return Observation(status=200, headers={"content-type": "application/json"}, body=b'{"id":"pb1"}')
        return obs

    _cfg, result = await _result(leak)
    doc = json.loads(to_json(result))
    finding = next(c for c in doc["cases"] if c["key"] == "bob:project.read:PB1")
    assert finding["status"] == "finding_candidate" and finding["severity"] == "high"
    assert finding["confidence"] == "medium" and finding["review_state"] == "needs_review"
    assert finding["expected"] == "deny_not_found" and finding["observed"] == "allow"
    assert doc["summary"]["exit_code"] == 1


async def test_the_report_never_contains_response_bodies_only_hashes_of_redacted_evidence() -> None:
    from boundarycheck.report import to_json  # noqa: PLC0415

    _cfg, result = await _result()
    text = to_json(result)
    assert '"items"' not in text and "next_cursor" not in text
    assert all(len(ref) == 64 for c in json.loads(text)["cases"] for ref in c["redacted_evidence_refs"])


async def test_two_identical_runs_produce_identical_reports_apart_from_run_metadata() -> None:
    from boundarycheck.report import to_json  # noqa: PLC0415

    def scrub(doc: dict[str, Any]) -> dict[str, Any]:
        for key in ("run_id", "started_at", "finished_at"):
            doc.pop(key, None)
        for case in doc["cases"]:
            case.pop("observed_at", None)
        return doc

    _c1, one = await _result()
    _c2, two = await _result()
    assert scrub(json.loads(to_json(one))) == scrub(json.loads(to_json(two)))


async def test_markdown_renders_the_same_facts_and_states_the_limits() -> None:
    from boundarycheck.report import to_markdown  # noqa: PLC0415

    _cfg, result = await _result()
    md = to_markdown(result)
    assert md.startswith("# boundarycheck report")
    for status in ("no_issue_observed", "finding_candidate", "inconclusive", "not_run"):
        assert status in md
    assert "does not mean" in md.lower() and "secure" in md.lower()
    assert result.run_id in md and "unit" in md


async def test_markdown_cannot_be_broken_or_injected_by_hostile_response_content() -> None:
    from boundarycheck.model import Observation  # noqa: PLC0415
    from boundarycheck.report import to_markdown  # noqa: PLC0415

    evil = "x`\n| fake | row |\n# Heading\n<script>alert(1)</script>[link](http://evil.invalid)"

    def leak(case: Any, obs: Any) -> Any:
        if case.key == "alice:project.read:PA1":
            return Observation(
                status=200,
                headers={"content-type": "application/json"},
                body=('{"id":"pa1","' + evil.replace('"', "").replace("\n", "\\n") + '":1}').encode(),
            )
        return obs

    _cfg, result = await _result(leak)
    md = to_markdown(result)
    assert "<script>" not in md and "\n# Heading" not in md and "\n| fake | row |" not in md
    assert "](http://evil.invalid)" not in md


async def test_a_clean_run_report_does_not_say_secure() -> None:
    from boundarycheck.report import to_markdown  # noqa: PLC0415

    _cfg, result = await _result()
    md = to_markdown(result).lower()
    # the only place the word may appear is the disclaimer that says the opposite
    assert md.count("is secure") == md.count("does not mean the target is secure") and "no vulnerabilities" not in md
