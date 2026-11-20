"""Planning, running, statuses and exit codes (docs/contract.md s1, s2, s5)."""

from __future__ import annotations

import socket
from typing import Any

import pytest

from tests.support import FakeTransport, compliant, mini, parse

pytestmark = pytest.mark.milestone("S1")


async def _run(config: Any, transport: Any) -> Any:
    from boundarycheck.engine import run  # noqa: PLC0415

    return await run(config, transport)


def _statuses(result: Any) -> list[str]:
    return [c.status.value for c in result.cases]


# --------------------------------------------------------------------------- plan ----
def test_the_plan_is_complete_stable_unique_and_needs_no_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from boundarycheck.planner import plan  # noqa: PLC0415

    def no_sockets(*_a: Any, **_k: Any) -> None:
        raise AssertionError("planning must not open a socket")

    monkeypatch.setattr(socket, "socket", no_sockets)
    cfg = parse(mini())
    cases = plan(cfg)
    # (6 principals + anonymous) x (project.read x 5 projects + project.list x 4 tenants + contacts x 5)
    assert len(cases) == 7 * (5 + 4 + 5)
    assert len({c.key for c in cases}) == len(cases)
    assert [c.id for c in cases][:3] == ["BC-0001", "BC-0002", "BC-0003"]
    assert cases[0].principal is None  # anonymous first
    assert [c.key for c in plan(cfg)] == [c.key for c in cases]
    first = next(c for c in cases if c.key == "alice:project.read:PA1")
    assert first.path == "/v1/projects/pa1"


def test_a_path_is_built_only_from_validated_template_and_ids() -> None:
    from boundarycheck.planner import plan  # noqa: PLC0415

    for case in plan(parse(mini())):
        assert case.path.startswith("/v1/") and "{" not in case.path and ".." not in case.path


# ---------------------------------------------------------------------- exit codes ----
@pytest.mark.parametrize(
    ("statuses", "code"),
    [
        ([], 2),
        (["no_issue_observed"], 0),
        (["no_issue_observed"] * 5, 0),
        (["no_issue_observed", "finding_candidate"], 1),
        (["finding_candidate", "error"], 1),
        (["no_issue_observed", "inconclusive"], 2),
        (["no_issue_observed", "not_run"], 2),
        (["no_issue_observed", "incomplete"], 2),
        (["no_issue_observed", "policy_denied"], 2),
        (["no_issue_observed", "error"], 2),
        (["error"], 2),
    ],
)
def test_exit_code_table(statuses: list[str], code: int) -> None:
    from boundarycheck.model import Status, exit_code  # noqa: PLC0415

    assert exit_code(Status(s) for s in statuses) == code


# ------------------------------------------------------------------------- running ----
async def test_a_target_that_follows_the_policy_is_clean() -> None:
    cfg = parse(mini())
    transport = FakeTransport(compliant(cfg))
    result = await _run(cfg, transport)
    assert set(_statuses(result)) == {"no_issue_observed"}
    assert result.exit_code == 0 and transport.closed is False  # the caller owns the transport
    assert {m for m, _p, _w in transport.sent} == {"GET"}


async def test_every_planned_case_appears_exactly_once_plus_the_concealment_checks() -> None:
    from boundarycheck.planner import plan  # noqa: PLC0415

    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg)))
    access = [c for c in result.cases if c.rule_id != "BC-CONCEAL-01"]
    assert [c.key for c in access] == [c.key for c in plan(cfg)]
    conceal = [c for c in result.cases if c.rule_id == "BC-CONCEAL-01"]
    assert conceal and all(c.status.value == "no_issue_observed" for c in conceal)


async def test_a_principal_without_a_credential_is_not_run_and_the_run_cannot_be_clean() -> None:
    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg), creds={"alice"}))
    by_principal = {c.principal: c.status.value for c in result.cases if c.rule_id != "BC-CONCEAL-01"}
    assert by_principal["bob"] == "not_run" and by_principal["alice"] == "no_issue_observed"
    assert by_principal[None] == "no_issue_observed"
    assert result.exit_code == 2
    assert all(
        "credential" in (c.detail or "") for c in result.cases if c.status.value == "not_run" and c.principal == "bob"
    )


async def test_the_request_budget_is_a_hard_stop() -> None:
    data = mini()
    data["scope"]["target"]["request_budget"] = 5
    cfg = parse(data)
    transport = FakeTransport(compliant(cfg))
    result = await _run(cfg, transport)
    assert len(transport.sent) == 5
    assert _statuses(result).count("policy_denied") > 50 and result.exit_code == 2
    assert all("budget" in (c.detail or "") for c in result.cases if c.status.value == "policy_denied")


async def test_a_finding_is_reported_and_wins_the_exit_code() -> None:
    cfg = parse(mini())

    def leak(case: Any, obs: Any) -> Any:
        from boundarycheck.model import Observation  # noqa: PLC0415

        if case.key == "bob:project.read:PB1":
            return Observation(status=200, headers={"content-type": "application/json"}, body=b'{"id":"pb1"}')
        return obs

    result = await _run(
        cfg,
        FakeTransport(compliant(cfg, tweak=leak), creds={"alice", "bob", "carol", "gina", "dis"}),
    )
    assert result.exit_code == 1
    finding = next(c for c in result.cases if c.status.value == "finding_candidate" and c.key == "bob:project.read:PB1")
    assert finding.review_state == "needs_review" and finding.rule_id == "BC-TENANT-01"
    assert "not_run" in _statuses(result)


async def test_a_transport_exception_is_an_error_case_not_a_crash() -> None:
    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(lambda *_: RuntimeError("boom with secret-looking text")))
    assert set(_statuses(result)) <= {"error", "not_run"} and "error" in _statuses(result)
    assert all("secret-looking" not in (c.detail or "") for c in result.cases)  # exceptions are summarized, not echoed
    assert result.exit_code == 2


async def test_a_policy_refusal_from_the_transport_is_policy_denied() -> None:
    from boundarycheck.model import PolicyRefusal  # noqa: PLC0415

    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(lambda *_: PolicyRefusal("method not allowed")))
    assert set(_statuses(result)) == {"policy_denied"}


async def test_an_egress_violation_aborts_the_run() -> None:
    from boundarycheck.model import EgressViolation  # noqa: PLC0415

    cfg = parse(mini())
    transport = FakeTransport(lambda *_: EgressViolation("peer was not loopback"))
    result = await _run(cfg, transport)
    assert len(transport.sent) == 1  # nothing else was sent after the violation
    assert _statuses(result).count("error") == 1 and set(_statuses(result)) == {"error", "not_run"}
    assert any("abort" in (c.detail or "").lower() for c in result.cases if c.status.value == "not_run")


async def test_the_transport_is_never_asked_for_a_non_read_method() -> None:
    cfg = parse(mini())
    transport = FakeTransport(compliant(cfg))
    await _run(cfg, transport)
    assert all(m in {"GET", "HEAD"} for m, _p, _w in transport.sent)


# --------------------------------------------------------------------- concealment ----
async def test_a_hidden_object_that_answers_differently_from_a_missing_one_is_a_finding() -> None:
    from boundarycheck.model import Observation  # noqa: PLC0415

    cfg = parse(mini())

    def distinguishable(case: Any, obs: Any) -> Any:
        if case.resource.key == "PB1" and obs.status == 404:  # same status, different body
            return Observation(
                status=404,
                headers=obs.headers,
                body=b'{"code":"deny_not_found","detail":"exists but hidden"}',
            )
        return obs

    result = await _run(cfg, FakeTransport(compliant(cfg, tweak=distinguishable)))
    bad = [c for c in result.cases if c.rule_id == "BC-CONCEAL-01" and c.status.value == "finding_candidate"]
    assert bad and all(c.resource == "PB1" for c in bad)
    assert not [c for c in result.cases if c.rule_id != "BC-CONCEAL-01" and c.status.value == "finding_candidate"]


async def test_request_ids_do_not_make_a_hidden_object_distinguishable() -> None:
    cfg = parse(mini())  # compliant() already puts a different request_id in every body and header
    result = await _run(cfg, FakeTransport(compliant(cfg)))
    assert all(c.status.value == "no_issue_observed" for c in result.cases if c.rule_id == "BC-CONCEAL-01")


async def test_without_a_missing_resource_probe_concealment_is_declared_untested() -> None:
    data = mini()
    data["resources"] = [r for r in data["resources"] if r["key"] != "PX"]
    cfg = parse(data)
    result = await _run(cfg, FakeTransport(compliant(cfg)))
    assert not [c for c in result.cases if c.rule_id == "BC-CONCEAL-01" and c.action == "project.read"]
    assert any("project" in lim and "concealment" in lim.lower() for lim in result.limitations)


async def test_concealment_with_an_unusable_peer_is_incomplete_not_clean() -> None:
    from boundarycheck.model import Observation  # noqa: PLC0415

    cfg = parse(mini())

    def broken_probe(case: Any, obs: Any) -> Any:
        return Observation(status=None, headers={}, body=b"", error="timeout") if case.resource.key == "PX" else obs

    result = await _run(cfg, FakeTransport(compliant(cfg, tweak=broken_probe)))
    pairs = [c for c in result.cases if c.rule_id == "BC-CONCEAL-01" and c.action == "project.read"]
    assert pairs and all(c.status.value in {"incomplete", "inconclusive"} for c in pairs)
    assert result.exit_code == 2


# ----------------------------------------------------------------- redaction in runs ----
async def test_an_echoed_credential_is_removed_from_the_evidence() -> None:
    from boundarycheck.model import Observation  # noqa: PLC0415

    token = "tok-" + "Zq81xKd02LmPq77"
    cfg = parse(mini())

    def echo(case: Any, obs: Any) -> Any:
        if case.key == "alice:project.read:PA1":
            return Observation(
                status=200,
                headers={"content-type": "application/json", "x-echo": token},
                body=f'{{"id":"pa1","title":"{token}"}}'.encode(),
            )
        return obs

    result = await _run(cfg, FakeTransport(compliant(cfg, tweak=echo), secrets=[token]))
    assert result.evidence and token not in repr(result.evidence) and token not in repr(result.cases)


async def test_if_redaction_fails_the_case_is_an_error_and_its_blob_is_discarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from boundarycheck import redact  # noqa: PLC0415

    def broken(self: Any, observation: Any) -> Any:
        raise redact.RedactionError("cannot redact")

    monkeypatch.setattr(redact.Redactor, "observation", broken)
    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg)))
    assert set(_statuses(result)) == {"error"} and result.evidence == {} and result.exit_code == 2
    assert all(c.evidence_refs == [] for c in result.cases)


async def test_evidence_refs_point_at_stored_blobs_by_their_sha256() -> None:
    import hashlib  # noqa: PLC0415
    import json  # noqa: PLC0415

    cfg = parse(mini())
    result = await _run(cfg, FakeTransport(compliant(cfg)))
    refs = {r for c in result.cases for r in c.evidence_refs}
    assert refs and refs <= set(result.evidence)
    for sha, blob in result.evidence.items():
        assert hashlib.sha256(json.dumps(blob, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == sha
