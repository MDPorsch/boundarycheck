"""Write checks on a state-aware transport (docs/contract.md s9), at the unit level.

A write is only ever planned where the policy says it must be refused. What the target answered is
compared as for reads; what it did to its own state is judged by an independent snapshot diff. A
refusal that persisted the write is a finding whatever the status code says."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from tests.support import FakeTransport, StatefulFake, compliant, dump, mini, parse, write_config

pytestmark = pytest.mark.milestone("M4")

WRITES = {"project.write", "project.create"}


def _bad(text: str, needle: str | None = None) -> None:
    from boundarycheck.config import ConfigError, parse_config  # noqa: PLC0415

    with pytest.raises(ConfigError) as caught:
        parse_config(text)
    if needle is not None:
        assert needle.lower() in str(caught.value).lower(), str(caught.value)


async def _run(config: Any, transport: Any, **kwargs: Any) -> Any:
    from boundarycheck.engine import run  # noqa: PLC0415

    return await run(config, transport, **kwargs)


def _case(result: Any, key: str) -> Any:
    return next(c for c in result.cases if c.key == key)


def _writes(result: Any) -> list[Any]:
    return [c for c in result.cases if c.action in WRITES]


# ------------------------------------------------------------------------------- config ----
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_write_methods_and_a_static_body_are_accepted(method: str) -> None:
    data = write_config()
    data["actions"][-2]["method"] = method
    action = parse(data).actions[-2]
    assert (
        action.method == method
        and action.is_write
        and action.body == {"title": "boundarycheck probe", "row_version": 1}
    )


def test_a_read_action_is_not_a_write() -> None:
    assert not parse(mini()).actions[0].is_write


@pytest.mark.parametrize("method", ["OPTIONS", "get", "TRACE", "CONNECT", "post", ""])
def test_any_other_method_is_still_refused(method: str) -> None:
    data = mini()
    data["actions"][0]["method"] = method
    _bad(dump(data))


def test_the_refusal_of_an_unknown_method_says_which_are_accepted() -> None:
    data = mini()
    data["actions"][0]["method"] = "TRACE"
    _bad(dump(data), "GET")


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_a_body_on_a_read_action_is_refused(method: str) -> None:
    data = mini()
    data["actions"][0]["method"] = method
    data["actions"][0]["body"] = {"a": 1}
    _bad(dump(data), "body")


@pytest.mark.parametrize("body", [["a"], "text", 5, True])
def test_a_body_must_be_a_json_object(body: Any) -> None:
    data = write_config()
    data["actions"][-2]["body"] = body
    _bad(dump(data))


def test_a_body_is_size_limited() -> None:
    data = write_config()
    data["actions"][-2]["body"] = {"title": "x" * 5000}
    _bad(dump(data), "body")


def test_a_body_is_depth_limited() -> None:
    nested: dict[str, Any] = {"v": 1}
    for _ in range(10):
        nested = {"n": nested}
    data = write_config()
    data["actions"][-2]["body"] = nested
    _bad(dump(data), "body")


def test_a_body_must_be_plain_json_data_not_a_yaml_date() -> None:
    text = dump(write_config()).replace(
        "title: boundarycheck probe\n    row_version: 1", "title: 2024-01-01\n    row_version: 1", 1
    )
    assert "2024-01-01" in text
    _bad(text, "body")


def test_a_write_action_still_needs_a_capability_entry() -> None:
    data = write_config()
    del data["policy"]["capabilities"]["project.write"]
    _bad(dump(data), "capabilities")


# -------------------------------------------------------------------------------- plan ----
def test_write_cases_are_planned_only_where_the_policy_refuses_the_request() -> None:
    from boundarycheck.model import Outcome  # noqa: PLC0415
    from boundarycheck.planner import plan  # noqa: PLC0415

    cases = [c for c in plan(parse(write_config())) if c.action.is_write]
    assert cases, "no write case was planned"
    assert all(c.expected.outcome is not Outcome.ALLOW for c in cases)
    keys = {c.key for c in cases}
    assert "bob:project.write:PA1" in keys  # a viewer may not write
    assert "anonymous:project.write:PA1" in keys
    assert "alice:project.write:PA1" not in keys  # an owner may: never sent
    assert "alice:project.create:tA" not in keys


def test_unexercised_writes_counts_exactly_the_combinations_the_policy_allows() -> None:
    from boundarycheck.model import Outcome  # noqa: PLC0415
    from boundarycheck.oracle import Oracle  # noqa: PLC0415
    from boundarycheck.planner import plan, unexercised_writes  # noqa: PLC0415

    cfg = parse(write_config())
    oracle = Oracle(cfg)
    allowed = sum(
        1
        for principal in [None, *cfg.principals]
        for action in cfg.actions
        if action.is_write
        for resource in cfg.resources
        if resource.kind == action.resource_kind
        and oracle.expected_for(principal, action, resource).outcome is Outcome.ALLOW
    )
    assert allowed > 0 and unexercised_writes(cfg) == allowed
    assert unexercised_writes(parse(mini())) == 0
    assert len([c for c in plan(cfg) if c.action.is_write]) + allowed == 7 * (5 + 4)


def test_adding_write_actions_does_not_renumber_nor_change_the_read_plan() -> None:
    from boundarycheck.planner import plan  # noqa: PLC0415

    reads = [(c.key, c.path, c.expected) for c in plan(parse(mini()))]
    kept = [(c.key, c.path, c.expected) for c in plan(parse(write_config())) if not c.action.is_write]
    assert kept == reads


# ---------------------------------------------------------------------------- compare ----
def _verdict(key: str, status: int | None, changes: list[Any], body: bytes = b"{}", error: str | None = None) -> Any:
    from boundarycheck.comparator import compare_write  # noqa: PLC0415
    from boundarycheck.model import Observation  # noqa: PLC0415
    from boundarycheck.planner import plan  # noqa: PLC0415

    cfg = parse(write_config())
    case = next(c for c in plan(cfg) if c.key == key)
    return compare_write(
        cfg,
        case,
        Observation(status=status, headers={"content-type": "application/json"}, body=body, error=error),
        changes,
    )


def _changed() -> list[Any]:
    from boundarycheck.statediff import StateChange  # noqa: PLC0415

    return [StateChange("projects", "p-1", "modified")]


def test_the_expected_refusal_and_no_change_is_clean() -> None:
    assert _verdict("bob:project.write:PA1", 403, []).status.value == "no_issue_observed"


@pytest.mark.parametrize("status", [401, 403, 404, 422, 500, 503, 409, 302])
def test_a_refusal_or_error_that_still_changed_state_is_a_mutation_finding(status: int) -> None:
    verdict = _verdict("bob:project.write:PA1", status, _changed())
    assert verdict.status.value == "finding_candidate" and verdict.rule_id == "BC-MUTATION-01"
    assert verdict.severity == "high" and verdict.confidence == "high"
    assert "projects" in verdict.detail and "SENTINEL" not in verdict.detail


def test_a_mutation_is_a_finding_even_when_the_status_is_exactly_the_expected_denial() -> None:
    verdict = _verdict("bob:project.write:PA1", 403, _changed())
    assert verdict.observed == "deny_forbidden" and verdict.rule_id == "BC-MUTATION-01"


def test_a_2xx_where_a_refusal_is_expected_keeps_the_access_rule_and_mentions_the_change() -> None:
    verdict = _verdict("bob:project.write:PA1", 200, _changed())
    assert verdict.status.value == "finding_candidate" and verdict.rule_id == "BC-ROLE-01"
    assert "state" in verdict.detail.lower() and "changed" in verdict.detail.lower()
    quiet = _verdict("bob:project.write:PA1", 200, [])
    assert quiet.rule_id == "BC-ROLE-01" and "changed" not in quiet.detail.lower()


def test_a_different_denial_without_a_change_is_a_finding_as_for_reads() -> None:
    verdict = _verdict("bob:project.write:PA1", 404, [])
    assert verdict.status.value == "finding_candidate" and verdict.rule_id != "BC-MUTATION-01"


def test_an_unmapped_status_without_a_change_is_inconclusive() -> None:
    assert _verdict("bob:project.write:PA1", 422, []).status.value == "inconclusive"
    assert _verdict("bob:project.write:PA1", 500, []).status.value == "inconclusive"


@pytest.mark.parametrize("error", ["timeout", "connection", "body_too_large"])
def test_a_transport_failure_is_incomplete_unless_state_changed(error: str) -> None:
    assert _verdict("bob:project.write:PA1", None, [], error=error).status.value == "incomplete"
    assert _verdict("bob:project.write:PA1", None, _changed(), error=error).rule_id == "BC-MUTATION-01"


# --------------------------------------------------------------------------------- engine ----
async def test_a_state_aware_target_that_refuses_cleanly_is_clean_and_is_never_reset() -> None:
    cfg = parse(write_config())
    transport = StatefulFake(compliant(cfg))
    result = await _run(cfg, transport)
    writes = _writes(result)
    assert len(writes) > 20 and {c.status.value for c in result.cases} == {"no_issue_observed"}
    assert result.exit_code == 0 and transport.resets == 0
    assert transport.snapshots == 1 + len(writes)  # one baseline, then one per write case


async def test_a_refusal_that_still_wrote_is_found_by_the_diff_and_the_state_is_restored() -> None:
    cfg = parse(write_config())
    transport = StatefulFake(
        compliant(cfg), mutates=lambda m, p, who: m == "PATCH" and p == "/v1/projects/pa1" and who == "bob"
    )
    result = await _run(cfg, transport)
    found = [c for c in result.cases if c.status.value == "finding_candidate"]
    assert [c.key for c in found] == ["bob:project.write:PA1"]
    case = found[0]
    assert case.rule_id == "BC-MUTATION-01" and case.severity == "high" and case.confidence == "high"
    assert case.observed == "deny_forbidden" and case.review_state == "needs_review"
    assert case.state_changes == [{"table": "projects", "key": "p-1", "kind": "modified"}]
    assert result.exit_code == 1 and transport.resets == 1
    assert "CHANGED SECRET TITLE" not in json.dumps([vars(c) for c in result.cases])


async def test_one_mutation_does_not_colour_the_cases_after_it() -> None:
    """Without the restore, the changed row would make every later diff non-empty."""
    cfg = parse(write_config())
    transport = StatefulFake(compliant(cfg), mutates=lambda m, p, who: who == "bob" and m == "PATCH")
    result = await _run(cfg, transport)
    found = {c.key for c in result.cases if c.status.value == "finding_candidate"}
    assert found == {f"bob:project.write:{k}" for k in ("PA1", "PA2", "PB1", "PC1", "PX")}
    assert transport.resets == len(found)


async def test_a_server_error_that_still_wrote_is_a_finding_too() -> None:
    from boundarycheck.model import Observation  # noqa: PLC0415

    cfg = parse(write_config())

    def tweak(case: Any, obs: Any) -> Any:
        if case.key == "bob:project.write:PA1":
            return Observation(status=500, headers=obs.headers, body=b'{"code":"internal.error"}')
        return obs

    transport = StatefulFake(
        compliant(cfg, tweak=tweak), mutates=lambda m, p, who: who == "bob" and p == "/v1/projects/pa1" and m == "PATCH"
    )
    result = await _run(cfg, transport)
    assert _case(result, "bob:project.write:PA1").rule_id == "BC-MUTATION-01"


async def test_a_2xx_to_a_forbidden_write_is_the_access_finding_and_the_change_is_reset() -> None:
    from boundarycheck.model import Observation  # noqa: PLC0415

    cfg = parse(write_config())

    def tweak(case: Any, obs: Any) -> Any:
        if case.key == "bob:project.write:PA1":
            return Observation(status=200, headers=obs.headers, body=b'{"id":"pa1"}')
        return obs

    transport = StatefulFake(
        compliant(cfg, tweak=tweak), mutates=lambda m, p, who: who == "bob" and m == "PATCH" and p.endswith("pa1")
    )
    result = await _run(cfg, transport)
    case = _case(result, "bob:project.write:PA1")
    assert case.rule_id == "BC-ROLE-01" and case.status.value == "finding_candidate"
    assert case.state_changes and transport.resets == 1


async def test_the_write_request_carries_exactly_the_declared_body_and_reads_carry_none() -> None:
    cfg = parse(write_config())
    transport = StatefulFake(compliant(cfg))
    await _run(cfg, transport)
    expected = json.dumps(
        {"title": "boundarycheck probe", "row_version": 1}, sort_keys=True, separators=(",", ":")
    ).encode()
    for (method, _path, _who), body in zip(transport.sent, transport.bodies, strict=True):
        assert (
            body is None
            if method == "GET"
            else body
            in (
                expected,
                json.dumps(
                    {"title": "boundarycheck probe", "market": "UK"}, sort_keys=True, separators=(",", ":")
                ).encode(),
            )
        )


async def test_a_failing_snapshot_is_an_error_never_clean_and_stops_the_remaining_writes() -> None:
    cfg = parse(write_config())
    transport = StatefulFake(compliant(cfg))
    transport.fail_snapshot_on = 3  # the baseline is call 1; this is the second write case's snapshot
    result = await _run(cfg, transport)
    writes = _writes(result)
    statuses = [c.status.value for c in writes]
    assert statuses[0] == "no_issue_observed" and statuses[1] == "error"
    assert set(statuses[2:]) == {"not_run"} and "snapshot" in writes[1].detail.lower()
    assert result.exit_code == 2


async def test_a_failing_baseline_snapshot_means_no_write_is_sent() -> None:
    cfg = parse(write_config())
    transport = StatefulFake(compliant(cfg))
    transport.fail_snapshot_on = 1
    result = await _run(cfg, transport)
    assert not any(m != "GET" for m, _p, _w in transport.sent)
    assert {c.status.value for c in _writes(result)} == {"not_run"} and result.exit_code == 2


async def test_a_failing_restore_keeps_the_finding_and_stops_the_remaining_writes() -> None:
    cfg = parse(write_config())
    transport = StatefulFake(
        compliant(cfg), mutates=lambda m, p, who: who == "bob" and p.endswith("pa1") and m == "PATCH"
    )
    transport.fail_reset = True
    result = await _run(cfg, transport)
    writes = _writes(result)
    index = next(i for i, c in enumerate(writes) if c.key == "bob:project.write:PA1")
    assert writes[index].rule_id == "BC-MUTATION-01" and writes[index].status.value == "finding_candidate"
    assert {c.status.value for c in writes[index + 1 :]} == {"not_run"}
    assert result.exit_code == 1  # a finding still wins


async def test_a_target_that_cannot_report_its_state_is_never_sent_a_write() -> None:
    cfg = parse(write_config())
    transport = FakeTransport(compliant(cfg))
    result = await _run(cfg, transport)
    assert not any(m != "GET" for m, _p, _w in transport.sent)
    writes = _writes(result)
    assert writes and {c.status.value for c in writes} == {"not_run"}
    assert all("state snapshot" in c.detail for c in writes)
    assert result.exit_code == 2
    reads = [c for c in result.cases if c.action not in WRITES]
    assert {c.status.value for c in reads} == {"no_issue_observed"}


async def test_reads_only_omits_the_writes_says_so_and_can_be_clean() -> None:
    from boundarycheck.planner import plan  # noqa: PLC0415

    cfg = parse(write_config())
    transport = FakeTransport(compliant(cfg))
    result = await _run(cfg, transport, reads_only=True)
    omitted = len([c for c in plan(cfg) if c.action.is_write])
    assert not _writes(result) and result.exit_code == 0
    assert not any(m != "GET" for m, _p, _w in transport.sent)
    notes = [lim for lim in result.limitations if "reads-only" in lim.lower() or "reads only" in lim.lower()]
    assert notes and str(omitted) in notes[0]


async def test_writes_the_policy_allows_are_disclosed_as_not_exercised() -> None:
    from boundarycheck.planner import unexercised_writes  # noqa: PLC0415

    cfg = parse(write_config())
    result = await _run(cfg, StatefulFake(compliant(cfg)))
    notes = [lim for lim in result.limitations if "not exercised" in lim.lower()]
    assert notes and str(unexercised_writes(cfg)) in notes[0]
    plain = await _run(parse(mini()), FakeTransport(compliant(parse(mini()))))
    assert not any("not exercised" in lim.lower() for lim in plain.limitations)


async def test_the_limitations_no_longer_claim_that_nothing_writes() -> None:
    cfg = parse(write_config())
    result = await _run(cfg, StatefulFake(compliant(cfg)))
    text = " ".join(result.limitations).lower()
    assert "fixture" in text and "write" in text
    assert "sends read-only requests (get/head). write-path authorization" not in text


async def test_concealment_is_derived_from_read_cases_only() -> None:
    plain_cfg, write_cfg = parse(mini()), parse(write_config())
    plain = await _run(plain_cfg, FakeTransport(compliant(plain_cfg)))
    mixed = await _run(write_cfg, StatefulFake(compliant(write_cfg)))
    assert [c.key for c in plain.cases if c.id.startswith("BC-C")] == [
        c.key for c in mixed.cases if c.id.startswith("BC-C")
    ]


async def test_a_run_with_writes_is_reproducible() -> None:
    cfg = parse(write_config())
    first = await _run(
        cfg, StatefulFake(compliant(cfg), mutates=lambda m, p, who: who == "bob" and m == "PATCH"), run_id="r"
    )
    second = await _run(
        cfg, StatefulFake(compliant(cfg), mutates=lambda m, p, who: who == "bob" and m == "PATCH"), run_id="r"
    )
    strip = lambda r: [(c.key, c.status.value, c.rule_id, c.state_changes) for c in r.cases]  # noqa: E731
    assert strip(first) == strip(second)


# --------------------------------------------------------------------------------- report ----
async def test_the_report_names_where_state_changed_and_never_what_it_held() -> None:
    from boundarycheck.report import to_json, to_markdown  # noqa: PLC0415

    cfg = parse(write_config())
    transport = StatefulFake(
        compliant(cfg), mutates=lambda m, p, who: who == "bob" and p.endswith("pa1") and m == "PATCH"
    )
    result = await _run(cfg, transport)
    doc = json.loads(to_json(result))
    case = next(c for c in doc["cases"] if c["key"] == "bob:project.write:PA1")
    assert case["state_changes"] == [{"table": "projects", "key": "p-1", "kind": "modified"}]
    assert all(c["state_changes"] == [] for c in doc["cases"] if c["key"] != "bob:project.write:PA1")
    markdown = to_markdown(result)
    for text in (to_json(result), markdown):
        assert "CHANGED SECRET TITLE" not in text and "title one" not in text
    assert "BC-MUTATION-01" in markdown and "projects" in markdown


def test_the_config_is_not_mutated_by_planning_writes() -> None:
    from boundarycheck.planner import plan  # noqa: PLC0415

    cfg = parse(write_config())
    before = copy.deepcopy(cfg.model_dump())
    plan(cfg)
    assert cfg.model_dump() == before


async def test_a_restore_that_does_not_restore_is_noticed_and_stops_the_remaining_writes() -> None:
    cfg = parse(write_config())
    transport = StatefulFake(
        compliant(cfg), mutates=lambda m, p, who: who == "bob" and p.endswith("pa1") and m == "PATCH"
    )
    transport.reset_is_a_lie = True
    result = await _run(cfg, transport)
    writes = _writes(result)
    index = next(i for i, c in enumerate(writes) if c.key == "bob:project.write:PA1")
    assert writes[index].rule_id == "BC-MUTATION-01"
    assert {c.status.value for c in writes[index + 1 :]} == {"not_run"}
    assert any("not restored" in c.detail for c in writes[index + 1 :])


async def test_a_request_that_failed_but_still_wrote_is_a_finding_not_just_an_error() -> None:
    cfg = parse(write_config())

    def responder(method: str, path: str, who: str | None) -> Any:
        if method == "PATCH" and path.endswith("pa1") and who == "bob":
            return RuntimeError("the connection died after the write")
        return compliant(cfg)(method, path, who)

    transport = StatefulFake(responder, mutates=lambda m, p, who: who == "bob" and p.endswith("pa1") and m == "PATCH")
    result = await _run(cfg, transport)
    case = _case(result, "bob:project.write:PA1")
    assert case.rule_id == "BC-MUTATION-01" and case.status.value == "finding_candidate" and case.state_changes
    assert transport.resets == 1


async def test_a_request_that_failed_and_wrote_nothing_is_an_error() -> None:
    cfg = parse(write_config())

    def responder(method: str, path: str, who: str | None) -> Any:
        if method == "PATCH" and path.endswith("pa1") and who == "bob":
            return RuntimeError("boom")
        return compliant(cfg)(method, path, who)

    result = await _run(cfg, StatefulFake(responder))
    case = _case(result, "bob:project.write:PA1")
    assert case.status.value == "error" and case.state_changes == []
