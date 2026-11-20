"""The comparator maps what was observed to a decision and compares it with the expectation
(docs/contract.md s2 and s4). A status code is never trusted alone."""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests.support import mini, parse

pytestmark = pytest.mark.milestone("S1")


def _obs(status: int | None, body: Any = None, headers: dict[str, str] | None = None, error: str | None = None) -> Any:
    from boundarycheck.model import Observation  # noqa: PLC0415

    raw = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    return Observation(status=status, headers={"content-type": "application/json", **(headers or {})}, body=raw, error=error)


def _case(principal: str | None, action: str, resource: str, data: dict[str, Any] | None = None) -> Any:
    from boundarycheck.planner import plan  # noqa: PLC0415

    cfg = parse(data or mini())
    key = f"{principal or 'anonymous'}:{action}:{resource}"
    return cfg, next(c for c in plan(cfg) if c.key == key)


def _verdict(principal: str | None, action: str, resource: str, observation: Any, data: dict[str, Any] | None = None) -> Any:
    from boundarycheck.comparator import compare  # noqa: PLC0415

    cfg, case = _case(principal, action, resource, data)
    return compare(cfg, case, observation)


DETAIL = {"id": "pa1", "title": "t", "contacts": [{"id": "c1"}]}


@pytest.mark.parametrize(
    ("status", "outcome"),
    [(200, "allow"), (201, "allow"), (204, "allow"), (401, "deny_unauthenticated"), (403, "deny_forbidden"), (404, "deny_not_found")],
)
def test_classify_maps_only_the_documented_statuses(status: int, outcome: str) -> None:
    from boundarycheck.comparator import classify  # noqa: PLC0415

    assert classify(_obs(status)).value == outcome


@pytest.mark.parametrize("status", [100, 301, 302, 304, 307, 400, 405, 409, 410, 413, 415, 418, 422, 429, 500, 502, 503, 504, 599])
def test_every_other_status_is_unmapped(status: int) -> None:
    from boundarycheck.comparator import classify  # noqa: PLC0415

    assert classify(_obs(status)) is None


def test_matching_allow_with_declared_fields_is_no_issue() -> None:
    v = _verdict("bob", "project.read", "PA1", _obs(200, DETAIL))
    assert v.status.value == "no_issue_observed"


def test_matching_denial_is_no_issue() -> None:
    assert _verdict("bob", "project.read", "PB1", _obs(404, {"code": "x"})).status.value == "no_issue_observed"
    assert _verdict(None, "project.read", "PA1", _obs(401)).status.value == "no_issue_observed"
    assert _verdict("bob", "contact.private.read", "PA1", _obs(403)).status.value == "no_issue_observed"


def test_a_cross_tenant_read_that_succeeds_is_a_finding_with_a_stable_rule_and_severity() -> None:
    v = _verdict("bob", "project.read", "PB1", _obs(200, DETAIL))
    assert v.status.value == "finding_candidate"
    assert v.rule_id == "BC-TENANT-01" and v.severity == "high" and v.confidence == "medium"
    assert v.observed == "allow"


def test_each_reason_has_its_own_rule_id() -> None:
    cases = {
        "BC-AUTHN-01": (None, "project.read", "PA1", _obs(200, DETAIL)),
        "BC-STATE-01": ("dis", "project.read", "PA1", _obs(200, DETAIL)),
        "BC-STATE-02": ("gina", "project.read", "PC1", _obs(200, DETAIL)),
        "BC-SCOPE-01": ("alice", "project.read", "PA2", _obs(200, DETAIL)),
        "BC-ROLE-01": ("bob", "contact.private.read", "PA1", _obs(200, {"items": [], "next_cursor": None, "total": 0})),
    }
    for rule, (p, a, r, o) in cases.items():
        v = _verdict(p, a, r, o)
        assert (v.status.value, v.rule_id) == ("finding_candidate", rule), rule


def test_a_403_where_a_404_was_expected_is_an_existence_oracle_finding() -> None:
    v = _verdict("bob", "project.read", "PB1", _obs(403))
    assert v.status.value == "finding_candidate" and "existence" in v.detail.lower()


def test_an_expected_allow_that_is_denied_is_a_low_severity_finding_that_fails_closed() -> None:
    v = _verdict("alice", "project.read", "PA1", _obs(403))
    assert v.status.value == "finding_candidate" and v.severity == "low"


def test_an_undeclared_field_is_exposure_and_the_finding_names_the_path_never_the_value() -> None:
    leaky = {**DETAIL, "contacts": [{"id": "c1", "email_private": "SECRET-VALUE-XYZ"}]}
    v = _verdict("bob", "project.read", "PA1", _obs(200, leaky))
    assert v.status.value == "finding_candidate" and v.rule_id == "BC-FIELDS-01"
    assert "contacts[].email_private" in v.detail
    assert "SECRET-VALUE-XYZ" not in v.detail


def test_a_field_above_the_role_floor_is_exposure_for_a_viewer_but_fine_for_an_owner() -> None:
    body = {**DETAIL, "owner_principal_id": "p1"}
    assert _verdict("bob", "project.read", "PA1", _obs(200, body)).status.value == "finding_candidate"
    assert _verdict("alice", "project.read", "PA1", _obs(200, body)).status.value == "no_issue_observed"


def test_a_missing_declared_field_is_not_an_exposure() -> None:
    assert _verdict("bob", "project.read", "PA1", _obs(200, {"id": "pa1"})).status.value == "no_issue_observed"


def test_an_allow_body_that_cannot_be_parsed_is_inconclusive_not_clean() -> None:
    assert _verdict("bob", "project.read", "PA1", _obs(200, b"<html>not json</html>")).status.value == "inconclusive"
    assert _verdict("bob", "project.read", "PA1", _obs(200, b"[1,2]")).status.value == "inconclusive"


@pytest.mark.parametrize("status", [301, 400, 422, 429, 500, 503])
def test_unmapped_statuses_are_inconclusive_never_clean(status: int) -> None:
    for principal, resource in (("bob", "PA1"), ("bob", "PB1")):
        assert _verdict(principal, "project.read", resource, _obs(status)).status.value == "inconclusive"


@pytest.mark.parametrize("error", ["timeout", "connection", "body_too_large", "unreadable"])
def test_transport_failures_are_incomplete_never_clean(error: str) -> None:
    assert _verdict("bob", "project.read", "PA1", _obs(None, error=error)).status.value == "incomplete"
    assert _verdict("bob", "project.read", "PB1", _obs(None, error=error)).status.value == "incomplete"


def test_a_redirect_is_policy_denied() -> None:
    assert _verdict("bob", "project.read", "PA1", _obs(None, error="redirect")).status.value == "policy_denied"


def test_a_list_may_only_name_objects_the_principal_may_see() -> None:
    ok = {"items": [{"id": "pa1", "title": "t"}], "next_cursor": None, "total": 1}
    assert _verdict("alice", "project.list", "tA", _obs(200, ok)).status.value == "no_issue_observed"
    leak = {"items": [{"id": "pa1", "title": "t"}, {"id": "pa2", "title": "hidden"}], "next_cursor": None, "total": 1}
    v = _verdict("alice", "project.list", "tA", _obs(200, leak))
    assert v.status.value == "finding_candidate" and v.rule_id == "BC-LIST-01"
    assert "pa2" in v.detail


def test_a_list_total_must_match_the_visible_count() -> None:
    body = {"items": [{"id": "pa1", "title": "t"}], "next_cursor": None, "total": 2}
    v = _verdict("alice", "project.list", "tA", _obs(200, body))
    assert v.status.value == "finding_candidate" and "total" in v.detail


def test_a_list_naming_an_undeclared_object_is_inconclusive() -> None:
    body = {"items": [{"id": "zzz-unknown", "title": "t"}], "next_cursor": None, "total": 1}
    assert _verdict("alice", "project.list", "tA", _obs(200, body)).status.value == "inconclusive"


def test_a_list_envelope_may_not_carry_extra_keys() -> None:
    body = {"items": [], "next_cursor": None, "total": 0, "debug": {"sql": "select"}}
    v = _verdict("alice", "project.list", "tA", _obs(200, body))
    assert v.status.value == "finding_candidate" and "debug" in v.detail


def test_page_items_are_checked_against_the_surface_fields() -> None:
    clean = {"items": [{"id": "c1", "email_private": "x"}], "next_cursor": None, "total": 1}
    assert _verdict("alice", "contact.private.read", "PA1", _obs(200, clean)).status.value == "no_issue_observed"
    leaky = {"items": [{"id": "c1", "email_private": "x", "ssn": "y"}], "next_cursor": None, "total": 1}
    assert _verdict("alice", "contact.private.read", "PA1", _obs(200, leaky)).status.value == "finding_candidate"


# ------------------------------------------------------------------------ concealment ----
def test_signature_ignores_declared_volatile_body_fields_and_request_id_headers() -> None:
    from boundarycheck.comparator import signature  # noqa: PLC0415

    a = _obs(404, {"code": "resource.not_found", "request_id": "1"}, {"x-request-id": "1"})
    b = _obs(404, {"request_id": "2", "code": "resource.not_found"}, {"x-request-id": "2"})
    assert signature(a, ["request_id"]) == signature(b, ["request_id"])


def test_signature_notices_status_content_type_and_body_differences() -> None:
    from boundarycheck.comparator import signature  # noqa: PLC0415

    base = _obs(404, {"code": "resource.not_found"})
    assert signature(base, []) != signature(_obs(403, {"code": "resource.not_found"}), [])
    assert signature(base, []) != signature(_obs(404, {"code": "other"}), [])
    assert signature(base, []) != signature(_obs(404, {"code": "resource.not_found"}, {"content-type": "text/plain"}), [])
    assert signature(base, []) != signature(_obs(404, {"code": "resource.not_found"}, {"cache-control": "no-store"}), [])


def test_signature_ignores_volatile_fields_at_any_depth() -> None:
    from boundarycheck.comparator import signature  # noqa: PLC0415

    a = _obs(404, {"outer": {"request_id": "1", "k": 1}})
    b = _obs(404, {"outer": {"request_id": "2", "k": 1}})
    assert signature(a, ["request_id"]) == signature(b, ["request_id"])
