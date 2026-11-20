"""The oracle decides what SHOULD happen, from the declared policy only (docs/contract.md s3)."""

from __future__ import annotations

from typing import Any

import pytest

from tests.support import mini, parse

pytestmark = pytest.mark.milestone("S1")


def _expect(data: dict[str, Any], principal: str | None, action: str, resource: str) -> Any:
    from boundarycheck.oracle import expected_for  # noqa: PLC0415

    cfg = parse(data)
    act = next(a for a in cfg.actions if a.id == action)
    res = next(r for r in cfg.resources if r.key == resource)
    return expected_for(cfg, principal, act, res)


@pytest.mark.parametrize(
    ("principal", "action", "resource", "outcome", "reason"),
    [
        (None, "project.read", "PA1", "deny_unauthenticated", "unauthenticated"),
        (None, "project.read", "PX", "deny_unauthenticated", "unauthenticated"),
        ("alice", "project.read", "PA1", "allow", "allowed"),
        ("bob", "project.read", "PA1", "allow", "allowed"),
        # cross tenant: concealed as not found, never forbidden
        ("bob", "project.read", "PB1", "deny_not_found", "no_membership"),
        ("carol", "project.read", "PA1", "deny_not_found", "no_membership"),
        # a missing object looks exactly like a hidden one
        ("alice", "project.read", "PX", "deny_not_found", "no_membership"),
        # a revoked membership is no membership
        ("frank", "project.read", "PA1", "deny_not_found", "no_membership"),
        # a disabled principal is stopped first, even for an object that does not exist
        ("dis", "project.read", "PA1", "deny_forbidden", "principal_inactive"),
        ("dis", "project.read", "PX", "deny_forbidden", "principal_inactive"),
        # members of a suspended tenant are told; non-members are not
        ("gina", "project.read", "PC1", "deny_forbidden", "tenant_inactive"),
        ("alice", "project.read", "PC1", "deny_not_found", "no_membership"),
        # scope (hidden market) is evaluated BEFORE role: even an owner gets 404
        ("alice", "project.read", "PA2", "deny_not_found", "scope_hidden"),
        ("bob", "contact.private.read", "PA2", "deny_not_found", "scope_hidden"),
        # role
        ("bob", "contact.private.read", "PA1", "deny_forbidden", "role_denied"),
        ("alice", "contact.private.read", "PA1", "allow", "allowed"),
        # tenant-level route
        ("alice", "project.list", "tA", "allow", "allowed"),
        ("alice", "project.list", "tB", "deny_not_found", "no_membership"),
        ("alice", "project.list", "tX", "deny_not_found", "no_membership"),
        ("gina", "project.list", "tC", "deny_forbidden", "tenant_inactive"),
    ],
)
def test_decision_table(principal: str | None, action: str, resource: str, outcome: str, reason: str) -> None:
    got = _expect(mini(), principal, action, resource)
    assert (got.outcome.value, got.reason) == (outcome, reason)


def test_hidden_is_not_found_false_turns_concealment_into_forbidden() -> None:
    data = mini()
    data["policy"]["hidden_is_not_found"] = False
    got = _expect(data, "bob", "project.read", "PB1")
    assert got.outcome.value == "deny_forbidden" and got.reason == "no_membership"


def test_the_role_comes_from_the_membership_of_the_resources_tenant_not_from_elsewhere() -> None:
    data = mini()
    data["memberships"].append({"principal": "bob", "tenant": "B", "role": "owner", "status": "active"})
    # bob is a viewer in A and an owner in B: roles must not bleed across tenants
    assert _expect(data, "bob", "contact.private.read", "PA1").outcome.value == "deny_forbidden"
    assert _expect(data, "bob", "contact.private.read", "PB1").outcome.value == "allow"


def test_visible_fields_depend_on_the_role_floor() -> None:
    owner = _expect(mini(), "alice", "project.read", "PA1")
    viewer = _expect(mini(), "bob", "project.read", "PA1")
    assert "owner_principal_id" in owner.visible_fields
    assert "owner_principal_id" not in viewer.visible_fields
    assert {"id", "title", "contacts", "contacts[].id"} <= viewer.visible_fields


def test_a_denial_has_no_visible_fields() -> None:
    assert _expect(mini(), "bob", "project.read", "PB1").visible_fields is None


def test_a_list_names_exactly_the_objects_the_principal_may_see() -> None:
    owner = _expect(mini(), "alice", "project.list", "tA")
    assert owner.visible_ids == frozenset({"pa1"})  # PA2 is hidden by scope
    assert _expect(mini(), "alice", "project.read", "PA1").visible_ids is None
    assert _expect(mini(), "alice", "project.list", "tB").visible_ids is None


def test_the_attribute_scope_is_per_tenant() -> None:
    data = mini()
    data["tenants"][0]["allowed"] = {"market": ["UK", "US"]}
    assert _expect(data, "alice", "project.read", "PA2").outcome.value == "allow"


def test_a_tenant_without_a_declared_scope_does_not_hide_anything() -> None:
    data = mini()
    data["tenants"][0]["allowed"] = {}
    assert _expect(data, "alice", "project.read", "PA2").outcome.value == "allow"


def test_a_resource_that_does_not_declare_a_scoped_attribute_is_not_subject_to_it() -> None:
    """Documented choice: a forgotten attribute makes the oracle expect `allow`, so a correct target
    that hides the object is reported as a low-severity candidate (fails closed) rather than a
    missing attribute silently hiding things or raising a false high-severity alarm."""
    data = mini()
    data["resources"][5]["attributes"] = {}
    assert _expect(data, "alice", "project.read", "PA2").outcome.value == "allow"


def test_the_oracle_is_deterministic_and_pure() -> None:
    a = _expect(mini(), "bob", "contact.private.read", "PA1")
    b = _expect(mini(), "bob", "contact.private.read", "PA1")
    assert a == b
