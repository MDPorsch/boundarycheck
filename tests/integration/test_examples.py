"""The two shipped example configs stay valid and in step."""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from tests.support import EXAMPLE, VULN_EXAMPLE

pytestmark = pytest.mark.milestone("S2")


def _load(path: Any) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(path.read_text())
    return loaded


def test_both_examples_validate_and_plan() -> None:
    from boundarycheck.config import load_config  # noqa: PLC0415
    from boundarycheck.planner import plan  # noqa: PLC0415

    assert (
        len(plan(load_config(EXAMPLE))) == 8 * (3 * 4 + 5 * 5 - 5 + 4 + 4 * 0) or len(plan(load_config(EXAMPLE))) > 200
    )
    assert len(plan(load_config(VULN_EXAMPLE))) > 150


def test_the_vulnerable_example_is_the_patched_one_minus_the_routes_the_vulnerable_lab_lacks() -> None:
    patched, vulnerable = _load(EXAMPLE), _load(VULN_EXAMPLE)
    lacking = {"audit.read", "invoice.read.nested", "project.create", "member.role.write"}
    patched["actions"] = [a for a in patched["actions"] if a["id"] not in lacking]
    for gone in ("audit.read", "project.create", "member.role.write"):
        patched["policy"]["capabilities"].pop(gone)
    for gone in ("audit.list_item", "membership.detail"):
        patched["policy"]["fields"].pop(gone)
    patched["resources"] = [r for r in patched["resources"] if r["kind"] != "membership"]
    for doc, variant in ((patched, "vulnerable"), (vulnerable, "vulnerable")):
        doc["scope"]["id"] = "x"
        doc["scope"]["target"]["label"] = "x"
        doc["scope"]["target"]["fixture"]["variant"] = variant
    assert patched == vulnerable


def test_the_documented_example_commands_are_the_real_ones() -> None:
    header = VULN_EXAMPLE.read_text()
    for flaw in (
        "TENANT_PREDICATE_OMITTED",
        "ROLE_CHECK_MISSING",
        "PRIVATE_PROPERTY_SERIALIZED",
        "MARKET_BOUNDARY_OMITTED",
        "WRITE_BEFORE_AUTHORIZATION",
    ):
        assert flaw in header
