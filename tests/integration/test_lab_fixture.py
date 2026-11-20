"""S1 + S2 acceptance: the product judged against the reference lab.

The patched lab must be clean; each deliberately broken variant must be detected, and with exactly
one flaw on only that flaw's rule families may fire (attribution). All requests are reads."""

from __future__ import annotations

import json
from typing import Any

import pytest
import yaml

from tests.support import EXAMPLE, VULN_EXAMPLE

pytestmark = pytest.mark.milestone("S2")


async def _lab(variant: str = "patched", flaws: tuple[str, ...] = (), data: dict[str, Any] | None = None) -> Any:
    from boundarycheck.config import load_config, parse_config  # noqa: PLC0415
    from boundarycheck.engine import run  # noqa: PLC0415
    from boundarycheck.transports.lab_fixture import LabFixtureTransport  # noqa: PLC0415

    cfg = (
        parse_config(yaml.safe_dump(data, sort_keys=False))
        if data
        else load_config(VULN_EXAMPLE if variant == "vulnerable" else EXAMPLE)
    )
    async with LabFixtureTransport.open(cfg, variant=variant, flaws=flaws) as transport:
        return await run(cfg, transport)


def _findings(result: Any) -> dict[str, Any]:
    return {c.key: c for c in result.cases if c.status.value == "finding_candidate"}


def _summary(result: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in result.cases:
        counts[c.status.value] = counts.get(c.status.value, 0) + 1
    return counts


async def test_the_patched_lab_is_clean() -> None:
    result = await _lab()
    assert _summary(result) == {"no_issue_observed": len(result.cases)}, [
        (c.key, c.status.value, c.detail) for c in result.cases if c.status.value != "no_issue_observed"
    ][:5]
    assert len(result.cases) >= 240 and result.exit_code == 0
    assert result.transport == "fixture:tenant-boundary-lab:patched"


async def test_the_vulnerable_lab_with_every_flaw_off_is_clean_too() -> None:
    result = await _lab("vulnerable", ())
    assert result.exit_code == 0, [(c.key, c.detail) for c in result.cases if c.status.value != "no_issue_observed"][:5]


SINGLE = {
    "TENANT_PREDICATE_OMITTED": (
        {"bob:project.read:PB1", "bob:project.list:tenant-B", "bob:invoice.read:IB1"},
        {
            "BC-TENANT-01",
            "BC-FIELDS-01",
        },  # FIELDS: the editor role of one tenant bleeds into another
    ),
    "ROLE_CHECK_MISSING": ({"bob:contact.private.read:PA1"}, {"BC-ROLE-01"}),
    "PRIVATE_PROPERTY_SERIALIZED": (
        {"bob:project.read:PA1", "alice:project.read:PA1"},
        {"BC-FIELDS-01"},
    ),
    "MARKET_BOUNDARY_OMITTED": (
        {
            "alice:project.read:PA2",
            "alice:invoice.read:IA2",
            "alice:contact.private.read:PA2",
            "alice:project.list:tenant-A",
        },
        {"BC-SCOPE-01", "BC-LIST-01"},
    ),
}


# Since M4 the write checks run too. A write the tenant flaw lets through can be a ROLE finding as well:
# dave is an EDITOR of A and a VIEWER of B, and the flaw applies his A role to B's project.
WRITE_ACTIONS = {"project.write", "project.create", "member.role.write"}
WRITE_EXTRA = {"TENANT_PREDICATE_OMITTED": {"BC-ROLE-01"}}


@pytest.mark.parametrize("flaw", sorted(SINGLE))
async def test_each_flaw_is_detected_and_only_its_own_rule_families_fire(flaw: str) -> None:
    must_find, allowed_rules = SINGLE[flaw]
    result = await _lab("vulnerable", (flaw,))
    found = _findings(result)
    assert result.exit_code == 1
    assert must_find <= set(found), sorted(must_find - set(found))
    reads = {c.rule_id for c in found.values() if c.action not in WRITE_ACTIONS}
    writes = {c.rule_id for c in found.values() if c.action in WRITE_ACTIONS}
    assert reads <= allowed_rules, reads - allowed_rules
    assert writes <= allowed_rules | WRITE_EXTRA.get(flaw, set()), writes
    # nothing else went wrong: every other case is clean, or a concealment comparison that was not
    # evaluated precisely because one of its two requests is itself a finding
    for c in (c for c in result.cases if c.key not in found):
        assert c.status.value == "no_issue_observed" or (
            c.rule_id == "BC-CONCEAL-01" and c.status.value == "inconclusive" and "finding_candidate" in c.detail
        ), (c.key, c.status.value, c.detail)


async def test_the_tenant_flaw_has_two_further_consequences_the_tool_attributes_correctly() -> None:
    """Beyond the lab's own exploit list: an unscoped membership lookup (1) lets the editor role of
    tenant A bleed into tenant B (dave sees owner_principal_id on B's project) and (2) makes the
    suspended-tenant member gina answer 403 where a non-member must get 404 (existence oracle)."""
    found = _findings(await _lab("vulnerable", ("TENANT_PREDICATE_OMITTED",)))
    bleed = found["dave:project.read:PB1"]
    assert bleed.rule_id == "BC-FIELDS-01" and "owner_principal_id" in bleed.detail
    oracle = found["gina:project.read:PA1"]
    assert oracle.rule_id == "BC-TENANT-01" and oracle.severity == "medium" and "existence" in oracle.detail


async def test_the_private_property_finding_names_the_field_never_the_value() -> None:
    result = await _lab("vulnerable", ("PRIVATE_PROPERTY_SERIALIZED",))
    detail = _findings(result)["bob:project.read:PA1"].detail
    assert "contacts[].email_private" in detail and "SENTINEL" not in detail
    assert "SENTINEL-PRIV" not in json.dumps(result.evidence)  # the private values are masked by redaction.mask_fields


async def test_the_market_flaw_is_found_in_the_list_total_as_well_as_in_the_item() -> None:
    result = await _lab("vulnerable", ("MARKET_BOUNDARY_OMITTED",))
    assert "BC-LIST-01" in {c.rule_id for c in _findings(result).values()}


async def test_all_four_flaws_together_trip_every_rule_family() -> None:
    from tests.support_lab import ALL_FLAWS  # noqa: PLC0415

    result = await _lab("vulnerable", ALL_FLAWS)
    assert result.exit_code == 1
    assert {"BC-TENANT-01", "BC-ROLE-01", "BC-FIELDS-01", "BC-SCOPE-01", "BC-LIST-01"} <= {
        c.rule_id for c in _findings(result).values()
    }


async def test_a_hidden_market_object_is_indistinguishable_from_a_missing_one_on_the_patched_lab() -> None:
    result = await _lab()
    conceal = [c for c in result.cases if c.rule_id == "BC-CONCEAL-01"]
    assert len(conceal) >= 20 and {c.status.value for c in conceal} == {"no_issue_observed"}


async def test_the_fixture_run_is_reproducible() -> None:
    from boundarycheck.report import to_json  # noqa: PLC0415

    def scrub(text: str) -> dict[str, Any]:
        doc = json.loads(text)
        for key in ("run_id", "started_at", "finished_at"):
            doc.pop(key, None)
        for case in doc["cases"]:
            case.pop("observed_at", None)
            # The evidence is the real (redacted) response, and the lab puts a fresh request id in
            # every error body, so the evidence HASHES differ between runs. Every verdict is identical.
            case.pop("redacted_evidence_refs", None)
        return doc

    assert scrub(to_json(await _lab())) == scrub(to_json(await _lab()))


async def test_no_credential_reaches_the_report_or_the_evidence() -> None:
    from boundarycheck.config import load_config  # noqa: PLC0415
    from boundarycheck.engine import run  # noqa: PLC0415
    from boundarycheck.report import to_json, to_markdown  # noqa: PLC0415
    from boundarycheck.transports.lab_fixture import LabFixtureTransport  # noqa: PLC0415

    cfg = load_config(EXAMPLE)
    async with LabFixtureTransport.open(cfg, variant="patched", flaws=()) as transport:
        secrets = transport.secrets()
        result = await run(cfg, transport)
    assert len(secrets) == 7 and all(len(s) > 40 for s in secrets)
    blob = to_json(result) + to_markdown(result) + json.dumps(result.evidence)
    assert not [s for s in secrets if s in blob]


# ---------------------------------------------------- the two documented limit cases ----
def _example() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(EXAMPLE.read_text())
    return loaded


async def test_documented_false_positive_a_wrong_policy_is_reported_as_a_finding_candidate() -> None:
    """The tool judges the target against the policy it was GIVEN. A policy that is wrong (here:
    it says viewers may read private contacts) makes a correct target look broken. That is why a
    finding is a *candidate* that needs review, and why `confidence` is never `high`."""
    data = _example()
    data["policy"]["capabilities"]["contact.private.read"] = ["viewer", "editor", "admin", "owner"]
    result = await _lab(data=data)
    found = _findings(result)
    assert result.exit_code == 1 and "bob:contact.private.read:PA1" in found
    assert {c.rule_id for c in found.values()} == {"BC-ACCESS-01"} and {c.severity for c in found.values()} == {"low"}
    assert all("fails closed" in c.detail for c in found.values())


async def test_documented_inconclusive_a_response_the_tool_cannot_map_is_never_clean() -> None:
    """The lab answers 422 for a path id that is not a UUID. That status maps to no decision, so
    those cases are inconclusive and the run cannot exit 0."""
    data = _example()
    for res in data["resources"]:
        if res["key"] == "project-missing":
            res["ids"]["project_id"] = "not-a-uuid"
    result = await _lab(data=data)
    inconclusive = [c for c in result.cases if c.status.value == "inconclusive"]
    assert inconclusive and all(
        c.resource == "project-missing" or c.key.endswith("~project-missing") for c in inconclusive
    )
    assert any(c.resource == "project-missing" and c.rule_id != "BC-CONCEAL-01" for c in inconclusive)
    assert result.exit_code == 2
