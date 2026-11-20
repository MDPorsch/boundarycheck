"""M4 acceptance: write checks and the state diff, judged against the reference lab (in process).

The patched lab must refuse every write and change nothing. Each flaw that lets a write through, and
the fifth flaw that writes and THEN refuses, must be found, and only by the right rule. A runner that
only reads would call the fifth flaw clean, and one test shows exactly that."""

from __future__ import annotations

from typing import Any

import pytest

from tests.support import EXAMPLE, VULN_EXAMPLE

pytestmark = pytest.mark.milestone("M4")

WRITE_ACTIONS = {"project.write", "project.create", "member.role.write"}


async def _lab(variant: str = "patched", flaws: tuple[str, ...] = (), **kwargs: Any) -> Any:
    from boundarycheck.config import load_config  # noqa: PLC0415
    from boundarycheck.engine import run  # noqa: PLC0415
    from boundarycheck.transports.lab_fixture import LabFixtureTransport  # noqa: PLC0415

    cfg = load_config(VULN_EXAMPLE if variant == "vulnerable" else EXAMPLE)
    async with LabFixtureTransport.open(cfg, variant=variant, flaws=flaws) as transport:
        result = await run(cfg, transport, **kwargs)
        final = await transport.snapshot() if getattr(transport, "state_aware", False) else None
    return result, final


def _writes(result: Any) -> list[Any]:
    return [c for c in result.cases if c.action in WRITE_ACTIONS]


def _findings(result: Any) -> dict[str, Any]:
    return {c.key: c for c in result.cases if c.status.value == "finding_candidate"}


def _not_clean(result: Any) -> list[tuple[str, str, str]]:
    return [(c.key, c.status.value, c.detail) for c in result.cases if c.status.value != "no_issue_observed"][:6]


async def test_the_lab_transport_is_state_aware_and_the_example_declares_writes() -> None:
    from boundarycheck.config import load_config  # noqa: PLC0415
    from boundarycheck.transports.lab_fixture import LabFixtureTransport  # noqa: PLC0415

    cfg = load_config(EXAMPLE)
    assert {a.id for a in cfg.actions if a.is_write} == WRITE_ACTIONS
    async with LabFixtureTransport.open(cfg) as transport:
        assert transport.state_aware is True
        before = await transport.snapshot()
        assert {"projects", "memberships", "tenants"} <= set(before)
        assert "audit_events" not in before and "alembic_version" not in before


async def test_the_patched_lab_refuses_every_write_and_changes_nothing() -> None:
    result, final = await _lab()
    writes = _writes(result)
    assert len(writes) >= 60, len(writes)
    assert {c.action for c in writes} == WRITE_ACTIONS
    assert not _not_clean(result), _not_clean(result)
    assert result.exit_code == 0 and all(c.state_changes == [] for c in result.cases)
    assert final is not None


async def test_the_fifth_flaw_is_found_by_the_state_diff_and_only_by_it() -> None:
    result, _ = await _lab("vulnerable", ("WRITE_BEFORE_AUTHORIZATION",))
    found = _findings(result)
    assert result.exit_code == 1
    assert {c.rule_id for c in found.values()} == {"BC-MUTATION-01"}
    assert {
        "bob:project.write:PA1",
        "carla:project.write:PA1",
        "gina:project.write:PC1",
        "alice:project.write:PB1",
    } <= set(found)
    assert all(c.action == "project.write" for c in found.values())
    assert all(c.state_changes and c.state_changes[0]["table"] == "projects" for c in found.values())
    # the status code is exactly the correct refusal in every one of them
    assert all(c.observed == c.expected for c in found.values())
    # nothing else is wrong: every read, every other write and every concealment comparison is clean
    others = [c for c in result.cases if c.key not in found]
    assert {c.status.value for c in others} == {"no_issue_observed"}


async def test_a_runner_that_only_reads_calls_the_fifth_flaw_clean() -> None:
    """Why the diff exists: without it the same flawed lab passes."""
    result, _ = await _lab("vulnerable", ("WRITE_BEFORE_AUTHORIZATION",), reads_only=True)
    assert result.exit_code == 0 and not _writes(result)
    assert any("reads-only" in lim.lower() or "reads only" in lim.lower() for lim in result.limitations)


async def test_the_write_exploits_of_the_role_flaw_are_now_detected() -> None:
    result, _ = await _lab("vulnerable", ("ROLE_CHECK_MISSING",))
    found = _findings(result)
    assert "bob:project.write:PA1" in found and found["bob:project.write:PA1"].rule_id == "BC-ROLE-01"
    assert found["bob:project.write:PA1"].state_changes, "the write really happened and the diff saw it"
    assert {c.rule_id for c in found.values()} <= {"BC-ROLE-01"}


async def test_the_write_exploit_of_the_tenant_flaw_is_now_detected() -> None:
    result, _ = await _lab("vulnerable", ("TENANT_PREDICATE_OMITTED",))
    found = _findings(result)
    assert "alice:project.write:PB1" in found and found["alice:project.write:PB1"].rule_id == "BC-TENANT-01"
    # dave is an editor of A and only a viewer of B; the flaw applies his A role to B's project
    assert "dave:project.write:PB1" in found and found["dave:project.write:PB1"].rule_id == "BC-ROLE-01"
    writes = {c.rule_id for c in found.values() if c.action in WRITE_ACTIONS}
    reads = {c.rule_id for c in found.values() if c.action not in WRITE_ACTIONS}
    assert writes <= {"BC-TENANT-01", "BC-ROLE-01"} and reads <= {"BC-TENANT-01", "BC-FIELDS-01"}


async def test_a_flaw_that_is_only_about_serialization_adds_no_write_finding() -> None:
    result, _ = await _lab("vulnerable", ("PRIVATE_PROPERTY_SERIALIZED",))
    assert not [c for c in _findings(result).values() if c.action in WRITE_ACTIONS]


async def test_the_market_flaw_lets_the_hidden_project_be_written_and_is_found_by_the_scope_rule() -> None:
    result, _ = await _lab("vulnerable", ("MARKET_BOUNDARY_OMITTED",))
    writes = {k: c for k, c in _findings(result).items() if c.action in WRITE_ACTIONS}
    # every member of tenant A who reaches the hidden project is a finding: alice and dave are let in
    # (a write that happens), bob is refused for his ROLE instead of the market (a different denial)
    assert set(writes) == {f"{who}:project.write:PA2" for who in ("alice", "bob", "dave")}
    assert {c.rule_id for c in writes.values()} == {"BC-SCOPE-01"}
    assert writes["alice:project.write:PA2"].state_changes, "the hidden project really was written"
    assert not writes["bob:project.write:PA2"].state_changes, "bob was refused, so nothing was written"


async def test_every_flaw_at_once_finds_all_three_kinds() -> None:
    result, _ = await _lab(
        "vulnerable", ("TENANT_PREDICATE_OMITTED", "ROLE_CHECK_MISSING", "WRITE_BEFORE_AUTHORIZATION")
    )
    rules = {c.rule_id for c in _findings(result).values() if c.action == "project.write"}
    assert {"BC-MUTATION-01", "BC-ROLE-01", "BC-TENANT-01"} <= rules


async def test_the_lab_is_pristine_again_after_a_run_that_made_changes() -> None:
    from boundarycheck.config import load_config  # noqa: PLC0415
    from boundarycheck.engine import run  # noqa: PLC0415
    from boundarycheck.transports.lab_fixture import LabFixtureTransport  # noqa: PLC0415

    cfg = load_config(VULN_EXAMPLE)
    async with LabFixtureTransport.open(cfg, variant="vulnerable", flaws=("WRITE_BEFORE_AUTHORIZATION",)) as transport:
        pristine = await transport.snapshot()
        result = await run(cfg, transport)
        assert result.exit_code == 1
        assert await transport.snapshot() == pristine


async def test_a_run_against_the_flawed_lab_is_reproducible() -> None:
    first, _ = await _lab("vulnerable", ("WRITE_BEFORE_AUTHORIZATION",), run_id="r")
    second, _ = await _lab("vulnerable", ("WRITE_BEFORE_AUTHORIZATION",), run_id="r")
    strip = lambda r: [(c.key, c.status.value, c.rule_id, c.state_changes) for c in r.cases]  # noqa: E731
    assert strip(first) == strip(second)


async def test_the_fixture_transport_refuses_methods_it_does_not_know() -> None:
    from boundarycheck.config import load_config  # noqa: PLC0415
    from boundarycheck.model import PolicyRefusal  # noqa: PLC0415
    from boundarycheck.transports.lab_fixture import LabFixtureTransport  # noqa: PLC0415

    async with LabFixtureTransport.open(load_config(EXAMPLE)) as transport:
        for method in ("TRACE", "CONNECT", "OPTIONS", "get"):
            with pytest.raises(PolicyRefusal):
                await transport.send(method, "/v1/projects/x", "alice")


async def test_a_body_is_refused_on_a_read_and_a_write_without_a_body_is_not_invented() -> None:
    from boundarycheck.config import load_config  # noqa: PLC0415
    from boundarycheck.model import PolicyRefusal  # noqa: PLC0415
    from boundarycheck.transports.lab_fixture import LabFixtureTransport  # noqa: PLC0415

    async with LabFixtureTransport.open(load_config(EXAMPLE)) as transport:
        with pytest.raises(PolicyRefusal):
            await transport.send("GET", "/v1/projects/x", "alice", b"{}")
