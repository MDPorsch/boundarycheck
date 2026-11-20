"""v0.3 (docs/design-v0.3.md s1): an action may request the root path `/`. Every other path rule stays."""

from __future__ import annotations

from typing import Any

import pytest

from tests.support import dump, fake_server, fake_token, mini, parse

pytestmark = pytest.mark.milestone("V3")


def _with_path(path: str) -> dict[str, Any]:
    data = mini()
    data["actions"].append(
        {"id": "root.read", "method": "GET", "path": path, "resource_kind": "tenant", "surface": "project.detail"}
    )
    data["policy"]["capabilities"]["root.read"] = ["viewer", "editor", "admin", "owner"]
    return data


def test_the_root_path_is_accepted_and_planned_as_a_slash() -> None:
    from boundarycheck.planner import plan  # noqa: PLC0415

    cfg = parse(_with_path("/"))
    cases = [c for c in plan(cfg) if c.action.id == "root.read"]
    assert cases and {c.path for c in cases} == {"/"}


def test_the_root_path_with_a_parameter_is_still_a_normal_path() -> None:
    from boundarycheck.planner import plan  # noqa: PLC0415

    cfg = parse(_with_path("/{tenant_id}"))
    assert {c.path for c in plan(cfg) if c.action.id == "root.read"} == {"/ta", "/tb", "/tc", "/tx"}


@pytest.mark.parametrize("path", ["", "//", "///", "/ ", " /", "/?x=1", "/#f", "/..", "/./", "/.", "/%2e", "/a//b", "\\", "/\n"])
def test_every_other_path_rule_is_unchanged(path: str) -> None:
    from boundarycheck.config import ConfigError, parse_config  # noqa: PLC0415

    with pytest.raises(ConfigError):
        parse_config(dump(_with_path(path)))


async def test_the_live_transport_sends_the_root_path_exactly_once_as_a_slash() -> None:
    from boundarycheck.transports.live import LiveTransport  # noqa: PLC0415

    token = fake_token()
    with fake_server() as server:
        server.json("/", {"hello": "root"})
        transport = LiveTransport(
            server.base_url, credentials={"alice": "BC_A"}, environ={"BC_A": token}, resolver=lambda _h: ["127.0.0.1"]
        )
        try:
            obs = await transport.send("GET", "/", "alice")
        finally:
            await transport.aclose()
        assert obs.status == 200 and b"root" in obs.body
        assert [r["path"] for r in server.requests] == ["/"]
