"""The plan: principal x action x resource, in a stable order, computed without any network."""

from __future__ import annotations

from dataclasses import dataclass

from boundarycheck.config import ANONYMOUS, Action, Config, Resource
from boundarycheck.oracle import Expected, Oracle, build_path


@dataclass(frozen=True)
class BoundaryCase:
    id: str
    key: str
    principal: str | None  # None is the implicit anonymous principal
    action: Action
    resource: Resource
    expected: Expected
    path: str

    @property
    def rule_id(self) -> str:
        return self.expected.rule_id


def plan(config: Config) -> list[BoundaryCase]:
    oracle = Oracle(config)
    principals: list[str | None] = [None, *config.principals]
    cases: list[BoundaryCase] = []
    for principal in principals:
        for action in config.actions:
            for resource in config.resources:
                if resource.kind != action.resource_kind:
                    continue
                key = f"{principal or ANONYMOUS}:{action.id}:{resource.key}"
                cases.append(
                    BoundaryCase(
                        id=f"BC-{len(cases) + 1:04d}",
                        key=key,
                        principal=principal,
                        action=action,
                        resource=resource,
                        expected=oracle.expected_for(principal, action, resource),
                        path=build_path(action, resource),
                    )
                )
    return cases
