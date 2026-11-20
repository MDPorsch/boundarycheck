"""The plan: principal x action x resource, in a stable order, computed without any network."""

from __future__ import annotations

from dataclasses import dataclass

from boundarycheck.config import ANONYMOUS, Action, Config, Resource
from boundarycheck.model import Outcome
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
                expected = oracle.expected_for(principal, action, resource)
                if action.is_write and expected.outcome is Outcome.ALLOW:
                    continue  # a write the policy allows is never sent (docs/contract.md s9.2)
                key = f"{principal or ANONYMOUS}:{action.id}:{resource.key}"
                cases.append(
                    BoundaryCase(
                        id=f"BC-{len(cases) + 1:04d}",
                        key=key,
                        principal=principal,
                        action=action,
                        resource=resource,
                        expected=expected,
                        path=build_path(action, resource),
                    )
                )
    return cases


def unexercised_writes(config: Config) -> int:
    """How many (principal, write action, resource) combinations the policy ALLOWS and the run
    therefore does not send. Reported, so that "no write finding" is never read as "writes tested"."""
    oracle = Oracle(config)
    return sum(
        1
        for principal in [None, *config.principals]
        for action in config.actions
        if action.is_write
        for resource in config.resources
        if resource.kind == action.resource_kind
        and oracle.expected_for(principal, action, resource).outcome is Outcome.ALLOW
    )
