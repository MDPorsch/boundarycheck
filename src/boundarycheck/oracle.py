"""The oracle: what SHOULD happen, decided from the declared policy only (docs/contract.md s3).

Independence is structural: this module imports nothing from the engine, the transports or the
target (tests/unit/test_independence.py). A bug in whatever is being judged cannot be mirrored here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from boundarycheck.config import Action, Config, Resource
from boundarycheck.model import Outcome

RULE_BY_REASON = {
    "unauthenticated": "BC-AUTHN-01",
    "principal_inactive": "BC-STATE-01",
    "no_membership": "BC-TENANT-01",
    "tenant_inactive": "BC-STATE-02",
    "scope_hidden": "BC-SCOPE-01",
    "role_denied": "BC-ROLE-01",
    "allowed": "BC-ACCESS-01",
}


@dataclass(frozen=True)
class Expected:
    outcome: Outcome
    reason: str
    role: str | None = None
    visible_fields: frozenset[str] | None = None
    visible_ids: frozenset[str] | None = None

    @property
    def rule_id(self) -> str:
        return RULE_BY_REASON[self.reason]


class Oracle:
    """Indexes a config once; `expected_for` is a pure function of (principal, action, resource)."""

    def __init__(self, config: Config) -> None:
        self._cfg = config
        self._tenants = {t.key: t for t in config.tenants}
        self._active = {(m.principal, m.tenant): m.role for m in config.memberships if m.status == "active"}
        self._rank = {role: index for index, role in enumerate(config.policy.roles)}

    def _hidden(self) -> Outcome:
        return Outcome.DENY_NOT_FOUND if self._cfg.policy.hidden_is_not_found else Outcome.DENY_FORBIDDEN

    def _in_scope(self, tenant_key: str, resource: Resource) -> bool:
        """A resource is outside the tenant's scope when it declares an attribute whose value the
        tenant is not permitted. A resource that does not declare the attribute is not subject to it."""
        for attribute, permitted in self._tenants[tenant_key].allowed.items():
            value = resource.attributes.get(attribute)
            if value is not None and value not in permitted:
                return False
        return True

    def expected_for(self, principal: str | None, action: Action, resource: Resource) -> Expected:  # noqa: PLR0911
        if principal is None:
            return Expected(Outcome.DENY_UNAUTHENTICATED, "unauthenticated")
        if self._cfg.principals[principal].status != "active":
            return Expected(Outcome.DENY_FORBIDDEN, "principal_inactive")
        role = self._active.get((principal, resource.tenant)) if resource.tenant is not None else None
        if not resource.exists or role is None or resource.tenant is None:
            return Expected(self._hidden(), "no_membership")
        tenant = self._tenants[resource.tenant]
        if tenant.state != "active":
            return Expected(Outcome.DENY_FORBIDDEN, "tenant_inactive", role)
        if not self._in_scope(resource.tenant, resource):
            return Expected(self._hidden(), "scope_hidden", role)
        if role not in self._cfg.policy.capabilities.get(action.cap, []):
            return Expected(Outcome.DENY_FORBIDDEN, "role_denied", role)
        floor = self._cfg.policy.fields.get(action.surface, {})
        visible = frozenset(path for path, minimum in floor.items() if self._rank[role] >= self._rank[minimum])
        return Expected(Outcome.ALLOW, "allowed", role, visible, self._visible_ids(action, resource))

    def _visible_ids(self, action: Action, resource: Resource) -> frozenset[str] | None:
        spec = action.list_spec
        if spec is None:
            return None
        return frozenset(
            r.ids[spec.id_key]
            for r in self._cfg.resources
            if r.kind == spec.kind and r.exists and r.tenant == resource.tenant and resource.tenant is not None
            and self._in_scope(resource.tenant, r)
        )  # fmt: skip


def expected_for(config: Config, principal: str | None, action: Action, resource: Resource) -> Expected:
    return Oracle(config).expected_for(principal, action, resource)


_PARAM = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


def build_path(action: Action, resource: Resource) -> str:
    """The request path: the validated template with the resource's validated ids substituted."""
    return _PARAM.sub(lambda m: resource.ids[m.group(1)], action.path)
