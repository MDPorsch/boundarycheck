"""SARIF 2.1.0 output (docs/design-v0.3.md s4).

Findings are results. Every case that was not clean and not a finding (inconclusive, incomplete, not_run,
policy_denied, error) is a tool notification, and the invocation records the exit code, so a run that was not
clean never looks clean in a viewer. Like the Markdown report it holds statuses, rule ids, the NAMES of
fields and the table, key and kind of changed rows, and never a response body or a credential.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Final

import yaml

from boundarycheck.engine import CaseResult, RunResult
from boundarycheck.model import Status

SARIF_VERSION: Final = "2.1.0"
SCHEMA_URI: Final = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI: Final = "https://github.com/MDPorsch/boundarycheck"
MAX_NOTIFICATIONS: Final = 200
MAX_MESSAGE: Final = 1000
FINGERPRINT: Final = "boundarycheck/case/v1"
NOTICE: Final = (
    "This file names your tenants, principals, routes and policy actions (never a response body or a credential). "
    "Uploading it to the code scanning of a PUBLIC repository publishes those names; for client work keep it private."
)

# rule id -> (name, short description, help, default level)
RULES: Final[dict[str, tuple[str, str, str, str]]] = {
    "BC-AUTHN-01": (
        "UnauthenticatedAccess",
        "A request without a credential was served",
        "A request with no credential was answered as if it were authenticated. Require authentication on this route.",
        "error",
    ),
    "BC-STATE-01": (
        "DisabledPrincipalServed",
        "A disabled principal was served",
        "A principal your policy marks disabled still got an answer. Refuse disabled accounts before any object lookup.",
        "error",
    ),
    "BC-TENANT-01": (
        "CrossTenantAccess",
        "Access across tenants (BOLA)",
        "A principal reached an object in a tenant where it has no active membership. Scope every lookup by the caller's tenant.",
        "error",
    ),
    "BC-STATE-02": (
        "SuspendedTenantServed",
        "A suspended tenant's data was served",
        "A member of a suspended tenant was served. Refuse requests for tenants that are not active.",
        "warning",
    ),
    "BC-SCOPE-01": (
        "OutOfScopeObjectServed",
        "An object outside the tenant's allowed scope was served",
        "An object whose attribute (for example its market) the tenant may not use was served. Apply the scope gate before the role gate.",
        "error",
    ),
    "BC-ROLE-01": (
        "RoleLimitNotEnforced",
        "A role limit was not enforced (BFLA)",
        "A role reached a route its policy denies. Check the capability for the caller's role on every route.",
        "error",
    ),
    "BC-ACCESS-01": (
        "AccessDeniedWherePolicyAllows",
        "Access was denied where the policy allows it",
        "The API failed closed where your declared policy allows access. Check the policy first, then the API.",
        "note",
    ),
    "BC-FIELDS-01": (
        "FieldExposure",
        "A response carries a field the role may not see (BOPLA)",
        "A field above the caller's role appeared in a response. Project responses by role, including nested and list items.",
        "warning",
    ),
    "BC-LIST-01": (
        "ListLeak",
        "A list names or counts objects the principal may not see",
        "A list route named an object, or a total, the principal may not see. Filter the list and its count by the caller's scope.",
        "error",
    ),
    "BC-CONCEAL-01": (
        "ExistenceOracle",
        "A hidden object answers differently from a missing one",
        "A hidden object and a missing one are distinguishable (status, headers or body shape). Answer both identically.",
        "warning",
    ),
    "BC-MUTATION-01": (
        "RefusedWriteChangedState",
        "A refused or failed request still changed state",
        "The target refused (or failed) a write and still persisted it. Run every authorization check before any side effect.",
        "error",
    ),
}
_LEVELS: Final = {"high": "error", "medium": "warning", "low": "note"}
_CONTROL: Final = re.compile(
    "[\x00-\x1f\x7f-\x9f"
    + chr(0x2028)
    + chr(0x2029)
    + "".join(map(chr, range(0x202A, 0x202F)))
    + "".join(map(chr, range(0x2066, 0x206A)))
    + "]+"
)
_SAFE_PATH: Final = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
DEFAULT_URI: Final = "boundarycheck.yaml"


def level_for(severity: str | None) -> str:
    return _LEVELS.get(severity or "", "warning")


def _text(value: object, limit: int = MAX_MESSAGE) -> str:
    return _CONTROL.sub(" ", str(value))[:limit]


def safe_uri(path: str) -> str:
    """A repository-relative path for the config file, or just its file name. Never absolute, never a scheme,
    never `..`: whatever the operator typed, this cannot point a viewer outside the repository."""
    if _SAFE_PATH.fullmatch(path or "") and not any(part in {".", ".."} for part in path.split("/")):
        return path
    name = (path or "").replace("\\", "/").rsplit("/", 1)[-1]
    return name if _SAFE_PATH.fullmatch(name) and name not in {".", ".."} else DEFAULT_URI


def action_lines(text: str) -> dict[str, int]:
    """The 1-based line of each action's declaration in the config, by action id. Never raises."""
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, ValueError, RecursionError):
        return {}
    found: dict[str, int] = {}
    if not isinstance(root, yaml.MappingNode):
        return found
    for key, value in root.value:
        if getattr(key, "value", None) != "actions" or not isinstance(value, yaml.SequenceNode):
            continue
        for item in value.value:
            if not isinstance(item, yaml.MappingNode):
                continue
            for k, v in item.value:
                if getattr(k, "value", None) == "id" and isinstance(v, yaml.ScalarNode):
                    found.setdefault(str(v.value), item.start_mark.line + 1)
    return found


def _rules() -> list[dict[str, Any]]:
    return [
        {
            "id": rule, "name": name, "shortDescription": {"text": short},
            "fullDescription": {"text": short + ". " + help_text}, "help": {"text": help_text},
            "defaultConfiguration": {"level": level}, "helpUri": f"{INFORMATION_URI}/blob/main/docs/contract.md",
            "properties": {"tags": ["security", "authorization"]},
        }
        for rule, (name, short, help_text, level) in RULES.items()
    ]  # fmt: skip


def _fingerprint(result: RunResult, case: CaseResult) -> str:
    return hashlib.sha256(f"{result.scope_id}|{case.rule_id}|{case.key}".encode()).hexdigest()[:32]


def _result(
    result: RunResult, case: CaseResult, index: dict[str, int], uri: str, lines: Mapping[str, int]
) -> dict[str, Any]:
    return {
        "ruleId": case.rule_id,
        "ruleIndex": index[case.rule_id],
        "level": level_for(case.severity),
        "kind": "fail",
        "message": {"text": _text(f"{case.id} {case.key}: {case.detail}")},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(1, lines.get(case.action, 1))},
                },
                "logicalLocations": [{"name": _text(case.key, 200), "kind": "member", "fullyQualifiedName": _text(case.key, 400)}],
            }
        ],
        "partialFingerprints": {FINGERPRINT: _fingerprint(result, case)},
        "properties": {
            "case": case.id, "principal": case.principal or "anonymous", "action": case.action, "resource": case.resource,
            "expected": case.expected, "observed": case.observed, "reason": case.reason, "severity": case.severity,
            "confidence": case.confidence, "review_state": case.review_state,
            "evidence": list(case.evidence_refs), "state_changes": [dict(c) for c in case.state_changes],
        },
    }  # fmt: skip


def _notifications(cases: list[CaseResult]) -> list[dict[str, Any]]:
    others = [c for c in cases if c.status not in (Status.NO_ISSUE_OBSERVED, Status.FINDING_CANDIDATE)]
    notes = [
        {
            "level": "error" if c.status is Status.ERROR else "warning",
            "message": {"text": _text(f"{c.id} {c.key}: {c.status.value}: {c.detail}")},
            "properties": {"status": c.status.value, "case": c.id},
        }
        for c in others[:MAX_NOTIFICATIONS]
    ]
    if len(others) > MAX_NOTIFICATIONS:
        notes.append(
            {
                "level": "warning",
                "message": {
                    "text": f"{len(others) - MAX_NOTIFICATIONS} more case(s) were not clean and are not listed here; see report.json"
                },
            }
        )
    return notes


def to_sarif(result: RunResult, *, config_uri: str = DEFAULT_URI, lines: Mapping[str, int] | None = None) -> str:
    uri = safe_uri(config_uri)
    index = {rule: i for i, rule in enumerate(RULES)}
    findings = [c for c in result.cases if c.status is Status.FINDING_CANDIDATE and c.rule_id in index]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "boundarycheck", "version": result.tool_version, "informationUri": INFORMATION_URI,
                "rules": _rules(),
            }
        },
        "invocations": [
            {
                "executionSuccessful": result.exit_code in (0, 1),
                "exitCode": result.exit_code,
                "startTimeUtc": result.started_at,
                "endTimeUtc": result.finished_at,
                "toolExecutionNotifications": _notifications(result.cases),
                "properties": {"attestation": _text(result.attestation, 2000), "limitations": [_text(x, 600) for x in result.limitations]},
            }
        ],
        "artifacts": [{"location": {"uri": uri}}],
        "results": [_result(result, c, index, uri, lines or {}) for c in findings],
        "properties": {
            "notice": NOTICE, "scope": _text(result.scope_id, 200), "target": _text(result.target_label, 200),
            "transport": _text(result.transport, 300), "run_id": result.run_id,
        },
    }  # fmt: skip
    return (
        json.dumps(
            {"$schema": SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]},
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
    )
