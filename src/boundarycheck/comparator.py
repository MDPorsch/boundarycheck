"""The comparator: what was OBSERVED against what was EXPECTED (docs/contract.md s4).

Like the oracle it imports nothing that talks to a target. A status code is never trusted alone:
a matching `allow` is also checked against the declared field projection and, for lists, against
the declared set of objects the principal may see.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from boundarycheck.config import Action, Config
from boundarycheck.model import Observation, Outcome, Status

ENVELOPE = ("items", "next_cursor", "total")
_SAFE = re.compile(r"[^A-Za-z0-9_.\[\]-]")
SIGNATURE_HEADERS = ("content-type", "cache-control", "www-authenticate")


@dataclass(frozen=True)
class Verdict:
    status: Status
    observed: str | None
    detail: str
    rule_id: str
    severity: str | None = None
    confidence: str | None = None


def classify(observation: Observation) -> Outcome | None:
    """Map an HTTP status to a decision. Anything else is unmapped (None): never guessed."""
    status = observation.status
    if status is None:
        return None
    if 200 <= status < 300:
        return Outcome.ALLOW
    return {
        401: Outcome.DENY_UNAUTHENTICATED,
        403: Outcome.DENY_FORBIDDEN,
        404: Outcome.DENY_NOT_FOUND,
    }.get(status)


def _clean(text: object, limit: int = 60) -> str:
    """Names that came from the target are shown only in a restricted alphabet."""
    return _SAFE.sub("?", str(text))[:limit]


def paths(value: Any, prefix: str = "") -> Iterator[str]:
    """Every field path in a JSON value: `a`, `a.b`, `items[].id` (lists are transparent)."""
    if isinstance(value, dict):
        for key, inner in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield path
            yield from paths(inner, path)
    elif isinstance(value, list):
        for element in value:
            yield from paths(element, f"{prefix}[]")


def _exposed(found: set[str], allowed: frozenset[str], prefix: str = "") -> list[str]:
    return sorted(prefix + p for p in found if p not in allowed)


def _names(items: list[str]) -> str:
    shown = ", ".join(_clean(i) for i in items[:5])
    return shown + (f" (and {len(items) - 5} more)" if len(items) > 5 else "")


def _finding(case: Any, observed: Outcome, obs: Observation) -> Verdict:
    exp = case.expected
    base = f"expected {exp.outcome.value} ({exp.reason}), observed {observed.value} (HTTP {obs.status})"
    if observed is Outcome.ALLOW:
        severity = "medium" if exp.reason == "tenant_inactive" else "high"
        return Verdict(
            Status.FINDING_CANDIDATE,
            observed.value,
            base + ": access was granted where the policy denies it",
            case.rule_id,
            severity,
            "medium",
        )
    if exp.outcome is Outcome.ALLOW:
        return Verdict(
            Status.FINDING_CANDIDATE,
            observed.value,
            base + ": denied where the policy allows it (fails closed; check the policy first)",
            case.rule_id,
            "low",
            "medium",
        )
    if exp.outcome is Outcome.DENY_NOT_FOUND and observed is Outcome.DENY_FORBIDDEN:
        return Verdict(
            Status.FINDING_CANDIDATE,
            observed.value,
            base + ": the response reveals that the object exists (existence oracle)",
            case.rule_id,
            "medium",
            "medium",
        )
    return Verdict(
        Status.FINDING_CANDIDATE,
        observed.value,
        base + ": a different denial than declared",
        case.rule_id,
        "low",
        "medium",
    )


def compare(config: Config, case: Any, observation: Observation) -> Verdict:
    if observation.error == "redirect":
        return Verdict(
            Status.POLICY_DENIED,
            None,
            "a redirect was returned and is never followed",
            case.rule_id,
        )
    if observation.error is not None:
        return Verdict(
            Status.INCOMPLETE,
            None,
            f"the request did not complete ({_clean(observation.error, 30)})",
            case.rule_id,
        )
    observed = classify(observation)
    if observed is None:
        return Verdict(
            Status.INCONCLUSIVE,
            None,
            f"HTTP {observation.status} does not map to a decision",
            case.rule_id,
        )
    if observed is not case.expected.outcome:
        return _finding(case, observed, observation)
    ok = Verdict(
        Status.NO_ISSUE_OBSERVED,
        observed.value,
        f"observed {observed.value} as declared",
        case.rule_id,
    )
    if observed is not Outcome.ALLOW or case.action.method == "HEAD" or observation.status == 204:
        return ok
    return _check_allowed(config, case, observation, ok)


def _check_allowed(config: Config, case: Any, obs: Observation, ok: Verdict) -> Verdict:  # noqa: PLR0911
    try:
        doc = json.loads(obs.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return Verdict(
            Status.INCONCLUSIVE,
            "allow",
            "the response body is not JSON, so its fields cannot be checked",
            case.rule_id,
        )
    if not isinstance(doc, dict):
        return Verdict(Status.INCONCLUSIVE, "allow", "the response body is not a JSON object", case.rule_id)
    action: Action = case.action
    visible: frozenset[str] = case.expected.visible_fields or frozenset()
    if action.paged:
        spec = action.list_spec
        envelope = set(ENVELOPE) | ({spec.total_field} if spec is not None and spec.total_field else set())
        extra = sorted(set(doc) - envelope)
        if extra:
            return _exposure(case, f"unexpected top-level field(s): {_names(extra)}")
        items = doc.get("items")
        if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
            return Verdict(Status.INCONCLUSIVE, "allow", "'items' is not a list of objects", case.rule_id)
        leaked = _exposed({p for i in items for p in paths(i)}, visible, "items[].")
        if leaked:
            return _exposure(case, f"undeclared field(s) in items: {_names(leaked)}")
    else:
        leaked = _exposed(set(paths(doc)), visible)
        if leaked:
            return _exposure(case, f"undeclared field(s) exposed: {_names(leaked)}")
    if action.list_spec is not None:
        return _check_list(config, case, doc, ok)
    return ok


def _exposure(case: Any, detail: str) -> Verdict:
    role = case.expected.role or "?"
    return Verdict(
        Status.FINDING_CANDIDATE,
        "allow",
        f"{detail} (role {_clean(role)}; names only, values are never reported)",
        "BC-FIELDS-01",
        "medium",
        "medium",
    )


def _check_list(config: Config, case: Any, doc: dict[str, Any], ok: Verdict) -> Verdict:
    spec = case.action.list_spec
    visible: frozenset[str] = case.expected.visible_ids or frozenset()
    known = {r.ids[spec.id_key]: r.key for r in config.resources if r.kind == spec.kind and spec.id_key in r.ids}
    ids = [i.get(spec.item_id_field) for i in doc["items"]]
    leaked = [f"{known[i]} ({i})" for i in ids if isinstance(i, str) and i in known and i not in visible]
    if leaked:
        return Verdict(
            Status.FINDING_CANDIDATE,
            "allow",
            f"the list names object(s) this principal may not see: {', '.join(leaked)}",
            "BC-LIST-01",
            "high",
            "medium",
        )
    total = doc.get(spec.total_field) if spec.total_field is not None else None
    if spec.total_field is not None and total != len(visible):
        return Verdict(
            Status.FINDING_CANDIDATE,
            "allow",
            f"list total is {_clean(total, 20)} but the principal may see {len(visible)} object(s)",
            "BC-LIST-01",
            "high",
            "medium",
        )
    unknown = [i for i in ids if not isinstance(i, str) or i not in known]
    if unknown:
        return Verdict(
            Status.INCONCLUSIVE,
            "allow",
            f"the list names {len(unknown)} object(s) that the config does not declare",
            case.rule_id,
        )
    return ok


# ---------------------------------------------------------------------------- concealment ----
def _canonical(value: Any, ignore: frozenset[str]) -> Any:
    if isinstance(value, dict):
        return {k: _canonical(v, ignore) for k, v in value.items() if k not in ignore}
    if isinstance(value, list):
        return [_canonical(v, ignore) for v in value]
    return value


def signature_parts(observation: Observation, ignore_fields: list[str]) -> dict[str, str]:
    """The comparable shape of a response: status, selected headers, body (volatile fields removed)."""
    headers: Mapping[str, str] = {k.lower(): v for k, v in observation.headers.items()}
    try:
        body = json.dumps(
            _canonical(json.loads(observation.body.decode("utf-8")), frozenset(ignore_fields)),
            sort_keys=True,
        )
    except (ValueError, UnicodeDecodeError):
        body = "raw:" + hashlib.sha256(observation.body).hexdigest()
    parts = {"status": str(observation.status), "body": body}
    parts.update({f"header:{name}": headers.get(name, "") for name in SIGNATURE_HEADERS})
    return parts


def signature(observation: Observation, ignore_fields: list[str]) -> str:
    return hashlib.sha256(json.dumps(signature_parts(observation, ignore_fields), sort_keys=True).encode()).hexdigest()


def differences(a: Observation, b: Observation, ignore_fields: list[str]) -> list[str]:
    """Which parts of two responses differ: 'status', 'body' or 'header:<name>' (never the content)."""
    pa, pb = signature_parts(a, ignore_fields), signature_parts(b, ignore_fields)
    return sorted(k for k in pa if pa[k] != pb[k])
