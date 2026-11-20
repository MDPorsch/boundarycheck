"""Run a plan against a transport and judge every result (docs/contract.md s1, s2, s4, s5)."""

from __future__ import annotations

import hashlib
import json
import secrets as _secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from boundarycheck import __version__
from boundarycheck.comparator import Verdict, compare, differences
from boundarycheck.config import Config, Resource
from boundarycheck.model import EgressViolation, Observation, PolicyRefusal, Status, exit_code
from boundarycheck.planner import BoundaryCase, plan
from boundarycheck.redact import RedactionError, Redactor, SecretLeakError, assert_no_secrets

CONCEAL_RULE = "BC-CONCEAL-01"
STATIC_LIMITATIONS = (
    "no_issue_observed means the response to that one request matched the declared policy. "
    "It does not mean the target is secure.",
    "Expected results come from the policy in the config, written by the assessor. "
    "The tool cannot tell a wrong policy from a vulnerable target.",
    "v0.1 sends read-only requests (GET/HEAD). Write-path authorization, concurrency and timing "
    "behaviour are not tested.",
    "Only the principals, resources and actions declared in the config were exercised. "
    "Undeclared routes and objects were not.",
    "A SHA-256 over stored evidence proves the integrity of the stored redacted bytes. "
    "It does not prove where they came from.",
)
ATTESTATION_FIXTURE = "In-process fixture run: no network was used and no authorization attestation is required."
ATTESTATION_LIVE = (
    "Loopback-only run: a per-run authorization attestation is not required because this tool connected only to "
    "loopback addresses. It cannot see where a loopback listener (an SSH tunnel, a local proxy) forwards traffic, "
    "so the operator remains responsible for testing only systems they own or are authorized to assess."
)


class Transport(Protocol):
    name: str

    def has_credential(self, principal: str | None) -> bool: ...
    def secrets(self) -> list[str]: ...
    async def send(self, method: str, path: str, principal: str | None) -> Observation: ...
    async def aclose(self) -> None: ...


@dataclass
class CaseResult:
    id: str
    key: str
    rule_id: str
    status: Status
    principal: str | None
    action: str
    resource: str
    expected: str
    observed: str | None
    reason: str
    detail: str
    severity: str | None = None
    confidence: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    review_state: str = "not_applicable"
    observed_at: str = ""


@dataclass
class RunResult:
    run_id: str
    tool_version: str
    scope_id: str
    target_label: str
    transport: str
    started_at: str
    finished_at: str
    attestation: str
    cases: list[CaseResult]
    limitations: list[str]
    evidence: dict[str, dict[str, Any]]

    @property
    def exit_code(self) -> int:
        return exit_code(c.status for c in self.cases)


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id(moment: datetime) -> str:
    return f"{moment.astimezone(UTC).strftime('%Y%m%dT%H%M%SZ')}-{_secrets.token_hex(4)}"


def _blob_hash(blob: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(blob, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _result(case: BoundaryCase, status: Status, detail: str, when: str, verdict: Verdict | None = None) -> CaseResult:
    return CaseResult(
        id=case.id, key=case.key, rule_id=verdict.rule_id if verdict else case.rule_id, status=status,
        principal=case.principal, action=case.action.id, resource=case.resource.key,
        expected=case.expected.outcome.value, observed=verdict.observed if verdict else None,
        reason=case.expected.reason, detail=detail,
        severity=verdict.severity if verdict else None, confidence=verdict.confidence if verdict else None,
        review_state="needs_review" if status is Status.FINDING_CANDIDATE else "not_applicable",
        limitations=["single request; the declared policy is the assessor's, so a candidate needs human review"]
        if status is Status.FINDING_CANDIDATE else [],
        observed_at=when,
    )  # fmt: skip


async def run(  # noqa: PLR0915 - the per-case loop is one straight sequence of guarded steps
    config: Config, transport: Transport, *, run_id: str | None = None, now: datetime | None = None
) -> RunResult:
    started = now or datetime.now(UTC)
    cases = plan(config)
    redactor = Redactor(config.redaction.mask_fields, transport.secrets())
    budget = config.scope.target.request_budget
    ignore = list(config.policy.concealment.ignore_body_fields)
    results: dict[str, CaseResult] = {}
    seen: dict[str, Observation] = {}
    evidence: dict[str, dict[str, Any]] = {}
    sent = 0
    aborted = False

    for case in cases:
        when = _iso(now or datetime.now(UTC))
        who = case.principal or "anonymous"
        if aborted:
            results[case.key] = _result(
                case,
                Status.NOT_RUN,
                "run aborted after an egress violation; nothing further was sent",
                when,
            )
            continue
        if not transport.has_credential(case.principal):
            results[case.key] = _result(
                case,
                Status.NOT_RUN,
                f"no credential supplied for principal '{who}' on this transport",
                when,
            )
            continue
        if sent >= budget:
            results[case.key] = _result(
                case,
                Status.POLICY_DENIED,
                f"request budget exhausted ({budget} requests); not sent",
                when,
            )
            continue
        sent += 1
        try:
            observation = await transport.send(case.action.method, case.path, case.principal)
        except PolicyRefusal as exc:
            results[case.key] = _result(case, Status.POLICY_DENIED, f"refused by the transport: {exc}", when)
            continue
        except EgressViolation as exc:
            aborted = True
            results[case.key] = _result(case, Status.ERROR, f"egress violation, run aborted: {exc}", when)
            continue
        except Exception as exc:
            results[case.key] = _result(case, Status.ERROR, f"transport error ({type(exc).__name__})", when)
            continue
        seen[case.key] = observation
        verdict = compare(config, case, observation)
        result = _result(case, verdict.status, verdict.detail, when, verdict)
        try:
            blob = redactor.observation(observation)
            text = json.dumps(blob, sort_keys=True)
            assert_no_secrets([text], transport.secrets())
        except (RedactionError, SecretLeakError):
            results[case.key] = _result(
                case,
                Status.ERROR,
                "redaction failed; the evidence for this case was discarded",
                when,
            )
            continue
        sha = _blob_hash(blob)
        evidence[sha] = blob
        result.evidence_refs = [sha]
        results[case.key] = result

    ordered = [results[c.key] for c in cases]
    concealment, limitations = _concealment(config, cases, results, seen, ignore, now)
    finished = now or datetime.now(UTC)
    return RunResult(
        run_id=run_id or new_run_id(started), tool_version=__version__, scope_id=config.scope.id,
        target_label=config.scope.target.label, transport=transport.name,
        started_at=_iso(started), finished_at=_iso(finished),
        attestation=ATTESTATION_FIXTURE if transport.name.startswith("fixture") else ATTESTATION_LIVE,
        cases=ordered + concealment, limitations=[*STATIC_LIMITATIONS, *limitations], evidence=evidence,
    )  # fmt: skip


_PRIORITY = (Status.ERROR, Status.INCOMPLETE, Status.POLICY_DENIED, Status.NOT_RUN)


def _concealment(  # noqa: PLR0913, PLR0917
    config: Config, cases: list[BoundaryCase], results: dict[str, CaseResult],
    seen: dict[str, Observation], ignore: list[str], now: datetime | None,
) -> tuple[list[CaseResult], list[str]]:  # fmt: skip
    """A hidden object must answer exactly like a missing one. Derived from the access cases."""
    probes: dict[str, Resource] = {}
    for resource in config.resources:
        if not resource.exists:
            probes.setdefault(resource.kind, resource)
    out: list[CaseResult] = []
    untested: set[str] = set()
    for case in cases:
        if case.principal is None or not case.resource.exists or case.expected.outcome.value != "deny_not_found":
            continue
        probe = probes.get(case.action.resource_kind)
        if probe is None:
            untested.add(case.action.resource_kind)
            continue
        peer_key = f"{case.principal}:{case.action.id}:{probe.key}"
        hidden, peer = results[case.key], results[peer_key]
        when = _iso(now or datetime.now(UTC))
        status, detail = _conceal_status(hidden, peer, seen.get(case.key), seen.get(peer_key), ignore)
        out.append(
            CaseResult(
                id=f"BC-C{len(out) + 1:03d}", key=f"{case.key}~{probe.key}", rule_id=CONCEAL_RULE, status=status,
                principal=case.principal, action=case.action.id, resource=case.resource.key,
                expected="deny_not_found", observed=hidden.observed, reason="concealment", detail=detail,
                severity="medium" if status is Status.FINDING_CANDIDATE else None,
                confidence="medium" if status is Status.FINDING_CANDIDATE else None,
                review_state="needs_review" if status is Status.FINDING_CANDIDATE else "not_applicable",
                evidence_refs=[*hidden.evidence_refs, *peer.evidence_refs], observed_at=when,
            )
        )  # fmt: skip
    notes = [
        f"Concealment (hidden object vs missing object) was not tested for resource kind '{kind}': "
        "declare a resource of that kind with exists: false."
        for kind in sorted(untested)
    ]
    return out, notes


def _conceal_status(
    hidden: CaseResult,
    peer: CaseResult,
    a: Observation | None,
    b: Observation | None,
    ignore: list[str],
) -> tuple[Status, str]:
    for wanted in _PRIORITY:
        for side in (hidden, peer):
            if side.status is wanted:
                return wanted, f"peer {side.id}: {side.detail}"
    if (
        hidden.status is not Status.NO_ISSUE_OBSERVED
        or peer.status is not Status.NO_ISSUE_OBSERVED
        or a is None
        or b is None
    ):
        bad = hidden if hidden.status is not Status.NO_ISSUE_OBSERVED else peer
        return Status.INCONCLUSIVE, f"not evaluated: peer {bad.id} is {bad.status.value}"
    diff = differences(a, b, ignore)
    if diff:
        return (
            Status.FINDING_CANDIDATE,
            f"a hidden object answers differently from a missing one (differs in: {', '.join(diff)}): existence oracle",
        )
    return Status.NO_ISSUE_OBSERVED, "a hidden object is indistinguishable from a missing one"
