"""Run a plan against a transport and judge every result (docs/contract.md s1, s2, s4, s5)."""

from __future__ import annotations

import hashlib
import json
import secrets as _secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from boundarycheck import __version__
from boundarycheck.comparator import Verdict, compare, compare_write, differences
from boundarycheck.config import Config, Resource
from boundarycheck.model import EgressViolation, Observation, PolicyRefusal, Status, exit_code
from boundarycheck.planner import BoundaryCase, plan, unexercised_writes
from boundarycheck.redact import RedactionError, Redactor, SecretLeakError, assert_no_secrets
from boundarycheck.statediff import Snapshot, StateChange, diff

CONCEAL_RULE = "BC-CONCEAL-01"
STATIC_LIMITATIONS = (
    "no_issue_observed means the response to that one request matched the declared policy. "
    "It does not mean the target is secure.",
    "Expected results come from the policy in the config, written by the assessor. "
    "The tool cannot tell a wrong policy from a vulnerable target.",
    "Reads use GET/HEAD. Write checks exist only on the in-process fixture transport, send only requests the "
    "policy says must be refused, and are judged by a state diff. The write behaviour of a live target, "
    "concurrency and timing are not tested.",
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
    """`send` takes a `body` only for a write. A transport that can report and restore its own state
    sets `state_aware = True` and provides `snapshot()` and `reset_state()`; only such a transport is
    ever sent a write (docs/contract.md s9)."""

    name: str

    def has_credential(self, principal: str | None) -> bool: ...
    def secrets(self) -> list[str]: ...
    async def send(self, method: str, path: str, principal: str | None) -> Observation: ...
    async def aclose(self) -> None: ...


NO_STATE = (
    "write checks need a state snapshot, which this transport cannot take; "
    "use the fixture transport (or --reads-only to leave writes out)"
)


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
    state_changes: list[dict[str, str]] = field(default_factory=list)


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


async def _settle(transport: Any, baseline: Snapshot) -> tuple[list[StateChange], str | None]:
    """Snapshot after a write and, if anything changed, restore the pristine state and CHECK that it
    is pristine. Returns the changes and, if state can no longer be trusted, the reason to stop writing."""
    try:
        changes = diff(baseline, await transport.snapshot())
    except Exception:
        return [], "the state snapshot after the request failed; the remaining write checks were not run"
    if not changes:
        return [], None
    try:
        await transport.reset_state()
        restored = await transport.snapshot()
    except Exception:
        return changes, "the pristine state could not be restored; the remaining write checks were not run"
    if diff(baseline, restored):
        return changes, "the pristine state was not restored; the remaining write checks were not run"
    return changes, None


def _body(case: BoundaryCase) -> bytes | None:
    if case.action.body is None:
        return None
    return json.dumps(case.action.body, sort_keys=True, separators=(",", ":")).encode("utf-8")


async def run(  # noqa: PLR0912, PLR0915 - the per-case loop is one straight sequence of guarded steps
    config: Config,
    transport: Transport,
    *,
    run_id: str | None = None,
    now: datetime | None = None,
    reads_only: bool = False,
) -> RunResult:
    started = now or datetime.now(UTC)
    planned = plan(config)
    cases = [c for c in planned if not (reads_only and c.action.is_write)]
    omitted = len(planned) - len(cases)
    redactor = Redactor(config.redaction.mask_fields, transport.secrets())
    budget = config.scope.target.request_budget
    ignore = list(config.policy.concealment.ignore_body_fields)
    results: dict[str, CaseResult] = {}
    seen: dict[str, Observation] = {}
    evidence: dict[str, dict[str, Any]] = {}
    sent = 0
    aborted = False
    stateful: Any = transport  # the write-only parts of the protocol (body, snapshot, reset_state)
    state_aware = bool(getattr(transport, "state_aware", False))
    baseline: Snapshot | None = None
    halted: str | None = None  # why no further write is sent
    if state_aware and any(c.action.is_write for c in cases):
        try:
            baseline = await stateful.snapshot()
        except Exception:
            halted = "the baseline state snapshot could not be taken; no write was sent"

    for case in cases:
        when = _iso(now or datetime.now(UTC))
        who = case.principal or "anonymous"
        is_write = case.action.is_write
        if aborted:
            results[case.key] = _result(
                case,
                Status.NOT_RUN,
                "run aborted after an egress violation; nothing further was sent",
                when,
            )
            continue
        if is_write and not state_aware:
            results[case.key] = _result(case, Status.NOT_RUN, NO_STATE, when)
            continue
        if is_write and halted is not None:
            results[case.key] = _result(case, Status.NOT_RUN, halted, when)
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
        failure: BaseException | None = None
        try:
            if is_write:
                observation = await stateful.send(case.action.method, case.path, case.principal, _body(case))
            else:
                observation = await transport.send(case.action.method, case.path, case.principal)
        except PolicyRefusal as exc:
            results[case.key] = _result(case, Status.POLICY_DENIED, f"refused by the transport: {exc}", when)
            continue
        except EgressViolation as exc:
            aborted = True
            results[case.key] = _result(case, Status.ERROR, f"egress violation, run aborted: {exc}", when)
            continue
        except Exception as exc:
            failure = exc
            observation = Observation(status=None, error="unreadable")
        changes: list[StateChange] = []
        if is_write and baseline is not None:
            changes, halted = await _settle(stateful, baseline)
            if halted is not None and not changes and failure is None:
                results[case.key] = _result(case, Status.ERROR, halted, when)
                continue
        if failure is not None:
            if changes:  # the request failed, yet state changed: that is still a finding
                verdict = compare_write(config, case, observation, changes)
                failed = _result(case, verdict.status, verdict.detail, when, verdict)
                failed.state_changes = [c.as_dict() for c in changes]
                results[case.key] = failed
            else:
                results[case.key] = _result(case, Status.ERROR, f"transport error ({type(failure).__name__})", when)
            continue
        seen[case.key] = observation
        verdict = compare_write(config, case, observation, changes) if is_write else compare(config, case, observation)
        result = _result(case, verdict.status, verdict.detail, when, verdict)
        result.state_changes = [c.as_dict() for c in changes]
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
    if omitted:
        limitations.append(
            f"--reads-only: {omitted} write case(s) were left out at the operator's request; "
            "write-path authorization was not tested in this run."
        )
    elif unexercised_writes(config):
        limitations.append(
            f"{unexercised_writes(config)} write combination(s) that the policy allows were not exercised by design: "
            "write checks send only requests the policy says must be refused."
        )
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
        if (
            case.action.is_write
            or case.principal is None
            or not case.resource.exists
            or case.expected.outcome.value != "deny_not_found"
        ):
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
