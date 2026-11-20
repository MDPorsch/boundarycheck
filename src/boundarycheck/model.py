"""Neutral vocabulary shared by every module. Imports nothing from the rest of the package, so the
judges (oracle, comparator) can depend on it without depending on anything that talks to a target."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum


class Outcome(StrEnum):
    """A decision. Derived from the declared policy (expected) or from a response (observed)."""

    ALLOW = "allow"
    DENY_UNAUTHENTICATED = "deny_unauthenticated"
    DENY_FORBIDDEN = "deny_forbidden"
    DENY_NOT_FOUND = "deny_not_found"


class Status(StrEnum):
    """Per-case status. Nothing is collapsed: `no_issue_observed` is not "secure"."""

    NO_ISSUE_OBSERVED = "no_issue_observed"
    FINDING_CANDIDATE = "finding_candidate"
    POLICY_DENIED = "policy_denied"
    NOT_RUN = "not_run"
    INCOMPLETE = "incomplete"
    ERROR = "error"
    INCONCLUSIVE = "inconclusive"


def exit_code(statuses: Iterable[Status]) -> int:
    """0 only if there is at least one case and every case is `no_issue_observed`; 1 if any case is
    a finding candidate; 2 for everything else. A failed or partial run can never exit 0."""
    seen = list(statuses)
    if any(s is Status.FINDING_CANDIDATE for s in seen):
        return 1
    if seen and all(s is Status.NO_ISSUE_OBSERVED for s in seen):
        return 0
    return 2


@dataclass(frozen=True)
class Observation:
    """What a transport saw. `error` is one of: timeout, connection, body_too_large, redirect,
    unreadable (the response never became a usable answer)."""

    status: int | None
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None


class PolicyRefusal(Exception):
    """The tool refused to send a request (method, path, budget, missing credential)."""


class EgressViolation(Exception):
    """A rule that keeps traffic on loopback was about to be, or was, broken. Aborts the run."""


class TransportUnavailable(Exception):
    """A transport cannot be built (the lab is not installed, the config lacks what it needs)."""
