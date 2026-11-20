"""The authorization window (docs/remote-live-design.md s4.2).

The operator DECLARES that an assessment is authorized, for a named engagement and a window of time.
The tool enforces the window and says plainly, in every report, that it cannot verify the declaration.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from boundarycheck.config import MAX_WINDOW_DAYS, Authorization


class AuthorizationError(Exception):
    """The run may not start. The message is safe to show."""


def _shown(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def check_window(authorization: Authorization, now: datetime) -> None:
    if authorization.not_before is not None and now < authorization.not_before:
        raise AuthorizationError(
            f"the authorization window has not started (not_before {_shown(authorization.not_before)}); "
            "it is not yet valid"
        )
    if now > authorization.not_after:
        raise AuthorizationError(f"the authorization window has expired (not_after {_shown(authorization.not_after)})")
    if authorization.not_after - now > timedelta(days=MAX_WINDOW_DAYS):
        raise AuthorizationError(
            f"the authorization window is too long: not_after is more than {MAX_WINDOW_DAYS} days away"
        )


def describe(authorization: Authorization) -> str:
    start = _shown(authorization.not_before) if authorization.not_before is not None else "now"
    return (
        f"engagement {authorization.engagement}, window {start} to {_shown(authorization.not_after)} "
        "(declared by the operator; the tool cannot verify it)"
    )


def attestation(authorization: Authorization, where: str) -> str:
    start = _shown(authorization.not_before) if authorization.not_before is not None else "the start of the run"
    return (
        f"Remote run. Authorization was declared by the operator for engagement {authorization.engagement} "
        f"(valid from {start} to {_shown(authorization.not_after)}) and acknowledged with --ack-authorization. "
        "The tool does not and cannot verify it. "
        f"Connected only to {where}."
    )
