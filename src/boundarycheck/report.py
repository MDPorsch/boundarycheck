"""Reports (docs/contract.md s8). JSON is the source of truth; Markdown renders the same data.

No response body ever appears here, only statuses, rule ids, names of fields and SHA-256 references
to the redacted evidence. Text that came from the target is sanitised before it reaches Markdown."""

from __future__ import annotations

import json
import re
from typing import Any

from boundarycheck.engine import CaseResult, RunResult
from boundarycheck.model import Status

SCHEMA_VERSION = "1"
_MD_SPECIAL = re.compile(r"([\\`|<>\[\]()#*_~&])")
_CONTROL = re.compile(
    "[\x00-\x1f\x7f-\x9f" + chr(0x2028) + chr(0x2029) + "]+"
)  # includes line and paragraph separators


def _case_json(c: CaseResult) -> dict[str, Any]:
    return {
        "id": c.id, "key": c.key, "rule_id": c.rule_id, "status": c.status.value, "severity": c.severity,
        "confidence": c.confidence, "principal": c.principal or "anonymous", "action": c.action,
        "resource": c.resource, "expected": c.expected, "observed": c.observed, "reason": c.reason,
        "detail": c.detail, "redacted_evidence_refs": list(c.evidence_refs), "limitations": list(c.limitations),
        "review_state": c.review_state, "observed_at": c.observed_at,
        "state_changes": [dict(change) for change in c.state_changes],
    }  # fmt: skip


def document(result: RunResult) -> dict[str, Any]:
    by_status = {s.value: 0 for s in Status}
    for case in result.cases:
        by_status[case.status.value] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "boundarycheck", "version": result.tool_version},
        "run_id": result.run_id,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "scope": {"id": result.scope_id, "target_label": result.target_label},
        "transport": result.transport,
        "attestation": result.attestation,
        "summary": {
            "total": len(result.cases),
            "by_status": by_status,
            "exit_code": result.exit_code,
        },
        "limitations": list(result.limitations),
        "cases": [_case_json(c) for c in result.cases],
    }


def to_json(result: RunResult) -> str:
    return json.dumps(document(result), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _esc(value: object) -> str:
    """Make text safe inside a Markdown table cell: no control characters, no markup."""
    return _MD_SPECIAL.sub(r"\\\1", _CONTROL.sub(" ", str(value)))[:300]


def _row(c: CaseResult) -> str:
    cells = [
        c.id,
        c.rule_id,
        c.severity or "-",
        c.principal or "anonymous",
        c.action,
        c.resource,
        f"{c.expected} -> {c.observed or '-'}",
        c.detail,
    ]
    return "| " + " | ".join(_esc(x) for x in cells) + " |"


def to_markdown(result: RunResult) -> str:
    doc = document(result)
    lines = [
        "# boundarycheck report",
        "",
        f"* run: `{result.run_id}`",
        f"* scope: {_esc(result.scope_id)} (target {_esc(result.target_label)})",
        f"* transport: {_esc(result.transport)}",
        f"* tool: boundarycheck {_esc(result.tool_version)}",
        f"* started {result.started_at}, finished {result.finished_at}",
        f"* {_esc(result.attestation)}",
        f"* exit code: **{doc['summary']['exit_code']}**",
        "",
        "> `no_issue_observed` does not mean the target is secure: it means one request matched the declared policy.",
        "",
        "## Summary",
        "",
        "| status | cases |",
        "|---|---|",
        *[f"| {name} | {count} |" for name, count in doc["summary"]["by_status"].items()],
        "",
    ]
    header = [
        "| id | rule | severity | principal | action | resource | expected -> observed | detail |",
        "|---|---|---|---|---|---|---|---|",
    ]
    findings = [c for c in result.cases if c.status is Status.FINDING_CANDIDATE]
    others = [c for c in result.cases if c.status not in (Status.FINDING_CANDIDATE, Status.NO_ISSUE_OBSERVED)]
    lines += [
        "## Finding candidates (need human review)",
        "",
        *(header + [_row(c) for c in findings] if findings else ["None."]),
        "",
    ]
    lines += [
        "## Not clean and not a finding",
        "",
        *(header + [_row(c) for c in others] if others else ["None."]),
        "",
    ]
    lines += ["## Limitations", "", *[f"* {_esc(x)}" for x in result.limitations], ""]
    return "\n".join(lines)
