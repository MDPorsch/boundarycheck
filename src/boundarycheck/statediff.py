"""State snapshots and their diff (docs/contract.md s9).

Neutral on purpose: this module imports nothing that talks to a target, so the judges may use it. A
diff names WHERE state changed (table, primary key, kind) and never WHAT it held: a value from the
target must not reach a report through this path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ChangeKind = Literal["added", "removed", "modified"]
Snapshot = dict[str, tuple[tuple[Any, ...], ...]]


class SnapshotError(Exception):
    """A snapshot could not be taken. Never an empty snapshot: that would read as "nothing changed"."""


@dataclass(frozen=True, order=True)
class StateChange:
    table: str
    key: str
    kind: ChangeKind

    def as_dict(self) -> dict[str, str]:
        return {"table": self.table, "key": self.key, "kind": self.kind}


def diff(before: Snapshot, after: Snapshot) -> list[StateChange]:
    """Every row added, removed or modified in any table, sorted. Snapshots over different table
    sets cannot be compared: that is an error, never an empty diff."""
    if set(before) != set(after):
        raise ValueError("snapshots cover different tables; they cannot be compared")
    changes: list[StateChange] = []
    for table in sorted(before):
        old = {str(row[0]): row for row in before[table]}
        new = {str(row[0]): row for row in after[table]}
        changes.extend(StateChange(table, key, "removed") for key in old.keys() - new.keys())
        changes.extend(StateChange(table, key, "added") for key in new.keys() - old.keys())
        changes.extend(StateChange(table, key, "modified") for key in old.keys() & new.keys() if old[key] != new[key])
    return sorted(changes)
