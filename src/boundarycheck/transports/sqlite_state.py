"""Taking and restoring a SQLite snapshot. This is the I/O half of the state diff (see statediff.py,
which is pure so that the judges may use it). Used only by the in-process lab adapter."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Final

from boundarycheck.statediff import Snapshot, SnapshotError

#: A correct refusal APPENDS an audit row, and the migration table is not business state.
EXCLUDED_TABLES: Final = frozenset({"audit_events", "alembic_version"})


def snapshot_sqlite(path: Path, *, exclude: frozenset[str] = EXCLUDED_TABLES) -> Snapshot:
    """Every table of a SQLite file except `exclude` (discovered from the file, so a table nobody
    listed is still covered), rows ordered by the first column. Opened read-only."""
    if not Path(path).is_file():
        raise SnapshotError("the database file to snapshot does not exist")
    try:
        connection = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error:
        raise SnapshotError("the database could not be opened for a snapshot") from None
    try:
        names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            if row[0] not in exclude
        ]
        snapshot: Snapshot = {}
        for name in names:
            quoted = '"' + name.replace('"', '""') + '"'
            snapshot[name] = tuple(tuple(row) for row in connection.execute(f"SELECT * FROM {quoted} ORDER BY 1"))  # noqa: S608
        return snapshot
    except sqlite3.Error:
        raise SnapshotError("the database could not be read for a snapshot") from None
    finally:
        connection.close()
