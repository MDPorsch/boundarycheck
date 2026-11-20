"""The state diff (docs/contract.md s9): it must see every kind of change, name where it happened,
never carry a value, and refuse to compare snapshots that do not cover the same tables."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.milestone("M4")


def _diff(before: dict[str, Any], after: dict[str, Any]) -> Any:
    from boundarycheck.statediff import diff  # noqa: PLC0415

    return diff(before, after)


def _change(table: str, key: str, kind: str) -> Any:
    from boundarycheck.statediff import StateChange  # noqa: PLC0415

    return StateChange(table, key, kind)


def test_identical_snapshots_have_an_empty_diff() -> None:
    snap = {"projects": (("p1", "t"),)}
    assert _diff(snap, snap) == []


def test_an_added_row_is_reported_with_its_table_and_key() -> None:
    assert _diff({"projects": (("p1", "t"),)}, {"projects": (("p1", "t"), ("p2", "t"))}) == [
        _change("projects", "p2", "added")
    ]


def test_a_removed_row_is_reported() -> None:
    assert _diff({"invoices": (("i1", 5), ("i2", 6))}, {"invoices": (("i1", 5),)}) == [
        _change("invoices", "i2", "removed")
    ]


def test_a_modified_row_is_reported_even_when_one_column_changes() -> None:
    assert _diff({"projects": (("p1", "A", "old", 1),)}, {"projects": (("p1", "A", "old", 2),)}) == [
        _change("projects", "p1", "modified")
    ]


def test_a_change_of_a_value_type_is_a_modification_not_silence() -> None:
    assert _diff({"projects": ((1, "x"),)}, {"projects": (("1", "x"),)}) == [_change("projects", "1", "modified")]


def test_changes_come_back_sorted_by_table_then_key_whatever_the_order_found() -> None:
    before = {"projects": (("b", 1),), "memberships": (("m1", "viewer"),)}
    after = {"projects": (("a", 1),), "memberships": (("m1", "viewer"), ("m2", "owner"))}
    assert _diff(before, after) == [
        _change("memberships", "m2", "added"),
        _change("projects", "a", "added"),
        _change("projects", "b", "removed"),
    ]


def test_snapshots_over_different_tables_cannot_be_compared() -> None:
    with pytest.raises(ValueError, match="different tables"):
        _diff({"projects": ()}, {"projects": (), "invoices": ()})
    with pytest.raises(ValueError, match="different tables"):
        _diff({"projects": (), "invoices": ()}, {"projects": ()})


def test_a_diff_never_carries_a_value() -> None:
    secret = "SENTINEL-SECRET-VALUE"
    changes = _diff({"projects": (("p1", "old"),)}, {"projects": (("p1", secret),)})
    assert secret not in repr(changes) and "old" not in repr(changes)
    assert set(vars(changes[0])) == {"table", "key", "kind"}


def test_as_dict_has_exactly_table_key_and_kind() -> None:
    assert _change("projects", "p1", "added").as_dict() == {"table": "projects", "key": "p1", "kind": "added"}


# ------------------------------------------------------------------ the SQLite snapshot ----
def _database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE projects (id TEXT PRIMARY KEY, title TEXT);
        CREATE TABLE "odd table" (id INTEGER PRIMARY KEY, note TEXT);
        CREATE TABLE audit_events (id TEXT PRIMARY KEY, decision TEXT);
        CREATE TABLE alembic_version (version_num TEXT);
        INSERT INTO projects VALUES ('p2', 'two'), ('p1', 'one');
        INSERT INTO "odd table" VALUES (1, 'x');
        INSERT INTO audit_events VALUES ('a1', 'deny');
        INSERT INTO alembic_version VALUES ('0001');
        """
    )
    connection.commit()
    return connection


def _snapshot(path: Path) -> Any:
    from boundarycheck.transports.sqlite_state import snapshot_sqlite  # noqa: PLC0415

    return snapshot_sqlite(path)


def test_a_sqlite_snapshot_covers_every_table_except_the_excluded_ones(tmp_path: Path) -> None:
    db = tmp_path / "t.sqlite"
    _database(db).close()
    snap = _snapshot(db)
    assert set(snap) == {"projects", "odd table"}  # audit_events and alembic_version are excluded
    assert snap["projects"] == (("p1", "one"), ("p2", "two"))  # ordered by the first column


def test_a_new_table_is_covered_without_anyone_listing_it(tmp_path: Path) -> None:
    db = tmp_path / "t.sqlite"
    connection = _database(db)
    before = _snapshot(db)
    connection.execute("CREATE TABLE secrets (id TEXT PRIMARY KEY, v TEXT)")
    connection.execute("INSERT INTO secrets VALUES ('s1', 'v')")
    connection.commit()
    connection.close()
    after = _snapshot(db)
    assert "secrets" in after  # discovered from the database itself, not from a list in the tool
    with pytest.raises(ValueError, match="different tables"):  # and never silently ignored
        _diff(before, after)


def test_a_row_change_in_any_covered_table_is_seen_and_an_audit_append_is_not(tmp_path: Path) -> None:
    db = tmp_path / "t.sqlite"
    connection = _database(db)
    before = _snapshot(db)
    connection.execute("INSERT INTO audit_events VALUES ('a2', 'deny')")  # what a correct refusal does
    connection.commit()
    assert _diff(before, _snapshot(db)) == []
    connection.execute("UPDATE \"odd table\" SET note = 'y' WHERE id = 1")  # a quoted table name
    connection.commit()
    connection.close()
    assert _diff(before, _snapshot(db)) == [_change("odd table", "1", "modified")]


def test_a_missing_database_is_an_error_not_an_empty_snapshot(tmp_path: Path) -> None:
    from boundarycheck.statediff import SnapshotError  # noqa: PLC0415

    with pytest.raises(SnapshotError, match="does not exist"):
        _snapshot(tmp_path / "nope.sqlite")


def test_a_snapshot_cannot_write(tmp_path: Path) -> None:
    """The snapshot opens the file read-only: whatever happens, it must not change the state it judges."""
    db = tmp_path / "t.sqlite"
    _database(db).close()
    before = db.read_bytes()
    _snapshot(db)
    assert db.read_bytes() == before
