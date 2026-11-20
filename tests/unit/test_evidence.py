"""The run store (docs/contract.md s7): private files, no traversal, no secrets, bounded retention."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.support import FakeTransport, compliant, mini, parse

pytestmark = pytest.mark.milestone("S1")


async def _saved(root: Path, secrets: list[str] | None = None, now: datetime | None = None) -> tuple[Any, Any, Path]:
    from boundarycheck.engine import run  # noqa: PLC0415
    from boundarycheck.evidence import RunStore  # noqa: PLC0415
    from boundarycheck.report import to_json, to_markdown  # noqa: PLC0415

    cfg = parse(mini())
    result = await run(cfg, FakeTransport(compliant(cfg)), now=now)
    store = RunStore(root)
    path = store.save(result, to_json(result), to_markdown(result), secrets or [])
    return store, result, path


async def test_a_run_is_stored_with_private_permissions_and_content_addressed_evidence(tmp_path: Path) -> None:
    _store, result, path = await _saved(tmp_path / "runs")
    assert path.name == result.run_id
    assert (path / "report.json").is_file() and (path / "report.md").is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o700 and stat.S_IMODE((path / "evidence").stat().st_mode) == 0o700
    assert stat.S_IMODE((path / "report.json").stat().st_mode) == 0o600
    blobs = list((path / "evidence").iterdir())
    assert blobs and len(blobs) == len(result.evidence)
    for blob in blobs:
        assert stat.S_IMODE(blob.stat().st_mode) == 0o600
        assert blob.name == hashlib.sha256(blob.read_bytes()).hexdigest() + ".json"
        json.loads(blob.read_bytes())


async def test_a_world_writable_runs_directory_is_refused(tmp_path: Path) -> None:
    from boundarycheck.evidence import RunStore, StoreError  # noqa: PLC0415

    root = tmp_path / "shared"
    root.mkdir()
    root.chmod(0o777)
    with pytest.raises(StoreError, match="(?i)writable"):
        RunStore(root).list_runs()
    with pytest.raises(StoreError, match="(?i)writable"):
        await _saved(root)


async def test_nothing_is_written_when_a_secret_would_be_stored(tmp_path: Path) -> None:
    from boundarycheck.engine import run  # noqa: PLC0415
    from boundarycheck.evidence import RunStore  # noqa: PLC0415
    from boundarycheck.redact import SecretLeakError  # noqa: PLC0415

    cfg = parse(mini())
    result = await run(cfg, FakeTransport(compliant(cfg)))
    store = RunStore(tmp_path / "runs")
    with pytest.raises(SecretLeakError):
        store.save(result, "report with tok-" + "Zq81xKd02LmPq77 inside", "md", ["tok-" + "Zq81xKd02LmPq77"])
    assert not (tmp_path / "runs").exists() or list((tmp_path / "runs").iterdir()) == []


@pytest.mark.parametrize("bad", ["../x", "..", "a/b", "", "x" * 80, "20261119T201500Z-ZZZZZZZZ", "20261119T201500Z-abcdef1", ".hidden"])
def test_run_ids_are_validated_so_nothing_can_traverse(bad: str, tmp_path: Path) -> None:
    from boundarycheck.evidence import RunStore, StoreError, valid_run_id  # noqa: PLC0415

    assert valid_run_id(bad) is False
    with pytest.raises(StoreError):
        RunStore(tmp_path).read_report(bad, "json")


def test_a_well_formed_run_id_is_accepted() -> None:
    from boundarycheck.evidence import valid_run_id  # noqa: PLC0415

    assert valid_run_id("20261119T201500Z-abcdef12") is True


async def test_read_report_returns_what_was_saved_and_rejects_unknown_formats(tmp_path: Path) -> None:
    from boundarycheck.evidence import StoreError  # noqa: PLC0415

    store, result, _path = await _saved(tmp_path / "runs")
    assert json.loads(store.read_report(result.run_id, "json"))["run_id"] == result.run_id
    assert store.read_report(result.run_id, "md").startswith("# boundarycheck report")
    with pytest.raises(StoreError):
        store.read_report(result.run_id, "html")
    with pytest.raises(StoreError, match="(?i)no such run"):
        store.read_report("20200101T000000Z-00000000", "json")


async def test_list_runs_is_newest_first_and_ignores_junk(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    old = datetime(2026, 1, 1, tzinfo=UTC)
    new = datetime(2026, 6, 1, tzinfo=UTC)
    store, a, _ = await _saved(root, now=old)
    _s, b, _ = await _saved(root, now=new)
    (root / "not-a-run").mkdir()
    (root / "stray.txt").write_text("x")
    listed = store.list_runs()
    assert [r["run_id"] for r in listed] == [b.run_id, a.run_id]
    assert {"run_id", "scope_id", "total", "exit_code", "started_at"} <= set(listed[0])


async def test_purge_removes_only_old_runs_and_leaves_everything_else(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    now = datetime(2026, 11, 19, tzinfo=UTC)
    store, old, _ = await _saved(root, now=now - timedelta(days=40))
    _s, fresh, _ = await _saved(root, now=now - timedelta(days=2))
    (root / "keep-me").mkdir()
    (root / "keep-me" / "f").write_text("x")
    removed = store.purge(timedelta(days=30), now=now)
    assert removed == [old.run_id]
    assert not (root / old.run_id).exists() and (root / fresh.run_id).exists()
    assert (root / "keep-me" / "f").exists()


async def test_purge_never_follows_a_symlink_out_of_the_runs_directory(tmp_path: Path) -> None:
    root = tmp_path / "runs"
    now = datetime(2026, 11, 19, tzinfo=UTC)
    store, _old, _ = await _saved(root, now=now - timedelta(days=90))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious").write_text("do not delete")
    link = root / "20200101T000000Z-deadbeef"
    os.symlink(outside, link)
    store.purge(timedelta(days=30), now=now)
    assert (outside / "precious").read_text() == "do not delete"


@pytest.mark.parametrize(("text", "delta"), [("30d", timedelta(days=30)), ("12h", timedelta(hours=12)), ("45m", timedelta(minutes=45)), ("1d", timedelta(days=1))])
def test_retention_ages_parse(text: str, delta: timedelta) -> None:
    from boundarycheck.evidence import parse_age  # noqa: PLC0415

    assert parse_age(text) == delta


@pytest.mark.parametrize("text", ["", "30", "d", "-1d", "0d", "1w", "1.5d", "30 d", "9999999d"])
def test_bad_ages_are_refused(text: str) -> None:
    from boundarycheck.evidence import StoreError, parse_age  # noqa: PLC0415

    with pytest.raises(StoreError):
        parse_age(text)
