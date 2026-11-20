"""The run store (docs/contract.md s7): private files, validated ids, no secrets, bounded retention."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from boundarycheck.engine import RunResult
from boundarycheck.redact import assert_no_secrets

_RUN_ID = re.compile(r"^(\d{8}T\d{6}Z)-[0-9a-f]{8}$")
_AGE = re.compile(r"^(\d{1,6})([dhm])$")
_UNITS = {"d": "days", "h": "hours", "m": "minutes"}


class StoreError(Exception):
    """A problem with the runs directory or a run; the message is safe to show."""


def valid_run_id(run_id: str) -> bool:
    return bool(_RUN_ID.fullmatch(run_id))


def _run_time(run_id: str) -> datetime:
    match = _RUN_ID.fullmatch(run_id)
    if match is None:
        raise StoreError("invalid run id")
    return datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


def parse_age(text: str) -> timedelta:
    match = _AGE.fullmatch(text)
    if match is None or int(match.group(1)) == 0:
        raise StoreError("age must look like 30d, 12h or 45m (a positive whole number and d, h or m)")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


class RunStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    # ------------------------------------------------------------------------- the directory ----
    def _check_root(self, *, create: bool) -> bool:
        if self.root.is_symlink():
            raise StoreError("the runs directory is a symbolic link; refusing to use it")
        if not self.root.exists():
            if not create:
                return False
            self.root.mkdir(parents=True, mode=0o700)
        if not self.root.is_dir():
            raise StoreError("the runs path exists but is not a directory")
        if self.root.stat().st_mode & stat.S_IWOTH:
            raise StoreError("the runs directory is world-writable; refusing to use it (chmod o-w)")
        return True

    # --------------------------------------------------------------------------------- write ----
    def save(
        self, result: RunResult, json_text: str, md_text: str, secrets: Iterable[str], *, sarif: str | None = None
    ) -> Path:
        blobs = {sha: json.dumps(blob, sort_keys=True, separators=(",", ":")) for sha, blob in result.evidence.items()}
        assert_no_secrets([json_text, md_text, sarif or "", *blobs.values()], list(secrets))  # before anything exists
        if not valid_run_id(result.run_id):
            raise StoreError("invalid run id")
        self._check_root(create=True)
        run_dir = self.root / result.run_id
        run_dir.mkdir(mode=0o700)
        (run_dir / "evidence").mkdir(mode=0o700)
        for sha, text in blobs.items():
            _write_private(run_dir / "evidence" / f"{sha}.json", text.encode())
        _write_private(run_dir / "report.json", json_text.encode())
        _write_private(run_dir / "report.md", md_text.encode())
        if sarif is not None:
            _write_private(run_dir / "report.sarif", sarif.encode())
        return run_dir

    # ---------------------------------------------------------------------------------- read ----
    def _entries(self) -> list[Path]:
        if not self._check_root(create=False):
            return []
        return sorted(p for p in self.root.iterdir() if valid_run_id(p.name) and p.is_dir() and not p.is_symlink())

    def list_runs(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for path in self._entries():
            try:
                doc = json.loads((path / "report.json").read_text())
                rows.append(
                    {
                        "run_id": path.name, "scope_id": doc["scope"]["id"], "total": doc["summary"]["total"],
                        "exit_code": doc["summary"]["exit_code"], "started_at": doc["started_at"],
                    }
                )  # fmt: skip
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return sorted(rows, key=lambda r: (r["started_at"], r["run_id"]), reverse=True)

    def read_report(self, run_id: str, fmt: str) -> str:
        if not valid_run_id(run_id):
            raise StoreError("invalid run id")
        if fmt not in ("json", "md", "sarif"):
            raise StoreError("format must be json, md or sarif")
        self._check_root(create=False)
        path = self.root / run_id / f"report.{fmt}"
        if path.is_symlink() or not path.is_file():
            raise StoreError("no such run")
        return path.read_text()

    # --------------------------------------------------------------------------------- purge ----
    def purge(self, older_than: timedelta, now: datetime | None = None) -> list[str]:
        cutoff = (now or datetime.now(UTC)) - older_than
        removed = []
        for path in self._entries():
            if _run_time(path.name) < cutoff:
                shutil.rmtree(path)
                removed.append(path.name)
        return removed
