"""What a stranger actually gets: a wheel without the lab, installable in a clean environment."""

from __future__ import annotations

import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from tests.support import EXAMPLE, ROOT

pytestmark = pytest.mark.milestone("S4")


@pytest.fixture(scope="module")
def dist(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("dist")
    subprocess.run(["uv", "build", "--out-dir", str(out)], cwd=ROOT, check=True, capture_output=True, text=True)  # noqa: S607
    return out


def test_the_wheel_contains_the_package_and_never_the_lab(dist: Path) -> None:
    wheel = next(dist.glob("*.whl"))
    names = zipfile.ZipFile(wheel).namelist()
    assert "boundarycheck/py.typed" in names and "boundarycheck/cli.py" in names
    assert not [n for n in names if n.startswith(("tenantlab", "lab/")) or "/vulnerable/" in n or n.startswith("tests/")]
    assert any(n.endswith("licenses/LICENSE") for n in names) and any(n.endswith("licenses/NOTICE") for n in names)
    meta = next(n for n in names if n.endswith("METADATA"))
    text = zipfile.ZipFile(wheel).read(meta).decode()
    assert "tenant-boundary-lab" not in text and "License-Expression: Apache-2.0" in text
    assert "Requires-Dist: pyyaml" in text and "Requires-Dist: typer" in text
    entry = zipfile.ZipFile(wheel).read(next(n for n in names if n.endswith("entry_points.txt"))).decode()
    assert "boundarycheck = boundarycheck.cli:app" in entry


def test_the_source_distribution_does_not_carry_the_lab_submodule(dist: Path) -> None:
    sdist = next(dist.glob("*.tar.gz"))
    names = tarfile.open(sdist).getnames()  # noqa: SIM115
    assert names and not [n for n in names if "/lab/" in n or n.endswith("/lab")]


def test_a_clean_environment_runs_the_tool_without_the_lab(dist: Path, tmp_path: Path) -> None:
    venv = tmp_path / "venv"
    subprocess.run(["uv", "venv", "--python", "3.13", str(venv)], check=True, capture_output=True, text=True)  # noqa: S607
    wheel = next(dist.glob("*.whl"))
    subprocess.run(["uv", "pip", "install", "--python", str(venv / "bin" / "python"), str(wheel)], check=True, capture_output=True, text=True)  # noqa: S607
    exe = str(venv / "bin" / "boundarycheck")

    def call(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([exe, *args], capture_output=True, text=True, cwd=tmp_path, check=False)  # noqa: S603

    assert call("--help").returncode == 0
    assert call("validate", "--config", str(EXAMPLE)).returncode == 0
    init = call("init", "--output", str(tmp_path / "starter.yaml"))
    assert init.returncode == 0 and call("validate", "--config", str(tmp_path / "starter.yaml")).returncode == 0
    fixture = call("test", "--config", str(EXAMPLE), "--transport", "fixture")
    assert fixture.returncode == 2 and "tenant-boundary-lab" in fixture.stdout + fixture.stderr
    assert "Traceback" not in fixture.stdout + fixture.stderr
