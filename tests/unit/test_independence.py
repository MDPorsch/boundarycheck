"""Structural independence (docs/contract.md s3): the judge must not be able to inherit the bugs of
the thing being judged, and only one module may know the lab exists."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.milestone("S1")

SRC = Path(__file__).resolve().parents[2] / "src" / "boundarycheck"
JUDGES = ("oracle.py", "comparator.py")
ALLOWED_FOR_JUDGES = {"boundarycheck.model", "boundarycheck.config"}
STDLIB_OK = {
    "__future__",
    "collections",
    "dataclasses",
    "enum",
    "hashlib",
    "json",
    "typing",
    "re",
    "functools",
    "itertools",
}


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = f"boundarycheck.{base}" if base else "boundarycheck"
            found.add(base)
            found |= {f"{base}.{a.name}" for a in node.names}
    return found


@pytest.mark.parametrize("name", JUDGES)
def test_the_judges_import_only_the_neutral_model_and_the_standard_library(name: str) -> None:
    for module in _imports(SRC / name):
        root = module.split(".")[0]
        if root == "boundarycheck":
            assert module in ALLOWED_FOR_JUDGES or module.startswith(tuple(ALLOWED_FOR_JUDGES)), (
                name,
                module,
            )
        else:
            assert root in STDLIB_OK, (name, module)


def _modules() -> list[Path]:
    """Every product module; a vacuous pass (no files) is a failure, never a pass."""
    found = sorted(SRC.rglob("*.py"))
    assert len(found) >= 10 and (SRC / "transports" / "lab_fixture.py").is_file(), (
        "the product modules do not exist yet"
    )
    return found


def test_only_the_lab_adapter_may_import_the_lab() -> None:
    offenders = []
    for path in _modules():
        if path.name == "lab_fixture.py":
            continue
        if any(m.split(".")[0] == "tenantlab" for m in _imports(path)):
            offenders.append(path.name)
    assert not offenders, offenders


def test_the_lab_is_imported_lazily_even_in_its_adapter() -> None:
    tree = ast.parse((SRC / "transports" / "lab_fixture.py").read_text())
    top_level = [n for n in tree.body if isinstance(n, ast.Import | ast.ImportFrom)]
    assert not any(
        (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "tenantlab")
        or (isinstance(n, ast.Import) and any(a.name.split(".")[0] == "tenantlab" for a in n.names))
        for n in top_level
    ), "importing boundarycheck must work without the lab installed"


def test_nothing_imports_a_module_named_by_the_config() -> None:
    for path in _modules():
        source = path.read_text()
        assert "importlib.import_module" not in source and "__import__(" not in source, path.name
        assert "eval(" not in source and "exec(" not in source.replace("execute", ""), path.name
