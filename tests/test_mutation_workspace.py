# SPDX-License-Identifier: Apache-2.0
"""Mutation staging preserves source, dependency lock, test selection and gates."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

import pytest

from scripts.prepare_mutation_workspace import prepare

ROOT = Path(__file__).resolve().parents[1]


def test_monorepo_copy_preserves_every_source_and_nonlayout_setting(tmp_path: Path) -> None:
    output = tmp_path / "workspace"
    manifest = prepare(ROOT, output)
    original = tomllib.loads((ROOT / "pyproject.toml").read_text())
    rewritten = tomllib.loads((output / "pyproject.toml").read_text())
    before = original["tool"]["mutmut"]
    after = rewritten["tool"]["mutmut"]
    assert after["source_paths"] == ["src"]
    assert "pythonpath=src" in after["pytest_add_cli_args"]
    assert len(after["only_mutate"]) == len(before["only_mutate"])
    assert (output / "uv.lock").read_bytes() == (ROOT / "uv.lock").read_bytes()
    assert not (output / ".cache").exists() and not (output / ".git").exists()
    for target in before["only_mutate"]:
        entry = manifest[target]
        assert entry["path"] in after["only_mutate"]
        expected = hashlib.sha256((ROOT / target).read_bytes()).hexdigest()
        assert entry["sha256"] == expected
        assert hashlib.sha256((output / entry["path"]).read_bytes()).hexdigest() == expected
    for key in before:
        if key not in {"source_paths", "only_mutate", "pytest_add_cli_args"}:
            assert before[key] == after[key]
    rewritten["tool"]["mutmut"] = before
    assert rewritten == original
    with pytest.raises(ValueError, match="mutation_workspace_already_exists"):
        prepare(ROOT, output)


def test_colliding_source_names_fail_instead_of_overwriting(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    for name in ("src/pkg/a.py", "packages/extra/src/pkg/a.py"):
        path = root / name
        path.parent.mkdir(parents=True)
        path.write_text("value = 1\n")
    (root / "publication-files.txt").write_text("src/**\npackages/**\npyproject.toml\n")
    (root / "pyproject.toml").write_text(
        '[tool.mutmut]\nsource_paths=["src","packages/extra/src"]\n'
        'only_mutate=["src/pkg/a.py"]\npytest_add_cli_args=["-q"]\n'
    )
    with pytest.raises(ValueError, match="mutation_source_collision"):
        prepare(root, tmp_path / "output")
