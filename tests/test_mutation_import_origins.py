# SPDX-License-Identifier: Apache-2.0
"""A mutation baseline must import its copied targets, including nested packages."""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path


def test_every_mutation_target_is_imported_from_the_current_source_tree() -> None:
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mutmut"]
    for target in config["only_mutate"]:
        path = Path(target)
        source = next(Path(p) for p in config["source_paths"] if path.is_relative_to(p))
        name = ".".join(path.relative_to(source).with_suffix("").parts)
        module = importlib.import_module(name)
        assert module.__file__ is not None
        assert Path(module.__file__).resolve() == (root / target).resolve(), name
