# SPDX-License-Identifier: Apache-2.0
"""Exercise the pinned generator and reject silent class/import exclusions."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest
from mutmut.mutation.file_mutation import mutate_file_contents

from scripts.check_mutation_scope import check_scope, required_prefixes

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("filename", "cls", "method"),
    [("epistemic.py", "Domain", "advance"), ("epistemic_planning.py", "PolicySearch", "enumerate")],
)
def test_pinned_generator_reaches_control_methods(filename: str, cls: str, method: str) -> None:
    path = ROOT / "src/collective_phase_control_fabric/v6" / filename
    code = path.read_text(encoding="utf-8")
    node = next(n for n in ast.parse(code).body if isinstance(n, ast.ClassDef) and n.name == cls)
    function = next(n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == method)
    assert function.end_lineno is not None
    _, names = mutate_file_contents(
        str(path), code, set(range(function.lineno, function.end_lineno + 1))
    )
    assert any(f"ǁ{cls}ǁ{method}__mutmut_" in name for name in names)


def test_scope_rejects_empty_cli_and_hidden_class_exclusions() -> None:
    names = {p + "example__mutmut_1" for p in required_prefixes()}
    check_scope(names)
    for excluded in ("cpcf_cli.epistemic.", "ǁDomainǁadvance", "ǁPolicySearchǁenumerate"):
        with pytest.raises(ValueError, match="mutation_scope_missing"):
            check_scope({n for n in names if excluded not in n})


def test_mutation_pytest_paths_resolve_nested_packages_inside_mutants() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["mutmut"]
    args = config["pytest_add_cli_args"]
    setting = args[args.index("-o") + 1]
    assert setting.startswith("pythonpath=")
    paths = set(setting.removeprefix("pythonpath=").split())
    assert set(config["source_paths"]) <= paths
    assert all(not Path(p).is_absolute() and ".." not in Path(p).parts for p in paths)
