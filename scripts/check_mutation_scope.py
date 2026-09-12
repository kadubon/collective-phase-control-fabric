# SPDX-License-Identifier: Apache-2.0
"""Reject empty mutation targets and missing epistemic control methods.

This checks catalogue membership only. Full execution and score checks remain
separate and must still reject interrupted, missing or unsuccessful shards.
"""

from __future__ import annotations

import argparse
import tomllib
from pathlib import Path

from scripts.merge_mutation_results import read_results

ROOT = Path(__file__).resolve().parents[1]
METHODS: dict[str, dict[str, tuple[str, ...]]] = {
    "collective_phase_control_fabric.v6.epistemic": {
        "Domain": ("_validate", "advance", "mark_entry", "terminal", "replay", "pay"),
    },
    "collective_phase_control_fabric.v6.epistemic_planning": {
        "PolicySearch": ("enumerate",),
    },
}


def required_prefixes(root: Path = ROOT) -> set[str]:
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mutmut"]
    prefixes = set()
    for target in config["only_mutate"]:
        path = Path(target)
        source = next(Path(p) for p in config["source_paths"] if path.is_relative_to(p))
        module = ".".join(path.relative_to(source).with_suffix("").parts)
        prefixes.add(module + ".")
    for module, classes in METHODS.items():
        for cls, methods in classes.items():
            for method in methods:
                prefixes.add(f"{module}.xǁ{cls}ǁ{method}__mutmut_")
    return prefixes


def check_scope(names: set[str], root: Path = ROOT) -> None:
    missing = sorted(p for p in required_prefixes(root) if not any(n.startswith(p) for n in names))
    if missing:
        raise ValueError("mutation_scope_missing: " + ", ".join(missing))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    try:
        check_scope(set(read_results(args.results)))
    except (OSError, ValueError, StopIteration) as error:
        print(f"mutation scope check failed: {error}")
        return 1
    print("mutation scope includes every configured module and required control method")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
