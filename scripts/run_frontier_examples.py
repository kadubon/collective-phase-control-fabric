# SPDX-License-Identifier: Apache-2.0
"""Generate the eight exact, synthetic endogenous-frontier scenario reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from collective_phase_control_fabric.v6.frontier_examples import SCENARIOS, frontier_example
from collective_phase_control_fabric.v6.growth import plan_growth
from collective_phase_control_fabric.v6.models import GrowthPolicyNode

ROOT = Path(__file__).resolve().parents[1]


def paths(node: GrowthPolicyNode | None) -> list[list[str]]:
    if node is None or node.action_id is None:
        return [[]]
    return [
        [node.action_id, successor, *tail]
        for successor, child in sorted(node.branches.items())
        for tail in paths(child)
    ]


def reports() -> dict[str, Any]:
    result = {}
    for name in SCENARIOS:
        plan = plan_growth(*frontier_example(name))
        s = plan.spec
        result[name] = {
            "code": s.code,
            "solution_class": s.solution_class,
            "selected_policy_paths": paths(s.policy),
            "safe_fallback_paths": paths(s.safe_fallback),
            "objective": s.objective.model_dump(mode="json") if s.objective else None,
            "diagnostics": s.frontier_diagnostics.model_dump(mode="json"),
            "comparisons": [x.model_dump(mode="json") for x in s.comparisons],
            "counterexamples": s.counterexamples,
            "synthetic": True,
            "empirical_attribution": "undetermined",
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = reports()
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    target = ROOT / "docs" / "examples" / "frontier-comparison.json"
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != encoded:
            raise SystemExit("frontier example report differs from the executable catalogue")
    else:
        target.write_text(encoded, encoding="utf-8", newline="\n")
    for name, value in report.items():
        print(f"{name}: {value['code']}; policy={value['selected_policy_paths']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
