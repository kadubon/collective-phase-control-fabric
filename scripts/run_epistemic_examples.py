# SPDX-License-Identifier: Apache-2.0
"""Generate finite model examples and negative controls; no external evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cpcf_cli.epistemic import example_report

ROOT = Path(__file__).resolve().parents[1]


def policy(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        key: spec[key]
        for key in (
            "code",
            "input_digest",
            "policy",
            "objective",
            "search",
            "peak_support",
            "primitive_transitions",
        )
    }


def reports() -> dict[str, Any]:
    output = {}
    for name in (
        "epistemic-probe",
        "epistemic-ambiguous",
        "epistemic-verifier",
        "epistemic-budget",
    ):
        report = example_report(name)
        output[name] = policy(report["plan"]["spec"])
    for name in ("epistemic-information", "epistemic-uninformative"):
        report = example_report(name)["spec"]
        output[name] = {
            key: report[key]
            for key in (
                "masked_channel",
                "optional_sensing_actions",
                "information_use",
                "net_sensing",
            )
        }
        output[name]["policies"] = {
            key: policy(report[key]["spec"])
            for key in ("full", "information_blind", "without_sensing")
        }
    integrated = example_report("epistemic-integrated")
    compiled = integrated["synthesis"]["spec"]
    output["epistemic-integrated"] = {
        "code": integrated["code"],
        "synthetic_observation": integrated["synthetic_observation"],
        "support": integrated["after_observation"],
        "initial_policy": policy(integrated["plan"]["spec"]),
        "workflow": compiled["candidates"][0],
        "certificate": compiled["certificates"][0],
        "reuse_without_formation_preferred": compiled["reuse_without_formation_preferred"],
        "replanned_policy": policy(integrated["replanned"]["plan"]["spec"]),
        "continuation_check": integrated["replanned"]["policy_check"],
    }
    absent = example_report("epistemic-no-composition")["spec"]
    output["epistemic-no-composition"] = {
        key: absent[key] for key in ("code", "search", "candidates", "formation_costs_incurred")
    }
    output["epistemic-rejected-composition"] = example_report("epistemic-rejected-composition")
    return {
        "synthetic": True,
        "execution_authorized": False,
        "empirical_attribution": "undetermined",
        "examples": output,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    values = reports()
    encoded = json.dumps(values, indent=2, sort_keys=True) + "\n"
    target = ROOT / "docs/examples/epistemic-comparison.json"
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != encoded:
            raise SystemExit("epistemic example report differs from the executable catalogue")
    else:
        target.write_text(encoded, encoding="utf-8", newline="\n")
    print(
        "Generated/checked "
        + str(len(values["examples"]))
        + " finite epistemic/composition examples"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
