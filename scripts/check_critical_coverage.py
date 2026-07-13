# SPDX-License-Identifier: Apache-2.0
"""Enforce branch-enabled coverage independently for each critical subsystem."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

GROUPS: dict[str, tuple[str, ...]] = {
    "parsing-schemas": (
        "src/collective_phase_control_fabric/v6/canonical.py",
        "src/collective_phase_control_fabric/v6/models.py",
        "src/collective_phase_control_fabric/v6/registry.py",
    ),
    "trust-provenance": (
        "src/collective_phase_control_fabric/v6/trust.py",
        "src/collective_phase_control_fabric/v6/authority.py",
    ),
    "storage": (
        "src/collective_phase_control_fabric/v6/storage.py",
        "packages/cpcf-api/src/cpcf_api/db.py",
        "packages/cpcf-api/src/cpcf_api/object_store.py",
    ),
    "api-authorization": ("packages/cpcf-api/src/cpcf_api/auth.py",),
    "projection": ("src/collective_phase_control_fabric/v6/projection.py",),
    "runner": (
        "src/collective_phase_control_fabric/v6/runner.py",
        "packages/cpcf-api/src/cpcf_api/runner_gateway.py",
    ),
    "science-perturbation": (
        "src/collective_phase_control_fabric/v6/science.py",
        "src/collective_phase_control_fabric/v6/structural_analysis.py",
        "src/collective_phase_control_fabric/v6/intervention.py",
    ),
    "planning": ("src/collective_phase_control_fabric/v6/planning.py",),
    "trials": ("src/collective_phase_control_fabric/v6/trials.py",),
    "coordination": ("src/collective_phase_control_fabric/v6/coordination.py",),
    "repairs": ("src/collective_phase_control_fabric/v6/repairs.py",),
    "onboarding": ("src/collective_phase_control_fabric/v6/onboarding.py",),
}


def _normalized(value: str) -> str:
    return value.replace("\\", "/").removeprefix("./")


def evaluate(path: Path, minimum: float) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_files = payload.get("files")
    if not isinstance(raw_files, dict):
        raise ValueError("coverage JSON has no files object")
    files = {_normalized(name): value for name, value in raw_files.items()}
    results: dict[str, float] = {}
    failures: list[str] = []
    for group, names in GROUPS.items():
        covered = 0
        total = 0
        missing: list[str] = []
        for name in names:
            value = files.get(name)
            if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
                missing.append(name)
                continue
            summary = value["summary"]
            covered += int(summary.get("covered_lines", 0)) + int(
                summary.get("covered_branches", 0)
            )
            total += int(summary.get("num_statements", 0)) + int(summary.get("num_branches", 0))
        if missing:
            failures.append(f"{group}:missing={','.join(missing)}")
            continue
        score = 100.0 if total == 0 else covered * 100.0 / total
        results[group] = score
        if score + 1e-12 < minimum:
            failures.append(f"{group}:{score:.2f}<{minimum:.2f}")
    if failures:
        raise ValueError("critical coverage failed: " + "; ".join(failures))
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("coverage_json", type=Path)
    parser.add_argument("--minimum", type=float, default=95.0)
    args = parser.parse_args()
    if not 0 <= args.minimum <= 100:
        raise SystemExit("coverage minimum must be between 0 and 100")
    try:
        results = evaluate(args.coverage_json, args.minimum)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error
    print(
        "critical coverage passed: "
        + ", ".join(f"{name}={score:.2f}%" for name, score in sorted(results.items()))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
