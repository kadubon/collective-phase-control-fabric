# SPDX-License-Identifier: Apache-2.0
"""Verify all packaged deterministic fixture expectations."""

from __future__ import annotations

import json
from pathlib import Path

from collective_phase_control_fabric.engine import analyze
from collective_phase_control_fabric.fixtures import FIXTURE_NAMES, fixture

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    for name in FIXTURE_NAMES:
        descriptor = json.loads((ROOT / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))
        if descriptor["fixture_name"] != name or descriptor["synthetic"] is not True:
            raise RuntimeError(f"malformed fixture descriptor: {name}")
        data = fixture(name)
        report = analyze(
            data["contract"],
            data["network"],
            data["productive_witness"],
            data["maintenance_witness"],
        )
        expected = data["expected"]
        if (
            "ladder_level" in expected
            and report["phase_projection"]["ladder_level"] != expected["ladder_level"]
        ):
            raise RuntimeError(f"ladder mismatch: {name}")
        if "detectors" in expected:
            active = {
                item["detector"]
                for item in report["false_positive_detections"]
                if item["blocking"] is True
            }
            if not set(expected["detectors"]) <= active:
                raise RuntimeError(f"detector mismatch: {name}")
        if "external_claim_bundle_compatible" in expected:
            actual = report["external_claim_bundle"]["external_claim_bundle_compatible"]
            if actual is not expected["external_claim_bundle_compatible"]:
                raise RuntimeError(f"external bundle mismatch: {name}")
    print(f"validated {len(FIXTURE_NAMES)} fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
