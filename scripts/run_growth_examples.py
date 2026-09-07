# SPDX-License-Identifier: Apache-2.0
"""Generate/check the deterministic growth comparison report from executable models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from collective_phase_control_fabric.v6.growth_examples import comparison_example

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = {
        name: comparison_example(name)
        for name in ("preparation", "verification", "communication", "all-failure", "no-advantage")
    }
    encoded = (
        json.dumps(
            report, default=lambda obj: obj.model_dump(mode="json"), indent=2, sort_keys=True
        )
        + "\n"
    )
    target = ROOT / "docs" / "examples" / "growth-comparison.json"
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != encoded:
            raise SystemExit("growth example report differs from the executable catalogue")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(encoded, encoding="utf-8", newline="\n")
    for name, value in report.items():
        growth = value["growth"]
        print(
            f"{name}: {growth['code']}; action={growth['primary_action']}; "
            f"entry={growth['time_to_modelled_entry']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
