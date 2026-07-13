# SPDX-License-Identifier: Apache-2.0
"""Export the closed v0.6 runtime model registry as JSON Schema 2020-12."""

from pathlib import Path

from collective_phase_control_fabric.v6.registry import write_schemas

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    write_schemas(ROOT / "schemas" / "v0.6.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
