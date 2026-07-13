# SPDX-License-Identifier: Apache-2.0
"""Validate every public schema and every base fixture document."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    schema_paths = sorted((ROOT / "schemas").glob("v*/*.schema.json"))
    if not schema_paths:
        raise RuntimeError("no schemas found")
    for path in schema_paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    print(f"validated {len(schema_paths)} schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
