# SPDX-License-Identifier: Apache-2.0
"""Deprecated v0.1 negative-test adapter; it cannot produce a promotable artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from collective_phase_control_fabric.canonical import digest_json, load_json


def main() -> int:
    """Emit an explicit failure receipt so Boolean-only legacy success cannot promote state."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    args = parser.parse_args()
    value = load_json(args.request)
    if not isinstance(value, dict) or not isinstance(value.get("action_id"), str):
        print(
            json.dumps(
                {
                    "schema_version": "0.2.0",
                    "action_id": "unknown",
                    "outcome": "failure",
                    "artifacts": [],
                    "failure_code": "malformed_request",
                }
            )
        )
        return 2
    print(
        json.dumps(
            {
                "schema_version": "0.2.0",
                "action_id": value["action_id"],
                "request_digest": digest_json(value),
                "outcome": "failure",
                "artifacts": [],
                "failure_code": "legacy_boolean_adapter_deprecated",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
