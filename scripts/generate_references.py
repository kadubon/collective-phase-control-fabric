# SPDX-License-Identifier: Apache-2.0
"""Generate runtime-derived CLI, API, error, and agent reference documents."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from cpcf_api.app import create_app
from cpcf_cli.main import build_parser

from collective_phase_control_fabric.v6.catalog import AGENT_GUIDANCE, ERROR_CATALOG

ROOT = Path(__file__).resolve().parents[1]


def _commands(
    parser: argparse.ArgumentParser, prefix: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for action in parser._actions:  # argparse exposes no public subparser traversal API.
        if not isinstance(action, argparse._SubParsersAction):
            continue
        choice_help = {
            item.dest: item.help
            for item in action._choices_actions
        }
        for name, child in sorted(action.choices.items()):
            command = (*prefix, name)
            result.append(
                {
                    "argv": list(command),
                    "description": child.description or choice_help.get(name) or "",
                    "help": choice_help.get(name),
                }
            )
            result.extend(_commands(child, command))
    return result


def documents() -> dict[str, Any]:
    return {
        "agent-guidance.json": AGENT_GUIDANCE,
        "cli.json": {"program": "cpcf", "commands": _commands(build_parser())},
        "error-catalog.json": ERROR_CATALOG,
        "openapi.json": create_app().openapi(),
    }


def _encoded(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    destination = ROOT / "docs" / "reference" / "generated"
    if args.check:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for name, value in documents().items():
                (target / name).write_text(_encoded(value), encoding="utf-8", newline="\n")
            mismatches = [
                name
                for name in documents()
                if not (destination / name).is_file()
                or (destination / name).read_bytes() != (target / name).read_bytes()
            ]
        if mismatches:
            print("generated reference mismatch: " + ", ".join(sorted(mismatches)))
            return 1
        print("generated references match runtime registries")
        return 0
    destination.mkdir(parents=True, exist_ok=True)
    for name, value in documents().items():
        (destination / name).write_text(_encoded(value), encoding="utf-8", newline="\n")
    print(f"generated {len(documents())} runtime reference documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
