# SPDX-License-Identifier: Apache-2.0
"""Reconstruct one complete mutation catalogue from five disjoint CI shards."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
from pathlib import Path

from scripts.check_mutation_score import COUNTED_FAILURES, COUNTED_SUCCESSES, INCOMPLETE

SHARDS = 5
MUTANT_NAME = re.compile(r"\S+__mutmut_([1-9][0-9]*)\Z")
TERMINAL = COUNTED_FAILURES | COUNTED_SUCCESSES


def read_results(path: Path) -> dict[str, str]:
    results: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        name, separator, status = line.strip().rpartition(": ")
        if not separator or MUTANT_NAME.fullmatch(name) is None:
            raise ValueError("mutation_result_malformed")
        if name in results:
            raise ValueError("mutation_result_duplicate")
        if status not in TERMINAL | INCOMPLETE:
            raise ValueError("mutation_result_status_unknown")
        results[name] = status
    if not results:
        raise ValueError("mutation_catalogue_empty")
    return results


def merge_results(directory: Path, catalogue_path: Path, *, parts: int = 1) -> dict[str, str]:
    if parts not in {1, 4, 8}:
        raise ValueError("mutation_partition_count_invalid")
    declaration = json.loads(catalogue_path.read_text(encoding="utf-8"))
    if not isinstance(declaration, dict) or set(declaration) != {
        "mutmut_version",
        "mutant_count",
        "sorted_names_sha256",
    }:
        raise ValueError("mutation_catalogue_declaration_invalid")
    if declaration["mutmut_version"] != importlib.metadata.version("mutmut"):
        raise ValueError("mutation_tool_version_mismatch")
    names = [
        f"mutation-shard-{shard}" + (f"-{part}" if parts > 1 else "")
        for part in range(parts)
        for shard in range(SHARDS)
    ]
    expected = set(names)
    if {path.name for path in directory.iterdir()} != expected:
        raise ValueError("mutation_shard_set_mismatch")
    reports = []
    for folder_name in names:
        folder = directory / folder_name
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError("mutation_shard_path_invalid")
        path = folder / "mutation-results.txt"
        if path.is_symlink() or not path.is_file():
            raise ValueError("mutation_shard_report_missing")
        if set(folder.iterdir()) != {path}:
            raise ValueError("mutation_shard_files_unexpected")
        reports.append(read_results(path))
    catalogue = set(reports[0])
    if any(set(report) != catalogue for report in reports[1:]):
        raise ValueError("mutation_catalogue_mismatch")
    digest = hashlib.sha256("".join(name + "\n" for name in sorted(catalogue)).encode()).hexdigest()
    if (
        type(declaration["mutant_count"]) is not int
        or len(catalogue) != declaration["mutant_count"]
        or digest != declaration["sorted_names_sha256"]
    ):
        raise ValueError("mutation_declared_catalogue_mismatch")
    combined: dict[str, str] = {}
    for name in sorted(catalogue):
        # Physical subdivision retains each original modulo-five logical owner.
        owner = int(name.rsplit("__mutmut_", 1)[1]) % (SHARDS * parts)
        for index, report in enumerate(reports):
            status = report[name]
            if index == owner:
                if status not in TERMINAL:
                    raise ValueError("mutation_shard_incomplete")
                combined[name] = status
            elif status != "not checked":
                raise ValueError("mutation_shard_overlap")
    return combined


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--catalogue", type=Path, required=True)
    parser.add_argument("--parts", type=int, choices=(1, 4, 8), default=1)
    args = parser.parse_args()
    try:
        combined = merge_results(args.directory, args.catalogue, parts=args.parts)
        args.output.write_text(
            "".join(f"{name}: {status}\n" for name, status in combined.items()),
            encoding="utf-8",
            newline="\n",
        )
    except (OSError, ValueError) as error:
        code = str(error) if isinstance(error, ValueError) else "mutation_shard_io_error"
        print(f"mutation shard gate failed: {code}")
        return 1
    print(
        f"mutation shards complete: {len(combined)} unique mutants across "
        f"{SHARDS} logical shards and {SHARDS * args.parts} execution parts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
