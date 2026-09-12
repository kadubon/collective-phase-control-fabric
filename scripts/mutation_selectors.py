# SPDX-License-Identifier: Apache-2.0
"""Print literal selectors for one quarter of a modulo-five mutation shard."""

from __future__ import annotations

import argparse

from scripts.merge_mutation_results import SHARDS

PARTS = 4


def selectors(shard: int, part: int) -> list[str]:
    if not 0 <= shard < SHARDS or not 0 <= part < PARTS:
        raise ValueError("mutation_partition_invalid")
    residue = shard + SHARDS * part
    tens = "02468" if residue < 10 else "13579"
    patterns = [f"*__mutmut_*[{tens}]{residue % 10}"]
    if 0 < residue < 10:
        patterns.append(f"*__mutmut_{residue}")
    return patterns


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, choices=range(SHARDS), required=True)
    parser.add_argument("--part", type=int, choices=range(PARTS), required=True)
    args = parser.parse_args()
    for pattern in selectors(args.shard, args.part):
        print(pattern)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
