# SPDX-License-Identifier: Apache-2.0
"""Print literal selectors for one eighth of a modulo-five mutation shard."""

from __future__ import annotations

import argparse

from scripts.merge_mutation_results import SHARDS

PARTS = 8


def selectors(shard: int, part: int) -> list[str]:
    if not 0 <= shard < SHARDS or not 0 <= part < PARTS:
        raise ValueError("mutation_partition_invalid")
    residue = shard + SHARDS * part
    # 1000 is divisible by 40, so the final three digits determine ownership.
    # A hundreds digit contributes 0 or 20 modulo 40 according to its parity.
    patterns = []
    for parity, hundreds in ((0, "02468"), (1, "13579")):
        first_tens = ((residue - 20 * parity) % 40) // 10
        tens = "".join(str(digit) for digit in range(first_tens, 10, 4))
        patterns.append(f"*__mutmut_*[{hundreds}][{tens}]{residue % 10}")
    # Short positive indices have no hundreds digit. Match them exactly once.
    patterns.extend(f"*__mutmut_{number}" for number in range(residue, 100, 40) if number)
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
