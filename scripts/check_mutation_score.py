# SPDX-License-Identifier: Apache-2.0
"""Enforce a mutation score without printing mutant source or names."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

COUNTED_FAILURES = {"survived", "no tests", "suspicious", "timeout", "segfault"}
COUNTED_SUCCESSES = {"killed", "caught by type check"}
INCOMPLETE = {"not checked", "check was interrupted by user"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("--minimum", type=float, default=85.0)
    args = parser.parse_args()
    counts: Counter[str] = Counter()
    for line in args.results.read_text(encoding="utf-8").splitlines():
        _, separator, status = line.rpartition(": ")
        if separator:
            counts[status.strip()] += 1
    incomplete = sum(counts[item] for item in INCOMPLETE)
    successful = sum(counts[item] for item in COUNTED_SUCCESSES)
    failed = sum(counts[item] for item in COUNTED_FAILURES)
    total = successful + failed
    if incomplete or total == 0:
        print(
            f"mutation gate incomplete: evaluated={total} incomplete={incomplete}",
        )
        return 1
    score = successful * 100.0 / total
    print(f"mutation score: {score:.2f}% across {total} counted mutants")
    return 0 if score >= args.minimum else 1


if __name__ == "__main__":
    raise SystemExit(main())
