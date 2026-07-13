# SPDX-License-Identifier: Apache-2.0
"""Exercise a deterministic local metadata/CAS backup and restore round trip."""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from collective_phase_control_fabric.v6.canonical import (
    canonical_bytes,
    digest_bytes,
    loads_bounded,
)

COMMIT = re.compile(r"^[0-9a-f]{40}$")


def restore_round_trip() -> dict[str, Any]:
    source = {
        "tenants": {
            "tenant-a": {
                "current_generation": "sha256:" + "1" * 64,
                "objects": {
                    digest_bytes(b"object-a"): "object-a",
                    digest_bytes(b"object-b"): "object-b",
                },
                "history": ["sha256:" + "2" * 64, "sha256:" + "3" * 64],
            },
            "tenant-b": {
                "current_generation": "sha256:" + "4" * 64,
                "objects": {digest_bytes(b"object-c"): "object-c"},
                "history": ["sha256:" + "5" * 64],
            },
        }
    }
    backup_started = perf_counter()
    archive = canonical_bytes(source)
    archive_digest = digest_bytes(archive)
    backup_seconds = perf_counter() - backup_started
    restore_started = perf_counter()
    restored = loads_bounded(archive)
    restore_seconds = perf_counter() - restore_started
    if restored != source or digest_bytes(canonical_bytes(restored)) != archive_digest:
        raise AssertionError("restored state does not match the backup manifest")
    if set(restored["tenants"]) != {"tenant-a", "tenant-b"}:
        raise AssertionError("tenant scope changed during restore")
    return {
        "archive_digest": archive_digest,
        "backup_microseconds": round(backup_seconds * 1_000_000),
        "restore_microseconds": round(restore_seconds * 1_000_000),
        "tenant_count": 2,
        "object_count": 3,
        "generation_and_history_binding": "passed",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if COMMIT.fullmatch(args.commit) is None:
        raise SystemExit("commit must be a lowercase 40-character Git SHA")
    try:
        observations = restore_round_trip()
    except (AssertionError, TypeError, ValueError) as error:
        raise SystemExit(str(error)) from error
    content: dict[str, Any] = {
        "schema_version": "cpcf.io/operations-evidence/v1",
        "kind": "reference-restore-harness",
        "commit_sha": args.commit,
        "observed_at": datetime.now(UTC).isoformat(),
        "claim_boundary": (
            "Local canonical round trip only; not a PostgreSQL PITR, object-store versioning, "
            "RPO, RTO, or intended-deployment restore result."
        ),
        "observations": observations,
    }
    content["evidence_digest"] = digest_bytes(canonical_bytes(content))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(content, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("restore harness passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
