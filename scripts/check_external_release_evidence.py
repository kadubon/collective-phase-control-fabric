# SPDX-License-Identifier: Apache-2.0
"""Fail closed unless external commercial release gates are bound to the release commit."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_GATES = {
    "availability_soak",
    "backup_restore",
    "load_profile",
    "chaos_profile",
    "threat_model_review",
    "penetration_test",
}


def _integer(value: Any, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def validate_manifest(value: Any, *, version: str, commit: str) -> list[str]:
    reasons: list[str] = []
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "release_version",
        "commit_sha",
        "gates",
    }:
        return ["release_evidence_manifest_shape_invalid"]
    if value.get("schema_version") != "cpcf.io/release-evidence/v1":
        reasons.append("release_evidence_schema_version_invalid")
    if value.get("release_version") != version:
        reasons.append("release_evidence_version_mismatch")
    if value.get("commit_sha") != commit or COMMIT.fullmatch(str(value.get("commit_sha"))) is None:
        reasons.append("release_evidence_commit_mismatch")
    gates = value.get("gates")
    if not isinstance(gates, list):
        return [*reasons, "release_evidence_gates_invalid"]
    if len(gates) != len(REQUIRED_GATES):
        reasons.append("release_evidence_gate_count_invalid")
    by_name: dict[str, dict[str, Any]] = {}
    for gate in gates:
        if not isinstance(gate, dict) or set(gate) != {
            "name",
            "passed",
            "independent",
            "evidence_digest",
            "details",
        }:
            reasons.append("release_evidence_gate_shape_invalid")
            continue
        name = gate.get("name")
        if not isinstance(name, str) or name in by_name:
            reasons.append("release_evidence_gate_name_invalid_or_duplicate")
            continue
        by_name[name] = gate
        if gate.get("passed") is not True:
            reasons.append(f"release_gate_not_passed:{name}")
        if not isinstance(gate.get("independent"), bool):
            reasons.append(f"release_gate_independence_invalid:{name}")
        if DIGEST.fullmatch(str(gate.get("evidence_digest"))) is None:
            reasons.append(f"release_gate_digest_invalid:{name}")
        if not isinstance(gate.get("details"), dict):
            reasons.append(f"release_gate_details_invalid:{name}")
    missing = REQUIRED_GATES - set(by_name)
    if missing:
        reasons.append("release_evidence_gates_missing:" + ",".join(sorted(missing)))
    unexpected = set(by_name) - REQUIRED_GATES
    if unexpected:
        reasons.append("release_evidence_gates_unexpected:" + ",".join(sorted(unexpected)))
    for name in ("threat_model_review", "penetration_test"):
        if name in by_name and by_name[name].get("independent") is not True:
            reasons.append(f"release_gate_independence_required:{name}")
    soak = by_name.get("availability_soak", {}).get("details")
    if not isinstance(soak, dict) or _integer(soak.get("duration_seconds"), 0) < 2_592_000:
        reasons.append("availability_soak_shorter_than_30_days")
    restore = by_name.get("backup_restore", {}).get("details")
    if not isinstance(restore, dict) or restore.get("intended_deployment") is not True:
        reasons.append("restore_not_run_in_intended_deployment")
    penetration = by_name.get("penetration_test", {}).get("details")
    if (
        not isinstance(penetration, dict)
        or _integer(penetration.get("open_blocking_findings"), -1) != 0
    ):
        reasons.append("penetration_test_blocking_findings_open")
    return sorted(set(reasons))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        value = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit("external release evidence is missing or invalid") from error
    reasons = validate_manifest(value, version=args.version, commit=args.commit)
    if reasons:
        raise SystemExit("external release evidence rejected: " + "; ".join(reasons))
    print("external release evidence accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
