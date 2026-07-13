# SPDX-License-Identifier: Apache-2.0
"""Run the bounded in-memory commercial-scale admission reference harness."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from cpcf_api.app import InMemoryBackend

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes

COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _bind_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    return {**payload, "evidence_digest": digest_bytes(canonical_bytes(payload))}


async def run_profile(
    tenants: int, workspaces: int, audits: int, concurrency: int
) -> dict[str, Any]:
    if not 1 <= tenants <= workspaces or not 1 <= audits <= workspaces:
        raise ValueError("load profile counts are inconsistent")
    if not 1 <= concurrency <= 1000:
        raise ValueError("load concurrency is outside the bounded profile")
    backend = InMemoryBackend()
    semaphore = asyncio.Semaphore(concurrency)
    workspace_latencies: list[float] = []

    async def create(index: int) -> None:
        tenant_id = f"tenant-{index % tenants:03d}"
        workspace_id = f"workspace-{index:05d}"
        async with semaphore:
            started = perf_counter()
            await backend.create_workspace(
                tenant_id,
                workspace_id,
                "sha256:" + "1" * 64,
                "sha256:" + "2" * 64,
            )
            workspace_latencies.append(perf_counter() - started)

    started = perf_counter()
    await asyncio.gather(*(create(index) for index in range(workspaces)))
    workspace_elapsed = perf_counter() - started
    job_latencies: list[float] = []

    async def enqueue(index: int) -> None:
        tenant_id = f"tenant-{index % tenants:03d}"
        workspace_id = f"workspace-{index:05d}"
        async with semaphore:
            admitted = perf_counter()
            job_id = await backend.enqueue(tenant_id, workspace_id, "analysis")
            job_latencies.append(perf_counter() - admitted)
            if await backend.job(tenant_id, job_id) is None:
                raise AssertionError("admitted job is not tenant-readable")
            other_tenant = f"tenant-{(index + 1) % tenants:03d}"
            if other_tenant != tenant_id and await backend.job(other_tenant, job_id) is not None:
                raise AssertionError("cross-tenant job read succeeded")

    admitted = perf_counter()
    await asyncio.gather(*(enqueue(index) for index in range(audits)))
    job_elapsed = perf_counter() - admitted
    if len(backend.workspaces) != workspaces or len(backend.jobs) != audits:
        raise AssertionError("load harness cardinality mismatch")
    return {
        "profile": {
            "tenants": tenants,
            "workspaces": workspaces,
            "concurrent_audit_admissions": audits,
            "task_concurrency": concurrency,
        },
        "observations": {
            "workspace_total_microseconds": round(workspace_elapsed * 1_000_000),
            "workspace_create_p95_microseconds": round(
                _percentile(workspace_latencies, 0.95) * 1_000_000
            ),
            "audit_admission_total_microseconds": round(job_elapsed * 1_000_000),
            "audit_admission_p95_microseconds": round(_percentile(job_latencies, 0.95) * 1_000_000),
            "cross_tenant_job_isolation": "passed",
        },
        "targets": {
            "audit_admission_p95_microseconds": 1_000_000,
            "audit_admission_target_met": _percentile(job_latencies, 0.95) <= 1.0,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenants", type=int, default=100)
    parser.add_argument("--workspaces", type=int, default=10_000)
    parser.add_argument("--audits", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=100)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if COMMIT.fullmatch(args.commit) is None:
        raise SystemExit("commit must be a lowercase 40-character Git SHA")
    try:
        result = asyncio.run(
            run_profile(args.tenants, args.workspaces, args.audits, args.concurrency)
        )
    except (AssertionError, ValueError) as error:
        raise SystemExit(str(error)) from error
    payload = _bind_evidence(
        {
            "schema_version": "cpcf.io/operations-evidence/v1",
            "kind": "reference-load-harness",
            "commit_sha": args.commit,
            "observed_at": datetime.now(UTC).isoformat(),
            "claim_boundary": (
                "In-memory reference admission evidence only; not a service availability, "
                "database, object-store, or production latency claim."
            ),
            **result,
        }
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(
        f"load harness passed: {args.tenants} tenants, {args.workspaces} workspaces, "
        f"{args.audits} audits"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
