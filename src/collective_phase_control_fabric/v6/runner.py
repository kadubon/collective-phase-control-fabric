# SPDX-License-Identifier: Apache-2.0
"""External runner lease and signed-receipt conformance checks."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from collective_phase_control_fabric.v6.models import (
    CapabilityDocument,
    RunnerJob,
    RunnerReceipt,
    StrictModel,
)
from collective_phase_control_fabric.v6.registry import document_digest


class RunnerConformance(StrictModel):
    accepted: bool
    code: str
    reasons: list[str] = Field(default_factory=list)


def validate_receipt(
    job: RunnerJob,
    receipt: RunnerReceipt,
    capability: CapabilityDocument,
    *,
    received_at: datetime,
    expected_runner_principal_id: str,
    prior_attempts: set[tuple[str, int]],
) -> RunnerConformance:
    reasons: list[str] = []
    if receipt.spec.job_digest != document_digest(job):
        reasons.append("runner_job_digest_mismatch")
    if receipt.spec.job_id != job.spec.job_id:
        reasons.append("runner_job_id_mismatch")
    if receipt.spec.attempt != job.spec.attempt:
        reasons.append("runner_attempt_mismatch")
    if receipt.spec.lease_id != job.spec.lease_id:
        reasons.append("runner_lease_id_mismatch")
    if received_at > job.spec.lease_expires_at:
        reasons.append("runner_lease_expired")
    if (job.spec.job_id, job.spec.attempt) in prior_attempts:
        reasons.append("runner_attempt_replay")
    if receipt.spec.runner_principal_id != expected_runner_principal_id:
        reasons.append("runner_principal_unrecognized")
    if receipt.spec.image_digest != job.spec.image_digest:
        reasons.append("runner_image_digest_mismatch")
    if set(receipt.spec.material_digests) != set(capability.spec.material_digests):
        reasons.append("runner_material_closure_mismatch")
    if receipt.spec.stdout_captured_bytes > job.spec.stdout_limit:
        reasons.append("runner_stdout_limit_exceeded")
    if receipt.spec.stderr_captured_bytes > job.spec.stderr_limit:
        reasons.append("runner_stderr_limit_exceeded")
    if receipt.spec.timeout:
        reasons.append("runner_timeout_maps_to_failure")
    if not receipt.spec.cleanup_complete:
        reasons.append("runner_cleanup_incomplete")
    if (
        job.spec.network_policy == "runner-attested"
        and receipt.spec.isolation_profile_digest is None
    ):
        reasons.append("runner_network_isolation_attestation_missing")
    if (
        job.spec.filesystem_policy == "runner-attested"
        and receipt.spec.isolation_profile_digest is None
    ):
        reasons.append("runner_filesystem_isolation_attestation_missing")
    return RunnerConformance(
        accepted=not reasons,
        code="runner_receipt_conformant" if not reasons else "runner_receipt_rejected",
        reasons=sorted(set(reasons)),
    )
