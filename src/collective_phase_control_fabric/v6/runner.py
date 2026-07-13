# SPDX-License-Identifier: Apache-2.0
"""External runner lease and signed-receipt conformance checks."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from collective_phase_control_fabric.v6.models import (
    CapabilityDocument,
    ExecutionPolicy,
    JsonValue,
    RunnerJob,
    RunnerReceipt,
    StrictModel,
)
from collective_phase_control_fabric.v6.projection import resolve_pointer
from collective_phase_control_fabric.v6.registry import (
    document_digest,
    parse_document,
    schema_digest,
)


class RunnerConformance(StrictModel):
    accepted: bool
    code: str
    reasons: list[str] = Field(default_factory=list)


def validate_receipt(
    job: RunnerJob,
    receipt: RunnerReceipt,
    capability: CapabilityDocument,
    execution_policy: ExecutionPolicy,
    *,
    received_at: datetime,
    expected_runner_principal_id: str,
    prior_attempts: set[tuple[str, int]],
    available_digests: set[str],
    artifact_lengths: dict[str, int],
    output_document: JsonValue | None = None,
) -> RunnerConformance:
    reasons: list[str] = []
    if receipt.spec.job_digest != document_digest(job):
        reasons.append("runner_job_digest_mismatch")
    if job.spec.capability_digest != document_digest(capability):
        reasons.append("runner_capability_digest_mismatch")
    if job.spec.execution_policy_digest != document_digest(execution_policy):
        reasons.append("runner_execution_policy_digest_mismatch")
    if capability.spec.execution_policy_digest != document_digest(execution_policy):
        reasons.append("capability_execution_policy_digest_mismatch")
    if capability.spec.output_schema_digest != schema_digest(capability.spec.output_schema_name):
        reasons.append("runner_output_schema_digest_mismatch")
    if receipt.spec.job_id != job.spec.job_id:
        reasons.append("runner_job_id_mismatch")
    if receipt.spec.attempt != job.spec.attempt:
        reasons.append("runner_attempt_mismatch")
    if receipt.spec.lease_id != job.spec.lease_id:
        reasons.append("runner_lease_id_mismatch")
    if received_at > job.spec.lease_expires_at:
        reasons.append("runner_lease_expired")
    if receipt.spec.completed_at > received_at:
        reasons.append("runner_receipt_completed_in_future")
    if receipt.spec.started_at < job.metadata.created_at:
        reasons.append("runner_start_before_job_creation")
    if receipt.spec.completed_at > job.spec.lease_expires_at:
        reasons.append("runner_completion_after_lease_expiry")
    if (job.spec.job_id, job.spec.attempt) in prior_attempts:
        reasons.append("runner_attempt_replay")
    if receipt.spec.runner_principal_id != expected_runner_principal_id:
        reasons.append("runner_principal_unrecognized")
    if receipt.spec.image_digest != job.spec.image_digest:
        reasons.append("runner_image_digest_mismatch")
    if capability.spec.image_digest != job.spec.image_digest:
        reasons.append("runner_capability_image_mismatch")
    if job.spec.image_digest not in execution_policy.spec.allowed_image_digests:
        reasons.append("runner_image_not_allowed_by_execution_policy")
    expected_materials = (
        set(capability.spec.material_digests)
        | set(job.spec.input_digests)
        | {
            job.spec.capability_statement_digest,
            job.spec.execution_policy_statement_digest,
        }
    )
    if set(receipt.spec.material_digests) != expected_materials:
        reasons.append("runner_material_closure_mismatch")
    referenced_digests = expected_materials | {
        receipt.spec.stdout_digest,
        receipt.spec.stderr_digest,
        *receipt.spec.output_digests,
    }
    if not referenced_digests.issubset(available_digests):
        reasons.append("runner_artifact_digest_missing")
    if artifact_lengths.get(receipt.spec.stdout_digest) != receipt.spec.stdout_captured_bytes:
        reasons.append("runner_stdout_length_mismatch")
    if artifact_lengths.get(receipt.spec.stderr_digest) != receipt.spec.stderr_captured_bytes:
        reasons.append("runner_stderr_length_mismatch")
    output_artifacts = {
        receipt.spec.stdout_digest,
        receipt.spec.stderr_digest,
        *receipt.spec.output_digests,
    }
    if sum(artifact_lengths.get(item, 0) for item in output_artifacts) > (
        execution_policy.spec.maximum_output_bytes
    ):
        reasons.append("runner_output_policy_exceeded")
    if job.spec.timeout_seconds > execution_policy.spec.timeout_seconds:
        reasons.append("runner_timeout_policy_exceeded")
    if job.spec.stdout_limit > execution_policy.spec.stdout_limit:
        reasons.append("runner_stdout_policy_exceeded")
    if job.spec.stderr_limit > execution_policy.spec.stderr_limit:
        reasons.append("runner_stderr_policy_exceeded")
    if job.spec.network_policy != execution_policy.spec.network_policy:
        reasons.append("runner_network_policy_mismatch")
    if job.spec.filesystem_policy != execution_policy.spec.filesystem_policy:
        reasons.append("runner_filesystem_policy_mismatch")
    if receipt.spec.stdout_captured_bytes > job.spec.stdout_limit:
        reasons.append("runner_stdout_limit_exceeded")
    if receipt.spec.stderr_captured_bytes > job.spec.stderr_limit:
        reasons.append("runner_stderr_limit_exceeded")
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
    classified_outcome = "timeout" if receipt.spec.timeout else "failure"
    if not receipt.spec.timeout and receipt.spec.return_code is not None:
        classified_outcome = capability.spec.return_code_outcomes.get(
            str(receipt.spec.return_code), "failure"
        )
        if classified_outcome != "failure":
            if len(receipt.spec.output_digests) != 1 or output_document is None:
                reasons.append("runner_output_schema_document_missing")
                classified_outcome = "failure"
            elif not isinstance(output_document, dict):
                reasons.append("runner_output_schema_document_invalid")
                classified_outcome = "failure"
            else:
                try:
                    parsed_output = parse_document(output_document)
                except ValueError:
                    reasons.append("runner_output_schema_document_invalid")
                    classified_outcome = "failure"
                else:
                    if parsed_output.kind != capability.spec.output_schema_name:
                        reasons.append("runner_output_kind_mismatch")
                        classified_outcome = "failure"
        selector = capability.spec.output_selector
        if selector is not None and classified_outcome != "failure":
            if output_document is None:
                reasons.append("runner_output_selector_document_missing")
                classified_outcome = "failure"
            else:
                try:
                    selected = resolve_pointer(output_document, selector.json_pointer)
                except ValueError:
                    reasons.append("runner_output_selector_invalid")
                    classified_outcome = "failure"
                else:
                    if not isinstance(selected, str) or selected not in selector.values:
                        reasons.append("runner_output_selector_unrecognized")
                        classified_outcome = "failure"
                    else:
                        classified_outcome = selector.values[selected]
    if receipt.spec.claimed_outcome != classified_outcome:
        reasons.append("runner_outcome_forged")
    return RunnerConformance(
        accepted=not reasons,
        code="runner_receipt_conformant" if not reasons else "runner_receipt_rejected",
        reasons=sorted(set(reasons)),
    )
