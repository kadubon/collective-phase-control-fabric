# SPDX-License-Identifier: Apache-2.0
"""Receipt-backed projection reconstruction and independent promotion."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from collective_phase_control_fabric.v6.canonical import digest_bytes, loads_bounded
from collective_phase_control_fabric.v6.models import (
    Document,
    PendingProjection,
    ProjectionApproval,
    RunnerReceipt,
    SourceArtifactEnvelope,
    StrictModel,
)
from collective_phase_control_fabric.v6.registry import (
    document_digest,
    parse_document,
    schema_digest,
)


class ProjectionResult(StrictModel):
    promoted: bool
    code: str
    reasons: list[str] = Field(default_factory=list)
    projected_document_digest: str | None = None


def resolve_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("json_pointer_must_start_with_slash")
    current = value
    for raw_segment in pointer[1:].split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if segment not in current:
                raise ValueError("json_pointer_member_missing")
            current = current[segment]
        elif isinstance(current, list):
            if segment == "-" or not segment.isdigit():
                raise ValueError("json_pointer_array_index_invalid")
            index = int(segment)
            if index >= len(current):
                raise ValueError("json_pointer_array_index_missing")
            current = current[index]
        else:
            raise ValueError("json_pointer_traverses_scalar")
    return current


def reconstruct_projection(
    pending: PendingProjection,
    approval: ProjectionApproval,
    runner_receipt: RunnerReceipt,
    source_envelope: SourceArtifactEnvelope,
    raw_output: bytes,
) -> tuple[ProjectionResult, Document | None]:
    reasons: list[str] = []
    pending_digest = document_digest(pending)
    if approval.spec.projection_digest != pending_digest:
        reasons.append("projection_approval_binding_mismatch")
    if approval.spec.producer_principal_id != pending.spec.producer_principal_id:
        reasons.append("projection_producer_binding_mismatch")
    if approval.spec.verifier_principal_id == pending.spec.producer_principal_id:
        reasons.append("projection_independent_verifier_required")
    if pending.spec.runner_receipt_digest != document_digest(runner_receipt):
        reasons.append("projection_runner_receipt_binding_mismatch")
    if pending.spec.source_artifact_envelope_digest != document_digest(source_envelope):
        reasons.append("projection_source_envelope_binding_mismatch")
    raw_digest = digest_bytes(raw_output)
    if raw_digest != pending.spec.raw_output_digest:
        reasons.append("projection_raw_output_digest_mismatch")
    if raw_digest != source_envelope.spec.raw_digest:
        reasons.append("source_envelope_raw_digest_mismatch")
    if len(raw_output) != source_envelope.spec.byte_length:
        reasons.append("source_envelope_byte_length_mismatch")
    if pending.spec.expected_schema_digest != schema_digest(pending.spec.expected_schema_name):
        reasons.append("projection_expected_schema_digest_mismatch")
    if source_envelope.spec.expected_schema_name != pending.spec.expected_schema_name:
        reasons.append("projection_source_schema_name_mismatch")
    if source_envelope.spec.expected_schema_digest != pending.spec.expected_schema_digest:
        reasons.append("projection_source_schema_digest_mismatch")
    projected: Document | None = None
    if not reasons:
        try:
            raw_value = loads_bounded(raw_output)
            selected = resolve_pointer(raw_value, pending.spec.json_pointer)
            if not isinstance(selected, dict):
                raise ValueError("projected_value_must_be_object")
            projected = parse_document(selected)
            if projected.kind != pending.spec.expected_schema_name:
                reasons.append("projected_kind_mismatch")
            if document_digest(projected) != pending.spec.projected_digest:
                reasons.append("projected_digest_mismatch")
        except ValueError as error:
            reasons.append(str(error))
    reasons = sorted(set(reasons))
    return (
        ProjectionResult(
            promoted=not reasons,
            code="projection_promoted" if not reasons else "projection_not_promoted",
            reasons=reasons,
            projected_document_digest=document_digest(projected) if projected is not None else None,
        ),
        projected if not reasons else None,
    )
