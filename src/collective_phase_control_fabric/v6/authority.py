# SPDX-License-Identifier: Apache-2.0
"""Single fail-closed loader for an authoritative CPCF v0.6 generation."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from collective_phase_control_fabric.v6.canonical import (
    canonical_bytes,
    digest_bytes,
    loads_bounded,
)
from collective_phase_control_fabric.v6.models import (
    ArtifactRecord,
    AuditEvent,
    CoordinationEventDocument,
    CoordinationPlan,
    Document,
    DsseEnvelope,
    EvidenceAttestation,
    Lifecycle,
    MeasurementProtocol,
    PendingProjection,
    ProjectionApproval,
    ProjectionApprovalSpec,
    ProtocolAmendment,
    QuorumDecisionDocument,
    RunnerReceipt,
    SignedPayload,
    SignedStatement,
    SourceArtifactEnvelope,
    TrialResult,
    TrustedTimeReceipt,
    TrustPolicyDocument,
    WorkspaceGeneration,
)
from collective_phase_control_fabric.v6.projection import reconstruct_projection, resolve_pointer
from collective_phase_control_fabric.v6.registry import document_digest, parse_document
from collective_phase_control_fabric.v6.storage import (
    ObjectStore,
    validate_history,
    validate_ledger,
)
from collective_phase_control_fabric.v6.trust import (
    evaluate_quorum,
    inspect_genesis,
    verify_envelope,
)


@dataclass(frozen=True)
class AuthoritativeView:
    """Objects that remain authoritative after complete read-time recomputation."""

    valid: bool
    generation: WorkspaceGeneration
    objects: dict[str, Document]
    signed_subjects: dict[str, Document]
    statement_envelopes: dict[str, DsseEnvelope]
    subject_statements: dict[str, tuple[str, ...]]
    subject_principals: dict[str, frozenset[str]]
    statement_principals: dict[str, str]
    statement_roles: dict[str, str]
    quarantined: dict[str, tuple[str, ...]]
    reasons: tuple[str, ...]


def _signed_subject(statement: SignedStatement) -> tuple[SignedPayload, Document]:
    try:
        payload_bytes = base64.b64decode(statement.spec.envelope.payload, validate=True)
        payload = SignedPayload.model_validate_json(
            canonical_bytes(loads_bounded(payload_bytes)), strict=True
        )
        return payload, parse_document(payload.subject)
    except (TypeError, ValueError) as error:
        raise ValueError("signed_statement_payload_invalid") from error


def _lifecycle(document: Document) -> Lifecycle | None:
    value = getattr(getattr(document, "spec", None), "lifecycle", None)
    return value if isinstance(value, Lifecycle) else None


def _lifecycle_reasons(document: Document, evaluation_time: datetime) -> list[str]:
    lifecycle = _lifecycle(document)
    if lifecycle is None:
        return []
    reasons: list[str] = []
    if evaluation_time < lifecycle.valid_from:
        reasons.append("object_not_yet_valid")
    if evaluation_time > lifecycle.valid_until:
        reasons.append("object_expired")
    if lifecycle.withdrawn_at is not None and evaluation_time >= lifecycle.withdrawn_at:
        reasons.append("object_withdrawn")
    return reasons


def _claimed_signer(document: Document) -> tuple[str, str] | None:
    """Return the identity and role that a typed subject is allowed to claim."""

    if isinstance(document, CoordinationPlan):
        return document.spec.plan_principal_id, "coordination_plan"
    if isinstance(document, CoordinationEventDocument):
        return document.spec.actor_principal_id, "coordination_event"
    if isinstance(document, ArtifactRecord):
        return document.spec.producer_principal_id, "trial_artifact_producer"
    if isinstance(document, MeasurementProtocol):
        return document.spec.author_principal_id, "protocol_author"
    if isinstance(document, ProtocolAmendment):
        return document.spec.author_principal_id, "protocol_author"
    if isinstance(document, TrialResult):
        return document.spec.evaluator_principal_id, "evaluator"
    return None


def _required_quorum(document: Document) -> str | None:
    if isinstance(document, MeasurementProtocol):
        return "protocol_registration"
    if isinstance(document, ProtocolAmendment):
        return "protocol_amendment"
    if isinstance(document, TrialResult):
        return "acceleration_compatibility"
    return None


def _validate_source_envelope(
    envelope: SourceArtifactEnvelope,
    store: ObjectStore,
) -> list[str]:
    reasons: list[str] = []
    tenant_id = envelope.metadata.tenant_id
    if not store.exists(tenant_id, envelope.spec.raw_digest):
        return ["source_raw_artifact_missing"]
    raw = store.get(tenant_id, envelope.spec.raw_digest)
    if digest_bytes(raw) != envelope.spec.raw_digest:
        reasons.append("source_raw_artifact_digest_mismatch")
    if len(raw) != envelope.spec.byte_length:
        reasons.append("source_raw_artifact_length_mismatch")
    return reasons


def _validate_evidence_pointer(
    evidence: EvidenceAttestation,
    source_envelopes: list[SourceArtifactEnvelope],
    store: ObjectStore,
) -> list[str]:
    matching = [
        item
        for item in source_envelopes
        if item.spec.raw_digest == evidence.spec.raw_artifact_digest
        and item.metadata.tenant_id == evidence.metadata.tenant_id
        and item.metadata.workspace_id == evidence.metadata.workspace_id
    ]
    if len(matching) != 1:
        return ["evidence_source_envelope_not_unique"]
    raw = store.get(evidence.metadata.tenant_id, evidence.spec.raw_artifact_digest)
    try:
        selected = resolve_pointer(loads_bounded(raw), evidence.spec.json_pointer)
        projected = digest_bytes(canonical_bytes(selected))
    except (TypeError, ValueError):
        return ["evidence_source_pointer_invalid"]
    return [] if projected == evidence.spec.projected_digest else ["evidence_projection_mismatch"]


def load_authoritative_generation(
    generation: WorkspaceGeneration,
    store: ObjectStore,
    *,
    policy: TrustPolicyDocument,
    trusted_time: TrustedTimeReceipt,
    expected_root_spki_fingerprint: str,
    expected_genesis_envelope_fingerprint: str,
) -> AuthoritativeView:
    """Recompute ledger, signatures, time, source chains, lifecycle, and quorum.

    Stored validation flags are never consumed. Ordinary native objects become authoritative only
    through a verified ``signed-statement``. Audit events and quorum decisions are derived records
    and are independently recomputed before use.
    """

    reasons = validate_ledger(generation, store)
    tenant_id = generation.metadata.tenant_id
    workspace_id = generation.metadata.workspace_id
    entries = {item.object_digest: item for item in generation.spec.ledger}
    parsed: dict[str, Document] = {}
    quarantine: dict[str, set[str]] = {}

    def reject(digest: str, *codes: str) -> None:
        quarantine.setdefault(digest, set()).update(codes)

    for digest, entry in entries.items():
        if entry.authority_status != "active" or entry.object_kind == "raw-artifact":
            continue
        try:
            parsed_document = parse_document(loads_bounded(store.get(tenant_id, digest)))
        except (KeyError, TypeError, ValueError):
            reject(digest, "ledger_document_invalid")
            continue
        if document_digest(parsed_document) != digest:
            reject(digest, "ledger_document_digest_mismatch")
        if parsed_document.metadata.tenant_id != tenant_id:
            reject(digest, "ledger_document_tenant_mismatch")
        if parsed_document.metadata.workspace_id != workspace_id:
            reject(digest, "ledger_document_workspace_mismatch")
        if not quarantine.get(digest):
            parsed[digest] = parsed_document

    statement_envelopes: dict[str, DsseEnvelope] = {}
    signed_subjects: dict[str, Document] = {}
    subject_statements: dict[str, list[str]] = {}
    statement_principals: dict[str, str] = {}
    statement_roles: dict[str, str] = {}
    source_envelopes: list[SourceArtifactEnvelope] = []
    evaluation_time = trusted_time.spec.issued_at
    active_policy_digest = document_digest(policy)
    active_time_digest = document_digest(trusted_time)

    for digest, current_document in parsed.items():
        if not isinstance(current_document, SignedStatement):
            continue
        try:
            _, subject = _signed_subject(current_document)
        except ValueError as error:
            reject(digest, str(error))
            continue
        if isinstance(subject, TrustPolicyDocument) and subject.spec.policy_sequence == 0:
            verification = inspect_genesis(
                current_document.spec.envelope,
                expected_root_spki_fingerprint=expected_root_spki_fingerprint,
                expected_envelope_fingerprint=expected_genesis_envelope_fingerprint,
            )
        else:
            verification, _ = verify_envelope(
                current_document.spec.envelope, policy, trusted_time=trusted_time
            )
        statement_envelopes[digest] = current_document.spec.envelope
        if not verification.valid:
            reject(digest, *verification.reasons)
            continue
        if verification.principal_id is not None:
            statement_principals[digest] = verification.principal_id
        if verification.role is not None:
            statement_roles[digest] = verification.role
        subject_digest = document_digest(subject)
        lifecycle_reasons = _lifecycle_reasons(subject, evaluation_time)
        if lifecycle_reasons:
            reject(digest, *lifecycle_reasons)
            continue
        if subject_digest not in signed_subjects:
            signed_subjects[subject_digest] = subject
            subject_statements[subject_digest] = []
        subject_statements[subject_digest].append(digest)
        if isinstance(subject, SourceArtifactEnvelope) and not any(
            document_digest(item) == subject_digest for item in source_envelopes
        ):
            source_envelopes.append(subject)

    if active_policy_digest not in signed_subjects:
        reasons.append("active_trust_policy_not_signed_in_generation")
    if active_time_digest not in signed_subjects:
        reasons.append("active_trusted_time_not_signed_in_generation")

    for subject_digest, subject in signed_subjects.items():
        subject_reasons: list[str] = []
        claimed_signer = _claimed_signer(subject)
        if claimed_signer is not None:
            principal_id, required_role = claimed_signer
            matching = [
                statement_digest
                for statement_digest in subject_statements[subject_digest]
                if statement_digest not in quarantine
                and statement_principals.get(statement_digest) == principal_id
                and statement_roles.get(statement_digest) == required_role
            ]
            if not matching:
                subject_reasons.append("typed_subject_signer_binding_mismatch")
        if isinstance(subject, SourceArtifactEnvelope):
            subject_reasons.extend(_validate_source_envelope(subject, store))
        if isinstance(subject, EvidenceAttestation):
            subject_reasons.extend(_validate_evidence_pointer(subject, source_envelopes, store))
        if subject_reasons:
            for statement_digest in subject_statements[subject_digest]:
                reject(statement_digest, *subject_reasons)
            reasons.extend(f"{code}:{subject_digest}" for code in subject_reasons)

    for digest, current_document in parsed.items():
        if not isinstance(current_document, (SignedStatement, QuorumDecisionDocument, AuditEvent)):
            reject(digest, "unsigned_authoritative_object")

    derived: dict[str, Document] = {}
    for digest, current_document in parsed.items():
        if isinstance(current_document, QuorumDecisionDocument):
            envelopes: list[DsseEnvelope] = []
            missing = False
            for statement_digest in current_document.spec.statement_digests:
                envelope = statement_envelopes.get(statement_digest)
                if envelope is None or statement_digest in quarantine:
                    reject(digest, "quorum_statement_missing_or_invalid")
                    missing = True
                else:
                    envelopes.append(envelope)
            if missing:
                continue
            result = evaluate_quorum(
                current_document.spec.decision_type,
                current_document.spec.subject_digest,
                envelopes,
                policy,
                trusted_time=trusted_time,
            )
            if current_document.spec.decided_at > evaluation_time:
                reject(digest, "quorum_decision_from_future")
            if not result.valid:
                reject(digest, *result.reasons)
            if not quarantine.get(digest):
                derived[digest] = current_document

    for subject_digest, subject in signed_subjects.items():
        decision_type = _required_quorum(subject)
        if decision_type is None:
            continue
        decisions = [
            document
            for document in derived.values()
            if isinstance(document, QuorumDecisionDocument)
            and document.spec.decision_type == decision_type
            and document.spec.subject_digest == subject_digest
        ]
        if len(decisions) != 1:
            for statement_digest in subject_statements[subject_digest]:
                reject(statement_digest, f"{decision_type}_quorum_not_unique")
            reasons.append(f"{decision_type}_quorum_not_unique:{subject_digest}")

    promoted_projections: dict[str, Document] = {}
    for pending_digest, pending_document in signed_subjects.items():
        if not isinstance(pending_document, PendingProjection):
            continue
        if not pending_document.spec.changes_authoritative_state:
            continue
        pending_reasons: list[str] = []
        decisions = [
            item
            for item in derived.values()
            if isinstance(item, QuorumDecisionDocument)
            and item.spec.decision_type == "projection_promotion"
            and item.spec.subject_digest == pending_digest
        ]
        if len(decisions) != 1:
            pending_reasons.append("projection_promotion_quorum_not_unique")
        valid_statements = [
            digest for digest in subject_statements[pending_digest] if digest not in quarantine
        ]
        producer_statements = [
            digest
            for digest in valid_statements
            if statement_roles.get(digest) == "projection_authority"
            and statement_principals.get(digest) == pending_document.spec.producer_principal_id
        ]
        verifier_statements = [
            digest
            for digest in valid_statements
            if statement_roles.get(digest) == "projection_verifier"
            and statement_principals.get(digest) != pending_document.spec.producer_principal_id
        ]
        if len(producer_statements) != 1:
            pending_reasons.append("projection_producer_statement_not_unique")
        if len(verifier_statements) != 1:
            pending_reasons.append("projection_verifier_statement_not_unique")
        runner_receipt = signed_subjects.get(pending_document.spec.runner_receipt_digest)
        if not isinstance(runner_receipt, RunnerReceipt):
            pending_reasons.append("projection_runner_receipt_missing")
        elif not any(
            statement_principals.get(statement) == runner_receipt.spec.runner_principal_id
            and statement not in quarantine
            for statement in subject_statements[pending_document.spec.runner_receipt_digest]
        ):
            pending_reasons.append("runner_receipt_principal_binding_mismatch")
        source_envelope = signed_subjects.get(pending_document.spec.source_artifact_envelope_digest)
        if not isinstance(source_envelope, SourceArtifactEnvelope):
            pending_reasons.append("projection_source_envelope_missing")
        elif not any(
            statement not in quarantine
            for statement in subject_statements[
                pending_document.spec.source_artifact_envelope_digest
            ]
        ):
            pending_reasons.append("projection_source_envelope_not_authoritative")
        if not store.exists(tenant_id, pending_document.spec.raw_output_digest):
            pending_reasons.append("projection_raw_output_missing")
        if not pending_reasons:
            checked_runner = cast(RunnerReceipt, runner_receipt)
            checked_source = cast(SourceArtifactEnvelope, source_envelope)
            decision = decisions[0]
            verifier_principal = statement_principals[verifier_statements[0]]
            approval = ProjectionApproval(
                metadata=pending_document.metadata.model_copy(
                    update={
                        "object_id": f"approval:{pending_document.spec.projection_id}",
                        "created_at": decision.spec.decided_at,
                    }
                ),
                spec=ProjectionApprovalSpec(
                    projection_digest=pending_digest,
                    producer_principal_id=pending_document.spec.producer_principal_id,
                    verifier_principal_id=verifier_principal,
                    approved_at=decision.spec.decided_at,
                ),
            )
            projection, projected_document = reconstruct_projection(
                pending_document,
                approval,
                checked_runner,
                checked_source,
                store.get(tenant_id, pending_document.spec.raw_output_digest),
            )
            if not projection.promoted or projected_document is None:
                pending_reasons.extend(projection.reasons or ["projection_reconstruction_failed"])
            else:
                promoted_projections[document_digest(projected_document)] = projected_document
        if pending_reasons:
            for statement_digest in subject_statements[pending_digest]:
                reject(statement_digest, *pending_reasons)
            reasons.extend(f"{code}:{pending_digest}" for code in pending_reasons)

    events: list[AuditEvent] = []
    for item in parsed.values():
        if isinstance(item, AuditEvent) and document_digest(item) not in quarantine:
            events.append(item)
    events.sort(key=lambda item: item.spec.occurred_at)
    reasons.extend(validate_history(events, generation.spec.history_head_digest))
    reasons.extend(
        f"{code}:{digest}" for digest, codes in quarantine.items() for code in sorted(codes)
    )
    authoritative = {
        digest: subject
        for digest, subject in signed_subjects.items()
        if any(statement not in quarantine for statement in subject_statements[digest])
    }
    authoritative.update(derived)
    authoritative.update(promoted_projections)
    normalized_quarantine = {
        digest: tuple(sorted(codes)) for digest, codes in sorted(quarantine.items())
    }
    normalized_reasons = tuple(sorted(set(reasons)))
    active_statement_principals = {
        digest: principal
        for digest, principal in statement_principals.items()
        if digest not in quarantine
    }
    active_statement_roles = {
        digest: role for digest, role in statement_roles.items() if digest not in quarantine
    }
    normalized_subject_statements = {
        digest: tuple(sorted(statement_digests))
        for digest, statement_digests in subject_statements.items()
    }
    subject_principals = {
        digest: frozenset(
            active_statement_principals[statement]
            for statement in statement_digests
            if statement in active_statement_principals
        )
        for digest, statement_digests in normalized_subject_statements.items()
    }
    return AuthoritativeView(
        valid=not normalized_reasons,
        generation=generation,
        objects=authoritative,
        signed_subjects=signed_subjects,
        statement_envelopes=statement_envelopes,
        subject_statements=normalized_subject_statements,
        subject_principals=subject_principals,
        statement_principals=active_statement_principals,
        statement_roles=active_statement_roles,
        quarantined=normalized_quarantine,
        reasons=normalized_reasons,
    )
