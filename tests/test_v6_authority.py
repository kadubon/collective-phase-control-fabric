# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
from datetime import timedelta

import pytest

from collective_phase_control_fabric.v6.authority import (
    AuthoritativeView,
    _lifecycle_reasons,
    _signed_subject,
    _validate_evidence_pointer,
    _validate_source_envelope,
    load_authoritative_generation,
)
from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import (
    AuditEvent,
    AuditEventSpec,
    Document,
    EvidenceAttestation,
    EvidenceSpec,
    LedgerEntry,
    Lifecycle,
    Metadata,
    PendingProjection,
    PendingProjectionSpec,
    QuorumDecisionDocument,
    QuorumDecisionSpec,
    RunnerReceipt,
    RunnerReceiptSpec,
    SignedStatement,
    SignedStatementSpec,
    SourceArtifactEnvelope,
    SourceArtifactSpec,
    StateAttestation,
    StateSpec,
    WorkspaceGeneration,
    WorkspaceGenerationSpec,
)
from collective_phase_control_fabric.v6.registry import document_digest, schema_digest
from collective_phase_control_fabric.v6.storage import MemoryObjectStore, generation_digest
from collective_phase_control_fabric.v6.trust import (
    build_protected_header,
    public_key_fingerprint,
    sign_document,
)
from tests.v6_helpers import NOW, VALID_FROM, VALID_UNTIL, metadata, trust_fixture


def _statement(document: Document, role: str, key_name: str) -> SignedStatement:
    policy, trusted_time, keys = trust_fixture()
    principals = {
        "root": policy.spec.principals[0],
        "auditor": policy.spec.principals[1],
        "time": policy.spec.principals[2],
    }
    principal = principals[key_name]
    trusted_digest = None if document is policy else document_digest(trusted_time)
    protected = build_protected_header(
        document,
        principal=principal,
        role=role,
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=trusted_digest,
    )
    envelope = sign_document(
        document,
        private_key=keys[key_name],
        protected=protected,
    )
    return SignedStatement(
        metadata=metadata(f"statement-{role}-{document_digest(document)}"),
        spec=SignedStatementSpec(envelope=envelope),
    )


def _generation(
    store: MemoryObjectStore,
    documents: list[Document],
    *,
    include_unsigned_state: bool = False,
    raw_objects: tuple[bytes, ...] = (),
) -> WorkspaceGeneration:
    event = AuditEvent(
        metadata=metadata("event-authority"),
        spec=AuditEventSpec(
            event_id="event-authority",
            event_type="workspace_created",
            occurred_at=NOW,
        ),
    )
    entries: list[LedgerEntry] = []
    for document in [*documents, event]:
        raw = canonical_bytes(document.model_dump(mode="json", exclude_none=True))
        digest = store.put("tenant-a", raw)
        entries.append(
            LedgerEntry(
                object_digest=digest,
                object_kind=document.kind,
                authority_status="active",
            )
        )
    if include_unsigned_state:
        state = StateAttestation(
            metadata=metadata("unsigned-state"),
            spec=StateSpec(
                state_id="unsigned-state",
                available=True,
                lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
            ),
        )
        raw = canonical_bytes(state.model_dump(mode="json", exclude_none=True))
        entries.append(
            LedgerEntry(
                object_digest=store.put("tenant-a", raw),
                object_kind=state.kind,
                authority_status="active",
            )
        )
    for raw in raw_objects:
        entries.append(
            LedgerEntry(
                object_digest=store.put("tenant-a", raw),
                object_kind="raw-artifact",
                authority_status="active",
            )
        )
    event_digest = document_digest(event)
    placeholder = WorkspaceGeneration(
        metadata=metadata("generation-authority"),
        spec=WorkspaceGenerationSpec(
            generation_digest="sha256:" + "0" * 64,
            sequence=0,
            ledger=entries,
            history_head_digest=event_digest,
        ),
    )
    return placeholder.model_copy(
        update={
            "spec": placeholder.spec.model_copy(
                update={"generation_digest": generation_digest(placeholder)}
            )
        }
    )


def _load_documents(
    documents: list[Document],
    *,
    raw_objects: tuple[bytes, ...] = (),
) -> AuthoritativeView:
    policy, trusted_time, _ = trust_fixture()
    policy_statement = next(
        item
        for item in documents
        if isinstance(item, SignedStatement) and _signed_subject(item)[1] == policy
    )
    store = MemoryObjectStore()
    generation = _generation(store, documents, raw_objects=raw_objects)
    return load_authoritative_generation(
        generation,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=public_key_fingerprint(policy.spec.principals[0]),
        expected_genesis_envelope_fingerprint=digest_bytes(
            canonical_bytes(policy_statement.spec.envelope.model_dump(mode="json"))
        ),
    )


def _append_ledger_bytes(
    generation: WorkspaceGeneration,
    store: MemoryObjectStore,
    raw: bytes,
    kind: str,
    *,
    digest_override: str | None = None,
) -> WorkspaceGeneration:
    digest = digest_override or store.put("tenant-a", raw)
    if digest_override is not None:
        store.values[("tenant-a", digest_override)] = raw
    placeholder = generation.model_copy(
        update={
            "spec": generation.spec.model_copy(
                update={
                    "generation_digest": "sha256:" + "0" * 64,
                    "ledger": [
                        *generation.spec.ledger,
                        LedgerEntry(
                            object_digest=digest,
                            object_kind=kind,
                            authority_status="active",
                        ),
                    ],
                }
            )
        }
    )
    return placeholder.model_copy(
        update={
            "spec": placeholder.spec.model_copy(
                update={"generation_digest": generation_digest(placeholder)}
            )
        }
    )


def test_authoritative_loader_promotes_only_reverified_signed_subjects() -> None:
    policy, trusted_time, _ = trust_fixture()
    state = StateAttestation(
        metadata=metadata("state-authority"),
        spec=StateSpec(
            state_id="state-authority",
            available=True,
            food=True,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )
    policy_statement = _statement(policy, "workspace_root", "root")
    time_statement = _statement(trusted_time, "timestamp", "time")
    state_statement = _statement(state, "state_source", "root")
    store = MemoryObjectStore()
    generation = _generation(store, [policy_statement, time_statement, state_statement])
    root = policy.spec.principals[0]
    view = load_authoritative_generation(
        generation,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=public_key_fingerprint(root),
        expected_genesis_envelope_fingerprint=digest_bytes(
            canonical_bytes(policy_statement.spec.envelope.model_dump(mode="json"))
        ),
    )
    assert view.valid
    assert document_digest(state) in view.objects
    assert document_digest(policy) in view.objects
    assert document_digest(trusted_time) in view.objects
    assert not view.quarantined


def test_authoritative_loader_rejects_unsigned_native_authority() -> None:
    policy, trusted_time, _ = trust_fixture()
    policy_statement = _statement(policy, "workspace_root", "root")
    time_statement = _statement(trusted_time, "timestamp", "time")
    store = MemoryObjectStore()
    generation = _generation(
        store,
        [policy_statement, time_statement],
        include_unsigned_state=True,
    )
    root = policy.spec.principals[0]
    view = load_authoritative_generation(
        generation,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=public_key_fingerprint(root),
        expected_genesis_envelope_fingerprint=digest_bytes(
            canonical_bytes(policy_statement.spec.envelope.model_dump(mode="json"))
        ),
    )
    assert not view.valid
    assert any("unsigned_authoritative_object" in reason for reason in view.reasons)
    assert all(item.kind != "state-attestation" for item in view.objects.values())


def test_authoritative_loader_counts_role_separated_signatures_over_identical_subject() -> None:
    policy, trusted_time, _ = trust_fixture()
    state = StateAttestation(
        metadata=metadata("state-quorum"),
        spec=StateSpec(
            state_id="state-quorum",
            available=True,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )
    policy_statement = _statement(policy, "workspace_root", "root")
    time_statement = _statement(trusted_time, "timestamp", "time")
    producer = _statement(state, "projection_authority", "root")
    verifier = _statement(state, "projection_verifier", "auditor")
    decision = QuorumDecisionDocument(
        metadata=metadata("decision-projection-quorum"),
        spec=QuorumDecisionSpec(
            decision_type="projection_promotion",
            subject_digest=document_digest(state),
            statement_digests=[document_digest(producer), document_digest(verifier)],
            decided_at=NOW,
        ),
    )
    store = MemoryObjectStore()
    generation = _generation(
        store,
        [policy_statement, time_statement, producer, verifier, decision],
    )
    root = policy.spec.principals[0]
    view = load_authoritative_generation(
        generation,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=public_key_fingerprint(root),
        expected_genesis_envelope_fingerprint=digest_bytes(
            canonical_bytes(policy_statement.spec.envelope.model_dump(mode="json"))
        ),
    )
    assert view.valid
    assert document_digest(state) in view.objects
    assert document_digest(decision) in view.objects


def test_authoritative_loader_reconstructs_projection_only_after_quorum() -> None:
    policy, trusted_time, _ = trust_fixture()
    projected = StateAttestation(
        metadata=metadata("projected-authority-state"),
        spec=StateSpec(
            state_id="projected-authority-state",
            available=True,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )
    raw = canonical_bytes({"projected": projected.model_dump(mode="json", exclude_none=True)})
    raw_digest = digest_bytes(raw)
    source = SourceArtifactEnvelope(
        metadata=metadata("source-projection"),
        spec=SourceArtifactSpec(
            raw_digest=raw_digest,
            byte_length=len(raw),
            media_type="application/json",
            source_system="fixture-source",
            source_uri="urn:cpcf:test:projection",
            acquired_at=NOW,
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
        ),
    )
    receipt = RunnerReceipt(
        metadata=metadata("runner-receipt-projection"),
        spec=RunnerReceiptSpec(
            job_digest="sha256:" + "1" * 64,
            job_id="job-projection",
            attempt=1,
            lease_id="lease-projection",
            runner_principal_id="root-principal",
            image_digest="sha256:" + "2" * 64,
            stdout_digest=raw_digest,
            stderr_digest="sha256:" + "3" * 64,
            stdout_captured_bytes=len(raw),
            stderr_captured_bytes=0,
            stdout_discarded_bytes=0,
            stderr_discarded_bytes=0,
            return_code=0,
            timeout=False,
            claimed_outcome="success",
            cleanup_complete=True,
            output_digests=[raw_digest],
            started_at=NOW,
            completed_at=NOW,
        ),
    )
    pending = PendingProjection(
        metadata=metadata("pending-projection-authority"),
        spec=PendingProjectionSpec(
            projection_id="projection-authority",
            runner_receipt_digest=document_digest(receipt),
            source_artifact_envelope_digest=document_digest(source),
            producer_principal_id="root-principal",
            raw_output_digest=raw_digest,
            json_pointer="/projected",
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
            projected_digest=document_digest(projected),
            changes_authoritative_state=True,
        ),
    )
    policy_statement = _statement(policy, "workspace_root", "root")
    time_statement = _statement(trusted_time, "timestamp", "time")
    source_statement = _statement(source, "state_source", "root")
    receipt_statement = _statement(receipt, "state_source", "root")
    producer = _statement(pending, "projection_authority", "root")
    verifier = _statement(pending, "projection_verifier", "auditor")
    decision = QuorumDecisionDocument(
        metadata=metadata("decision-projection-authority"),
        spec=QuorumDecisionSpec(
            decision_type="projection_promotion",
            subject_digest=document_digest(pending),
            statement_digests=[document_digest(producer), document_digest(verifier)],
            decided_at=NOW,
        ),
    )
    store = MemoryObjectStore()
    generation = _generation(
        store,
        [
            policy_statement,
            time_statement,
            source_statement,
            receipt_statement,
            producer,
            verifier,
            decision,
        ],
        raw_objects=(raw,),
    )
    root = policy.spec.principals[0]
    view = load_authoritative_generation(
        generation,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=public_key_fingerprint(root),
        expected_genesis_envelope_fingerprint=digest_bytes(
            canonical_bytes(policy_statement.spec.envelope.model_dump(mode="json"))
        ),
    )
    assert view.valid
    assert view.objects[document_digest(projected)] == projected


def test_authoritative_source_pointer_lifecycle_and_payload_failures_are_closed() -> None:
    policy, _, _ = trust_fixture()
    invalid_statement = _statement(policy, "workspace_root", "root").model_copy(
        update={
            "spec": SignedStatementSpec(
                envelope=_statement(policy, "workspace_root", "root").spec.envelope.model_copy(
                    update={"payload": "!!!!"}
                )
            )
        }
    )
    with pytest.raises(ValueError, match="signed_statement_payload_invalid"):
        _signed_subject(invalid_statement)

    future = StateAttestation(
        metadata=metadata("state-future"),
        spec=StateSpec(
            state_id="state-future",
            available=True,
            lifecycle=Lifecycle(
                valid_from=NOW + timedelta(hours=1),
                valid_until=NOW + timedelta(hours=2),
            ),
        ),
    )
    expired = future.model_copy(
        update={
            "spec": future.spec.model_copy(
                update={
                    "lifecycle": Lifecycle(
                        valid_from=NOW - timedelta(hours=2),
                        valid_until=NOW - timedelta(hours=1),
                        withdrawn_at=NOW - timedelta(hours=1),
                    )
                }
            )
        }
    )
    assert _lifecycle_reasons(future, NOW) == ["object_not_yet_valid"]
    assert _lifecycle_reasons(expired, NOW) == ["object_expired", "object_withdrawn"]

    raw = canonical_bytes({"evidence": {"value": 1}})
    store = MemoryObjectStore()
    raw_digest = store.put("tenant-a", raw)
    source = SourceArtifactEnvelope(
        metadata=metadata("source-evidence"),
        spec=SourceArtifactSpec(
            raw_digest=raw_digest,
            byte_length=len(raw),
            media_type="application/json",
            source_system="fixture-source",
            source_uri="urn:cpcf:test:evidence",
            acquired_at=NOW,
            expected_schema_name="evidence-attestation",
            expected_schema_digest=schema_digest("evidence-attestation"),
        ),
    )
    evidence = EvidenceAttestation(
        metadata=metadata("evidence-pointer"),
        spec=EvidenceSpec(
            evidence_id="evidence-pointer",
            evidence_type="test",
            raw_artifact_digest=raw_digest,
            json_pointer="/evidence",
            projected_digest=digest_bytes(canonical_bytes({"value": 1})),
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )
    assert not _validate_source_envelope(source, store)
    assert not _validate_evidence_pointer(evidence, [source], store)
    assert _validate_evidence_pointer(evidence, [], store) == [
        "evidence_source_envelope_not_unique"
    ]
    wrong_pointer = evidence.model_copy(
        update={"spec": evidence.spec.model_copy(update={"json_pointer": "/missing"})}
    )
    assert _validate_evidence_pointer(wrong_pointer, [source], store) == [
        "evidence_source_pointer_invalid"
    ]
    wrong_projection = evidence.model_copy(
        update={"spec": evidence.spec.model_copy(update={"projected_digest": "sha256:" + "0" * 64})}
    )
    assert _validate_evidence_pointer(wrong_projection, [source], store) == [
        "evidence_projection_mismatch"
    ]
    wrong_length = source.model_copy(
        update={"spec": source.spec.model_copy(update={"byte_length": len(raw) + 1})}
    )
    assert _validate_source_envelope(wrong_length, store) == ["source_raw_artifact_length_mismatch"]
    missing = source.model_copy(
        update={"spec": source.spec.model_copy(update={"raw_digest": "sha256:" + "0" * 64})}
    )
    assert _validate_source_envelope(missing, store) == ["source_raw_artifact_missing"]
    store.values[("tenant-a", raw_digest)] = b"corrupt"
    corrupt = _validate_source_envelope(source, store)
    assert "source_raw_artifact_digest_mismatch" in corrupt
    assert "source_raw_artifact_length_mismatch" in corrupt


def _projection_case(
    *,
    include_decision: bool = True,
    include_producer: bool = True,
    include_verifier: bool = True,
    include_runner: bool = True,
    include_source: bool = True,
    include_raw: bool = True,
    source_length_delta: int = 0,
    runner_principal_id: str = "root-principal",
    projected_digest: str | None = None,
    changes_authoritative_state: bool = True,
) -> tuple[AuthoritativeView, StateAttestation]:
    policy, trusted_time, _ = trust_fixture()
    projected = StateAttestation(
        metadata=metadata("projected-negative-state"),
        spec=StateSpec(
            state_id="projected-negative-state",
            available=True,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )
    raw = canonical_bytes({"projected": projected.model_dump(mode="json", exclude_none=True)})
    raw_digest = digest_bytes(raw)
    source = SourceArtifactEnvelope(
        metadata=metadata("source-negative-projection"),
        spec=SourceArtifactSpec(
            raw_digest=raw_digest,
            byte_length=len(raw) + source_length_delta,
            media_type="application/json",
            source_system="fixture-source",
            source_uri="urn:cpcf:test:negative-projection",
            acquired_at=NOW,
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
        ),
    )
    receipt = RunnerReceipt(
        metadata=metadata("runner-receipt-negative"),
        spec=RunnerReceiptSpec(
            job_digest="sha256:" + "4" * 64,
            job_id="job-negative",
            attempt=1,
            lease_id="lease-negative",
            runner_principal_id=runner_principal_id,
            image_digest="sha256:" + "5" * 64,
            stdout_digest=raw_digest,
            stderr_digest="sha256:" + "6" * 64,
            stdout_captured_bytes=len(raw),
            stderr_captured_bytes=0,
            stdout_discarded_bytes=0,
            stderr_discarded_bytes=0,
            return_code=0,
            timeout=False,
            claimed_outcome="success",
            cleanup_complete=True,
            output_digests=[raw_digest],
            started_at=NOW,
            completed_at=NOW,
        ),
    )
    pending = PendingProjection(
        metadata=metadata("pending-negative-projection"),
        spec=PendingProjectionSpec(
            projection_id="negative-projection",
            runner_receipt_digest=document_digest(receipt),
            source_artifact_envelope_digest=document_digest(source),
            producer_principal_id="root-principal",
            raw_output_digest=raw_digest,
            json_pointer="/projected",
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
            projected_digest=projected_digest or document_digest(projected),
            changes_authoritative_state=changes_authoritative_state,
        ),
    )
    policy_statement = _statement(policy, "workspace_root", "root")
    documents: list[Document] = [
        policy_statement,
        _statement(trusted_time, "timestamp", "time"),
    ]
    if include_source:
        documents.append(_statement(source, "state_source", "root"))
    if include_runner:
        documents.append(_statement(receipt, "state_source", "root"))
    producer = _statement(pending, "projection_authority", "root")
    verifier = _statement(pending, "projection_verifier", "auditor")
    if include_producer:
        documents.append(producer)
    if include_verifier:
        documents.append(verifier)
    if include_decision:
        documents.append(
            QuorumDecisionDocument(
                metadata=metadata("decision-negative-projection"),
                spec=QuorumDecisionSpec(
                    decision_type="projection_promotion",
                    subject_digest=document_digest(pending),
                    statement_digests=[document_digest(producer), document_digest(verifier)],
                    decided_at=NOW,
                ),
            )
        )
    store = MemoryObjectStore()
    generation = _generation(
        store,
        documents,
        raw_objects=(raw,) if include_raw else (),
    )
    view = load_authoritative_generation(
        generation,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=public_key_fingerprint(policy.spec.principals[0]),
        expected_genesis_envelope_fingerprint=digest_bytes(
            canonical_bytes(policy_statement.spec.envelope.model_dump(mode="json"))
        ),
    )
    return view, projected


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        ({"include_decision": False}, "projection_promotion_quorum_not_unique"),
        (
            {"include_decision": False, "include_verifier": False},
            "projection_verifier_statement_not_unique",
        ),
        (
            {"include_decision": False, "include_producer": False},
            "projection_producer_statement_not_unique",
        ),
        ({"include_runner": False}, "projection_runner_receipt_missing"),
        (
            {"runner_principal_id": "auditor-principal"},
            "runner_receipt_principal_binding_mismatch",
        ),
        ({"include_source": False}, "projection_source_envelope_missing"),
        (
            {"source_length_delta": 1},
            "projection_source_envelope_not_authoritative",
        ),
        ({"include_raw": False}, "projection_raw_output_missing"),
        ({"projected_digest": "sha256:" + "0" * 64}, "projected_digest_mismatch"),
    ],
)
def test_authoritative_projection_failure_matrix(options: dict[str, object], reason: str) -> None:
    view, projected = _projection_case(**options)  # type: ignore[arg-type]
    assert not view.valid
    assert any(reason in item for item in view.reasons)
    assert document_digest(projected) not in view.objects


def test_non_authoritative_projection_remains_pending_without_quorum() -> None:
    view, projected = _projection_case(
        include_decision=False,
        changes_authoritative_state=False,
    )
    assert view.valid
    assert document_digest(projected) not in view.objects


def test_authoritative_loader_rejects_malformed_scope_signature_and_lifecycle() -> None:
    policy, trusted_time, _ = trust_fixture()
    policy_statement = _statement(policy, "workspace_root", "root")
    time_statement = _statement(trusted_time, "timestamp", "time")
    base_documents: list[Document] = [policy_statement, time_statement]
    store = MemoryObjectStore()
    base = _generation(store, base_documents)

    malformed = _append_ledger_bytes(base, store, b"not-json", "signed-statement")
    malformed_view = load_authoritative_generation(
        malformed,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=public_key_fingerprint(policy.spec.principals[0]),
        expected_genesis_envelope_fingerprint=digest_bytes(
            canonical_bytes(policy_statement.spec.envelope.model_dump(mode="json"))
        ),
    )
    assert any("ledger_document_invalid" in item for item in malformed_view.reasons)

    foreign = StateAttestation(
        metadata=Metadata(
            tenant_id="tenant-b",
            workspace_id="workspace-b",
            object_id="foreign-state",
            created_at=NOW,
        ),
        spec=StateSpec(
            state_id="foreign-state",
            available=True,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )
    foreign_raw = canonical_bytes(foreign.model_dump(mode="json", exclude_none=True))
    foreign_generation = _append_ledger_bytes(
        base,
        store,
        foreign_raw,
        foreign.kind,
    )
    foreign_view = load_authoritative_generation(
        foreign_generation,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=public_key_fingerprint(policy.spec.principals[0]),
        expected_genesis_envelope_fingerprint=digest_bytes(
            canonical_bytes(policy_statement.spec.envelope.model_dump(mode="json"))
        ),
    )
    assert any("ledger_document_tenant_mismatch" in item for item in foreign_view.reasons)
    assert any("ledger_document_workspace_mismatch" in item for item in foreign_view.reasons)

    fake_digest = "sha256:" + "f" * 64
    mismatched_generation = _append_ledger_bytes(
        base,
        store,
        canonical_bytes(policy_statement.model_dump(mode="json", exclude_none=True)),
        policy_statement.kind,
        digest_override=fake_digest,
    )
    mismatched_view = load_authoritative_generation(
        mismatched_generation,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=public_key_fingerprint(policy.spec.principals[0]),
        expected_genesis_envelope_fingerprint=digest_bytes(
            canonical_bytes(policy_statement.spec.envelope.model_dump(mode="json"))
        ),
    )
    assert any("ledger_document_digest_mismatch" in item for item in mismatched_view.reasons)

    expired = StateAttestation(
        metadata=metadata("expired-signed-state"),
        spec=StateSpec(
            state_id="expired-signed-state",
            available=True,
            lifecycle=Lifecycle(
                valid_from=NOW - timedelta(hours=2),
                valid_until=NOW - timedelta(hours=1),
            ),
        ),
    )
    expired_view = _load_documents(
        [policy_statement, time_statement, _statement(expired, "state_source", "root")]
    )
    assert any("object_expired" in item for item in expired_view.reasons)

    signed = _statement(
        StateAttestation(
            metadata=metadata("tampered-signed-state"),
            spec=StateSpec(
                state_id="tampered-signed-state",
                available=True,
                lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
            ),
        ),
        "state_source",
        "root",
    )
    bad_signature = signed.model_copy(
        update={
            "spec": SignedStatementSpec(
                envelope=signed.spec.envelope.model_copy(
                    update={
                        "signatures": [
                            signed.spec.envelope.signatures[0].model_copy(
                                update={"sig": base64.b64encode(b"\x00" * 64).decode("ascii")}
                            )
                        ]
                    }
                )
            )
        }
    )
    signature_view = _load_documents([policy_statement, time_statement, bad_signature])
    assert any("signature_invalid" in item for item in signature_view.reasons)


def test_authoritative_loader_validates_evidence_and_quorum_failure_modes() -> None:
    policy, trusted_time, _ = trust_fixture()
    policy_statement = _statement(policy, "workspace_root", "root")
    time_statement = _statement(trusted_time, "timestamp", "time")
    raw = canonical_bytes({"evidence": {"value": 1}})
    raw_digest = digest_bytes(raw)
    source = SourceArtifactEnvelope(
        metadata=metadata("loader-source-evidence"),
        spec=SourceArtifactSpec(
            raw_digest=raw_digest,
            byte_length=len(raw),
            media_type="application/json",
            source_system="fixture-source",
            source_uri="urn:cpcf:test:loader-evidence",
            acquired_at=NOW,
            expected_schema_name="evidence-attestation",
            expected_schema_digest=schema_digest("evidence-attestation"),
        ),
    )
    evidence = EvidenceAttestation(
        metadata=metadata("loader-evidence"),
        spec=EvidenceSpec(
            evidence_id="loader-evidence",
            evidence_type="test",
            raw_artifact_digest=raw_digest,
            json_pointer="/evidence",
            projected_digest=digest_bytes(canonical_bytes({"value": 1})),
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )
    evidence_view = _load_documents(
        [
            policy_statement,
            time_statement,
            _statement(source, "state_source", "root"),
            _statement(evidence, "state_source", "root"),
        ],
        raw_objects=(raw,),
    )
    assert evidence_view.valid
    assert document_digest(evidence) in evidence_view.objects

    missing_statements = QuorumDecisionDocument(
        metadata=metadata("missing-quorum-statements"),
        spec=QuorumDecisionSpec(
            decision_type="projection_promotion",
            subject_digest="sha256:" + "1" * 64,
            statement_digests=["sha256:" + "2" * 64, "sha256:" + "3" * 64],
            decided_at=NOW,
        ),
    )
    missing_view = _load_documents([policy_statement, time_statement, missing_statements])
    assert any("quorum_statement_missing_or_invalid" in item for item in missing_view.reasons)

    state = StateAttestation(
        metadata=metadata("quorum-state-failures"),
        spec=StateSpec(
            state_id="quorum-state-failures",
            available=True,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )
    producer = _statement(state, "projection_authority", "root")
    verifier = _statement(state, "projection_verifier", "auditor")
    future = QuorumDecisionDocument(
        metadata=metadata("future-quorum-decision"),
        spec=QuorumDecisionSpec(
            decision_type="projection_promotion",
            subject_digest=document_digest(state),
            statement_digests=[document_digest(producer), document_digest(verifier)],
            decided_at=NOW + timedelta(hours=1),
        ),
    )
    future_view = _load_documents([policy_statement, time_statement, producer, verifier, future])
    assert any("quorum_decision_from_future" in item for item in future_view.reasons)

    unknown = future.model_copy(
        update={
            "metadata": metadata("unknown-quorum-decision"),
            "spec": future.spec.model_copy(
                update={"decision_type": "unknown_decision", "decided_at": NOW}
            ),
        }
    )
    unknown_view = _load_documents([policy_statement, time_statement, producer, verifier, unknown])
    assert any("unknown_decision" in item for item in unknown_view.reasons)

    empty_view = _load_documents([policy_statement])
    assert "active_trusted_time_not_signed_in_generation" in empty_view.reasons
