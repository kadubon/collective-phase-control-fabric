# SPDX-License-Identifier: Apache-2.0
"""Adversarial branch tests for v0.6 security and evidence boundaries."""

from __future__ import annotations

import base64
import io
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from collective_phase_control_fabric.v6.canonical import (
    InputLimitError,
    _scan_nesting,
    _unique_object,
    _validate_tree,
    canonical_bytes,
    digest_bytes,
    digest_document,
    loads_bounded,
    read_limited,
    read_path_limited,
)
from collective_phase_control_fabric.v6.coordination import validate_coordination
from collective_phase_control_fabric.v6.kms import (
    AwsKmsSigner,
    AzureKeyVaultSigner,
    GoogleKmsSigner,
    Pkcs11Signer,
    encode_signature,
    normalize_p256_der,
)
from collective_phase_control_fabric.v6.models import (
    CoordinationEventDocument,
    CoordinationEventSpec,
    CoordinationPlan,
    CoordinationPlanSpec,
    DsseEnvelope,
    PendingProjection,
    PendingProjectionSpec,
    ProjectionApproval,
    ProjectionApprovalSpec,
    ProtocolAmendment,
    ProtocolAmendmentSpec,
    QuorumRule,
    SourceArtifactEnvelope,
    SourceArtifactSpec,
    TrustPolicySpec,
)
from collective_phase_control_fabric.v6.projection import reconstruct_projection, resolve_pointer
from collective_phase_control_fabric.v6.registry import (
    DocumentValidationError,
    _close_schema,
    document_digest,
    parse_document,
    parse_document_bytes,
    schema_digest,
    schema_for_kind,
    write_schemas,
)
from collective_phase_control_fabric.v6.runner import validate_receipt
from collective_phase_control_fabric.v6.storage import (
    ConcurrentGenerationError,
    MemoryGenerationRepository,
    MemoryObjectStore,
    WorkspaceState,
    assert_safe_legacy_root,
    quarantine_legacy_entries,
    validate_history,
    validate_ledger,
)
from collective_phase_control_fabric.v6.trials import assess_trial
from collective_phase_control_fabric.v6.trust import (
    P256_ORDER,
    _time_status,
    _verify_signature,
    build_protected_header,
    evaluate_quorum,
    inspect_genesis,
    public_key_fingerprint,
    sign_document,
    validate_policy,
    verify_envelope,
)
from tests.test_v6_service_boundaries import runner_fixture, state_document, trial_fixture
from tests.v6_helpers import NOW, VALID_FROM, metadata, trust_fixture


def valid_projection_fixture() -> tuple[
    PendingProjection,
    ProjectionApproval,
    object,
    SourceArtifactEnvelope,
    bytes,
]:
    _, _, receipt = runner_fixture()
    projected = state_document()
    raw = canonical_bytes({"projected": projected.model_dump(mode="json", exclude_none=True)})
    raw_digest = digest_bytes(raw)
    source = SourceArtifactEnvelope(
        metadata=metadata("source-fixture"),
        spec=SourceArtifactSpec(
            raw_digest=raw_digest,
            byte_length=len(raw),
            media_type="application/json",
            source_system="runner",
            source_uri="urn:test:projection",
            acquired_at=NOW,
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
        ),
    )
    pending = PendingProjection(
        metadata=metadata("pending-fixture"),
        spec=PendingProjectionSpec(
            projection_id="projection-fixture",
            runner_receipt_digest=document_digest(receipt),
            source_artifact_envelope_digest=document_digest(source),
            producer_principal_id="producer",
            raw_output_digest=raw_digest,
            json_pointer="/projected",
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
            projected_digest=document_digest(projected),
            changes_authoritative_state=True,
        ),
    )
    approval = ProjectionApproval(
        metadata=metadata("approval-fixture"),
        spec=ProjectionApprovalSpec(
            projection_digest=document_digest(pending),
            producer_principal_id="producer",
            verifier_principal_id="verifier",
            approved_at=NOW,
        ),
    )
    return pending, approval, receipt, source, raw


def test_bounded_input_parser_covers_lexical_and_tree_limits(tmp_path: Path) -> None:
    assert read_limited(io.BytesIO(b"abc"), 3) == b"abc"
    with pytest.raises(InputLimitError, match="raw_input_too_large"):
        read_limited(io.BytesIO(b"abcd"), 3)
    source = tmp_path / "input.json"
    source.write_bytes(b"{}")
    assert read_path_limited(source, 2) == b"{}"

    for value in (b"}", b'"unterminated', b'{"x": [1}'):
        with pytest.raises(ValueError, match="malformed_json_structure"):
            loads_bounded(value)
    with pytest.raises(ValueError, match="json_not_utf8"):
        loads_bounded(b'{"x":"\xff"}')
    with pytest.raises(ValueError, match="top_level_json_object_required"):
        loads_bounded(b"[]")
    with pytest.raises(InputLimitError, match="json_integer_outside_i_json_range"):
        loads_bounded(b'{"x":9007199254740992}')
    with pytest.raises(InputLimitError, match="json_array_item_limit"):
        loads_bounded(canonical_bytes({"x": [None] * 100_001}))
    with pytest.raises(InputLimitError, match="json_object_member_limit"):
        loads_bounded(canonical_bytes({str(index): None for index in range(10_001)}))


def test_policy_validation_reports_every_identity_and_sequence_defect() -> None:
    policy, _, _ = trust_fixture()
    root = policy.spec.principals[0]
    duplicate = root.model_copy(
        update={
            "valid_until": root.valid_from,
            "compromised_at": NOW,
            "revoked_at": None,
        }
    )
    malformed = root.model_copy(update={"public_key_base64": "!" * 40})
    spec = TrustPolicySpec.model_construct(
        policy_sequence=1,
        prior_policy_digest=None,
        root_key_id="missing-root",
        principals=[root, duplicate, malformed],
        quorum_rules=[
            QuorumRule(decision_type="trust_update", required_roles=["one", "two"]),
            QuorumRule(decision_type="trust_update", required_roles=["one", "two"]),
        ],
    )
    broken = policy.model_copy(update={"spec": spec})
    reasons = validate_policy(broken)
    assert {
        "duplicate_principal_id",
        "duplicate_key_id",
        "public_key_base64_invalid",
        "principal_validity_interval_invalid",
        "compromise_requires_revocation",
        "public_key_reused_by_multiple_principals",
        "exactly_one_matching_workspace_root_required",
        "duplicate_quorum_decision_type",
        "non_genesis_policy_requires_predecessor",
    }.issubset(reasons)

    invalid_genesis = policy.model_copy(
        update={
            "spec": policy.spec.model_copy(update={"prior_policy_digest": "sha256:" + "1" * 64})
        }
    )
    assert "genesis_policy_cannot_have_predecessor" in validate_policy(invalid_genesis)


def _signed_state(
    *, role: str = "state_source", source_system: str = "fixture-source"
) -> tuple[object, object, object, object]:
    policy, trusted_time, keys = trust_fixture()
    document = state_document()
    header = build_protected_header(
        document,
        principal=policy.spec.principals[0],
        role=role,
        source_system=source_system,
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=document_digest(trusted_time),
    )
    return (
        policy,
        trusted_time,
        document,
        sign_document(document, private_key=keys["root"], protected=header),
    )


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("schema_name", "evidence-attestation", "schema_kind_mismatch"),
        ("schema_digest", "sha256:" + "0" * 64, "schema_digest_mismatch"),
        ("payload_digest", "sha256:" + "0" * 64, "payload_digest_mismatch"),
        ("tenant_id", "other-tenant", "tenant_binding_mismatch"),
        ("workspace_id", "other-workspace", "workspace_binding_mismatch"),
        ("policy_sequence", 1, "policy_sequence_from_future"),
        (
            "trusted_time_receipt_digest",
            "sha256:" + "0" * 64,
            "trusted_time_receipt_binding_mismatch",
        ),
    ],
)
def test_verify_envelope_rejects_tampered_protected_bindings(
    field: str, value: object, reason: str
) -> None:
    policy, trusted_time, _, envelope = _signed_state()
    payload = loads_bounded(base64.b64decode(envelope.payload))
    payload["protected"][field] = value
    tampered = envelope.model_copy(
        update={"payload": base64.b64encode(canonical_bytes(payload)).decode("ascii")}
    )
    result, document = verify_envelope(tampered, policy, trusted_time=trusted_time)
    assert document is not None
    assert not result.valid
    assert reason in result.reasons
    assert "signature_invalid" in result.reasons


def test_verify_envelope_rejects_authorization_time_and_signature_failures() -> None:
    policy, trusted_time, _, envelope = _signed_state(role="unauthorized", source_system="bad")
    payload = loads_bounded(base64.b64decode(envelope.payload))
    payload["protected"]["scope"] = ["other-workspace"]
    changed = envelope.model_copy(
        update={"payload": base64.b64encode(canonical_bytes(payload)).decode("ascii")}
    )
    result, _ = verify_envelope(changed, policy, trusted_time=trusted_time)
    assert {
        "role_not_authorized",
        "source_system_not_authorized",
        "scope_not_authorized",
        "signature_invalid",
    }.issubset(result.reasons)

    malformed = DsseEnvelope.model_construct(
        payloadType=envelope.payloadType,
        payload="not-base64",
        signatures=envelope.signatures,
    )
    invalid, document = verify_envelope(malformed, policy, trusted_time=trusted_time)
    assert invalid.code == "signed_payload_invalid" and document is None

    no_time, _ = verify_envelope(envelope, policy, trusted_time=None)
    assert "authoritative_time_receipt_required" in no_time.reasons


def test_time_status_distinguishes_future_expiry_and_revocation_modes() -> None:
    policy, _, _ = trust_fixture()
    root = policy.spec.principals[0]
    assert _time_status(root, NOW + timedelta(days=1), NOW) == ["signature_from_future"]
    assert "signing_time_outside_key_validity" in _time_status(
        root, VALID_FROM - timedelta(seconds=1), NOW
    )
    prospective = root.model_copy(update={"revoked_at": NOW, "revocation_mode": "prospective"})
    assert "signature_after_revocation" in _time_status(prospective, NOW, NOW)
    retroactive = root.model_copy(
        update={
            "revoked_at": NOW,
            "compromised_at": NOW - timedelta(days=1),
            "revocation_mode": "retroactive",
        }
    )
    assert "signature_invalidated_by_retroactive_revocation" in _time_status(retroactive, NOW, NOW)


def test_quorum_requires_exact_roles_subjects_and_independent_domains() -> None:
    policy, trusted_time, keys = trust_fixture()
    subject = state_document()
    subject_digest = document_digest(subject)
    envelopes = []
    for principal, role, key_name in (
        (policy.spec.principals[0], "projection_authority", "root"),
        (policy.spec.principals[1], "projection_verifier", "auditor"),
    ):
        header = build_protected_header(
            subject,
            principal=principal,
            role=role,
            source_system="fixture-source",
            scope=["workspace-a"],
            signing_time=NOW,
            policy_sequence=0,
            trusted_time_receipt_digest=document_digest(trusted_time),
        )
        envelopes.append(sign_document(subject, private_key=keys[key_name], protected=header))
    assert evaluate_quorum(
        "projection_promotion", subject_digest, envelopes, policy, trusted_time=trusted_time
    ).valid
    missing = evaluate_quorum(
        "invented", subject_digest, envelopes, policy, trusted_time=trusted_time
    )
    assert missing.code == "quorum_rule_missing"
    mismatch = evaluate_quorum(
        "projection_promotion",
        "sha256:" + "0" * 64,
        envelopes,
        policy,
        trusted_time=trusted_time,
    )
    assert mismatch.code == "quorum_subject_mismatch"
    incomplete = evaluate_quorum(
        "projection_promotion", subject_digest, envelopes[:1], policy, trusted_time=trusted_time
    )
    assert "required_quorum_roles_not_satisfied" in incomplete.reasons


def test_genesis_rejects_invalid_payload_and_non_genesis_policy() -> None:
    policy, _, keys = trust_fixture()
    root = policy.spec.principals[0]
    header = build_protected_header(
        policy,
        principal=root,
        role="workspace_root",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=None,
    )
    envelope = sign_document(policy, private_key=keys["root"], protected=header)
    malformed = envelope.model_copy(update={"payload": "not-base64"})
    assert (
        inspect_genesis(
            malformed,
            expected_root_spki_fingerprint="sha256:" + "0" * 64,
            expected_envelope_fingerprint="sha256:" + "0" * 64,
        ).code
        == "genesis_invalid"
    )

    successor = policy.model_copy(
        update={
            "spec": policy.spec.model_copy(
                update={
                    "policy_sequence": 1,
                    "prior_policy_digest": document_digest(policy),
                }
            )
        }
    )
    successor_header = build_protected_header(
        successor,
        principal=root,
        role="workspace_root",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=1,
        trusted_time_receipt_digest=None,
    )
    successor_envelope = sign_document(
        successor, private_key=keys["root"], protected=successor_header
    )
    result = inspect_genesis(
        successor_envelope,
        expected_root_spki_fingerprint="sha256:" + "0" * 64,
        expected_envelope_fingerprint=digest_bytes(
            canonical_bytes(successor_envelope.model_dump(mode="json"))
        ),
    )
    assert "genesis_policy_required" in result.reasons


def test_projection_pointer_and_binding_failures_are_fail_closed() -> None:
    assert resolve_pointer({"a/b": {"~key": ["value"]}}, "/a~1b/~0key/0") == "value"
    for value, pointer, reason in (
        ({}, "invalid", "json_pointer_must_start_with_slash"),
        ({}, "/missing", "json_pointer_member_missing"),
        ({"x": []}, "/x/-", "json_pointer_array_index_invalid"),
        ({"x": []}, "/x/0", "json_pointer_array_index_missing"),
        ({"x": 1}, "/x/y", "json_pointer_traverses_scalar"),
    ):
        with pytest.raises(ValueError, match=reason):
            resolve_pointer(value, pointer)

    _, _, receipt = runner_fixture()
    from collective_phase_control_fabric.v6.models import (
        PendingProjection,
        PendingProjectionSpec,
        ProjectionApproval,
        ProjectionApprovalSpec,
        SourceArtifactEnvelope,
        SourceArtifactSpec,
    )
    from collective_phase_control_fabric.v6.registry import schema_digest
    from tests.test_v6_service_boundaries import state_document as projected_state

    projected = projected_state()
    raw = canonical_bytes({"projected": projected.model_dump(mode="json", exclude_none=True)})
    source = SourceArtifactEnvelope(
        metadata=metadata("source"),
        spec=SourceArtifactSpec(
            raw_digest=digest_bytes(raw),
            byte_length=len(raw),
            media_type="application/json",
            source_system="runner",
            source_uri="urn:test",
            acquired_at=NOW,
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
        ),
    )
    pending = PendingProjection(
        metadata=metadata("pending"),
        spec=PendingProjectionSpec(
            projection_id="projection",
            runner_receipt_digest="sha256:" + "0" * 64,
            source_artifact_envelope_digest="sha256:" + "1" * 64,
            producer_principal_id="producer",
            raw_output_digest=digest_bytes(raw),
            json_pointer="/missing",
            expected_schema_name="state-attestation",
            expected_schema_digest="sha256:" + "2" * 64,
            projected_digest="sha256:" + "3" * 64,
            changes_authoritative_state=True,
        ),
    )
    approval = ProjectionApproval(
        metadata=metadata("approval"),
        spec=ProjectionApprovalSpec(
            projection_digest="sha256:" + "4" * 64,
            producer_principal_id="other-producer",
            verifier_principal_id="verifier",
            approved_at=NOW,
        ),
    )
    result, document = reconstruct_projection(pending, approval, receipt, source, raw + b" ")
    assert document is None
    assert {
        "projection_approval_binding_mismatch",
        "projection_producer_binding_mismatch",
        "projection_runner_receipt_binding_mismatch",
        "projection_source_envelope_binding_mismatch",
        "projection_raw_output_digest_mismatch",
        "source_envelope_raw_digest_mismatch",
        "source_envelope_byte_length_mismatch",
        "projection_expected_schema_digest_mismatch",
    }.issubset(result.reasons)


def test_runner_receipt_reports_all_boundaries() -> None:
    capability, job, receipt = runner_fixture()
    changed = receipt.model_copy(
        update={
            "spec": receipt.spec.model_copy(
                update={
                    "job_digest": "sha256:" + "0" * 64,
                    "job_id": "other-job",
                    "attempt": 2,
                    "lease_id": "other-lease",
                    "runner_principal_id": "unknown-runner",
                    "image_digest": "sha256:" + "1" * 64,
                    "material_digests": [],
                    "stdout_captured_bytes": job.spec.stdout_limit + 1,
                    "stderr_captured_bytes": job.spec.stderr_limit + 1,
                    "timeout": True,
                    "cleanup_complete": False,
                    "isolation_profile_digest": None,
                }
            )
        }
    )
    result = validate_receipt(
        job,
        changed,
        capability,
        received_at=job.spec.lease_expires_at + timedelta(seconds=1),
        expected_runner_principal_id="runner-principal",
        prior_attempts={(job.spec.job_id, job.spec.attempt)},
    )
    assert not result.accepted
    assert len(result.reasons) == 15


def test_coordination_invalid_transitions_and_deadline_are_reported() -> None:
    plan = CoordinationPlan(
        metadata=metadata("plan"),
        spec=CoordinationPlanSpec(
            session_id="session-1",
            participant_principals=["one", "two"],
            verifier_principals=["two"],
            commit_deadline=NOW - timedelta(hours=2),
            reveal_deadline=NOW - timedelta(hours=1),
            termination_deadline=NOW - timedelta(minutes=1),
            maximum_exposures=0,
        ),
    )
    invalid = CoordinationEventDocument(
        metadata=metadata("invalid"),
        spec=CoordinationEventSpec(
            session_id="session-1",
            event_id="invalid",
            event_type="reveal",
            actor_principal_id="one",
            occurred_at=NOW,
            prior_event_digest="sha256:" + "0" * 64,
        ),
    )
    result = validate_coordination(
        {document_digest(plan): plan, document_digest(invalid): invalid}, NOW
    )
    assert result.status == "violated"
    assert {
        "coordination_event_chain_broken:invalid",
        "invalid_coordination_transition:CREATED:reveal",
        "coordination_not_terminated",
        "coordination_termination_deadline_missed",
    }.issubset(result.blockers)
    assert validate_coordination({}, NOW).status == "unknown"


def test_trial_assessment_separates_provenance_and_outcome_contradictions() -> None:
    protocol, raw_objects, result = trial_fixture()
    objects = dict(raw_objects)
    registration_digest = next(
        digest
        for digest, item in objects.items()
        if item.kind == "quorum-decision"  # type: ignore[attr-defined]
    )
    del objects[registration_digest]
    for digest in (
        protocol.spec.dataset_record_digest,
        protocol.spec.assignment_record_digest,
        protocol.spec.analysis_executable_record_digest,
    ):
        objects.pop(digest)
    assessment = assess_trial(protocol, objects)  # type: ignore[arg-type]
    assert {
        "typed_dataset_record_missing",
        "typed_assignment_record_missing",
        "typed_analysis-executable_record_missing",
        "independent_protocol_registration_quorum_required",
    }.issubset(assessment.blockers)

    amendment = ProtocolAmendment(
        metadata=metadata("amendment"),
        spec=ProtocolAmendmentSpec(
            protocol_digest=document_digest(protocol),
            prior_amendment_digest="sha256:" + "9" * 64,
            sequence=2,
            amended_at=protocol.spec.time_zero,
            changes=["estimand"],
        ),
    )
    raw_objects[document_digest(amendment)] = amendment
    reversed_effect = result.spec.effects[0].model_copy(
        update={"lower": "2", "upper": "1", "quality_value": "0"}
    )
    invalid_result = result.model_copy(
        update={
            "spec": result.spec.model_copy(
                update={
                    "evaluator_principal_id": "other",
                    "dataset_record_digest": "sha256:" + "6" * 64,
                    "assignment_record_digest": "sha256:" + "7" * 64,
                    "analysis_executable_record_digest": "sha256:" + "8" * 64,
                    "observation_completed_at": protocol.spec.time_zero,
                    "effects": [reversed_effect],
                }
            )
        }
    )
    raw_objects.pop(document_digest(result))
    raw_objects[document_digest(invalid_result)] = invalid_result
    contradicted = assess_trial(protocol, raw_objects)  # type: ignore[arg-type]
    assert contradicted.status == "external_quality_or_safety_contradiction"
    assert "result_evaluator_mismatch" in contradicted.blockers
    assert "quality_floor_contradiction:time-effect" in contradicted.contradictions
    assert "effect_interval_reversed:time-effect" in contradicted.contradictions
    assert "amendment_sequence_gap_or_fork" in contradicted.contradictions
    assert "amendment_hash_chain_fork" in contradicted.contradictions
    assert "post_start_protocol_amendment" in contradicted.contradictions


def test_storage_reports_ledger_history_and_repository_failures(tmp_path: Path) -> None:
    from collective_phase_control_fabric.v6.models import (
        AuditEvent,
        AuditEventSpec,
        LedgerEntry,
        WorkspaceGeneration,
        WorkspaceGenerationSpec,
    )
    from collective_phase_control_fabric.v6.storage import generation_digest

    store = MemoryObjectStore()
    event = AuditEvent(
        metadata=metadata("event"),
        spec=AuditEventSpec(event_id="event", event_type="workspace_created", occurred_at=NOW),
    )
    raw = canonical_bytes(event.model_dump(mode="json", exclude_none=True))
    actual = store.put("tenant-a", raw)
    store.values[("tenant-a", "sha256:" + "1" * 64)] = raw
    invalid_raw = store.put("tenant-a", b"not-json")
    missing = "sha256:" + "2" * 64
    dangling = "sha256:" + "4" * 64
    placeholder = WorkspaceGeneration(
        metadata=metadata("generation"),
        spec=WorkspaceGenerationSpec(
            generation_digest="sha256:" + "0" * 64,
            sequence=0,
            ledger=[
                LedgerEntry(
                    object_digest=actual,
                    object_kind="state-attestation",
                    authority_status="active",
                    source_digests=[dangling],
                ),
                LedgerEntry(
                    object_digest=actual, object_kind="audit-event", authority_status="active"
                ),
                LedgerEntry(
                    object_digest="sha256:" + "1" * 64,
                    object_kind="audit-event",
                    authority_status="active",
                ),
                LedgerEntry(
                    object_digest=invalid_raw, object_kind="audit-event", authority_status="active"
                ),
                LedgerEntry(
                    object_digest=missing,
                    object_kind="raw-artifact",
                    authority_status="quarantined",
                ),
            ],
            history_head_digest="sha256:" + "3" * 64,
        ),
    )
    reasons = validate_ledger(placeholder, store)
    assert any(item.startswith("ledger_object_digest_duplicate") for item in reasons)
    assert any(item.startswith("ledger_kind_mismatch") for item in reasons)
    assert any(item.startswith("ledger_raw_digest_mismatch") for item in reasons)
    assert any(item.startswith("ledger_document_invalid") for item in reasons)
    assert any(item.startswith("ledger_object_missing") for item in reasons)
    assert any(item.startswith("ledger_source_dangling") for item in reasons)
    assert "history_head_missing_from_ledger" in reasons

    event_duplicate = event.model_copy(
        update={"metadata": metadata("event-copy"), "spec": event.spec.model_copy()}
    )
    history = validate_history([event, event_duplicate], "sha256:" + "4" * 64)
    assert "history_event_id_duplicate" in history
    assert "history_chain_broken:1" in history
    assert "history_head_mismatch" in history

    valid_placeholder = placeholder.model_copy(
        update={
            "spec": placeholder.spec.model_copy(
                update={
                    "ledger": [
                        LedgerEntry(
                            object_digest=actual,
                            object_kind="audit-event",
                            authority_status="active",
                        )
                    ],
                    "history_head_digest": actual,
                }
            )
        }
    )
    valid_generation = valid_placeholder.model_copy(
        update={
            "spec": valid_placeholder.spec.model_copy(
                update={"generation_digest": generation_digest(valid_placeholder)}
            )
        }
    )
    repository = MemoryGenerationRepository()
    state = WorkspaceState(generation=valid_generation, objects={actual: event})
    repository.create(state)
    assert repository.get("tenant-a", "workspace-a") is state
    with pytest.raises(ConcurrentGenerationError, match="workspace_already_exists"):
        repository.create(state)
    wrong_predecessor = valid_generation.model_copy(
        update={
            "spec": valid_generation.spec.model_copy(
                update={"sequence": 1, "prior_generation_digest": "sha256:" + "5" * 64}
            )
        }
    )
    with pytest.raises(ConcurrentGenerationError, match="generation_predecessor_mismatch"):
        repository.commit(
            WorkspaceState(generation=wrong_predecessor, objects={actual: event}),
            expected_generation_digest=valid_generation.spec.generation_digest,
        )
    wrong_sequence = wrong_predecessor.model_copy(
        update={
            "spec": wrong_predecessor.spec.model_copy(
                update={
                    "prior_generation_digest": valid_generation.spec.generation_digest,
                    "sequence": 2,
                }
            )
        }
    )
    with pytest.raises(ConcurrentGenerationError, match="generation_sequence_mismatch"):
        repository.commit(
            WorkspaceState(generation=wrong_sequence, objects={actual: event}),
            expected_generation_digest=valid_generation.spec.generation_digest,
        )

    assert [item.object_digest for item in quarantine_legacy_entries([actual, actual])] == [actual]
    directory = tmp_path / "legacy"
    directory.mkdir()
    assert assert_safe_legacy_root(directory) == directory.resolve()
    link = tmp_path / "legacy-link"
    try:
        link.symlink_to(directory, target_is_directory=True)
    except OSError:
        return
    with pytest.raises(ValueError, match="legacy_workspace_link_rejected"):
        assert_safe_legacy_root(link)


def test_kms_signers_normalize_provider_encodings() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    message = b"evidence"
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    normalized = normalize_p256_der(der)
    assert len(normalized) == 64
    assert base64.b64decode(encode_signature(normalized)) == normalized

    class AwsClient:
        def sign(self, **_: object) -> dict[str, bytes]:
            return {"Signature": der}

    class GoogleResponse:
        signature = der

    class GoogleClient:
        def asymmetric_sign(self, **_: object) -> GoogleResponse:
            return GoogleResponse()

    class AzureResponse:
        signature = normalized

    class AzureClient:
        def sign(self, *_: object) -> AzureResponse:
            return AzureResponse()

    class Pkcs11Key:
        def sign(self, *_: object, **__: object) -> bytes:
            return der

    class AzureDerResponse:
        signature = der

    class AzureDerClient:
        def sign(self, *_: object) -> AzureDerResponse:
            return AzureDerResponse()

    class Pkcs11RawKey:
        def sign(self, *_: object, **__: object) -> bytes:
            return normalized

    assert len(AwsKmsSigner(AwsClient(), "aws-key").sign(message)) == 64
    assert len(GoogleKmsSigner(GoogleClient(), "gcp-key").sign(message)) == 64
    assert AzureKeyVaultSigner(AzureClient(), "azure-key").sign(message) == normalized
    assert len(AzureKeyVaultSigner(AzureDerClient(), "azure-der-key").sign(message)) == 64
    assert len(Pkcs11Signer(Pkcs11Key(), "pkcs11-key").sign(message)) == 64
    assert Pkcs11Signer(Pkcs11RawKey(), "pkcs11-raw-key").sign(message) == normalized
    with pytest.raises(ValueError):
        normalize_p256_der(encode_dss_signature(0, P256_ORDER))


def test_p256_principals_sign_verify_and_reject_algorithm_or_encoding_substitution() -> None:
    policy, trusted_time, _ = trust_fixture()
    key = ec.generate_private_key(ec.SECP256R1())
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    root = policy.spec.principals[0].model_copy(
        update={
            "algorithm": "ecdsa-p256-sha256",
            "public_key_base64": base64.b64encode(der).decode("ascii"),
        }
    )
    p256_policy = policy.model_copy(
        update={
            "spec": policy.spec.model_copy(
                update={"principals": [root, *policy.spec.principals[1:]]}
            )
        }
    )
    document = state_document()
    header = build_protected_header(
        document,
        principal=root,
        role="state_source",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=document_digest(trusted_time),
    )
    envelope = sign_document(document, private_key=key, protected=header)
    assert verify_envelope(envelope, p256_policy, trusted_time=trusted_time)[0].valid
    assert public_key_fingerprint(root).startswith("sha256:")

    with pytest.raises(InvalidSignature):
        _verify_signature(root, b"message", b"short")
    with pytest.raises(InvalidSignature):
        _verify_signature(root, b"message", b"\x00" * 64)

    malformed_ed25519 = root.model_copy(
        update={"algorithm": "ed25519", "public_key_base64": base64.b64encode(b"short").decode()}
    )
    with pytest.raises(ValueError, match="ed25519_public_key_length_invalid"):
        public_key_fingerprint(malformed_ed25519)
    malformed_der = root.model_copy(
        update={"public_key_base64": base64.b64encode(b"not-der").decode()}
    )
    with pytest.raises(ValueError, match="ecdsa_public_key_der_invalid"):
        public_key_fingerprint(malformed_der)
    p384 = (
        ec.generate_private_key(ec.SECP384R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    wrong_curve = root.model_copy(update={"public_key_base64": base64.b64encode(p384).decode()})
    with pytest.raises(ValueError, match="ecdsa_public_key_curve_invalid"):
        public_key_fingerprint(wrong_curve)


def test_envelope_unknown_principal_disallowed_kind_and_invalid_time_are_diagnostic() -> None:
    policy, trusted_time, document, envelope = _signed_state()
    payload = loads_bounded(base64.b64decode(envelope.payload))
    payload["protected"]["key_id"] = "unknown-key"
    payload["protected"]["principal_id"] = "unknown-principal"
    unknown = envelope.model_copy(
        update={"payload": base64.b64encode(canonical_bytes(payload)).decode("ascii")}
    )
    assert (
        "pinned_principal_unknown_or_ambiguous"
        in verify_envelope(unknown, policy, trusted_time=trusted_time)[0].reasons
    )

    root = policy.spec.principals[0].model_copy(
        update={
            "allowed_kinds": [
                kind for kind in policy.spec.principals[0].allowed_kinds if kind != document.kind
            ]
        }
    )
    restricted = policy.model_copy(
        update={
            "spec": policy.spec.model_copy(
                update={"principals": [root, *policy.spec.principals[1:]]}
            )
        }
    )
    assert (
        "document_kind_not_authorized"
        in verify_envelope(envelope, restricted, trusted_time=trusted_time)[0].reasons
    )

    invalid_time = trusted_time.model_copy(
        update={
            "spec": trusted_time.spec.model_copy(
                update={"valid_until": trusted_time.spec.issued_at - timedelta(seconds=1)}
            )
        }
    )
    _, _, keys = trust_fixture()
    invalid_header = build_protected_header(
        document,
        principal=policy.spec.principals[0],
        role="state_source",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=document_digest(invalid_time),
    )
    invalid_envelope = sign_document(document, private_key=keys["root"], protected=invalid_header)
    assert (
        "trusted_time_receipt_expired_at_issue"
        in verify_envelope(invalid_envelope, policy, trusted_time=invalid_time)[0].reasons
    )


def test_quorum_collision_diagnostics_cover_principal_key_and_shared_domains() -> None:
    policy, trusted_time, keys = trust_fixture()
    root = policy.spec.principals[0].model_copy(
        update={"roles": [*policy.spec.principals[0].roles, "projection_verifier"]}
    )
    collision_policy = policy.model_copy(
        update={
            "spec": policy.spec.model_copy(
                update={"principals": [root, *policy.spec.principals[1:]]}
            )
        }
    )
    document = state_document()
    envelopes = []
    for role in ("projection_authority", "projection_verifier"):
        header = build_protected_header(
            document,
            principal=root,
            role=role,
            source_system="fixture-source",
            scope=["workspace-a"],
            signing_time=NOW,
            policy_sequence=0,
            trusted_time_receipt_digest=document_digest(trusted_time),
        )
        envelopes.append(sign_document(document, private_key=keys["root"], protected=header))
    result = evaluate_quorum(
        "projection_promotion",
        document_digest(document),
        envelopes,
        collision_policy,
        trusted_time=trusted_time,
    )
    assert {
        "quorum_principal_id_collision",
        "quorum_key_id_collision",
        "quorum_infrastructure_collision",
        "quorum_correlation_collision",
    }.issubset(result.reasons)


def test_genesis_wrong_root_fingerprint_is_rejected_after_envelope_binding() -> None:
    policy, _, keys = trust_fixture()
    root = policy.spec.principals[0]
    header = build_protected_header(
        policy,
        principal=root,
        role="workspace_root",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=None,
    )
    envelope = sign_document(policy, private_key=keys["root"], protected=header)
    fingerprint = digest_bytes(canonical_bytes(envelope.model_dump(mode="json")))
    result = inspect_genesis(
        envelope,
        expected_root_spki_fingerprint="sha256:" + "0" * 64,
        expected_envelope_fingerprint=fingerprint,
    )
    assert "genesis_root_spki_fingerprint_mismatch" in result.reasons


def test_trial_registration_timing_missing_results_and_all_design_tiers() -> None:
    protocol, objects, result = trial_fixture()
    result_digest = document_digest(result)
    no_result = dict(objects)
    no_result.pop(result_digest)
    pending = assess_trial(protocol, no_result)  # type: ignore[arg-type]
    assert pending.status == "registered_not_observed"

    registration_digest, registration = next(
        (digest, item)
        for digest, item in objects.items()
        if item.kind == "quorum-decision"  # type: ignore[attr-defined]
    )
    late_registration = registration.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": registration.spec.model_copy(update={"decided_at": protocol.spec.time_zero})  # type: ignore[attr-defined]
        }
    )
    late = dict(objects)
    late[registration_digest] = late_registration
    assert (
        "protocol_registered_after_time_zero"
        in assess_trial(
            protocol,
            late,  # type: ignore[arg-type]
        ).contradictions
    )

    for design, tier in (
        ("descriptive", "descriptive_observation"),
        ("observational", "observational_association_compatible"),
        ("quasi-experimental", "quasi_experimental_compatible"),
        ("randomized", "preregistered_randomized_acceleration_bundle_compatible"),
    ):
        designed = result.model_copy(  # type: ignore[attr-defined]
            update={
                "metadata": metadata(f"result-{design}"),
                "spec": result.spec.model_copy(update={"design": design}),  # type: ignore[attr-defined]
            }
        )
        selected = dict(objects)
        selected.pop(result_digest)
        selected[document_digest(designed)] = designed
        assert assess_trial(protocol, selected).tier == tier  # type: ignore[arg-type]


def test_trial_missing_outcomes_unfavorable_effects_and_result_bindings_are_distinct() -> None:
    from collective_phase_control_fabric.v6.models import OutcomeDefinition

    protocol, objects, result = trial_fixture()
    result_digest = document_digest(result)
    unfavorable = result.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": result.spec.model_copy(  # type: ignore[attr-defined]
                update={"effects": [result.spec.effects[0].model_copy(update={"upper": "0"})]}
            )
        }
    )
    objects.pop(result_digest)
    objects[document_digest(unfavorable)] = unfavorable
    inconclusive = assess_trial(protocol, objects)  # type: ignore[arg-type]
    assert inconclusive.status == "externally_observed_inconclusive"
    assert not inconclusive.contradictions

    second_outcome = OutcomeDefinition(
        outcome_id="quality-effect",
        unit="second",
        direction="higher",
        minimum_effect="2",
        quality_floor="0",
    )
    expanded_protocol = protocol.model_copy(  # type: ignore[attr-defined]
        update={
            "metadata": metadata("expanded-protocol"),
            "spec": protocol.spec.model_copy(  # type: ignore[attr-defined]
                update={"outcomes": [*protocol.spec.outcomes, second_outcome]}
            ),
        }
    )
    expanded_digest = document_digest(expanded_protocol)
    registration_digest, registration = next(
        (digest, item)
        for digest, item in objects.items()
        if item.kind == "quorum-decision"  # type: ignore[attr-defined]
    )
    objects[registration_digest] = registration.model_copy(  # type: ignore[attr-defined]
        update={"spec": registration.spec.model_copy(update={"subject_digest": expanded_digest})}  # type: ignore[attr-defined]
    )
    invalid = unfavorable.model_copy(  # type: ignore[attr-defined]
        update={
            "metadata": metadata("invalid-result-bindings"),
            "spec": unfavorable.spec.model_copy(  # type: ignore[attr-defined]
                update={
                    "protocol_digest": expanded_digest,
                    "issued_at": unfavorable.spec.observation_completed_at,
                    "analysis_executable_record_digest": "sha256:" + "c" * 64,
                }
            ),
        }
    )
    objects.pop(document_digest(unfavorable))
    objects[document_digest(invalid)] = invalid
    assessed = assess_trial(expanded_protocol, objects)  # type: ignore[arg-type]
    assert "result_issued_before_observation_completion" in assessed.contradictions
    assert "primary_outcome_bundle_incomplete_or_extra" in assessed.contradictions
    assert "result_analysis_executable_binding_mismatch" in assessed.blockers


def test_canonical_internal_limits_cover_escaped_strings_and_non_json_values() -> None:
    _scan_nesting(b'{"escaped":"\\"","nested":{}}', 64)
    with pytest.raises(InputLimitError, match="json_nesting_too_deep"):
        _validate_tree({}, depth=65)
    with pytest.raises(InputLimitError, match="json_object_member_limit"):
        _unique_object([(str(index), None) for index in range(10_001)])
    with pytest.raises(ValueError, match="unsupported_json_value"):
        _validate_tree(object())
    assert digest_document({"value": True}) == digest_bytes(canonical_bytes({"value": True}))


def test_registry_rejects_every_discriminator_failure_and_exports_runtime_schemas(
    tmp_path: Path,
) -> None:
    assert str(DocumentValidationError("code")) == "code"
    detailed = DocumentValidationError("code", "detail")
    assert str(detailed) == "code: detail"
    assert detailed.code == "code" and detailed.detail == "detail"
    assert (
        _close_schema([{"properties": {"x": {"type": "string"}}}])[0]["additionalProperties"]
        is False
    )
    assert _close_schema("scalar") == "scalar"
    with pytest.raises(DocumentValidationError, match="unknown_document_kind"):
        schema_for_kind("unknown")

    valid = state_document().model_dump(mode="json", exclude_none=True)
    assert parse_document(valid) == state_document()
    assert parse_document_bytes(canonical_bytes(valid)) == state_document()
    for value, code in (
        ({**valid, "api_version": "cpcf.io/v9"}, "unsupported_document_version"),
        ({key: item for key, item in valid.items() if key != "kind"}, "document_kind_required"),
        ({**valid, "kind": 1}, "document_kind_required"),
        ({**valid, "kind": "unknown"}, "unknown_document_kind"),
        ({**valid, "unexpected": True}, "document_schema_invalid"),
    ):
        with pytest.raises(DocumentValidationError) as error:
            parse_document(value)
        assert error.value.code == code

    destination = tmp_path / "schemas"
    write_schemas(destination)
    assert (destination / "registry-manifest.json").is_file()
    assert (destination / "state-attestation.schema.json").is_file()


def test_projection_reconstruction_covers_remaining_failures() -> None:
    pending, approval, receipt, source, raw = valid_projection_fixture()
    promoted, projected = reconstruct_projection(
        pending,
        approval,
        receipt,
        source,
        raw,  # type: ignore[arg-type]
    )
    assert promoted.promoted and projected == state_document()

    direct_raw = canonical_bytes(state_document().model_dump(mode="json", exclude_none=True))
    direct_source = source.model_copy(
        update={
            "spec": source.spec.model_copy(
                update={"raw_digest": digest_bytes(direct_raw), "byte_length": len(direct_raw)}
            )
        }
    )
    direct_pending = pending.model_copy(
        update={
            "spec": pending.spec.model_copy(
                update={
                    "source_artifact_envelope_digest": document_digest(direct_source),
                    "raw_output_digest": digest_bytes(direct_raw),
                    "json_pointer": "",
                }
            )
        }
    )
    direct_approval = approval.model_copy(
        update={
            "spec": approval.spec.model_copy(
                update={"projection_digest": document_digest(direct_pending)}
            )
        }
    )
    assert reconstruct_projection(
        direct_pending,
        direct_approval,
        receipt,  # type: ignore[arg-type]
        direct_source,
        direct_raw,
    )[0].promoted

    wrong_source = source.model_copy(
        update={
            "spec": source.spec.model_copy(
                update={
                    "expected_schema_name": "evidence-attestation",
                    "expected_schema_digest": "sha256:" + "0" * 64,
                }
            )
        }
    )
    wrong_pending = pending.model_copy(
        update={
            "spec": pending.spec.model_copy(
                update={"source_artifact_envelope_digest": document_digest(wrong_source)}
            )
        }
    )
    wrong_approval = approval.model_copy(
        update={
            "spec": approval.spec.model_copy(
                update={"projection_digest": document_digest(wrong_pending)}
            )
        }
    )
    wrong_result, _ = reconstruct_projection(
        wrong_pending,
        wrong_approval,
        receipt,  # type: ignore[arg-type]
        wrong_source,
        raw,
    )
    assert {
        "projection_source_schema_name_mismatch",
        "projection_source_schema_digest_mismatch",
    }.issubset(wrong_result.reasons)

    scalar_raw = canonical_bytes({"projected": "scalar"})
    scalar_source = source.model_copy(
        update={
            "spec": source.spec.model_copy(
                update={"raw_digest": digest_bytes(scalar_raw), "byte_length": len(scalar_raw)}
            )
        }
    )
    scalar_pending = pending.model_copy(
        update={
            "spec": pending.spec.model_copy(
                update={
                    "source_artifact_envelope_digest": document_digest(scalar_source),
                    "raw_output_digest": digest_bytes(scalar_raw),
                }
            )
        }
    )
    scalar_approval = approval.model_copy(
        update={
            "spec": approval.spec.model_copy(
                update={"projection_digest": document_digest(scalar_pending)}
            )
        }
    )
    scalar_result, _ = reconstruct_projection(
        scalar_pending,
        scalar_approval,
        receipt,  # type: ignore[arg-type]
        scalar_source,
        scalar_raw,
    )
    assert "projected_value_must_be_object" in scalar_result.reasons

    digest_mismatch = pending.model_copy(
        update={"spec": pending.spec.model_copy(update={"projected_digest": "sha256:" + "9" * 64})}
    )
    digest_approval = approval.model_copy(
        update={
            "spec": approval.spec.model_copy(
                update={"projection_digest": document_digest(digest_mismatch)}
            )
        }
    )
    digest_result, _ = reconstruct_projection(
        digest_mismatch,
        digest_approval,
        receipt,  # type: ignore[arg-type]
        source,
        raw,
    )
    assert "projected_digest_mismatch" in digest_result.reasons


def test_coordination_reports_commit_reveal_exposure_and_integration_evidence_failures() -> None:
    plan = CoordinationPlan(
        metadata=metadata("coordination-assurance-plan"),
        spec=CoordinationPlanSpec(
            session_id="session-assurance",
            participant_principals=["one", "two"],
            verifier_principals=["two"],
            commit_deadline=NOW + timedelta(minutes=1),
            reveal_deadline=NOW + timedelta(minutes=2),
            termination_deadline=NOW + timedelta(minutes=3),
            maximum_exposures=0,
        ),
    )
    objects: dict[str, object] = {document_digest(plan): plan}
    prior: str | None = None
    rows = (
        ("open", "open_commit", None, None),
        ("commit", "commit", None, None),
        ("close", "close_commit", None, None),
        ("reveal-open", "open_reveal", None, None),
        ("reveal", "reveal", "sha256:" + "1" * 64, None),
        ("exposure", "exposure", None, "sha256:" + "2" * 64),
        ("verify", "verification", None, "sha256:" + "3" * 64),
        ("integrate", "integration", None, None),
        ("terminate", "terminate", None, None),
    )
    for index, (event_id, event_type, commitment, artifact) in enumerate(rows):
        item = CoordinationEventDocument(
            metadata=metadata(f"coordination-{event_id}"),
            spec=CoordinationEventSpec(
                session_id="session-assurance",
                event_id=event_id,
                event_type=event_type,  # type: ignore[arg-type]
                actor_principal_id="one",
                occurred_at=NOW + timedelta(seconds=index),
                artifact_digest=artifact,
                commitment_digest=commitment,
                prior_event_digest=prior,
            ),
        )
        prior = document_digest(item)
        objects[prior] = item
    result = validate_coordination(objects, NOW)  # type: ignore[arg-type]
    assert result.detail == "terminal_state=TERMINATED"
    assert {
        "commitment_digest_required",
        "reveal_without_matching_commitment",
        "coordination_exposure_limit_exceeded",
        "integration_artifact_required",
    }.issubset(result.blockers)
