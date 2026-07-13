# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
from datetime import timedelta

import httpx
import pytest
from cpcf_api.app import InMemoryBackend, StaticAuthenticator, create_app
from cpcf_api.auth import PrincipalContext
from cpcf_api.db import rls_statements
from cpcf_api.object_store import S3ObjectStore

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import (
    ArtifactRecord,
    ArtifactRecordSpec,
    AuditEvent,
    AuditEventSpec,
    CapabilityDocument,
    CapabilitySpec,
    EffectInterval,
    ExecutionPolicy,
    ExecutionPolicySpec,
    LedgerEntry,
    Lifecycle,
    MeasurementProtocol,
    MeasurementProtocolSpec,
    OutcomeDefinition,
    OutcomeSelector,
    PendingProjection,
    PendingProjectionSpec,
    ProjectionApproval,
    ProjectionApprovalSpec,
    QuorumDecisionDocument,
    QuorumDecisionSpec,
    RunnerJob,
    RunnerJobSpec,
    RunnerReceipt,
    RunnerReceiptSpec,
    SourceArtifactEnvelope,
    SourceArtifactSpec,
    StateAttestation,
    StateSpec,
    TrialResult,
    TrialResultSpec,
    WorkspaceGeneration,
    WorkspaceGenerationSpec,
)
from collective_phase_control_fabric.v6.projection import reconstruct_projection
from collective_phase_control_fabric.v6.registry import document_digest, schema_digest
from collective_phase_control_fabric.v6.runner import validate_receipt
from collective_phase_control_fabric.v6.storage import (
    ConcurrentGenerationError,
    MemoryGenerationRepository,
    MemoryObjectStore,
    WorkspaceState,
    generation_digest,
    validate_history,
    validate_ledger,
)
from collective_phase_control_fabric.v6.trials import assess_trial
from tests.v6_helpers import NOW, VALID_FROM, VALID_UNTIL, metadata

GENESIS_BODY = {
    "root_spki_fingerprint": "sha256:" + "1" * 64,
    "genesis_envelope_fingerprint": "sha256:" + "2" * 64,
}


def state_document() -> StateAttestation:
    return StateAttestation(
        metadata=metadata("projected-state"),
        spec=StateSpec(
            state_id="projected-state",
            available=True,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )


def four_branches() -> list[dict[str, object]]:
    return [
        {
            "outcome": outcome,
            "resource_delta_lower": {},
            "resource_delta_upper": {},
        }
        for outcome in ("success", "partial", "failure", "timeout")
    ]


def runner_fixture() -> tuple[CapabilityDocument, ExecutionPolicy, RunnerJob, RunnerReceipt]:
    from collective_phase_control_fabric.v6.models import BranchEffect

    image_digest = "sha256:" + "a" * 64
    execution_policy = ExecutionPolicy(
        metadata=metadata("runner-execution-policy"),
        spec=ExecutionPolicySpec(
            execution_policy_id="runner-execution-policy",
            allowed_image_digests=[image_digest],
            timeout_seconds=30,
            stdout_limit=1024,
            stderr_limit=1024,
            maximum_input_bytes=4096,
            maximum_output_bytes=4096,
            network_policy="runner-attested",
            filesystem_policy="runner-attested",
        ),
    )
    capability = CapabilityDocument(
        metadata=metadata("runner-capability"),
        spec=CapabilitySpec(
            capability_id="runner-capability",
            adapter_principal_id="adapter-principal",
            verifier_principal_id="verifier-principal",
            execution_policy_digest=document_digest(execution_policy),
            image_digest=image_digest,
            material_digests=["sha256:" + "b" * 64],
            argv=["/adapter/run"],
            output_schema_name="state-attestation",
            output_schema_digest=schema_digest("state-attestation"),
            return_code_outcomes={"0": "success"},
            repeatable=False,
            branches=[BranchEffect.model_validate(value) for value in four_branches()],
        ),
    )
    capability_statement_digest = "sha256:" + "2" * 64
    policy_statement_digest = "sha256:" + "3" * 64
    output = state_document()
    output_bytes = canonical_bytes(output.model_dump(mode="json", exclude_none=True))
    output_digest = digest_bytes(output_bytes)
    job = RunnerJob(
        metadata=metadata("job"),
        spec=RunnerJobSpec(
            job_id="job-1",
            action_digest="sha256:" + "c" * 64,
            capability_digest=document_digest(capability),
            capability_statement_digest=capability_statement_digest,
            execution_policy_digest=document_digest(execution_policy),
            execution_policy_statement_digest=policy_statement_digest,
            generation_digest="sha256:" + "d" * 64,
            attempt=1,
            lease_id="lease-1",
            lease_expires_at=NOW + timedelta(minutes=1),
            input_digests=[],
            image_digest=capability.spec.image_digest,
            timeout_seconds=30,
            stdout_limit=1024,
            stderr_limit=1024,
            network_policy="runner-attested",
            filesystem_policy="runner-attested",
        ),
    )
    receipt = RunnerReceipt(
        metadata=metadata("receipt"),
        spec=RunnerReceiptSpec(
            job_digest=document_digest(job),
            job_id="job-1",
            attempt=1,
            lease_id="lease-1",
            runner_principal_id="runner-principal",
            image_digest=capability.spec.image_digest,
            material_digests=[
                *capability.spec.material_digests,
                capability_statement_digest,
                policy_statement_digest,
            ],
            stdout_digest="sha256:" + "e" * 64,
            stderr_digest="sha256:" + "f" * 64,
            stdout_captured_bytes=10,
            stderr_captured_bytes=10,
            stdout_discarded_bytes=0,
            stderr_discarded_bytes=0,
            return_code=0,
            timeout=False,
            claimed_outcome="success",
            cleanup_complete=True,
            isolation_profile_digest="sha256:" + "1" * 64,
            output_digests=[output_digest],
            started_at=NOW,
            completed_at=NOW,
        ),
    )
    return capability, execution_policy, job, receipt


def test_runner_rejects_replay_timeout_and_unattested_cleanup() -> None:
    capability, execution_policy, job, receipt = runner_fixture()
    available = {
        *receipt.spec.material_digests,
        receipt.spec.stdout_digest,
        receipt.spec.stderr_digest,
        *receipt.spec.output_digests,
    }
    valid = validate_receipt(
        job,
        receipt,
        capability,
        execution_policy,
        received_at=NOW,
        expected_runner_principal_id="runner-principal",
        prior_attempts=set(),
        available_digests=available,
        artifact_lengths={
            receipt.spec.stdout_digest: receipt.spec.stdout_captured_bytes,
            receipt.spec.stderr_digest: receipt.spec.stderr_captured_bytes,
            receipt.spec.output_digests[0]: len(
                canonical_bytes(state_document().model_dump(mode="json", exclude_none=True))
            ),
        },
        output_document=state_document().model_dump(mode="json", exclude_none=True),
    )
    assert valid.accepted
    bad = receipt.model_copy(
        update={
            "spec": receipt.spec.model_copy(
                update={
                    "timeout": True,
                    "claimed_outcome": "timeout",
                    "cleanup_complete": False,
                }
            )
        }
    )
    result = validate_receipt(
        job,
        bad,
        capability,
        execution_policy,
        received_at=NOW,
        expected_runner_principal_id="runner-principal",
        prior_attempts={("job-1", 1)},
        available_digests=available,
        artifact_lengths={
            receipt.spec.stdout_digest: receipt.spec.stdout_captured_bytes,
            receipt.spec.stderr_digest: receipt.spec.stderr_captured_bytes,
            receipt.spec.output_digests[0]: len(
                canonical_bytes(state_document().model_dump(mode="json", exclude_none=True))
            ),
        },
        output_document=state_document().model_dump(mode="json", exclude_none=True),
    )
    assert not result.accepted
    assert "runner_attempt_replay" in result.reasons
    assert "runner_cleanup_incomplete" in result.reasons


def test_runner_conformance_recomputes_every_signed_policy_boundary() -> None:
    capability, execution_policy, job, receipt = runner_fixture()
    invalid_capability = capability.model_copy(
        update={
            "spec": capability.spec.model_copy(
                update={
                    "execution_policy_digest": "sha256:" + "7" * 64,
                    "output_schema_digest": "sha256:" + "8" * 64,
                    "image_digest": "sha256:" + "9" * 64,
                }
            )
        }
    )
    invalid_policy = execution_policy.model_copy(
        update={
            "spec": execution_policy.spec.model_copy(
                update={
                    "allowed_image_digests": ["sha256:" + "0" * 64],
                    "timeout_seconds": 1,
                    "stdout_limit": 1,
                    "stderr_limit": 1,
                    "maximum_output_bytes": 1,
                    "network_policy": "none",
                    "filesystem_policy": "none",
                }
            )
        }
    )
    invalid_job = job.model_copy(
        update={
            "spec": job.spec.model_copy(
                update={
                    "capability_digest": "sha256:" + "1" * 64,
                    "execution_policy_digest": "sha256:" + "2" * 64,
                }
            )
        }
    )
    invalid_receipt = receipt.model_copy(
        update={
            "spec": receipt.spec.model_copy(
                update={
                    "started_at": job.metadata.created_at - timedelta(seconds=1),
                    "completed_at": job.spec.lease_expires_at + timedelta(seconds=1),
                }
            )
        }
    )
    result = validate_receipt(
        invalid_job,
        invalid_receipt,
        invalid_capability,
        invalid_policy,
        received_at=NOW,
        expected_runner_principal_id="runner-principal",
        prior_attempts=set(),
        available_digests=set(invalid_receipt.spec.material_digests)
        | {
            invalid_receipt.spec.stdout_digest,
            invalid_receipt.spec.stderr_digest,
            *invalid_receipt.spec.output_digests,
        },
        artifact_lengths={
            invalid_receipt.spec.stdout_digest: invalid_receipt.spec.stdout_captured_bytes,
            invalid_receipt.spec.stderr_digest: invalid_receipt.spec.stderr_captured_bytes,
            invalid_receipt.spec.output_digests[0]: 100,
        },
        output_document=state_document().model_dump(mode="json", exclude_none=True),
    )
    assert {
        "capability_execution_policy_digest_mismatch",
        "runner_capability_digest_mismatch",
        "runner_capability_image_mismatch",
        "runner_completion_after_lease_expiry",
        "runner_execution_policy_digest_mismatch",
        "runner_filesystem_policy_mismatch",
        "runner_image_not_allowed_by_execution_policy",
        "runner_network_policy_mismatch",
        "runner_output_policy_exceeded",
        "runner_output_schema_digest_mismatch",
        "runner_receipt_completed_in_future",
        "runner_start_before_job_creation",
        "runner_stderr_policy_exceeded",
        "runner_stdout_policy_exceeded",
        "runner_timeout_policy_exceeded",
    }.issubset(result.reasons)


def test_runner_output_schema_and_selector_fail_closed() -> None:
    capability, execution_policy, job, receipt = runner_fixture()
    available = {
        *receipt.spec.material_digests,
        receipt.spec.stdout_digest,
        receipt.spec.stderr_digest,
        *receipt.spec.output_digests,
    }
    lengths = {
        receipt.spec.stdout_digest: receipt.spec.stdout_captured_bytes,
        receipt.spec.stderr_digest: receipt.spec.stderr_captured_bytes,
        receipt.spec.output_digests[0]: len(
            canonical_bytes(state_document().model_dump(mode="json", exclude_none=True))
        ),
    }

    def checked(output: object, selected_capability: CapabilityDocument = capability) -> set[str]:
        selected_job = job.model_copy(
            update={
                "spec": job.spec.model_copy(
                    update={"capability_digest": document_digest(selected_capability)}
                )
            }
        )
        selected_receipt = receipt.model_copy(
            update={
                "spec": receipt.spec.model_copy(
                    update={"job_digest": document_digest(selected_job)}
                )
            }
        )
        return set(
            validate_receipt(
                selected_job,
                selected_receipt,
                selected_capability,
                execution_policy,
                received_at=NOW,
                expected_runner_principal_id="runner-principal",
                prior_attempts=set(),
                available_digests=available,
                artifact_lengths=lengths,
                output_document=output,
            ).reasons
        )

    assert "runner_output_schema_document_missing" in checked(None)
    assert "runner_output_schema_document_invalid" in checked([])
    assert "runner_output_schema_document_invalid" in checked({"kind": "invalid"})
    assert "runner_output_kind_mismatch" in checked(
        execution_policy.model_dump(mode="json", exclude_none=True)
    )

    selector_capability = capability.model_copy(
        update={
            "spec": capability.spec.model_copy(
                update={
                    "output_selector": OutcomeSelector(
                        json_pointer="/spec/state_id",
                        values={"projected-state": "success"},
                    )
                }
            )
        }
    )
    valid_output = state_document().model_dump(mode="json", exclude_none=True)
    assert not checked(valid_output, selector_capability)
    invalid_pointer = selector_capability.model_copy(
        update={
            "spec": selector_capability.spec.model_copy(
                update={
                    "output_selector": OutcomeSelector(
                        json_pointer="/missing", values={"value": "success"}
                    )
                }
            )
        }
    )
    assert "runner_output_selector_invalid" in checked(valid_output, invalid_pointer)
    assert "runner_output_selector_unrecognized" in checked(
        valid_output,
        selector_capability.model_copy(
            update={
                "spec": selector_capability.spec.model_copy(
                    update={
                        "output_selector": OutcomeSelector(
                            json_pointer="/spec/state_id", values={"other": "success"}
                        )
                    }
                )
            }
        ),
    )


def test_projection_reconstructs_exact_pointer_and_independent_approval() -> None:
    _, _, _, receipt = runner_fixture()
    projected = state_document()
    raw = canonical_bytes({"projected": projected.model_dump(mode="json", exclude_none=True)})
    raw_digest = digest_bytes(raw)
    source = SourceArtifactEnvelope(
        metadata=metadata("source-envelope"),
        spec=SourceArtifactSpec(
            raw_digest=raw_digest,
            byte_length=len(raw),
            media_type="application/json",
            source_system="runner",
            source_uri="urn:cpcf:runner:job-1:stdout",
            acquired_at=NOW,
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
        ),
    )
    pending = PendingProjection(
        metadata=metadata("pending"),
        spec=PendingProjectionSpec(
            projection_id="projection-1",
            runner_receipt_digest=document_digest(receipt),
            source_artifact_envelope_digest=document_digest(source),
            producer_principal_id="adapter-principal",
            raw_output_digest=raw_digest,
            json_pointer="/projected",
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
            projected_digest=document_digest(projected),
            changes_authoritative_state=True,
        ),
    )
    approval = ProjectionApproval(
        metadata=metadata("approval"),
        spec=ProjectionApprovalSpec(
            projection_digest=document_digest(pending),
            producer_principal_id="adapter-principal",
            verifier_principal_id="verifier-principal",
            approved_at=NOW,
        ),
    )
    result, reconstructed = reconstruct_projection(pending, approval, receipt, source, raw)
    assert result.promoted and reconstructed == projected
    corrupted, _ = reconstruct_projection(pending, approval, receipt, source, raw + b" ")
    assert not corrupted.promoted
    assert "projection_raw_output_digest_mismatch" in corrupted.reasons


def test_generation_ledger_and_optimistic_commit_are_closed() -> None:
    object_store = MemoryObjectStore()
    event = AuditEvent(
        metadata=metadata("event-1"),
        spec=AuditEventSpec(
            event_id="event-1",
            event_type="workspace_created",
            occurred_at=NOW,
        ),
    )
    event_bytes = canonical_bytes(event.model_dump(mode="json", exclude_none=True))
    event_digest = object_store.put("tenant-a", event_bytes)
    placeholder = WorkspaceGeneration(
        metadata=metadata("generation-0"),
        spec=WorkspaceGenerationSpec(
            generation_digest="sha256:" + "0" * 64,
            sequence=0,
            ledger=[
                LedgerEntry(
                    object_digest=event_digest,
                    object_kind="audit-event",
                    authority_status="active",
                )
            ],
            history_head_digest=event_digest,
        ),
    )
    generation = placeholder.model_copy(
        update={
            "spec": placeholder.spec.model_copy(
                update={"generation_digest": generation_digest(placeholder)}
            )
        }
    )
    assert not validate_ledger(generation, object_store)
    assert not validate_history([event], event_digest)
    repository = MemoryGenerationRepository()
    state = WorkspaceState(generation=generation, objects={event_digest: event})
    repository.create(state)
    with pytest.raises(ConcurrentGenerationError, match="workspace_generation_changed"):
        repository.commit(state, expected_generation_digest="sha256:" + "9" * 64)


def trial_fixture() -> tuple[MeasurementProtocol, dict[str, object], TrialResult]:
    objects: dict[str, object] = {}
    artifact_digests: dict[str, str] = {}
    for artifact_type, marker in (
        ("dataset", "1"),
        ("assignment", "2"),
        ("analysis-executable", "3"),
    ):
        item = ArtifactRecord(
            metadata=metadata(f"artifact-{artifact_type}"),
            spec=ArtifactRecordSpec(
                artifact_type=artifact_type,  # type: ignore[arg-type]
                artifact_digest="sha256:" + marker * 64,
                acquisition_committed_at=NOW - timedelta(days=2),
                source_system="trial-source",
            ),
        )
        digest = document_digest(item)
        objects[digest] = item
        artifact_digests[artifact_type] = digest
    protocol = MeasurementProtocol(
        metadata=metadata("protocol"),
        spec=MeasurementProtocolSpec(
            protocol_id="protocol-1",
            author_principal_id="author",
            registrar_principal_id="registrar",
            evaluator_principal_id="evaluator",
            quality_verifier_principal_id="quality-verifier",
            eligibility="Registered eligibility criteria.",
            treatment_strategy="CPCF-guided intervention.",
            comparison_strategy="Registered comparison strategy.",
            time_zero=NOW,
            observation_complete_at=NOW + timedelta(days=1),
            estimand="Difference in completion time while preserving quality.",
            outcomes=[
                OutcomeDefinition(
                    outcome_id="time-effect",
                    unit="second",
                    direction="lower",
                    minimum_effect="-1",
                    quality_floor="1",
                )
            ],
            multiplicity_policy="One primary outcome; no multiplicity adjustment required.",
            assignment_record_digest=artifact_digests["assignment"],
            dataset_record_digest=artifact_digests["dataset"],
            analysis_executable_record_digest=artifact_digests["analysis-executable"],
            missing_data_policy="Treat missing primary outcomes as unfavorable.",
            stopping_rule="Stop after the registered observation window.",
            exclusion_policy="No post-assignment exclusions.",
            primary_result_id="primary-result-1",
        ),
    )
    registration = QuorumDecisionDocument(
        metadata=metadata("registration"),
        spec=QuorumDecisionSpec(
            decision_type="protocol_registration",
            subject_digest=document_digest(protocol),
            statement_digests=["sha256:" + "4" * 64, "sha256:" + "5" * 64],
            decided_at=NOW - timedelta(hours=1),
        ),
    )
    objects[document_digest(registration)] = registration
    result = TrialResult(
        metadata=metadata("result"),
        spec=TrialResultSpec(
            primary_result_id="primary-result-1",
            protocol_digest=document_digest(protocol),
            dataset_record_digest=artifact_digests["dataset"],
            assignment_record_digest=artifact_digests["assignment"],
            analysis_executable_record_digest=artifact_digests["analysis-executable"],
            evaluator_principal_id="evaluator",
            observation_completed_at=NOW + timedelta(days=1),
            issued_at=NOW + timedelta(days=1, minutes=1),
            design="randomized",
            effects=[
                EffectInterval(outcome_id="time-effect", lower="-2", upper="-1", quality_value="1")
            ],
        ),
    )
    objects[document_digest(result)] = result
    return protocol, objects, result


def test_trial_retains_duplicate_primary_results_as_contradiction() -> None:
    protocol, raw_objects, result = trial_fixture()
    objects = {key: value for key, value in raw_objects.items()}  # type: ignore[misc]
    assessment = assess_trial(protocol, objects)  # type: ignore[arg-type]
    assert assessment.tier == "preregistered_randomized_acceleration_bundle_compatible"
    duplicate = result.model_copy(update={"metadata": metadata("result-duplicate")})
    objects[document_digest(duplicate)] = duplicate
    contradiction = assess_trial(protocol, objects)  # type: ignore[arg-type]
    assert contradiction.status == "protocol_deviation"
    assert "multiple_primary_results" in contradiction.contradictions


def test_trial_models_reject_role_collisions_and_duplicate_outcomes() -> None:
    protocol, _, result = trial_fixture()
    with pytest.raises(ValueError, match="author and registrar"):
        type(protocol.spec).model_validate(
            {
                **protocol.spec.model_dump(mode="json"),
                "registrar_principal_id": protocol.spec.author_principal_id,
            }
        )
    duplicate_effect = result.spec.effects[0]
    with pytest.raises(ValueError, match="outcome identifiers"):
        type(result.spec).model_validate(
            {
                **result.spec.model_dump(mode="json"),
                "effects": [
                    duplicate_effect.model_dump(mode="json"),
                    duplicate_effect.model_dump(mode="json"),
                ],
            }
        )


def test_api_requires_idempotency_generation_and_tenant_authority() -> None:
    backend = InMemoryBackend()
    principal = PrincipalContext(
        subject="user-a", tenant_id="tenant-a", roles=frozenset({"tenant_admin"})
    )
    app = create_app(
        backend=backend,
        authenticator=StaticAuthenticator(principal, "test-token"),
    )

    async def exercise() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://cpcf.test",
        ) as client:
            headers = {"Authorization": "Bearer test-token", "Idempotency-Key": "a" * 16}
            missing = await client.post(
                "/v1/workspaces/missing/analyses",
                json={},
                headers={**headers, "If-Match": "sha256:" + "0" * 64},
            )
            assert missing.status_code == 404
            assert missing.json()["code"] == "workspace_not_found"
            created = await client.post(
                "/v1/workspaces",
                json={"workspace_id": "workspace-a", **GENESIS_BODY},
                headers={**headers, "traceparent": "attacker-controlled-not-a-trace"},
            )
            assert created.status_code == 201
            body = created.json()
            assert len(body["trace_id"]) == 32
            assert set(body["trace_id"]) <= set("0123456789abcdef")
            replay = await client.post(
                "/v1/workspaces",
                json={"workspace_id": "workspace-a", **GENESIS_BODY},
                headers=headers,
            )
            assert replay.json() == body
            mismatched_replay = await client.post(
                "/v1/workspaces",
                json={"workspace_id": "workspace-b", **GENESIS_BODY},
                headers=headers,
            )
            assert mismatched_replay.status_code == 409
            assert (
                mismatched_replay.json()["code"] == "idempotency_key_reused_with_different_request"
            )
            failed = await client.post(
                "/v1/workspaces/workspace-a/analyses",
                json={},
                headers={
                    **headers,
                    "Idempotency-Key": "b" * 16,
                    "If-Match": "sha256:" + "0" * 64,
                },
            )
            assert failed.status_code == 412
            accepted = await client.post(
                "/v1/workspaces/workspace-a/analyses",
                json={},
                headers={
                    **headers,
                    "Idempotency-Key": "c" * 16,
                    "If-Match": body["generation_digest"],
                },
            )
            assert accepted.status_code == 202
            assert accepted.json()["code"] == "analysis_queued"
            backend.workspaces[("tenant-a", "workspace-a")].generation_digest = "sha256:" + "9" * 64
            replay_after_generation_change = await client.post(
                "/v1/workspaces/workspace-a/analyses",
                json={},
                headers={
                    **headers,
                    "Idempotency-Key": "c" * 16,
                    "If-Match": body["generation_digest"],
                },
            )
            assert replay_after_generation_change.json() == accepted.json()

    asyncio.run(exercise())


def test_rls_is_forced_and_s3_keys_reject_traversal() -> None:
    statements = rls_statements()
    assert all(
        any(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' == item for item in statements)
        for table in (
            "workspaces",
            "objects",
            "generations",
            "object_ledger",
            "audit_events",
            "quarantine",
            "outbox",
            "idempotency_keys",
        )
    )
    store = S3ObjectStore(object(), "bucket")
    with pytest.raises(ValueError, match="invalid_tenant_id"):
        store._key("../tenant", "sha256:" + "0" * 64)


def test_s3_store_fails_closed_on_access_denial_and_bounds_downloads() -> None:
    class ClientError(Exception):
        def __init__(self, code: str, status: int) -> None:
            self.response = {
                "Error": {"Code": code},
                "ResponseMetadata": {"HTTPStatusCode": status},
            }

    class Exceptions:
        pass

    Exceptions.ClientError = ClientError

    class DeniedClient:
        exceptions = Exceptions

        def head_object(self, **_: object) -> object:
            raise ClientError("AccessDenied", 403)

        def put_object(self, **_: object) -> object:
            raise ClientError("AccessDenied", 403)

    denied = S3ObjectStore(DeniedClient(), "bucket")
    with pytest.raises(ClientError):
        denied.exists("tenant-a", "sha256:" + "0" * 64)
    with pytest.raises(ClientError):
        denied.put("tenant-a", b"value")

    class Body:
        def read(self, amount: int) -> bytes:
            return b"x" * amount

    class OversizedClient:
        exceptions = Exceptions

        def get_object(self, **_: object) -> dict[str, object]:
            return {"ContentLength": 5, "Body": Body()}

    bounded = S3ObjectStore(OversizedClient(), "bucket", maximum_object_bytes=4)
    with pytest.raises(RuntimeError, match="output_too_large"):
        bounded.get("tenant-a", "sha256:" + "0" * 64)
