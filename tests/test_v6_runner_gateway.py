# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cpcf_api.runner_gateway import (
    InMemoryRunnerGateway,
    RunnerGatewayError,
    RunnerRegistration,
    RunnerTask,
    VerifiedStatement,
    _statement_subject,
    create_runner_app,
    parse_envoy_xfcc,
)
from cpcf_cli.main import main as cli_main

from collective_phase_control_fabric.v6.canonical import canonical_bytes
from collective_phase_control_fabric.v6.models import (
    BranchEffect,
    CapabilityDocument,
    CapabilitySpec,
    Document,
    ExecutionPolicy,
    ExecutionPolicySpec,
    Lifecycle,
    OutcomeName,
    PendingProjection,
    PendingProjectionSpec,
    RunnerJob,
    RunnerReceipt,
    RunnerReceiptSpec,
    SignedStatement,
    SignedStatementSpec,
    StateAttestation,
    StateSpec,
)
from collective_phase_control_fabric.v6.registry import document_digest, schema_digest
from collective_phase_control_fabric.v6.storage import MemoryObjectStore
from collective_phase_control_fabric.v6.trust import (
    build_protected_header,
    sign_document,
    verify_envelope,
)
from tests.v6_helpers import NOW, metadata, trust_fixture


class FixtureAuthority:
    def __init__(self) -> None:
        self.policy, self.trusted_time, self.keys = trust_fixture()

    def statement(
        self, document: Document, principal_index: int, role: str, key: str
    ) -> SignedStatement:
        principal = self.policy.spec.principals[principal_index]
        protected = build_protected_header(
            document,
            principal=principal,
            role=role,
            source_system="fixture-source",
            scope=["workspace-a"],
            signing_time=NOW,
            policy_sequence=0,
            trusted_time_receipt_digest=document_digest(self.trusted_time),
        )
        return SignedStatement(
            metadata=metadata(f"statement-{document.kind}-{document.metadata.object_id}-{role}"),
            spec=SignedStatementSpec(
                envelope=sign_document(document, private_key=self.keys[key], protected=protected)
            ),
        )

    def sign(self, job: RunnerJob) -> SignedStatement:
        return self.statement(job, 0, "job_dispatcher", "root")

    def verify(self, statement: SignedStatement, *, evaluated_at: datetime) -> VerifiedStatement:
        del evaluated_at
        result, _ = verify_envelope(
            statement.spec.envelope,
            self.policy,
            trusted_time=self.trusted_time,
        )
        if not result.valid or result.principal_id is None or result.role is None:
            raise RunnerGatewayError("runner_signed_statement_invalid")
        return VerifiedStatement(
            statement=statement,
            subject=_statement_subject(statement),
            principal_id=result.principal_id,
            role=result.role,
        )


class QuarantiningMemoryStore(MemoryObjectStore):
    def __init__(self) -> None:
        super().__init__()
        self.quarantined: list[tuple[str, str, str]] = []

    def quarantine_unreferenced(self, tenant_id: str, digest: str, reason: str) -> None:
        self.quarantined.append((tenant_id, digest, reason))


def branches() -> list[BranchEffect]:
    return [
        BranchEffect.model_validate(
            {"outcome": outcome, "resource_delta_lower": {}, "resource_delta_upper": {}}
        )
        for outcome in ("success", "partial", "failure", "timeout")
    ]


def runner_case() -> tuple[
    InMemoryRunnerGateway,
    FixtureAuthority,
    RunnerRegistration,
    QuarantiningMemoryStore,
]:
    store = QuarantiningMemoryStore()
    authority = FixtureAuthority()
    policy = ExecutionPolicy(
        metadata=metadata("gateway-policy"),
        spec=ExecutionPolicySpec(
            execution_policy_id="gateway-policy",
            allowed_image_digests=["sha256:" + "a" * 64],
            timeout_seconds=30,
            stdout_limit=1024,
            stderr_limit=1024,
            maximum_input_bytes=65_536,
            maximum_output_bytes=4096,
            network_policy="runner-attested",
            filesystem_policy="runner-attested",
        ),
    )
    material = store.put("tenant-a", b"material")
    input_digest = store.put("tenant-a", b"input")
    capability = CapabilityDocument(
        metadata=metadata("gateway-capability"),
        spec=CapabilitySpec(
            capability_id="gateway-capability",
            adapter_principal_id="root-principal",
            verifier_principal_id="auditor-principal",
            execution_policy_digest=document_digest(policy),
            image_digest="sha256:" + "a" * 64,
            material_digests=[material],
            argv=["/adapter/run"],
            output_schema_name="state-attestation",
            output_schema_digest=schema_digest("state-attestation"),
            return_code_outcomes={"0": "success"},
            repeatable=False,
            branches=branches(),
        ),
    )
    capability_statement = authority.statement(capability, 0, "capability_authority", "root")
    execution_policy_statement = authority.statement(
        policy, 1, "execution_policy_authority", "auditor"
    )
    for statement in (capability_statement, execution_policy_statement):
        stored = store.put(
            "tenant-a", canonical_bytes(statement.model_dump(mode="json", exclude_none=True))
        )
        assert stored == document_digest(statement)
    gateway = InMemoryRunnerGateway(object_store=store, signer=authority, verifier=authority)
    uri = "spiffe://runners.cpcf.test/tenant/tenant-a/runner/runner-a"
    registration = RunnerRegistration(
        tenant_id="tenant-a",
        runner_id="runner-a",
        principal_id="runner-principal",
        uri_san=uri,
        certificate_fingerprint="sha256:" + "1" * 64,
    )
    gateway.register(registration)
    gateway.dispatch(
        RunnerTask(
            tenant_id="tenant-a",
            workspace_id="workspace-a",
            job_id="job-a",
            action_digest="sha256:" + "b" * 64,
            generation_digest="sha256:" + "c" * 64,
            capability=capability,
            capability_statement=capability_statement,
            execution_policy=policy,
            execution_policy_statement=execution_policy_statement,
            input_digests=(input_digest,),
        ),
        admitted_at=NOW,
    )
    return gateway, authority, registration, store


def completion_bundle(
    gateway: InMemoryRunnerGateway,
    authority: FixtureAuthority,
    registration: RunnerRegistration,
    store: QuarantiningMemoryStore,
    *,
    output_bytes: bytes | None = None,
    return_code: int = 0,
    claimed_outcome: OutcomeName = "success",
) -> tuple[RunnerJob, SignedStatement, SignedStatement]:
    claim = asyncio.run(gateway.claim(registration, claimed_at=NOW))
    projected = StateAttestation(
        metadata=metadata("completion-bundle-output"),
        spec=StateSpec(
            state_id="completion-bundle-output",
            available=True,
            lifecycle=Lifecycle(
                valid_from=NOW - timedelta(days=1),
                valid_until=NOW + timedelta(days=1),
            ),
        ),
    )
    raw_output = output_bytes or canonical_bytes(
        projected.model_dump(mode="json", exclude_none=True)
    )
    stdout = store.put("tenant-a", b"completion-stdout")
    stderr = store.put("tenant-a", b"completion-stderr")
    output = store.put("tenant-a", raw_output)
    for digest in (stdout, stderr, output):
        asyncio.run(
            gateway.record_artifact(registration, claim.job.spec.lease_id, digest, received_at=NOW)
        )
    receipt = RunnerReceipt(
        metadata=metadata("completion-bundle-receipt"),
        spec=RunnerReceiptSpec(
            job_digest=document_digest(claim.job),
            job_id=claim.job.spec.job_id,
            attempt=claim.job.spec.attempt,
            lease_id=claim.job.spec.lease_id,
            runner_principal_id=registration.principal_id,
            image_digest=claim.job.spec.image_digest,
            material_digests=sorted(
                {
                    *claim.job.spec.input_digests,
                    *gateway.tasks[("tenant-a", "job-a")].task.capability.spec.material_digests,
                    claim.job.spec.capability_statement_digest,
                    claim.job.spec.execution_policy_statement_digest,
                }
            ),
            stdout_digest=stdout,
            stderr_digest=stderr,
            stdout_captured_bytes=len(b"completion-stdout"),
            stderr_captured_bytes=len(b"completion-stderr"),
            stdout_discarded_bytes=0,
            stderr_discarded_bytes=0,
            return_code=return_code,
            timeout=False,
            claimed_outcome=claimed_outcome,
            cleanup_complete=True,
            isolation_profile_digest="sha256:" + "d" * 64,
            output_digests=[output],
            started_at=NOW,
            completed_at=NOW,
        ),
    )
    receipt_statement = authority.statement(receipt, 3, "runner_receipt", "runner")
    pending = PendingProjection(
        metadata=metadata("completion-bundle-pending"),
        spec=PendingProjectionSpec(
            projection_id="completion-bundle-pending",
            runner_receipt_digest=document_digest(receipt),
            source_artifact_envelope_digest="sha256:" + "e" * 64,
            producer_principal_id="root-principal",
            raw_output_digest=output,
            json_pointer="",
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
            projected_digest=document_digest(projected),
            changes_authoritative_state=True,
        ),
    )
    pending_statement = authority.statement(pending, 0, "projection_authority", "root")
    return claim.job, receipt_statement, pending_statement


def test_envoy_identity_is_exact_and_registration_is_pinned() -> None:
    gateway, _, registration, _ = runner_case()
    header = "Hash=" + "1" * 64 + ";URI=spiffe://runners.cpcf.test/tenant/tenant-a/runner/runner-a"
    identity = parse_envoy_xfcc(header, expected_trust_domain="runners.cpcf.test")
    assert gateway.authenticate(identity) == registration
    for invalid in (
        "",
        header + ",Hash=" + "2" * 64,
        header + ";Hash=" + "2" * 64,
        header.replace("runners.cpcf.test", "other.example"),
        header.replace("1" * 64, "not-a-hash"),
    ):
        with pytest.raises(RunnerGatewayError):
            parse_envoy_xfcc(invalid, expected_trust_domain="runners.cpcf.test")
    with pytest.raises(RunnerGatewayError, match="runner_identity_not_registered"):
        gateway.authenticate(replace(identity, fingerprint="sha256:" + "2" * 64))
    with pytest.raises(RunnerGatewayError, match="runner_registration_duplicate"):
        gateway.register(registration)


def test_runner_claim_heartbeat_completion_and_pending_projection() -> None:
    gateway, authority, registration, store = runner_case()
    claim = asyncio.run(gateway.claim(registration, claimed_at=NOW))
    assert _statement_subject(claim.job_statement) == claim.job
    asyncio.run(
        gateway.heartbeat(
            registration,
            claim.job.spec.lease_id,
            1,
            received_at=NOW,
        )
    )
    stdout = store.put("tenant-a", b"stdout")
    stderr = store.put("tenant-a", b"stderr")
    projected = StateAttestation(
        metadata=metadata("runner-output-state"),
        spec=StateSpec(
            state_id="runner-output-state",
            available=True,
            lifecycle=Lifecycle(
                valid_from=NOW - timedelta(days=1),
                valid_until=NOW + timedelta(days=1),
            ),
        ),
    )
    output = store.put(
        "tenant-a", canonical_bytes(projected.model_dump(mode="json", exclude_none=True))
    )
    for digest in (stdout, stderr, output):
        asyncio.run(
            gateway.record_artifact(
                registration,
                claim.job.spec.lease_id,
                digest,
                received_at=NOW,
            )
        )
    materials = sorted(
        set(claim.job.spec.input_digests)
        | set(gateway.tasks[("tenant-a", "job-a")].task.capability.spec.material_digests)
        | {
            claim.job.spec.capability_statement_digest,
            claim.job.spec.execution_policy_statement_digest,
        }
    )
    receipt = RunnerReceipt(
        metadata=metadata("gateway-receipt"),
        spec=RunnerReceiptSpec(
            job_digest=document_digest(claim.job),
            job_id=claim.job.spec.job_id,
            attempt=claim.job.spec.attempt,
            lease_id=claim.job.spec.lease_id,
            runner_principal_id="runner-principal",
            image_digest=claim.job.spec.image_digest,
            material_digests=materials,
            stdout_digest=stdout,
            stderr_digest=stderr,
            stdout_captured_bytes=len(b"stdout"),
            stderr_captured_bytes=len(b"stderr"),
            stdout_discarded_bytes=0,
            stderr_discarded_bytes=0,
            return_code=0,
            timeout=False,
            claimed_outcome="success",
            cleanup_complete=True,
            isolation_profile_digest="sha256:" + "d" * 64,
            output_digests=[output],
            started_at=NOW,
            completed_at=NOW,
        ),
    )
    receipt_statement = authority.statement(receipt, 3, "runner_receipt", "runner")
    pending = PendingProjection(
        metadata=metadata("gateway-pending"),
        spec=PendingProjectionSpec(
            projection_id="gateway-pending",
            runner_receipt_digest=document_digest(receipt),
            source_artifact_envelope_digest="sha256:" + "e" * 64,
            producer_principal_id="root-principal",
            raw_output_digest=output,
            json_pointer="",
            expected_schema_name="state-attestation",
            expected_schema_digest=schema_digest("state-attestation"),
            projected_digest=document_digest(projected),
            changes_authoritative_state=True,
        ),
    )
    pending_statement = authority.statement(pending, 0, "projection_authority", "root")
    completed = asyncio.run(
        gateway.complete(
            registration,
            claim.job.spec.lease_id,
            receipt_statement,
            [pending_statement],
            received_at=NOW,
        )
    )
    assert completed.conformance.accepted
    assert completed.pending_projection_statement_digests == (document_digest(pending_statement),)
    with pytest.raises(RunnerGatewayError, match="runner_lease_stale"):
        asyncio.run(
            gateway.complete(
                registration,
                claim.job.spec.lease_id,
                receipt_statement,
                [],
                received_at=NOW,
            )
        )


def test_runner_completion_rejects_unbound_receipts_outputs_and_projections() -> None:
    missing_job, authority, registration, _ = runner_case()
    missing_claim = asyncio.run(missing_job.claim(registration, claimed_at=NOW))
    missing_job.tasks[("tenant-a", "job-a")].job = None
    with pytest.raises(RunnerGatewayError, match="runner_job_not_bound"):
        asyncio.run(
            missing_job.complete(
                registration,
                missing_claim.job.spec.lease_id,
                missing_job.tasks[("tenant-a", "job-a")].task.capability_statement,
                [],
                received_at=NOW,
            )
        )

    invalid_signature, authority, registration, store = runner_case()
    job, receipt_statement, pending_statement = completion_bundle(
        invalid_signature, authority, registration, store
    )
    with pytest.raises(RunnerGatewayError, match="runner_receipt_signature_invalid"):
        asyncio.run(
            invalid_signature.complete(
                registration,
                job.spec.lease_id,
                pending_statement,
                [],
                received_at=NOW,
            )
        )

    invalid_output, authority, registration, store = runner_case()
    job, receipt_statement, _ = completion_bundle(
        invalid_output,
        authority,
        registration,
        store,
        output_bytes=b"not-json",
    )
    with pytest.raises(RunnerGatewayError, match="runner_selector_output_invalid"):
        asyncio.run(
            invalid_output.complete(
                registration,
                job.spec.lease_id,
                receipt_statement,
                [],
                received_at=NOW,
            )
        )

    nonconformant, authority, registration, store = runner_case()
    job, receipt_statement, _ = completion_bundle(nonconformant, authority, registration, store)
    receipt = _statement_subject(receipt_statement)
    assert isinstance(receipt, RunnerReceipt)
    forged = receipt.model_copy(
        update={"spec": receipt.spec.model_copy(update={"claimed_outcome": "failure"})}
    )
    forged_statement = authority.statement(forged, 3, "runner_receipt", "runner")
    with pytest.raises(RunnerGatewayError, match="runner_receipt_nonconformant"):
        asyncio.run(
            nonconformant.complete(
                registration,
                job.spec.lease_id,
                forged_statement,
                [],
                received_at=NOW,
            )
        )

    invalid_projection, authority, registration, store = runner_case()
    job, receipt_statement, pending_statement = completion_bundle(
        invalid_projection, authority, registration, store
    )
    with pytest.raises(RunnerGatewayError, match="runner_pending_projection_invalid"):
        asyncio.run(
            invalid_projection.complete(
                registration,
                job.spec.lease_id,
                receipt_statement,
                [receipt_statement],
                received_at=NOW,
            )
        )
    with pytest.raises(RunnerGatewayError, match="runner_pending_projection_duplicate"):
        asyncio.run(
            invalid_projection.complete(
                registration,
                job.spec.lease_id,
                receipt_statement,
                [pending_statement, pending_statement],
                received_at=NOW,
            )
        )

    failure_projection, authority, registration, store = runner_case()
    job, receipt_statement, pending_statement = completion_bundle(
        failure_projection,
        authority,
        registration,
        store,
        return_code=1,
        claimed_outcome="failure",
    )
    with pytest.raises(RunnerGatewayError, match="runner_failure_projection_rejected"):
        asyncio.run(
            failure_projection.complete(
                registration,
                job.spec.lease_id,
                receipt_statement,
                [pending_statement],
                received_at=NOW,
            )
        )


def test_runner_rejects_stale_lease_replay_and_missing_materials() -> None:
    gateway, _, registration, store = runner_case()
    claim = asyncio.run(gateway.claim(registration, claimed_at=NOW))
    with pytest.raises(RunnerGatewayError, match="runner_heartbeat_sequence_invalid"):
        asyncio.run(
            gateway.heartbeat(
                registration,
                claim.job.spec.lease_id,
                2,
                received_at=NOW,
            )
        )
    with pytest.raises(RunnerGatewayError, match="runner_lease_stale"):
        asyncio.run(
            gateway.record_artifact(
                registration,
                claim.job.spec.lease_id,
                store.put("tenant-a", b"late"),
                received_at=NOW + timedelta(minutes=2),
            )
        )
    with pytest.raises(RunnerGatewayError, match="runner_certificate_binding_duplicate"):
        gateway.register(replace(registration, runner_id="runner-b"))

    missing_store = MemoryObjectStore()
    missing_gateway = InMemoryRunnerGateway(
        object_store=missing_store,
        signer=gateway.signer,
        verifier=gateway.verifier,
    )
    task = gateway.tasks[("tenant-a", "job-a")].task
    with pytest.raises(RunnerGatewayError, match="runner_material_missing"):
        missing_gateway.dispatch(task, admitted_at=NOW)


def test_runner_dispatch_requires_distinct_signed_capability_authorities() -> None:
    gateway, authority, registration, store = runner_case()
    task = gateway.tasks[("tenant-a", "job-a")].task
    replacement = authority.statement(task.capability, 0, "job_dispatcher", "root")
    store.put("tenant-a", canonical_bytes(replacement.model_dump(mode="json", exclude_none=True)))
    other = InMemoryRunnerGateway(object_store=store, signer=authority, verifier=authority)
    other.register(registration)
    with pytest.raises(RunnerGatewayError, match="runner_capability_authority_invalid"):
        other.dispatch(replace(task, capability_statement=replacement), admitted_at=NOW)

    invalid_policy_statement = authority.statement(
        task.execution_policy, 0, "job_dispatcher", "root"
    )
    store.put(
        "tenant-a",
        canonical_bytes(invalid_policy_statement.model_dump(mode="json", exclude_none=True)),
    )
    policy_gateway = InMemoryRunnerGateway(object_store=store, signer=authority, verifier=authority)
    policy_gateway.register(registration)
    with pytest.raises(RunnerGatewayError, match="runner_execution_policy_authority_invalid"):
        policy_gateway.dispatch(
            replace(task, execution_policy_statement=invalid_policy_statement),
            admitted_at=NOW,
        )

    other.dispatch(task, admitted_at=NOW)
    with pytest.raises(RunnerGatewayError, match="runner_job_duplicate"):
        other.dispatch(task, admitted_at=NOW)


def test_runner_task_and_lease_limits_fail_closed() -> None:
    gateway, authority, registration, store = runner_case()
    task = gateway.tasks[("tenant-a", "job-a")].task
    with pytest.raises(ValueError, match="runner lease"):
        replace(task, lease_seconds=0)
    with pytest.raises(ValueError, match="input digests must be unique"):
        replace(task, input_digests=(task.input_digests[0],) * 2)
    with pytest.raises(ValueError, match="capability policy binding"):
        replace(
            task,
            capability=task.capability.model_copy(
                update={
                    "spec": task.capability.spec.model_copy(
                        update={"execution_policy_digest": "sha256:" + "0" * 64}
                    )
                }
            ),
        )
    with pytest.raises(ValueError, match="tenant or workspace binding"):
        replace(task, tenant_id="tenant-other")
    with pytest.raises(ValueError, match="image is not allowed"):
        replace(
            task,
            execution_policy=task.execution_policy.model_copy(
                update={
                    "spec": task.execution_policy.spec.model_copy(
                        update={"allowed_image_digests": ["sha256:" + "9" * 64]}
                    )
                }
            ),
            capability=task.capability.model_copy(
                update={
                    "spec": task.capability.spec.model_copy(
                        update={
                            "execution_policy_digest": document_digest(
                                task.execution_policy.model_copy(
                                    update={
                                        "spec": task.execution_policy.spec.model_copy(
                                            update={"allowed_image_digests": ["sha256:" + "9" * 64]}
                                        )
                                    }
                                )
                            )
                        }
                    )
                }
            ),
        )

    huge = store.put("tenant-a", b"x" * 65_537)
    limited = InMemoryRunnerGateway(object_store=store, signer=authority, verifier=authority)
    limited.register(registration)
    with pytest.raises(RunnerGatewayError, match="runner_material_limit_exceeded"):
        limited.dispatch(replace(task, input_digests=(huge,)), admitted_at=NOW)

    empty = InMemoryRunnerGateway(object_store=store, signer=authority, verifier=authority)
    empty.register(registration)
    with pytest.raises(RunnerGatewayError, match="runner_job_not_available"):
        asyncio.run(empty.claim(registration, claimed_at=NOW))
    gateway.tasks[("tenant-a", "job-a")].attempt = 32
    with pytest.raises(RunnerGatewayError, match="runner_attempt_limit_exhausted"):
        asyncio.run(gateway.claim(registration, claimed_at=NOW))


def test_runner_internal_state_rejects_missing_and_excess_artifacts() -> None:
    gateway, _, registration, store = runner_case()
    claim = asyncio.run(gateway.claim(registration, claimed_at=NOW))
    with pytest.raises(RunnerGatewayError, match="runner_lease_not_found"):
        asyncio.run(
            gateway.record_artifact(
                registration, "unknown-lease", "sha256:" + "0" * 64, received_at=NOW
            )
        )
    with pytest.raises(RunnerGatewayError, match="runner_artifact_missing_after_upload"):
        asyncio.run(
            gateway.record_artifact(
                registration,
                claim.job.spec.lease_id,
                "sha256:" + "0" * 64,
                received_at=NOW,
            )
        )
    oversized = store.put("tenant-a", b"y" * 4097)
    with pytest.raises(RunnerGatewayError, match="runner_artifact_limit_exceeded"):
        asyncio.run(
            gateway.record_artifact(
                registration, claim.job.spec.lease_id, oversized, received_at=NOW
            )
        )
    state = gateway.tasks[("tenant-a", "job-a")]
    state.artifact_digests = {f"sha256:{value:064x}" for value in range(10_002)}
    assert (
        asyncio.run(
            gateway.remaining_artifact_bytes(
                registration, claim.job.spec.lease_id, evaluated_at=NOW
            )
        )
        == 0
    )


def test_runner_signed_statement_parser_and_disabled_registration_fail_closed() -> None:
    with pytest.raises(ValueError, match="runner_gateway_error_code_unregistered"):
        RunnerGatewayError("unregistered")
    gateway, authority, registration, _ = runner_case()
    statement = gateway.tasks[("tenant-a", "job-a")].task.capability_statement
    malformed = statement.model_copy(
        update={
            "spec": statement.spec.model_copy(
                update={
                    "envelope": statement.spec.envelope.model_copy(update={"payload": "not-base64"})
                }
            )
        }
    )
    with pytest.raises(RunnerGatewayError, match="runner_signed_statement_invalid"):
        _statement_subject(malformed)
    malformed_gateway = InMemoryRunnerGateway(
        object_store=gateway.object_store, signer=authority, verifier=authority
    )
    malformed_gateway.register(registration)
    with pytest.raises(RunnerGatewayError, match="runner_capability_authority_invalid"):
        malformed_gateway.dispatch(
            replace(
                gateway.tasks[("tenant-a", "job-a")].task,
                capability_statement=malformed,
            ),
            admitted_at=NOW,
        )
    disabled = replace(registration, enabled=False)
    other = InMemoryRunnerGateway(
        object_store=gateway.object_store, signer=authority, verifier=authority
    )
    other.register(disabled)
    identity = parse_envoy_xfcc(
        "Hash=" + "1" * 64 + ";URI=" + registration.uri_san,
        expected_trust_domain="runners.cpcf.test",
    )
    with pytest.raises(RunnerGatewayError, match="runner_identity_not_registered"):
        other.authenticate(identity)


def test_runner_failed_job_signature_rolls_back_attempt() -> None:
    gateway, authority, registration, store = runner_case()
    task = gateway.tasks[("tenant-a", "job-a")].task

    class FailingSigner:
        def sign(self, job: RunnerJob) -> SignedStatement:
            del job
            raise RuntimeError("signer unavailable")

    failing = InMemoryRunnerGateway(object_store=store, signer=FailingSigner(), verifier=authority)
    failing.register(registration)
    failing.dispatch(task, admitted_at=NOW)
    with pytest.raises(RunnerGatewayError, match="runner_job_signature_invalid"):
        asyncio.run(failing.claim(registration, claimed_at=NOW))
    state = failing.tasks[("tenant-a", "job-a")]
    assert state.status == "queued"
    assert state.attempt == 0
    assert state.lease_id is None

    class WrongRoleSigner:
        def sign(self, job: RunnerJob) -> SignedStatement:
            return authority.statement(job, 0, "projection_authority", "root")

    wrong = InMemoryRunnerGateway(object_store=store, signer=WrongRoleSigner(), verifier=authority)
    wrong.register(registration)
    wrong.dispatch(task, admitted_at=NOW)
    with pytest.raises(RunnerGatewayError, match="runner_job_signature_invalid"):
        asyncio.run(wrong.claim(registration, claimed_at=NOW))


def test_runner_failed_artifact_admission_is_quarantined() -> None:
    gateway, _, registration, store = runner_case()
    claim = asyncio.run(gateway.claim(registration, claimed_at=NOW))
    moments = iter((NOW, NOW + timedelta(minutes=2)))
    app = create_runner_app(
        gateway,
        store,
        expected_trust_domain="runners.cpcf.test",
        clock=lambda: next(moments),
    )
    xfcc = "Hash=" + "1" * 64 + ";URI=" + registration.uri_san
    artifact = b"orphaned-after-lease-expiry"
    digest = hashlib.sha256(artifact).hexdigest()

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://runner.test"
        ) as client:
            response = await client.put(
                f"/v1/runner/leases/{claim.job.spec.lease_id}/artifacts/sha256/{digest}",
                content=artifact,
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "q" * 16,
                },
            )
            assert response.status_code == 409
            assert response.json()["code"] == "runner_lease_stale"

    asyncio.run(exercise())
    assert store.quarantined == [
        (
            "tenant-a",
            "sha256:" + digest,
            "runner_artifact_admission_failed",
        )
    ]


def test_runner_api_rejects_invalid_identity_digest_and_artifact_budgets() -> None:
    gateway, _, registration, store = runner_case()
    claim = asyncio.run(gateway.claim(registration, claimed_at=NOW))
    app = create_runner_app(
        gateway,
        store,
        expected_trust_domain="runners.cpcf.test",
        clock=lambda: NOW,
    )
    xfcc = "Hash=" + "1" * 64 + ";URI=" + registration.uri_san

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://runner.test"
        ) as client:
            live = await client.get(
                "/health/live",
                headers={"traceparent": "00-" + "1" * 32 + "-" + "2" * 16 + "-01"},
            )
            assert live.json()["trace_id"] == "1" * 32
            invalid_identity = await client.post(
                "/v1/runner/leases/claim",
                headers={
                    "X-Forwarded-Client-Cert": xfcc.replace("1" * 64, "2" * 64),
                    "Idempotency-Key": "i" * 16,
                },
            )
            assert invalid_identity.status_code == 401
            invalid_digest = await client.put(
                f"/v1/runner/leases/{claim.job.spec.lease_id}/artifacts/sha256/not-a-digest",
                content=b"x",
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "d" * 16,
                },
            )
            assert invalid_digest.status_code == 422
            mismatch = await client.put(
                f"/v1/runner/leases/{claim.job.spec.lease_id}/artifacts/sha256/{'0' * 64}",
                content=b"x",
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "m" * 16,
                },
            )
            assert mismatch.status_code == 422
            state = gateway.tasks[("tenant-a", "job-a")]
            state.task = replace(
                state.task,
                execution_policy=state.task.execution_policy.model_copy(
                    update={
                        "spec": state.task.execution_policy.spec.model_copy(
                            update={"maximum_output_bytes": 1}
                        )
                    }
                ),
                capability=state.task.capability.model_copy(
                    update={
                        "spec": state.task.capability.spec.model_copy(
                            update={
                                "execution_policy_digest": document_digest(
                                    state.task.execution_policy.model_copy(
                                        update={
                                            "spec": state.task.execution_policy.spec.model_copy(
                                                update={"maximum_output_bytes": 1}
                                            )
                                        }
                                    )
                                )
                            }
                        )
                    }
                ),
            )
            oversized_body = b"xx"
            oversized = await client.put(
                f"/v1/runner/leases/{claim.job.spec.lease_id}/artifacts/sha256/"
                f"{hashlib.sha256(oversized_body).hexdigest()}",
                content=oversized_body,
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "o" * 16,
                },
            )
            assert oversized.status_code == 413
            state.artifact_digests = {f"sha256:{value:064x}" for value in range(10_002)}
            exhausted = await client.put(
                f"/v1/runner/leases/{claim.job.spec.lease_id}/artifacts/sha256/"
                f"{hashlib.sha256(b'x').hexdigest()}",
                content=b"x",
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "e" * 16,
                },
            )
            assert exhausted.status_code == 413

    asyncio.run(exercise())


def test_runner_api_detects_object_store_digest_invariant_failure() -> None:
    gateway, _, registration, store = runner_case()
    claim = asyncio.run(gateway.claim(registration, claimed_at=NOW))

    class CollisionStore:
        def put(self, tenant_id: str, data: bytes) -> str:
            del tenant_id, data
            return "sha256:" + "0" * 64

        def get(self, tenant_id: str, digest: str) -> bytes:
            return store.get(tenant_id, digest)

        def exists(self, tenant_id: str, digest: str) -> bool:
            return store.exists(tenant_id, digest)

    app = create_runner_app(
        gateway,
        CollisionStore(),
        expected_trust_domain="runners.cpcf.test",
        clock=lambda: NOW,
    )
    xfcc = "Hash=" + "1" * 64 + ";URI=" + registration.uri_san
    artifact = b"collision"

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://runner.test"
        ) as client:
            response = await client.put(
                f"/v1/runner/leases/{claim.job.spec.lease_id}/artifacts/sha256/"
                f"{hashlib.sha256(artifact).hexdigest()}",
                content=artifact,
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "c" * 16,
                },
            )
            assert response.status_code == 409
            assert response.json()["code"] == "runner_artifact_storage_invariant_failed"

    asyncio.run(exercise())


def test_runner_api_requires_sanitized_mtls_identity_and_idempotency() -> None:
    gateway, authority, _, store = runner_case()
    app = create_runner_app(
        gateway,
        store,
        expected_trust_domain="runners.cpcf.test",
        clock=lambda: NOW,
    )
    xfcc = "Hash=" + "1" * 64 + ";URI=spiffe://runners.cpcf.test/tenant/tenant-a/runner/runner-a"

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://runner.test"
        ) as client:
            missing = await client.post(
                "/v1/runner/leases/claim", headers={"Idempotency-Key": "m" * 16}
            )
            assert missing.status_code == 422
            claimed = await client.post(
                "/v1/runner/leases/claim",
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "c" * 16,
                },
            )
            assert claimed.status_code == 200
            job = RunnerJob.model_validate(claimed.json()["claims"]["job"])
            replay = await client.post(
                "/v1/runner/leases/claim",
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "c" * 16,
                },
            )
            assert replay.json()["claims"]["job"]["spec"]["lease_id"] == job.spec.lease_id
            heartbeat = await client.post(
                f"/v1/runner/leases/{job.spec.lease_id}/heartbeat",
                json={"sequence": 1},
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "h" * 16,
                },
            )
            assert heartbeat.status_code == 200
            conflict = await client.post(
                f"/v1/runner/leases/{job.spec.lease_id}/heartbeat",
                json={"sequence": 2},
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "h" * 16,
                },
            )
            assert conflict.status_code == 409
            artifact = b"runner-output"
            digest = hashlib.sha256(artifact).hexdigest()
            uploaded = await client.put(
                f"/v1/runner/leases/{job.spec.lease_id}/artifacts/sha256/{digest}",
                content=artifact,
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "a" * 16,
                },
            )
            assert uploaded.status_code == 200
            assert uploaded.json()["objects_written"] == ["sha256:" + digest]

            projected = StateAttestation(
                metadata=metadata("api-runner-output"),
                spec=StateSpec(
                    state_id="api-runner-output",
                    available=True,
                    lifecycle=Lifecycle(
                        valid_from=NOW - timedelta(days=1),
                        valid_until=NOW + timedelta(days=1),
                    ),
                ),
            )
            artifacts = {
                "stdout": b"stdout-api",
                "stderr": b"stderr-api",
                "output": canonical_bytes(projected.model_dump(mode="json", exclude_none=True)),
            }
            digests: dict[str, str] = {}
            for name, value in artifacts.items():
                value_digest = hashlib.sha256(value).hexdigest()
                response = await client.put(
                    f"/v1/runner/leases/{job.spec.lease_id}/artifacts/sha256/{value_digest}",
                    content=value,
                    headers={
                        "X-Forwarded-Client-Cert": xfcc,
                        "Idempotency-Key": (name + "x" * 16)[:16],
                    },
                )
                assert response.status_code == 200
                digests[name] = "sha256:" + value_digest
            receipt = RunnerReceipt(
                metadata=metadata("api-runner-receipt"),
                spec=RunnerReceiptSpec(
                    job_digest=document_digest(job),
                    job_id=job.spec.job_id,
                    attempt=job.spec.attempt,
                    lease_id=job.spec.lease_id,
                    runner_principal_id="runner-principal",
                    image_digest=job.spec.image_digest,
                    material_digests=sorted(
                        {
                            *job.spec.input_digests,
                            *gateway.tasks[
                                ("tenant-a", "job-a")
                            ].task.capability.spec.material_digests,
                            job.spec.capability_statement_digest,
                            job.spec.execution_policy_statement_digest,
                        }
                    ),
                    stdout_digest=digests["stdout"],
                    stderr_digest=digests["stderr"],
                    stdout_captured_bytes=len(artifacts["stdout"]),
                    stderr_captured_bytes=len(artifacts["stderr"]),
                    stdout_discarded_bytes=0,
                    stderr_discarded_bytes=0,
                    return_code=0,
                    timeout=False,
                    claimed_outcome="success",
                    cleanup_complete=True,
                    isolation_profile_digest="sha256:" + "d" * 64,
                    output_digests=[digests["output"]],
                    started_at=NOW,
                    completed_at=NOW,
                ),
            )
            receipt_statement = authority.statement(receipt, 3, "runner_receipt", "runner")
            pending = PendingProjection(
                metadata=metadata("api-pending-projection"),
                spec=PendingProjectionSpec(
                    projection_id="api-pending-projection",
                    runner_receipt_digest=document_digest(receipt),
                    source_artifact_envelope_digest="sha256:" + "e" * 64,
                    producer_principal_id="root-principal",
                    raw_output_digest=digests["output"],
                    json_pointer="",
                    expected_schema_name="state-attestation",
                    expected_schema_digest=schema_digest("state-attestation"),
                    projected_digest=document_digest(projected),
                    changes_authoritative_state=True,
                ),
            )
            pending_statement = authority.statement(pending, 0, "projection_authority", "root")
            completed = await client.post(
                f"/v1/runner/leases/{job.spec.lease_id}/complete",
                json={
                    "receipt_statement": receipt_statement.model_dump(
                        mode="json", exclude_none=True
                    ),
                    "projection_statements": [
                        pending_statement.model_dump(mode="json", exclude_none=True)
                    ],
                },
                headers={
                    "X-Forwarded-Client-Cert": xfcc,
                    "Idempotency-Key": "z" * 16,
                },
            )
            assert completed.status_code == 200
            assert completed.json()["code"] == "runner_receipt_recorded_pending_projection"
            assert completed.json()["unknowns"] == ["projection_requires_independent_approval"]

    asyncio.run(exercise())


def test_runner_cli_conformance_uses_digest_bound_local_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gateway, authority, registration, store = runner_case()
    job, receipt_statement, _ = completion_bundle(gateway, authority, registration, store)
    receipt = _statement_subject(receipt_statement)
    assert isinstance(receipt, RunnerReceipt)
    task = gateway.tasks[("tenant-a", "job-a")].task
    documents = {
        "job": job,
        "receipt": receipt,
        "capability": task.capability,
        "execution-policy": task.execution_policy,
    }
    paths: dict[str, Path] = {}
    for name, document in documents.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(canonical_bytes(document.model_dump(mode="json", exclude_none=True)))
        paths[name] = path
    bindings: list[str] = []
    for index, digest in enumerate(
        sorted(
            {
                *receipt.spec.material_digests,
                receipt.spec.stdout_digest,
                receipt.spec.stderr_digest,
                *receipt.spec.output_digests,
            }
        )
    ):
        path = tmp_path / f"artifact-{index}.bin"
        path.write_bytes(store.get("tenant-a", digest))
        bindings.extend(["--artifact", f"{digest}={path}"])
    result = cli_main(
        [
            "runner",
            "conformance",
            str(paths["job"]),
            str(paths["receipt"]),
            str(paths["capability"]),
            str(paths["execution-policy"]),
            "--runner-principal",
            registration.principal_id,
            "--received-at",
            NOW.isoformat(),
            *bindings,
            "--json",
        ]
    )
    assert result == 0
    assert json.loads(capsys.readouterr().out)["code"] == "runner_receipt_conformant"
