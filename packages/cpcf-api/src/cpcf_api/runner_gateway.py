# SPDX-License-Identifier: Apache-2.0
"""Outbound runner lease service behind an identity-sanitizing mTLS gateway."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from collective_phase_control_fabric.v6.canonical import canonical_bytes, loads_bounded
from collective_phase_control_fabric.v6.catalog import RUNNER_GATEWAY_ERROR_CODES
from collective_phase_control_fabric.v6.models import (
    CapabilityDocument,
    Document,
    ExecutionPolicy,
    PendingProjection,
    RunnerJob,
    RunnerJobSpec,
    RunnerReceipt,
    SignedPayload,
    SignedStatement,
)
from collective_phase_control_fabric.v6.registry import document_digest, parse_document
from collective_phase_control_fabric.v6.runner import RunnerConformance, validate_receipt
from collective_phase_control_fabric.v6.storage import ObjectStore

XFCC_LIMIT = 4096
SPIFFE_PATTERN = re.compile(
    r"^spiffe://(?P<trust_domain>[a-z0-9.-]{1,253})/tenant/"
    r"(?P<tenant>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})/runner/"
    r"(?P<runner>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})$"
)
HASH_PATTERN = re.compile(r"^[0-9A-Fa-f]{64}$")


class RunnerGatewayError(RuntimeError):
    """Stable fail-closed runner transport error."""

    def __init__(self, code: str) -> None:
        if code not in RUNNER_GATEWAY_ERROR_CODES:
            raise ValueError("runner_gateway_error_code_unregistered")
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CertificateIdentity:
    tenant_id: str
    runner_id: str
    uri_san: str
    fingerprint: str
    trust_domain: str


def parse_envoy_xfcc(value: str, *, expected_trust_domain: str) -> CertificateIdentity:
    """Parse the single sanitized XFCC element produced by the CPCF Envoy configuration."""

    if not value or len(value) > XFCC_LIMIT or "," in value:
        raise RunnerGatewayError("runner_certificate_header_invalid")
    fields: dict[str, str] = {}
    for component in value.split(";"):
        key, separator, raw = component.partition("=")
        if not separator or key not in {"Hash", "URI"} or key in fields:
            raise RunnerGatewayError("runner_certificate_header_invalid")
        fields[key] = raw.strip('"')
    if set(fields) != {"Hash", "URI"} or HASH_PATTERN.fullmatch(fields["Hash"]) is None:
        raise RunnerGatewayError("runner_certificate_header_invalid")
    match = SPIFFE_PATTERN.fullmatch(fields["URI"])
    if match is None or match.group("trust_domain") != expected_trust_domain:
        raise RunnerGatewayError("runner_certificate_identity_untrusted")
    return CertificateIdentity(
        tenant_id=match.group("tenant"),
        runner_id=match.group("runner"),
        uri_san=fields["URI"],
        fingerprint="sha256:" + fields["Hash"].lower(),
        trust_domain=match.group("trust_domain"),
    )


@dataclass(frozen=True)
class RunnerRegistration:
    tenant_id: str
    runner_id: str
    principal_id: str
    uri_san: str
    certificate_fingerprint: str
    enabled: bool = True


@dataclass(frozen=True)
class VerifiedStatement:
    statement: SignedStatement
    subject: Document
    principal_id: str
    role: str


class StatementVerifier(Protocol):
    def verify(
        self, statement: SignedStatement, *, evaluated_at: datetime
    ) -> VerifiedStatement: ...


class JobSigner(Protocol):
    def sign(self, job: RunnerJob) -> SignedStatement: ...


@dataclass(frozen=True)
class RunnerTask:
    tenant_id: str
    workspace_id: str
    job_id: str
    action_digest: str
    generation_digest: str
    capability: CapabilityDocument
    capability_statement: SignedStatement
    execution_policy: ExecutionPolicy
    execution_policy_statement: SignedStatement
    input_digests: tuple[str, ...]
    lease_seconds: int = 60

    def __post_init__(self) -> None:
        if not 1 <= self.lease_seconds <= 300:
            raise ValueError("runner lease must be between 1 and 300 seconds")
        if len(self.input_digests) != len(set(self.input_digests)):
            raise ValueError("runner task input digests must be unique")
        if self.capability.spec.execution_policy_digest != document_digest(self.execution_policy):
            raise ValueError("runner task capability policy binding mismatch")
        if (
            self.capability.metadata.tenant_id != self.tenant_id
            or self.execution_policy.metadata.tenant_id != self.tenant_id
            or self.capability.metadata.workspace_id != self.workspace_id
            or self.execution_policy.metadata.workspace_id != self.workspace_id
        ):
            raise ValueError("runner task tenant or workspace binding mismatch")
        if (
            self.capability.spec.image_digest
            not in self.execution_policy.spec.allowed_image_digests
        ):
            raise ValueError("runner task image is not allowed by execution policy")


@dataclass
class RunnerTaskState:
    task: RunnerTask
    status: str = "queued"
    attempt: int = 0
    lease_id: str | None = None
    lease_expires_at: datetime | None = None
    heartbeat_sequence: int = 0
    runner_principal_id: str | None = None
    job: RunnerJob | None = None
    job_statement: SignedStatement | None = None
    artifact_digests: set[str] = field(default_factory=set)
    receipt_statement_digest: str | None = None
    pending_projection_statement_digests: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunnerClaim:
    job: RunnerJob
    job_statement: SignedStatement


@dataclass(frozen=True)
class RunnerCompletion:
    conformance: RunnerConformance
    receipt_statement_digest: str
    pending_projection_statement_digests: tuple[str, ...]


def _statement_subject(statement: SignedStatement) -> Document:
    try:
        payload_bytes = base64.b64decode(statement.spec.envelope.payload, validate=True)
        payload = SignedPayload.model_validate_json(
            canonical_bytes(loads_bounded(payload_bytes)), strict=True
        )
        return parse_document(payload.subject)
    except (TypeError, ValueError) as error:
        raise RunnerGatewayError("runner_signed_statement_invalid") from error


class InMemoryRunnerGateway:
    """Deterministic state-machine reference; production uses the PostgreSQL repository."""

    def __init__(
        self,
        *,
        object_store: ObjectStore,
        signer: JobSigner,
        verifier: StatementVerifier,
    ) -> None:
        self.object_store = object_store
        self.signer = signer
        self.verifier = verifier
        self.registrations: dict[tuple[str, str], RunnerRegistration] = {}
        self.tasks: dict[tuple[str, str], RunnerTaskState] = {}
        self.completed_attempts: set[tuple[str, int]] = set()
        self.idempotency: dict[tuple[str, str, str], tuple[str, object]] = {}
        self._lock = asyncio.Lock()
        self._idempotency_lock = asyncio.Lock()

    async def idempotent(
        self,
        registration: RunnerRegistration,
        key: str,
        request_digest: str,
        operation: Callable[[], Awaitable[object]],
    ) -> object:
        """Serialize one runner mutation and replay only an identical request."""

        cache_key = (registration.tenant_id, registration.principal_id, key)
        async with self._idempotency_lock:
            cached = self.idempotency.get(cache_key)
            if cached is not None:
                if not secrets.compare_digest(cached[0], request_digest):
                    raise RunnerGatewayError("runner_idempotency_key_reused")
                return cached[1]
            result = await operation()
            self.idempotency[cache_key] = (request_digest, result)
            return result

    def register(self, registration: RunnerRegistration) -> None:
        key = (registration.tenant_id, registration.runner_id)
        if key in self.registrations:
            raise RunnerGatewayError("runner_registration_duplicate")
        if any(
            item.certificate_fingerprint == registration.certificate_fingerprint
            or item.uri_san == registration.uri_san
            for item in self.registrations.values()
        ):
            raise RunnerGatewayError("runner_certificate_binding_duplicate")
        self.registrations[key] = registration

    def dispatch(self, task: RunnerTask, *, admitted_at: datetime) -> None:
        key = (task.tenant_id, task.job_id)
        if key in self.tasks:
            raise RunnerGatewayError("runner_job_duplicate")
        try:
            capability_authority = self.verifier.verify(
                task.capability_statement, evaluated_at=admitted_at
            )
            policy_authority = self.verifier.verify(
                task.execution_policy_statement, evaluated_at=admitted_at
            )
        except Exception as error:
            raise RunnerGatewayError("runner_capability_authority_invalid") from error
        if (
            capability_authority.role != "capability_authority"
            or capability_authority.principal_id != task.capability.spec.adapter_principal_id
            or capability_authority.subject != task.capability
            or _statement_subject(task.capability_statement) != task.capability
        ):
            raise RunnerGatewayError("runner_capability_authority_invalid")
        if (
            policy_authority.role != "execution_policy_authority"
            or policy_authority.principal_id != task.capability.spec.verifier_principal_id
            or policy_authority.principal_id == capability_authority.principal_id
            or policy_authority.subject != task.execution_policy
            or _statement_subject(task.execution_policy_statement) != task.execution_policy
        ):
            raise RunnerGatewayError("runner_execution_policy_authority_invalid")
        authority_materials = {
            document_digest(task.capability_statement),
            document_digest(task.execution_policy_statement),
        }
        expected_materials = (
            set(task.input_digests)
            | set(task.capability.spec.material_digests)
            | authority_materials
        )
        if not all(self.object_store.exists(task.tenant_id, item) for item in expected_materials):
            raise RunnerGatewayError("runner_material_missing")
        if (
            sum(len(self.object_store.get(task.tenant_id, item)) for item in expected_materials)
            > task.execution_policy.spec.maximum_input_bytes
        ):
            raise RunnerGatewayError("runner_material_limit_exceeded")
        self.tasks[key] = RunnerTaskState(task=task)

    def authenticate(self, identity: CertificateIdentity) -> RunnerRegistration:
        registration = self.registrations.get((identity.tenant_id, identity.runner_id))
        if (
            registration is None
            or not registration.enabled
            or not secrets.compare_digest(
                registration.certificate_fingerprint, identity.fingerprint
            )
            or not secrets.compare_digest(registration.uri_san, identity.uri_san)
        ):
            raise RunnerGatewayError("runner_identity_not_registered")
        return registration

    async def claim(self, registration: RunnerRegistration, *, claimed_at: datetime) -> RunnerClaim:
        async with self._lock:
            candidates = [
                state
                for (tenant_id, _), state in self.tasks.items()
                if tenant_id == registration.tenant_id
                and (
                    state.status == "queued"
                    or (
                        state.status == "leased"
                        and state.lease_expires_at is not None
                        and state.lease_expires_at < claimed_at
                    )
                )
            ]
            if not candidates:
                raise RunnerGatewayError("runner_job_not_available")
            state = min(candidates, key=lambda item: item.task.job_id)
            if state.attempt >= 32:
                raise RunnerGatewayError("runner_attempt_limit_exhausted")
            state.attempt += 1
            state.lease_id = secrets.token_hex(16)
            state.lease_expires_at = claimed_at + timedelta(seconds=state.task.lease_seconds)
            state.heartbeat_sequence = 0
            state.runner_principal_id = registration.principal_id
            state.status = "leased"
            policy = state.task.execution_policy.spec
            job = RunnerJob(
                metadata=state.task.capability.metadata.model_copy(
                    update={
                        "object_id": f"job:{state.task.job_id}:{state.attempt}",
                        "created_at": claimed_at,
                    }
                ),
                spec=RunnerJobSpec(
                    job_id=state.task.job_id,
                    action_digest=state.task.action_digest,
                    capability_digest=document_digest(state.task.capability),
                    capability_statement_digest=document_digest(state.task.capability_statement),
                    execution_policy_digest=document_digest(state.task.execution_policy),
                    execution_policy_statement_digest=document_digest(
                        state.task.execution_policy_statement
                    ),
                    generation_digest=state.task.generation_digest,
                    attempt=state.attempt,
                    lease_id=state.lease_id,
                    lease_expires_at=state.lease_expires_at,
                    input_digests=list(state.task.input_digests),
                    image_digest=state.task.capability.spec.image_digest,
                    timeout_seconds=policy.timeout_seconds,
                    stdout_limit=policy.stdout_limit,
                    stderr_limit=policy.stderr_limit,
                    network_policy=policy.network_policy,
                    filesystem_policy=policy.filesystem_policy,
                ),
            )
            try:
                statement = self.signer.sign(job)
                verified = self.verifier.verify(statement, evaluated_at=claimed_at)
                if (
                    verified.role != "job_dispatcher"
                    or verified.subject != job
                    or _statement_subject(statement) != job
                ):
                    raise RunnerGatewayError("runner_job_signature_invalid")
            except Exception as error:
                state.attempt -= 1
                state.lease_id = None
                state.lease_expires_at = None
                state.runner_principal_id = None
                state.status = "queued"
                if isinstance(error, RunnerGatewayError):
                    raise
                raise RunnerGatewayError("runner_job_signature_invalid") from error
            state.job = job
            state.job_statement = statement
            return RunnerClaim(job=job, job_statement=statement)

    def _active_state(
        self,
        registration: RunnerRegistration,
        lease_id: str,
        *,
        evaluated_at: datetime,
    ) -> RunnerTaskState:
        matches = [
            state
            for (tenant_id, _), state in self.tasks.items()
            if tenant_id == registration.tenant_id and state.lease_id == lease_id
        ]
        if len(matches) != 1:
            raise RunnerGatewayError("runner_lease_not_found")
        state = matches[0]
        if (
            state.status != "leased"
            or state.runner_principal_id != registration.principal_id
            or state.lease_expires_at is None
            or evaluated_at > state.lease_expires_at
        ):
            raise RunnerGatewayError("runner_lease_stale")
        return state

    async def heartbeat(
        self,
        registration: RunnerRegistration,
        lease_id: str,
        sequence: int,
        *,
        received_at: datetime,
    ) -> None:
        async with self._lock:
            state = self._active_state(registration, lease_id, evaluated_at=received_at)
            if sequence != state.heartbeat_sequence + 1:
                raise RunnerGatewayError("runner_heartbeat_sequence_invalid")
            state.heartbeat_sequence = sequence

    async def record_artifact(
        self,
        registration: RunnerRegistration,
        lease_id: str,
        digest: str,
        *,
        received_at: datetime,
    ) -> None:
        async with self._lock:
            state = self._active_state(registration, lease_id, evaluated_at=received_at)
            if not self.object_store.exists(registration.tenant_id, digest):
                raise RunnerGatewayError("runner_artifact_missing_after_upload")
            proposed = state.artifact_digests | {digest}
            if (
                sum(len(self.object_store.get(registration.tenant_id, item)) for item in proposed)
                > state.task.execution_policy.spec.maximum_output_bytes
            ):
                raise RunnerGatewayError("runner_artifact_limit_exceeded")
            state.artifact_digests.add(digest)

    async def remaining_artifact_bytes(
        self,
        registration: RunnerRegistration,
        lease_id: str,
        *,
        evaluated_at: datetime,
    ) -> int:
        """Return the signed-policy remainder before accepting an upload body."""

        async with self._lock:
            state = self._active_state(registration, lease_id, evaluated_at=evaluated_at)
            if len(state.artifact_digests) >= 10_002:
                return 0
            consumed = sum(
                len(self.object_store.get(registration.tenant_id, digest))
                for digest in state.artifact_digests
            )
            return max(0, state.task.execution_policy.spec.maximum_output_bytes - consumed)

    async def complete(
        self,
        registration: RunnerRegistration,
        lease_id: str,
        receipt_statement: SignedStatement,
        projection_statements: list[SignedStatement],
        *,
        received_at: datetime,
    ) -> RunnerCompletion:
        async with self._lock:
            state = self._active_state(registration, lease_id, evaluated_at=received_at)
            if state.job is None:
                raise RunnerGatewayError("runner_job_not_bound")
            verified_receipt = self.verifier.verify(receipt_statement, evaluated_at=received_at)
            if (
                not isinstance(verified_receipt.subject, RunnerReceipt)
                or verified_receipt.role != "runner_receipt"
                or verified_receipt.principal_id != registration.principal_id
                or _statement_subject(receipt_statement) != verified_receipt.subject
            ):
                raise RunnerGatewayError("runner_receipt_signature_invalid")
            receipt = verified_receipt.subject
            available = (
                set(state.artifact_digests)
                | set(state.task.input_digests)
                | set(state.task.capability.spec.material_digests)
                | {
                    document_digest(state.task.capability_statement),
                    document_digest(state.task.execution_policy_statement),
                }
            )
            artifact_lengths = {
                digest: len(self.object_store.get(registration.tenant_id, digest))
                for digest in available
            }
            output_document = None
            if len(receipt.spec.output_digests) == 1:
                try:
                    output_document = loads_bounded(
                        self.object_store.get(
                            registration.tenant_id, receipt.spec.output_digests[0]
                        )
                    )
                except (KeyError, TypeError, ValueError) as error:
                    raise RunnerGatewayError("runner_selector_output_invalid") from error
            conformance = validate_receipt(
                state.job,
                receipt,
                state.task.capability,
                state.task.execution_policy,
                received_at=received_at,
                expected_runner_principal_id=registration.principal_id,
                prior_attempts=set(self.completed_attempts),
                available_digests=available,
                artifact_lengths=artifact_lengths,
                output_document=output_document,
            )
            if not conformance.accepted:
                raise RunnerGatewayError("runner_receipt_nonconformant")
            pending_digests: list[str] = []
            for statement in projection_statements:
                verified = self.verifier.verify(statement, evaluated_at=received_at)
                pending = verified.subject
                if (
                    not isinstance(pending, PendingProjection)
                    or verified.role != "projection_authority"
                    or verified.principal_id != state.task.capability.spec.adapter_principal_id
                    or pending.spec.runner_receipt_digest != document_digest(receipt)
                    or pending.spec.raw_output_digest not in receipt.spec.output_digests
                    or _statement_subject(statement) != pending
                ):
                    raise RunnerGatewayError("runner_pending_projection_invalid")
                if receipt.spec.claimed_outcome not in {"success", "partial"}:
                    raise RunnerGatewayError("runner_failure_projection_rejected")
                pending_digests.append(document_digest(statement))
            if len(pending_digests) != len(set(pending_digests)):
                raise RunnerGatewayError("runner_pending_projection_duplicate")
            receipt_bytes = canonical_bytes(
                receipt_statement.model_dump(mode="json", exclude_none=True)
            )
            stored_receipt = self.object_store.put(registration.tenant_id, receipt_bytes)
            if stored_receipt != document_digest(receipt_statement):
                raise RunnerGatewayError("runner_receipt_storage_invariant_failed")
            for statement in projection_statements:
                raw = canonical_bytes(statement.model_dump(mode="json", exclude_none=True))
                if self.object_store.put(registration.tenant_id, raw) != document_digest(statement):
                    raise RunnerGatewayError("runner_projection_storage_invariant_failed")
            self.completed_attempts.add((state.task.job_id, state.attempt))
            state.receipt_statement_digest = stored_receipt
            state.pending_projection_statement_digests = tuple(sorted(pending_digests))
            state.status = "completed"
            return RunnerCompletion(
                conformance=conformance,
                receipt_statement_digest=stored_receipt,
                pending_projection_statement_digests=state.pending_projection_statement_digests,
            )


class RunnerApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    code: str
    effect_class: str
    tenant_id: str | None = None
    workspace_id: str | None = None
    generation_digest: str | None = None
    job_id: str | None = None
    objects_written: list[str] = Field(default_factory=list)
    authority_required: list[str] = Field(default_factory=list)
    claims: dict[str, Any] = Field(default_factory=dict)
    unknowns: list[str] = Field(default_factory=list)
    quarantined_objects: list[str] = Field(default_factory=list)
    next_safe_commands: list[list[str]] = Field(default_factory=list)
    trace_id: str


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sequence: int = Field(ge=1, le=1_000_000)


class CompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    receipt_statement: SignedStatement
    projection_statements: list[SignedStatement] = Field(default_factory=list, max_length=64)


def create_runner_app(
    gateway: InMemoryRunnerGateway,
    object_store: ObjectStore,
    *,
    expected_trust_domain: str,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    """Create the loopback-only runner API intended to sit behind Envoy mTLS."""

    current_time = clock or (lambda: datetime.now(UTC))
    app = FastAPI(
        title="CPCF Outbound Runner API",
        version="0.6.0",
        openapi_version="3.1.0",
        docs_url=None,
        redoc_url=None,
    )

    def trace(request: Request) -> str:
        supplied = request.headers.get("traceparent", "")
        match = re.fullmatch(r"[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}", supplied)
        return match.group(1) if match is not None else secrets.token_hex(16)

    async def registration(
        xfcc: str = Header(alias="X-Forwarded-Client-Cert", max_length=XFCC_LIMIT),
    ) -> RunnerRegistration:
        identity = parse_envoy_xfcc(xfcc, expected_trust_domain=expected_trust_domain)
        return gateway.authenticate(identity)

    registration_dependency = Depends(registration)

    @app.exception_handler(RunnerGatewayError)
    async def runner_error(request: Request, error: RunnerGatewayError) -> JSONResponse:
        body = RunnerApiResponse(
            status="error",
            code=error.code,
            effect_class="none",
            next_safe_commands=[],
            trace_id=trace(request),
        )
        status_code = 401 if "identity" in error.code or "certificate" in error.code else 409
        return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _: RequestValidationError) -> JSONResponse:
        body = RunnerApiResponse(
            status="error",
            code="runner_request_schema_invalid",
            effect_class="none",
            trace_id=trace(request),
        )
        return JSONResponse(status_code=422, content=body.model_dump(mode="json"))

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException) -> JSONResponse:
        body = RunnerApiResponse(
            status="error",
            code=str(error.detail),
            effect_class="none",
            trace_id=trace(request),
        )
        return JSONResponse(status_code=error.status_code, content=body.model_dump(mode="json"))

    @app.get("/health/live")
    async def live(request: Request) -> RunnerApiResponse:
        return RunnerApiResponse(
            status="ok",
            code="runner_gateway_live",
            effect_class="inspect",
            trace_id=trace(request),
        )

    @app.post("/v1/runner/leases/claim")
    async def claim(
        request: Request,
        runner: RunnerRegistration = registration_dependency,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=16, max_length=128),
    ) -> RunnerApiResponse:
        requested_at = current_time()
        request_digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_bytes(
                    {
                        "operation": "runner_claim",
                        "tenant_id": runner.tenant_id,
                        "principal_id": runner.principal_id,
                    }
                )
            ).hexdigest()
        )

        async def perform() -> object:
            return await gateway.claim(runner, claimed_at=requested_at)

        value = await gateway.idempotent(runner, idempotency_key, request_digest, perform)
        if not isinstance(value, RunnerClaim):
            raise RunnerGatewayError("runner_idempotency_type_mismatch")
        return RunnerApiResponse(
            status="ok",
            code="runner_lease_claimed",
            effect_class="remote_write",
            tenant_id=runner.tenant_id,
            workspace_id=value.job.metadata.workspace_id,
            generation_digest=value.job.spec.generation_digest,
            job_id=value.job.spec.job_id,
            authority_required=["registered_runner_certificate", "job_dispatcher"],
            claims={
                "job": value.job.model_dump(mode="json", exclude_none=True),
                "job_statement": value.job_statement.model_dump(mode="json", exclude_none=True),
            },
            next_safe_commands=[],
            trace_id=trace(request),
        )

    @app.post("/v1/runner/leases/{lease_id}/heartbeat")
    async def heartbeat(
        lease_id: str,
        body: HeartbeatRequest,
        request: Request,
        runner: RunnerRegistration = registration_dependency,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=16, max_length=128),
    ) -> RunnerApiResponse:
        received_at = current_time()
        request_digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_bytes(
                    {
                        "operation": "runner_heartbeat",
                        "lease_id": lease_id,
                        "sequence": body.sequence,
                    }
                )
            ).hexdigest()
        )

        async def perform() -> object:
            await gateway.heartbeat(runner, lease_id, body.sequence, received_at=received_at)
            return body.sequence

        await gateway.idempotent(runner, idempotency_key, request_digest, perform)
        return RunnerApiResponse(
            status="ok",
            code="runner_heartbeat_recorded",
            effect_class="remote_write",
            tenant_id=runner.tenant_id,
            claims={"lease_id": lease_id, "sequence": body.sequence},
            trace_id=trace(request),
        )

    @app.put("/v1/runner/leases/{lease_id}/artifacts/sha256/{hex_digest}")
    async def upload_artifact(
        lease_id: str,
        hex_digest: str,
        request: Request,
        runner: RunnerRegistration = registration_dependency,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=16, max_length=128),
    ) -> RunnerApiResponse:
        if re.fullmatch(r"[0-9a-f]{64}", hex_digest) is None:
            raise HTTPException(422, "runner_artifact_digest_invalid")
        maximum = min(
            64 * 1024 * 1024,
            await gateway.remaining_artifact_bytes(runner, lease_id, evaluated_at=current_time()),
        )
        if maximum <= 0:
            raise HTTPException(413, "runner_artifact_budget_exhausted")
        chunks: list[bytes] = []
        size = 0
        content_hash = hashlib.sha256()
        async for chunk in request.stream():
            size += len(chunk)
            if size > maximum:
                raise HTTPException(413, "runner_artifact_too_large")
            chunks.append(chunk)
            content_hash.update(chunk)
        expected = "sha256:" + hex_digest
        if not secrets.compare_digest(expected, "sha256:" + content_hash.hexdigest()):
            raise HTTPException(422, "runner_artifact_digest_mismatch")
        request_digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_bytes(
                    {
                        "operation": "runner_artifact_upload",
                        "lease_id": lease_id,
                        "digest": expected,
                        "size": size,
                    }
                )
            ).hexdigest()
        )

        async def perform() -> object:
            data = b"".join(chunks)
            existed = object_store.exists(runner.tenant_id, expected)
            stored: str | None = None
            try:
                stored = object_store.put(runner.tenant_id, data)
                if stored != expected:
                    raise RunnerGatewayError("runner_artifact_storage_invariant_failed")
                await gateway.record_artifact(runner, lease_id, stored, received_at=current_time())
                return stored
            except Exception:
                quarantine = getattr(object_store, "quarantine_unreferenced", None)
                if not existed and stored is not None and callable(quarantine):
                    quarantine(
                        runner.tenant_id,
                        stored,
                        "runner_artifact_admission_failed",
                    )
                raise

        stored = await gateway.idempotent(runner, idempotency_key, request_digest, perform)
        if not isinstance(stored, str):
            raise RunnerGatewayError("runner_idempotency_type_mismatch")
        return RunnerApiResponse(
            status="ok",
            code="runner_artifact_recorded",
            effect_class="remote_write",
            tenant_id=runner.tenant_id,
            objects_written=[stored],
            claims={"lease_id": lease_id, "byte_length": size},
            trace_id=trace(request),
        )

    @app.post("/v1/runner/leases/{lease_id}/complete")
    async def complete(
        lease_id: str,
        body: CompletionRequest,
        request: Request,
        runner: RunnerRegistration = registration_dependency,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=16, max_length=128),
    ) -> RunnerApiResponse:
        received_at = current_time()
        request_digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_bytes(
                    {
                        "operation": "runner_complete",
                        "lease_id": lease_id,
                        "receipt": document_digest(body.receipt_statement),
                        "projections": sorted(
                            document_digest(item) for item in body.projection_statements
                        ),
                    }
                )
            ).hexdigest()
        )

        async def perform() -> object:
            return await gateway.complete(
                runner,
                lease_id,
                body.receipt_statement,
                body.projection_statements,
                received_at=received_at,
            )

        value = await gateway.idempotent(runner, idempotency_key, request_digest, perform)
        if not isinstance(value, RunnerCompletion):
            raise RunnerGatewayError("runner_idempotency_type_mismatch")
        return RunnerApiResponse(
            status="ok",
            code="runner_receipt_recorded_pending_projection",
            effect_class="remote_write",
            tenant_id=runner.tenant_id,
            objects_written=[
                value.receipt_statement_digest,
                *value.pending_projection_statement_digests,
            ],
            claims={
                "lease_id": lease_id,
                "conformance": value.conformance.model_dump(mode="json"),
            },
            unknowns=["projection_requires_independent_approval"]
            if value.pending_projection_statement_digests
            else [],
            authority_required=["runner_receipt", "projection_verifier"],
            trace_id=trace(request),
        )

    return app
