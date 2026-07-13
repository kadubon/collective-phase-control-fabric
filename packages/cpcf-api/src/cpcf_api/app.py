# SPDX-License-Identifier: Apache-2.0
"""FastAPI control plane with optimistic generations and stable response envelopes."""

from __future__ import annotations

import re
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Protocol

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import DOCUMENT_MODELS
from collective_phase_control_fabric.v6.registry import registry_manifest, schema_for_kind
from cpcf_api.auth import Authenticator, PrincipalContext, authorize


class ApiResponse(BaseModel):
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


class WorkspaceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass
class WorkspaceRecord:
    tenant_id: str
    workspace_id: str
    generation_digest: str
    sequence: int = 0
    quarantined: list[str] = field(default_factory=list)


class Backend(Protocol):
    async def startup(self) -> None: ...

    async def create_workspace(self, tenant_id: str, workspace_id: str) -> WorkspaceRecord: ...

    async def workspace(self, tenant_id: str, workspace_id: str) -> WorkspaceRecord: ...

    async def enqueue(self, tenant_id: str, workspace_id: str, topic: str) -> str: ...

    async def job(self, tenant_id: str, job_id: str) -> dict[str, Any] | None: ...

    async def idempotency_get(
        self, tenant_id: str, key: str, request_digest: str
    ) -> ApiResponse | None: ...

    async def idempotency_put(
        self, tenant_id: str, key: str, request_digest: str, response: ApiResponse
    ) -> None: ...


class InMemoryBackend:
    """Deterministic development backend; production injects PostgreSQL/S3 repositories."""

    def __init__(self) -> None:
        self.workspaces: dict[tuple[str, str], WorkspaceRecord] = {}
        self.idempotency: dict[tuple[str, str], tuple[str, ApiResponse]] = {}
        self.jobs: dict[str, dict[str, Any]] = {}

    async def startup(self) -> None:
        return None

    async def create_workspace(self, tenant_id: str, workspace_id: str) -> WorkspaceRecord:
        key = (tenant_id, workspace_id)
        if key in self.workspaces:
            raise ValueError("workspace_already_exists")
        digest = digest_bytes(
            canonical_bytes(
                {
                    "tenant_id": tenant_id,
                    "workspace_id": workspace_id,
                    "sequence": 0,
                    "created_at": "immutable-genesis",
                }
            )
        )
        record = WorkspaceRecord(tenant_id, workspace_id, digest)
        self.workspaces[key] = record
        return record

    async def workspace(self, tenant_id: str, workspace_id: str) -> WorkspaceRecord:
        try:
            return self.workspaces[(tenant_id, workspace_id)]
        except KeyError as error:
            raise ValueError("workspace_not_found") from error

    async def enqueue(self, tenant_id: str, workspace_id: str, topic: str) -> str:
        job_id = secrets.token_hex(16)
        self.jobs[job_id] = {
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "topic": topic,
            "status": "queued",
        }
        return job_id

    async def job(self, tenant_id: str, job_id: str) -> dict[str, Any] | None:
        value = self.jobs.get(job_id)
        return value if value is not None and value["tenant_id"] == tenant_id else None

    async def idempotency_get(
        self, tenant_id: str, key: str, request_digest: str
    ) -> ApiResponse | None:
        cached = self.idempotency.get((tenant_id, key))
        if cached is None:
            return None
        if not secrets.compare_digest(cached[0], request_digest):
            raise ValueError("idempotency_key_reused_with_different_request")
        return cached[1]

    async def idempotency_put(
        self, tenant_id: str, key: str, request_digest: str, response: ApiResponse
    ) -> None:
        cached = self.idempotency.get((tenant_id, key))
        if cached is not None and not secrets.compare_digest(cached[0], request_digest):
            raise ValueError("idempotency_key_reused_with_different_request")
        self.idempotency[(tenant_id, key)] = (request_digest, response)


class StaticAuthenticator:
    """Explicit test/development authenticator; never selected from environment implicitly."""

    def __init__(self, principal: PrincipalContext, development_bearer: str) -> None:
        self.principal = principal
        self.development_bearer = development_bearer

    async def authenticate(self, token: str) -> PrincipalContext:
        if not secrets.compare_digest(token, self.development_bearer):
            raise ValueError("token_invalid")
        return self.principal


security = HTTPBearer(auto_error=False)
security_dependency = Depends(security)


def create_app(
    *,
    backend: Backend | None = None,
    authenticator: Authenticator | None = None,
) -> FastAPI:
    backend_service: Backend = backend or InMemoryBackend()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> Any:
        await backend_service.startup()
        yield

    app = FastAPI(
        title="CPCF Evidence-Control API",
        version="0.6.0",
        openapi_version="3.1.0",
        docs_url="/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.backend = backend_service
    app.state.authenticator = authenticator

    def trace(request: Request) -> str:
        supplied = request.headers.get("traceparent", "")
        match = re.fullmatch(
            r"[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}",
            supplied,
        )
        return match.group(1) if match is not None else secrets.token_hex(16)

    async def principal(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = security_dependency,
    ) -> PrincipalContext:
        configured: Authenticator | None = request.app.state.authenticator
        if configured is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "oidc_not_configured")
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer_token_required")
        try:
            return await configured.authenticate(credentials.credentials)
        except Exception as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token_not_verified") from error

    principal_dependency = Depends(principal)

    async def require_workspace(tenant_id: str, workspace_id: str) -> WorkspaceRecord:
        try:
            return await backend_service.workspace(tenant_id, workspace_id)
        except ValueError as error:
            raise HTTPException(404, str(error)) from error

    def mutation_digest(
        request: Request,
        actor: PrincipalContext,
        body: BaseModel | dict[str, Any],
        *,
        expected_generation: str | None = None,
    ) -> str:
        return digest_bytes(
            canonical_bytes(
                {
                    "method": request.method,
                    "path": request.url.path,
                    "tenant_id": actor.tenant_id,
                    "subject": actor.subject,
                    "expected_generation": expected_generation,
                    "body": body.model_dump(mode="json", exclude_none=True)
                    if isinstance(body, BaseModel)
                    else body,
                }
            )
        )

    @app.exception_handler(PermissionError)
    async def permission_handler(request: Request, error: PermissionError) -> Any:
        from fastapi.responses import JSONResponse

        body = ApiResponse(
            status="error",
            code=str(error),
            effect_class="none",
            authority_required=[],
            next_safe_commands=[],
            trace_id=trace(request),
        )
        return JSONResponse(status_code=403, content=body.model_dump(mode="json"))

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, error: HTTPException) -> Any:
        from fastapi.responses import JSONResponse

        body = ApiResponse(
            status="error",
            code=str(error.detail),
            effect_class="none",
            next_safe_commands=[],
            trace_id=trace(request),
        )
        return JSONResponse(status_code=error.status_code, content=body.model_dump(mode="json"))

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(request: Request, error: RequestValidationError) -> Any:
        from fastapi.responses import JSONResponse

        body = ApiResponse(
            status="error",
            code="request_schema_invalid",
            effect_class="none",
            unknowns=[str(item.get("type", "validation_error")) for item in error.errors()],
            next_safe_commands=[],
            trace_id=trace(request),
        )
        return JSONResponse(status_code=422, content=body.model_dump(mode="json"))

    @app.get("/health/live")
    async def live(request: Request) -> ApiResponse:
        return ApiResponse(
            status="ok", code="service_live", effect_class="inspect", trace_id=trace(request)
        )

    @app.get("/health/ready")
    async def ready(request: Request) -> ApiResponse:
        configured = request.app.state.authenticator is not None
        return ApiResponse(
            status="ok" if configured else "blocked",
            code="service_ready" if configured else "oidc_not_configured",
            effect_class="inspect",
            unknowns=[] if configured else ["authentication_unavailable"],
            trace_id=trace(request),
        )

    @app.get("/v1/schemas")
    async def schemas(request: Request) -> ApiResponse:
        return ApiResponse(
            status="ok",
            code="schema_registry",
            effect_class="inspect",
            claims=registry_manifest(),
            trace_id=trace(request),
        )

    @app.get("/v1/schemas/{kind}")
    async def schema(kind: str, request: Request) -> ApiResponse:
        if kind not in DOCUMENT_MODELS:
            raise HTTPException(404, "unknown_document_kind")
        return ApiResponse(
            status="ok",
            code="schema_document",
            effect_class="inspect",
            claims={"schema": schema_for_kind(kind)},
            trace_id=trace(request),
        )

    @app.post("/v1/workspaces", status_code=201)
    async def create_workspace(
        body: WorkspaceCreate,
        request: Request,
        actor: PrincipalContext = principal_dependency,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=16, max_length=128),
    ) -> ApiResponse:
        authorize(actor, "workspace:create", actor.tenant_id)
        request_digest = mutation_digest(request, actor, body)
        cache_key = (actor.tenant_id, idempotency_key, request_digest)
        try:
            cached = await backend_service.idempotency_get(*cache_key)
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
        if cached is not None:
            return cached
        try:
            workspace = await backend_service.create_workspace(actor.tenant_id, body.workspace_id)
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
        response = ApiResponse(
            status="ok",
            code="workspace_created",
            effect_class="local_write",
            tenant_id=actor.tenant_id,
            workspace_id=body.workspace_id,
            generation_digest=workspace.generation_digest,
            authority_required=["tenant_admin"],
            next_safe_commands=[
                ["cpcf", "agent", "onboard", "--workspace", body.workspace_id, "--json"]
            ],
            trace_id=trace(request),
        )
        await backend_service.idempotency_put(*cache_key, response)
        return response

    @app.get("/v1/workspaces/{workspace_id}")
    async def workspace_status(
        workspace_id: str,
        request: Request,
        actor: PrincipalContext = principal_dependency,
    ) -> ApiResponse:
        authorize(actor, "workspace:read", actor.tenant_id)
        workspace = await require_workspace(actor.tenant_id, workspace_id)
        return ApiResponse(
            status="ok",
            code="workspace_status",
            effect_class="inspect",
            tenant_id=actor.tenant_id,
            workspace_id=workspace_id,
            generation_digest=workspace.generation_digest,
            quarantined_objects=workspace.quarantined,
            claims={"generation_sequence": workspace.sequence},
            trace_id=trace(request),
        )

    @app.post("/v1/workspaces/{workspace_id}/analyses", status_code=202)
    async def start_analysis(
        workspace_id: str,
        request: Request,
        actor: PrincipalContext = principal_dependency,
        idempotency_key: str = Header(alias="Idempotency-Key", min_length=16, max_length=128),
        if_match: str = Header(alias="If-Match"),
    ) -> ApiResponse:
        authorize(actor, "analysis:start", actor.tenant_id)
        request_digest = mutation_digest(request, actor, {}, expected_generation=if_match)
        cache_key = (actor.tenant_id, idempotency_key, request_digest)
        try:
            cached = await backend_service.idempotency_get(*cache_key)
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
        if cached is not None:
            return cached
        workspace = await require_workspace(actor.tenant_id, workspace_id)
        if if_match != workspace.generation_digest:
            raise HTTPException(412, "workspace_generation_changed")
        job_id = await backend_service.enqueue(actor.tenant_id, workspace_id, "analysis")
        response = ApiResponse(
            status="accepted",
            code="analysis_queued",
            effect_class="plan",
            tenant_id=actor.tenant_id,
            workspace_id=workspace_id,
            generation_digest=workspace.generation_digest,
            job_id=job_id,
            authority_required=["auditor", "planner", "tenant_admin"],
            next_safe_commands=[["cpcf", "audit", "status", job_id, "--json"]],
            trace_id=trace(request),
        )
        await backend_service.idempotency_put(*cache_key, response)
        return response

    @app.get("/v1/jobs/{job_id}")
    async def job_status(
        job_id: str,
        request: Request,
        actor: PrincipalContext = principal_dependency,
    ) -> ApiResponse:
        job = await backend_service.job(actor.tenant_id, job_id)
        if job is None:
            raise HTTPException(404, "job_not_found")
        authorize(actor, "workspace:read", actor.tenant_id)
        return ApiResponse(
            status=job["status"],
            code="job_status",
            effect_class="inspect",
            tenant_id=actor.tenant_id,
            workspace_id=job["workspace_id"],
            job_id=job_id,
            claims={"topic": job["topic"]},
            trace_id=trace(request),
        )

    @app.get("/v1/workspaces/{workspace_id}/onboarding")
    async def onboard(
        workspace_id: str,
        request: Request,
        actor: PrincipalContext = principal_dependency,
    ) -> ApiResponse:
        authorize(actor, "workspace:read", actor.tenant_id)
        workspace = await require_workspace(actor.tenant_id, workspace_id)
        unknowns = [
            "trust_genesis_not_imported",
            "trusted_time_not_imported",
            "analysis_snapshot_not_available",
            "runner_not_registered",
            "trial_evidence_unmeasured",
        ]
        return ApiResponse(
            status="blocked",
            code="onboarding_decisions_required",
            effect_class="inspect",
            tenant_id=actor.tenant_id,
            workspace_id=workspace_id,
            generation_digest=workspace.generation_digest,
            unknowns=unknowns,
            quarantined_objects=workspace.quarantined,
            next_safe_commands=[
                ["cpcf", "trust", "genesis-inspect", "POLICY", "--json"],
                ["cpcf", "time", "inspect", "RECEIPT", "--json"],
            ],
            trace_id=trace(request),
        )

    return app


app = create_app()
