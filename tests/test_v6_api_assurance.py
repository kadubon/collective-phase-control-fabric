# SPDX-License-Identifier: Apache-2.0
"""Control-plane, OIDC, object-store, and service-entry assurance tests."""

from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cpcf_api.app import InMemoryBackend, StaticAuthenticator, create_app
from cpcf_api.auth import OidcAuthenticator, PrincipalContext, authorize
from cpcf_api.object_store import S3ObjectStore

from collective_phase_control_fabric.v6.canonical import digest_bytes

GENESIS_BODY = {
    "root_spki_fingerprint": "sha256:" + "1" * 64,
    "genesis_envelope_fingerprint": "sha256:" + "2" * 64,
}


def principal(*roles: str, tenant: str = "tenant-a") -> PrincipalContext:
    return PrincipalContext(subject="subject-a", tenant_id=tenant, roles=frozenset(roles))


async def request(app: object, method: str, path: str, **kwargs: object) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="https://cpcf.test",
    ) as client:
        return await client.request(method, path, **kwargs)


def test_authorization_and_static_authenticator_are_deny_by_default() -> None:
    admin = principal("tenant_admin")
    authorize(admin, "workspace:create", "tenant-a")
    with pytest.raises(PermissionError, match="cross_tenant_access_denied"):
        authorize(admin, "workspace:create", "tenant-b")
    with pytest.raises(PermissionError, match="operation_denied_by_default"):
        authorize(principal("unknown-role"), "workspace:create", "tenant-a")

    authenticator = StaticAuthenticator(admin, "development-token")
    assert asyncio.run(authenticator.authenticate("development-token")) == admin
    with pytest.raises(ValueError, match="token_invalid"):
        asyncio.run(authenticator.authenticate("wrong"))


def test_oidc_configuration_and_claim_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        OidcAuthenticator("http://issuer", "audience", "https://issuer/jwks")
    with pytest.raises(ValueError, match="between 60 and 86400"):
        OidcAuthenticator(
            "https://issuer", "audience", "https://issuer/jwks", maximum_token_lifetime_seconds=1
        )
    authenticator = OidcAuthenticator(
        "https://issuer/", "audience", "https://issuer/jwks", maximum_token_lifetime_seconds=100
    )
    authenticator.jwks = SimpleNamespace(
        get_signing_key_from_jwt=lambda _: SimpleNamespace(key="public-key")
    )

    claims: dict[str, object] = {
        "sub": "subject",
        "tenant_id": "tenant-a",
        "roles": ["auditor", 1],
        "iat": 100,
        "exp": 200,
    }
    monkeypatch.setattr(jwt, "decode", lambda *args, **kwargs: dict(claims))
    context = asyncio.run(authenticator.authenticate("token"))
    assert context.roles == frozenset({"auditor"})
    assert authenticator.issuer == "https://issuer"

    for update, message in (
        ({"tenant_id": None}, "tenant_id and roles"),
        ({"roles": "auditor"}, "tenant_id and roles"),
        ({"iat": "100"}, "numeric iat and exp"),
        ({"exp": "200"}, "numeric iat and exp"),
        ({"exp": 100}, "expiry must follow"),
        ({"exp": 201}, "lifetime exceeds"),
    ):
        monkeypatch.setattr(jwt, "decode", lambda *args, u=update, **kwargs: {**claims, **u})
        with pytest.raises(jwt.InvalidTokenError, match=message):
            asyncio.run(authenticator.authenticate("token"))


def test_api_health_schema_auth_validation_and_permission_handlers() -> None:
    unauthenticated = create_app()
    assert (
        asyncio.run(request(unauthenticated, "GET", "/health/live")).json()["code"]
        == "service_live"
    )
    ready = asyncio.run(request(unauthenticated, "GET", "/health/ready")).json()
    assert ready["status"] == "blocked" and ready["code"] == "oidc_not_configured"
    assert (
        asyncio.run(request(unauthenticated, "GET", "/v1/schemas")).json()["code"]
        == "schema_registry"
    )
    assert asyncio.run(request(unauthenticated, "GET", "/v1/schemas/unknown")).status_code == 404
    no_oidc = asyncio.run(request(unauthenticated, "GET", "/v1/workspaces/one"))
    assert no_oidc.status_code == 503 and no_oidc.json()["code"] == "oidc_not_configured"

    backend = InMemoryBackend()
    app = create_app(
        backend=backend,
        authenticator=StaticAuthenticator(principal("auditor"), "token"),
    )
    missing_bearer = asyncio.run(request(app, "GET", "/v1/workspaces/one"))
    assert missing_bearer.status_code == 401
    bad_bearer = asyncio.run(
        request(app, "GET", "/v1/workspaces/one", headers={"Authorization": "Bearer bad"})
    )
    assert bad_bearer.json()["code"] == "token_not_verified"
    denied = asyncio.run(
        request(
            app,
            "POST",
            "/v1/workspaces",
            headers={"Authorization": "Bearer token", "Idempotency-Key": "a" * 16},
            json={"workspace_id": "workspace-a", **GENESIS_BODY},
        )
    )
    assert denied.status_code == 403 and denied.json()["code"] == "operation_denied_by_default"
    invalid = asyncio.run(
        request(
            app,
            "POST",
            "/v1/workspaces",
            headers={"Authorization": "Bearer token", "Idempotency-Key": "short"},
            json={"workspace_id": "../invalid"},
        )
    )
    assert invalid.status_code == 422 and invalid.json()["code"] == "request_schema_invalid"


def test_api_workspace_job_status_onboarding_and_idempotency_paths() -> None:
    backend = InMemoryBackend()
    app = create_app(
        backend=backend,
        authenticator=StaticAuthenticator(principal("tenant_admin"), "token"),
    )
    auth = {"Authorization": "Bearer token", "Idempotency-Key": "a" * 16}
    trace_id = "1" * 32
    created = asyncio.run(
        request(
            app,
            "POST",
            "/v1/workspaces",
            headers={**auth, "traceparent": f"00-{trace_id}-{'2' * 16}-01"},
            json={"workspace_id": "workspace-a", **GENESIS_BODY},
        )
    )
    assert created.status_code == 201 and created.json()["trace_id"] == trace_id
    generation = created.json()["generation_digest"]
    conflict = asyncio.run(
        request(
            app,
            "POST",
            "/v1/workspaces",
            headers={**auth, "Idempotency-Key": "b" * 16},
            json={"workspace_id": "workspace-a", **GENESIS_BODY},
        )
    )
    assert conflict.status_code == 409 and conflict.json()["code"] == "workspace_already_exists"
    status = asyncio.run(
        request(app, "GET", "/v1/workspaces/workspace-a", headers={"Authorization": "Bearer token"})
    )
    assert status.json()["claims"] == {"generation_sequence": 0}
    onboard = asyncio.run(
        request(
            app,
            "GET",
            "/v1/workspaces/workspace-a/onboarding",
            headers={"Authorization": "Bearer token"},
        )
    )
    assert onboard.json()["code"] == "onboarding_decisions_required"

    accepted = asyncio.run(
        request(
            app,
            "POST",
            "/v1/workspaces/workspace-a/analyses",
            headers={
                "Authorization": "Bearer token",
                "Idempotency-Key": "c" * 16,
                "If-Match": generation,
            },
        )
    )
    job_id = accepted.json()["job_id"]
    job = asyncio.run(
        request(app, "GET", f"/v1/jobs/{job_id}", headers={"Authorization": "Bearer token"})
    )
    assert job.json()["status"] == "queued"
    missing_job = asyncio.run(
        request(app, "GET", "/v1/jobs/missing", headers={"Authorization": "Bearer token"})
    )
    assert missing_job.status_code == 404


def test_api_cas_upload_is_digest_scoped_bounded_and_quarantined() -> None:
    backend = InMemoryBackend()
    app = create_app(
        backend=backend,
        authenticator=StaticAuthenticator(principal("tenant_admin"), "token"),
    )
    created = asyncio.run(
        request(
            app,
            "POST",
            "/v1/workspaces",
            headers={"Authorization": "Bearer token", "Idempotency-Key": "a" * 16},
            json={"workspace_id": "cas-workspace", **GENESIS_BODY},
        )
    ).json()
    digest = digest_bytes(b"data")
    uploaded = asyncio.run(
        request(
            app,
            "PUT",
            f"/v1/workspaces/cas-workspace/cas/sha256/{digest[7:]}",
            headers={
                "Authorization": "Bearer token",
                "Idempotency-Key": "b" * 16,
                "If-Match": created["generation_digest"],
            },
            content=b"data",
        )
    )
    assert uploaded.status_code == 201
    assert uploaded.json()["code"] == "cas_object_uploaded_quarantined"
    assert uploaded.json()["quarantined_objects"] == [digest]
    mismatch = asyncio.run(
        request(
            app,
            "PUT",
            f"/v1/workspaces/cas-workspace/cas/sha256/{'0' * 64}",
            headers={
                "Authorization": "Bearer token",
                "Idempotency-Key": "c" * 16,
                "If-Match": created["generation_digest"],
            },
            content=b"data",
        )
    )
    assert mismatch.status_code == 422
    assert mismatch.json()["code"] == "cas_upload_digest_mismatch"


def test_in_memory_backend_cross_tenant_job_and_idempotency_write_collision() -> None:
    backend = InMemoryBackend()

    async def exercise() -> None:
        await backend.startup()
        workspace = await backend.create_workspace(
            "tenant-a", "workspace-a", "sha256:" + "1" * 64, "sha256:" + "2" * 64
        )
        assert await backend.workspace("tenant-a", "workspace-a") == workspace
        with pytest.raises(ValueError, match="workspace_already_exists"):
            await backend.create_workspace(
                "tenant-a", "workspace-a", "sha256:" + "1" * 64, "sha256:" + "2" * 64
            )
        with pytest.raises(ValueError, match="workspace_not_found"):
            await backend.workspace("tenant-a", "missing")
        job_id = await backend.enqueue("tenant-a", "workspace-a", "analysis")
        assert await backend.job("tenant-b", job_id) is None
        response = SimpleNamespace()
        await backend.idempotency_put("tenant-a", "key", "request-a", response)  # type: ignore[arg-type]
        assert await backend.idempotency_get("tenant-a", "key", "request-a") is response
        with pytest.raises(ValueError, match="idempotency_key_reused"):
            await backend.idempotency_get("tenant-a", "key", "request-b")
        with pytest.raises(ValueError, match="idempotency_key_reused"):
            await backend.idempotency_put(
                "tenant-a",
                "key",
                "request-b",
                response,  # type: ignore[arg-type]
            )

    asyncio.run(exercise())


class ClientError(Exception):
    def __init__(self, code: str, status: int) -> None:
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class Exceptions:
    pass


Exceptions.ClientError = ClientError


class Body:
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.closed = False

    def read(self, amount: int) -> bytes:
        return self.value[:amount]

    def close(self) -> None:
        self.closed = True


class S3Client:
    exceptions = Exceptions

    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}
        self.metadata: dict[str, dict[str, object]] = {}
        self.tags: dict[str, object] = {}
        self.versioning = "Enabled"
        self.encryption: dict[str, object] = {
            "ServerSideEncryptionConfiguration": {"Rules": [{"Apply": "kms"}]}
        }
        self.encryption_error: ClientError | None = None

    def head_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
        del Bucket
        if Key not in self.values:
            raise ClientError("NoSuchKey", 404)
        return self.metadata[Key]

    def put_object(
        self, *, Bucket: str, Key: str, Body: bytes, IfNoneMatch: str, **_: object
    ) -> None:
        del Bucket
        assert IfNoneMatch == "*"
        if Key in self.values:
            raise ClientError("PreconditionFailed", 412)
        self.values[Key] = Body
        self.metadata[Key] = {
            "ContentLength": len(Body),
            "Metadata": {"sha256": digest_bytes(Body)[7:]},
        }

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
        del Bucket
        value = self.values[Key]
        return {"ContentLength": len(value), "Body": Body(value)}

    def put_object_tagging(self, *, Bucket: str, Key: str, Tagging: object) -> None:
        del Bucket
        self.tags[Key] = Tagging

    def get_bucket_versioning(self, *, Bucket: str) -> dict[str, object]:
        del Bucket
        return {"Status": self.versioning}

    def get_bucket_encryption(self, *, Bucket: str) -> dict[str, object]:
        del Bucket
        if self.encryption_error is not None:
            raise self.encryption_error
        return self.encryption


def test_s3_immutable_cas_configuration_put_get_exists_and_integrity_failures() -> None:
    for kwargs in (
        {"bucket": ""},
        {"bucket": "bucket", "prefix": "../bad"},
        {"bucket": "bucket", "maximum_object_bytes": 0},
        {"bucket": "bucket", "maximum_object_bytes": 64 * 1024 * 1024 + 1},
    ):
        with pytest.raises(ValueError, match="invalid_object_store_configuration"):
            S3ObjectStore(S3Client(), **kwargs)  # type: ignore[arg-type]
    client = S3Client()
    store = S3ObjectStore(client, "bucket", maximum_object_bytes=4)
    with pytest.raises(ValueError, match="invalid_content_digest"):
        store.exists("tenant-a", "invalid")
    with pytest.raises(ValueError, match="invalid_content_digest"):
        store.exists("tenant-a", "sha256:" + "G" * 64)
    with pytest.raises(ValueError, match="input_too_large"):
        store.put("tenant-a", b"12345")
    with pytest.raises(ValueError, match="expected_digest_mismatch"):
        store.put_expected("tenant-a", "sha256:" + "0" * 64, b"data")
    with pytest.raises(ValueError, match="input_too_large"):
        store.put_expected("tenant-a", "sha256:" + "0" * 64, b"12345")
    digest = store.put("tenant-a", b"data")
    assert store.put("tenant-a", b"data") == digest
    assert store.exists("tenant-a", digest)
    assert not store.exists("tenant-a", "sha256:" + "0" * 64)
    assert store.get("tenant-a", digest) == b"data"
    key = store._key("tenant-a", digest)
    store.quarantine_unreferenced("tenant-a", digest, "database_transaction_rolled_back")
    assert key in client.tags
    with pytest.raises(ValueError, match="invalid_quarantine_reason"):
        store.quarantine_unreferenced("tenant-a", digest, "")
    assert not store.validate_bucket_posture()
    client.versioning = "Suspended"
    client.encryption = {"ServerSideEncryptionConfiguration": {"Rules": []}}
    assert store.validate_bucket_posture() == [
        "object_store_encryption_not_configured",
        "object_store_versioning_not_enabled",
    ]
    client.versioning = "Enabled"
    client.encryption_error = ClientError("ServerSideEncryptionConfigurationNotFoundError", 400)
    assert store.validate_bucket_posture() == ["object_store_encryption_not_configured"]
    client.encryption_error = ClientError("AccessDenied", 403)
    with pytest.raises(ClientError):
        store.validate_bucket_posture()
    client.encryption_error = None

    client.metadata[key]["ContentLength"] = 3
    with pytest.raises(RuntimeError, match="immutable_object_key_collision"):
        store.put("tenant-a", b"data")
    client.metadata[key]["ContentLength"] = 4
    client.values[key] = b"fail"
    with pytest.raises(RuntimeError, match="digest_mismatch"):
        store.get("tenant-a", digest)
    client.values[key] = b"longer"
    with pytest.raises(RuntimeError, match="output_too_large"):
        store.get("tenant-a", digest)

    class NoCloseBody:
        def read(self, _: int) -> bytes:
            return b"abc"

    class MismatchedClient(S3Client):
        def get_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
            del Bucket, Key
            return {"ContentLength": 4, "Body": NoCloseBody()}

    with pytest.raises(RuntimeError, match="output_size_mismatch"):
        S3ObjectStore(MismatchedClient(), "bucket", maximum_object_bytes=4).get("tenant-a", digest)


def test_service_entrypoints_fail_stably_and_run_with_explicit_configuration(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from cpcf_api import main as api_main
    from cpcf_worker import main as worker_main

    monkeypatch.delenv("CPCF_DATABASE_URL", raising=False)
    assert api_main.main() == 2
    assert "CPCF_DATABASE_URL is required" in capsys.readouterr().err
    monkeypatch.setenv("CPCF_DATABASE_URL", "postgresql+psycopg://example")
    monkeypatch.delenv("CPCF_OIDC_ISSUER", raising=False)
    assert api_main.main() == 2
    assert "CPCF_OIDC_ISSUER is required" in capsys.readouterr().err

    calls: list[tuple[object, ...]] = []
    monkeypatch.setenv("CPCF_OIDC_ISSUER", "https://issuer")
    monkeypatch.setenv("CPCF_BIND_PORT", "9090")
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    assert api_main.main() == 0 and calls

    def worker_success(coroutine: object) -> int:
        coroutine.close()  # type: ignore[attr-defined]
        return 1

    monkeypatch.setattr(worker_main.asyncio, "run", worker_success)
    assert worker_main.main() == 1

    def worker_missing(coroutine: object) -> int:
        coroutine.close()  # type: ignore[attr-defined]
        raise ModuleNotFoundError

    monkeypatch.setattr(worker_main.asyncio, "run", worker_missing)
    assert worker_main.main() == 2
    assert "worker extra is required" in capsys.readouterr().err


def test_production_required_configuration_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CPCF_OIDC_ISSUER", "https://issuer")
    monkeypatch.setenv("CPCF_OIDC_AUDIENCE", "audience")
    monkeypatch.setenv("CPCF_OIDC_JWKS_URL", "https://issuer/jwks")
    monkeypatch.setenv("CPCF_DATABASE_URL", "postgresql+psycopg://user@host/database")
    monkeypatch.setenv("CPCF_OBJECT_BUCKET", "bucket")
    production = importlib.import_module("cpcf_api.production")
    assert production.app.title == "CPCF Evidence-Control API"
    monkeypatch.delenv("CPCF_OBJECT_BUCKET")
    with pytest.raises(RuntimeError, match="CPCF_OBJECT_BUCKET is required"):
        production._required("CPCF_OBJECT_BUCKET")
