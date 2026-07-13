# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL unit-of-work and worker claim-path assurance without external effects."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from cpcf_api.app import ApiResponse
from cpcf_api.db import (
    IdempotencyRow,
    OutboxRow,
    PostgresBackend,
    WorkspaceRow,
    assert_application_role,
    lock_workspace,
    make_engine,
    set_tenant,
)
from sqlalchemy.exc import IntegrityError


class AsyncContext:
    def __init__(self, value: object, error: BaseException | None = None) -> None:
        self.value = value
        self.error = error

    async def __aenter__(self) -> object:
        if self.error is not None:
            raise self.error
        return self.value

    async def __aexit__(self, *_: object) -> None:
        return None


class Sessions:
    def __init__(self, session: object, error: BaseException | None = None) -> None:
        self.session = session
        self.error = error

    def __call__(self) -> AsyncContext:
        return AsyncContext(self.session, self.error)

    def begin(self) -> AsyncContext:
        return AsyncContext(self.session, self.error)


class Result:
    def __init__(self, *, one: object = None, scalar: object = None) -> None:
        self.one = one
        self.scalar = scalar

    def one_or_none(self) -> object:
        return self.one

    def scalar_one(self) -> object:
        return self.scalar

    def scalar_one_or_none(self) -> object:
        return self.scalar


def response() -> ApiResponse:
    return ApiResponse(
        status="ok",
        code="test",
        effect_class="inspect",
        trace_id="1" * 32,
    )


def test_engine_tenant_setting_application_role_and_workspace_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="psycopg async URL"):
        make_engine("sqlite:///local")
    engine = object()
    monkeypatch.setattr("cpcf_api.db.create_async_engine", lambda *args, **kwargs: engine)
    assert make_engine("postgresql+psycopg://user@host/database") is engine

    session = SimpleNamespace(execute=AsyncMock())
    asyncio.run(set_tenant(session, "tenant-a"))
    assert session.execute.await_count == 1

    async def role_case(posture: object, owned: int = 0) -> None:
        role_session = SimpleNamespace(
            execute=AsyncMock(side_effect=[Result(one=posture), Result(scalar=owned)])
        )
        await assert_application_role(role_session)

    asyncio.run(role_case(SimpleNamespace(rolsuper=False, rolbypassrls=False)))
    for posture in (
        None,
        SimpleNamespace(rolsuper=True, rolbypassrls=False),
        SimpleNamespace(rolsuper=False, rolbypassrls=True),
    ):
        with pytest.raises(RuntimeError, match="bypasses_rls"):
            asyncio.run(role_case(posture))
    with pytest.raises(RuntimeError, match="owns_tenant_tables"):
        asyncio.run(role_case(SimpleNamespace(rolsuper=False, rolbypassrls=False), owned=1))

    async def lock_case(row: object, expected: str = "generation") -> object:
        lock_session = SimpleNamespace(execute=AsyncMock(), get=AsyncMock(return_value=row))
        return await lock_workspace(lock_session, "tenant-a", "workspace-a", expected)

    valid = SimpleNamespace(current_generation_digest="generation")
    assert asyncio.run(lock_case(valid)) is valid
    with pytest.raises(KeyError, match="workspace_not_found"):
        asyncio.run(lock_case(None))
    with pytest.raises(RuntimeError, match="workspace_generation_changed"):
        asyncio.run(lock_case(valid, "other"))


def backend_with(session: object, error: BaseException | None = None) -> PostgresBackend:
    backend = PostgresBackend.__new__(PostgresBackend)
    backend.sessions = Sessions(session, error)  # type: ignore[assignment]
    return backend


def test_postgres_backend_startup_create_workspace_and_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cpcf_api.db.assert_application_role", AsyncMock())
    startup_session = SimpleNamespace()
    asyncio.run(backend_with(startup_session).startup())

    session = SimpleNamespace(execute=AsyncMock(), add=Mock(), get=AsyncMock())
    backend = backend_with(session)
    created = asyncio.run(backend.create_workspace("tenant-a", "workspace-a"))
    assert created.workspace_id == "workspace-a" and created.sequence == 0
    assert session.add.call_args.args[0].tenant_id == "tenant-a"

    failure = IntegrityError("statement", {}, Exception("duplicate"))
    with pytest.raises(ValueError, match="workspace_already_exists"):
        asyncio.run(backend_with(session, failure).create_workspace("tenant-a", "workspace-a"))

    now = datetime.now(UTC)
    row = WorkspaceRow(
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        current_generation_digest="sha256:" + "1" * 64,
        generation_sequence=2,
        created_at=now,
    )
    session.get = AsyncMock(return_value=row)
    loaded = asyncio.run(backend.workspace("tenant-a", "workspace-a"))
    assert loaded.sequence == 2
    session.get = AsyncMock(return_value=None)
    with pytest.raises(ValueError, match="workspace_not_found"):
        asyncio.run(backend.workspace("tenant-a", "missing"))


def test_postgres_backend_outbox_job_and_idempotency_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cpcf_api.db.secrets.token_hex", lambda _: "message-id")
    session = SimpleNamespace(execute=AsyncMock(), add=Mock(), get=AsyncMock())
    backend = backend_with(session)
    assert asyncio.run(backend.enqueue("tenant-a", "workspace-a", "analysis")) == "message-id"
    assert isinstance(session.add.call_args.args[0], OutboxRow)

    session.get = AsyncMock(return_value=None)
    assert asyncio.run(backend.job("tenant-a", "missing")) is None
    for completed, leased, status in (
        (datetime.now(UTC), None, "succeeded"),
        (None, datetime.now(UTC), "running"),
        (None, None, "queued"),
    ):
        session.get = AsyncMock(
            return_value=SimpleNamespace(
                completed_at=completed,
                leased_until=leased,
                workspace_id="workspace-a",
                topic="analysis",
            )
        )
        assert asyncio.run(backend.job("tenant-a", "message-id"))["status"] == status  # type: ignore[index]

    session.get = AsyncMock(return_value=None)
    assert asyncio.run(backend.idempotency_get("tenant-a", "key", "request")) is None
    expired = SimpleNamespace(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    session.get = AsyncMock(return_value=expired)
    assert asyncio.run(backend.idempotency_get("tenant-a", "key", "request")) is None
    cached_response = response()
    from collective_phase_control_fabric.v6.canonical import canonical_bytes

    current = SimpleNamespace(
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        request_digest="request",
        response_body=canonical_bytes(cached_response.model_dump(mode="json")),
    )
    session.get = AsyncMock(return_value=current)
    assert asyncio.run(backend.idempotency_get("tenant-a", "key", "request")) == cached_response
    with pytest.raises(ValueError, match="idempotency_key_reused"):
        asyncio.run(backend.idempotency_get("tenant-a", "key", "different"))

    session.get = AsyncMock(return_value=SimpleNamespace(request_digest="request"))
    asyncio.run(backend.idempotency_put("tenant-a", "key", "request", cached_response))
    with pytest.raises(ValueError, match="idempotency_key_reused"):
        asyncio.run(backend.idempotency_put("tenant-a", "key", "different", cached_response))
    session.get = AsyncMock(return_value=None)
    asyncio.run(backend.idempotency_put("tenant-a", "new", "request", cached_response))
    assert isinstance(session.add.call_args.args[0], IdempotencyRow)


def test_worker_claim_query_missing_configuration_empty_and_available_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlalchemy.ext.asyncio
    from cpcf_worker import main as worker_main

    monkeypatch.delenv("CPCF_DATABASE_URL", raising=False)
    monkeypatch.delenv("CPCF_WORKER_TENANT", raising=False)
    with pytest.raises(RuntimeError, match="required"):
        asyncio.run(worker_main.run_once())

    monkeypatch.setenv("CPCF_DATABASE_URL", "postgresql+psycopg://example")
    monkeypatch.setenv("CPCF_WORKER_TENANT", "tenant-a")
    monkeypatch.setattr("cpcf_api.db.make_engine", lambda _: object())
    session = SimpleNamespace(execute=AsyncMock(return_value=Result(scalar=None)))
    sessions = Sessions(session)
    monkeypatch.setattr(
        sqlalchemy.ext.asyncio,
        "async_sessionmaker",
        lambda *args, **kwargs: sessions,
    )
    assert asyncio.run(worker_main.run_once()) == 0
    session.execute = AsyncMock(return_value=Result(scalar="message-id"))
    assert asyncio.run(worker_main.run_once()) == 1
