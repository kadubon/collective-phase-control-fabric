# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL 18 schema, forced RLS, generation locking, and transactional outbox."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKeyConstraint,
    Index,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from collective_phase_control_fabric.v6.canonical import (
    canonical_bytes,
    digest_bytes,
    loads_bounded,
)
from cpcf_api.app import ApiResponse, WorkspaceRecord


class Base(DeclarativeBase):
    pass


class WorkspaceRow(Base):
    __tablename__ = "workspaces"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    current_generation_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    generation_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ObjectRow(Base):
    __tablename__ = "objects"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    object_digest: Mapped[str] = mapped_column(String(71), primary_key=True)
    object_kind: Mapped[str] = mapped_column(String(128), nullable=False)
    authority_status: Mapped[str] = mapped_column(String(32), nullable=False)
    byte_length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    object_key: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class GenerationRow(Base):
    __tablename__ = "generations"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    generation_digest: Mapped[str] = mapped_column(String(71), primary_key=True)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    prior_generation_digest: Mapped[str | None] = mapped_column(String(71))
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "workspace_id"],
            ["workspaces.tenant_id", "workspaces.workspace_id"],
        ),
        UniqueConstraint("tenant_id", "workspace_id", "sequence"),
    )


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    event_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    prior_event_digest: Mapped[str | None] = mapped_column(String(71))
    event: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "event_digest"),)


class OutboxRow(Base):
    __tablename__ = "outbox"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    message_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    topic: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    leased_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (Index("ix_outbox_claim", "topic", "available_at", "leased_until"),)


class IdempotencyRow(Base):
    __tablename__ = "idempotency_keys"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    response_status: Mapped[int] = mapped_column(BigInteger, nullable=False)
    response_body: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


TENANT_TABLES = (
    "workspaces",
    "objects",
    "generations",
    "audit_events",
    "outbox",
    "idempotency_keys",
)


def rls_statements() -> list[str]:
    statements: list[str] = []
    for table in TENANT_TABLES:
        statements.extend(
            [
                f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY',
                f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY',
                (
                    f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
                    "USING (tenant_id = current_setting('app.tenant_id', true)) "
                    "WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
                ),
            ]
        )
    return statements


def make_engine(database_url: str) -> AsyncEngine:
    if not database_url.startswith("postgresql+psycopg://"):
        raise ValueError("PostgreSQL psycopg async URL required")
    return create_async_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=40,
        pool_recycle=1800,
    )


async def set_tenant(session: AsyncSession, tenant_id: str) -> None:
    # Bound parameter is retained; no tenant-controlled SQL identifier is interpolated.
    await session.execute(
        text("SELECT set_config('app.tenant_id', :tenant, true)"), {"tenant": tenant_id}
    )


async def assert_application_role(session: AsyncSession) -> None:
    """Fail startup when the connected role can bypass the tenant RLS boundary."""

    posture = (
        await session.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        )
    ).one_or_none()
    if posture is None or bool(posture.rolsuper) or bool(posture.rolbypassrls):
        raise RuntimeError("database_application_role_bypasses_rls")
    owned = (
        await session.execute(
            text(
                "SELECT COUNT(*) FROM pg_class AS c "
                "JOIN pg_namespace AS n ON n.oid = c.relnamespace "
                "WHERE n.nspname = current_schema() "
                "AND c.relname = ANY(:tables) AND pg_get_userbyid(c.relowner) = current_user"
            ),
            {"tables": list(TENANT_TABLES)},
        )
    ).scalar_one()
    if int(owned) != 0:
        raise RuntimeError("database_application_role_owns_tenant_tables")


async def lock_workspace(
    session: AsyncSession,
    tenant_id: str,
    workspace_id: str,
    expected_generation: str,
) -> WorkspaceRow:
    await set_tenant(session, tenant_id)
    row = await session.get(
        WorkspaceRow,
        {"tenant_id": tenant_id, "workspace_id": workspace_id},
        with_for_update=True,
    )
    if row is None:
        raise KeyError("workspace_not_found")
    if row.current_generation_digest != expected_generation:
        raise RuntimeError("workspace_generation_changed")
    return row


class PostgresBackend:
    """Serializable tenant backend using forced RLS and a transactional outbox."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def startup(self) -> None:
        async with self.sessions() as session:
            await assert_application_role(session)

    async def create_workspace(self, tenant_id: str, workspace_id: str) -> WorkspaceRecord:
        now = datetime.now(UTC)
        generation = digest_bytes(
            canonical_bytes(
                {
                    "tenant_id": tenant_id,
                    "workspace_id": workspace_id,
                    "sequence": 0,
                    "created_at": now.isoformat(),
                }
            )
        )
        try:
            async with self.sessions.begin() as session:
                await set_tenant(session, tenant_id)
                session.add(
                    WorkspaceRow(
                        tenant_id=tenant_id,
                        workspace_id=workspace_id,
                        current_generation_digest=generation,
                        generation_sequence=0,
                        created_at=now,
                    )
                )
        except IntegrityError as error:
            raise ValueError("workspace_already_exists") from error
        return WorkspaceRecord(tenant_id, workspace_id, generation)

    async def workspace(self, tenant_id: str, workspace_id: str) -> WorkspaceRecord:
        async with self.sessions() as session:
            await set_tenant(session, tenant_id)
            row = await session.get(
                WorkspaceRow, {"tenant_id": tenant_id, "workspace_id": workspace_id}
            )
            if row is None:
                raise ValueError("workspace_not_found")
            return WorkspaceRecord(
                tenant_id=row.tenant_id,
                workspace_id=row.workspace_id,
                generation_digest=row.current_generation_digest,
                sequence=row.generation_sequence,
            )

    async def enqueue(self, tenant_id: str, workspace_id: str, topic: str) -> str:
        message_id = secrets.token_hex(16)
        async with self.sessions.begin() as session:
            await set_tenant(session, tenant_id)
            session.add(
                OutboxRow(
                    tenant_id=tenant_id,
                    message_id=message_id,
                    workspace_id=workspace_id,
                    topic=topic,
                    payload={"workspace_id": workspace_id, "topic": topic},
                    available_at=datetime.now(UTC),
                )
            )
        return message_id

    async def job(self, tenant_id: str, job_id: str) -> dict[str, Any] | None:
        async with self.sessions() as session:
            await set_tenant(session, tenant_id)
            row = await session.get(OutboxRow, {"tenant_id": tenant_id, "message_id": job_id})
            if row is None:
                return None
            status = (
                "succeeded" if row.completed_at else "running" if row.leased_until else "queued"
            )
            return {
                "tenant_id": tenant_id,
                "workspace_id": row.workspace_id,
                "topic": row.topic,
                "status": status,
            }

    async def idempotency_get(
        self, tenant_id: str, key: str, request_digest: str
    ) -> ApiResponse | None:
        async with self.sessions() as session:
            await set_tenant(session, tenant_id)
            row = await session.get(
                IdempotencyRow, {"tenant_id": tenant_id, "idempotency_key": key}
            )
            if row is None or row.expires_at <= datetime.now(UTC):
                return None
            if not secrets.compare_digest(row.request_digest, request_digest):
                raise ValueError("idempotency_key_reused_with_different_request")
            return ApiResponse.model_validate(loads_bounded(row.response_body))

    async def idempotency_put(
        self, tenant_id: str, key: str, request_digest: str, response: ApiResponse
    ) -> None:
        body = canonical_bytes(response.model_dump(mode="json", exclude_none=True))
        async with self.sessions.begin() as session:
            await set_tenant(session, tenant_id)
            existing = await session.get(
                IdempotencyRow, {"tenant_id": tenant_id, "idempotency_key": key}
            )
            if existing is not None:
                if not secrets.compare_digest(existing.request_digest, request_digest):
                    raise ValueError("idempotency_key_reused_with_different_request")
                return
            session.add(
                IdempotencyRow(
                    tenant_id=tenant_id,
                    idempotency_key=key,
                    request_digest=request_digest,
                    response_status=200,
                    response_body=body,
                    expires_at=datetime.now(UTC) + timedelta(hours=24),
                )
            )
