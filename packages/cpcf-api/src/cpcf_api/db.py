# SPDX-License-Identifier: Apache-2.0
"""PostgreSQL 18 schema, forced RLS, generation locking, and transactional outbox."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
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
    select,
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

from collective_phase_control_fabric.v6.authority import (
    AuthoritativeView,
    load_authoritative_generation,
)
from collective_phase_control_fabric.v6.canonical import (
    canonical_bytes,
    digest_bytes,
    loads_bounded,
)
from collective_phase_control_fabric.v6.models import (
    AuditEvent,
    TrustedTimeReceipt,
    TrustPolicyDocument,
    WorkspaceGeneration,
)
from collective_phase_control_fabric.v6.registry import document_digest, parse_document
from collective_phase_control_fabric.v6.storage import (
    ObjectStore,
    generation_digest,
    validate_ledger,
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
    root_spki_fingerprint: Mapped[str] = mapped_column(String(71), nullable=False)
    genesis_envelope_fingerprint: Mapped[str] = mapped_column(String(71), nullable=False)
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


class LedgerRow(Base):
    __tablename__ = "object_ledger"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    generation_digest: Mapped[str] = mapped_column(String(71), primary_key=True)
    object_digest: Mapped[str] = mapped_column(String(71), primary_key=True)
    object_kind: Mapped[str] = mapped_column(String(128), nullable=False)
    authority_status: Mapped[str] = mapped_column(String(32), nullable=False)
    source_digests: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "workspace_id", "generation_digest"],
            ["generations.tenant_id", "generations.workspace_id", "generations.generation_digest"],
        ),
        ForeignKeyConstraint(
            ["tenant_id", "object_digest"],
            ["objects.tenant_id", "objects.object_digest"],
        ),
    )


class QuarantineRow(Base):
    __tablename__ = "quarantine"
    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    object_digest: Mapped[str] = mapped_column(String(71), primary_key=True)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    quarantined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "workspace_id"],
            ["workspaces.tenant_id", "workspaces.workspace_id"],
        ),
        ForeignKeyConstraint(
            ["tenant_id", "object_digest"],
            ["objects.tenant_id", "objects.object_digest"],
        ),
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
    "object_ledger",
    "audit_events",
    "quarantine",
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


@dataclass(frozen=True)
class ObjectAdmission:
    object_digest: str
    object_kind: str
    authority_status: str
    byte_length: int
    object_key: str


@dataclass(frozen=True)
class GenerationMutation:
    tenant_id: str
    workspace_id: str
    expected_generation: str
    generation: WorkspaceGeneration
    audit_event: AuditEvent
    idempotency_key: str
    request_digest: str
    response: ApiResponse
    object_admissions: tuple[ObjectAdmission, ...] = ()
    quarantine_additions: tuple[tuple[str, str], ...] = ()
    quarantine_resolutions: tuple[str, ...] = ()
    outbox_topic: str | None = None
    outbox_payload: dict[str, Any] = field(default_factory=dict)


def _validate_generation_mutation(
    mutation: GenerationMutation,
    object_store: ObjectStore,
) -> None:
    generation = mutation.generation
    if generation.metadata.tenant_id != mutation.tenant_id:
        raise ValueError("generation_tenant_mismatch")
    if generation.metadata.workspace_id != mutation.workspace_id:
        raise ValueError("generation_workspace_mismatch")
    if generation.spec.generation_digest != generation_digest(generation):
        raise ValueError("generation_digest_mismatch")
    if generation.spec.prior_generation_digest != mutation.expected_generation:
        raise ValueError("generation_predecessor_mismatch")
    if not 16 <= len(mutation.idempotency_key) <= 128:
        raise ValueError("idempotency_key_length_invalid")
    request_hash = mutation.request_digest.removeprefix("sha256:")
    if (
        len(request_hash) != 64
        or request_hash != request_hash.lower()
        or any(character not in "0123456789abcdef" for character in request_hash)
    ):
        raise ValueError("request_digest_invalid")
    if mutation.response.generation_digest != generation.spec.generation_digest:
        raise ValueError("response_generation_binding_mismatch")
    if document_digest(mutation.audit_event) != generation.spec.history_head_digest:
        raise ValueError("generation_history_head_mismatch")
    if mutation.audit_event.metadata.tenant_id != mutation.tenant_id:
        raise ValueError("audit_event_tenant_mismatch")
    if mutation.audit_event.metadata.workspace_id != mutation.workspace_id:
        raise ValueError("audit_event_workspace_mismatch")
    ledger_reasons = validate_ledger(generation, object_store)
    if ledger_reasons:
        raise ValueError("generation_ledger_invalid:" + ",".join(ledger_reasons))
    admissions = {item.object_digest: item for item in mutation.object_admissions}
    if len(admissions) != len(mutation.object_admissions):
        raise ValueError("object_admission_digest_duplicate")
    ledger = {item.object_digest: item for item in generation.spec.ledger}
    for digest, admission in admissions.items():
        entry = ledger.get(digest)
        if entry is None:
            raise ValueError("object_admission_not_in_generation")
        if (
            entry.object_kind != admission.object_kind
            or entry.authority_status != admission.authority_status
        ):
            raise ValueError("object_admission_ledger_mismatch")
        if admission.byte_length != len(object_store.get(mutation.tenant_id, digest)):
            raise ValueError("object_admission_length_mismatch")
        key_parts = admission.object_key.split("/")
        if (
            "\\" in admission.object_key
            or any(part in {"", ".", ".."} for part in key_parts)
            or key_parts[-3:] != [mutation.tenant_id, "sha256", digest[7:]]
        ):
            raise ValueError("object_admission_key_not_tenant_digest_scoped")
    quarantine_digests = [digest for digest, _ in mutation.quarantine_additions]
    if len(quarantine_digests) != len(set(quarantine_digests)):
        raise ValueError("quarantine_addition_duplicate")
    if len(mutation.quarantine_resolutions) != len(set(mutation.quarantine_resolutions)):
        raise ValueError("quarantine_resolution_duplicate")


def _quarantine_interrupted_uploads(
    object_store: ObjectStore,
    tenant_id: str,
    admissions: tuple[ObjectAdmission, ...],
) -> None:
    quarantine = getattr(object_store, "quarantine_unreferenced", None)
    if not callable(quarantine):
        return
    for admission in admissions:
        quarantine(tenant_id, admission.object_digest, "database_transaction_rolled_back")


class PostgresBackend:
    """Serializable tenant backend using forced RLS and a transactional outbox."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def startup(self) -> None:
        async with self.sessions() as session:
            await assert_application_role(session)

    async def create_workspace(
        self,
        tenant_id: str,
        workspace_id: str,
        root_spki_fingerprint: str,
        genesis_envelope_fingerprint: str,
    ) -> WorkspaceRecord:
        now = datetime.now(UTC)
        generation = digest_bytes(
            canonical_bytes(
                {
                    "tenant_id": tenant_id,
                    "workspace_id": workspace_id,
                    "sequence": 0,
                    "root_spki_fingerprint": root_spki_fingerprint,
                    "genesis_envelope_fingerprint": genesis_envelope_fingerprint,
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
                        root_spki_fingerprint=root_spki_fingerprint,
                        genesis_envelope_fingerprint=genesis_envelope_fingerprint,
                        created_at=now,
                    )
                )
        except IntegrityError as error:
            raise ValueError("workspace_already_exists") from error
        return WorkspaceRecord(
            tenant_id,
            workspace_id,
            generation,
            root_spki_fingerprint=root_spki_fingerprint,
            genesis_envelope_fingerprint=genesis_envelope_fingerprint,
        )

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
                root_spki_fingerprint=row.root_spki_fingerprint,
                genesis_envelope_fingerprint=row.genesis_envelope_fingerprint,
            )

    async def authoritative_view(
        self,
        tenant_id: str,
        workspace_id: str,
        object_store: ObjectStore,
        *,
        policy: TrustPolicyDocument,
        trusted_time: TrustedTimeReceipt,
    ) -> AuthoritativeView:
        """Load one DB snapshot and route every authoritative read through the shared loader."""

        async with self.sessions() as session:
            await set_tenant(session, tenant_id)
            workspace = await session.get(
                WorkspaceRow,
                {"tenant_id": tenant_id, "workspace_id": workspace_id},
            )
            if workspace is None:
                raise ValueError("workspace_not_found")
            row = await session.get(
                GenerationRow,
                {
                    "tenant_id": tenant_id,
                    "workspace_id": workspace_id,
                    "generation_digest": workspace.current_generation_digest,
                },
            )
            if row is None:
                raise ValueError("workspace_generation_not_admitted")
            parsed = parse_document(row.manifest)
            if not isinstance(parsed, WorkspaceGeneration):
                raise ValueError("workspace_generation_document_required")
            ledger_result = await session.execute(
                select(LedgerRow).where(
                    LedgerRow.tenant_id == tenant_id,
                    LedgerRow.workspace_id == workspace_id,
                    LedgerRow.generation_digest == workspace.current_generation_digest,
                )
            )
            stored_ledger = {
                (
                    item.object_digest,
                    item.object_kind,
                    item.authority_status,
                    tuple(item.source_digests),
                )
                for item in ledger_result.scalars().all()
            }
            manifest_ledger = {
                (
                    item.object_digest,
                    item.object_kind,
                    item.authority_status,
                    tuple(item.source_digests),
                )
                for item in parsed.spec.ledger
            }
            if stored_ledger != manifest_ledger:
                raise RuntimeError("database_ledger_manifest_mismatch")
            return load_authoritative_generation(
                parsed,
                object_store,
                policy=policy,
                trusted_time=trusted_time,
                expected_root_spki_fingerprint=workspace.root_spki_fingerprint,
                expected_genesis_envelope_fingerprint=workspace.genesis_envelope_fingerprint,
            )

    async def commit_generation(
        self,
        mutation: GenerationMutation,
        object_store: ObjectStore,
    ) -> ApiResponse:
        """Atomically commit every authoritative database effect for one generation."""

        _validate_generation_mutation(mutation, object_store)
        now = datetime.now(UTC)
        admissions = {item.object_digest: item for item in mutation.object_admissions}
        try:
            async with self.sessions.begin() as session:
                await session.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
                await set_tenant(session, mutation.tenant_id)
                existing_idempotency = await session.get(
                    IdempotencyRow,
                    {
                        "tenant_id": mutation.tenant_id,
                        "idempotency_key": mutation.idempotency_key,
                    },
                )
                if existing_idempotency is not None:
                    if not secrets.compare_digest(
                        existing_idempotency.request_digest, mutation.request_digest
                    ):
                        raise ValueError("idempotency_key_reused_with_different_request")
                    return ApiResponse.model_validate(
                        loads_bounded(existing_idempotency.response_body)
                    )
                workspace = await lock_workspace(
                    session,
                    mutation.tenant_id,
                    mutation.workspace_id,
                    mutation.expected_generation,
                )
                if mutation.generation.spec.sequence != workspace.generation_sequence + 1:
                    raise ValueError("generation_sequence_mismatch")
                prior_generation = await session.get(
                    GenerationRow,
                    {
                        "tenant_id": mutation.tenant_id,
                        "workspace_id": mutation.workspace_id,
                        "generation_digest": mutation.expected_generation,
                    },
                )
                prior_history_head: str | None = None
                if prior_generation is not None:
                    prior_spec = prior_generation.manifest.get("spec", {})
                    if isinstance(prior_spec, dict):
                        candidate = prior_spec.get("history_head_digest")
                        prior_history_head = candidate if isinstance(candidate, str) else None
                if mutation.audit_event.spec.prior_event_digest != prior_history_head:
                    raise ValueError("audit_event_predecessor_mismatch")
                for entry in mutation.generation.spec.ledger:
                    stored = await session.get(
                        ObjectRow,
                        {
                            "tenant_id": mutation.tenant_id,
                            "object_digest": entry.object_digest,
                        },
                    )
                    admission = admissions.get(entry.object_digest)
                    if stored is None:
                        if admission is None:
                            raise ValueError("object_admission_required")
                        session.add(
                            ObjectRow(
                                tenant_id=mutation.tenant_id,
                                object_digest=admission.object_digest,
                                object_kind=admission.object_kind,
                                authority_status=admission.authority_status,
                                byte_length=admission.byte_length,
                                object_key=admission.object_key,
                                created_at=now,
                            )
                        )
                    elif stored.object_kind != entry.object_kind or stored.byte_length != len(
                        object_store.get(mutation.tenant_id, entry.object_digest)
                    ):
                        raise ValueError("stored_object_metadata_mismatch")
                # Ledger rows have a composite foreign key to the object table.  An
                # explicit boundary makes the insert order independent of dialect
                # and ORM unit-of-work heuristics while retaining one transaction.
                await session.flush()
                session.add(
                    GenerationRow(
                        tenant_id=mutation.tenant_id,
                        workspace_id=mutation.workspace_id,
                        generation_digest=mutation.generation.spec.generation_digest,
                        sequence=mutation.generation.spec.sequence,
                        prior_generation_digest=mutation.expected_generation,
                        manifest=mutation.generation.model_dump(mode="json", exclude_none=True),
                        created_at=now,
                    )
                )
                await session.flush()
                for entry in mutation.generation.spec.ledger:
                    session.add(
                        LedgerRow(
                            tenant_id=mutation.tenant_id,
                            workspace_id=mutation.workspace_id,
                            generation_digest=mutation.generation.spec.generation_digest,
                            object_digest=entry.object_digest,
                            object_kind=entry.object_kind,
                            authority_status=entry.authority_status,
                            source_digests=list(entry.source_digests),
                        )
                    )
                session.add(
                    AuditEventRow(
                        tenant_id=mutation.tenant_id,
                        workspace_id=mutation.workspace_id,
                        event_sequence=mutation.generation.spec.sequence,
                        event_digest=document_digest(mutation.audit_event),
                        prior_event_digest=mutation.audit_event.spec.prior_event_digest,
                        event=mutation.audit_event.model_dump(mode="json", exclude_none=True),
                    )
                )
                for digest, reason_code in mutation.quarantine_additions:
                    if digest not in {
                        item.object_digest for item in mutation.generation.spec.ledger
                    }:
                        raise ValueError("quarantine_object_not_in_generation")
                    existing_quarantine = await session.get(
                        QuarantineRow,
                        {
                            "tenant_id": mutation.tenant_id,
                            "workspace_id": mutation.workspace_id,
                            "object_digest": digest,
                        },
                    )
                    if existing_quarantine is None:
                        session.add(
                            QuarantineRow(
                                tenant_id=mutation.tenant_id,
                                workspace_id=mutation.workspace_id,
                                object_digest=digest,
                                reason_code=reason_code,
                                quarantined_at=now,
                            )
                        )
                    else:
                        existing_quarantine.reason_code = reason_code
                        existing_quarantine.quarantined_at = now
                        existing_quarantine.resolved_at = None
                for digest in mutation.quarantine_resolutions:
                    existing_quarantine = await session.get(
                        QuarantineRow,
                        {
                            "tenant_id": mutation.tenant_id,
                            "workspace_id": mutation.workspace_id,
                            "object_digest": digest,
                        },
                    )
                    if existing_quarantine is None or existing_quarantine.resolved_at is not None:
                        raise ValueError("quarantine_resolution_not_active")
                    existing_quarantine.resolved_at = now
                if mutation.outbox_topic is not None:
                    session.add(
                        OutboxRow(
                            tenant_id=mutation.tenant_id,
                            message_id=secrets.token_hex(16),
                            workspace_id=mutation.workspace_id,
                            topic=mutation.outbox_topic,
                            payload=dict(mutation.outbox_payload),
                            available_at=now,
                        )
                    )
                response_body = canonical_bytes(
                    mutation.response.model_dump(mode="json", exclude_none=True)
                )
                session.add(
                    IdempotencyRow(
                        tenant_id=mutation.tenant_id,
                        idempotency_key=mutation.idempotency_key,
                        request_digest=mutation.request_digest,
                        response_status=200,
                        response_body=response_body,
                        expires_at=now + timedelta(hours=24),
                    )
                )
                workspace.current_generation_digest = mutation.generation.spec.generation_digest
                workspace.generation_sequence = mutation.generation.spec.sequence
        except Exception:
            _quarantine_interrupted_uploads(
                object_store, mutation.tenant_id, mutation.object_admissions
            )
            raise
        return mutation.response

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
