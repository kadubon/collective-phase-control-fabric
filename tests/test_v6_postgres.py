# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime

import pytest
from cpcf_api.app import ApiResponse
from cpcf_api.db import GenerationMutation, ObjectAdmission, PostgresBackend, make_engine

from collective_phase_control_fabric.v6.canonical import canonical_bytes
from collective_phase_control_fabric.v6.models import (
    AuditEvent,
    AuditEventSpec,
    LedgerEntry,
    Metadata,
    WorkspaceGeneration,
    WorkspaceGenerationSpec,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.storage import MemoryObjectStore, generation_digest

psycopg = pytest.importorskip("psycopg")


@pytest.mark.postgres
def test_application_role_guard_rejects_owner_and_accepts_rls_role() -> None:
    app_url = os.environ.get("CPCF_TEST_DATABASE_URL")
    owner_url = os.environ.get("CPCF_TEST_OWNER_DATABASE_URL")
    if not app_url or not owner_url:
        pytest.skip("PostgreSQL application and owner URLs are not configured")

    async def verify() -> None:
        app_engine = make_engine(app_url)
        owner_engine = make_engine(owner_url)
        try:
            await PostgresBackend(app_engine).startup()
            with pytest.raises(RuntimeError, match="database_application_role_bypasses_rls"):
                await PostgresBackend(owner_engine).startup()
        finally:
            await app_engine.dispose()
            await owner_engine.dispose()

    asyncio.run(verify())


@pytest.mark.postgres
def test_forced_rls_prevents_cross_tenant_visibility() -> None:
    url = os.environ.get("CPCF_TEST_DATABASE_URL")
    if not url:
        pytest.skip("CPCF_TEST_DATABASE_URL is not configured")
    with (
        psycopg.connect(url.replace("postgresql+psycopg://", "postgresql://")) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname='workspaces'"
        )
        assert cursor.fetchone() == (True, True)
        for tenant in ("tenant-a", "tenant-b"):
            cursor.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
            cursor.execute(
                "INSERT INTO workspaces "
                "(tenant_id, workspace_id, current_generation_digest, "
                "generation_sequence, root_spki_fingerprint, "
                "genesis_envelope_fingerprint, created_at) "
                "VALUES (%s, 'workspace', %s, 0, %s, %s, %s)",
                (
                    tenant,
                    "sha256:" + ("a" if tenant == "tenant-a" else "b") * 64,
                    "sha256:" + "1" * 64,
                    "sha256:" + "2" * 64,
                    datetime.now(UTC),
                ),
            )
        cursor.execute("SELECT set_config('app.tenant_id', 'tenant-a', true)")
        cursor.execute("SELECT tenant_id FROM workspaces ORDER BY tenant_id")
        assert cursor.fetchall() == [("tenant-a",)]


@pytest.mark.postgres
def test_serializable_generation_unit_of_work_advances_all_authoritative_rows() -> None:
    url = os.environ.get("CPCF_TEST_DATABASE_URL")
    if not url:
        pytest.skip("CPCF_TEST_DATABASE_URL is not configured")

    async def verify() -> None:
        engine = make_engine(url)
        backend = PostgresBackend(engine)
        store = MemoryObjectStore()
        now = datetime.now(UTC)
        try:
            workspace = await backend.create_workspace(
                "tenant-a",
                "uow-workspace",
                "sha256:" + "1" * 64,
                "sha256:" + "2" * 64,
            )
            event = AuditEvent(
                metadata=Metadata(
                    tenant_id="tenant-a",
                    workspace_id="uow-workspace",
                    object_id="uow-event",
                    created_at=now,
                ),
                spec=AuditEventSpec(
                    event_id="uow-event",
                    event_type="object_imported",
                    occurred_at=now,
                ),
            )
            event_bytes = canonical_bytes(event.model_dump(mode="json", exclude_none=True))
            event_digest = store.put("tenant-a", event_bytes)
            placeholder = WorkspaceGeneration(
                metadata=Metadata(
                    tenant_id="tenant-a",
                    workspace_id="uow-workspace",
                    object_id="uow-generation",
                    created_at=now,
                ),
                spec=WorkspaceGenerationSpec(
                    generation_digest="sha256:" + "0" * 64,
                    prior_generation_digest=workspace.generation_digest,
                    sequence=1,
                    ledger=[
                        LedgerEntry(
                            object_digest=event_digest,
                            object_kind="audit-event",
                            authority_status="active",
                        )
                    ],
                    history_head_digest=document_digest(event),
                ),
            )
            generation = placeholder.model_copy(
                update={
                    "spec": placeholder.spec.model_copy(
                        update={"generation_digest": generation_digest(placeholder)}
                    )
                }
            )
            response = ApiResponse(
                status="ok",
                code="generation_committed",
                effect_class="remote_write",
                tenant_id="tenant-a",
                workspace_id="uow-workspace",
                generation_digest=generation.spec.generation_digest,
                trace_id="1" * 32,
            )
            mutation = GenerationMutation(
                tenant_id="tenant-a",
                workspace_id="uow-workspace",
                expected_generation=workspace.generation_digest,
                generation=generation,
                audit_event=event,
                idempotency_key="postgres-uow-key",
                request_digest="sha256:" + "3" * 64,
                response=response,
                object_admissions=(
                    ObjectAdmission(
                        object_digest=event_digest,
                        object_kind="audit-event",
                        authority_status="active",
                        byte_length=len(event_bytes),
                        object_key=f"cpcf/tenant-a/sha256/{event_digest[7:]}",
                    ),
                ),
                outbox_topic="analysis",
                outbox_payload={"workspace_id": "uow-workspace"},
            )
            assert await backend.commit_generation(mutation, store) == response
            current = await backend.workspace("tenant-a", "uow-workspace")
            assert current.generation_digest == generation.spec.generation_digest
            assert current.sequence == 1
            assert await backend.commit_generation(mutation, store) == response
        finally:
            await engine.dispose()

    asyncio.run(verify())
