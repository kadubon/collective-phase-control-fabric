# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime

import pytest
from cpcf_api.db import PostgresBackend, make_engine

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
                "generation_sequence, created_at) "
                "VALUES (%s, 'workspace', %s, 0, %s)",
                (
                    tenant,
                    "sha256:" + ("a" if tenant == "tenant-a" else "b") * 64,
                    datetime.now(UTC),
                ),
            )
        cursor.execute("SELECT set_config('app.tenant_id', 'tenant-a', true)")
        cursor.execute("SELECT tenant_id FROM workspaces ORDER BY tenant_id")
        assert cursor.fetchall() == [("tenant-a",)]
