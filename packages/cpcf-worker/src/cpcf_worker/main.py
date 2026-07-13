# SPDX-License-Identifier: Apache-2.0
"""Trusted analysis worker entrypoint.

The worker accepts only typed audit jobs. Adapter execution is deliberately absent.
"""

from __future__ import annotations

import asyncio
import os
import sys


async def run_once() -> int:
    from cpcf_api.db import make_engine, set_tenant
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker

    database_url = os.environ.get("CPCF_DATABASE_URL")
    tenant_id = os.environ.get("CPCF_WORKER_TENANT")
    if not database_url or not tenant_id:
        raise RuntimeError("CPCF_DATABASE_URL and CPCF_WORKER_TENANT are required")
    engine = make_engine(database_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions.begin() as session:
        await set_tenant(session, tenant_id)
        row = await session.execute(
            text(
                "SELECT message_id FROM outbox "
                "WHERE topic = 'analysis' AND completed_at IS NULL "
                "AND (leased_until IS NULL OR leased_until < clock_timestamp()) "
                "ORDER BY available_at, message_id FOR UPDATE SKIP LOCKED LIMIT 1"
            )
        )
        return 0 if row.scalar_one_or_none() is None else 1


def main() -> int:
    try:
        return asyncio.run(run_once())
    except ModuleNotFoundError:
        print(
            "The worker extra is required. Install it with: "
            'pip install "collective-phase-control-fabric[worker]"',
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
