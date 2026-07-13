# SPDX-License-Identifier: Apache-2.0
"""Provision the disposable non-owner PostgreSQL role used by CI RLS tests."""

from __future__ import annotations

import os

import psycopg
from psycopg import sql


def main() -> int:
    owner_url = os.environ["CPCF_DATABASE_OWNER_URL"].replace(
        "postgresql+psycopg://", "postgresql://"
    )
    role = "cpcf_app_test"
    password = os.environ["CPCF_DATABASE_APP_PASSWORD"]
    with (
        psycopg.connect(owner_url, autocommit=True) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
        if cursor.fetchone() is None:
            cursor.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                    "NOCREATEROLE NOINHERIT NOBYPASSRLS"
                ).format(sql.Identifier(role), sql.Literal(password))
            )
        cursor.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
        cursor.execute(
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}"
            ).format(sql.Identifier(role))
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
