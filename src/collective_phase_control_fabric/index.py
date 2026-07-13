# SPDX-License-Identifier: Apache-2.0
"""Rebuildable SQLite index for CPCF-owned content-addressed artifacts."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path


def index_artifact(database: Path, digest: str, path: Path, size: int) -> None:
    """Index a CPCF CAS object; authoritative external state is never stored here."""

    database.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS cas_objects "
            "(digest TEXT PRIMARY KEY, relative_path TEXT NOT NULL, size INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT OR REPLACE INTO cas_objects(digest, relative_path, size) VALUES (?, ?, ?)",
            (digest, str(path), size),
        )


def inspect_index(database: Path) -> dict[str, int | bool]:
    """Return index health without creating a database."""

    if not database.is_file():
        return {"exists": False, "object_count": 0}
    with closing(sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)) as connection:
        row = connection.execute("SELECT COUNT(*) FROM cas_objects").fetchone()
    return {"exists": True, "object_count": int(row[0]) if row else 0}
