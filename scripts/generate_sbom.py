# SPDX-License-Identifier: Apache-2.0
"""Generate a deterministic CycloneDX 1.6 inventory from the frozen uv lock."""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
import uuid
from pathlib import Path
from typing import Any


def _hashes(package: dict[str, Any]) -> list[dict[str, str]]:
    values: set[str] = set()
    sdist = package.get("sdist")
    if isinstance(sdist, dict) and isinstance(sdist.get("hash"), str):
        values.add(sdist["hash"])
    for wheel in package.get("wheels", []):
        if isinstance(wheel, dict) and isinstance(wheel.get("hash"), str):
            values.add(wheel["hash"])
    return [
        {"alg": "SHA-256", "content": value.removeprefix("sha256:")}
        for value in sorted(values)
        if value.startswith("sha256:")
    ]


def generate(lock_path: Path) -> dict[str, Any]:
    raw = lock_path.read_bytes()
    lock = tomllib.loads(raw.decode("utf-8"))
    components: list[dict[str, Any]] = []
    for package in sorted(
        lock.get("package", []), key=lambda item: (item["name"], item["version"])
    ):
        name = str(package["name"])
        version = str(package["version"])
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{name}@{version}",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
        }
        hashes = _hashes(package)
        if hashes:
            component["hashes"] = hashes
        components.append(component)
    lock_digest = hashlib.sha256(raw).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, lock_digest)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "pkg:pypi/cpcf-core@0.6.0",
                "name": "CPCF uv workspace",
                "version": "0.6.0",
            },
            "properties": [{"name": "cpcf:uv-lock-sha256", "value": lock_digest}],
        },
        "components": components,
    }


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate_sbom.py UV_LOCK OUTPUT_JSON")
    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            generate(Path(sys.argv[1])), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
