# SPDX-License-Identifier: Apache-2.0
"""Immutable, single-pointer workspace generations for CPCF v0.3."""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from copy import deepcopy
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import (
    canonical_v3_bytes,
    digest_v3_json,
    loads_json_strict,
)
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.locking import WorkspaceLock
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject, JsonValue


def _atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        try:
            directory = os.open(path.parent, os.O_RDONLY)
        except (AttributeError, OSError):
            directory = None
        if directory is not None:
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def _generation_digest(value: JsonObject) -> str:
    payload = deepcopy(value)
    payload.pop("generation_id", None)
    return digest_v3_json(cast(JsonValue, payload))


class GenerationStore:
    """Own immutable generation manifests and one atomic CURRENT pointer."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.control = self.root / ".cpcf"
        self.cas = ContentAddressedStore(self.control / "cas")

    @property
    def current_path(self) -> Path:
        return self.control / "CURRENT"

    def current_id(self) -> str | None:
        if not self.current_path.is_file():
            return None
        value = self.current_path.read_text(encoding="ascii").strip()
        return value or None

    def manifest_path(self, generation_id: str) -> Path:
        if not generation_id.startswith("sha256:") or len(generation_id) != 71:
            raise ValueError("malformed generation identifier")
        return self.control / "generations" / generation_id.split(":", 1)[1] / "manifest.json"

    def load_manifest(self, generation_id: str | None = None) -> JsonObject:
        selected = generation_id or self.current_id()
        if selected is None:
            raise FileNotFoundError("workspace CURRENT generation is missing")
        value = loads_json_strict(self.manifest_path(selected).read_bytes())
        if not isinstance(value, dict):
            raise ValueError("generation manifest must be an object")
        if value.get("generation_id") != selected or _generation_digest(value) != selected:
            raise ValueError("generation digest mismatch")
        errors = validation_errors("workspace-generation", value, "0.3.0")
        if errors:
            raise ValueError(f"generation schema invalid: {errors[0]['message']}")
        return value

    def put_json(self, value: JsonValue) -> str:
        return self.cas.put(canonical_v3_bytes(value)).digest

    def get_json(self, digest: str) -> JsonValue:
        return loads_json_strict(self.cas.get(digest))

    def commit(self, payload: JsonObject, *, expected_current: str | None) -> JsonObject:
        """Commit one complete generation through a single pointer replacement."""

        with WorkspaceLock(self.root):
            actual = self.current_id()
            if actual != expected_current:
                return {
                    "command_status": "failed",
                    "failure_code": "concurrent_generation_comparison_failed",
                    "expected_generation": expected_current,
                    "actual_generation": actual,
                    "generation_committed": False,
                }
            manifest = deepcopy(payload)
            manifest["schema_version"] = "0.3.0"
            manifest["previous_generation"] = actual
            manifest.pop("generation_id", None)
            generation_id = _generation_digest(manifest)
            manifest["generation_id"] = generation_id
            errors = validation_errors("workspace-generation", manifest, "0.3.0")
            if errors:
                return {
                    "command_status": "failed",
                    "failure_code": "generation_schema_invalid",
                    "schema_errors": errors,
                    "generation_committed": False,
                }
            target = self.manifest_path(generation_id)
            if target.exists():
                existing = loads_json_strict(target.read_bytes())
                if existing != manifest:
                    raise RuntimeError("generation digest collision")
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                _atomic_bytes(target, canonical_v3_bytes(manifest) + b"\n")
            _atomic_bytes(self.current_path, f"{generation_id}\n".encode("ascii"))
            return {
                "command_status": "ok",
                "generation_id": generation_id,
                "previous_generation": actual,
                "generation_committed": True,
                "authoritative_pointer": str(self.current_path),
            }

    def verify_chain(self) -> list[JsonObject]:
        errors: list[JsonObject] = []
        seen: set[str] = set()
        selected = self.current_id()
        while selected is not None:
            if selected in seen:
                errors.append({"code": "generation_cycle", "generation_id": selected})
                break
            seen.add(selected)
            try:
                manifest = self.load_manifest(selected)
            except (FileNotFoundError, ValueError) as error:
                errors.append(
                    {"code": "generation_invalid", "generation_id": selected, "detail": str(error)}
                )
                break
            previous = manifest.get("previous_generation")
            selected = previous if isinstance(previous, str) else None
        return errors


def empty_generation(
    *, contract_digest: str, trust_policy_digest: str, analysis_epoch: str
) -> JsonObject:
    """Return the first-generation payload before its identifier is derived."""

    return {
        "schema_version": "0.3.0",
        "generation_id": "sha256:" + "0" * 64,
        "previous_generation": None,
        "contract_digest": contract_digest,
        "trust_policy_digest": trust_policy_digest,
        "analysis_epoch": analysis_epoch,
        "raw_artifacts": [],
        "envelopes": [],
        "receipts": [],
        "projections": [],
        "history": [],
        "quarantine": [],
    }
