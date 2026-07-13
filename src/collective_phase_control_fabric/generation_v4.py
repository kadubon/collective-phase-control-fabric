# SPDX-License-Identifier: Apache-2.0
"""Immutable typed-object generations for CPCF v0.4."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import canonical_v3_bytes, digest_v3_json
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.generation import _atomic_bytes
from collective_phase_control_fabric.limits import (
    MAX_JSON_BYTES,
    load_json_bounded,
    loads_json_bounded,
)
from collective_phase_control_fabric.locking import WorkspaceLock
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject, JsonValue

V4 = "0.4.0"


def generation_digest(value: JsonObject) -> str:
    """Digest a manifest without its self-identifying generation field."""

    payload = deepcopy(value)
    payload.pop("generation_id", None)
    return digest_v3_json(cast(JsonValue, payload))


def ledger_entry(
    digest: str,
    *,
    kind: str,
    schema_ref: str,
    source_chain: list[str] | None = None,
    authority_key_id: str | None = None,
    lifecycle: str = "active",
) -> JsonObject:
    """Create one closed typed ledger entry."""

    return {
        "digest": digest,
        "kind": kind,
        "schema_ref": schema_ref,
        "source_chain": source_chain or [],
        "authority_key_id": authority_key_id,
        "lifecycle": lifecycle,
    }


class GenerationStoreV4:
    """Own native v0.4 CAS objects, manifests, and the atomic CURRENT pointer."""

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
        selected = self.current_path.read_text(encoding="ascii").strip()
        return selected or None

    def manifest_path(self, generation_id: str) -> Path:
        if not generation_id.startswith("sha256:") or len(generation_id) != 71:
            raise ValueError("malformed generation identifier")
        return self.control / "generations" / generation_id[7:] / "manifest.json"

    def put_json(self, value: JsonValue) -> str:
        return self.cas.put(canonical_v3_bytes(value)).digest

    def get_json(self, digest: str) -> JsonValue:
        return loads_json_bounded(self.cas.get_limited(digest, MAX_JSON_BYTES))

    def load_manifest(self, generation_id: str | None = None) -> JsonObject:
        selected = generation_id or self.current_id()
        if selected is None:
            raise FileNotFoundError("workspace CURRENT generation is missing")
        value = load_json_bounded(self.manifest_path(selected))
        if not isinstance(value, dict):
            raise ValueError("generation manifest must be an object")
        if value.get("schema_version") != V4:
            raise ValueError("not a native v0.4 generation")
        if value.get("generation_id") != selected or generation_digest(value) != selected:
            raise ValueError("generation digest mismatch")
        errors = validation_errors("workspace-generation", value, V4)
        if errors:
            raise ValueError(f"generation schema invalid: {errors[0]['message']}")
        return value

    def commit(self, payload: JsonObject, *, expected_current: str | None) -> JsonObject:
        """Validate and expose a complete generation with one atomic pointer replacement."""

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
            manifest["schema_version"] = V4
            manifest["previous_generation"] = actual
            manifest["history_root"] = digest_v3_json(cast(JsonValue, manifest.get("history", [])))
            manifest.pop("generation_id", None)
            identifier = generation_digest(manifest)
            manifest["generation_id"] = identifier
            errors = validation_errors("workspace-generation", manifest, V4)
            digests = [
                str(item.get("digest"))
                for item in manifest.get("objects", [])
                if isinstance(item, dict)
            ]
            if len(digests) != len(set(digests)):
                errors.append({"message": "duplicate object digest", "json_pointer": "/objects"})
            history = manifest.get("history", [])
            if isinstance(history, list):
                for index, event in enumerate(history):
                    if not isinstance(event, dict) or event.get(
                        "previous_event_digest"
                    ) != digest_v3_json(cast(JsonValue, history[:index])):
                        errors.append(
                            {
                                "message": "history hash chain invalid",
                                "json_pointer": f"/history/{index}",
                            }
                        )
            if errors:
                return {
                    "command_status": "failed",
                    "failure_code": "generation_schema_invalid",
                    "schema_errors": errors,
                    "generation_committed": False,
                }
            target = self.manifest_path(identifier)
            if target.exists():
                existing = load_json_bounded(target)
                if existing != manifest:
                    raise RuntimeError("generation digest collision")
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                _atomic_bytes(target, canonical_v3_bytes(manifest) + b"\n")
            _atomic_bytes(self.current_path, f"{identifier}\n".encode("ascii"))
            return {
                "command_status": "ok",
                "generation_id": identifier,
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
            except (OSError, ValueError) as error:
                errors.append(
                    {"code": "generation_invalid", "generation_id": selected, "detail": str(error)}
                )
                break
            previous = manifest.get("previous_generation")
            selected = previous if isinstance(previous, str) else None
        return errors


def empty_generation_v4(
    *,
    contract_digest: str,
    trust_policy_digest: str,
    trusted_time_receipt_digest: str | None,
    analysis_epoch: str | None,
    objects: list[JsonObject],
    quarantine: list[str] | None = None,
) -> JsonObject:
    """Return a first-generation v0.4 payload."""

    return {
        "schema_version": V4,
        "generation_id": "sha256:" + "0" * 64,
        "previous_generation": None,
        "contract_digest": contract_digest,
        "trust_policy_digest": trust_policy_digest,
        "trusted_time_receipt_digest": trusted_time_receipt_digest,
        "analysis_epoch": analysis_epoch,
        "objects": objects,
        "history": [],
        "history_root": digest_v3_json([]),
        "quarantine": quarantine or [],
    }
