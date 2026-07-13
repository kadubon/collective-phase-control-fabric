# SPDX-License-Identifier: Apache-2.0
"""Strict typed-object generations and hash-chained history for CPCF v0.5."""

from __future__ import annotations

import re
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

V5 = "0.5.0"
GENERATION_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_GENERATION_DEPTH = 4096
MAX_CURRENT_BYTES = 72
REPARSE_POINT = 0x400

KIND_SCHEMAS: dict[str, str | None] = {
    "contract": "phase-contract",
    "genesis-policy-statement": "signed-statement",
    "trust-policy": "trust-policy",
    "trust-quorum-decision": "signed-statement",
    "trusted-time-receipt": "signed-statement",
    "unit-registry": "unit-registry",
    "typed-flow-profile": "typed-flow-profile",
    "raw-artifact": None,
    "principal-attestation": "signed-statement",
    "adapter-capability": "signed-statement",
    "execution-policy": "signed-statement",
    "process-receipt": "process-receipt",
    "action-receipt": "action-receipt",
    "pending-projection": "pending-projection",
    "projection-approval": "signed-statement",
    "promoted-projection": None,
    "analysis-snapshot": "analysis-snapshot",
    "scientific-witness": "signed-statement",
    "perturbation-suite": "signed-statement",
    "perturbation-result": "perturbation-result",
    "coordination-plan": "coordination-plan",
    "coordination-session": "coordination-session",
    "coordination-event": "signed-statement",
    "measurement-protocol": "signed-statement",
    "registration-receipt": "signed-statement",
    "protocol-amendment": "signed-statement",
    "dataset-record": "signed-statement",
    "analysis-executable-record": "signed-statement",
    "trial-result-certificate": "signed-statement",
    "acceleration-evidence": "signed-statement",
    "bundle-root-attestation": "signed-statement",
    "legacy-manifest": None,
}


def generation_digest(value: JsonObject) -> str:
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
    authority_policy_digest: str | None = None,
    lifecycle: str = "active",
) -> JsonObject:
    if kind not in KIND_SCHEMAS:
        raise ValueError(f"unregistered ledger kind: {kind}")
    return {
        "digest": digest,
        "kind": kind,
        "schema_ref": schema_ref,
        "source_chain": source_chain or [],
        "authority_key_id": authority_key_id,
        "authority_policy_digest": authority_policy_digest,
        "lifecycle": lifecycle,
    }


def history_event(
    history: list[JsonObject], *, event_id: str, event_type: str, subject_digests: list[str]
) -> JsonObject:
    event: JsonObject = {
        "event_id": event_id,
        "event_type": event_type,
        "subject_digests": sorted(set(subject_digests)),
        "previous_event_digest": history[-1].get("event_digest") if history else None,
    }
    event["event_digest"] = digest_v3_json(cast(JsonValue, event))
    return event


def _is_reparse(path: Path) -> bool:
    try:
        stat = path.lstat()
    except OSError:
        return False
    return path.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & REPARSE_POINT)


def _assert_no_link_components(root: Path, path: Path) -> None:
    root_absolute = root.absolute()
    path_absolute = path.absolute()
    try:
        relative = path_absolute.relative_to(root_absolute)
    except ValueError as error:
        raise ValueError("authoritative path escapes workspace") from error
    cursor = root_absolute
    if cursor.exists() and _is_reparse(cursor):
        raise ValueError("workspace root cannot be a link or reparse point")
    for part in relative.parts:
        cursor = cursor / part
        if cursor.exists() and _is_reparse(cursor):
            raise ValueError("authoritative path contains a link or reparse point")


class GenerationStoreV5:
    """Own immutable v0.5 CAS objects, manifests, and one bounded CURRENT pointer."""

    def __init__(self, root: Path) -> None:
        self.root = root.absolute()
        self.control = self.root / ".cpcf"
        _assert_no_link_components(self.root, self.control)
        self.cas = ContentAddressedStore(self.control / "cas")

    @property
    def current_path(self) -> Path:
        return self.control / "CURRENT"

    def current_id(self) -> str | None:
        if not self.current_path.is_file():
            return None
        _assert_no_link_components(self.root, self.current_path)
        with self.current_path.open("rb") as stream:
            data = stream.read(MAX_CURRENT_BYTES + 1)
        if len(data) > MAX_CURRENT_BYTES:
            raise ValueError("CURRENT exceeds the bounded identifier size")
        try:
            selected = data.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise ValueError("CURRENT must contain ASCII") from error
        if not GENERATION_PATTERN.fullmatch(selected):
            raise ValueError("CURRENT contains a malformed generation identifier")
        return selected

    def manifest_path(self, generation_id: str) -> Path:
        if not GENERATION_PATTERN.fullmatch(generation_id):
            raise ValueError("malformed generation identifier")
        target = self.control / "generations" / generation_id[7:] / "manifest.json"
        _assert_no_link_components(self.root, target)
        return target

    def put_json(self, value: JsonValue) -> str:
        return self.cas.put(canonical_v3_bytes(value)).digest

    def put_bytes(self, value: bytes) -> str:
        return self.cas.put(value).digest

    def get_json(self, digest: str) -> JsonValue:
        return loads_json_bounded(self.cas.get_limited(digest, MAX_JSON_BYTES))

    def load_manifest(self, generation_id: str | None = None) -> JsonObject:
        selected = generation_id or self.current_id()
        if selected is None:
            raise FileNotFoundError("workspace CURRENT generation is missing")
        value = load_json_bounded(self.manifest_path(selected))
        if not isinstance(value, dict):
            raise ValueError("generation manifest must be an object")
        if value.get("schema_version") != V5:
            raise ValueError("not a native v0.5 generation")
        if value.get("generation_id") != selected or generation_digest(value) != selected:
            raise ValueError("generation digest mismatch")
        errors = validation_errors("workspace-generation", value, V5)
        if errors:
            raise ValueError(f"generation schema invalid: {errors[0]['message']}")
        return value

    @staticmethod
    def _validate_history(history: object) -> list[JsonObject]:
        errors: list[JsonObject] = []
        if not isinstance(history, list):
            return [{"message": "history must be an array", "json_pointer": "/history"}]
        previous: str | None = None
        event_ids: set[str] = set()
        for index, candidate in enumerate(history):
            if not isinstance(candidate, dict):
                errors.append(
                    {
                        "message": "history event must be an object",
                        "json_pointer": f"/history/{index}",
                    }
                )
                continue
            errors.extend(validation_errors("history-event", candidate, V5))
            event = deepcopy(candidate)
            recorded = event.pop("event_digest", None)
            if candidate.get("previous_event_digest") != previous:
                errors.append(
                    {
                        "message": "history previous digest mismatch",
                        "json_pointer": f"/history/{index}/previous_event_digest",
                    }
                )
            if recorded != digest_v3_json(cast(JsonValue, event)):
                errors.append(
                    {
                        "message": "history event digest mismatch",
                        "json_pointer": f"/history/{index}/event_digest",
                    }
                )
            event_id = str(candidate.get("event_id"))
            if event_id in event_ids:
                errors.append(
                    {
                        "message": "duplicate history event_id",
                        "json_pointer": f"/history/{index}/event_id",
                    }
                )
            event_ids.add(event_id)
            previous = str(recorded) if isinstance(recorded, str) else None
        return errors

    def commit(self, payload: JsonObject, *, expected_current: str | None) -> JsonObject:
        """Validate and expose one complete generation with a bounded lock."""

        try:
            lock = WorkspaceLock(self.root, timeout_seconds=10.0)
            with lock:
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
                manifest["schema_version"] = V5
                manifest["previous_generation"] = actual
                history = cast(list[JsonObject], manifest.get("history", []))
                manifest["history_root"] = (
                    str(history[-1]["event_digest"]) if history else digest_v3_json([])
                )
                manifest.pop("generation_id", None)
                identifier = generation_digest(manifest)
                manifest["generation_id"] = identifier
                errors = validation_errors("workspace-generation", manifest, V5)
                errors.extend(self._validate_history(history))
                object_entries = [
                    item for item in manifest.get("objects", []) if isinstance(item, dict)
                ]
                object_digests: set[str] = set()
                for index, entry in enumerate(object_entries):
                    digest = str(entry.get("digest"))
                    if digest in object_digests:
                        errors.append(
                            {
                                "message": "duplicate object digest",
                                "json_pointer": f"/objects/{index}/digest",
                            }
                        )
                    object_digests.add(digest)
                    if entry.get("kind") not in KIND_SCHEMAS:
                        errors.append(
                            {
                                "message": "unregistered object kind",
                                "json_pointer": f"/objects/{index}/kind",
                            }
                        )
                for index, entry in enumerate(object_entries):
                    for source in entry.get("source_chain", []):
                        if source not in object_digests:
                            errors.append(
                                {
                                    "message": "dangling source-chain digest",
                                    "json_pointer": f"/objects/{index}/source_chain",
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
                    _assert_no_link_components(self.root, target)
                    _atomic_bytes(target, canonical_v3_bytes(manifest) + b"\n")
                _atomic_bytes(self.current_path, f"{identifier}\n".encode("ascii"))
                return {
                    "command_status": "ok",
                    "generation_id": identifier,
                    "previous_generation": actual,
                    "generation_committed": True,
                    "authoritative_pointer": str(self.current_path),
                }
        except TimeoutError:
            return {
                "command_status": "failed",
                "failure_code": "workspace_lock_timeout",
                "generation_committed": False,
            }

    def verify_chain(self) -> list[JsonObject]:
        errors: list[JsonObject] = []
        seen: set[str] = set()
        selected = self.current_id()
        depth = 0
        while selected is not None:
            depth += 1
            if depth > MAX_GENERATION_DEPTH:
                errors.append(
                    {"code": "generation_chain_limit_exceeded", "maximum": MAX_GENERATION_DEPTH}
                )
                break
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


def empty_generation_v5(
    *,
    contract_digest: str,
    trust_policy_digest: str,
    trusted_time_receipt_digest: str | None,
    analysis_epoch: str | None,
    objects: list[JsonObject],
    quarantine: list[str] | None = None,
) -> JsonObject:
    return {
        "schema_version": V5,
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
