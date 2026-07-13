# SPDX-License-Identifier: Apache-2.0
"""v0.2 source envelopes, projection receipts, and recomputed validation."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import (
    canonical_bytes,
    digest_bytes,
    digest_json,
    load_json,
    write_canonical,
)
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.locking import WorkspaceLock
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject, JsonValue, TruthStatus


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def parse_schema_ref(reference: str) -> tuple[str, str]:
    """Parse NAME, NAME@VERSION, or VERSION/NAME into a supported pair."""

    if "@" in reference:
        name, version = reference.rsplit("@", 1)
    elif "/" in reference and reference.split("/", 1)[0].lstrip("v").startswith("0."):
        version, name = reference.split("/", 1)
    else:
        name, version = reference, "0.2.0"
    return name.removesuffix(".schema.json"), version.removeprefix("v")


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _compatibility(left: object, right: object) -> TruthStatus:
    if not isinstance(left, dict) or not isinstance(right, dict):
        return "unknown"
    return "true" if digest_json(left) == digest_json(right) else "false"


def signature_status(value: JsonObject) -> TruthStatus:
    """Verify a supplied public-key signature, or preserve unknown when unavailable/absent."""

    signature = value.get("signature")
    if signature is None:
        return "unknown"
    if not isinstance(signature, dict):
        return "false"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
    except ImportError:
        return "unknown"
    try:
        public_key = serialization.load_pem_public_key(
            str(signature["public_key_pem"]).encode("utf-8")
        )
        supplied = base64.b64decode(str(signature["signature_base64"]), validate=True)
        payload = dict(value)
        payload.pop("signature", None)
        message = canonical_bytes(cast(JsonValue, payload))
        algorithm = signature.get("algorithm")
        if algorithm == "ed25519" and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(supplied, message)
        elif algorithm == "rsa-pss-sha256" and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                supplied,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        else:
            return "false"
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return "false"
    return "true"


def recompute_validation(
    value: JsonValue,
    raw: bytes,
    schema_ref: str,
    evaluation_time: str,
    contract: JsonObject | None = None,
    expected_digest: str | None = None,
) -> JsonObject:
    """Recompute every validation coordinate; input Booleans are ignored."""

    name, version = parse_schema_ref(schema_ref)
    try:
        errors = validation_errors(name, value, version)
        schema_status: TruthStatus = "false" if errors else "true"
    except KeyError:
        errors = [{"message": "unsupported schema", "json_pointer": "/"}]
        schema_status = "false"
    actual_digest = digest_bytes(raw)
    digest_status: TruthStatus = (
        "true" if expected_digest is None or expected_digest == actual_digest else "false"
    )
    contextual_certificate = name == "external-certificate"
    expiry_status: TruthStatus = "unknown" if contextual_certificate else "true"
    scope_status: TruthStatus = "unknown" if contextual_certificate else "true"
    resource_status: TruthStatus = "unknown" if contextual_certificate else "true"
    baseline_status: TruthStatus = "unknown" if contextual_certificate else "true"
    signature: TruthStatus = "true"
    if isinstance(value, dict):
        expires = _time(value.get("expires_at") or value.get("expiry"))
        evaluated = _time(evaluation_time)
        if expires is not None and evaluated is not None:
            expiry_status = "true" if expires >= evaluated else "false"
        if contract is not None and contextual_certificate:
            scope_status = _compatibility(value.get("scope"), contract.get("scope"))
            resource_status = _compatibility(
                value.get("resource_envelope"), contract.get("resource_envelope")
            )
            baseline_status = _compatibility(
                value.get("baseline"),
                contract.get("external_measurement_policy", {}).get("baseline"),
            )
        if value.get("signature") is not None:
            signature = signature_status(value)
    return {
        "schema": schema_status,
        "digest": digest_status,
        "expiry": expiry_status,
        "scope": scope_status,
        "resource": resource_status,
        "baseline": baseline_status,
        "signature": signature,
        "schema_errors": errors,
        "actual_digest": actual_digest,
    }


def inspect_source(
    report: Path,
    source_system: str,
    schema_ref: str,
    *,
    evaluation_time: str | None = None,
    contract: JsonObject | None = None,
) -> JsonObject:
    """Inspect an upstream file without writing or modifying it."""

    raw = report.read_bytes()
    try:
        value = cast(JsonValue, json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        value = None
    evaluated = evaluation_time or (
        str(contract.get("evaluation_time")) if contract else "1970-01-01T00:00:00Z"
    )
    validation = recompute_validation(value, raw, schema_ref, evaluated, contract)
    digest = digest_bytes(raw)
    envelope: JsonObject = {
        "schema_version": "0.2.0",
        "envelope_id": f"envelope:{digest.split(':', 1)[1][:24]}",
        "source_system": source_system,
        "schema_ref": schema_ref,
        "raw_artifact_digest": digest,
        "raw_size": len(raw),
        "scope": value.get("scope", {}) if isinstance(value, dict) else {},
        "lifecycle": {
            "issued_at": value.get("issued_at") if isinstance(value, dict) else None,
            "expires_at": value.get("expires_at") if isinstance(value, dict) else None,
        },
        "lineage": sorted(
            str(item)
            for item in (value.get("lineage", []) if isinstance(value, dict) else [])
            if isinstance(item, str)
        ),
        "source_pointers": ["/"],
        "imported_at": _utc_now(),
        "signature": value.get("signature") if isinstance(value, dict) else None,
    }
    return {
        "command_status": "ok" if validation["schema"] == "true" else "failed",
        "source_path": str(report.resolve()),
        "source_modified": False,
        "source_system": source_system,
        "envelope": envelope,
        "validation_results": validation,
        "network_call_performed": False,
    }


def _projection_destination(root: Path, schema_ref: str, value: JsonObject) -> Path:
    name, _ = parse_schema_ref(schema_ref)
    if name == "transformation-network":
        return root / "network.json"
    if name == "action":
        return root / "actions" / f"{digest_json(value).split(':', 1)[1]}.json"
    if name == "adapter-capability":
        return root / "adapter-capabilities" / f"{digest_json(value).split(':', 1)[1]}.json"
    if name.endswith("witness"):
        witness_id = str(value.get("witness_id", digest_json(value).split(":", 1)[1][:24]))
        safe = digest_json(witness_id).split(":", 1)[1][:24]
        return root / "witnesses" / f"{safe}.json"
    return root / ".cpcf" / "projections" / f"{digest_json(value).split(':', 1)[1]}.json"


def _workspace_state_digest(root: Path) -> str:
    records: dict[str, JsonValue] = {}
    for path in [
        root / "contract.json",
        root / "network.json",
        root / "actions.json",
        *sorted((root / "witnesses").glob("*.json")),
        *sorted((root / "adapter-capabilities").glob("*.json")),
        *sorted((root / ".cpcf" / "envelopes").glob("*.json")),
        *sorted((root / ".cpcf" / "receipts").glob("*.json")),
        *sorted((root / ".cpcf" / "projections").glob("*.json")),
    ]:
        if path.is_file():
            records[str(path.relative_to(root)).replace("\\", "/")] = load_json(path)
    return digest_json(records)


def compile_actions(root: Path) -> None:
    """Compile individually receipt-bound action documents into deterministic planner input."""

    actions = [
        value
        for path in sorted((root / "actions").glob("*.json"))
        if isinstance((value := load_json(path)), dict)
    ]
    identifiers = [str(action.get("action_id")) for action in actions]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate action identifier")
    write_canonical(
        root / "actions.json",
        {
            "schema_version": "0.2.0",
            "actions": sorted(actions, key=lambda item: str(item["action_id"])),
        },
    )


def import_source(
    report: Path,
    workspace: Path,
    source_system: str,
    schema_ref: str,
    *,
    apply: bool,
) -> JsonObject:
    """Copy raw bytes into workspace CAS and project only schema-valid objects."""

    contract_value = load_json(workspace / "contract.json")
    if not isinstance(contract_value, dict):
        raise ValueError("workspace contract must be a JSON object")
    inspected = inspect_source(
        report,
        source_system,
        schema_ref,
        evaluation_time=str(contract_value.get("evaluation_time")),
        contract=contract_value,
    )
    inspected["applied"] = False
    if not apply:
        inspected["next_safe_command"] = [
            "cpcf",
            "source",
            "import",
            str(report.resolve()),
            "--workspace",
            str(workspace.resolve()),
            "--source-system",
            source_system,
            "--schema-ref",
            schema_ref,
            "--apply",
            "--json",
        ]
        return inspected
    validation_for_apply = cast(JsonObject, inspected["validation_results"])
    if inspected["command_status"] != "ok":
        inspected["failure_code"] = "source_schema_invalid"
        return inspected
    if any(
        validation_for_apply.get(key) != "true"
        for key in ("schema", "digest", "expiry", "scope", "resource", "baseline", "signature")
    ):
        inspected["command_status"] = "failed"
        inspected["failure_code"] = "source_validation_not_true"
        return inspected
    raw = report.read_bytes()
    value = cast(JsonValue, json.loads(raw.decode("utf-8")))
    if not isinstance(value, dict):
        raise ValueError("projected source must be a JSON object")
    with WorkspaceLock(workspace):
        store = ContentAddressedStore(workspace / ".cpcf" / "cas")
        artifact = store.put(raw)
        envelope = cast(JsonObject, inspected["envelope"])
        envelope_path = (
            workspace / ".cpcf" / "envelopes" / f"{envelope['envelope_id'].replace(':', '-')}.json"
        )
        write_canonical(envelope_path, envelope)
        destination = _projection_destination(workspace, schema_ref, value)
        write_canonical(destination, value)
        projected_digest = digest_json(value)
        validation = cast(JsonObject, inspected["validation_results"])
        receipt_seed: JsonObject = {
            "schema_version": "0.2.0",
            "action_id": "source:import",
            "envelope_ref": envelope["envelope_id"],
            "executable_digest": None,
            "invocation_digest": digest_json(
                {"source_system": source_system, "schema_ref": schema_ref, "raw": artifact.digest}
            ),
            "raw_artifact_digest": artifact.digest,
            "projected_object_digests": [projected_digest],
            "projected_objects": [
                {
                    "digest": projected_digest,
                    "schema_ref": schema_ref,
                    "source_pointer": "/",
                }
            ],
            "source_pointers": ["/"],
            "validation_results": {
                key: validation[key]
                for key in (
                    "schema",
                    "digest",
                    "expiry",
                    "scope",
                    "resource",
                    "baseline",
                    "signature",
                )
            },
            "evaluation_time": contract_value["evaluation_time"],
        }
        receipt_seed["receipt_id"] = f"receipt:{digest_json(receipt_seed).split(':', 1)[1][:24]}"
        receipt_path = (
            workspace
            / ".cpcf"
            / "receipts"
            / f"{receipt_seed['receipt_id'].replace(':', '-')}.json"
        )
        write_canonical(receipt_path, receipt_seed)
        if parse_schema_ref(schema_ref)[0] == "action":
            compile_actions(workspace)
        manifest_path = workspace / ".cpcf" / "workspace.json"
        manifest = load_json(manifest_path)
        if isinstance(manifest, dict):
            manifest["state_digest"] = _workspace_state_digest(workspace)
            write_canonical(manifest_path, manifest)
    inspected.update(
        {
            "command_status": "ok",
            "applied": True,
            "raw_artifact_ref": artifact.digest,
            "projection_path": str(destination.resolve()),
            "projection_receipt": receipt_seed,
            "source_modified": False,
        }
    )
    return inspected


def validate_unique_ids(
    network: JsonObject, actions: list[JsonObject], envelopes: list[JsonObject]
) -> list[str]:
    """Report duplicate identifiers before any lossy dictionary indexing."""

    errors: list[str] = []
    for collection, key, label in (
        (network.get("nodes", []), "node_id", "node"),
        (network.get("transformations", []), "transformation_id", "transformation"),
        (actions, "action_id", "action"),
        (envelopes, "envelope_id", "source"),
    ):
        values = (
            [item.get(key) for item in collection if isinstance(item, dict)]
            if isinstance(collection, list)
            else []
        )
        duplicates = sorted({str(value) for value in values if values.count(value) > 1})
        errors.extend(f"duplicate_{label}_id:{value}" for value in duplicates)
    return errors


def receipt_source_backed(receipt: JsonObject, store: ContentAddressedStore) -> TruthStatus:
    """Return true only for a recomputable raw chain with no false/unknown core checks."""

    raw_digest = receipt.get("raw_artifact_digest")
    if not isinstance(raw_digest, str) or not store.verify(raw_digest):
        return "false"
    results = receipt.get("validation_results", {})
    if not isinstance(results, dict):
        return "false"
    if results.get("schema") != "true" or results.get("digest") != "true":
        return "false"
    required_context = ("expiry", "scope", "resource", "baseline", "signature")
    if any(results.get(key) == "false" for key in required_context):
        return "false"
    return "unknown" if any(results.get(key) == "unknown" for key in required_context) else "true"
