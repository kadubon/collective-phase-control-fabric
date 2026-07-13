# SPDX-License-Identifier: Apache-2.0
"""Native v0.2 workspace creation, migration, rebuilding, and strict audit."""

from __future__ import annotations

import hashlib
import json
import shutil
from contextlib import suppress
from copy import deepcopy
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_json, load_json, write_canonical
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.locking import WorkspaceLock
from collective_phase_control_fabric.planner import _v2_filter
from collective_phase_control_fabric.process import run_process
from collective_phase_control_fabric.provenance import (
    _projection_destination,
    compile_actions,
    parse_schema_ref,
    receipt_source_backed,
    recompute_validation,
    validate_unique_ids,
)
from collective_phase_control_fabric.repairs import generate_repairs
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject, JsonValue


def workspace_version(root: Path) -> str:
    """Return the explicit workspace version, falling back to legacy v0.1."""

    manifest = root / ".cpcf" / "workspace.json"
    if manifest.is_file():
        value = load_json(manifest)
        if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
            return str(value["schema_version"])
    contract = root / "contract.json"
    if contract.is_file():
        value = load_json(contract)
        if isinstance(value, dict) and value.get("schema_version") == "0.2.0":
            return "0.2.0"
    return "0.1.0"


def initialize_workspace(contract_path: Path, output: Path) -> JsonObject:
    """Create an empty native workspace without inventing targets or evidence."""

    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output}")
    value = load_json(contract_path)
    errors = validation_errors("phase-contract", value, "0.2.0")
    if errors:
        return {
            "command_status": "failed",
            "failure_code": "contract_schema_invalid",
            "schema_errors": errors,
            "next_safe_command": ["cpcf", "contract", "validate", str(contract_path), "--json"],
        }
    if not isinstance(value, dict):
        raise ValueError("phase contract must be a JSON object")
    output.mkdir(parents=True, exist_ok=True)
    write_canonical(output / "contract.json", value)
    write_canonical(
        output / "network.json",
        {
            "schema_version": "0.2.0",
            "network_id": f"network:{value['contract_id']}",
            "nodes": [],
            "transformations": [],
        },
    )
    write_canonical(output / "actions.json", {"schema_version": "0.2.0", "actions": []})
    manifest: JsonObject = {
        "schema_version": "0.2.0",
        "contract_digest": digest_json(value),
        "state_digest": state_digest(output),
        "migration": None,
        "source_of_record_migrated": False,
    }
    write_canonical(output / ".cpcf" / "workspace.json", manifest)
    write_canonical(output / ".cpcf" / "history.json", {"records": []})
    return {
        "command_status": "ok",
        "workspace": str(output.resolve()),
        "schema_version": "0.2.0",
        "contract_digest": manifest["contract_digest"],
        "external_artifacts_modified": False,
        "next_safe_command": [
            "cpcf",
            "source",
            "inspect",
            "REPORT",
            "--source-system",
            "SOURCE",
            "--schema-ref",
            "REF",
            "--json",
        ],
    }


def _migrate_contract(old: JsonObject) -> JsonObject:
    migrated = deepcopy(old)
    migrated["schema_version"] = "0.2.0"
    migrated["evaluation_time"] = old.get("created_at", "1970-01-01T00:00:00Z")
    migrated.setdefault(
        "control_policy",
        {
            "planning_horizon": 1,
            "beam_width": 32,
            "candidate_cap": 64,
            "retry_policy": {
                "maximum_retries": old.get("lifecycle_policy", {}).get("maximum_retry_count", 0)
            },
        },
    )
    migrated.setdefault(
        "formation_policy", {"causal_sequence_required": True, "maximum_layer_count": 64}
    )
    robustness = old.get("robustness_policy", {})
    migrated.setdefault(
        "support_core_policy",
        {
            "minimum_independent_support_groups": max(
                1, int(robustness.get("minimum_source_systems", 1))
            )
            if isinstance(robustness, dict)
            else 1,
            "minimum_independent_verifier_groups": max(
                1, int(robustness.get("minimum_independent_verifiers", 1))
            )
            if isinstance(robustness, dict)
            else 1,
            "perturbation_suite_refs": [],
        },
    )
    migrated.setdefault(
        "rate_policy", {"levels_requiring_external_rate_evidence": ["L3", "L4", "L5"]}
    )
    return migrated


def migrate_workspace(old: Path, output: Path, target: str) -> JsonObject:
    """Copy a legacy workspace and quarantine embedded postconditions."""

    if target != "0.2.0":
        return {"command_status": "failed", "failure_code": "unsupported_migration_target"}
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output}")
    contract = load_json(old / "contract.json")
    network = load_json(old / "network.json")
    if not isinstance(contract, dict) or not isinstance(network, dict):
        raise ValueError("legacy contract and network must be objects")
    migrated_contract = _migrate_contract(contract)
    output.mkdir(parents=True, exist_ok=True)
    write_canonical(output / "contract.json", migrated_contract)
    migrated_network = deepcopy(network)
    migrated_network["schema_version"] = "0.2.0"
    migrated_network.setdefault("network_id", f"network:{migrated_contract['contract_id']}")
    write_canonical(output / "network.json", migrated_network)
    old_actions_value = (
        load_json(old / "actions.json") if (old / "actions.json").is_file() else {"actions": []}
    )
    old_actions = (
        old_actions_value.get("actions", []) if isinstance(old_actions_value, dict) else []
    )
    quarantined: list[JsonObject] = []
    for action in old_actions:
        if not isinstance(action, dict):
            continue
        quarantined.append(
            {
                "repair_id": f"legacy:{action.get('action_id')}",
                "repair_kind": "legacy_action_rebinding_required",
                "binding_status": "unbound_repair",
                "executable": False,
                "legacy_expected_postcondition": action.get("postcondition_contract"),
                "legacy_action_digest": digest_json(action),
            }
        )
    write_canonical(output / "actions.json", {"schema_version": "0.2.0", "actions": []})
    write_canonical(output / ".cpcf" / "legacy-repairs.json", {"repairs": quarantined})
    for name in ("productive_witness.json", "maintenance_witness.json"):
        source = old / name
        if source.is_file():
            destination = output / ".cpcf" / "legacy-artifacts" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    manifest: JsonObject = {
        "schema_version": "0.2.0",
        "contract_digest": digest_json(migrated_contract),
        "state_digest": state_digest(output),
        "migration": {
            "from": str(old.resolve()),
            "from_version": workspace_version(old),
            "copy_on_write": True,
        },
        "source_of_record_migrated": False,
    }
    write_canonical(output / ".cpcf" / "workspace.json", manifest)
    write_canonical(output / ".cpcf" / "history.json", {"records": []})
    return {
        "command_status": "ok",
        "workspace": str(output.resolve()),
        "old_workspace": str(old.resolve()),
        "old_workspace_modified": False,
        "schema_version": "0.2.0",
        "quarantined_legacy_actions": len(quarantined),
        "next_safe_command": [
            "cpcf",
            "doctor",
            "--workspace",
            str(output.resolve()),
            "--strict",
            "--json",
        ],
    }


def rebuild_projections(root: Path) -> JsonObject:
    """Rebuild projected objects from raw CAS and envelope metadata."""

    if workspace_version(root) != "0.2.0":
        return {"command_status": "failed", "failure_code": "legacy_workspace_requires_migration"}
    contract = load_json(root / "contract.json")
    if not isinstance(contract, dict):
        raise ValueError("contract must be an object")
    store = ContentAddressedStore(root / ".cpcf" / "cas")
    rebuilt: list[JsonObject] = []
    rejected: list[JsonObject] = []
    with WorkspaceLock(root):
        for envelope_path in sorted((root / ".cpcf" / "envelopes").glob("*.json")):
            envelope = load_json(envelope_path)
            if not isinstance(envelope, dict):
                continue
            digest = envelope.get("raw_artifact_digest")
            if not isinstance(digest, str) or not store.verify(digest):
                rejected.append(
                    {"envelope_ref": envelope.get("envelope_id"), "failure_code": "digest_mismatch"}
                )
                continue
            raw = store.get(digest)
            try:
                value = cast(JsonValue, json.loads(raw.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                rejected.append(
                    {
                        "envelope_ref": envelope.get("envelope_id"),
                        "failure_code": "malformed_report",
                    }
                )
                continue
            validation = recompute_validation(
                value,
                raw,
                str(envelope.get("schema_ref")),
                str(contract.get("evaluation_time")),
                contract,
                digest,
            )
            if (
                validation["schema"] != "true"
                or validation["digest"] != "true"
                or any(
                    validation[key] == "false"
                    for key in ("expiry", "scope", "resource", "baseline", "signature")
                )
            ):
                rejected.append(
                    {
                        "envelope_ref": envelope.get("envelope_id"),
                        "failure_code": "projection_validation_failed",
                        "validation_results": validation,
                    }
                )
                continue
            if not isinstance(value, dict):
                continue
            destination = _projection_destination(root, str(envelope["schema_ref"]), value)
            write_canonical(destination, value)
            rebuilt.append(
                {
                    "envelope_ref": envelope["envelope_id"],
                    "projection_path": str(destination.resolve()),
                    "projection_digest": digest_json(value),
                }
            )
        if (root / "actions").is_dir():
            compile_actions(root)
        manifest_path = root / ".cpcf" / "workspace.json"
        manifest = load_json(manifest_path) if manifest_path.is_file() else None
        if isinstance(manifest, dict):
            manifest["state_digest"] = state_digest(root)
            write_canonical(manifest_path, manifest)
    return {
        "command_status": "ok" if not rejected else "partial",
        "rebuilt": rebuilt,
        "rejected": rejected,
        "source_artifacts_modified": False,
    }


def strict_doctor(root: Path, analysis: JsonObject | None = None) -> JsonObject:
    """Validate all native files, CAS chains, identifiers, and migration state."""

    version = workspace_version(root)
    errors: list[JsonObject] = []
    if version != "0.2.0":
        errors.append(
            {
                "code": "unsupported_version",
                "path": str(root),
                "detail": "execution requires copy-on-write migration",
            }
        )
    manifest_path = root / ".cpcf" / "workspace.json"
    manifest = load_json(manifest_path) if manifest_path.is_file() else None
    if not isinstance(manifest, dict):
        errors.append({"code": "workspace_manifest_missing", "path": str(manifest_path)})
    elif manifest.get("state_digest") != state_digest(root):
        errors.append({"code": "workspace_state_digest_mismatch", "path": str(manifest_path)})
    contract = load_json(root / "contract.json") if (root / "contract.json").is_file() else None
    network = load_json(root / "network.json") if (root / "network.json").is_file() else None
    actions_value = (
        load_json(root / "actions.json") if (root / "actions.json").is_file() else {"actions": []}
    )
    actions = actions_value.get("actions", []) if isinstance(actions_value, dict) else []
    if isinstance(contract, dict):
        errors.extend(
            {"code": "schema_invalid", "path": "contract.json", **item}
            for item in validation_errors("phase-contract", contract, version)
        )
    else:
        errors.append({"code": "missing_typed_input", "path": "contract.json"})
    if isinstance(network, dict):
        errors.extend(
            {"code": "schema_invalid", "path": "network.json", **item}
            for item in validation_errors("transformation-network", network, version)
        )
    else:
        errors.append({"code": "missing_typed_input", "path": "network.json"})
    envelope_paths = sorted((root / ".cpcf" / "envelopes").glob("*.json"))
    envelopes = [value for path in envelope_paths if isinstance((value := load_json(path)), dict)]
    for path, envelope in zip(envelope_paths, envelopes, strict=False):
        errors.extend(
            {"code": "schema_invalid", "path": str(path), **item}
            for item in validation_errors("source-artifact-envelope", envelope, "0.2.0")
        )
    if isinstance(network, dict):
        errors.extend(
            {"code": "duplicate_id", "detail": item}
            for item in validate_unique_ids(network, cast(list[JsonObject], actions), envelopes)
        )
    store = ContentAddressedStore(root / ".cpcf" / "cas")
    for object_path in sorted((root / ".cpcf" / "cas" / "sha256").glob("*/*")):
        digest = f"sha256:{object_path.parent.name}{object_path.name}"
        if not store.verify(digest):
            errors.append({"code": "digest_mismatch", "path": str(object_path)})
    envelope_by_id = {str(item.get("envelope_id")): item for item in envelopes}
    for index, action in enumerate(actions if isinstance(actions, list) else []):
        if not isinstance(action, dict):
            errors.append({"code": "schema_invalid", "path": f"actions.json/actions/{index}"})
            continue
        errors.extend(
            {"code": "schema_invalid", "path": f"actions.json/actions/{index}", **item}
            for item in validation_errors("action", action, "0.2.0")
        )
        argv = action.get("exact_argv", [])
        if isinstance(argv, list) and argv:
            executable = str(argv[0])
            if shutil.which(executable) is None and not Path(executable).is_file():
                errors.append(
                    {
                        "code": "adapter_executable_missing",
                        "path": f"actions.json/actions/{index}/exact_argv/0",
                    }
                )
    receipts: list[JsonObject] = []
    for path in sorted((root / ".cpcf" / "receipts").glob("*.json")):
        value = load_json(path)
        if not isinstance(value, dict):
            errors.append({"code": "schema_invalid", "path": str(path)})
            continue
        receipts.append(value)
        errors.extend(
            {"code": "schema_invalid", "path": str(path), **item}
            for item in validation_errors("projection-receipt", value, "0.2.0")
        )
        if receipt_source_backed(value, store) == "false":
            errors.append({"code": "digest_mismatch", "path": str(path)})
        bound_envelope = envelope_by_id.get(str(value.get("envelope_ref")))
        raw_digest = value.get("raw_artifact_digest")
        if bound_envelope is None:
            errors.append({"code": "receipt_missing_envelope", "path": str(path)})
        elif (
            isinstance(raw_digest, str) and store.verify(raw_digest) and isinstance(contract, dict)
        ):
            raw = store.get(raw_digest)
            try:
                projected_value = cast(JsonValue, json.loads(raw.decode("utf-8")))
            except (UnicodeDecodeError, json.JSONDecodeError):
                projected_value = None
            recomputed = recompute_validation(
                projected_value,
                raw,
                str(bound_envelope.get("schema_ref")),
                str(contract.get("evaluation_time")),
                contract,
                str(bound_envelope.get("raw_artifact_digest")),
            )
            declared_results = value.get("validation_results", {})
            for key in ("schema", "digest", "expiry", "scope", "resource", "baseline", "signature"):
                if not isinstance(declared_results, dict) or declared_results.get(
                    key
                ) != recomputed.get(key):
                    errors.append(
                        {
                            "code": "receipt_validation_mismatch",
                            "path": str(path),
                            "coordinate": key,
                            "declared": declared_results.get(key)
                            if isinstance(declared_results, dict)
                            else None,
                            "recomputed": recomputed.get(key),
                        }
                    )
    for path in sorted((root / ".cpcf" / "transitions").glob("*.json")):
        value = load_json(path)
        errors.extend(
            {"code": "schema_invalid", "path": str(path), **item}
            for item in validation_errors("structural-transition", value, "0.2.0")
        )
    receipt_by_projection = {
        str(projected): receipt
        for receipt in receipts
        for projected in receipt.get("projected_object_digests", [])
        if isinstance(projected, str)
    }
    if (
        isinstance(network, dict)
        and (network.get("nodes") or network.get("transformations"))
        and (
            (network_receipt := receipt_by_projection.get(digest_json(network))) is None
            or receipt_source_backed(network_receipt, store) != "true"
        )
    ):
        errors.append(
            {"code": "network_projection_receipt_missing_or_invalid", "path": "network.json"}
        )
    capability_ids: set[str] = set()
    for path in sorted((root / "adapter-capabilities").glob("*.json")):
        capability = load_json(path)
        if not isinstance(capability, dict):
            errors.append({"code": "schema_invalid", "path": str(path)})
            continue
        errors.extend(
            {"code": "schema_invalid", "path": str(path), **item}
            for item in validation_errors("adapter-capability", capability, "0.2.0")
        )
        capability_id = capability.get("capability_id")
        if isinstance(capability_id, str):
            if capability_id in capability_ids:
                errors.append(
                    {
                        "code": "duplicate_adapter_capability_id",
                        "path": str(path),
                        "id": capability_id,
                    }
                )
            capability_ids.add(capability_id)
        receipt = receipt_by_projection.get(digest_json(capability))
        if receipt is None or receipt_source_backed(receipt, store) != "true":
            errors.append(
                {"code": "adapter_capability_receipt_missing_or_invalid", "path": str(path)}
            )
    projection_ids: set[str] = set()
    for path in sorted((root / ".cpcf" / "projections").glob("*.json")):
        projection = load_json(path)
        if not isinstance(projection, dict):
            errors.append({"code": "schema_invalid", "path": str(path)})
            continue
        projection_digest = digest_json(projection)
        projection_id = projection.get("certificate_id") or projection.get("witness_id")
        if isinstance(projection_id, str):
            if projection_id in projection_ids:
                errors.append(
                    {"code": "duplicate_projection_id", "path": str(path), "id": projection_id}
                )
            projection_ids.add(projection_id)
        receipt = receipt_by_projection.get(projection_digest)
        metadata = next(
            (
                item
                for item in (receipt.get("projected_objects", []) if receipt else [])
                if isinstance(item, dict) and item.get("digest") == projection_digest
            ),
            None,
        )
        if metadata is None:
            errors.append({"code": "receipt_missing", "path": str(path)})
            continue
        schema_name, schema_version = parse_schema_ref(str(metadata.get("schema_ref")))
        errors.extend(
            {"code": "schema_invalid", "path": str(path), **item}
            for item in validation_errors(schema_name, projection, schema_version)
        )
    for index, action in enumerate(actions if isinstance(actions, list) else []):
        receipt = (
            receipt_by_projection.get(digest_json(action)) if isinstance(action, dict) else None
        )
        if receipt is None or receipt_source_backed(receipt, store) != "true":
            errors.append(
                {
                    "code": "action_projection_receipt_missing_or_invalid",
                    "path": f"actions.json/actions/{index}",
                }
            )
        if isinstance(action, dict):
            _, capability_failure = _bound_capability(root, action, store)
            if capability_failure is not None:
                errors.append(
                    {
                        "code": capability_failure,
                        "path": f"actions.json/actions/{index}",
                    }
                )
    witness_ids: set[str] = set()
    for path in sorted((root / "witnesses").glob("*.json")):
        witness = load_json(path)
        if not isinstance(witness, dict):
            errors.append({"code": "schema_invalid", "path": str(path)})
            continue
        witness_id = witness.get("witness_id")
        if isinstance(witness_id, str):
            if witness_id in witness_ids:
                errors.append({"code": "duplicate_witness_id", "path": str(path), "id": witness_id})
            witness_ids.add(witness_id)
        receipt = receipt_by_projection.get(digest_json(witness))
        projected_metadata = next(
            (
                item
                for item in (receipt.get("projected_objects", []) if receipt else [])
                if isinstance(item, dict) and item.get("digest") == digest_json(witness)
            ),
            None,
        )
        if projected_metadata is None:
            errors.append({"code": "receipt_missing", "path": str(path)})
            continue
        schema_name, schema_version = parse_schema_ref(str(projected_metadata.get("schema_ref")))
        errors.extend(
            {"code": "schema_invalid", "path": str(path), **item}
            for item in validation_errors(schema_name, witness, schema_version)
        )
    report: JsonObject = {
        "command_status": "ok" if not errors else "failed",
        "workspace": str(root.resolve()),
        "schema_version": version,
        "strict": True,
        "errors": errors,
        "envelope_count": len(envelopes),
        "receipt_count": len(receipts),
        "source_of_record_migrated": False,
        "execution_allowed": version == "0.2.0" and not errors,
    }
    report["repairs"] = generate_repairs(analysis or {}, report)
    return report


def state_digest(root: Path) -> str:
    """Digest authoritative CPCF projection files, excluding locks and derived reports."""

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


def invocation_path(root: Path, action_id: str) -> Path:
    """Return a filesystem-safe invocation filename derived from the canonical action ID."""

    token = digest_json(action_id).split(":", 1)[1]
    return root / ".cpcf" / "invocations" / f"action-{token}.json"


def _native_action(root: Path, action_id: str) -> JsonObject:
    value = load_json(root / "actions.json")
    actions = value.get("actions", []) if isinstance(value, dict) else []
    matches = [
        item for item in actions if isinstance(item, dict) and item.get("action_id") == action_id
    ]
    if len(matches) != 1:
        raise KeyError(action_id)
    return cast(JsonObject, matches[0])


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _bound_capability(
    root: Path, action: JsonObject, store: ContentAddressedStore
) -> tuple[JsonObject | None, str | None]:
    capabilities = [
        value
        for path in sorted((root / "adapter-capabilities").glob("*.json"))
        if isinstance((value := load_json(path)), dict)
        and value.get("capability_id") == action.get("adapter_capability_ref")
    ]
    if len(capabilities) != 1:
        return None, "adapter_capability_missing_or_ambiguous"
    capability = capabilities[0]
    capability_digest = digest_json(capability)
    receipts = [
        value
        for path in sorted((root / ".cpcf" / "receipts").glob("*.json"))
        if isinstance((value := load_json(path)), dict)
        and capability_digest in value.get("projected_object_digests", [])
    ]
    if not any(receipt_source_backed(receipt, store) == "true" for receipt in receipts):
        return None, "adapter_capability_receipt_missing_or_invalid"
    if capability.get("adapter") != action.get("adapter"):
        return None, "adapter_capability_identity_mismatch"
    operations = [
        item
        for item in capability.get("operations", [])
        if isinstance(item, dict) and item.get("operation") == action.get("operation")
    ]
    if len(operations) != 1:
        return None, "adapter_operation_not_registered"
    operation = operations[0]
    if action.get("effect_class") not in operation.get("effect_classes", []):
        return None, "adapter_effect_class_not_registered"
    argv = action.get("exact_argv", [])
    executable = shutil.which(str(argv[0])) if isinstance(argv, list) and argv else None
    if executable is None or _file_digest(Path(executable)) != operation.get("executable_digest"):
        return None, "adapter_executable_digest_mismatch"
    allowed_receipts = set(operation.get("receipt_schema_refs", []))
    allowed_mappings = {
        (str(item.get("source_pointer")), str(item.get("target_schema")))
        for item in operation.get("projection_mappings", [])
        if isinstance(item, dict)
    }
    for branch in action.get("outcomes", {}).values():
        if not isinstance(branch, dict) or branch.get("receipt_schema_ref") not in allowed_receipts:
            return None, "adapter_receipt_schema_not_registered"
        mappings = {
            (str(item.get("source_pointer")), str(item.get("target_schema")))
            for item in branch.get("projection_targets", [])
            if isinstance(item, dict)
        }
        if not mappings <= allowed_mappings:
            return None, "adapter_projection_mapping_not_registered"
    return operation, None


def prepare_native_step(root: Path, action_id: str) -> JsonObject:
    """Prepare a native action without executing it or embedding a post-state object."""

    action = _native_action(root, action_id)
    if any(
        key in action.get("postcondition_contract", {})
        for key in (
            "productive_witness",
            "maintenance_witness",
            "evidence",
            "witnesses",
            "nodes",
            "promoted_state",
            "add_nodes",
            "available_states",
            "edge_updates",
        )
    ):
        return {"command_status": "failed", "failure_code": "embedded_postcondition_forbidden"}
    request: JsonObject = {
        "request_schema_version": "0.2.0",
        "action_id": action_id,
        "operation": action.get("operation"),
        "effect_class": action.get("effect_class"),
        "outcome_contract_digest": digest_json(action.get("outcomes")),
        "pre_state_digest": state_digest(root),
    }
    path = invocation_path(root, action_id)
    write_canonical(path, request)
    return {
        "command_status": "ok",
        "action_id": action_id,
        "invocation_request": str(path.resolve()),
        "invocation_digest": digest_json(request),
        "exact_argv": action.get("exact_argv"),
        "effect_class": action.get("effect_class"),
        "executed": False,
    }


def _pointer(value: JsonValue, pointer: str) -> JsonValue:
    if pointer == "/":
        return value
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must start with /")
    current: JsonValue = value
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise KeyError(pointer)
            current = cast(JsonValue, current[token])
        elif isinstance(current, list):
            current = cast(JsonValue, current[int(token)])
        else:
            raise KeyError(pointer)
    return current


def run_native_step(root: Path, action_id: str, mode: str) -> JsonObject:
    """Execute one native action and promote only receipt-bound raw output projections."""

    action = _native_action(root, action_id)
    store = ContentAddressedStore(root / ".cpcf" / "cas")
    action_digest = digest_json(action)
    action_receipts = [
        value
        for path in sorted((root / ".cpcf" / "receipts").glob("*.json"))
        if isinstance((value := load_json(path)), dict)
        and action_digest in value.get("projected_object_digests", [])
    ]
    if not any(receipt_source_backed(receipt, store) == "true" for receipt in action_receipts):
        return {
            "command_status": "failed",
            "failure_code": "action_projection_receipt_missing_or_invalid",
            "transition_written": False,
        }
    _, capability_failure = _bound_capability(root, action, store)
    if capability_failure is not None:
        return {
            "command_status": "failed",
            "failure_code": capability_failure,
            "transition_written": False,
        }
    contract_value = load_json(root / "contract.json")
    network_value = load_json(root / "network.json")
    if not isinstance(contract_value, dict) or not isinstance(network_value, dict):
        return {
            "command_status": "failed",
            "failure_code": "workspace_uninitialized",
            "transition_written": False,
        }
    eligibility_failure = _v2_filter(action, contract_value)
    if eligibility_failure is not None:
        return {
            "command_status": "failed",
            "failure_code": eligibility_failure,
            "transition_written": False,
        }
    authority_records = {
        str(node.get("node_id"))
        for node in network_value.get("nodes", [])
        if isinstance(node, dict)
        and node.get("type") == "authority_record"
        and node.get("available") is True
        and node.get("lifecycle_status") in {"valid", "active"}
    }
    required_authority = {
        str(item) for item in action.get("required_authority_refs", []) if isinstance(item, str)
    }
    if not required_authority <= authority_records:
        return {
            "command_status": "failed",
            "failure_code": "missing_authority",
            "transition_written": False,
        }
    if action.get("effect_class") == "external_effect":
        return {"command_status": "failed", "failure_code": "external_effect_rejected"}
    if mode == "run" and action.get("effect_class") == "local_write":
        return {"command_status": "failed", "failure_code": "local_write_requires_apply"}
    existing_invocation = invocation_path(root, action_id)
    if existing_invocation.is_file():
        request = load_json(existing_invocation)
        prepared: JsonObject = {
            "command_status": "ok",
            "invocation_request": str(existing_invocation.resolve()),
            "invocation_digest": digest_json(request),
        }
    else:
        prepared = prepare_native_step(root, action_id)
        if prepared.get("command_status") != "ok":
            return prepared
        request = load_json(Path(str(prepared["invocation_request"])))
    if not isinstance(request, dict):
        raise ValueError("invocation request malformed")
    with WorkspaceLock(root):
        locked_pre_digest = state_digest(root)
        if request.get("pre_state_digest") != locked_pre_digest:
            return {
                "command_status": "failed",
                "failure_code": "concurrent_state_comparison_failed",
                "transition_written": False,
            }
        receipt = run_process(
            cast(list[str], action.get("exact_argv")),
            root,
            root,
            timeout_seconds=float(action.get("timeout_seconds", 30)),
            stdout_limit=int(action.get("stdout_limit", 1_048_576)),
            stderr_limit=int(action.get("stderr_limit", 1_048_576)),
        )
        raw = bytes.fromhex(str(receipt["stdout_raw_hex"]))
        artifact = store.put(raw)
        parsed: JsonValue = None
        with suppress(UnicodeDecodeError, json.JSONDecodeError):
            parsed = cast(JsonValue, json.loads(raw.decode("utf-8")))
        if receipt.get("timed_out") is True:
            outcome = "timeout"
        elif receipt.get("stdout_truncated") is True or not isinstance(parsed, dict):
            outcome = "failure"
        else:
            declared_outcome = parsed.get("outcome")
            outcome = (
                declared_outcome
                if declared_outcome in {"success", "partial", "failure", "timeout"}
                else "failure"
            )
        outcomes = action.get("outcomes", {})
        branch = outcomes.get(outcome) if isinstance(outcomes, dict) else None
        if not isinstance(branch, dict):
            return {
                "command_status": "failed",
                "failure_code": "outcome_branch_missing",
                "transition_written": False,
            }
        receipt_schema_errors: list[JsonObject] = []
        receipt_schema_ref = branch.get("receipt_schema_ref")
        if isinstance(receipt_schema_ref, str):
            receipt_name, receipt_version = parse_schema_ref(receipt_schema_ref)
            receipt_schema_errors = validation_errors(receipt_name, parsed, receipt_version)
        else:
            receipt_schema_errors = [
                {"message": "receipt schema reference missing", "json_pointer": "/"}
            ]
        projection_digests: list[str] = []
        projected_objects: list[JsonObject] = []
        projection_paths: list[str] = []
        projection_errors: list[JsonObject] = []
        if receipt_schema_errors:
            projection_errors.append(
                {
                    "failure_code": "outcome_receipt_schema_invalid",
                    "schema_errors": receipt_schema_errors,
                }
            )
        if not isinstance(parsed, dict) or parsed.get("action_id") != action_id:
            projection_errors.append({"failure_code": "outcome_receipt_action_binding_mismatch"})
        staged: list[tuple[Path, JsonObject]] = []
        for mapping in branch.get("projection_targets", []):
            if not isinstance(mapping, dict):
                projection_errors.append({"failure_code": "projection_mapping_malformed"})
                continue
            source_pointer = mapping.get("source_pointer")
            target_schema = mapping.get("target_schema")
            if not isinstance(source_pointer, str) or not isinstance(target_schema, str):
                projection_errors.append({"failure_code": "projection_mapping_malformed"})
                continue
            try:
                projected = _pointer(parsed, source_pointer)
            except (KeyError, ValueError, IndexError):
                projection_errors.append(
                    {"failure_code": "source_pointer_missing", "source_pointer": source_pointer}
                )
                continue
            name, version = parse_schema_ref(target_schema)
            errors = validation_errors(name, projected, version)
            if errors or not isinstance(projected, dict):
                projection_errors.append(
                    {
                        "failure_code": "projected_object_schema_invalid",
                        "source_pointer": source_pointer,
                        "schema_errors": errors,
                    }
                )
                continue
            destination = _projection_destination(root, target_schema, projected)
            staged.append((destination, projected))
            projection_digests.append(digest_json(projected))
            projected_objects.append(
                {
                    "digest": digest_json(projected),
                    "schema_ref": target_schema,
                    "source_pointer": source_pointer,
                }
            )
            projection_paths.append(str(destination.resolve()))
        valid_projection = not projection_errors and receipt.get("stdout_truncated") is False
        for destination, projected in staged if valid_projection else []:
            write_canonical(destination, projected)
        contract = load_json(root / "contract.json")
        if not isinstance(contract, dict):
            raise ValueError("workspace contract must remain an object")
        validation_results: JsonObject = {
            "schema": "true" if isinstance(parsed, dict) and not receipt_schema_errors else "false",
            "digest": "true" if receipt.get("stdout_full_digest") == artifact.digest else "false",
            "expiry": "true",
            "scope": "true",
            "resource": "true" if branch.get("protected_floor_status") == "true" else "false",
            "baseline": "true",
            "signature": "true",
        }
        envelope_id = f"envelope:{artifact.digest.split(':', 1)[1][:24]}"
        envelope: JsonObject = {
            "schema_version": "0.2.0",
            "envelope_id": envelope_id,
            "source_system": str(action.get("adapter")),
            "schema_ref": str(branch.get("receipt_schema_ref")),
            "raw_artifact_digest": artifact.digest,
            "raw_size": len(raw),
            "scope": {},
            "lifecycle": {},
            "lineage": [],
            "source_pointers": [str(item) for item in branch.get("source_pointers", [])],
            "imported_at": str(contract.get("evaluation_time")),
            "signature": None,
        }
        write_canonical(
            root / ".cpcf" / "envelopes" / f"{envelope_id.replace(':', '-')}.json", envelope
        )
        projection_receipt: JsonObject = {
            "schema_version": "0.2.0",
            "action_id": action_id,
            "envelope_ref": envelope_id,
            "executable_digest": receipt.get("executable_digest"),
            "invocation_digest": prepared["invocation_digest"],
            "raw_artifact_digest": artifact.digest,
            "projected_object_digests": projection_digests if valid_projection else [],
            "projected_objects": projected_objects if valid_projection else [],
            "source_pointers": [str(item) for item in branch.get("source_pointers", [])],
            "validation_results": validation_results,
            "evaluation_time": contract["evaluation_time"],
        }
        projection_receipt["receipt_id"] = (
            f"receipt:{digest_json(projection_receipt).split(':', 1)[1][:24]}"
        )
        write_canonical(
            root
            / ".cpcf"
            / "receipts"
            / f"{projection_receipt['receipt_id'].replace(':', '-')}.json",
            projection_receipt,
        )
        post_digest = state_digest(root)
        source_backed = (
            "true"
            if valid_projection and all(value == "true" for value in validation_results.values())
            else "false"
        )
        history_path = root / ".cpcf" / "history.json"
        history_value = load_json(history_path) if history_path.is_file() else {"records": []}
        history = history_value.get("records", []) if isinstance(history_value, dict) else []
        transition: JsonObject = {
            "schema_version": "0.2.0",
            "transition_id": f"transition:{len(history) + 1:04d}",
            "action_id": action_id,
            "pre_state_digest": locked_pre_digest,
            "post_state_digest": post_digest,
            "outcome": outcome,
            "projection_receipt_refs": [projection_receipt["receipt_id"]],
            "source_backed_post_state": source_backed,
            "projection_errors": projection_errors,
            "process_receipt": receipt,
            "progress": "structural_progress"
            if post_digest != locked_pre_digest and source_backed == "true"
            else "no_progress",
            "action_signature": digest_json(
                {
                    "adapter": action.get("adapter"),
                    "operation": action.get("operation"),
                    "argv": action.get("exact_argv"),
                }
            ),
        }
        history.append(transition)
        write_canonical(history_path, {"records": history})
        write_canonical(
            root
            / ".cpcf"
            / "transitions"
            / f"{transition['transition_id'].replace(':', '-')}.json",
            transition,
        )
        manifest = load_json(root / ".cpcf" / "workspace.json")
        if isinstance(manifest, dict):
            manifest["state_digest"] = post_digest
            write_canonical(root / ".cpcf" / "workspace.json", manifest)
    return {
        "command_status": "ok" if source_backed == "true" else "failed",
        "outcome": outcome,
        "projection_paths": projection_paths if valid_projection else [],
        "projection_receipt": projection_receipt,
        "structural_transition": transition,
        "source_backed_post_state": source_backed,
    }
