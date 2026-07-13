# SPDX-License-Identifier: Apache-2.0
"""Workspace lifecycle, action explanations, and actual transition records."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from pathlib import Path

from collective_phase_control_fabric.canonical import digest_json, load_json, write_canonical
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.demos import bootstrap_demo as bootstrap_v2_demo
from collective_phase_control_fabric.engine import analyze
from collective_phase_control_fabric.index import inspect_index
from collective_phase_control_fabric.planner import plan_actions
from collective_phase_control_fabric.provenance import receipt_source_backed
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject
from collective_phase_control_fabric.workspace_v2 import (
    prepare_native_step,
    run_native_step,
    strict_doctor,
    workspace_version,
)


def _object(path: Path) -> JsonObject | None:
    if not path.is_file():
        return None
    value = load_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_workspace(
    root: Path,
) -> tuple[
    JsonObject | None,
    JsonObject | None,
    JsonObject | None,
    JsonObject | None,
    list[JsonObject],
    list[JsonObject],
]:
    """Load finite CPCF projections and local planner history."""

    contract = _object(root / "contract.json")
    network = _object(root / "network.json")
    productive = _object(root / "productive_witness.json")
    maintenance = _object(root / "maintenance_witness.json")
    actions_value = _object(root / "actions.json") or {"actions": []}
    history_value = _object(root / ".cpcf" / "history.json") or {"records": []}
    actions = [item for item in actions_value.get("actions", []) if isinstance(item, dict)]
    history = [item for item in history_value.get("records", []) if isinstance(item, dict)]
    return contract, network, productive, maintenance, actions, history


def inspect_workspace(root: Path) -> JsonObject:
    """Analyze a workspace and attach stable projection paths."""

    contract, network, productive, maintenance, _, _ = load_workspace(root)
    witnesses: dict[str, JsonObject] = {}
    if (
        workspace_version(root) == "0.2.0"
        and isinstance(network, dict)
        and isinstance(contract, dict)
    ):
        runtime_network = deepcopy(network)
        store = ContentAddressedStore(root / ".cpcf" / "cas")
        receipt_by_projection: dict[str, JsonObject] = {}
        for path in sorted((root / ".cpcf" / "receipts").glob("*.json")):
            receipt = _object(path)
            if receipt is None:
                continue
            for projected_digest in receipt.get("projected_object_digests", []):
                if isinstance(projected_digest, str):
                    receipt_by_projection[projected_digest] = receipt
        network_receipt = receipt_by_projection.get(digest_json(network))
        network_source_backed = (
            network_receipt is not None and receipt_source_backed(network_receipt, store) == "true"
        )
        for edge in runtime_network.get("transformations", []):
            if isinstance(edge, dict):
                edge["schema_version"] = "0.2.0"
                edge["_source_backed_runtime"] = network_source_backed
                expiry = edge.get("expires_at") or edge.get("expiry")
                if expiry is not None:
                    try:
                        expired = datetime.fromisoformat(
                            str(expiry).replace("Z", "+00:00")
                        ) < datetime.fromisoformat(
                            str(contract.get("evaluation_time")).replace("Z", "+00:00")
                        )
                        edge["lifecycle_status"] = "expired" if expired else "valid"
                    except ValueError:
                        edge["lifecycle_status"] = "unknown"
        expiring_types = {
            "evidence",
            "verifier_report",
            "authority_record",
            "hazard_record",
            "resource_record",
            "lifecycle_record",
        }
        for node in runtime_network.get("nodes", []):
            if not isinstance(node, dict) or node.get("type") not in expiring_types:
                continue
            expiry = node.get("expires_at") or node.get("expiry")
            if expiry is None:
                node["lifecycle_status"] = "unknown"
                continue
            try:
                expired = datetime.fromisoformat(
                    str(expiry).replace("Z", "+00:00")
                ) < datetime.fromisoformat(
                    str(contract.get("evaluation_time")).replace("Z", "+00:00")
                )
                node["lifecycle_status"] = "expired" if expired else "valid"
            except ValueError:
                node["lifecycle_status"] = "unknown"
        for path in sorted((root / "witnesses").glob("*.json")):
            witness = _object(path)
            if witness is None:
                continue
            receipt = receipt_by_projection.get(digest_json(witness))
            if receipt is None or receipt_source_backed(receipt, store) != "true":
                continue
            schema_name: str | None = None
            for projected in receipt.get("projected_objects", []):
                if isinstance(projected, dict) and projected.get("digest") == digest_json(witness):
                    schema_name = str(projected.get("schema_ref", "")).split("@", 1)[0]
                    break
            if schema_name:
                witnesses[schema_name] = witness
                if schema_name == "productive-plan-witness":
                    productive = witness
                if schema_name in {"maintenance-witness", "persistence-witness"}:
                    maintenance = witness
        for path in sorted((root / ".cpcf" / "projections").glob("*.json")):
            projection = _object(path)
            if projection is None or projection.get("schema_version") != "0.2.0":
                continue
            receipt = receipt_by_projection.get(digest_json(projection))
            if receipt is None or receipt_source_backed(receipt, store) == "false":
                continue
            if projection.get("certificate_kind"):
                node = deepcopy(projection)
                node["node_id"] = projection.get("certificate_id")
                node["type"] = "external_certificate"
                node["_cpcf_validation"] = receipt.get("validation_results", {})
                runtime_network.setdefault("nodes", []).append(node)
        network = runtime_network
    result = analyze(contract, network, productive, maintenance, witnesses)
    result["workspace"] = str(root.resolve())
    result["workspace_schema_version"] = workspace_version(root)
    return result


def _demo_action(root: Path) -> JsonObject:
    """Build a legacy planner-only fixture; it is never installed or executable."""

    return {
        "action_id": "action:legacy-planner-fixture",
        "purpose": "Exercise v0.1 read-only planning compatibility.",
        "priority_class": 6,
        "targeted_barrier_ids": [],
        "targeted_seed_ids": [],
        "targeted_target_paths": [],
        "required_role": "fixture",
        "coordination_recommendation": "none",
        "independence_requirement": "not_applicable",
        "adapter": "deprecated_fixture",
        "operation": "never_execute",
        "exact_argv": [str(root / "nonexistent-deprecated-fixture")],
        "effect_class": "validate",
        "network_class": "none",
        "input_refs": ["state:input", "evidence:source", "report:verifier"],
        "required_authority_refs": [],
        "resource_upper_bounds": {"local_io": {"quantity": "1", "unit": "operation"}},
        "output_contract": {"type": "none"},
        "postcondition_contract": {},
        "conditional_impact_projection": None,
        "local_writes": [],
        "required_flag": "not_applicable",
        "reason_refs": [],
        "alternative_action_ids": [],
        "source_version_supported": True,
        "report_malformed": False,
        "authority_status": True,
        "hazard_status": True,
        "recursive_reuse_valid": True,
        "independence_valid": True,
        "lifecycle_status": True,
        "protected_floor_violation": False,
    }


def bootstrap_demo(root: Path, scenario: str = "orientation-only-reachability") -> JsonObject:
    """Create one native receipt-backed v0.2 demonstration workspace."""

    return bootstrap_v2_demo(root, scenario)


def doctor(root: Path, strict: bool = False) -> JsonObject:
    """Inspect required files, schemas, path boundaries, and rebuildable index health."""

    if strict:
        return strict_doctor(root, inspect_workspace(root))

    errors: list[JsonObject] = []
    files = {
        name: (root / name).is_file() for name in ("contract.json", "network.json", "actions.json")
    }
    for name, schema_name in (
        ("contract.json", "phase-contract"),
        ("network.json", "transformation-network"),
    ):
        if files[name]:
            value = load_json(root / name)
            version = workspace_version(root)
            errors.extend(
                {"file": name, **error} for error in validation_errors(schema_name, value, version)
            )
    boundary_valid = root.resolve() == root.absolute().resolve()
    status = "ok" if all(files.values()) and not errors and boundary_valid else "failed"
    return {
        "command_status": status,
        "workspace": str(root.resolve()),
        "required_files": files,
        "schema_errors": errors,
        "path_boundary_valid": boundary_valid,
        "sqlite_index": inspect_index(root / ".cpcf" / "index.sqlite3"),
        "sqlite_role": "rebuildable_cpcf_cas_index_only",
        "source_of_record_migrated": False,
        "network_required": False,
    }


def next_actions(root: Path) -> JsonObject:
    """Compute filtered conditional impacts and Pareto selection."""

    contract, network, productive, maintenance, actions, history = load_workspace(root)
    if contract is None or network is None:
        return {"command_status": "failed", "reason": "workspace_uninitialized"}
    analysis = (
        inspect_workspace(root)
        if workspace_version(root) == "0.2.0"
        else analyze(contract, network, productive, maintenance)
    )
    result = plan_actions(
        actions,
        contract,
        network,
        productive,
        maintenance,
        analysis,
        history,
        analyze,
    )
    result["command_status"] = "ok"
    result["phase_projection"] = analysis["phase_projection"]
    return result


def action_by_id(root: Path, action_id: str) -> JsonObject:
    """Return one declared action by exact stable identifier."""

    *_, actions, _ = load_workspace(root)
    for action in actions:
        if action.get("action_id") == action_id:
            return action
    raise KeyError(action_id)


def explain_action(root: Path, action_id: str) -> JsonObject:
    """Explain barriers, paths, seeds, detector relations, and non-claims."""

    action = action_by_id(root, action_id)
    analysis = inspect_workspace(root)
    return {
        "command_status": "ok",
        "action_id": action_id,
        "current_barrier_reason": action.get("reason_refs", []),
        "blocked_target_paths": action.get("targeted_target_paths", []),
        "related_formation_seeds": action.get("targeted_seed_ids", []),
        "false_cycle_relation": [
            item
            for item in analysis.get("false_positive_detections", [])
            if item.get("blocking") is True
        ],
        "deadlock_relation": analysis.get("regeneration_deadlocks", []),
        "verification_queue_relation": analysis.get("verification_load", {}),
        "priority_class_reason": {
            "priority_class": action.get("priority_class"),
            "rule": "productive-plan evidence acquisition follows integrity and formation repair",
        },
        "conditional_impact": next(
            (
                item.get("conditional_impact_projection")
                for item in [
                    next_actions(root).get("primary_action"),
                    *next_actions(root).get("pareto_alternatives", []),
                ]
                if isinstance(item, dict) and item.get("action_id") == action_id
            ),
            None,
        ),
        "success_postcondition": action.get("postcondition_contract"),
        "does_not_prove": [
            "operation success",
            "measured acceleration",
            "intelligence gain",
            "external settlement",
            "authority",
            "physical outcome",
        ],
    }


def prepare_step(root: Path, action_id: str) -> JsonObject:
    """Write one exact invocation request without running the operation."""

    if workspace_version(root) == "0.2.0":
        return prepare_native_step(root, action_id)

    action = action_by_id(root, action_id)
    analysis = inspect_workspace(root)
    request: JsonObject = {
        "request_schema_version": "0.1.0",
        "action_id": action_id,
        "operation": action["operation"],
        "effect_class": action["effect_class"],
        "input_refs": action["input_refs"],
        "output_contract": action["output_contract"],
        "postcondition_contract_digest": digest_json(action["postcondition_contract"]),
        "pre_network_digest": analysis["phase_projection"]["network_ref"],
        "pre_barrier_digest": analysis["phase_projection"]["barrier_ref"],
    }
    action_token = digest_json(action_id).split(":", 1)[1]
    path = root / ".cpcf" / "invocations" / f"legacy-action-{action_token}.json"
    write_canonical(path, request)
    return {
        "command_status": "ok",
        "action_id": action_id,
        "invocation_request": str(path.resolve()),
        "exact_argv": action["exact_argv"],
        "effect_class": action["effect_class"],
        "required_flag": action["required_flag"],
        "executed": False,
    }


def run_step(root: Path, action_id: str, mode: str) -> JsonObject:
    """Execute exactly one registered action and rebuild every structural projection."""

    if workspace_version(root) == "0.2.0":
        return run_native_step(root, action_id, mode)
    return {
        "command_status": "failed",
        "reason": "legacy_action_not_executable",
        "failure_code": "legacy_action_not_executable",
        "next_safe_command": [
            "cpcf",
            "workspace",
            "migrate",
            "--workspace",
            str(root.resolve()),
            "--out",
            str((root.parent / f"{root.name}-v0.2").resolve()),
            "--to",
            "0.2.0",
            "--json",
        ],
    }
