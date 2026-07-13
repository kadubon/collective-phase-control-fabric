# SPDX-License-Identifier: Apache-2.0
"""One-action, process-bound execution for CPCF v0.3."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_v3_json, loads_json_strict
from collective_phase_control_fabric.generation import GenerationStore
from collective_phase_control_fabric.planner_v3 import BRANCHES, plan_v3
from collective_phase_control_fabric.process import run_process
from collective_phase_control_fabric.provenance import parse_schema_ref
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject, JsonValue, id_set
from collective_phase_control_fabric.workspace_v3 import _pointer, valid_projections_v3


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _resolve_executable(value: str) -> Path | None:
    located = shutil.which(value)
    path = Path(located) if located else Path(value)
    return path.resolve() if path.is_file() else None


def _objects(root: Path) -> tuple[JsonObject, dict[str, list[JsonObject]]]:
    manifest, projections = valid_projections_v3(root)
    result: dict[str, list[JsonObject]] = {}
    for record, value in projections:
        result.setdefault(str(record["schema_ref"]).split("@", 1)[0], []).append(value)
    return manifest, result


def run_action_v3(root: Path, action_id: str, *, apply: bool) -> JsonObject:
    if not apply:
        return {
            "command_status": "failed",
            "failure_code": "apply_required",
            "effect_class": "local_write",
            "files_written": [],
            "authority_required": [],
            "next_safe_commands": [
                ["cpcf", "control", "run", "--workspace", str(root), action_id, "--apply", "--json"]
            ],
        }
    plan = plan_v3(root)
    safe_ids = {
        str(item.get("action_id"))
        for item in [
            plan.get("primary_action"),
            *cast(list[object], plan.get("pareto_alternatives", [])),
        ]
        if isinstance(item, dict)
    }
    if action_id not in safe_ids:
        return {
            "command_status": "failed",
            "failure_code": "action_not_currently_safe_or_selected",
            "effect_class": "inspect",
            "files_written": [],
            "authority_required": [],
            "next_safe_commands": [
                ["cpcf", "control", "next", "--workspace", str(root), "--compact", "--json"]
            ],
        }
    try:
        manifest, objects = _objects(root)
        current = str(manifest["generation_id"])
        action = next(
            item for item in objects.get("action", []) if item.get("action_id") == action_id
        )
        capability = next(
            item
            for item in objects.get("adapter-capability", [])
            if item.get("capability_id") == action.get("capability_ref")
        )
        effect = next(
            item
            for item in objects.get("branch-effect-contract", [])
            if item.get("effect_id") == capability.get("branch_effect_ref")
        )
    except (OSError, StopIteration, ValueError) as error:
        return {
            "command_status": "failed",
            "failure_code": "action_binding_invalid",
            "detail": str(error),
        }
    executable = _resolve_executable(str(capability["executable"]))
    argv_prefix = capability.get("argv_prefix", [])
    if executable is None or not isinstance(argv_prefix, list) or not argv_prefix:
        return {"command_status": "failed", "failure_code": "adapter_executable_missing"}
    if _resolve_executable(str(argv_prefix[0])) != executable:
        return {"command_status": "failed", "failure_code": "adapter_argv_executable_mismatch"}
    if _file_digest(executable) != capability.get("executable_digest"):
        return {"command_status": "failed", "failure_code": "adapter_executable_digest_mismatch"}
    argv = [*cast(list[str], argv_prefix), *cast(list[str], action.get("arguments", []))]
    workspace_resolved = root.resolve()
    for argument in argv[1:]:
        candidate = Path(argument)
        if candidate.is_absolute():
            try:
                resolved = candidate.resolve()
                if resolved == workspace_resolved or workspace_resolved in resolved.parents:
                    return {
                        "command_status": "failed",
                        "failure_code": "workspace_path_in_adapter_argv",
                    }
            except OSError:
                pass
    store = GenerationStore(root)
    contract = store.get_json(str(manifest["contract_digest"]))
    if not isinstance(contract, dict):
        return {"command_status": "failed", "failure_code": "generation_contract_invalid"}
    invocation: JsonObject = {
        "schema_version": "0.3.0",
        "action_id": action_id,
        "capability_digest": digest_v3_json(cast(JsonValue, capability)),
        "generation_before": current,
        "arguments": action.get("arguments", []),
    }
    invocation_digest = digest_v3_json(invocation)
    with tempfile.TemporaryDirectory(prefix="cpcf-v0.3-") as temporary:
        invocation_root = Path(temporary)
        process_receipt = run_process(
            argv,
            invocation_root,
            invocation_root,
            timeout_seconds=30,
            stdout_limit=1_048_576,
            stderr_limit=1_048_576,
        )
    if store.current_id() != current or store.verify_chain():
        return {
            "command_status": "failed",
            "failure_code": "unexpected_workspace_mutation_during_adapter_execution",
            "generation_committed": False,
        }
    raw = bytes.fromhex(str(process_receipt["stdout_raw_hex"]))
    parsed: JsonValue = None
    if (
        process_receipt.get("exit_code") == 0
        and process_receipt.get("timed_out") is False
        and process_receipt.get("stdout_truncated") is False
        and process_receipt.get("stdout_utf8_valid") is True
    ):
        try:
            parsed = loads_json_strict(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            parsed = None
    if parsed is not None:
        try:
            output_name, output_version = parse_schema_ref(str(capability["output_schema_ref"]))
            if (
                validation_errors(output_name, parsed, output_version)
                or not isinstance(parsed, dict)
                or parsed.get("action_id") != action_id
            ):
                parsed = None
        except (KeyError, ValueError):
            parsed = None
    if process_receipt.get("timed_out") is True:
        outcome = "timeout"
    elif process_receipt.get("exit_code") != 0 or parsed is None:
        outcome = "failure"
    else:
        selector = capability.get("outcome_selector", {})
        try:
            selected = _pointer(parsed, str(selector["source_pointer"]))
            mapped = selector["mapping"].get(str(selected))
            outcome = mapped if mapped in BRANCHES else "failure"
        except (KeyError, TypeError, ValueError, IndexError):
            outcome = "failure"
    branch = effect["branches"][outcome]
    raw_digest = store.cas.put(raw).digest
    process_receipt_digest = store.put_json(cast(JsonValue, process_receipt))
    projected_objects: list[JsonObject] = []
    projection_records: list[JsonObject] = []
    projection_errors: list[JsonObject] = []
    if parsed is not None:
        for possibility in branch.get("projection_possibilities", []):
            try:
                projected = _pointer(parsed, str(possibility["source_pointer"]))
                schema_ref = str(possibility["target_schema"])
                name, version = parse_schema_ref(schema_ref)
                errors = validation_errors(name, projected, version)
                if errors:
                    projection_errors.append(
                        {"source_pointer": possibility["source_pointer"], "schema_errors": errors}
                    )
                    continue
                digest = store.put_json(projected)
                projected_objects.append(
                    {
                        "digest": digest,
                        "schema_ref": schema_ref,
                        "source_pointer": possibility["source_pointer"],
                    }
                )
            except (KeyError, TypeError, ValueError, IndexError) as error:
                projection_errors.append(
                    {"failure_code": "projection_reconstruction_failed", "detail": str(error)}
                )
    source_backed = (
        "true"
        if not projection_errors
        and len(projected_objects) == len(branch.get("projection_possibilities", []))
        else "false"
    )
    envelope: JsonObject = {
        "schema_version": "0.3.0",
        "envelope_id": f"envelope:{raw_digest.split(':', 1)[1][:24]}",
        "source_system": str(capability["adapter"]),
        "schema_ref": str(capability["output_schema_ref"]),
        "raw_artifact_digest": raw_digest,
        "raw_size": len(raw),
        "scope": contract.get("scope", {}),
        "lifecycle": {},
        "lineage": [action_id],
        "source_pointers": sorted({str(item["source_pointer"]) for item in projected_objects})
        or [""],
        "imported_at": str(manifest["analysis_epoch"]),
        "signature_requirement": "process_bound",
    }
    envelope_digest = store.put_json(envelope)
    projection_receipt: JsonObject = {
        "schema_version": "0.3.0",
        "receipt_id": f"receipt:{invocation_digest.split(':', 1)[1][:24]}",
        "envelope_digest": envelope_digest,
        "raw_artifact_digest": raw_digest,
        "invocation_digest": invocation_digest,
        "executable_digest": process_receipt["executable_digest"],
        "return_code": process_receipt["exit_code"],
        "timed_out": process_receipt["timed_out"],
        "stdout_truncated": process_receipt["stdout_truncated"],
        "stderr_truncated": process_receipt["stderr_truncated"],
        "projected_objects": projected_objects if source_backed == "true" else [],
        "cached_validation": {
            "schema": "true" if parsed is not None else "false",
            "digest": "true" if process_receipt["stdout_full_digest"] == raw_digest else "false",
            "pointer": "true" if not projection_errors else "false",
            "expiry": "not_applicable",
            "scope": "true",
            "resource": "true",
            "baseline": "not_applicable",
            "signature": "not_applicable",
            "return_code": "true" if process_receipt["exit_code"] == 0 else "false",
            "output_limits": "true" if not process_receipt["stdout_truncated"] else "false",
        },
        "evaluation_time": str(manifest["analysis_epoch"]),
    }
    projection_receipt_digest = store.put_json(projection_receipt)
    for item in projected_objects if source_backed == "true" else []:
        projection_records.append(
            {
                "object_digest": item["digest"],
                "schema_ref": item["schema_ref"],
                "receipt_digest": projection_receipt_digest,
                "source_pointer": item["source_pointer"],
            }
        )
    action_receipt: JsonObject = {
        "schema_version": "0.3.0",
        "action_id": action_id,
        "generation_before": current,
        "generation_after": None,
        "outcome": outcome,
        "process_receipt_digest": process_receipt_digest,
        "projection_receipt_digest": projection_receipt_digest,
        "source_backed_post_state": source_backed,
    }
    action_receipt_digest = store.put_json(action_receipt)
    payload = deepcopy(manifest)
    payload["raw_artifacts"] = sorted({*cast(list[str], manifest["raw_artifacts"]), raw_digest})
    payload["envelopes"] = sorted({*cast(list[str], manifest["envelopes"]), envelope_digest})
    payload["receipts"] = sorted(
        {*cast(list[str], manifest["receipts"]), projection_receipt_digest}
    )
    payload["projections"] = sorted(
        [*cast(list[JsonObject], manifest["projections"]), *projection_records],
        key=lambda item: (str(item["schema_ref"]), str(item["object_digest"])),
    )
    payload["history"] = [
        *cast(list[JsonObject], manifest["history"]),
        {
            "event_type": "action_executed",
            "action_id": action_id,
            "outcome": outcome,
            "progress": "receipt_backed_projection" if projection_records else "no_progress",
            "action_receipt_digest": action_receipt_digest,
            "previous_event_digest": digest_v3_json(cast(JsonValue, manifest["history"])),
        },
    ]
    committed = store.commit(payload, expected_current=current)
    return {
        "command_status": committed.get("command_status"),
        "failure_code": committed.get("failure_code"),
        "action_id": action_id,
        "outcome": outcome,
        "generation_before": current,
        "generation_after": committed.get("generation_id"),
        "source_backed_post_state": source_backed,
        "projection_errors": projection_errors,
        "process_receipt_digest": process_receipt_digest,
        "action_receipt_digest": action_receipt_digest,
        "generation_committed": committed.get("generation_committed", False),
        "effect_class": str(capability["effect_class"]),
        "files_written": [str(store.current_path)]
        if committed.get("command_status") == "ok"
        else [],
        "authority_required": sorted(
            id_set(action.get("required_authority_refs"))
            | id_set(action.get("required_hazard_refs"))
        ),
        "next_safe_commands": [["cpcf", "doctor", "--workspace", str(root), "--json"]],
        "one_step_execution_limit": 1,
        "os_sandbox_claim": False,
        "network_sandbox_claim": False,
    }
