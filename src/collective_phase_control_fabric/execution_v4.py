# SPDX-License-Identifier: Apache-2.0
"""One-action isolated execution with complete v0.4 process provenance."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.generation_v4 import GenerationStoreV4, ledger_entry
from collective_phase_control_fabric.limits import (
    HARD_CAPTURE_BYTES,
    HARD_PROCESS_SECONDS,
    loads_json_bounded,
)
from collective_phase_control_fabric.planner_v4 import BRANCHES, plan_v4
from collective_phase_control_fabric.process import ENV_ALLOWLIST, run_process
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject, JsonValue
from collective_phase_control_fabric.workspace_v4 import active_attestations_v4, response


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _inventory(root: Path) -> str:
    control = root.resolve() / ".cpcf"
    records: list[JsonObject] = []
    if control.is_dir():
        for path in sorted(control.rglob("*"), key=lambda item: str(item)):
            if not path.is_file() or path.name.endswith(".lock"):
                continue
            resolved = path.resolve()
            if control != resolved and control not in resolved.parents:
                raise ValueError("workspace inventory path escape")
            records.append(
                {
                    "path": str(path.relative_to(control)).replace("\\", "/"),
                    "digest": _file_digest(path),
                    "size": path.stat().st_size,
                }
            )
    return digest_v3_json(cast(JsonValue, records))


def _pointer(value: JsonValue, pointer: str) -> JsonValue:
    if pointer == "":
        return value
    current = value
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise ValueError("outcome selector pointer missing")
    return current


def _action(statements: list[JsonObject], action_id: str) -> JsonObject | None:
    for statement in statements:
        payload = statement.get("payload")
        if not isinstance(payload, dict) or payload.get("subject_id") != action_id:
            continue
        attributes = payload.get("attributes")
        if (
            payload.get("record_type") == "evidence"
            and isinstance(attributes, dict)
            and attributes.get("evidence_type") == "action"
        ):
            return statement
    return None


def run_action_v4(root: Path, action_id: str, *, apply: bool) -> JsonObject:
    if not apply:
        return response(
            "failed",
            "apply_required",
            effect_class="local_write",
            next_commands=[
                ["cpcf", "control", "run", "--workspace", str(root), action_id, "--apply", "--json"]
            ],
        )
    plan = plan_v4(root)
    safe_ids = {
        str(item.get("action_id"))
        for item in [
            plan.get("primary_action"),
            *cast(list[object], plan.get("pareto_alternatives", [])),
        ]
        if isinstance(item, dict)
    }
    if action_id not in safe_ids:
        return response(
            "failed",
            "action_not_currently_safe_or_selected",
            next_commands=[
                ["cpcf", "control", "next", "--workspace", str(root), "--compact", "--json"]
            ],
        )
    try:
        manifest, _, statements, _ = active_attestations_v4(root)
        statement = _action(statements, action_id)
        if statement is None:
            raise ValueError("action attestation missing")
        attributes = cast(JsonObject, statement["payload"]["attributes"])
        executable_value = str(attributes["executable"])
        located = shutil.which(executable_value)
        executable = Path(located).resolve() if located else Path(executable_value).resolve()
        if not executable.is_file():
            raise ValueError("adapter executable missing")
        if _file_digest(executable) != attributes.get("executable_digest"):
            raise ValueError("adapter executable digest mismatch")
        argv_prefix = attributes.get("argv_prefix")
        arguments = attributes.get("arguments", [])
        execution_policy = attributes.get("execution_policy")
        if not isinstance(argv_prefix, list) or not argv_prefix or not isinstance(arguments, list):
            raise ValueError("adapter argv invalid")
        if not isinstance(execution_policy, dict):
            raise ValueError("signed execution policy missing")
        if validation_errors("execution-policy", execution_policy, "0.4.0"):
            raise ValueError("signed execution policy invalid")
        timeout = min(HARD_PROCESS_SECONDS, int(execution_policy["timeout_seconds"]))
        stdout_limit = min(HARD_CAPTURE_BYTES, int(execution_policy["stdout_bytes"]))
        stderr_limit = min(HARD_CAPTURE_BYTES, int(execution_policy["stderr_bytes"]))
        stdin_limit = min(HARD_CAPTURE_BYTES, int(execution_policy["stdin_bytes"]))
        permitted_environment = frozenset(
            str(item) for item in execution_policy["permitted_environment_keys"]
        )
        if not permitted_environment <= ENV_ALLOWLIST:
            raise ValueError("execution policy requests non-minimal environment key")
        argv = [*cast(list[str], argv_prefix), *cast(list[str], arguments)]
        if Path(shutil.which(argv[0]) or argv[0]).resolve() != executable:
            raise ValueError("adapter argv executable mismatch")
        workspace_resolved = root.resolve()
        for argument in argv[1:]:
            normalized_argument = argument.replace("/", "\\").casefold()
            normalized_workspace = str(workspace_resolved).replace("/", "\\").casefold()
            if normalized_workspace in normalized_argument:
                raise ValueError("workspace path embedded in adapter argv")
            candidate = Path(argument)
            if candidate.is_absolute():
                resolved = candidate.resolve()
                if resolved == workspace_resolved or workspace_resolved in resolved.parents:
                    raise ValueError("workspace path in adapter argv")
    except (KeyError, OSError, TypeError, ValueError) as error:
        return response("failed", "action_binding_invalid", detail=str(error))
    store = GenerationStoreV4(root)
    current = str(manifest["generation_id"])
    invocation = {
        "schema_version": "0.4.0",
        "action_id": action_id,
        "action_statement_digest": digest_v3_json(statement),
        "generation_before": current,
        "arguments": arguments,
        "execution_policy": execution_policy,
    }
    invocation_digest = digest_v3_json(invocation)
    before = _inventory(root)
    with tempfile.TemporaryDirectory(prefix="cpcf-v0.4-") as temporary:
        invocation_root = Path(temporary)
        process = run_process(
            argv,
            invocation_root,
            invocation_root,
            timeout_seconds=timeout,
            stdin_limit=stdin_limit,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            environment_allowlist=permitted_environment,
        )
    after = _inventory(root)
    if before != after or store.current_id() != current:
        return response(
            "failed",
            "unexpected_workspace_mutation_during_adapter_execution",
            generation=current,
            workspace_before_digest=before,
            workspace_after_digest=after,
        )
    raw = bytes.fromhex(str(process["stdout_raw_hex"]))
    parsed: JsonValue = None
    if (
        process.get("exit_code") == 0
        and process.get("timed_out") is False
        and process.get("stdout_truncated") is False
        and process.get("stdout_utf8_valid") is True
    ):
        try:
            parsed = loads_json_bounded(raw, maximum_bytes=stdout_limit)
        except (ValueError, json.JSONDecodeError):
            parsed = None
    if process.get("timed_out") is True:
        outcome = "timeout"
    elif process.get("exit_code") != 0 or parsed is None:
        outcome = "failure"
    else:
        selector = attributes.get("outcome_selector")
        try:
            if not isinstance(selector, dict):
                raise ValueError("outcome selector missing")
            selected = _pointer(parsed, str(selector["source_pointer"]))
            mapping = selector.get("mapping")
            mapped = mapping.get(str(selected)) if isinstance(mapping, dict) else None
            outcome = str(mapped) if mapped in BRANCHES else "failure"
        except (KeyError, TypeError, ValueError, IndexError):
            outcome = "failure"
    raw_digest = store.cas.put(raw).digest
    receipt: JsonObject = {
        "schema_version": "0.4.0",
        "receipt_id": f"process:{invocation_digest[7:]}",
        "executable_digest": str(process["executable_digest"]),
        "invocation_digest": invocation_digest,
        "return_code": process["exit_code"],
        "timed_out": process["timed_out"],
        "stdout_digest": str(process["stdout_full_digest"]),
        "stderr_digest": str(process["stderr_full_digest"]),
        "stdout_captured_bytes": process["stdout_byte_count_captured"],
        "stdout_discarded_bytes": int(process["stdout_byte_count_total"])
        - int(process["stdout_byte_count_captured"]),
        "stderr_captured_bytes": process["stderr_byte_count_captured"],
        "stderr_discarded_bytes": int(process["stderr_byte_count_total"])
        - int(process["stderr_byte_count_captured"]),
        "environment_keys": process["environment_keys"],
        "workspace_before_digest": before,
        "workspace_after_digest": after,
        "sandbox_status": "not_provided",
    }
    receipt_errors = validation_errors("process-receipt", receipt, "0.4.0")
    if receipt_errors:
        return response("failed", "process_receipt_invalid", schema_errors=receipt_errors)
    receipt_digest = store.put_json(receipt)
    action_receipt: JsonObject = {
        "schema_version": "0.4.0",
        "object_id": f"action-receipt:{invocation_digest[7:]}",
        "analysis_snapshot_digest": digest_v3_json(
            cast(JsonValue, plan.get("scientific_profile", {}))
        ),
        "payload": {
            "action_id": action_id,
            "generation_before": current,
            "outcome": outcome,
            "process_receipt_digest": receipt_digest,
            "raw_output_digest": raw_digest,
            "state_promoted": False,
        },
    }
    action_receipt_digest = store.put_json(action_receipt)
    payload = deepcopy(manifest)
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(
            raw_digest,
            kind="adapter-raw-output",
            schema_ref=str(attributes.get("output_schema_ref", "unknown@0.4.0")),
            lifecycle="quarantined",
        ),
        ledger_entry(
            receipt_digest,
            kind="process-receipt",
            schema_ref="process-receipt@0.4.0",
            source_chain=[raw_digest],
        ),
        ledger_entry(
            action_receipt_digest,
            kind="action-receipt",
            schema_ref="action-receipt@0.4.0",
            source_chain=[receipt_digest, raw_digest],
            authority_key_id=str(statement["protected"]["key_id"]),
        ),
    ]
    payload["quarantine"] = sorted(set([*payload.get("quarantine", []), raw_digest]))
    payload["history"] = [
        *payload.get("history", []),
        {
            "event_type": "action_executed",
            "action_id": action_id,
            "outcome": outcome,
            "action_receipt_digest": action_receipt_digest,
            "state_promoted": False,
            "previous_event_digest": digest_v3_json(cast(JsonValue, manifest.get("history", []))),
        },
    ]
    committed = store.commit(payload, expected_current=current)
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        claims=["process_outcome_receipt_bound"],
        unknowns=["output_state_promotion"],
        quarantined=[raw_digest],
        action_id=action_id,
        outcome=outcome,
        process_receipt_digest=receipt_digest,
        action_receipt_digest=action_receipt_digest,
        source_backed_post_state="unknown",
        one_step_execution_limit=1,
        os_sandbox_claim=False,
        network_sandbox_claim=False,
    )
