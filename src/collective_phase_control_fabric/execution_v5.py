# SPDX-License-Identifier: Apache-2.0
"""CAS-pinned local execution and two-phase projection promotion for CPCF v0.5."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.generation_v5 import (
    GenerationStoreV5,
    history_event,
    ledger_entry,
)
from collective_phase_control_fabric.limits import (
    HARD_CAPTURE_BYTES,
    HARD_PROCESS_SECONDS,
    loads_json_bounded,
)
from collective_phase_control_fabric.planner_v5 import BRANCHES, plan_v5
from collective_phase_control_fabric.process import ENV_ALLOWLIST, run_process
from collective_phase_control_fabric.schema import load_schema, validation_errors
from collective_phase_control_fabric.science_v5 import science_audit_v5
from collective_phase_control_fabric.trust_v5 import verify_statement
from collective_phase_control_fabric.types import JsonObject, JsonValue
from collective_phase_control_fabric.workspace_v5 import active_attestations_v5, response

RISK_ACKNOWLEDGEMENT = "UNSANDBOXED_LOCAL_EXECUTION"


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _inventory(root: Path) -> str:
    resolved_root = root.absolute()
    records: list[JsonObject] = []
    for path in sorted(resolved_root.rglob("*"), key=lambda item: str(item)):
        if not path.is_file() or path == resolved_root / ".cpcf" / "workspace.lock":
            continue
        if path.is_symlink():
            raise ValueError("workspace inventory contains a symbolic link")
        resolved = path.resolve()
        if resolved != resolved_root and resolved_root not in resolved.parents:
            raise ValueError("workspace inventory path escape")
        records.append(
            {
                "path": str(path.relative_to(resolved_root)).replace("\\", "/"),
                "digest": _file_digest(path),
                "size": path.stat().st_size,
            }
        )
    return digest_v3_json(cast(JsonValue, records))


def _pointer(value: JsonValue, pointer: str) -> JsonValue:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must start with slash")
    current = value
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise ValueError("JSON pointer does not resolve")
    return current


def _attributes(statement: JsonObject) -> JsonObject:
    payload = statement.get("payload")
    value = payload.get("attributes") if isinstance(payload, dict) else None
    return value if isinstance(value, dict) else {}


def _subject(statement: JsonObject) -> str:
    payload = statement.get("payload")
    return str(payload.get("subject_id")) if isinstance(payload, dict) else ""


def _evidence(
    statements: list[JsonObject], subject_id: str, evidence_type: str
) -> JsonObject | None:
    matches = [
        item
        for item in statements
        if _subject(item) == subject_id and _attributes(item).get("evidence_type") == evidence_type
    ]
    return matches[0] if len(matches) == 1 else None


def inspect_execution_risk_v5(root: Path) -> JsonObject:
    try:
        generation = GenerationStoreV5(root).current_id()
    except (OSError, ValueError) as error:
        return response("failed", "execution_risk_inspection_failed", detail=str(error))
    return response(
        "ok",
        None,
        generation=generation,
        claims=["local_process_limits_and_mutation_detection_available"],
        unknowns=["filesystem_read_containment", "network_containment", "kernel_isolation"],
        required_acknowledgement=RISK_ACKNOWLEDGEMENT,
        sandbox_status="not_provided",
        filesystem_read_sandbox=False,
        network_sandbox=False,
        os_sandbox_claim=False,
    )


def run_action_v5(
    root: Path, action_id: str, *, apply: bool, risk_acknowledgement: str | None
) -> JsonObject:
    if not apply:
        return response("failed", "apply_required", effect_class="local_write")
    if risk_acknowledgement != RISK_ACKNOWLEDGEMENT:
        return response(
            "failed",
            "unsandboxed_execution_risk_acknowledgement_required",
            authority_required=[RISK_ACKNOWLEDGEMENT],
            unknowns=["filesystem_read_containment", "network_containment"],
            next_commands=[
                ["cpcf", "execution", "inspect-risk", "--workspace", str(root), "--json"]
            ],
        )
    plan = plan_v5(root)
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
        manifest, _, statements, _ = active_attestations_v5(root)
        action = _evidence(statements, action_id, "action")
        if action is None:
            raise ValueError("action attestation missing")
        action_attributes = _attributes(action)
        capability_id = str(action_attributes["capability_ref"])
        capability = _evidence(statements, capability_id, "adapter_capability")
        if capability is None:
            raise ValueError("independently signed adapter capability missing")
        capability_attributes = _attributes(capability)
        if action.get("protected", {}).get("principal_id") == capability.get("protected", {}).get(
            "principal_id"
        ):
            raise ValueError("action and capability principals must be distinct")
        store = GenerationStoreV5(root)
        current = str(manifest["generation_id"])
        ledger = {
            str(item.get("digest")): item
            for item in manifest.get("objects", [])
            if isinstance(item, dict)
        }
        executable_digest = str(capability_attributes["executable_digest"])
        material_digests = [str(item) for item in capability_attributes.get("material_digests", [])]
        if executable_digest not in ledger or any(item not in ledger for item in material_digests):
            raise ValueError("capability executable or material is not pinned in the generation")
        execution_policy = capability_attributes.get("execution_policy")
        if not isinstance(execution_policy, dict) or validation_errors(
            "execution-policy", execution_policy, "0.5.0"
        ):
            raise ValueError("signed execution policy invalid")
        argv_template = capability_attributes.get("argv_prefix")
        arguments = action_attributes.get("arguments", [])
        if (
            not isinstance(argv_template, list)
            or not argv_template
            or argv_template[0] != "{executable}"
            or not isinstance(arguments, list)
        ):
            raise ValueError("capability argv template invalid")
        timeout = min(HARD_PROCESS_SECONDS, int(execution_policy["timeout_seconds"]))
        stdin_limit = min(HARD_CAPTURE_BYTES, int(execution_policy["stdin_bytes"]))
        stdout_limit = min(HARD_CAPTURE_BYTES, int(execution_policy["stdout_bytes"]))
        stderr_limit = min(HARD_CAPTURE_BYTES, int(execution_policy["stderr_bytes"]))
        permitted_environment = frozenset(
            str(item) for item in execution_policy["permitted_environment_keys"]
        )
        if not permitted_environment <= ENV_ALLOWLIST:
            raise ValueError("execution policy requests non-minimal environment key")
        capability_digest = digest_v3_json(capability)
        capability_entry = ledger.get(capability_digest)
        if (
            not isinstance(capability_entry, dict)
            or capability_entry.get("kind") != "principal-attestation"
        ):
            raise ValueError("capability attestation is not in the live ledger")
    except (KeyError, OSError, TypeError, ValueError) as error:
        return response("failed", "action_binding_invalid", detail=str(error))
    invocation = {
        "schema_version": "0.5.0",
        "action_id": action_id,
        "action_statement_digest": digest_v3_json(action),
        "capability_statement_digest": capability_digest,
        "generation_before": current,
        "arguments": arguments,
        "execution_policy": execution_policy,
        "material_digests": material_digests,
    }
    invocation_digest = digest_v3_json(cast(JsonValue, invocation))
    before = _inventory(root)
    with tempfile.TemporaryDirectory(prefix="cpcf-v0.5-") as temporary:
        invocation_root = Path(temporary)
        executable_name = "adapter.exe" if os.name == "nt" else "adapter"
        executable = invocation_root / executable_name
        executable.write_bytes(store.cas.get(executable_digest))
        if os.name != "nt":
            executable.chmod(0o700)
        materials: list[Path] = []
        for index, digest in enumerate(material_digests):
            material = invocation_root / f"material-{index:03d}"
            material.write_bytes(store.cas.get(digest))
            materials.append(material)
        argv: list[str] = []
        for value in cast(list[str], argv_template):
            if value == "{executable}":
                argv.append(str(executable))
            elif value.startswith("{material:") and value.endswith("}"):
                index = int(value[10:-1])
                argv.append(str(materials[index]))
            else:
                argv.append(value)
        argv.extend(cast(list[str], arguments))
        if any(str(root.absolute()).casefold() in item.casefold() for item in argv):
            return response("failed", "workspace_path_embedded_in_adapter_argv")
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
    output_schema_ref = str(capability_attributes.get("output_schema_ref"))
    output_schema_digest = str(capability_attributes.get("output_schema_digest"))
    output_valid = False
    if (
        process.get("exit_code") == 0
        and process.get("timed_out") is False
        and process.get("stdout_truncated") is False
        and process.get("drain_status") == "complete"
        and process.get("stdout_utf8_valid") is True
    ):
        try:
            parsed = loads_json_bounded(raw, maximum_bytes=stdout_limit)
            schema_name, version = output_schema_ref.rsplit("@", 1)
            output_valid = (
                version == "0.5.0"
                and digest_v3_json(cast(JsonValue, load_schema(schema_name, version)))
                == output_schema_digest
                and not validation_errors(schema_name, parsed, version)
            )
        except (KeyError, ValueError, json.JSONDecodeError):
            output_valid = False
    exit_mapping = capability_attributes.get("exit_code_mapping")
    mapped_exit = (
        exit_mapping.get(str(process.get("exit_code"))) if isinstance(exit_mapping, dict) else None
    )
    if process.get("timed_out") is True:
        outcome = "timeout"
    elif not output_valid or mapped_exit not in BRANCHES:
        outcome = "failure"
    else:
        selector = capability_attributes.get("outcome_selector")
        try:
            if not isinstance(selector, dict):
                raise ValueError("selector missing")
            selected = _pointer(parsed, str(selector["source_pointer"]))
            mapping = selector.get("mapping")
            selected_outcome = mapping.get(str(selected)) if isinstance(mapping, dict) else None
            outcome = (
                str(selected_outcome)
                if selected_outcome == mapped_exit and selected_outcome in BRANCHES
                else "failure"
            )
        except (KeyError, TypeError, ValueError, IndexError):
            outcome = "failure"
    raw_digest = store.put_bytes(raw)
    receipt: JsonObject = {
        "schema_version": "0.5.0",
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
        "process_group_cleanup": process["process_group_cleanup"],
        "drain_status": process["drain_status"],
        "timeout_seconds": str(timeout),
        "stdin_limit": stdin_limit,
        "stdout_limit": stdout_limit,
        "stderr_limit": stderr_limit,
        "material_digests": material_digests,
    }
    receipt_errors = validation_errors("process-receipt", receipt, "0.5.0")
    if receipt_errors:
        return response("failed", "process_receipt_invalid", schema_errors=receipt_errors)
    process_receipt_digest = store.put_json(receipt)
    audit = science_audit_v5(root)
    snapshot = str(audit.get("analysis_snapshot_digest", digest_v3_json({})))
    pending_objects: list[tuple[str, JsonObject]] = []
    if output_valid and parsed is not None and outcome in {"success", "partial"}:
        for index, route in enumerate(capability_attributes.get("projection_routes", [])):
            if not isinstance(route, dict):
                continue
            try:
                projected = _pointer(parsed, str(route["source_pointer"]))
                target_ref = str(route["target_schema_ref"])
                target_name, target_version = target_ref.rsplit("@", 1)
                if validation_errors(target_name, projected, target_version):
                    continue
            except (KeyError, ValueError):
                continue
            pending: JsonObject = {
                "schema_version": "0.5.0",
                "projection_id": f"projection:{invocation_digest[7:]}:{index}",
                "invocation_digest": invocation_digest,
                "capability_statement_digest": capability_digest,
                "raw_output_digest": raw_digest,
                "source_pointer": route["source_pointer"],
                "target_schema_ref": target_ref,
                "projected_digest": digest_v3_json(projected),
                "analysis_snapshot_digest": snapshot,
            }
            pending_objects.append((store.put_json(pending), pending))
    action_receipt: JsonObject = {
        "schema_version": "0.5.0",
        "receipt_id": f"action-receipt:{invocation_digest[7:]}",
        "action_id": action_id,
        "generation_before": current,
        "analysis_snapshot_digest": snapshot,
        "capability_statement_digest": capability_digest,
        "process_receipt_digest": process_receipt_digest,
        "raw_output_digest": raw_digest,
        "outcome": outcome,
        "pending_projection_digests": [item[0] for item in pending_objects],
        "state_promoted": False,
    }
    action_receipt_digest = store.put_json(action_receipt)
    payload = deepcopy(manifest)
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(
            raw_digest, kind="raw-artifact", schema_ref=output_schema_ref, lifecycle="quarantined"
        ),
        ledger_entry(
            process_receipt_digest,
            kind="process-receipt",
            schema_ref="process-receipt@0.5.0",
            source_chain=[raw_digest, executable_digest, *material_digests],
        ),
        *(
            ledger_entry(
                digest,
                kind="pending-projection",
                schema_ref="pending-projection@0.5.0",
                source_chain=[raw_digest, capability_digest],
            )
            for digest, _ in pending_objects
        ),
        ledger_entry(
            action_receipt_digest,
            kind="action-receipt",
            schema_ref="action-receipt@0.5.0",
            source_chain=[
                process_receipt_digest,
                raw_digest,
                *(item[0] for item in pending_objects),
            ],
            authority_key_id=str(action["protected"]["key_id"]),
        ),
    ]
    payload["quarantine"] = sorted(set([*payload.get("quarantine", []), raw_digest]))
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:action:{invocation_digest[7:]}",
            event_type="action_executed",
            subject_digests=[
                action_receipt_digest,
                process_receipt_digest,
                raw_digest,
                *(item[0] for item in pending_objects),
            ],
        ),
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
        unknowns=["projection_promotion"] if pending_objects else [],
        quarantined=[raw_digest],
        action_id=action_id,
        outcome=outcome,
        process_receipt_digest=process_receipt_digest,
        action_receipt_digest=action_receipt_digest,
        pending_projections=[item[1] for item in pending_objects],
        source_backed_post_state="unknown",
        sandbox_status="not_provided",
        one_step_execution_limit=1,
    )


def pending_projections_v5(root: Path) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        manifest = store.load_manifest()
        pending = [
            store.get_json(str(item["digest"]))
            for item in manifest.get("objects", [])
            if isinstance(item, dict)
            and item.get("kind") == "pending-projection"
            and item.get("lifecycle") == "active"
        ]
    except (OSError, ValueError) as error:
        return response("failed", "pending_projection_inspection_failed", detail=str(error))
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        unknowns=["projection_promotion"] if pending else [],
        pending_projections=pending,
    )


def approve_projection_v5(
    root: Path, projection_id: str, approval_path: Path, *, apply: bool
) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        manifest = store.load_manifest()
        policy = store.get_json(str(manifest["trust_policy_digest"]))
        approval = loads_json_bounded(approval_path.read_bytes())
        if (
            not isinstance(policy, dict)
            or not isinstance(approval, dict)
            or not isinstance(manifest.get("analysis_epoch"), str)
        ):
            raise ValueError("approval trust or time unavailable")
        matches = [
            (entry, store.get_json(str(entry["digest"])))
            for entry in manifest.get("objects", [])
            if isinstance(entry, dict)
            and entry.get("kind") == "pending-projection"
            and entry.get("lifecycle") == "active"
        ]
        selected = [
            (entry, value)
            for entry, value in matches
            if isinstance(value, dict) and value.get("projection_id") == projection_id
        ]
        if len(selected) != 1:
            raise ValueError("pending projection not found or duplicated")
        pending_entry, pending = selected[0]
    except (OSError, ValueError) as error:
        return response("failed", "projection_approval_input_invalid", detail=str(error))
    checked = verify_statement(
        approval,
        policy,
        authoritative_time=str(manifest["analysis_epoch"]),
        expected_schema_ref="projection-approval@0.5.0",
        expected_role="projection_verifier",
    )
    reasons = list(checked.get("reasons", []))
    if approval.get("payload", {}).get("projection_digest") != pending_entry.get("digest"):
        reasons.append("approval_projection_digest_mismatch")
    if approval.get("payload", {}).get("trusted_time_receipt_digest") != manifest.get(
        "trusted_time_receipt_digest"
    ):
        reasons.append("approval_trusted_time_mismatch")
    capability = store.get_json(str(pending["capability_statement_digest"]))
    if not isinstance(capability, dict):
        reasons.append("projection_capability_missing")
    else:
        capability_checked = verify_statement(
            capability,
            policy,
            authoritative_time=str(manifest["analysis_epoch"]),
            expected_schema_ref="principal-attestation@0.5.0",
            expected_role="projection_authority",
        )
        reasons.extend(str(item) for item in capability_checked.get("reasons", []))
        if capability.get("protected", {}).get("principal_id") == approval.get("protected", {}).get(
            "principal_id"
        ):
            reasons.append("projection_quorum_identity_not_disjoint")
    try:
        raw = loads_json_bounded(store.cas.get(str(pending["raw_output_digest"])))
        projected = _pointer(raw, str(pending["source_pointer"]))
        if digest_v3_json(projected) != pending.get("projected_digest"):
            reasons.append("pending_projection_reconstruction_mismatch")
        target_name, target_version = str(pending["target_schema_ref"]).rsplit("@", 1)
        reasons.extend(
            f"projected_schema:{item['json_pointer']}:{item['message']}"
            for item in validation_errors(target_name, projected, target_version)
        )
    except (OSError, ValueError):
        projected = None
        reasons.append("pending_projection_not_reproducible")
    if reasons:
        return response("failed", "projection_approval_invalid", reasons=sorted(set(reasons)))
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    approval_digest = store.put_json(approval)
    projected_digest = store.put_json(projected)
    promoted_kind = "promoted-projection"
    promoted_schema = str(pending["target_schema_ref"])
    authority_key: str | None = None
    if promoted_schema == "signed-statement@0.5.0" and isinstance(projected, dict):
        source_checked = verify_statement(
            projected, policy, authoritative_time=str(manifest["analysis_epoch"])
        )
        if source_checked.get("status") != "true":
            return response(
                "failed",
                "projected_signed_statement_invalid",
                reasons=source_checked.get("reasons", []),
            )
        if projected.get("protected", {}).get("schema_ref") == "principal-attestation@0.5.0":
            promoted_kind = "principal-attestation"
            authority_key = str(projected["protected"]["key_id"])
    promoted_source_chain = [
        str(pending_entry["digest"]),
        approval_digest,
        str(pending["raw_output_digest"]),
        str(pending["capability_statement_digest"]),
    ]
    if promoted_kind == "principal-attestation" and isinstance(projected, dict):
        inner_payload = projected.get("payload")
        if isinstance(inner_payload, dict) and isinstance(
            inner_payload.get("source_artifact_digest"), str
        ):
            promoted_source_chain.append(str(inner_payload["source_artifact_digest"]))
    objects: list[JsonObject] = []
    for entry in manifest.get("objects", []):
        if isinstance(entry, dict) and entry.get("digest") == pending_entry.get("digest"):
            objects.append(cast(JsonObject, {**entry, "lifecycle": "withdrawn"}))
        elif isinstance(entry, dict):
            objects.append(entry)
    objects.extend(
        [
            ledger_entry(
                approval_digest,
                kind="projection-approval",
                schema_ref="signed-statement@0.5.0",
                source_chain=[str(pending_entry["digest"])],
                authority_key_id=str(approval["protected"]["key_id"]),
                authority_policy_digest=str(manifest["trust_policy_digest"]),
            ),
            ledger_entry(
                projected_digest,
                kind=promoted_kind,
                schema_ref=promoted_schema,
                source_chain=sorted(set(promoted_source_chain)),
                authority_key_id=authority_key,
                authority_policy_digest=(
                    str(manifest["trust_policy_digest"])
                    if promoted_kind == "principal-attestation"
                    else None
                ),
            ),
        ]
    )
    payload = deepcopy(manifest)
    payload["objects"] = objects
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:projection:{projected_digest[7:]}",
            event_type="projection_approved",
            subject_digests=[str(pending_entry["digest"]), approval_digest, projected_digest],
        ),
    ]
    committed = store.commit(payload, expected_current=str(manifest["generation_id"]))
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        claims=["projection_reconstructed_and_role_quorum_approved"],
        projection_id=projection_id,
        promoted_digest=projected_digest,
        promoted_kind=promoted_kind,
        source_backed_post_state="true",
    )
