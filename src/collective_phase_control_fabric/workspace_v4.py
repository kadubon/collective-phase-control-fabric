# SPDX-License-Identifier: Apache-2.0
"""Native v0.4 workspace, provenance, migration, doctor, and onboarding workflows."""

from __future__ import annotations

import shutil
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import (
    digest_bytes,
    digest_v3_json,
    write_canonical,
)
from collective_phase_control_fabric.generation import GenerationStore
from collective_phase_control_fabric.generation_v4 import (
    V4,
    GenerationStoreV4,
    empty_generation_v4,
    ledger_entry,
)
from collective_phase_control_fabric.limits import MAX_RAW_BYTES, LimitExceeded, load_json_bounded
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.trust_v4 import (
    validate_policy,
    verify_statement,
    verify_time_receipt,
)
from collective_phase_control_fabric.types import JsonObject, JsonValue


def response(
    status: str,
    code: str | None,
    *,
    effect_class: str = "inspect",
    generation: str | None = None,
    files_written: list[str] | None = None,
    authority_required: list[str] | None = None,
    claims: list[str] | None = None,
    unknowns: list[str] | None = None,
    quarantined: list[str] | None = None,
    next_commands: list[list[str]] | None = None,
    **extra: object,
) -> JsonObject:
    """Return the uniform native v0.4 command envelope."""

    return {
        "command_status": status,
        "failure_code": code,
        "status": status,
        "code": code,
        "effect_class": effect_class,
        "workspace_generation": generation,
        "files_written": files_written or [],
        "authority_required": authority_required or [],
        "claims": claims or [],
        "unknowns": unknowns or [],
        "quarantined_objects": quarantined or [],
        "next_safe_commands": next_commands or [],
        "network_accessed": False,
        "external_effect": False,
        **extra,
    }


def workspace_version(root: Path) -> str | None:
    """Read a generation version without assuming that every CURRENT workspace is v0.3."""

    current = root / ".cpcf" / "CURRENT"
    if current.is_file():
        try:
            identifier = current.read_text(encoding="ascii").strip()
            manifest = root / ".cpcf" / "generations" / identifier[7:] / "manifest.json"
            value = load_json_bounded(manifest)
            if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
                return str(value["schema_version"])
        except (OSError, ValueError):
            return None
    for candidate in (root / ".cpcf" / "workspace.json", root / "contract.json"):
        if candidate.is_file():
            try:
                value = load_json_bounded(candidate)
            except (OSError, ValueError):
                continue
            if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
                return str(value["schema_version"])
    return None


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
            raise ValueError(f"JSON pointer does not resolve: {pointer}")
    return current


def _read_raw_bounded(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_RAW_BYTES + 1)
    if len(data) > MAX_RAW_BYTES:
        raise LimitExceeded("maximum_raw_bytes_exceeded", observed=len(data), maximum=MAX_RAW_BYTES)
    return data


def validate_trust_policy_v4(path: Path, root_fingerprint: str | None = None) -> JsonObject:
    try:
        value = load_json_bounded(path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trust_policy_parse_failed", detail=str(error))
    if not isinstance(value, dict):
        return response("failed", "trust_policy_not_object")
    errors = validate_policy(value, root_fingerprint)
    return response(
        "ok" if not errors else "failed",
        None if not errors else "trust_policy_invalid",
        effect_class="validate",
        authority_required=[str(value.get("root_key_id"))],
        schema_errors=errors,
        principal_count=len(value.get("principals", [])),
        single_key_compromise_resilient=False,
        threshold_trust=False,
    )


def inspect_time_receipt_v4(receipt_path: Path, trust_path: Path) -> JsonObject:
    try:
        receipt = load_json_bounded(receipt_path)
        trust = load_json_bounded(trust_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trusted_time_input_invalid", detail=str(error))
    if not isinstance(receipt, dict) or not isinstance(trust, dict):
        return response("failed", "trusted_time_input_not_object")
    verified = verify_time_receipt(receipt, trust)
    return response(
        "ok" if verified["status"] == "true" else "failed",
        None if verified["status"] == "true" else "trusted_time_receipt_invalid",
        effect_class="validate",
        claims=["trusted_time_receipt_valid"] if verified["status"] == "true" else [],
        unknowns=[] if verified["status"] == "true" else ["authoritative_time"],
        verification=verified,
    )


def initialize_workspace_v4(
    contract_path: Path,
    trust_path: Path,
    output: Path,
    root_fingerprint: str,
    time_receipt_path: Path | None = None,
) -> JsonObject:
    """Create a native v0.4 generation with explicit out-of-band root bootstrap."""

    if output.exists():
        return response("failed", "output_already_exists")
    try:
        contract = load_json_bounded(contract_path)
        trust = load_json_bounded(trust_path)
        time_receipt = load_json_bounded(time_receipt_path) if time_receipt_path else None
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "workspace_input_invalid", detail=str(error))
    if not isinstance(contract, dict) or not isinstance(trust, dict):
        return response("failed", "workspace_input_not_object")
    contract_errors = validation_errors("phase-contract", contract, V4)
    trust_errors = validate_policy(trust, root_fingerprint)
    contract_digest = digest_v3_json(contract)
    verified_time: JsonObject | None = None
    if time_receipt is not None:
        if not isinstance(time_receipt, dict):
            return response("failed", "trusted_time_receipt_not_object")
        verified_time = verify_time_receipt(
            time_receipt, trust, expected_subject_digest=contract_digest
        )
        if verified_time["status"] != "true":
            trust_errors.append(
                {"message": "trusted time receipt invalid", "reasons": verified_time["reasons"]}
            )
    if contract_errors or trust_errors:
        return response(
            "failed",
            "workspace_input_invalid",
            contract_schema_errors=contract_errors,
            trust_schema_errors=trust_errors,
        )
    output.mkdir(parents=True)
    store = GenerationStoreV4(output)
    contract_cas = store.put_json(contract)
    trust_cas = store.put_json(trust)
    objects = [
        ledger_entry(contract_cas, kind="contract", schema_ref="phase-contract@0.4.0"),
        ledger_entry(
            trust_cas,
            kind="trust-policy",
            schema_ref="trust-policy@0.4.0",
            authority_key_id=str(trust["root_key_id"]),
        ),
    ]
    time_cas: str | None = None
    epoch: str | None = None
    if isinstance(time_receipt, dict) and verified_time is not None:
        time_cas = store.put_json(time_receipt)
        epoch = str(verified_time["event_time"])
        objects.append(
            ledger_entry(
                time_cas,
                kind="trusted-time-receipt",
                schema_ref="signed-statement@0.4.0",
                source_chain=[contract_cas],
                authority_key_id=str(time_receipt["protected"]["key_id"]),
            )
        )
    payload = empty_generation_v4(
        contract_digest=contract_cas,
        trust_policy_digest=trust_cas,
        trusted_time_receipt_digest=time_cas,
        analysis_epoch=epoch,
        objects=objects,
    )
    committed = store.commit(payload, expected_current=None)
    if committed.get("command_status") != "ok":
        shutil.rmtree(output)
        return response("failed", str(committed.get("failure_code")), detail=committed)
    identifier = str(committed["generation_id"])
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=identifier,
        files_written=[str(store.current_path), str(store.manifest_path(identifier))],
        authority_required=[str(trust["root_key_id"])],
        claims=["immutable_generation_created"],
        unknowns=[] if epoch else ["authoritative_time", "state_promotion"],
        next_commands=[
            ["cpcf", "agent", "onboard", "--workspace", str(output), "--compact", "--json"]
        ],
        workspace=str(output.resolve()),
        schema_version=V4,
        execution_allowed=False,
    )


def _documents(store: GenerationStoreV4, manifest: JsonObject) -> tuple[JsonObject, JsonObject]:
    contract = store.get_json(str(manifest["contract_digest"]))
    trust = store.get_json(str(manifest["trust_policy_digest"]))
    if not isinstance(contract, dict) or not isinstance(trust, dict):
        raise ValueError("contract and trust policy must be objects")
    return contract, trust


def _current_time(
    store: GenerationStoreV4, manifest: JsonObject, trust: JsonObject
) -> tuple[str | None, JsonObject | None]:
    digest = manifest.get("trusted_time_receipt_digest")
    if not isinstance(digest, str):
        return None, None
    value = store.get_json(digest)
    if not isinstance(value, dict):
        return None, None
    verified = verify_time_receipt(value, trust)
    return (
        str(verified["event_time"]) if verified.get("status") == "true" else None,
        verified,
    )


def import_raw_v4(
    report: Path, root: Path, source_system: str, schema_ref: str, *, apply: bool
) -> JsonObject:
    """Copy bounded raw bytes into CAS without promoting them as evidence."""

    store = GenerationStoreV4(root)
    try:
        manifest = store.load_manifest()
        raw = _read_raw_bounded(report)
    except (OSError, LimitExceeded) as error:
        return response("failed", "source_read_failed", detail=str(error))
    # JSON sources are bounded and duplicate-key checked before import.
    try:
        load_json_bounded(report)
    except (ValueError, LimitExceeded) as error:
        return response("failed", "source_json_invalid", detail=str(error))
    if not apply:
        return response(
            "failed",
            "apply_required",
            generation=str(manifest["generation_id"]),
            next_commands=[
                [
                    "cpcf",
                    "source",
                    "import",
                    str(report),
                    "--workspace",
                    str(root),
                    "--source-system",
                    source_system,
                    "--schema-ref",
                    schema_ref,
                    "--apply",
                    "--json",
                ]
            ],
        )
    digest = store.cas.put(raw).digest
    payload = deepcopy(manifest)
    entry = ledger_entry(
        digest,
        kind="raw-artifact",
        schema_ref=schema_ref,
        lifecycle="quarantined",
    )
    if digest not in {
        item.get("digest") for item in payload.get("objects", []) if isinstance(item, dict)
    }:
        payload["objects"] = [*payload.get("objects", []), entry]
    payload["quarantine"] = sorted(set([*payload.get("quarantine", []), digest]))
    committed = store.commit(payload, expected_current=str(manifest["generation_id"]))
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        claims=["raw_artifact_content_addressed"],
        unknowns=["source_authority", "state_promotion"],
        quarantined=[digest],
        raw_digest=digest,
        source_system=source_system,
        schema_ref=schema_ref,
    )


def inspect_source_v4(
    report: Path, trust_path: Path, source_system: str, schema_ref: str
) -> JsonObject:
    """Bounded source inspection never promotes or writes the raw object."""

    try:
        value = load_json_bounded(report)
        trust = load_json_bounded(trust_path)
        raw = _read_raw_bounded(report)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "source_inspection_input_invalid", detail=str(error))
    if not isinstance(trust, dict):
        return response("failed", "trust_policy_not_object")
    reasons: list[str] = []
    signature_status = "not_applicable"
    if isinstance(value, dict) and value.get("schema_version") == V4 and "protected" in value:
        protected = value.get("protected")
        signed_at = protected.get("signed_at") if isinstance(protected, dict) else None
        verified = verify_statement(
            value,
            trust,
            authoritative_time=str(signed_at),
            expected_schema_ref=schema_ref,
            expected_source_system=source_system,
        )
        signature_status = str(verified["status"])
        reasons.extend(str(item) for item in verified.get("reasons", []))
    return response(
        "ok" if not reasons else "failed",
        None if not reasons else "source_signature_invalid",
        effect_class="validate",
        claims=["bounded_raw_source_inspected"] if not reasons else [],
        unknowns=["state_promotion"],
        raw_digest=digest_bytes(raw),
        raw_size=len(raw),
        source_system=source_system,
        schema_ref=schema_ref,
        signature_status=signature_status,
        reasons=reasons,
    )


def inspect_attestation_v4(attestation_path: Path, trust_path: Path) -> JsonObject:
    try:
        statement = load_json_bounded(attestation_path)
        trust = load_json_bounded(trust_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "attestation_input_invalid", detail=str(error))
    if not isinstance(statement, dict) or not isinstance(trust, dict):
        return response("failed", "attestation_input_not_object")
    protected = statement.get("protected", {})
    signed_at = protected.get("signed_at") if isinstance(protected, dict) else None
    verified = verify_statement(
        statement,
        trust,
        authoritative_time=str(signed_at),
        expected_schema_ref="principal-attestation@0.4.0",
    )
    payload = statement.get("payload")
    payload_errors = (
        validation_errors("principal-attestation", payload, V4)
        if isinstance(payload, dict)
        else [{"message": "attestation payload must be an object"}]
    )
    valid = verified["status"] == "true" and not payload_errors
    return response(
        "ok" if valid else "failed",
        None if valid else "attestation_invalid",
        effect_class="validate",
        claims=["signature_and_payload_valid"] if valid else [],
        verification=verified,
        payload_schema_errors=payload_errors,
    )


def _validate_attestation_chain(
    store: GenerationStoreV4,
    statement: JsonObject,
    trust: JsonObject,
    epoch: str,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    checked = verify_statement(
        statement,
        trust,
        authoritative_time=epoch,
        expected_schema_ref="principal-attestation@0.4.0",
    )
    reasons.extend(str(item) for item in checked.get("reasons", []))
    payload = statement.get("payload")
    if not isinstance(payload, dict):
        return False, sorted(set([*reasons, "attestation_payload_missing"]))
    reasons.extend(
        f"payload_schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("principal-attestation", payload, V4)
    )
    try:
        valid_from = datetime.fromisoformat(str(payload["valid_from"]).replace("Z", "+00:00"))
        valid_until = datetime.fromisoformat(str(payload["valid_until"]).replace("Z", "+00:00"))
        evaluated = datetime.fromisoformat(epoch.replace("Z", "+00:00"))
        if not valid_from <= evaluated <= valid_until or payload.get("lifecycle") != "active":
            reasons.append("attestation_not_live")
    except (KeyError, ValueError):
        reasons.append("attestation_lifecycle_invalid")
    raw_digest = payload.get("source_artifact_digest")
    if not isinstance(raw_digest, str) or not store.cas.verify(raw_digest):
        reasons.append("source_artifact_missing_or_digest_invalid")
    else:
        try:
            raw = store.get_json(raw_digest)
            projected = _pointer(raw, str(payload.get("source_pointer", "")))
            if digest_v3_json(projected) != payload.get("subject_digest"):
                reasons.append("attested_subject_not_reproducible_from_source_pointer")
            expected_subject = {
                key: payload.get(key)
                for key in (
                    "record_type",
                    "subject_id",
                    "lifecycle",
                    "valid_from",
                    "valid_until",
                    "lineage_refs",
                    "correlation_domains",
                    "attributes",
                )
            }
            if projected != expected_subject:
                reasons.append("attestation_fields_not_equal_to_projected_source_object")
        except (OSError, ValueError):
            reasons.append("source_projection_reconstruction_failed")
    return not reasons, sorted(set(reasons))


def import_attestation_v4(attestation_path: Path, root: Path, *, apply: bool) -> JsonObject:
    store = GenerationStoreV4(root)
    try:
        manifest = store.load_manifest()
        _, trust = _documents(store, manifest)
        epoch, time_report = _current_time(store, manifest, trust)
        statement = load_json_bounded(attestation_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "attestation_import_input_invalid", detail=str(error))
    if epoch is None or time_report is None:
        return response(
            "failed",
            "authoritative_time_receipt_required",
            generation=str(manifest["generation_id"]),
            unknowns=["authoritative_time", "state_promotion"],
        )
    if not isinstance(statement, dict):
        return response("failed", "attestation_not_object")
    valid, reasons = _validate_attestation_chain(store, statement, trust, epoch)
    if not valid:
        return response(
            "failed",
            "attestation_source_chain_invalid",
            generation=str(manifest["generation_id"]),
            reasons=reasons,
        )
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    digest = store.put_json(statement)
    payload = deepcopy(manifest)
    attested = cast(JsonObject, statement["payload"])
    raw_digest = str(attested["source_artifact_digest"])
    entry = ledger_entry(
        digest,
        kind="principal-attestation",
        schema_ref="signed-statement@0.4.0",
        source_chain=[raw_digest, str(manifest["trusted_time_receipt_digest"])],
        authority_key_id=str(statement["protected"]["key_id"]),
    )
    payload["objects"] = [*payload.get("objects", []), entry]
    payload["quarantine"] = [item for item in payload.get("quarantine", []) if item != raw_digest]
    for item in payload["objects"]:
        if isinstance(item, dict) and item.get("digest") == raw_digest:
            item["lifecycle"] = "active"
    committed = store.commit(payload, expected_current=str(manifest["generation_id"]))
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        claims=["typed_source_attestation_promoted"],
        attestation_digest=digest,
        attestation_id=attested.get("attestation_id"),
    )


def active_attestations_v4(
    root: Path,
) -> tuple[JsonObject, JsonObject, list[JsonObject], list[JsonObject]]:
    """Return freshly verified active attestations and rejection diagnostics."""

    store = GenerationStoreV4(root)
    manifest = store.load_manifest()
    contract, trust = _documents(store, manifest)
    epoch, _ = _current_time(store, manifest, trust)
    valid: list[JsonObject] = []
    rejected: list[JsonObject] = []
    if epoch is None:
        return manifest, contract, valid, [{"code": "authoritative_time_receipt_required"}]
    for entry in manifest.get("objects", []):
        if not isinstance(entry, dict) or entry.get("kind") != "principal-attestation":
            continue
        digest = str(entry.get("digest"))
        try:
            value = store.get_json(digest)
        except (OSError, ValueError) as error:
            rejected.append({"digest": digest, "reasons": [str(error)]})
            continue
        if not isinstance(value, dict):
            rejected.append({"digest": digest, "reasons": ["statement_not_object"]})
            continue
        accepted, reasons = _validate_attestation_chain(store, value, trust, epoch)
        if accepted:
            valid.append(value)
        else:
            rejected.append({"digest": digest, "reasons": reasons})
    return manifest, contract, valid, rejected


def doctor_v4(root: Path, *, quick: bool = False) -> JsonObject:
    store = GenerationStoreV4(root)
    errors = store.verify_chain()
    try:
        manifest = store.load_manifest()
        contract, trust = _documents(store, manifest)
    except (OSError, ValueError) as error:
        return response("failed", "workspace_generation_invalid", detail=str(error))
    errors.extend(
        {"code": "contract_schema_invalid", **item}
        for item in validation_errors("phase-contract", contract, V4)
    )
    errors.extend({"code": "trust_policy_invalid", **item} for item in validate_policy(trust))
    entries = [item for item in manifest.get("objects", []) if isinstance(item, dict)]
    digests = {str(item.get("digest")) for item in entries}
    ancestor_generations: set[str] = set()
    selected_generation: str | None = str(manifest["generation_id"])
    while selected_generation is not None and selected_generation not in ancestor_generations:
        ancestor_generations.add(selected_generation)
        selected_manifest = store.load_manifest(selected_generation)
        previous = selected_manifest.get("previous_generation")
        selected_generation = previous if isinstance(previous, str) else None
    identifiers: list[str] = []
    for entry in entries:
        entry_errors = validation_errors("object-ledger-entry", entry, V4)
        errors.extend({"code": "ledger_entry_invalid", **item} for item in entry_errors)
        digest = str(entry.get("digest"))
        if not store.cas.verify(digest):
            errors.append({"code": "cas_digest_invalid", "digest": digest})
        for source in entry.get("source_chain", []):
            generation_reference = source in {
                manifest.get("generation_id"),
                manifest.get("previous_generation"),
            }
            if source not in digests and not generation_reference:
                errors.append(
                    {"code": "ledger_source_reference_missing", "digest": digest, "source": source}
                )
        if not quick and store.cas.verify(digest):
            try:
                value = store.get_json(digest)
            except (OSError, ValueError):
                value = None
            if isinstance(value, dict):
                for key in (
                    "attestation_id",
                    "record_id",
                    "receipt_id",
                    "object_id",
                    "protocol_id",
                    "result_id",
                    "action_id",
                    "capability_id",
                    "event_id",
                ):
                    if isinstance(value.get(key), str):
                        identifiers.append(str(value[key]))
                inner = value.get("payload")
                if isinstance(inner, dict):
                    for key in ("attestation_id", "protocol_id", "result_id", "event_id"):
                        if isinstance(inner.get(key), str):
                            identifiers.append(str(inner[key]))
                    attributes = inner.get("attributes")
                    if (
                        isinstance(attributes, dict)
                        and isinstance(attributes.get("analysis_base_generation_id"), str)
                        and attributes["analysis_base_generation_id"] not in ancestor_generations
                    ):
                        errors.append(
                            {
                                "code": "analysis_base_generation_not_in_history",
                                "digest": digest,
                            }
                        )
    duplicates = sorted({item for item in identifiers if identifiers.count(item) > 1})
    errors.extend(
        {"code": "duplicate_semantic_identifier", "identifier": item} for item in duplicates
    )
    if manifest.get("history_root") != digest_v3_json(cast(JsonValue, manifest.get("history", []))):
        errors.append({"code": "history_hash_chain_invalid"})
    history = manifest.get("history", [])
    if isinstance(history, list):
        for index, event in enumerate(history):
            if not isinstance(event, dict) or event.get("previous_event_digest") != digest_v3_json(
                cast(JsonValue, history[:index])
            ):
                errors.append({"code": "history_event_chain_invalid", "event_index": index})
    epoch, time_report = _current_time(store, manifest, trust)
    if time_report is None or time_report.get("status") != "true":
        errors.append({"code": "authoritative_time_receipt_missing_or_invalid"})
    rejected: list[JsonObject] = []
    if not quick:
        try:
            _, _, _, rejected = active_attestations_v4(root)
        except (OSError, ValueError) as error:
            errors.append({"code": "attestation_recomputation_failed", "detail": str(error)})
        errors.extend({"code": "attestation_not_source_backed", **item} for item in rejected)
    cas_root = store.control / "cas" / "sha256"
    orphaned: list[str] = []
    if cas_root.is_dir():
        for path in cas_root.rglob("*"):
            if path.is_file():
                relative = "".join(path.relative_to(cas_root).parts)
                digest = f"sha256:{relative}"
                if digest not in digests:
                    orphaned.append(digest)
    execution_allowed = not errors and not quick and epoch is not None
    return response(
        "ok" if not errors else "failed",
        None if not errors else "workspace_audit_failed",
        effect_class="validate",
        generation=str(manifest["generation_id"]),
        claims=["complete_ledger_reference_closure"] if not errors else [],
        unknowns=[] if execution_allowed else ["execution_eligibility"],
        quarantined=list(cast(list[str], manifest.get("quarantine", []))),
        errors=errors,
        orphaned_cas_objects=sorted(orphaned),
        strict=not quick,
        execution_allowed=execution_allowed,
        analysis_epoch=epoch,
    )


def status_v4(root: Path) -> JsonObject:
    if workspace_version(root) != V4:
        return response(
            "ok",
            "legacy_workspace_inspect_only",
            unknowns=["execution_eligibility"],
            next_commands=[
                [
                    "cpcf",
                    "workspace",
                    "migrate",
                    "--workspace",
                    str(root),
                    "--trust-policy",
                    "TRUST_POLICY.json",
                    "--time-receipt",
                    "TIME.json",
                    "--root-key-fingerprint",
                    "sha256:ROOT",
                    "--out",
                    f"{root}-v0.4",
                    "--to",
                    V4,
                    "--json",
                ]
            ],
            schema_version=workspace_version(root),
            execution_allowed=False,
        )
    store = GenerationStoreV4(root)
    manifest = store.load_manifest()
    audit = doctor_v4(root)
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        claims=list(audit.get("claims", [])),
        unknowns=list(audit.get("unknowns", [])),
        quarantined=list(cast(list[str], manifest.get("quarantine", []))),
        schema_version=V4,
        previous_generation=manifest.get("previous_generation"),
        analysis_epoch=manifest.get("analysis_epoch"),
        object_count=len(manifest.get("objects", [])),
        execution_allowed=audit.get("execution_allowed") is True,
        doctor_status=audit.get("command_status"),
    )


def advance_time_v4(root: Path, receipt_path: Path, *, apply: bool) -> JsonObject:
    store = GenerationStoreV4(root)
    try:
        manifest = store.load_manifest()
        _, trust = _documents(store, manifest)
        receipt = load_json_bounded(receipt_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trusted_time_input_invalid", detail=str(error))
    if not isinstance(receipt, dict):
        return response("failed", "trusted_time_receipt_not_object")
    verified = verify_time_receipt(
        receipt, trust, expected_subject_digest=str(manifest["generation_id"])
    )
    if verified["status"] != "true":
        return response("failed", "trusted_time_receipt_invalid", verification=verified)
    old_epoch = manifest.get("analysis_epoch")
    if isinstance(old_epoch, str):
        old = datetime.fromisoformat(old_epoch.replace("Z", "+00:00"))
        new = datetime.fromisoformat(str(verified["event_time"]).replace("Z", "+00:00"))
        if new < old:
            return response("failed", "analysis_epoch_rollback_rejected")
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    digest = store.put_json(receipt)
    payload = deepcopy(manifest)
    payload["trusted_time_receipt_digest"] = digest
    payload["analysis_epoch"] = verified["event_time"]
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(
            digest,
            kind="trusted-time-receipt",
            schema_ref="signed-statement@0.4.0",
            source_chain=[str(manifest["generation_id"])],
            authority_key_id=str(receipt["protected"]["key_id"]),
        ),
    ]
    payload["history"] = [
        *payload.get("history", []),
        {
            "event_type": "authoritative_time_advanced",
            "time_receipt_digest": digest,
            "from": old_epoch,
            "to": verified["event_time"],
            "previous_event_digest": digest_v3_json(cast(JsonValue, manifest.get("history", []))),
        },
    ]
    committed = store.commit(payload, expected_current=str(manifest["generation_id"]))
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        claims=["authoritative_time_advanced"],
        analysis_epoch=verified["event_time"],
    )


def update_trust_policy_v4(
    root: Path, policy_statement_path: Path, time_receipt_path: Path, *, apply: bool
) -> JsonObject:
    """Rotate a policy only through the prior root and a subject-bound time receipt."""

    store = GenerationStoreV4(root)
    try:
        manifest = store.load_manifest()
        _, old_policy = _documents(store, manifest)
        statement = load_json_bounded(policy_statement_path)
        receipt = load_json_bounded(time_receipt_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trust_policy_update_input_invalid", detail=str(error))
    if not isinstance(statement, dict) or not isinstance(statement.get("payload"), dict):
        return response("failed", "signed_trust_policy_required")
    if not isinstance(receipt, dict):
        return response("failed", "trusted_time_receipt_not_object")
    new_policy = cast(JsonObject, statement["payload"])
    new_digest = digest_v3_json(new_policy)
    time_check = verify_time_receipt(receipt, old_policy, expected_subject_digest=new_digest)
    reasons = list(time_check.get("reasons", []))
    if time_check.get("status") == "true":
        statement_check = verify_statement(
            statement,
            old_policy,
            authoritative_time=str(time_check["event_time"]),
            expected_schema_ref="trust-policy@0.4.0",
            expected_role="workspace_root",
        )
        reasons.extend(str(item) for item in statement_check.get("reasons", []))
    reasons.extend(str(item.get("message")) for item in validate_policy(new_policy))
    if new_policy.get("previous_policy_digest") != manifest.get("trust_policy_digest"):
        reasons.append("previous_policy_digest_mismatch")
    if new_policy.get("policy_sequence") != int(old_policy.get("policy_sequence", -1)) + 1:
        reasons.append("policy_sequence_not_monotonic")
    if reasons:
        return response("failed", "trust_policy_update_invalid", reasons=sorted(set(reasons)))
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    statement_digest = store.put_json(statement)
    policy_digest = store.put_json(new_policy)
    receipt_digest = store.put_json(receipt)
    payload = deepcopy(manifest)
    payload["trust_policy_digest"] = policy_digest
    payload["trusted_time_receipt_digest"] = receipt_digest
    payload["analysis_epoch"] = time_check["event_time"]
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(
            statement_digest,
            kind="trust-policy-update-statement",
            schema_ref="signed-statement@0.4.0",
            source_chain=[str(manifest["trust_policy_digest"])],
            authority_key_id=str(statement["protected"]["key_id"]),
        ),
        ledger_entry(
            policy_digest,
            kind="trust-policy",
            schema_ref="trust-policy@0.4.0",
            source_chain=[statement_digest, str(manifest["trust_policy_digest"])],
            authority_key_id=str(new_policy["root_key_id"]),
        ),
        ledger_entry(
            receipt_digest,
            kind="trusted-time-receipt",
            schema_ref="signed-statement@0.4.0",
            source_chain=[policy_digest],
            authority_key_id=str(receipt["protected"]["key_id"]),
        ),
    ]
    payload["history"] = [
        *payload.get("history", []),
        {
            "event_type": "trust_policy_updated",
            "from": manifest["trust_policy_digest"],
            "to": policy_digest,
            "policy_sequence": new_policy["policy_sequence"],
            "previous_event_digest": digest_v3_json(cast(JsonValue, manifest.get("history", []))),
        },
    ]
    committed = store.commit(payload, expected_current=str(manifest["generation_id"]))
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        authority_required=[str(old_policy["root_key_id"])],
        claims=["trust_policy_monotonic_update_committed"],
        policy_digest=policy_digest,
        policy_sequence=new_policy["policy_sequence"],
    )


def explain_missing_contract_v4(path: Path) -> JsonObject:
    try:
        value = load_json_bounded(path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "contract_parse_failed", detail=str(error))
    if not isinstance(value, dict):
        return response("failed", "contract_not_object")
    if value.get("draft_executable") is False and isinstance(value.get("missing_decisions"), list):
        return response(
            "failed",
            "contract_decisions_missing",
            effect_class="validate",
            missing_decisions=sorted(str(item) for item in value["missing_decisions"]),
            contract_executable=False,
        )
    errors = validation_errors("phase-contract", value, V4)
    missing = sorted(
        {
            str(error["message"]).split("'")[1]
            for error in errors
            if "is a required property" in str(error.get("message"))
        }
    )
    return response(
        "ok" if not errors else "failed",
        None if not errors else "contract_decisions_missing",
        effect_class="validate",
        schema_errors=errors,
        missing_decisions=missing,
        contract_executable=not errors,
    )


def scaffold_contract_v4(output: Path, profile: str) -> JsonObject:
    """Create an explicitly non-executable draft without inventing user decisions."""

    if output.exists():
        return response("failed", "output_already_exists")
    missing = [
        "contract.scope",
        "contract.target_states",
        "contract.initial_available_states",
        "contract.protected_floors",
        "contract.resource_envelope",
        "contract.required_dimensions",
        "contract.perturbation_suite_refs",
        "trust_policy.principals",
        "trust_policy.root_key_id",
        "external_time_principal",
        "independence_domains",
    ]
    if profile == "measured":
        missing.extend(
            [
                "measurement_protocol.eligibility",
                "measurement_protocol.strategies",
                "measurement_protocol.assignment",
                "measurement_protocol.estimand",
                "measurement_protocol.primary_outcomes",
                "measurement_protocol.dataset_commitment",
                "measurement_protocol.analysis_executable",
                "external_registration_principal",
                "external_evaluator_principal",
            ]
        )
    draft: JsonObject = {
        "schema_version": V4,
        "draft_id": f"contract-draft:{profile}",
        "profile": profile,
        "proposed_contract": {
            "schema_version": V4,
            "control_policy": {
                "planning_horizon": 1,
                "beam_width": 32,
                "candidate_cap": 64,
                "retry_limit": 0,
            },
            "analysis_limits": {
                "maximum_raw_bytes": 67_108_864,
                "maximum_json_depth": 64,
                "maximum_nodes": 10_000,
                "maximum_transformations": 10_000,
                "maximum_rational_bits": 4_096,
                "maximum_operations": 10_000_000,
                "solver_seconds": 30,
            },
            "non_claims": [
                "collective superintelligence inference",
                "physical phase equivalence",
                "causal acceleration certification",
            ],
        },
        "missing_decisions": missing,
        "draft_executable": False,
    }
    output.mkdir(parents=True)
    target = output / "contract-draft.json"
    write_canonical(target, draft)
    return response(
        "ok",
        None,
        effect_class="local_write",
        files_written=[str(target.resolve())],
        unknowns=missing,
        next_commands=[["cpcf", "contract", "explain-missing", str(target), "--json"]],
        draft=str(target.resolve()),
        draft_executable=False,
        missing_decisions=missing,
    )


def _migrate_contract(old: JsonObject) -> JsonObject:
    control = cast(
        JsonObject,
        old.get("control_policy") if isinstance(old.get("control_policy"), dict) else {},
    )
    limits = cast(
        JsonObject,
        old.get("analysis_limits") if isinstance(old.get("analysis_limits"), dict) else {},
    )
    return {
        "schema_version": V4,
        "contract_id": str(old.get("contract_id", "migrated-contract")),
        "scope": old.get("scope", {}),
        "target_states": old.get("target_states", []),
        "initial_available_states": old.get("initial_available_states", []),
        "protected_floors": old.get("protected_floors", {}),
        "resource_envelope": old.get("resource_envelope", {}),
        "control_policy": {
            "planning_horizon": min(3, max(1, int(control.get("planning_horizon", 1)))),
            "beam_width": min(32, max(1, int(control.get("beam_width", 32)))),
            "candidate_cap": min(64, max(1, int(control.get("candidate_cap", 64)))),
            "retry_limit": min(16, max(0, int(control.get("retry_limit", 0)))),
        },
        "required_dimensions": [
            "provenance_integrity",
            "structural_reachability",
            "causal_formation",
            "exact_self_maintenance",
            "finite_resource_persistence",
            "target_bound_generative_catalysis",
            "verification_capacity",
            "effective_independence",
            "perturbation_robustness",
        ],
        "perturbation_suite_refs": old.get("support_core_policy", {}).get(
            "perturbation_suite_refs", []
        )
        if isinstance(old.get("support_core_policy"), dict)
        else [],
        "analysis_limits": {
            "maximum_raw_bytes": min(67_108_864, int(limits.get("maximum_raw_bytes", 16_777_216))),
            "maximum_json_depth": min(64, int(limits.get("maximum_json_depth", 64))),
            "maximum_nodes": min(10_000, int(limits.get("maximum_nodes", 10_000))),
            "maximum_transformations": min(
                10_000, int(limits.get("maximum_transformations", 10_000))
            ),
            "maximum_rational_bits": min(4_096, int(limits.get("maximum_rational_bits", 4_096))),
            "maximum_operations": 10_000_000,
            "solver_seconds": 30,
        },
        "non_claims": sorted(
            set(
                [
                    *cast(list[str], old.get("non_claims", [])),
                    "collective superintelligence inference",
                    "physical phase equivalence",
                    "causal acceleration certification",
                ]
            )
        ),
    }


def migrate_workspace_v4(
    old_root: Path,
    trust_path: Path,
    time_receipt_path: Path,
    output: Path,
    root_fingerprint: str,
) -> JsonObject:
    """Copy raw legacy records and quarantine all legacy authority-bearing objects."""

    if output.exists():
        return response("failed", "output_already_exists")
    version = workspace_version(old_root)
    if version not in {"0.1.0", "0.2.0", "0.3.0"}:
        return response("failed", "unsupported_migration_source", schema_version=version)
    try:
        if version == "0.3.0":
            old_store = GenerationStore(old_root)
            old_manifest = old_store.load_manifest()
            old_contract_value = old_store.get_json(str(old_manifest["contract_digest"]))
        else:
            old_manifest = {}
            old_contract_value = load_json_bounded(old_root / "contract.json")
        trust = load_json_bounded(trust_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "migration_source_invalid", detail=str(error))
    if not isinstance(old_contract_value, dict) or not isinstance(trust, dict):
        return response("failed", "migration_source_not_object")
    contract = _migrate_contract(old_contract_value)
    if validation_errors("phase-contract", contract, V4):
        return response(
            "failed",
            "migrated_contract_requires_user_decisions",
            schema_errors=validation_errors("phase-contract", contract, V4),
        )
    # The time receipt is bound to the migrated contract digest.
    time_value = load_json_bounded(time_receipt_path)
    if not isinstance(time_value, dict):
        return response("failed", "trusted_time_receipt_not_object")
    verified_time = verify_time_receipt(
        time_value, trust, expected_subject_digest=digest_v3_json(contract)
    )
    policy_errors = validate_policy(trust, root_fingerprint)
    if policy_errors or verified_time["status"] != "true":
        return response(
            "failed",
            "migration_trust_invalid",
            trust_errors=policy_errors,
            time_verification=verified_time,
        )
    output.mkdir(parents=True)
    store = GenerationStoreV4(output)
    contract_digest = store.put_json(contract)
    trust_digest = store.put_json(trust)
    time_digest = store.put_json(time_value)
    objects = [
        ledger_entry(contract_digest, kind="contract", schema_ref="phase-contract@0.4.0"),
        ledger_entry(
            trust_digest,
            kind="trust-policy",
            schema_ref="trust-policy@0.4.0",
            authority_key_id=str(trust["root_key_id"]),
        ),
        ledger_entry(
            time_digest,
            kind="trusted-time-receipt",
            schema_ref="signed-statement@0.4.0",
            source_chain=[contract_digest],
            authority_key_id=str(time_value["protected"]["key_id"]),
        ),
    ]
    quarantine: list[str] = []
    if version == "0.3.0":
        old_store = GenerationStore(old_root)
        raw_set = set(old_manifest.get("raw_artifacts", []))
        referenced: set[str] = set(raw_set)
        referenced.update(cast(list[str], old_manifest.get("envelopes", [])))
        referenced.update(cast(list[str], old_manifest.get("receipts", [])))
        referenced.update(
            str(item.get("object_digest"))
            for item in old_manifest.get("projections", [])
            if isinstance(item, dict)
        )
        for digest in sorted(referenced):
            try:
                copied = store.cas.put(old_store.cas.get(digest)).digest
            except OSError:
                continue
            kind = "legacy-raw-artifact" if digest in raw_set else "legacy-authority-object"
            objects.append(
                ledger_entry(
                    copied,
                    kind=kind,
                    schema_ref=f"legacy@{version}",
                    lifecycle="quarantined",
                )
            )
            quarantine.append(copied)
    payload = empty_generation_v4(
        contract_digest=contract_digest,
        trust_policy_digest=trust_digest,
        trusted_time_receipt_digest=time_digest,
        analysis_epoch=str(verified_time["event_time"]),
        objects=objects,
        quarantine=sorted(set(quarantine)),
    )
    payload["history"] = [
        {
            "event_type": "copy_on_write_migration",
            "source_version": version,
            "legacy_objects_quarantined": len(quarantine),
            "legacy_signatures_reinterpreted": False,
            "previous_event_digest": digest_v3_json([]),
        }
    ]
    committed = store.commit(payload, expected_current=None)
    if committed.get("command_status") != "ok":
        shutil.rmtree(output)
        return response("failed", str(committed.get("failure_code")), detail=committed)
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        quarantined=sorted(set(quarantine)),
        claims=["legacy_raw_records_copied", "legacy_authority_quarantined"],
        unknowns=["fresh_v0.4_attestations"],
        source_workspace=str(old_root.resolve()),
        source_workspace_modified=False,
        schema_version=V4,
        execution_allowed=False,
    )


def repairs_v4(root: Path) -> list[JsonObject]:
    """Generate typed, non-placeholder repairs from native blockers."""

    audit = doctor_v4(root)
    repairs: list[JsonObject] = []
    mapping = {
        "authoritative_time_receipt_missing_or_invalid": (
            "import_trusted_time",
            [
                "cpcf",
                "workspace",
                "advance-time",
                "--workspace",
                str(root),
                "--time-receipt",
                "TIME_RECEIPT.json",
                "--apply",
                "--json",
            ],
        ),
        "attestation_not_source_backed": (
            "replace_source_attestation",
            [
                "cpcf",
                "attestation",
                "import",
                "ATTESTATION.json",
                "--workspace",
                str(root),
                "--apply",
                "--json",
            ],
        ),
        "ledger_source_reference_missing": (
            "rebuild_or_reimport_source_chain",
            ["cpcf", "doctor", "--workspace", str(root), "--json"],
        ),
        "cas_digest_invalid": (
            "restore_content_addressed_object",
            [
                "cpcf",
                "source",
                "import",
                "REPORT.json",
                "--workspace",
                str(root),
                "--source-system",
                "SOURCE",
                "--schema-ref",
                "SCHEMA@0.4.0",
                "--apply",
                "--json",
            ],
        ),
    }
    for index, error in enumerate(audit.get("errors", [])):
        if not isinstance(error, dict):
            continue
        code = str(error.get("code"))
        repair_type, command = mapping.get(
            code,
            ("unbound_repair", ["cpcf", "agent", "onboard", "--workspace", str(root), "--json"]),
        )
        repairs.append(
            {
                "repair_id": f"repair:{digest_v3_json({'index': index, 'error': error})[7:]}",
                "repair_type": repair_type,
                "blocking_code": code,
                "executable": repair_type != "unbound_repair",
                "command": command if repair_type != "unbound_repair" else None,
                "details": error,
            }
        )
    for digest in audit.get("quarantined_objects", []):
        repairs.append(
            {
                "repair_id": f"repair:{digest_bytes(str(digest).encode())[7:]}",
                "repair_type": "fresh_v0.4_attestation_required",
                "blocking_code": "legacy_object_quarantined",
                "executable": False,
                "command": None,
                "details": {"digest": digest},
            }
        )
    return sorted(repairs, key=lambda item: str(item["repair_id"]))


def repair_list_v4(root: Path) -> JsonObject:
    repairs = repairs_v4(root)
    store = GenerationStoreV4(root)
    generation = store.current_id()
    return response(
        "ok",
        None,
        generation=generation,
        unknowns=["unbound_repairs"] if any(not item["executable"] for item in repairs) else [],
        repairs=repairs,
    )


def repair_show_v4(root: Path, repair_id: str) -> JsonObject:
    matches = [item for item in repairs_v4(root) if item["repair_id"] == repair_id]
    if len(matches) != 1:
        return response("failed", "repair_not_found")
    return response("ok", None, generation=GenerationStoreV4(root).current_id(), repair=matches[0])


def onboard_v4(root: Path) -> JsonObject:
    status = status_v4(root)
    if status.get("schema_version") != V4:
        return status
    audit = doctor_v4(root)
    repairs = repairs_v4(root)
    next_commands: list[list[str]] = [
        ["cpcf", "doctor", "--workspace", str(root), "--json"],
        ["cpcf", "science", "audit", "--workspace", str(root), "--compact", "--json"],
        ["cpcf", "repair", "list", "--workspace", str(root), "--json"],
    ]
    if audit.get("execution_allowed") is True:
        next_commands.append(
            ["cpcf", "control", "next", "--workspace", str(root), "--compact", "--json"]
        )
    return response(
        "ok",
        None,
        generation=str(status.get("workspace_generation")),
        claims=["workspace_blockers_recomputed"],
        unknowns=list(audit.get("unknowns", [])),
        quarantined=list(audit.get("quarantined_objects", [])),
        next_commands=next_commands,
        execution_allowed=audit.get("execution_allowed") is True,
        unresolved_user_decisions=[
            item["blocking_code"] for item in repairs if not item["executable"]
        ],
        trust_model="single_pinned_ed25519_key_per_principal",
        strongest_native_claim="operational_organization_profile",
        measured_acceleration_requires_external_preregistered_evidence=True,
        collective_superintelligence_phase_inferred=False,
        os_sandbox_claim=False,
        solver_profile="optional_z3_with_bounded_exact_fallback",
    )
