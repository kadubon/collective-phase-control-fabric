# SPDX-License-Identifier: Apache-2.0
"""Trustworthy v0.3 workspace, projection, onboarding, and migration operations."""

from __future__ import annotations

import hashlib
import json
import shutil
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import (
    digest_bytes,
    digest_v3_json,
    load_json,
    load_json_strict,
    loads_json_strict,
    write_canonical,
)
from collective_phase_control_fabric.generation import GenerationStore, empty_generation
from collective_phase_control_fabric.provenance import parse_schema_ref
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.trust import verify_pinned_signature
from collective_phase_control_fabric.types import JsonObject, JsonValue, id_set

V3 = "0.3.0"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _json_depth(value: JsonValue) -> int:
    if isinstance(value, dict):
        return 1 + max((_json_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_json_depth(item) for item in value), default=0)
    return 1


def _executable_digest(value: str) -> str | None:
    located = shutil.which(value)
    path = Path(located) if located else Path(value)
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError:
        return None
    return f"sha256:{digest.hexdigest()}"


def _meta(
    value: JsonObject,
    *,
    effect_class: str,
    files_written: list[str] | None = None,
    authority_required: list[str] | None = None,
    next_commands: list[list[str]] | None = None,
) -> JsonObject:
    value["effect_class"] = effect_class
    value["files_written"] = files_written or []
    value["authority_required"] = authority_required or []
    value["next_safe_commands"] = next_commands or []
    value["network_accessed"] = False
    value["external_effect"] = False
    return value


def _failed(
    code: str, *, next_commands: list[list[str]] | None = None, **extra: object
) -> JsonObject:
    return _meta(
        {"command_status": "failed", "failure_code": code, **extra},
        effect_class="inspect",
        next_commands=next_commands,
    )


def workspace_version_v3(root: Path) -> str | None:
    current = root / ".cpcf" / "CURRENT"
    if current.is_file():
        return V3
    manifest = root / ".cpcf" / "workspace.json"
    if manifest.is_file():
        value = load_json(manifest)
        if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
            return str(value["schema_version"])
    contract = root / "contract.json"
    if contract.is_file():
        value = load_json(contract)
        if isinstance(value, dict) and isinstance(value.get("schema_version"), str):
            return str(value["schema_version"])
    return None


def scaffold_contract(output: Path, profile: str) -> JsonObject:
    """Write a schema-valid draft that explicitly names every missing user decision."""

    if output.exists():
        return _failed("output_already_exists")
    output.mkdir(parents=True)
    missing = [
        "contract.scope",
        "contract.target_states",
        "contract.initial_available_states",
        "contract.state_coordinate_registry",
        "contract.protected_floors",
        "contract.resource_envelope",
        "trust_policy.principals",
        "independence_domains",
        "perturbation_suites",
    ]
    if profile == "measured":
        missing.extend(
            [
                "measurement_protocol.comparison",
                "measurement_protocol.assignment",
                "measurement_protocol.outcomes",
                "measurement_protocol.quality_floors",
            ]
        )
    draft: JsonObject = {
        "schema_version": V3,
        "draft_id": "draft:replace-with-user-defined-id",
        "profile": profile,
        "missing_decisions": missing,
        "candidate_contract": {},
    }
    target = output / "contract-draft.json"
    write_canonical(target, draft)
    return _meta(
        {
            "command_status": "ok",
            "draft": str(target.resolve()),
            "draft_executable": False,
            "missing_decisions": missing,
        },
        effect_class="local_write",
        files_written=[str(target.resolve())],
        next_commands=[["cpcf", "schema", "show", "phase-contract", "--version", V3, "--json"]],
    )


def validate_trust_policy(path: Path) -> JsonObject:
    try:
        value = load_json_strict(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return _failed("trust_policy_parse_failed", detail=str(error))
    errors = validation_errors("trust-policy", value, V3)
    principals = value.get("principals", []) if isinstance(value, dict) else []
    key_ids = [item.get("key_id") for item in principals if isinstance(item, dict)]
    if len(key_ids) != len(set(key_ids)):
        errors.append({"message": "duplicate pinned key_id", "json_pointer": "/principals"})
    return _meta(
        {
            "command_status": "ok" if not errors else "failed",
            "failure_code": None if not errors else "trust_policy_invalid",
            "trust_policy": str(path.resolve()),
            "schema_errors": errors,
            "principal_count": len(principals),
            "threshold_trust": False,
            "single_key_compromise_resilient": False,
        },
        effect_class="validate",
        next_commands=[]
        if not errors
        else [["cpcf", "schema", "show", "trust-policy", "--version", V3, "--json"]],
    )


def _load_generation_documents(
    store: GenerationStore, manifest: JsonObject
) -> tuple[JsonObject, JsonObject]:
    contract = store.get_json(str(manifest["contract_digest"]))
    trust = store.get_json(str(manifest["trust_policy_digest"]))
    if not isinstance(contract, dict) or not isinstance(trust, dict):
        raise ValueError("generation contract and trust policy must be objects")
    return contract, trust


def initialize_workspace_v3(contract_path: Path, trust_path: Path, output: Path) -> JsonObject:
    if output.exists():
        return _failed("output_already_exists")
    try:
        contract = load_json_strict(contract_path)
        trust = load_json_strict(trust_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        return _failed("input_parse_failed", detail=str(error))
    contract_errors = validation_errors("phase-contract", contract, V3)
    trust_errors = validation_errors("trust-policy", trust, V3)
    if isinstance(contract, dict) and isinstance(trust, dict):
        key_ids = [
            item.get("key_id") for item in trust.get("principals", []) if isinstance(item, dict)
        ]
        if len(key_ids) != len(set(key_ids)):
            trust_errors.append(
                {"message": "duplicate pinned key_id", "json_pointer": "/principals"}
            )
        if not any(
            isinstance(item, dict) and item.get("scope") == contract.get("scope")
            for item in trust.get("principals", [])
        ):
            trust_errors.append(
                {
                    "message": "no pinned principal matches contract scope",
                    "json_pointer": "/principals",
                }
            )
    if (
        contract_errors
        or trust_errors
        or not isinstance(contract, dict)
        or not isinstance(trust, dict)
    ):
        return _failed(
            "workspace_input_invalid",
            contract_schema_errors=contract_errors,
            trust_schema_errors=trust_errors,
        )
    output.mkdir(parents=True)
    store = GenerationStore(output)
    contract_digest = store.put_json(contract)
    trust_digest = store.put_json(trust)
    payload = empty_generation(
        contract_digest=contract_digest,
        trust_policy_digest=trust_digest,
        analysis_epoch=str(contract["evaluation_time"]),
    )
    committed = store.commit(payload, expected_current=None)
    if committed.get("command_status") != "ok":
        shutil.rmtree(output)
        return committed
    return _meta(
        {
            **committed,
            "workspace": str(output.resolve()),
            "schema_version": V3,
            "execution_allowed": True,
            "source_of_record_migrated": False,
        },
        effect_class="local_write",
        files_written=[
            str(store.current_path),
            str(store.manifest_path(str(committed["generation_id"]))),
        ],
        authority_required=[str(trust["policy_id"])],
        next_commands=[
            ["cpcf", "agent", "onboard", "--workspace", str(output), "--compact", "--json"]
        ],
    )


def _parse_time(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed


def advance_time_v3(root: Path, target: str, *, apply: bool) -> JsonObject:
    store = GenerationStore(root)
    try:
        manifest = store.load_manifest()
        current = store.current_id()
        old = _parse_time(manifest["analysis_epoch"])
        new = _parse_time(target)
    except (OSError, ValueError, KeyError) as error:
        return _failed("analysis_epoch_invalid", detail=str(error))
    if new < old:
        return _failed("analysis_epoch_rollback_rejected")
    if not apply:
        return _failed(
            "apply_required",
            next_commands=[
                [
                    "cpcf",
                    "workspace",
                    "advance-time",
                    "--workspace",
                    str(root),
                    "--to",
                    target,
                    "--apply",
                    "--json",
                ]
            ],
        )
    payload = deepcopy(manifest)
    payload["analysis_epoch"] = target
    payload["history"] = [
        *cast(list[object], manifest.get("history", [])),
        {
            "event_type": "analysis_epoch_advanced",
            "from": str(manifest["analysis_epoch"]),
            "to": target,
            "previous_event_digest": digest_v3_json(cast(JsonValue, manifest.get("history", []))),
        },
    ]
    committed = store.commit(payload, expected_current=current)
    return _meta(
        committed,
        effect_class="local_write",
        files_written=[str(store.current_path)] if committed.get("command_status") == "ok" else [],
        next_commands=[["cpcf", "doctor", "--workspace", str(root), "--json"]],
    )


def _pointer(value: JsonValue, pointer: str) -> JsonValue:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must be absolute")
    current = value
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = cast(JsonValue, current[token])
        elif isinstance(current, list):
            current = cast(JsonValue, current[int(token)])
        else:
            raise ValueError("JSON pointer traverses a scalar")
    return current


def _source_role(schema_ref: str) -> str:
    name, _ = parse_schema_ref(schema_ref)
    if name == "adapter-capability":
        return "adapter_capability"
    if name == "action":
        return "action_author"
    if name in {"measurement-protocol", "trial-result-certificate"}:
        return "evaluator"
    return "source"


def inspect_source_v3(
    report: Path,
    trust_path: Path,
    source_system: str,
    schema_ref: str,
    *,
    evaluation_time: str | None = None,
    expected_scope: JsonObject | None = None,
) -> JsonObject:
    try:
        raw = report.read_bytes()
        value = loads_json_strict(raw)
        trust = load_json_strict(trust_path)
        name, version = parse_schema_ref(schema_ref)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError) as error:
        return _failed("source_parse_failed", detail=str(error))
    errors = validation_errors(name, value, version)
    trust_errors = validation_errors("trust-policy", trust, V3)
    errors.extend(trust_errors)
    if not isinstance(value, dict) or not isinstance(trust, dict):
        return _failed("source_or_trust_not_object", schema_errors=errors)
    evaluated = evaluation_time or _now()
    signature = verify_pinned_signature(
        value,
        trust,
        schema_ref=schema_ref,
        source_system=source_system,
        role=_source_role(schema_ref),
        evaluation_time=evaluated,
    )
    scope_valid = True
    if expected_scope is not None:
        principal = next(
            (
                item
                for item in trust.get("principals", [])
                if isinstance(item, dict) and item.get("key_id") == signature.get("key_id")
            ),
            None,
        )
        scope_valid = isinstance(principal, dict) and principal.get("scope") == expected_scope
    valid = not errors and signature.get("status") == "true" and scope_valid
    return _meta(
        {
            "command_status": "ok" if valid else "failed",
            "failure_code": None if valid else "source_validation_failed",
            "report": str(report.resolve()),
            "raw_artifact_digest": digest_bytes(raw),
            "raw_size": len(raw),
            "schema_ref": schema_ref,
            "schema_errors": errors,
            "signature_verification": signature,
            "scope_status": "true" if scope_valid else "false",
            "source_system": source_system,
            "source_pointers": [""],
            "source_artifact_modified": False,
        },
        effect_class="inspect",
        authority_required=[str(signature.get("key_id", "unknown"))],
    )


def _lifecycle_status(value: JsonObject, epoch: str) -> str:
    expires = value.get("expires_at")
    if expires is None:
        return "not_applicable"
    try:
        return "true" if _parse_time(expires) >= _parse_time(epoch) else "false"
    except ValueError:
        return "false"


def import_source_v3(
    report: Path,
    root: Path,
    source_system: str,
    schema_ref: str,
    *,
    apply: bool,
) -> JsonObject:
    if not apply:
        return _failed(
            "apply_required",
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
    store = GenerationStore(root)
    try:
        manifest = store.load_manifest()
        current = store.current_id()
        contract, trust = _load_generation_documents(store, manifest)
        raw = report.read_bytes()
        maximum = int(contract["analysis_limits"]["maximum_raw_bytes"])
        if len(raw) > maximum:
            return _failed("analysis_limit_exceeded", limit="maximum_raw_bytes", maximum=maximum)
        value = loads_json_strict(raw)
        name, version = parse_schema_ref(schema_ref)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError) as error:
        return _failed("source_import_precondition_failed", detail=str(error))
    errors = validation_errors(name, value, version)
    if errors or not isinstance(value, dict):
        return _failed("source_schema_invalid", schema_errors=errors)
    if _json_depth(value) > int(contract["analysis_limits"]["maximum_json_depth"]):
        return _failed(
            "analysis_limit_exceeded",
            limit="maximum_json_depth",
            maximum=int(contract["analysis_limits"]["maximum_json_depth"]),
        )
    signature = verify_pinned_signature(
        value,
        trust,
        schema_ref=schema_ref,
        source_system=source_system,
        role=_source_role(schema_ref),
        evaluation_time=str(manifest["analysis_epoch"]),
    )
    principal = next(
        (
            item
            for item in trust.get("principals", [])
            if isinstance(item, dict) and item.get("key_id") == signature.get("key_id")
        ),
        None,
    )
    if signature.get("status") != "true":
        return _failed("source_signature_invalid", signature_verification=signature)
    if not isinstance(principal, dict) or principal.get("scope") != contract.get("scope"):
        return _failed("source_scope_mismatch")
    raw_digest = store.cas.put(raw).digest
    projected_digest = store.put_json(value)
    envelope: JsonObject = {
        "schema_version": V3,
        "envelope_id": f"envelope:{raw_digest.split(':', 1)[1][:24]}",
        "source_system": source_system,
        "schema_ref": schema_ref,
        "raw_artifact_digest": raw_digest,
        "raw_size": len(raw),
        "scope": cast(JsonObject, contract.get("scope", {})),
        "lifecycle": {"expires_at": value["expires_at"]} if "expires_at" in value else {},
        "lineage": sorted(id_set(value.get("lineage"))),
        "source_pointers": [""],
        "imported_at": str(manifest["analysis_epoch"]),
        "signature_requirement": "required",
    }
    envelope_digest = store.put_json(envelope)
    validation: JsonObject = {
        "schema": "true",
        "digest": "true",
        "pointer": "true",
        "expiry": _lifecycle_status(value, str(manifest["analysis_epoch"])),
        "scope": "true",
        "resource": "not_applicable",
        "baseline": "not_applicable",
        "signature": "true",
        "return_code": "not_applicable",
        "output_limits": "not_applicable",
    }
    receipt: JsonObject = {
        "schema_version": V3,
        "receipt_id": f"receipt:{raw_digest.split(':', 1)[1][:24]}",
        "envelope_digest": envelope_digest,
        "raw_artifact_digest": raw_digest,
        "invocation_digest": None,
        "executable_digest": None,
        "return_code": None,
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "projected_objects": [
            {"digest": projected_digest, "schema_ref": schema_ref, "source_pointer": ""}
        ],
        "cached_validation": validation,
        "evaluation_time": str(manifest["analysis_epoch"]),
    }
    receipt_digest = store.put_json(receipt)
    projection_record = {
        "object_digest": projected_digest,
        "schema_ref": schema_ref,
        "receipt_digest": receipt_digest,
        "source_pointer": "",
    }
    payload = deepcopy(manifest)
    payload["raw_artifacts"] = sorted({*cast(list[str], manifest["raw_artifacts"]), raw_digest})
    payload["envelopes"] = sorted({*cast(list[str], manifest["envelopes"]), envelope_digest})
    payload["receipts"] = sorted({*cast(list[str], manifest["receipts"]), receipt_digest})
    existing = [
        item
        for item in cast(list[JsonObject], manifest["projections"])
        if item.get("object_digest") != projected_digest
    ]
    payload["projections"] = sorted(
        [*existing, projection_record],
        key=lambda item: (str(item["schema_ref"]), str(item["object_digest"])),
    )
    committed = store.commit(payload, expected_current=current)
    return _meta(
        {
            **committed,
            "source_system": source_system,
            "raw_artifact_digest": raw_digest,
            "projected_object_digest": projected_digest,
            "receipt_digest": receipt_digest,
            "source_artifact_modified": False,
        },
        effect_class="local_write",
        files_written=[str(store.current_path)] if committed.get("command_status") == "ok" else [],
        authority_required=[str(signature["key_id"])],
        next_commands=[["cpcf", "doctor", "--workspace", str(root), "--json"]],
    )


def _recompute_projection(
    store: GenerationStore,
    manifest: JsonObject,
    record: JsonObject,
    contract: JsonObject,
    trust: JsonObject,
) -> JsonObject:
    reasons: list[str] = []
    try:
        receipt_value = store.get_json(str(record["receipt_digest"]))
        if not isinstance(receipt_value, dict):
            raise ValueError("receipt must be an object")
        receipt = receipt_value
        envelope_value = store.get_json(str(receipt["envelope_digest"]))
        if not isinstance(envelope_value, dict):
            raise ValueError("envelope must be an object")
        envelope = envelope_value
        raw_digest = str(receipt["raw_artifact_digest"])
        raw = store.cas.get(raw_digest)
        if raw_digest != envelope.get("raw_artifact_digest"):
            reasons.append("raw_digest_binding_mismatch")
        root = loads_json_strict(raw)
        raw_name, raw_version = parse_schema_ref(str(envelope["schema_ref"]))
        if validation_errors(raw_name, root, raw_version):
            reasons.append("raw_schema_invalid")
        process_bound = envelope.get("signature_requirement") == "process_bound"
        if not isinstance(root, dict):
            reasons.append("signed_root_not_object")
        elif not process_bound:
            signature = verify_pinned_signature(
                root,
                trust,
                schema_ref=str(envelope["schema_ref"]),
                source_system=str(envelope["source_system"]),
                role=_source_role(str(envelope["schema_ref"])),
                evaluation_time=str(manifest["analysis_epoch"]),
            )
            if signature.get("status") != "true":
                reasons.append("signature_recomputation_failed")
        if process_bound:
            if envelope.get("scope") != contract.get("scope"):
                reasons.append("scope_recomputation_failed")
            if receipt.get("invocation_digest") is None or receipt.get("executable_digest") is None:
                reasons.append("process_binding_missing")
        else:
            principal_key = (
                root.get("signature", {}).get("key_id")
                if isinstance(root, dict) and isinstance(root.get("signature"), dict)
                else None
            )
            principal = next(
                (
                    item
                    for item in trust.get("principals", [])
                    if isinstance(item, dict) and item.get("key_id") == principal_key
                ),
                None,
            )
            if not isinstance(principal, dict) or principal.get("scope") != contract.get("scope"):
                reasons.append("scope_recomputation_failed")
        pointer = str(record["source_pointer"])
        projected = _pointer(root, pointer)
        name, version = parse_schema_ref(str(record["schema_ref"]))
        if validation_errors(name, projected, version):
            reasons.append("projected_schema_invalid")
        calculated = digest_v3_json(projected)
        if calculated != record.get("object_digest"):
            reasons.append("projected_digest_mismatch")
        if not store.cas.verify(calculated):
            reasons.append("projected_object_missing")
        declared = [
            item
            for item in receipt.get("projected_objects", [])
            if isinstance(item, dict)
            and item.get("digest") == calculated
            and item.get("schema_ref") == record.get("schema_ref")
            and item.get("source_pointer") == pointer
        ]
        if len(declared) != 1:
            reasons.append("receipt_projection_binding_invalid")
        if (
            _lifecycle_status(
                root if isinstance(root, dict) else {}, str(manifest["analysis_epoch"])
            )
            == "false"
        ):
            reasons.append("source_expired")
        if receipt.get("timed_out") is True or receipt.get("stdout_truncated") is True:
            reasons.append("process_output_incomplete")
        if receipt.get("return_code") not in {None, 0}:
            reasons.append("process_return_code_failed")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        reasons.append(f"projection_recomputation_error:{type(error).__name__}")
        projected = None
    return {
        "status": "true" if not reasons else "false",
        "reasons": sorted(set(reasons)),
        "projection": projected,
        "cached_validation_authoritative": False,
    }


def valid_projections_v3(root: Path) -> tuple[JsonObject, list[tuple[JsonObject, JsonObject]]]:
    store = GenerationStore(root)
    manifest = store.load_manifest()
    contract, trust = _load_generation_documents(store, manifest)
    results: list[tuple[JsonObject, JsonObject]] = []
    for record in cast(list[JsonObject], manifest.get("projections", [])):
        checked = _recompute_projection(store, manifest, record, contract, trust)
        if checked["status"] == "true" and isinstance(checked.get("projection"), dict):
            results.append((record, cast(JsonObject, checked["projection"])))
    return manifest, results


def rebuild_projections_v3(root: Path) -> JsonObject:
    try:
        store = GenerationStore(root)
        manifest = store.load_manifest()
        contract, trust = _load_generation_documents(store, manifest)
    except (OSError, ValueError) as error:
        return _failed("workspace_generation_invalid", detail=str(error))
    results = [
        {
            "object_digest": record.get("object_digest"),
            **_recompute_projection(store, manifest, record, contract, trust),
        }
        for record in cast(list[JsonObject], manifest.get("projections", []))
    ]
    rejected = [item for item in results if item["status"] != "true"]
    return _meta(
        {
            "command_status": "ok" if not rejected else "failed",
            "failure_code": None if not rejected else "projection_rebuild_failed",
            "generation_id": manifest["generation_id"],
            "projection_count": len(results),
            "valid_projection_count": len(results) - len(rejected),
            "results": results,
            "generation_committed": False,
        },
        effect_class="validate",
        next_commands=[]
        if not rejected
        else [["cpcf", "doctor", "--workspace", str(root), "--json"]],
    )


def doctor_v3(root: Path, *, quick: bool = False) -> JsonObject:
    store = GenerationStore(root)
    errors = store.verify_chain()
    try:
        manifest = store.load_manifest()
        contract, trust = _load_generation_documents(store, manifest)
    except (OSError, ValueError) as error:
        return _failed("workspace_generation_invalid", detail=str(error))
    errors.extend(
        {"code": "contract_schema_invalid", **item}
        for item in validation_errors("phase-contract", contract, V3)
    )
    errors.extend(
        {"code": "trust_policy_schema_invalid", **item}
        for item in validation_errors("trust-policy", trust, V3)
    )
    for digest in [
        *cast(list[str], manifest.get("raw_artifacts", [])),
        *cast(list[str], manifest.get("envelopes", [])),
        *cast(list[str], manifest.get("receipts", [])),
        *[
            str(item.get("object_digest"))
            for item in manifest.get("projections", [])
            if isinstance(item, dict)
        ],
    ]:
        if not store.cas.verify(digest):
            errors.append({"code": "cas_digest_invalid", "digest": digest})
    if not quick:
        for record in cast(list[JsonObject], manifest.get("projections", [])):
            checked = _recompute_projection(store, manifest, record, contract, trust)
            if checked["status"] != "true":
                errors.append(
                    {
                        "code": "projection_not_source_backed",
                        "object_digest": record.get("object_digest"),
                        "reasons": checked["reasons"],
                    }
                )
        valid_objects: list[JsonObject] = []
        for record in cast(list[JsonObject], manifest.get("projections", [])):
            checked = _recompute_projection(store, manifest, record, contract, trust)
            if checked["status"] == "true" and isinstance(checked.get("projection"), dict):
                valid_objects.append(cast(JsonObject, checked["projection"]))
        identifiers: list[str] = []
        for value in valid_objects:
            for key in (
                "action_id",
                "capability_id",
                "effect_id",
                "witness_id",
                "protocol_id",
                "result_id",
                "suite_id",
                "ledger_id",
                "marking_id",
                "network_id",
            ):
                if isinstance(value.get(key), str):
                    identifiers.append(str(value[key]))
            if value.get("schema_version") == V3 and isinstance(value.get("capability_id"), str):
                actual = _executable_digest(str(value.get("executable")))
                if actual != value.get("executable_digest"):
                    errors.append(
                        {
                            "code": "adapter_executable_missing_or_digest_mismatch",
                            "capability_id": value["capability_id"],
                        }
                    )
        duplicates = sorted({item for item in identifiers if identifiers.count(item) > 1})
        errors.extend(
            {"code": "duplicate_projection_identifier", "identifier": item} for item in duplicates
        )
        history = manifest.get("history", [])
        if isinstance(history, list):
            for index, event in enumerate(history):
                if not isinstance(event, dict) or event.get(
                    "previous_event_digest"
                ) != digest_v3_json(cast(JsonValue, history[:index])):
                    errors.append({"code": "history_hash_chain_invalid", "event_index": index})
    return _meta(
        {
            "command_status": "ok" if not errors else "failed",
            "failure_code": None if not errors else "workspace_audit_failed",
            "workspace": str(root.resolve()),
            "schema_version": V3,
            "generation_id": manifest["generation_id"],
            "strict": not quick,
            "errors": errors,
            "execution_allowed": not errors and not quick,
            "cached_validation_authoritative": False,
            "single_pointer_transactional_state": True,
        },
        effect_class="validate",
        next_commands=[]
        if not errors
        else [["cpcf", "project", "rebuild", "--workspace", str(root), "--json"]],
    )


def workspace_status_v3(root: Path) -> JsonObject:
    version = workspace_version_v3(root)
    if version != V3:
        return _meta(
            {
                "command_status": "ok",
                "workspace": str(root.resolve()),
                "schema_version": version,
                "execution_allowed": False,
                "failure_code": "legacy_workspace_inspect_only",
            },
            effect_class="inspect",
            next_commands=[
                [
                    "cpcf",
                    "workspace",
                    "migrate",
                    "--workspace",
                    str(root),
                    "--trust-policy",
                    "TRUST_POLICY.json",
                    "--out",
                    f"{root}-v0.3",
                    "--to",
                    V3,
                    "--json",
                ]
            ],
        )
    store = GenerationStore(root)
    manifest = store.load_manifest()
    audit = doctor_v3(root)
    return _meta(
        {
            "command_status": "ok",
            "workspace": str(root.resolve()),
            "schema_version": V3,
            "generation_id": manifest["generation_id"],
            "previous_generation": manifest["previous_generation"],
            "analysis_epoch": manifest["analysis_epoch"],
            "projection_count": len(manifest["projections"]),
            "quarantine_count": len(manifest["quarantine"]),
            "execution_allowed": audit.get("execution_allowed") is True,
            "doctor_status": audit["command_status"],
        },
        effect_class="inspect",
        next_commands=[
            ["cpcf", "agent", "onboard", "--workspace", str(root), "--compact", "--json"]
        ],
    )


def onboard_agent_v3(root: Path) -> JsonObject:
    status = workspace_status_v3(root)
    if status.get("schema_version") != V3:
        return status
    next_commands: list[list[str]] = [["cpcf", "doctor", "--workspace", str(root), "--json"]]
    if status.get("execution_allowed") is True:
        next_commands.extend(
            [
                ["cpcf", "science", "audit", "--workspace", str(root), "--compact", "--json"],
                ["cpcf", "control", "next", "--workspace", str(root), "--compact", "--json"],
            ]
        )
    return _meta(
        {
            "command_status": "ok",
            "workspace": str(root.resolve()),
            "schema_version": V3,
            "generation_id": status.get("generation_id"),
            "execution_allowed": status.get("execution_allowed"),
            "unresolved_user_decisions": [],
            "trust_model": "single_pinned_ed25519_key_per_principal",
            "strongest_native_claim": "structural_organization_status",
            "measured_acceleration_requires_external_trial": True,
            "collective_superintelligence_phase_inferred": False,
            "os_sandbox_claim": False,
        },
        effect_class="inspect",
        next_commands=next_commands,
    )


def _migrate_contract_v3(old: JsonObject) -> JsonObject:
    control = old.get("control_policy", {}) if isinstance(old.get("control_policy"), dict) else {}
    support = (
        old.get("support_core_policy", {})
        if isinstance(old.get("support_core_policy"), dict)
        else {}
    )
    rate = old.get("rate_policy", {}) if isinstance(old.get("rate_policy"), dict) else {}
    return {
        "schema_version": V3,
        "contract_id": str(old.get("contract_id", "contract:migrated")),
        "phase_label": str(old.get("phase_label", "user-defined external label")),
        "scope": old.get("scope", {}) if isinstance(old.get("scope"), dict) else {},
        "evaluation_time": str(
            old.get("evaluation_time", old.get("created_at", "1970-01-01T00:00:00Z"))
        ),
        "target_states": sorted(id_set(old.get("target_states"))),
        "initial_available_states": sorted(id_set(old.get("initial_available_states"))),
        "state_coordinate_registry": old.get("state_coordinate_registry", {})
        if isinstance(old.get("state_coordinate_registry"), dict)
        else {},
        "unit_registry": {},
        "protected_floors": old.get("protected_floors", {})
        if isinstance(old.get("protected_floors"), dict)
        else {},
        "resource_envelope": old.get("resource_envelope", {})
        if isinstance(old.get("resource_envelope"), dict)
        else {},
        "control_policy": {
            "planning_horizon": int(control.get("planning_horizon", 1)),
            "beam_width": int(control.get("beam_width", 32)),
            "candidate_cap": int(control.get("candidate_cap", 64)),
            "retry_limit": int((control.get("retry_policy") or {}).get("maximum_retries", 0))
            if isinstance(control.get("retry_policy"), dict)
            else 0,
        },
        "formation_policy": {
            "maximum_layer_count": int(
                (old.get("formation_policy") or {}).get("maximum_layer_count", 64)
            )
            if isinstance(old.get("formation_policy"), dict)
            else 64
        },
        "support_core_policy": {
            "minimum_support_domains": int(support.get("minimum_independent_support_groups", 1)),
            "minimum_verifier_domains": int(support.get("minimum_independent_verifier_groups", 1)),
            "perturbation_suite_refs": sorted(id_set(support.get("perturbation_suite_refs"))),
        },
        "rate_policy": {
            "levels_requiring_evidence": sorted(
                id_set(rate.get("levels_requiring_external_rate_evidence"))
            )
        },
        "analysis_limits": {
            "maximum_raw_bytes": 16_777_216,
            "maximum_json_depth": 64,
            "maximum_nodes": 10_000,
            "maximum_transformations": 10_000,
            "maximum_rational_bits": 4096,
            "maximum_siphon_species": 20,
        },
        "non_claims": list(
            old.get(
                "non_claims",
                [
                    "collective superintelligence",
                    "physical phase transition",
                    "measured acceleration",
                ],
            )
        ),
    }


def migrate_workspace_v3(old_root: Path, trust_path: Path, output: Path, target: str) -> JsonObject:
    if target != V3:
        return _failed("unsupported_migration_target")
    if output.exists():
        return _failed("output_already_exists")
    old_contract_path = old_root / "contract.json"
    if not old_contract_path.is_file():
        return _failed("legacy_contract_missing")
    try:
        old_contract = load_json(old_contract_path)
        trust = load_json_strict(trust_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return _failed("migration_input_invalid", detail=str(error))
    if not isinstance(old_contract, dict) or validation_errors("trust-policy", trust, V3):
        return _failed("migration_input_invalid")
    contract = _migrate_contract_v3(old_contract)
    contract_errors = validation_errors("phase-contract", contract, V3)
    if isinstance(trust, dict) and not any(
        isinstance(item, dict) and item.get("scope") == contract.get("scope")
        for item in trust.get("principals", [])
    ):
        contract_errors.append(
            {
                "message": "no pinned principal matches migrated contract scope",
                "json_pointer": "/scope",
            }
        )
    if contract_errors:
        return _failed("migrated_contract_invalid", schema_errors=contract_errors)
    output.mkdir(parents=True)
    store = GenerationStore(output)
    contract_digest = store.put_json(contract)
    trust_digest = store.put_json(trust)
    quarantined: list[JsonObject] = []
    raw_digests: list[str] = []
    for path in sorted(item for item in old_root.rglob("*") if item.is_file()):
        try:
            relative = str(path.relative_to(old_root))
            raw_digest = store.cas.put(path.read_bytes()).digest
        except OSError:
            continue
        raw_digests.append(raw_digest)
        quarantined.append(
            {
                "legacy_path": relative,
                "raw_digest": raw_digest,
                "reason": "v0.1-v0.2 records require v0.3 revalidation and rebinding",
                "executable": False,
            }
        )
    payload = empty_generation(
        contract_digest=contract_digest,
        trust_policy_digest=trust_digest,
        analysis_epoch=str(contract["evaluation_time"]),
    )
    payload["raw_artifacts"] = sorted(set(raw_digests))
    payload["quarantine"] = quarantined
    committed = store.commit(payload, expected_current=None)
    return _meta(
        {
            **committed,
            "workspace": str(output.resolve()),
            "legacy_workspace": str(old_root.resolve()),
            "legacy_workspace_modified": False,
            "quarantined_record_count": len(quarantined),
            "execution_allowed": committed.get("command_status") == "ok",
            "source_of_record_migrated": False,
        },
        effect_class="local_write",
        files_written=[str(store.current_path)] if committed.get("command_status") == "ok" else [],
        authority_required=[str(trust.get("policy_id", "unknown"))]
        if isinstance(trust, dict)
        else [],
        next_commands=[["cpcf", "doctor", "--workspace", str(output), "--json"]],
    )


def _trial_source_system(root: Path, result: JsonObject) -> str | None:
    store = GenerationStore(root)
    manifest = store.load_manifest()
    _, trust = _load_generation_documents(store, manifest)
    key_id = result.get("evaluator_key_id")
    principal = next(
        (
            item
            for item in trust.get("principals", [])
            if isinstance(item, dict)
            and item.get("key_id") == key_id
            and "evaluator" in item.get("roles", [])
        ),
        None,
    )
    systems = principal.get("source_systems", []) if isinstance(principal, dict) else []
    return sorted(str(item) for item in systems)[0] if systems else None


def inspect_trial_v3(result_path: Path, root: Path) -> JsonObject:
    try:
        result = load_json_strict(result_path)
        if not isinstance(result, dict):
            return _failed("trial_result_not_object")
        source_system = _trial_source_system(root, result)
        store = GenerationStore(root)
        manifest = store.load_manifest()
        contract, _ = _load_generation_documents(store, manifest)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return _failed("trial_inspection_failed", detail=str(error))
    if source_system is None:
        return _failed("trusted_evaluator_source_system_missing")
    # No trust policy export is written: inspect directly from the pinned generation policy.
    raw = result_path.read_bytes()
    name_errors = validation_errors("trial-result-certificate", result, V3)
    _, trust = _load_generation_documents(store, manifest)
    signature = verify_pinned_signature(
        result,
        trust,
        schema_ref="trial-result-certificate@0.3.0",
        source_system=source_system,
        role="evaluator",
        evaluation_time=str(manifest["analysis_epoch"]),
    )
    principal = next(
        (
            item
            for item in trust.get("principals", [])
            if isinstance(item, dict) and item.get("key_id") == result.get("evaluator_key_id")
        ),
        None,
    )
    scope_ok = isinstance(principal, dict) and principal.get("scope") == contract.get("scope")
    _, projections = valid_projections_v3(root)
    protocol_bound = any(
        _schema_name == "measurement-protocol"
        and digest_v3_json(cast(JsonValue, value)) == result.get("protocol_digest")
        for record, value in projections
        for _schema_name in [str(record.get("schema_ref", "")).split("@", 1)[0]]
    )
    valid = not name_errors and signature.get("status") == "true" and scope_ok and protocol_bound
    return _meta(
        {
            "command_status": "ok" if valid else "failed",
            "failure_code": None if valid else "trial_result_invalid",
            "trial_result": str(result_path.resolve()),
            "raw_artifact_digest": digest_bytes(raw),
            "schema_errors": name_errors,
            "signature_verification": signature,
            "scope_status": "true" if scope_ok else "false",
            "protocol_binding_status": "true" if protocol_bound else "false",
            "source_system": source_system,
            "trial_imported": False,
        },
        effect_class="inspect",
        authority_required=[str(result.get("evaluator_key_id", "unknown"))],
        next_commands=[
            [
                "cpcf",
                "trial",
                "import",
                str(result_path),
                "--workspace",
                str(root),
                "--apply",
                "--json",
            ]
        ]
        if valid
        else [],
    )


def import_trial_v3(result_path: Path, root: Path, *, apply: bool) -> JsonObject:
    try:
        result = load_json_strict(result_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return _failed("trial_import_failed", detail=str(error))
    if not isinstance(result, dict):
        return _failed("trial_result_not_object")
    inspected = inspect_trial_v3(result_path, root)
    if inspected.get("command_status") != "ok":
        return inspected
    source_system = _trial_source_system(root, result)
    if source_system is None:
        return _failed("trusted_evaluator_source_system_missing")
    return import_source_v3(
        result_path,
        root,
        source_system,
        "trial-result-certificate@0.3.0",
        apply=apply,
    )
