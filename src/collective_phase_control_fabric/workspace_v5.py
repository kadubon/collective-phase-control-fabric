# SPDX-License-Identifier: Apache-2.0
"""Native v0.5 workspace, complete ledger doctor, migration, and onboarding."""

from __future__ import annotations

import shutil
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_v3_json, write_canonical
from collective_phase_control_fabric.generation_v5 import (
    KIND_SCHEMAS,
    V5,
    GenerationStoreV5,
    empty_generation_v5,
    history_event,
    ledger_entry,
)
from collective_phase_control_fabric.limits import MAX_RAW_BYTES, LimitExceeded, load_json_bounded
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.trust_v5 import (
    QUORUM_ROLES,
    validate_policy,
    verify_genesis,
    verify_role_quorum,
    verify_statement,
    verify_time_receipt,
)
from collective_phase_control_fabric.types import JsonObject, JsonValue

MANDATORY_DIMENSIONS = {
    "provenance_integrity",
    "trust_quorum",
    "temporal_integrity",
    "structural_reachability",
    "causal_formation",
    "dimensional_consistency",
    "exact_self_maintenance",
    "finite_horizon_resource_persistence",
    "target_bound_generative_catalysis",
    "verification_capacity",
    "effective_independence",
    "coordination_protocol_integrity",
    "perturbation_robustness",
}


def scaffold_contract_v5(output: Path, profile: str) -> JsonObject:
    if output.exists():
        return response("failed", "output_already_exists")
    missing = [
        "contract.contract_id",
        "contract.scope",
        "contract.target_states",
        "contract.initial_available_states",
        "contract.protected_floors",
        "contract.resource_envelope",
        "contract.perturbation_suite_refs",
        "contract.minimum_effective_independence",
        "unit_registry.base_dimensions",
        "unit_registry.units",
        "trust_policy.principals",
        "trust_policy.root_key_id",
        "genesis_statement",
        "trusted_time_principal",
    ]
    if profile == "measured":
        missing.extend(
            [
                "measurement_protocol.design_tier",
                "measurement_protocol.eligibility",
                "measurement_protocol.strategies",
                "measurement_protocol.assignment",
                "measurement_protocol.estimand",
                "measurement_protocol.primary_outcomes",
                "measurement_protocol.multiplicity_policy",
                "measurement_protocol.dataset_record",
                "measurement_protocol.analysis_executable_record",
                "registration_principal",
                "evaluator_principal",
                "quality_safety_verifier_principal",
            ]
        )
    draft: JsonObject = {
        "schema_version": V5,
        "draft_id": f"contract-draft:{profile}",
        "profile": profile,
        "proposed_contract": {
            "schema_version": V5,
            "control_policy": {
                "planning_horizon": 1,
                "beam_width": 32,
                "candidate_cap": 64,
                "retry_limit": 0,
            },
            "required_dimensions": sorted(MANDATORY_DIMENSIONS),
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
    registry_draft: JsonObject = {
        "schema_version": V5,
        "registry_id": "USER_DECISION_REQUIRED",
        "base_dimensions": [],
        "units": {},
    }
    trust_draft: JsonObject = {
        "schema_version": V5,
        "policy_id": "USER_DECISION_REQUIRED",
        "policy_sequence": 0,
        "previous_policy_digest": None,
        "root_key_id": "USER_DECISION_REQUIRED",
        "principals": [],
        "quorum_rules": {key: list(value) for key, value in QUORUM_ROLES.items()},
    }
    output.mkdir(parents=True)
    targets = {
        "contract-draft.json": draft,
        "unit-registry-draft.json": registry_draft,
        "trust-policy-draft.json": trust_draft,
    }
    for name, value in targets.items():
        write_canonical(output / name, value)
    return response(
        "ok",
        None,
        effect_class="local_write",
        files_written=[str((output / name).absolute()) for name in targets],
        unknowns=missing,
        next_commands=[
            ["cpcf", "contract", "explain-missing", str(output / "contract-draft.json"), "--json"]
        ],
        draft_executable=False,
        missing_decisions=missing,
    )


def explain_missing_contract_v5(path: Path) -> JsonObject:
    try:
        value = load_json_bounded(path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "contract_draft_invalid", detail=str(error))
    if not isinstance(value, dict) or value.get("schema_version") != V5:
        return response("failed", "contract_draft_not_v0.5")
    missing = [str(item) for item in value.get("missing_decisions", [])]
    return response("ok", None, unknowns=missing, draft_executable=False, missing_decisions=missing)


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


def _read_raw(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_RAW_BYTES + 1)
    if len(data) > MAX_RAW_BYTES:
        raise LimitExceeded("maximum_raw_bytes_exceeded", observed=len(data), maximum=MAX_RAW_BYTES)
    return data


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _pointer(value: JsonValue, pointer: str) -> JsonValue:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must be empty or start with slash")
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


def workspace_version(root: Path) -> str | None:
    current = root / ".cpcf" / "CURRENT"
    if current.is_file():
        try:
            with current.open("rb") as stream:
                identifier = stream.read(73).decode("ascii").strip()
            if len(identifier) != 71 or not identifier.startswith("sha256:"):
                return None
            manifest = root / ".cpcf" / "generations" / identifier[7:] / "manifest.json"
            value = load_json_bounded(manifest)
            return str(value.get("schema_version")) if isinstance(value, dict) else None
        except (OSError, UnicodeDecodeError, ValueError):
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


def _documents(store: GenerationStoreV5, manifest: JsonObject) -> tuple[JsonObject, JsonObject]:
    contract = store.get_json(str(manifest["contract_digest"]))
    policy = store.get_json(str(manifest["trust_policy_digest"]))
    if not isinstance(contract, dict) or not isinstance(policy, dict):
        raise ValueError("contract and trust policy must be objects")
    return contract, policy


def _current_time(
    store: GenerationStoreV5, manifest: JsonObject, policy: JsonObject
) -> tuple[str | None, JsonObject | None]:
    digest = manifest.get("trusted_time_receipt_digest")
    if not isinstance(digest, str):
        return None, None
    receipt = store.get_json(digest)
    if not isinstance(receipt, dict):
        return None, None
    checked = verify_time_receipt(receipt, policy)
    return (
        (str(checked["event_time"]), checked)
        if checked.get("status") == "true"
        else (None, checked)
    )


def inspect_genesis_v5(
    policy_path: Path, genesis_path: Path, root_fingerprint: str, time_receipt_path: Path
) -> JsonObject:
    try:
        policy = load_json_bounded(policy_path)
        genesis = load_json_bounded(genesis_path)
        time_receipt = load_json_bounded(time_receipt_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trust_genesis_input_invalid", detail=str(error))
    if (
        not isinstance(policy, dict)
        or not isinstance(genesis, dict)
        or not isinstance(time_receipt, dict)
    ):
        return response("failed", "trust_genesis_input_not_object")
    time_payload = time_receipt.get("payload")
    event_time = time_payload.get("event_time") if isinstance(time_payload, dict) else None
    time_check = verify_time_receipt(time_receipt, policy)
    genesis_check = verify_genesis(policy, genesis, root_fingerprint, str(event_time))
    valid = time_check.get("status") == "true" and genesis_check.get("status") == "true"
    return response(
        "ok" if valid else "failed",
        None if valid else "trust_genesis_invalid",
        effect_class="validate",
        claims=["complete_genesis_policy_authenticated"] if valid else [],
        unknowns=[] if valid else ["workspace_trust_genesis"],
        genesis_verification=genesis_check,
        time_verification=time_check,
    )


def validate_policy_v5(path: Path, root_fingerprint: str | None = None) -> JsonObject:
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
        claims=["role_quorum_policy_structurally_valid"] if not errors else [],
        schema_errors=errors,
        threshold_cryptography=False,
    )


def inspect_time_receipt_v5(receipt_path: Path, policy_path: Path) -> JsonObject:
    try:
        receipt = load_json_bounded(receipt_path)
        policy = load_json_bounded(policy_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trusted_time_input_invalid", detail=str(error))
    if not isinstance(receipt, dict) or not isinstance(policy, dict):
        return response("failed", "trusted_time_input_not_object")
    checked = verify_time_receipt(receipt, policy)
    valid = checked.get("status") == "true"
    return response(
        "ok" if valid else "failed",
        None if valid else "trusted_time_receipt_invalid",
        effect_class="validate",
        claims=["trusted_time_receipt_valid"] if valid else [],
        unknowns=[] if valid else ["authoritative_time"],
        verification=checked,
    )


def inspect_signed_object_v5(statement_path: Path, policy_path: Path) -> JsonObject:
    try:
        statement = load_json_bounded(statement_path)
        policy = load_json_bounded(policy_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "signed_object_input_invalid", detail=str(error))
    if not isinstance(statement, dict) or not isinstance(policy, dict):
        return response("failed", "signed_object_input_not_object")
    signed_at = statement.get("protected", {}).get("signed_at")
    checked = verify_statement(statement, policy, authoritative_time=str(signed_at))
    valid = checked.get("status") == "true"
    return response(
        "ok" if valid else "failed",
        None if valid else "signed_object_invalid",
        effect_class="validate",
        claims=["signed_object_valid_at_signing_time"] if valid else [],
        unknowns=["current_lifecycle"] if valid else ["signature_authority"],
        verification=checked,
    )


def initialize_workspace_v5(
    contract_path: Path,
    policy_path: Path,
    genesis_path: Path,
    unit_registry_path: Path,
    output: Path,
    root_fingerprint: str,
    time_receipt_path: Path,
) -> JsonObject:
    """Create a root-authenticated native v0.5 generation."""

    if output.exists():
        return response("failed", "output_already_exists")
    try:
        contract = load_json_bounded(contract_path)
        policy = load_json_bounded(policy_path)
        genesis = load_json_bounded(genesis_path)
        registry = load_json_bounded(unit_registry_path)
        time_receipt = load_json_bounded(time_receipt_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "workspace_input_invalid", detail=str(error))
    if not all(
        isinstance(item, dict) for item in (contract, policy, genesis, registry, time_receipt)
    ):
        return response("failed", "workspace_input_not_object")
    contract = cast(JsonObject, contract)
    policy = cast(JsonObject, policy)
    genesis = cast(JsonObject, genesis)
    registry = cast(JsonObject, registry)
    time_receipt = cast(JsonObject, time_receipt)
    errors: list[JsonObject] = []
    errors.extend(
        {"domain": "contract", **item} for item in validation_errors("phase-contract", contract, V5)
    )
    errors.extend(
        {"domain": "policy", **item} for item in validate_policy(policy, root_fingerprint)
    )
    errors.extend(
        {"domain": "unit_registry", **item}
        for item in validation_errors("unit-registry", registry, V5)
    )
    registry_digest = digest_v3_json(registry)
    if contract.get("unit_registry_ref") != registry_digest:
        errors.append({"domain": "contract", "message": "unit_registry_ref digest mismatch"})
    required = {str(item) for item in contract.get("required_dimensions", [])}
    if required != MANDATORY_DIMENSIONS:
        errors.append(
            {"domain": "contract", "message": "all native operational dimensions are mandatory"}
        )
    contract_digest = digest_v3_json(contract)
    time_check = verify_time_receipt(time_receipt, policy, expected_subject_digest=contract_digest)
    event_time = str(time_check.get("event_time"))
    genesis_check = verify_genesis(policy, genesis, root_fingerprint, event_time)
    if time_check.get("status") != "true":
        errors.append(
            {
                "domain": "trusted_time",
                "message": "trusted time receipt invalid",
                "reasons": time_check.get("reasons", []),
            }
        )
    if genesis_check.get("status") != "true":
        errors.append(
            {
                "domain": "trust_genesis",
                "message": "genesis statement invalid",
                "reasons": genesis_check.get("reasons", []),
            }
        )
    if errors:
        return response("failed", "workspace_input_invalid", validation_errors=errors)
    output.mkdir(parents=True)
    try:
        store = GenerationStoreV5(output)
        contract_cas = store.put_json(contract)
        policy_cas = store.put_json(policy)
        genesis_cas = store.put_json(genesis)
        registry_cas = store.put_json(registry)
        time_cas = store.put_json(time_receipt)
        objects = [
            ledger_entry(contract_cas, kind="contract", schema_ref="phase-contract@0.5.0"),
            ledger_entry(registry_cas, kind="unit-registry", schema_ref="unit-registry@0.5.0"),
            ledger_entry(
                policy_cas,
                kind="trust-policy",
                schema_ref="trust-policy@0.5.0",
                authority_key_id=str(policy["root_key_id"]),
            ),
            ledger_entry(
                genesis_cas,
                kind="genesis-policy-statement",
                schema_ref="signed-statement@0.5.0",
                source_chain=[policy_cas],
                authority_key_id=str(policy["root_key_id"]),
                authority_policy_digest=policy_cas,
            ),
            ledger_entry(
                time_cas,
                kind="trusted-time-receipt",
                schema_ref="signed-statement@0.5.0",
                source_chain=[contract_cas],
                authority_key_id=str(time_receipt["protected"]["key_id"]),
                authority_policy_digest=policy_cas,
            ),
        ]
        payload = empty_generation_v5(
            contract_digest=contract_cas,
            trust_policy_digest=policy_cas,
            trusted_time_receipt_digest=time_cas,
            analysis_epoch=event_time,
            objects=objects,
        )
        payload["history"] = [
            history_event(
                [],
                event_id="history:workspace-initialized",
                event_type="workspace_initialized",
                subject_digests=[contract_cas, policy_cas, genesis_cas, registry_cas, time_cas],
            )
        ]
        committed = store.commit(payload, expected_current=None)
        if committed.get("command_status") != "ok":
            raise RuntimeError(str(committed))
    except Exception as error:
        shutil.rmtree(output, ignore_errors=True)
        return response("failed", "workspace_initialization_failed", detail=str(error))
    generation = str(committed["generation_id"])
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=generation,
        files_written=[str(store.current_path), str(store.manifest_path(generation))],
        authority_required=[str(policy["root_key_id"])],
        claims=["root_authenticated_immutable_generation_created"],
        next_commands=[
            ["cpcf", "agent", "onboard", "--workspace", str(output), "--compact", "--json"]
        ],
        workspace=str(output.absolute()),
        schema_version=V5,
        execution_allowed=False,
    )


def import_raw_v5(
    source_path: Path, root: Path, source_system: str, schema_ref: str, *, apply: bool
) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        manifest = store.load_manifest()
        data = _read_raw(source_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "source_read_failed", detail=str(error))
    digest = store.put_bytes(data)
    if not apply:
        return response(
            "failed", "apply_required", generation=str(manifest["generation_id"]), raw_digest=digest
        )
    if any(
        isinstance(item, dict) and item.get("digest") == digest
        for item in manifest.get("objects", [])
    ):
        return response(
            "failed",
            "source_already_imported",
            generation=str(manifest["generation_id"]),
            raw_digest=digest,
        )
    payload = deepcopy(manifest)
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(digest, kind="raw-artifact", schema_ref=schema_ref),
    ]
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:raw:{digest[7:]}",
            event_type="object_imported",
            subject_digests=[digest],
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
        claims=["raw_bytes_preserved"],
        raw_digest=digest,
        source_system=source_system,
        source_path=str(source_path.absolute()),
    )


def _validate_attestation(
    store: GenerationStoreV5,
    statement: JsonObject,
    policy: JsonObject,
    epoch: str,
    object_digests: set[str],
) -> list[str]:
    reasons: list[str] = []
    checked = verify_statement(
        statement,
        policy,
        authoritative_time=epoch,
        expected_schema_ref="principal-attestation@0.5.0",
    )
    reasons.extend(str(item) for item in checked.get("reasons", []))
    payload = statement.get("payload")
    if not isinstance(payload, dict):
        return sorted(set([*reasons, "attestation_payload_missing"]))
    raw_digest = payload.get("source_artifact_digest")
    if not isinstance(raw_digest, str) or raw_digest not in object_digests:
        reasons.append("source_artifact_not_in_generation")
        return sorted(set(reasons))
    try:
        raw = store.get_json(raw_digest)
        projected = _pointer(raw, str(payload.get("source_pointer", "")))
    except (OSError, ValueError):
        reasons.append("source_projection_not_reproducible")
    else:
        if digest_v3_json(projected) != payload.get("subject_digest"):
            reasons.append("source_projection_digest_mismatch")
    valid_from = _time(payload.get("valid_from"))
    valid_until = _time(payload.get("valid_until"))
    evaluated = _time(epoch)
    if (
        valid_from is None
        or valid_until is None
        or evaluated is None
        or not (valid_from <= evaluated <= valid_until)
    ):
        reasons.append("attestation_outside_lifecycle_interval")
    if payload.get("lifecycle") != "active":
        reasons.append("attestation_lifecycle_not_active")
    return sorted(set(reasons))


def import_attestation_v5(statement_path: Path, root: Path, *, apply: bool) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        manifest = store.load_manifest()
        _, policy = _documents(store, manifest)
        epoch, _ = _current_time(store, manifest, policy)
        value = load_json_bounded(statement_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "attestation_import_input_invalid", detail=str(error))
    if epoch is None:
        return response("failed", "authoritative_time_receipt_required")
    if not isinstance(value, dict):
        return response("failed", "attestation_not_object")
    object_digests = {
        str(item.get("digest")) for item in manifest.get("objects", []) if isinstance(item, dict)
    }
    reasons = _validate_attestation(store, value, policy, epoch, object_digests)
    if reasons:
        return response("failed", "attestation_not_source_backed", reasons=reasons)
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    digest = store.put_json(value)
    if digest in object_digests:
        return response("failed", "attestation_already_imported")
    raw_digest = str(value["payload"]["source_artifact_digest"])
    payload = deepcopy(manifest)
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(
            digest,
            kind="principal-attestation",
            schema_ref="signed-statement@0.5.0",
            source_chain=[raw_digest],
            authority_key_id=str(value["protected"]["key_id"]),
            authority_policy_digest=str(manifest["trust_policy_digest"]),
        ),
    ]
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:attestation:{digest[7:]}",
            event_type="object_imported",
            subject_digests=[digest, raw_digest],
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
        claims=["typed_source_attestation_imported"],
        attestation_digest=digest,
    )


SIGNED_IMPORT_KINDS = {
    "dataset-record": "dataset-record",
    "analysis-executable-record": "analysis-executable-record",
    "typed-flow-profile": "scientific-witness",
    "formation-sequence-witness": "scientific-witness",
    "organization-witness": "scientific-witness",
    "generalized-raf-witness": "scientific-witness",
    "siphon-coverage-witness": "scientific-witness",
    "rate-feasibility-witness": "scientific-witness",
    "verification-network-witness": "scientific-witness",
    "evidence-tier": "acceleration-evidence",
    "adapter-capability": "adapter-capability",
    "execution-policy": "execution-policy",
}


def import_signed_object_v5(statement_path: Path, root: Path, *, apply: bool) -> JsonObject:
    """Import one registered signed object without bypassing specialized protocol workflows."""

    try:
        store = GenerationStoreV5(root)
        manifest = store.load_manifest()
        _, policy = _documents(store, manifest)
        epoch, _ = _current_time(store, manifest, policy)
        statement = load_json_bounded(statement_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "signed_object_input_invalid", detail=str(error))
    if epoch is None or not isinstance(statement, dict):
        return response("failed", "signed_object_or_authoritative_time_missing")
    schema_ref = statement.get("protected", {}).get("schema_ref")
    if not isinstance(schema_ref, str) or "@" not in schema_ref:
        return response("failed", "signed_object_schema_missing")
    schema_name = schema_ref.rsplit("@", 1)[0]
    if schema_name == "principal-attestation":
        return import_attestation_v5(statement_path, root, apply=apply)
    kind = SIGNED_IMPORT_KINDS.get(schema_name)
    if kind is None:
        return response(
            "failed",
            "signed_object_requires_specialized_workflow",
            next_commands=[
                ["cpcf", "agent", "onboard", "--workspace", str(root), "--compact", "--json"]
            ],
            schema_name=schema_name,
        )
    checked = verify_statement(
        statement, policy, authoritative_time=epoch, expected_schema_ref=schema_ref
    )
    if checked.get("status") != "true":
        return response("failed", "signed_object_invalid", reasons=checked.get("reasons", []))
    payload_value = statement.get("payload")
    if not isinstance(payload_value, dict):
        return response("failed", "signed_object_payload_missing")
    entries = [item for item in manifest.get("objects", []) if isinstance(item, dict)]
    available = {str(item.get("digest")) for item in entries}
    source_chain: list[str] = []
    for field, value in payload_value.items():
        if (
            field.endswith("_digest")
            and isinstance(value, str)
            and value.startswith("sha256:")
            and value in available
        ):
            source_chain.append(value)
    if schema_name in {"dataset-record", "analysis-executable-record"} and not source_chain:
        return response("failed", "signed_object_source_chain_missing")
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    statement_digest = store.put_json(statement)
    if statement_digest in available:
        return response("failed", "signed_object_already_imported")
    payload = deepcopy(manifest)
    new_entries = [
        ledger_entry(
            statement_digest,
            kind=kind,
            schema_ref="signed-statement@0.5.0",
            source_chain=sorted(set(source_chain)),
            authority_key_id=str(statement["protected"]["key_id"]),
            authority_policy_digest=str(manifest["trust_policy_digest"]),
        )
    ]
    promoted_payload_digest: str | None = None
    if schema_name == "typed-flow-profile":
        promoted_payload_digest = store.put_json(payload_value)
        new_entries.append(
            ledger_entry(
                promoted_payload_digest,
                kind="typed-flow-profile",
                schema_ref="typed-flow-profile@0.5.0",
                source_chain=[statement_digest],
                authority_key_id=str(statement["protected"]["key_id"]),
                authority_policy_digest=str(manifest["trust_policy_digest"]),
            )
        )
    payload["objects"] = [*payload.get("objects", []), *new_entries]
    history = cast(list[JsonObject], payload.get("history", []))
    subjects = [statement_digest, *([promoted_payload_digest] if promoted_payload_digest else [])]
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:signed:{statement_digest[7:]}",
            event_type="object_imported",
            subject_digests=subjects,
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
        claims=["registered_signed_object_imported"],
        object_digest=statement_digest,
        promoted_payload_digest=promoted_payload_digest,
        object_kind=kind,
    )


def active_attestations_v5(
    root: Path,
) -> tuple[JsonObject, JsonObject, list[JsonObject], list[JsonObject]]:
    store = GenerationStoreV5(root)
    manifest = store.load_manifest()
    contract, policy = _documents(store, manifest)
    epoch, _ = _current_time(store, manifest, policy)
    valid: list[JsonObject] = []
    rejected: list[JsonObject] = []
    if epoch is None:
        return manifest, contract, [], [{"code": "authoritative_time_receipt_required"}]
    object_digests = {
        str(item.get("digest")) for item in manifest.get("objects", []) if isinstance(item, dict)
    }
    for entry in manifest.get("objects", []):
        if not isinstance(entry, dict) or entry.get("kind") != "principal-attestation":
            continue
        digest = str(entry.get("digest"))
        try:
            statement = store.get_json(digest)
        except (OSError, ValueError) as error:
            rejected.append({"digest": digest, "reasons": [str(error)]})
            continue
        if not isinstance(statement, dict):
            rejected.append({"digest": digest, "reasons": ["statement_not_object"]})
            continue
        reasons = _validate_attestation(store, statement, policy, epoch, object_digests)
        if reasons:
            rejected.append({"digest": digest, "reasons": reasons})
        else:
            valid.append(statement)
    return manifest, contract, valid, rejected


def doctor_v5(root: Path, *, quick: bool = False) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        errors = store.verify_chain()
        manifest = store.load_manifest()
        contract, policy = _documents(store, manifest)
    except (OSError, ValueError) as error:
        return response("failed", "workspace_generation_invalid", detail=str(error))
    errors.extend(
        {"code": "contract_schema_invalid", **item}
        for item in validation_errors("phase-contract", contract, V5)
    )
    errors.extend({"code": "trust_policy_invalid", **item} for item in validate_policy(policy))
    entries = [item for item in manifest.get("objects", []) if isinstance(item, dict)]
    digests = {str(item.get("digest")) for item in entries}
    identifiers: set[str] = set()
    duplicate_identifiers: set[str] = set()
    epoch, time_check = _current_time(store, manifest, policy)
    for entry in entries:
        digest = str(entry.get("digest"))
        errors.extend(
            {"code": "ledger_entry_invalid", "digest": digest, **item}
            for item in validation_errors("object-ledger-entry", entry, V5)
        )
        kind = str(entry.get("kind"))
        registered_schema = KIND_SCHEMAS.get(kind)
        if kind not in KIND_SCHEMAS:
            errors.append({"code": "ledger_kind_unregistered", "digest": digest, "kind": kind})
        if not store.cas.verify(digest):
            errors.append({"code": "cas_digest_invalid", "digest": digest})
            continue
        expected_schema_ref = (
            f"{registered_schema}@0.5.0" if registered_schema is not None else None
        )
        if expected_schema_ref is not None and entry.get("schema_ref") != expected_schema_ref:
            errors.append(
                {
                    "code": "ledger_kind_schema_mismatch",
                    "digest": digest,
                    "expected_schema_ref": expected_schema_ref,
                }
            )
        for source in entry.get("source_chain", []):
            if source not in digests:
                errors.append(
                    {"code": "ledger_source_reference_missing", "digest": digest, "source": source}
                )
        if quick or registered_schema is None:
            continue
        try:
            value = store.get_json(digest)
        except (OSError, ValueError) as error:
            errors.append(
                {"code": "ledger_object_parse_failed", "digest": digest, "detail": str(error)}
            )
            continue
        errors.extend(
            {"code": "ledger_object_schema_invalid", "digest": digest, **item}
            for item in validation_errors(registered_schema, value, V5)
        )
        if isinstance(value, dict):
            inner = value.get("payload") if isinstance(value.get("payload"), dict) else value
            primary_fields = {
                "principal-attestation": "attestation_id",
                "trusted-time-receipt": "receipt_id",
                "process-receipt": "receipt_id",
                "action-receipt": "receipt_id",
                "pending-projection": "projection_id",
                "projection-approval": "approval_id",
                "coordination-session": "session_id",
                "measurement-protocol": "protocol_id",
                "registration-receipt": "receipt_id",
                "protocol-amendment": "amendment_id",
                "dataset-record": "dataset_id",
                "analysis-executable-record": "executable_id",
                "trial-result-certificate": "result_id",
            }
            field = primary_fields.get(kind)
            identifier = inner.get(field) if field is not None and isinstance(inner, dict) else None
            if isinstance(identifier, str):
                typed_identifier = f"{kind}:{identifier}"
                if typed_identifier in identifiers:
                    duplicate_identifiers.add(typed_identifier)
                identifiers.add(typed_identifier)
            if registered_schema == "signed-statement" and epoch is not None:
                authority_policy_digest = entry.get("authority_policy_digest")
                authority_policy = (
                    store.get_json(str(authority_policy_digest))
                    if isinstance(authority_policy_digest, str)
                    else None
                )
                if not isinstance(authority_policy, dict):
                    errors.append(
                        {"code": "signed_object_authority_policy_missing", "digest": digest}
                    )
                else:
                    checked = verify_statement(value, authority_policy, authoritative_time=epoch)
                    if checked.get("status") != "true":
                        errors.append(
                            {
                                "code": "signed_ledger_object_invalid",
                                "digest": digest,
                                "reasons": checked.get("reasons", []),
                            }
                        )
                if entry.get("authority_key_id") != value.get("protected", {}).get("key_id"):
                    errors.append({"code": "ledger_authority_key_mismatch", "digest": digest})
            if kind == "principal-attestation" and isinstance(value.get("payload"), dict):
                raw_digest = value["payload"].get("source_artifact_digest")
                if raw_digest not in entry.get("source_chain", []):
                    errors.append({"code": "attestation_source_chain_incomplete", "digest": digest})
            if kind == "typed-flow-profile":
                sources = [str(item) for item in entry.get("source_chain", [])]
                signed_sources = []
                for source in sources:
                    try:
                        source_value = store.get_json(source)
                    except (OSError, ValueError):
                        continue
                    if (
                        isinstance(source_value, dict)
                        and source_value.get("payload") == value
                        and source_value.get("protected", {}).get("schema_ref")
                        == "typed-flow-profile@0.5.0"
                    ):
                        signed_sources.append(source)
                if len(signed_sources) != 1:
                    errors.append(
                        {"code": "typed_flow_signed_projection_mismatch", "digest": digest}
                    )
            if kind == "process-receipt":
                required_sources = {
                    str(value.get("executable_digest")),
                    *[str(item) for item in value.get("material_digests", [])],
                }
                if not required_sources <= set(entry.get("source_chain", [])):
                    errors.append(
                        {"code": "process_receipt_source_chain_incomplete", "digest": digest}
                    )
            if kind == "action-receipt":
                required_sources = {
                    str(value.get("process_receipt_digest")),
                    str(value.get("raw_output_digest")),
                    *[str(item) for item in value.get("pending_projection_digests", [])],
                }
                if not required_sources <= set(entry.get("source_chain", [])):
                    errors.append(
                        {"code": "action_receipt_source_chain_incomplete", "digest": digest}
                    )
    errors.extend(
        {"code": "duplicate_semantic_identifier", "identifier": item}
        for item in sorted(duplicate_identifiers)
    )
    if time_check is None or time_check.get("status") != "true":
        errors.append({"code": "authoritative_time_receipt_missing_or_invalid"})
    rejected: list[JsonObject] = []
    if not quick:
        try:
            _, _, _, rejected = active_attestations_v5(root)
        except (OSError, ValueError) as error:
            errors.append({"code": "attestation_recomputation_failed", "detail": str(error)})
        errors.extend({"code": "attestation_not_source_backed", **item} for item in rejected)
    quarantine = [str(item) for item in manifest.get("quarantine", [])]
    for digest in quarantine:
        if digest not in digests:
            errors.append({"code": "quarantine_reference_missing", "digest": digest})
    cas_root = store.control / "cas" / "sha256"
    orphaned: list[str] = []
    if cas_root.is_dir():
        for path in cas_root.rglob("*"):
            if path.is_file():
                relative = "".join(path.relative_to(cas_root).parts)
                digest = f"sha256:{relative}"
                if digest not in digests:
                    orphaned.append(digest)
    execution_allowed = not errors and not quick and epoch is not None and not quarantine
    return response(
        "ok" if not errors else "failed",
        None if not errors else "workspace_audit_failed",
        effect_class="validate",
        generation=str(manifest["generation_id"]),
        claims=["complete_typed_ledger_reference_closure"] if not errors else [],
        unknowns=[] if execution_allowed else ["execution_eligibility"],
        quarantined=quarantine,
        errors=errors,
        orphaned_cas_objects=sorted(orphaned),
        strict=not quick,
        execution_allowed=execution_allowed,
        analysis_epoch=epoch,
    )


def status_v5(root: Path) -> JsonObject:
    version = workspace_version(root)
    if version != V5:
        return response(
            "ok",
            "legacy_workspace_inspect_only",
            unknowns=["execution_eligibility"],
            next_commands=[
                ["cpcf", "workspace", "migrate", "--workspace", str(root), "--to", V5, "--json"]
            ],
            schema_version=version,
            execution_allowed=False,
        )
    manifest = GenerationStoreV5(root).load_manifest()
    audit = doctor_v5(root)
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        quarantined=list(cast(list[str], manifest.get("quarantine", []))),
        schema_version=V5,
        execution_allowed=audit.get("execution_allowed", False),
        audit_status=audit.get("status"),
        analysis_epoch=manifest.get("analysis_epoch"),
    )


def advance_time_v5(root: Path, receipt_path: Path, *, apply: bool) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        manifest = store.load_manifest()
        _, policy = _documents(store, manifest)
        current_epoch, current_report = _current_time(store, manifest, policy)
        receipt = load_json_bounded(receipt_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trusted_time_advance_input_invalid", detail=str(error))
    if current_epoch is None or current_report is None or not isinstance(receipt, dict):
        return response("failed", "authoritative_time_receipt_required")
    checked = verify_time_receipt(
        receipt, policy, expected_subject_digest=str(manifest["generation_id"])
    )
    reasons = list(checked.get("reasons", []))
    try:
        new_time = _time(checked.get("event_time"))
        old_time = _time(current_epoch)
        if new_time is None or old_time is None or new_time <= old_time:
            reasons.append("trusted_time_not_monotonic")
        if int(checked.get("serial", -1)) <= int(current_report.get("serial", -1)):
            reasons.append("trusted_time_serial_not_monotonic")
    except (TypeError, ValueError):
        reasons.append("trusted_time_sequence_invalid")
    if reasons:
        return response("failed", "trusted_time_advance_invalid", reasons=sorted(set(reasons)))
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    digest = store.put_json(receipt)
    payload = deepcopy(manifest)
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(
            digest,
            kind="trusted-time-receipt",
            schema_ref="signed-statement@0.5.0",
            source_chain=[str(manifest["generation_id"])],
            authority_key_id=str(receipt["protected"]["key_id"]),
            authority_policy_digest=str(manifest["trust_policy_digest"]),
        ),
    ]
    # A generation digest may be referenced by a history event but is not an object-ledger source.
    payload["objects"][-1]["source_chain"] = []
    payload["trusted_time_receipt_digest"] = digest
    payload["analysis_epoch"] = checked["event_time"]
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:time:{digest[7:]}",
            event_type="time_advanced",
            subject_digests=[digest],
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
        claims=["authoritative_time_advanced"],
        analysis_epoch=checked["event_time"],
    )


def update_trust_policy_v5(
    root: Path,
    policy_path: Path,
    time_receipt_path: Path,
    quorum_statement_paths: list[Path],
    *,
    apply: bool,
) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        manifest = store.load_manifest()
        _, old_policy = _documents(store, manifest)
        current_epoch, _ = _current_time(store, manifest, old_policy)
        new_policy = load_json_bounded(policy_path)
        time_receipt = load_json_bounded(time_receipt_path)
        quorum_statements = [load_json_bounded(path) for path in quorum_statement_paths]
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trust_update_input_invalid", detail=str(error))
    if (
        current_epoch is None
        or not isinstance(new_policy, dict)
        or not isinstance(time_receipt, dict)
        or not all(isinstance(item, dict) for item in quorum_statements)
    ):
        return response("failed", "trust_update_input_not_object")
    new_digest = digest_v3_json(new_policy)
    reasons = [str(item["message"]) for item in validate_policy(new_policy)]
    if new_policy.get("policy_sequence") != int(old_policy.get("policy_sequence", -1)) + 1:
        reasons.append("trust_policy_sequence_not_monotonic")
    if new_policy.get("previous_policy_digest") != manifest.get("trust_policy_digest"):
        reasons.append("trust_policy_previous_digest_mismatch")
    time_check = verify_time_receipt(time_receipt, old_policy, expected_subject_digest=new_digest)
    reasons.extend(str(item) for item in time_check.get("reasons", []))
    quorum = verify_role_quorum(
        cast(list[JsonObject], quorum_statements),
        old_policy,
        decision_type="trust_update",
        authoritative_time=str(time_check.get("event_time", current_epoch)),
        subject_digest=new_digest,
    )
    reasons.extend(str(item) for item in quorum.get("reasons", []))
    if reasons:
        return response("failed", "trust_update_quorum_invalid", reasons=sorted(set(reasons)))
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    policy_digest = store.put_json(new_policy)
    time_digest = store.put_json(time_receipt)
    quorum_digests = [store.put_json(cast(JsonObject, item)) for item in quorum_statements]
    objects: list[JsonObject] = []
    for entry in manifest.get("objects", []):
        if isinstance(entry, dict) and entry.get("digest") == manifest.get("trust_policy_digest"):
            objects.append(cast(JsonObject, {**entry, "lifecycle": "withdrawn"}))
        elif isinstance(entry, dict):
            objects.append(entry)
    objects.extend(
        [
            ledger_entry(
                policy_digest,
                kind="trust-policy",
                schema_ref="trust-policy@0.5.0",
                source_chain=quorum_digests,
                authority_key_id=str(new_policy["root_key_id"]),
            ),
            ledger_entry(
                time_digest,
                kind="trusted-time-receipt",
                schema_ref="signed-statement@0.5.0",
                source_chain=[policy_digest],
                authority_key_id=str(time_receipt["protected"]["key_id"]),
                authority_policy_digest=str(manifest["trust_policy_digest"]),
            ),
            *(
                ledger_entry(
                    digest,
                    kind="trust-quorum-decision",
                    schema_ref="signed-statement@0.5.0",
                    source_chain=[policy_digest, time_digest],
                    authority_key_id=str(cast(JsonObject, statement)["protected"]["key_id"]),
                    authority_policy_digest=str(manifest["trust_policy_digest"]),
                )
                for digest, statement in zip(quorum_digests, quorum_statements, strict=True)
            ),
        ]
    )
    payload = deepcopy(manifest)
    payload["objects"] = objects
    payload["trust_policy_digest"] = policy_digest
    payload["trusted_time_receipt_digest"] = time_digest
    payload["analysis_epoch"] = time_check["event_time"]
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:trust:{policy_digest[7:]}",
            event_type="trust_updated",
            subject_digests=[policy_digest, time_digest, *quorum_digests],
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
        claims=["role_quorum_trust_policy_updated"],
        policy_sequence=new_policy["policy_sequence"],
    )


def migrate_workspace_v5(
    old_root: Path,
    contract_path: Path,
    policy_path: Path,
    genesis_path: Path,
    unit_registry_path: Path,
    time_receipt_path: Path,
    output: Path,
    root_fingerprint: str,
) -> JsonObject:
    """Copy raw legacy material and quarantine it behind a fresh v0.5 genesis."""

    initialized = initialize_workspace_v5(
        contract_path,
        policy_path,
        genesis_path,
        unit_registry_path,
        output,
        root_fingerprint,
        time_receipt_path,
    )
    if initialized.get("command_status") != "ok":
        return initialized
    store = GenerationStoreV5(output)
    manifest = store.load_manifest()
    copied: list[str] = []
    source_control = old_root / ".cpcf"
    if source_control.is_dir():
        for path in sorted(source_control.rglob("*"), key=lambda item: str(item)):
            if not path.is_file() or path.name.endswith(".lock"):
                continue
            try:
                data = _read_raw(path)
            except (OSError, LimitExceeded):
                continue
            copied.append(store.put_bytes(data))
    payload = deepcopy(manifest)
    existing = {
        str(item.get("digest")) for item in payload.get("objects", []) if isinstance(item, dict)
    }
    new_digests = sorted(set(copied) - existing)
    payload["objects"] = [
        *payload.get("objects", []),
        *(
            ledger_entry(
                item,
                kind="legacy-manifest",
                schema_ref=f"legacy-workspace@{workspace_version(old_root) or 'unknown'}",
                lifecycle="quarantined",
            )
            for item in new_digests
        ),
    ]
    payload["quarantine"] = sorted(set([*payload.get("quarantine", []), *new_digests]))
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:migration:{manifest['generation_id'][7:]}",
            event_type="legacy_migrated",
            subject_digests=new_digests,
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
        quarantined=new_digests,
        claims=["legacy_raw_material_copied"],
        unknowns=["legacy_authority_revalidation"],
        legacy_schema_version=workspace_version(old_root),
        execution_allowed=False,
    )


def inspect_quorum_v5(
    statement_paths: list[Path], root: Path, decision_type: str, subject_digest: str
) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        manifest = store.load_manifest()
        _, policy = _documents(store, manifest)
        epoch, _ = _current_time(store, manifest, policy)
        statements = [load_json_bounded(path) for path in statement_paths]
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trust_quorum_input_invalid", detail=str(error))
    if epoch is None or not all(isinstance(item, dict) for item in statements):
        return response("failed", "trust_quorum_input_invalid")
    checked = verify_role_quorum(
        cast(list[JsonObject], statements),
        policy,
        decision_type=decision_type,
        authoritative_time=epoch,
        subject_digest=subject_digest,
    )
    return response(
        "ok" if checked.get("status") == "true" else "failed",
        None if checked.get("status") == "true" else "trust_quorum_invalid",
        effect_class="validate",
        generation=str(manifest["generation_id"]),
        claims=[f"{decision_type}_role_quorum_satisfied"]
        if checked.get("status") == "true"
        else [],
        unknowns=[] if checked.get("status") == "true" else [decision_type],
        quorum=checked,
    )


def repairs_v5(root: Path) -> list[JsonObject]:
    audit = doctor_v5(root)
    from collective_phase_control_fabric.planner_v5 import plan_v5
    from collective_phase_control_fabric.science_v5 import science_audit_v5
    from collective_phase_control_fabric.trials_v5 import acceleration_status_v5

    science = science_audit_v5(root)
    planner = plan_v5(root)
    trial = acceleration_status_v5(root)
    repairs: list[JsonObject] = []

    def add(code: str, category: str, command: list[str], authority: list[str]) -> None:
        repair_id = f"repair:{category}:{len(repairs):04d}"
        repairs.append(
            {
                "repair_id": repair_id,
                "category": category,
                "blocker_code": code,
                "binding_status": "unbound_repair",
                "executable": False,
                "authority_required": authority,
                "next_safe_command": command,
            }
        )

    for item in audit.get("errors", []):
        if isinstance(item, dict):
            add(
                str(item.get("code")),
                "trust_or_ledger",
                ["cpcf", "doctor", "--workspace", str(root), "--json"],
                ["workspace_administrator"],
            )
    profile = science.get("operational_organization_profile", {})
    if isinstance(profile, dict):
        for dimension, status in sorted(profile.items()):
            if status != "satisfied":
                add(
                    f"dimension_{status}",
                    str(dimension),
                    ["cpcf", "science", "audit", "--workspace", str(root), "--compact", "--json"],
                    ["source_or_measurement_principal"],
                )
    if planner.get("failure_code") == "candidate_set_overflow_unknown":
        add(
            "candidate_set_overflow_unknown",
            "planner",
            ["cpcf", "control", "next", "--workspace", str(root), "--compact", "--json"],
            ["contract_author"],
        )
    if trial.get("acceleration_status") in {"unmeasured", "registered_not_observed"}:
        add(
            str(trial.get("acceleration_status")),
            "trial",
            ["cpcf", "agent", "onboard", "--workspace", str(root), "--compact", "--json"],
            ["protocol_author", "registration", "timestamp"],
        )
    for _digest in audit.get("quarantined_objects", []):
        add(
            "quarantined_migration_object",
            "quarantine",
            [
                "cpcf",
                "attestation",
                "import",
                "REISSUED.json",
                "--workspace",
                str(root),
                "--apply",
                "--json",
            ],
            ["original_source_principal"],
        )
    unique: dict[tuple[str, str], JsonObject] = {}
    for repair in repairs:
        unique.setdefault((str(repair["category"]), str(repair["blocker_code"])), repair)
    return list(unique.values())


def repair_list_v5(root: Path) -> JsonObject:
    store = GenerationStoreV5(root)
    return response("ok", None, generation=store.current_id(), repairs=repairs_v5(root))


def repair_show_v5(root: Path, repair_id: str) -> JsonObject:
    matches = [item for item in repairs_v5(root) if item.get("repair_id") == repair_id]
    if len(matches) != 1:
        return response("failed", "repair_not_found")
    return response("ok", None, generation=GenerationStoreV5(root).current_id(), repair=matches[0])


def onboard_v5(root: Path) -> JsonObject:
    version = workspace_version(root)
    if version != V5:
        return status_v5(root)
    audit = doctor_v5(root)
    from collective_phase_control_fabric.coordination_v5 import coordination_status_v5
    from collective_phase_control_fabric.planner_v5 import plan_v5
    from collective_phase_control_fabric.science_v5 import science_audit_v5
    from collective_phase_control_fabric.trials_v5 import acceleration_status_v5

    science = science_audit_v5(root)
    planner = plan_v5(root)
    trials = acceleration_status_v5(root)
    coordination = coordination_status_v5(root)
    blockers = sorted(
        {
            *(str(item.get("code")) for item in audit.get("errors", []) if isinstance(item, dict)),
            *(f"science:{item}" for item in science.get("unknowns", [])),
            *(f"planner:{item}" for item in planner.get("unknowns", [])),
            *(f"trial:{item}" for item in trials.get("unknowns", [])),
            *(f"coordination:{item}" for item in coordination.get("unknowns", [])),
        }
    )
    commands: list[list[str]] = []
    if audit.get("command_status") != "ok":
        commands.append(["cpcf", "doctor", "--workspace", str(root), "--json"])
    if science.get("operational_organization_compatible") is not True:
        commands.append(
            ["cpcf", "science", "audit", "--workspace", str(root), "--compact", "--json"]
        )
    if planner.get("primary_action") is not None:
        commands.append(
            ["cpcf", "control", "next", "--workspace", str(root), "--compact", "--json"]
        )
    return response(
        "ok",
        None,
        generation=cast(str | None, audit.get("workspace_generation")),
        claims=["native_v0.5_onboarding_audit_completed"],
        unknowns=blockers,
        quarantined=list(cast(list[str], audit.get("quarantined_objects", []))),
        next_commands=commands,
        doctor=audit,
        science=science,
        planner=planner,
        trial=trials,
        coordination=coordination,
    )
