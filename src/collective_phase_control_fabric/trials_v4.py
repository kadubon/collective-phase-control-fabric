# SPDX-License-Identifier: Apache-2.0
"""Externally registered measurement protocol and result bindings for CPCF v0.4."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.generation_v4 import GenerationStoreV4, ledger_entry
from collective_phase_control_fabric.limits import LimitExceeded, load_json_bounded
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.trust_v4 import verify_statement
from collective_phase_control_fabric.types import JsonObject
from collective_phase_control_fabric.workspace_v4 import response

V4 = "0.4.0"


def _time(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed


def _workspace(root: Path) -> tuple[GenerationStoreV4, JsonObject, JsonObject, str]:
    store = GenerationStoreV4(root)
    manifest = store.load_manifest()
    trust = store.get_json(str(manifest["trust_policy_digest"]))
    if not isinstance(trust, dict) or not isinstance(manifest.get("analysis_epoch"), str):
        raise ValueError("workspace trust or authoritative time is unavailable")
    return store, manifest, trust, str(manifest["analysis_epoch"])


def _verify_protocol(
    protocol: JsonObject, registration: JsonObject, trust: JsonObject
) -> tuple[bool, list[str], JsonObject | None]:
    reasons: list[str] = []
    registered_payload = registration.get("payload")
    protocol_payload = protocol.get("payload")
    if not isinstance(registered_payload, dict) or not isinstance(protocol_payload, dict):
        return False, ["protocol_or_registration_payload_missing"], None
    reasons.extend(
        f"protocol_schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("measurement-protocol", protocol_payload, V4)
    )
    reasons.extend(
        f"registration_schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("registration-receipt", registered_payload, V4)
    )
    registered_at = registered_payload.get("registered_at")
    registration_check = verify_statement(
        registration,
        trust,
        authoritative_time=str(registered_at),
        expected_schema_ref="registration-receipt@0.4.0",
        expected_role="registration",
    )
    reasons.extend(str(item) for item in registration_check.get("reasons", []))
    protocol_check = verify_statement(
        protocol,
        trust,
        authoritative_time=str(registered_at),
        expected_schema_ref="measurement-protocol@0.4.0",
        expected_role="protocol_author",
    )
    reasons.extend(str(item) for item in protocol_check.get("reasons", []))
    protocol_digest = digest_v3_json(protocol)
    if registered_payload.get("protocol_digest") != protocol_digest:
        reasons.append("registration_protocol_digest_mismatch")
    try:
        if _time(registered_at) >= _time(protocol_payload["time_zero"]):
            reasons.append("registration_not_before_time_zero")
        if _time(protocol_payload["time_zero"]) >= _time(protocol_payload["observation_end"]):
            reasons.append("protocol_observation_window_invalid")
    except (KeyError, ValueError):
        reasons.append("protocol_or_registration_time_invalid")
    if protocol_payload.get("registration_key_id") != registration.get("protected", {}).get(
        "key_id"
    ):
        reasons.append("registration_principal_binding_mismatch")
    return not reasons, sorted(set(reasons)), protocol_payload


def inspect_protocol_v4(protocol_path: Path, registration_path: Path, root: Path) -> JsonObject:
    try:
        _, manifest, trust, _ = _workspace(root)
        protocol = load_json_bounded(protocol_path)
        registration = load_json_bounded(registration_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trial_protocol_input_invalid", detail=str(error))
    if not isinstance(protocol, dict) or not isinstance(registration, dict):
        return response("failed", "trial_protocol_input_not_object")
    valid, reasons, payload = _verify_protocol(protocol, registration, trust)
    return response(
        "ok" if valid else "failed",
        None if valid else "trial_protocol_invalid",
        effect_class="validate",
        generation=str(manifest["generation_id"]),
        claims=["externally_registered_protocol_valid"] if valid else [],
        unknowns=[] if valid else ["preregistration_order"],
        protocol_id=payload.get("protocol_id") if payload else None,
        protocol_digest=digest_v3_json(protocol),
        reasons=reasons,
    )


def import_protocol_v4(
    protocol_path: Path,
    registration_path: Path,
    root: Path,
    *,
    apply: bool,
) -> JsonObject:
    try:
        store, manifest, trust, _ = _workspace(root)
        protocol = load_json_bounded(protocol_path)
        registration = load_json_bounded(registration_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trial_protocol_input_invalid", detail=str(error))
    if not isinstance(protocol, dict) or not isinstance(registration, dict):
        return response("failed", "trial_protocol_input_not_object")
    valid, reasons, payload_value = _verify_protocol(protocol, registration, trust)
    if not valid or payload_value is None:
        return response("failed", "trial_protocol_invalid", reasons=reasons)
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    protocol_digest = store.put_json(protocol)
    registration_digest = store.put_json(registration)
    existing = {
        str(item.get("digest")) for item in manifest.get("objects", []) if isinstance(item, dict)
    }
    if protocol_digest in existing:
        return response("failed", "trial_protocol_already_imported")
    payload = deepcopy(manifest)
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(
            registration_digest,
            kind="registration-receipt",
            schema_ref="signed-statement@0.4.0",
            source_chain=[protocol_digest],
            authority_key_id=str(registration["protected"]["key_id"]),
        ),
        ledger_entry(
            protocol_digest,
            kind="measurement-protocol",
            schema_ref="signed-statement@0.4.0",
            source_chain=[registration_digest],
            authority_key_id=str(protocol["protected"]["key_id"]),
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
        claims=["externally_registered_protocol_bound"],
        protocol_id=payload_value["protocol_id"],
        protocol_digest=protocol_digest,
        acceleration_status="registered_not_observed",
    )


def _protocols(store: GenerationStoreV4, manifest: JsonObject) -> dict[str, tuple[str, JsonObject]]:
    result: dict[str, tuple[str, JsonObject]] = {}
    for entry in manifest.get("objects", []):
        if not isinstance(entry, dict) or entry.get("kind") != "measurement-protocol":
            continue
        digest = str(entry["digest"])
        statement = store.get_json(digest)
        if isinstance(statement, dict) and isinstance(statement.get("payload"), dict):
            protocol_id = str(statement["payload"].get("protocol_id"))
            result[protocol_id] = (digest, statement)
    return result


def _result_validation(result: JsonObject, root: Path) -> tuple[bool, list[str], JsonObject | None]:
    store, manifest, trust, epoch = _workspace(root)
    payload = result.get("payload")
    if not isinstance(payload, dict):
        return False, ["trial_result_payload_missing"], None
    reasons = [
        f"result_schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("trial-result-certificate", payload, V4)
    ]
    verified = verify_statement(
        result,
        trust,
        authoritative_time=epoch,
        expected_schema_ref="trial-result-certificate@0.4.0",
        expected_role="evaluator",
    )
    reasons.extend(str(item) for item in verified.get("reasons", []))
    protocols = _protocols(store, manifest)
    selected = protocols.get(str(payload.get("protocol_id")))
    protocol_payload: JsonObject | None = None
    if selected is None:
        reasons.append("bound_protocol_missing")
    else:
        digest, protocol = selected
        protocol_payload = cast(JsonObject, protocol["payload"])
        if payload.get("protocol_digest") != digest:
            reasons.append("result_protocol_digest_mismatch")
        if payload.get("result_id") != protocol_payload.get("primary_result_id"):
            reasons.append("result_not_preregistered_primary_identity")
        if payload.get("dataset_digest") != protocol_payload.get("dataset_commitment_digest"):
            reasons.append("result_dataset_commitment_mismatch")
        if payload.get("analysis_executable_digest") != protocol_payload.get(
            "analysis_executable_digest"
        ):
            reasons.append("result_analysis_executable_mismatch")
    ledger = {
        str(item.get("digest")) for item in manifest.get("objects", []) if isinstance(item, dict)
    }
    for key in ("dataset_digest", "analysis_executable_digest"):
        object_digest = payload.get(key)
        if (
            not isinstance(object_digest, str)
            or object_digest not in ledger
            or not store.cas.verify(object_digest)
        ):
            reasons.append(f"result_{key}_not_in_generation_cas")
    try:
        started = _time(payload["observation_started_at"])
        ended = _time(payload["observation_ended_at"])
        completed = _time(payload["completed_at"])
        evaluated = _time(epoch)
        if not started < ended <= completed <= evaluated:
            reasons.append("result_observation_or_completion_order_invalid")
        if protocol_payload is not None and (
            started < _time(protocol_payload["time_zero"])
            or ended > _time(protocol_payload["observation_end"])
        ):
            reasons.append("result_outside_preregistered_observation_window")
    except (KeyError, ValueError):
        reasons.append("result_time_invalid")
    intervals = payload.get("effect_intervals", {})
    if isinstance(intervals, dict):
        for metric, interval in intervals.items():
            if not isinstance(interval, dict):
                reasons.append(f"result_interval_invalid:{metric}")
                continue
            try:
                if Fraction(str(interval["lower"])) > Fraction(str(interval["upper"])):
                    reasons.append(f"result_interval_orientation_invalid:{metric}")
            except (KeyError, ValueError, ZeroDivisionError):
                reasons.append(f"result_interval_invalid:{metric}")
    else:
        reasons.append("result_effect_intervals_invalid")
    if payload.get("amendment_chain_digest") is not None:
        reasons.append("protocol_deviation")
    return not reasons, sorted(set(reasons)), protocol_payload


def inspect_result_v4(result_path: Path, root: Path) -> JsonObject:
    try:
        result = load_json_bounded(result_path)
        manifest = GenerationStoreV4(root).load_manifest()
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trial_result_input_invalid", detail=str(error))
    if not isinstance(result, dict):
        return response("failed", "trial_result_not_object")
    valid, reasons, _ = _result_validation(result, root)
    status = (
        "protocol_deviation"
        if "protocol_deviation" in reasons
        else ("externally_observed_inconclusive" if valid else "unmeasured")
    )
    return response(
        "ok" if valid else "failed",
        None if valid else "trial_result_invalid",
        effect_class="validate",
        generation=str(manifest["generation_id"]),
        claims=["external_result_provenance_valid"] if valid else [],
        unknowns=["causality", "statistical_method_validity"],
        acceleration_status=status,
        reasons=reasons,
        causal_proof=False,
        statistical_method_certified_by_cpcf=False,
    )


def import_result_v4(result_path: Path, root: Path, *, apply: bool) -> JsonObject:
    try:
        store, manifest, _, _ = _workspace(root)
        result = load_json_bounded(result_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trial_result_input_invalid", detail=str(error))
    if not isinstance(result, dict) or not isinstance(result.get("payload"), dict):
        return response("failed", "trial_result_not_object")
    valid, reasons, protocol = _result_validation(result, root)
    if not valid:
        return response("failed", "trial_result_invalid", reasons=reasons)
    result_id = str(result["payload"]["result_id"])
    existing_primary: list[str] = []
    for entry in manifest.get("objects", []):
        if not isinstance(entry, dict) or entry.get("kind") != "trial-result-certificate":
            continue
        value = store.get_json(str(entry["digest"]))
        if (
            isinstance(value, dict)
            and isinstance(value.get("payload"), dict)
            and value["payload"].get("protocol_id") == result["payload"].get("protocol_id")
        ):
            existing_primary.append(str(value["payload"].get("result_id")))
    if existing_primary:
        return response(
            "failed",
            "multiple_primary_trial_results_contradiction",
            existing_primary_results=existing_primary,
            incoming_result=result_id,
        )
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    digest = store.put_json(result)
    payload = deepcopy(manifest)
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(
            digest,
            kind="trial-result-certificate",
            schema_ref="signed-statement@0.4.0",
            source_chain=[
                str(result["payload"]["protocol_digest"]),
                str(result["payload"]["dataset_digest"]),
                str(result["payload"]["analysis_executable_digest"]),
            ],
            authority_key_id=str(result["protected"]["key_id"]),
        ),
    ]
    committed = store.commit(payload, expected_current=str(manifest["generation_id"]))
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    acceleration = acceleration_status_v4(root, generation_override=str(committed["generation_id"]))
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        claims=list(cast(list[str], acceleration.get("claims", []))),
        unknowns=["causality", "statistical_method_validity"],
        result_id=result_id,
        acceleration_status=acceleration.get("acceleration_status"),
        protocol=protocol,
    )


def acceleration_status_v4(root: Path, generation_override: str | None = None) -> JsonObject:
    """Derive one non-selective acceleration state from all bound primary results."""

    store = GenerationStoreV4(root)
    manifest = store.load_manifest(generation_override)
    protocols = _protocols(store, manifest)
    results: list[JsonObject] = []
    for entry in manifest.get("objects", []):
        if isinstance(entry, dict) and entry.get("kind") == "trial-result-certificate":
            value = store.get_json(str(entry["digest"]))
            if isinstance(value, dict):
                results.append(value)
    if not protocols:
        status = "unmeasured"
    elif not results:
        status = "registered_not_observed"
    else:
        supported = False
        contradiction = False
        inconclusive = False
        for result in results:
            payload = result.get("payload", {})
            if not isinstance(payload, dict):
                continue
            protocol_entry = protocols.get(str(payload.get("protocol_id")))
            protocol_payload = (
                protocol_entry[1].get("payload") if protocol_entry is not None else None
            )
            for metric, interval in payload.get("effect_intervals", {}).items():
                if not isinstance(interval, dict):
                    continue
                lower = Fraction(str(interval["lower"]))
                upper = Fraction(str(interval["upper"]))
                if metric in {"time", "cost"}:
                    supported |= upper < 0
                    contradiction |= lower > 0
                elif metric in {"quality", "safety"}:
                    contradiction |= lower < 0
                inconclusive |= lower <= 0 <= upper
            if isinstance(protocol_payload, dict):
                for category in ("quality", "safety"):
                    floors = protocol_payload.get(f"{category}_floors", {})
                    observed = payload.get(f"{category}_intervals", {})
                    if not isinstance(floors, dict) or not isinstance(observed, dict):
                        contradiction = True
                        continue
                    for metric, floor in floors.items():
                        interval = observed.get(metric)
                        if not isinstance(floor, dict) or not isinstance(interval, dict):
                            contradiction = True
                            continue
                        try:
                            if interval.get("unit") != floor.get("unit") or Fraction(
                                str(interval["lower"])
                            ) < Fraction(str(floor["quantity"])):
                                contradiction = True
                        except (KeyError, ValueError, ZeroDivisionError):
                            contradiction = True
        status = (
            "external_quality_or_safety_contradiction"
            if contradiction
            else "external_acceleration_bundle_compatible"
            if supported and not inconclusive
            else "externally_observed_inconclusive"
        )
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        claims=[status] if status == "external_acceleration_bundle_compatible" else [],
        unknowns=["causality", "statistical_method_validity"],
        acceleration_status=status,
        primary_result_count=len(results),
    )
