# SPDX-License-Identifier: Apache-2.0
"""Role-separated external evidence tiers and preregistration bindings for CPCF v0.5."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.generation_v5 import (
    GenerationStoreV5,
    history_event,
    ledger_entry,
)
from collective_phase_control_fabric.limits import LimitExceeded, load_json_bounded
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.trust_v5 import verify_statement, verify_time_receipt
from collective_phase_control_fabric.types import JsonObject
from collective_phase_control_fabric.workspace_v5 import response

TIER_BY_DESIGN = {
    "descriptive": "descriptive_observation",
    "observational": "observational_association_compatible",
    "quasi_experimental": "quasi_experimental_compatible",
    "randomized": "preregistered_randomized_acceleration_bundle_compatible",
}


def _time(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed


def _workspace(root: Path) -> tuple[GenerationStoreV5, JsonObject, JsonObject, str]:
    store = GenerationStoreV5(root)
    manifest = store.load_manifest()
    policy = store.get_json(str(manifest["trust_policy_digest"]))
    epoch = manifest.get("analysis_epoch")
    if not isinstance(policy, dict) or not isinstance(epoch, str):
        raise ValueError("workspace trust or authoritative time unavailable")
    return store, manifest, policy, epoch


def _principal(policy: JsonObject, key_id: object) -> JsonObject | None:
    matches = [
        item
        for item in policy.get("principals", [])
        if isinstance(item, dict) and item.get("key_id") == key_id
    ]
    return matches[0] if len(matches) == 1 else None


def _roles_disjoint(policy: JsonObject, statements: list[JsonObject]) -> list[str]:
    reasons: list[str] = []
    candidates = [
        _principal(policy, item.get("protected", {}).get("key_id")) for item in statements
    ]
    principals: list[JsonObject] = [item for item in candidates if item is not None]
    ids = [str(item.get("principal_id")) for item in principals]
    keys = [str(item.get("key_id")) for item in principals]
    if len(ids) != len(statements) or len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
        reasons.append("evidence_quorum_identity_not_disjoint")
    for field in ("infrastructure_domains", "correlation_domains"):
        seen: set[str] = set()
        for principal in principals:
            domains = {str(item) for item in principal.get(field, [])}
            if seen & domains:
                reasons.append(f"evidence_quorum_{field}_not_disjoint")
            seen |= domains
    return reasons


def _verify_protocol_bundle(
    protocol: JsonObject,
    registration: JsonObject,
    time_receipt: JsonObject,
    policy: JsonObject,
) -> tuple[bool, list[str], JsonObject | None]:
    reasons: list[str] = []
    protocol_payload = protocol.get("payload")
    registration_payload = registration.get("payload")
    time_payload = time_receipt.get("payload")
    if (
        not isinstance(protocol_payload, dict)
        or not isinstance(registration_payload, dict)
        or not isinstance(time_payload, dict)
    ):
        return False, ["protocol_registration_or_time_payload_missing"], None
    event_time = str(time_payload.get("event_time"))
    protocol_digest = digest_v3_json(protocol)
    time_digest = digest_v3_json(time_receipt)
    reasons.extend(
        f"protocol_schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("measurement-protocol", protocol_payload, "0.5.0")
    )
    reasons.extend(
        f"registration_schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("registration-receipt", registration_payload, "0.5.0")
    )
    protocol_check = verify_statement(
        protocol,
        policy,
        authoritative_time=event_time,
        expected_schema_ref="measurement-protocol@0.5.0",
        expected_role="protocol_author",
    )
    registration_check = verify_statement(
        registration,
        policy,
        authoritative_time=event_time,
        expected_schema_ref="registration-receipt@0.5.0",
        expected_role="registration",
    )
    time_check = verify_time_receipt(time_receipt, policy, expected_subject_digest=protocol_digest)
    reasons.extend(
        str(item)
        for report in (protocol_check, registration_check, time_check)
        for item in report.get("reasons", [])
    )
    reasons.extend(_roles_disjoint(policy, [protocol, registration, time_receipt]))
    if registration_payload.get("protocol_digest") != protocol_digest:
        reasons.append("registration_protocol_digest_mismatch")
    if registration_payload.get("trusted_time_receipt_digest") != time_digest:
        reasons.append("registration_trusted_time_digest_mismatch")
    if registration_payload.get("registered_at") != time_payload.get("event_time"):
        reasons.append("registration_time_not_externally_attested")
    if protocol_payload.get("registration_key_id") != registration.get("protected", {}).get(
        "key_id"
    ):
        reasons.append("registration_principal_binding_mismatch")
    if protocol_payload.get("evaluator_key_id") == protocol.get("protected", {}).get("key_id"):
        reasons.append("protocol_author_and_evaluator_not_distinct")
    try:
        if _time(event_time) >= _time(protocol_payload["time_zero"]):
            reasons.append("registration_not_before_time_zero")
        if _time(protocol_payload["time_zero"]) >= _time(protocol_payload["observation_end"]):
            reasons.append("protocol_observation_window_invalid")
    except (KeyError, ValueError):
        reasons.append("protocol_or_registration_time_invalid")
    assignment = protocol_payload.get("assignment")
    expected_assignment = {
        "randomized": "randomized",
        "quasi_experimental": "as_if_random",
        "observational": "observed",
        "descriptive": "none",
    }.get(str(protocol_payload.get("design_tier")))
    if not isinstance(assignment, dict) or assignment.get("method") != expected_assignment:
        reasons.append("design_tier_assignment_mismatch")
    return not reasons, sorted(set(reasons)), protocol_payload


def inspect_protocol_v5(
    protocol_path: Path, registration_path: Path, time_receipt_path: Path, root: Path
) -> JsonObject:
    try:
        _, manifest, policy, _ = _workspace(root)
        protocol = load_json_bounded(protocol_path)
        registration = load_json_bounded(registration_path)
        time_receipt = load_json_bounded(time_receipt_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trial_protocol_input_invalid", detail=str(error))
    if (
        not isinstance(protocol, dict)
        or not isinstance(registration, dict)
        or not isinstance(time_receipt, dict)
    ):
        return response("failed", "trial_protocol_input_not_object")
    valid, reasons, payload = _verify_protocol_bundle(protocol, registration, time_receipt, policy)
    return response(
        "ok" if valid else "failed",
        None if valid else "trial_protocol_invalid",
        effect_class="validate",
        generation=str(manifest["generation_id"]),
        claims=["independently_timed_registered_protocol_valid"] if valid else [],
        unknowns=[] if valid else ["preregistration_order"],
        protocol_id=payload.get("protocol_id") if payload else None,
        protocol_digest=digest_v3_json(protocol),
        evidence_tier=TIER_BY_DESIGN.get(str(payload.get("design_tier"))) if payload else None,
        reasons=reasons,
    )


def import_protocol_v5(
    protocol_path: Path,
    registration_path: Path,
    time_receipt_path: Path,
    root: Path,
    *,
    apply: bool,
) -> JsonObject:
    try:
        store, manifest, policy, _ = _workspace(root)
        protocol = load_json_bounded(protocol_path)
        registration = load_json_bounded(registration_path)
        time_receipt = load_json_bounded(time_receipt_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trial_protocol_input_invalid", detail=str(error))
    if (
        not isinstance(protocol, dict)
        or not isinstance(registration, dict)
        or not isinstance(time_receipt, dict)
    ):
        return response("failed", "trial_protocol_input_not_object")
    valid, reasons, protocol_payload = _verify_protocol_bundle(
        protocol, registration, time_receipt, policy
    )
    if not valid or protocol_payload is None:
        return response("failed", "trial_protocol_invalid", reasons=reasons)
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    protocol_digest = store.put_json(protocol)
    registration_digest = store.put_json(registration)
    time_digest = store.put_json(time_receipt)
    existing = {
        str(item.get("digest")) for item in manifest.get("objects", []) if isinstance(item, dict)
    }
    if protocol_digest in existing:
        return response("failed", "trial_protocol_already_imported")
    payload = deepcopy(manifest)
    entries = [
        ledger_entry(
            time_digest,
            kind="trusted-time-receipt",
            schema_ref="signed-statement@0.5.0",
            source_chain=[protocol_digest],
            authority_key_id=str(time_receipt["protected"]["key_id"]),
            authority_policy_digest=str(manifest["trust_policy_digest"]),
        ),
        ledger_entry(
            registration_digest,
            kind="registration-receipt",
            schema_ref="signed-statement@0.5.0",
            source_chain=[protocol_digest, time_digest],
            authority_key_id=str(registration["protected"]["key_id"]),
            authority_policy_digest=str(manifest["trust_policy_digest"]),
        ),
        ledger_entry(
            protocol_digest,
            kind="measurement-protocol",
            schema_ref="signed-statement@0.5.0",
            source_chain=[registration_digest, time_digest],
            authority_key_id=str(protocol["protected"]["key_id"]),
            authority_policy_digest=str(manifest["trust_policy_digest"]),
        ),
    ]
    payload["objects"] = [
        *payload.get("objects", []),
        *(item for item in entries if item["digest"] not in existing),
    ]
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:protocol:{protocol_digest[7:]}",
            event_type="protocol_imported",
            subject_digests=[protocol_digest, registration_digest, time_digest],
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
        claims=["role_separated_preregistered_protocol_bound"],
        protocol_id=protocol_payload["protocol_id"],
        protocol_digest=protocol_digest,
        acceleration_status="registered_not_observed",
        evidence_tier=TIER_BY_DESIGN[str(protocol_payload["design_tier"])],
    )


def _objects(
    store: GenerationStoreV5, manifest: JsonObject, kind: str
) -> list[tuple[str, JsonObject]]:
    result: list[tuple[str, JsonObject]] = []
    for entry in manifest.get("objects", []):
        if (
            isinstance(entry, dict)
            and entry.get("kind") == kind
            and entry.get("lifecycle") == "active"
        ):
            value = store.get_json(str(entry["digest"]))
            if isinstance(value, dict):
                result.append((str(entry["digest"]), value))
    return result


def import_amendment_v5(
    amendment_path: Path,
    time_receipt_path: Path,
    root: Path,
    *,
    apply: bool,
) -> JsonObject:
    try:
        store, manifest, policy, epoch = _workspace(root)
        amendment = load_json_bounded(amendment_path)
        time_receipt = load_json_bounded(time_receipt_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "protocol_amendment_input_invalid", detail=str(error))
    if (
        not isinstance(amendment, dict)
        or not isinstance(time_receipt, dict)
        or not isinstance(amendment.get("payload"), dict)
    ):
        return response("failed", "protocol_amendment_input_not_object")
    amendment_payload = cast(JsonObject, amendment["payload"])
    amendment_digest = digest_v3_json(amendment)
    time_check = verify_time_receipt(time_receipt, policy, expected_subject_digest=amendment_digest)
    amendment_check = verify_statement(
        amendment,
        policy,
        authoritative_time=str(time_check.get("event_time", epoch)),
        expected_schema_ref="protocol-amendment@0.5.0",
        expected_role="protocol_author",
    )
    reasons = [
        *(str(item) for item in time_check.get("reasons", [])),
        *(str(item) for item in amendment_check.get("reasons", [])),
    ]
    protocols = {
        digest: statement for digest, statement in _objects(store, manifest, "measurement-protocol")
    }
    protocol = protocols.get(str(amendment_payload.get("protocol_digest")))
    if protocol is None:
        reasons.append("amendment_protocol_missing")
    else:
        protocol_payload = protocol.get("payload", {})
        if _time(amendment_payload.get("effective_at")) >= _time(protocol_payload.get("time_zero")):
            reasons.append("post_start_protocol_deviation")
    previous = amendment_payload.get("previous_amendment_digest")
    existing_amendments = {digest for digest, _ in _objects(store, manifest, "protocol-amendment")}
    if previous is not None and previous not in existing_amendments:
        reasons.append("amendment_chain_predecessor_missing")
    if reasons:
        return response(
            "failed",
            "protocol_amendment_invalid",
            reasons=sorted(set(reasons)),
            acceleration_status="protocol_deviation"
            if "post_start_protocol_deviation" in reasons
            else "registered_not_observed",
        )
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    stored_amendment = store.put_json(amendment)
    stored_time = store.put_json(time_receipt)
    payload = deepcopy(manifest)
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(
            stored_time,
            kind="trusted-time-receipt",
            schema_ref="signed-statement@0.5.0",
            source_chain=[stored_amendment],
            authority_key_id=str(time_receipt["protected"]["key_id"]),
            authority_policy_digest=str(manifest["trust_policy_digest"]),
        ),
        ledger_entry(
            stored_amendment,
            kind="protocol-amendment",
            schema_ref="signed-statement@0.5.0",
            source_chain=[
                str(amendment_payload["protocol_digest"]),
                stored_time,
                *([str(previous)] if previous else []),
            ],
            authority_key_id=str(amendment["protected"]["key_id"]),
            authority_policy_digest=str(manifest["trust_policy_digest"]),
        ),
    ]
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:amendment:{stored_amendment[7:]}",
            event_type="amendment_imported",
            subject_digests=[stored_amendment, stored_time],
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
        claims=["pre_start_protocol_amendment_bound"],
        amendment_digest=stored_amendment,
    )


def _validate_result(result: JsonObject, root: Path) -> tuple[bool, list[str], JsonObject | None]:
    store, manifest, policy, epoch = _workspace(root)
    payload = result.get("payload")
    if not isinstance(payload, dict):
        return False, ["trial_result_payload_missing"], None
    reasons = [
        f"result_schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("trial-result-certificate", payload, "0.5.0")
    ]
    checked = verify_statement(
        result,
        policy,
        authoritative_time=epoch,
        expected_schema_ref="trial-result-certificate@0.5.0",
        expected_role="evaluator",
    )
    reasons.extend(str(item) for item in checked.get("reasons", []))
    protocols = {
        str(statement.get("payload", {}).get("protocol_id")): (digest, statement)
        for digest, statement in _objects(store, manifest, "measurement-protocol")
    }
    selected = protocols.get(str(payload.get("protocol_id")))
    protocol_payload: JsonObject | None = None
    if selected is None:
        reasons.append("bound_protocol_missing")
    else:
        protocol_digest, protocol = selected
        protocol_payload = cast(JsonObject, protocol["payload"])
        if payload.get("protocol_digest") != protocol_digest:
            reasons.append("result_protocol_digest_mismatch")
        if payload.get("result_id") != protocol_payload.get("primary_result_id"):
            reasons.append("result_not_unique_preregistered_primary_identity")
        if result.get("protected", {}).get("key_id") != protocol_payload.get("evaluator_key_id"):
            reasons.append("result_evaluator_key_mismatch")
        if payload.get("dataset_digest") != protocol_payload.get("dataset_commitment_digest"):
            reasons.append("result_dataset_commitment_mismatch")
        if payload.get("analysis_executable_digest") != protocol_payload.get(
            "analysis_executable_digest"
        ):
            reasons.append("result_analysis_executable_mismatch")
    ledger_by_kind = {
        kind: {digest for digest, _ in _objects(store, manifest, kind)}
        for kind in ("dataset-record", "analysis-executable-record")
    }
    if payload.get("dataset_digest") not in ledger_by_kind["dataset-record"]:
        reasons.append("typed_dataset_record_missing")
    if (
        payload.get("analysis_executable_digest")
        not in ledger_by_kind["analysis-executable-record"]
    ):
        reasons.append("typed_analysis_executable_record_missing")
    try:
        started = _time(payload["observation_started_at"])
        ended = _time(payload["observation_ended_at"])
        completed = _time(payload["completed_at"])
        signed = _time(result.get("protected", {}).get("signed_at"))
        evaluated = _time(epoch)
        if not started < ended <= completed <= signed <= evaluated:
            reasons.append("result_observation_completion_or_signing_order_invalid")
        if protocol_payload is not None and (
            started < _time(protocol_payload["time_zero"])
            or ended > _time(protocol_payload["observation_end"])
        ):
            reasons.append("result_outside_preregistered_observation_window")
    except (KeyError, ValueError):
        reasons.append("result_time_invalid")
    if protocol_payload is not None:
        outcomes = {
            str(item.get("outcome_id")): item
            for item in protocol_payload.get("primary_outcomes", [])
            if isinstance(item, dict)
        }
        intervals = payload.get("effect_intervals")
        if not isinstance(intervals, dict) or set(intervals) != set(outcomes):
            reasons.append("primary_outcome_bundle_incomplete")
        else:
            for outcome_id, interval in intervals.items():
                definition = outcomes[outcome_id]
                if not isinstance(interval, dict) or interval.get("unit") != definition.get("unit"):
                    reasons.append(f"outcome_unit_mismatch:{outcome_id}")
                    continue
                try:
                    lower, upper = (
                        Fraction(str(interval["lower"])),
                        Fraction(str(interval["upper"])),
                    )
                    if lower > upper:
                        reasons.append(f"result_interval_orientation_invalid:{outcome_id}")
                except (KeyError, ValueError, ZeroDivisionError):
                    reasons.append(f"result_interval_invalid:{outcome_id}")
    amendments = [
        statement
        for _, statement in _objects(store, manifest, "protocol-amendment")
        if statement.get("payload", {}).get("protocol_digest") == payload.get("protocol_digest")
    ]
    if amendments:
        expected_chain = digest_v3_json([digest_v3_json(item) for item in amendments])
        if payload.get("amendment_chain_digest") != expected_chain:
            reasons.append("result_amendment_chain_mismatch")
    elif payload.get("amendment_chain_digest") is not None:
        reasons.append("unbound_amendment_chain")
    return not reasons, sorted(set(reasons)), protocol_payload


def inspect_result_v5(result_path: Path, root: Path) -> JsonObject:
    try:
        result = load_json_bounded(result_path)
        manifest = GenerationStoreV5(root).load_manifest()
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trial_result_input_invalid", detail=str(error))
    if not isinstance(result, dict):
        return response("failed", "trial_result_not_object")
    valid, reasons, protocol = _validate_result(result, root)
    tier = TIER_BY_DESIGN.get(str(protocol.get("design_tier"))) if protocol else None
    return response(
        "ok" if valid else "failed",
        None if valid else "trial_result_invalid",
        effect_class="validate",
        generation=str(manifest["generation_id"]),
        claims=["external_result_provenance_valid"] if valid else [],
        unknowns=["causality", "statistical_method_validity"],
        acceleration_status="externally_observed_inconclusive" if valid else "unmeasured",
        evidence_tier=tier,
        reasons=reasons,
        causal_proof=False,
        statistical_method_certified_by_cpcf=False,
    )


def import_result_v5(result_path: Path, root: Path, *, apply: bool) -> JsonObject:
    try:
        store, manifest, _, _ = _workspace(root)
        result = load_json_bounded(result_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "trial_result_input_invalid", detail=str(error))
    if not isinstance(result, dict) or not isinstance(result.get("payload"), dict):
        return response("failed", "trial_result_not_object")
    valid, reasons, protocol = _validate_result(result, root)
    if not valid:
        return response("failed", "trial_result_invalid", reasons=reasons)
    existing = [
        statement
        for _, statement in _objects(store, manifest, "trial-result-certificate")
        if statement.get("payload", {}).get("protocol_id") == result["payload"].get("protocol_id")
    ]
    if existing:
        return response(
            "failed",
            "multiple_primary_trial_results_contradiction",
            existing_primary_results=[
                item.get("payload", {}).get("result_id") for item in existing
            ],
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
            schema_ref="signed-statement@0.5.0",
            source_chain=[
                str(result["payload"][field])
                for field in ("protocol_digest", "dataset_digest", "analysis_executable_digest")
            ],
            authority_key_id=str(result["protected"]["key_id"]),
            authority_policy_digest=str(manifest["trust_policy_digest"]),
        ),
    ]
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:trial:{digest[7:]}",
            event_type="trial_result_imported",
            subject_digests=[digest],
        ),
    ]
    committed = store.commit(payload, expected_current=str(manifest["generation_id"]))
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    acceleration = acceleration_status_v5(root, generation_override=str(committed["generation_id"]))
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        claims=list(cast(list[str], acceleration.get("claims", []))),
        unknowns=["causality", "statistical_method_validity"],
        result_id=result["payload"]["result_id"],
        acceleration_status=acceleration.get("acceleration_status"),
        evidence_tier=TIER_BY_DESIGN.get(str(protocol.get("design_tier"))) if protocol else None,
    )


def _floors_preserved(protocol: JsonObject, result: JsonObject) -> bool:
    for category in ("quality", "safety"):
        floors = protocol.get(f"{category}_floors", {})
        observed = result.get(f"{category}_intervals", {})
        if not isinstance(floors, dict) or not isinstance(observed, dict):
            return False
        for metric, floor in floors.items():
            interval = observed.get(metric)
            if not isinstance(floor, dict) or not isinstance(interval, dict):
                return False
            try:
                if interval.get("unit") != floor.get("unit") or Fraction(
                    str(interval["lower"])
                ) < Fraction(str(floor["quantity"])):
                    return False
            except (KeyError, ValueError, ZeroDivisionError):
                return False
    return True


def acceleration_status_v5(root: Path, generation_override: str | None = None) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        manifest = store.load_manifest(generation_override)
        policy = store.get_json(str(manifest["trust_policy_digest"]))
        if not isinstance(policy, dict):
            raise ValueError("trust policy missing")
        epoch = str(manifest["analysis_epoch"])
    except (OSError, ValueError) as error:
        return response("failed", "acceleration_status_failed", detail=str(error))
    protocols = {
        str(statement.get("payload", {}).get("protocol_id")): (digest, statement)
        for digest, statement in _objects(store, manifest, "measurement-protocol")
    }
    results = _objects(store, manifest, "trial-result-certificate")
    if not protocols:
        return response(
            "ok",
            None,
            generation=str(manifest["generation_id"]),
            unknowns=["external_measurement"],
            acceleration_status="unmeasured",
            evidence_tier=None,
        )
    if not results:
        tiers = [
            tier
            for item in protocols.values()
            if (tier := TIER_BY_DESIGN.get(str(item[1].get("payload", {}).get("design_tier"))))
            is not None
        ]
        highest = max(tiers, default=None)
        return response(
            "ok",
            None,
            generation=str(manifest["generation_id"]),
            unknowns=["external_result"],
            acceleration_status="registered_not_observed",
            evidence_tier=highest,
        )
    contradiction = False
    supported_tiers: list[str] = []
    evidence_records = _objects(store, manifest, "acceleration-evidence")
    for result_digest, result in results:
        valid, _, protocol_payload = _validate_result(result, root)
        if (
            not valid
            or protocol_payload is None
            or not _floors_preserved(protocol_payload, cast(JsonObject, result["payload"]))
        ):
            contradiction = True
            continue
        intervals = cast(JsonObject, result["payload"]).get("effect_intervals", {})
        outcomes = {
            str(item.get("outcome_id")): item
            for item in protocol_payload.get("primary_outcomes", [])
            if isinstance(item, dict)
        }
        supported = True
        for outcome_id, definition in outcomes.items():
            interval = intervals.get(outcome_id) if isinstance(intervals, dict) else None
            if not isinstance(interval, dict):
                supported = False
                continue
            minimum = Fraction(str(definition["minimum_effect"]))
            lower, upper = Fraction(str(interval["lower"])), Fraction(str(interval["upper"]))
            supported &= (
                lower >= minimum if definition["direction"] == "increase" else upper <= -minimum
            )
        tier = TIER_BY_DESIGN.get(str(protocol_payload.get("design_tier")))
        if supported and tier is not None:
            if tier == "preregistered_randomized_acceleration_bundle_compatible":
                matching = [
                    statement
                    for _, statement in evidence_records
                    if statement.get("payload", {}).get("result_digest") == result_digest
                    and statement.get("payload", {}).get("tier") == tier
                    and statement.get("payload", {}).get("quality_safety_status") == "preserved"
                ]
                if len(matching) != 1:
                    continue
                evidence = matching[0]
                checked = verify_statement(
                    evidence,
                    policy,
                    authoritative_time=epoch,
                    expected_schema_ref="evidence-tier@0.5.0",
                    expected_role="quality_safety_verifier",
                )
                current_time = store.get_json(str(manifest["trusted_time_receipt_digest"]))
                if (
                    checked.get("status") != "true"
                    or not isinstance(current_time, dict)
                    or _roles_disjoint(policy, [result, evidence, current_time])
                ):
                    continue
            supported_tiers.append(tier)
    status = (
        "external_quality_or_safety_contradiction"
        if contradiction
        else "external_acceleration_bundle_compatible"
        if "preregistered_randomized_acceleration_bundle_compatible" in supported_tiers
        else "externally_observed_inconclusive"
    )
    tier = (
        "preregistered_randomized_acceleration_bundle_compatible"
        if status == "external_acceleration_bundle_compatible"
        else (sorted(supported_tiers)[-1] if supported_tiers else None)
    )
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        claims=["external_acceleration_bundle_compatible"]
        if status == "external_acceleration_bundle_compatible"
        else [],
        unknowns=["causality", "statistical_method_validity"],
        acceleration_status=status,
        evidence_tier=tier,
        primary_result_count=len(results),
    )
