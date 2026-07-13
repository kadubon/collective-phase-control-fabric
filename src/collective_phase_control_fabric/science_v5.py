# SPDX-License-Identifier: Apache-2.0
"""Evidence-bound operational organization analysis for CPCF v0.5."""

from __future__ import annotations

from collections import defaultdict
from fractions import Fraction
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.generation_v5 import GenerationStoreV5
from collective_phase_control_fabric.limits import MAX_ANALYSIS_OPERATIONS, MAX_PERTURBATIONS
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject, JsonValue, id_set
from collective_phase_control_fabric.workspace_v5 import (
    MANDATORY_DIMENSIONS,
    active_attestations_v5,
    doctor_v5,
    response,
)


def _fraction(value: object) -> Fraction:
    result = Fraction(str(value))
    if result.numerator.bit_length() > 4096 or result.denominator.bit_length() > 4096:
        raise OverflowError("rational_bit_length_exceeded")
    return result


def _payload(statement: JsonObject) -> JsonObject:
    value = statement.get("payload")
    return value if isinstance(value, dict) else {}


def _attributes(statement: JsonObject) -> JsonObject:
    value = _payload(statement).get("attributes")
    return value if isinstance(value, dict) else {}


def _subject(statement: JsonObject) -> str:
    return str(_payload(statement).get("subject_id", ""))


def _record_type(statement: JsonObject) -> str:
    return str(_payload(statement).get("record_type", ""))


def analysis_snapshot_digest_v5(
    manifest: JsonObject, contract: JsonObject, statements: list[JsonObject]
) -> str:
    """Bind analysis to every authoritative input in the immutable generation."""

    witness_types = {
        "formation_sequence_witness",
        "organization_witness",
        "rate_feasibility_witness",
        "siphon_coverage_witness",
        "typed_flow_profile",
    }
    analysis_statement_digests = {
        digest_v3_json(item)
        for item in statements
        if _record_type(item) == "evidence"
        and _attributes(item).get("evidence_type") in witness_types
    }
    analysis_source_digests = {
        str(_payload(item).get("source_artifact_digest"))
        for item in statements
        if digest_v3_json(item) in analysis_statement_digests
        and isinstance(_payload(item).get("source_artifact_digest"), str)
    }
    excluded_ledger_kinds = {
        "analysis-snapshot",
        "scientific-witness",
        "typed-flow-profile",
        "perturbation-result",
    }
    return digest_v3_json(
        cast(
            JsonValue,
            {
                "schema_version": "0.5.0",
                "contract_digest": manifest.get("contract_digest"),
                "trust_policy_digest": manifest.get("trust_policy_digest"),
                "trusted_time_receipt_digest": manifest.get("trusted_time_receipt_digest"),
                "analysis_epoch": manifest.get("analysis_epoch"),
                "unit_registry_ref": contract.get("unit_registry_ref"),
                "ledger": sorted(
                    [
                        str(item.get("digest")),
                        str(item.get("kind")),
                        str(item.get("lifecycle")),
                    ]
                    for item in manifest.get("objects", [])
                    if isinstance(item, dict)
                    and item.get("kind") not in excluded_ledger_kinds
                    and item.get("digest") not in analysis_statement_digests
                    and item.get("digest") not in analysis_source_digests
                ),
                "attestations": sorted(
                    digest_v3_json(item)
                    for item in statements
                    if digest_v3_json(item) not in analysis_statement_digests
                ),
                "quarantine": sorted(str(item) for item in manifest.get("quarantine", [])),
            },
        )
    )


def _network(
    statements: list[JsonObject],
) -> tuple[set[str], dict[str, JsonObject], set[str], set[str], set[str]]:
    available: set[str] = set()
    transformations: dict[str, JsonObject] = {}
    catalysts: set[str] = set()
    inhibitors: set[str] = set()
    evidence: set[str] = set()
    for statement in statements:
        kind = _record_type(statement)
        subject = _subject(statement)
        attributes = _attributes(statement)
        if kind == "state" and attributes.get("available") is True:
            available.add(subject)
        elif kind == "transformation":
            if subject in transformations:
                raise ValueError("duplicate transformation identifier")
            transformations[subject] = attributes
        elif kind == "catalyst" and attributes.get("available") is True:
            catalysts.add(subject)
        elif kind == "inhibitor" and attributes.get("available") is True:
            inhibitors.add(subject)
        elif kind in {"authority", "evidence"}:
            available.add(subject)
            evidence.add(subject)
    return available, transformations, catalysts, inhibitors, evidence


def _enabled(
    edge: JsonObject,
    available: set[str],
    catalysts: set[str],
    inhibitors: set[str],
) -> bool:
    if not id_set(edge.get("inputs")) <= available:
        return False
    if not id_set(edge.get("authority_refs")) <= available:
        return False
    if not id_set(edge.get("evidence_refs")) <= available:
        return False
    if id_set(edge.get("inhibitors")) & inhibitors:
        return False
    clauses = edge.get("catalyst_clauses", [])
    if edge.get("explicitly_uncatalyzed") is True:
        return not clauses
    if not isinstance(clauses, list) or not clauses:
        return False
    return all(isinstance(clause, list) and id_set(clause) & catalysts for clause in clauses)


def _closure(
    initial: set[str],
    transformations: dict[str, JsonObject],
    catalysts: set[str],
    inhibitors: set[str],
    operation_budget: int,
) -> tuple[set[str], dict[str, int], set[str], int]:
    available = set(initial)
    available_catalysts = set(catalysts)
    layers = {item: 0 for item in initial}
    used: set[str] = set()
    operations = 0
    layer = 0
    while True:
        additions: set[str] = set()
        next_catalysts: set[str] = set()
        for transformation_id in sorted(transformations):
            operations += 1
            if operations > operation_budget:
                raise RuntimeError("unknown_due_to_budget")
            edge = transformations[transformation_id]
            if _enabled(edge, available, available_catalysts, inhibitors):
                outputs = id_set(edge.get("outputs"))
                if outputs - available:
                    additions |= outputs
                    used.add(transformation_id)
                    produced_catalysts = id_set(edge.get("produced_catalysts"))
                    next_catalysts |= produced_catalysts
        if not additions:
            break
        layer += 1
        for item in sorted(additions):
            layers.setdefault(item, layer)
        available |= additions
        available_catalysts |= next_catalysts
    return available, layers, used, operations


def _organization(
    statements: list[JsonObject],
    transformations: dict[str, JsonObject],
    snapshot: str,
    targets: set[str],
) -> tuple[str, list[str]]:
    witnesses = [
        item
        for item in statements
        if _record_type(item) == "evidence"
        and _attributes(item).get("evidence_type") == "organization_witness"
    ]
    reasons: list[str] = []
    if len(witnesses) != 1:
        return "unknown" if not witnesses else "violated", ["one_organization_witness_required"]
    witness = _attributes(witnesses[0])
    if witness.get("analysis_snapshot_digest") != snapshot:
        reasons.append("organization_snapshot_mismatch")
    refs = id_set(witness.get("transformation_refs"))
    if not refs or not refs <= set(transformations):
        reasons.append("organization_transformation_set_invalid")
    produced = (
        set().union(*(id_set(transformations[item].get("outputs")) for item in refs))
        if refs
        else set()
    )
    if not targets <= produced:
        reasons.append("organization_not_target_bound")
    flux = witness.get("feasible_flux")
    if not isinstance(flux, dict) or set(flux) != refs:
        reasons.append("organization_flux_domain_mismatch")
        return "violated", sorted(set(reasons))
    balances: defaultdict[str, Fraction] = defaultdict(Fraction)
    try:
        for transformation_id in sorted(refs):
            multiplier = _fraction(flux[transformation_id])
            if multiplier <= 0:
                reasons.append(f"organization_flux_not_strictly_positive:{transformation_id}")
            for coordinate, amount in (
                transformations[transformation_id].get("coordinate_flows", {}).items()
            ):
                balances[str(coordinate)] += multiplier * _fraction(amount)
    except (KeyError, ValueError, ZeroDivisionError, OverflowError):
        reasons.append("organization_exact_balance_invalid")
    reasons.extend(
        f"organization_negative_maintenance_balance:{item}"
        for item, value in sorted(balances.items())
        if value < 0
    )
    return ("satisfied" if not reasons else "violated"), sorted(set(reasons))


def validate_typed_flow_profile(
    profile: JsonObject, registry: JsonObject, *, live_source_ids: set[str], snapshot: str
) -> JsonObject:
    """Recompute an exact finite-horizon marking and fed-siphon coverage."""

    reasons = [
        f"schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("typed-flow-profile", profile, "0.5.0")
    ]
    if profile.get("analysis_snapshot_digest") != snapshot:
        reasons.append("typed_flow_snapshot_mismatch")
    if profile.get("unit_registry_digest") != digest_v3_json(registry):
        reasons.append("typed_flow_unit_registry_mismatch")
    units = registry.get("units")
    if not isinstance(units, dict):
        return {"status": "violated", "reasons": [*reasons, "unit_registry_invalid"]}
    coordinates = profile.get("coordinates")
    transformations = profile.get("transformations")
    counts = profile.get("action_counts")
    supplies = profile.get("boundary_rates")
    if (
        not isinstance(coordinates, dict)
        or not isinstance(transformations, dict)
        or not isinstance(counts, list)
        or not isinstance(supplies, list)
    ):
        return {"status": "violated", "reasons": [*reasons, "typed_flow_structure_invalid"]}
    horizon = profile.get("horizon_steps")
    if not isinstance(horizon, int) or horizon != len(counts) or horizon != len(supplies):
        reasons.append("typed_flow_horizon_length_mismatch")
    time_unit = units.get(str(profile.get("time_unit")))
    if not isinstance(time_unit, dict):
        reasons.append("typed_flow_time_unit_unknown")
    try:
        duration = _fraction(profile.get("step_duration"))
        if duration <= 0:
            reasons.append("typed_flow_duration_not_positive")
    except (ValueError, ZeroDivisionError, OverflowError):
        duration = Fraction(0)
        reasons.append("typed_flow_duration_invalid")
    marking: dict[str, Fraction] = {}
    floors: dict[str, Fraction] = {}
    for coordinate, declaration in coordinates.items():
        if not isinstance(declaration, dict):
            reasons.append(f"coordinate_declaration_invalid:{coordinate}")
            continue
        unit = units.get(str(declaration.get("unit")))
        if not isinstance(unit, dict):
            reasons.append(f"coordinate_unit_unknown:{coordinate}")
            continue
        try:
            marking[str(coordinate)] = _fraction(declaration["initial"])
            floors[str(coordinate)] = _fraction(declaration["protected_floor"])
        except (KeyError, ValueError, ZeroDivisionError, OverflowError):
            reasons.append(f"coordinate_quantity_invalid:{coordinate}")
    trajectory = [dict(marking)]
    try:
        for step, (actions, boundary) in enumerate(zip(counts, supplies, strict=True)):
            if not isinstance(actions, dict) or not isinstance(boundary, dict):
                raise ValueError("flow step must be an object")
            delta: defaultdict[str, Fraction] = defaultdict(Fraction)
            for transformation_id, count in actions.items():
                declaration = transformations.get(transformation_id)
                if not isinstance(declaration, dict):
                    reasons.append(f"unknown_trajectory_transformation:{transformation_id}")
                    continue
                amount = _fraction(count)
                if amount < 0:
                    reasons.append(f"negative_action_count:{transformation_id}:{step}")
                flow = declaration.get("flow")
                if not isinstance(flow, dict):
                    reasons.append(f"transformation_flow_invalid:{transformation_id}")
                    continue
                for coordinate, coefficient in flow.items():
                    if coordinate not in marking:
                        reasons.append(f"flow_coordinate_unknown:{coordinate}")
                    delta[str(coordinate)] += amount * _fraction(coefficient)
            for coordinate, rate in boundary.items():
                if coordinate not in marking:
                    reasons.append(f"boundary_coordinate_unknown:{coordinate}")
                delta[str(coordinate)] += _fraction(rate) * duration
            for coordinate in marking:
                marking[coordinate] += delta[coordinate]
                if marking[coordinate] < floors[coordinate]:
                    reasons.append(f"prefix_floor_violation:{coordinate}:{step + 1}")
            trajectory.append(dict(marking))
    except (ValueError, ZeroDivisionError, OverflowError) as error:
        reasons.append(f"typed_flow_exact_arithmetic_invalid:{error}")
    for siphon in profile.get("fed_siphons", []):
        if not isinstance(siphon, dict):
            reasons.append("fed_siphon_record_invalid")
            continue
        siphon_coordinates = id_set(siphon.get("coordinates"))
        refs = id_set(siphon.get("source_refs"))
        coverage = siphon.get("coverage")
        if not refs or not refs <= live_source_ids:
            reasons.append("fed_siphon_source_not_live")
        if coverage == "initially_marked" and not any(
            trajectory[0].get(item, Fraction(0)) > 0 for item in siphon_coordinates
        ):
            reasons.append("fed_siphon_not_initially_marked")
        elif coverage == "boundary_fed" and not any(
            isinstance(step, dict)
            and any(_fraction(step.get(item, "0")) > 0 for item in siphon_coordinates)
            for step in supplies
        ):
            reasons.append("fed_siphon_not_boundary_fed")
        elif coverage == "replenished" and not any(
            isinstance(declaration, dict)
            and isinstance(declaration.get("flow"), dict)
            and any(
                _fraction(declaration["flow"].get(item, "0")) > 0 for item in siphon_coordinates
            )
            for declaration in transformations.values()
        ):
            reasons.append("fed_siphon_not_replenished")
    return {
        "status": "satisfied" if not reasons else "violated",
        "reasons": sorted(set(reasons)),
        "trajectory": [
            {key: str(value) for key, value in sorted(marking_value.items())}
            for marking_value in trajectory
        ],
        "exact_rational_recheck": True,
    }


def _verification(statements: list[JsonObject]) -> tuple[str, list[str]]:
    records = [item for item in statements if _record_type(item) == "verifier"]
    if not records:
        return "unknown", ["typed_verifier_records_required"]
    subjects = {_subject(item) for item in statements}
    source_digests = {
        str(_payload(item).get("subject_digest"))
        for item in statements
        if isinstance(_payload(item).get("subject_digest"), str)
    }
    reasons: list[str] = []
    routed_arrival = Fraction(0)
    for record in sorted(records, key=_subject):
        attributes = _attributes(record)
        source = attributes.get("source_record_digest")
        if (
            source == _payload(record).get("subject_digest")
            or not isinstance(source, str)
            or source not in source_digests
        ):
            reasons.append(f"verifier_source_record_invalid:{_subject(record)}")
        try:
            arrival = max(_fraction(attributes.get("arrival_upper", "0")), routed_arrival)
            service = _fraction(attributes.get("service_lower", "0"))
            amplification = _fraction(attributes.get("routing_amplification", "1"))
            if arrival >= service:
                reasons.append(f"verifier_overloaded:{_subject(record)}")
            routed_arrival = arrival * amplification
        except (ValueError, ZeroDivisionError, OverflowError):
            reasons.append(f"verifier_interval_invalid:{_subject(record)}")
        if not id_set(attributes.get("source_refs", [])) <= subjects:
            reasons.append(f"verifier_source_ref_missing:{_subject(record)}")
    return ("satisfied" if not reasons else "violated"), sorted(set(reasons))


def _independence(statements: list[JsonObject], minimum: int) -> tuple[str, list[str], int]:
    records = [item for item in statements if _record_type(item) == "independence"]
    reasons: list[str] = []
    groups: list[set[str]] = []
    for record in records:
        payload = _payload(record)
        attributes = _attributes(record)
        protected = record.get("protected")
        if not isinstance(protected, dict):
            continue
        observer = attributes.get("observer_attestation_ref")
        commitment = attributes.get("commitment_digest")
        if not isinstance(observer, str) or observer == payload.get("attestation_id"):
            reasons.append(f"independence_observer_invalid:{_subject(record)}")
        if not isinstance(commitment, str):
            reasons.append(f"independence_commitment_missing:{_subject(record)}")
        domains = {
            str(protected.get("principal_id")),
            *id_set(payload.get("lineage_refs")),
            *id_set(payload.get("correlation_domains")),
            *id_set(attributes.get("infrastructure_domains")),
        }
        groups.append(domains)
    components: list[set[str]] = []
    for group in groups:
        touching = [item for item in components if item & group]
        merged = set(group)
        for item in touching:
            merged |= item
            components.remove(item)
        components.append(merged)
    precommit_exposures = [
        item
        for item in statements
        if _record_type(item) == "exposure" and _attributes(item).get("before_commitment") is True
    ]
    exposed_artifacts = {
        str(_attributes(item).get("artifact_digest")) for item in precommit_exposures
    }
    effective = max(0, len(components) - len(exposed_artifacts))
    if effective < minimum:
        reasons.append(f"effective_independence_below_contract_minimum:{effective}:{minimum}")
    return (
        ("satisfied" if not reasons else "violated" if records else "unknown"),
        sorted(set(reasons or ([] if records else ["independence_attestations_required"]))),
        effective,
    )


def _quorum_feasible(policy: JsonObject) -> tuple[str, list[str]]:
    principals = [
        item
        for item in policy.get("principals", [])
        if isinstance(item, dict) and item.get("revoked") is False
    ]
    reasons: list[str] = []
    required_roles = {"workspace_root", "trust_auditor", "timestamp"}
    choices = {
        role: [item for item in principals if role in item.get("roles", [])]
        for role in required_roles
    }
    if any(not items for items in choices.values()):
        return "violated", ["trust_update_quorum_role_unavailable"]
    feasible = False
    for root in choices["workspace_root"]:
        for auditor in choices["trust_auditor"]:
            for timestamp in choices["timestamp"]:
                selected = [root, auditor, timestamp]
                ids = {str(item.get("principal_id")) for item in selected}
                keys = {str(item.get("key_id")) for item in selected}
                infrastructure = [
                    set(str(value) for value in item.get("infrastructure_domains", []))
                    for item in selected
                ]
                disjoint = not any(
                    infrastructure[left] & infrastructure[right]
                    for left in range(3)
                    for right in range(left + 1, 3)
                )
                if len(ids) == 3 and len(keys) == 3 and disjoint:
                    feasible = True
    if not feasible:
        reasons.append("trust_update_quorum_not_disjoint")
    return ("satisfied" if feasible else "violated"), reasons


def _coordination(store: GenerationStoreV5, manifest: JsonObject) -> tuple[str, list[str]]:
    sessions: list[JsonObject] = []
    for entry in manifest.get("objects", []):
        if (
            isinstance(entry, dict)
            and entry.get("kind") == "coordination-session"
            and entry.get("lifecycle") == "active"
        ):
            value = store.get_json(str(entry["digest"]))
            if isinstance(value, dict):
                sessions.append(value)
    if not sessions:
        return "unknown", ["bounded_coordination_session_not_observed"]
    reasons: list[str] = []
    for session in sessions:
        if session.get("state") != "TERMINATED":
            reasons.append(f"coordination_session_not_terminated:{session.get('session_id')}")
        if session.get("verification_capacity_satisfied") is not True:
            reasons.append(
                f"coordination_verification_capacity_unsatisfied:{session.get('session_id')}"
            )
        if set(session.get("commitments", {})) != set(session.get("reveals", {})):
            reasons.append(f"coordination_commit_reveal_incomplete:{session.get('session_id')}")
    return ("satisfied" if not reasons else "violated"), sorted(set(reasons))


def _evaluate(
    store: GenerationStoreV5,
    manifest: JsonObject,
    contract: JsonObject,
    policy: JsonObject,
    statements: list[JsonObject],
    rejected: list[JsonObject],
    *,
    include_robustness: bool,
) -> JsonObject:
    snapshot = analysis_snapshot_digest_v5(manifest, contract, statements)
    profile = {dimension: "unknown" for dimension in MANDATORY_DIMENSIONS}
    reasons: dict[str, list[str]] = {dimension: [] for dimension in MANDATORY_DIMENSIONS}
    doctor = doctor_v5(store.root)
    profile["provenance_integrity"] = (
        "satisfied" if doctor.get("command_status") == "ok" and not rejected else "violated"
    )
    reasons["provenance_integrity"] = [
        f"rejected_attestation:{item.get('digest')}" for item in rejected
    ]
    quorum_status, quorum_reasons = _quorum_feasible(policy)
    profile["trust_quorum"] = quorum_status
    reasons["trust_quorum"] = quorum_reasons
    profile["temporal_integrity"] = "satisfied" if manifest.get("analysis_epoch") else "unknown"
    if profile["temporal_integrity"] != "satisfied":
        reasons["temporal_integrity"] = ["trusted_time_required"]
    operation_budget = min(
        MAX_ANALYSIS_OPERATIONS,
        int(contract.get("analysis_limits", {}).get("maximum_operations", MAX_ANALYSIS_OPERATIONS)),
    )
    try:
        initial, transformations, catalysts, inhibitors, _ = _network(statements)
        reachable, layers, used, operations = _closure(
            initial, transformations, catalysts, inhibitors, operation_budget
        )
    except RuntimeError:
        reasons["structural_reachability"] = ["unknown_due_to_budget"]
        return {
            "profile": profile,
            "reasons": reasons,
            "analysis_snapshot_digest": snapshot,
            "operation_count": operation_budget,
        }
    except ValueError as error:
        profile["provenance_integrity"] = "violated"
        reasons["provenance_integrity"].append(str(error))
        reachable, layers, used, operations = set(), {}, set(), 0
    targets = id_set(contract.get("target_states"))
    missing = sorted(targets - reachable)
    profile["structural_reachability"] = "satisfied" if not missing else "violated"
    reasons["structural_reachability"] = [f"target_unreachable:{item}" for item in missing]
    strictly_prior = all(
        all(
            layers.get(input_id, 0) < layers.get(output_id, 0)
            for input_id in id_set(transformations[transformation_id].get("inputs"))
            for output_id in id_set(transformations[transformation_id].get("outputs"))
        )
        for transformation_id in used
    )
    profile["causal_formation"] = "satisfied" if not missing and strictly_prior else "violated"
    reasons["causal_formation"] = (
        []
        if profile["causal_formation"] == "satisfied"
        else ["strictly_prior_formation_not_established"]
    )
    organization_status, organization_reasons = _organization(
        statements, transformations, snapshot, targets
    )
    profile["exact_self_maintenance"] = organization_status
    reasons["exact_self_maintenance"] = organization_reasons
    registry = store.get_json(str(contract.get("unit_registry_ref")))
    typed_profiles: list[JsonObject] = []
    for entry in manifest.get("objects", []):
        if (
            isinstance(entry, dict)
            and entry.get("kind") == "typed-flow-profile"
            and entry.get("lifecycle") == "active"
        ):
            candidate = store.get_json(str(entry["digest"]))
            if isinstance(candidate, dict):
                typed_profiles.append(candidate)
    live_ids = {_subject(item) for item in statements}
    if not isinstance(registry, dict):
        typed_result = {"status": "violated", "reasons": ["unit_registry_missing"]}
    elif len(typed_profiles) != 1:
        typed_result = {
            "status": "unknown" if not typed_profiles else "violated",
            "reasons": ["one_typed_flow_profile_required"],
        }
    else:
        typed_result = validate_typed_flow_profile(
            typed_profiles[0], registry, live_source_ids=live_ids, snapshot=snapshot
        )
    profile["dimensional_consistency"] = str(typed_result["status"])
    profile["finite_horizon_resource_persistence"] = str(typed_result["status"])
    reasons["dimensional_consistency"] = list(cast(list[str], typed_result.get("reasons", [])))
    reasons["finite_horizon_resource_persistence"] = list(
        cast(list[str], typed_result.get("reasons", []))
    )
    productive = {
        item
        for item in used
        if id_set(transformations[item].get("outputs")) & targets or item in used
    }
    raf_reasons: list[str] = []
    if not productive:
        raf_reasons.append("target_productive_transformation_set_empty")
    for transformation_id in sorted(productive):
        edge = transformations[transformation_id]
        if edge.get("explicitly_uncatalyzed") is not True and not edge.get("catalyst_clauses"):
            raf_reasons.append(f"catalyst_clause_missing:{transformation_id}")
    profile["target_bound_generative_catalysis"] = (
        "satisfied" if productive and not raf_reasons else "violated"
    )
    reasons["target_bound_generative_catalysis"] = raf_reasons
    verification_status, verification_reasons = _verification(statements)
    profile["verification_capacity"] = verification_status
    reasons["verification_capacity"] = verification_reasons
    independence_status, independence_reasons, independence_count = _independence(
        statements, int(contract.get("minimum_effective_independence", 2))
    )
    profile["effective_independence"] = independence_status
    reasons["effective_independence"] = independence_reasons
    coordination_status, coordination_reasons = _coordination(store, manifest)
    profile["coordination_protocol_integrity"] = coordination_status
    reasons["coordination_protocol_integrity"] = coordination_reasons
    perturbation_results: list[JsonObject] = []
    if include_robustness:
        suite_refs = id_set(contract.get("perturbation_suite_refs"))
        suites = [
            item
            for item in statements
            if _record_type(item) == "evidence"
            and _attributes(item).get("evidence_type") == "perturbation_suite"
            and _subject(item) in suite_refs
        ]
        if not suite_refs or len(suites) != len(suite_refs):
            profile["perturbation_robustness"] = "violated"
            reasons["perturbation_robustness"] = ["required_nonempty_perturbation_suite_missing"]
        else:
            robust = True
            unknown = False
            for suite in suites:
                scenarios = _attributes(suite).get("scenarios")
                acceptance = id_set(_attributes(suite).get("acceptance_dimensions"))
                if (
                    not isinstance(scenarios, list)
                    or not scenarios
                    or len(scenarios) > MAX_PERTURBATIONS
                    or not (MANDATORY_DIMENSIONS - {"perturbation_robustness"}) <= acceptance
                ):
                    robust = False
                    reasons["perturbation_robustness"].append(
                        f"perturbation_suite_incomplete:{_subject(suite)}"
                    )
                    continue
                for scenario in scenarios:
                    if not isinstance(scenario, dict):
                        robust = False
                        continue
                    removed_subjects = id_set(scenario.get("remove_subjects"))
                    removed_keys = id_set(scenario.get("remove_key_ids"))
                    reduced = [
                        item
                        for item in statements
                        if _subject(item) not in removed_subjects
                        and str(item.get("protected", {}).get("key_id")) not in removed_keys
                    ]
                    reduced_manifest = cast(
                        JsonObject,
                        {
                            **manifest,
                            "objects": [
                                entry
                                for entry in manifest.get("objects", [])
                                if not isinstance(entry, dict)
                                or entry.get("authority_key_id") not in removed_keys
                            ],
                        },
                    )
                    evaluated = _evaluate(
                        store,
                        reduced_manifest,
                        contract,
                        policy,
                        reduced,
                        [],
                        include_robustness=False,
                    )
                    reduced_profile = cast(JsonObject, evaluated["profile"])
                    failures = sorted(
                        dimension
                        for dimension in MANDATORY_DIMENSIONS - {"perturbation_robustness"}
                        if reduced_profile.get(dimension) != "satisfied"
                    )
                    robust &= not failures
                    unknown |= any(
                        reduced_profile.get(item) == "unknown"
                        for item in MANDATORY_DIMENSIONS - {"perturbation_robustness"}
                    )
                    perturbation_results.append(
                        {
                            "scenario_id": scenario.get("scenario_id"),
                            "removed_subjects": sorted(removed_subjects),
                            "removed_key_ids": sorted(removed_keys),
                            "profile": reduced_profile,
                            "failed_dimensions": failures,
                            "analysis_snapshot_digest": evaluated["analysis_snapshot_digest"],
                        }
                    )
            profile["perturbation_robustness"] = (
                "unknown" if unknown else "satisfied" if robust else "violated"
            )
    return {
        "profile": profile,
        "reasons": reasons,
        "analysis_snapshot_digest": snapshot,
        "operation_count": operations,
        "reachable_states": sorted(reachable),
        "formation_layers": {key: layers[key] for key in sorted(layers)},
        "effective_independence_domain_count": independence_count,
        "typed_flow_result": typed_result,
        "perturbation_results": perturbation_results,
    }


def science_audit_v5(root: Path) -> JsonObject:
    try:
        store = GenerationStoreV5(root)
        manifest, contract, statements, rejected = active_attestations_v5(root)
        policy = store.get_json(str(manifest["trust_policy_digest"]))
        if not isinstance(policy, dict):
            raise ValueError("trust policy missing")
        evaluated = _evaluate(
            store, manifest, contract, policy, statements, rejected, include_robustness=True
        )
    except (OSError, KeyError, TypeError, ValueError) as error:
        return response("failed", "science_audit_failed", detail=str(error))
    profile = cast(JsonObject, evaluated["profile"])
    compatible = all(profile.get(item) == "satisfied" for item in MANDATORY_DIMENSIONS)
    unknowns = sorted(
        item
        for item in MANDATORY_DIMENSIONS
        if profile.get(item) in {"unknown", "unknown_due_to_budget"}
    )
    from collective_phase_control_fabric.trials_v5 import acceleration_status_v5

    acceleration = acceleration_status_v5(root)
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        claims=["operational_organization_compatible"] if compatible else [],
        unknowns=unknowns,
        quarantined=list(cast(list[str], manifest.get("quarantine", []))),
        operational_organization_profile=profile,
        operational_organization_compatible=compatible,
        reasons=evaluated["reasons"],
        analysis_snapshot_digest=evaluated["analysis_snapshot_digest"],
        operation_count=evaluated["operation_count"],
        reachable_states=evaluated.get("reachable_states", []),
        formation_layers=evaluated.get("formation_layers", {}),
        effective_independence_domain_count=evaluated.get("effective_independence_domain_count", 0),
        typed_flow_result=evaluated.get("typed_flow_result", {}),
        perturbation_results=evaluated.get("perturbation_results", []),
        legacy_inspection=None,
        collective_superintelligence_phase_inferred=False,
        physical_phase_inferred=False,
        causal_acceleration_certified=False,
        acceleration_status=acceleration.get("acceleration_status"),
        acceleration_evidence_tier=acceleration.get("evidence_tier"),
    )


def perturbation_replay_v5(root: Path, suite_id: str) -> JsonObject:
    audit = science_audit_v5(root)
    try:
        manifest, _, statements, _ = active_attestations_v5(root)
    except (OSError, ValueError) as error:
        return response("failed", "perturbation_workspace_invalid", detail=str(error))
    exists = any(
        _subject(item) == suite_id
        and _attributes(item).get("evidence_type") == "perturbation_suite"
        for item in statements
    )
    if not exists:
        return response("failed", "perturbation_suite_not_found")
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        claims=["full_reduced_snapshot_audit_replayed"],
        unknowns=list(cast(list[str], audit.get("unknowns", []))),
        suite_id=suite_id,
        results=list(cast(list[JsonObject], audit.get("perturbation_results", []))),
    )


def intervention_analysis_v5(root: Path) -> JsonObject:
    """Return the finite blocker frontier and planner-derived Pareto interventions."""

    audit = science_audit_v5(root)
    if audit.get("command_status") != "ok":
        return audit
    from collective_phase_control_fabric.planner_v5 import plan_v5
    from collective_phase_control_fabric.structural_v5 import (
        bounded_minimal_cut_sets,
        bounded_one_safe_occurrence_prefix,
        exact_flux_coupling,
    )

    plan = plan_v5(root)
    _, contract, statements, _ = active_attestations_v5(root)
    initial, transformations, _, _, _ = _network(statements)
    coordinates = sorted(
        {
            str(coordinate)
            for transformation in transformations.values()
            for coordinate in transformation.get("coordinate_flows", {})
        }
    )
    budget = min(
        100_000,
        int(contract.get("analysis_limits", {}).get("maximum_operations", 100_000)),
    )
    flux_coupling = exact_flux_coupling(transformations, coordinates)
    cut_sets = bounded_minimal_cut_sets(
        initial,
        transformations,
        id_set(contract.get("target_states")),
        maximum_cut_size=3,
        operation_budget=budget,
    )
    occurrence_prefix = bounded_one_safe_occurrence_prefix(
        initial, transformations, operation_budget=budget
    )
    profile = cast(JsonObject, audit.get("operational_organization_profile", {}))
    blockers = sorted(item for item, status in profile.items() if status != "satisfied")
    reasons = cast(JsonObject, audit.get("reasons", {}))
    frontier = [
        {
            "dimension": item,
            "reasons": reasons.get(item, []),
            "minimality": "bounded_declared_registry",
        }
        for item in blockers
    ]
    return response(
        "ok",
        None,
        generation=cast(str | None, audit.get("workspace_generation")),
        claims=["finite_blocker_frontier_computed"],
        unknowns=list(cast(list[str], audit.get("unknowns", []))),
        blocker_frontier=frontier,
        primary_intervention=plan.get("primary_action"),
        pareto_interventions=plan.get("pareto_alternatives", []),
        counterexample_policy_trees=plan.get("and_or_policy_trees", []),
        flux_coupling=flux_coupling,
        minimal_cut_sets=cut_sets,
        one_safe_occurrence_prefix=occurrence_prefix,
        general_controllability_claim=False,
        scalar_score_used=False,
    )
