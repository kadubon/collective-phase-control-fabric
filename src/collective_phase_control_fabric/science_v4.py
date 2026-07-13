# SPDX-License-Identifier: Apache-2.0
"""Evidence-bound operational organization analysis for CPCF v0.4."""

from __future__ import annotations

from fractions import Fraction
from itertools import combinations
from pathlib import Path
from typing import Any, cast

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.limits import (
    MAX_ANALYSIS_OPERATIONS,
    MAX_PERTURBATIONS,
    MAX_RATIONAL_BITS,
)
from collective_phase_control_fabric.types import JsonObject, JsonValue, id_set
from collective_phase_control_fabric.workspace_v4 import active_attestations_v4, response

DIMENSIONS = (
    "provenance_integrity",
    "structural_reachability",
    "causal_formation",
    "exact_self_maintenance",
    "finite_resource_persistence",
    "target_bound_generative_catalysis",
    "verification_capacity",
    "effective_independence",
    "perturbation_robustness",
)


def _fraction(value: object) -> Fraction:
    parsed = Fraction(str(value))
    if (
        parsed.numerator.bit_length() > MAX_RATIONAL_BITS
        or parsed.denominator.bit_length() > MAX_RATIONAL_BITS
    ):
        raise ValueError("maximum_rational_bits_exceeded")
    return parsed


def _payloads(statements: list[JsonObject]) -> list[JsonObject]:
    return [
        cast(JsonObject, statement["payload"])
        for statement in statements
        if isinstance(statement.get("payload"), dict)
    ]


def _attributes(record: JsonObject) -> JsonObject:
    value = record.get("attributes")
    return value if isinstance(value, dict) else {}


def _records(records: list[JsonObject], record_type: str) -> list[JsonObject]:
    return [item for item in records if item.get("record_type") == record_type]


def _scientific_records(records: list[JsonObject], evidence_type: str) -> list[JsonObject]:
    return [
        item
        for item in _records(records, "evidence")
        if _attributes(item).get("evidence_type") == evidence_type
    ]


def _snapshot_digest(generation_id: str, contract: JsonObject, records: list[JsonObject]) -> str:
    declared_bases = {
        str(_attributes(item).get("analysis_base_generation_id"))
        for item in _records(records, "evidence")
        if isinstance(_attributes(item).get("analysis_base_generation_id"), str)
    }
    analysis_generation = next(iter(declared_bases)) if len(declared_bases) == 1 else generation_id
    transformations = sorted(
        str(item.get("subject_digest")) for item in _records(records, "transformation")
    )
    markings = sorted(
        str(item.get("subject_digest"))
        for item in records
        if item.get("record_type") in {"state", "resource_observation", "boundary_supply"}
    )
    return digest_v3_json(
        cast(
            JsonValue,
            {
                "analysis_base_generation_id": analysis_generation,
                "targets": sorted(id_set(contract.get("target_states"))),
                "transformations": transformations,
                "markings": markings,
            },
        )
    )


def _network(records: list[JsonObject]) -> tuple[set[str], dict[str, JsonObject]]:
    available = {
        str(item["subject_id"])
        for item in _records(records, "state")
        if _attributes(item).get("available") is True
    }
    available.update(str(item["subject_id"]) for item in _records(records, "authority"))
    available.update(str(item["subject_id"]) for item in _records(records, "hazard"))
    available.update(str(item["subject_id"]) for item in _records(records, "catalyst"))
    available.update(str(item["subject_id"]) for item in _records(records, "inhibitor"))
    available.update(str(item["subject_id"]) for item in _records(records, "evidence"))
    transformations: dict[str, JsonObject] = {}
    for item in _records(records, "transformation"):
        subject = str(item["subject_id"])
        if subject in transformations:
            raise ValueError(f"duplicate transformation subject: {subject}")
        transformations[subject] = _attributes(item)
    return available, transformations


def _enabled(edge: JsonObject, available: set[str]) -> bool:
    if not id_set(edge.get("inputs")) <= available:
        return False
    if not id_set(edge.get("authority_refs")) <= available:
        return False
    if not id_set(edge.get("evidence_refs")) <= available:
        return False
    if id_set(edge.get("inhibitors")) & available:
        return False
    clauses = edge.get("catalyst_clauses", [])
    if not isinstance(clauses, list):
        return False
    if edge.get("explicitly_uncatalyzed") is True:
        return True
    return bool(clauses) and all(id_set(clause) & available for clause in clauses)


def _closure(
    initial: set[str], transformations: dict[str, JsonObject], operation_budget: int
) -> tuple[set[str], dict[str, int], int]:
    available = set(initial)
    layers: dict[str, int] = {item: 0 for item in available}
    operations = 0
    layer = 0
    while True:
        layer += 1
        additions: set[str] = set()
        for edge_id in sorted(transformations):
            operations += 1
            if operations > operation_budget:
                raise RuntimeError("unknown_due_to_budget")
            edge = transformations[edge_id]
            if _enabled(edge, available):
                additions.update(id_set(edge.get("outputs")) - available)
        if not additions:
            break
        for item in sorted(additions):
            layers[item] = layer
        available.update(additions)
    return available, layers, operations


def _organization(
    records: list[JsonObject],
    transformations: dict[str, JsonObject],
    snapshot_digest: str,
) -> tuple[str, list[str], dict[str, Fraction]]:
    witnesses = _scientific_records(records, "organization_witness")
    if len(witnesses) != 1:
        return "unknown", ["exactly_one_organization_witness_required"], {}
    attributes = _attributes(witnesses[0])
    if attributes.get("analysis_snapshot_digest") != snapshot_digest:
        return "violated", ["organization_snapshot_mismatch"], {}
    flux_raw = attributes.get("flux")
    if not isinstance(flux_raw, dict) or not flux_raw:
        return "violated", ["strictly_positive_flux_required"], {}
    try:
        flux = {str(key): _fraction(value) for key, value in flux_raw.items()}
    except (ValueError, ZeroDivisionError):
        return "violated", ["flux_rational_invalid"], {}
    if set(flux) != set(transformations) or any(value <= 0 for value in flux.values()):
        return "violated", ["flux_transformation_set_or_positivity_invalid"], flux
    balances: dict[str, Fraction] = {}
    for edge_id, edge in transformations.items():
        flows = edge.get("coordinate_flows", {})
        if not isinstance(flows, dict):
            return "violated", [f"coordinate_flows_invalid:{edge_id}"], flux
        for coordinate, value in flows.items():
            try:
                balances[str(coordinate)] = balances.get(str(coordinate), Fraction(0)) + flux[
                    edge_id
                ] * _fraction(value)
            except (ValueError, ZeroDivisionError):
                return "violated", [f"coordinate_flow_invalid:{edge_id}:{coordinate}"], flux
    negative = sorted(coordinate for coordinate, value in balances.items() if value < 0)
    if negative:
        return "violated", [f"negative_maintenance_balance:{item}" for item in negative], flux
    return "satisfied", [], flux


def _formation(
    contract: JsonObject,
    records: list[JsonObject],
    initial: set[str],
    transformations: dict[str, JsonObject],
    snapshot_digest: str,
) -> tuple[str, list[str]]:
    witnesses = _scientific_records(records, "formation_sequence_witness")
    if len(witnesses) != 1:
        return "unknown", ["exactly_one_formation_sequence_witness_required"]
    attributes = _attributes(witnesses[0])
    if attributes.get("analysis_snapshot_digest") != snapshot_digest:
        return "violated", ["formation_snapshot_mismatch"]
    steps = attributes.get("steps")
    if not isinstance(steps, list) or not steps:
        return "violated", ["formation_steps_required"]
    available = set(initial)
    resources: dict[str, Fraction] = {}
    units: dict[str, str] = {}
    for record in _records(records, "resource_observation"):
        observed = _attributes(record)
        try:
            coordinate = str(observed["coordinate"])
            resources[coordinate] = _fraction(observed["quantity"])
            units[coordinate] = str(observed["unit"])
        except (KeyError, ValueError, ZeroDivisionError):
            return "violated", ["formation_resource_observation_invalid"]
    used: list[str] = []
    reasons: list[str] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            reasons.append(f"formation_step_invalid:{index}")
            continue
        edge_id = str(step.get("transformation_id"))
        edge = transformations.get(edge_id)
        if edge is None:
            reasons.append(f"formation_transformation_missing:{edge_id}")
            continue
        try:
            multiplier = _fraction(step.get("multiplier", "1"))
        except (ValueError, ZeroDivisionError):
            reasons.append(f"formation_multiplier_invalid:{edge_id}")
            continue
        if multiplier <= 0:
            reasons.append(f"formation_multiplier_not_positive:{edge_id}")
        if not _enabled(edge, available):
            reasons.append(f"formation_not_strictly_prior_enabled:{edge_id}")
        flows = edge.get("coordinate_flows", {})
        if not isinstance(flows, dict):
            reasons.append(f"formation_coordinate_flows_invalid:{edge_id}")
            continue
        for coordinate, value in flows.items():
            resources[str(coordinate)] = resources.get(
                str(coordinate), Fraction(0)
            ) + multiplier * _fraction(value)
        for coordinate, floor in contract.get("protected_floors", {}).items():
            if not isinstance(floor, dict) or units.get(coordinate) != floor.get("unit"):
                reasons.append(f"formation_floor_unit_or_observation_missing:{coordinate}")
            elif resources.get(coordinate, Fraction(0)) < _fraction(floor["quantity"]):
                reasons.append(f"formation_prefix_floor_violation:{index}:{coordinate}")
        available.update(id_set(edge.get("outputs")))
        used.append(edge_id)
    if set(used) != set(transformations):
        reasons.append("formation_transformation_set_mismatch")
    if not id_set(contract.get("target_states")) <= available:
        reasons.append("formation_targets_not_produced")
    return ("satisfied" if not reasons else "violated"), reasons


def _resources(
    contract: JsonObject,
    records: list[JsonObject],
    transformations: dict[str, JsonObject],
    flux: dict[str, Fraction],
    snapshot_digest: str,
) -> tuple[str, list[str]]:
    if not flux:
        return "unknown", ["organization_flux_unavailable"]
    observations: dict[str, tuple[Fraction, str]] = {}
    for record in _records(records, "resource_observation"):
        attributes = _attributes(record)
        coordinate = str(attributes.get("coordinate"))
        try:
            observations[coordinate] = (_fraction(attributes["quantity"]), str(attributes["unit"]))
        except (KeyError, ValueError, ZeroDivisionError):
            return "violated", [f"resource_observation_invalid:{coordinate}"]
    supplies: dict[str, Fraction] = {}
    for record in _records(records, "boundary_supply"):
        attributes = _attributes(record)
        coordinate = str(attributes.get("coordinate"))
        try:
            supplies[coordinate] = supplies.get(coordinate, Fraction(0)) + _fraction(
                attributes["quantity"]
            )
        except (KeyError, ValueError, ZeroDivisionError):
            return "violated", [f"boundary_supply_invalid:{coordinate}"]
    reasons: list[str] = []
    unknown = False
    for coordinate, floor in contract.get("protected_floors", {}).items():
        if not isinstance(floor, dict) or coordinate not in observations:
            reasons.append(f"protected_resource_observation_missing:{coordinate}")
            continue
        quantity, unit = observations[coordinate]
        if unit != floor.get("unit"):
            reasons.append(f"protected_resource_unit_mismatch:{coordinate}")
            continue
        net = quantity + supplies.get(coordinate, Fraction(0))
        for edge_id, edge in transformations.items():
            flows = edge.get("coordinate_flows", {})
            if isinstance(flows, dict) and coordinate in flows:
                net += flux[edge_id] * _fraction(flows[coordinate])
        if net < _fraction(floor["quantity"]):
            reasons.append(f"protected_resource_floor_violation:{coordinate}")
    rate_witnesses = _scientific_records(records, "rate_feasibility_witness")
    if len(rate_witnesses) != 1:
        reasons.append("rate_feasibility_witness_required")
    else:
        rate = _attributes(rate_witnesses[0])
        if rate.get("analysis_snapshot_digest") != snapshot_digest:
            reasons.append("rate_snapshot_mismatch")
        if id_set(rate.get("transformation_refs")) != set(transformations):
            reasons.append("rate_transformation_set_mismatch")
        live_attestation_ids = {str(item.get("attestation_id")) for item in records}
        if not id_set(rate.get("source_refs")) <= live_attestation_ids:
            reasons.append("rate_source_reference_not_live")
        feasible_flux = rate.get("feasible_flux")
        if not isinstance(feasible_flux, dict):
            reasons.append("rate_feasible_flux_missing")
        else:
            try:
                if {key: _fraction(value) for key, value in feasible_flux.items()} != flux:
                    reasons.append("rate_feasible_flux_mismatch")
            except (ValueError, ZeroDivisionError):
                reasons.append("rate_feasible_flux_invalid")
        intervals = rate.get("rate_intervals")
        if not isinstance(intervals, dict) or set(intervals) != set(transformations):
            reasons.append("rate_interval_coverage_incomplete")
        else:
            rate_units = {
                str(item.get("unit")) for item in intervals.values() if isinstance(item, dict)
            }
            if len(rate_units) != 1:
                reasons.append("rate_interval_units_not_common")
            for edge_id, interval in intervals.items():
                if not isinstance(interval, dict):
                    reasons.append(f"rate_interval_invalid:{edge_id}")
                    continue
                try:
                    lower = _fraction(interval["lower"])
                    upper = _fraction(interval["upper"])
                    if lower > flux[edge_id] or upper < flux[edge_id] or lower > upper:
                        reasons.append(f"rate_flux_outside_interval:{edge_id}")
                except (KeyError, ValueError, ZeroDivisionError):
                    reasons.append(f"rate_interval_invalid:{edge_id}")
        if not isinstance(rate.get("observation_window"), dict):
            reasons.append("rate_observation_window_missing")
    siphon_witnesses = _scientific_records(records, "siphon_coverage_witness")
    if len(siphon_witnesses) != 1:
        reasons.append("siphon_coverage_witness_required")
    elif _attributes(siphon_witnesses[0]).get("analysis_snapshot_digest") != snapshot_digest:
        reasons.append("siphon_snapshot_mismatch")
    else:
        species = sorted(
            set().union(
                *(
                    id_set(edge.get("inputs")) | id_set(edge.get("outputs"))
                    for edge in transformations.values()
                )
            )
        )
        if len(species) > 16:
            unknown = True
        else:
            siphons: list[set[str]] = []
            for size in range(1, len(species) + 1):
                for candidate_tuple in combinations(species, size):
                    candidate = set(candidate_tuple)
                    if any(existing <= candidate for existing in siphons):
                        continue
                    is_siphon = all(
                        not (id_set(edge.get("outputs")) & candidate)
                        or bool(id_set(edge.get("inputs")) & candidate)
                        for edge in transformations.values()
                    )
                    if is_siphon:
                        siphons.append(candidate)
            declared = _attributes(siphon_witnesses[0]).get("covered_siphons", [])
            covered = (
                {
                    tuple(sorted(str(item) for item in value))
                    for value in declared
                    if isinstance(value, list)
                }
                if isinstance(declared, list)
                else set()
            )
            missing_siphons = [
                sorted(siphon) for siphon in siphons if tuple(sorted(siphon)) not in covered
            ]
            if missing_siphons:
                reasons.append("minimal_siphon_coverage_incomplete")
    profiles = _scientific_records(records, "open_system_resource_profile")
    if len(profiles) != 1:
        reasons.append("open_system_resource_profile_required")
    else:
        attributes = _attributes(profiles[0])
        if attributes.get("analysis_snapshot_digest") != snapshot_digest:
            reasons.append("resource_profile_snapshot_mismatch")
        internal = id_set(attributes.get("internal_coordinates"))
        boundary = id_set(attributes.get("boundary_coordinates"))
        if internal & boundary:
            reasons.append("internal_boundary_coordinate_overlap")
        weights_raw = attributes.get("potential_weights", {})
        if not isinstance(weights_raw, dict) or set(weights_raw) != internal:
            reasons.append("resource_potential_coordinate_coverage_incomplete")
        else:
            try:
                weights = {key: _fraction(value) for key, value in weights_raw.items()}
                if any(value <= 0 for value in weights.values()):
                    reasons.append("resource_potential_weights_not_positive")
                for protected in contract.get("protected_floors", {}):
                    if protected not in weights or weights[protected] <= 0:
                        reasons.append(f"protected_coordinate_weight_missing:{protected}")
                for edge_id, edge in transformations.items():
                    flows = edge.get("coordinate_flows", {})
                    if not isinstance(flows, dict):
                        reasons.append(f"resource_flow_invalid:{edge_id}")
                        continue
                    gain = sum(
                        (weights[coordinate] * _fraction(flows.get(coordinate, "0")))
                        for coordinate in internal
                    )
                    credit = _fraction(edge.get("validated_boundary_supply_credit", "0"))
                    if gain - credit > 0:
                        reasons.append(f"closed_positive_resource_gain:{edge_id}")
            except (ValueError, ZeroDivisionError):
                reasons.append("resource_potential_rational_invalid")
    if reasons:
        return "violated", reasons
    if unknown:
        return "unknown", ["minimal_siphon_search_unknown_due_to_budget"]
    return "satisfied", []


def _raf(
    contract: JsonObject,
    transformations: dict[str, JsonObject],
    initial: set[str],
    layers: dict[str, int],
    reachable: set[str],
) -> tuple[str, list[str]]:
    targets = id_set(contract.get("target_states"))
    if not targets <= reachable:
        return "violated", ["target_not_structurally_reachable"]
    reasons: list[str] = []
    for edge_id, edge in transformations.items():
        outputs = id_set(edge.get("outputs"))
        if not outputs & targets and not any(output in layers for output in outputs):
            continue
        if edge.get("explicitly_uncatalyzed") is True:
            continue
        output_layer = min((layers[item] for item in outputs if item in layers), default=0)
        clauses = edge.get("catalyst_clauses", [])
        if not clauses:
            reasons.append(f"catalyst_clause_missing:{edge_id}")
            continue
        for index, clause in enumerate(clauses):
            catalysts = id_set(clause)
            if not any(
                item in initial or layers.get(item, output_layer) < output_layer
                for item in catalysts
            ):
                reasons.append(f"non_prior_or_circular_catalyst:{edge_id}:{index}")
    return ("satisfied" if not reasons else "violated"), reasons


def _verification(records: list[JsonObject]) -> tuple[str, list[str]]:
    stages = _records(records, "verifier")
    if not stages:
        return "unknown", ["verifier_stage_attestations_required"]
    reasons: list[str] = []
    live_source_digests = {str(item.get("source_artifact_digest")) for item in records} | {
        str(item.get("subject_digest")) for item in records
    }
    windows: set[str] = set()
    independence_domains: set[str] = set()
    for stage in stages:
        attributes = _attributes(stage)
        try:
            arrival = _fraction(attributes["arrival_upper"])
            service = _fraction(attributes["service_lower"])
            if str(attributes["arrival_unit"]) != str(attributes["service_unit"]):
                reasons.append(f"verifier_unit_mismatch:{stage['subject_id']}")
            elif service <= 0 or arrival >= service:
                reasons.append(f"verifier_overloaded:{stage['subject_id']}")
            window = attributes.get("observation_window")
            if not isinstance(window, dict):
                reasons.append(f"verifier_window_missing:{stage['subject_id']}")
            else:
                windows.add(digest_v3_json(cast(JsonValue, window)))
            amplification = _fraction(attributes.get("routing_amplification", "1"))
            if amplification < 1:
                reasons.append(f"routing_amplification_invalid:{stage['subject_id']}")
            independence = attributes.get("independence_domain")
            if not isinstance(independence, str) or not independence:
                reasons.append(f"verifier_independence_domain_missing:{stage['subject_id']}")
            else:
                if independence in independence_domains:
                    reasons.append(f"verifier_independence_domain_reused:{independence}")
                independence_domains.add(independence)
            if attributes.get("source_record_digest") not in live_source_digests:
                reasons.append(f"verifier_source_record_missing:{stage['subject_id']}")
            arrival_curve = attributes.get("arrival_curve")
            service_curve = attributes.get("service_curve")
            if arrival_curve is not None or service_curve is not None:
                if not isinstance(arrival_curve, list) or not isinstance(service_curve, list):
                    reasons.append(f"network_calculus_curve_pair_invalid:{stage['subject_id']}")
                elif len(arrival_curve) != len(service_curve) or not arrival_curve:
                    reasons.append(f"network_calculus_curve_grid_invalid:{stage['subject_id']}")
                else:
                    backlog = max(
                        _fraction(left) - _fraction(right)
                        for left, right in zip(arrival_curve, service_curve, strict=True)
                    )
                    declared_backlog = _fraction(attributes.get("backlog_upper", "0"))
                    if backlog > declared_backlog:
                        reasons.append(
                            f"network_calculus_backlog_bound_invalid:{stage['subject_id']}"
                        )
        except (KeyError, ValueError, ZeroDivisionError):
            reasons.append(f"verifier_interval_invalid:{stage['subject_id']}")
    if len(windows) > 1:
        reasons.append("verifier_observation_windows_not_common")
    return ("satisfied" if not reasons else "violated"), reasons


def _independence(
    statements: list[JsonObject], records: list[JsonObject]
) -> tuple[str, list[str], int]:
    observations = [
        item
        for item in _records(records, "independence")
        if _attributes(item).get("observed_closed_boundary") is True
    ]
    if not observations:
        return "unknown", ["trusted_compartment_observation_required"], 0
    attestation_ids = {str(item.get("attestation_id")) for item in records}
    subject_digests = {str(item.get("subject_digest")) for item in records}
    principal_by_attestation = {
        str(statement["payload"].get("attestation_id")): str(statement["protected"].get("key_id"))
        for statement in statements
        if isinstance(statement.get("payload"), dict)
        and isinstance(statement.get("protected"), dict)
    }
    domains: list[set[str]] = []
    reasons: list[str] = []
    for record in observations:
        principal = principal_by_attestation.get(str(record.get("attestation_id")))
        if principal is None:
            reasons.append(f"independence_principal_missing:{record.get('attestation_id')}")
            continue
        attributes = _attributes(record)
        if (
            attributes.get("commitment_digest") is None
            or attributes.get("observer_attestation_ref") is None
        ):
            reasons.append(f"independence_commitment_or_observer_missing:{record['subject_id']}")
        elif attributes.get("commitment_digest") not in subject_digests:
            reasons.append(f"independence_commitment_not_live:{record['subject_id']}")
        elif attributes.get("observer_attestation_ref") not in attestation_ids:
            reasons.append(f"independence_observer_not_live:{record['subject_id']}")
        domain = {
            principal,
            *cast(list[str], record.get("lineage_refs", [])),
            *cast(list[str], record.get("correlation_domains", [])),
        }
        infrastructure = attributes.get("infrastructure_domains", [])
        if isinstance(infrastructure, list):
            domain.update(str(item) for item in infrastructure)
        domains.append(domain)
    # Connected components under any shared dependency are the effective domains.
    components: list[set[str]] = []
    for domain in domains:
        touching = [item for item in components if item & domain]
        merged = set(domain)
        for item in touching:
            merged.update(item)
            components.remove(item)
        components.append(merged)
    exposures = _records(records, "exposure")
    if any(_attributes(item).get("before_commitment") is True for item in exposures):
        reasons.append("precommit_information_exposure_detected")
    status = "satisfied" if components and not reasons else "violated" if reasons else "unknown"
    return status, reasons, len(components)


def _evaluate(
    generation_id: str,
    contract: JsonObject,
    statements: list[JsonObject],
    rejected: list[JsonObject],
    *,
    include_robustness: bool,
) -> JsonObject:
    records = _payloads(statements)
    snapshot = _snapshot_digest(generation_id, contract, records)
    operation_budget = min(
        MAX_ANALYSIS_OPERATIONS,
        int(contract.get("analysis_limits", {}).get("maximum_operations", MAX_ANALYSIS_OPERATIONS)),
    )
    reasons: dict[str, list[str]] = {item: [] for item in DIMENSIONS}
    profile = {item: "unknown" for item in DIMENSIONS}
    profile["provenance_integrity"] = "satisfied" if statements and not rejected else "violated"
    reasons["provenance_integrity"] = (
        [f"rejected_attestation:{item.get('digest')}" for item in rejected]
        if rejected
        else ([] if statements else ["typed_attestations_required"])
    )
    declared_bases = {
        str(_attributes(item).get("analysis_base_generation_id"))
        for item in _records(records, "evidence")
        if isinstance(_attributes(item).get("analysis_base_generation_id"), str)
    }
    if len(declared_bases) > 1:
        profile["provenance_integrity"] = "violated"
        reasons["provenance_integrity"].append("cross_generation_witness_composition")
    attestation_ids = [str(item.get("attestation_id")) for item in records]
    duplicate_attestation_ids = sorted(
        {item for item in attestation_ids if attestation_ids.count(item) > 1}
    )
    typed_subjects = [
        (str(item.get("record_type")), str(item.get("subject_id"))) for item in records
    ]
    duplicate_typed_subjects = sorted(
        {item for item in typed_subjects if typed_subjects.count(item) > 1}
    )
    if duplicate_attestation_ids or duplicate_typed_subjects:
        profile["provenance_integrity"] = "violated"
        reasons["provenance_integrity"].extend(
            f"duplicate_attestation_id:{item}" for item in duplicate_attestation_ids
        )
        reasons["provenance_integrity"].extend(
            f"duplicate_typed_subject:{kind}:{subject}"
            for kind, subject in duplicate_typed_subjects
        )
    try:
        initial, transformations = _network(records)
        reachable, layers, operations = _closure(initial, transformations, operation_budget)
    except RuntimeError:
        return {
            "profile": profile,
            "reasons": {**reasons, "structural_reachability": ["unknown_due_to_budget"]},
            "analysis_snapshot_digest": snapshot,
            "operation_count": operation_budget,
        }
    targets = id_set(contract.get("target_states"))
    missing = sorted(targets - reachable)
    profile["structural_reachability"] = "satisfied" if not missing else "violated"
    reasons["structural_reachability"] = [f"target_unreachable:{item}" for item in missing]
    formation_status, formation_reasons = _formation(
        contract, records, initial, transformations, snapshot
    )
    profile["causal_formation"] = formation_status
    reasons["causal_formation"] = formation_reasons
    organization_status, organization_reasons, flux = _organization(
        records, transformations, snapshot
    )
    profile["exact_self_maintenance"] = organization_status
    reasons["exact_self_maintenance"] = organization_reasons
    resource_status, resource_reasons = _resources(
        contract, records, transformations, flux, snapshot
    )
    profile["finite_resource_persistence"] = resource_status
    reasons["finite_resource_persistence"] = resource_reasons
    raf_status, raf_reasons = _raf(contract, transformations, initial, layers, reachable)
    profile["target_bound_generative_catalysis"] = raf_status
    reasons["target_bound_generative_catalysis"] = raf_reasons
    verification_status, verification_reasons = _verification(records)
    profile["verification_capacity"] = verification_status
    reasons["verification_capacity"] = verification_reasons
    independence_status, independence_reasons, domain_count = _independence(statements, records)
    profile["effective_independence"] = independence_status
    reasons["effective_independence"] = independence_reasons
    perturbation_results: list[JsonObject] = []
    if include_robustness:
        suites = _scientific_records(records, "perturbation_suite")
        required_refs = id_set(contract.get("perturbation_suite_refs"))
        available_refs = {str(item.get("subject_id")) for item in suites}
        if not required_refs or not required_refs <= available_refs:
            profile["perturbation_robustness"] = "violated"
            reasons["perturbation_robustness"] = ["required_nonempty_perturbation_suite_missing"]
        else:
            robust = True
            unknown = False
            for suite in suites:
                attributes = _attributes(suite)
                scenarios = attributes.get("scenarios", [])
                acceptance = id_set(attributes.get("acceptance_dimensions"))
                if (
                    not isinstance(scenarios, list)
                    or not scenarios
                    or len(scenarios) > MAX_PERTURBATIONS
                ):
                    robust = False
                    reasons["perturbation_robustness"].append(
                        f"perturbation_scenarios_invalid:{suite.get('subject_id')}"
                    )
                    continue
                required_dimensions = id_set(contract.get("required_dimensions")) - {
                    "perturbation_robustness"
                }
                if not required_dimensions <= acceptance:
                    robust = False
                    reasons["perturbation_robustness"].append(
                        f"perturbation_acceptance_incomplete:{suite.get('subject_id')}"
                    )
                    continue
                for scenario in scenarios:
                    if not isinstance(scenario, dict):
                        robust = False
                        continue
                    removed_subjects = id_set(scenario.get("remove_subjects"))
                    removed_keys = id_set(scenario.get("remove_key_ids"))
                    reduced = [
                        statement
                        for statement in statements
                        if isinstance(statement.get("payload"), dict)
                        and str(statement["payload"].get("subject_id")) not in removed_subjects
                        and isinstance(statement.get("protected"), dict)
                        and str(statement["protected"].get("key_id")) not in removed_keys
                        and statement["payload"].get("attestation_id")
                        != suite.get("attestation_id")
                    ]
                    evaluated = _evaluate(
                        generation_id, contract, reduced, [], include_robustness=False
                    )
                    scenario_profile = cast(JsonObject, evaluated["profile"])
                    failures = sorted(
                        dimension
                        for dimension in required_dimensions
                        if scenario_profile.get(dimension) != "satisfied"
                    )
                    unknown |= any(
                        scenario_profile.get(item) == "unknown" for item in required_dimensions
                    )
                    robust &= not failures
                    perturbation_results.append(
                        {
                            "scenario_id": scenario.get("scenario_id"),
                            "removed_subjects": sorted(removed_subjects),
                            "removed_key_ids": sorted(removed_keys),
                            "profile": scenario_profile,
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
        "effective_independence_domain_count": domain_count,
        "perturbation_results": perturbation_results,
    }


def science_audit_v4(root: Path) -> JsonObject:
    """Recompute the multidimensional profile from typed source-backed attestations."""

    try:
        manifest, contract, statements, rejected = active_attestations_v4(root)
        evaluated = _evaluate(
            str(manifest["generation_id"]), contract, statements, rejected, include_robustness=True
        )
    except (OSError, KeyError, TypeError, ValueError) as error:
        return response("failed", "science_audit_failed", detail=str(error))
    profile = cast(JsonObject, evaluated["profile"])
    required = id_set(contract.get("required_dimensions"))
    compatible = bool(required) and all(profile.get(item) == "satisfied" for item in required)
    unknowns = sorted(item for item in required if profile.get(item) == "unknown")
    from collective_phase_control_fabric.trials_v4 import acceleration_status_v4

    acceleration = acceleration_status_v4(root)
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
        perturbation_results=evaluated.get("perturbation_results", []),
        legacy_inspection=None,
        collective_superintelligence_phase_inferred=False,
        physical_phase_inferred=False,
        causal_acceleration_certified=False,
        acceleration_status=acceleration.get("acceleration_status"),
        acceleration_claims=acceleration.get("claims", []),
    )


def perturbation_replay_v4(root: Path, suite_id: str) -> JsonObject:
    audit = science_audit_v4(root)
    results = [item for item in audit.get("perturbation_results", []) if isinstance(item, dict)]
    try:
        _, _, statements, _ = active_attestations_v4(root)
    except (OSError, ValueError) as error:
        return response("failed", "perturbation_workspace_invalid", detail=str(error))
    suite_exists = any(
        isinstance(statement.get("payload"), dict)
        and statement["payload"].get("subject_id") == suite_id
        and _attributes(cast(JsonObject, statement["payload"])).get("evidence_type")
        == "perturbation_suite"
        for statement in statements
    )
    if not suite_exists:
        return response("failed", "perturbation_suite_not_found")
    return response(
        "ok",
        None,
        generation=cast(str | None, audit.get("workspace_generation")),
        claims=["full_operational_profile_replayed"],
        unknowns=list(cast(list[str], audit.get("unknowns", []))),
        suite_id=suite_id,
        results=results,
        baseline_profile=audit.get("operational_organization_profile"),
    )


def _minimal_cut_sets(
    contract: JsonObject, records: list[JsonObject], maximum_cardinality: int = 3
) -> JsonObject:
    initial, transformations = _network(records)
    targets = id_set(contract.get("target_states"))
    if len(transformations) > 20:
        return {"status": "unknown_due_to_budget", "cut_sets": [], "complete": False}
    cuts: list[list[str]] = []
    identifiers = sorted(transformations)
    for size in range(1, min(maximum_cardinality, len(identifiers)) + 1):
        for candidate in combinations(identifiers, size):
            if any(set(existing) <= set(candidate) for existing in cuts):
                continue
            reduced = {key: value for key, value in transformations.items() if key not in candidate}
            reachable, _, _ = _closure(initial, reduced, MAX_ANALYSIS_OPERATIONS)
            if not targets <= reachable:
                cuts.append(list(candidate))
    return {
        "status": "complete_within_cardinality_bound",
        "cut_sets": cuts,
        "maximum_cardinality": maximum_cardinality,
        "complete": maximum_cardinality >= len(identifiers),
    }


def _z3_fraction(value: Fraction) -> Any:
    import z3  # type: ignore[import-untyped]

    return z3.Q(value.numerator, value.denominator)


def _flux_coupling(contract: JsonObject, records: list[JsonObject]) -> JsonObject:
    """Classify exact steady-state activity coupling when the optional solver is present."""

    profiles = _scientific_records(records, "open_system_resource_profile")
    if len(profiles) != 1:
        return {
            "status": "unknown_resource_profile_required",
            "solution_class": "unknown",
            "solver_backend": None,
            "blocked": [],
            "directionally_coupled": [],
            "fully_coupled": [],
        }
    try:
        import z3
    except ImportError:
        return {
            "status": "unknown_solver_unavailable",
            "solution_class": "unknown",
            "solver_backend": None,
            "blocked": [],
            "directionally_coupled": [],
            "fully_coupled": [],
        }
    profile = _attributes(profiles[0])
    if profile.get("balance_mode") != "steady_state":
        return {
            "status": "unknown_steady_state_not_declared",
            "solution_class": "unknown",
            "solver_backend": z3.get_version_string(),
            "blocked": [],
            "directionally_coupled": [],
            "fully_coupled": [],
        }
    internal = id_set(profile.get("internal_coordinates"))
    _, transformations = _network(records)
    identifiers = sorted(transformations)
    if not internal or not identifiers:
        return {
            "status": "unknown_empty_flux_model",
            "solution_class": "unknown",
            "solver_backend": z3.get_version_string(),
            "blocked": [],
            "directionally_coupled": [],
            "fully_coupled": [],
        }
    variables = {item: z3.Real(f"flux_{index}") for index, item in enumerate(identifiers)}
    solver = z3.Solver()
    timeout = min(300, int(contract.get("analysis_limits", {}).get("solver_seconds", 30)))
    solver.set(timeout=timeout * 1000)
    for edge_id in identifiers:
        solver.add(variables[edge_id] >= 0)
    for coordinate in sorted(internal):
        terms = []
        for edge_id in identifiers:
            flows = transformations[edge_id].get("coordinate_flows", {})
            if isinstance(flows, dict) and coordinate in flows:
                terms.append(_z3_fraction(_fraction(flows[coordinate])) * variables[edge_id])
        solver.add(z3.Sum(terms) == 0 if terms else z3.BoolVal(True))
    solver.add(z3.Sum([variables[item] for item in identifiers]) > 0)

    def possible(*constraints: object) -> tuple[bool | None, Any | None]:
        solver.push()
        solver.add(*constraints)
        checked = solver.check()
        model = solver.model() if checked == z3.sat else None
        solver.pop()
        if checked == z3.unknown:
            return None, None
        return checked == z3.sat, model

    blocked: list[str] = []
    for edge_id in identifiers:
        feasible, _ = possible(variables[edge_id] > 0)
        if feasible is None:
            return {
                "status": "unknown_due_to_budget",
                "solution_class": "unknown",
                "solver_backend": z3.get_version_string(),
                "blocked": blocked,
                "directionally_coupled": [],
                "fully_coupled": [],
            }
        if not feasible:
            blocked.append(edge_id)
    active = [item for item in identifiers if item not in blocked]
    directional: list[JsonObject] = []
    direction_set: set[tuple[str, str]] = set()
    for left in active:
        for right in active:
            if left == right:
                continue
            counterexample, _ = possible(variables[left] > 0, variables[right] == 0)
            if counterexample is None:
                return {
                    "status": "unknown_due_to_budget",
                    "solution_class": "unknown",
                    "solver_backend": z3.get_version_string(),
                    "blocked": blocked,
                    "directionally_coupled": directional,
                    "fully_coupled": [],
                }
            if not counterexample:
                direction_set.add((left, right))
                directional.append({"from": left, "to": right})
    full: list[JsonObject] = []
    for index, left in enumerate(active):
        for right in active[index + 1 :]:
            if (left, right) not in direction_set or (right, left) not in direction_set:
                continue
            feasible, model = possible(variables[left] > 0, variables[right] > 0)
            if not feasible or model is None:
                continue
            left_value = model.evaluate(variables[left], model_completion=True)
            right_value = model.evaluate(variables[right], model_completion=True)
            ratio_fraction = Fraction(
                left_value.numerator_as_long(), left_value.denominator_as_long()
            ) / Fraction(right_value.numerator_as_long(), right_value.denominator_as_long())
            ratio = _z3_fraction(ratio_fraction)
            variable_ratio, _ = possible(
                variables[left] > 0,
                variables[right] > 0,
                variables[left] != ratio * variables[right],
            )
            if variable_ratio is False:
                full.append({"left": left, "right": right, "ratio": str(ratio_fraction)})
    return {
        "status": "complete",
        "solution_class": "solver_complete",
        "solver_backend": f"z3-solver:{z3.get_version_string()}",
        "solver_timeout_seconds": timeout,
        "blocked": blocked,
        "directionally_coupled": directional,
        "fully_coupled": full,
        "physical_or_metabolic_equivalence_claimed": False,
    }


def _bounded_one_safe_unfolding(
    contract: JsonObject, records: list[JsonObject], maximum_events: int = 256
) -> JsonObject:
    """Enumerate a bounded occurrence prefix for an explicitly declared 1-safe profile.

    This is a finite causal reachability diagnostic. It is not an unbounded Petri-net
    decidability result and does not claim a complete McMillan prefix.
    """

    if contract.get("scope", {}).get("one_safe_profile") is not True:
        return {
            "status": "unknown_profile_not_declared",
            "complete": False,
            "events": [],
            "conflicts": [],
        }
    initial, transformations = _network(records)
    if maximum_events < 1:
        return {
            "status": "unknown_due_to_budget",
            "complete": False,
            "events": [],
            "conflicts": [],
        }
    queue: list[tuple[frozenset[str], tuple[str, ...]]] = [(frozenset(initial), ())]
    seen: set[frozenset[str]] = {frozenset(initial)}
    events: list[JsonObject] = []
    alternatives: dict[tuple[str, ...], list[str]] = {}
    exhausted = False
    while queue:
        marking, history = queue.pop(0)
        enabled: list[tuple[str, frozenset[str]]] = []
        for edge_id in sorted(transformations):
            edge = transformations[edge_id]
            if not _enabled(edge, set(marking)):
                continue
            consumed = id_set(edge.get("inputs"))
            produced = id_set(edge.get("outputs"))
            next_marking_set = (set(marking) - consumed) | produced
            if (produced - consumed) & set(marking):
                continue
            enabled.append((edge_id, frozenset(next_marking_set)))
        alternatives[history] = [edge_id for edge_id, _ in enabled]
        for edge_id, occurrence_marking in enabled:
            if len(events) >= maximum_events:
                exhausted = True
                break
            next_history = (*history, edge_id)
            events.append(
                {
                    "event_id": digest_v3_json(list(next_history)),
                    "transformation_id": edge_id,
                    "causal_prefix": list(history),
                    "marking": sorted(occurrence_marking),
                }
            )
            if occurrence_marking not in seen:
                seen.add(occurrence_marking)
                queue.append((occurrence_marking, next_history))
        if exhausted:
            break
    conflicts = [
        {"causal_prefix": list(prefix), "alternatives": choices}
        for prefix, choices in sorted(alternatives.items())
        if len(choices) > 1
    ]
    return {
        "status": "unknown_due_to_budget" if exhausted else "complete_bounded_state_prefix",
        "complete": not exhausted,
        "maximum_events": maximum_events,
        "events": events,
        "conflicts": conflicts,
        "unbounded_petri_net_claimed": False,
    }


def intervention_analysis_v4(root: Path) -> JsonObject:
    """Return evidence-bound blocker and finite structural intervention information."""

    audit = science_audit_v4(root)
    if audit.get("command_status") != "ok":
        return audit
    try:
        manifest, contract, statements, _ = active_attestations_v4(root)
    except (OSError, ValueError) as error:
        return response("failed", "intervention_workspace_invalid", detail=str(error))
    records = _payloads(statements)
    blockers = [
        {
            "dimension": dimension,
            "status": status,
            "reasons": audit.get("reasons", {}).get(dimension, []),
        }
        for dimension, status in audit.get("operational_organization_profile", {}).items()
        if status != "satisfied"
    ]
    actions = [
        item
        for item in _scientific_records(records, "action")
        if _attributes(item).get("executable") is True
    ]
    pareto = sorted(
        [
            {
                "action_id": item.get("subject_id"),
                "guaranteed_additions": sorted(id_set(_attributes(item).get("must_add"))),
                "worst_case_resources": _attributes(item).get("resource_intervals", {}),
                "debt": sorted(id_set(_attributes(item).get("debt"))),
                "verification_load": _attributes(item).get("verification_load"),
                "independence_erosion": _attributes(item).get("independence_erosion"),
            }
            for item in actions
        ],
        key=lambda item: str(item["action_id"]),
    )[:3]
    cuts = _minimal_cut_sets(contract, records)
    coupling = _flux_coupling(contract, records)
    unfolding = _bounded_one_safe_unfolding(contract, records)
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        claims=["finite_structural_intervention_portfolio"],
        unknowns=["general_network_controllability", "expected_utility"],
        blocker_frontier=blockers,
        pareto_interventions=pareto,
        minimal_cut_sets=cuts,
        flux_coupling=coupling,
        bounded_one_safe_unfolding=unfolding,
        scalar_score_used=False,
        success_probability_used=False,
        physical_or_metabolic_equivalence_claimed=False,
    )
