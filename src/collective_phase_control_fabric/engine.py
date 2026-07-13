# SPDX-License-Identifier: Apache-2.0
"""Deterministic end-to-end structural analysis."""

from __future__ import annotations

from collective_phase_control_fabric.barrier import build_barrier_vector
from collective_phase_control_fabric.canonical import digest_json
from collective_phase_control_fabric.collective import collective_condition, external_claim_bundle
from collective_phase_control_fabric.coordination import derive_coordination_plan
from collective_phase_control_fabric.deadlock import regeneration_deadlocks
from collective_phase_control_fabric.detectors import detect_false_positives, has_blocking_detection
from collective_phase_control_fabric.metrics import critical_path, verification_load
from collective_phase_control_fabric.network import (
    feasible_closure,
    reached_targets,
    verified_closure,
)
from collective_phase_control_fabric.robustness import structural_robustness
from collective_phase_control_fabric.science import (
    independent_support_core,
    invariant_diagnostics,
    perturbation_replay,
    validate_coordinate_invariant,
    validate_formation_sequence,
    validate_generative_catalysis,
    validate_persistence,
    validate_rate_intervals,
    validate_resource_potential,
    verification_network,
)
from collective_phase_control_fabric.seed import formation_seeds
from collective_phase_control_fabric.types import JsonObject
from collective_phase_control_fabric.witnesses import (
    validate_catalysts,
    validate_maintenance_witness,
    validate_productive_witness,
)


def _robust_candidate(contract: JsonObject, robustness: JsonObject) -> tuple[bool, list[str]]:
    policy = contract.get("robustness_policy", {})
    if not isinstance(policy, dict):
        return False, ["robustness_policy_malformed"]
    reasons: list[str] = []
    required_paths = policy.get("minimum_independent_target_paths")
    if not isinstance(required_paths, int):
        reasons.append("minimum_independent_target_paths_unknown")
    elif robustness.get("independent_target_path_count", 0) < required_paths:
        reasons.append("independent_target_path_count_insufficient")
    required_verifiers = policy.get("minimum_independent_verifiers")
    verifier_spf = robustness.get("verifier_single_point_failure_ids", [])
    if not isinstance(required_verifiers, int):
        reasons.append("minimum_independent_verifiers_unknown")
    elif required_verifiers > 1 and verifier_spf:
        reasons.append("verifier_redundancy_insufficient")
    tolerated = policy.get("tolerated_single_failures")
    sensitive = sum(
        bool(item.get("lost_targets"))
        for item in robustness.get("single_node_removal_sensitivity", [])
    )
    if not isinstance(tolerated, int):
        reasons.append("failure_tolerance_unknown")
    elif sensitive > tolerated:
        reasons.append("failure_tolerance_exceeded")
    required_sources = policy.get("minimum_source_systems")
    source_counts = robustness.get("source_system_concentration", {}).get("counts", {})
    if not isinstance(required_sources, int):
        reasons.append("minimum_source_systems_unknown")
    elif len(source_counts) < required_sources:
        reasons.append("source_diversity_insufficient")
    return not reasons, reasons


def analyze(
    contract: JsonObject | None,
    network: JsonObject | None,
    productive_witness: JsonObject | None = None,
    maintenance_witness: JsonObject | None = None,
    witnesses: dict[str, JsonObject] | None = None,
) -> JsonObject:
    """Analyze one finite projection without modifying any source-of-record state."""

    if contract is None:
        return {
            "command_status": "ok",
            "phase_projection": {
                "ladder_level": None,
                "structural_status": "uninitialized",
                "progress_classes": [],
                "contract_ref": None,
            },
            "non_claims": ["No positive state is inferred without a PhaseContract."],
        }
    if network is None:
        return {
            "command_status": "partial",
            "phase_projection": {
                "ladder_level": None,
                "structural_status": "network_missing",
                "progress_classes": [],
                "contract_ref": digest_json(contract),
            },
        }
    node_ids = [
        node.get("node_id")
        for node in network.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("node_id"), str)
    ]
    edge_ids = [
        edge.get("transformation_id")
        for edge in network.get("transformations", [])
        if isinstance(edge, dict) and isinstance(edge.get("transformation_id"), str)
    ]
    duplicate_ids = sorted(
        {str(item) for item in [*node_ids, *edge_ids] if [*node_ids, *edge_ids].count(item) > 1}
    )
    if duplicate_ids:
        return {
            "command_status": "failed",
            "failure_code": "duplicate_identifiers",
            "duplicate_identifiers": duplicate_ids,
            "phase_projection": {
                "ladder_level": None,
                "structural_status": "invalid_network",
                "progress_classes": [],
                "contract_ref": digest_json(contract),
            },
        }
    feasible = feasible_closure(contract, network)
    verified = verified_closure(contract, network, feasible)
    productive = validate_productive_witness(contract, network, verified, productive_witness)
    maintenance = validate_maintenance_witness(maintenance_witness, network)
    catalyst = validate_catalysts(network, maintenance.valid is True and productive.valid is True)
    collective = collective_condition(contract, network)
    detections = detect_false_positives(contract, network, verified, productive_witness)
    deadlocks = regeneration_deadlocks(contract, network, verified)
    seeds = formation_seeds(contract, network, verified)
    robustness = structural_robustness(contract, network, verified)
    load = verification_load(contract)
    path = critical_path(contract)
    blockers_present = has_blocking_detection(detections)
    feasible_targets = reached_targets(contract, feasible)
    verified_targets = reached_targets(contract, verified)
    ladder = -1
    statuses: list[str] = []
    if feasible_targets:
        ladder = 0
        statuses.append("structural_reachability")
    if verified_targets and not blockers_present:
        ladder = 1
        statuses.append("verified_enabling_closure")
    native_v2 = contract.get("schema_version") == "0.2.0"
    supplied = witnesses or {}
    formation = (
        validate_formation_sequence(contract, network, supplied.get("formation-sequence-witness"))
        if native_v2
        else {"status": "not_applicable", "valid": True, "reasons": []}
    )
    invariants = invariant_diagnostics(contract, network) if native_v2 else {}
    coordinate_invariant = (
        validate_coordinate_invariant(
            contract, network, supplied.get("coordinate-invariant-witness")
        )
        if native_v2
        else {"status": "not_applicable", "valid": True}
    )
    persistence = (
        validate_persistence(contract, network, supplied.get("persistence-witness"))
        if native_v2
        else {"status": "not_applicable", "valid": maintenance.valid}
    )
    rates = (
        validate_rate_intervals(supplied.get("rate-interval-witness"))
        if native_v2
        else {"status": "not_applicable", "valid": True}
    )
    generative = (
        validate_generative_catalysis(
            contract, network, supplied.get("generative-catalytic-witness")
        )
        if native_v2
        else {"status": "not_applicable", "valid": catalyst.valid}
    )
    potential = (
        validate_resource_potential(network, supplied.get("resource-potential-witness"))
        if native_v2
        else {"status": "not_applicable", "valid": True}
    )
    support_core = independent_support_core(contract, network) if native_v2 else {}
    perturbations = perturbation_replay(contract, network) if native_v2 else {}
    verification = (
        verification_network(supplied.get("verification-network-witness")) if native_v2 else {}
    )
    formation_valid = formation.get("valid") is True
    potential_valid = potential.get("valid") is True if native_v2 else True
    if (
        productive.valid is True
        and ladder >= 1
        and not blockers_present
        and formation_valid
        and potential_valid
    ):
        ladder = 2
        statuses.append("productive_organization_candidate")
    required_rate_levels = (
        set(contract.get("rate_policy", {}).get("levels_requiring_external_rate_evidence", []))
        if native_v2
        else set()
    )
    rate_l3 = "L3" not in required_rate_levels or rates.get("valid") is True
    if (
        (persistence.get("valid") is True if native_v2 else maintenance.valid is True)
        and ladder >= 2
        and rate_l3
    ):
        ladder = 3
        statuses.append("maintained_organization_candidate")
    rate_l4 = "L4" not in required_rate_levels or rates.get("valid") is True
    if (
        (generative.get("valid") is True if native_v2 else catalyst.valid is True)
        and ladder >= 3
        and rate_l4
    ):
        ladder = 4
        statuses.append("catalytic_organization_candidate")
    robust, robust_reasons = _robust_candidate(contract, robustness)
    rate_l5 = "L5" not in required_rate_levels or rates.get("valid") is True
    v2_robust = support_core.get("status") == "true" and not any(
        item.get("support_core_collapse") or item.get("lost_targets")
        for item in perturbations.get("results", [])
    )
    if (v2_robust if native_v2 else robust) and ladder >= 4 and rate_l5:
        ladder = 5
        statuses.append("robust_organization_candidate")
    external = external_claim_bundle(contract, network, collective)
    barriers = build_barrier_vector(
        verified,
        detections,
        deadlocks,
        seeds,
        productive.status,
        str(persistence.get("status")) if native_v2 else maintenance.status,
        collective,
    )
    contract_ref = digest_json(contract)
    network_ref = digest_json(network)
    result: JsonObject = {
        "command_status": "ok",
        "source_decisions": [],
        "phase_projection": {
            "ladder_level": f"L{ladder}" if ladder >= 0 else None,
            "structural_status": statuses[-1] if statuses else "not_reachable",
            "progress_classes": statuses,
            "contract_ref": contract_ref,
            "network_ref": network_ref,
            "closure_refs": [digest_json(feasible.__dict__), digest_json(verified.__dict__)],
            "productive_witness_refs": [productive.witness_ref] if productive.witness_ref else [],
            "maintenance_witness_refs": [maintenance.witness_ref]
            if maintenance.witness_ref
            else [],
            "seed_refs": [str(seed["seed_id"]) for seed in seeds],
            "barrier_ref": digest_json(barriers),
            "robustness_ref": digest_json(robustness),
            "transition_ref": None,
            "external_certificate_refs": external["certificate_refs"],
        },
        "feasible_closure": {
            "available_states": list(feasible.available_states),
            "applied_transformations": list(feasible.applied_transformations),
            "blocked": list(feasible.blocked),
            "reached_targets": feasible_targets,
        },
        "verified_enabling_closure": {
            "available_states": list(verified.available_states),
            "applied_transformations": list(verified.applied_transformations),
            "blocked": list(verified.blocked),
            "reached_targets": verified_targets,
        },
        "productive_witness": {
            "status": productive.status,
            "valid": productive.valid,
            "reasons": list(productive.reasons),
            "balances": productive.balances,
        },
        "maintenance_witness": {
            "status": maintenance.status,
            "valid": maintenance.valid,
            "reasons": list(maintenance.reasons),
        },
        "catalyst": {
            "status": catalyst.status,
            "valid": catalyst.valid,
            "reasons": list(catalyst.reasons),
            **catalyst.balances,
        },
        "collective_condition": collective,
        "false_positive_detections": detections,
        "regeneration_deadlocks": deadlocks,
        "formation_seeds": seeds,
        "barrier_vector": barriers,
        "structural_robustness": {**robustness, "robust_candidate_reasons": robust_reasons},
        "verification_load": load,
        "critical_path": path,
        "external_claim_bundle": external,
        "scientific_layers": {
            "structural_reachability": feasible_targets,
            "causal_formation": formation,
            "stoichiometric_productivity": {
                "status": productive.status,
                "valid": productive.valid,
                "balances": productive.balances,
            },
            "persistence_and_bounded_rate": {"persistence": persistence, "rate_intervals": rates},
            "external_empirical_phase_evidence": external,
        }
        if native_v2
        else {},
        "formation_sequence": formation,
        "stoichiometric_diagnostics": invariants,
        "coordinate_invariant": coordinate_invariant,
        "persistence": persistence,
        "rate_intervals": rates,
        "generative_catalysis": generative,
        "resource_potential": potential,
        "independent_support_core": support_core,
        "perturbation_replay": perturbations,
        "verification_network": verification,
        "coordination_plan": derive_coordination_plan(contract, network) if native_v2 else {},
        "non_claims": [
            "Structural analysis is not a measurement of time, cost, performance, or intelligence.",
            "Imported certificates are checked for compatibility, not scientific truth.",
            "CPCF does not grant authority, execute external effects, or settle source records.",
        ],
    }
    result["analysis_digest"] = digest_json(result)
    return result
