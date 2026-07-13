# SPDX-License-Identifier: Apache-2.0
"""Ordered hard filters, conditional replay, and unit-aware Pareto selection."""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import datetime
from fractions import Fraction

from collective_phase_control_fabric.canonical import digest_json
from collective_phase_control_fabric.types import JsonObject, id_set, tri

Analyzer = Callable[
    [JsonObject | None, JsonObject | None, JsonObject | None, JsonObject | None], JsonObject
]

HARD_FILTERS = (
    "unsupported_version",
    "malformed_report",
    "unknown_effect_class",
    "external_effect",
    "missing_authority",
    "critical_hazard",
    "missing_input_closure",
    "unknown_output_contract",
    "resource_envelope_violation",
    "recursive_reuse_violation",
    "independence_violation",
    "lifecycle_invalidity",
    "protected_floor_violation",
)

AFFORDANCE_REPAIR_KINDS = frozenset(
    {
        "missing_typed_input",
        "missing_typed_output",
        "ambiguous_tool_schema",
        "missing_observable_precondition",
        "missing_receipt",
        "missing_deterministic_reducer",
        "missing_failure_code",
        "missing_digest",
        "missing_timeout",
        "missing_resource_bound",
        "repeated_common_computation",
        "verifier_overload",
    }
)


def _filter_action(action: JsonObject, contract: JsonObject, analysis: JsonObject) -> str | None:
    if tri(action.get("source_version_supported")) != "true":
        return HARD_FILTERS[0]
    if action.get("report_malformed") is True:
        return HARD_FILTERS[1]
    effect_class = action.get("effect_class")
    if effect_class not in {"inspect", "validate", "plan", "local_write", "external_effect"}:
        return HARD_FILTERS[2]
    if effect_class == "external_effect":
        return HARD_FILTERS[3]
    if (
        id_set(action.get("required_authority_refs"))
        and tri(action.get("authority_status")) != "true"
    ):
        return HARD_FILTERS[4]
    if tri(action.get("hazard_status")) != "true":
        return HARD_FILTERS[5]
    available = set(analysis.get("verified_enabling_closure", {}).get("available_states", []))
    if not id_set(action.get("input_refs")) <= available:
        return HARD_FILTERS[6]
    if not isinstance(action.get("output_contract"), dict):
        return HARD_FILTERS[7]
    envelope = contract.get("resource_envelope", {})
    bounds = action.get("resource_upper_bounds", {})
    if not isinstance(envelope, dict) or not isinstance(bounds, dict):
        return HARD_FILTERS[8]
    for coordinate, bound in bounds.items():
        declared = envelope.get(coordinate)
        if not isinstance(bound, dict) or not isinstance(declared, dict):
            return HARD_FILTERS[8]
        if bound.get("unit") != declared.get("unit"):
            return HARD_FILTERS[8]
        try:
            if Fraction(str(bound.get("quantity"))) > Fraction(str(declared.get("maximum"))):
                return HARD_FILTERS[8]
        except (ValueError, ZeroDivisionError):
            return HARD_FILTERS[8]
    if tri(action.get("recursive_reuse_valid")) != "true":
        return HARD_FILTERS[9]
    if tri(action.get("independence_valid")) != "true":
        return HARD_FILTERS[10]
    if tri(action.get("lifecycle_status")) != "true":
        return HARD_FILTERS[11]
    if action.get("protected_floor_violation") is not False:
        return HARD_FILTERS[12]
    return None


def apply_postcondition(
    network: JsonObject,
    productive_witness: JsonObject | None,
    maintenance_witness: JsonObject | None,
    postcondition: JsonObject,
) -> tuple[JsonObject, JsonObject | None, JsonObject | None]:
    """Apply only a declared finite postcondition to a temporary projection."""

    projected = deepcopy(network)
    nodes = projected.setdefault("nodes", [])
    if isinstance(nodes, list):
        for node_id in postcondition.get("available_states", []):
            for node in nodes:
                if isinstance(node, dict) and node.get("node_id") == node_id:
                    node["available"] = True
        additions = postcondition.get("add_nodes", [])
        if isinstance(additions, list):
            nodes.extend(deepcopy([item for item in additions if isinstance(item, dict)]))
    edge_updates = postcondition.get("edge_updates", {})
    if isinstance(edge_updates, dict):
        for edge in projected.get("transformations", []):
            if isinstance(edge, dict) and edge.get("transformation_id") in edge_updates:
                update = edge_updates[edge["transformation_id"]]
                if isinstance(update, dict):
                    edge.update(deepcopy(update))
    projected_productive = deepcopy(productive_witness)
    projected_maintenance = deepcopy(maintenance_witness)
    if isinstance(postcondition.get("productive_witness"), dict):
        projected_productive = deepcopy(postcondition["productive_witness"])
    if isinstance(postcondition.get("maintenance_witness"), dict):
        projected_maintenance = deepcopy(postcondition["maintenance_witness"])
    return projected, projected_productive, projected_maintenance


def _barrier_count(analysis: JsonObject, coordinate: str | None = None) -> int:
    coordinates = analysis.get("barrier_vector", {}).get("coordinates", {})
    if not isinstance(coordinates, dict):
        return 0
    selected = [coordinate] if coordinate else list(coordinates)
    return sum(len(coordinates.get(item, {}).get("blocker_ids", [])) for item in selected)


def _seed_count(analysis: JsonObject) -> int:
    return sum(len(seed.get("unmet_states", [])) for seed in analysis.get("formation_seeds", []))


def _spf_count(analysis: JsonObject) -> int:
    robustness = analysis.get("structural_robustness", {})
    return len(robustness.get("catalyst_single_point_failure_ids", [])) + len(
        robustness.get("verifier_single_point_failure_ids", [])
    )


def conditional_impact(
    action: JsonObject,
    contract: JsonObject,
    network: JsonObject,
    productive_witness: JsonObject | None,
    maintenance_witness: JsonObject | None,
    before: JsonObject,
    analyzer: Analyzer,
) -> JsonObject:
    """Replay declared postconditions without assuming the operation succeeds."""

    postcondition = action.get("postcondition_contract", {})
    if not isinstance(postcondition, dict):
        postcondition = {}
    projected_network, projected_productive, projected_maintenance = apply_postcondition(
        network, productive_witness, maintenance_witness, postcondition
    )
    after = analyzer(contract, projected_network, projected_productive, projected_maintenance)
    before_targets = set(before.get("verified_enabling_closure", {}).get("reached_targets", []))
    after_targets = set(after.get("verified_enabling_closure", {}).get("reached_targets", []))
    before_ladder = before.get("phase_projection", {}).get("ladder_level")
    after_ladder = after.get("phase_projection", {}).get("ladder_level")
    ladder_extension = int(
        isinstance(before_ladder, str)
        and isinstance(after_ladder, str)
        and int(after_ladder[1:]) > int(before_ladder[1:])
    )
    return {
        "conditionally_reachable_targets": sorted(after_targets),
        "conditionally_reduced_barrier_coordinates": [
            coordinate
            for coordinate in before.get("barrier_vector", {}).get("coordinates", {})
            if _barrier_count(after, coordinate) < _barrier_count(before, coordinate)
        ],
        "conditionally_resolved_seed_deficits": max(0, _seed_count(before) - _seed_count(after)),
        "conditionally_extended_closure": sorted(after_targets - before_targets),
        "conditionally_removed_single_point_failures": max(
            0, _spf_count(before) - _spf_count(after)
        ),
        "conditionally_removed_deadlocks": max(
            0,
            len(before.get("regeneration_deadlocks", []))
            - len(after.get("regeneration_deadlocks", [])),
        ),
        "conditionally_introduced_debt": postcondition.get("introduced_debt", []),
        "resource_upper_bound_vector": action.get("resource_upper_bounds", {}),
        "verification_load_effect": postcondition.get("verification_load_effect", "unknown"),
        "correlation_concentration_effect": postcondition.get(
            "correlation_concentration_effect", "unknown"
        ),
        "target_path_unlock_count": len(after_targets - before_targets),
        "barrier_coordinate_reduction_count": sum(
            _barrier_count(after, coordinate) < _barrier_count(before, coordinate)
            for coordinate in before.get("barrier_vector", {}).get("coordinates", {})
        ),
        "seed_deficit_reduction_count": max(0, _seed_count(before) - _seed_count(after)),
        "productive_organization_extension_count": ladder_extension,
        "robustness_improvement_count": max(0, _spf_count(before) - _spf_count(after)),
        "deadlock_removal_count": max(
            0,
            len(before.get("regeneration_deadlocks", []))
            - len(after.get("regeneration_deadlocks", [])),
        ),
        "observability_gain_count": max(
            0, _barrier_count(before, "observability") - _barrier_count(after, "observability")
        ),
        "newly_introduced_debt_count": len(postcondition.get("introduced_debt", [])),
        "verification_load_increase": postcondition.get("verification_load_increase", "unknown"),
        "source_concentration_increase": postcondition.get(
            "source_concentration_increase", "unknown"
        ),
        "correlation_concentration_increase": postcondition.get(
            "correlation_concentration_increase", "unknown"
        ),
        "projected_analysis_digest": after.get("analysis_digest"),
    }


MAXIMIZE = (
    "target_path_unlock_count",
    "barrier_coordinate_reduction_count",
    "seed_deficit_reduction_count",
    "productive_organization_extension_count",
    "robustness_improvement_count",
    "deadlock_removal_count",
    "observability_gain_count",
)
MINIMIZE = ("newly_introduced_debt_count",)


def _impact_dominates(left: JsonObject, right: JsonObject) -> bool:
    strict = False
    for field in MAXIMIZE:
        if int(left[field]) < int(right[field]):
            return False
        strict = strict or int(left[field]) > int(right[field])
    for field in MINIMIZE:
        if int(left[field]) > int(right[field]):
            return False
        strict = strict or int(left[field]) < int(right[field])
    left_resources = left.get("resource_upper_bound_vector", {})
    right_resources = right.get("resource_upper_bound_vector", {})
    if set(left_resources) != set(right_resources):
        return False
    for coordinate in left_resources:
        left_value = left_resources[coordinate]
        right_value = right_resources[coordinate]
        if left_value.get("unit") != right_value.get("unit"):
            return False
        left_quantity = Fraction(str(left_value.get("quantity")))
        right_quantity = Fraction(str(right_value.get("quantity")))
        if left_quantity > right_quantity:
            return False
        strict = strict or left_quantity < right_quantity
    for field in (
        "verification_load_increase",
        "source_concentration_increase",
        "correlation_concentration_increase",
    ):
        if left.get(field) != right.get(field):
            return False
    return strict


def plan_actions(
    actions: list[JsonObject],
    contract: JsonObject,
    network: JsonObject,
    productive_witness: JsonObject | None,
    maintenance_witness: JsonObject | None,
    analysis: JsonObject,
    history: list[JsonObject],
    analyzer: Analyzer,
) -> JsonObject:
    """Return one strict Pareto winner or at most three nondominated alternatives."""

    if contract.get("schema_version") == "0.2.0":
        return plan_contingent_actions(actions, contract, analysis, history)

    network_digest = digest_json(network)
    barrier_digest = digest_json(analysis.get("barrier_vector", {}))
    stagnated = {
        str(item.get("action_signature"))
        for item in history
        if item.get("progress") == "no_progress"
        and item.get("post_network_digest") == network_digest
        and item.get("post_barrier_digest") == barrier_digest
    }
    eligible: list[JsonObject] = []
    rejected: list[JsonObject] = []
    for action in sorted(
        actions, key=lambda item: (int(item.get("priority_class", 99)), str(item.get("action_id")))
    ):
        signature = digest_json(
            {
                "adapter": action.get("adapter"),
                "operation": action.get("operation"),
                "argv": action.get("exact_argv"),
            }
        )
        if signature in stagnated:
            rejected.append({"action_id": action.get("action_id"), "reason": "stagnated"})
            continue
        reason = _filter_action(action, contract, analysis)
        if reason:
            rejected.append({"action_id": action.get("action_id"), "reason": reason})
            continue
        candidate = deepcopy(action)
        candidate["action_signature"] = signature
        candidate["conditional_impact_projection"] = conditional_impact(
            action,
            contract,
            network,
            productive_witness,
            maintenance_witness,
            analysis,
            analyzer,
        )
        eligible.append(candidate)
    active_priority = min(
        (int(action.get("priority_class", 99)) for action in eligible), default=None
    )
    active = [
        action for action in eligible if int(action.get("priority_class", 99)) == active_priority
    ]
    deferred = [
        {"action_id": action.get("action_id"), "reason": "higher_priority_class_active"}
        for action in eligible
        if action not in active
    ]
    nondominated = [
        action
        for action in active
        if not any(
            _impact_dominates(
                other["conditional_impact_projection"], action["conditional_impact_projection"]
            )
            for other in active
            if other is not action
        )
    ]
    strict_winners = [
        action
        for action in active
        if all(
            other is action
            or _impact_dominates(
                action["conditional_impact_projection"], other["conditional_impact_projection"]
            )
            for other in active
        )
    ]
    primary = strict_winners[0] if len(strict_winners) == 1 else None
    alternatives = [] if primary else nondominated[:3]
    return {
        "primary_action": primary,
        "pareto_alternatives": alternatives,
        "rejected_actions": rejected,
        "deferred_actions": deferred,
        "active_priority_class": active_priority,
        "selection_method": "unit-aware_partial_order",
    }


def _v2_branch_projection(branch: object) -> JsonObject:
    """Normalize a declared branch forecast without promoting projected objects."""

    if not isinstance(branch, dict):
        return {
            "safe": False,
            "unsafe_reasons": ["outcome_branch_missing_or_malformed"],
            **{field: 0 for field in MAXIMIZE},
            "newly_introduced_debt_count": 1,
            "resource_upper_bound_vector": {},
        }
    reasons: list[str] = []
    for field in ("protected_floor_status", "authority_status", "hazard_status"):
        if branch.get(field) != "true":
            reasons.append(f"{field}_not_true")
    debt = branch.get("debt")
    rollback = branch.get("rollback_obligations")
    if not isinstance(debt, list):
        reasons.append("debt_unknown")
        debt = ["unknown"]
    if not isinstance(rollback, list):
        reasons.append("rollback_obligations_unknown")
    forecast = branch.get("forecast", {})
    if not isinstance(forecast, dict):
        forecast = {}
    impact: JsonObject = {
        field: int(forecast.get(field, 0))
        if isinstance(forecast.get(field, 0), int) and int(forecast.get(field, 0)) >= 0
        else 0
        for field in MAXIMIZE
    }
    impact.update(
        {
            "safe": not reasons,
            "unsafe_reasons": reasons,
            "newly_introduced_debt_count": len(debt),
            "resource_upper_bound_vector": branch.get("resource_upper_bounds", {}),
            "projection_targets": branch.get("projection_targets", []),
            "receipt_schema_ref": branch.get("receipt_schema_ref"),
            "declared_objects_promoted": False,
        }
    )
    return impact


def _v2_filter(
    action: JsonObject, contract: JsonObject, analysis: JsonObject | None = None
) -> str | None:
    if action.get("schema_version") != "0.2.0":
        return "unsupported_version"
    if action.get("effect_class") not in {
        "inspect",
        "validate",
        "plan",
        "local_write",
        "external_effect",
    }:
        return "unknown_effect_class"
    if action.get("effect_class") == "external_effect":
        return "external_effect"
    if not isinstance(action.get("exact_argv"), list) or not action.get("exact_argv"):
        return "unbound_repair_not_executable"
    try:
        expires = datetime.fromisoformat(str(action["expires_at"]).replace("Z", "+00:00"))
        evaluated = datetime.fromisoformat(str(contract["evaluation_time"]).replace("Z", "+00:00"))
        if expires.tzinfo is None or evaluated.tzinfo is None or expires < evaluated:
            return "lifecycle_invalidity"
    except (KeyError, ValueError):
        return "lifecycle_invalidity"
    if analysis is not None:
        available = set(analysis.get("verified_enabling_closure", {}).get("available_states", []))
        if not id_set(action.get("input_refs")) <= available:
            return "missing_input_closure"
        if not id_set(action.get("required_authority_refs")) <= available:
            return "missing_authority"
    outcomes = action.get("outcomes")
    if not isinstance(outcomes, dict) or set(outcomes) != {
        "success",
        "partial",
        "failure",
        "timeout",
    }:
        return "four_outcome_contract_required"
    projections = {name: _v2_branch_projection(outcomes[name]) for name in sorted(outcomes)}
    if not all(item["safe"] for item in projections.values()):
        return "unsafe_outcome_branch"
    envelope = contract.get("resource_envelope", {})
    if not isinstance(envelope, dict):
        return "resource_envelope_violation"
    for projection in projections.values():
        bounds = projection.get("resource_upper_bound_vector", {})
        if not isinstance(bounds, dict):
            return "resource_envelope_violation"
        for coordinate, bound in bounds.items():
            declared = envelope.get(coordinate)
            if not isinstance(bound, dict) or not isinstance(declared, dict):
                return "resource_envelope_violation"
            try:
                if bound.get("unit") != declared.get("unit") or exact_number_like(
                    bound.get("quantity")
                ) > exact_number_like(declared.get("maximum")):
                    return "resource_envelope_violation"
            except ValueError:
                return "resource_envelope_violation"
    return None


def exact_number_like(value: object) -> Fraction:
    """Parse planner quantities as exact rationals without accepting floats."""

    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ValueError("exact quantity required")
    return Fraction(str(value))


def _contingent_dominates(left: JsonObject, right: JsonObject) -> bool:
    """Require success improvement and no worse outcome across every branch."""

    strict = False
    for branch in ("success", "partial", "failure", "timeout"):
        left_impact = left[branch]
        right_impact = right[branch]
        for field in MAXIMIZE:
            if int(left_impact[field]) < int(right_impact[field]):
                return False
            strict |= int(left_impact[field]) > int(right_impact[field])
        if int(left_impact["newly_introduced_debt_count"]) > int(
            right_impact["newly_introduced_debt_count"]
        ):
            return False
        strict |= int(left_impact["newly_introduced_debt_count"]) < int(
            right_impact["newly_introduced_debt_count"]
        )
    return strict


def _sequence_impact(sequence: tuple[JsonObject, ...]) -> tuple[int, ...]:
    """Return a deterministic additive search key for bounded beam exploration."""

    return tuple(
        sum(int(action["branch_projections"]["success"][field]) for action in sequence)
        for field in MAXIMIZE
    )


def plan_contingent_actions(
    actions: list[JsonObject],
    contract: JsonObject,
    analysis: JsonObject,
    history: list[JsonObject],
) -> JsonObject:
    """Plan only actions whose success, partial, failure, and timeout branches are safe."""

    policy = contract.get("control_policy", {})
    horizon = policy.get("planning_horizon", 1) if isinstance(policy, dict) else 1
    beam_width = (
        min(32, policy.get("beam_width", 32))
        if isinstance(policy, dict) and isinstance(policy.get("beam_width", 32), int)
        else 32
    )
    candidate_cap = (
        min(64, policy.get("candidate_cap", 64))
        if isinstance(policy, dict) and isinstance(policy.get("candidate_cap", 64), int)
        else 64
    )
    rejected: list[JsonObject] = []
    eligible: list[JsonObject] = []
    retry_policy = policy.get("retry_policy", {}) if isinstance(policy, dict) else {}
    maximum_retries = (
        retry_policy.get("maximum_retries", 0) if isinstance(retry_policy, dict) else 0
    )
    maximum_retries = maximum_retries if isinstance(maximum_retries, int) else 0
    retry_counts: dict[str, int] = {}
    for item in history:
        if item.get("progress") == "no_progress":
            signature = str(item.get("action_signature"))
            retry_counts[signature] = retry_counts.get(signature, 0) + 1
    stagnant = {signature for signature, count in retry_counts.items() if count >= maximum_retries}
    for source in sorted(
        actions[:candidate_cap],
        key=lambda item: (int(item.get("priority_class", 99)), str(item.get("action_id"))),
    ):
        signature = digest_json(
            {
                "adapter": source.get("adapter"),
                "operation": source.get("operation"),
                "argv": source.get("exact_argv"),
            }
        )
        if signature in stagnant:
            rejected.append({"action_id": source.get("action_id"), "reason": "stagnated"})
            continue
        reason = _v2_filter(source, contract, analysis)
        if reason:
            rejected.append({"action_id": source.get("action_id"), "reason": reason})
            continue
        action = deepcopy(source)
        outcomes = action["outcomes"]
        action["branch_projections"] = {
            name: _v2_branch_projection(outcomes[name])
            for name in ("success", "partial", "failure", "timeout")
        }
        action["action_signature"] = signature
        eligible.append(action)
    active_priority = min((int(item.get("priority_class", 99)) for item in eligible), default=None)
    active = [item for item in eligible if int(item.get("priority_class", 99)) == active_priority]
    nondominated = [
        item
        for item in active
        if not any(
            _contingent_dominates(other["branch_projections"], item["branch_projections"])
            for other in active
            if other is not item
        )
    ]
    strict = [
        item
        for item in active
        if all(
            other is item
            or _contingent_dominates(item["branch_projections"], other["branch_projections"])
            for other in active
        )
    ]
    primary = strict[0] if len(strict) == 1 else None
    alternatives = [] if primary else nondominated[:3]
    sequences: list[tuple[JsonObject, ...]] = [(item,) for item in active]
    if isinstance(horizon, int) and horizon > 1:
        beam = sequences
        for _ in range(1, min(3, horizon)):
            expanded = [
                (*sequence, candidate)
                for sequence in beam
                for candidate in active
                if candidate not in sequence
            ]
            if not expanded:
                break
            beam = sorted(
                expanded,
                key=lambda sequence: (
                    tuple(-value for value in _sequence_impact(sequence)),
                    tuple(str(item.get("action_id")) for item in sequence),
                ),
            )[:beam_width]
        sequences = beam
    return {
        "primary_action": primary,
        "pareto_alternatives": alternatives,
        "rejected_actions": rejected,
        "deferred_actions": [
            {"action_id": item.get("action_id"), "reason": "higher_priority_class_active"}
            for item in eligible
            if item not in active
        ],
        "active_priority_class": active_priority,
        "selection_method": "four_branch_conditional_pareto_partial_order",
        "solution_class": "exact" if horizon == 1 else "approximate",
        "planning_horizon": horizon,
        "beam_width": None if horizon == 1 else beam_width,
        "candidate_cap": candidate_cap,
        "beam_sequences": [
            [item.get("action_id") for item in sequence] for sequence in sequences[:beam_width]
        ]
        if horizon != 1
        else [],
        "one_step_execution_limit": 1,
    }
