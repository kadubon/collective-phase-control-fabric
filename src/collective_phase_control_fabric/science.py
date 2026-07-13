# SPDX-License-Identifier: Apache-2.0
"""Exact, bounded scientific analogues used by the v0.2 structural model.

These algorithms check declared finite witnesses.  They do not identify a physical phase,
simulate kinetics, infer thermodynamics, or establish general network controllability.
"""

from __future__ import annotations

from datetime import datetime
from fractions import Fraction
from itertools import combinations

import networkx as nx

from collective_phase_control_fabric.network import initial_states, transformation_index
from collective_phase_control_fabric.types import JsonObject, id_set
from collective_phase_control_fabric.witnesses import exact_number


def _flow(edge: JsonObject, coordinate: str) -> Fraction:
    total = Fraction(0)
    for sign, field in ((-1, "consumed_coordinates"), (1, "produced_coordinates")):
        values = edge.get(field, {})
        if isinstance(values, dict) and isinstance(values.get(coordinate), dict):
            total += sign * exact_number(values[coordinate].get("quantity"))
    return total


def stoichiometric_matrix(contract: JsonObject, network: JsonObject) -> JsonObject:
    """Return the exact rational coordinate-by-transformation matrix."""

    registry = contract.get("state_coordinate_registry", {})
    coordinates = sorted(registry) if isinstance(registry, dict) else []
    edges = transformation_index(network)
    transformations = sorted(edges)
    matrix: list[list[str]] = []
    errors: list[str] = []
    for coordinate in coordinates:
        row: list[str] = []
        for transformation_id in transformations:
            try:
                row.append(str(_flow(edges[transformation_id], coordinate)))
            except ValueError:
                row.append("unknown")
                errors.append(f"invalid_flow:{transformation_id}:{coordinate}")
        matrix.append(row)
    return {
        "coordinates": coordinates,
        "transformations": transformations,
        "matrix": matrix,
        "errors": sorted(errors),
        "arithmetic": "exact_rational",
    }


def _fraction_matrix(matrix: list[list[str]]) -> list[list[Fraction]]:
    return [[exact_number(value) for value in row] for row in matrix]


def exact_nullspace(matrix: list[list[str]]) -> list[list[str]]:
    """Compute a deterministic reduced-row-echelon nullspace basis over rationals."""

    values = _fraction_matrix(matrix)
    column_count = len(values[0]) if values else 0
    if any(len(row) != column_count for row in values):
        raise ValueError("ragged matrix")
    row_count = len(values)
    pivot_columns: list[int] = []
    pivot_row = 0
    for column in range(column_count):
        selected = next(
            (row for row in range(pivot_row, row_count) if values[row][column] != 0), None
        )
        if selected is None:
            continue
        values[pivot_row], values[selected] = values[selected], values[pivot_row]
        divisor = values[pivot_row][column]
        values[pivot_row] = [item / divisor for item in values[pivot_row]]
        for row in range(row_count):
            if row == pivot_row:
                continue
            multiplier = values[row][column]
            if multiplier:
                values[row] = [
                    value - multiplier * pivot
                    for value, pivot in zip(values[row], values[pivot_row], strict=True)
                ]
        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == row_count:
            break
    free_columns = [column for column in range(column_count) if column not in pivot_columns]
    basis: list[list[str]] = []
    for free in free_columns:
        vector = [Fraction(0) for _ in range(column_count)]
        vector[free] = Fraction(1)
        for row, pivot in enumerate(pivot_columns):
            vector[pivot] = -values[row][free]
        basis.append([str(value) for value in vector])
    return basis


def invariant_diagnostics(contract: JsonObject, network: JsonObject) -> JsonObject:
    """Return P- and T-like nullspace bases as diagnostics, never inferred witnesses."""

    report = stoichiometric_matrix(contract, network)
    if report["errors"]:
        return {**report, "p_nullspace_basis": [], "t_nullspace_basis": []}
    matrix = report["matrix"]
    transpose = [list(column) for column in zip(*matrix, strict=False)] if matrix else []
    return {
        **report,
        "t_nullspace_basis": exact_nullspace(matrix),
        "p_nullspace_basis": exact_nullspace(transpose),
        "basis_role": "diagnostic_only; supplied nonnegative witnesses remain mandatory",
    }


def validate_coordinate_invariant(
    contract: JsonObject, network: JsonObject, witness: JsonObject | None
) -> JsonObject:
    """Recalculate one supplied nonnegative P- or T-semiflow analogue."""

    if witness is None:
        return {"status": "unknown", "valid": None, "reasons": ["witness_missing"]}
    matrix_report = stoichiometric_matrix(contract, network)
    if matrix_report["errors"]:
        return {"status": "false", "valid": False, "reasons": matrix_report["errors"]}
    kind = witness.get("kind")
    labels = (
        matrix_report["coordinates"]
        if kind == "p_semiflow_analog"
        else matrix_report["transformations"]
    )
    coefficients = witness.get("coefficients", {})
    reasons: list[str] = []
    try:
        vector = [exact_number(coefficients[label]) for label in labels]
    except (KeyError, TypeError, ValueError):
        return {"status": "false", "valid": False, "reasons": ["coefficient_invalid"]}
    if any(value < 0 for value in vector) or not any(value > 0 for value in vector):
        reasons.append("nonnegative_nonzero_vector_required")
    matrix = _fraction_matrix(matrix_report["matrix"])
    if kind == "p_semiflow_analog":
        residual = [
            sum(vector[row] * matrix[row][column] for row in range(len(matrix)))
            for column in range(len(matrix[0]) if matrix else 0)
        ]
    elif kind == "t_semiflow_analog":
        residual = [
            sum(matrix[row][column] * vector[column] for column in range(len(vector)))
            for row in range(len(matrix))
        ]
    else:
        return {"status": "false", "valid": False, "reasons": ["kind_invalid"]}
    if any(value != 0 for value in residual):
        reasons.append("invariant_identity_failed")
    return {
        "status": "true" if not reasons else "false",
        "valid": not reasons,
        "reasons": reasons,
        "residual": [str(value) for value in residual],
    }


def _floor_value(value: object) -> Fraction:
    if isinstance(value, dict):
        return exact_number(value.get("quantity"))
    return exact_number(value)


def validate_formation_sequence(
    contract: JsonObject, network: JsonObject, witness: JsonObject | None
) -> JsonObject:
    """Check strict layer causality and every protected-coordinate prefix."""

    if witness is None:
        return {"status": "unknown", "valid": None, "reasons": ["formation_sequence_missing"]}
    edges = transformation_index(network)
    layers = witness.get("layers")
    if not isinstance(layers, list) or not layers:
        return {"status": "false", "valid": False, "reasons": ["formation_layers_missing"]}
    maximum = contract.get("formation_policy", {}).get("maximum_layer_count")
    reasons: list[str] = []
    if not isinstance(maximum, int) or len(layers) > maximum:
        reasons.append("maximum_layer_count_exceeded_or_unknown")
    available = initial_states(contract, network)
    initial_balance = witness.get("initial_coordinate_balances", {})
    balances: dict[str, Fraction] = {}
    try:
        balances = {key: exact_number(value) for key, value in initial_balance.items()}
    except (AttributeError, ValueError):
        reasons.append("initial_coordinate_balances_invalid")
    floors = contract.get("protected_floors", {})
    prefix: list[JsonObject] = []
    seen: set[str] = set()
    for layer_index, layer in enumerate(layers):
        if not isinstance(layer, list) or not layer:
            reasons.append(f"layer_invalid:{layer_index}")
            continue
        additions: set[str] = set()
        for transformation_id in sorted(str(item) for item in layer):
            if transformation_id in seen:
                reasons.append(f"duplicate_transformation:{transformation_id}")
                continue
            seen.add(transformation_id)
            edge = edges.get(transformation_id)
            if edge is None:
                reasons.append(f"transformation_missing:{transformation_id}")
                continue
            prerequisites = (
                id_set(edge.get("required_inputs"))
                | id_set(edge.get("read_enablers"))
                | id_set(edge.get("required_evidence"))
                | id_set(edge.get("required_authority_refs"))
                | id_set(edge.get("required_catalysts"))
            )
            if not prerequisites <= available:
                reasons.append(f"causal_prerequisite_not_prior:{transformation_id}")
            additions |= id_set(edge.get("produced_outputs"))
            for coordinate in set(balances) | set(floors):
                try:
                    balances[coordinate] = balances.get(coordinate, Fraction(0)) + _flow(
                        edge, coordinate
                    )
                except ValueError:
                    reasons.append(f"coordinate_flow_invalid:{transformation_id}:{coordinate}")
        for coordinate, floor in floors.items() if isinstance(floors, dict) else []:
            try:
                if balances.get(coordinate, Fraction(0)) < _floor_value(floor):
                    reasons.append(f"prefix_floor_violation:{layer_index}:{coordinate}")
            except ValueError:
                reasons.append(f"protected_floor_invalid:{coordinate}")
        available |= additions
        prefix.append(
            {
                "layer": layer_index,
                "balances": {key: str(value) for key, value in sorted(balances.items())},
            }
        )
    return {
        "status": "true" if not reasons else "false",
        "valid": not reasons,
        "reasons": sorted(set(reasons)),
        "formed_states": sorted(available),
        "prefix_balances": prefix,
    }


def validate_generative_catalysis(
    contract: JsonObject, network: JsonObject, witness: JsonObject | None
) -> JsonObject:
    """Compute food-supported closure with catalysts required in an earlier iteration."""

    if witness is None:
        return {"status": "unknown", "valid": None, "reasons": ["catalytic_witness_missing"]}
    edges = transformation_index(network)
    available = id_set(witness.get("food_states")) | initial_states(contract, network)
    bindings = witness.get("catalyst_bindings", {})
    if not isinstance(bindings, dict):
        return {"status": "false", "valid": False, "reasons": ["catalyst_bindings_invalid"]}
    applied: set[str] = set()
    layers: list[list[str]] = []
    while True:
        layer: list[str] = []
        additions: set[str] = set()
        for transformation_id, edge in sorted(edges.items()):
            catalysts = id_set(bindings.get(transformation_id))
            inputs = id_set(edge.get("required_inputs")) | id_set(edge.get("read_enablers"))
            if (
                transformation_id not in applied
                and catalysts
                and inputs <= available
                and catalysts <= available
            ):
                layer.append(transformation_id)
                additions |= id_set(edge.get("produced_outputs"))
        if not layer:
            break
        applied.update(layer)
        available.update(additions)
        layers.append(layer)
    required = set(bindings)
    blocked = sorted(required - applied)
    reasons = [f"circular_or_unavailable_catalyst:{item}" for item in blocked]
    return {
        "status": "true" if not reasons and required else ("false" if reasons else "unknown"),
        "valid": not reasons and bool(required),
        "reasons": reasons or ([] if required else ["catalyst_bindings_empty"]),
        "generative_layers": layers,
        "available_states": sorted(available),
    }


def validate_rate_intervals(witness: JsonObject | None) -> JsonObject:
    """Check external bounded-rate feasibility without a kinetic model."""

    if witness is None:
        return {"status": "unknown", "valid": None, "reasons": ["rate_interval_missing"]}
    reasons: list[str] = []
    source_refs = id_set(witness.get("source_refs"))
    if not source_refs:
        reasons.append("external_source_refs_missing")
    window = witness.get("observation_window", {})
    try:
        if datetime.fromisoformat(
            str(window["start"]).replace("Z", "+00:00")
        ) >= datetime.fromisoformat(str(window["end"]).replace("Z", "+00:00")):
            reasons.append("observation_window_invalid")
    except (KeyError, TypeError, ValueError):
        reasons.append("observation_window_invalid")
    units: set[str] = set()
    for item in witness.get("intervals", []):
        if not isinstance(item, dict):
            reasons.append("interval_invalid")
            continue
        try:
            lower, upper = exact_number(item.get("lower")), exact_number(item.get("upper"))
            if lower < 0 or upper < lower:
                reasons.append(f"interval_infeasible:{item.get('transformation_id')}")
        except ValueError:
            reasons.append(f"interval_invalid:{item.get('transformation_id')}")
        if isinstance(item.get("unit"), str):
            units.add(item["unit"])
    if len(units) != 1:
        reasons.append("common_rate_unit_required")
    return {
        "status": "true" if not reasons else "false",
        "valid": not reasons,
        "reasons": sorted(set(reasons)),
        "kinetic_simulation_performed": False,
    }


def validate_resource_potential(network: JsonObject, witness: JsonObject | None) -> JsonObject:
    """Reject declared closed positive-potential cycles lacking external supply."""

    if witness is None:
        return {"status": "unknown", "valid": None, "reasons": ["resource_potential_missing"]}
    edges = transformation_index(network)
    try:
        weights = {
            key: exact_number(value) for key, value in witness.get("coordinate_weights", {}).items()
        }
    except (AttributeError, ValueError):
        return {"status": "false", "valid": False, "reasons": ["coordinate_weights_invalid"]}
    graph: nx.DiGraph[str] = nx.DiGraph()
    for left_id, left in edges.items():
        graph.add_node(left_id)
        outputs = id_set(left.get("produced_outputs"))
        for right_id, right in edges.items():
            if outputs & (
                id_set(right.get("required_inputs")) | id_set(right.get("read_enablers"))
            ):
                graph.add_edge(left_id, right_id)
    supply_refs = id_set(witness.get("external_supply_refs"))
    violating: list[list[str]] = []
    for cycle in sorted(
        (sorted(item) for item in nx.simple_cycles(graph)), key=lambda item: (len(item), item)
    ):
        gain = sum(
            (
                _flow(edges[edge_id], coordinate) * weight
                for edge_id in cycle
                for coordinate, weight in weights.items()
            ),
            Fraction(0),
        )
        cycle_supplies = {
            ref for edge_id in cycle for ref in id_set(edges[edge_id].get("external_supply_refs"))
        }
        if gain > 0 and not cycle_supplies & supply_refs:
            violating.append(cycle)
    return {
        "status": "true" if not violating else "false",
        "valid": not violating,
        "reasons": ["closed_positive_gain_cycle_without_external_supply"] if violating else [],
        "violating_cycles": violating,
        "thermodynamic_proof": False,
    }


def validate_persistence(
    contract: JsonObject, network: JsonObject, witness: JsonObject | None
) -> JsonObject:
    """Check replenishment and operational maintenance coverage."""

    if witness is None:
        return {"status": "unknown", "valid": None, "reasons": ["persistence_witness_missing"]}
    reasons: list[str] = []
    replenished = id_set(witness.get("replenished_coordinates")) | id_set(
        witness.get("conserved_coordinates")
    )
    consumed = {
        coordinate
        for edge in transformation_index(network).values()
        for coordinate in (
            edge.get("consumed_coordinates", {})
            if isinstance(edge.get("consumed_coordinates"), dict)
            else {}
        )
    }
    protected = set(contract.get("protected_floors", {}))
    for coordinate in sorted(consumed & protected - replenished):
        reasons.append(f"protected_consumption_uncovered:{coordinate}")
    for field in (
        "renewal_refs",
        "expiry_coverage_refs",
        "verifier_capacity_refs",
        "rollback_refs",
        "failure_response_refs",
    ):
        if not id_set(witness.get(field)):
            reasons.append(f"{field}_missing")
    return {"status": "true" if not reasons else "false", "valid": not reasons, "reasons": reasons}


def _deduplicated_groups(
    nodes: dict[str, JsonObject], refs: set[str], active_nodes: set[str]
) -> set[str]:
    unique_artifacts: dict[tuple[object, object, object, object], set[str]] = {}
    for ref in refs & active_nodes:
        node = nodes[ref]
        group = node.get("independence_group")
        if not isinstance(group, str):
            continue
        key = (
            node.get("digest"),
            node.get("source_event"),
            node.get("lineage"),
            node.get("correlation_group"),
        )
        unique_artifacts.setdefault(key, set()).add(group)
    return {sorted(groups)[0] for groups in unique_artifacts.values() if groups}


def independent_support_core(contract: JsonObject, network: JsonObject) -> JsonObject:
    """Iteratively prune records below declared independent support thresholds."""

    policy = contract.get("support_core_policy", {})
    support_minimum = policy.get("minimum_independent_support_groups")
    verifier_minimum = policy.get("minimum_independent_verifier_groups")
    if not isinstance(support_minimum, int) or not isinstance(verifier_minimum, int):
        return {"status": "unknown", "reasons": ["support_core_thresholds_unknown"]}
    nodes = {
        str(node.get("node_id")): node
        for node in network.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("node_id"), str)
    }
    edges = transformation_index(network)
    active_nodes, active_edges = set(nodes), set(edges)
    rounds: list[JsonObject] = []
    while True:
        removed_edges: set[str] = set()
        for edge_id in active_edges:
            edge = edges[edge_id]

            support_groups = _deduplicated_groups(
                nodes, id_set(edge.get("support_refs")), active_nodes
            )
            verifier_groups = _deduplicated_groups(
                nodes, id_set(edge.get("verifier_refs")), active_nodes
            )
            if len(support_groups) < support_minimum or len(verifier_groups) < verifier_minimum:
                removed_edges.add(edge_id)
        produced = {
            node
            for edge_id in active_edges - removed_edges
            for node in id_set(edges[edge_id].get("produced_outputs"))
        }
        retained_seed = initial_states(contract, network)
        removed_nodes = active_nodes - produced - retained_seed
        if not removed_edges and not removed_nodes:
            break
        active_edges -= removed_edges
        active_nodes -= removed_nodes
        rounds.append(
            {
                "removed_transformations": sorted(removed_edges),
                "removed_states": sorted(removed_nodes),
            }
        )
    targets = id_set(contract.get("target_states"))
    return {
        "status": "true" if targets <= active_nodes else "false",
        "active_states": sorted(active_nodes),
        "active_transformations": sorted(active_edges),
        "pruning_rounds": rounds,
        "collapsed_targets": sorted(targets - active_nodes),
        "physical_k_core_claim": False,
    }


def perturbation_replay(contract: JsonObject, network: JsonObject) -> JsonObject:
    """Replay only explicitly declared finite perturbation suites."""

    suites = contract.get("perturbation_suites", [])
    results: list[JsonObject] = []
    for suite in suites if isinstance(suites, list) else []:
        if not isinstance(suite, dict):
            continue
        removed = id_set(suite.get("remove_ids"))
        copy: JsonObject = {
            **network,
            "nodes": [
                node
                for node in network.get("nodes", [])
                if isinstance(node, dict) and node.get("node_id") not in removed
            ],
            "transformations": [
                edge
                for edge in network.get("transformations", [])
                if isinstance(edge, dict) and edge.get("transformation_id") not in removed
            ],
        }
        available = initial_states(contract, copy)
        edges = transformation_index(copy)
        depth = 0
        while True:
            invalid = {
                edge_id
                for edge_id, edge in edges.items()
                if not id_set(edge.get("required_inputs")) <= available
            }
            if not invalid:
                break
            lost_outputs = {
                item
                for edge_id in invalid
                for item in id_set(edges[edge_id].get("produced_outputs"))
            }
            available -= lost_outputs
            for edge_id in invalid:
                edges.pop(edge_id)
            depth += 1
        targets = id_set(contract.get("target_states"))
        core = independent_support_core(contract, copy)
        results.append(
            {
                "suite_id": suite.get("suite_id"),
                "cascade_depth": depth,
                "lost_targets": sorted(targets - available),
                "newly_exposed_seeds": sorted(
                    id_set(contract.get("initial_available_states")) - available
                ),
                "support_core_collapse": core.get("status") == "false",
            }
        )
    return {
        "declared_suite_count": len(results),
        "results": results,
        "undeclared_failures_inferred": False,
    }


def intervention_cover(contract: JsonObject, actions: list[JsonObject]) -> JsonObject:
    """Find an exact minimum action cover over declared intervention requirements."""

    requirements = id_set(contract.get("intervention_requirements"))
    eligible = [(str(action.get("action_id")), id_set(action.get("covers"))) for action in actions]
    covers: list[list[str]] = []
    for size in range(len(eligible) + 1):
        for selected in combinations(eligible, size):
            if requirements <= set().union(*(coverage for _, coverage in selected)):
                covers.append(sorted(identifier for identifier, _ in selected))
        if covers:
            break
    return {
        "requirements": sorted(requirements),
        "minimum_covers": sorted(covers),
        "solution_class": "exact_finite_declared_actions",
        "general_controllability_claim": False,
    }


def verification_network(witness: JsonObject | None) -> JsonObject:
    """Check interval utilization and condition Little outputs on external assumptions."""

    if witness is None:
        return {"status": "unknown", "reasons": ["verification_network_witness_missing"]}
    stages: list[JsonObject] = []
    bottlenecks: list[str] = []
    reasons: list[str] = []
    for stage in witness.get("stages", []):
        if not isinstance(stage, dict):
            reasons.append("stage_invalid")
            continue
        stage_id = str(stage.get("stage_id"))
        try:
            arrival_upper = exact_number(stage.get("arrival_upper"))
            service_lower = exact_number(stage.get("service_lower"))
            if service_lower <= 0:
                raise ValueError("nonpositive service")
            utilization_upper = arrival_upper / service_lower
            overloaded = utilization_upper >= 1
            if overloaded:
                bottlenecks.append(stage_id)
            stages.append(
                {
                    "stage_id": stage_id,
                    "utilization_upper": str(utilization_upper),
                    "overloaded": overloaded,
                }
            )
        except ValueError:
            reasons.append(f"stage_interval_invalid:{stage_id}")
    little: JsonObject | None = None
    if witness.get("stationarity_established") is True and witness.get("means_established") is True:
        little = {
            "eligible": True,
            "identity": "L=lambda*W",
            "values": "external_means_required_per_stage",
        }
    return {
        "status": "false" if reasons else "true",
        "reasons": reasons,
        "stages": stages,
        "bottleneck_set": sorted(bottlenecks),
        "candidate_fan_out_allowed": not bottlenecks,
        "little_law": little
        or {"eligible": False, "reason": "stationarity_and_means_not_established"},
    }
