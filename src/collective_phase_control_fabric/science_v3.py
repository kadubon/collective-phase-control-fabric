# SPDX-License-Identifier: Apache-2.0
"""Exact, provenance-aware operational science for CPCF v0.3."""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from datetime import datetime
from fractions import Fraction
from itertools import combinations
from pathlib import Path
from typing import cast

import networkx as nx

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.generation import GenerationStore
from collective_phase_control_fabric.types import JsonObject, JsonValue, id_set
from collective_phase_control_fabric.workspace_v3 import valid_projections_v3


def _fraction(value: object, maximum_bits: int) -> Fraction:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ValueError("exact rational required")
    result = Fraction(str(value))
    if (
        result.numerator.bit_length() > maximum_bits
        or result.denominator.bit_length() > maximum_bits
    ):
        raise ValueError("rational bit-length limit exceeded")
    return result


def _schema_name(record: JsonObject) -> str:
    return str(record.get("schema_ref", "")).split("@", 1)[0]


def _objects_by_schema(
    projections: list[tuple[JsonObject, JsonObject]],
) -> dict[str, list[JsonObject]]:
    result: dict[str, list[JsonObject]] = defaultdict(list)
    for record, value in projections:
        result[_schema_name(record)].append(value)
    return result


def _one(objects: dict[str, list[JsonObject]], name: str) -> JsonObject | None:
    values = objects.get(name, [])
    return values[0] if len(values) == 1 else None


def _node_index(network: JsonObject) -> dict[str, JsonObject]:
    nodes = [item for item in network.get("nodes", []) if isinstance(item, dict)]
    result = {str(item.get("node_id")): item for item in nodes}
    if len(result) != len(nodes):
        raise ValueError("duplicate node identifiers")
    return result


def _edge_index(network: JsonObject) -> dict[str, JsonObject]:
    edges = [item for item in network.get("transformations", []) if isinstance(item, dict)]
    result = {str(item.get("transformation_id")): item for item in edges}
    if len(result) != len(edges):
        raise ValueError("duplicate transformation identifiers")
    return result


def _enabled(edge: JsonObject, available: set[str], nodes: dict[str, JsonObject]) -> bool:
    prerequisites = (
        id_set(edge.get("required_inputs"))
        | id_set(edge.get("read_enablers"))
        | id_set(edge.get("required_evidence"))
        | id_set(edge.get("required_authority_refs"))
        | id_set(edge.get("required_hazard_refs"))
    )
    if not prerequisites <= available or id_set(edge.get("inhibitors")) & available:
        return False
    clauses = [id_set(item) for item in edge.get("catalyst_clauses", []) if isinstance(item, list)]
    catalyst_ok = edge.get("explicitly_uncatalyzed") is True or any(
        clause and clause <= available for clause in clauses
    )
    if not catalyst_ok:
        return False
    outputs = id_set(edge.get("produced_outputs"))
    return bool(outputs) and outputs <= set(nodes)


def structural_closure(
    contract: JsonObject, network: JsonObject, marking: JsonObject | None
) -> JsonObject:
    nodes = _node_index(network)
    edges = _edge_index(network)
    initial = id_set(contract.get("initial_available_states"))
    if marking is None:
        return {
            "status": "unknown",
            "available_states": [],
            "applied_transformations": [],
            "reasons": ["receipt_backed_state_marking_missing"],
        }
    initial &= id_set(marking.get("state_refs"))
    available = {
        item for item in initial if item in nodes and nodes[item].get("lifecycle") == "active"
    }
    applied: set[str] = set()
    while True:
        changed = False
        for edge_id, edge in sorted(edges.items()):
            if edge_id in applied or not _enabled(edge, available, nodes):
                continue
            available |= id_set(edge.get("produced_outputs"))
            applied.add(edge_id)
            changed = True
        if not changed:
            break
    targets = id_set(contract.get("target_states"))
    return {
        "status": "true" if targets <= available else "false",
        "available_states": sorted(available),
        "applied_transformations": sorted(applied),
        "reached_targets": sorted(targets & available),
        "missing_targets": sorted(targets - available),
        "reasons": [] if targets <= available else ["targets_not_structurally_reachable"],
    }


def _flow(edge: JsonObject, coordinate: str, maximum_bits: int) -> Fraction:
    flows = edge.get("coordinate_flows", {})
    if not isinstance(flows, dict) or not isinstance(flows.get(coordinate), dict):
        return Fraction(0)
    return _fraction(flows[coordinate].get("quantity"), maximum_bits)


def validate_organization(
    contract: JsonObject,
    network: JsonObject,
    witness: JsonObject | None,
    live_refs: set[str],
) -> JsonObject:
    if witness is None:
        return {"status": "unknown", "valid": None, "reasons": ["organization_witness_missing"]}
    reasons: list[str] = []
    edges = _edge_index(network)
    selected_edges = id_set(witness.get("transformation_refs"))
    selected_states = id_set(witness.get("state_refs"))
    targets = id_set(contract.get("target_states"))
    if id_set(witness.get("target_refs")) != targets or not targets <= selected_states:
        reasons.append("organization_target_binding_mismatch")
    if str(witness.get("network_ref")) != str(network.get("network_id")):
        reasons.append("organization_network_binding_mismatch")
    if not selected_edges or not selected_edges <= set(edges):
        reasons.append("organization_transformation_set_invalid")
    flux = witness.get("flux", {})
    if not isinstance(flux, dict) or set(flux) != selected_edges:
        reasons.append("organization_flux_coverage_invalid")
        flux = {}
    maximum_bits = int(contract["analysis_limits"]["maximum_rational_bits"])
    parsed_flux: dict[str, Fraction] = {}
    try:
        parsed_flux = {key: _fraction(value, maximum_bits) for key, value in flux.items()}
    except ValueError as error:
        reasons.append(str(error))
    if any(value <= 0 for value in parsed_flux.values()):
        reasons.append("strictly_positive_flux_required")
    for edge_id in sorted(selected_edges & set(edges)):
        edge = edges[edge_id]
        inputs = id_set(edge.get("required_inputs")) | id_set(edge.get("read_enablers"))
        outputs = id_set(edge.get("produced_outputs"))
        if not inputs <= selected_states or not outputs <= selected_states:
            reasons.append(f"organization_not_closed:{edge_id}")
    balances: dict[str, str] = {}
    for coordinate in sorted(contract.get("state_coordinate_registry", {})):
        balance = sum(
            parsed_flux.get(edge_id, Fraction(0)) * _flow(edges[edge_id], coordinate, maximum_bits)
            for edge_id in selected_edges & set(edges)
        )
        balances[coordinate] = str(balance)
        if balance < 0:
            reasons.append(f"organization_not_self_maintaining:{coordinate}")
    if not id_set(witness.get("source_refs")) <= live_refs:
        reasons.append("organization_source_refs_not_live")
    return {
        "status": "true" if not reasons else "false",
        "valid": not reasons,
        "reasons": sorted(set(reasons)),
        "balances": balances,
        "closed": not any(item.startswith("organization_not_closed") for item in reasons),
        "self_maintaining": not any(
            item.startswith("organization_not_self_maintaining") for item in reasons
        ),
        "chemical_equivalence_claim": False,
    }


def validate_formation(
    contract: JsonObject,
    network: JsonObject,
    marking: JsonObject | None,
    witness: JsonObject | None,
    organization: JsonObject | None,
) -> JsonObject:
    if witness is None or marking is None or organization is None:
        return {
            "status": "unknown",
            "valid": None,
            "reasons": ["formation_marking_or_organization_missing"],
        }
    reasons: list[str] = []
    edges = _edge_index(network)
    nodes = _node_index(network)
    targets = id_set(contract.get("target_states"))
    transformation_refs = id_set(witness.get("transformation_refs"))
    if transformation_refs != id_set(organization.get("transformation_refs")):
        reasons.append("formation_organization_transformation_mismatch")
    if id_set(witness.get("target_refs")) != targets:
        reasons.append("formation_target_binding_mismatch")
    if witness.get("network_ref") != network.get("network_id"):
        reasons.append("formation_network_binding_mismatch")
    if witness.get("initial_marking_ref") != marking.get("marking_id"):
        reasons.append("formation_marking_binding_mismatch")
    layers = witness.get("layers", [])
    maximum_layers = int(contract["formation_policy"]["maximum_layer_count"])
    if not isinstance(layers, list) or not layers or len(layers) > maximum_layers:
        reasons.append("formation_layer_limit_invalid")
        layers = []
    flattened = [item for layer in layers if isinstance(layer, list) for item in layer]
    if len(flattened) != len(set(flattened)) or set(flattened) != transformation_refs:
        reasons.append("formation_layer_coverage_invalid")
    available = id_set(marking.get("state_refs")) & set(nodes)
    maximum_bits = int(contract["analysis_limits"]["maximum_rational_bits"])
    balances: dict[str, Fraction] = {}
    try:
        for coordinate, value in marking.get("coordinates", {}).items():
            balances[coordinate] = _fraction(value.get("quantity"), maximum_bits)
    except (AttributeError, ValueError):
        reasons.append("state_marking_coordinates_invalid")
    prefix: list[JsonObject] = []
    for layer_index, layer in enumerate(layers):
        if not isinstance(layer, list) or not layer:
            reasons.append(f"formation_layer_invalid:{layer_index}")
            continue
        prior = set(available)
        additions: set[str] = set()
        for edge_id in layer:
            edge = edges.get(str(edge_id))
            if edge is None:
                reasons.append(f"formation_transformation_missing:{edge_id}")
                continue
            if not _enabled(edge, prior, nodes):
                reasons.append(f"formation_prerequisite_not_strictly_prior:{edge_id}")
            additions |= id_set(edge.get("produced_outputs"))
            for coordinate in contract.get("state_coordinate_registry", {}):
                try:
                    balances[coordinate] = balances.get(coordinate, Fraction(0)) + _flow(
                        edge, coordinate, maximum_bits
                    )
                    floor = contract.get("protected_floors", {}).get(coordinate)
                    if isinstance(floor, dict) and balances[coordinate] < _fraction(
                        floor.get("quantity"), maximum_bits
                    ):
                        reasons.append(
                            f"formation_prefix_floor_violation:{layer_index}:{edge_id}:{coordinate}"
                        )
                except ValueError:
                    reasons.append(f"formation_coordinate_invalid:{edge_id}:{coordinate}")
        available |= additions
        prefix.append(
            {
                "layer": layer_index,
                "available_states": sorted(available),
                "balances": {key: str(value) for key, value in sorted(balances.items())},
            }
        )
    if not targets <= available:
        reasons.append("formation_targets_not_formed")
    return {
        "status": "true" if not reasons else "false",
        "valid": not reasons,
        "reasons": sorted(set(reasons)),
        "prefix": prefix,
    }


def validate_resource_accounting(
    contract: JsonObject,
    network: JsonObject,
    witness: JsonObject | None,
    transformation_refs: set[str],
    live_refs: set[str],
) -> JsonObject:
    if witness is None:
        return {
            "status": "unknown",
            "valid": None,
            "reasons": ["open_system_resource_witness_missing"],
        }
    reasons: list[str] = []
    edges = _edge_index(network)
    maximum_bits = int(contract["analysis_limits"]["maximum_rational_bits"])
    registry = set(contract.get("state_coordinate_registry", {}))
    weights_value = witness.get("coordinate_weights", {})
    credits_value = witness.get("boundary_supply_credits", {})
    try:
        weights = {key: _fraction(value, maximum_bits) for key, value in weights_value.items()}
        credits = {key: _fraction(value, maximum_bits) for key, value in credits_value.items()}
    except (AttributeError, ValueError) as error:
        return {"status": "false", "valid": False, "reasons": [str(error)]}
    if set(weights) != registry:
        reasons.append("resource_weight_coordinate_coverage_invalid")
    protected = id_set(witness.get("protected_coordinates"))
    if protected != set(contract.get("protected_floors", {})) or any(
        weights.get(item, Fraction(0)) <= 0 for item in protected
    ):
        reasons.append("protected_coordinate_positive_weights_required")
    if witness.get("network_ref") != network.get("network_id"):
        reasons.append("resource_network_binding_mismatch")
    if not id_set(witness.get("source_refs")) <= live_refs:
        reasons.append("resource_source_refs_not_live")
    residuals: dict[str, str] = {}
    for edge_id in sorted(transformation_refs):
        edge = edges.get(edge_id)
        if edge is None:
            reasons.append(f"resource_transformation_missing:{edge_id}")
            continue
        gain = sum(
            weights.get(coordinate, Fraction(0)) * _flow(edge, coordinate, maximum_bits)
            for coordinate in registry
        )
        supply_refs = id_set(edge.get("boundary_supply_refs"))
        if not supply_refs <= live_refs:
            reasons.append(f"resource_boundary_supply_not_live:{edge_id}")
        credit = sum(credits.get(ref, Fraction(0)) for ref in supply_refs)
        residual = gain - credit
        residuals[edge_id] = str(residual)
        if residual > 0:
            reasons.append(f"positive_internal_gain_without_supply_credit:{edge_id}")
    return {
        "status": "true" if not reasons else "false",
        "valid": not reasons,
        "reasons": sorted(set(reasons)),
        "dual_residuals": residuals,
        "thermodynamic_proof": False,
    }


def validate_rate_feasibility(
    contract: JsonObject,
    network: JsonObject,
    witness: JsonObject | None,
    transformation_refs: set[str],
    live_refs: set[str],
) -> JsonObject:
    if witness is None:
        return {"status": "unknown", "valid": None, "reasons": ["rate_feasibility_witness_missing"]}
    reasons: list[str] = []
    maximum_bits = int(contract["analysis_limits"]["maximum_rational_bits"])
    edges = _edge_index(network)
    intervals = witness.get("rate_intervals", {})
    flux = witness.get("feasible_flux", {})
    if (
        not isinstance(intervals, dict)
        or not isinstance(flux, dict)
        or set(intervals) != transformation_refs
        or set(flux) != transformation_refs
    ):
        reasons.append("rate_transformation_coverage_invalid")
        intervals = {}
        flux = {}
    parsed_flux: dict[str, Fraction] = {}
    try:
        for edge_id in sorted(transformation_refs):
            lower = _fraction(intervals[edge_id]["lower"], maximum_bits)
            upper = _fraction(intervals[edge_id]["upper"], maximum_bits)
            value = _fraction(flux[edge_id], maximum_bits)
            parsed_flux[edge_id] = value
            if lower < 0 or upper < lower or not lower <= value <= upper:
                reasons.append(f"rate_interval_or_flux_invalid:{edge_id}")
    except (KeyError, TypeError, ValueError):
        reasons.append("rate_interval_or_flux_malformed")
    if witness.get("network_ref") != network.get("network_id"):
        reasons.append("rate_network_binding_mismatch")
    if not id_set(witness.get("source_refs")) <= live_refs:
        reasons.append("rate_source_refs_not_live")
    try:
        window = witness["observation_window"]
        if datetime.fromisoformat(
            str(window["start"]).replace("Z", "+00:00")
        ) >= datetime.fromisoformat(str(window["end"]).replace("Z", "+00:00")):
            reasons.append("rate_observation_window_invalid")
    except (KeyError, TypeError, ValueError):
        reasons.append("rate_observation_window_invalid")
    balances: dict[str, str] = {}
    for coordinate in contract.get("protected_floors", {}):
        balance = sum(
            parsed_flux.get(edge_id, Fraction(0)) * _flow(edges[edge_id], coordinate, maximum_bits)
            for edge_id in transformation_refs
            if edge_id in edges
        )
        balances[coordinate] = str(balance)
        if balance < 0:
            reasons.append(f"rate_protected_coordinate_depletion:{coordinate}")
    return {
        "status": "true" if not reasons else "false",
        "valid": not reasons,
        "reasons": sorted(set(reasons)),
        "protected_balance_rates": balances,
        "kinetic_simulation_performed": False,
    }


def validate_generalized_raf(
    contract: JsonObject,
    network: JsonObject,
    marking: JsonObject | None,
    witness: JsonObject | None,
    transformation_refs: set[str],
    live_refs: set[str],
) -> JsonObject:
    if witness is None or marking is None:
        return {"status": "unknown", "valid": None, "reasons": ["raf_witness_or_marking_missing"]}
    reasons: list[str] = []
    edges = _edge_index(network)
    nodes = _node_index(network)
    targets = id_set(contract.get("target_states"))
    if id_set(witness.get("transformation_refs")) != transformation_refs:
        reasons.append("raf_organization_transformation_mismatch")
    if id_set(witness.get("target_refs")) != targets:
        reasons.append("raf_target_binding_mismatch")
    if witness.get("network_ref") != network.get("network_id"):
        reasons.append("raf_network_binding_mismatch")
    food = id_set(witness.get("food_state_refs"))
    initial = id_set(marking.get("state_refs")) & id_set(contract.get("initial_available_states"))
    if not food <= initial:
        reasons.append("raf_food_not_receipt_backed_initial_state")
    if not id_set(witness.get("source_refs")) <= live_refs:
        reasons.append("raf_source_refs_not_live")
    available = set(food)
    remaining = set(transformation_refs)
    layers: list[list[str]] = []
    while remaining:
        layer = [
            edge_id
            for edge_id in sorted(remaining)
            if edge_id in edges and _enabled(edges[edge_id], available, nodes)
        ]
        if not layer:
            break
        additions = {
            item for edge_id in layer for item in id_set(edges[edge_id].get("produced_outputs"))
        }
        available |= additions
        remaining -= set(layer)
        layers.append(layer)
    if remaining:
        reasons.extend(f"raf_not_generatively_formable:{item}" for item in sorted(remaining))
    if not targets <= available:
        reasons.append("raf_targets_not_generated")
    supplied_layers = witness.get("layers", [])
    if supplied_layers != layers:
        reasons.append("raf_layer_recomputation_mismatch")
    return {
        "status": "true" if not reasons else "false",
        "valid": not reasons,
        "reasons": sorted(set(reasons)),
        "generative_layers": layers,
        "maximal_within_declared_set": not remaining,
    }


def _minimal_siphons(network: JsonObject, maximum_species: int) -> tuple[str, list[set[str]]]:
    nodes = sorted(_node_index(network))
    if len(nodes) > maximum_species or 2 ** len(nodes) - 1 > 100_000:
        return "unknown", []
    edges = _edge_index(network)
    siphons: list[set[str]] = []
    for size in range(1, len(nodes) + 1):
        for selected_tuple in combinations(nodes, size):
            selected = set(selected_tuple)
            if any(existing <= selected for existing in siphons):
                continue
            valid = True
            for edge in edges.values():
                if (
                    id_set(edge.get("produced_outputs")) & selected
                    and not id_set(edge.get("required_inputs")) & selected
                ):
                    valid = False
                    break
            if valid:
                siphons.append(selected)
    return "true", siphons


def validate_siphon_coverage(
    contract: JsonObject,
    network: JsonObject,
    witness: JsonObject | None,
    live_refs: set[str],
) -> JsonObject:
    if witness is None:
        return {"status": "unknown", "valid": None, "reasons": ["siphon_coverage_witness_missing"]}
    exhaustive, calculated = _minimal_siphons(
        network, int(contract["analysis_limits"]["maximum_siphon_species"])
    )
    supplied = {
        frozenset(id_set(item))
        for item in witness.get("minimal_siphons", [])
        if isinstance(item, list)
    }
    actual = {frozenset(item) for item in calculated}
    reasons: list[str] = []
    if witness.get("network_ref") != network.get("network_id"):
        reasons.append("siphon_network_binding_mismatch")
    if exhaustive != "true":
        reasons.append("siphon_absence_not_exhaustively_established")
    elif supplied != actual or witness.get("search_complete") is not True:
        reasons.append("minimal_siphon_recomputation_mismatch")
    coverage = witness.get("coverage_refs", {})
    if not isinstance(coverage, dict):
        reasons.append("siphon_coverage_map_invalid")
        coverage = {}
    for siphon in supplied:
        key = ",".join(sorted(siphon))
        if not id_set(coverage.get(key)) or not id_set(coverage.get(key)) <= live_refs:
            reasons.append(f"siphon_uncovered:{key}")
    if not id_set(witness.get("source_refs")) <= live_refs:
        reasons.append("siphon_source_refs_not_live")
    status = "unknown" if exhaustive != "true" else ("true" if not reasons else "false")
    return {
        "status": status,
        "valid": True if status == "true" else (False if status == "false" else None),
        "reasons": sorted(set(reasons)),
        "minimal_siphons": [sorted(item) for item in calculated],
        "solution_class": "exact_exhaustive" if exhaustive == "true" else "bounded_unknown",
    }


def validate_verification_network(witness: JsonObject | None, live_refs: set[str]) -> JsonObject:
    if witness is None:
        return {
            "status": "unknown",
            "valid": None,
            "reasons": ["verification_network_witness_missing"],
        }
    reasons: list[str] = []
    stages = {
        str(item.get("stage_id")): item
        for item in witness.get("stages", [])
        if isinstance(item, dict)
    }
    graph: nx.DiGraph[str] = nx.DiGraph()
    graph.add_nodes_from(stages)
    fanout: dict[tuple[str, str], Fraction] = {}
    try:
        for route in witness.get("routing", []):
            left, right = str(route["from"]), str(route["to"])
            graph.add_edge(left, right)
            fanout[(left, right)] = Fraction(str(route["fanout_upper"]))
    except (KeyError, TypeError, ValueError):
        reasons.append("verification_routing_invalid")
    if not nx.is_directed_acyclic_graph(graph):
        reasons.append("verification_routing_cycle")
        order = sorted(stages)
    else:
        order = list(nx.topological_sort(graph))
    propagated: dict[str, Fraction] = {}
    bottlenecks: list[str] = []
    for stage_id in order:
        stage = stages.get(stage_id)
        if stage is None:
            reasons.append(f"verification_stage_missing:{stage_id}")
            continue
        try:
            arrival_lower = Fraction(str(stage["arrival_lower"]))
            declared = Fraction(str(stage["arrival_upper"]))
            service_upper = Fraction(str(stage["service_upper"]))
            incoming = sum(
                (
                    propagated.get(parent, Fraction(0)) * fanout[(parent, stage_id)]
                    for parent in graph.predecessors(stage_id)
                ),
                Fraction(0),
            )
            arrival = max(declared, incoming)
            service = Fraction(str(stage["service_lower"]))
            backlog = Fraction(str(stage["backlog"]))
            if arrival_lower < 0 or declared < arrival_lower:
                reasons.append(f"verification_arrival_interval_invalid:{stage_id}")
            if service <= 0 or service_upper < service:
                reasons.append(f"verification_service_interval_invalid:{stage_id}")
            if service <= arrival or backlog < 0:
                bottlenecks.append(stage_id)
            propagated[stage_id] = arrival
        except (KeyError, TypeError, ValueError, ZeroDivisionError):
            reasons.append(f"verification_stage_interval_invalid:{stage_id}")
        if not id_set(stage.get("source_refs")) <= live_refs:
            reasons.append(f"verification_stage_source_not_live:{stage_id}")
    if not id_set(witness.get("source_refs")) <= live_refs:
        reasons.append("verification_source_refs_not_live")
    if bottlenecks:
        reasons.append("verification_stage_overloaded_or_backlog_not_drainable")
    return {
        "status": "true" if not reasons else "false",
        "valid": not reasons,
        "reasons": sorted(set(reasons)),
        "bottleneck_set": sorted(bottlenecks),
        "candidate_fan_out_allowed": not bottlenecks and not reasons,
        "little_law": {
            "eligible": witness.get("stationarity_established") is True
            and witness.get("means_established") is True,
            "values_computed": False,
        },
    }


def effective_independence(
    network: JsonObject, ledger: JsonObject | None, trusted_key_ids: set[str]
) -> JsonObject:
    nodes = _node_index(network)
    eroded: set[str] = set()
    if ledger is not None:
        committed: set[str] = set()
        for event in ledger.get("events", []):
            if not isinstance(event, dict):
                continue
            domain = event.get("independence_domain")
            if not isinstance(domain, str):
                continue
            if event.get("event_type") == "commit":
                committed.add(domain)
            elif event.get("event_type") == "consume" and domain not in committed:
                eroded.add(domain)
    graph: nx.Graph[str] = nx.Graph()
    for node in nodes.values():
        domain = node.get("independence_domain")
        if (
            isinstance(domain, str)
            and domain not in eroded
            and node.get("principal_key_id") in trusted_key_ids
        ):
            graph.add_node(domain)
    by_infrastructure: dict[str, set[str]] = defaultdict(set)
    by_correlation: dict[str, set[str]] = defaultdict(set)
    for node in nodes.values():
        domain = node.get("independence_domain")
        if (
            not isinstance(domain, str)
            or domain in eroded
            or node.get("principal_key_id") not in trusted_key_ids
        ):
            continue
        if isinstance(node.get("infrastructure_domain"), str):
            by_infrastructure[str(node["infrastructure_domain"])].add(domain)
        if isinstance(node.get("correlation_group"), str):
            by_correlation[str(node["correlation_group"])].add(domain)
    for groups in [*by_infrastructure.values(), *by_correlation.values()]:
        for left, right in combinations(sorted(groups), 2):
            graph.add_edge(left, right)
    component_of = {
        domain: sorted(component)[0]
        for component in nx.connected_components(graph)
        for domain in component
    }
    return {
        "status": "false" if eroded else "true",
        "eroded_domains": sorted(eroded),
        "effective_domain_of": component_of,
        "effective_domain_count": len(set(component_of.values())),
        "model_names_establish_independence": False,
        "untrusted_principals_establish_independence": False,
    }


def support_core(
    contract: JsonObject,
    network: JsonObject,
    independence: JsonObject,
) -> JsonObject:
    nodes = _node_index(network)
    edges = _edge_index(network)
    mapping = cast(dict[str, str], independence.get("effective_domain_of", {}))
    support_minimum = int(contract["support_core_policy"]["minimum_support_domains"])
    verifier_minimum = int(contract["support_core_policy"]["minimum_verifier_domains"])
    active_edges = set(edges)
    active_nodes = set(nodes)
    rounds: list[JsonObject] = []
    while True:
        remove: set[str] = set()
        for edge_id in active_edges:
            edge = edges[edge_id]
            support_domains = {
                mapping.get(str(nodes[ref].get("independence_domain")))
                for ref in id_set(edge.get("support_refs")) & active_nodes
                if ref in nodes
            }
            verifier_domains = {
                mapping.get(str(nodes[ref].get("independence_domain")))
                for ref in id_set(edge.get("verifier_refs")) & active_nodes
                if ref in nodes
            }
            support_domains.discard(None)
            verifier_domains.discard(None)
            if len(support_domains) < support_minimum or len(verifier_domains) < verifier_minimum:
                remove.add(edge_id)
        produced = {
            item
            for edge_id in active_edges - remove
            for item in id_set(edges[edge_id].get("produced_outputs"))
        }
        initial = id_set(contract.get("initial_available_states"))
        remove_nodes = active_nodes - produced - initial
        if not remove and not remove_nodes:
            break
        active_edges -= remove
        active_nodes -= remove_nodes
        rounds.append(
            {"removed_transformations": sorted(remove), "removed_states": sorted(remove_nodes)}
        )
    targets = id_set(contract.get("target_states"))
    return {
        "status": "true" if targets <= active_nodes else "false",
        "active_states": sorted(active_nodes),
        "active_transformations": sorted(active_edges),
        "collapsed_targets": sorted(targets - active_nodes),
        "rounds": rounds,
        "physical_k_core_claim": False,
    }


def perturbation_replay_v3(
    contract: JsonObject,
    network: JsonObject,
    marking: JsonObject | None,
    suites: list[JsonObject],
    independence: JsonObject,
) -> JsonObject:
    required = id_set(contract["support_core_policy"].get("perturbation_suite_refs"))
    by_id = {str(item.get("suite_id")): item for item in suites}
    if not required or not required <= set(by_id):
        return {
            "status": "false",
            "valid": False,
            "reasons": ["required_nonempty_perturbation_suites_missing"],
            "results": [],
        }
    results: list[JsonObject] = []
    accepted = True
    for suite_id in sorted(required):
        suite = by_id[suite_id]
        acceptance = suite["acceptance"]
        case_results: list[JsonObject] = []
        for case in suite["cases"]:
            removed = id_set(case.get("remove_refs"))
            reduced_network: JsonObject = {
                **network,
                "nodes": [
                    item
                    for item in network.get("nodes", [])
                    if isinstance(item, dict) and item.get("node_id") not in removed
                ],
                "transformations": [
                    item
                    for item in network.get("transformations", [])
                    if isinstance(item, dict) and item.get("transformation_id") not in removed
                ],
            }
            reduced_marking = deepcopy(marking) if marking is not None else None
            if reduced_marking is not None:
                reduced_marking["state_refs"] = sorted(
                    id_set(reduced_marking.get("state_refs")) - removed
                )
                for coordinate, reduction in case.get("resource_reductions", {}).items():
                    current = reduced_marking.get("coordinates", {}).get(coordinate)
                    if not isinstance(current, dict) or not isinstance(reduction, dict):
                        continue
                    if current.get("unit") != reduction.get("unit"):
                        current["quantity"] = "-1"
                    else:
                        current["quantity"] = str(
                            Fraction(str(current["quantity"]))
                            - Fraction(str(reduction["quantity"]))
                        )
            closure = structural_closure(contract, reduced_network, reduced_marking)
            core = support_core(contract, reduced_network, independence)
            lost = closure.get("missing_targets", [])
            depth = len(core.get("rounds", []))
            floor_violations: list[str] = []
            if reduced_marking is not None:
                for coordinate, floor in contract.get("protected_floors", {}).items():
                    current = reduced_marking.get("coordinates", {}).get(coordinate)
                    if (
                        not isinstance(current, dict)
                        or not isinstance(floor, dict)
                        or current.get("unit") != floor.get("unit")
                        or Fraction(str(current.get("quantity", "0")))
                        < Fraction(str(floor.get("quantity", "0")))
                    ):
                        floor_violations.append(str(coordinate))
            case_ok = (
                len(lost) <= int(acceptance["maximum_lost_targets"])
                and depth <= int(acceptance["maximum_cascade_depth"])
                and (not acceptance["support_core_must_survive"] or core["status"] == "true")
                and not floor_violations
            )
            accepted &= case_ok
            case_results.append(
                {
                    "case_id": case["case_id"],
                    "lost_targets": lost,
                    "cascade_depth": depth,
                    "support_core_collapse": core["status"] != "true",
                    "protected_floor_violations": sorted(floor_violations),
                    "accepted": case_ok,
                }
            )
        results.append({"suite_id": suite_id, "case_results": case_results})
    return {
        "status": "true" if accepted else "false",
        "valid": accepted,
        "reasons": [] if accepted else ["perturbation_acceptance_failed"],
        "results": results,
        "undeclared_failures_inferred": False,
    }


def acceleration_evidence(
    contract: JsonObject,
    protocols: list[JsonObject],
    results: list[JsonObject],
    live_refs: set[str],
) -> JsonObject:
    required_protocols = id_set(contract.get("measurement_protocol_refs"))
    supplied_protocols = {
        str(item.get("protocol_id"))
        for item in protocols
        if isinstance(item.get("protocol_id"), str)
    }
    if required_protocols and required_protocols != supplied_protocols:
        return {
            "status": "unmeasured",
            "reasons": ["required_measurement_protocols_missing_or_ambiguous"],
            "causal_proof": False,
        }
    if not results:
        return {"status": "unmeasured", "reasons": ["trial_result_missing"], "causal_proof": False}
    protocols_by_digest = {digest_v3_json(cast(JsonValue, item)): item for item in protocols}
    compatible = False
    inconclusive = False
    contradiction = False
    reasons: list[str] = []
    for result in results:
        protocol = protocols_by_digest.get(str(result.get("protocol_digest")))
        if protocol is None:
            reasons.append("trial_protocol_binding_missing")
            continue
        if id_set(protocol.get("target_refs")) != id_set(contract.get("target_states")):
            reasons.append("trial_target_binding_mismatch")
            continue
        if protocol.get("evaluator_key_id") != result.get("evaluator_key_id"):
            reasons.append("trial_evaluator_binding_mismatch")
            continue
        if (
            not id_set(protocol.get("source_refs")) <= live_refs
            or not id_set(result.get("source_refs")) <= live_refs
        ):
            reasons.append("trial_source_refs_not_live")
            continue
        try:
            registered = datetime.fromisoformat(
                str(protocol["registered_at"]).replace("Z", "+00:00")
            )
            started = datetime.fromisoformat(
                str(protocol["observation_window"]["start"]).replace("Z", "+00:00")
            )
            completed = datetime.fromisoformat(str(result["completed_at"]).replace("Z", "+00:00"))
            if not registered < started <= completed:
                reasons.append("trial_preregistration_order_invalid")
                continue
        except (KeyError, TypeError, ValueError):
            reasons.append("trial_time_binding_invalid")
            continue
        outcome_spec = {str(item["metric"]): item for item in protocol["outcomes"]}
        result_intervals = {str(item["metric"]): item for item in result["effect_intervals"]}
        if set(outcome_spec) != set(result_intervals):
            reasons.append("trial_outcome_coverage_mismatch")
            continue
        supported = True
        crossed = False
        for metric, spec in outcome_spec.items():
            interval = result_intervals[metric]
            try:
                lower, upper = Fraction(interval["lower"]), Fraction(interval["upper"])
            except (KeyError, ValueError, ZeroDivisionError):
                reasons.append(f"trial_interval_invalid:{metric}")
                supported = False
                continue
            if (
                lower > upper
                or interval.get("unit") != spec.get("unit")
                or interval.get("direction") != spec.get("direction")
            ):
                reasons.append(f"trial_interval_binding_invalid:{metric}")
                supported = False
            directional = upper < 0 if spec["direction"] == "minimize" else lower > 0
            crossed |= lower <= 0 <= upper
            supported &= directional
        quality_floors = protocol.get("quality_floors", {})
        quality = {str(item["metric"]): item for item in result.get("quality_intervals", [])}
        for metric, floor in quality_floors.items():
            interval = quality.get(metric)
            if interval is None or interval.get("unit") != floor.get("unit"):
                contradiction = True
                reasons.append(f"trial_quality_floor_unresolved:{metric}")
                continue
            if Fraction(str(interval["lower"])) < Fraction(str(floor["quantity"])):
                contradiction = True
                reasons.append(f"trial_quality_floor_contradiction:{metric}")
        compatible |= supported and not contradiction
        inconclusive |= crossed
    if contradiction:
        status = "external_quality_or_safety_contradiction"
    elif compatible:
        status = "external_acceleration_bundle_compatible"
    elif inconclusive or results:
        status = "externally_observed_inconclusive"
    else:
        status = "unmeasured"
    return {
        "status": status,
        "reasons": sorted(set(reasons)),
        "causal_proof": False,
        "statistical_method_certified_by_cpcf": False,
    }


def science_audit_v3(root: Path) -> JsonObject:
    """Evaluate all v0.3 layers from freshly recomputed source-backed projections."""

    try:
        manifest, projections = valid_projections_v3(root)
        store = GenerationStore(root)
        contract_value = store.get_json(str(manifest["contract_digest"]))
        if not isinstance(contract_value, dict):
            raise ValueError("contract must be an object")
        contract = contract_value
        trust_value = store.get_json(str(manifest["trust_policy_digest"]))
        if not isinstance(trust_value, dict):
            raise ValueError("trust policy must be an object")
        objects = _objects_by_schema(projections)
        network = _one(objects, "transformation-network")
        marking = _one(objects, "state-marking")
        if network is None:
            return {
                "command_status": "ok",
                "structural_organization_level": None,
                "status": "unmeasured",
                "reasons": ["one_source_backed_network_required"],
                "generation_id": manifest["generation_id"],
                "collective_superintelligence_phase_inferred": False,
            }
        if len(network.get("nodes", [])) > int(contract["analysis_limits"]["maximum_nodes"]) or len(
            network.get("transformations", [])
        ) > int(contract["analysis_limits"]["maximum_transformations"]):
            return {
                "command_status": "failed",
                "failure_code": "analysis_limit_exceeded",
                "structural_organization_level": None,
            }
        live_refs = {
            str(node.get("node_id"))
            for node in network.get("nodes", [])
            if isinstance(node, dict) and node.get("lifecycle") == "active"
        }
        trusted_key_ids = {
            str(item.get("key_id"))
            for item in trust_value.get("principals", [])
            if isinstance(item, dict) and item.get("revoked") is False
        }
        closure = structural_closure(contract, network, marking)
        organization_witness = _one(objects, "organization-witness")
        organization = validate_organization(contract, network, organization_witness, live_refs)
        formation = validate_formation(
            contract,
            network,
            marking,
            _one(objects, "formation-sequence-witness"),
            organization_witness,
        )
        transformation_refs = (
            id_set(organization_witness.get("transformation_refs"))
            if organization_witness
            else set()
        )
        resource = validate_resource_accounting(
            contract,
            network,
            _one(objects, "open-system-resource-witness"),
            transformation_refs,
            live_refs,
        )
        rates = validate_rate_feasibility(
            contract,
            network,
            _one(objects, "rate-feasibility-witness"),
            transformation_refs,
            live_refs,
        )
        siphons = validate_siphon_coverage(
            contract, network, _one(objects, "siphon-coverage-witness"), live_refs
        )
        verification = validate_verification_network(
            _one(objects, "verification-network-witness"), live_refs
        )
        raf = validate_generalized_raf(
            contract,
            network,
            marking,
            _one(objects, "generalized-raf-witness"),
            transformation_refs,
            live_refs,
        )
        independence = effective_independence(
            network, _one(objects, "coordination-event-ledger"), trusted_key_ids
        )
        core = support_core(contract, network, independence)
        perturbations = perturbation_replay_v3(
            contract, network, marking, objects.get("perturbation-suite", []), independence
        )
        acceleration = acceleration_evidence(
            contract,
            objects.get("measurement-protocol", []),
            objects.get("trial-result-certificate", []),
            live_refs,
        )
    except (OSError, KeyError, TypeError, ValueError) as error:
        return {
            "command_status": "failed",
            "failure_code": "science_audit_failed",
            "detail": str(error),
            "structural_organization_level": None,
        }
    level = -1
    progress: list[str] = []
    if closure["status"] == "true":
        level = 0
        progress.append("receipt_backed_structural_reachability")
    if level >= 0:
        level = 1
        progress.append("source_backed_enabling_state")
    if level >= 1 and organization["status"] == "true" and formation["status"] == "true":
        level = 2
        progress.append("causal_closed_self_maintaining_organization")
    if (
        level >= 2
        and resource["status"] == "true"
        and rates["status"] == "true"
        and siphons["status"] == "true"
        and verification["status"] == "true"
    ):
        level = 3
        progress.append("finite_resource_persistence_candidate")
    if level >= 3 and raf["status"] == "true":
        level = 4
        progress.append("target_bound_generative_catalysis_candidate")
    if level >= 4 and core["status"] == "true" and perturbations["status"] == "true":
        level = 5
        progress.append("declared_perturbation_robustness_candidate")
    return {
        "command_status": "ok",
        "generation_id": manifest["generation_id"],
        "analysis_epoch": manifest["analysis_epoch"],
        "structural_organization_level": f"L{level}" if level >= 0 else None,
        "progress_classes": progress,
        "layers": {
            "structural_reachability": closure,
            "causal_formation": formation,
            "exact_organization": organization,
            "open_system_resource_accounting": resource,
            "rate_feasibility": rates,
            "siphon_coverage": siphons,
            "verification_network": verification,
            "generalized_generative_raf": raf,
            "effective_independence": independence,
            "independent_support_core": core,
            "perturbation_replay": perturbations,
        },
        "operational_acceleration": acceleration,
        "collective_superintelligence_phase_inferred": False,
        "physical_phase_transition_inferred": False,
        "thermodynamic_model_executed": False,
        "monotone_across_time": False,
        "external_claim_bundle_compatible": acceleration["status"]
        == "external_acceleration_bundle_compatible",
    }
