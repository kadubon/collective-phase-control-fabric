# SPDX-License-Identifier: Apache-2.0
"""Singleton-exact and SCC-conservative regeneration deadlock detection."""

from __future__ import annotations

import networkx as nx

from collective_phase_control_fabric.network import ClosureResult, transformation_index
from collective_phase_control_fabric.types import JsonObject, id_set


def regeneration_deadlocks(
    contract: JsonObject,
    network: JsonObject,
    closure: ClosureResult,
) -> list[JsonObject]:
    """Detect unavailable prerequisite sets whose internal producers depend on the same set."""

    available = set(closure.available_states)
    target_paths = contract.get("target_paths", [])
    needed: set[str] = set()
    if isinstance(target_paths, list):
        for path in target_paths:
            if isinstance(path, dict):
                needed.update(id_set(path.get("required_states")) - available)
    transformations = transformation_index(network)
    producers: dict[str, list[JsonObject]] = {state: [] for state in needed}
    for edge in transformations.values():
        for state in id_set(edge.get("produced_outputs")) & needed:
            producers[state].append(edge)
    dependency: nx.DiGraph[str] = nx.DiGraph()
    dependency.add_nodes_from(needed)
    for state, edges in producers.items():
        for edge in edges:
            for required in id_set(edge.get("required_inputs")) & needed:
                dependency.add_edge(state, required)
    results: list[JsonObject] = []
    for state in sorted(needed):
        edges = producers[state]
        if edges and all(state in id_set(edge.get("required_inputs")) for edge in edges):
            external = any(edge.get("source_system") != "CPCF" for edge in edges)
            results.append(
                {
                    "deadlock_id": f"regeneration_deadlock:{state}",
                    "states": [state],
                    "exactness": "singleton_exact",
                    "producer_transformations": sorted(
                        str(edge["transformation_id"]) for edge in edges
                    ),
                    "external_dependency": external,
                    "recommended_handoff": "external_producer" if external else "affordance_repair",
                }
            )
    for component in nx.strongly_connected_components(dependency):
        if len(component) <= 1:
            continue
        closed = True
        component_edges: set[str] = set()
        external = False
        for state in component:
            edges = producers[state]
            if not edges or any(
                not (id_set(edge.get("required_inputs")) & component) for edge in edges
            ):
                closed = False
                break
            component_edges.update(str(edge["transformation_id"]) for edge in edges)
            external = external or any(edge.get("source_system") != "CPCF" for edge in edges)
        if closed:
            stable = "+".join(sorted(component))
            results.append(
                {
                    "deadlock_id": f"regeneration_deadlock:{stable}",
                    "states": sorted(component),
                    "exactness": "scc_conservative",
                    "producer_transformations": sorted(component_edges),
                    "external_dependency": external,
                    "recommended_handoff": "external_producer" if external else "affordance_repair",
                }
            )
    return sorted(results, key=lambda item: str(item["deadlock_id"]))
