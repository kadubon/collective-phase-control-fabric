# SPDX-License-Identifier: Apache-2.0
"""Deterministic false-positive detectors for capability networks."""

from __future__ import annotations

from collections import Counter

import networkx as nx

from collective_phase_control_fabric.network import ClosureResult, node_index, target_states
from collective_phase_control_fabric.types import INVALID_LIFECYCLE, JsonObject, id_set

BLOCKING_DETECTORS = frozenset(
    {
        "self_certifying_cycle",
        "nonproductive_cycle",
        "duplicate_mass",
        "stale_closure",
        "proxy_only_closure",
        "resource_sink_cycle",
        "authority_loop",
    }
)


def bipartite_graph(network: JsonObject) -> nx.DiGraph[str]:
    """Build a lossless bipartite graph for diagnostics, not exact cut claims."""

    graph: nx.DiGraph[str] = nx.DiGraph()
    nodes = node_index(network)
    for node_id, node in nodes.items():
        graph.add_node(node_id, kind="state", record=node)
    for edge in network.get("transformations", []):
        if not isinstance(edge, dict) or not isinstance(edge.get("transformation_id"), str):
            continue
        edge_id = f"transformation:{edge['transformation_id']}"
        graph.add_node(edge_id, kind="transformation", record=edge)
        for node_id in sorted(
            id_set(edge.get("required_inputs")) | id_set(edge.get("read_enablers"))
        ):
            graph.add_edge(node_id, edge_id)
        for node_id in sorted(id_set(edge.get("produced_outputs"))):
            graph.add_edge(edge_id, node_id)
    return graph


def _cyclic_components(graph: nx.DiGraph[str]) -> list[set[str]]:
    return [
        set(component)
        for component in nx.strongly_connected_components(graph)
        if len(component) > 1 or any(graph.has_edge(node, node) for node in component)
    ]


def _result(detector: str, blocker_ids: list[str], source_refs: list[str]) -> JsonObject:
    return {
        "detector": detector,
        "blocking": bool(blocker_ids),
        "blocker_ids": sorted(set(blocker_ids)),
        "source_refs": sorted(set(source_refs)),
    }


def detect_false_positives(
    contract: JsonObject,
    network: JsonObject,
    verified: ClosureResult,
    productive_witness: JsonObject | None,
) -> list[JsonObject]:
    """Run every required false-positive detector with stable output ordering."""

    graph = bipartite_graph(network)
    nodes = node_index(network)
    cycles = _cyclic_components(graph)
    self_cycles: list[str] = []
    nonproductive: list[str] = []
    resource_sinks: list[str] = []
    authority_loops: list[str] = []
    targets = target_states(contract)
    for index, component in enumerate(cycles):
        records = [graph.nodes[node].get("record", {}) for node in component]
        actor_values = {record.get("actor_id") for record in records if record.get("actor_id")}
        correlation_values = {
            record.get("correlation_group") for record in records if record.get("correlation_group")
        }
        typed = {record.get("type") for record in records if record.get("type")}
        component_id = f"cycle:{index:03d}"
        has_evidence = bool(typed & {"evidence", "verifier_report"})
        has_candidate = bool(typed & {"claim", "capability_candidate", "skill_candidate"})
        if (
            has_evidence
            and has_candidate
            and (len(actor_values) <= 1 or len(correlation_values) <= 1)
        ):
            self_cycles.append(component_id)
        state_ids = component & set(nodes)
        descendants = set().union(*(nx.descendants(graph, item) for item in component))
        if not (targets & (state_ids | descendants)) and typed <= {
            "artifact",
            "claim",
            "evidence",
            "verifier_report",
            "task_reference",
            "residual",
            "capability_candidate",
            "skill_candidate",
        }:
            nonproductive.append(component_id)
        transformations = [
            record
            for record in records
            if isinstance(record, dict) and "transformation_id" in record
        ]
        if transformations and any(edge.get("consumed_coordinates") for edge in transformations):
            produced_types = {nodes[item].get("type") for item in state_ids if item in nodes}
            if not produced_types & {"target_state", "admitted_capability", "certified_catalyst"}:
                resource_sinks.append(component_id)
        if "authority_record" in typed and has_evidence:
            authority_loops.append(component_id)

    support_nodes = [
        nodes[node_id]
        for node_id in verified.available_states
        if node_id in nodes
        and nodes[node_id].get("type") in {"evidence", "verifier_report", "external_certificate"}
    ]
    duplicate_ids: list[str] = []
    for key in ("digest", "source_event", "lineage"):
        counts = Counter(node.get(key) for node in support_nodes if node.get(key) is not None)
        duplicate_ids.extend(f"{key}:{value}" for value, count in counts.items() if count > 1)

    stale_ids = sorted(
        node_id
        for node_id in verified.available_states
        if nodes.get(node_id, {}).get("lifecycle_status") in INVALID_LIFECYCLE
    )
    proxy_ids: list[str] = []
    if productive_witness:
        registry = contract.get("state_coordinate_registry", {})
        if isinstance(registry, dict):
            proxy_ids = sorted(
                coordinate
                for coordinate in id_set(productive_witness.get("target_positive_coordinates"))
                if isinstance(registry.get(coordinate), dict)
                and registry[coordinate].get("proxy_only") is True
            )
    results = [
        _result("self_certifying_cycle", self_cycles, self_cycles),
        _result("nonproductive_cycle", nonproductive, nonproductive),
        _result(
            "duplicate_mass", duplicate_ids, [str(node.get("node_id")) for node in support_nodes]
        ),
        _result("stale_closure", stale_ids, stale_ids),
        _result("proxy_only_closure", proxy_ids, proxy_ids),
        _result("resource_sink_cycle", resource_sinks, resource_sinks),
        _result("authority_loop", authority_loops, authority_loops),
    ]
    return sorted(results, key=lambda item: str(item["detector"]))


def has_blocking_detection(results: list[JsonObject]) -> bool:
    """Return whether a required detector produced a blocking result."""

    return any(
        item.get("detector") in BLOCKING_DETECTORS and item.get("blocking") is True
        for item in results
    )
