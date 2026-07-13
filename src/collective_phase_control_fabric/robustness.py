# SPDX-License-Identifier: Apache-2.0
"""Exact single-failure sensitivity and bounded hypergraph cut analysis."""

from __future__ import annotations

from copy import deepcopy
from itertools import combinations

from collective_phase_control_fabric.network import (
    ClosureResult,
    reached_targets,
    verified_closure,
)
from collective_phase_control_fabric.types import JsonObject, id_set


def _remove(network: JsonObject, candidate_ids: set[str]) -> JsonObject:
    copy = deepcopy(network)
    copy["nodes"] = [
        node
        for node in copy.get("nodes", [])
        if isinstance(node, dict) and str(node.get("node_id")) not in candidate_ids
    ]
    copy["transformations"] = [
        edge
        for edge in copy.get("transformations", [])
        if isinstance(edge, dict) and str(edge.get("transformation_id")) not in candidate_ids
    ]
    return copy


def _target_loss(
    contract: JsonObject,
    network: JsonObject,
    baseline_targets: set[str],
    candidate_ids: set[str],
) -> set[str]:
    after = verified_closure(contract, _remove(network, candidate_ids))
    return baseline_targets - set(reached_targets(contract, after))


def _concentration(values: list[str]) -> JsonObject:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    total = len(values)
    maximum = max(counts.values(), default=0)
    return {
        "counts": dict(sorted(counts.items())),
        "maximum_share": str(maximum) + "/" + str(total) if total else "unknown",
    }


def structural_robustness(
    contract: JsonObject,
    network: JsonObject,
    verified: ClosureResult,
) -> JsonObject:
    """Recompute the actual hypergraph after removals; no simple-graph exactness claim."""

    baseline_targets = set(reached_targets(contract, verified))
    nodes = [node for node in network.get("nodes", []) if isinstance(node, dict)]
    edges = [edge for edge in network.get("transformations", []) if isinstance(edge, dict)]
    node_ids = sorted(str(node["node_id"]) for node in nodes)
    edge_ids = sorted(str(edge["transformation_id"]) for edge in edges)
    node_sensitivity: list[JsonObject] = [
        {
            "node_id": node_id,
            "lost_targets": sorted(_target_loss(contract, network, baseline_targets, {node_id})),
        }
        for node_id in node_ids
    ]
    transformation_sensitivity: list[JsonObject] = [
        {
            "transformation_id": edge_id,
            "lost_targets": sorted(_target_loss(contract, network, baseline_targets, {edge_id})),
        }
        for edge_id in edge_ids
    ]
    catalyst_ids = {
        str(node["node_id"]) for node in nodes if node.get("type") == "certified_catalyst"
    }
    verifier_ids = {str(node["node_id"]) for node in nodes if node.get("type") == "verifier_report"}
    catalyst_spf = sorted(
        item["node_id"]
        for item in node_sensitivity
        if item["node_id"] in catalyst_ids and item["lost_targets"]
    )
    verifier_spf = sorted(
        item["node_id"]
        for item in node_sensitivity
        if item["node_id"] in verifier_ids and item["lost_targets"]
    )
    expiry_sensitive = sorted(
        item["node_id"]
        for item in node_sensitivity
        if item["lost_targets"]
        and any(node.get("node_id") == item["node_id"] and node.get("expiry") for node in nodes)
    )
    node_by_id = {str(node.get("node_id")): node for node in nodes}
    edge_by_id = {str(edge.get("transformation_id")): edge for edge in edges}
    declared_paths: list[set[str]] = []
    for path in contract.get("target_paths", []):
        if not isinstance(path, dict):
            continue
        transformation_ids = {
            str(item) for item in path.get("transformation_ids", []) if isinstance(item, str)
        }
        if transformation_ids and transformation_ids <= set(verified.applied_transformations):
            independence_tokens = {f"transformation:{item}" for item in transformation_ids}
            for transformation_id in transformation_ids:
                edge = edge_by_id[transformation_id]
                if isinstance(edge.get("source_system"), str):
                    independence_tokens.add(f"source:{edge['source_system']}")
                support_refs = (
                    id_set(edge.get("required_evidence"))
                    | id_set(edge.get("support_refs"))
                    | id_set(edge.get("verifier_refs"))
                )
                for reference in support_refs:
                    node = node_by_id.get(str(reference), {})
                    for field in (
                        "digest",
                        "source_event",
                        "lineage",
                        "correlation_group",
                        "source_system",
                    ):
                        if node.get(field) is not None:
                            independence_tokens.add(f"{field}:{node[field]}")
            declared_paths.append(independence_tokens)
    independent_path_count = 0
    for size in range(1, len(declared_paths) + 1):
        if any(
            all(
                left.isdisjoint(right)
                for index, left in enumerate(selected)
                for right in selected[index + 1 :]
            )
            for selected in combinations(declared_paths, size)
        ):
            independent_path_count = size
    policy = contract.get("robustness_policy", {})
    declared_candidates = policy.get("failure_candidates") if isinstance(policy, dict) else None
    candidates = sorted(
        {str(item) for item in declared_candidates if isinstance(item, str)}
        if isinstance(declared_candidates, list)
        else set(node_ids) | set(edge_ids)
    )
    cuts: list[JsonObject] = []
    if len(candidates) <= 12:
        minimal: list[set[str]] = []
        for size in range(1, len(candidates) + 1):
            for subset_tuple in combinations(candidates, size):
                subset = set(subset_tuple)
                if any(existing <= subset for existing in minimal):
                    continue
                loss = _target_loss(contract, network, baseline_targets, subset)
                if loss:
                    minimal.append(subset)
                    cuts.append(
                        {
                            "candidate_ids": sorted(subset),
                            "lost_targets": sorted(loss),
                            "solution_class": "exact",
                        }
                    )
                    if len(cuts) >= 16:
                        break
            if len(cuts) >= 16:
                break
        cut_class = "exact"
    else:
        ranked = [item for item in node_sensitivity if item["lost_targets"]] + [
            item for item in transformation_sensitivity if item["lost_targets"]
        ]
        for item in ranked[:16]:
            identifier = str(item.get("node_id", item.get("transformation_id")))
            cuts.append(
                {
                    "candidate_ids": [identifier],
                    "lost_targets": item["lost_targets"],
                    "solution_class": "heuristic_not_proof",
                }
            )
        cut_class = "heuristic_not_proof"
    source_values = [
        str(record["source_system"])
        for record in [*nodes, *edges]
        if isinstance(record.get("source_system"), str)
    ]
    correlation_values = [
        str(node["correlation_group"])
        for node in nodes
        if isinstance(node.get("correlation_group"), str)
    ]
    return {
        "single_node_removal_sensitivity": node_sensitivity,
        "single_transformation_removal_sensitivity": transformation_sensitivity,
        "catalyst_single_point_failure_ids": catalyst_spf,
        "verifier_single_point_failure_ids": verifier_spf,
        "evidence_expiry_sensitivity_ids": expiry_sensitive,
        "source_system_concentration": _concentration(source_values),
        "correlation_group_concentration": _concentration(correlation_values),
        "independent_target_path_count": independent_path_count,
        "target_path_independence_basis": (
            "transformation, evidence digest/event/lineage/correlation, verifier, "
            "and source disjointness"
        ),
        "minimal_cuts": cuts,
        "minimal_cut_solution_class": cut_class,
        "exactness_note": "Exact results replay the directed hypergraph closure after removal.",
    }
