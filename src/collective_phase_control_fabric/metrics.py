# SPDX-License-Identifier: Apache-2.0
"""Gated verification-load and work-graph critical-path calculations."""

from __future__ import annotations

from fractions import Fraction

import networkx as nx

from collective_phase_control_fabric.types import JsonObject
from collective_phase_control_fabric.witnesses import exact_number


def verification_load(contract: JsonObject) -> JsonObject:
    """Compute rho only when rates, units, window, and source references are known."""

    policy = contract.get("external_measurement_policy", {})
    if not isinstance(policy, dict):
        return {"status": "unknown", "rho": None, "blockers": ["measurement_policy_malformed"]}
    report = policy.get("verification_load")
    required = (
        "eligible_candidate_arrival_rate",
        "verifier_service_rate",
        "time_unit",
        "observation_window",
        "source_refs",
    )
    if not isinstance(report, dict) or any(not report.get(field) for field in required):
        return {"status": "unknown", "rho": None, "blockers": ["verification_load_inputs_missing"]}
    try:
        arrival = exact_number(report["eligible_candidate_arrival_rate"])
        service = exact_number(report["verifier_service_rate"])
    except ValueError:
        return {"status": "unknown", "rho": None, "blockers": ["verification_load_rate_invalid"]}
    if service <= 0:
        return {"status": "unknown", "rho": None, "blockers": ["verifier_service_rate_nonpositive"]}
    rho: Fraction = arrival / service
    overloaded = rho >= 1
    return {
        "status": "verification_overload" if overloaded else "within_declared_capacity",
        "rho": f"{rho.numerator}/{rho.denominator}",
        "blockers": ["verification_overload"] if overloaded else [],
        "candidate_fan_out_recommended": False if overloaded else None,
        "source_refs": report["source_refs"],
    }


def critical_path(contract: JsonObject) -> JsonObject:
    """Calculate a duration-gated DAG critical path and task-structure coordination guard."""

    task_structure = contract.get("task_structure", "unknown")
    work_graph = contract.get("work_graph", {})
    if not isinstance(work_graph, dict):
        return {"status": "unknown", "coordination_recommendation": None}
    tasks = work_graph.get("tasks", [])
    dependencies = work_graph.get("dependencies", [])
    if not isinstance(tasks, list) or not isinstance(dependencies, list):
        return {"status": "unknown", "coordination_recommendation": None}
    if not tasks or any(not isinstance(task, dict) or "duration" not in task for task in tasks):
        recommendation = None
        if task_structure == "sequential":
            recommendation = "one solver path plus one independent verifier"
        return {
            "status": "unknown",
            "reason": "duration_or_resource_bound_missing",
            "coordination_recommendation": recommendation,
            "parallel_fan_out_allowed": False if task_structure == "sequential" else None,
        }
    graph: nx.DiGraph[str] = nx.DiGraph()
    try:
        for task in tasks:
            graph.add_node(str(task["task_id"]), duration=exact_number(task["duration"]))
        for dependency in dependencies:
            if isinstance(dependency, dict):
                graph.add_edge(str(dependency["before"]), str(dependency["after"]))
    except (KeyError, ValueError):
        return {"status": "unknown", "reason": "work_graph_value_invalid"}
    if not nx.is_directed_acyclic_graph(graph):
        return {"status": "unknown", "reason": "work_graph_not_acyclic"}
    best: dict[str, Fraction] = {}
    predecessor: dict[str, str | None] = {}
    for node in nx.topological_sort(graph):
        candidates = [(best[parent], parent) for parent in graph.predecessors(node)]
        previous, parent = max(
            candidates, default=(Fraction(0), None), key=lambda item: (item[0], str(item[1]))
        )
        best[node] = previous + graph.nodes[node]["duration"]
        predecessor[node] = parent
    end = max(best, key=lambda item: (best[item], item))
    path: list[str] = []
    cursor: str | None = end
    while cursor is not None:
        path.append(cursor)
        cursor = predecessor[cursor]
    path.reverse()
    if task_structure == "sequential":
        recommendation = "one solver path plus one independent verifier"
        fan_out: bool | None = False
    elif task_structure == "parallel_decomposable":
        recommendation = "parallelize only dependency-independent ready work"
        fan_out = True
    elif task_structure in {"dynamic_exploration", "mixed"}:
        recommendation = (
            "separate compartments with delayed synthesis and bounded diffusion"
            if task_structure == "dynamic_exploration"
            else "use subtask-specific coordination profiles"
        )
        fan_out = None
    else:
        recommendation = None
        fan_out = None
    duration = best[end]
    return {
        "status": "computed",
        "critical_path": path,
        "duration": f"{duration.numerator}/{duration.denominator}",
        "coordination_recommendation": recommendation,
        "parallel_fan_out_allowed": fan_out,
    }
