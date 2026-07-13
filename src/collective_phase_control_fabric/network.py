# SPDX-License-Identifier: Apache-2.0
"""Finite monotone AND/OR directed-hypergraph closure algorithms."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

from collective_phase_control_fabric.types import VALID_LIFECYCLE, JsonObject, id_set, tri


@dataclass(frozen=True)
class ClosureResult:
    """A deterministic fixed-point result."""

    available_states: tuple[str, ...]
    applied_transformations: tuple[str, ...]
    blocked: tuple[JsonObject, ...]


def node_index(network: JsonObject) -> dict[str, JsonObject]:
    """Index well-formed node objects by stable identifier."""

    nodes = network.get("nodes", [])
    if not isinstance(nodes, list):
        return {}
    result: dict[str, JsonObject] = {}
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("node_id"), str):
            continue
        identifier = str(node["node_id"])
        if identifier in result:
            raise ValueError(f"duplicate node identifier: {identifier}")
        result[identifier] = node
    return result


def transformation_index(network: JsonObject) -> dict[str, JsonObject]:
    """Index well-formed transformation objects by stable identifier."""

    transformations = network.get("transformations", [])
    if not isinstance(transformations, list):
        return {}
    result: dict[str, JsonObject] = {}
    for edge in transformations:
        if not isinstance(edge, dict) or not isinstance(edge.get("transformation_id"), str):
            continue
        identifier = str(edge["transformation_id"])
        if identifier in result:
            raise ValueError(f"duplicate transformation identifier: {identifier}")
        result[identifier] = edge
    return result


def initial_states(contract: JsonObject, network: JsonObject) -> set[str]:
    """Return declared initial states that are not lifecycle-invalid."""

    nodes = node_index(network)
    declared = id_set(contract.get("initial_available_states"))
    explicitly_available = {
        node_id
        for node_id, node in nodes.items()
        if node.get("available") is True and node.get("lifecycle_status") in VALID_LIFECYCLE
    }
    return {
        node_id
        for node_id in (declared | explicitly_available) & set(nodes)
        if nodes[node_id].get("lifecycle_status") in VALID_LIFECYCLE
    }


def _base_edge_blockers(
    edge: JsonObject, available: set[str], nodes: dict[str, JsonObject]
) -> list[str]:
    blockers: list[str] = []
    if edge.get("schema_version") == "0.2.0" and edge.get("_source_backed_runtime") is not True:
        blockers.append("source_projection_receipt_missing_or_invalid")
    if edge.get("schema_valid") is not True:
        blockers.append("schema_invalid_or_unknown")
    if edge.get("effect_class") == "external_effect":
        blockers.append("external_effect_rejected")
    if edge.get("effect_class") not in {"inspect", "validate", "plan", "local_write"}:
        blockers.append("unknown_effect_class")
    if tri(edge.get("authority_status")) != "true" and id_set(edge.get("required_authority_refs")):
        blockers.append("authority_invalid_or_unknown")
    if tri(edge.get("hazard_status")) != "true":
        blockers.append("hazard_invalid_or_unknown")
    if tri(edge.get("lifecycle_status")) != "true":
        blockers.append("lifecycle_invalid_or_unknown")
    if tri(edge.get("source_version_supported")) != "true":
        blockers.append("source_version_unsupported_or_unknown")
    if tri(edge.get("output_contract_status")) != "true":
        blockers.append("output_contract_unknown")
    inhibitors = id_set(edge.get("inhibitors"))
    if inhibitors & available:
        blockers.append("active_inhibitor")
    required = id_set(edge.get("required_inputs")) | id_set(edge.get("read_enablers"))
    if not required <= available:
        blockers.append("missing_input_closure")
    outputs = id_set(edge.get("produced_outputs"))
    if not outputs <= set(nodes):
        blockers.append("output_state_missing")
    elif any(nodes[output].get("lifecycle_status") not in VALID_LIFECYCLE for output in outputs):
        blockers.append("output_lifecycle_invalid_or_unknown")
    return blockers


def feasible_closure(contract: JsonObject, network: JsonObject) -> ClosureResult:
    """Compute queue-based monotone closure without converting unknown to true."""

    available = initial_states(contract, network)
    nodes = node_index(network)
    transformations = transformation_index(network)
    pending = deque(sorted(transformations))
    applied: set[str] = set()
    while pending:
        transformation_id = pending.popleft()
        if transformation_id in applied:
            continue
        edge = transformations[transformation_id]
        if _base_edge_blockers(edge, available, nodes):
            continue
        outputs = id_set(edge.get("produced_outputs"))
        if outputs - available:
            available.update(outputs)
            applied.add(transformation_id)
            pending.extend(sorted(set(transformations) - applied))
        else:
            applied.add(transformation_id)
    blocked = tuple(
        {
            "transformation_id": transformation_id,
            "blockers": _base_edge_blockers(edge, available, nodes),
        }
        for transformation_id, edge in sorted(transformations.items())
        if transformation_id not in applied
    )
    return ClosureResult(tuple(sorted(available)), tuple(sorted(applied)), blocked)


def _verified_edge_blockers(
    edge: JsonObject,
    available: set[str],
    nodes: dict[str, JsonObject],
) -> list[str]:
    blockers = _base_edge_blockers(edge, available, nodes)
    evidence = id_set(edge.get("required_evidence"))
    roles = id_set(edge.get("required_verifier_roles"))
    if not evidence:
        blockers.append("evidence_missing")
    available_evidence = {
        node_id
        for node_id in available
        if nodes.get(node_id, {}).get("type")
        in {"evidence", "verifier_report", "external_certificate"}
    }
    if evidence and not evidence <= available_evidence:
        blockers.append("evidence_missing")
    available_roles = {
        str(nodes[node_id].get("verifier_role"))
        for node_id in available
        if node_id in nodes and nodes[node_id].get("type") == "verifier_report"
    }
    if roles and not roles <= available_roles:
        blockers.append("verifier_missing")
    if edge.get("blocking_residual_hidden") is True:
        blockers.append("blocking_residual_hidden")
    if edge.get("self_issued_evidence_only") is True:
        blockers.append("self_issued_evidence_only")
    if edge.get("protected_floor_violation") is True:
        blockers.append("protected_floor_violation")
    support_nodes = [nodes[item] for item in evidence if item in nodes]
    for key in ("digest", "source_event", "lineage"):
        values = [node.get(key) for node in support_nodes if node.get(key) is not None]
        if len(values) != len(set(values)):
            blockers.append(f"duplicate_{key}_support")
    if any(node.get("lifecycle_status") not in VALID_LIFECYCLE for node in support_nodes):
        blockers.append("stale_dependency")
    return sorted(set(blockers))


def verified_closure(
    contract: JsonObject,
    network: JsonObject,
    feasible: ClosureResult | None = None,
) -> ClosureResult:
    """Rebuild closure using only source-backed, verifier-backed transformations."""

    feasible_result = feasible or feasible_closure(contract, network)
    feasible_edges = set(feasible_result.applied_transformations)
    nodes = node_index(network)
    available = initial_states(contract, network)
    transformations = transformation_index(network)
    pending = deque(sorted(feasible_edges))
    applied: set[str] = set()
    while pending:
        transformation_id = pending.popleft()
        edge = transformations[transformation_id]
        if _verified_edge_blockers(edge, available, nodes):
            continue
        outputs = id_set(edge.get("produced_outputs"))
        changed = bool(outputs - available)
        available.update(outputs)
        applied.add(transformation_id)
        if changed:
            pending.extend(sorted(feasible_edges - applied))
    blocked = tuple(
        {
            "transformation_id": transformation_id,
            "blockers": _verified_edge_blockers(
                transformations[transformation_id], available, nodes
            ),
        }
        for transformation_id in sorted(feasible_edges - applied)
    )
    return ClosureResult(tuple(sorted(available)), tuple(sorted(applied)), blocked)


def target_states(contract: JsonObject) -> set[str]:
    """Return only explicitly declared targets."""

    return id_set(contract.get("target_states"))


def reached_targets(contract: JsonObject, closure: ClosureResult) -> list[str]:
    """Return declared targets in a closure."""

    return sorted(target_states(contract) & set(closure.available_states))


def all_edge_blockers(result: ClosureResult) -> Iterable[str]:
    """Yield blocker identifiers from a closure report."""

    for item in result.blocked:
        blockers = item.get("blockers", [])
        if isinstance(blockers, list):
            yield from (str(blocker) for blocker in blockers)
