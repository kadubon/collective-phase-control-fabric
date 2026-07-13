# SPDX-License-Identifier: Apache-2.0
"""Bounded exact and approximate formation-seed search."""

from __future__ import annotations

from collections import defaultdict

from collective_phase_control_fabric.network import ClosureResult, transformation_index
from collective_phase_control_fabric.types import JsonObject, id_set, tri


def _eligible(edge: JsonObject) -> bool:
    return (
        edge.get("effect_class") != "external_effect"
        and tri(edge.get("source_version_supported")) == "true"
        and tri(edge.get("lifecycle_status")) == "true"
        and (
            not id_set(edge.get("required_authority_refs"))
            or tri(edge.get("authority_status")) == "true"
        )
    )


def _minimal(sets: list[frozenset[str]]) -> list[frozenset[str]]:
    unique = sorted(set(sets), key=lambda value: (len(value), tuple(sorted(value))))
    output: list[frozenset[str]] = []
    for value in unique:
        if not any(existing <= value for existing in output):
            output.append(value)
    return output


def formation_seeds(
    contract: JsonObject,
    network: JsonObject,
    closure: ClosureResult,
) -> list[JsonObject]:
    """Compute at most three deterministic seeds without general hyperpath enumeration."""

    available = set(closure.available_states)
    transformations = transformation_index(network)
    producers: dict[str, list[JsonObject]] = defaultdict(list)
    for edge in transformations.values():
        if _eligible(edge):
            for output in id_set(edge.get("produced_outputs")):
                producers[output].append(edge)
    unresolved: set[str] = set()
    visiting: set[str] = set()

    def collect(state: str) -> None:
        if state in available or state in visiting:
            return
        visiting.add(state)
        unresolved.add(state)
        for edge in producers.get(state, []):
            for required in id_set(edge.get("required_inputs")) | id_set(edge.get("read_enablers")):
                collect(required)
        visiting.remove(state)

    for target in id_set(contract.get("target_states")):
        collect(target)
    if not unresolved:
        return []
    exact = len(unresolved) <= 16
    memo: dict[str, list[frozenset[str]]] = {}

    def solve(state: str, stack: frozenset[str], depth: int = 0) -> list[frozenset[str]]:
        if state in available:
            return [frozenset()]
        if not exact and depth >= 24:
            return [frozenset({state})]
        if state in stack:
            return [frozenset({state})]
        if state in memo:
            return memo[state]
        edges = sorted(producers.get(state, []), key=lambda edge: str(edge["transformation_id"]))
        if not edges:
            return [frozenset({state})]
        choices: list[frozenset[str]] = []
        for edge in edges:
            combinations: list[frozenset[str]] = [frozenset()]
            required = sorted(
                id_set(edge.get("required_inputs")) | id_set(edge.get("read_enablers"))
            )
            for item in required:
                next_sets = solve(item, stack | {state}, depth + 1)
                combinations = [left | right for left in combinations for right in next_sets]
                combinations = _minimal(combinations)
                if not exact:
                    combinations = combinations[:32]
            choices.extend(combinations)
            if not exact:
                choices = _minimal(choices)[:32]
        memo[state] = _minimal(choices)
        return memo[state]

    combined: list[frozenset[str]] = [frozenset()]
    for target in sorted(id_set(contract.get("target_states"))):
        choices = solve(target, frozenset())
        combined = _minimal([left | right for left in combined for right in choices])
        combined = combined[: (3 if exact else 32)]
    selected = _minimal(combined)[:3]
    return [
        {
            "seed_id": f"formation_seed:{index + 1:02d}",
            "unmet_states": sorted(seed),
            "transformation_ids": [],
            "solution_class": "exact" if exact else "approximate",
            "search_limits": {
                "unresolved_atom_count": len(unresolved),
                "maximum_results": 3,
                "beam_width": None if exact else 32,
                "maximum_depth": None if exact else 24,
            },
        }
        for index, seed in enumerate(selected)
    ]
