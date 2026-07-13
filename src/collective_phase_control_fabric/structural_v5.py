# SPDX-License-Identifier: Apache-2.0
"""Bounded exact structural diagnostics for CPCF v0.5."""

from __future__ import annotations

from collections import deque
from fractions import Fraction
from itertools import combinations

from collective_phase_control_fabric.types import JsonObject, id_set


def exact_nullspace(matrix: list[list[Fraction]]) -> list[list[Fraction]]:
    """Return an exact rational basis for the right nullspace of a finite matrix."""

    if not matrix:
        return []
    columns = len(matrix[0])
    if any(len(row) != columns for row in matrix):
        raise ValueError("matrix rows have inconsistent lengths")
    reduced = [list(row) for row in matrix]
    pivot_columns: list[int] = []
    pivot_row = 0
    for column in range(columns):
        selected = next(
            (row for row in range(pivot_row, len(reduced)) if reduced[row][column] != 0),
            None,
        )
        if selected is None:
            continue
        reduced[pivot_row], reduced[selected] = reduced[selected], reduced[pivot_row]
        divisor = reduced[pivot_row][column]
        reduced[pivot_row] = [item / divisor for item in reduced[pivot_row]]
        for row in range(len(reduced)):
            if row == pivot_row or reduced[row][column] == 0:
                continue
            multiplier = reduced[row][column]
            reduced[row] = [
                left - multiplier * right
                for left, right in zip(reduced[row], reduced[pivot_row], strict=True)
            ]
        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == len(reduced):
            break
    free_columns = [column for column in range(columns) if column not in pivot_columns]
    basis: list[list[Fraction]] = []
    for free in free_columns:
        vector = [Fraction(0) for _ in range(columns)]
        vector[free] = Fraction(1)
        for row, pivot in enumerate(pivot_columns):
            vector[pivot] = -reduced[row][free]
        basis.append(vector)
    return basis


def exact_flux_coupling(
    transformations: dict[str, JsonObject], coordinates: list[str]
) -> JsonObject:
    """Compute sound exact coupling classes in the homogeneous balance subspace."""

    identifiers = sorted(transformations)
    matrix = [
        [
            Fraction(str(transformations[item].get("coordinate_flows", {}).get(coordinate, "0")))
            for item in identifiers
        ]
        for coordinate in coordinates
    ]
    basis = exact_nullspace(matrix)
    signatures = {
        identifier: tuple(vector[index] for vector in basis)
        for index, identifier in enumerate(identifiers)
    }
    blocked = sorted(
        identifier for identifier, signature in signatures.items() if not any(signature)
    )
    remaining = [item for item in identifiers if item not in blocked]
    groups: list[list[str]] = []
    ratios: dict[str, str] = {}
    while remaining:
        anchor = remaining.pop(0)
        anchor_signature = signatures[anchor]
        group = [anchor]
        for candidate in list(remaining):
            candidate_signature = signatures[candidate]
            ratio: Fraction | None = None
            proportional = True
            for left, right in zip(anchor_signature, candidate_signature, strict=True):
                if left == 0 and right == 0:
                    continue
                if left == 0 or right == 0:
                    proportional = False
                    break
                current = right / left
                ratio = current if ratio is None else ratio
                if current != ratio:
                    proportional = False
                    break
            if proportional and ratio is not None:
                group.append(candidate)
                remaining.remove(candidate)
                ratios[f"{anchor}|{candidate}"] = str(ratio)
        groups.append(group)
    return {
        "blocked_transformations": blocked,
        "fully_coupled_classes": [item for item in groups if len(item) > 1],
        "coupling_ratios": ratios,
        "nullspace_dimension": len(basis),
        "arithmetic": "exact_rational",
        "solution_class": "sound_complete_for_homogeneous_linear_equalities",
        "thermodynamic_feasibility_inferred": False,
    }


def _closure(
    initial: set[str], transformations: dict[str, JsonObject], removed: set[str]
) -> set[str]:
    available = set(initial)
    while True:
        additions: set[str] = set()
        for identifier in sorted(set(transformations) - removed):
            edge = transformations[identifier]
            if id_set(edge.get("inputs")) <= available:
                additions |= id_set(edge.get("outputs"))
        if additions <= available:
            return available
        available |= additions


def bounded_minimal_cut_sets(
    initial: set[str],
    transformations: dict[str, JsonObject],
    targets: set[str],
    *,
    maximum_cut_size: int,
    operation_budget: int,
) -> JsonObject:
    """Enumerate inclusion-minimal transformation cuts within explicit bounds."""

    cuts: list[tuple[str, ...]] = []
    operations = 0
    identifiers = sorted(transformations)
    exhausted = False
    for size in range(1, min(maximum_cut_size, len(identifiers)) + 1):
        for candidate in combinations(identifiers, size):
            operations += 1
            if operations > operation_budget:
                exhausted = True
                break
            candidate_set = set(candidate)
            if any(set(existing) <= candidate_set for existing in cuts):
                continue
            if not targets <= _closure(initial, transformations, candidate_set):
                cuts.append(candidate)
        if exhausted:
            break
    return {
        "minimal_cut_sets": [list(item) for item in cuts],
        "complete_within_cut_size": not exhausted,
        "maximum_cut_size": maximum_cut_size,
        "operation_count": min(operations, operation_budget),
        "status": "unknown_due_to_budget" if exhausted else "satisfied",
        "general_controllability_inferred": False,
    }


def bounded_one_safe_occurrence_prefix(
    initial: set[str],
    transformations: dict[str, JsonObject],
    *,
    operation_budget: int,
) -> JsonObject:
    """Build a finite 1-safe occurrence prefix with conflict, causality, and cutoffs."""

    initial_conditions = {place: f"condition:initial:{place}" for place in sorted(initial)}
    queue: deque[tuple[dict[str, str], int]] = deque([(initial_conditions, 0)])
    seen_markings: dict[tuple[str, ...], int] = {tuple(sorted(initial)): 0}
    conditions: dict[str, JsonObject] = {
        identifier: {"condition_id": identifier, "place": place, "producer_event": None}
        for place, identifier in initial_conditions.items()
    }
    events: dict[str, JsonObject] = {}
    consumers: dict[str, set[str]] = {}
    operations = 0
    exhausted = False
    while queue:
        marking, depth = queue.popleft()
        places = set(marking)
        for transformation_id in sorted(transformations):
            operations += 1
            if operations > operation_budget:
                exhausted = True
                queue.clear()
                break
            edge = transformations[transformation_id]
            inputs = id_set(edge.get("inputs"))
            outputs = id_set(edge.get("outputs"))
            if not inputs <= places or (outputs - inputs) & places:
                continue
            consumed = tuple(sorted(marking[item] for item in inputs))
            event_id = "event:" + transformation_id + ":" + digest_tuple(consumed)
            if event_id in events:
                continue
            produced: dict[str, str] = {
                place: f"condition:{event_id}:{place}" for place in sorted(outputs)
            }
            next_marking = {
                place: condition for place, condition in marking.items() if place not in inputs
            }
            next_marking.update(produced)
            marking_key = tuple(sorted(next_marking))
            cutoff = marking_key in seen_markings and seen_markings[marking_key] <= depth + 1
            events[event_id] = {
                "event_id": event_id,
                "transformation_id": transformation_id,
                "consumed_conditions": list(consumed),
                "produced_conditions": sorted(produced.values()),
                "depth": depth + 1,
                "cutoff": cutoff,
            }
            for condition_id in consumed:
                consumers.setdefault(condition_id, set()).add(event_id)
            for place, condition_id in produced.items():
                conditions[condition_id] = {
                    "condition_id": condition_id,
                    "place": place,
                    "producer_event": event_id,
                }
            if not cutoff:
                seen_markings[marking_key] = depth + 1
                queue.append((next_marking, depth + 1))
    conflicts = sorted(
        [left, right]
        for event_set in consumers.values()
        for left, right in combinations(sorted(event_set), 2)
    )
    return {
        "conditions": [conditions[item] for item in sorted(conditions)],
        "events": [events[item] for item in sorted(events)],
        "conflicts": conflicts,
        "cutoff_event_ids": sorted(item for item, event in events.items() if event["cutoff"]),
        "operation_count": min(operations, operation_budget),
        "status": "unknown_due_to_budget" if exhausted else "satisfied",
        "profile": "declared_1_safe",
    }


def digest_tuple(value: tuple[str, ...]) -> str:
    """Return a short deterministic identifier fragment for local occurrence nodes."""

    import hashlib

    return hashlib.sha256("\x00".join(value).encode("utf-8")).hexdigest()[:24]
