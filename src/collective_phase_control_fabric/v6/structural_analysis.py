# SPDX-License-Identifier: Apache-2.0
"""Bounded exact structural analyses used by the v0.6 audit and intervention layers."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from itertools import combinations, pairwise
from typing import Protocol, TypedDict

from collective_phase_control_fabric.v6.models import TransformationAttestation


class BudgetLike(Protocol):
    def spend(self, amount: int = 1) -> None: ...


@dataclass(frozen=True)
class EnumerationResult:
    values: tuple[tuple[str, ...], ...]
    exhaustive: bool


@dataclass(frozen=True)
class CurveBounds:
    backlog: Fraction
    delay: Fraction | None
    exhaustive: bool


@dataclass(frozen=True)
class FluxCouplingAnalysis:
    status: str
    blocked: tuple[str, ...]
    fully_coupled_classes: tuple[tuple[str, ...], ...]
    exact_models_rechecked: bool
    solver_name: str
    solver_version: str


@dataclass(frozen=True)
class PrefixCondition:
    condition_id: str
    state_id: str
    producer_event_id: str | None


@dataclass(frozen=True)
class PrefixEvent:
    event_id: str
    transformation_id: str
    preset_condition_ids: tuple[str, ...]
    postset_condition_ids: tuple[str, ...]
    causal_predecessor_ids: tuple[str, ...]
    conflict_event_ids: tuple[str, ...]


class _RawEvent(TypedDict):
    event_id: str
    transformation_id: str
    preset_condition_ids: tuple[str, ...]
    postset_condition_ids: tuple[str, ...]
    causal_predecessor_ids: tuple[str, ...]
    conflict_event_ids: list[str]


@dataclass(frozen=True)
class OccurrencePrefix:
    conditions: tuple[PrefixCondition, ...]
    events: tuple[PrefixEvent, ...]
    cutoff_event_ids: tuple[str, ...]
    exhaustive: bool


def _flows(
    transformation: TransformationAttestation,
) -> tuple[set[str], set[str]]:
    inputs = {
        coordinate
        for coordinate, value in transformation.spec.inputs.items()
        if Fraction(value) > 0
    }
    outputs = {
        coordinate
        for coordinate, value in transformation.spec.outputs.items()
        if Fraction(value) > 0
    }
    return inputs, outputs


def enumerate_minimal_siphons(
    transformations: Mapping[str, TransformationAttestation],
    coordinates: Iterable[str],
    budget: BudgetLike,
    *,
    maximum_coordinates: int = 20,
) -> EnumerationResult:
    """Enumerate minimal siphons exactly inside an explicit coordinate bound.

    A nonempty set S is a siphon when every transformation producing a member of S also consumes a
    member of S. Exhaustion is explicit rather than being interpreted as absence.
    """

    ordered = tuple(sorted(set(coordinates)))
    if len(ordered) > maximum_coordinates:
        return EnumerationResult((), False)
    flow_pairs = [_flows(item) for item in transformations.values()]
    minimal: list[frozenset[str]] = []
    for size in range(1, len(ordered) + 1):
        for candidate_values in combinations(ordered, size):
            budget.spend()
            candidate = frozenset(candidate_values)
            if any(existing.issubset(candidate) for existing in minimal):
                continue
            is_siphon = all(
                not (outputs & candidate) or bool(inputs & candidate)
                for inputs, outputs in flow_pairs
            )
            if is_siphon:
                minimal.append(candidate)
    return EnumerationResult(tuple(tuple(sorted(item)) for item in minimal), True)


def unfed_siphons(
    siphons: Iterable[Iterable[str]],
    initial_markings: Mapping[str, Fraction],
    supplied_coordinates: Iterable[str],
) -> tuple[tuple[str, ...], ...]:
    supplied = set(supplied_coordinates)
    result = []
    for siphon_values in siphons:
        siphon = set(siphon_values)
        initially_marked = any(initial_markings.get(item, Fraction(0)) > 0 for item in siphon)
        if not initially_marked and not siphon.intersection(supplied):
            result.append(tuple(sorted(siphon)))
    return tuple(sorted(result))


def structural_closure(
    initial_states: Iterable[str],
    transformations: Mapping[str, TransformationAttestation],
    *,
    allowed_transformations: Iterable[str] | None = None,
    budget: BudgetLike,
) -> set[str]:
    available = set(initial_states)
    allowed = (
        set(transformations)
        if allowed_transformations is None
        else set(allowed_transformations).intersection(transformations)
    )
    changed = True
    while changed:
        changed = False
        for identifier in sorted(allowed):
            budget.spend()
            inputs, outputs = _flows(transformations[identifier])
            if inputs.issubset(available) and not outputs.issubset(available):
                available.update(outputs)
                changed = True
    return available


def enumerate_minimal_cut_sets(
    initial_states: Iterable[str],
    targets: Iterable[str],
    transformations: Mapping[str, TransformationAttestation],
    budget: BudgetLike,
    *,
    maximum_transformations: int = 20,
) -> EnumerationResult:
    ordered = tuple(sorted(transformations))
    target_set = set(targets)
    if len(ordered) > maximum_transformations:
        return EnumerationResult((), False)
    if not target_set.issubset(structural_closure(initial_states, transformations, budget=budget)):
        return EnumerationResult(((),), True)
    minimal: list[frozenset[str]] = []
    for size in range(1, len(ordered) + 1):
        for values in combinations(ordered, size):
            budget.spend()
            candidate = frozenset(values)
            if any(existing.issubset(candidate) for existing in minimal):
                continue
            allowed = set(ordered) - candidate
            reached = structural_closure(
                initial_states,
                transformations,
                allowed_transformations=allowed,
                budget=budget,
            )
            if not target_set.issubset(reached):
                minimal.append(candidate)
    return EnumerationResult(tuple(tuple(sorted(item)) for item in minimal), True)


def enumerate_minimal_enablement_sets(
    initial_states: Iterable[str],
    targets: Iterable[str],
    transformations: Mapping[str, TransformationAttestation],
    budget: BudgetLike,
    *,
    maximum_transformations: int = 20,
) -> EnumerationResult:
    ordered = tuple(sorted(transformations))
    target_set = set(targets)
    if len(ordered) > maximum_transformations:
        return EnumerationResult((), False)
    minimal: list[frozenset[str]] = []
    for size in range(len(ordered) + 1):
        for values in combinations(ordered, size):
            budget.spend()
            candidate = frozenset(values)
            if any(existing.issubset(candidate) for existing in minimal):
                continue
            reached = structural_closure(
                initial_states,
                transformations,
                allowed_transformations=candidate,
                budget=budget,
            )
            if target_set.issubset(reached):
                minimal.append(candidate)
    return EnumerationResult(tuple(tuple(sorted(item)) for item in minimal), True)


def _interpolate(points: Sequence[tuple[Fraction, Fraction]], at: Fraction) -> Fraction | None:
    if at < points[0][0] or at > points[-1][0]:
        return None
    for (left_t, left_v), (right_t, right_v) in pairwise(points):
        if left_t <= at <= right_t:
            if at == left_t or right_t == left_t:
                return left_v
            return left_v + (right_v - left_v) * (at - left_t) / (right_t - left_t)
    return points[-1][1]


def _inverse_crossing(
    points: Sequence[tuple[Fraction, Fraction]],
    value: Fraction,
    not_before: Fraction,
) -> Fraction | None:
    if value > points[-1][1]:
        return None
    for (left_t, _left_v), (right_t, right_v) in pairwise(points):
        if right_t < not_before or right_v < value:
            continue
        start_t = max(left_t, not_before)
        start_v = _interpolate(points, start_t)
        if start_v is None:
            continue
        if start_v >= value:
            return start_t
        if right_v == start_v:
            continue
        return start_t + (value - start_v) * (right_t - start_t) / (right_v - start_v)
    return None


def deterministic_curve_bounds(
    arrival_points: Sequence[tuple[Fraction, Fraction]],
    service_points: Sequence[tuple[Fraction, Fraction]],
    budget: BudgetLike,
) -> CurveBounds:
    """Compute exact vertical and horizontal deviations over piecewise-rational curves."""

    horizon = min(arrival_points[-1][0], service_points[-1][0])
    candidate_times = {
        time for time, _ in [*arrival_points, *service_points] if Fraction(0) <= time <= horizon
    }
    for _, service_value in service_points:
        crossing = _inverse_crossing(arrival_points, service_value, Fraction(0))
        if crossing is not None and crossing <= horizon:
            candidate_times.add(crossing)
    backlog = Fraction(0)
    delay = Fraction(0)
    exhaustive = True
    for at in sorted(candidate_times):
        budget.spend()
        arrival = _interpolate(arrival_points, at)
        service = _interpolate(service_points, at)
        if arrival is None or service is None:
            exhaustive = False
            continue
        backlog = max(backlog, arrival - service)
        crossing = _inverse_crossing(service_points, arrival, at)
        if crossing is None:
            exhaustive = False
        else:
            delay = max(delay, crossing - at)
    return CurveBounds(max(backlog, Fraction(0)), delay if exhaustive else None, exhaustive)


def _stoichiometric_matrix(
    transformations: Mapping[str, TransformationAttestation],
    identifiers: Sequence[str],
) -> tuple[tuple[str, ...], list[list[Fraction]]]:
    coordinates = tuple(
        sorted(
            {
                coordinate
                for identifier in identifiers
                for coordinate in (
                    set(transformations[identifier].spec.inputs)
                    | set(transformations[identifier].spec.outputs)
                )
            }
        )
    )
    matrix: list[list[Fraction]] = []
    for coordinate in coordinates:
        row = []
        for identifier in identifiers:
            item = transformations[identifier]
            row.append(
                Fraction(item.spec.outputs.get(coordinate, "0"))
                - Fraction(item.spec.inputs.get(coordinate, "0"))
            )
        matrix.append(row)
    return coordinates, matrix


def _nullspace(matrix: list[list[Fraction]], columns: int) -> list[list[Fraction]]:
    rows = [list(row) for row in matrix]
    pivot_columns: list[int] = []
    pivot_row = 0
    for column in range(columns):
        selected = next(
            (index for index in range(pivot_row, len(rows)) if rows[index][column] != 0),
            None,
        )
        if selected is None:
            continue
        rows[pivot_row], rows[selected] = rows[selected], rows[pivot_row]
        divisor = rows[pivot_row][column]
        rows[pivot_row] = [value / divisor for value in rows[pivot_row]]
        for index, row in enumerate(rows):
            if index == pivot_row or row[column] == 0:
                continue
            factor = row[column]
            rows[index] = [
                left - factor * right for left, right in zip(row, rows[pivot_row], strict=True)
            ]
        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == len(rows):
            break
    free_columns = [item for item in range(columns) if item not in pivot_columns]
    basis: list[list[Fraction]] = []
    for free in free_columns:
        vector = [Fraction(0) for _ in range(columns)]
        vector[free] = Fraction(1)
        for row_index, pivot in enumerate(pivot_columns):
            vector[pivot] = -rows[row_index][free]
        basis.append(vector)
    return basis


def _proportional(left: Sequence[Fraction], right: Sequence[Fraction]) -> bool:
    ratio: Fraction | None = None
    for left_value, right_value in zip(left, right, strict=True):
        if left_value == 0 and right_value == 0:
            continue
        if left_value == 0 or right_value == 0:
            return False
        current = left_value / right_value
        if current <= 0:
            return False
        if ratio is None:
            ratio = current
        elif current != ratio:
            return False
    return ratio is not None


def exact_flux_coupling(
    transformations: Mapping[str, TransformationAttestation],
    budget: BudgetLike,
) -> FluxCouplingAnalysis:
    """Find blocked and fully coupled steady-state fluxes with exact rational rechecks."""

    try:
        import z3  # type: ignore[import-untyped]
    except ImportError:
        return FluxCouplingAnalysis("unknown", (), (), False, "unavailable", "unavailable")
    identifiers = tuple(sorted(transformations))
    if not identifiers:
        return FluxCouplingAnalysis("satisfied", (), (), True, "z3", z3.get_version_string())
    _, matrix = _stoichiometric_matrix(transformations, identifiers)
    variables = [z3.Real(f"v_{index}") for index in range(len(identifiers))]

    def q(value: Fraction) -> object:
        return z3.Q(value.numerator, value.denominator)

    base = [variable >= 0 for variable in variables]
    base.append(z3.Sum(variables) == 1)
    for row in matrix:
        base.append(
            z3.Sum([q(value) * variable for value, variable in zip(row, variables, strict=True)])
            == 0
        )
    blocked: list[str] = []
    for index, identifier in enumerate(identifiers):
        budget.spend()
        solver = z3.Solver()
        solver.add(*base, variables[index] > 0)
        if solver.check() != z3.sat:
            blocked.append(identifier)
            continue
        model = solver.model()
        fluxes: list[Fraction] = []
        for variable in variables:
            value = model.eval(variable, model_completion=True)
            fluxes.append(Fraction(value.numerator_as_long(), value.denominator_as_long()))
        if any(value < 0 for value in fluxes) or sum(fluxes) != 1:
            raise ValueError("solver model failed exact nonnegative normalization recheck")
        for row in matrix:
            if sum(value * flux for value, flux in zip(row, fluxes, strict=True)) != 0:
                raise ValueError("solver model failed exact stoichiometric recheck")
        if fluxes[index] <= 0:
            raise ValueError("solver model failed exact positive-flux recheck")
    unblocked = [item for item in identifiers if item not in blocked]
    unblocked_indexes = [identifiers.index(item) for item in unblocked]
    reduced_matrix = [[row[index] for index in unblocked_indexes] for row in matrix]
    basis = _nullspace(reduced_matrix, len(unblocked))
    rows_by_flux = [
        [basis_vector[index] for basis_vector in basis] for index in range(len(unblocked))
    ]
    parent = list(range(len(unblocked)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for left, right in combinations(range(len(unblocked)), 2):
        budget.spend()
        if _proportional(rows_by_flux[left], rows_by_flux[right]):
            union(left, right)
    classes: dict[int, list[str]] = {}
    for index, identifier in enumerate(unblocked):
        classes.setdefault(find(index), []).append(identifier)
    coupled = tuple(sorted(tuple(values) for values in classes.values() if len(values) > 1))
    return FluxCouplingAnalysis(
        "satisfied",
        tuple(blocked),
        coupled,
        True,
        "z3",
        z3.get_version_string(),
    )


def bounded_occurrence_prefix(
    initial_states: Iterable[str],
    transformations: Mapping[str, TransformationAttestation],
    budget: BudgetLike,
    *,
    maximum_events: int = 4096,
) -> OccurrencePrefix:
    """Build a deterministic bounded 1-safe occurrence prefix.

    Non-unit stoichiometry is outside this profile and returns a non-exhaustive empty prefix.
    """

    for item in transformations.values():
        if any(
            Fraction(value) != 1
            for value in [*item.spec.inputs.values(), *item.spec.outputs.values()]
        ):
            return OccurrencePrefix((), (), (), False)
    conditions: dict[str, PrefixCondition] = {}
    initial_marking: dict[str, str] = {}
    for index, state in enumerate(sorted(set(initial_states))):
        condition_id = f"c-init-{index}"
        conditions[condition_id] = PrefixCondition(condition_id, state, None)
        initial_marking[state] = condition_id
    queue: deque[tuple[dict[str, str], frozenset[str]]] = deque([(initial_marking, frozenset())])
    seen_markings: dict[frozenset[str], int] = {frozenset(initial_marking): 0}
    raw_events: list[_RawEvent] = []
    cutoff: list[str] = []
    exhausted = True
    while queue:
        marking, history = queue.popleft()
        for transformation_id in sorted(transformations):
            budget.spend()
            item = transformations[transformation_id]
            inputs, outputs = _flows(item)
            if not inputs.issubset(marking) or set(item.spec.inhibitors).intersection(marking):
                continue
            if (
                not item.spec.uncatalyzed
                and item.spec.catalyst_clauses
                and not any(
                    set(clause.all_of).issubset(marking) for clause in item.spec.catalyst_clauses
                )
            ):
                continue
            remaining_states = set(marking) - inputs
            if outputs.intersection(remaining_states):
                continue
            if len(raw_events) >= maximum_events:
                exhausted = False
                queue.clear()
                break
            event_id = f"e-{len(raw_events)}"
            preset = tuple(marking[state] for state in sorted(inputs))
            dependency_conditions = set(preset)
            for clause in item.spec.catalyst_clauses:
                if set(clause.all_of).issubset(marking):
                    dependency_conditions.update(marking[state] for state in clause.all_of)
                    break
            direct_causal: set[str] = set()
            for condition_id in dependency_conditions:
                producer = conditions[condition_id].producer_event_id
                if producer is not None:
                    direct_causal.add(producer)
            causal = set(direct_causal)
            for predecessor in direct_causal:
                previous = next(item for item in raw_events if item["event_id"] == predecessor)
                causal.update(previous["causal_predecessor_ids"])
            postset: list[str] = []
            successor = {
                state: condition for state, condition in marking.items() if state not in inputs
            }
            for state in sorted(outputs):
                condition_id = f"c-{len(conditions)}"
                conditions[condition_id] = PrefixCondition(condition_id, state, event_id)
                successor[state] = condition_id
                postset.append(condition_id)
            conflicts = [
                str(previous["event_id"])
                for previous in raw_events
                if set(preset).intersection(previous["preset_condition_ids"])
                and str(previous["event_id"]) not in causal
            ]
            raw_events.append(
                {
                    "event_id": event_id,
                    "transformation_id": transformation_id,
                    "preset_condition_ids": preset,
                    "postset_condition_ids": tuple(postset),
                    "causal_predecessor_ids": tuple(sorted(causal)),
                    "conflict_event_ids": conflicts,
                }
            )
            abstract_marking = frozenset(successor)
            depth = len(history) + 1
            previous_depth = seen_markings.get(abstract_marking)
            if previous_depth is not None and previous_depth <= depth:
                cutoff.append(event_id)
            else:
                seen_markings[abstract_marking] = depth
                queue.append((successor, frozenset({*history, event_id})))
    conflict_map: dict[str, set[str]] = {
        str(item["event_id"]): set(item["conflict_event_ids"]) for item in raw_events
    }
    for event_id, related_events in list(conflict_map.items()):
        for other in related_events:
            conflict_map.setdefault(other, set()).add(event_id)
    events = tuple(
        PrefixEvent(
            event_id=str(item["event_id"]),
            transformation_id=str(item["transformation_id"]),
            preset_condition_ids=item["preset_condition_ids"],
            postset_condition_ids=item["postset_condition_ids"],
            causal_predecessor_ids=item["causal_predecessor_ids"],
            conflict_event_ids=tuple(sorted(conflict_map[str(item["event_id"])])),
        )
        for item in raw_events
    )
    return OccurrencePrefix(tuple(conditions.values()), events, tuple(cutoff), exhausted)
