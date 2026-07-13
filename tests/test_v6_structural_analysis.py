# SPDX-License-Identifier: Apache-2.0
"""Differential small-network tests for bounded exact v0.6 structural analyses."""

from __future__ import annotations

import builtins
from fractions import Fraction
from itertools import combinations

import pytest

from collective_phase_control_fabric.v6.models import (
    DOCUMENT_MODELS,
    CatalystClause,
    Lifecycle,
    TransformationAttestation,
    TransformationSpec,
)
from collective_phase_control_fabric.v6.science import Budget
from collective_phase_control_fabric.v6.structural_analysis import (
    _interpolate,
    _inverse_crossing,
    _nullspace,
    _proportional,
    _stoichiometric_matrix,
    bounded_occurrence_prefix,
    deterministic_curve_bounds,
    enumerate_minimal_cut_sets,
    enumerate_minimal_enablement_sets,
    enumerate_minimal_siphons,
    exact_flux_coupling,
    exact_generalized_generative_raf,
    structural_closure,
    unfed_siphons,
)
from tests.v6_helpers import VALID_FROM, VALID_UNTIL, metadata


def transformation(
    identifier: str,
    inputs: dict[str, str],
    outputs: dict[str, str],
) -> TransformationAttestation:
    return TransformationAttestation(
        metadata=metadata(identifier),
        spec=TransformationSpec(
            transformation_id=identifier,
            inputs=inputs,
            outputs=outputs,
            uncatalyzed=True,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )


def catalyzed_transformation(
    identifier: str,
    inputs: dict[str, str],
    outputs: dict[str, str],
    *,
    catalysts: tuple[str, ...] = (),
    inhibitors: tuple[str, ...] = (),
    uncatalyzed: bool = False,
) -> TransformationAttestation:
    return TransformationAttestation(
        metadata=metadata(identifier),
        spec=TransformationSpec(
            transformation_id=identifier,
            inputs=inputs,
            outputs=outputs,
            catalyst_clauses=([CatalystClause(all_of=list(catalysts))] if catalysts else []),
            inhibitors=list(inhibitors),
            uncatalyzed=uncatalyzed,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )


def test_result_and_attestation_kinds_are_closed_and_registered() -> None:
    assert {
        "rate-observation-attestation",
        "service-curve-attestation",
        "siphon-analysis-result",
        "flux-coupling-result",
        "cut-set-analysis-result",
        "occurrence-prefix-result",
        "intervention-portfolio",
        "signed-statement",
        "operational-profile-result",
        "perturbation-result",
        "planner-result",
        "trial-assessment",
        "coordination-session",
        "repair-record",
    }.issubset(DOCUMENT_MODELS)


def test_minimal_siphons_and_fed_obligations_match_exhaustive_reference() -> None:
    network = {
        "forward": transformation("forward", {"A": "1"}, {"B": "1"}),
        "reverse": transformation("reverse", {"B": "1"}, {"A": "1"}),
    }
    result = enumerate_minimal_siphons(network, {"A", "B"}, Budget(operations=1000))
    assert result.exhaustive
    assert result.values == (("A", "B"),)
    assert unfed_siphons(result.values, {}, set()) == (("A", "B"),)
    assert unfed_siphons(result.values, {"A": Fraction(1)}, set()) == ()
    limited = enumerate_minimal_siphons(
        network,
        {f"S{index}" for index in range(21)},
        Budget(operations=1000),
    )
    assert not limited.exhaustive


def test_generalized_and_generative_raf_match_exhaustive_small_network_reference() -> None:
    network = {
        "catalyzed": catalyzed_transformation(
            "catalyzed", {"A": "1"}, {"B": "1"}, catalysts=("C",)
        ),
        "catalyst-source": catalyzed_transformation(
            "catalyst-source", {"A": "1"}, {"C": "1"}, uncatalyzed=True
        ),
    }
    result = exact_generalized_generative_raf(
        network,
        {"A"},
        set(),
        set(),
        Budget(operations=10_000),
    )
    assert result.exhaustive and result.full_set_is_raf
    assert result.maximal_rafs == (("catalyst-source", "catalyzed"),)
    assert result.generative_layers == (("catalyst-source",), ("catalyzed",))
    assert set(result.generative_closure) == {"A", "B", "C"}

    circular = {
        "make-b": catalyzed_transformation("make-b", {"A": "1"}, {"B": "1"}, catalysts=("C",)),
        "make-c": catalyzed_transformation("make-c", {"A": "1"}, {"C": "1"}, catalysts=("B",)),
    }
    circular_result = exact_generalized_generative_raf(
        circular,
        {"A"},
        set(),
        set(),
        Budget(operations=10_000),
    )
    assert circular_result.full_set_is_raf
    assert circular_result.generative_layers == ()
    assert circular_result.generative_closure == ("A",)

    inhibited = {
        "productive": catalyzed_transformation(
            "productive",
            {"A": "1"},
            {"B": "1"},
            catalysts=("A",),
            inhibitors=("X",),
        ),
        "inhibitor-source": catalyzed_transformation(
            "inhibitor-source", {"A": "1"}, {"X": "1"}, uncatalyzed=True
        ),
    }
    inhibited_result = exact_generalized_generative_raf(
        inhibited,
        {"A"},
        set(),
        set(),
        Budget(operations=10_000),
    )
    assert not inhibited_result.full_set_is_raf
    assert set(inhibited_result.maximal_rafs) == {
        ("inhibitor-source",),
        ("productive",),
    }

    identifiers = tuple(sorted(inhibited))
    independently_valid: set[tuple[str, ...]] = set()
    for size in range(1, len(identifiers) + 1):
        for values in combinations(identifiers, size):
            closure = {"A"}
            changed = True
            while changed:
                changed = False
                for identifier in values:
                    spec = inhibited[identifier].spec
                    if set(spec.inputs).issubset(closure):
                        before = len(closure)
                        closure.update(spec.outputs)
                        changed = changed or before != len(closure)
            if all(
                not set(inhibited[identifier].spec.inhibitors).intersection(closure)
                and (
                    inhibited[identifier].spec.uncatalyzed
                    or any(
                        set(clause.all_of).issubset(closure)
                        for clause in inhibited[identifier].spec.catalyst_clauses
                    )
                )
                for identifier in values
            ):
                independently_valid.add(values)
    independent_maximal = {
        values
        for values in independently_valid
        if not any(set(values) < set(other) for other in independently_valid)
    }
    assert set(inhibited_result.maximal_rafs) == independent_maximal

    oversized = {
        f"r-{index}": catalyzed_transformation(
            f"r-{index}", {"A": "1"}, {f"S-{index}": "1"}, uncatalyzed=True
        )
        for index in range(21)
    }
    assert not exact_generalized_generative_raf(
        oversized,
        {"A"},
        set(),
        set(),
        Budget(operations=100),
    ).exhaustive


def test_cut_and_enablement_sets_are_semantically_minimal() -> None:
    network = {
        "first": transformation("first", {"A": "1"}, {"B": "1"}),
        "second": transformation("second", {"B": "1"}, {"target": "1"}),
    }
    cuts = enumerate_minimal_cut_sets({"A"}, {"target"}, network, Budget(operations=10_000))
    covers = enumerate_minimal_enablement_sets(
        {"A"}, {"target"}, network, Budget(operations=10_000)
    )
    assert cuts.exhaustive and set(cuts.values) == {("first",), ("second",)}
    assert covers.exhaustive and covers.values == (("first", "second"),)


def test_piecewise_rational_network_calculus_bounds_are_exact() -> None:
    bounds = deterministic_curve_bounds(
        [(Fraction(0), Fraction(0)), (Fraction(1), Fraction(2)), (Fraction(2), Fraction(4))],
        [(Fraction(0), Fraction(0)), (Fraction(1), Fraction(1)), (Fraction(4), Fraction(4))],
        Budget(operations=1000),
    )
    assert bounds.exhaustive
    assert bounds.backlog == 2
    assert bounds.delay == 2


def test_flux_blocking_and_coupling_models_are_rechecked_exactly() -> None:
    network = {
        "forward": transformation("forward", {"A": "1"}, {"B": "1"}),
        "reverse": transformation("reverse", {"B": "1"}, {"A": "1"}),
        "drain": transformation("drain", {"A": "1"}, {"sink": "1"}),
    }
    result = exact_flux_coupling(network, Budget(operations=10_000))
    assert result.status == "satisfied"
    assert result.exact_models_rechecked
    assert result.blocked == ("drain",)
    assert result.fully_coupled_classes == (("forward", "reverse"),)


def test_bounded_occurrence_prefix_records_conflict_and_causality() -> None:
    network = {
        "left": transformation("left", {"A": "1"}, {"B": "1"}),
        "right": transformation("right", {"A": "1"}, {"C": "1"}),
    }
    prefix = bounded_occurrence_prefix({"A"}, network, Budget(operations=10_000))
    assert prefix.exhaustive
    assert len(prefix.events) == 2
    left, right = prefix.events
    assert left.conflict_event_ids == (right.event_id,)
    assert right.conflict_event_ids == (left.event_id,)
    assert not left.causal_predecessor_ids
    assert not right.causal_predecessor_ids


def test_structural_closure_bounds_unreachable_targets_and_allowed_edges() -> None:
    network = {
        "first": transformation("first", {"A": "1"}, {"B": "1", "zero": "0"}),
        "second": transformation("second", {"B": "1"}, {"target": "1"}),
    }
    assert structural_closure({"A"}, network, budget=Budget(operations=100)) == {
        "A",
        "B",
        "target",
    }
    assert structural_closure(
        {"A"}, network, allowed_transformations={"first", "unknown"}, budget=Budget(operations=100)
    ) == {"A", "B"}
    unreachable = enumerate_minimal_cut_sets(set(), {"target"}, network, Budget(operations=100))
    assert unreachable.values == ((),) and unreachable.exhaustive
    assert not enumerate_minimal_cut_sets(
        {"A"}, {"target"}, network, Budget(operations=100), maximum_transformations=1
    ).exhaustive
    assert not enumerate_minimal_enablement_sets(
        {"A"}, {"target"}, network, Budget(operations=100), maximum_transformations=1
    ).exhaustive
    initially_enabled = enumerate_minimal_enablement_sets(
        {"target"}, {"target"}, network, Budget(operations=100)
    )
    assert initially_enabled.values == ((),)


def test_siphon_minimality_and_external_supply_paths_are_distinct() -> None:
    network = {
        "cycle-a": transformation("cycle-a", {"A": "1"}, {"B": "1"}),
        "cycle-b": transformation("cycle-b", {"B": "1"}, {"A": "1"}),
        "self": transformation("self", {"C": "1"}, {"C": "1"}),
    }
    siphons = enumerate_minimal_siphons(network, {"A", "B", "C"}, Budget(operations=1000))
    assert siphons.values == (("C",), ("A", "B"))
    assert unfed_siphons(siphons.values, {}, {"C"}) == (("A", "B"),)
    assert unfed_siphons(siphons.values, {"A": Fraction(0)}, {"A"}) == (("C",),)


def test_curve_helpers_cover_boundaries_flat_segments_and_incomplete_horizons() -> None:
    points = [(Fraction(0), Fraction(0)), (Fraction(1), Fraction(1))]
    assert _interpolate(points, Fraction(-1)) is None
    assert _interpolate(points, Fraction(2)) is None
    assert _interpolate(points, Fraction(0)) == 0
    assert _interpolate(points, Fraction(1, 2)) == Fraction(1, 2)
    assert _inverse_crossing(points, Fraction(2), Fraction(0)) is None
    assert _inverse_crossing(points, Fraction(1), Fraction(2)) is None
    flat = [(Fraction(0), Fraction(0)), (Fraction(1), Fraction(0))]
    assert _inverse_crossing(flat, Fraction(1), Fraction(0)) is None
    incomplete = deterministic_curve_bounds(
        [(Fraction(0), Fraction(0)), (Fraction(1), Fraction(2))],
        [(Fraction(0), Fraction(0)), (Fraction(1), Fraction(1))],
        Budget(operations=100),
    )
    assert not incomplete.exhaustive
    assert incomplete.delay is None
    assert incomplete.backlog == 1


def test_exact_linear_algebra_handles_pivots_free_columns_and_proportionality() -> None:
    network = {
        "forward": transformation("forward", {"A": "1"}, {"B": "1"}),
        "reverse": transformation("reverse", {"B": "1"}, {"A": "1"}),
    }
    coordinates, matrix = _stoichiometric_matrix(network, ["forward", "reverse"])
    assert coordinates == ("A", "B")
    assert _nullspace(matrix, 2) == [[Fraction(1), Fraction(1)]]
    assert _nullspace([], 2) == [
        [Fraction(1), Fraction(0)],
        [Fraction(0), Fraction(1)],
    ]
    assert _nullspace([[Fraction(0), Fraction(1)]], 2) == [[Fraction(1), Fraction(0)]]
    assert _proportional([Fraction(1), Fraction(2)], [Fraction(2), Fraction(4)])
    with pytest.raises(ValueError):
        _proportional([Fraction(1)], [Fraction(1), Fraction(2)])
    assert not _proportional([Fraction(1), Fraction(1)], [Fraction(1), Fraction(0)])
    assert not _proportional([Fraction(1), Fraction(0)], [Fraction(1), Fraction(1)])
    assert not _proportional([Fraction(0)], [Fraction(1)])
    assert not _proportional([Fraction(1)], [Fraction(-1)])
    assert not _proportional([Fraction(1), Fraction(2)], [Fraction(1), Fraction(3)])
    assert not _proportional([Fraction(0)], [Fraction(0)])


def test_flux_analysis_reports_empty_network_and_missing_optional_solver(
    monkeypatch: object,
) -> None:
    assert exact_flux_coupling({}, Budget(operations=100)).status == "satisfied"
    original_import = builtins.__import__

    def fail_z3(name: str, *args: object, **kwargs: object) -> object:
        if name == "z3":
            raise ImportError
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_z3)  # type: ignore[attr-defined]
    unavailable = exact_flux_coupling(
        {"one": transformation("one", {"A": "1"}, {"A": "1"})},
        Budget(operations=100),
    )
    assert unavailable.status == "unknown"
    assert not unavailable.exact_models_rechecked


def test_occurrence_prefix_rejects_non_unit_profiles_and_marks_cutoffs_and_limits() -> None:
    non_unit = {"double": transformation("double", {"A": "2"}, {"B": "1"})}
    assert not bounded_occurrence_prefix({"A"}, non_unit, Budget(operations=100)).exhaustive

    cycle = {
        "forward": transformation("forward", {"A": "1"}, {"B": "1"}),
        "reverse": transformation("reverse", {"B": "1"}, {"A": "1"}),
    }
    prefix = bounded_occurrence_prefix({"A"}, cycle, Budget(operations=100))
    assert prefix.cutoff_event_ids
    assert prefix.events[1].causal_predecessor_ids == (prefix.events[0].event_id,)

    limited = bounded_occurrence_prefix({"A"}, cycle, Budget(operations=100), maximum_events=0)
    assert not limited.exhaustive and not limited.events

    inhibited = transformation("inhibited", {"A": "1"}, {"B": "1"}).model_copy(
        update={
            "spec": transformation("inhibited", {"A": "1"}, {"B": "1"}).spec.model_copy(
                update={"inhibitors": ["A"]}
            )
        }
    )
    assert not bounded_occurrence_prefix(
        {"A"}, {"inhibited": inhibited}, Budget(operations=100)
    ).events

    catalyst_required = transformation("catalyst-required", {"A": "1"}, {"B": "1"}).model_copy(
        update={
            "spec": transformation("catalyst-required", {"A": "1"}, {"B": "1"}).spec.model_copy(
                update={
                    "uncatalyzed": False,
                    "catalyst_clauses": [CatalystClause(all_of=["cat"])],
                }
            )
        }
    )
    assert not bounded_occurrence_prefix(
        {"A"}, {"catalyst-required": catalyst_required}, Budget(operations=100)
    ).events
    catalyzed = bounded_occurrence_prefix(
        {"A", "cat"},
        {"catalyst-required": catalyst_required},
        Budget(operations=100),
    )
    assert len(catalyzed.events) == 1
    assert len(catalyzed.events[0].preset_condition_ids) == 1

    output_already_marked = transformation("duplicate-output", {"A": "1"}, {"B": "1"})
    assert not bounded_occurrence_prefix(
        {"A", "B"}, {"duplicate-output": output_already_marked}, Budget(operations=100)
    ).events
