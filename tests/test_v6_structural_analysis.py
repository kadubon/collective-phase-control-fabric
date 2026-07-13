# SPDX-License-Identifier: Apache-2.0
"""Differential small-network tests for bounded exact v0.6 structural analyses."""

from __future__ import annotations

from fractions import Fraction

from collective_phase_control_fabric.v6.models import (
    DOCUMENT_MODELS,
    Lifecycle,
    TransformationAttestation,
    TransformationSpec,
)
from collective_phase_control_fabric.v6.science import Budget
from collective_phase_control_fabric.v6.structural_analysis import (
    bounded_occurrence_prefix,
    deterministic_curve_bounds,
    enumerate_minimal_cut_sets,
    enumerate_minimal_enablement_sets,
    enumerate_minimal_siphons,
    exact_flux_coupling,
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


def test_result_and_attestation_kinds_are_closed_and_registered() -> None:
    assert {
        "rate-observation-attestation",
        "service-curve-attestation",
        "siphon-analysis-result",
        "flux-coupling-result",
        "cut-set-analysis-result",
        "occurrence-prefix-result",
        "intervention-portfolio",
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
