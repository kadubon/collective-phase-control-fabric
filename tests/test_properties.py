# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction

from hypothesis import given
from hypothesis import strategies as st

from collective_phase_control_fabric.barrier import BARRIER_COORDINATES, dominates
from collective_phase_control_fabric.canonical import digest_json
from collective_phase_control_fabric.demos import demo_documents
from collective_phase_control_fabric.network import feasible_closure
from collective_phase_control_fabric.planner import _contingent_dominates, _v2_branch_projection
from collective_phase_control_fabric.science import (
    exact_nullspace,
    validate_formation_sequence,
)


@given(st.dictionaries(st.text(min_size=1, max_size=8), st.integers(), max_size=12))
def test_canonical_digest_is_mapping_order_invariant(value: dict[str, int]) -> None:
    assert digest_json(value) == digest_json(dict(reversed(list(value.items()))))


@given(st.booleans())
def test_monotone_closure_is_transformation_order_invariant(reverse: bool) -> None:
    contract, network, _ = demo_documents("orientation-only-reachability")
    extra = deepcopy(network["transformations"][0])
    extra["transformation_id"] = "transform:secondary"
    extra["required_inputs"] = ["state:target"]
    extra["produced_outputs"] = ["state:secondary"]
    extra["produced_coordinates"] = {}
    network["nodes"].append(
        {
            "node_id": "state:secondary",
            "type": "artifact",
            "available": False,
            "lifecycle_status": "valid",
        }
    )
    network["transformations"].append(extra)
    for edge in network["transformations"]:
        edge["_source_backed_runtime"] = True
    expected = feasible_closure(contract, network)
    if reverse:
        network["transformations"].reverse()
    actual = feasible_closure(contract, network)
    assert actual.available_states == expected.available_states
    assert actual.applied_transformations == expected.applied_transformations


@given(
    st.integers(min_value=-20, max_value=20).filter(lambda value: value != 0),
    st.integers(min_value=-20, max_value=20).filter(lambda value: value != 0),
)
def test_exact_nullspace_basis_satisfies_rational_identity(left: int, right: int) -> None:
    basis = exact_nullspace([[str(left), str(right)]])
    assert len(basis) == 1
    vector = [Fraction(item) for item in basis[0]]
    assert Fraction(left) * vector[0] + Fraction(right) * vector[1] == 0


@given(st.sampled_from(["protected_floor_status", "authority_status", "hazard_status"]))
def test_unknown_outcome_coordinate_is_never_safe(field: str) -> None:
    branch = {
        "receipt_schema_ref": "action-receipt@0.2.0",
        "source_pointers": [],
        "projection_targets": [],
        "debt": [],
        "rollback_obligations": [],
        "resource_upper_bounds": {},
        "protected_floor_status": "true",
        "authority_status": "true",
        "hazard_status": "true",
    }
    branch[field] = "unknown"
    assert _v2_branch_projection(branch)["safe"] is False


@given(st.integers(min_value=0, max_value=8))
def test_formation_prefix_below_floor_never_valid(deficit: int) -> None:
    contract, network, _ = demo_documents("orientation-only-reachability")
    contract["protected_floors"] = {"protected_resource": str(deficit + 1)}
    witness = {
        "layers": [["transform:produce"]],
        "initial_coordinate_balances": {"protected_resource": str(deficit)},
    }
    assert validate_formation_sequence(contract, network, witness)["valid"] is False


@given(st.integers(min_value=0, max_value=6), st.integers(min_value=0, max_value=6))
def test_contingent_dominance_is_asymmetric_when_strict(left_gain: int, right_gain: int) -> None:
    def impact(gain: int) -> dict[str, object]:
        branch = {
            "safe": True,
            "unsafe_reasons": [],
            "newly_introduced_debt_count": 0,
            "resource_upper_bound_vector": {},
            "target_path_unlock_count": gain,
            "barrier_coordinate_reduction_count": 0,
            "seed_deficit_reduction_count": 0,
            "productive_organization_extension_count": 0,
            "robustness_improvement_count": 0,
            "deadlock_removal_count": 0,
            "observability_gain_count": 0,
        }
        return {name: dict(branch) for name in ("success", "partial", "failure", "timeout")}

    left, right = impact(left_gain), impact(right_gain)
    if left_gain > right_gain:
        assert _contingent_dominates(left, right) is True
        assert _contingent_dominates(right, left) is False
    elif right_gain > left_gain:
        assert _contingent_dominates(right, left) is True
        assert _contingent_dominates(left, right) is False
    else:
        assert _contingent_dominates(left, right) is False


@given(st.sets(st.text(min_size=1, max_size=5), max_size=8))
def test_barrier_strict_partial_order_is_irreflexive(blockers: set[str]) -> None:
    vector = {
        "coordinates": {
            coordinate: {"blocker_ids": sorted(blockers), "known_or_unknown": "known"}
            for coordinate in BARRIER_COORDINATES
        }
    }
    assert dominates(vector, vector) is False
