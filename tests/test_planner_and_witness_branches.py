# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from collective_phase_control_fabric.engine import analyze
from collective_phase_control_fabric.fixtures import (
    fixture,
    maintenance_witness,
    productive_witness,
)
from collective_phase_control_fabric.network import verified_closure
from collective_phase_control_fabric.planner import (
    AFFORDANCE_REPAIR_KINDS,
    _filter_action,
    _impact_dominates,
    apply_postcondition,
    conditional_impact,
    plan_actions,
)
from collective_phase_control_fabric.witnesses import validate_productive_witness
from collective_phase_control_fabric.workspace import _demo_action


def _witness_result(mutator: str) -> tuple[bool | None, tuple[str, ...]]:
    data = fixture("verified_productive_organization")
    witness = productive_witness()
    edge = data["network"]["transformations"][0]
    if mutator == "missing_coefficients":
        witness["transformation_coefficients"] = {}
    elif mutator == "unknown_transformation":
        witness["transformation_coefficients"] = {"absent": "1"}
    elif mutator == "invalid_coefficient":
        witness["transformation_coefficients"]["transform:produce"] = "bad"
    elif mutator == "negative_coefficient":
        witness["transformation_coefficients"]["transform:produce"] = "-1"
    elif mutator == "unknown_coordinate":
        edge["produced_coordinates"]["absent"] = {"quantity": "1", "unit": "x"}
    elif mutator == "flow_unit":
        edge["produced_coordinates"]["target_units"]["unit"] = "wrong"
    elif mutator == "flow_quantity":
        edge["produced_coordinates"]["target_units"]["quantity"] = "bad"
    elif mutator == "supplies_malformed":
        witness["external_supplies"] = []
    elif mutator == "unknown_supply":
        witness["external_supplies"]["absent"] = {"quantity": "1", "unit": "x"}
    elif mutator == "supply_unit":
        witness["external_supplies"]["protected_resource"]["unit"] = "wrong"
    elif mutator == "supply_quantity":
        witness["external_supplies"]["protected_resource"]["quantity"] = "bad"
    elif mutator == "expected_malformed":
        witness["expected_net_balances"] = []
    elif mutator == "expected_missing":
        del witness["expected_net_balances"]["target_units"]
    elif mutator == "expected_invalid":
        witness["expected_net_balances"]["target_units"] = "bad"
    elif mutator == "targets_missing":
        witness["target_positive_coordinates"] = []
    elif mutator == "unknown_target":
        witness["target_positive_coordinates"] = ["absent"]
    elif mutator == "nonpositive_target":
        witness["transformation_coefficients"]["transform:produce"] = "0"
        witness["expected_net_balances"]["target_units"] = "0"
    elif mutator == "unknown_protected":
        witness["protected_nonnegative_coordinates"] = ["absent"]
    elif mutator == "negative_protected":
        witness["external_supplies"] = {}
        witness["expected_net_balances"]["protected_resource"] = "-1"
    verified = verified_closure(data["contract"], data["network"])
    result = validate_productive_witness(data["contract"], data["network"], verified, witness)
    return result.valid, result.reasons


@pytest.mark.parametrize(
    "mutator",
    [
        "missing_coefficients",
        "unknown_transformation",
        "invalid_coefficient",
        "negative_coefficient",
        "unknown_coordinate",
        "flow_unit",
        "flow_quantity",
        "supplies_malformed",
        "unknown_supply",
        "supply_unit",
        "supply_quantity",
        "expected_malformed",
        "expected_missing",
        "expected_invalid",
        "targets_missing",
        "unknown_target",
        "nonpositive_target",
        "unknown_protected",
        "negative_protected",
    ],
)
def test_productive_witness_fail_closed_branches(mutator: str) -> None:
    valid, reasons = _witness_result(mutator)
    assert valid is False
    assert reasons


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (
            {"required_authority_refs": ["authority:needed"], "authority_status": False},
            "missing_authority",
        ),
        ({"input_refs": ["state:absent"]}, "missing_input_closure"),
        ({"resource_upper_bounds": []}, "resource_envelope_violation"),
        (
            {"resource_upper_bounds": {"local_io": {"quantity": "11", "unit": "operation"}}},
            "resource_envelope_violation",
        ),
        (
            {"resource_upper_bounds": {"local_io": {"quantity": "1", "unit": "wrong"}}},
            "resource_envelope_violation",
        ),
    ],
)
def test_remaining_hard_filter_branches(
    tmp_path: Path, change: dict[str, object], reason: str
) -> None:
    data = fixture("reachability_without_productivity")
    analysis = analyze(data["contract"], data["network"])
    action = _demo_action(tmp_path)
    action.update(change)
    assert _filter_action(action, data["contract"], analysis) == reason


def _impact(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "target_path_unlock_count": 1,
        "barrier_coordinate_reduction_count": 1,
        "seed_deficit_reduction_count": 1,
        "productive_organization_extension_count": 1,
        "robustness_improvement_count": 1,
        "deadlock_removal_count": 1,
        "observability_gain_count": 1,
        "newly_introduced_debt_count": 0,
        "resource_upper_bound_vector": {"io": {"quantity": "1", "unit": "operation"}},
        "verification_load_increase": "unknown",
        "source_concentration_increase": "unknown",
        "correlation_concentration_increase": "unknown",
    }
    value.update(updates)
    return value


def test_pareto_comparison_is_unit_aware_and_strict() -> None:
    strong = _impact()
    weak = _impact(target_path_unlock_count=0, newly_introduced_debt_count=1)
    assert _impact_dominates(strong, weak)
    assert not _impact_dominates(weak, strong)
    assert not _impact_dominates(strong, deepcopy(strong))
    incompatible = _impact(
        resource_upper_bound_vector={"compute": {"quantity": "1", "unit": "second"}}
    )
    assert not _impact_dominates(strong, incompatible)
    different_unit = _impact(resource_upper_bound_vector={"io": {"quantity": "1", "unit": "byte"}})
    assert not _impact_dominates(strong, different_unit)
    expensive = _impact(resource_upper_bound_vector={"io": {"quantity": "2", "unit": "operation"}})
    assert not _impact_dominates(expensive, strong)
    changed_unknown = _impact(verification_load_increase="1/10")
    assert not _impact_dominates(strong, changed_unknown)


def test_apply_postcondition_all_declared_mutations() -> None:
    data = fixture("reachability_without_productivity")
    postcondition = {
        "available_states": ["state:target"],
        "add_nodes": [
            {
                "node_id": "observation:new",
                "type": "observation",
                "available": True,
                "lifecycle_status": "valid",
            }
        ],
        "edge_updates": {"transform:produce": {"output_contract_status": True}},
        "productive_witness": productive_witness(),
        "maintenance_witness": maintenance_witness(),
    }
    network, productive, maintenance = apply_postcondition(
        data["network"], None, None, postcondition
    )
    assert any(node.get("node_id") == "observation:new" for node in network["nodes"])
    assert (
        next(node for node in network["nodes"] if node["node_id"] == "state:target")["available"]
        is True
    )
    assert productive["witness_id"] == "productive-witness:demo"
    assert maintenance["witness_id"] == "maintenance-witness:demo"


def test_conditional_impact_with_no_postcondition(tmp_path: Path) -> None:
    data = fixture("reachability_without_productivity")
    before = analyze(data["contract"], data["network"])
    action = _demo_action(tmp_path)
    action["postcondition_contract"] = None
    impact = conditional_impact(
        action,
        data["contract"],
        data["network"],
        None,
        None,
        before,
        analyze,
    )
    assert impact["target_path_unlock_count"] == 0


def test_priority_class_keeps_affordance_repair_first(tmp_path: Path) -> None:
    data = fixture("reachability_without_productivity")
    analysis = analyze(data["contract"], data["network"])
    productive_action = _demo_action(tmp_path)
    repair_action = deepcopy(productive_action)
    repair_action.update(
        {
            "action_id": "action:repair-receipt",
            "action_kind": "affordance_repair",
            "affordance_repair_kind": "missing_receipt",
            "priority_class": 2,
            "postcondition_contract": {},
        }
    )
    plan = plan_actions(
        [productive_action, repair_action],
        data["contract"],
        data["network"],
        None,
        None,
        analysis,
        [],
        analyze,
    )
    assert "missing_receipt" in AFFORDANCE_REPAIR_KINDS
    assert plan["active_priority_class"] == 2
    assert plan["primary_action"]["action_id"] == "action:repair-receipt"
    assert plan["deferred_actions"][0]["action_id"] == productive_action["action_id"]
