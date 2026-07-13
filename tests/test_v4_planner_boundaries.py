# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from fractions import Fraction
from pathlib import Path

import pytest

from collective_phase_control_fabric.planner_v4 import (
    _branch_state,
    _dominates,
    _eligible,
    _initial_state,
    _interval_not_worse,
    _safe_branch,
    _tree,
    explain_action_v4,
    plan_v4,
)
from tests.test_v4 import NOW, _contract
from tests.test_v4_operational import _action_attributes, _branch


def _statement(kind: str, subject: str, attributes: dict[str, object]) -> dict[str, object]:
    return {"payload": {"record_type": kind, "subject_id": subject, "attributes": attributes}}


def test_abstract_state_and_worst_case_branch_coordinates() -> None:
    statements = [
        _statement("state", "state:seed", {"available": True}),
        _statement("authority", "authority:run", {}),
        _statement("hazard", "hazard:guard", {}),
        _statement(
            "resource_observation",
            "resource:energy",
            {"coordinate": "energy", "quantity": "2", "unit": "unit"},
        ),
        _statement("independence", "domain:one", {}),
    ]
    state = _initial_state(statements, {"operational_organization_profile": {"x": "satisfied"}})
    branch = _branch([])
    branch["must_remove"] = ["hazard:guard"]
    branch["may_remove"] = ["state:seed"]
    branch["debt"] = ["debt:one"]
    branch["resource_intervals"] = {"energy": {"lower": "-1", "upper": "0", "unit": "unit"}}
    branch["verification_load_upper"] = "1/2"
    branch["independence_domains_removed"] = ["domain:one"]
    projected = _branch_state(state, branch)
    assert projected["resources"]["energy"] == Fraction(1)
    assert projected["debt"] == {"debt:one"}
    assert projected["verification_load"] == Fraction(1, 2)
    assert projected["independence_domains"] == set()
    assert "state:seed" not in projected["states"]

    contract = _contract()
    contract["protected_floors"] = {"energy": {"quantity": "2", "unit": "unit"}}
    safe, reasons, _ = _safe_branch(state, branch, contract, {"authority:run"}, {"hazard:guard"})
    assert safe is False
    assert "hazard_guard_not_preserved" in reasons
    assert "protected_floor_violation:energy" in reasons
    overloaded = _branch([])
    overloaded["verification_load_upper"] = "1"
    assert (
        "verification_capacity_overloaded"
        in _safe_branch(state, overloaded, contract, set(), set())[1]
    )


def test_eligibility_rejections_and_interval_dominance() -> None:
    contract = _contract()
    state = {
        "states": {"state:seed", "authority:run"},
        "resources": {},
        "units": {},
        "debt": set(),
        "verification_load": Fraction(0),
        "independence_domains": set(),
        "authority": {"authority:run"},
        "hazards": set(),
        "scientific_profile": {},
        "trial_bindings": set(),
    }
    invalid_attributes = _action_attributes()
    invalid_attributes["expires_at"] = "invalid"
    invalid_attributes["input_refs"] = ["missing"]
    invalid_attributes["required_authority_refs"] = ["missing-authority"]
    invalid_attributes["required_hazard_refs"] = ["missing-hazard"]
    invalid_attributes["branches"] = {"success": _branch([])}
    invalid = {
        "payload": {
            "record_type": "evidence",
            "subject_id": "action:invalid",
            "attributes": invalid_attributes,
        }
    }
    accepted, rejected = _eligible([invalid], state, contract, NOW)
    assert accepted == []
    assert "action_expiry_invalid" in rejected[0]["reasons"]
    assert "branch_missing:timeout" in rejected[0]["reasons"]

    assert _interval_not_worse(
        {"lower": "1", "upper": "2", "unit": "u"},
        {"lower": "0", "upper": "3", "unit": "u"},
        prefer_larger=True,
    ) == (True, True)
    assert _interval_not_worse(None, None, prefer_larger=False) == (True, False)
    assert _interval_not_worse(
        {"lower": "0", "upper": "1", "unit": "a"},
        {"lower": "0", "upper": "1", "unit": "b"},
        prefer_larger=False,
    ) == (False, False)
    left = {
        "branch_reports": {
            name: {
                "guaranteed_additions": ["x"],
                "debt": [],
                "resource_intervals": {},
                "time_interval": {"lower": "0", "upper": "1", "unit": "s"},
                "cost_interval": {"lower": "0", "upper": "1", "unit": "c"},
                "quality_interval": {"lower": "2", "upper": "3", "unit": "q"},
                "verification_load_upper": "0",
                "independence_erosion_count": 0,
            }
            for name in ("success", "partial", "failure", "timeout")
        }
    }
    right = {
        "branch_reports": {
            name: {
                **left["branch_reports"][name],
                "guaranteed_additions": [],
                "debt": ["d"],
            }
            for name in ("success", "partial", "failure", "timeout")
        }
    }
    assert _dominates(left, right) is True
    assert _dominates(right, left) is False


def test_and_or_tree_and_action_explanation(monkeypatch: pytest.MonkeyPatch) -> None:
    contract = _contract()
    contract["target_states"] = ["target"]
    action = {
        "action_id": "action:one",
        "attributes": {"repeatable": False},
        "branch_states": {
            "success": {"states": {"target"}},
            "partial": {"states": set()},
            "failure": {"states": set()},
            "timeout": {"states": set()},
        },
    }
    tree = _tree(action, [], contract, NOW, {"target"}, 1, 32, set())
    assert tree["strong_target_policy"] is False
    assert tree["outcomes"]["success"]["target_guaranteed"] is True

    state = {
        "states": {"state:seed", "authority:run"},
        "resources": {},
        "units": {},
        "debt": set(),
        "verification_load": Fraction(0),
        "independence_domains": set(),
        "authority": {"authority:run"},
        "hazards": set(),
        "scientific_profile": {},
        "trial_bindings": set(),
    }
    parent = {
        "action_id": "action:parent",
        "attributes": {"repeatable": False},
        "branch_states": {name: state for name in ("success", "partial", "failure", "timeout")},
    }
    child_attributes = _action_attributes()
    child = {
        "payload": {
            "record_type": "evidence",
            "subject_id": "action:child",
            "attributes": child_attributes,
        }
    }
    strong = _tree(parent, [child], contract, NOW, {"state:target"}, 2, 32, set())
    assert strong["strong_target_policy"] is True
    cycle = _tree(
        parent,
        [child],
        contract,
        NOW,
        {"state:target"},
        2,
        32,
        {("action:parent", tuple(sorted(state["states"])))},
    )
    assert cycle["strong_target_policy"] is False

    monkeypatch.setattr(
        "collective_phase_control_fabric.planner_v4.plan_v4",
        lambda root: {
            "workspace_generation": "sha256:" + "a" * 64,
            "primary_action": {"action_id": "action:one"},
            "pareto_alternatives": [],
            "rejected_actions": [{"action_id": "action:two", "reasons": ["unsafe"]}],
        },
    )
    assert explain_action_v4(Path("unused"), "action:one")["selection"] == "primary"
    assert explain_action_v4(Path("unused"), "action:two")["rejection"]["reasons"] == ["unsafe"]
    assert explain_action_v4(Path("unused"), "action:missing")["failure_code"] == "action_not_found"


def test_planner_malformed_coordinate_and_workspace_failure_matrix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed_state = _initial_state(
        [
            {"payload": None},
            _statement(
                "resource_observation",
                "bad-resource",
                {"coordinate": "energy", "quantity": "1/0", "unit": "unit"},
            ),
        ],
        {},
    )
    assert malformed_state["resources"] == {}
    state = {
        "states": {"state:seed", "authority:run"},
        "resources": {"energy": Fraction(1)},
        "units": {"energy": "unit"},
        "debt": set(),
        "verification_load": Fraction(0),
        "independence_domains": set(),
        "authority": {"authority:run"},
        "hazards": set(),
        "scientific_profile": {},
        "trial_bindings": set(),
    }
    invalid_interval = _branch([])
    invalid_interval["resource_intervals"] = {
        "energy": {"lower": "1/0", "upper": "0", "unit": "unit"}
    }
    assert _safe_branch(state, invalid_interval, _contract(), set(), set())[1] == [
        "branch_interval_invalid"
    ]
    malformed_floor_contract = _contract()
    malformed_floor_contract["protected_floors"] = {"bad": "not-an-object"}
    assert (
        "protected_floor_invalid:bad"
        in _safe_branch(state, _branch([]), malformed_floor_contract, set(), set())[1]
    )
    unit_floor_contract = _contract()
    unit_floor_contract["protected_floors"] = {"energy": {"quantity": "0", "unit": "different"}}
    assert (
        "protected_floor_unit_mismatch:energy"
        in _safe_branch(state, _branch([]), unit_floor_contract, set(), set())[1]
    )

    expired = _action_attributes()
    expired["expires_at"] = "2026-01-01T00:00:00Z"
    no_branches = _action_attributes()
    no_branches["branches"] = None
    _, rejected = _eligible(
        [
            _statement("evidence", "action:expired", expired),
            _statement("evidence", "action:no-branches", no_branches),
        ],
        state,
        _contract(),
        NOW,
    )
    reasons = {item["action_id"]: item["reasons"] for item in rejected}
    assert "action_expired" in reasons["action:expired"]
    assert "branch_effect_contract_missing" in reasons["action:no-branches"]
    assert _interval_not_worse(
        {"lower": "bad", "upper": "bad", "unit": "u"},
        {"lower": "0", "upper": "0", "unit": "u"},
        prefer_larger=True,
    ) == (False, False)

    monkeypatch.setattr(
        "collective_phase_control_fabric.planner_v4.active_attestations_v4",
        lambda root: (_ for _ in ()).throw(OSError("broken")),
    )
    assert plan_v4(Path("unused"))["failure_code"] == "planner_workspace_invalid"
    monkeypatch.setattr(
        "collective_phase_control_fabric.planner_v4.active_attestations_v4",
        lambda root: ({"generation_id": "sha256:" + "a" * 64}, _contract(), [], []),
    )
    monkeypatch.setattr(
        "collective_phase_control_fabric.planner_v4.science_audit_v4", lambda root: {}
    )
    assert plan_v4(Path("unused"))["failure_code"] == "authoritative_time_receipt_required"
    action = _statement("evidence", "action:many", _action_attributes())
    monkeypatch.setattr(
        "collective_phase_control_fabric.planner_v4.active_attestations_v4",
        lambda root: (
            {"generation_id": "sha256:" + "a" * 64, "analysis_epoch": NOW},
            _contract(),
            [action] * 4097,
            [],
        ),
    )
    assert plan_v4(Path("unused"))["failure_code"] == "action_registry_limit_exceeded"
