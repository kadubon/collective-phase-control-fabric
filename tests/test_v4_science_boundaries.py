# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction

import pytest

from collective_phase_control_fabric.science_v4 import (
    _bounded_one_safe_unfolding,
    _closure,
    _enabled,
    _evaluate,
    _flux_coupling,
    _formation,
    _fraction,
    _independence,
    _minimal_cut_sets,
    _network,
    _organization,
    _raf,
    _resources,
    _verification,
)
from tests.test_v4 import _contract

SNAPSHOT = "sha256:" + "a" * 64
GENERATION = "sha256:" + "b" * 64


def _record(
    attestation: str,
    kind: str,
    subject: str,
    attributes: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "0.4.0",
        "attestation_id": attestation,
        "record_type": kind,
        "subject_id": subject,
        "subject_digest": "sha256:" + f"{len(attestation):064x}",
        "source_artifact_digest": "sha256:" + f"{len(subject) + 100:064x}",
        "source_pointer": "/value",
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "lineage_refs": [],
        "correlation_domains": [],
        "attributes": attributes,
    }


def _edge(flow: str = "0") -> dict[str, object]:
    return {
        "inputs": ["seed"],
        "outputs": ["target"],
        "authority_refs": [],
        "evidence_refs": [],
        "inhibitors": [],
        "catalyst_clauses": [["catalyst"]],
        "explicitly_uncatalyzed": False,
        "coordinate_flows": {"energy": flow},
        "validated_boundary_supply_credit": "0",
    }


def test_exact_fraction_network_and_closure_boundaries() -> None:
    assert _fraction("1/2") == Fraction(1, 2)
    with pytest.raises(ValueError):
        _fraction(str(1 << 5000))
    with pytest.raises(ZeroDivisionError):
        _fraction("1/0")
    records = [
        _record("a", "state", "seed", {"available": True}),
        _record("b", "catalyst", "catalyst", {}),
        _record("c", "transformation", "edge", _edge()),
    ]
    initial, transformations = _network(records)
    reachable, layers, operations = _closure(initial, transformations, 10)
    assert "target" in reachable and layers["target"] == 1 and operations >= 1
    with pytest.raises(RuntimeError, match="unknown_due_to_budget"):
        _closure(initial, transformations, 0)
    with pytest.raises(ValueError, match="duplicate transformation"):
        _network([*records, _record("d", "transformation", "edge", _edge())])
    assert _enabled({"inputs": ["missing"]}, set()) is False
    assert _enabled({"inputs": [], "authority_refs": ["missing"]}, set()) is False
    assert (
        _enabled({"inputs": [], "authority_refs": [], "evidence_refs": ["missing"]}, set()) is False
    )
    assert (
        _enabled(
            {"inputs": [], "authority_refs": [], "evidence_refs": [], "inhibitors": ["block"]},
            {"block"},
        )
        is False
    )
    assert (
        _enabled(
            {
                "inputs": [],
                "authority_refs": [],
                "evidence_refs": [],
                "catalyst_clauses": "bad",
            },
            set(),
        )
        is False
    )


def test_organization_and_formation_negative_matrix() -> None:
    contract = _contract()
    contract["target_states"] = ["target"]
    contract["protected_floors"] = {"energy": {"quantity": "2", "unit": "unit"}}
    transformations = {"edge": _edge("-1")}
    assert _organization([], transformations, SNAPSHOT)[0] == "unknown"
    bad_snapshot = _record(
        "org",
        "evidence",
        "org",
        {
            "evidence_type": "organization_witness",
            "analysis_snapshot_digest": "wrong",
            "flux": {"edge": "1"},
        },
    )
    assert _organization([bad_snapshot], transformations, SNAPSHOT)[0] == "violated"
    zero_flux = deepcopy(bad_snapshot)
    zero_flux["attributes"] = {
        "evidence_type": "organization_witness",
        "analysis_snapshot_digest": SNAPSHOT,
        "flux": {"edge": "0"},
    }
    assert _organization([zero_flux], transformations, SNAPSHOT)[0] == "violated"
    negative = deepcopy(zero_flux)
    negative["attributes"]["flux"] = {"edge": "1"}
    assert (
        "negative_maintenance_balance:energy"
        in _organization([negative], transformations, SNAPSHOT)[1]
    )
    invalid_flux = deepcopy(negative)
    invalid_flux["attributes"]["flux"] = {"edge": "bad"}
    assert "flux_rational_invalid" in _organization([invalid_flux], transformations, SNAPSHOT)[1]
    invalid_flows = {"edge": {**_edge(), "coordinate_flows": []}}
    assert "coordinate_flows_invalid:edge" in _organization([negative], invalid_flows, SNAPSHOT)[1]

    resource = _record(
        "resource",
        "resource_observation",
        "energy",
        {"coordinate": "energy", "quantity": "2", "unit": "unit"},
    )
    assert _formation(contract, [], {"seed", "catalyst"}, transformations, SNAPSHOT)[0] == "unknown"
    empty = _record(
        "formation",
        "evidence",
        "formation",
        {
            "evidence_type": "formation_sequence_witness",
            "analysis_snapshot_digest": SNAPSHOT,
            "steps": [],
        },
    )
    assert (
        _formation(contract, [empty, resource], {"seed", "catalyst"}, transformations, SNAPSHOT)[0]
        == "violated"
    )
    formation = deepcopy(empty)
    formation["attributes"]["steps"] = [{"transformation_id": "edge", "multiplier": "1"}]
    status, reasons = _formation(
        contract, [formation, resource], {"seed", "catalyst"}, transformations, SNAPSHOT
    )
    assert status == "violated"
    assert any(reason.startswith("formation_prefix_floor_violation") for reason in reasons)
    malformed_steps = deepcopy(formation)
    malformed_steps["attributes"]["steps"] = ["bad", {"transformation_id": "missing"}]
    _, malformed_reasons = _formation(
        contract, [malformed_steps, resource], {"seed"}, transformations, SNAPSHOT
    )
    assert "formation_step_invalid:0" in malformed_reasons
    assert "formation_transformation_missing:missing" in malformed_reasons


def test_resource_rate_siphon_and_potential_negative_matrix() -> None:
    contract = _contract()
    contract["protected_floors"] = {"energy": {"quantity": "1", "unit": "unit"}}
    transformations = {"edge": _edge("1")}
    assert _resources(contract, [], transformations, {}, SNAPSHOT)[0] == "unknown"
    bad_resource = _record(
        "resource",
        "resource_observation",
        "energy",
        {"coordinate": "energy", "quantity": "bad", "unit": "unit"},
    )
    assert (
        _resources(contract, [bad_resource], transformations, {"edge": Fraction(1)}, SNAPSHOT)[0]
        == "violated"
    )
    resource = deepcopy(bad_resource)
    resource["attributes"]["quantity"] = "0"
    rate = _record(
        "rate",
        "evidence",
        "rate",
        {
            "evidence_type": "rate_feasibility_witness",
            "analysis_snapshot_digest": SNAPSHOT,
            "source_refs": ["missing"],
            "transformation_refs": [],
            "feasible_flux": {"edge": "2"},
            "rate_intervals": {"edge": {"lower": "2", "upper": "1", "unit": "rate"}},
        },
    )
    siphon = _record(
        "siphon",
        "evidence",
        "siphon",
        {
            "evidence_type": "siphon_coverage_witness",
            "analysis_snapshot_digest": SNAPSHOT,
            "covered_siphons": [],
        },
    )
    profile = _record(
        "profile",
        "evidence",
        "profile",
        {
            "evidence_type": "open_system_resource_profile",
            "analysis_snapshot_digest": "wrong",
            "balance_mode": "steady_state",
            "internal_coordinates": ["energy"],
            "boundary_coordinates": ["energy"],
            "potential_weights": {},
        },
    )
    status, reasons = _resources(
        contract,
        [resource, rate, siphon, profile],
        transformations,
        {"edge": Fraction(1)},
        SNAPSHOT,
    )
    assert status == "violated"
    assert "rate_transformation_set_mismatch" in reasons
    assert "internal_boundary_coordinate_overlap" in reasons
    assert "resource_potential_coordinate_coverage_incomplete" in reasons
    supply = _record(
        "supply",
        "boundary_supply",
        "supply",
        {"coordinate": "energy", "quantity": "bad", "unit": "unit"},
    )
    assert _resources(
        contract, [resource, supply], transformations, {"edge": Fraction(1)}, SNAPSHOT
    )[1] == ["boundary_supply_invalid:energy"]


def test_raf_verification_and_independence_negative_matrix() -> None:
    contract = _contract()
    contract["target_states"] = ["target"]
    status, _ = _raf(contract, {"edge": _edge()}, {"seed"}, {}, {"seed"})
    assert status == "violated"
    status, reasons = _raf(contract, {"edge": _edge()}, {"seed"}, {"target": 1}, {"seed", "target"})
    assert status == "violated" and any("circular" in item for item in reasons)
    uncatalyzed = _edge()
    uncatalyzed["explicitly_uncatalyzed"] = True
    assert (
        _raf(contract, {"edge": uncatalyzed}, {"seed"}, {"target": 1}, {"seed", "target"})[0]
        == "satisfied"
    )

    assert _verification([])[0] == "unknown"
    overloaded = _record(
        "verifier",
        "verifier",
        "verifier",
        {
            "arrival_upper": "2",
            "service_lower": "1",
            "arrival_unit": "a",
            "service_unit": "a",
            "routing_amplification": "0",
            "independence_domain": "shared",
            "source_record_digest": "missing",
            "arrival_curve": ["2"],
            "service_curve": ["0"],
            "backlog_upper": "0",
        },
    )
    status, reasons = _verification([overloaded, deepcopy(overloaded)])
    assert status == "violated"
    assert any("overloaded" in item for item in reasons)
    assert any("reused" in item for item in reasons)
    mismatched = deepcopy(overloaded)
    mismatched["attributes"]["service_unit"] = "b"
    mismatched["subject_id"] = "verifier:mismatch"
    assert any("unit_mismatch" in item for item in _verification([mismatched])[1])
    malformed_curve = deepcopy(overloaded)
    malformed_curve["attributes"]["arrival_curve"] = "bad"
    assert any("curve_pair_invalid" in item for item in _verification([malformed_curve])[1])
    unequal_curve = deepcopy(overloaded)
    unequal_curve["attributes"]["arrival_curve"] = ["1", "2"]
    assert any("curve_grid_invalid" in item for item in _verification([unequal_curve])[1])

    assert _independence([], [])[0] == "unknown"
    observation = _record(
        "independence",
        "independence",
        "independence",
        {
            "observed_closed_boundary": True,
            "commitment_digest": "missing",
            "observer_attestation_ref": "missing",
            "infrastructure_domains": ["shared"],
        },
    )
    exposure = _record(
        "exposure",
        "exposure",
        "exposure",
        {"before_commitment": True, "artifact_digest": "sha256:" + "0" * 64},
    )
    statements = [{"payload": observation, "protected": {"key_id": "key"}}]
    status, reasons, _ = _independence(statements, [observation, exposure])
    assert status == "violated"
    assert "precommit_information_exposure_detected" in reasons


def test_evaluate_duplicate_binding_budget_and_cut_sets() -> None:
    contract = _contract()
    contract["target_states"] = ["target"]
    record = _record("duplicate", "state", "seed", {"available": True})
    statements = [
        {"payload": record, "protected": {"key_id": "one"}},
        {"payload": deepcopy(record), "protected": {"key_id": "two"}},
    ]
    evaluated = _evaluate(GENERATION, contract, statements, [], include_robustness=False)
    assert evaluated["profile"]["provenance_integrity"] == "violated"
    assert _minimal_cut_sets(contract, [record])["cut_sets"] == []
    many = [_record(str(index), "transformation", f"edge:{index}", _edge()) for index in range(21)]
    assert _minimal_cut_sets(contract, many)["status"] == "unknown_due_to_budget"


def test_exact_flux_coupling_solver_profiles() -> None:
    contract = _contract()
    assert _flux_coupling(contract, [])["status"] == "unknown_resource_profile_required"
    profile = _record(
        "profile",
        "evidence",
        "profile",
        {
            "evidence_type": "open_system_resource_profile",
            "balance_mode": "self_maintenance",
            "internal_coordinates": ["energy"],
            "boundary_coordinates": [],
            "potential_weights": {"energy": "1"},
        },
    )
    assert _flux_coupling(contract, [profile])["status"] == "unknown_steady_state_not_declared"
    profile["attributes"]["balance_mode"] = "steady_state"
    assert _flux_coupling(contract, [profile])["status"] == "unknown_empty_flux_model"
    blocked = _record(
        "blocked",
        "transformation",
        "blocked",
        {**_edge("1"), "explicitly_uncatalyzed": True},
    )
    assert _flux_coupling(contract, [profile, blocked])["blocked"] == ["blocked"]
    forward = _record(
        "forward",
        "transformation",
        "forward",
        {**_edge("1"), "explicitly_uncatalyzed": True},
    )
    reverse = _record(
        "reverse",
        "transformation",
        "reverse",
        {**_edge("-1"), "explicitly_uncatalyzed": True},
    )
    coupled = _flux_coupling(contract, [profile, forward, reverse])
    assert coupled["status"] == "complete"
    assert coupled["fully_coupled"][0]["ratio"] == "1"


def test_perturbation_invalid_suite_branches_remain_non_promoting() -> None:
    contract = _contract()
    contract["required_dimensions"] = ["provenance_integrity", "perturbation_robustness"]
    contract["perturbation_suite_refs"] = ["suite"]
    suite = _record(
        "suite-attestation",
        "evidence",
        "suite",
        {
            "evidence_type": "perturbation_suite",
            "scenarios": [],
            "acceptance_dimensions": ["provenance_integrity"],
        },
    )
    statement = {"payload": suite, "protected": {"key_id": "key"}}
    evaluated = _evaluate(GENERATION, contract, [statement], [], include_robustness=True)
    assert evaluated["profile"]["perturbation_robustness"] == "violated"
    suite["attributes"]["scenarios"] = [
        {"scenario_id": "one", "remove_subjects": [], "remove_key_ids": []}
    ]
    suite["attributes"]["acceptance_dimensions"] = []
    evaluated = _evaluate(GENERATION, contract, [statement], [], include_robustness=True)
    assert (
        "perturbation_acceptance_incomplete:suite"
        in evaluated["reasons"]["perturbation_robustness"]
    )


def test_bounded_one_safe_unfolding_is_explicitly_scoped_and_budgeted() -> None:
    contract = _contract()
    records = [
        _record("seed", "state", "seed", {"available": True}),
        _record("catalyst", "catalyst", "catalyst", {}),
        _record("left", "transformation", "left", _edge()),
        _record(
            "right",
            "transformation",
            "right",
            {**_edge(), "outputs": ["alternate"]},
        ),
    ]
    assert _bounded_one_safe_unfolding(contract, records)["status"] == (
        "unknown_profile_not_declared"
    )
    contract["scope"]["one_safe_profile"] = True
    complete = _bounded_one_safe_unfolding(contract, records)
    assert complete["status"] == "complete_bounded_state_prefix"
    assert complete["conflicts"][0]["alternatives"] == ["left", "right"]
    assert complete["unbounded_petri_net_claimed"] is False
    limited = _bounded_one_safe_unfolding(contract, records, maximum_events=1)
    assert limited["status"] == "unknown_due_to_budget"
    assert _bounded_one_safe_unfolding(contract, records, maximum_events=0)["complete"] is False
