# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy

from collective_phase_control_fabric.barrier import build_barrier_vector, dominates
from collective_phase_control_fabric.collective import collective_condition, external_claim_bundle
from collective_phase_control_fabric.deadlock import regeneration_deadlocks
from collective_phase_control_fabric.detectors import detect_false_positives, has_blocking_detection
from collective_phase_control_fabric.fixtures import fixture
from collective_phase_control_fabric.metrics import critical_path, verification_load
from collective_phase_control_fabric.network import verified_closure
from collective_phase_control_fabric.robustness import structural_robustness
from collective_phase_control_fabric.seed import formation_seeds
from collective_phase_control_fabric.witnesses import validate_maintenance_witness


def test_verification_load_unknown_and_below_capacity() -> None:
    data = fixture("reachability_without_productivity")
    assert verification_load(data["contract"])["status"] == "unknown"
    data["contract"]["external_measurement_policy"] = {
        "verification_load": {
            "eligible_candidate_arrival_rate": "1",
            "verifier_service_rate": "2",
            "time_unit": "hour",
            "observation_window": "P1D",
            "source_refs": ["fixture:load"],
        }
    }
    report = verification_load(data["contract"])
    assert report["rho"] == "1/2"
    assert report["blockers"] == []
    data["contract"]["external_measurement_policy"]["verification_load"][
        "verifier_service_rate"
    ] = "0"
    assert verification_load(data["contract"])["status"] == "unknown"


def test_critical_path_unknown_parallel_and_cycle() -> None:
    data = fixture("reachability_without_productivity")
    contract = data["contract"]
    contract["task_structure"] = "parallel_decomposable"
    report = critical_path(contract)
    assert report["critical_path"] == ["work:produce", "work:verify"]
    assert report["parallel_fan_out_allowed"] is True
    contract["work_graph"]["tasks"][0].pop("duration")
    assert critical_path(contract)["status"] == "unknown"
    contract = fixture("reachability_without_productivity")["contract"]
    contract["work_graph"]["dependencies"].append(
        {"before": "work:verify", "after": "work:produce"}
    )
    assert critical_path(contract)["reason"] == "work_graph_not_acyclic"


def test_maintenance_requires_every_field() -> None:
    assert validate_maintenance_witness(None).valid is None
    witness = {"validity_horizon": "P1D"}
    result = validate_maintenance_witness(witness)
    assert result.valid is False
    assert "renewal_obligations_missing" in result.reasons


def test_barrier_partial_order() -> None:
    data = fixture("reachability_without_productivity")
    verified = verified_closure(data["contract"], data["network"])
    collective = collective_condition(data["contract"], data["network"])
    before = build_barrier_vector(verified, [], [], [], "unknown", "unknown", collective)
    after = deepcopy(before)
    after["coordinates"]["productivity"]["blocker_ids"] = []
    assert dominates(after, before)
    after["coordinates"]["authority"]["blocker_ids"] = ["new"]
    assert not dominates(after, before)


def test_exact_structural_sensitivity_and_declared_path_count() -> None:
    data = fixture("reachability_without_productivity")
    verified = verified_closure(data["contract"], data["network"])
    report = structural_robustness(data["contract"], data["network"], verified)
    assert report["independent_target_path_count"] == 1
    assert report["minimal_cut_solution_class"] == "exact"
    assert any(item["lost_targets"] for item in report["single_transformation_removal_sensitivity"])


def test_nonblocking_detector_results_are_complete() -> None:
    data = fixture("reachability_without_productivity")
    verified = verified_closure(data["contract"], data["network"])
    results = detect_false_positives(data["contract"], data["network"], verified, None)
    assert len(results) == 7
    assert not has_blocking_detection(results)


def test_scc_conservative_deadlock() -> None:
    data = fixture("reachability_without_productivity")
    contract = data["contract"]
    network = data["network"]
    contract["initial_available_states"] = ["evidence:source", "report:verifier"]
    contract["target_paths"][0]["required_states"] = ["state:a", "state:b"]
    network["nodes"].extend(
        [
            {
                "node_id": "state:a",
                "type": "artifact",
                "available": False,
                "lifecycle_status": "valid",
            },
            {
                "node_id": "state:b",
                "type": "artifact",
                "available": False,
                "lifecycle_status": "valid",
            },
        ]
    )
    base = network["transformations"][0]
    first = deepcopy(base)
    first.update(
        {
            "transformation_id": "produce:a",
            "required_inputs": ["state:b"],
            "produced_outputs": ["state:a"],
        }
    )
    second = deepcopy(base)
    second.update(
        {
            "transformation_id": "produce:b",
            "required_inputs": ["state:a"],
            "produced_outputs": ["state:b"],
        }
    )
    network["transformations"] = [first, second]
    verified = verified_closure(contract, network)
    deadlocks = regeneration_deadlocks(contract, network, verified)
    assert any(item["exactness"] == "scc_conservative" for item in deadlocks)


def test_exact_seed_for_absent_atom() -> None:
    data = fixture("regeneration_deadlock")
    verified = verified_closure(data["contract"], data["network"])
    seeds = formation_seeds(data["contract"], data["network"], verified)
    assert seeds
    assert seeds[0]["solution_class"] == "exact"


def test_external_bundle_false_for_failed_collective() -> None:
    data = fixture("external_claim_bundle")
    data["contract"]["collective_policy"]["minimum_independent_contribution_groups"] = 2
    collective = collective_condition(data["contract"], data["network"])
    report = external_claim_bundle(data["contract"], data["network"], collective)
    assert report["external_claim_bundle_compatible"] is False
