# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy

from collective_phase_control_fabric.collective import collective_condition
from collective_phase_control_fabric.engine import analyze
from collective_phase_control_fabric.fixtures import fixture, productive_witness
from collective_phase_control_fabric.network import verified_closure
from collective_phase_control_fabric.robustness import structural_robustness
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.seed import formation_seeds
from collective_phase_control_fabric.witnesses import validate_catalysts


def _source_decision(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "source_system": "fixture",
        "source_ref": "ref:1",
        "accepted": "unknown",
        "settled": "unknown",
        "authorized": "unknown",
        "operationally_usable": "unknown",
        "executed": "unknown",
        "physical_outcome_verified": "unknown",
        "source_json_pointers": [],
        "raw_artifact_ref": "sha256:fixture",
    }
    value.update(updates)
    return value


def test_status_fields_are_independent() -> None:
    assert not validation_errors(
        "source-decision",
        _source_decision(accepted=True, settled=False, authorized=True, executed=False),
    )
    assert not validation_errors(
        "source-decision",
        _source_decision(executed=True, physical_outcome_verified=False),
    )


def test_reachable_does_not_imply_productive() -> None:
    data = fixture("reachability_without_productivity")
    report = analyze(data["contract"], data["network"])
    assert report["feasible_closure"]["reached_targets"]
    assert report["productive_witness"]["status"] == "unknown"


def test_productive_does_not_imply_maintained() -> None:
    data = fixture("productivity_without_maintenance")
    report = analyze(data["contract"], data["network"], data["productive_witness"])
    assert report["productive_witness"]["valid"] is True
    assert report["maintenance_witness"]["valid"] is None


def test_reusable_looking_does_not_imply_catalyst() -> None:
    data = fixture("verified_productive_organization")
    assert data["network"]["transformations"][0]["reusable_enablers"]
    result = validate_catalysts(data["network"], maintained=True)
    assert result.valid is None


def test_agent_or_model_count_does_not_establish_collective_independence() -> None:
    data = fixture("reachability_without_productivity")
    data["contract"]["collective_policy"]["minimum_independent_contribution_groups"] = 2
    for index in range(10):
        data["network"]["nodes"].append(
            {
                "node_id": f"agent:{index}",
                "type": "artifact",
                "available": True,
                "contribution": True,
                "model_name": f"model-{index}",
                "role_prompt": f"role-{index}",
                "lifecycle_status": "valid",
            }
        )
    result = collective_condition(data["contract"], data["network"])
    assert result["status"] == "unknown"


def test_phase_label_and_diagnostics_do_not_promote_status() -> None:
    data = fixture("reachability_without_productivity")
    baseline = analyze(data["contract"], data["network"])
    data["contract"]["phase_label"] = "real ASI proven"
    for index in range(50):
        data["network"]["nodes"].append(
            {
                "node_id": f"observation:{index}",
                "type": "observation",
                "available": True,
                "lifecycle_status": "valid",
            }
        )
    after = analyze(data["contract"], data["network"])
    assert after["phase_projection"]["ladder_level"] == baseline["phase_projection"]["ladder_level"]


def test_frontier_certificate_does_not_prove_phase() -> None:
    data = fixture("external_claim_bundle")
    data["network"]["nodes"] = [
        node
        for node in data["network"]["nodes"]
        if node.get("certificate_kind") in {None, "frontier_exceedance"}
    ]
    report = analyze(data["contract"], data["network"])
    assert report["external_claim_bundle"]["external_claim_bundle_compatible"] is False


def test_external_certificate_absence_remains_unknown() -> None:
    data = fixture("reachability_without_productivity")
    report = analyze(data["contract"], data["network"])
    assert report["external_claim_bundle"]["external_claim_bundle_compatible"] == "unknown"


def test_duplicate_mass_does_not_increase_support() -> None:
    data = fixture("reachability_without_productivity")
    duplicate = deepcopy(data["network"]["nodes"][1])
    duplicate["node_id"] = "evidence:duplicate"
    data["network"]["nodes"].append(duplicate)
    data["contract"]["initial_available_states"].append("evidence:duplicate")
    data["network"]["transformations"][0]["required_evidence"].append("evidence:duplicate")
    report = analyze(data["contract"], data["network"])
    active = {item["detector"] for item in report["false_positive_detections"] if item["blocking"]}
    assert "duplicate_mass" in active
    assert report["phase_projection"]["ladder_level"] == "L0"


def test_expired_evidence_leaves_verified_closure() -> None:
    data = fixture("reachability_without_productivity")
    data["network"]["nodes"][1]["lifecycle_status"] = "expired"
    report = analyze(data["contract"], data["network"])
    assert "state:target" not in report["verified_enabling_closure"]["available_states"]


def test_seed_search_is_bounded_and_approximate() -> None:
    data = fixture("reachability_without_productivity")
    network = data["network"]
    edge = network["transformations"][0]
    edge["required_inputs"] = [f"missing:{index:02d}" for index in range(17)]
    closure = verified_closure(data["contract"], network)
    seeds = formation_seeds(data["contract"], network, closure)
    assert len(seeds) <= 3
    assert seeds[0]["solution_class"] == "approximate"
    assert seeds[0]["search_limits"]["beam_width"] == 32


def test_large_cut_set_is_never_reported_as_proof() -> None:
    data = fixture("reachability_without_productivity")
    edge = data["network"]["transformations"][0]
    for index in range(13):
        node_id = f"support:{index:02d}"
        data["network"]["nodes"].append(
            {
                "node_id": node_id,
                "type": "artifact",
                "available": True,
                "lifecycle_status": "valid",
                "source_system": "fixture",
            }
        )
        data["contract"]["initial_available_states"].append(node_id)
        edge["required_inputs"].append(node_id)
    verified = verified_closure(data["contract"], data["network"])
    report = structural_robustness(data["contract"], data["network"], verified)
    assert report["minimal_cut_solution_class"] == "heuristic_not_proof"
    assert all(cut["solution_class"] == "heuristic_not_proof" for cut in report["minimal_cuts"])


def test_proxy_only_and_structural_improvement_are_not_performance_claims() -> None:
    data = fixture("verified_productive_organization")
    data["contract"]["state_coordinate_registry"]["target_units"]["proxy_only"] = True
    report = analyze(data["contract"], data["network"], productive_witness())
    assert report["productive_witness"]["valid"] is False
    assert all(
        "performance" not in status for status in report["phase_projection"]["progress_classes"]
    )
