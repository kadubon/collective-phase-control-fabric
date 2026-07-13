# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path

import pytest

from collective_phase_control_fabric.canonical import digest_bytes, load_json, write_canonical
from collective_phase_control_fabric.coordination import independence_exposure_ledger
from collective_phase_control_fabric.demos import bootstrap_demo, demo_documents
from collective_phase_control_fabric.planner import (
    MAXIMIZE,
    _contingent_dominates,
    _v2_branch_projection,
    _v2_filter,
    exact_number_like,
    plan_contingent_actions,
)
from collective_phase_control_fabric.process import run_process
from collective_phase_control_fabric.provenance import import_source
from collective_phase_control_fabric.science import (
    exact_nullspace,
    independent_support_core,
    validate_coordinate_invariant,
    validate_formation_sequence,
    validate_generative_catalysis,
    validate_rate_intervals,
    validate_resource_potential,
    verification_network,
)
from collective_phase_control_fabric.workspace import (
    doctor,
    inspect_workspace,
    prepare_step,
    run_step,
)


def _branch(
    *, safe: str = "true", targets: list[dict[str, str]] | None = None
) -> dict[str, object]:
    return {
        "receipt_schema_ref": "action-receipt@0.2.0",
        "source_pointers": ["/artifacts/0"] if targets else [],
        "projection_targets": targets or [],
        "debt": [],
        "rollback_obligations": [],
        "resource_upper_bounds": {"local_io": {"quantity": "1", "unit": "operation"}},
        "protected_floor_status": safe,
        "authority_status": "true",
        "hazard_status": "true",
        "forecast": {"target_path_unlock_count": 1},
    }


def _action(argv: list[str]) -> dict[str, object]:
    return {
        "schema_version": "0.2.0",
        "action_id": "action:receipt-bound",
        "purpose": "Import one emitted formation witness.",
        "priority_class": 1,
        "adapter": "controlled-test-process",
        "adapter_capability_ref": "capability:controlled-test-process",
        "operation": "emit_receipt",
        "exact_argv": argv,
        "effect_class": "validate",
        "input_refs": [],
        "required_authority_refs": [],
        "resource_upper_bounds": {"local_io": {"quantity": "1", "unit": "operation"}},
        "expires_at": "2027-01-01T00:00:00Z",
        "outcomes": {
            "success": _branch(
                targets=[
                    {
                        "source_pointer": "/artifacts/0",
                        "target_schema": "formation-sequence-witness@0.2.0",
                    }
                ]
            ),
            "partial": _branch(),
            "failure": _branch(),
            "timeout": _branch(),
        },
    }


def _import_controlled_capability(root: Path, source_path: Path) -> None:
    capability = {
        "schema_version": "0.2.0",
        "capability_id": "capability:controlled-test-process",
        "adapter": "controlled-test-process",
        "expires_at": "2027-01-01T00:00:00Z",
        "operations": [
            {
                "operation": "emit_receipt",
                "executable_digest": digest_bytes(Path(sys.executable).read_bytes()),
                "effect_classes": ["validate"],
                "receipt_schema_refs": ["action-receipt@0.2.0"],
                "projection_mappings": [
                    {
                        "source_pointer": "/artifacts/0",
                        "target_schema": "formation-sequence-witness@0.2.0",
                    }
                ],
            }
        ],
    }
    write_canonical(source_path, capability)
    result = import_source(
        source_path,
        root,
        "controlled-test-registry",
        "adapter-capability@0.2.0",
        apply=True,
    )
    assert result["applied"] is True


def test_spoofed_receipt_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "spoofed"
    bootstrap_demo(root, "spoofed-receipt-rejection")
    report = doctor(root, strict=True)
    assert report["command_status"] == "failed"
    assert any(error["code"] == "digest_mismatch" for error in report["errors"])
    assert inspect_workspace(root)["phase_projection"]["ladder_level"] is None


def test_external_bundle_does_not_promote_structural_ladder(tmp_path: Path) -> None:
    root = tmp_path / "external"
    bootstrap_demo(root, "external-l6-l8-certificate-import")
    report = inspect_workspace(root)
    assert report["phase_projection"]["ladder_level"] == "L1"
    assert report["external_claim_bundle"]["external_claim_bundle_compatible"] is True


def test_native_action_projects_only_raw_receipt_artifact(tmp_path: Path) -> None:
    root = tmp_path / "native"
    bootstrap_demo(root)
    witness = {
        "schema_version": "0.2.0",
        "witness_id": "formation:emitted",
        "layers": [["transform:produce"]],
        "initial_coordinate_balances": {"protected_resource": "1", "target_units": "0"},
    }
    output = {
        "schema_version": "0.2.0",
        "action_id": "action:receipt-bound",
        "outcome": "success",
        "artifacts": [witness],
    }
    argv = [sys.executable, "-c", f"import json; print(json.dumps({output!r}))"]
    action_path = tmp_path / "native-action.json"
    _import_controlled_capability(root, tmp_path / "native-capability.json")
    write_canonical(action_path, _action(argv))
    assert (
        import_source(
            action_path,
            root,
            "controlled-test-registry",
            "action@0.2.0",
            apply=True,
        )["applied"]
        is True
    )
    result = run_step(root, "action:receipt-bound", "run")
    assert result["command_status"] == "ok"
    assert result["source_backed_post_state"] == "true"
    projected = list((root / "witnesses").glob("*.json"))
    assert len(projected) == 1
    assert load_json(projected[0]) == witness
    assert doctor(root, strict=True)["command_status"] == "ok"


def test_boolean_only_output_cannot_promote(tmp_path: Path) -> None:
    root = tmp_path / "boolean"
    bootstrap_demo(root)
    output = {"action_id": "action:receipt-bound", "output_contract_valid": True}
    argv = [sys.executable, "-c", f"import json; print(json.dumps({output!r}))"]
    action_path = tmp_path / "boolean-action.json"
    _import_controlled_capability(root, tmp_path / "boolean-capability.json")
    write_canonical(action_path, _action(argv))
    import_source(
        action_path,
        root,
        "controlled-test-registry",
        "action@0.2.0",
        apply=True,
    )
    result = run_step(root, "action:receipt-bound", "run")
    assert result["command_status"] == "failed"
    assert result["source_backed_post_state"] == "false"
    assert not list((root / "witnesses").glob("*.json"))


def test_prepared_action_rejects_concurrent_state_change(tmp_path: Path) -> None:
    root = tmp_path / "compare-and-swap"
    bootstrap_demo(root)
    action = _action([sys.executable, "--version"])
    action_path = tmp_path / "cas-action.json"
    _import_controlled_capability(root, tmp_path / "cas-capability.json")
    write_canonical(action_path, action)
    import_source(
        action_path,
        root,
        "controlled-test-registry",
        "action@0.2.0",
        apply=True,
    )
    assert prepare_step(root, "action:receipt-bound")["executed"] is False
    contract = load_json(root / "contract.json")
    assert isinstance(contract, dict)
    contract["concurrent_change"] = True
    write_canonical(root / "contract.json", contract)
    result = run_step(root, "action:receipt-bound", "run")
    assert result["failure_code"] == "concurrent_state_comparison_failed"
    assert result["transition_written"] is False


def test_every_outcome_branch_must_be_safe() -> None:
    contract, _, _ = demo_documents("orientation-only-reachability")
    action = _action([sys.executable, "--version"])
    action["outcomes"]["timeout"] = _branch(safe="unknown")
    plan = plan_contingent_actions([action], contract, {}, [])
    assert plan["primary_action"] is None
    assert plan["rejected_actions"][0]["reason"] == "unsafe_outcome_branch"
    contract["control_policy"]["planning_horizon"] = 2
    action["outcomes"]["timeout"] = _branch()
    plan = plan_contingent_actions([action], contract, {}, [])
    assert plan["solution_class"] == "approximate"


def test_contingent_planner_fail_closed_filter_matrix() -> None:
    contract, _, _ = demo_documents("orientation-only-reachability")
    valid = _action([sys.executable, "--version"])
    cases = [
        ({**valid, "schema_version": "0.1.0"}, "unsupported_version"),
        ({**valid, "effect_class": "bad"}, "unknown_effect_class"),
        ({**valid, "effect_class": "external_effect"}, "external_effect"),
        ({**valid, "exact_argv": []}, "unbound_repair_not_executable"),
        ({**valid, "outcomes": {}}, "four_outcome_contract_required"),
    ]
    for action, reason in cases:
        assert _v2_filter(action, contract) == reason
    malformed = _v2_branch_projection(None)
    assert malformed["safe"] is False
    unknown_fields = _branch()
    unknown_fields["debt"] = None
    unknown_fields["rollback_obligations"] = None
    unknown_fields["forecast"] = []
    assert _v2_branch_projection(unknown_fields)["safe"] is False
    bad_envelope = deepcopy(contract)
    bad_envelope["resource_envelope"] = []
    assert _v2_filter(valid, bad_envelope) == "resource_envelope_violation"
    bad_bounds = deepcopy(valid)
    bad_bounds["outcomes"]["success"]["resource_upper_bounds"] = []
    assert _v2_filter(bad_bounds, contract) == "resource_envelope_violation"
    missing_coordinate = deepcopy(valid)
    missing_coordinate["outcomes"]["success"]["resource_upper_bounds"] = {
        "unknown": {"quantity": "1", "unit": "x"}
    }
    assert _v2_filter(missing_coordinate, contract) == "resource_envelope_violation"
    wrong_unit = deepcopy(valid)
    wrong_unit["outcomes"]["success"]["resource_upper_bounds"] = {
        "local_io": {"quantity": "1", "unit": "wrong"}
    }
    assert _v2_filter(wrong_unit, contract) == "resource_envelope_violation"
    bad_quantity = deepcopy(valid)
    bad_quantity["outcomes"]["success"]["resource_upper_bounds"] = {
        "local_io": {"quantity": [], "unit": "operation"}
    }
    assert _v2_filter(bad_quantity, contract) == "resource_envelope_violation"
    with pytest.raises(ValueError):
        exact_number_like(True)


def test_contingent_dominance_stagnation_priority_and_beam() -> None:
    contract, _, _ = demo_documents("orientation-only-reachability")
    first = _action([sys.executable, "--version"])
    second = deepcopy(first)
    second["action_id"] = "action:second"
    second["priority_class"] = 2
    for branch in second["outcomes"].values():
        branch["forecast"] = {field: 0 for field in MAXIMIZE}
    plan = plan_contingent_actions([first, second], contract, {}, [])
    assert plan["primary_action"]["action_id"] == "action:receipt-bound"
    assert plan["deferred_actions"][0]["action_id"] == "action:second"
    left = plan["primary_action"]["branch_projections"]
    right_action = deepcopy(first)
    for branch in right_action["outcomes"].values():
        branch["forecast"] = {field: 0 for field in MAXIMIZE}
    right = {
        name: _v2_branch_projection(right_action["outcomes"][name])
        for name in ("success", "partial", "failure", "timeout")
    }
    assert _contingent_dominates(left, right) is True
    assert _contingent_dominates(right, left) is False
    signature = plan["primary_action"]["action_signature"]
    stagnant = plan_contingent_actions(
        [first], contract, {}, [{"action_signature": signature, "progress": "no_progress"}]
    )
    assert stagnant["rejected_actions"][0]["reason"] == "stagnated"
    contract["control_policy"]["planning_horizon"] = 3
    second["priority_class"] = 1
    beam = plan_contingent_actions([first, second], contract, {}, [])
    assert beam["beam_sequences"]
    assert beam["one_step_execution_limit"] == 1


def test_exact_rational_invariants_and_causal_prefix() -> None:
    assert exact_nullspace([["1", "1"]]) == [["-1", "1"]]
    contract, network, _ = demo_documents("orientation-only-reachability")
    invariant = {
        "kind": "p_semiflow_analog",
        "coefficients": {"protected_resource": "2", "target_units": "1"},
    }
    assert validate_coordinate_invariant(contract, network, invariant)["valid"] is True
    formation = {
        "layers": [["transform:produce"]],
        "initial_coordinate_balances": {"protected_resource": "0", "target_units": "0"},
    }
    result = validate_formation_sequence(contract, network, formation)
    assert result["valid"] is False
    assert any("prefix_floor_violation" in reason for reason in result["reasons"])
    network["transformations"][0]["required_inputs"] = ["state:target"]
    assert validate_formation_sequence(contract, network, formation)["valid"] is False


def test_self_dependent_catalyst_and_rate_fail_closed() -> None:
    contract, network, _ = demo_documents("orientation-only-reachability")
    network["transformations"][0]["required_catalysts"] = ["state:target"]
    witness = {
        "food_states": [],
        "catalyst_bindings": {"transform:produce": ["state:target"]},
    }
    result = validate_generative_catalysis(contract, network, witness)
    assert result["valid"] is False
    rate = {
        "observation_window": {"start": "2025-02-01T00:00:00Z", "end": "2025-01-01T00:00:00Z"},
        "intervals": [
            {"transformation_id": "transform:produce", "lower": "2", "upper": "1", "unit": "x/hour"}
        ],
        "source_refs": [],
    }
    assert validate_rate_intervals(rate)["valid"] is False


def test_positive_closed_resource_cycle_requires_supply() -> None:
    _, network, _ = demo_documents("orientation-only-reachability")
    reverse = deepcopy(network["transformations"][0])
    reverse.update(
        {
            "transformation_id": "transform:return",
            "required_inputs": ["state:target"],
            "produced_outputs": ["state:input"],
            "consumed_coordinates": {},
            "produced_coordinates": {"target_units": {"quantity": "1", "unit": "artifact"}},
        }
    )
    network["transformations"].append(reverse)
    witness = {"coordinate_weights": {"target_units": "1"}, "external_supply_refs": []}
    result = validate_resource_potential(network, witness)
    assert result["valid"] is False
    assert result["thermodynamic_proof"] is False


def test_support_dedup_verification_overload_and_exposure() -> None:
    contract, network, _ = demo_documents("orientation-only-reachability")
    contract["support_core_policy"]["minimum_independent_support_groups"] = 2
    duplicate = deepcopy(network["nodes"][1])
    duplicate["node_id"] = "evidence:duplicate"
    duplicate["independence_group"] = "claimed-other-group"
    network["nodes"].append(duplicate)
    network["transformations"][0]["support_refs"].append("evidence:duplicate")
    assert independent_support_core(contract, network)["status"] == "false"
    queue = {
        "stages": [
            {
                "stage_id": "review",
                "arrival_upper": "2",
                "service_lower": "1",
            }
        ],
        "stationarity_established": False,
        "means_established": False,
    }
    checked = verification_network(queue)
    assert checked["candidate_fan_out_allowed"] is False
    assert checked["little_law"]["eligible"] is False
    exposure = independence_exposure_ledger(
        [
            {
                "event_id": "event:consume",
                "event_type": "consume",
                "independence_group": "group:a",
                "artifact_digest": "sha256:shared",
            },
            {"event_id": "event:commit", "event_type": "commit", "independence_group": "group:a"},
        ]
    )
    assert exposure["status"] == "false"
    assert exposure["retroactive_independence_allowed"] is False


def test_stream_capture_bound_is_enforced_during_drain(tmp_path: Path) -> None:
    receipt = run_process(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 2000000)"],
        tmp_path,
        tmp_path,
        stdout_limit=1024,
    )
    assert receipt["stdout_truncated"] is True
    assert receipt["stdout_byte_count_captured"] == 1024
    assert receipt["stdout_byte_count_total"] == 2_000_000
    assert receipt["maximum_retained_output_bytes"] == 1_049_600
