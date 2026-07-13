# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collective_phase_control_fabric.canonical import digest_bytes, digest_v3_json, write_canonical
from collective_phase_control_fabric.execution_v3 import run_action_v3
from collective_phase_control_fabric.generation import GenerationStore
from collective_phase_control_fabric.planner_v3 import _eligible
from collective_phase_control_fabric.science_v3 import (
    acceleration_evidence,
    effective_independence,
    perturbation_replay_v3,
    structural_closure,
    support_core,
    validate_formation,
    validate_generalized_raf,
    validate_organization,
    validate_rate_feasibility,
    validate_resource_accounting,
    validate_siphon_coverage,
    validate_verification_network,
)
from collective_phase_control_fabric.trust import signable_payload, verify_pinned_signature
from collective_phase_control_fabric.workspace_v3 import (
    advance_time_v3,
    doctor_v3,
    import_source_v3,
    import_trial_v3,
    inspect_source_v3,
    inspect_trial_v3,
    migrate_workspace_v3,
    onboard_agent_v3,
    rebuild_projections_v3,
    scaffold_contract,
    validate_trust_policy,
    workspace_status_v3,
)
from tests.test_v3 import (
    EPOCH,
    SCOPE,
    _contract,
    _import,
    _key_material,
    _scientific_documents,
    _signed,
    _workspace,
)


def test_v3_workspace_command_branches(tmp_path: Path) -> None:
    root, private, policy = _workspace(tmp_path)
    trust_path = tmp_path / "trust-copy.json"
    write_canonical(trust_path, policy)
    assert validate_trust_policy(trust_path)["command_status"] == "ok"
    duplicate = deepcopy(policy)
    duplicate["principals"].append(deepcopy(duplicate["principals"][0]))
    duplicate_path = tmp_path / "trust-duplicate.json"
    write_canonical(duplicate_path, duplicate)
    assert validate_trust_policy(duplicate_path)["failure_code"] == "trust_policy_invalid"

    draft = tmp_path / "draft"
    assert scaffold_contract(draft, "structural")["command_status"] == "ok"
    assert scaffold_contract(draft, "structural")["failure_code"] == "output_already_exists"

    status = workspace_status_v3(root)
    assert status["execution_allowed"] is True
    assert onboard_agent_v3(root)["measured_acceleration_requires_external_trial"] is True
    assert doctor_v3(root, quick=True)["execution_allowed"] is False
    assert rebuild_projections_v3(root)["projection_count"] == 0

    dry = advance_time_v3(root, "2026-01-16T00:00:00Z", apply=False)
    assert dry["failure_code"] == "apply_required"
    assert advance_time_v3(root, "2025-12-01T00:00:00Z", apply=True)["failure_code"] == (
        "analysis_epoch_rollback_rejected"
    )
    advanced = advance_time_v3(root, "2026-01-16T00:00:00Z", apply=True)
    assert advanced["command_status"] == "ok"
    assert doctor_v3(root)["command_status"] == "ok"

    network = _scientific_documents()["transformation-network"]
    report = tmp_path / "network.json"
    write_canonical(report, _signed(private, network, "transformation-network@0.3.0"))
    inspected = inspect_source_v3(
        report,
        trust_path,
        "fixture",
        "transformation-network@0.3.0",
        evaluation_time="2026-01-16T00:00:00Z",
        expected_scope=SCOPE,
    )
    assert inspected["command_status"] == "ok"
    assert (
        import_source_v3(
            report,
            root,
            "fixture",
            "transformation-network@0.3.0",
            apply=False,
        )["failure_code"]
        == "apply_required"
    )

    attacker = Ed25519PrivateKey.generate()
    spoof = tmp_path / "spoof.json"
    write_canonical(spoof, _signed(attacker, network, "transformation-network@0.3.0"))
    spoofed = import_source_v3(
        spoof,
        root,
        "fixture",
        "transformation-network@0.3.0",
        apply=True,
    )
    assert spoofed["failure_code"] == "source_signature_invalid"

    oversized = deepcopy(network)
    oversized["extensions"] = {"org.example.padding": "x" * 1_100_000}
    oversized_path = tmp_path / "oversized.json"
    write_canonical(
        oversized_path,
        _signed(private, oversized, "transformation-network@0.3.0"),
    )
    assert (
        import_source_v3(
            oversized_path,
            root,
            "fixture",
            "transformation-network@0.3.0",
            apply=True,
        )["failure_code"]
        == "analysis_limit_exceeded"
    )


def test_v3_process_bound_success_projection(tmp_path: Path) -> None:
    root, private, _ = _workspace(tmp_path)
    documents = _scientific_documents()
    for name in ("transformation-network", "state-marking"):
        _import(tmp_path, root, private, name, documents[name])
    observation = {
        "schema_version": "0.3.0",
        "observation_id": "observation:runtime",
        "value": "bounded local result",
        "source_refs": ["evidence"],
    }
    script = (
        "import json;print(json.dumps("
        + repr(
            {
                "schema_version": "0.3.0",
                "action_id": "action:success",
                "outcome": "success",
                "observation": observation,
            }
        )
        + "))"
    )
    executable = Path(sys.executable).resolve()
    projection = {
        "source_pointer": "/observation",
        "target_schema": "adapter-observation@0.3.0",
    }
    branch = {
        "must_add": [],
        "may_add": ["target"],
        "must_remove": [],
        "may_remove": [],
        "resource_intervals": {"resource": {"lower": "0", "upper": "0", "unit": "token"}},
        "debt": [],
        "rollback_obligations": [],
        "projection_possibilities": [projection],
    }
    effect = {
        "schema_version": "0.3.0",
        "effect_id": "effect:success",
        "branches": {
            name: deepcopy(branch) for name in ("success", "partial", "failure", "timeout")
        },
    }
    capability = {
        "schema_version": "0.3.0",
        "capability_id": "capability:success",
        "adapter": "fixture",
        "operation": "success",
        "effect_class": "inspect",
        "executable": str(executable),
        "executable_digest": digest_bytes(executable.read_bytes()),
        "argv_prefix": [str(executable), "-c", script],
        "output_schema_ref": "adapter-output@0.3.0",
        "outcome_selector": {
            "source_pointer": "/outcome",
            "mapping": {
                "success": "success",
                "partial": "partial",
                "failure": "failure",
                "timeout": "timeout",
            },
        },
        "branch_effect_ref": "effect:success",
    }
    action = {
        "schema_version": "0.3.0",
        "action_id": "action:success",
        "capability_ref": "capability:success",
        "arguments": [],
        "input_refs": ["seed"],
        "required_authority_refs": ["authority"],
        "required_hazard_refs": [],
        "expires_at": "2026-12-31T00:00:00Z",
        "priority_class": 1,
    }
    for name, value in (
        ("branch-effect-contract", effect),
        ("adapter-capability", capability),
        ("action", action),
    ):
        _import(tmp_path, root, private, name, value)
    assert run_action_v3(root, "action:success", apply=False)["failure_code"] == "apply_required"
    assert run_action_v3(root, "action:missing", apply=True)["failure_code"] == (
        "action_not_currently_safe_or_selected"
    )
    result = run_action_v3(root, "action:success", apply=True)
    assert result["outcome"] == "success", result
    assert result["source_backed_post_state"] == "true"
    assert doctor_v3(root)["command_status"] == "ok"


def test_v3_recomputed_projection_tamper_and_doctor_findings(tmp_path: Path) -> None:
    root, private, _ = _workspace(tmp_path)
    network = _scientific_documents()["transformation-network"]
    _import(tmp_path, root, private, "transformation-network", network)
    store = GenerationStore(root)
    manifest = store.load_manifest()
    manifest["projections"][0]["object_digest"] = "sha256:" + "9" * 64
    committed = store.commit(manifest, expected_current=store.current_id())
    assert committed["command_status"] == "ok"
    rebuilt = rebuild_projections_v3(root)
    assert rebuilt["failure_code"] == "projection_rebuild_failed"
    audit = doctor_v3(root)
    codes = {item["code"] for item in audit["errors"]}
    assert "cas_digest_invalid" in codes
    assert "projection_not_source_backed" in codes


def test_v3_trial_inspect_and_import(tmp_path: Path) -> None:
    root, private, _ = _workspace(tmp_path)
    network = _scientific_documents()["transformation-network"]
    _import(tmp_path, root, private, "transformation-network", network)
    protocol = {
        "schema_version": "0.3.0",
        "protocol_id": "protocol:test",
        "registered_at": "2026-01-01T00:00:00Z",
        "target_refs": ["target"],
        "comparison": "external comparison",
        "assignment": "external assignment",
        "observation_window": {
            "start": "2026-01-02T00:00:00Z",
            "end": "2026-01-12T00:00:00Z",
        },
        "outcomes": [{"metric": "duration", "direction": "minimize", "unit": "second"}],
        "quality_floors": {},
        "stopping_rule": "external fixed rule",
        "missing_data_policy": "external missing-data policy",
        "analysis_method": "external interval method",
        "evaluator_key_id": "key:test",
        "source_refs": ["evidence"],
    }
    signed_protocol = _signed(private, protocol, "measurement-protocol@0.3.0")
    protocol_path = tmp_path / "protocol.json"
    write_canonical(protocol_path, signed_protocol)
    assert (
        import_source_v3(
            protocol_path,
            root,
            "fixture",
            "measurement-protocol@0.3.0",
            apply=True,
        )["command_status"]
        == "ok"
    )
    result = {
        "schema_version": "0.3.0",
        "result_id": "result:inspect",
        "protocol_digest": digest_v3_json(signed_protocol),
        "dataset_digest": "sha256:" + "4" * 64,
        "analysis_executable_digest": "sha256:" + "5" * 64,
        "completed_at": "2026-01-13T00:00:00Z",
        "effect_intervals": [
            {
                "metric": "duration",
                "direction": "minimize",
                "lower": "-1",
                "upper": "1",
                "unit": "second",
            }
        ],
        "quality_intervals": [],
        "time_uniform": True,
        "assumptions": ["external assumptions"],
        "source_refs": ["evidence"],
        "evaluator_key_id": "key:test",
    }
    result_path = tmp_path / "result.json"
    write_canonical(result_path, _signed(private, result, "trial-result-certificate@0.3.0"))
    assert inspect_trial_v3(result_path, root)["command_status"] == "ok"
    assert import_trial_v3(result_path, root, apply=False)["failure_code"] == "apply_required"
    assert import_trial_v3(result_path, root, apply=True)["command_status"] == "ok"

    unknown = deepcopy(result)
    unknown["evaluator_key_id"] = "key:unknown"
    unknown_path = tmp_path / "result-unknown.json"
    write_canonical(
        unknown_path,
        _signed(private, unknown, "trial-result-certificate@0.3.0"),
    )
    assert inspect_trial_v3(unknown_path, root)["failure_code"] == (
        "trusted_evaluator_source_system_missing"
    )


def test_v3_planner_filter_failures_are_conservative() -> None:
    contract = _contract()
    state = {
        "states": {"authority", "seed"},
        "resources": {"resource": 10},
        "units": {"resource": "token"},
    }
    branch = {
        "must_add": [],
        "may_add": [],
        "must_remove": [],
        "may_remove": [],
        "resource_intervals": {"resource": {"lower": "0", "upper": "0", "unit": "token"}},
        "debt": [],
        "rollback_obligations": [],
        "projection_possibilities": [],
    }
    effect = {
        "effect_id": "effect:test",
        "branches": {
            name: deepcopy(branch) for name in ("success", "partial", "failure", "timeout")
        },
    }
    capability = {"capability_id": "cap:test", "branch_effect_ref": "effect:test"}
    base = {
        "action_id": "action:test",
        "capability_ref": "cap:test",
        "input_refs": ["seed"],
        "required_authority_refs": ["authority"],
        "required_hazard_refs": [],
        "expires_at": "2026-12-31T00:00:00Z",
    }
    eligible, rejected = _eligible(
        [base], {"cap:test": capability}, {"effect:test": effect}, state, contract
    )
    assert len(eligible) == 1 and not rejected

    variants = []
    missing_input = deepcopy(base)
    missing_input["action_id"] = "action:missing-input"
    missing_input["input_refs"] = ["missing"]
    variants.append(missing_input)
    expired = deepcopy(base)
    expired["action_id"] = "action:expired"
    expired["expires_at"] = "2025-01-01T00:00:00Z"
    variants.append(expired)
    unknown_capability = deepcopy(base)
    unknown_capability["action_id"] = "action:no-capability"
    unknown_capability["capability_ref"] = "missing"
    variants.append(unknown_capability)
    bad_effect = deepcopy(effect)
    bad_effect["branches"]["failure"]["may_remove"] = ["authority"]
    bad_effect["branches"]["timeout"]["resource_intervals"]["resource"]["unit"] = "second"
    eligible, rejected = _eligible(
        [*variants, base],
        {"cap:test": capability},
        {"effect:test": bad_effect},
        state,
        contract,
    )
    assert not eligible
    reasons = {reason for item in rejected for reason in item["reasons"]}
    assert "action_inputs_unavailable" in reasons
    assert "action_expired" in reasons
    assert "signed_capability_missing" in reasons
    assert "unsafe_branch:failure" in reasons
    assert "unsafe_branch:timeout" in reasons


def test_pinned_key_failure_coordinates() -> None:
    private, policy = _key_material()
    base = {"schema_version": "0.3.0", "scope": SCOPE}
    signed = _signed(private, base, "artifact@0.3.0")
    unsigned = deepcopy(base)
    assert (
        verify_pinned_signature(
            unsigned,
            policy,
            schema_ref="artifact@0.3.0",
            source_system="fixture",
            role="source",
            evaluation_time=EPOCH,
        )["status"]
        == "false"
    )
    wrong_source = verify_pinned_signature(
        signed,
        policy,
        schema_ref="artifact@0.3.0",
        source_system="wrong",
        role="wrong",
        evaluation_time=EPOCH,
    )
    assert "source_system_not_authorized" in wrong_source["reasons"]
    assert "schema_not_authorized" in wrong_source["reasons"]
    assert "role_not_authorized" in wrong_source["reasons"]

    revoked = deepcopy(policy)
    revoked["principals"][0]["revoked"] = True
    assert (
        "pinned_key_revoked"
        in verify_pinned_signature(
            signed,
            revoked,
            schema_ref="artifact@0.3.0",
            source_system="fixture",
            role="source",
            evaluation_time=EPOCH,
        )["reasons"]
    )

    malformed = deepcopy(signed)
    malformed["signature"]["signature_base64"] = "not-base64"
    malformed["signature"]["payload_digest"] = "sha256:" + "0" * 64
    failures = verify_pinned_signature(
        malformed,
        policy,
        schema_ref="artifact@0.3.0",
        source_system="fixture",
        role="source",
        evaluation_time="invalid",
    )["reasons"]
    assert "key_or_signature_time_invalid" in failures
    assert "signed_payload_digest_mismatch" in failures
    assert "ed25519_signature_invalid" in failures

    evaluator = deepcopy(base)
    evaluator["evaluator_key_id"] = "key:other"
    evaluator_signed = _signed(private, evaluator, "artifact@0.3.0")
    assert (
        "evaluator_identity_signature_mismatch"
        in verify_pinned_signature(
            evaluator_signed,
            policy,
            schema_ref="artifact@0.3.0",
            source_system="fixture",
            role="evaluator",
            evaluation_time=EPOCH,
        )["reasons"]
    )


def test_v3_science_negative_and_unknown_branches() -> None:
    contract = _contract()
    documents = _scientific_documents()
    network = documents["transformation-network"]
    marking = documents["state-marking"]
    organization = documents["organization-witness"]
    live = {"authority", "evidence", "seed", "supply", "target"}

    assert structural_closure(contract, network, None)["status"] == "unknown"
    assert validate_organization(contract, network, None, live)["status"] == "unknown"
    bad_organization = deepcopy(organization)
    bad_organization["flux"] = {"transform:target": "-1"}
    bad_organization["source_refs"] = ["missing"]
    assert validate_organization(contract, network, bad_organization, live)["status"] == "false"

    assert validate_formation(contract, network, None, None, None)["status"] == "unknown"
    bad_formation = deepcopy(documents["formation-sequence-witness"])
    bad_formation["layers"] = [["missing"]]
    assert validate_formation(contract, network, marking, bad_formation, organization)[
        "status"
    ] == ("false")

    assert (
        validate_resource_accounting(contract, network, None, {"transform:target"}, live)["status"]
        == "unknown"
    )
    positive_network = deepcopy(network)
    positive_network["transformations"][0]["coordinate_flows"]["resource"]["quantity"] = "2"
    assert (
        validate_resource_accounting(
            contract,
            positive_network,
            documents["open-system-resource-witness"],
            {"transform:target"},
            live,
        )["status"]
        == "false"
    )

    assert (
        validate_rate_feasibility(contract, network, None, {"transform:target"}, live)["status"]
        == "unknown"
    )
    bad_rate = deepcopy(documents["rate-feasibility-witness"])
    bad_rate["rate_intervals"]["transform:target"] = {"lower": "2", "upper": "1"}
    assert (
        validate_rate_feasibility(contract, network, bad_rate, {"transform:target"}, live)["status"]
        == "false"
    )

    assert (
        validate_generalized_raf(contract, network, None, None, {"transform:target"}, live)[
            "status"
        ]
        == "unknown"
    )
    bad_raf = deepcopy(documents["generalized-raf-witness"])
    bad_raf["food_state_refs"] = ["target"]
    assert (
        validate_generalized_raf(contract, network, marking, bad_raf, {"transform:target"}, live)[
            "status"
        ]
        == "false"
    )

    assert validate_siphon_coverage(contract, network, None, live)["status"] == "unknown"
    limited = deepcopy(contract)
    limited["analysis_limits"]["maximum_siphon_species"] = 1
    assert (
        validate_siphon_coverage(limited, network, documents["siphon-coverage-witness"], live)[
            "status"
        ]
        == "unknown"
    )

    assert validate_verification_network(None, live)["status"] == "unknown"
    overloaded = deepcopy(documents["verification-network-witness"])
    overloaded["stages"][0]["service_lower"] = "1"
    overloaded["routing"] = [{"from": "stage:verify", "to": "stage:verify", "fanout_upper": "1"}]
    assert validate_verification_network(overloaded, live)["status"] == "false"

    independence = effective_independence(network, None, {"key:test"})
    core = support_core(contract, network, independence)
    assert core["status"] == "true"
    assert perturbation_replay_v3(contract, network, marking, [], independence)["status"] == (
        "false"
    )

    assert acceleration_evidence(contract, [], [], live)["status"] == "unmeasured"


def test_v3_science_adversarial_binding_matrix() -> None:
    contract = _contract()
    documents = _scientific_documents()
    network = documents["transformation-network"]
    marking = documents["state-marking"]
    organization = documents["organization-witness"]
    live = {"authority", "evidence", "seed", "supply", "target"}

    duplicate_nodes = deepcopy(network)
    duplicate_nodes["nodes"].append(deepcopy(duplicate_nodes["nodes"][0]))
    with pytest.raises(ValueError, match="duplicate node"):
        structural_closure(contract, duplicate_nodes, marking)
    duplicate_edges = deepcopy(network)
    duplicate_edges["transformations"].append(deepcopy(duplicate_edges["transformations"][0]))
    with pytest.raises(ValueError, match="duplicate transformation"):
        structural_closure(contract, duplicate_edges, marking)
    catalyzed = deepcopy(network)
    catalyzed["transformations"][0]["explicitly_uncatalyzed"] = False
    catalyzed["transformations"][0]["catalyst_clauses"] = [["target"]]
    assert structural_closure(contract, catalyzed, marking)["status"] == "false"

    bad_org = deepcopy(organization)
    bad_org.update(
        {
            "target_refs": [],
            "network_ref": "network:wrong",
            "transformation_refs": ["missing"],
            "state_refs": ["seed"],
            "flux": {"unexpected": True},
            "source_refs": ["missing"],
        }
    )
    reasons = validate_organization(contract, network, bad_org, live)["reasons"]
    assert "organization_target_binding_mismatch" in reasons
    assert "organization_network_binding_mismatch" in reasons
    assert "organization_transformation_set_invalid" in reasons
    assert "organization_flux_coverage_invalid" in reasons
    consuming = deepcopy(network)
    consuming["transformations"][0]["coordinate_flows"]["resource"]["quantity"] = "-1"
    assert (
        "organization_not_self_maintaining:resource"
        in validate_organization(contract, consuming, organization, live)["reasons"]
    )
    not_closed = deepcopy(organization)
    not_closed["state_refs"] = ["seed"]
    assert any(
        item.startswith("organization_not_closed")
        for item in validate_organization(contract, network, not_closed, live)["reasons"]
    )

    bad_form = deepcopy(documents["formation-sequence-witness"])
    bad_form.update(
        {
            "target_refs": [],
            "network_ref": "network:wrong",
            "initial_marking_ref": "marking:wrong",
            "transformation_refs": [],
            "layers": [[]],
        }
    )
    bad_marking = deepcopy(marking)
    bad_marking["coordinates"] = {"resource": {"quantity": True, "unit": "token"}}
    reasons = validate_formation(contract, network, bad_marking, bad_form, organization)["reasons"]
    assert "formation_organization_transformation_mismatch" in reasons
    assert "formation_target_binding_mismatch" in reasons
    assert "formation_network_binding_mismatch" in reasons
    assert "formation_marking_binding_mismatch" in reasons
    assert "state_marking_coordinates_invalid" in reasons
    assert "formation_layer_invalid:0" in reasons
    floor_contract = deepcopy(contract)
    floor_contract["protected_floors"]["resource"]["quantity"] = "11"
    assert any(
        "formation_prefix_floor_violation" in item
        for item in validate_formation(
            floor_contract,
            network,
            marking,
            documents["formation-sequence-witness"],
            organization,
        )["reasons"]
    )

    invalid_resource = deepcopy(documents["open-system-resource-witness"])
    invalid_resource.update(
        {
            "coordinate_weights": {"resource": True},
            "network_ref": "network:wrong",
            "source_refs": ["missing"],
        }
    )
    assert (
        validate_resource_accounting(contract, network, invalid_resource, {"missing"}, live)[
            "status"
        ]
        == "false"
    )
    missing_supply = deepcopy(network)
    missing_supply["transformations"][0]["boundary_supply_refs"] = ["missing"]
    reasons = validate_resource_accounting(
        contract,
        missing_supply,
        documents["open-system-resource-witness"],
        {"transform:target"},
        live,
    )["reasons"]
    assert "resource_boundary_supply_not_live:transform:target" in reasons

    malformed_rate = deepcopy(documents["rate-feasibility-witness"])
    malformed_rate.update(
        {
            "network_ref": "network:wrong",
            "source_refs": ["missing"],
            "observation_window": {"start": "bad", "end": "bad"},
            "rate_intervals": {},
            "feasible_flux": {},
        }
    )
    rate_reasons = validate_rate_feasibility(
        contract, network, malformed_rate, {"transform:target"}, live
    )["reasons"]
    assert "rate_transformation_coverage_invalid" in rate_reasons
    assert "rate_network_binding_mismatch" in rate_reasons
    assert "rate_source_refs_not_live" in rate_reasons
    assert "rate_observation_window_invalid" in rate_reasons
    assert (
        "rate_protected_coordinate_depletion:resource"
        in validate_rate_feasibility(
            contract,
            consuming,
            documents["rate-feasibility-witness"],
            {"transform:target"},
            live,
        )["reasons"]
    )

    bad_raf = deepcopy(documents["generalized-raf-witness"])
    bad_raf.update(
        {
            "network_ref": "network:wrong",
            "target_refs": [],
            "transformation_refs": [],
            "food_state_refs": [],
            "layers": [],
            "source_refs": ["missing"],
        }
    )
    raf_reasons = validate_generalized_raf(
        contract, catalyzed, marking, bad_raf, {"transform:target"}, live
    )["reasons"]
    assert "raf_organization_transformation_mismatch" in raf_reasons
    assert "raf_target_binding_mismatch" in raf_reasons
    assert "raf_network_binding_mismatch" in raf_reasons
    assert "raf_source_refs_not_live" in raf_reasons
    assert "raf_targets_not_generated" in raf_reasons

    bad_siphon = deepcopy(documents["siphon-coverage-witness"])
    bad_siphon.update(
        {
            "network_ref": "network:wrong",
            "minimal_siphons": [],
            "coverage_refs": [],
            "search_complete": False,
            "source_refs": ["missing"],
        }
    )
    siphon_reasons = validate_siphon_coverage(contract, network, bad_siphon, live)["reasons"]
    assert "siphon_network_binding_mismatch" in siphon_reasons
    assert "minimal_siphon_recomputation_mismatch" in siphon_reasons
    assert "siphon_coverage_map_invalid" in siphon_reasons
    assert "siphon_source_refs_not_live" in siphon_reasons

    malformed_verification = deepcopy(documents["verification-network-witness"])
    malformed_verification["routing"] = [{"invalid": True}]
    malformed_verification["stages"][0]["arrival_upper"] = "bad"
    malformed_verification["stages"][0]["source_refs"] = ["missing"]
    malformed_verification["source_refs"] = ["missing"]
    verification_reasons = validate_verification_network(malformed_verification, live)["reasons"]
    assert "verification_routing_invalid" in verification_reasons
    assert "verification_stage_interval_invalid:stage:verify" in verification_reasons
    assert "verification_stage_source_not_live:stage:verify" in verification_reasons
    assert "verification_source_refs_not_live" in verification_reasons

    merged_network = deepcopy(network)
    other = deepcopy(merged_network["nodes"][0])
    other["node_id"] = "other"
    other["independence_domain"] = "domain:other"
    merged_network["nodes"].append(other)
    ledger = {
        "events": [
            "malformed",
            {"event_type": "consume"},
            {"event_type": "commit", "independence_domain": "domain:test"},
        ]
    }
    independence = effective_independence(merged_network, ledger, {"key:test"})
    assert independence["effective_domain_count"] == 1
    strict_contract = deepcopy(contract)
    strict_contract["support_core_policy"]["minimum_support_domains"] = 2
    assert support_core(strict_contract, network, independence)["status"] == "false"


def test_v3_external_acceleration_failure_matrix() -> None:
    contract = _contract()
    live = {"evidence", "target"}
    protocol = {
        "protocol_id": "protocol:test",
        "registered_at": "2026-01-01T00:00:00Z",
        "target_refs": ["target"],
        "observation_window": {
            "start": "2026-01-02T00:00:00Z",
            "end": "2026-01-03T00:00:00Z",
        },
        "outcomes": [{"metric": "duration", "direction": "minimize", "unit": "second"}],
        "quality_floors": {"quality": {"quantity": "1", "unit": "score"}},
        "evaluator_key_id": "key:test",
        "source_refs": ["evidence"],
    }
    digest = digest_v3_json(protocol)
    base_result = {
        "protocol_digest": digest,
        "completed_at": "2026-01-03T00:00:00Z",
        "effect_intervals": [
            {
                "metric": "duration",
                "direction": "minimize",
                "lower": "-1",
                "upper": "1",
                "unit": "second",
            }
        ],
        "quality_intervals": [],
        "evaluator_key_id": "key:test",
        "source_refs": ["evidence"],
    }
    assert acceleration_evidence(contract, [], [base_result], live)["status"] == "unmeasured"
    missing_protocol = deepcopy(base_result)
    missing_protocol["protocol_digest"] = "sha256:" + "0" * 64
    assert acceleration_evidence(contract, [protocol], [missing_protocol], live)["status"] == (
        "externally_observed_inconclusive"
    )
    wrong_target = deepcopy(protocol)
    wrong_target["target_refs"] = ["other"]
    wrong_result = deepcopy(base_result)
    wrong_result["protocol_digest"] = digest_v3_json(wrong_target)
    report = acceleration_evidence(contract, [wrong_target], [wrong_result], live)
    assert "trial_target_binding_mismatch" in report["reasons"]
    wrong_evaluator = deepcopy(base_result)
    wrong_evaluator["evaluator_key_id"] = "key:other"
    report = acceleration_evidence(contract, [protocol], [wrong_evaluator], live)
    assert "trial_evaluator_binding_mismatch" in report["reasons"]
    missing_source = deepcopy(base_result)
    missing_source["source_refs"] = ["missing"]
    report = acceleration_evidence(contract, [protocol], [missing_source], live)
    assert "trial_source_refs_not_live" in report["reasons"]
    contradiction = deepcopy(base_result)
    contradiction["quality_intervals"] = [
        {
            "metric": "quality",
            "direction": "maximize",
            "lower": "0",
            "upper": "0",
            "unit": "score",
        }
    ]
    assert acceleration_evidence(contract, [protocol], [contradiction], live)["status"] == (
        "external_quality_or_safety_contradiction"
    )


def test_v3_migration_is_copy_on_write(tmp_path: Path) -> None:
    _, policy = _key_material()
    trust_path = tmp_path / "trust.json"
    write_canonical(trust_path, policy)
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    old = deepcopy(_contract())
    old["schema_version"] = "0.2.0"
    old["control_policy"] = {
        "planning_horizon": 1,
        "beam_width": 8,
        "candidate_cap": 16,
        "retry_policy": {"maximum_retries": 0},
    }
    old["formation_policy"] = {"causal_sequence_required": True, "maximum_layer_count": 8}
    old["support_core_policy"] = {
        "minimum_independent_support_groups": 1,
        "minimum_independent_verifier_groups": 1,
        "perturbation_suite_refs": [],
    }
    old["rate_policy"] = {"levels_requiring_external_rate_evidence": ["L3"]}
    for key in ("analysis_limits", "measurement_protocol_refs", "unit_registry"):
        old.pop(key, None)
    write_canonical(legacy / "contract.json", old)
    write_canonical(legacy / "actions.json", {"actions": [{"legacy": True}]})
    before = (legacy / "actions.json").read_bytes()
    migrated = tmp_path / "migrated"
    result = migrate_workspace_v3(legacy, trust_path, migrated, "0.3.0")
    assert result["command_status"] == "ok", result
    assert result["quarantined_record_count"] == 2
    assert (legacy / "actions.json").read_bytes() == before
    manifest = GenerationStore(migrated).load_manifest()
    assert manifest["quarantine"]
    assert workspace_status_v3(legacy)["execution_allowed"] is False


def test_signable_payload_is_domain_separated() -> None:
    value = {"schema_version": "0.3.0"}
    left, left_digest = signable_payload(value, "left@0.3.0")
    right, right_digest = signable_payload(value, "right@0.3.0")
    assert left != right
    assert left_digest != right_digest
    assert base64.b64encode(left)
    assert digest_v3_json(value).startswith("sha256:")
