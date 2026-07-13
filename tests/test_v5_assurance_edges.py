# SPDX-License-Identifier: Apache-2.0
"""Adversarial assurance for the inspection-only v0.5 compatibility surface."""

from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
from pathlib import Path

import pytest

from collective_phase_control_fabric.canonical import digest_v3_json, write_canonical
from collective_phase_control_fabric.coordination_v5 import (
    coordination_commit_v5,
    coordination_init_v5,
    coordination_reveal_v5,
    coordination_route_v5,
    coordination_status_v5,
    coordination_terminate_v5,
)
from collective_phase_control_fabric.generation_v5 import GenerationStoreV5
from collective_phase_control_fabric.planner_v5 import (
    BRANCHES,
    _bound_actions,
    _dominates,
    _initial_state,
    _interval_upper,
    _safe_branch,
    _state_digest,
    _successor,
    _tree,
    explain_action_v5,
    plan_v5,
)
from collective_phase_control_fabric.science_v5 import (
    _closure,
    _enabled,
    _independence,
    _network,
    _organization,
    _quorum_feasible,
    _verification,
    intervention_analysis_v5,
    perturbation_replay_v5,
    validate_typed_flow_profile,
)
from collective_phase_control_fabric.trials_v5 import (
    _floors_preserved,
    _roles_disjoint,
    _verify_protocol_bundle,
    acceleration_status_v5,
    import_amendment_v5,
    import_protocol_v5,
    import_result_v5,
    inspect_protocol_v5,
    inspect_result_v5,
)
from collective_phase_control_fabric.trust_v5 import (
    key_fingerprint,
    schema_digest,
    validate_policy,
    verify_genesis,
    verify_role_quorum,
    verify_statement,
    verify_time_receipt,
)
from collective_phase_control_fabric.workspace_v5 import (
    _pointer,
    _read_raw,
    _time,
    advance_time_v5,
    doctor_v5,
    explain_missing_contract_v5,
    import_raw_v5,
    import_signed_object_v5,
    inspect_genesis_v5,
    inspect_quorum_v5,
    inspect_signed_object_v5,
    inspect_time_receipt_v5,
    migrate_workspace_v5,
    onboard_v5,
    repair_list_v5,
    repair_show_v5,
    scaffold_contract_v5,
    status_v5,
    validate_policy_v5,
    workspace_version,
)
from tests.test_v5 import NOW, _policy, _statement, _workspace


def statement(
    subject: str,
    record_type: str,
    attributes: dict[str, object],
    *,
    principal: str = "principal:a",
) -> dict[str, object]:
    return {
        "protected": {"principal_id": principal},
        "payload": {
            "record_type": record_type,
            "subject_id": subject,
            "attributes": attributes,
        },
    }


def branch(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "must_add": [],
        "may_add": [],
        "must_remove": [],
        "may_remove": [],
        "resource_intervals": {},
        "debt": [],
        "rollback_obligations": [],
        "verification_load_upper": "0",
        "independence_domains_removed": [],
        "time_interval": {"lower": "0", "upper": "1", "unit": "second"},
        "cost_interval": {"lower": "0", "upper": "1", "unit": "credit"},
        "quality_interval": {"lower": "1", "upper": "1", "unit": "score"},
    }
    value.update(updates)
    return value


def planner_state() -> dict[str, object]:
    statements = [
        statement("state:input", "state", {"available": True}),
        statement("state:ignored", "state", {"available": False}),
        statement("authority:a", "authority", {}),
        statement("hazard:h", "hazard", {}),
        statement(
            "resource:first",
            "resource_observation",
            {"coordinate": "fuel", "quantity": "2", "unit": "unit"},
        ),
        statement(
            "resource:duplicate",
            "resource_observation",
            {"coordinate": "fuel", "quantity": "99", "unit": "unit"},
        ),
        statement(
            "resource:invalid",
            "resource_observation",
            {"coordinate": "bad", "quantity": "1/0", "unit": "unit"},
        ),
        statement("independence:a", "independence", {}),
    ]
    return _initial_state(
        {"generation_id": "sha256:" + "1" * 64, "analysis_epoch": NOW},
        statements,
        {"operational_organization_profile": {"structural_reachability": "satisfied"}},
    )


def test_v5_planner_state_and_branch_safety_edges() -> None:
    state = planner_state()
    assert state["resources"] == {"fuel": Fraction(2)}
    assert "state:ignored" not in state["states"]
    assert len(_state_digest(state)) == 71

    effect = branch(
        must_add=["state:target"],
        may_remove=["authority:a", "hazard:h"],
        resource_intervals={"fuel": {"lower": "-3", "upper": "-1"}},
        debt=["debt:a"],
        rollback_obligations=["rollback:a"],
        verification_load_upper="1",
        independence_domains_removed=["independence:a"],
    )
    successor = _successor(state, effect)
    assert successor["resources"]["fuel"] == -1
    assert successor["scientific_profile"]["structural_reachability"] == "unknown"
    safe, reasons, _ = _safe_branch(
        state,
        effect,
        {
            "protected_floors": {
                "fuel": {"quantity": "0", "unit": "unit"},
                "bad": "not-a-floor",
                "other": {"quantity": "1", "unit": "other"},
            }
        },
        {"authority:a"},
        {"hazard:h"},
    )
    assert safe is False
    assert {
        "authority_not_preserved",
        "hazard_guard_not_preserved",
        "protected_floor_violation:fuel",
        "protected_floor_invalid:bad",
        "protected_floor_unit_mismatch:other",
        "verification_capacity_overloaded",
    } <= set(reasons)
    invalid = branch(resource_intervals={"fuel": {"lower": "1/0"}})
    assert _safe_branch(state, invalid, {}, set(), set())[:2] == (
        False,
        ["branch_interval_invalid"],
    )


def test_v5_planner_binding_dominance_and_tree_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    state = planner_state()
    safe = branch(must_add=["state:target"])
    action = statement(
        "action:a",
        "evidence",
        {
            "evidence_type": "action",
            "capability_ref": "capability:a",
            "expires_at": "2026-12-01T00:00:00Z",
            "input_refs": ["state:input"],
            "required_authority_refs": ["authority:a"],
            "required_hazard_refs": ["hazard:h"],
        },
        principal="principal:action",
    )
    capability = statement(
        "capability:a",
        "evidence",
        {
            "evidence_type": "adapter_capability",
            "projection_routes": [{"guaranteed_subject_ids": ["state:target"]}],
            "branches": {name: deepcopy(safe) for name in BRANCHES},
        },
        principal="principal:capability",
    )
    accepted, rejected = _bound_actions([action, capability], state, {}, NOW)
    assert len(accepted) == 1 and rejected == []
    public_tree = _tree(accepted[0], [action, capability], {}, NOW, 2, 1, set())
    assert all("children" in item for item in public_tree["outcomes"].values())
    cycle_key = ("action:a", _state_digest(accepted[0]["branch_states"]["success"]))
    cycle = _tree(accepted[0], [action, capability], {}, NOW, 2, 1, {cycle_key})
    assert cycle["outcomes"]["success"]["cycle"] == "non_progress_cycle_rejected"

    malformed_action = deepcopy(action)
    malformed_action["payload"]["attributes"].update(
        {
            "capability_ref": "missing",
            "expires_at": "not-time",
            "input_refs": ["missing"],
            "required_authority_refs": ["missing"],
            "required_hazard_refs": ["missing"],
        }
    )
    _, rejected = _bound_actions([malformed_action], state, {}, NOW)
    assert {
        "independently_signed_capability_missing",
        "action_expiry_invalid",
        "action_inputs_unavailable",
        "action_authority_unavailable",
        "action_hazard_guard_unavailable",
        "capability_branch_effect_contract_missing",
    } <= set(rejected[0]["reasons"])

    same_signer = deepcopy(capability)
    same_signer["protected"]["principal_id"] = "principal:action"
    same_signer["payload"]["attributes"]["projection_routes"] = []
    del same_signer["payload"]["attributes"]["branches"]["timeout"]
    _, rejected = _bound_actions([action, same_signer], state, {}, NOW)
    assert "action_and_capability_principals_not_distinct" in rejected[0]["reasons"]
    assert "capability_branch_missing:timeout" in rejected[0]["reasons"]
    assert "branch_addition_without_projection_route:success" in rejected[0]["reasons"]

    left = {"branches": {name: branch(must_add=["a", "b"]) for name in BRANCHES}}
    right = {"branches": {name: branch(must_add=["a"], debt=["d"]) for name in BRANCHES}}
    assert _dominates(left, right) is True
    assert _dominates(right, left) is False
    assert _interval_upper({}, "cost_interval") == (Fraction(10**18), "missing")
    assert _interval_upper({"cost_interval": {"upper": "1/0", "unit": "x"}}, "cost_interval") == (
        Fraction(10**18),
        "invalid",
    )


def test_v5_workspace_helpers_and_invalid_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _time(None) is None
    assert _time("invalid") is None
    assert _time("2026-01-01T00:00:00") is None
    assert _pointer({"a/b": {"~": ["value"]}}, "/a~1b/~0/0") == "value"
    assert _pointer({"a": 1}, "") == {"a": 1}
    for pointer in ("bad", "/missing", "/a/0"):
        with pytest.raises(ValueError):
            _pointer({"a": 1}, pointer)

    missing = tmp_path / "missing.json"
    assert explain_missing_contract_v5(missing)["code"] == "contract_draft_invalid"
    scalar = tmp_path / "scalar.json"
    scalar.write_text("[]", encoding="utf-8")
    assert validate_policy_v5(scalar)["code"] == "trust_policy_not_object"
    assert (
        inspect_genesis_v5(scalar, scalar, "bad", scalar)["code"]
        == "trust_genesis_input_not_object"
    )
    assert inspect_time_receipt_v5(scalar, scalar)["code"] == "trusted_time_input_not_object"
    assert inspect_signed_object_v5(scalar, scalar)["code"] == "signed_object_input_not_object"

    output = tmp_path / "draft"
    created = scaffold_contract_v5(output, "measured")
    assert created["status"] == "ok"
    assert scaffold_contract_v5(output, "measured")["code"] == "output_already_exists"
    assert explain_missing_contract_v5(output / "contract-draft.json")["missing_decisions"]
    wrong = tmp_path / "wrong.json"
    write_canonical(wrong, {"schema_version": "0.4.0"})
    assert explain_missing_contract_v5(wrong)["code"] == "contract_draft_not_v0.5"

    oversized = tmp_path / "large.bin"
    oversized.write_bytes(b"x")
    monkeypatch.setattr("collective_phase_control_fabric.workspace_v5.MAX_RAW_BYTES", 0)
    with pytest.raises(Exception, match="maximum_raw_bytes_exceeded"):
        _read_raw(oversized)


def test_v5_native_workspace_status_repair_import_and_migration(tmp_path: Path) -> None:
    workspace, policy, _ = _workspace(tmp_path / "native")
    store = GenerationStoreV5(workspace)
    manifest = store.load_manifest()
    policy_path = tmp_path / "policy.json"
    write_canonical(policy_path, policy)

    assert workspace_version(workspace) == "0.5.0"
    assert doctor_v5(workspace)["status"] == "ok"
    assert status_v5(workspace)["schema_version"] == "0.5.0"
    assert repair_list_v5(workspace)["status"] == "ok"
    assert repair_show_v5(workspace, "missing")["code"] == "repair_not_found"
    assert onboard_v5(workspace)["claims"] == ["native_v0.5_onboarding_audit_completed"]
    assert plan_v5(workspace)["status"] == "ok"
    assert explain_action_v5(workspace, "missing")["code"] == "action_not_found"

    raw = tmp_path / "raw.json"
    write_canonical(raw, {"value": 1})
    preview = import_raw_v5(raw, workspace, "source", "record@0.5.0", apply=False)
    assert preview["code"] == "apply_required"
    imported = import_raw_v5(raw, workspace, "source", "record@0.5.0", apply=True)
    assert imported["status"] == "ok"
    assert import_raw_v5(raw, workspace, "source", "record@0.5.0", apply=True)["code"] == (
        "source_already_imported"
    )
    invalid = tmp_path / "invalid-signed.json"
    write_canonical(invalid, {})
    assert import_signed_object_v5(invalid, workspace, apply=True)["code"] == (
        "signed_object_schema_missing"
    )
    assert advance_time_v5(workspace, invalid, apply=False)["code"] == (
        "trusted_time_advance_invalid"
    )
    assert (
        inspect_quorum_v5([invalid], workspace, "trust_update", digest_v3_json(policy))["code"]
        == "trust_quorum_invalid"
    )

    legacy = tmp_path / "legacy"
    legacy.mkdir()
    write_canonical(legacy / "contract.json", {"schema_version": "0.4.0"})
    assert status_v5(legacy)["code"] == "legacy_workspace_inspect_only"
    control = legacy / ".cpcf"
    control.mkdir()
    (control / "raw.bin").write_bytes(b"legacy")

    contract = store.get_json(str(manifest["contract_digest"]))
    registry_digest = next(
        item["digest"] for item in manifest["objects"] if item["kind"] == "unit-registry"
    )
    registry = store.get_json(registry_digest)
    genesis_digest = next(
        item["digest"] for item in manifest["objects"] if item["kind"] == "genesis-policy-statement"
    )
    genesis = store.get_json(genesis_digest)
    time_receipt = store.get_json(str(manifest["trusted_time_receipt_digest"]))
    paths: dict[str, Path] = {}
    for name, value in {
        "contract": contract,
        "policy": policy,
        "genesis": genesis,
        "registry": registry,
        "time": time_receipt,
    }.items():
        paths[name] = tmp_path / f"migration-{name}.json"
        write_canonical(paths[name], value)
    root_public = _policy()[0]["principals"][0]["public_key_base64"]
    from collective_phase_control_fabric.trust_v5 import key_fingerprint

    fingerprint = key_fingerprint(root_public)
    assert validate_policy_v5(paths["policy"], fingerprint)["status"] == "ok"
    assert inspect_time_receipt_v5(paths["time"], paths["policy"])["status"] == "ok"
    assert inspect_signed_object_v5(paths["genesis"], paths["policy"])["status"] == "ok"
    assert (
        inspect_genesis_v5(paths["policy"], paths["genesis"], fingerprint, paths["time"])["status"]
        == "ok"
    )
    migrated = migrate_workspace_v5(
        legacy,
        paths["contract"],
        paths["policy"],
        paths["genesis"],
        paths["registry"],
        paths["time"],
        tmp_path / "migrated",
        fingerprint,
    )
    assert migrated["status"] == "ok"
    assert migrated["quarantined_objects"]


def test_v5_science_network_formation_and_organization_edges() -> None:
    state = statement("state:a", "state", {"available": True})
    authority = statement("authority:a", "authority", {})
    catalyst = statement("catalyst:a", "catalyst", {"available": True})
    inhibitor = statement("inhibitor:a", "inhibitor", {"available": True})
    evidence = statement("evidence:a", "evidence", {"evidence_type": "source"})
    edge = {
        "inputs": ["state:a"],
        "outputs": ["state:b"],
        "authority_refs": ["authority:a"],
        "evidence_refs": ["evidence:a"],
        "catalyst_clauses": [["catalyst:a"]],
        "inhibitors": [],
        "produced_catalysts": ["catalyst:b"],
        "coordinate_flows": {"fuel": "0"},
    }
    transformation = statement("transformation:a", "transformation", edge)
    available, transformations, catalysts, inhibitors, evidence_ids = _network(
        [state, authority, catalyst, inhibitor, evidence, transformation]
    )
    assert available == {"state:a", "authority:a", "evidence:a"}
    assert evidence_ids == {"authority:a", "evidence:a"}
    assert _enabled(edge, available, catalysts, set()) is True
    assert _enabled({**edge, "inputs": ["missing"]}, available, catalysts, set()) is False
    assert _enabled({**edge, "authority_refs": ["missing"]}, available, catalysts, set()) is False
    assert _enabled({**edge, "evidence_refs": ["missing"]}, available, catalysts, set()) is False
    assert (
        _enabled({**edge, "inhibitors": ["inhibitor:a"]}, available, catalysts, inhibitors) is False
    )
    assert _enabled({**edge, "catalyst_clauses": []}, available, catalysts, set()) is False
    assert (
        _enabled(
            {**edge, "explicitly_uncatalyzed": True, "catalyst_clauses": []},
            available,
            catalysts,
            set(),
        )
        is True
    )
    reached, layers, used, operations = _closure(available, transformations, catalysts, set(), 10)
    assert "state:b" in reached and layers["state:b"] == 1
    assert used == {"transformation:a"} and operations >= 1
    with pytest.raises(RuntimeError, match="unknown_due_to_budget"):
        _closure(available, transformations, catalysts, set(), 0)
    with pytest.raises(ValueError, match="duplicate transformation"):
        _network([transformation, transformation])

    no_witness = _organization([], transformations, "snapshot", {"state:b"})
    assert no_witness[0] == "unknown"
    witness = statement(
        "organization:a",
        "evidence",
        {
            "evidence_type": "organization_witness",
            "analysis_snapshot_digest": "wrong",
            "transformation_refs": ["transformation:a"],
            "feasible_flux": {"transformation:a": "-1"},
        },
    )
    result = _organization([witness], transformations, "snapshot", {"state:missing"})
    assert result[0] == "violated"
    assert {
        "organization_snapshot_mismatch",
        "organization_not_target_bound",
        "organization_flux_not_strictly_positive:transformation:a",
    } <= set(result[1])


def test_v5_typed_flow_verifier_independence_and_quorum_edges() -> None:
    registry = {
        "units": {
            "unit": {"dimension_vector": {"amount": 1}, "scale": "1"},
            "second": {"dimension_vector": {"time": 1}, "scale": "1"},
        }
    }
    profile = {
        "analysis_snapshot_digest": "wrong",
        "unit_registry_digest": "wrong",
        "time_unit": "missing",
        "step_duration": "-1",
        "horizon_steps": 2,
        "coordinates": {
            "fuel": {"unit": "unit", "initial": "1", "protected_floor": "1"},
            "bad-unit": {"unit": "missing", "initial": "0", "protected_floor": "0"},
            "bad-declaration": "bad",
        },
        "transformations": {
            "consume": {"flow": {"fuel": "-2", "unknown": "1"}},
            "bad": {"flow": "bad"},
        },
        "action_counts": [{"consume": "1", "missing": "-1"}],
        "boundary_rates": [
            {"fuel": "0", "unknown": "1"},
            {"fuel": "0"},
        ],
        "fed_siphons": [
            "bad",
            {"coordinates": ["fuel"], "source_refs": ["missing"], "coverage": "initially_marked"},
            {"coordinates": ["fuel"], "source_refs": ["live"], "coverage": "boundary_fed"},
            {"coordinates": ["fuel"], "source_refs": ["live"], "coverage": "replenished"},
        ],
    }
    result = validate_typed_flow_profile(
        profile, registry, live_source_ids={"live"}, snapshot="snapshot"
    )
    assert result["status"] == "violated"
    reasons = set(result["reasons"])
    assert "typed_flow_snapshot_mismatch" in reasons
    assert "typed_flow_horizon_length_mismatch" in reasons
    assert any(item.startswith("prefix_floor_violation:fuel") for item in reasons)
    assert "fed_siphon_not_boundary_fed" in reasons
    assert "fed_siphon_not_replenished" in reasons

    assert _verification([]) == ("unknown", ["typed_verifier_records_required"])
    source = statement("source:a", "evidence", {})
    source["payload"]["subject_digest"] = "digest:source"
    verifier = statement(
        "verifier:a",
        "verifier",
        {
            "source_record_digest": "digest:source",
            "arrival_upper": "2",
            "service_lower": "1",
            "routing_amplification": "2",
            "source_refs": ["missing"],
        },
    )
    verification = _verification([source, verifier])
    assert verification[0] == "violated"
    assert "verifier_overloaded:verifier:a" in verification[1]
    assert "verifier_source_ref_missing:verifier:a" in verification[1]

    independence = statement(
        "independence:a",
        "independence",
        {"observer_attestation_ref": None, "commitment_digest": None},
    )
    exposure = statement(
        "exposure:a",
        "exposure",
        {"before_commitment": True, "artifact_digest": "artifact:a"},
    )
    status, reasons, effective = _independence([independence, exposure], 2)
    assert status == "violated" and effective == 0
    assert "independence_observer_invalid:independence:a" in reasons
    assert _independence([], 1)[0] == "unknown"

    assert _quorum_feasible({"principals": []}) == (
        "violated",
        ["trust_update_quorum_role_unavailable"],
    )
    colliding = {
        "principal_id": "p",
        "key_id": "k",
        "roles": ["workspace_root", "trust_auditor", "timestamp"],
        "revoked": False,
        "infrastructure_domains": ["shared"],
    }
    assert _quorum_feasible({"principals": [colliding]}) == (
        "violated",
        ["trust_update_quorum_not_disjoint"],
    )


def test_v5_trials_and_interventions_fail_closed(tmp_path: Path) -> None:
    workspace, policy, keys = _workspace(tmp_path / "trial")
    scalar = tmp_path / "scalar.json"
    scalar.write_text("[]", encoding="utf-8")
    assert inspect_protocol_v5(scalar, scalar, scalar, workspace)["code"] == (
        "trial_protocol_input_not_object"
    )
    assert import_protocol_v5(scalar, scalar, scalar, workspace, apply=True)["code"] == (
        "trial_protocol_input_not_object"
    )
    assert import_amendment_v5(scalar, scalar, workspace, apply=True)["code"] == (
        "protocol_amendment_input_not_object"
    )
    assert inspect_result_v5(scalar, workspace)["code"] == "trial_result_not_object"
    assert import_result_v5(scalar, workspace, apply=True)["code"] == "trial_result_not_object"
    valid, reasons, payload = _verify_protocol_bundle({}, {}, {}, policy)
    assert valid is False and reasons == ["protocol_registration_or_time_payload_missing"]
    assert payload is None
    assert _roles_disjoint(policy, [{}, {}]) == ["evidence_quorum_identity_not_disjoint"]
    assert _floors_preserved({"quality_floors": []}, {}) is False
    assert (
        _floors_preserved(
            {"quality_floors": {"q": {"quantity": "2", "unit": "score"}}},
            {"quality_intervals": {"q": {"lower": "1", "unit": "score"}}},
        )
        is False
    )
    assert acceleration_status_v5(workspace)["acceleration_status"] == "unmeasured"
    assert perturbation_replay_v5(workspace, "missing")["code"] == ("perturbation_suite_not_found")
    intervention = intervention_analysis_v5(workspace)
    assert intervention["status"] == "ok"
    assert intervention["blocker_frontier"]

    amendment = _statement(
        keys["protocol"],
        {
            "schema_version": "0.5.0",
            "amendment_id": "amendment:missing-protocol",
            "protocol_digest": "sha256:" + "1" * 64,
            "previous_amendment_digest": "sha256:" + "2" * 64,
            "amended_protocol_digest": "sha256:" + "3" * 64,
            "effective_at": NOW,
            "trusted_time_receipt_digest": "sha256:" + "4" * 64,
        },
        schema_ref="protocol-amendment@0.5.0",
        key_id="key:protocol",
        principal_id="principal:protocol",
        role="protocol_author",
        source_system="principal:protocol",
    )
    amendment_path = tmp_path / "amendment.json"
    write_canonical(amendment_path, amendment)
    amendment_time = _statement(
        keys["time"],
        {
            "schema_version": "0.5.0",
            "receipt_id": "time:amendment",
            "receipt_type": "trusted_time",
            "event_time": NOW,
            "subject_digest": digest_v3_json(amendment),
            "serial": 2,
        },
        schema_ref="trusted-time-receipt@0.5.0",
        key_id="key:time",
        principal_id="principal:time",
        role="timestamp",
        source_system="principal:time",
    )
    amendment_time_path = tmp_path / "amendment-time.json"
    write_canonical(amendment_time_path, amendment_time)
    amendment_result = import_amendment_v5(
        amendment_path, amendment_time_path, workspace, apply=True
    )
    assert amendment_result["code"] == "protocol_amendment_invalid"
    assert "amendment_protocol_missing" in amendment_result["reasons"]
    assert "amendment_chain_predecessor_missing" in amendment_result["reasons"]

    trial_result = _statement(
        keys["evaluator"],
        {
            "schema_version": "0.5.0",
            "result_id": "result:missing-protocol",
            "protocol_id": "protocol:missing",
            "protocol_digest": "sha256:" + "1" * 64,
            "dataset_digest": "sha256:" + "2" * 64,
            "analysis_executable_digest": "sha256:" + "3" * 64,
            "observation_started_at": "invalid",
            "observation_ended_at": NOW,
            "completed_at": NOW,
            "effect_intervals": {
                "outcome": {
                    "lower": "2",
                    "upper": "1",
                    "unit": "unit",
                    "estimand_status": "supported",
                }
            },
            "quality_intervals": {},
            "safety_intervals": {},
            "amendment_chain_digest": "sha256:" + "4" * 64,
        },
        schema_ref="trial-result-certificate@0.5.0",
        key_id="key:evaluator",
        principal_id="principal:evaluator",
        role="evaluator",
        source_system="principal:evaluator",
    )
    trial_result_path = tmp_path / "trial-result.json"
    write_canonical(trial_result_path, trial_result)
    inspected = inspect_result_v5(trial_result_path, workspace)
    assert inspected["code"] == "trial_result_invalid"
    assert "bound_protocol_missing" in inspected["reasons"]
    assert "typed_dataset_record_missing" in inspected["reasons"]
    assert "typed_analysis_executable_record_missing" in inspected["reasons"]
    assert "result_time_invalid" in inspected["reasons"]
    assert "unbound_amendment_chain" in inspected["reasons"]


def test_v5_trust_policy_and_statement_adversarial_branches() -> None:
    policy, keys = _policy()
    root = next(item for item in policy["principals"] if item["key_id"] == "key:root")
    with pytest.raises(ValueError, match="32 bytes"):
        key_fingerprint("YQ==")
    with pytest.raises(ValueError, match="NAME@VERSION"):
        schema_digest("invalid")
    with pytest.raises(ValueError, match=r"0\.5\.0"):
        schema_digest("trust-policy@0.4.0")

    invalid_policy = deepcopy(policy)
    invalid_policy["root_key_id"] = "wrong"
    invalid_policy["quorum_rules"]["trust_update"] = []
    duplicate = deepcopy(invalid_policy["principals"][0])
    duplicate.update(
        {
            "revoked": True,
            "revoked_at": None,
            "compromised_at": "2028-01-01T00:00:00Z",
            "public_key_base64": "invalid",
        }
    )
    invalid_policy["principals"].append(duplicate)
    errors = validate_policy(invalid_policy, "sha256:" + "0" * 64)
    messages = {str(item["message"]) for item in errors}
    assert "duplicate principal_id" in messages
    assert "duplicate key_id" in messages
    assert "invalid Ed25519 public key" in messages
    assert "revoked principal requires revoked_at" in messages
    assert "exactly one workspace_root principal is required" in messages
    assert any("quorum roles" in item for item in messages)

    inconsistent = deepcopy(policy)
    inconsistent["principals"][0]["revoked_at"] = "2026-05-01T00:00:00Z"
    inconsistent["principals"][1]["revoked"] = True
    inconsistent["principals"][1]["revoked_at"] = "2026-05-01T00:00:00Z"
    inconsistent["principals"][1]["compromised_at"] = "2026-06-01T00:00:00Z"
    messages = {str(item["message"]) for item in validate_policy(inconsistent, "wrong")}
    assert "non-revoked principal cannot declare revoked_at" in messages
    assert "compromised_at cannot follow revoked_at" in messages
    assert "out-of-band root fingerprint mismatch" in messages

    payload = {"schema_version": "0.5.0", "policy_id": "policy:test"}
    valid = _statement(
        keys["root"],
        payload,
        schema_ref="trust-policy@0.5.0",
        key_id="key:root",
        principal_id="principal:root",
        role="workspace_root",
        source_system="principal:root",
    )
    assert (
        verify_statement(valid, policy, authoritative_time=NOW, validate_payload=False)["status"]
        == "true"
    )
    assert (
        "protected_header_missing"
        in verify_statement({}, policy, authoritative_time=NOW)["reasons"]
    )

    tampered = deepcopy(valid)
    tampered["protected"].update(
        {
            "domain": "wrong",
            "canonicalization_profile": "wrong",
            "schema_ref": "unknown@0.5.0",
            "schema_digest": "wrong",
            "payload_digest": "wrong",
            "principal_id": "wrong",
            "role": "wrong",
            "source_system": "wrong",
            "scope": {"wrong": True},
            "signed_at": "invalid",
        }
    )
    reasons = verify_statement(
        tampered,
        policy,
        authoritative_time="invalid",
        expected_schema_ref="trust-policy@0.5.0",
        expected_role="workspace_root",
        expected_source_system="principal:root",
        expected_scope=root["scope"],
    )["reasons"]
    assert {
        "signature_domain_or_version_mismatch",
        "canonicalization_profile_mismatch",
        "signed_schema_unknown",
        "signed_schema_mismatch",
        "signed_role_mismatch",
        "signed_source_system_mismatch",
        "signed_scope_mismatch",
        "signed_payload_digest_mismatch",
        "authoritative_or_signing_time_invalid",
        "principal_identity_mismatch",
        "role_not_authorized",
        "source_system_not_authorized",
        "schema_not_authorized",
        "principal_scope_mismatch",
        "key_validity_time_invalid",
        "ed25519_signature_invalid",
    } <= set(reasons)

    future = deepcopy(valid)
    future["protected"]["signed_at"] = "2027-01-01T00:00:00Z"
    assert (
        "signature_from_future"
        in verify_statement(future, policy, authoritative_time=NOW, validate_payload=False)[
            "reasons"
        ]
    )
    unknown = deepcopy(valid)
    unknown["protected"]["key_id"] = "missing"
    assert (
        "pinned_key_unknown_or_duplicate"
        in verify_statement(unknown, policy, authoritative_time=NOW, validate_payload=False)[
            "reasons"
        ]
    )

    revoked_policy = deepcopy(policy)
    revoked_root = next(
        item for item in revoked_policy["principals"] if item["key_id"] == "key:root"
    )
    revoked_root["revoked"] = True
    revoked_root["revoked_at"] = "2026-01-01T00:00:00Z"
    revoked_root["compromised_at"] = "2026-01-01T00:00:00Z"
    reasons = verify_statement(
        valid, revoked_policy, authoritative_time=NOW, validate_payload=False
    )["reasons"]
    assert "pinned_key_revoked_at_signing_time" in reasons
    assert "pinned_key_compromised_at_signing_time" in reasons


def test_v5_genesis_time_and_quorum_adversarial_branches() -> None:
    policy, keys = _policy()
    payload = {"schema_version": "0.5.0", "receipt_type": "wrong", "event_time": NOW}
    invalid_time = _statement(
        keys["time"],
        payload,
        schema_ref="trusted-time-receipt@0.5.0",
        key_id="key:time",
        principal_id="principal:time",
        role="timestamp",
        source_system="principal:time",
    )
    assert verify_time_receipt({}, policy)["reasons"] == [
        "time_receipt_payload_or_event_time_invalid"
    ]
    reasons = verify_time_receipt(invalid_time, policy, expected_subject_digest="expected")[
        "reasons"
    ]
    assert "time_receipt_type_invalid" in reasons
    assert "time_receipt_subject_mismatch" in reasons
    assert "time_receipt_serial_invalid" in reasons

    genesis = _statement(
        keys["root"],
        {"not": "policy"},
        schema_ref="trust-policy@0.5.0",
        key_id="key:root",
        principal_id="principal:root",
        role="workspace_root",
        source_system="principal:root",
    )
    checked = verify_genesis(policy, genesis, "wrong", NOW)
    assert checked["status"] == "false"
    assert "genesis_statement_payload_not_complete_policy" in checked["reasons"]

    assert verify_role_quorum(
        [], policy, decision_type="unknown", authoritative_time=NOW, subject_digest="digest"
    )["reasons"] == ["unknown_quorum_decision_type"]
    malformed = verify_role_quorum(
        [{}, {"protected": {}, "payload": {}}],
        policy,
        decision_type="projection_promotion",
        authoritative_time=NOW,
        subject_digest="digest",
    )
    assert malformed["status"] == "false"
    assert "quorum_statement_malformed" in malformed["reasons"]
    assert "unexpected_quorum_role:None" in malformed["reasons"]


def test_v5_coordination_invalid_states_and_preview_paths(tmp_path: Path) -> None:
    workspace, _, keys = _workspace(tmp_path / "coordination")
    scalar = tmp_path / "scalar.json"
    scalar.write_text("[]", encoding="utf-8")
    assert coordination_init_v5(workspace, scalar, apply=True)["code"] == (
        "coordination_plan_not_object"
    )
    invalid_plan = tmp_path / "invalid-plan.json"
    write_canonical(invalid_plan, {})
    assert coordination_init_v5(workspace, invalid_plan, apply=True)["code"] == (
        "coordination_plan_invalid"
    )
    plan = tmp_path / "plan.json"
    write_canonical(
        plan,
        {
            "schema_version": "0.5.0",
            "plan_id": "plan:assurance",
            "participant_principals": ["principal:p1", "principal:p2"],
            "verifier_stage_refs": ["verifier:a"],
            "maximum_exposure_events": 1,
            "termination_rule": "capacity_blocked",
        },
    )
    assert coordination_init_v5(workspace, plan, apply=False)["code"] == "apply_required"
    created = coordination_init_v5(workspace, plan, apply=True)
    session_id = str(created["session_id"])
    assert coordination_route_v5(workspace, session_id, apply=True)["code"] == (
        "coordination_route_precondition_unsatisfied"
    )
    assert (
        coordination_terminate_v5(workspace, session_id, reason="all_verified", apply=True)["code"]
        == "coordination_success_termination_precondition_unsatisfied"
    )
    assert coordination_commit_v5(workspace, session_id, scalar, apply=True)["code"] == (
        "coordination_session_or_event_missing"
    )

    proposal = {"answer": "one"}
    nonce = "nonce-000000000001"
    commitment = _statement(
        keys["p1"],
        {
            "schema_version": "0.5.0",
            "commitment_id": "commitment:assurance",
            "session_id": session_id,
            "participant_principal_id": "principal:p1",
            "commitment_digest": digest_v3_json({"proposal": proposal, "nonce": nonce}),
            "committed_at": NOW,
        },
        schema_ref="proposal-commitment@0.5.0",
        key_id="key:p1",
        principal_id="principal:p1",
        role="proposal_author",
        source_system="principal:p1",
    )
    commitment_path = tmp_path / "commitment.json"
    write_canonical(commitment_path, commitment)
    assert (
        coordination_commit_v5(workspace, session_id, commitment_path, apply=False)["code"]
        == "apply_required"
    )
    assert (
        coordination_commit_v5(workspace, session_id, commitment_path, apply=True)["status"] == "ok"
    )
    assert (
        coordination_commit_v5(workspace, session_id, commitment_path, apply=True)["code"]
        == "coordination_duplicate_commitment"
    )
    commitment_p2 = _statement(
        keys["p2"],
        {
            **commitment["payload"],
            "commitment_id": "commitment:assurance:p2",
            "participant_principal_id": "principal:p2",
        },
        schema_ref="proposal-commitment@0.5.0",
        key_id="key:p2",
        principal_id="principal:p2",
        role="proposal_author",
        source_system="principal:p2",
    )
    commitment_p2_path = tmp_path / "commitment-p2.json"
    write_canonical(commitment_p2_path, commitment_p2)
    assert (
        coordination_commit_v5(workspace, session_id, commitment_p2_path, apply=True)["status"]
        == "ok"
    )

    assert coordination_route_v5(workspace, session_id, apply=False)["code"] == "apply_required"
    assert coordination_route_v5(workspace, session_id, apply=True)["coordination_state"] == (
        "COMMIT_CLOSED"
    )
    assert coordination_route_v5(workspace, session_id, apply=True)["coordination_state"] == (
        "REVEAL_OPEN"
    )
    reveal = _statement(
        keys["p1"],
        {
            "schema_version": "0.5.0",
            "reveal_id": "reveal:assurance",
            "session_id": session_id,
            "participant_principal_id": "principal:p1",
            "proposal": proposal,
            "nonce": "nonce-wrong-000001",
            "revealed_at": NOW,
        },
        schema_ref="proposal-reveal@0.5.0",
        key_id="key:p1",
        principal_id="principal:p1",
        role="proposal_author",
        source_system="principal:p1",
    )
    reveal_path = tmp_path / "reveal.json"
    write_canonical(reveal_path, reveal)
    assert coordination_reveal_v5(workspace, session_id, reveal_path, apply=True)["code"] == (
        "coordination_commit_reveal_mismatch"
    )
    assert (
        coordination_terminate_v5(workspace, session_id, reason="explicit", apply=False)["code"]
        == "apply_required"
    )
    assert coordination_status_v5(workspace)["incomplete_sessions"] == [session_id]
    assert (
        coordination_terminate_v5(workspace, session_id, reason="explicit", apply=True)[
            "coordination_state"
        ]
        == "TERMINATED"
    )
