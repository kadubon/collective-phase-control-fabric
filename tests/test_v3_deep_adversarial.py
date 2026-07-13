# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

import collective_phase_control_fabric.execution_v3 as execution
import collective_phase_control_fabric.generation as generation_module
import collective_phase_control_fabric.workspace_v3 as workspace_v3_module
from collective_phase_control_fabric.bundle import create_bundle, verify_bundle
from collective_phase_control_fabric.canonical import (
    canonical_v3_bytes,
    digest_bytes,
    load_json_strict,
)
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.demos import demo_documents
from collective_phase_control_fabric.engine import _robust_candidate, analyze
from collective_phase_control_fabric.fake_adapter import main as fake_adapter_main
from collective_phase_control_fabric.generation import (
    GenerationStore,
    _atomic_bytes,
    _generation_digest,
    empty_generation,
)
from collective_phase_control_fabric.planner_v3 import _branch_safe, _dominates, _eligible, plan_v3
from collective_phase_control_fabric.science_v3 import (
    _fraction,
    acceleration_evidence,
    effective_independence,
    perturbation_replay_v3,
    validate_formation,
    validate_organization,
    validate_resource_accounting,
    validate_siphon_coverage,
    validate_verification_network,
)
from collective_phase_control_fabric.trust import signature_coordinate, verify_pinned_signature
from collective_phase_control_fabric.workspace_v2 import (
    initialize_workspace,
    rebuild_projections,
)
from collective_phase_control_fabric.workspace_v3 import (
    _lifecycle_status,
    _load_generation_documents,
    _parse_time,
    _pointer,
    _recompute_projection,
    advance_time_v3,
    doctor_v3,
    import_source_v3,
    import_trial_v3,
    initialize_workspace_v3,
    inspect_source_v3,
    inspect_trial_v3,
    migrate_workspace_v3,
    onboard_agent_v3,
    rebuild_projections_v3,
    validate_trust_policy,
    workspace_status_v3,
    workspace_version_v3,
)
from tests.test_v3 import (
    _contract,
    _import,
    _key_material,
    _scientific_documents,
    _workspace,
)


def _runtime_objects(root: Path) -> tuple[dict[str, object], dict[str, list[dict[str, object]]]]:
    manifest = GenerationStore(root).load_manifest()
    branch = {
        "must_add": [],
        "may_add": [],
        "must_remove": [],
        "may_remove": [],
        "resource_intervals": {},
        "debt": [],
        "rollback_obligations": [],
        "projection_possibilities": [],
    }
    effect = {
        "effect_id": "effect:unit",
        "branches": {
            name: deepcopy(branch) for name in ("success", "partial", "failure", "timeout")
        },
    }
    executable = Path(sys.executable).resolve()
    capability = {
        "capability_id": "capability:unit",
        "adapter": "fixture",
        "operation": "unit",
        "effect_class": "inspect",
        "executable": str(executable),
        "executable_digest": digest_bytes(executable.read_bytes()),
        "argv_prefix": [str(executable), "-c", "pass"],
        "output_schema_ref": "adapter-output@0.3.0",
        "outcome_selector": {
            "source_pointer": "/outcome",
            "mapping": {name: name for name in ("success", "partial", "failure", "timeout")},
        },
        "branch_effect_ref": "effect:unit",
    }
    action = {
        "action_id": "action:unit",
        "capability_ref": "capability:unit",
        "arguments": [],
        "input_refs": [],
        "required_authority_refs": [],
        "required_hazard_refs": [],
    }
    return manifest, {
        "action": [action],
        "adapter-capability": [capability],
        "branch-effect-contract": [effect],
    }


def _receipt(payload: bytes, **updates: object) -> dict[str, object]:
    receipt: dict[str, object] = {
        "argv": [sys.executable],
        "working_directory": ".",
        "executable_digest": digest_bytes(Path(sys.executable).read_bytes()),
        "exit_code": 0,
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "stdout_utf8_valid": True,
        "stderr_utf8_valid": True,
        "stdout_raw_hex": payload.hex(),
        "stderr_raw_hex": "",
        "stdout_full_digest": digest_bytes(payload),
        "stderr_full_digest": digest_bytes(b""),
    }
    receipt.update(updates)
    return receipt


def _install_execution_unit(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> dict[str, list[dict[str, object]]]:
    _, objects = _runtime_objects(root)
    monkeypatch.setattr(
        execution,
        "plan_v3",
        lambda _root: {"primary_action": {"action_id": "action:unit"}, "pareto_alternatives": []},
    )
    monkeypatch.setattr(
        execution,
        "_objects",
        lambda _root: (GenerationStore(root).load_manifest(), objects),
    )
    return objects


def test_generation_rejects_partial_corrupt_and_concurrent_state(tmp_path: Path) -> None:
    store = GenerationStore(tmp_path / "missing")
    assert store.current_id() is None
    with pytest.raises(FileNotFoundError):
        store.load_manifest()
    with pytest.raises(ValueError, match="malformed"):
        store.manifest_path("bad")

    root, _, _ = _workspace(tmp_path)
    store = GenerationStore(root)
    current = store.current_id()
    assert current is not None
    manifest = store.load_manifest()
    assert store.commit(manifest, expected_current="sha256:" + "0" * 64)["failure_code"] == (
        "concurrent_generation_comparison_failed"
    )
    invalid = empty_generation(
        contract_digest=str(manifest["contract_digest"]),
        trust_policy_digest=str(manifest["trust_policy_digest"]),
        analysis_epoch=str(manifest["analysis_epoch"]),
    )
    invalid.pop("history")
    assert (
        store.commit(invalid, expected_current=current)["failure_code"]
        == "generation_schema_invalid"
    )

    list_digest = store.put_json([])
    assert store.get_json(list_digest) == []
    manifest_path = store.manifest_path(current)
    original = manifest_path.read_bytes()
    manifest_path.write_bytes(b"[]")
    with pytest.raises(ValueError, match="must be an object"):
        store.load_manifest()
    assert store.verify_chain()[0]["code"] == "generation_invalid"
    manifest_path.write_bytes(original)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(store, "load_manifest", lambda selected=None: {"previous_generation": selected})
    assert store.verify_chain()[0]["code"] == "generation_cycle"
    monkey.undo()


def test_signature_coordinate_never_promotes_unsigned_or_non_object() -> None:
    _, policy = _key_material()
    assert (
        signature_coordinate(
            [],
            policy,
            schema_ref="artifact@0.3.0",
            source_system="fixture",
            role="source",
            evaluation_time="2026-01-15T00:00:00Z",
            required=False,
        )
        == "not_applicable"
    )
    assert (
        signature_coordinate(
            [],
            policy,
            schema_ref="artifact@0.3.0",
            source_system="fixture",
            role="source",
            evaluation_time="2026-01-15T00:00:00Z",
            required=True,
        )
        == "false"
    )
    assert (
        signature_coordinate(
            {},
            policy,
            schema_ref="artifact@0.3.0",
            source_system="fixture",
            role="source",
            evaluation_time="2026-01-15T00:00:00Z",
            required=True,
        )
        == "false"
    )


def test_execution_preflight_binding_and_path_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _ = _workspace(tmp_path)
    objects = _install_execution_unit(monkeypatch, root)
    capability = objects["adapter-capability"][0]

    monkeypatch.setattr(execution, "_resolve_executable", lambda value: None)
    assert (
        execution.run_action_v3(root, "action:unit", apply=True)["failure_code"]
        == "adapter_executable_missing"
    )

    executable = Path(sys.executable).resolve()
    monkeypatch.setattr(
        execution,
        "_resolve_executable",
        lambda value: executable if value == str(executable) else Path(__file__).resolve(),
    )
    capability["argv_prefix"] = ["different"]
    assert (
        execution.run_action_v3(root, "action:unit", apply=True)["failure_code"]
        == "adapter_argv_executable_mismatch"
    )

    monkeypatch.setattr(execution, "_resolve_executable", lambda value: executable)
    capability["argv_prefix"] = [str(executable)]
    capability["executable_digest"] = "sha256:" + "0" * 64
    assert (
        execution.run_action_v3(root, "action:unit", apply=True)["failure_code"]
        == "adapter_executable_digest_mismatch"
    )

    capability["executable_digest"] = digest_bytes(executable.read_bytes())
    capability["argv_prefix"] = [str(executable), str(root / "forbidden")]
    assert (
        execution.run_action_v3(root, "action:unit", apply=True)["failure_code"]
        == "workspace_path_in_adapter_argv"
    )

    monkeypatch.setattr(
        execution, "_objects", lambda _root: (_ for _ in ()).throw(ValueError("broken"))
    )
    assert (
        execution.run_action_v3(root, "action:unit", apply=True)["failure_code"]
        == "action_binding_invalid"
    )


def test_execution_process_status_selector_and_projection_are_authoritative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, _ = _workspace(tmp_path)
    objects = _install_execution_unit(monkeypatch, root)
    capability = objects["adapter-capability"][0]
    effect = objects["branch-effect-contract"][0]

    cases = [
        (_receipt(b"not-json"), "failure"),
        (
            _receipt(
                json.dumps(
                    {"schema_version": "0.3.0", "action_id": "wrong", "outcome": "success"}
                ).encode()
            ),
            "failure",
        ),
        (_receipt(b"{}", timed_out=True), "timeout"),
    ]
    for receipt, expected in cases:
        monkeypatch.setattr(execution, "run_process", lambda *args, value=receipt, **kwargs: value)
        result = execution.run_action_v3(root, "action:unit", apply=True)
        assert result["outcome"] == expected

    valid = {
        "schema_version": "0.3.0",
        "action_id": "action:unit",
        "outcome": "success",
        "observation": {
            "schema_version": "0.3.0",
            "observation_id": "observation:unit",
            "value": "value",
            "source_refs": [],
        },
    }
    payload = json.dumps(valid).encode()
    monkeypatch.setattr(execution, "run_process", lambda *args, **kwargs: _receipt(payload))
    capability["outcome_selector"] = {"source_pointer": "/missing", "mapping": {}}
    assert execution.run_action_v3(root, "action:unit", apply=True)["outcome"] == "failure"

    capability["outcome_selector"] = {
        "source_pointer": "/outcome",
        "mapping": {"success": "success"},
    }
    effect["branches"]["success"]["projection_possibilities"] = [
        {"source_pointer": "/observation", "target_schema": "state-marking@0.3.0"},
        {"source_pointer": "/missing", "target_schema": "adapter-observation@0.3.0"},
    ]
    result = execution.run_action_v3(root, "action:unit", apply=True)
    assert result["outcome"] == "success"
    assert result["source_backed_post_state"] == "false"
    assert len(result["projection_errors"]) == 2

    capability["output_schema_ref"] = "invalid"
    assert execution.run_action_v3(root, "action:unit", apply=True)["outcome"] == "failure"


def test_planner_rejects_hazard_expiry_retry_and_malformed_branches(tmp_path: Path) -> None:
    contract = _contract()
    state = {"states": {"authority", "hazard", "seed"}, "resources": {}, "units": {}}
    branch = {
        "must_add": [],
        "may_add": [],
        "must_remove": [],
        "may_remove": [],
        "resource_intervals": {},
        "debt": [],
        "rollback_obligations": [],
        "projection_possibilities": [],
    }
    effect = {
        "effect_id": "effect",
        "branches": {
            name: deepcopy(branch) for name in ("success", "partial", "failure", "timeout")
        },
    }
    capability = {"branch_effect_ref": "effect"}
    action = {
        "action_id": "action",
        "capability_ref": "cap",
        "input_refs": ["seed"],
        "required_authority_refs": ["authority"],
        "required_hazard_refs": ["hazard"],
        "expires_at": "bad",
    }
    eligible, rejected = _eligible(
        [action],
        {"cap": capability},
        {"effect": effect},
        state,
        contract,
        exhausted_actions={"action"},
    )
    assert not eligible
    reasons = rejected[0]["reasons"]
    assert "action_retry_limit_reached" in reasons
    assert "action_expiry_invalid" in reasons

    action["expires_at"] = "2026-12-01T00:00:00Z"
    action["required_hazard_refs"] = ["missing"]
    effect["branches"].pop("timeout")
    _, rejected = _eligible([action], {"cap": capability}, {"effect": effect}, state, contract)
    assert "action_hazard_guard_unavailable" in rejected[0]["reasons"]
    assert "branch_missing:timeout" in rejected[0]["reasons"]

    assert plan_v3(tmp_path / "not-a-workspace")["failure_code"] == "planner_workspace_invalid"


def test_workspace_invalid_input_and_legacy_orientation_paths(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert workspace_version_v3(missing) is None
    assert workspace_status_v3(missing)["execution_allowed"] is False
    assert onboard_agent_v3(missing)["execution_allowed"] is False
    assert rebuild_projections_v3(missing)["failure_code"] == "workspace_generation_invalid"
    assert advance_time_v3(missing, "bad", apply=True)["failure_code"] == ("analysis_epoch_invalid")

    legacy = tmp_path / "legacy"
    (legacy / ".cpcf").mkdir(parents=True)
    (legacy / ".cpcf" / "workspace.json").write_text('{"schema_version":"0.2.0"}', encoding="utf-8")
    assert workspace_version_v3(legacy) == "0.2.0"
    assert workspace_status_v3(legacy)["failure_code"] == "legacy_workspace_inspect_only"

    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert validate_trust_policy(bad)["failure_code"] == "trust_policy_parse_failed"
    assert initialize_workspace_v3(bad, bad, tmp_path / "bad-workspace")["failure_code"] == (
        "input_parse_failed"
    )
    root, _, policy = _workspace(tmp_path / "valid")
    contract_path = tmp_path / "contract-copy.json"
    trust_path = tmp_path / "trust-copy.json"
    contract_path.write_text(json.dumps(_contract()), encoding="utf-8")
    trust_path.write_text(json.dumps(policy), encoding="utf-8")
    assert initialize_workspace_v3(contract_path, trust_path, root)["failure_code"] == (
        "output_already_exists"
    )

    wrong_scope = deepcopy(policy)
    wrong_scope["principals"][0]["scope"] = {"project": "other", "environment": "test"}
    wrong_path = tmp_path / "wrong-trust.json"
    wrong_path.write_text(json.dumps(wrong_scope), encoding="utf-8")
    assert (
        initialize_workspace_v3(contract_path, wrong_path, tmp_path / "wrong-workspace")[
            "failure_code"
        ]
        == "workspace_input_invalid"
    )

    with pytest.raises(ValueError, match="timezone"):
        _parse_time("2026-01-01T00:00:00")
    assert _pointer({"a/b": [{"~": "ok"}]}, "/a~1b/0/~0") == "ok"
    with pytest.raises(ValueError, match="absolute"):
        _pointer({}, "relative")
    with pytest.raises(ValueError, match="scalar"):
        _pointer({"value": 1}, "/value/next")
    assert _lifecycle_status({}, "2026-01-01T00:00:00Z") == "not_applicable"
    assert _lifecycle_status({"expires_at": "bad"}, "2026-01-01T00:00:00Z") == "false"


def test_workspace_source_trial_and_migration_fail_closed(tmp_path: Path) -> None:
    root, _, policy = _workspace(tmp_path)
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps(policy), encoding="utf-8")
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    assert (
        inspect_source_v3(malformed, trust_path, "fixture", "state-marking@0.3.0")["failure_code"]
        == "source_parse_failed"
    )
    assert (
        import_source_v3(malformed, root, "fixture", "state-marking@0.3.0", apply=True)[
            "failure_code"
        ]
        == "source_import_precondition_failed"
    )

    scalar = tmp_path / "scalar.json"
    scalar.write_text("[]", encoding="utf-8")
    assert (
        inspect_source_v3(scalar, trust_path, "fixture", "state-marking@0.3.0")["failure_code"]
        == "source_or_trust_not_object"
    )
    assert (
        import_source_v3(scalar, root, "fixture", "state-marking@0.3.0", apply=True)["failure_code"]
        == "source_schema_invalid"
    )
    assert inspect_trial_v3(scalar, root)["failure_code"] == "trial_result_not_object"
    assert import_trial_v3(scalar, root, apply=True)["failure_code"] == "trial_result_not_object"
    assert import_trial_v3(malformed, root, apply=True)["failure_code"] == "trial_import_failed"

    assert (
        migrate_workspace_v3(root, trust_path, tmp_path / "out", "0.4.0")["failure_code"]
        == "unsupported_migration_target"
    )
    assert (
        migrate_workspace_v3(tmp_path / "no-legacy", trust_path, tmp_path / "out", "0.3.0")[
            "failure_code"
        ]
        == "legacy_contract_missing"
    )
    output = tmp_path / "exists"
    output.mkdir()
    assert migrate_workspace_v3(root, trust_path, output, "0.3.0")["failure_code"] == (
        "output_already_exists"
    )


def test_perturbation_resources_verifier_intervals_and_trial_bindings() -> None:
    contract = _contract()
    documents = _scientific_documents()
    network = documents["transformation-network"]
    marking = documents["state-marking"]
    live = {"authority", "evidence", "seed", "supply", "target"}
    independence = effective_independence(network, None, {"key:test"})
    suite = deepcopy(documents["perturbation-suite"])
    suite["cases"][0]["resource_reductions"] = {"resource": {"quantity": "11", "unit": "token"}}
    replay = perturbation_replay_v3(contract, network, marking, [suite], independence)
    case = replay["results"][0]["case_results"][0]
    assert case["protected_floor_violations"] == ["resource"]
    assert replay["status"] == "false"

    verification = deepcopy(documents["verification-network-witness"])
    verification["stages"][0]["arrival_lower"] = "3"
    verification["stages"][0]["arrival_upper"] = "2"
    verification["stages"][0]["service_lower"] = "4"
    verification["stages"][0]["service_upper"] = "3"
    reasons = validate_verification_network(verification, live)["reasons"]
    assert "verification_arrival_interval_invalid:stage:verify" in reasons
    assert "verification_service_interval_invalid:stage:verify" in reasons

    protocol = {
        "protocol_id": "protocol:test",
        "registered_at": "bad",
        "target_refs": ["target"],
        "observation_window": {"start": "bad"},
        "outcomes": [{"metric": "duration", "direction": "minimize", "unit": "second"}],
        "quality_floors": {"quality": {"quantity": "1", "unit": "score"}},
        "evaluator_key_id": "key:test",
        "source_refs": ["evidence"],
    }
    from collective_phase_control_fabric.canonical import digest_v3_json

    result = {
        "protocol_digest": digest_v3_json(protocol),
        "completed_at": "bad",
        "effect_intervals": [],
        "quality_intervals": [],
        "evaluator_key_id": "key:test",
        "source_refs": ["evidence"],
    }
    report = acceleration_evidence(contract, [protocol], [result], live)
    assert "trial_time_binding_invalid" in report["reasons"]

    protocol["registered_at"] = "2026-01-01T00:00:00Z"
    protocol["observation_window"] = {"start": "2026-01-02T00:00:00Z"}
    result["completed_at"] = "2026-01-03T00:00:00Z"
    result["protocol_digest"] = digest_v3_json(protocol)
    report = acceleration_evidence(contract, [protocol], [result], live)
    assert "trial_outcome_coverage_mismatch" in report["reasons"]

    result["effect_intervals"] = [
        {
            "metric": "duration",
            "direction": "minimize",
            "lower": "bad",
            "upper": "0",
            "unit": "second",
        }
    ]
    report = acceleration_evidence(contract, [protocol], [result], live)
    assert "trial_interval_invalid:duration" in report["reasons"]


def test_projection_recomputation_rejects_every_broken_binding(tmp_path: Path) -> None:
    root, private, _ = _workspace(tmp_path)
    _import(
        tmp_path,
        root,
        private,
        "transformation-network",
        _scientific_documents()["transformation-network"],
    )
    store = GenerationStore(root)
    manifest = store.load_manifest()
    contract, trust = _load_generation_documents(store, manifest)
    record = deepcopy(manifest["projections"][0])
    receipt = store.get_json(str(record["receipt_digest"]))
    assert isinstance(receipt, dict)
    envelope = store.get_json(str(receipt["envelope_digest"]))
    assert isinstance(envelope, dict)

    def check(
        changed_receipt: dict[str, object],
        changed_record: dict[str, object] | None = None,
        changed_trust: dict[str, object] | None = None,
    ) -> list[str]:
        candidate = deepcopy(changed_record or record)
        candidate["receipt_digest"] = store.put_json(changed_receipt)
        result = _recompute_projection(
            store,
            manifest,
            candidate,
            contract,
            changed_trust or trust,
        )
        assert result["status"] == "false"
        return result["reasons"]

    bad_envelope = deepcopy(receipt)
    bad_envelope["envelope_digest"] = store.put_json([])
    assert any(item.startswith("projection_recomputation_error") for item in check(bad_envelope))

    mismatched_envelope = deepcopy(envelope)
    mismatched_envelope["raw_artifact_digest"] = "sha256:" + "0" * 64
    mismatch_receipt = deepcopy(receipt)
    mismatch_receipt["envelope_digest"] = store.put_json(mismatched_envelope)
    assert "raw_digest_binding_mismatch" in check(mismatch_receipt)

    process_envelope = deepcopy(envelope)
    process_envelope["signature_requirement"] = "process_bound"
    process_envelope["scope"] = {"project": "wrong", "environment": "test"}
    process_receipt = deepcopy(receipt)
    process_receipt.update(
        {
            "envelope_digest": store.put_json(process_envelope),
            "invocation_digest": None,
            "executable_digest": None,
            "timed_out": True,
            "stdout_truncated": True,
            "return_code": 1,
            "projected_objects": [],
        }
    )
    reasons = check(process_receipt)
    for expected in (
        "scope_recomputation_failed",
        "process_binding_missing",
        "receipt_projection_binding_invalid",
        "process_output_incomplete",
        "process_return_code_failed",
    ):
        assert expected in reasons

    invalid_record = deepcopy(record)
    invalid_record["schema_ref"] = "adapter-observation@0.3.0"
    invalid_record["object_digest"] = "sha256:" + "1" * 64
    reasons = check(receipt, invalid_record)
    assert "projected_schema_invalid" in reasons
    assert "projected_digest_mismatch" in reasons

    unsigned_raw = canonical_v3_bytes(
        {
            "schema_version": "0.3.0",
            "marking_id": "m",
            "state_refs": [],
            "coordinates": {},
            "source_refs": [],
        }
    )
    unsigned_digest = store.cas.put(unsigned_raw).digest
    unsigned_envelope = deepcopy(envelope)
    unsigned_envelope["raw_artifact_digest"] = unsigned_digest
    unsigned_envelope["schema_ref"] = "state-marking@0.3.0"
    unsigned_receipt = deepcopy(receipt)
    unsigned_receipt["raw_artifact_digest"] = unsigned_digest
    unsigned_receipt["envelope_digest"] = store.put_json(unsigned_envelope)
    assert "signature_recomputation_failed" in check(unsigned_receipt)


def test_legacy_rebuild_rejects_digest_malformed_and_schema_spoofs(tmp_path: Path) -> None:
    contract, _, _ = demo_documents("orientation-only-reachability")
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    root = tmp_path / "v2"
    assert initialize_workspace(contract_path, root)["command_status"] == "ok"
    envelope_dir = root / ".cpcf" / "envelopes"
    envelope_dir.mkdir(parents=True)
    store = ContentAddressedStore(root / ".cpcf" / "cas")

    bad_digest = {
        "envelope_id": "envelope:missing",
        "raw_artifact_digest": "sha256:" + "0" * 64,
        "schema_ref": "state-marking@0.2.0",
    }
    (envelope_dir / "01.json").write_text(json.dumps(bad_digest), encoding="utf-8")
    malformed_artifact = store.put(b"not-json")
    malformed = {
        "envelope_id": "envelope:malformed",
        "raw_artifact_digest": malformed_artifact.digest,
        "schema_ref": "state-marking@0.2.0",
    }
    (envelope_dir / "02.json").write_text(json.dumps(malformed), encoding="utf-8")
    invalid_artifact = store.put(b"{}")
    invalid = {
        "envelope_id": "envelope:invalid",
        "raw_artifact_digest": invalid_artifact.digest,
        "schema_ref": "state-marking@0.2.0",
    }
    (envelope_dir / "03.json").write_text(json.dumps(invalid), encoding="utf-8")
    (envelope_dir / "04.json").write_text("[]", encoding="utf-8")
    report = rebuild_projections(root)
    assert report["command_status"] == "partial"
    assert {item["failure_code"] for item in report["rejected"]} == {
        "digest_mismatch",
        "malformed_report",
        "projection_validation_failed",
    }


def test_cas_canonical_demo_engine_and_deprecated_adapter_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = ContentAddressedStore(tmp_path / "cas")
    with pytest.raises(ValueError, match="malformed"):
        store.get("md5:bad")
    assert store.verify("sha256:" + "0" * 64) is False
    artifact = store.put(b"original")
    artifact.path.write_bytes(b"corrupt")
    with pytest.raises(RuntimeError, match="verification"):
        store.get(artifact.digest)
    with pytest.raises(RuntimeError, match="corrupted"):
        store.put(b"original")

    with pytest.raises(ValueError, match="floating"):
        canonical_v3_bytes({"value": 1.5})  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="exact range"):
        canonical_v3_bytes({"value": 9_007_199_254_740_992})
    with pytest.raises(ValueError, match="unsupported"):
        canonical_v3_bytes({"value": {1, 2}})  # type: ignore[dict-item]

    with pytest.raises(KeyError):
        demo_documents("missing")
    cycle = demo_documents("causal-cycle-without-formation")
    assert cycle[1]["transformations"][0]["required_inputs"] == ["state:target"]
    catalyst = demo_documents("generative-catalyst")
    assert "generative-catalytic-witness@0.2.0" in catalyst[2]
    assert demo_documents("verification-overload-repair")[2]

    assert _robust_candidate({"robustness_policy": []}, {})[0] is False
    robust, reasons = _robust_candidate(
        {"robustness_policy": {}},
        {"single_node_removal_sensitivity": [], "source_system_concentration": {"counts": {}}},
    )
    assert robust is False and len(reasons) == 4
    assert analyze(None, None)["phase_projection"]["structural_status"] == "uninitialized"
    assert analyze(_contract(), None)["phase_projection"]["structural_status"] == "network_missing"

    request = tmp_path / "request.json"
    request.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["fake-adapter", "--request", str(request)])
    assert fake_adapter_main() == 2
    assert "malformed_request" in capsys.readouterr().out
    request.write_text('{"action_id":"action:test"}', encoding="utf-8")
    assert fake_adapter_main() == 0
    assert "legacy_boolean_adapter_deprecated" in capsys.readouterr().out


def test_remaining_fail_closed_coordinates_and_retry_history(tmp_path: Path) -> None:
    private, policy = _key_material()
    malformed_key = {"signature": {}}
    assert verify_pinned_signature(
        malformed_key,
        policy,
        schema_ref="artifact@0.3.0",
        source_system="fixture",
        role="source",
        evaluation_time="2026-01-15T00:00:00Z",
    )["reasons"] == ["signature_key_id_invalid"]
    unknown_key = {"signature": {"key_id": "unknown"}}
    assert verify_pinned_signature(
        unknown_key,
        policy,
        schema_ref="artifact@0.3.0",
        source_system="fixture",
        role="source",
        evaluation_time="2026-01-15T00:00:00Z",
    )["reasons"] == ["pinned_key_unknown_or_duplicate"]

    from tests.test_v3 import _signed

    scoped = _signed(
        private,
        {"schema_version": "0.3.0", "scope": {"project": "wrong"}},
        "artifact@0.3.0",
    )
    report = verify_pinned_signature(
        scoped,
        policy,
        schema_ref="artifact@0.3.0",
        source_system="fixture",
        role="source",
        evaluation_time="2035-01-15T00:00:00Z",
    )
    assert "signature_scope_mismatch" in report["reasons"]
    assert "key_or_signature_outside_validity_interval" in report["reasons"]

    invalid_public = deepcopy(policy)
    invalid_public["principals"][0]["public_key_base64"] = "YQ=="
    assert (
        "ed25519_signature_invalid"
        in verify_pinned_signature(
            scoped,
            invalid_public,
            schema_ref="artifact@0.3.0",
            source_system="fixture",
            role="source",
            evaluation_time="2026-01-15T00:00:00Z",
        )["reasons"]
    )

    robust, reasons = _robust_candidate(
        {
            "robustness_policy": {
                "minimum_independent_target_paths": 2,
                "minimum_independent_verifiers": 2,
                "tolerated_single_failures": 0,
                "minimum_source_systems": 2,
            }
        },
        {
            "independent_target_path_count": 1,
            "verifier_single_point_failure_ids": ["verifier"],
            "single_node_removal_sensitivity": [{"lost_targets": ["target"]}],
            "source_system_concentration": {"counts": {"one": 1}},
        },
    )
    assert robust is False and len(reasons) == 4

    no_trial_contract = deepcopy(_contract())
    no_trial_contract["measurement_protocol_refs"] = []
    assert acceleration_evidence(no_trial_contract, [], [], set())["status"] == "unmeasured"

    root, _, _ = _workspace(tmp_path)
    store = GenerationStore(root)
    manifest = store.load_manifest()
    manifest["history"] = [
        {
            "event_type": "action_executed",
            "action_id": "action:retried",
            "progress": "no_progress",
            "previous_event_digest": "sha256:" + "0" * 64,
        }
    ]
    assert store.commit(manifest, expected_current=store.current_id())["command_status"] == "ok"
    assert plan_v3(root)["command_status"] == "ok"


def test_core_storage_planner_and_science_boundary_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_open = generation_module.os.open

    def directory_open_fails(path: object, flags: int, *args: int) -> int:
        if Path(path) == tmp_path and not args:
            raise OSError("directory fsync unavailable")
        return original_open(path, flags, *args)

    monkeypatch.setattr(generation_module.os, "open", directory_open_fails)
    target = tmp_path / "atomic.json"
    _atomic_bytes(target, b"{}")
    assert target.read_bytes() == b"{}"
    monkeypatch.setattr(generation_module.os, "open", original_open)

    original_fsync = generation_module.os.fsync
    original_close = generation_module.os.close

    def directory_open_succeeds(path: object, flags: int, *args: int) -> int:
        if Path(path) == tmp_path and not args:
            return 987_654
        return original_open(path, flags, *args)

    monkeypatch.setattr(generation_module.os, "open", directory_open_succeeds)
    monkeypatch.setattr(
        generation_module.os,
        "fsync",
        lambda descriptor: None if descriptor == 987_654 else original_fsync(descriptor),
    )
    monkeypatch.setattr(
        generation_module.os,
        "close",
        lambda descriptor: None if descriptor == 987_654 else original_close(descriptor),
    )
    second_target = tmp_path / "atomic-fsync.json"
    _atomic_bytes(second_target, b"{}")
    assert second_target.read_bytes() == b"{}"
    monkeypatch.setattr(generation_module.os, "open", original_open)
    monkeypatch.setattr(generation_module.os, "fsync", original_fsync)
    monkeypatch.setattr(generation_module.os, "close", original_close)

    root, _, _ = _workspace(tmp_path / "storage")
    store = GenerationStore(root)
    current = store.current_id()
    assert current is not None
    path = store.manifest_path(current)
    original = path.read_bytes()
    manifest = store.load_manifest()
    changed = deepcopy(manifest)
    changed["analysis_epoch"] = "2026-01-16T00:00:00Z"
    path.write_bytes(canonical_v3_bytes(changed))
    with pytest.raises(ValueError, match="digest mismatch"):
        store.load_manifest()
    path.write_bytes(original)

    invalid = deepcopy(manifest)
    invalid.pop("history")
    invalid.pop("generation_id")
    invalid_id = _generation_digest(invalid)
    invalid["generation_id"] = invalid_id
    invalid_path = store.manifest_path(invalid_id)
    invalid_path.parent.mkdir(parents=True)
    invalid_path.write_bytes(canonical_v3_bytes(invalid))
    with pytest.raises(ValueError, match="schema invalid"):
        store.load_manifest(invalid_id)

    state = {
        "states": {"authority"},
        "resources": {"resource": 0},
        "units": {"resource": "token"},
    }
    unsafe, reasons = _branch_safe(
        state,
        {
            "must_remove": ["authority"],
            "may_remove": [],
            "must_add": [],
            "resource_intervals": {"ignored": "bad"},
        },
        {
            "protected_floors": {
                "malformed": "bad",
                "resource": {"quantity": "1", "unit": "token"},
            }
        },
        {"authority"},
    )
    assert unsafe is False
    assert "authority_not_preserved" in reasons
    assert "protected_floor_malformed:malformed" in reasons
    assert "protected_floor_violation:resource" in reasons

    def reports(additions: int, debt: int, resources: dict[str, str]) -> dict[str, object]:
        return {
            "branch_reports": {
                name: {
                    "guaranteed_addition_count": additions,
                    "debt_count": debt,
                    "resource_lower_changes": resources,
                    "resource_units": {key: "token" for key in resources},
                }
                for name in ("success", "partial", "failure", "timeout")
            }
        }

    assert _dominates(reports(0, 0, {}), reports(1, 0, {})) is False
    assert _dominates(reports(1, 1, {}), reports(1, 0, {})) is False
    assert _dominates(reports(1, 0, {"a": "0"}), reports(1, 0, {})) is False
    assert _dominates(reports(1, 0, {"a": "-1"}), reports(1, 0, {"a": "0"})) is False

    contract = _contract()
    documents = _scientific_documents()
    network = documents["transformation-network"]
    marking = documents["state-marking"]
    live = {"authority", "evidence", "seed", "supply", "target"}
    with pytest.raises(ValueError, match="bit-length"):
        _fraction("1024", 2)
    bad_organization = deepcopy(documents["organization-witness"])
    bad_organization["flux"] = {"transform:target": "bad"}
    assert "Invalid literal" in " ".join(
        validate_organization(contract, network, bad_organization, live)["reasons"]
    )
    short_contract = deepcopy(contract)
    short_contract["formation_policy"]["maximum_layer_count"] = 0
    assert (
        "formation_layer_limit_invalid"
        in validate_formation(
            short_contract,
            network,
            marking,
            documents["formation-sequence-witness"],
            documents["organization-witness"],
        )["reasons"]
    )
    incomplete_resource = deepcopy(documents["open-system-resource-witness"])
    incomplete_resource["coordinate_weights"] = {}
    incomplete_resource["protected_coordinates"] = []
    reasons = validate_resource_accounting(
        contract, network, incomplete_resource, {"missing"}, live
    )["reasons"]
    assert "resource_weight_coordinate_coverage_invalid" in reasons
    assert "protected_coordinate_positive_weights_required" in reasons
    assert "resource_transformation_missing:missing" in reasons
    uncovered = deepcopy(documents["siphon-coverage-witness"])
    uncovered["coverage_refs"] = {}
    assert any(
        item.startswith("siphon_uncovered")
        for item in validate_siphon_coverage(contract, network, uncovered, live)["reasons"]
    )


def test_workspace_v3_migration_and_doctor_error_boundaries(tmp_path: Path) -> None:
    _, policy = _key_material()
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps(policy), encoding="utf-8")
    assert doctor_v3(tmp_path / "missing")["failure_code"] == "workspace_generation_invalid"

    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "contract.json").write_text("[]", encoding="utf-8")
    assert (
        migrate_workspace_v3(legacy, trust_path, tmp_path / "out-a", "0.3.0")["failure_code"]
        == "migration_input_invalid"
    )
    (legacy / "contract.json").write_text("{", encoding="utf-8")
    assert (
        migrate_workspace_v3(legacy, trust_path, tmp_path / "out-b", "0.3.0")["failure_code"]
        == "migration_input_invalid"
    )
    (legacy / "contract.json").write_text(json.dumps({"schema_version": "0.2.0"}), encoding="utf-8")
    wrong_scope = deepcopy(policy)
    wrong_scope["principals"][0]["scope"] = {"project": "different", "environment": "test"}
    wrong_path = tmp_path / "wrong.json"
    wrong_path.write_text(json.dumps(wrong_scope), encoding="utf-8")
    assert (
        migrate_workspace_v3(legacy, wrong_path, tmp_path / "out-c", "0.3.0")["failure_code"]
        == "migrated_contract_invalid"
    )

    scalar_trial = tmp_path / "trial.json"
    scalar_trial.write_text("{}", encoding="utf-8")
    assert inspect_trial_v3(scalar_trial, tmp_path / "missing")["failure_code"] == (
        "trial_inspection_failed"
    )


def test_workspace_v3_depth_scope_history_and_trial_rejections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private, policy = _key_material()
    contract = _contract()
    contract_path = tmp_path / "contract.json"
    trust_path = tmp_path / "trust.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    trust_path.write_text(json.dumps(policy), encoding="utf-8")
    root = tmp_path / "workspace"
    assert initialize_workspace_v3(contract_path, trust_path, root)["command_status"] == "ok"

    from tests.test_v3 import _signed

    marking_path = tmp_path / "marking.json"
    marking_path.write_text(
        json.dumps(
            _signed(
                private,
                _scientific_documents()["state-marking"],
                "state-marking@0.3.0",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(workspace_v3_module, "_json_depth", lambda value: 10_000)
    assert (
        import_source_v3(marking_path, root, "fixture", "state-marking@0.3.0", apply=True)[
            "failure_code"
        ]
        == "analysis_limit_exceeded"
    )
    monkeypatch.undo()

    monkeypatch.setattr(
        workspace_v3_module,
        "verify_pinned_signature",
        lambda *args, **kwargs: {"status": "true", "key_id": "key:test", "reasons": []},
    )
    original_loader = workspace_v3_module._load_generation_documents

    def wrong_scope_loader(
        store: GenerationStore, manifest: dict[str, object]
    ) -> tuple[dict[str, object], dict[str, object]]:
        loaded_contract, loaded_trust = original_loader(store, manifest)
        changed = deepcopy(loaded_trust)
        changed["principals"][0]["scope"] = {"project": "wrong", "environment": "test"}
        return loaded_contract, changed

    monkeypatch.setattr(workspace_v3_module, "_load_generation_documents", wrong_scope_loader)
    assert (
        import_source_v3(marking_path, root, "fixture", "state-marking@0.3.0", apply=True)[
            "failure_code"
        ]
        == "source_scope_mismatch"
    )
    monkeypatch.undo()

    store = GenerationStore(root)
    manifest = store.load_manifest()
    manifest["history"] = [{"event_type": "invalid"}]
    assert store.commit(manifest, expected_current=store.current_id())["command_status"] == "ok"
    assert doctor_v3(root)["failure_code"] == "workspace_audit_failed"
    assert onboard_agent_v3(root)["execution_allowed"] is False

    invalid_trial = tmp_path / "invalid-trial.json"
    invalid_trial.write_text('{"evaluator_key_id":"unknown"}', encoding="utf-8")
    assert import_trial_v3(invalid_trial, root, apply=True)["failure_code"] == (
        "trusted_evaluator_source_system_missing"
    )


def test_v3_portable_bundle_preserves_generation_authority(tmp_path: Path) -> None:
    root, private, _ = _workspace(tmp_path)
    _import(
        tmp_path,
        root,
        private,
        "state-marking",
        _scientific_documents()["state-marking"],
    )
    bundle = tmp_path / "portable"
    manifest = create_bundle(root, bundle)
    assert manifest["bundle_schema_version"] == "0.3.0"
    checked = verify_bundle(bundle)
    assert checked["valid"] is True
    assert checked["generation_chain_errors"] == []
    assert checked["doctor_errors"] == []

    value = load_json_strict(bundle / "manifest.json")
    assert isinstance(value, dict)
    value["objects"].append(deepcopy(value["objects"][0]))
    from collective_phase_control_fabric.canonical import write_canonical

    write_canonical(bundle / "manifest.json", value)
    assert any(item.startswith("duplicate_object_path") for item in verify_bundle(bundle)["errors"])
