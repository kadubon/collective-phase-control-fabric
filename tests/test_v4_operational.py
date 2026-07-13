# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import shutil
import sys
from copy import deepcopy
from pathlib import Path

import pytest

import collective_phase_control_fabric.cli as cli_module
from collective_phase_control_fabric.bundle import create_bundle, verify_bundle
from collective_phase_control_fabric.canonical import digest_v3_json, write_canonical
from collective_phase_control_fabric.cli import build_parser, dispatch
from collective_phase_control_fabric.execution_v4 import run_action_v4
from collective_phase_control_fabric.generation import GenerationStore
from collective_phase_control_fabric.generation_v4 import GenerationStoreV4
from collective_phase_control_fabric.planner_v4 import plan_v4
from collective_phase_control_fabric.trials_v4 import (
    acceleration_status_v4,
    import_protocol_v4,
    import_result_v4,
    inspect_protocol_v4,
    inspect_result_v4,
)
from collective_phase_control_fabric.trust_v4 import key_fingerprint
from collective_phase_control_fabric.workspace_v4 import (
    _migrate_contract,
    advance_time_v4,
    doctor_v4,
    migrate_workspace_v4,
    onboard_v4,
    repair_list_v4,
    scaffold_contract_v4,
    status_v4,
    update_trust_policy_v4,
)
from tests.test_v4 import (
    NOW,
    _contract,
    _import_record,
    _key,
    _policy,
    _public,
    _statement,
    _workspace,
)


def _interval(lower: str = "0", upper: str = "0", unit: str = "unit") -> dict[str, str]:
    return {"lower": lower, "upper": upper, "unit": unit}


def _branch(must_add: list[str]) -> dict[str, object]:
    return {
        "must_add": must_add,
        "may_add": [],
        "must_remove": [],
        "may_remove": [],
        "debt": [],
        "rollback_obligations": [],
        "independence_domains_removed": [],
        "resource_intervals": {},
        "time_interval": _interval(unit="second"),
        "cost_interval": _interval(unit="credit"),
        "quality_interval": _interval(unit="quality"),
        "verification_load_upper": "0",
        "projection_possibilities": [],
    }


def _action_attributes(
    *,
    executable: str = "unused",
    executable_digest: str | None = None,
    code: str = "",
) -> dict[str, object]:
    branches = {
        name: _branch(["state:target"]) for name in ("success", "partial", "failure", "timeout")
    }
    return {
        "evidence_type": "action",
        "executable": executable,
        "executable_digest": executable_digest or "sha256:" + "0" * 64,
        "argv_prefix": [executable, "-c", code] if code else [executable],
        "arguments": [],
        "execution_policy": {
            "schema_version": "0.4.0",
            "policy_id": "execution:test",
            "timeout_seconds": 10,
            "stdin_bytes": 0,
            "stdout_bytes": 1_048_576,
            "stderr_bytes": 1_048_576,
            "permitted_environment_keys": ["PATH", "SYSTEMROOT"],
        },
        "output_schema_ref": "adapter-output@0.4.0",
        "outcome_selector": {
            "source_pointer": "/outcome",
            "mapping": {"success": "success"},
        },
        "input_refs": ["state:seed"],
        "required_authority_refs": ["authority:run"],
        "required_hazard_refs": [],
        "expires_at": "2026-12-31T00:00:00Z",
        "repeatable": False,
        "branches": branches,
        "must_add": ["state:target"],
        "resource_intervals": {},
        "debt": [],
        "verification_load": "0",
        "independence_erosion": 0,
    }


def _execution_case(
    tmp_path: Path,
    name: str,
    code: str,
    *,
    update: dict[str, object] | None = None,
) -> tuple[Path, str]:
    case = tmp_path / name
    case.mkdir()
    contract = _contract()
    contract["target_states"] = ["state:target"]
    workspace, source, _ = _workspace(case, contract)
    _import_record(
        case,
        workspace,
        source,
        attestation_id=f"attestation:seed-{name}",
        record_type="state",
        subject_id="state:seed",
        attributes={"available": True},
    )
    _import_record(
        case,
        workspace,
        source,
        attestation_id=f"attestation:authority-{name}",
        record_type="authority",
        subject_id="authority:run",
        attributes={},
    )
    executable = str(Path(sys.executable).resolve())
    digest = "sha256:" + hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    attributes = _action_attributes(executable=executable, executable_digest=digest, code=code)
    if update:
        attributes.update(update)
    action_id = f"action:{name}"
    _import_record(
        case,
        workspace,
        source,
        attestation_id=f"attestation:action-{name}",
        record_type="evidence",
        subject_id=action_id,
        attributes=attributes,
    )
    return workspace, action_id


def test_planner_filters_before_cap_and_reports_overflow(monkeypatch: pytest.MonkeyPatch) -> None:
    contract = _contract()
    contract["target_states"] = ["state:target"]
    manifest = {"generation_id": "sha256:" + "a" * 64, "analysis_epoch": NOW}
    state_statement = {
        "payload": {
            "record_type": "state",
            "subject_id": "state:seed",
            "attributes": {"available": True},
        }
    }
    authority_statement = {
        "payload": {
            "record_type": "authority",
            "subject_id": "authority:run",
            "attributes": {},
        }
    }

    def action(number: int, valid: bool) -> dict[str, object]:
        attributes = _action_attributes()
        attributes["input_refs"] = ["state:seed"] if valid else [f"missing:{number}"]
        return {
            "payload": {
                "record_type": "evidence",
                "subject_id": f"action:{number:03d}",
                "attributes": attributes,
            }
        }

    invalid_first = [action(number, False) for number in range(65)]
    valid_last = action(999, True)
    monkeypatch.setattr(
        "collective_phase_control_fabric.planner_v4.active_attestations_v4",
        lambda root: (
            manifest,
            contract,
            [state_statement, authority_statement, *invalid_first, valid_last],
            [],
        ),
    )
    monkeypatch.setattr(
        "collective_phase_control_fabric.planner_v4.science_audit_v4",
        lambda root: {"operational_organization_profile": {}, "unknowns": []},
    )
    planned = plan_v4(Path("unused"))
    assert planned["primary_action"]["action_id"] == "action:999"
    assert len(planned["rejected_actions"]) == 65

    valid = [action(number, True) for number in range(65)]
    monkeypatch.setattr(
        "collective_phase_control_fabric.planner_v4.active_attestations_v4",
        lambda root: (manifest, contract, [state_statement, authority_statement, *valid], []),
    )
    overflow = plan_v4(Path("unused"))
    assert overflow["failure_code"] == "candidate_set_overflow_unknown"
    assert overflow["unknowns"] == ["primary_action", "complete_contingent_policy"]


def test_local_execution_commits_closed_receipts_without_promoting_output(tmp_path: Path) -> None:
    contract = _contract()
    contract["target_states"] = ["state:target"]
    workspace, source, _ = _workspace(tmp_path, contract)
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:seed-exec",
        record_type="state",
        subject_id="state:seed",
        attributes={"available": True},
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:authority-exec",
        record_type="authority",
        subject_id="authority:run",
        attributes={},
    )
    executable = str(Path(sys.executable).resolve())
    digest = "sha256:" + hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    code = "import json;print(json.dumps({'outcome':'success'}))"
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:action-exec",
        record_type="evidence",
        subject_id="action:exec",
        attributes=_action_attributes(
            executable=executable,
            executable_digest=digest,
            code=code,
        ),
    )
    plan = plan_v4(workspace)
    assert plan["primary_action"]["action_id"] == "action:exec"
    assert run_action_v4(workspace, "action:exec", apply=False)["failure_code"] == "apply_required"
    assert run_action_v4(workspace, "action:missing", apply=True)["failure_code"] == (
        "action_not_currently_safe_or_selected"
    )
    executed = run_action_v4(workspace, "action:exec", apply=True)
    assert executed["command_status"] == "ok"
    assert executed["outcome"] == "success"
    assert executed["source_backed_post_state"] == "unknown"
    assert executed["quarantined_objects"]
    assert doctor_v4(workspace)["command_status"] == "ok"


def test_nonzero_process_status_is_authoritative_failure(tmp_path: Path) -> None:
    contract = _contract()
    contract["target_states"] = ["state:target"]
    workspace, source, _ = _workspace(tmp_path, contract)
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:seed-failure",
        record_type="state",
        subject_id="state:seed",
        attributes={"available": True},
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:authority-failure",
        record_type="authority",
        subject_id="authority:run",
        attributes={},
    )
    executable = str(Path(sys.executable).resolve())
    digest = "sha256:" + hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:action-failure",
        record_type="evidence",
        subject_id="action:failure",
        attributes=_action_attributes(
            executable=executable,
            executable_digest=digest,
            code="raise SystemExit(7)",
        ),
    )
    executed = run_action_v4(workspace, "action:failure", apply=True)
    assert executed["command_status"] == "ok"
    assert executed["outcome"] == "failure"
    assert executed["source_backed_post_state"] == "unknown"


def test_v4_execution_timeout_truncation_malformed_selector_and_mutation(tmp_path: Path) -> None:
    workspace, action_id = _execution_case(
        tmp_path,
        "timeout",
        "import time; time.sleep(2)",
        update={
            "execution_policy": {
                "schema_version": "0.4.0",
                "policy_id": "execution:timeout",
                "timeout_seconds": 1,
                "stdin_bytes": 0,
                "stdout_bytes": 1024,
                "stderr_bytes": 1024,
                "permitted_environment_keys": [],
            }
        },
    )
    assert run_action_v4(workspace, action_id, apply=False)["failure_code"] == "apply_required"
    assert run_action_v4(workspace, "action:missing", apply=True)["failure_code"] == (
        "action_not_currently_safe_or_selected"
    )
    timeout = run_action_v4(workspace, action_id, apply=True)
    assert timeout["outcome"] == "timeout"

    truncated_workspace, truncated_action = _execution_case(
        tmp_path,
        "truncated",
        "print('x' * 10000)",
        update={
            "execution_policy": {
                "schema_version": "0.4.0",
                "policy_id": "execution:truncated",
                "timeout_seconds": 10,
                "stdin_bytes": 0,
                "stdout_bytes": 64,
                "stderr_bytes": 64,
                "permitted_environment_keys": [],
            }
        },
    )
    truncated = run_action_v4(truncated_workspace, truncated_action, apply=True)
    assert truncated["outcome"] == "failure"

    malformed_workspace, malformed_action = _execution_case(
        tmp_path, "malformed", "print('not-json')"
    )
    malformed = run_action_v4(malformed_workspace, malformed_action, apply=True)
    assert malformed["outcome"] == "failure"

    selector_workspace, selector_action = _execution_case(
        tmp_path,
        "selector",
        'print(\'{"outcome": "forged"}\')',
        update={
            "outcome_selector": {
                "source_pointer": "/missing",
                "mapping": {"success": "success"},
            }
        },
    )
    selector = run_action_v4(selector_workspace, selector_action, apply=True)
    assert selector["outcome"] == "failure"

    mutation_case = tmp_path / "mutation"
    mutation_case.mkdir()
    contract = _contract()
    contract["target_states"] = ["state:target"]
    mutation_workspace, source, _ = _workspace(mutation_case, contract)
    for identifier, record_type, attributes in (
        ("state:seed", "state", {"available": True}),
        ("authority:run", "authority", {}),
    ):
        _import_record(
            mutation_case,
            mutation_workspace,
            source,
            attestation_id=f"attestation:{record_type}-mutation",
            record_type=record_type,
            subject_id=identifier,
            attributes=attributes,
        )
    executable = str(Path(sys.executable).resolve())
    digest = "sha256:" + hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    mutation_target = str(mutation_workspace / ".cpcf" / "unexpected")
    split = len(mutation_target) // 2
    mutation_code = (
        "from pathlib import Path; "
        f"Path({mutation_target[:split]!r} + {mutation_target[split:]!r}).write_text('x'); "
        'print(\'{"outcome": "success"}\')'
    )
    _import_record(
        mutation_case,
        mutation_workspace,
        source,
        attestation_id="attestation:action-mutation",
        record_type="evidence",
        subject_id="action:mutation",
        attributes=_action_attributes(
            executable=executable, executable_digest=digest, code=mutation_code
        ),
    )
    mutation = run_action_v4(mutation_workspace, "action:mutation", apply=True)
    assert mutation["failure_code"] == "unexpected_workspace_mutation_during_adapter_execution"


def test_external_registration_result_binding_and_uniqueness(tmp_path: Path) -> None:
    workspace, _, policy = _workspace(tmp_path)
    root = _key(1)
    dataset = tmp_path / "dataset.json"
    executable = tmp_path / "analysis.json"
    write_canonical(dataset, {"rows": [1, 2, 3]})
    write_canonical(executable, {"analysis": "fixed"})
    from collective_phase_control_fabric.workspace_v4 import import_raw_v4

    dataset_result = import_raw_v4(dataset, workspace, "local", "dataset@0.4.0", apply=True)
    executable_result = import_raw_v4(
        executable, workspace, "local", "analysis-executable@0.4.0", apply=True
    )
    protocol_payload = {
        "schema_version": "0.4.0",
        "protocol_id": "protocol:one",
        "primary_result_id": "result:one",
        "eligibility": {"population": "fixed"},
        "treatment_strategy": {"name": "cpcf"},
        "comparison_strategy": {"name": "control"},
        "assignment": {"method": "external"},
        "time_zero": "2026-07-02T00:00:00Z",
        "observation_end": "2026-07-03T00:00:00Z",
        "estimand": {"contrast": "difference"},
        "primary_outcomes": ["time"],
        "dataset_commitment_digest": dataset_result["raw_digest"],
        "analysis_executable_digest": executable_result["raw_digest"],
        "quality_floors": {"quality": {"quantity": "0", "unit": "quality"}},
        "safety_floors": {"safety": {"quantity": "0", "unit": "safety"}},
        "missing_data_policy": {"method": "fixed"},
        "stopping_rule": {"rule": "fixed_end"},
        "exclusion_policy": {"rule": "none"},
        "amendment_policy": {"post_start": "deviation"},
        "evaluator_key_id": "key:root",
        "registration_key_id": "key:root",
    }
    protocol = _statement(
        root,
        protocol_payload,
        schema_ref="measurement-protocol@0.4.0",
        key_id="key:root",
        role="protocol_author",
        source_system="author",
        signed_at="2026-06-30T00:00:00Z",
    )
    registration_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "registration:one",
        "protocol_digest": digest_v3_json(protocol),
        "registered_at": "2026-07-01T00:00:00Z",
        "serial": 1,
    }
    registration = _statement(
        root,
        registration_payload,
        schema_ref="registration-receipt@0.4.0",
        key_id="key:root",
        role="registration",
        source_system="registry",
        signed_at="2026-07-01T00:00:00Z",
    )
    protocol_path = tmp_path / "protocol.json"
    registration_path = tmp_path / "registration.json"
    write_canonical(protocol_path, protocol)
    write_canonical(registration_path, registration)
    assert (
        inspect_protocol_v4(protocol_path, registration_path, workspace)["command_status"] == "ok"
    )
    assert (
        import_protocol_v4(protocol_path, registration_path, workspace, apply=False)["failure_code"]
        == "apply_required"
    )
    bad_registration = deepcopy(registration)
    bad_registration["payload"]["protocol_digest"] = "sha256:" + "0" * 64
    bad_registration_path = tmp_path / "bad-registration.json"
    write_canonical(bad_registration_path, bad_registration)
    assert (
        inspect_protocol_v4(protocol_path, bad_registration_path, workspace)["failure_code"]
        == "trial_protocol_invalid"
    )
    missing_protocol = inspect_protocol_v4(
        tmp_path / "missing-protocol.json", registration_path, workspace
    )
    assert missing_protocol["failure_code"] == "trial_protocol_input_invalid"
    nonobject_protocol_path = tmp_path / "nonobject-protocol.json"
    write_canonical(nonobject_protocol_path, [])
    assert (
        inspect_protocol_v4(nonobject_protocol_path, registration_path, workspace)["failure_code"]
        == "trial_protocol_input_not_object"
    )
    protocol_cases = []
    after_start = deepcopy(registration)
    after_start["payload"]["registered_at"] = "2026-07-02T00:00:00Z"
    protocol_cases.append(("after-start", protocol, after_start))
    reversed_window = deepcopy(protocol)
    reversed_window["payload"]["observation_end"] = "2026-07-01T00:00:00Z"
    protocol_cases.append(("window", reversed_window, registration))
    invalid_time = deepcopy(protocol)
    invalid_time["payload"]["time_zero"] = "not-a-time"
    protocol_cases.append(("time", invalid_time, registration))
    wrong_principal = deepcopy(protocol)
    wrong_principal["payload"]["registration_key_id"] = "key:other"
    protocol_cases.append(("principal", wrong_principal, registration))
    no_registration_payload = deepcopy(registration)
    no_registration_payload["payload"] = None
    protocol_cases.append(("payload", protocol, no_registration_payload))
    for name, protocol_case, registration_case in protocol_cases:
        protocol_case_path = tmp_path / f"protocol-{name}.json"
        registration_case_path = tmp_path / f"registration-{name}.json"
        write_canonical(protocol_case_path, protocol_case)
        write_canonical(registration_case_path, registration_case)
        assert (
            inspect_protocol_v4(protocol_case_path, registration_case_path, workspace)[
                "failure_code"
            ]
            == "trial_protocol_invalid"
        )
        assert (
            import_protocol_v4(protocol_case_path, registration_case_path, workspace, apply=True)[
                "failure_code"
            ]
            == "trial_protocol_invalid"
        )
    imported_protocol = import_protocol_v4(protocol_path, registration_path, workspace, apply=True)
    assert imported_protocol["acceleration_status"] == "registered_not_observed"
    assert (
        import_protocol_v4(protocol_path, registration_path, workspace, apply=True)["failure_code"]
        == "trial_protocol_already_imported"
    )
    protocol_digest = imported_protocol["protocol_digest"]
    result_payload = {
        "schema_version": "0.4.0",
        "result_id": "result:one",
        "protocol_id": "protocol:one",
        "protocol_digest": protocol_digest,
        "dataset_digest": dataset_result["raw_digest"],
        "analysis_executable_digest": executable_result["raw_digest"],
        "observation_started_at": "2026-07-02T00:00:00Z",
        "observation_ended_at": "2026-07-03T00:00:00Z",
        "completed_at": "2026-07-04T00:00:00Z",
        "effect_intervals": {"time": {"lower": "-2", "upper": "-1", "unit": "hour"}},
        "quality_intervals": {"quality": {"lower": "1", "upper": "2", "unit": "quality"}},
        "safety_intervals": {"safety": {"lower": "1", "upper": "2", "unit": "safety"}},
        "amendment_chain_digest": None,
    }
    result = _statement(
        root,
        result_payload,
        schema_ref="trial-result-certificate@0.4.0",
        key_id="key:root",
        role="evaluator",
        source_system="evaluator",
        signed_at="2026-07-04T00:00:00Z",
    )
    result_path = tmp_path / "result.json"
    write_canonical(result_path, result)
    assert inspect_result_v4(result_path, workspace)["command_status"] == "ok"
    assert import_result_v4(result_path, workspace, apply=False)["failure_code"] == "apply_required"
    assert (
        inspect_result_v4(tmp_path / "missing-result.json", workspace)["failure_code"]
        == "trial_result_input_invalid"
    )
    nonobject_result_path = tmp_path / "nonobject-result.json"
    write_canonical(nonobject_result_path, [])
    assert (
        inspect_result_v4(nonobject_result_path, workspace)["failure_code"]
        == "trial_result_not_object"
    )
    for name, mutate in (
        (
            "orientation",
            lambda value: value["payload"]["effect_intervals"]["time"].update(
                {"lower": "2", "upper": "1"}
            ),
        ),
        (
            "future",
            lambda value: value["payload"].update({"completed_at": "2026-08-01T00:00:00Z"}),
        ),
        (
            "dataset",
            lambda value: value["payload"].update({"dataset_digest": "sha256:" + "f" * 64}),
        ),
        (
            "amendment",
            lambda value: value["payload"].update({"amendment_chain_digest": "sha256:" + "e" * 64}),
        ),
        ("protocol", lambda value: value["payload"].update({"protocol_id": "missing"})),
        (
            "protocol-digest",
            lambda value: value["payload"].update({"protocol_digest": "sha256:" + "d" * 64}),
        ),
        ("result-id", lambda value: value["payload"].update({"result_id": "not-primary"})),
        (
            "analysis",
            lambda value: value["payload"].update(
                {"analysis_executable_digest": "sha256:" + "c" * 64}
            ),
        ),
        (
            "outside-window",
            lambda value: value["payload"].update(
                {"observation_started_at": "2026-06-01T00:00:00Z"}
            ),
        ),
        (
            "bad-time",
            lambda value: value["payload"].update({"observation_started_at": "not-a-time"}),
        ),
        (
            "interval-object",
            lambda value: value["payload"]["effect_intervals"].update({"time": "bad"}),
        ),
        (
            "interval-number",
            lambda value: value["payload"]["effect_intervals"]["time"].update(
                {"lower": "not-a-number"}
            ),
        ),
        ("interval-map", lambda value: value["payload"].update({"effect_intervals": []})),
    ):
        changed_payload = deepcopy(result_payload)
        changed = _statement(
            root,
            changed_payload,
            schema_ref="trial-result-certificate@0.4.0",
            key_id="key:root",
            role="evaluator",
            source_system="evaluator",
            signed_at="2026-07-04T00:00:00Z",
        )
        mutate(changed)
        changed_path = tmp_path / f"bad-result-{name}.json"
        write_canonical(changed_path, changed)
        assert inspect_result_v4(changed_path, workspace)["failure_code"] == "trial_result_invalid"
        assert import_result_v4(changed_path, workspace, apply=True)["failure_code"] == (
            "trial_result_invalid"
        )
    no_payload_result = deepcopy(result)
    no_payload_result["payload"] = None
    no_payload_result_path = tmp_path / "result-no-payload.json"
    write_canonical(no_payload_result_path, no_payload_result)
    assert inspect_result_v4(no_payload_result_path, workspace)["failure_code"] == (
        "trial_result_invalid"
    )

    contradiction_workspace = tmp_path / "contradiction-workspace"
    shutil.copytree(workspace, contradiction_workspace)
    contradiction_payload = deepcopy(result_payload)
    contradiction_payload["effect_intervals"] = {
        "time": {"lower": "1", "upper": "2", "unit": "hour"},
        "quality": {"lower": "-2", "upper": "-1", "unit": "quality"},
    }
    contradiction_payload["quality_intervals"] = {}
    contradiction = _statement(
        root,
        contradiction_payload,
        schema_ref="trial-result-certificate@0.4.0",
        key_id="key:root",
        role="evaluator",
        source_system="evaluator",
        signed_at="2026-07-04T00:00:00Z",
    )
    contradiction_path = tmp_path / "contradiction.json"
    write_canonical(contradiction_path, contradiction)
    imported_contradiction = import_result_v4(
        contradiction_path, contradiction_workspace, apply=True
    )
    assert imported_contradiction["acceleration_status"] == (
        "external_quality_or_safety_contradiction"
    )
    imported_result = import_result_v4(result_path, workspace, apply=True)
    assert imported_result["acceleration_status"] == "external_acceleration_bundle_compatible"
    assert acceleration_status_v4(workspace)["primary_result_count"] == 1
    duplicate = deepcopy(result)
    duplicate_path = tmp_path / "duplicate-result.json"
    write_canonical(duplicate_path, duplicate)
    rejected = import_result_v4(duplicate_path, workspace, apply=True)
    assert rejected["failure_code"] == "multiple_primary_trial_results_contradiction"
    assert policy["policy_id"] == "policy:test"


def test_time_trust_onboarding_repairs_scaffold_and_unsigned_bundle(tmp_path: Path) -> None:
    workspace, _, _ = _workspace(tmp_path)
    root = _key(1)
    current = str(GenerationStoreV4(workspace).current_id())
    time_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "time:advance",
        "receipt_type": "trusted_time",
        "event_time": "2026-07-14T00:00:00Z",
        "subject_digest": current,
        "serial": 2,
    }
    time_statement = _statement(
        root,
        time_payload,
        schema_ref="trusted-time-receipt@0.4.0",
        key_id="key:root",
        role="timestamp",
        source_system="clock",
        signed_at="2026-07-14T00:00:00Z",
    )
    time_path = tmp_path / "advance-time.json"
    write_canonical(time_path, time_statement)
    advanced = advance_time_v4(workspace, time_path, apply=True)
    assert advanced["analysis_epoch"] == "2026-07-14T00:00:00Z"
    assert status_v4(workspace)["execution_allowed"] is True
    assert onboard_v4(workspace)["strongest_native_claim"] == "operational_organization_profile"
    assert repair_list_v4(workspace)["command_status"] == "ok"
    scaffold = scaffold_contract_v4(tmp_path / "scaffold", "measured")
    assert scaffold["draft_executable"] is False

    bundle = tmp_path / "bundle"
    create_bundle(workspace, bundle)
    verified = verify_bundle(bundle)
    assert verified["content_status"] == "content_consistent"
    assert verified["authenticity_status"] == "unknown"


def test_v4_bundle_root_attestation_separates_content_and_authenticity(tmp_path: Path) -> None:
    workspace, _, policy = _workspace(tmp_path)
    bundle = tmp_path / "signed-bundle"
    manifest = create_bundle(workspace, bundle)
    root = _key(1)
    root_payload = {
        "schema_version": "0.4.0",
        "bundle_manifest_digest": digest_v3_json(manifest),
        "generation_id": (bundle / ".cpcf" / "CURRENT").read_text(encoding="ascii").strip(),
    }
    statement = _statement(
        root,
        root_payload,
        schema_ref="bundle-root-attestation@0.4.0",
        key_id="key:root",
        role="bundle_signer",
        source_system="bundle",
    )
    policy_path = tmp_path / "bundle-policy.json"
    write_canonical(policy_path, policy)
    write_canonical(bundle / "root-attestation.json", statement)
    verified = verify_bundle(bundle, policy_path)
    assert verified["content_status"] == "content_consistent"
    assert verified["authenticity_status"] == "verified"
    statement["payload"]["bundle_manifest_digest"] = "sha256:" + "0" * 64
    write_canonical(bundle / "root-attestation.json", statement)
    rejected = verify_bundle(bundle, policy_path)
    assert rejected["content_status"] == "content_consistent"
    assert rejected["authenticity_status"] == "invalid"
    assert policy["root_key_id"] == "key:root"


def test_monotonic_root_signed_trust_update(tmp_path: Path) -> None:
    workspace, _, old_policy = _workspace(tmp_path)
    root = _key(1)
    store = GenerationStoreV4(workspace)
    manifest = store.load_manifest()
    new_policy = deepcopy(old_policy)
    new_policy["policy_sequence"] = 1
    new_policy["previous_policy_digest"] = manifest["trust_policy_digest"]
    policy_statement = _statement(
        root,
        new_policy,
        schema_ref="trust-policy@0.4.0",
        key_id="key:root",
        role="workspace_root",
        source_system="clock",
        signed_at="2026-07-14T00:00:00Z",
    )
    time_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "time:policy",
        "receipt_type": "trusted_time",
        "event_time": "2026-07-14T00:00:00Z",
        "subject_digest": digest_v3_json(new_policy),
        "serial": 2,
    }
    time_statement = _statement(
        root,
        time_payload,
        schema_ref="trusted-time-receipt@0.4.0",
        key_id="key:root",
        role="timestamp",
        source_system="clock",
        signed_at="2026-07-14T00:00:00Z",
    )
    policy_path = tmp_path / "new-policy.json"
    time_path = tmp_path / "policy-time.json"
    write_canonical(policy_path, policy_statement)
    write_canonical(time_path, time_statement)
    updated = update_trust_policy_v4(workspace, policy_path, time_path, apply=True)
    assert updated["policy_sequence"] == 1
    assert doctor_v4(workspace)["command_status"] == "ok"


def test_copy_on_write_v3_migration_quarantines_legacy_authority(tmp_path: Path) -> None:
    from tests.test_v3 import _workspace as v3_workspace

    legacy, _, _ = v3_workspace(tmp_path / "legacy-input")
    old_store = GenerationStore(legacy)
    old_manifest = old_store.load_manifest()
    old_contract = old_store.get_json(str(old_manifest["contract_digest"]))
    assert isinstance(old_contract, dict)
    migrated_contract = _migrate_contract(old_contract)
    root, source = _key(1), _key(2)
    trust = _policy(root, source)
    trust_path = tmp_path / "migration-trust.json"
    write_canonical(trust_path, trust)
    time_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "time:migration",
        "receipt_type": "trusted_time",
        "event_time": NOW,
        "subject_digest": digest_v3_json(migrated_contract),
        "serial": 1,
    }
    time_statement = _statement(
        root,
        time_payload,
        schema_ref="trusted-time-receipt@0.4.0",
        key_id="key:root",
        role="timestamp",
        source_system="clock",
    )
    time_path = tmp_path / "migration-time.json"
    write_canonical(time_path, time_statement)
    output = tmp_path / "migrated-v4"
    migrated = migrate_workspace_v4(
        legacy,
        trust_path,
        time_path,
        output,
        key_fingerprint(_public(root)),
    )
    assert migrated["command_status"] == "ok"
    assert migrated["source_workspace_modified"] is False
    assert migrated["execution_allowed"] is False
    assert doctor_v4(output)["command_status"] == "ok"


def test_workspace_without_external_time_stays_non_authoritative(tmp_path: Path) -> None:
    from collective_phase_control_fabric.workspace_v4 import initialize_workspace_v4

    root, source = _key(1), _key(2)
    contract = _contract()
    trust = _policy(root, source)
    contract_path = tmp_path / "no-time-contract.json"
    trust_path = tmp_path / "no-time-trust.json"
    write_canonical(contract_path, contract)
    write_canonical(trust_path, trust)
    workspace = tmp_path / "no-time-workspace"
    initialized = initialize_workspace_v4(
        contract_path, trust_path, workspace, key_fingerprint(_public(root)), None
    )
    assert "authoritative_time" in initialized["unknowns"]
    audit = doctor_v4(workspace)
    assert audit["failure_code"] == "workspace_audit_failed"
    repairs = repair_list_v4(workspace)
    assert any(item["repair_type"] == "import_trusted_time" for item in repairs["repairs"])


def test_v4_cli_routes_native_inspection_and_control_surfaces(tmp_path: Path) -> None:
    workspace, _, _ = _workspace(tmp_path)
    parser = build_parser()

    def run(*argv: str) -> dict[str, object]:
        result = dispatch(parser.parse_args(list(argv)))
        assert isinstance(result, dict)
        return result

    assert run("schema", "list", "--json")["current_version"] == "0.5.0"
    assert (
        run("schema", "show", "signed-statement", "--version", "0.4.0", "--json")["title"]
        == "CPCF Evidence-Bound Signed Statement v0.4"
    )
    assert (
        run("workspace", "status", "--workspace", str(workspace), "--json")["schema_version"]
        == "0.4.0"
    )
    assert (
        run("agent", "onboard", "--workspace", str(workspace), "--json")["strongest_native_claim"]
        == "operational_organization_profile"
    )
    assert run("doctor", "--workspace", str(workspace), "--json")["command_status"] == "ok"
    assert (
        run("science", "audit", "--workspace", str(workspace), "--json")[
            "collective_superintelligence_phase_inferred"
        ]
        is False
    )
    assert (
        run("phase", "inspect", "--workspace", str(workspace), "--json")["legacy_inspection"]
        is None
    )
    assert run("control", "next", "--workspace", str(workspace), "--json")["primary_action"] is None
    assert (
        run("agent", "next", "--workspace", str(workspace), "--json")["success_probability_used"]
        is False
    )
    assert run("repair", "list", "--workspace", str(workspace), "--json")["command_status"] == "ok"
    assert (
        run("intervention", "analyze", "--workspace", str(workspace), "--json")["scalar_score_used"]
        is False
    )
    bundle = tmp_path / "cli-bundle"
    assert (
        run("bundle", "create", "--workspace", str(workspace), "--out", str(bundle), "--json")[
            "bundle_schema_version"
        ]
        == "0.4.0"
    )
    assert run("bundle", "verify", str(bundle), "--json")["valid"] is True
    draft = tmp_path / "cli-draft"
    assert (
        run("contract", "scaffold", "--profile", "measured", "--out", str(draft), "--json")[
            "draft_executable"
        ]
        is False
    )
    assert (
        run("contract", "explain-missing", str(draft / "contract-draft.json"), "--json")[
            "failure_code"
        ]
        is None
    )


def test_cli_v4_dispatch_matrix_and_legacy_execution_rejections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parser = build_parser()
    marker = {"command_status": "ok", "marker": True}
    monkeypatch.setattr(cli_module, "workspace_version", lambda root: "0.4.0")
    monkeypatch.setattr(cli_module, "workspace_version_v3", lambda root: "0.4.0")
    monkeypatch.setattr(cli_module, "load_json_bounded", lambda path: {"schema_version": "0.4.0"})
    for name in (
        "explain_action_v4",
        "initialize_workspace_v4",
        "migrate_workspace_v4",
        "advance_time_v4",
        "validate_trust_policy_v4",
        "update_trust_policy_v4",
        "inspect_time_receipt_v4",
        "inspect_attestation_v4",
        "import_attestation_v4",
        "inspect_source_v4",
        "import_raw_v4",
        "doctor_v4",
        "repair_show_v4",
        "perturbation_replay_v4",
        "inspect_result_v4",
        "import_result_v4",
        "inspect_protocol_v4",
        "import_protocol_v4",
    ):
        monkeypatch.setattr(cli_module, name, lambda *args, **kwargs: marker)

    def run(*argv: str) -> dict[str, object]:
        result = dispatch(parser.parse_args(list(argv)))
        assert isinstance(result, dict)
        return result

    workspace = str(tmp_path / "workspace")
    file = str(tmp_path / "input.json")
    out = str(tmp_path / "out")
    assert (
        run("control", "run", "--workspace", workspace, "action", "--apply", "--json")[
            "failure_code"
        ]
        == "legacy_workspace_inspect_only"
    )
    assert run("agent", "why", "--workspace", workspace, "action", "--json")["marker"]
    missing_init = run("workspace", "init", "--contract", file, "--out", out, "--json")
    assert missing_init["failure_code"] == "v0.4_trust_policy_and_root_fingerprint_required"
    assert run(
        "workspace",
        "init",
        "--contract",
        file,
        "--trust-policy",
        file,
        "--root-key-fingerprint",
        "sha256:" + "a" * 64,
        "--out",
        out,
        "--json",
    )["marker"]
    missing_migration = run(
        "workspace", "migrate", "--workspace", workspace, "--out", out, "--to", "0.4.0"
    )
    assert missing_migration["failure_code"] == "v0.4_migration_trust_time_and_root_required"
    assert run(
        "workspace",
        "migrate",
        "--workspace",
        workspace,
        "--trust-policy",
        file,
        "--time-receipt",
        file,
        "--root-key-fingerprint",
        "sha256:" + "a" * 64,
        "--out",
        out,
        "--to",
        "0.4.0",
    )["marker"]
    assert (
        run("workspace", "advance-time", "--workspace", workspace, "--to", NOW)["failure_code"]
        == "authoritative_time_receipt_required"
    )
    assert run(
        "workspace",
        "advance-time",
        "--workspace",
        workspace,
        "--time-receipt",
        file,
        "--apply",
    )["marker"]
    assert run("trust", "validate", file, "--json")["marker"]
    assert run(
        "trust",
        "update",
        "--workspace",
        workspace,
        "--policy",
        file,
        "--time-receipt",
        file,
        "--apply",
    )["marker"]
    assert run("time", "inspect", file, "--trust-policy", file)["marker"]
    assert run("attestation", "inspect", file, "--trust-policy", file)["marker"]
    assert run("attestation", "import", file, "--workspace", workspace, "--apply")["marker"]
    assert run(
        "source",
        "inspect",
        file,
        "--trust-policy",
        file,
        "--source-system",
        "tutorial",
        "--schema-ref",
        "x@0.4.0",
    )["marker"]
    assert run(
        "source",
        "import",
        file,
        "--workspace",
        workspace,
        "--source-system",
        "tutorial",
        "--schema-ref",
        "x@0.4.0",
        "--apply",
    )["marker"]
    assert run("project", "rebuild", "--workspace", workspace)["marker"]
    assert run("repair", "show", "--workspace", workspace, "repair:id")["marker"]
    assert run("perturbation", "replay", "--workspace", workspace, "--suite", "suite")["marker"]
    for command in (
        ("trial", "inspect", file, "--workspace", workspace),
        ("trial", "import", file, "--workspace", workspace, "--apply"),
        (
            "trial",
            "protocol-inspect",
            file,
            "--registration-receipt",
            file,
            "--workspace",
            workspace,
        ),
        (
            "trial",
            "protocol-import",
            file,
            "--registration-receipt",
            file,
            "--workspace",
            workspace,
            "--apply",
        ),
        ("step", "prepare", "--workspace", workspace, "action"),
    ):
        assert run(*command)["marker"]
    assert (
        run("step", "run", "--workspace", workspace, "action", "--apply")["failure_code"]
        == "legacy_workspace_inspect_only"
    )

    monkeypatch.setattr(cli_module, "workspace_version", lambda root: "0.2.0")
    assert run("control", "run", "--workspace", workspace, "action")["failure_code"] == (
        "legacy_workspace_inspect_only"
    )
    assert (
        run("workspace", "advance-time", "--workspace", workspace, "--to", NOW)["failure_code"]
        == "legacy_workspace_inspect_only"
    )
    assert run("repair", "show", "--workspace", workspace, "repair:id")["failure_code"] == (
        "v0.4_workspace_required"
    )
    assert run("science", "audit", "--workspace", workspace)["failure_code"] == (
        "native_workspace_required"
    )
