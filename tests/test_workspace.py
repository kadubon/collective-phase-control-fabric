# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path

import pytest

from collective_phase_control_fabric.bundle import create_bundle, verify_bundle
from collective_phase_control_fabric.canonical import digest_json, load_json, write_canonical
from collective_phase_control_fabric.engine import analyze
from collective_phase_control_fabric.fixtures import fixture
from collective_phase_control_fabric.planner import _filter_action
from collective_phase_control_fabric.workspace import (
    _demo_action,
    action_by_id,
    bootstrap_demo,
    doctor,
    inspect_workspace,
    load_workspace,
    next_actions,
    run_step,
)
from collective_phase_control_fabric.workspace_v2 import migrate_workspace


def test_uninitialized_engine() -> None:
    report = analyze(None, None)
    assert report["phase_projection"]["structural_status"] == "uninitialized"
    report = analyze({"contract_id": "partial"}, None)
    assert report["command_status"] == "partial"


def test_demo_first_time_path_is_receipt_backed_and_non_optimistic(tmp_path: Path) -> None:
    root = tmp_path / "CPCF demo with spaces Ω"
    result = bootstrap_demo(root)
    assert result["command_status"] == "ok"
    assert doctor(root)["command_status"] == "ok"
    before = inspect_workspace(root)
    assert before["phase_projection"]["ladder_level"] == "L1"
    assert before["productive_witness"]["status"] == "unknown"
    planned = next_actions(root)
    assert planned["primary_action"] is None
    assert planned["pareto_alternatives"] == []
    assert load_json(root / "actions.json") == {"actions": [], "schema_version": "0.2.0"}
    assert doctor(root, strict=True)["command_status"] == "ok"
    assert verify_bundle(root / "bundle")["valid"] is True
    assert doctor(root / "bundle", strict=True)["command_status"] == "ok"
    assert inspect_workspace(root / "bundle")["phase_projection"]["ladder_level"] == "L1"


def test_legacy_action_cannot_execute_before_copy_on_write_migration(tmp_path: Path) -> None:
    root = tmp_path / "legacy"
    root.mkdir()
    data = fixture("reachability_without_productivity")
    write_canonical(root / "contract.json", data["contract"])
    write_canonical(root / "network.json", data["network"])
    action = _demo_action(root)
    write_canonical(root / "actions.json", {"actions": [action]})
    before = digest_json(load_json(root / "contract.json"))
    blocked = run_step(root, str(action["action_id"]), "run")
    assert blocked["failure_code"] == "legacy_action_not_executable"
    migrated = tmp_path / "native"
    assert migrate_workspace(root, migrated, "0.2.0")["command_status"] == "ok"
    assert digest_json(load_json(root / "contract.json")) == before
    assert load_json(migrated / "actions.json") == {"actions": [], "schema_version": "0.2.0"}


def test_bootstrap_rejects_nonempty_and_missing_action(tmp_path: Path) -> None:
    root = tmp_path / "not-empty"
    root.mkdir()
    (root / "existing").write_text("x", encoding="utf-8")
    with pytest.raises(FileExistsError):
        bootstrap_demo(root)
    empty = tmp_path / "empty"
    bootstrap_demo(empty)
    with pytest.raises(KeyError):
        action_by_id(empty, "missing")


def test_doctor_reports_schema_error(tmp_path: Path) -> None:
    root = tmp_path / "bad"
    bootstrap_demo(root)
    contract = load_json(root / "contract.json")
    assert isinstance(contract, dict)
    del contract["target_states"]
    write_canonical(root / "contract.json", contract)
    report = doctor(root)
    assert report["command_status"] == "failed"
    assert report["schema_errors"]


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("source_version_supported", False, "unsupported_version"),
        ("report_malformed", True, "malformed_report"),
        ("effect_class", "unknown", "unknown_effect_class"),
        ("effect_class", "external_effect", "external_effect"),
        ("hazard_status", False, "critical_hazard"),
        ("output_contract", None, "unknown_output_contract"),
        ("recursive_reuse_valid", False, "recursive_reuse_violation"),
        ("independence_valid", False, "independence_violation"),
        ("lifecycle_status", False, "lifecycle_invalidity"),
        ("protected_floor_violation", True, "protected_floor_violation"),
    ],
)
def test_planner_hard_filter_order(tmp_path: Path, field: str, value: object, reason: str) -> None:
    data = fixture("reachability_without_productivity")
    action = _demo_action(tmp_path)
    action[field] = value
    assert (
        _filter_action(action, data["contract"], analyze(data["contract"], data["network"]))
        == reason
    )


def test_v02_demo_has_no_executable_external_or_local_write_action(tmp_path: Path) -> None:
    root = tmp_path / "effects"
    bootstrap_demo(root)
    actions = load_json(root / "actions.json")
    assert isinstance(actions, dict)
    assert actions["actions"] == []


def test_bundle_detects_digest_mismatch_and_path_escape(tmp_path: Path) -> None:
    root = tmp_path / "bundle-workspace"
    bootstrap_demo(root)
    bundle = root / "separate-bundle"
    create_bundle(root, bundle)
    (bundle / "network.json").write_text("{}", encoding="utf-8")
    assert any("digest_mismatch" in error for error in verify_bundle(bundle)["errors"])
    manifest = load_json(bundle / "manifest.json")
    assert isinstance(manifest, dict)
    manifest["objects"][0]["path"] = "../escape.json"
    write_canonical(bundle / "manifest.json", manifest)
    assert any("path_escape" in error for error in verify_bundle(bundle)["errors"])


def test_load_workspace_empty_defaults(tmp_path: Path) -> None:
    contract, network, productive, maintenance, actions, history = load_workspace(tmp_path)
    assert (contract, network, productive, maintenance) == (None, None, None, None)
    assert actions == []
    assert history == []


def test_bundle_malformed_manifest(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(json.dumps([]), encoding="utf-8")
    assert verify_bundle(bundle)["command_status"] == "failed"
