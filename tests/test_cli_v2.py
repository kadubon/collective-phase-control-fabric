# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from collective_phase_control_fabric import adapters
from collective_phase_control_fabric.canonical import write_canonical
from collective_phase_control_fabric.cli import agent_explain, build_parser, dispatch, main
from collective_phase_control_fabric.demos import demo_documents
from collective_phase_control_fabric.fake_adapter import main as deprecated_adapter_main
from collective_phase_control_fabric.fixtures import fixture
from collective_phase_control_fabric.types import JsonObject


def _args(*values: str):
    return build_parser().parse_args(list(values))


def test_parser_and_dispatch_cover_native_command_surface(tmp_path: Path) -> None:
    contract, network, _ = demo_documents("orientation-only-reachability")
    contract_path = tmp_path / "contract.json"
    network_path = tmp_path / "upstream-network.json"
    write_canonical(contract_path, contract)
    write_canonical(network_path, network)
    workspace = tmp_path / "workspace"

    assert dispatch(_args("agent", "explain", "--json"))["version"] == "0.5.0"
    assert dispatch(_args("schema", "list", "--json"))["command_status"] == "ok"
    assert (
        dispatch(_args("schema", "show", "phase-contract", "--version", "0.2.0", "--json"))["title"]
        == "PhaseContract v0.2"
    )
    assert (
        dispatch(_args("contract", "validate", str(contract_path), "--json"))["command_status"]
        == "ok"
    )
    initialized = dispatch(
        _args(
            "workspace",
            "init",
            "--contract",
            str(contract_path),
            "--out",
            str(workspace),
            "--json",
        )
    )
    assert initialized["command_status"] == "ok"
    inspected = dispatch(
        _args(
            "source",
            "inspect",
            str(network_path),
            "--source-system",
            "test",
            "--schema-ref",
            "transformation-network@0.2.0",
            "--json",
        )
    )
    assert inspected["source_modified"] is False
    preview = dispatch(
        _args(
            "source",
            "import",
            str(network_path),
            "--workspace",
            str(workspace),
            "--source-system",
            "test",
            "--schema-ref",
            "transformation-network@0.2.0",
            "--json",
        )
    )
    assert preview["applied"] is False
    applied = dispatch(
        _args(
            "source",
            "import",
            str(network_path),
            "--workspace",
            str(workspace),
            "--source-system",
            "test",
            "--schema-ref",
            "transformation-network@0.2.0",
            "--apply",
            "--json",
        )
    )
    assert applied["applied"] is True
    assert (
        dispatch(_args("project", "rebuild", "--workspace", str(workspace), "--json"))[
            "command_status"
        ]
        == "ok"
    )
    assert (
        dispatch(_args("doctor", "--workspace", str(workspace), "--strict", "--json"))[
            "command_status"
        ]
        == "ok"
    )
    assert (
        dispatch(_args("phase", "inspect", "--workspace", str(workspace), "--compact", "--json"))[
            "phase_projection"
        ]["ladder_level"]
        == "L1"
    )
    assert (
        dispatch(_args("seed", "list", "--workspace", str(workspace), "--json"))["command_status"]
        == "ok"
    )
    assert dispatch(_args("repair", "list", "--workspace", str(workspace), "--json"))["repairs"]
    assert (
        dispatch(_args("control", "next", "--workspace", str(workspace), "--compact", "--json"))[
            "solution_class"
        ]
        == "exact"
    )
    assert (
        dispatch(_args("agent", "next", "--workspace", str(workspace), "--compact", "--json"))[
            "solution_class"
        ]
        == "exact"
    )
    assert dispatch(_args("adapter", "manifest", "--json"))["manifest_version"] == "0.2.0"
    assert (
        dispatch(_args("fixture", "show", "reachability_without_productivity", "--json"))[
            "fixture_name"
        ]
        == "reachability_without_productivity"
    )


def test_demo_bundle_migration_and_main_error_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    demo = tmp_path / "demo"
    result = dispatch(
        _args(
            "demo",
            "bootstrap",
            "--out",
            str(demo),
            "--scenario",
            "verification-overload-repair",
            "--json",
        )
    )
    assert result["command_status"] == "ok"
    assert dispatch(_args("bundle", "verify", str(demo / "bundle"), "--json"))["valid"] is True

    legacy = tmp_path / "legacy"
    legacy.mkdir()
    data = fixture("reachability_without_productivity")
    write_canonical(legacy / "contract.json", data["contract"])
    write_canonical(legacy / "network.json", data["network"])
    write_canonical(legacy / "actions.json", {"actions": []})
    migrated = tmp_path / "migrated"
    assert (
        dispatch(
            _args(
                "workspace",
                "migrate",
                "--workspace",
                str(legacy),
                "--out",
                str(migrated),
                "--to",
                "0.2.0",
                "--json",
            )
        )["command_status"]
        == "ok"
    )

    monkeypatch.setattr(sys, "argv", ["cpcf", "schema", "show", "missing", "--json"])
    assert main() == 2
    assert json.loads(capsys.readouterr().out)["failure_code"] == "required_field_or_schema_missing"
    monkeypatch.setattr(sys, "argv", ["cpcf", "agent", "explain", "--compact", "--json"])
    assert main() == 0
    assert json.loads(capsys.readouterr().out)["version"] == "0.5.0"


def test_adapter_registry_and_invocation_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = adapters.capability_manifest()
    assert manifest["manifest_version"] == "0.2.0"
    assert manifest["adapters"][0]["projection_mappings"]
    assert (
        adapters.invoke_read_only_adapter("bad", "bad", tmp_path)["reason"]
        == "unsupported_adapter_operation"
    )
    monkeypatch.setattr(adapters.shutil, "which", lambda _: None)
    assert (
        adapters.invoke_read_only_adapter("ccr", "agent_explain", tmp_path)["reason"]
        == "upstream_executable_not_found"
    )

    def fake_process(*args: object, **kwargs: object) -> JsonObject:
        del args, kwargs
        value = {
            "ok": True,
            "agent_manifest": {},
            "safe_boundaries": {},
            "v1_6_runtime": {},
        }
        encoded = json.dumps(value).encode()
        return {
            "stdout_utf8": encoded.decode(),
            "stdout_raw_hex": encoded.hex(),
            "stdout_truncated": False,
        }

    monkeypatch.setattr(adapters.shutil, "which", lambda _: sys.executable)
    monkeypatch.setattr(adapters, "run_process", fake_process)
    report = adapters.invoke_read_only_adapter("ccr", "agent_explain", tmp_path)
    assert report["command_status"] == "ok"
    assert report["raw_artifact_persisted"] is False


def test_deprecated_adapter_emits_only_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    request = tmp_path / "request.json"
    write_canonical(request, {"action_id": "action:legacy"})
    monkeypatch.setattr(sys, "argv", ["fake-adapter", "--request", str(request)])
    assert deprecated_adapter_main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["outcome"] == "failure"
    assert "output_contract_valid" not in output
    assert agent_explain()["legacy_claim_ladder_inspection_only"][-1] == "L8"
