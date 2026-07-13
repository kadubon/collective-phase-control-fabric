# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

from collective_phase_control_fabric.canonical import write_canonical
from collective_phase_control_fabric.cli import build_parser, dispatch
from tests.test_v3 import _contract, _key_material, _scientific_documents, _signed


def _args(*values: str):  # type: ignore[no-untyped-def]
    return build_parser().parse_args(list(values))


def test_cli_v3_onboarding_generation_and_analysis(tmp_path: Path) -> None:
    private, policy = _key_material()
    contract_path = tmp_path / "contract.json"
    trust_path = tmp_path / "trust.json"
    write_canonical(contract_path, _contract())
    write_canonical(trust_path, policy)
    draft = tmp_path / "draft"
    scaffold = dispatch(
        _args("contract", "scaffold", "--profile", "measured", "--out", str(draft), "--json")
    )
    assert scaffold["command_status"] == "ok"
    assert (
        dispatch(_args("contract", "validate", str(contract_path), "--json"))["command_status"]
        == "ok"
    )
    assert dispatch(_args("trust", "validate", str(trust_path), "--json"))["command_status"] == "ok"
    schemas = dispatch(_args("schema", "list", "--json"))
    assert "0.3.0" in schemas["versions"]
    assert dispatch(_args("schema", "show", "trust-policy", "--version", "0.3.0", "--json"))[
        "title"
    ].startswith("CPCF")

    root = tmp_path / "workspace"
    initialized = dispatch(
        _args(
            "workspace",
            "init",
            "--contract",
            str(contract_path),
            "--trust-policy",
            str(trust_path),
            "--out",
            str(root),
            "--json",
        )
    )
    assert initialized["schema_version"] == "0.3.0"
    assert (
        dispatch(_args("workspace", "status", "--workspace", str(root), "--json"))[
            "execution_allowed"
        ]
        is True
    )
    assert (
        dispatch(_args("agent", "onboard", "--workspace", str(root), "--compact", "--json"))[
            "strongest_native_claim"
        ]
        == "structural_organization_status"
    )
    assert dispatch(_args("doctor", "--workspace", str(root), "--json"))["command_status"] == ("ok")
    assert (
        dispatch(_args("doctor", "--workspace", str(root), "--quick", "--json"))[
            "execution_allowed"
        ]
        is False
    )
    assert (
        dispatch(_args("project", "rebuild", "--workspace", str(root), "--json"))["command_status"]
        == "ok"
    )
    assert (
        dispatch(_args("science", "audit", "--workspace", str(root), "--compact", "--json"))[
            "structural_organization_level"
        ]
        is None
    )
    assert (
        dispatch(_args("phase", "inspect", "--workspace", str(root), "--compact", "--json"))[
            "collective_superintelligence_phase_inferred"
        ]
        is False
    )
    assert (
        dispatch(_args("control", "next", "--workspace", str(root), "--compact", "--json"))[
            "primary_action"
        ]
        is None
    )
    assert (
        dispatch(
            _args(
                "control",
                "run",
                "--workspace",
                str(root),
                "action:missing",
                "--apply",
                "--json",
            )
        )["failure_code"]
        == "legacy_workspace_inspect_only"
    )
    assert (
        dispatch(
            _args(
                "workspace",
                "advance-time",
                "--workspace",
                str(root),
                "--to",
                "2026-01-16T00:00:00Z",
                "--apply",
                "--json",
            )
        )["command_status"]
        == "ok"
    )

    network_path = tmp_path / "network.json"
    network = _signed(
        private,
        _scientific_documents()["transformation-network"],
        "transformation-network@0.3.0",
    )
    write_canonical(network_path, network)
    assert (
        dispatch(
            _args(
                "source",
                "inspect",
                str(network_path),
                "--trust-policy",
                str(trust_path),
                "--source-system",
                "fixture",
                "--schema-ref",
                "transformation-network@0.3.0",
                "--json",
            )
        )["command_status"]
        == "ok"
    )
    assert (
        dispatch(
            _args(
                "source",
                "import",
                str(network_path),
                "--workspace",
                str(root),
                "--source-system",
                "fixture",
                "--schema-ref",
                "transformation-network@0.3.0",
                "--apply",
                "--json",
            )
        )["command_status"]
        == "ok"
    )


def test_cli_v3_legacy_execution_and_migration_guards(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    write_canonical(legacy / "contract.json", {"schema_version": "0.2.0"})
    status = dispatch(_args("workspace", "status", "--workspace", str(legacy), "--json"))
    assert status["failure_code"] == "legacy_workspace_inspect_only"
    assert (
        dispatch(
            _args(
                "control",
                "run",
                "--workspace",
                str(legacy),
                "action:any",
                "--apply",
                "--json",
            )
        )["execution_allowed"]
        is False
    )
    missing_trust = dispatch(
        _args(
            "workspace",
            "migrate",
            "--workspace",
            str(legacy),
            "--out",
            str(tmp_path / "new"),
            "--to",
            "0.3.0",
            "--json",
        )
    )
    assert missing_trust["failure_code"] == "trust_policy_required_for_v0.3_migration"
