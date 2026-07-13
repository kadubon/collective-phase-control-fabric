# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from collective_phase_control_fabric.execution_v4 import run_action_v4
from collective_phase_control_fabric.science_v4 import perturbation_replay_v4, science_audit_v4
from collective_phase_control_fabric.trials_v4 import (
    import_protocol_v4,
    import_result_v4,
    inspect_result_v4,
)
from collective_phase_control_fabric.workspace_v4 import (
    import_attestation_v4,
    import_raw_v4,
    initialize_workspace_v4,
    inspect_attestation_v4,
)

ROOT = Path(__file__).resolve().parents[1]


def test_installed_v4_tutorial_covers_trust_science_action_and_trial(tmp_path: Path) -> None:
    assets = tmp_path / "v4 tutorial assets"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "docs" / "tutorial-v0.4" / "generate.py"),
            "--out",
            str(assets),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = json.loads((assets / "manifest.json").read_text(encoding="utf-8"))
    workspace = tmp_path / "workspace"
    initialized = initialize_workspace_v4(
        assets / "phase-contract.json",
        assets / "trust-policy.json",
        workspace,
        str(manifest["root_fingerprint"]),
        assets / "trusted-time.json",
    )
    assert initialized["command_status"] == "ok"
    for stem in ("state", "suite", "action"):
        raw = import_raw_v4(
            assets / f"{stem}-raw.json",
            workspace,
            "tutorial",
            "typed-record@0.4.0",
            apply=True,
        )
        assert raw["command_status"] == "ok"
        imported = import_attestation_v4(assets / f"{stem}-attestation.json", workspace, apply=True)
        assert imported["command_status"] == "ok", imported
    forged = inspect_attestation_v4(
        assets / "forged-independence.json", assets / "trust-policy.json"
    )
    assert forged["command_status"] == "failed"
    audit = science_audit_v4(workspace)
    assert audit["operational_organization_compatible"] is True
    replay = perturbation_replay_v4(workspace, "suite:tutorial")
    assert replay["command_status"] == "ok"
    executed = run_action_v4(workspace, "action:tutorial", apply=True)
    assert executed["command_status"] == "ok"
    assert executed["outcome"] == "success"
    assert executed["os_sandbox_claim"] is False

    for name, schema in (
        ("dataset.json", "dataset-record@0.4.0"),
        ("analysis-spec.json", "analysis-executable-record@0.4.0"),
    ):
        assert (
            import_raw_v4(assets / name, workspace, "tutorial", schema, apply=True)[
                "command_status"
            ]
            == "ok"
        )
    protocol = import_protocol_v4(
        assets / "protocol.json", assets / "registration.json", workspace, apply=True
    )
    assert protocol["command_status"] == "ok", protocol
    inconclusive = inspect_result_v4(assets / "result-inconclusive.json", workspace)
    assert inconclusive["acceleration_status"] == "externally_observed_inconclusive"
    supported = import_result_v4(assets / "result-supported.json", workspace, apply=True)
    assert supported["acceleration_status"] == "external_acceleration_bundle_compatible"
