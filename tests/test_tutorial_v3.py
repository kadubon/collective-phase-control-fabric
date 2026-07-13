# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from collective_phase_control_fabric.canonical import load_json_strict
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.trust import verify_pinned_signature

ROOT = Path(__file__).resolve().parents[1]


def test_installed_tutorial_generator_emits_closed_signed_assets(tmp_path: Path) -> None:
    output = tmp_path / "tutorial assets"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "docs" / "tutorial-v0.3" / "generate.py"),
            "--out",
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    mapping = {
        "phase-contract.json": "phase-contract",
        "trust-policy.json": "trust-policy",
        "transformation-network.json": "transformation-network",
        "state-marking.json": "state-marking",
        "branch-effect-contract.json": "branch-effect-contract",
        "adapter-capability.json": "adapter-capability",
        "action.json": "action",
        "measurement-protocol.json": "measurement-protocol",
        "result-inconclusive.json": "trial-result-certificate",
        "result-supported.json": "trial-result-certificate",
        "spoofed-state-marking.json": "state-marking",
    }
    for filename, schema_name in mapping.items():
        value = load_json_strict(output / filename)
        assert not validation_errors(schema_name, value, "0.3.0"), filename
    trust = load_json_strict(output / "trust-policy.json")
    spoof = load_json_strict(output / "spoofed-state-marking.json")
    assert isinstance(trust, dict) and isinstance(spoof, dict)
    checked = verify_pinned_signature(
        spoof,
        trust,
        schema_ref="state-marking@0.3.0",
        source_system="tutorial",
        role="source",
        evaluation_time="2026-01-15T00:00:00Z",
    )
    assert checked["status"] == "false"
    assert "ed25519_signature_invalid" in checked["reasons"]
