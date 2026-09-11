# SPDX-License-Identifier: Apache-2.0
"""Visible-observation CLI replay and maintained facade boundaries."""

import json
from pathlib import Path
from typing import Any

from cpcf_cli.epistemic import example_report
from cpcf_cli.main import main

from collective_phase_control_fabric import growth_control as public


def test_cli_visible_replay_and_resumed_entry_epoch(tmp_path: Path, capsys: Any) -> None:
    example_report("epistemic-probe", tmp_path)
    args = [
        str(tmp_path / "contract.json"),
        "--objects",
        str(tmp_path / "objects"),
        "--frontier",
        str(tmp_path / "frontier.json"),
        "--epistemic",
        str(tmp_path / "epistemic.json"),
    ]
    for command in ("inspect", "support", "compare"):
        assert main(["growth", command, *args, "--json"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["code"].startswith("epistemic_")
    plan = tmp_path / "plan.json"
    assert main(["growth", "plan", *args, "--output", str(plan), "--json"]) == 0
    capsys.readouterr()
    assert main(["growth", "check-plan", *args, "--plan", str(plan), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["policy_feasible"]
    assert (
        main(
            [
                "growth",
                "replay",
                *args,
                "--plan",
                str(plan),
                "--observation-symbol",
                "blue",
                "--json",
            ]
        )
        == 0
    )
    replay = json.loads(capsys.readouterr().out)
    assert replay["next_action"] == "reuse-beta"
    assert replay["compatible_models"] == ["beta"]
    assert replay["observations_written"] == []
    assert (
        main(
            [
                "growth",
                "replay",
                *args,
                "--plan",
                str(plan),
                "--branch",
                "prepare:success",
                "--json",
            ]
        )
        == 1
    )
    assert (
        json.loads(capsys.readouterr().out)["code"] == "epistemic_hidden_branch_not_an_observation"
    )
    history = tmp_path / "history.json"
    history.write_text('[{"action_id":"prepare","observation":"red"}]', encoding="utf-8")
    assert (
        main(["growth", "plan", *args, "--history", str(history), "--output", str(plan), "--json"])
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "growth",
                "replay",
                *args,
                "--plan",
                str(plan),
                "--observation-symbol",
                "recorded",
                "--observation-symbol",
                "recorded",
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["next_action"] is None


def test_public_facade_exports_only_documented_surface() -> None:
    assert set(public.__all__) == {
        "Domain",
        "DocumentValidationError",
        "GrowthError",
        "canonical_support",
        "support_digest",
        "parse_document",
        "parse_document_bytes",
        "plan_epistemic",
        "check_epistemic_plan",
        "compare_epistemic",
        "information_value",
        "synthesize",
        "check_composition",
        "propose_catalogue",
        "replan_catalogue",
        "export_epistemic",
        "reassess_epistemic",
        "replan_epistemic",
    }
    assert all(callable(getattr(public, name)) for name in public.__all__)
