# SPDX-License-Identifier: Apache-2.0
"""Visible-observation CLI replay and maintained facade boundaries."""

import json
from pathlib import Path
from typing import Any

import pytest
from cpcf_cli.epistemic import example_report
from cpcf_cli.main import main

from collective_phase_control_fabric import growth_control as public
from tests.test_v6_growth_evidence import admitted_case, write_admission_fixture


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


def test_cli_typed_synthesis_fresh_check_proposal_and_replan(tmp_path: Path, capsys: Any) -> None:
    compiled = example_report("epistemic-composition", tmp_path)
    args = [
        str(tmp_path / "contract.json"),
        "--objects",
        str(tmp_path / "objects"),
        "--frontier",
        str(tmp_path / "frontier.json"),
        "--epistemic",
        str(tmp_path / "epistemic.json"),
    ]
    for name, document in (
        ("synthesis", compiled),
        ("candidate", compiled["spec"]["candidates"][0]),
        ("certificate", compiled["spec"]["certificates"][0]),
    ):
        (tmp_path / f"{name}.json").write_text(json.dumps(document), encoding="utf-8")
    request = ["--request", str(tmp_path / "request.json")]
    assert main(["growth", "synthesize", *args, *request, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["spec"]["reuse_without_formation_preferred"]
    chosen = ["--candidate", str(tmp_path / "candidate.json")]
    assert main(["growth", "check-composition", *args, *request, *chosen, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["spec"]["acceptance"] == "finite-model-domain-only"
    revision = tmp_path / "revision.json"
    assert (
        main(
            [
                "growth",
                "catalogue-propose",
                *args,
                *request,
                *chosen,
                "--synthesis",
                str(tmp_path / "synthesis.json"),
                "--output",
                str(revision),
                "--json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    reuse = [
        "growth",
        "catalogue-replan",
        *args,
        *request,
        *chosen,
        "--certificate",
        str(tmp_path / "certificate.json"),
        "--revision",
        str(revision),
        "--json",
    ]
    assert main(reuse) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "catalogue_model_only_opt_in_required"
    assert main([*reuse, "--model-only"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["policy_check"]["policy_feasible"] and not output["execution_authorized"]
    mask = tmp_path / "mask.json"
    mask.write_text(
        json.dumps({"red": "recorded", "blue": "recorded", "recorded": "recorded"}),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "growth",
                "information-value",
                *args,
                "--masked-channel",
                str(mask),
                "--sensing-action",
                "prepare",
                "--json",
            ]
        )
        == 0
    )
    value = json.loads(capsys.readouterr().out)
    assert value["spec"]["information_use"]["comparison_complete"]


def test_cli_fresh_admission_and_primitive_export(
    tmp_path: Path, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = admitted_case(monkeypatch, frontier_mode="valid", epistemic_mode="valid")
    args = write_admission_fixture(tmp_path, case[:5])
    _, _, _, _, jobs, frontier, e, eo = case
    for name, document in (
        ("frontier", frontier),
        ("epistemic", e),
        ("epistemic-observation", eo),
        ("job", jobs[0]),
    ):
        (tmp_path / f"{name}.json").write_text(document.model_dump_json(), encoding="utf-8")
    model = [
        "--frontier",
        str(tmp_path / "frontier.json"),
        "--epistemic",
        str(tmp_path / "epistemic.json"),
    ]
    observation = ["--epistemic-observation", str(tmp_path / "epistemic-observation.json")]
    for command in ("ingest", "reassess", "replan"):
        assert main(["growth", command, *args, *model, *observation, "--json"]) == 0
        result = json.loads(capsys.readouterr().out)
        if command == "replan":
            assert not result["execution_authorized"] and not result["signed_history_modified"]
        else:
            assert result["spec"]["external_evidence_compatibility"] == "compatible"
    plan = tmp_path / "plan.json"
    assert main(["growth", "plan", *args[:3], *model, "--output", str(plan), "--json"]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "growth",
                "export",
                *args[:3],
                *model,
                "--plan",
                str(plan),
                "--job",
                str(tmp_path / "job.json"),
                "--json",
            ]
        )
        == 0
    )
    exported = json.loads(capsys.readouterr().out)
    assert not exported["executed"] and not exported["authorized"]


@pytest.mark.parametrize(
    "scenario",
    [
        "epistemic-integrated",
        "epistemic-information",
        "epistemic-uninformative",
        "epistemic-no-composition",
        "epistemic-rejected-composition",
        "epistemic-budget",
    ],
)
def test_packaged_cli_examples_report_negative_results_honestly(scenario: str, capsys: Any) -> None:
    assert main(["growth", "example", "--scenario", scenario, "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    if scenario == "epistemic-integrated":
        assert result["replanned"]["policy_check"]["policy_feasible"]
        assert not result["execution_authorized"]
    elif scenario in {"epistemic-information", "epistemic-uninformative"}:
        assert result["kind"] == "information-value"
        assert result["spec"]["information_use"]["comparison_complete"]
    elif scenario == "epistemic-no-composition":
        assert result["spec"]["code"] == "composition_no_candidate"
        assert result["spec"]["candidates"] == [] and result["spec"]["formation_costs_incurred"]
    elif scenario == "epistemic-rejected-composition":
        assert result["code"] == "composition_constituent_tampered"
        assert not result["candidate_accepted"] and not result["execution_authorized"]
    else:
        assert result["plan"]["spec"]["code"] == "epistemic_support_budget"
        assert not result["plan"]["spec"]["search"]["complete"]
