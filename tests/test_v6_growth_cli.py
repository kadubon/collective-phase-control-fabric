# SPDX-License-Identifier: Apache-2.0
"""The complete installed CLI boundary, without an adapter or external dispatch."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cpcf_cli.main import main

from collective_phase_control_fabric.v6.canonical import canonical_bytes
from collective_phase_control_fabric.v6.growth_examples import write_example
from collective_phase_control_fabric.v6.registry import document_digest
from tests.test_v6_growth_evidence import admitted_case, write_admission_fixture


def test_cli_inspect_plan_check_compare_replay_and_text(tmp_path: Path, capsys: Any) -> None:
    write_example(tmp_path)
    args = [str(tmp_path / "contract.json"), "--objects", str(tmp_path / "objects")]
    plan = tmp_path / "plan.json"
    assert main(["growth", "inspect", *args, "--json"]) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert len(inspected["operational_organization_profile"]["dimensions"]) == 13
    assert inspected["measured_bounds"] == {}
    assert main(["growth", "plan", *args, "--output", str(plan)]) == 0
    assert "Recommended action: prepare" in capsys.readouterr().out
    assert main(["growth", "check-plan", *args, "--plan", str(plan), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["code"] == "growth_plan_checked"
    assert main(["growth", "compare", *args, "--json"]) == 0
    assert all(x["search"]["complete"] for x in json.loads(capsys.readouterr().out)["comparisons"])
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
        == 0
    )
    replay = json.loads(capsys.readouterr().out)
    assert replay["model_states"][-1]["elapsed"] == "1"
    assert replay["observations_written"] == []
    assert (
        main(["growth", "replay", *args, "--plan", str(plan), "--branch", "invented", "--json"])
        == 1
    )
    assert json.loads(capsys.readouterr().out)["code"] == "growth_undeclared_successor"
    assert main(["growth", "inspect", *args]) == 0
    assert "Offline model output" in capsys.readouterr().out


def test_cli_ingest_reassess_replan_and_export(
    tmp_path: Path, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = admitted_case(monkeypatch)
    args = write_admission_fixture(tmp_path, case)
    for command in ("ingest", "reassess", "replan"):
        assert main(["growth", command, *args, "--json"]) == 0
        result = json.loads(capsys.readouterr().out)
        if command == "replan":
            assert result["unsigned_contract_proposal"]["extensions"]["org.cpcf.growth"][
                "hypothetical"
            ]
            assert result["plan"]["spec"]["observed_entry"] == "undetermined"
        else:
            assert result["spec"]["external_evidence_compatibility"] == "compatible"
    basic = args[:3]
    plan = tmp_path / "plan.json"
    job = tmp_path / "draft-job.json"
    job.write_bytes(canonical_bytes(case[-1][0].model_dump(mode="json")))
    assert main(["growth", "plan", *basic, "--output", str(plan), "--json"]) == 0
    capsys.readouterr()
    assert main(["growth", "export", *basic, "--plan", str(plan), "--job", str(job), "--json"]) == 0
    proposal = json.loads(capsys.readouterr().out)
    assert proposal["executed"] is False and proposal["authorized"] is False
    assert proposal["job_digest"] == document_digest(case[-1][0])


def test_cli_examples_and_fail_closed_inputs(tmp_path: Path, capsys: Any) -> None:
    assert main(["growth", "example", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["repair"]["growth_objective"] == "outside-repair-scope"
    assert result["growth"]["primary_action"] == "prepare"
    assert (tmp_path / "contract.json").is_file()
    assert (
        main(
            [
                "growth",
                "inspect",
                str(tmp_path / "absent"),
                "--objects",
                str(tmp_path / "objects"),
                "--json",
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["code"] == "growth_cli_input_invalid"
    assert (
        main(
            [
                "growth",
                "inspect",
                str(next((tmp_path / "objects").glob("*.json"))),
                "--objects",
                str(tmp_path / "objects"),
                "--json",
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["code"] == "growth_cli_document_kind"
    first = next((tmp_path / "objects").glob("*.json"))
    (tmp_path / "objects" / "copy.json").write_bytes(first.read_bytes())
    assert (
        main(
            [
                "growth",
                "inspect",
                str(tmp_path / "contract.json"),
                "--objects",
                str(tmp_path / "objects"),
                "--json",
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["code"] == "growth_cli_duplicate_object"


def test_typed_raw_source_never_becomes_an_unsigned_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from collective_phase_control_fabric.v6.authority import load_authoritative_generation
    from collective_phase_control_fabric.v6.storage import validate_ledger

    _, _, observation, kwargs, _ = admitted_case(monkeypatch)
    assert validate_ledger(kwargs["generation"], kwargs["store"]) == []
    view = load_authoritative_generation(**kwargs)
    assert view.valid
    assert document_digest(observation) in view.objects
    assert all(raw not in view.objects for raw in observation.spec.source_artifact_digests)
