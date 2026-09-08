# SPDX-License-Identifier: Apache-2.0
"""Synthetic signature fixtures exercise authority boundaries, never real experiments."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cpcf_cli.main import main

from collective_phase_control_fabric.v6.canonical import canonical_bytes
from collective_phase_control_fabric.v6.frontier_examples import write_frontier_example
from collective_phase_control_fabric.v6.growth import check_plan, plan_growth
from collective_phase_control_fabric.v6.growth_evidence import export_proposal, replay
from collective_phase_control_fabric.v6.growth_frontier_evidence import (
    reassess_frontier,
    replan_frontier,
)
from collective_phase_control_fabric.v6.registry import document_digest, parse_document
from tests.test_v6_growth_evidence import admitted_case, write_admission_fixture


def test_fresh_admission_advances_only_unsigned_modelling_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, o, obs, admission, jobs, f = admitted_case(monkeypatch, frontier_mode="complete")
    original = [d.model_dump(mode="json") for d in (c, obs, f)]
    assessed = reassess_frontier(c, o, obs, f, **admission)
    assert assessed.spec.reasons == []
    assert assessed.spec.observed_entry == "compatible"
    assert assessed.spec.admitted_activation_action_ids == ["continue", "reuse"]
    assert assessed.spec.reconstructed_frontier_state.activation_depth == 2
    assert assessed.spec.continuation == "model-witness"
    assert assessed.spec.execution_authorized is False and assessed.spec.registration_required
    assert assessed.spec.empirical_attribution == "undetermined"
    assert parse_document(assessed.model_dump(mode="json")) == assessed
    proposed, advanced, fresh = replan_frontier(c, o, obs, f, **admission)
    assert fresh == assessed
    assert advanced.spec.latent_action_ids == []
    assert len(advanced.spec.initial_activation_lineage) == 2
    assert advanced.spec.parent_frontier_digest == document_digest(f)
    assert document_digest(obs) in advanced.spec.advancement_evidence_digests
    assert proposed.extensions["org.cpcf.growth"]["registration"] == "required"
    assert original == [d.model_dump(mode="json") for d in (c, obs, f)]
    plan = plan_growth(c, o, f)
    before = {d: x.model_dump(mode="json") for d, x in o.items()}
    trace = replay(c, o, plan, ["prepare:success", "reuse:success"], f)
    assert trace["observations_written"] == [] and trace["measured_bounds"] == {}
    assert trace["model_states"][-1]["activation_depth"] == 2
    assert before == {d: x.model_dump(mode="json") for d, x in o.items()}
    draft = export_proposal(c, o, plan, jobs[0], f)
    assert draft["authorized"] is False and draft["executed"] is False
    assert check_plan(c, o, plan, f) == plan.spec.checker_digest


@pytest.mark.parametrize(
    "mode,code",
    [
        ("ambiguous", "growth_frontier_successor_ambiguous"),
        ("no-rule", "growth_frontier_action_latent"),
    ],
)
def test_receipt_outcome_cannot_choose_a_favorable_activation(
    monkeypatch: pytest.MonkeyPatch, mode: str, code: str
) -> None:
    c, o, obs, admission, _, f = admitted_case(monkeypatch, frontier_mode=mode)
    assessed = reassess_frontier(c, o, obs, f, **admission)
    assert code in assessed.spec.reasons
    assert assessed.spec.reconstructed_frontier_state is None
    assert assessed.spec.admitted_activation_action_ids == []


@pytest.mark.parametrize("mode,lag", [("complete", 2), ("unfunded", 1), ("no-superiority", 1)])
def test_admitted_activation_is_separate_from_funded_growth_continuation(
    monkeypatch: pytest.MonkeyPatch, mode: str, lag: int
) -> None:
    c, o, obs, admission, _, f = admitted_case(monkeypatch, frontier_mode=mode, observation_lag=lag)
    assessed = reassess_frontier(c, o, obs, f, **admission)
    assert assessed.spec.admitted_activation_action_ids == ["continue", "reuse"]
    assert assessed.spec.continuation == "unavailable"
    assert assessed.spec.continuation_policy is None
    if lag == 2:
        assert "growth_continuation_state_stale" in assessed.spec.reasons


@pytest.mark.parametrize(
    "mode",
    [
        "missing-frontier-quorum",
        "missing-capability",
        "carried-missing-capability",
        "wrong-root",
        "tampered-frontier",
    ],
)
def test_evidence_weakening_never_strengthens_frontier_admission(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    c, o, obs, admission, _, f = admitted_case(monkeypatch, frontier_mode=mode)
    if mode == "wrong-root":
        admission["expected_root_spki_fingerprint"] = "sha256:" + "0" * 64
    if mode == "tampered-frontier":
        f = f.model_copy(
            update={"metadata": f.metadata.model_copy(update={"object_id": "changed"})}
        )
    assessed = reassess_frontier(c, o, obs, f, **admission)
    assert assessed.spec.reconstructed_frontier_state is None
    assert assessed.spec.continuation == "unavailable"
    assert assessed.spec.admitted_activation_action_ids == []
    assert assessed.spec.advancement_evidence_digests == []
    assert assessed.spec.reasons
    assert assessed.spec.observed_entry == "undetermined"
    with pytest.raises(ValueError, match=r"^growth_frontier_advancement_unavailable$"):
        replan_frontier(c, o, obs, f, **admission)


def test_installed_cli_frontier_inspect_plan_check_compare_replay(
    tmp_path: Path, capsys: Any
) -> None:
    write_frontier_example(tmp_path)
    args = [
        str(tmp_path / "contract.json"),
        "--objects",
        str(tmp_path / "objects"),
        "--frontier",
        str(tmp_path / "frontier.json"),
    ]
    assert main(["growth", "inspect", *args, "--json"]) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["model_state"]["activation_depth"] == 0
    assert inspected["frontier"]["spec"]["latent_action_ids"] == ["continue", "reuse"]
    plan = tmp_path / "plan.json"
    assert main(["growth", "plan", *args, "--output", str(plan)]) == 0
    assert "Model activation witness" in capsys.readouterr().out
    assert main(["growth", "check-plan", *args, "--plan", str(plan), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["frontier_diagnostics"]["endogenous_frontier_used"]
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
    assert json.loads(capsys.readouterr().out)["model_states"][-1]["activation_depth"] == 1
    assert main(["growth", "example", "--scenario", "frontier-chain", "--json"]) == 0
    assert (
        json.loads(capsys.readouterr().out)["plan"]["spec"]["frontier_diagnostics"][
            "maximum_activation_depth"
        ]
        == 2
    )


def test_cli_external_frontier_path_revalidates_original_records(
    tmp_path: Path, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    *case, frontier = admitted_case(monkeypatch, frontier_mode="complete")
    args = write_admission_fixture(tmp_path, tuple(case))
    path = tmp_path / "frontier.json"
    path.write_bytes(canonical_bytes(frontier.model_dump(mode="json")))
    for command in ("ingest", "reassess", "replan"):
        assert main(["growth", command, *args, "--frontier", str(path), "--json"]) == 0
        value = json.loads(capsys.readouterr().out)
        if command == "replan":
            assert value["unsigned_frontier_proposal"]["spec"]["latent_action_ids"] == []
            assert value["registration"] == "required-before-external-use"
        else:
            assert value["spec"]["admitted_activation_action_ids"] == ["continue", "reuse"]
