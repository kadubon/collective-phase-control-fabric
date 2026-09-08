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
from collective_phase_control_fabric.v6.growth import (
    F,
    GrowthError,
    attainment,
    check_plan,
    check_tree,
    compare,
    initial_state,
    input_digest,
    plan_growth,
)
from collective_phase_control_fabric.v6.growth_evidence import export_proposal, replay
from collective_phase_control_fabric.v6.growth_frontier_evidence import (
    reassess_frontier,
    replan_frontier,
)
from collective_phase_control_fabric.v6.models import GrowthCheckpoint
from collective_phase_control_fabric.v6.registry import document_digest, parse_document
from tests.test_v6_growth_evidence import admitted_case, write_admission_fixture


def test_fresh_admission_advances_only_unsigned_modelling_proposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, o, obs, admission, jobs, f = admitted_case(monkeypatch, frontier_mode="complete")
    original = [d.model_dump(mode="json") for d in (c, obs, f)]
    assessed = reassess_frontier(c, o, obs, f, **admission)
    assert assessed.spec.code == "growth_frontier_evidence_reassessed"
    assert assessed.spec.input_digest == input_digest(c, o, f)
    assert assessed.spec.reasons == []
    assert assessed.spec.observed_entry == "compatible"
    assert assessed.spec.admitted_activation_action_ids == ["continue", "reuse"]
    assert assessed.spec.reconstructed_frontier_state.activation_depth == 2
    assert assessed.spec.continuation == "model-witness"
    assert assessed.spec.continuation_policy is not None
    assert assessed.spec.continuation_model_state is not None
    assert assessed.spec.frontier_continuation_state is not None
    assert (
        assessed.spec.continuation_search is not None and assessed.spec.continuation_search.complete
    )
    assert assessed.spec.execution_authorized is False and assessed.spec.registration_required
    assert assessed.spec.empirical_attribution == "undetermined"
    assert parse_document(assessed.model_dump(mode="json")) == assessed
    proposed, advanced, fresh = replan_frontier(c, o, obs, f, **admission)
    assert fresh == assessed
    assert advanced.spec.latent_action_ids == []
    assert len(advanced.spec.initial_activation_lineage) == 2
    assert advanced.spec.parent_frontier_digest == document_digest(f)
    assert advanced.metadata.object_id == "growth-frontier-replan-proposal"
    assert document_digest(obs) in advanced.spec.advancement_evidence_digests
    assert proposed.extensions["org.cpcf.growth"]["registration"] == "required"
    assert original == [d.model_dump(mode="json") for d in (c, obs, f)]
    assert assessed.spec.proposed_contract == proposed
    assert assessed.spec.proposed_frontier == advanced
    assert assessed.spec.frontier_continuation_state == initial_state(proposed, advanced)
    assert assessed.spec.frontier_continuation_state.frontier_digest == document_digest(advanced)
    endpoint = assessed.spec.reconstructed_frontier_state
    check_tree(
        proposed,
        o,
        assessed.spec.continuation_policy,
        assessed.spec.frontier_continuation_state,
        entry=GrowthCheckpoint(time=endpoint.elapsed, capacities=endpoint.capacities),
        frontier=advanced,
    )
    altered = advanced.model_copy(
        update={"metadata": advanced.metadata.model_copy(update={"object_id": "altered-proposal"})}
    )
    with pytest.raises(GrowthError, match=r"^growth_frontier_digest_mismatch$"):
        check_tree(
            proposed,
            o,
            assessed.spec.continuation_policy,
            assessed.spec.frontier_continuation_state,
            entry=GrowthCheckpoint(time=endpoint.elapsed, capacities=endpoint.capacities),
            frontier=altered,
        )
    replanned = plan_growth(proposed, o, advanced)
    assert replanned.spec.code == "growth_no_guaranteed_entry" and replanned.spec.search.complete
    diagnostics = replanned.spec.frontier_diagnostics
    assert diagnostics.newly_enabled_action_ids == []
    assert diagnostics.witnesses
    assert all(w.carried_from_initial_frontier for w in diagnostics.witnesses)
    plan = plan_growth(c, o, f)
    before = {d: x.model_dump(mode="json") for d, x in o.items()}
    trace = replay(c, o, plan, ["prepare:success", "reuse:success"], f)
    assert trace["observations_written"] == [] and trace["measured_bounds"] == {}
    assert trace["model_states"][-1]["activation_depth"] == 2
    assert before == {d: x.model_dump(mode="json") for d, x in o.items()}
    draft = export_proposal(c, o, plan, jobs[0], f)
    assert draft["authorized"] is False and draft["executed"] is False
    assert check_plan(c, o, plan, f) == plan.spec.checker_digest


def test_admitted_frontier_comparison_reoptimizes_only_reachable_actions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, o, obs, admission, _, f = admitted_case(
        monkeypatch, frontier_mode="frontier-sensitive-comparator"
    )
    assessed = reassess_frontier(c, o, obs, f, **admission)
    assert assessed.spec.model_condition == "supported"
    assert assessed.spec.comparisons[0].upper_bound == "2/3"
    # Erasing the frontier would wrongly allow the latent continuation before discovery.
    assert compare(c, o)[0].upper_bound == "1"


def test_exact_comparator_margin_equality_cannot_establish_growth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, o, obs, admission, _, f = admitted_case(monkeypatch, frontier_mode="comparison-tie")
    assessed = reassess_frontier(c, o, obs, f, **admission)
    state = assessed.spec.reconstructed_frontier_state
    assert state is not None
    (comparison,) = [x for x in assessed.spec.comparisons if x.endpoint == state.elapsed]
    assert attainment(c, state) == F(comparison.upper_bound) + F(c.spec.comparison_margin)
    assert assessed.spec.code == "growth_frontier_evidence_reassessed"
    assert assessed.spec.model_condition == assessed.spec.observed_entry == "undetermined"
    assert assessed.spec.continuation == "unavailable"


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
        "missing-rule-capability",
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
    assert assessed.spec.code == "growth_frontier_reassessment_inconclusive"
    assert assessed.spec.reconstructed_frontier_state is None
    assert assessed.spec.continuation == "unavailable"
    assert assessed.spec.continuation_policy is None
    assert assessed.spec.continuation_model_state is None
    assert assessed.spec.continuation_search is None
    assert assessed.spec.model_condition == "undetermined"
    assert assessed.spec.admitted_activation_action_ids == []
    assert assessed.spec.advancement_evidence_digests == []
    assert assessed.spec.proposed_contract is None and assessed.spec.proposed_frontier is None
    assert assessed.spec.reasons
    if mode in {"missing-capability", "carried-missing-capability", "missing-rule-capability"}:
        assert "growth_frontier_activation_not_admitted" in assessed.spec.reasons
    elif mode == "tampered-frontier":
        assert "growth_frontier_not_admitted" in assessed.spec.reasons
    else:
        assert "growth_frontier_evidence_unavailable" in assessed.spec.reasons
        if mode == "missing-frontier-quorum":
            assert "protocol_registration_quorum_not_unique" in assessed.spec.reasons
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
