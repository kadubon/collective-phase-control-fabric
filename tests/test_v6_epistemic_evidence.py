# SPDX-License-Identifier: Apache-2.0
"""Synthetic signed fixtures exercise real admission; no operational evidence."""

import pytest

from collective_phase_control_fabric.v6.epistemic import Domain, support_digest
from collective_phase_control_fabric.v6.epistemic_checking import reference_comparisons
from collective_phase_control_fabric.v6.epistemic_evidence import (
    export_epistemic,
    reassess_epistemic,
    replan_epistemic,
)
from collective_phase_control_fabric.v6.epistemic_planning import plan_epistemic
from collective_phase_control_fabric.v6.growth import GrowthError
from collective_phase_control_fabric.v6.registry import document_digest
from tests.test_v6_growth_evidence import admitted_case


def test_fresh_signed_observation_replans_without_mutating_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, objects, obs, admission, jobs, frontier, e, eo = admitted_case(
        monkeypatch, epistemic_mode="valid", frontier_mode="valid"
    )
    d = Domain(c, objects, e, frontier)
    planned = plan_epistemic(d)
    exported = export_epistemic(d, planned, jobs[0])
    assert not exported["executed"] and not exported["authorized"]
    with pytest.raises(GrowthError, match=r"^epistemic_export_binding$"):
        export_epistemic(d, planned, jobs[1])
    originals = [document_digest(x) for x in (c, e, obs, eo)]
    result = reassess_epistemic(d, eo, obs, **admission)
    assert result.spec.reasons == []
    assert result.spec.external_evidence_compatibility == "compatible"
    assert result.spec.compatible_support_digest
    assert not result.spec.capability_admitted and not result.spec.execution_authorized
    proposal = replan_epistemic(d, eo, obs, **admission)
    assert proposal["signed_history_modified"] is False
    assert proposal["execution_authorized"] is False
    assert originals == [document_digest(x) for x in (c, e, obs, eo)]
    admission["expected_root_spki_fingerprint"] = "sha256:" + "0" * 64
    with pytest.raises(GrowthError, match="epistemic_replan_evidence_unavailable"):
        replan_epistemic(d, eo, obs, **admission)


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("wrong-symbol", "epistemic_measurement_mapping"),
        ("missing-quorum", "epistemic_observation_not_admitted"),
        ("invalid-json-object", "epistemic_measurement_mapping"),
        ("joint-mismatch", "epistemic_receipt_model_mismatch"),
    ],
)
def test_evidence_weakening_cannot_enable_replanning(
    monkeypatch: pytest.MonkeyPatch, mode: str, reason: str
) -> None:
    c, objects, obs, admission, _, f, e, eo = admitted_case(
        monkeypatch,
        epistemic_mode=mode,
        frontier_mode="ambiguous" if mode == "joint-mismatch" else "valid",
    )
    result = reassess_epistemic(Domain(c, objects, e, f), eo, obs, **admission)
    assert result.spec.external_evidence_compatibility == "incompatible"
    assert reason in result.spec.reasons
    assert result.spec.compatible_support_digest is None


def test_receipt_joint_validation_does_not_leak_hidden_ledger_to_controller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, objects, obs, admission, _, f, e, eo = admitted_case(
        monkeypatch, epistemic_mode="joint-ambiguous", frontier_mode="ambiguous"
    )
    d = Domain(c, objects, e, f)
    visible = d.replay(eo.spec.history, reference_comparisons(d))
    assert len(visible) == 2
    assessment = reassess_epistemic(d, eo, obs, **admission)
    assert assessment.spec.reasons == []
    assert assessment.spec.external_evidence_compatibility == "compatible"
    assert assessment.spec.compatible_support_digest == support_digest(visible)
