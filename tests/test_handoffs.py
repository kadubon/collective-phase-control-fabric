# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path

import pytest

from collective_phase_control_fabric.handoffs import verify_handoff

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "handoffs"


@pytest.mark.parametrize(
    "name",
    [
        "alt-capability-candidate.json",
        "pcs-skill-candidate.json",
        "vek-evidence-candidate.json",
        "cmgl-memory-candidate.json",
        "external-collective-advantage-certificate.json",
        "external-phase-evidence-certificate.json",
    ],
)
def test_fixture_handoff_remains_candidate(name: str) -> None:
    report = verify_handoff(ROOT / name)
    assert report["command_status"] == "ok"
    assert report["handoff_status"] == "candidate"
    assert report["source_decisions"][0]["accepted"] == "unknown"
    assert report["downstream_acceptance_inferred"] is False
    assert report["measurement_reproved_by_cpcf"] is False


def test_handoff_rejects_unknown_kind(tmp_path: Path) -> None:
    path = tmp_path / "unknown.json"
    path.write_text('{"kind":"unknown"}', encoding="utf-8")
    assert verify_handoff(path)["command_status"] == "failed"


def test_handoff_rejects_optimistic_downstream_acceptance(tmp_path: Path) -> None:
    source = ROOT / "alt-capability-candidate.json"
    path = tmp_path / "optimistic.json"
    path.write_text(
        source.read_text(encoding="utf-8").replace('"unknown"', "true"), encoding="utf-8"
    )
    report = verify_handoff(path)
    assert report["command_status"] == "failed"
