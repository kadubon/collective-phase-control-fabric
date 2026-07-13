# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path

import pytest

from collective_phase_control_fabric.engine import analyze
from collective_phase_control_fabric.fixtures import FIXTURE_NAMES, fixture


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_descriptors_and_determinism(name: str) -> None:
    root = Path(__file__).resolve().parents[1]
    descriptor = json.loads((root / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))
    first = fixture(name)
    second = fixture(name)
    assert first == second
    assert descriptor["fixture_name"] == name
    assert descriptor["synthetic"] is True


@pytest.mark.parametrize(
    ("name", "level"),
    [
        ("reachability_without_productivity", "L1"),
        ("verified_productive_organization", "L2"),
        ("productivity_without_maintenance", "L2"),
        ("certified_catalyst", "L4"),
    ],
)
def test_positive_fixture_levels(name: str, level: str) -> None:
    data = fixture(name)
    report = analyze(
        data["contract"], data["network"], data["productive_witness"], data["maintenance_witness"]
    )
    assert report["phase_projection"]["ladder_level"] == level


def test_false_autocatalysis_fixture() -> None:
    data = fixture("false_autocatalysis")
    report = analyze(data["contract"], data["network"])
    active = {item["detector"] for item in report["false_positive_detections"] if item["blocking"]}
    assert {"self_certifying_cycle", "nonproductive_cycle"} <= active
    assert report["phase_projection"]["ladder_level"] is None


def test_deadlock_fixture() -> None:
    data = fixture("regeneration_deadlock")
    report = analyze(data["contract"], data["network"])
    deadlock = report["regeneration_deadlocks"][0]
    assert deadlock["exactness"] == "singleton_exact"
    assert deadlock["external_dependency"] is True
    assert deadlock["recommended_handoff"] == "external_producer"


def test_overload_and_sequential_guards() -> None:
    overload = fixture("verification_overload")
    report = analyze(overload["contract"], overload["network"])
    assert report["verification_load"]["status"] == "verification_overload"
    assert report["verification_load"]["candidate_fan_out_recommended"] is False
    sequential = fixture("sequential_task_guard")
    report = analyze(sequential["contract"], sequential["network"])
    assert report["critical_path"]["parallel_fan_out_allowed"] is False
    assert "one solver path" in report["critical_path"]["coordination_recommendation"]


def test_external_bundle_fixture_has_only_compatibility_field() -> None:
    data = fixture("external_claim_bundle")
    report = analyze(data["contract"], data["network"])
    external = report["external_claim_bundle"]
    assert external["external_claim_bundle_compatible"] is False
    assert external["legacy_self_declared_validation_authoritative"] is False
    serialized = json.dumps(report)
    for forbidden in (
        "asi_proven",
        "superintelligence_proven",
        "real_phase_proven",
        "globally_settled",
    ):
        assert forbidden not in serialized
