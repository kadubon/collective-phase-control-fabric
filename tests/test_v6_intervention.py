# SPDX-License-Identifier: Apache-2.0
"""Integrated bounded structural and intervention analysis assurance."""

from __future__ import annotations

from collective_phase_control_fabric.v6.intervention import analyze_interventions
from collective_phase_control_fabric.v6.models import DimensionResult
from collective_phase_control_fabric.v6.science import Budget, audit_snapshot
from tests.test_v6_science_planner import action, build_science_fixture, capability


def test_integrated_analysis_binds_one_snapshot_and_exact_reference_results() -> None:
    snapshot, objects = build_science_fixture()
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    dimensions = dict(profile.dimensions)
    dimensions["causal_formation"] = DimensionResult(
        status="violated", blockers=["formation-blocker"]
    )
    blocked = profile.model_copy(
        update={"dimensions": dimensions, "operational_organization_compatible": False}
    )
    route = capability("route", "formation-blocker", "1")

    result = analyze_interventions(
        snapshot,
        objects,  # type: ignore[arg-type]
        blocked,
        [action("route", route)],
        [route],
        budget=Budget(operations=100_000),
    )

    assert result.siphons.status == "satisfied"
    assert result.cuts.status == "satisfied"
    assert result.cuts.minimal_cut_sets == [["transform"]]
    assert result.cuts.minimal_enablement_sets == [["transform"]]
    assert result.occurrence_prefix.status == "satisfied"
    assert result.occurrence_prefix.events[0].transformation_id == "transform"
    assert result.flux_coupling.exact_model_rechecked
    assert result.flux_coupling.blocked_transformations == ["transform"]
    assert result.portfolio.status == "satisfied"
    assert result.portfolio.blocker_frontier == ["formation-blocker"]
    assert result.portfolio.candidates[0].guaranteed_evidence_routes == ["typed-evidence-route"]
    assert result.portfolio.candidates[0].resolves_blockers == ["formation-blocker"]


def test_integrated_analysis_preserves_unknown_on_budget_exhaustion() -> None:
    snapshot, objects = build_science_fixture()
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    result = analyze_interventions(
        snapshot,
        objects,  # type: ignore[arg-type]
        profile,
        budget=Budget(operations=0),
    )

    assert result.siphons.status == "unknown_due_to_budget"
    assert result.flux_coupling.status == "unknown_due_to_budget"
    assert result.cuts.status == "unknown_due_to_budget"
    assert result.occurrence_prefix.status == "unknown_due_to_budget"
    assert result.portfolio.status == "unknown_due_to_budget"


def test_portfolio_filters_missing_and_duplicate_actions_and_reports_overflow() -> None:
    snapshot, objects = build_science_fixture()
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    dimensions = dict(profile.dimensions)
    dimensions["causal_formation"] = DimensionResult(
        status="violated", blockers=[f"blocker-{index}" for index in range(65)]
    )
    blocked = profile.model_copy(
        update={"dimensions": dimensions, "operational_organization_compatible": False}
    )
    capabilities = [capability(f"a{index}", f"blocker-{index}", "1") for index in range(65)]
    actions = [action(f"a{index}", item) for index, item in enumerate(capabilities)]
    duplicate = action("duplicate", capabilities[0])
    missing = duplicate.model_copy(
        update={
            "spec": duplicate.spec.model_copy(update={"capability_digest": "sha256:" + "f" * 64})
        }
    )
    result = analyze_interventions(
        snapshot,
        objects,  # type: ignore[arg-type]
        blocked,
        [missing, duplicate, *actions],
        capabilities,
        budget=Budget(operations=100_000),
    )
    assert result.portfolio.status == "unknown_due_to_budget"
    assert result.portfolio.solution_class == "incomplete"


def test_intervention_analysis_requires_authoritative_snapshot_time() -> None:
    snapshot, objects = build_science_fixture()
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    del objects[snapshot.spec.trusted_time_receipt_digest]
    result = analyze_interventions(
        snapshot,
        objects,  # type: ignore[arg-type]
        profile,
        budget=Budget(operations=100),
    )
    assert result.siphons.status == "unknown_due_to_budget"
    assert "trusted_time_receipt_missing" in result.portfolio.blocker_frontier
