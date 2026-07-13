# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collective_phase_control_fabric.v6.onboarding import OnboardingState, aggregate_onboarding
from collective_phase_control_fabric.v6.repairs import generate_repairs
from tests.v6_helpers import NOW


def test_repair_generation_is_deterministic_typed_and_non_executable_by_default() -> None:
    blockers = [
        "trust_quorum_unknown",
        "trusted_time_unknown",
        "resource_floor_violated",
        "raf_unknown_due_to_budget",
        "verification_capacity_violated",
        "coordination_unknown",
        "protocol_deviation",
        "runner_receipt_missing",
        "projection_promotion_quorum_not_unique",
        "candidate_set_overflow_unknown",
        "unclassified_blocker",
        "trust_quorum_unknown",
    ]
    repairs = generate_repairs(
        blockers,
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        created_at=NOW,
    )
    assert len(repairs) == len(set(blockers))
    assert [item.spec.blocker_code for item in repairs] == sorted(set(blockers))
    assert all(item.spec.status == "unbound" for item in repairs)
    assert all(item.spec.effect_class == "none" for item in repairs)
    assert all(item.spec.action_digest is None for item in repairs)
    assert all(item.spec.next_safe_commands == [] for item in repairs)
    assert any(
        "trust-policy" in item.spec.required_document_kinds
        for item in repairs
        if item.spec.blocker_code == "trust_quorum_unknown"
    )


def test_repair_generation_executes_only_an_explicitly_bound_action() -> None:
    action_digest = "sha256:" + "a" * 64
    repair = generate_repairs(
        ["resource_floor_violated"],
        tenant_id="tenant-a",
        workspace_id="workspace-a",
        created_at=NOW,
        bound_actions={"resource_floor_violated": action_digest},
    )[0]
    assert repair.spec.status == "open"
    assert repair.spec.effect_class == "execute"
    assert repair.spec.action_digest == action_digest


def test_onboarding_aggregates_every_live_subsystem_and_exact_recovery_commands() -> None:
    state = OnboardingState(
        workspace_id="workspace-a",
        generation_digest="sha256:" + "a" * 64,
        trust_status="unknown",
        temporal_status="violated",
        ledger_status="satisfied",
        quarantined_objects=["sha256:" + "b" * 64],
        science_dimensions={
            "provenance_integrity": "violated",
            "structural_reachability": "unknown_due_to_budget",
        },
        perturbation_status="unknown_due_to_budget",
        solver_status="unknown",
        planner_status="satisfied",
        runner_status="unknown",
        pending_projection_count=2,
        coordination_status="violated",
        trial_status="unknown",
        blocker_codes=["source_chain_invalid"],
    )
    report = aggregate_onboarding(state)
    assert report.status == "blocked"
    assert report.code == "onboarding_blockers_present"
    assert "trust_unknown" in report.blocker_codes
    assert "science_provenance_integrity_violated" in report.blocker_codes
    assert ["cpcf", "projection", "pending", "workspace-a", "--json"] in (report.next_safe_commands)
    assert ["cpcf", "intervention", "analyze", "workspace-a", "--json"] in (
        report.next_safe_commands
    )


def test_onboarding_ready_requires_observed_satisfaction_not_default_optimism() -> None:
    unknown = aggregate_onboarding(
        OnboardingState(
            workspace_id="workspace-a",
            generation_digest="sha256:" + "a" * 64,
        )
    )
    assert unknown.status == "blocked"

    ready = aggregate_onboarding(
        OnboardingState(
            workspace_id="workspace-a",
            generation_digest="sha256:" + "a" * 64,
            trust_status="satisfied",
            temporal_status="satisfied",
            ledger_status="satisfied",
            perturbation_status="satisfied",
            solver_status="satisfied",
            planner_status="satisfied",
            runner_status="satisfied",
            coordination_status="satisfied",
            trial_status="satisfied",
            science_dimensions={"provenance_integrity": "satisfied"},
        )
    )
    assert ready.status == "ok"
    assert ready.code == "onboarding_ready"
