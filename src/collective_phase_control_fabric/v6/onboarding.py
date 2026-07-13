# SPDX-License-Identifier: Apache-2.0
"""Live first-agent aggregation for a v0.6 workspace."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from collective_phase_control_fabric.v6.models import ProfileStatus, StrictModel

InspectionStatus = Literal["satisfied", "violated", "unknown", "unknown_due_to_budget"]


class OnboardingState(StrictModel):
    workspace_id: str
    generation_digest: str
    migration_status: InspectionStatus = "satisfied"
    trust_status: InspectionStatus = "unknown"
    temporal_status: InspectionStatus = "unknown"
    ledger_status: InspectionStatus = "unknown"
    quarantined_objects: list[str] = Field(default_factory=list, max_length=100_000)
    science_dimensions: dict[str, ProfileStatus] = Field(default_factory=dict, max_length=64)
    perturbation_status: InspectionStatus = "unknown"
    solver_status: InspectionStatus = "unknown"
    planner_status: InspectionStatus = "unknown"
    runner_status: InspectionStatus = "unknown"
    pending_projection_count: int = Field(default=0, ge=0, le=100_000)
    coordination_status: InspectionStatus = "unknown"
    trial_status: InspectionStatus = "unknown"
    quota_status: InspectionStatus = "satisfied"
    blocker_codes: list[str] = Field(default_factory=list, max_length=100_000)


class OnboardingReport(StrictModel):
    status: Literal["ok", "blocked"]
    code: Literal["onboarding_ready", "onboarding_blockers_present"]
    generation_digest: str
    subsystem_status: dict[str, InspectionStatus]
    science_dimensions: dict[str, ProfileStatus]
    blocker_codes: list[str]
    unresolved_human_decisions: list[str]
    next_safe_commands: list[list[str]]


def aggregate_onboarding(state: OnboardingState) -> OnboardingReport:
    """Aggregate actual subsystem observations without treating missing data as success."""

    subsystem_status: dict[str, InspectionStatus] = {
        "migration": state.migration_status,
        "trust": state.trust_status,
        "trusted_time": state.temporal_status,
        "ledger": state.ledger_status,
        "quarantine": "violated" if state.quarantined_objects else "satisfied",
        "perturbation": state.perturbation_status,
        "solver": state.solver_status,
        "planner": state.planner_status,
        "runner": state.runner_status,
        "pending_projections": "violated" if state.pending_projection_count else "satisfied",
        "coordination": state.coordination_status,
        "trials": state.trial_status,
        "quota": state.quota_status,
    }
    blockers = set(state.blocker_codes)
    for name, value in subsystem_status.items():
        if value != "satisfied":
            blockers.add(f"{name}_{value}")
    for name, value in state.science_dimensions.items():
        if value != "satisfied":
            blockers.add(f"science_{name}_{value}")

    unresolved = sorted(
        code
        for code in blockers
        if code.startswith(("trust_", "trusted_time_", "science_", "trials_"))
    )
    commands: list[list[str]] = [
        ["cpcf", "workspace", "status", state.workspace_id, "--json"],
        ["cpcf", "repair", "list", state.workspace_id, "--json"],
    ]
    if state.pending_projection_count:
        commands.append(["cpcf", "projection", "pending", state.workspace_id, "--json"])
    if state.trust_status != "satisfied":
        commands.append(["cpcf", "trust", "status", state.workspace_id, "--json"])
    if state.temporal_status != "satisfied":
        commands.append(["cpcf", "time", "status", state.workspace_id, "--json"])
    if state.planner_status == "satisfied":
        commands.append(["cpcf", "intervention", "analyze", state.workspace_id, "--json"])
    return OnboardingReport(
        status="ok" if not blockers else "blocked",
        code="onboarding_ready" if not blockers else "onboarding_blockers_present",
        generation_digest=state.generation_digest,
        subsystem_status=subsystem_status,
        science_dimensions=state.science_dimensions,
        blocker_codes=sorted(blockers),
        unresolved_human_decisions=unresolved,
        next_safe_commands=commands,
    )
