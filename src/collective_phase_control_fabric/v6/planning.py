# SPDX-License-Identifier: Apache-2.0
"""Four-outcome bounded contingent planning over signed abstract capability effects."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from pydantic import Field

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    AnalysisSnapshot,
    BranchEffect,
    CapabilityDocument,
    Document,
    OperationalProfile,
    ResourceObservationAttestation,
    StrictModel,
)
from collective_phase_control_fabric.v6.registry import document_digest, schema_digest
from collective_phase_control_fabric.v6.science import rational

MAX_ELIGIBLE = 64
BEAM_WIDTH = 32


class Counterexample(StrictModel):
    action_id: str
    outcome: str
    reason: str


class PolicyNode(StrictModel):
    state_digest: str
    action_id: str
    strong: bool
    branches: dict[str, PolicyNode | None]


class PlanResult(StrictModel):
    status: str
    code: str
    solution_class: str
    primary_action_id: str | None = None
    alternative_action_ids: list[str] = Field(default_factory=list)
    rejected: dict[str, list[str]] = Field(default_factory=dict)
    counterexamples: list[Counterexample] = Field(default_factory=list)
    policy: PolicyNode | None = None
    blocker_frontier: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class ControlState:
    generation_digest: str
    snapshot_digest: str
    live_objects: frozenset[str]
    resources: tuple[tuple[str, Fraction], ...]
    floors: tuple[tuple[str, Fraction], ...]
    blockers: frozenset[str]
    debt: frozenset[str]
    rollback: frozenset[str]
    evidence_routes: frozenset[str]
    trial_bindings: frozenset[str]
    pending_projections: frozenset[str]

    def digest(self) -> str:
        value = {
            "generation_digest": self.generation_digest,
            "snapshot_digest": self.snapshot_digest,
            "live_objects": sorted(self.live_objects),
            "resources": [[key, str(value)] for key, value in self.resources],
            "floors": [[key, str(value)] for key, value in self.floors],
            "blockers": sorted(self.blockers),
            "debt": sorted(self.debt),
            "rollback": sorted(self.rollback),
            "evidence_routes": sorted(self.evidence_routes),
            "trial_bindings": sorted(self.trial_bindings),
            "pending_projections": sorted(self.pending_projections),
        }
        return digest_bytes(canonical_bytes(value))


def _initial_state(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    profile: OperationalProfile,
) -> ControlState:
    resources: dict[str, Fraction] = {}
    ambiguous: set[str] = set()
    for item in objects.values():
        if isinstance(item, ResourceObservationAttestation):
            if item.spec.coordinate in resources:
                ambiguous.add(item.spec.coordinate)
            resources[item.spec.coordinate] = rational(item.spec.quantity)
    for coordinate in ambiguous:
        resources.pop(coordinate, None)
    blockers = {
        blocker
        for result in profile.dimensions.values()
        for blocker in result.blockers
        if result.status != "satisfied"
    }
    return ControlState(
        generation_digest=snapshot.spec.generation_digest,
        snapshot_digest=document_digest(snapshot),
        live_objects=frozenset([*snapshot.spec.object_digests, *snapshot.spec.witness_digests]),
        resources=tuple(sorted(resources.items())),
        floors=tuple(
            sorted((key, rational(value)) for key, value in snapshot.spec.protected_floors.items())
        ),
        blockers=frozenset(blockers),
        debt=frozenset(),
        rollback=frozenset(),
        evidence_routes=frozenset(),
        trial_bindings=frozenset(),
        pending_projections=frozenset(),
    )


def _semantic_key(action: ActionDocument, capability: CapabilityDocument) -> str:
    value = {
        "required": sorted(action.spec.required_object_digests),
        "protected": sorted(action.spec.protected_object_digests),
        "hazards": sorted(action.spec.prohibited_hazards),
        "capability": capability.spec.model_dump(mode="json", exclude_none=True),
    }
    return digest_bytes(canonical_bytes(value))


def _hard_filter(
    state: ControlState,
    action: ActionDocument,
    capability: CapabilityDocument | None,
) -> list[str]:
    reasons: list[str] = []
    if capability is None:
        return ["capability_missing"]
    if document_digest(capability) != action.spec.capability_digest:
        reasons.append("capability_digest_mismatch")
    if not set(action.spec.required_object_digests).issubset(state.live_objects):
        reasons.append("required_object_missing")
    try:
        expected_schema_digest = schema_digest(capability.spec.output_schema_name)
    except ValueError:
        expected_schema_digest = None
    if expected_schema_digest is None:
        reasons.append("capability_output_schema_unknown")
    elif capability.spec.output_schema_digest != expected_schema_digest:
        reasons.append("capability_output_schema_digest_mismatch")
    protected = set(action.spec.protected_object_digests)
    for branch in capability.spec.branches:
        if protected & (set(branch.must_remove) | set(branch.may_remove)):
            reasons.append(f"protected_object_may_be_removed:{branch.outcome}")
        if not _resource_safe(state, branch):
            reasons.append(f"resource_floor_may_fail:{branch.outcome}")
        if capability.spec.repeatable and not _strict_progress(
            state,
            _successor(state, branch),
            capability.spec.progress_measure,
        ):
            reasons.append(f"repeatability_progress_not_strict:{branch.outcome}")
    return sorted(set(reasons))


def _resource_safe(state: ControlState, branch: BranchEffect) -> bool:
    resources = dict(state.resources)
    floors = dict(state.floors)
    for coordinate, lower in branch.resource_delta_lower.items():
        resources[coordinate] = resources.get(coordinate, Fraction(0)) + rational(lower)
    return all(
        resources.get(coordinate, Fraction(0)) >= floor for coordinate, floor in floors.items()
    )


def _successor(state: ControlState, branch: BranchEffect) -> ControlState:
    removals = set(branch.must_remove) | set(branch.may_remove)
    live = (set(state.live_objects) - removals) | set(branch.must_add)
    resources = dict(state.resources)
    for coordinate, lower in branch.resource_delta_lower.items():
        resources[coordinate] = resources.get(coordinate, Fraction(0)) + rational(lower)
    return ControlState(
        generation_digest=state.generation_digest,
        snapshot_digest=state.snapshot_digest,
        live_objects=frozenset(live),
        resources=tuple(sorted(resources.items())),
        floors=state.floors,
        blockers=frozenset(set(state.blockers) - set(branch.resolves_blockers)),
        debt=frozenset(set(state.debt) | set(branch.debt)),
        rollback=frozenset(set(state.rollback) | set(branch.rollback_obligations)),
        evidence_routes=frozenset(
            set(state.evidence_routes) | set(branch.guaranteed_evidence_routes)
        ),
        trial_bindings=state.trial_bindings,
        pending_projections=frozenset(set(state.pending_projections) | set(branch.must_add)),
    )


def _strict_progress(
    prior: ControlState,
    successor: ControlState,
    measure: str | None,
) -> bool:
    if measure == "blocker_frontier":
        return successor.blockers < prior.blockers
    if measure == "evidence_routes":
        return successor.evidence_routes > prior.evidence_routes
    if measure is not None and measure.startswith("resource:"):
        coordinate = measure.removeprefix("resource:")
        return dict(successor.resources).get(coordinate, Fraction(0)) > dict(prior.resources).get(
            coordinate, Fraction(0)
        )
    return False


def _worst_coordinates(capability: CapabilityDocument) -> dict[str, Any]:
    branches = capability.spec.branches
    resolved = set(branches[0].resolves_blockers)
    evidence = set(branches[0].guaranteed_evidence_routes)
    for branch in branches[1:]:
        resolved &= set(branch.resolves_blockers)
        evidence &= set(branch.guaranteed_evidence_routes)
    return {
        "resolved": frozenset(resolved),
        "evidence": frozenset(evidence),
        "time": max(rational(item.time_upper) for item in branches),
        "cost": max(rational(item.cost_upper) for item in branches),
        "quality": min(rational(item.quality_lower) for item in branches),
        "verification": max(rational(item.verification_load_upper) for item in branches),
        "debt": frozenset(item for branch in branches for item in branch.debt),
        "rollback": frozenset(item for branch in branches for item in branch.rollback_obligations),
    }


def _dominates(left: CapabilityDocument, right: CapabilityDocument) -> bool:
    a = _worst_coordinates(left)
    b = _worst_coordinates(right)
    comparisons = (
        a["resolved"].issuperset(b["resolved"]),
        a["evidence"].issuperset(b["evidence"]),
        a["time"] <= b["time"],
        a["cost"] <= b["cost"],
        a["quality"] >= b["quality"],
        a["verification"] <= b["verification"],
        a["debt"].issubset(b["debt"]),
        a["rollback"].issubset(b["rollback"]),
    )
    strict = (
        a["resolved"] != b["resolved"]
        or a["evidence"] != b["evidence"]
        or a["time"] < b["time"]
        or a["cost"] < b["cost"]
        or a["quality"] > b["quality"]
        or a["verification"] < b["verification"]
        or a["debt"] != b["debt"]
        or a["rollback"] != b["rollback"]
    )
    return all(comparisons) and strict


def _eligible_at_state(
    state: ControlState,
    candidates: list[tuple[ActionDocument, CapabilityDocument]],
) -> list[tuple[ActionDocument, CapabilityDocument]]:
    return [pair for pair in candidates if not _hard_filter(state, pair[0], pair[1])]


def _strong_tree(
    state: ControlState,
    action: ActionDocument,
    capability: CapabilityDocument,
    candidates: list[tuple[ActionDocument, CapabilityDocument]],
    horizon: int,
    path: frozenset[tuple[str, str]],
) -> PolicyNode:
    state_digest = state.digest()
    key = (state_digest, action.spec.action_id)
    if key in path:
        return PolicyNode(
            state_digest=state_digest,
            action_id=action.spec.action_id,
            strong=False,
            branches={item.outcome: None for item in capability.spec.branches},
        )
    children: dict[str, PolicyNode | None] = {}
    strong = True
    for branch in capability.spec.branches:
        successor = _successor(state, branch)
        if not _resource_safe(state, branch):
            strong = False
            children[branch.outcome] = None
            continue
        if not successor.blockers:
            children[branch.outcome] = None
            continue
        if horizon <= 1:
            strong = False
            children[branch.outcome] = None
            continue
        next_candidates = _eligible_at_state(successor, candidates)
        next_candidates = sorted(next_candidates, key=lambda pair: pair[0].spec.action_id)[
            :BEAM_WIDTH
        ]
        chosen: PolicyNode | None = None
        for next_action, next_capability in next_candidates:
            if (
                next_action.spec.action_id == action.spec.action_id
                and not next_capability.spec.repeatable
            ):
                continue
            child = _strong_tree(
                successor,
                next_action,
                next_capability,
                candidates,
                horizon - 1,
                path | {key},
            )
            if child.strong:
                chosen = child
                break
        if chosen is None:
            strong = False
        children[branch.outcome] = chosen
    return PolicyNode(
        state_digest=state_digest,
        action_id=action.spec.action_id,
        strong=strong,
        branches=children,
    )


def plan_actions(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    profile: OperationalProfile,
    actions: Iterable[ActionDocument],
    capabilities: Iterable[CapabilityDocument],
    *,
    horizon: int = 1,
) -> PlanResult:
    if horizon not in (1, 2, 3):
        return PlanResult(status="error", code="planning_horizon_invalid", solution_class="none")
    state = _initial_state(snapshot, objects, profile)
    capability_by_digest: dict[str, CapabilityDocument] = {}
    duplicate_capability_digests: set[str] = set()
    for capability in capabilities:
        digest = document_digest(capability)
        if digest in capability_by_digest:
            duplicate_capability_digests.add(digest)
        capability_by_digest[digest] = capability
    rejected: dict[str, list[str]] = {}
    eligible: list[tuple[ActionDocument, CapabilityDocument]] = []
    seen_semantics: set[str] = set()
    for action in sorted(actions, key=lambda item: item.spec.action_id):
        found_capability = capability_by_digest.get(action.spec.capability_digest)
        reasons = _hard_filter(state, action, found_capability)
        if action.spec.capability_digest in duplicate_capability_digests:
            reasons.append("capability_digest_duplicate")
        if reasons or found_capability is None:
            rejected[action.spec.action_id] = sorted(set(reasons))
            continue
        semantic = _semantic_key(action, found_capability)
        if semantic in seen_semantics:
            rejected[action.spec.action_id] = ["exact_semantic_duplicate"]
            continue
        seen_semantics.add(semantic)
        eligible.append((action, found_capability))
    nondominated = [
        pair
        for pair in eligible
        if not any(other is not pair and _dominates(other[1], pair[1]) for other in eligible)
    ]
    if len(nondominated) > MAX_ELIGIBLE:
        return PlanResult(
            status="unknown",
            code="candidate_set_overflow_unknown",
            solution_class="incomplete",
            rejected=rejected,
            blocker_frontier=sorted(state.blockers),
        )
    if not nondominated:
        return PlanResult(
            status="blocked",
            code="no_branch_safe_action",
            solution_class="exact",
            rejected=rejected,
            blocker_frontier=sorted(state.blockers),
        )
    policies = [
        _strong_tree(state, action, capability, nondominated, horizon, frozenset())
        for action, capability in nondominated
    ]
    strong = [item for item in policies if item.strong]
    alternatives = [item.action_id for item in strong[:3]]
    primary: str | None = None
    policy: PolicyNode | None = None
    if len(nondominated) == 1 and strong:
        primary = strong[0].action_id
        policy = strong[0]
        alternatives = []
    counterexamples: list[Counterexample] = []
    for action, capability in nondominated:
        for branch in capability.spec.branches:
            successor = _successor(state, branch)
            if successor.blockers == state.blockers:
                counterexamples.append(
                    Counterexample(
                        action_id=action.spec.action_id,
                        outcome=branch.outcome,
                        reason="branch_guarantees_no_blocker_reduction",
                    )
                )
    if not strong:
        return PlanResult(
            status="blocked",
            code="no_strong_policy_within_horizon",
            solution_class="exact" if horizon == 1 else "approximate",
            rejected=rejected,
            counterexamples=counterexamples,
            blocker_frontier=sorted(state.blockers),
        )
    return PlanResult(
        status="ok",
        code="primary_strong_policy" if primary else "incomparable_safe_alternatives",
        solution_class="exact" if horizon == 1 else "approximate",
        primary_action_id=primary,
        alternative_action_ids=alternatives,
        rejected=rejected,
        counterexamples=counterexamples,
        policy=policy,
        blocker_frontier=sorted(state.blockers),
    )
