# SPDX-License-Identifier: Apache-2.0
"""Four-outcome bounded contingent planning over signed abstract capability effects."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from fractions import Fraction
from typing import Any

from pydantic import Field

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    AnalysisSnapshot,
    AuthorityAttestation,
    BranchEffect,
    CapabilityDocument,
    CoordinationEventDocument,
    CoordinationPlan,
    CoordinationSession,
    Document,
    IndependenceAttestation,
    OperationalProfile,
    PendingProjection,
    ResourceObservationAttestation,
    StrictModel,
    VerifierStageAttestation,
)
from collective_phase_control_fabric.v6.registry import document_digest, schema_digest
from collective_phase_control_fabric.v6.science import (
    analysis_basis_digest,
    audit_snapshot,
    rational,
)

MAX_ELIGIBLE = 64
BEAM_WIDTH = 32
TRIAL_KINDS = {
    "measurement-protocol",
    "protocol-amendment",
    "trial-artifact-record",
    "trial-result",
    "trial-assessment",
}


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
    trusted_time_receipt_digest: str
    scientific_profile_digest: str
    live_objects: frozenset[str]
    resources: tuple[tuple[str, Fraction], ...]
    resource_trajectory: tuple[tuple[tuple[str, Fraction], ...], ...]
    floors: tuple[tuple[str, Fraction], ...]
    blockers: frozenset[str]
    addressed_blockers: frozenset[str]
    dimension_statuses: tuple[tuple[str, str], ...]
    debt: frozenset[str]
    rollback: frozenset[str]
    evidence_routes: frozenset[str]
    authority_ids: frozenset[str]
    hazards: frozenset[str]
    verifier_stage_ids: frozenset[str]
    verification_load: Fraction
    independence_domains: frozenset[str]
    independence_erosion: Fraction
    correlation_concentration: Fraction
    cut_exposure: Fraction
    coordination_bindings: frozenset[str]
    trial_bindings: frozenset[str]
    pending_projections: frozenset[str]
    elapsed_time: Fraction
    monetary_cost: Fraction
    quality_floor: Fraction | None
    safety_floor: Fraction | None

    def digest(self) -> str:
        value = {
            "generation_digest": self.generation_digest,
            "snapshot_digest": self.snapshot_digest,
            "trusted_time_receipt_digest": self.trusted_time_receipt_digest,
            "scientific_profile_digest": self.scientific_profile_digest,
            "live_objects": sorted(self.live_objects),
            "resources": [[key, str(value)] for key, value in self.resources],
            "resource_trajectory": [
                [[key, str(value)] for key, value in marking]
                for marking in self.resource_trajectory
            ],
            "floors": [[key, str(value)] for key, value in self.floors],
            "blockers": sorted(self.blockers),
            "addressed_blockers": sorted(self.addressed_blockers),
            "dimension_statuses": [list(item) for item in self.dimension_statuses],
            "debt": sorted(self.debt),
            "rollback": sorted(self.rollback),
            "evidence_routes": sorted(self.evidence_routes),
            "authority_ids": sorted(self.authority_ids),
            "hazards": sorted(self.hazards),
            "verifier_stage_ids": sorted(self.verifier_stage_ids),
            "verification_load": str(self.verification_load),
            "independence_domains": sorted(self.independence_domains),
            "independence_erosion": str(self.independence_erosion),
            "correlation_concentration": str(self.correlation_concentration),
            "cut_exposure": str(self.cut_exposure),
            "coordination_bindings": sorted(self.coordination_bindings),
            "trial_bindings": sorted(self.trial_bindings),
            "pending_projections": sorted(self.pending_projections),
            "elapsed_time": str(self.elapsed_time),
            "monetary_cost": str(self.monetary_cost),
            "quality_floor": None if self.quality_floor is None else str(self.quality_floor),
            "safety_floor": None if self.safety_floor is None else str(self.safety_floor),
        }
        return digest_bytes(canonical_bytes(value))


def _initial_state(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    profile: OperationalProfile,
) -> ControlState:
    live_objects = frozenset(
        {
            *snapshot.spec.object_digests,
            *snapshot.spec.witness_digests,
            snapshot.spec.contract_digest,
            snapshot.spec.trust_policy_digest,
            snapshot.spec.trusted_time_receipt_digest,
            snapshot.spec.unit_registry_digest,
        }
    )
    resources: dict[str, Fraction] = {}
    ambiguous: set[str] = set()
    for digest, item in objects.items():
        if digest not in live_objects:
            continue
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
    live_documents = [item for digest, item in objects.items() if digest in live_objects]
    authorities = {
        item.spec.authority_id for item in live_documents if isinstance(item, AuthorityAttestation)
    }
    verifier_stages = {
        item.spec.stage_id for item in live_documents if isinstance(item, VerifierStageAttestation)
    }
    independence_domains = {
        item.spec.domain_id for item in live_documents if isinstance(item, IndependenceAttestation)
    }
    coordination_bindings = {
        document_digest(item)
        for item in live_documents
        if isinstance(item, (CoordinationPlan, CoordinationEventDocument, CoordinationSession))
    }
    trial_bindings = {document_digest(item) for item in live_documents if item.kind in TRIAL_KINDS}
    pending_projections = {
        document_digest(item) for item in live_documents if isinstance(item, PendingProjection)
    }
    marking = tuple(sorted(resources.items()))
    profile_digest = digest_bytes(
        canonical_bytes(profile.model_dump(mode="json", exclude_none=True))
    )
    return ControlState(
        generation_digest=snapshot.spec.generation_digest,
        snapshot_digest=document_digest(snapshot),
        trusted_time_receipt_digest=snapshot.spec.trusted_time_receipt_digest,
        scientific_profile_digest=profile_digest,
        live_objects=live_objects,
        resources=marking,
        resource_trajectory=(marking,),
        floors=tuple(
            sorted((key, rational(value)) for key, value in snapshot.spec.protected_floors.items())
        ),
        blockers=frozenset(blockers),
        addressed_blockers=frozenset(),
        dimension_statuses=tuple(
            sorted((name, result.status) for name, result in profile.dimensions.items())
        ),
        debt=frozenset(),
        rollback=frozenset(),
        evidence_routes=frozenset(),
        authority_ids=frozenset(authorities),
        hazards=frozenset(),
        verifier_stage_ids=frozenset(verifier_stages),
        verification_load=Fraction(0),
        independence_domains=frozenset(independence_domains),
        independence_erosion=Fraction(0),
        correlation_concentration=Fraction(0),
        cut_exposure=Fraction(0),
        coordination_bindings=frozenset(coordination_bindings),
        trial_bindings=frozenset(trial_bindings),
        pending_projections=frozenset(pending_projections),
        elapsed_time=Fraction(0),
        monetary_cost=Fraction(0),
        quality_floor=None,
        safety_floor=None,
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
    if set(action.spec.prohibited_hazards).intersection(state.hazards):
        reasons.append("prohibited_hazard_active")
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
        if set(action.spec.prohibited_hazards).intersection(branch.hazards_added):
            reasons.append(f"prohibited_hazard_may_be_added:{branch.outcome}")
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


def _snapshot_for_live_state(
    baseline: AnalysisSnapshot,
    live_objects: frozenset[str],
) -> AnalysisSnapshot:
    placeholder = baseline.model_copy(
        update={
            "spec": baseline.spec.model_copy(
                update={
                    "object_digests": [
                        digest for digest in baseline.spec.object_digests if digest in live_objects
                    ],
                    "witness_digests": [
                        digest for digest in baseline.spec.witness_digests if digest in live_objects
                    ],
                    "analysis_basis_digest": "sha256:" + "0" * 64,
                }
            )
        }
    )
    return placeholder.model_copy(
        update={
            "spec": placeholder.spec.model_copy(
                update={"analysis_basis_digest": analysis_basis_digest(placeholder)}
            )
        }
    )


def _recompute_scientific_state(
    state: ControlState,
    baseline: AnalysisSnapshot,
    objects: dict[str, Document],
) -> ControlState:
    successor_snapshot = _snapshot_for_live_state(baseline, state.live_objects)
    baseline_live = {
        *baseline.spec.object_digests,
        *baseline.spec.witness_digests,
        baseline.spec.contract_digest,
        baseline.spec.trust_policy_digest,
        baseline.spec.trusted_time_receipt_digest,
        baseline.spec.unit_registry_digest,
    }
    removed = baseline_live - set(state.live_objects)
    successor_objects = {digest: item for digest, item in objects.items() if digest not in removed}
    profile = audit_snapshot(successor_snapshot, successor_objects)
    recomputed_blockers = {
        blocker
        for result in profile.dimensions.values()
        for blocker in result.blockers
        if result.status != "satisfied"
    }
    live_documents = list(successor_objects.values())
    return replace(
        state,
        snapshot_digest=document_digest(successor_snapshot),
        scientific_profile_digest=digest_bytes(
            canonical_bytes(profile.model_dump(mode="json", exclude_none=True))
        ),
        blockers=frozenset(set(state.blockers) | recomputed_blockers),
        dimension_statuses=tuple(
            sorted((name, result.status) for name, result in profile.dimensions.items())
        ),
        authority_ids=frozenset(
            item.spec.authority_id
            for item in live_documents
            if isinstance(item, AuthorityAttestation)
        ),
        verifier_stage_ids=frozenset(
            item.spec.stage_id
            for item in live_documents
            if isinstance(item, VerifierStageAttestation)
        ),
        independence_domains=frozenset(
            item.spec.domain_id
            for item in live_documents
            if isinstance(item, IndependenceAttestation)
        ),
        coordination_bindings=frozenset(
            document_digest(item)
            for item in live_documents
            if isinstance(item, (CoordinationPlan, CoordinationEventDocument, CoordinationSession))
        ),
        trial_bindings=frozenset(
            document_digest(item) for item in live_documents if item.kind in TRIAL_KINDS
        ),
    )


def _lower_floor(prior: Fraction | None, current: Fraction) -> Fraction:
    return current if prior is None else min(prior, current)


def _successor(
    state: ControlState,
    branch: BranchEffect,
    *,
    baseline_snapshot: AnalysisSnapshot | None = None,
    objects: dict[str, Document] | None = None,
) -> ControlState:
    removals = set(branch.must_remove) | set(branch.may_remove)
    # Projected output is pending until a receipt-backed independent approval promotes it.
    live = set(state.live_objects) - removals
    resources = dict(state.resources)
    for coordinate, lower in branch.resource_delta_lower.items():
        resources[coordinate] = resources.get(coordinate, Fraction(0)) + rational(lower)
    marking = tuple(sorted(resources.items()))
    successor = replace(
        state,
        live_objects=frozenset(live),
        resources=marking,
        resource_trajectory=(*state.resource_trajectory, marking),
        addressed_blockers=frozenset(
            set(state.addressed_blockers)
            | set(branch.resolves_blockers).intersection(state.blockers)
        ),
        debt=frozenset(set(state.debt) | set(branch.debt)),
        rollback=frozenset(set(state.rollback) | set(branch.rollback_obligations)),
        evidence_routes=frozenset(
            set(state.evidence_routes) | set(branch.guaranteed_evidence_routes)
        ),
        pending_projections=frozenset(set(state.pending_projections) | set(branch.must_add)),
        hazards=frozenset(
            (set(state.hazards) - set(branch.hazards_removed)) | set(branch.hazards_added)
        ),
        verification_load=state.verification_load + rational(branch.verification_load_upper),
        independence_erosion=state.independence_erosion
        + rational(branch.independence_erosion_upper),
        correlation_concentration=state.correlation_concentration
        + rational(branch.correlation_concentration_upper),
        cut_exposure=state.cut_exposure + rational(branch.cut_exposure_upper),
        elapsed_time=state.elapsed_time + rational(branch.time_upper),
        monetary_cost=state.monetary_cost + rational(branch.cost_upper),
        quality_floor=_lower_floor(state.quality_floor, rational(branch.quality_lower)),
        safety_floor=_lower_floor(state.safety_floor, rational(branch.safety_lower)),
    )
    if baseline_snapshot is not None and objects is not None:
        return _recompute_scientific_state(successor, baseline_snapshot, objects)
    return successor


def _strict_progress(
    prior: ControlState,
    successor: ControlState,
    measure: str | None,
) -> bool:
    if measure == "blocker_frontier":
        return successor.addressed_blockers > prior.addressed_blockers
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
    resource_coordinates = {
        coordinate for branch in branches for coordinate in branch.resource_delta_lower
    }
    return {
        "resolved": frozenset(resolved),
        "evidence": frozenset(evidence),
        "time": max(rational(item.time_upper) for item in branches),
        "cost": max(rational(item.cost_upper) for item in branches),
        "quality": min(rational(item.quality_lower) for item in branches),
        "safety": min(rational(item.safety_lower) for item in branches),
        "verification": max(rational(item.verification_load_upper) for item in branches),
        "independence": max(rational(item.independence_erosion_upper) for item in branches),
        "correlation": max(rational(item.correlation_concentration_upper) for item in branches),
        "cut": max(rational(item.cut_exposure_upper) for item in branches),
        "resources": {
            coordinate: min(
                rational(branch.resource_delta_lower.get(coordinate, "0")) for branch in branches
            )
            for coordinate in resource_coordinates
        },
        "debt": frozenset(item for branch in branches for item in branch.debt),
        "rollback": frozenset(item for branch in branches for item in branch.rollback_obligations),
        "hazards": frozenset(item for branch in branches for item in branch.hazards_added),
    }


def _dominates(left: CapabilityDocument, right: CapabilityDocument) -> bool:
    a = _worst_coordinates(left)
    b = _worst_coordinates(right)
    resource_coordinates = set(a["resources"]) | set(b["resources"])
    resource_at_least_as_good = all(
        a["resources"].get(coordinate, Fraction(0)) >= b["resources"].get(coordinate, Fraction(0))
        for coordinate in resource_coordinates
    )
    resource_strict = any(
        a["resources"].get(coordinate, Fraction(0)) > b["resources"].get(coordinate, Fraction(0))
        for coordinate in resource_coordinates
    )
    comparisons = (
        a["resolved"].issuperset(b["resolved"]),
        a["evidence"].issuperset(b["evidence"]),
        a["time"] <= b["time"],
        a["cost"] <= b["cost"],
        a["quality"] >= b["quality"],
        a["safety"] >= b["safety"],
        a["verification"] <= b["verification"],
        a["independence"] <= b["independence"],
        a["correlation"] <= b["correlation"],
        a["cut"] <= b["cut"],
        resource_at_least_as_good,
        a["debt"].issubset(b["debt"]),
        a["rollback"].issubset(b["rollback"]),
        a["hazards"].issubset(b["hazards"]),
    )
    strict = (
        a["resolved"] != b["resolved"]
        or a["evidence"] != b["evidence"]
        or a["time"] < b["time"]
        or a["cost"] < b["cost"]
        or a["quality"] > b["quality"]
        or a["safety"] > b["safety"]
        or a["verification"] < b["verification"]
        or a["independence"] < b["independence"]
        or a["correlation"] < b["correlation"]
        or a["cut"] < b["cut"]
        or resource_strict
        or a["debt"] != b["debt"]
        or a["rollback"] != b["rollback"]
        or a["hazards"] != b["hazards"]
    )
    return all(comparisons) and strict


def _eligible_at_state(
    state: ControlState,
    candidates: list[tuple[ActionDocument, CapabilityDocument]],
) -> list[tuple[ActionDocument, CapabilityDocument]]:
    return [pair for pair in candidates if not _hard_filter(state, pair[0], pair[1])]


def _route_goal_satisfied(state: ControlState) -> bool:
    return bool(state.blockers) and state.blockers.issubset(state.addressed_blockers)


def _branch_makes_guaranteed_progress(prior: ControlState, successor: ControlState) -> bool:
    return bool(
        successor.addressed_blockers > prior.addressed_blockers and successor.evidence_routes
    )


def _strong_tree(
    state: ControlState,
    action: ActionDocument,
    capability: CapabilityDocument,
    candidates: list[tuple[ActionDocument, CapabilityDocument]],
    horizon: int,
    path: frozenset[tuple[str, str]],
    *,
    baseline_snapshot: AnalysisSnapshot | None = None,
    objects: dict[str, Document] | None = None,
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
        successor = _successor(
            state,
            branch,
            baseline_snapshot=baseline_snapshot,
            objects=objects,
        )
        if not _resource_safe(state, branch):
            strong = False
            children[branch.outcome] = None
            continue
        if not _branch_makes_guaranteed_progress(state, successor):
            strong = False
            children[branch.outcome] = None
            continue
        if _route_goal_satisfied(successor):
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
                baseline_snapshot=baseline_snapshot,
                objects=objects,
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
    if not state.blockers:
        return PlanResult(
            status="ok",
            code="no_intervention_required",
            solution_class="exact",
        )
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
        _strong_tree(
            state,
            action,
            capability,
            nondominated,
            horizon,
            frozenset(),
            baseline_snapshot=snapshot,
            objects=objects,
        )
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
            successor = _successor(
                state,
                branch,
                baseline_snapshot=snapshot,
                objects=objects,
            )
            if not _branch_makes_guaranteed_progress(state, successor):
                counterexamples.append(
                    Counterexample(
                        action_id=action.spec.action_id,
                        outcome=branch.outcome,
                        reason="branch_guarantees_no_evidence_route_progress",
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
