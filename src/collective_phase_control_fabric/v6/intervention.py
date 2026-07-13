# SPDX-License-Identifier: Apache-2.0
"""Bounded structural diagnostics and evidence-route intervention portfolios."""

from __future__ import annotations

from collections.abc import Iterable

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    AnalysisSnapshot,
    CapabilityDocument,
    CutSetAnalysisSpec,
    Document,
    FluxCouplingSpec,
    InterventionCandidate,
    InterventionPortfolioSpec,
    OccurrenceCondition,
    OccurrenceEvent,
    OccurrencePrefixSpec,
    OperationalProfile,
    SiphonAnalysisSpec,
    SupplyAttestation,
)
from collective_phase_control_fabric.v6.planning import (
    MAX_ELIGIBLE,
    _dominates,
    _hard_filter,
    _initial_state,
    _semantic_key,
    _worst_coordinates,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.science import (
    AnalysisBudgetExceeded,
    Budget,
    _available_sets,
    _live,
    _temporal,
    _transformations,
    rational,
)
from collective_phase_control_fabric.v6.structural_analysis import (
    bounded_occurrence_prefix,
    enumerate_minimal_cut_sets,
    enumerate_minimal_enablement_sets,
    enumerate_minimal_siphons,
    exact_flux_coupling,
    unfed_siphons,
)


class InterventionAnalysis:
    """Closed set of bounded specs produced from one immutable snapshot."""

    def __init__(
        self,
        *,
        siphons: SiphonAnalysisSpec,
        flux_coupling: FluxCouplingSpec,
        cuts: CutSetAnalysisSpec,
        occurrence_prefix: OccurrencePrefixSpec,
        portfolio: InterventionPortfolioSpec,
    ) -> None:
        self.siphons = siphons
        self.flux_coupling = flux_coupling
        self.cuts = cuts
        self.occurrence_prefix = occurrence_prefix
        self.portfolio = portfolio


def _used_operations(budget: Budget, initial: int) -> int:
    return max(0, initial - budget.remaining)


def _unknown_bundle(
    snapshot_digest: str,
    transformation_set_digest: str,
    targets: list[str],
    blocker_frontier: list[str],
    operation_count: int,
) -> InterventionAnalysis:
    return InterventionAnalysis(
        siphons=SiphonAnalysisSpec(
            analysis_snapshot_digest=snapshot_digest,
            exhaustive=False,
            status="unknown_due_to_budget",
            operation_count=operation_count,
        ),
        flux_coupling=FluxCouplingSpec(
            analysis_snapshot_digest=snapshot_digest,
            transformation_set_digest=transformation_set_digest,
            status="unknown_due_to_budget",
            solver_name="unavailable",
            solver_version="unavailable",
            exact_model_rechecked=False,
            operation_count=operation_count,
        ),
        cuts=CutSetAnalysisSpec(
            analysis_snapshot_digest=snapshot_digest,
            target_ids=targets,
            exhaustive=False,
            status="unknown_due_to_budget",
            operation_count=operation_count,
        ),
        occurrence_prefix=OccurrencePrefixSpec(
            analysis_snapshot_digest=snapshot_digest,
            exhaustive=False,
            status="unknown_due_to_budget",
            operation_count=operation_count,
        ),
        portfolio=InterventionPortfolioSpec(
            analysis_snapshot_digest=snapshot_digest,
            status="unknown_due_to_budget",
            blocker_frontier=blocker_frontier,
            solution_class="incomplete",
        ),
    )


def _portfolio(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    profile: OperationalProfile,
    actions: Iterable[ActionDocument],
    capabilities: Iterable[CapabilityDocument],
) -> InterventionPortfolioSpec:
    state = _initial_state(snapshot, objects, profile)
    capabilities_by_digest = {
        document_digest(capability): capability for capability in capabilities
    }
    eligible: list[tuple[ActionDocument, CapabilityDocument]] = []
    semantics: set[str] = set()
    for action in sorted(actions, key=lambda item: item.spec.action_id):
        capability = capabilities_by_digest.get(action.spec.capability_digest)
        if capability is None or _hard_filter(state, action, capability):
            continue
        semantic_key = _semantic_key(action, capability)
        if semantic_key in semantics:
            continue
        semantics.add(semantic_key)
        eligible.append((action, capability))
    nondominated = [
        pair
        for pair in eligible
        if not any(other is not pair and _dominates(other[1], pair[1]) for other in eligible)
    ]
    blocker_frontier = sorted(state.blockers)
    if len(nondominated) > MAX_ELIGIBLE:
        return InterventionPortfolioSpec(
            analysis_snapshot_digest=document_digest(snapshot),
            status="unknown_due_to_budget",
            blocker_frontier=blocker_frontier,
            solution_class="incomplete",
        )
    candidates: list[InterventionCandidate] = []
    for action, capability in nondominated:
        coordinates = _worst_coordinates(capability)
        candidates.append(
            InterventionCandidate(
                action_digest=document_digest(action),
                guaranteed_evidence_routes=sorted(coordinates["evidence"]),
                resolves_blockers=sorted(coordinates["resolved"] & state.blockers),
                resource_delta_lower={
                    key: str(value) for key, value in sorted(coordinates["resources"].items())
                },
                time_upper=str(coordinates["time"]),
                monetary_cost_upper=str(coordinates["cost"]),
                quality_lower=str(coordinates["quality"]),
                safety_lower=str(coordinates["safety"]),
                verification_load_upper=str(coordinates["verification"]),
                independence_erosion_upper=str(coordinates["independence"]),
                correlation_concentration_upper=str(coordinates["correlation"]),
                cut_exposure_upper=str(coordinates["cut"]),
                debt=sorted(coordinates["debt"]),
                rollback_obligations=sorted(coordinates["rollback"]),
                hazards_added=sorted(coordinates["hazards"]),
            )
        )
    return InterventionPortfolioSpec(
        analysis_snapshot_digest=document_digest(snapshot),
        status="satisfied" if candidates or not blocker_frontier else "violated",
        blocker_frontier=blocker_frontier,
        candidates=candidates,
        solution_class="bounded",
    )


def analyze_interventions(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    profile: OperationalProfile,
    actions: Iterable[ActionDocument] = (),
    capabilities: Iterable[CapabilityDocument] = (),
    *,
    budget: Budget | None = None,
) -> InterventionAnalysis:
    """Run every bounded structural analysis against the same immutable snapshot input view."""

    active_budget = budget or Budget()
    initial_operations = active_budget.remaining
    snapshot_digest = document_digest(snapshot)
    blocker_frontier = sorted(
        {
            blocker
            for result in profile.dimensions.values()
            if result.status != "satisfied"
            for blocker in result.blockers
        }
    )
    transformation_set_digest = digest_bytes(canonical_bytes({}))
    try:
        temporal, at = _temporal(snapshot, objects)
        if temporal.status != "satisfied" or at is None:
            return _unknown_bundle(
                snapshot_digest,
                transformation_set_digest,
                list(snapshot.spec.target_ids),
                [*blocker_frontier, *temporal.blockers],
                _used_operations(active_budget, initial_operations),
            )
        available, _, _, _ = _available_sets(objects, at)
        transformations = _transformations(objects, at)
        transformation_set_digest = digest_bytes(
            canonical_bytes(
                {
                    identifier: document_digest(item)
                    for identifier, item in sorted(transformations.items())
                }
            )
        )
        coordinates = {
            coordinate
            for transformation in transformations.values()
            for coordinate in set(transformation.spec.inputs) | set(transformation.spec.outputs)
        }
        siphons = enumerate_minimal_siphons(transformations, coordinates, active_budget)
        supplied = {
            item.spec.coordinate
            for item in objects.values()
            if isinstance(item, SupplyAttestation)
            and _live(item.spec.lifecycle, at)
            and rational(item.spec.rate_lower) > 0
        }
        initial_marking = {coordinate: rational("1") for coordinate in available}
        unfed = unfed_siphons(siphons.values, initial_marking, supplied)
        cuts = enumerate_minimal_cut_sets(
            available,
            snapshot.spec.target_ids,
            transformations,
            active_budget,
        )
        enablement = enumerate_minimal_enablement_sets(
            available,
            snapshot.spec.target_ids,
            transformations,
            active_budget,
        )
        flux = exact_flux_coupling(transformations, active_budget)
        prefix = bounded_occurrence_prefix(available, transformations, active_budget)
        operations = _used_operations(active_budget, initial_operations)
        exhaustive = siphons.exhaustive and cuts.exhaustive and enablement.exhaustive
        return InterventionAnalysis(
            siphons=SiphonAnalysisSpec(
                analysis_snapshot_digest=snapshot_digest,
                exhaustive=siphons.exhaustive,
                status=(
                    "unknown_due_to_budget"
                    if not siphons.exhaustive
                    else "violated"
                    if unfed
                    else "satisfied"
                ),
                minimal_siphons=[list(item) for item in siphons.values],
                unfed_siphons=[list(item) for item in unfed],
                operation_count=operations,
            ),
            flux_coupling=FluxCouplingSpec(
                analysis_snapshot_digest=snapshot_digest,
                transformation_set_digest=transformation_set_digest,
                status=("satisfied" if flux.status == "satisfied" else "unknown_due_to_budget"),
                blocked_transformations=list(flux.blocked),
                fully_coupled_classes=[list(item) for item in flux.fully_coupled_classes],
                solver_name=flux.solver_name,
                solver_version=flux.solver_version,
                exact_model_rechecked=flux.exact_models_rechecked,
                operation_count=operations,
            ),
            cuts=CutSetAnalysisSpec(
                analysis_snapshot_digest=snapshot_digest,
                target_ids=list(snapshot.spec.target_ids),
                exhaustive=exhaustive,
                status="satisfied" if exhaustive else "unknown_due_to_budget",
                minimal_cut_sets=[list(item) for item in cuts.values],
                minimal_enablement_sets=[list(item) for item in enablement.values],
                operation_count=operations,
            ),
            occurrence_prefix=OccurrencePrefixSpec(
                analysis_snapshot_digest=snapshot_digest,
                exhaustive=prefix.exhaustive,
                status="satisfied" if prefix.exhaustive else "unknown_due_to_budget",
                conditions=[
                    OccurrenceCondition(
                        condition_id=item.condition_id,
                        state_id=item.state_id,
                        producer_event_id=item.producer_event_id,
                    )
                    for item in prefix.conditions
                ],
                events=[
                    OccurrenceEvent(
                        event_id=item.event_id,
                        transformation_id=item.transformation_id,
                        preset_condition_ids=list(item.preset_condition_ids),
                        postset_condition_ids=list(item.postset_condition_ids),
                        causal_predecessor_ids=list(item.causal_predecessor_ids),
                        conflict_event_ids=list(item.conflict_event_ids),
                    )
                    for item in prefix.events
                ],
                cutoff_event_ids=list(prefix.cutoff_event_ids),
                operation_count=operations,
            ),
            portfolio=_portfolio(snapshot, objects, profile, actions, capabilities),
        )
    except AnalysisBudgetExceeded:
        return _unknown_bundle(
            snapshot_digest,
            transformation_set_digest,
            list(snapshot.spec.target_ids),
            blocker_frontier,
            _used_operations(active_budget, initial_operations),
        )
