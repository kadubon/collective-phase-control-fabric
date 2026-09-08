# SPDX-License-Identifier: Apache-2.0
"""Fresh admitted evidence may justify a new unsigned finite modelling proposal."""

from __future__ import annotations

from typing import Any, cast

from collective_phase_control_fabric.v6.authority import load_authoritative_generation
from collective_phase_control_fabric.v6.growth import (
    Budget,
    F,
    GrowthError,
    Search,
    attainment,
    check_tree,
    compare,
    initial_state,
    input_digest,
    objective_key,
    require,
    state_digest,
    successors,
    transition,
)
from collective_phase_control_fabric.v6.growth_evidence import (
    _seconds,
    _within_prediction,
    reassess,
    replan_contract,
)
from collective_phase_control_fabric.v6.growth_frontier import base_state, seed, validate_frontier
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    CapabilityDocument,
    Document,
    ExecutionPolicy,
    GrowthAssessment,
    GrowthAssessmentSpec,
    GrowthCapabilityFrontier,
    GrowthCheckpoint,
    GrowthContract,
    GrowthFrontierAssessment,
    GrowthFrontierAssessmentSpec,
    GrowthFrontierState,
    GrowthObservation,
    GrowthState,
    RunnerJob,
    RunnerReceipt,
    UnitRegistryDocument,
)
from collective_phase_control_fabric.v6.registry import document_digest


def _proposal(
    contract: GrowthContract,
    frontier: GrowthCapabilityFrontier,
    assessment: GrowthFrontierAssessment,
) -> tuple[GrowthContract, GrowthCapabilityFrontier]:
    state = assessment.spec.reconstructed_frontier_state
    require(state is not None, "growth_frontier_advancement_unavailable")
    state = cast(GrowthFrontierState, state)
    base = GrowthAssessment(
        metadata=assessment.metadata,
        spec=GrowthAssessmentSpec.model_validate(
            {
                k: v
                for k, v in assessment.spec.model_dump(mode="json").items()
                if k in GrowthAssessmentSpec.model_fields
            }
        ),
    )
    proposed = replan_contract(contract, base)
    proposed_frontier = frontier.model_copy(
        update={
            "metadata": frontier.metadata.model_copy(
                update={"object_id": "growth-frontier-replan-proposal"}
            ),
            "spec": frontier.spec.model_copy(
                update={
                    "contract_digest": document_digest(proposed),
                    "initial_enabled_action_ids": sorted(state.enabled_action_ids),
                    "initial_activation_lineage": state.activation_lineage,
                    "latent_action_ids": sorted(
                        {b.action_id for b in frontier.spec.bindings}
                        - set(state.enabled_action_ids)
                    ),
                    "parent_frontier_digest": document_digest(frontier),
                    "advancement_evidence_digests": assessment.spec.advancement_evidence_digests,
                }
            ),
        }
    )
    return proposed, proposed_frontier


def reassess_frontier(
    contract: GrowthContract,
    objects: dict[str, Document],
    observation: GrowthObservation,
    frontier: GrowthCapabilityFrontier,
    **admission: Any,
) -> GrowthFrontierAssessment:
    """Original evidence only. A cached assessment is neither accepted nor consulted.

    Existing reassessment independently validates every source, signature, quorum,
    measurement and receipt. A second read of the same immutable generation resolves
    admitted frontier/capability subjects and reconstructs every compatible outcome.
    Ambiguous activation is unknown, never a favorable choice of successor ID.
    """
    validate_frontier(contract, objects, frontier)
    base = reassess(contract, objects, observation, **admission)
    comparisons = compare(contract, objects, frontier)
    # Clear the no-frontier continuation and comparator interpretation before using it.
    data = base.spec.model_dump()
    data.update(
        input_digest=input_digest(contract, objects, frontier),
        comparisons=comparisons,
        continuation="unavailable",
        continuation_policy=None,
        continuation_model_state=None,
        continuation_search=None,
        model_condition="inconsistent"
        if not contract.spec.initial_state.model_ids
        else "undetermined",
        observed_entry="undetermined",
    )
    reasons = list(base.spec.reasons)
    reconstructed = None
    admitted_ids: list[str] = []
    evidence: set[str] = set()
    continuation_state = None
    try:
        require(
            base.spec.external_evidence_compatibility == "compatible"
            and base.spec.reassessed_state is not None,
            "growth_frontier_evidence_unavailable",
        )
        view = load_authoritative_generation(**admission)
        require(
            view.valid and document_digest(frontier) in view.objects, "growth_frontier_not_admitted"
        )
        evidence.update(
            [
                document_digest(frontier),
                document_digest(observation),
                *observation.spec.runner_receipt_digests,
            ]
        )
        state = seed(observation.spec.states[0], frontier)
        for index, receipt_digest in enumerate(observation.spec.runner_receipt_digests):
            receipt = cast(RunnerReceipt, view.objects[receipt_digest])
            job = cast(RunnerJob, view.objects[receipt.spec.job_digest])
            recipe = next(
                r
                for r in contract.spec.action_catalogue
                if r.action_digest == job.spec.action_digest
            )
            actual = observation.spec.states[index + 1]
            candidates = []
            for effect in successors(state, recipe):
                if effect.outcome != receipt.spec.claimed_outcome:
                    continue
                try:
                    predicted = transition(contract, base_state(state), recipe, effect, objects)
                except GrowthError:
                    continue
                if not _within_prediction(actual, predicted):
                    continue
                # A model-compatible branch that fails frontier validation invalidates
                # advancement; it must not be discarded in favor of another branch.
                expanded = cast(
                    GrowthFrontierState,
                    transition(contract, state, recipe, effect, objects, frontier),
                )
                candidates.append(
                    GrowthFrontierState.model_validate(
                        {**expanded.model_dump(), **actual.model_dump()}
                    )
                )
            require(bool(candidates), "growth_frontier_observation_outside_model")
            require(
                len({state_digest(s) for s in candidates}) == 1,
                "growth_frontier_successor_ambiguous",
            )
            after = candidates[0]
            for event in after.activation_lineage:
                # Carried lineage still needs current independently admitted materials.
                # Registration of a modelling proposal is not capability admission.
                binding = next(b for b in frontier.spec.bindings if b.action_id == event.action_id)
                rule = next(r for r in frontier.spec.activation_rules if r.rule_id == event.rule_id)
                required = {
                    binding.action_digest,
                    binding.capability_digest,
                    binding.execution_policy_digest,
                    *rule.required_capability_digests,
                }
                require(
                    all(
                        d in view.objects
                        and isinstance(
                            view.objects[d], (ActionDocument, CapabilityDocument, ExecutionPolicy)
                        )
                        for d in required
                    ),
                    "growth_frontier_activation_not_admitted",
                )
                evidence.update(required)
            state = after
        reconstructed = GrowthFrontierState.model_validate(
            {**state.model_dump(), **cast(GrowthState, base.spec.reassessed_state).model_dump()}
        )
        admitted_ids = sorted(x.action_id for x in state.activation_lineage)
        at_endpoint = [x for x in comparisons if F(x.endpoint) == F(reconstructed.elapsed)]
        supported = (
            bool(reconstructed.model_ids)
            and base.spec.arithmetic_check == "satisfied"
            and len(at_endpoint) == len(contract.spec.comparators)
            and attainment(contract, reconstructed) >= 1
            and all(
                x.search.complete
                and x.upper_bound is not None
                and attainment(contract, reconstructed)
                > F(x.upper_bound) + F(contract.spec.comparison_margin)
                for x in at_endpoint
            )
        )
        if supported:
            data.update(model_condition="supported", observed_entry="compatible")
    except GrowthError as error:
        reasons.append(error.code)
        reconstructed = None
        admitted_ids = []
        evidence.clear()
    result = GrowthFrontierAssessment(
        metadata=observation.metadata,
        spec=GrowthFrontierAssessmentSpec(
            **{
                **data,
                "reasons": sorted(set(reasons)),
                "code": "growth_frontier_evidence_reassessed"
                if reconstructed is not None
                else "growth_frontier_reassessment_inconclusive",
            },
            frontier_digest=document_digest(frontier),
            reconstructed_frontier_state=reconstructed,
            admitted_activation_action_ids=admitted_ids,
            advancement_evidence_digests=sorted(evidence),
        ),
    )
    if reconstructed is None:
        return result
    # Bind the proof and returned proposal to one pre-continuation evidence basis.
    # Rebuilding after adding the proof would change the contract's basis digest,
    # then the frontier digest, invalidating that same proof's state bindings.
    proposed, proposed_frontier = _proposal(contract, frontier, result)
    result = result.model_copy(
        update={
            "spec": result.spec.model_copy(
                update={"proposed_contract": proposed, "proposed_frontier": proposed_frontier}
            )
        }
    )
    if result.spec.model_condition == "supported":
        try:
            units = cast(UnitRegistryDocument, objects[contract.spec.unit_registry_digest])
            require(
                _seconds(admission["trusted_time"].spec.issued_at - contract.spec.model_time_origin)
                <= (F(reconstructed.elapsed) + F(contract.spec.planning_duration))
                * F(units.spec.units[units.spec.time_unit].scale),
                "growth_continuation_state_stale",
            )
            continuation_state = cast(
                GrowthFrontierState, initial_state(proposed, proposed_frontier)
            )
            entry = GrowthCheckpoint(
                time=reconstructed.elapsed, capacities=reconstructed.capacities
            )
            search = Search(
                proposed, objects, Budget(proposed.spec.search_limits), frontier=proposed_frontier
            )
            policies = search.enumerate(continuation_state, entry=entry)
            updates: dict[str, Any] = {"continuation_search": search.budget.report()}
            if policies:
                selected = min(policies, key=lambda p: objective_key(proposed, p))
                check_tree(
                    proposed,
                    objects,
                    selected.node,
                    continuation_state,
                    entry=entry,
                    frontier=proposed_frontier,
                )
                updates.update(
                    continuation="model-witness",
                    continuation_policy=selected.node,
                    continuation_model_state=base_state(continuation_state),
                    frontier_continuation_state=continuation_state,
                )
            result = result.model_copy(update={"spec": result.spec.model_copy(update=updates)})
        except GrowthError as error:
            result = result.model_copy(
                update={
                    "spec": result.spec.model_copy(
                        update={"reasons": sorted(set([*result.spec.reasons, error.code]))}
                    )
                }
            )
    return result


def replan_frontier(
    contract: GrowthContract,
    objects: dict[str, Document],
    observation: GrowthObservation,
    frontier: GrowthCapabilityFrontier,
    **admission: Any,
) -> tuple[GrowthContract, GrowthCapabilityFrontier, GrowthFrontierAssessment]:
    assessment = reassess_frontier(contract, objects, observation, frontier, **admission)
    require(
        assessment.spec.proposed_contract is not None
        and assessment.spec.proposed_frontier is not None,
        "growth_frontier_advancement_unavailable",
    )
    return (
        cast(GrowthContract, assessment.spec.proposed_contract),
        cast(GrowthCapabilityFrontier, assessment.spec.proposed_frontier),
        assessment,
    )
