# SPDX-License-Identifier: Apache-2.0
"""Read-only admission and arithmetic checks for externally measured growth records."""

from __future__ import annotations

import base64
from datetime import timedelta
from itertools import pairwise
from typing import Any, cast

from collective_phase_control_fabric.v6.authority import load_authoritative_generation
from collective_phase_control_fabric.v6.canonical import (
    loads_bounded,
)
from collective_phase_control_fabric.v6.growth import (
    Budget,
    F,
    GrowthError,
    Search,
    attainment,
    audit_model_boundary,
    block_supported,
    check_plan,
    check_state,
    check_tree,
    compare,
    content_digest,
    initial_state,
    input_digest,
    normalize,
    objective_key,
    require,
    successors,
    transition,
    validate_contract,
)
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    AnalysisSnapshot,
    CapabilityDocument,
    Document,
    ExecutionPolicy,
    GrowthAssessment,
    GrowthAssessmentSpec,
    GrowthCheckpoint,
    GrowthContract,
    GrowthInterval,
    GrowthObservation,
    GrowthPlan,
    GrowthPolicyNode,
    GrowthState,
    MeasurementProtocol,
    RunnerJob,
    RunnerReceipt,
    SignedPayload,
    SourceArtifactEnvelope,
    TrialResult,
    TrustedTimeReceipt,
    TrustPolicyDocument,
    UnitRegistryDocument,
    WorkspaceGeneration,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.runner import validate_receipt
from collective_phase_control_fabric.v6.storage import ObjectStore
from collective_phase_control_fabric.v6.trials import assess_trial


def replay(
    contract: GrowthContract, objects: dict[str, Document], plan: GrowthPlan, branch_ids: list[str]
) -> dict[str, Any]:
    checked = check_plan(contract, objects, plan)
    state = initial_state(contract)
    node = plan.spec.policy
    states = [state]
    for branch_id in branch_ids:
        require(node is not None and node.action_id is not None, "growth_replay_after_terminal")
        node = cast(GrowthPolicyNode, node)
        require(branch_id in node.branches, "growth_undeclared_successor")
        recipe = next(
            r
            for r in contract.spec.action_catalogue
            if cast(ActionDocument, objects[r.action_digest]).spec.action_id == node.action_id
        )
        effect = next(e for e in recipe.successors if e.successor_id == branch_id)
        state = transition(contract, state, recipe, effect, objects)
        states.append(state)
        node = node.branches[branch_id]
    return {
        "code": "growth_hypothetical_replay",
        "checker_digest": checked,
        "model_states": [s.model_dump(mode="json") for s in states],
        "boundary_audits": [audit_model_boundary(contract, objects, s) for s in states],
        "measured_bounds": {},
        "observations_written": [],
        "executed": False,
    }


def export_proposal(
    contract: GrowthContract, objects: dict[str, Document], plan: GrowthPlan, job: RunnerJob
) -> dict[str, Any]:
    """Check an operator-supplied unsigned job draft; do not sign, dispatch or lease it."""
    checked = check_plan(contract, objects, plan)
    root = cast(GrowthPolicyNode, plan.spec.policy)
    recipe = next(
        r
        for r in contract.spec.action_catalogue
        if cast(ActionDocument, objects[r.action_digest]).spec.action_id == root.action_id
    )
    action = cast(ActionDocument, objects[recipe.action_digest])
    cap = cast(CapabilityDocument, objects[action.spec.capability_digest])
    require(
        job.spec.action_digest == recipe.action_digest
        and job.spec.capability_digest == action.spec.capability_digest
        and job.spec.execution_policy_digest == cap.spec.execution_policy_digest
        and job.spec.image_digest == cap.spec.image_digest,
        "growth_proposal_binding_mismatch",
    )
    require(
        set(action.spec.required_object_digests) <= set(job.spec.input_digests),
        "growth_proposal_inputs_missing",
    )
    snapshot = cast(AnalysisSnapshot, objects[contract.spec.analysis_snapshot_digest])
    require(
        job.spec.generation_digest == snapshot.spec.generation_digest,
        "growth_proposal_generation_mismatch",
    )
    return {
        "code": "growth_proposed_external_job",
        "effect_class": "inspect",
        "runner_job": job.model_dump(mode="json"),
        "job_digest": document_digest(job),
        "checker_digest": checked,
        "executed": False,
        "authorized": False,
        "authority_required": plan.spec.required_authority,
    }


def _bounded_measurement(observation: GrowthObservation, state: GrowthState) -> GrowthState:
    domains = set(state.capacities)
    require(
        set(observation.spec.calibration_allowance)
        == domains
        == set(observation.spec.drift_allowance),
        "growth_calibration_domain",
    )
    capacities: dict[str, GrowthInterval] = {}
    for key, interval in state.capacities.items():
        bias = F(observation.spec.calibration_allowance[key])
        drift = F(observation.spec.drift_allowance[key])
        require(bias >= 0 and drift >= 0, "growth_calibration_invalid")
        capacities[key] = GrowthInterval(
            lower=str(max(F(0), F(interval.lower) - bias - drift)),
            upper=str(F(interval.upper) + bias + drift),
        )
    return state.model_copy(update={"capacities": capacities})


def _within_prediction(actual: GrowthState, predicted: GrowthState) -> bool:
    """The recorded exact transition must cover the measured ledger, including cost/debt."""
    if set(actual.capacities) != set(predicted.capacities):
        return False
    if not all(
        F(predicted.capacities[k].lower)
        <= F(actual.capacities[k].lower)
        <= F(actual.capacities[k].upper)
        <= F(predicted.capacities[k].upper)
        for k in actual.capacities
    ):
        return False
    # Measurement can narrow capacity intervals; every other declared ledger facet is retained.
    replacement = predicted.model_copy(update={"capacities": actual.capacities})
    return normalize(actual) == normalize(replacement)


def _seconds(delta: timedelta) -> F:
    return F(delta.days * 86400 + delta.seconds) + F(delta.microseconds, 1_000_000)


def reassess(
    contract: GrowthContract,
    objects: dict[str, Document],
    observation: GrowthObservation,
    *,
    generation: WorkspaceGeneration,
    store: ObjectStore,
    policy: TrustPolicyDocument,
    trusted_time: TrustedTimeReceipt,
    expected_root_spki_fingerprint: str,
    expected_genesis_envelope_fingerprint: str,
) -> GrowthAssessment:
    """Recompute authority on every call; cached admission flags are never an input."""
    validate_contract(contract, objects)
    c, obs = contract.spec, observation.spec
    reasons: list[str] = []
    arithmetic = "unknown"
    compatible = False
    model = "undetermined" if c.initial_state.model_ids else "inconsistent"
    if model == "inconsistent":
        reasons.append("growth_inconsistent_models")
    measured: dict[str, GrowthInterval] = {}
    final: GrowthState | None = None
    comparisons = compare(contract, objects)
    continuation_policy: GrowthPolicyNode | None = None
    continuation_state: GrowthState | None = None
    continuation_search = None
    observation_digest = document_digest(observation)
    view = load_authoritative_generation(
        generation,
        store,
        policy=policy,
        trusted_time=trusted_time,
        expected_root_spki_fingerprint=expected_root_spki_fingerprint,
        expected_genesis_envelope_fingerprint=expected_genesis_envelope_fingerprint,
    )
    if not view.valid:
        reasons.extend(sorted({reason.partition(":")[0] for reason in view.reasons}))
    try:
        require(
            view.valid and observation_digest in view.objects, "growth_observation_not_admitted"
        )
        require(
            obs.contract_digest == document_digest(contract), "growth_observation_contract_mismatch"
        )
        require(obs.versions == c.versions, "growth_observation_versions_changed")
        require(
            obs.lifecycle.valid_from <= trusted_time.spec.issued_at <= obs.lifecycle.valid_until,
            "growth_observation_expired",
        )
        require(
            obs.window in c.windows and obs.monitoring == "preregistered-boundaries",
            "growth_observation_window_changed",
        )
        require(
            len(set(obs.source_artifact_digests)) == len(obs.source_artifact_digests)
            and len(set(obs.runner_receipt_digests)) == len(obs.runner_receipt_digests),
            "growth_duplicate_evidence",
        )
        require(
            len(obs.runner_receipt_digests) == len(obs.states) - 1,
            "growth_observation_trace_incomplete",
        )
        available = {
            e.object_digest
            for e in generation.spec.ledger
            if store.exists(generation.metadata.tenant_id, e.object_digest)
        }
        require(set(obs.source_artifact_digests) <= available, "growth_source_missing")
        lengths = {d: len(store.get(generation.metadata.tenant_id, d)) for d in available}
        require(
            all(
                any(
                    isinstance(item, SourceArtifactEnvelope) and item.spec.raw_digest == d
                    for item in view.objects.values()
                )
                for d in obs.source_artifact_digests
            ),
            "growth_source_not_admitted",
        )
        protocol = view.objects.get(c.versions.protocol_digest)
        result = view.objects.get(obs.trial_result_digest)
        require(
            isinstance(protocol, MeasurementProtocol) and isinstance(result, TrialResult),
            "growth_trial_missing",
        )
        protocol = cast(MeasurementProtocol, protocol)
        result = cast(TrialResult, result)
        require(protocol.spec.time_zero == c.model_time_origin, "growth_trial_time_origin_mismatch")
        require(
            result.spec.protocol_digest == document_digest(protocol)
            and result.spec.evaluator_principal_id == obs.evaluator_principal_id,
            "growth_trial_binding_mismatch",
        )
        trial = assess_trial(
            protocol, view.objects, signer_principals=view.subject_principals, cas_digests=available
        )
        require(
            not trial.blockers and not trial.contradictions and trial.tier != "unmeasured",
            "growth_trial_incompatible",
        )
        effects = {e.outcome_id: e for e in result.spec.effects}
        definitions = {e.outcome_id: e for e in protocol.spec.outcomes}
        expected_ids = {f"{key}:{index}" for index in range(len(obs.states)) for key in c.domains}
        require(set(effects) == expected_ids, "growth_trial_measurement_incomplete")
        for index, state in enumerate(obs.states):
            for key in c.domains:
                outcome = effects[f"{key}:{index}"]
                require(
                    outcome.lower == state.capacities[key].lower
                    and outcome.upper == state.capacities[key].upper
                    and outcome.quality_value == state.quality[key]
                    and definitions[outcome.outcome_id].unit == c.domains[key].unit,
                    "growth_trial_measurement_mismatch",
                )
        require(
            _within_prediction(obs.states[0], initial_state(contract)),
            "growth_observation_seed_mismatch",
        )
        used_attempts: set[tuple[str, int]] = set()
        covered_sources: set[str] = set()
        for index, receipt_digest in enumerate(obs.runner_receipt_digests):
            receipt = view.objects.get(receipt_digest)
            require(isinstance(receipt, RunnerReceipt), "growth_receipt_not_admitted")
            receipt = cast(RunnerReceipt, receipt)
            require(
                receipt.spec.runner_principal_id
                in view.subject_principals.get(receipt_digest, frozenset()),
                "growth_receipt_principal_mismatch",
            )
            job = view.objects.get(receipt.spec.job_digest)
            require(isinstance(job, RunnerJob), "growth_job_not_admitted")
            job = cast(RunnerJob, job)
            cap = view.objects.get(job.spec.capability_digest)
            execution = view.objects.get(job.spec.execution_policy_digest)
            require(
                isinstance(cap, CapabilityDocument) and isinstance(execution, ExecutionPolicy),
                "growth_runner_materials_not_admitted",
            )
            cap = cast(CapabilityDocument, cap)
            execution = cast(ExecutionPolicy, execution)
            # Independently signed historical receipt time, not the model clock.
            receipt_times: list[TrustedTimeReceipt] = []
            for statement in view.subject_statements[receipt_digest]:
                if statement not in view.statement_principals:
                    continue
                payload = SignedPayload.model_validate_json(
                    base64.b64decode(view.statement_envelopes[statement].payload, validate=True)
                )
                time_doc = view.objects.get(payload.protected.trusted_time_receipt_digest or "")
                if isinstance(time_doc, TrustedTimeReceipt):
                    receipt_times.append(time_doc)
            require(bool(receipt_times), "growth_receipt_time_missing")
            output = None
            if len(receipt.spec.output_digests) == 1:
                output = loads_bounded(
                    store.get(generation.metadata.tenant_id, receipt.spec.output_digests[0])
                )
            conformance = validate_receipt(
                job,
                receipt,
                cap,
                execution,
                received_at=min(t.spec.issued_at for t in receipt_times),
                expected_runner_principal_id=receipt.spec.runner_principal_id,
                prior_attempts=used_attempts,
                available_digests=available,
                artifact_lengths=lengths,
                output_document=output,
            )
            require(conformance.accepted, "growth_receipt_nonconformant")
            used_attempts.add((job.spec.job_id, job.spec.attempt))
            units = cast(UnitRegistryDocument, objects[c.unit_registry_digest])
            time_scale = F(units.spec.units[units.spec.time_unit].scale)
            require(
                _seconds(receipt.spec.started_at - protocol.spec.time_zero)
                == F(obs.states[index].elapsed) * time_scale
                and _seconds(receipt.spec.completed_at - protocol.spec.time_zero)
                == F(obs.states[index + 1].elapsed) * time_scale,
                "growth_receipt_physical_time_mismatch",
            )
            covered_sources.update(receipt.spec.output_digests)
            covered_sources.add(receipt.spec.stdout_digest)
            recipes = [r for r in c.action_catalogue if r.action_digest == job.spec.action_digest]
            require(
                len(recipes) == 1
                and job.spec.capability_digest
                == cast(ActionDocument, objects[job.spec.action_digest]).spec.capability_digest,
                "growth_receipt_action_mismatch",
            )
            possible = [
                e
                for e in successors(obs.states[index], recipes[0])
                if e.outcome == receipt.spec.claimed_outcome
            ]
            predictions: list[GrowthState] = []
            for effect in possible:
                try:
                    predictions.append(
                        transition(contract, obs.states[index], recipes[0], effect, objects)
                    )
                except GrowthError:
                    continue
            require(
                any(_within_prediction(obs.states[index + 1], p) for p in predictions),
                "growth_observation_outside_model",
            )
        require(
            set(obs.source_artifact_digests) <= covered_sources, "growth_source_receipt_mismatch"
        )
        # Admission and trial compatibility do not establish arithmetic or attribution.
        compatible = True
        bounded = [_bounded_measurement(observation, state) for state in obs.states]
        for state in bounded:
            check_state(contract, state)
        require(
            all(F(a.elapsed) < F(b.elapsed) for a, b in pairwise(bounded)),
            "growth_observation_time_order",
        )
        final = bounded[-1].model_copy(
            update={
                "checkpoints": [
                    GrowthCheckpoint(time=s.elapsed, capacities=s.capacities) for s in bounded[:-1]
                ]
            }
        )
        require(
            F(bounded[0].elapsed) <= F(obs.window.start) and F(final.elapsed) == F(obs.window.end),
            "growth_observation_window_changed",
        )
        measured = final.capacities
        require(block_supported(final, obs.window), "growth_observed_block_not_supported")
        require(
            all(
                k in final.evidence and F(final.evidence[k]) >= F(final.elapsed)
                for k in c.required_entry_evidence
            )
            and not final.pending_results,
            "growth_observed_evidence_pending",
        )
        require(
            not {w.work_id for w in final.queue + final.obligations}
            & set(c.blocking_obligation_ids),
            "growth_observed_work_blocked",
        )
        arithmetic = "satisfied"
        at_endpoint = [x for x in comparisons if F(x.endpoint) == F(final.elapsed)]
        if not final.model_ids:
            model = "inconsistent"
        elif all(x.search.complete and x.upper_bound is not None for x in at_endpoint):
            model = (
                "supported"
                if attainment(contract, final) >= 1
                and all(
                    attainment(contract, final)
                    > F(cast(str, x.upper_bound)) + F(c.comparison_margin)
                    for x in at_endpoint
                )
                else "undetermined"
            )
    except GrowthError as error:
        reasons.append(error.code)
        if compatible:
            arithmetic = "violated"
        if not compatible or not measured:
            final = None
    if final is not None:
        final = final.model_copy(
            update={
                "actual_evidence_digests": sorted(
                    {observation_digest, *obs.runner_receipt_digests}
                ),
                "attribution": "attribution-unresolved",
            }
        )
        # Re-evaluation computation consumes another declared allowance in a MODEL ledger.
        # Its prediction is never written into the measured state above.
        if model == "supported":
            try:
                # Only the explicitly paid planning interval may bridge admission lag.
                # P0 has no additional unobserved waiting/arrival law.
                units = cast(UnitRegistryDocument, objects[c.unit_registry_digest])
                require(
                    _seconds(trusted_time.spec.issued_at - c.model_time_origin)
                    <= (F(final.elapsed) + F(c.planning_duration))
                    * F(units.spec.units[units.spec.time_unit].scale),
                    "growth_continuation_state_stale",
                )
                proposal = contract.model_copy(
                    update={"spec": c.model_copy(update={"initial_state": final})}
                )
                continuation_state = initial_state(proposal)
                search = Search(proposal, objects, Budget(c.search_limits))
                entry = GrowthCheckpoint(time=final.elapsed, capacities=final.capacities)
                candidates = search.enumerate(continuation_state, entry=entry)
                continuation_search = search.budget.report()
                if candidates:
                    chosen = min(candidates, key=lambda p: objective_key(proposal, p))
                    check_tree(proposal, objects, chosen.node, continuation_state, entry=entry)
                    continuation_policy = chosen.node
            except GrowthError as error:
                reasons.append(error.code)
    return GrowthAssessment(
        metadata=observation.metadata,
        spec=GrowthAssessmentSpec(
            contract_digest=document_digest(contract),
            input_digest=input_digest(contract, objects),
            code="growth_evidence_compatible"
            if compatible and not reasons
            else "growth_reassessment_inconclusive",
            model_condition=cast(Any, model),
            arithmetic_check=cast(Any, arithmetic),
            external_evidence_compatibility="compatible" if compatible else "unknown",
            observed_entry="compatible"
            if compatible and model == "supported" and arithmetic == "satisfied"
            else "undetermined",
            observation_digest=observation_digest,
            measured_bounds=measured,
            continuation="model-witness" if continuation_policy else "unavailable",
            continuation_policy=continuation_policy,
            continuation_model_state=continuation_state,
            continuation_search=continuation_search,
            continuation_expires=str(F(final.elapsed) + F(c.continuation_horizon))
            if final
            else None,
            reasons=reasons,
            comparisons=comparisons,
            reassessed_state=final,
        ),
    )


def replan_contract(contract: GrowthContract, assessment: GrowthAssessment) -> GrowthContract:
    """Construct an UNSIGNED modelling proposal after fresh reassessment in the caller.

    This helper conveys no admission or registration. The returned contract is a new
    hypothetical input, even if an external caller constructs an assessment object.
    """
    require(assessment.spec.reassessed_state is not None, "growth_replan_state_unavailable")
    state = cast(GrowthState, assessment.spec.reassessed_state)
    return contract.model_copy(
        update={
            "metadata": contract.metadata.model_copy(
                update={"object_id": "growth-replan-proposal"}
            ),
            "spec": contract.spec.model_copy(update={"initial_state": state}),
            "extensions": {
                **contract.extensions,
                "org.cpcf.growth": {
                    "parent_contract_digest": document_digest(contract),
                    "registration": "required",
                    "basis_assessment_digest": content_digest(assessment),
                    "hypothetical": True,
                },
            },
        }
    )
