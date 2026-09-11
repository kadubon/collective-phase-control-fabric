# SPDX-License-Identifier: Apache-2.0
"""Fresh original admission and a registered, deliberately narrow observation map.

Only a receipt-covered stdout JSON `observation` symbol enters the controller.
Unregistered timing, debug fields and simulator model IDs do not select a branch.
The original growth evidence path validates DSSE, trial, clocks, outputs and ledgers.
"""

from __future__ import annotations

from typing import Any, cast

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.authority import load_authoritative_generation
from collective_phase_control_fabric.v6.canonical import loads_bounded
from collective_phase_control_fabric.v6.epistemic import Domain, support_digest
from collective_phase_control_fabric.v6.epistemic_checking import (
    check_epistemic_plan,
    reference_comparisons,
)
from collective_phase_control_fabric.v6.epistemic_planning import plan_epistemic
from collective_phase_control_fabric.v6.growth_evidence import _within_prediction, reassess
from collective_phase_control_fabric.v6.growth_frontier import base_state
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    AnalysisSnapshot,
    CapabilityDocument,
    EpistemicAssessment,
    EpistemicAssessmentSpec,
    EpistemicHypothesis,
    EpistemicObservation,
    EpistemicPlan,
    EpistemicStep,
    GrowthCheckpoint,
    GrowthObservation,
    GrowthState,
    RunnerJob,
    RunnerReceipt,
)
from collective_phase_control_fabric.v6.registry import document_digest


def _joint_receipt_trace(
    domain: Domain,
    history: list[EpistemicStep],
    observation: GrowthObservation,
    receipts: list[RunnerReceipt],
) -> None:
    """Check joint consistency without exposing or using hidden ledger data as a signal."""

    def fits(actual: GrowthState, h: EpistemicHypothesis) -> bool:
        predicted = base_state(h.state)
        # The legacy field lists model alternatives, not a measured true theta.
        actual = actual.model_copy(update={"model_ids": predicted.model_ids})
        return _within_prediction(actual, predicted)

    joint = [h for h in domain.initial() if fits(observation.spec.states[0], h)]
    g.require(bool(joint), "epistemic_receipt_model_mismatch")
    budget = g.Budget(domain.contract.spec.search_limits)
    for index, (step, receipt) in enumerate(zip(history, receipts, strict=True)):
        following = []
        recipe = domain.recipes[step.action_id]
        for h in joint:
            if step.entry:
                h = h.model_copy(
                    update={
                        "entry": GrowthCheckpoint(
                            time=h.state.elapsed, capacities=h.state.capacities
                        )
                    }
                )
            for effect in g.successors(h.state, recipe):
                g.require(
                    budget.take("expansions", budget.limits.max_expansions),
                    "epistemic_check_budget",
                )
                if (
                    effect.outcome != receipt.spec.claimed_outcome
                    or step.observation
                    not in domain.kernel[(h.model_id, recipe.action_digest, effect.successor_id)]
                ):
                    continue
                after = g.transition(
                    domain.contract, h.state, recipe, effect, domain.objects, domain.frontier
                )
                candidate = domain.pay(
                    EpistemicHypothesis(
                        model_id=h.model_id,
                        state=after,
                        entry=h.entry,
                        primitive_steps=h.primitive_steps + 1,
                    )
                )
                if fits(observation.spec.states[index + 1], candidate):
                    following.append(candidate)
        g.require(bool(following), "epistemic_receipt_model_mismatch")
        joint = list(domain.bounded(following))


def export_epistemic(domain: Domain, plan: EpistemicPlan, job: RunnerJob) -> dict[str, Any]:
    checked = check_epistemic_plan(domain, plan)
    root = plan.spec.policy
    if root is None or root.action_id is None:
        raise g.GrowthError("epistemic_policy_missing")
    recipe = domain.recipes[root.action_id]
    action = cast(ActionDocument, domain.objects[recipe.action_digest])
    cap = cast(CapabilityDocument, domain.objects[action.spec.capability_digest])
    snapshot = cast(AnalysisSnapshot, domain.objects[domain.contract.spec.analysis_snapshot_digest])
    g.require(
        job.spec.action_digest == recipe.action_digest
        and job.spec.capability_digest == action.spec.capability_digest
        and job.spec.execution_policy_digest == cap.spec.execution_policy_digest
        and job.spec.image_digest == cap.spec.image_digest
        and job.spec.generation_digest == snapshot.spec.generation_digest,
        "epistemic_export_binding",
    )
    g.require(
        set(action.spec.required_object_digests) <= set(job.spec.input_digests),
        "epistemic_export_inputs",
    )
    return {
        "code": "epistemic_proposed_primitive_job",
        "runner_job": job.model_dump(mode="json"),
        "policy_check": checked,
        "executed": False,
        "authorized": False,
        "required_authority": ["existing-capability-admission", "external-runner-authorization"],
    }


def reassess_epistemic(
    domain: Domain,
    observation: EpistemicObservation,
    growth_observation: GrowthObservation,
    **admission: Any,
) -> EpistemicAssessment:
    base = reassess(domain.contract, domain.objects, growth_observation, **admission)
    view = load_authoritative_generation(**admission)
    reasons: list[str] = []
    support = None
    try:
        g.require(
            view.valid and base.spec.external_evidence_compatibility == "compatible",
            "epistemic_original_evidence_unavailable",
        )
        g.require(
            document_digest(observation) in view.objects
            and document_digest(domain.epistemic) in view.objects
            and (domain.frontier is None or document_digest(domain.frontier) in view.objects),
            "epistemic_observation_not_admitted",
        )
        g.require(
            observation.spec.epistemic_contract_digest == document_digest(domain.epistemic)
            and observation.spec.growth_observation_digest == document_digest(growth_observation)
            and observation.spec.evaluator_principal_id
            == growth_observation.spec.evaluator_principal_id,
            "epistemic_evidence_binding",
        )
        history = observation.spec.history
        receipts = growth_observation.spec.runner_receipt_digests
        g.require(len(history) == len(receipts), "epistemic_evidence_trace_incomplete")
        g.require(
            domain.observation_map == {s: s for s in domain.epistemic.spec.observation_alphabet},
            "epistemic_evidence_channel_mismatch",
        )
        admitted_receipts = []
        for step, digest in zip(history, receipts, strict=True):
            receipt = view.objects.get(digest)
            g.require(isinstance(receipt, RunnerReceipt), "epistemic_receipt_missing")
            receipt = cast(RunnerReceipt, receipt)
            admitted_receipts.append(receipt)
            job = view.objects.get(receipt.spec.job_digest)
            g.require(
                isinstance(job, RunnerJob) and step.action_id in domain.recipes,
                "epistemic_receipt_action",
            )
            job = cast(RunnerJob, job)
            g.require(
                job.spec.action_digest == domain.recipes[step.action_id].action_digest
                and receipt.spec.stdout_digest in growth_observation.spec.source_artifact_digests,
                "epistemic_receipt_action",
            )
            raw = admission["store"].get(
                view.generation.metadata.tenant_id, receipt.spec.stdout_digest
            )
            try:
                record = loads_bounded(raw)
            except ValueError as error:
                raise g.GrowthError("epistemic_measurement_mapping") from error
            g.require(
                record.get("epistemic_contract_digest") == document_digest(domain.epistemic)
                and record.get("observation") == step.observation,
                "epistemic_measurement_mapping",
            )
        support = domain.replay(history, reference_comparisons(domain))
        _joint_receipt_trace(domain, history, growth_observation, admitted_receipts)
    except g.GrowthError as error:
        reasons.append(error.code)
        support = None
    return EpistemicAssessment(
        metadata=observation.metadata,
        spec=EpistemicAssessmentSpec(
            input_digest=domain.digest(),
            observation_digest=document_digest(observation),
            code="epistemic_observation_compatible"
            if support
            else "epistemic_evidence_incompatible",
            external_evidence_compatibility="compatible" if support else "incompatible",
            legacy_evidence_assessment=base,
            compatible_support_digest=support_digest(support) if support else None,
            history=observation.spec.history if support else [],
            reasons=reasons,
        ),
    )


def replan_epistemic(
    domain: Domain,
    observation: EpistemicObservation,
    growth_observation: GrowthObservation,
    **admission: Any,
) -> dict[str, Any]:
    assessment = reassess_epistemic(domain, observation, growth_observation, **admission)
    g.require(
        assessment.spec.external_evidence_compatibility == "compatible",
        "epistemic_replan_evidence_unavailable",
    )
    plan = plan_epistemic(domain, assessment.spec.history)
    return {
        "code": "epistemic_unsigned_replan",
        "assessment": assessment.model_dump(mode="json"),
        "plan": plan.model_dump(mode="json"),
        "signed_history_modified": False,
        "requires_registration_before_external_use": True,
        "execution_authorized": False,
    }
