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
from collective_phase_control_fabric.v6.growth_evidence import reassess
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    AnalysisSnapshot,
    CapabilityDocument,
    EpistemicAssessment,
    EpistemicAssessmentSpec,
    EpistemicObservation,
    EpistemicPlan,
    GrowthObservation,
    RunnerJob,
    RunnerReceipt,
)
from collective_phase_control_fabric.v6.registry import document_digest


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
        for step, digest in zip(history, receipts, strict=True):
            receipt = view.objects.get(digest)
            g.require(isinstance(receipt, RunnerReceipt), "epistemic_receipt_missing")
            receipt = cast(RunnerReceipt, receipt)
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
    except g.GrowthError as error:
        reasons.append(error.code)
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
