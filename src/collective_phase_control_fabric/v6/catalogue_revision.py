# SPDX-License-Identifier: Apache-2.0
"""Copy-on-write model catalogue proposals with freshly checked procedural reuse.

The named composition is flattened to primitive policy decisions. The immutable
primitive library, kernel and physical horizon are not extended by a macro name.
These functions have no trust-store writes or execution-authority side effects.
"""

from __future__ import annotations

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.composition import check_composition, formation_domain
from collective_phase_control_fabric.v6.epistemic import Domain
from collective_phase_control_fabric.v6.epistemic_checking import check_epistemic_plan
from collective_phase_control_fabric.v6.epistemic_planning import plan_epistemic
from collective_phase_control_fabric.v6.models import (
    CatalogueRevision,
    CatalogueRevisionSpec,
    WorkflowCandidate,
    WorkflowCertificate,
    WorkflowRequest,
    WorkflowSynthesis,
)
from collective_phase_control_fabric.v6.registry import document_digest


def propose_catalogue(
    domain: Domain,
    request: WorkflowRequest,
    synthesis: WorkflowSynthesis,
    candidate: WorkflowCandidate,
    *,
    parent: CatalogueRevision | None = None,
) -> CatalogueRevision:
    g.require(
        synthesis.spec.request_digest == document_digest(request)
        and candidate in synthesis.spec.candidates,
        "catalogue_candidate_missing",
    )
    checked = check_composition(domain, request, candidate)
    g.require(checked in synthesis.spec.certificates, "catalogue_certificate_tampered")
    proposed = formation_domain(domain, request)
    g.require(
        proposed.epistemic == synthesis.spec.proposed_epistemic_contract,
        "catalogue_proposal_tampered",
    )
    revision = len(domain.epistemic.spec.cost_events) + 1
    g.require(revision <= 4, "catalogue_revision_quota")
    previous_work = sum(x.reserved_synthesis_expansions for x in domain.epistemic.spec.cost_events)
    if parent is not None:
        g.require(
            parent.spec.proposed_epistemic_contract == domain.epistemic
            and parent.spec.revision_number == revision - 1
            and request.spec.history[: len(parent.spec.history)] == parent.spec.history
            and parent.spec.primitive_step_limit == domain.contract.spec.max_decisions,
            "catalogue_parent_mismatch",
        )
        g.require(
            parent.spec.cumulative_synthesis_expansions == previous_work,
            "catalogue_parent_mismatch",
        )
    else:
        g.require(revision == 1, "catalogue_parent_missing")
    # Reserve the declared maximum, never trust a submitted search-counter claim.
    work = previous_work + domain.contract.spec.search_limits.max_expansions
    g.require(work <= 1_000_000, "catalogue_synthesis_quota")
    return CatalogueRevision(
        metadata=request.metadata,
        spec=CatalogueRevisionSpec(
            parent_revision_digest=document_digest(parent) if parent is not None else None,
            parent_epistemic_digest=document_digest(domain.epistemic),
            proposed_epistemic_contract=proposed.epistemic,
            history=request.spec.history,
            request_digest=document_digest(request),
            candidate_digest=document_digest(candidate),
            certificate_digest=document_digest(checked),
            revision_number=revision,
            cumulative_synthesis_expansions=work,
            primitive_step_limit=domain.contract.spec.max_decisions,
        ),
    )


def replan_catalogue(
    domain: Domain,
    request: WorkflowRequest,
    candidate: WorkflowCandidate,
    certificate: WorkflowCertificate,
    revision: CatalogueRevision,
    *,
    model_only_opt_in: bool = False,
) -> dict[str, object]:
    g.require(model_only_opt_in, "catalogue_model_only_opt_in_required")
    r = revision.spec
    g.require(
        r.parent_epistemic_digest == document_digest(domain.epistemic)
        and r.request_digest == document_digest(request)
        and r.candidate_digest == document_digest(candidate)
        and r.certificate_digest == document_digest(certificate)
        and r.history == request.spec.history
        and r.primitive_step_limit == domain.contract.spec.max_decisions
        and r.revision_number == len(domain.epistemic.spec.cost_events) + 1,
        "catalogue_revision_binding",
    )
    # Cached acceptance is not sufficient: unfold again against current objects.
    fresh = check_composition(domain, request, candidate)
    g.require(fresh == certificate, "catalogue_certificate_tampered")
    proposed = formation_domain(domain, request)
    g.require(proposed.epistemic == r.proposed_epistemic_contract, "catalogue_proposal_tampered")
    g.require(
        r.cumulative_synthesis_expansions
        == sum(x.reserved_synthesis_expansions for x in proposed.epistemic.spec.cost_events),
        "catalogue_synthesis_quota",
    )
    plan = plan_epistemic(proposed, r.history)
    if plan.spec.policy is None:
        g.require(not plan.spec.search.complete, "catalogue_search_contradiction")
        plan = plan.model_copy(
            update={
                "spec": plan.spec.model_copy(
                    update={
                        "code": "epistemic_incumbent",
                        "policy": candidate.spec.ir,
                        "policy_digest": g.content_digest(candidate.spec.ir),
                        "objective": fresh.spec.objective,
                    }
                )
            }
        )
    selected = None
    if plan.spec.policy is not None and plan.spec.policy == candidate.spec.ir:
        selected = document_digest(candidate)
    checked = check_epistemic_plan(proposed, plan) if plan.spec.policy else None
    return {
        "code": "catalogue_model_replanned",
        "revision_digest": document_digest(revision),
        "selected_workflow_digest": selected,
        "expanded_primitive_steps": candidate.spec.expanded_primitive_steps if selected else None,
        "plan": plan.model_dump(mode="json"),
        "policy_check": checked,
        "catalogue_entry": candidate.spec.workflow_id,
        "primitive_library_changed": False,
        "signed_history_modified": False,
        "capability_admitted": False,
        "execution_authorized": False,
        "empirical_attribution": "undetermined",
    }
