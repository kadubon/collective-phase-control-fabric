# SPDX-License-Identifier: Apache-2.0
"""Deterministically compile primitive observation trees; never execute code."""

from __future__ import annotations

from fractions import Fraction as F

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.composition import (
    check_composition,
    constituent_digests,
    expiry,
    formation_domain,
    ir_members,
    primitive_library,
)
from collective_phase_control_fabric.v6.epistemic import Domain
from collective_phase_control_fabric.v6.epistemic_planning import (
    LIMIT_CODES,
    PolicySearch,
    compare_epistemic,
    plan_epistemic,
    policy_key,
)
from collective_phase_control_fabric.v6.models import (
    GrowthObjective,
    WorkflowCandidate,
    WorkflowCandidateSpec,
    WorkflowCertificate,
    WorkflowRequest,
    WorkflowSynthesis,
    WorkflowSynthesisSpec,
)
from collective_phase_control_fabric.v6.registry import document_digest


def synthesize(domain: Domain, request: WorkflowRequest) -> WorkflowSynthesis:
    d = formation_domain(domain, request)
    library = primitive_library(d, request)
    comparisons = compare_epistemic(d, request.spec.history)
    search = PolicySearch(d, comparisons)
    search.budget.complete = all(item.search.complete for item in comparisons)
    candidates: list[WorkflowCandidate] = []
    certificates: list[WorkflowCertificate] = []
    try:
        start = d.replay(
            request.spec.history, compare_epistemic(d) if request.spec.history else comparisons
        )
        policies = search.enumerate(start, len(request.spec.history))
        for policy in sorted(policies, key=lambda p: policy_key(d, p)):
            ids, length = ir_members(policy.node)
            if not ids or not ids <= set(library) or length > request.spec.max_primitive_steps:
                continue
            fingerprint = g.content_digest(policy.node)
            # Enumeration branches on unique (entry, action, observed-child) tuples;
            # inductively every emitted primitive tree has a distinct identity.
            candidate = WorkflowCandidate(
                metadata=request.metadata,
                spec=WorkflowCandidateSpec(
                    request_digest=document_digest(request),
                    checked_domain_digest=d.digest(),
                    workflow_id="workflow-" + fingerprint.removeprefix("sha256:"),
                    ir=policy.node,
                    constituent_digests=constituent_digests(library, ids),
                    expanded_primitive_steps=length,
                    expires=expiry(d, ids),
                ),
            )
            try:
                certificate = check_composition(domain, request, candidate)
            except g.GrowthError as error:
                if "budget" in error.code:
                    search.budget.complete = False
                    break
                continue
            if len(candidates) == request.spec.max_candidates:
                search.budget.complete = False
                break
            candidates.append(candidate)
            certificates.append(certificate)
    except g.GrowthError as error:
        if error.code not in LIMIT_CODES:
            raise
        search.budget.complete = False
    # A pre-existing primitive policy is not charged for a composition it never forms.
    # These are different net-cost options, not a claim of pure computational benefit.
    primitive = plan_epistemic(domain, request.spec.history)
    preferred = None
    if primitive.spec.search.complete and search.budget.complete:

        def rank(obj: GrowthObjective) -> tuple[F, ...]:
            return (
                F(obj.worst_entry_time),
                -F(obj.terminal_min_attainment),
                *(F(obj.worst_cost[k]) for k in domain.contract.spec.cost_order),
                *(F(obj.worst_debt[k]) for k in sorted(domain.contract.spec.domains)),
                F(obj.worst_duration),
            )

        if primitive.spec.objective is not None:
            preferred = not certificates or rank(primitive.spec.objective) <= min(
                rank(c.spec.objective) for c in certificates
            )
        elif certificates:
            preferred = False
    return WorkflowSynthesis(
        metadata=request.metadata,
        spec=WorkflowSynthesisSpec(
            request_digest=document_digest(request),
            proposed_epistemic_contract=d.epistemic,
            code="composition_search_unknown"
            if not search.budget.complete
            else "composition_candidates_checked"
            if candidates
            else "composition_no_candidate",
            candidates=candidates,
            certificates=certificates,
            search=search.budget.report(),
            existing_primitive_alternative=primitive,
            reuse_without_formation_preferred=preferred,
        ),
    )
