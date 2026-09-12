# SPDX-License-Identifier: Apache-2.0
"""Bounded typed composition and independent unfolding over finite model domains.

The grammar is finite observation trees of existing primitives. A reusable name
does not add elementary reachability or compress the physical primitive horizon.
Formation and application allowances are explicit, unvalidated model premises.
"""

from __future__ import annotations

from fractions import Fraction as F
from typing import cast

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.epistemic import Domain, Support, support_digest
from collective_phase_control_fabric.v6.epistemic_checking import reference_comparisons
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    CapabilityDocument,
    EpistemicCostEvent,
    EpistemicPolicyNode,
    ExecutionPolicy,
    GrowthPolicyNode,
    Lifecycle,
    UnitRegistryDocument,
    WorkflowCandidate,
    WorkflowCertificate,
    WorkflowCertificateSpec,
    WorkflowPrimitiveBinding,
    WorkflowRequest,
)
from collective_phase_control_fabric.v6.registry import document_digest


def formation_domain(domain: Domain, request: WorkflowRequest) -> Domain:
    r = request.spec
    g.require(r.input_digest == domain.digest(), "composition_input_binding")
    g.require(
        set(r.formation_charges) == {"construction", "search", "checking", "transport"}
        and set(r.per_use_charges) == {"maintenance", "application"},
        "composition_costs_missing",
    )
    g.require(
        set(r.target_capacities) <= set(domain.contract.spec.domains)
        and set(r.maximum_spent) == set(domain.contract.spec.resource_units)
        and all(F(x) >= 0 for x in (*r.target_capacities.values(), *r.maximum_spent.values()))
        and F(r.formation_duration) >= 0
        and F(r.per_use_duration) >= 0,
        "composition_domain_invalid",
    )
    event = EpistemicCostEvent(
        event_id="workflow-" + document_digest(request).removeprefix("sha256:"),
        source_digest=document_digest(request),
        after_primitive_steps=len(r.history),
        charges={**r.formation_charges, **r.per_use_charges},
        duration=str(F(r.formation_duration) + F(r.per_use_duration)),
        reserved_synthesis_expansions=domain.contract.spec.search_limits.max_expansions,
    )
    g.require(
        sum(x.reserved_synthesis_expansions for x in domain.epistemic.spec.cost_events)
        + event.reserved_synthesis_expansions
        <= 1_000_000,
        "catalogue_synthesis_quota",
    )
    e = domain.epistemic.model_copy(
        update={
            "spec": domain.epistemic.spec.model_copy(
                update={
                    "cost_events": [*domain.epistemic.spec.cost_events, event],
                }
            )
        }
    )
    # Reparse the new closed document instead of trusting unchecked model_copy bounds.
    e = type(e).model_validate(e.model_dump(mode="json"))
    return Domain(
        domain.contract,
        domain.objects,
        e,
        domain.frontier,
        domain.observation_map,
        domain.excluded_actions,
        domain.excluded_interactions,
    )


def primitive_library(
    domain: Domain, request: WorkflowRequest
) -> dict[str, WorkflowPrimitiveBinding]:
    library: dict[str, WorkflowPrimitiveBinding] = {}
    for binding in request.spec.library:
        action = domain.objects.get(binding.action_digest)
        cap = domain.objects.get(binding.capability_digest)
        g.require(
            isinstance(action, ActionDocument)
            and isinstance(cap, CapabilityDocument)
            and isinstance(domain.objects.get(binding.execution_policy_digest), ExecutionPolicy),
            "composition_primitive_missing",
        )
        action, cap = cast(ActionDocument, action), cast(CapabilityDocument, cap)
        g.require(
            action.spec.action_id in domain.recipes
            and action.spec.action_id not in library
            and domain.recipes[action.spec.action_id].action_digest == binding.action_digest
            and action.spec.capability_digest == binding.capability_digest
            and cap.spec.output_schema_digest == binding.output_schema_digest
            and cap.spec.execution_policy_digest == binding.execution_policy_digest,
            "composition_primitive_binding",
        )
        library[action.spec.action_id] = binding
    return library


def ir_members(node: EpistemicPolicyNode) -> tuple[set[str], int]:
    stack: list[tuple[EpistemicPolicyNode, int, frozenset[int]]] = [(node, 0, frozenset())]
    members: set[str] = set()
    longest, visited = 0, 0
    while stack:
        current, depth, ancestors = stack.pop()
        visited += 1
        g.require(
            id(current) not in ancestors and depth <= 16 and visited <= 4096,
            "composition_grammar_bound",
        )
        if current.action_id is not None:
            members.add(current.action_id)
            longest = max(longest, depth + 1)
        stack.extend(
            (child, depth + 1, ancestors | {id(current)}) for child in current.branches.values()
        )
    return members, longest


def constituent_digests(library: dict[str, WorkflowPrimitiveBinding], ids: set[str]) -> list[str]:
    g.require(ids <= set(library), "composition_primitive_missing")
    return sorted(
        {
            digest
            for name in ids
            for digest in (
                library[name].action_digest,
                library[name].capability_digest,
                library[name].input_schema_digest,
                library[name].output_schema_digest,
                library[name].execution_policy_digest,
            )
        }
    )


def expiry(domain: Domain, ids: set[str]) -> str:
    units = cast(UnitRegistryDocument, domain.objects[domain.contract.spec.unit_registry_digest])
    scale = F(units.spec.units[units.spec.time_unit].scale)
    bounds = [F(domain.contract.spec.deadline), *(F(domain.recipes[name].expires) for name in ids)]
    lives: list[Lifecycle] = []
    for name in ids:
        action = cast(ActionDocument, domain.objects[domain.recipes[name].action_digest])
        cap = cast(CapabilityDocument, domain.objects[action.spec.capability_digest])
        for digest in (
            domain.recipes[name].action_digest,
            action.spec.capability_digest,
            cap.spec.execution_policy_digest,
            *action.spec.required_object_digests,
        ):
            life = getattr(getattr(domain.objects.get(digest), "spec", None), "lifecycle", None)
            if isinstance(life, Lifecycle):
                lives.append(life)
        if domain.frontier is not None:
            lives.extend(b.lifecycle for b in domain.frontier.spec.bindings if b.action_id == name)
    for life in lives:
        for at in (life.valid_until, life.withdrawn_at):
            if at is not None:
                delta = at - domain.contract.spec.model_time_origin
                bounds.append(
                    (F(delta.days * 86400 + delta.seconds) + F(delta.microseconds, 1_000_000))
                    / scale
                )
    return str(min(bounds))


def check_composition(
    domain: Domain, request: WorkflowRequest, candidate: WorkflowCandidate
) -> WorkflowCertificate:
    d = formation_domain(domain, request)
    r, c = request.spec, candidate.spec
    g.require(
        c.request_digest == document_digest(request) and c.checked_domain_digest == d.digest(),
        "composition_candidate_binding",
    )
    library = primitive_library(d, request)
    ids, length = ir_members(c.ir)
    g.require(
        bool(ids)
        and length == c.expanded_primitive_steps
        and length <= r.max_primitive_steps
        and length + len(r.history) <= d.contract.spec.max_decisions,
        "composition_primitive_budget",
    )
    g.require(
        c.constituent_digests == constituent_digests(library, ids) and c.expires == expiry(d, ids),
        "composition_constituent_tampered",
    )
    g.require(
        c.workflow_id == "workflow-" + g.content_digest(c.ir).removeprefix("sha256:"),
        "composition_ir_identity",
    )
    comparisons = reference_comparisons(d, r.history)
    start = d.replay(r.history, reference_comparisons(d) if r.history else comparisons)
    budget = g.Budget(d.contract.spec.search_limits)
    nodes = 0
    leaves: list[Support] = []

    def unfold(node: EpistemicPolicyNode, support: Support, record_type: str, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        g.require(
            nodes <= budget.limits.max_witness_nodes and depth <= r.max_primitive_steps,
            "composition_check_budget",
        )
        g.require(node.support_digest == support_digest(support), "composition_support_tampered")
        if node.entry:
            support = d.mark_entry(support, comparisons)
        if node.action_id is None:
            g.require(
                not node.branches
                and not node.entry
                and record_type == r.output_schema_digest
                and d.terminal(support),
                "composition_postcondition",
            )
            g.require(
                all(
                    all(
                        F(h.state.capacities[k].lower) >= F(v)
                        for k, v in r.target_capacities.items()
                    )
                    and all(
                        F(h.state.spent.get(k, "0")) <= F(v) for k, v in r.maximum_spent.items()
                    )
                    for h in support
                ),
                "composition_postcondition",
            )
            leaves.append(support)
            return
        binding = library.get(node.action_id)
        if binding is None or binding.input_schema_digest != record_type:
            raise g.GrowthError("composition_interface_type")
        g.require(not d.terminal(support), "composition_endpoint_overrun")
        outcomes = d.advance(support, node.action_id, budget)
        g.require(set(outcomes) == set(node.branches), "composition_observation_branch_missing")
        for symbol, after in outcomes.items():
            unfold(node.branches[symbol], after, binding.output_schema_digest, depth + 1)

    unfold(c.ir, start, r.input_schema_digest, 0)
    terminal = [h for group in leaves for h in group]
    objective = g.objective(
        d.contract,
        g.Candidate(
            GrowthPolicyNode(state_digest=support_digest(start)),
            [h.state for h in terminal],
            [F(h.entry.time) for h in terminal if h.entry is not None],
        ),
    )
    return WorkflowCertificate(
        metadata=request.metadata,
        spec=WorkflowCertificateSpec(
            request_digest=document_digest(request),
            candidate_digest=document_digest(candidate),
            input_digest=d.digest(),
            initial_support_digest=support_digest(start),
            terminal_support_digests=sorted(support_digest(s) for s in leaves),
            objective=objective,
            primitive_steps=length,
        ),
    )
