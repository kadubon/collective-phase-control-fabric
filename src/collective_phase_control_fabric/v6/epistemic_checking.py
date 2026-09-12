# SPDX-License-Identifier: Apache-2.0
"""Independent witness traversal and scalar comparator reference induction.

Does not import or invoke policy enumeration. Feasibility checking never certifies
the submitted search counters or global optimality. Comparator bounds are freshly
recomputed over common actions and observations at their fixed endpoints.
"""

from __future__ import annotations

from fractions import Fraction as F

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.epistemic import Domain, Support, support_digest
from collective_phase_control_fabric.v6.models import (
    EpistemicPlan,
    EpistemicPolicyNode,
    EpistemicStep,
    GrowthComparison,
    GrowthObjective,
    GrowthPolicyNode,
)
from collective_phase_control_fabric.v6.registry import document_digest


def reference_comparisons(
    domain: Domain, history: list[EpistemicStep] | None = None
) -> list[GrowthComparison]:
    results: list[GrowthComparison] = []
    resumed = domain.replay(history, reference_comparisons(domain)) if history else None
    for spec in sorted(domain.contract.spec.comparators, key=lambda x: x.comparator_id):
        d = Domain(
            domain.contract,
            domain.objects,
            domain.epistemic,
            domain.frontier,
            domain.observation_map,
            domain.excluded_actions,
            domain.excluded_interactions | frozenset(spec.excluded_interactions),
        )
        for endpoint in sorted({F(w.end) for w in d.contract.spec.windows}):
            budget = g.Budget(d.contract.spec.search_limits)

            def value(
                support: Support,
                depth: int,
                d: Domain = d,
                endpoint: F = endpoint,
                budget: g.Budget = budget,
            ) -> tuple[F, F] | None:
                g.require(budget.take("states", budget.limits.max_states), "epistemic_check_budget")
                budget.maximum_depth = max(budget.maximum_depth, depth)
                if all(F(h.state.elapsed) == endpoint for h in support):
                    return (
                        min(g.attainment(d.contract, h.state) for h in support),
                        min(g.attainment(d.contract, h.state, "upper") for h in support),
                    )
                if depth >= d.contract.spec.max_decisions or any(
                    F(h.state.elapsed) >= endpoint for h in support
                ):
                    return None
                g.require(
                    depth < min(budget.limits.max_depth, d.epistemic.spec.max_history),
                    "epistemic_check_budget",
                )
                options: list[tuple[F, F]] = []
                for action in sorted(d.recipes):
                    try:
                        branches = d.advance(support, action, budget)
                    except g.GrowthError as error:
                        if error.code in {"epistemic_support_budget", "epistemic_search_budget"}:
                            raise
                        continue
                    children = [value(child, depth + 1) for child in branches.values()]
                    if all(child is not None for child in children):
                        valid = [child for child in children if child is not None]
                        options.append((min(x[0] for x in valid), min(x[1] for x in valid)))
                return (max(x[0] for x in options), max(x[1] for x in options)) if options else None

            start = resumed if resumed is not None else d.initial()
            bounds = value(start, len(history or []))
            results.append(
                GrowthComparison(
                    comparator_id=spec.comparator_id,
                    endpoint=str(endpoint),
                    status="supported" if bounds else "undetermined",
                    lower_bound=str(bounds[0]) if bounds else None,
                    upper_bound=str(bounds[1]) if bounds else None,
                    search=budget.report(),
                    matched_basis_digest=domain.digest(),
                )
            )
    return results


def check_epistemic_plan(domain: Domain, plan: EpistemicPlan) -> dict[str, object]:
    p = plan.spec
    g.require(
        p.input_digest == domain.digest()
        and p.epistemic_contract_digest == document_digest(domain.epistemic)
        and p.observation_map == domain.observation_map
        and p.excluded_action_ids == sorted(domain.excluded_actions)
        and p.excluded_interactions == sorted(domain.excluded_interactions),
        "epistemic_plan_binding",
    )
    if p.policy is None or p.objective is None:
        raise g.GrowthError("epistemic_policy_missing")
    g.require(p.policy_digest == g.content_digest(p.policy), "epistemic_policy_digest")
    comparisons = reference_comparisons(domain, p.history)
    support = domain.replay(p.history, reference_comparisons(domain) if p.history else comparisons)
    nodes = 0
    checker_budget = g.Budget(domain.contract.spec.search_limits)

    def walk(node: EpistemicPolicyNode, current: Support, depth: int) -> list[Support]:
        nonlocal nodes
        nodes += 1
        g.require(
            nodes <= checker_budget.limits.max_witness_nodes
            and depth <= domain.contract.spec.max_decisions
            and depth <= domain.epistemic.spec.max_history,
            "epistemic_check_budget",
        )
        g.require(node.support_digest == support_digest(current), "epistemic_support_tampered")
        if node.entry:
            current = domain.mark_entry(current, comparisons)
        if node.action_id is None:
            g.require(
                not node.branches and not node.entry and domain.terminal(current),
                "epistemic_continuation_missing",
            )
            return [current]
        g.require(not domain.terminal(current), "epistemic_endpoint_overrun")
        branches = domain.advance(current, node.action_id, checker_budget)
        g.require(set(branches) == set(node.branches), "epistemic_observation_branch_missing")
        leaves: list[Support] = []
        for symbol, after in branches.items():
            leaves.extend(walk(node.branches[symbol], after, depth + 1))
        return leaves

    leaves = [h for group in walk(p.policy, support, len(p.history)) for h in group]
    computed: GrowthObjective = g.objective(
        domain.contract,
        g.Candidate(
            GrowthPolicyNode(state_digest=support_digest(support)),
            [h.state for h in leaves],
            [F(h.entry.time) for h in leaves if h.entry is not None],
        ),
    )
    g.require(computed == p.objective, "epistemic_objective_tampered")
    return {
        "code": "epistemic_policy_checked",
        "input_digest": domain.digest(),
        "policy_digest": p.policy_digest,
        "policy_feasible": True,
        "global_optimality_checked": False,
        "objective": computed.model_dump(mode="json"),
        "witness_nodes": nodes,
        "execution_authorized": False,
        "empirical_attribution": "undetermined",
    }
