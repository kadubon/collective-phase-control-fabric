# SPDX-License-Identifier: Apache-2.0
"""Exhaustive observation-policy enumeration; no hidden-state Bellman shortcut.

Memo entries retain every feasible policy and its correlated terminal ledgers.
The key includes full support, entry checkpoints and consumed primitive depth.
Thus the path-dependent objective is aggregated only after complete OR policies
and all their observation branches have been constructed.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction as F
from itertools import product
from typing import Any, cast

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.epistemic import Domain, Support, support_digest
from collective_phase_control_fabric.v6.models import (
    EpistemicPlan,
    EpistemicPlanSpec,
    EpistemicPolicyNode,
    EpistemicStep,
    GrowthComparison,
    GrowthObjective,
    GrowthPolicyNode,
)
from collective_phase_control_fabric.v6.registry import document_digest

LIMIT_CODES = {"epistemic_search_budget", "epistemic_support_budget", "epistemic_history_budget"}


@dataclass
class Policy:
    node: EpistemicPolicyNode
    leaves: Support
    nodes: int = 1


def policy_objective(domain: Domain, policy: Policy) -> GrowthObjective:
    g.require(all(h.entry is not None for h in policy.leaves), "epistemic_continuation_missing")
    return g.objective(
        domain.contract,
        g.Candidate(
            GrowthPolicyNode(state_digest=policy.node.support_digest),
            [h.state for h in policy.leaves],
            [F(h.entry.time) for h in policy.leaves if h.entry is not None],
        ),
    )


def policy_key(domain: Domain, policy: Policy) -> tuple[Any, ...]:
    obj = policy_objective(domain, policy)
    return (
        F(obj.worst_entry_time),
        -F(obj.terminal_min_attainment),
        *(F(obj.worst_cost[k]) for k in domain.contract.spec.cost_order),
        *(F(obj.worst_debt[k]) for k in sorted(domain.contract.spec.domains)),
        F(obj.worst_duration),
        policy.node.action_id or "",
        g.content_digest(policy.node),
    )


class PolicySearch:
    def __init__(
        self,
        domain: Domain,
        comparisons: list[GrowthComparison] | None = None,
        endpoint: F | None = None,
    ) -> None:
        self.domain = domain
        self.comparisons = comparisons if comparisons is not None else []
        self.endpoint = endpoint
        self.memo: dict[tuple[str, int], list[Policy]] = {}
        self.stored_nodes = 0
        self.budget = g.Budget(self.domain.contract.spec.search_limits)

    def enumerate(self, support: Support, depth: int = 0) -> list[Policy]:
        key = support_digest(support), depth
        if key in self.memo:
            return self.memo[key]
        if not self.budget.take("states", self.budget.limits.max_states):
            return []
        self.budget.maximum_depth = max(self.budget.maximum_depth, depth)
        if self.domain.terminal(support, self.endpoint):
            return [Policy(EpistemicPolicyNode(support_digest=key[0]), support)]
        if depth >= self.domain.contract.spec.max_decisions:
            return []
        if depth >= min(self.budget.limits.max_depth, self.domain.epistemic.spec.max_history):
            self.budget.complete = False
            return []
        if any(
            F(h.state.elapsed)
            >= (
                self.endpoint
                if self.endpoint is not None
                else F(h.entry.time) + F(self.domain.contract.spec.continuation_horizon)
                if h.entry
                else F(self.domain.contract.spec.deadline)
            )
            for h in support
        ):
            return []
        selections = [(False, support)]
        if self.endpoint is None and all(h.entry is None for h in support):
            try:
                selections.append((True, self.domain.mark_entry(support, self.comparisons)))
            except g.GrowthError as error:
                if error.code != "epistemic_hidden_entry":
                    raise
        found: list[Policy] = []
        for entry, selected in selections:
            for action in sorted(self.domain.recipes):
                try:
                    branches = self.domain.advance(selected, action, self.budget)
                except g.GrowthError as error:
                    if error.code in LIMIT_CODES:
                        self.budget.complete = False
                        return found
                    continue
                choices = [self.enumerate(child, depth + 1) for child in branches.values()]
                if any(not items for items in choices):
                    continue
                for children in product(*choices):
                    count = 1 + sum(child.nodes for child in children)
                    if (
                        self.stored_nodes + count > self.budget.limits.max_witness_nodes
                        or not self.budget.take("policies", self.budget.limits.max_policies)
                    ):
                        self.budget.complete = False
                        return found
                    self.stored_nodes += count
                    found.append(
                        Policy(
                            EpistemicPolicyNode(
                                support_digest=key[0],
                                action_id=action,
                                entry=entry,
                                branches={
                                    symbol: child.node
                                    for symbol, child in zip(branches, children, strict=True)
                                },
                            ),
                            tuple(h for child in children for h in child.leaves),
                            count,
                        )
                    )
        if self.budget.complete:
            self.memo[key] = found
        return found


def compare_epistemic(
    domain: Domain, history: list[EpistemicStep] | None = None
) -> list[GrowthComparison]:
    """Match initial information/resources and reoptimize every restricted class."""
    reports: list[GrowthComparison] = []
    resumed: Support | None = None
    for comparator in sorted(domain.contract.spec.comparators, key=lambda c: c.comparator_id):
        restricted = Domain(
            domain.contract,
            domain.objects,
            domain.epistemic,
            domain.frontier,
            domain.observation_map,
            domain.excluded_actions,
            domain.excluded_interactions | frozenset(comparator.excluded_interactions),
        )
        for endpoint in sorted({F(w.end) for w in domain.contract.spec.windows}):
            search = PolicySearch(restricted, endpoint=endpoint)
            inconsistent = False
            try:
                if history and resumed is None:
                    resumed = domain.replay(history, compare_epistemic(domain))
                start = resumed if resumed is not None else restricted.initial()
                policies = search.enumerate(start, len(history or []))
            except g.GrowthError as error:
                if error.code not in LIMIT_CODES | {"epistemic_inconsistent_support"}:
                    raise
                inconsistent = error.code == "epistemic_inconsistent_support"
                search.budget.complete = False
                policies = []
            lower = max(
                (min(g.attainment(domain.contract, h.state) for h in p.leaves) for p in policies),
                default=None,
            )
            upper = (
                max(
                    (
                        min(g.attainment(domain.contract, h.state, "upper") for h in p.leaves)
                        for p in policies
                    ),
                    default=None,
                )
                if search.budget.complete
                else None
            )
            reports.append(
                GrowthComparison(
                    comparator_id=comparator.comparator_id,
                    endpoint=str(endpoint),
                    status="inconsistent"
                    if inconsistent
                    else "supported"
                    if upper is not None
                    else "undetermined",
                    lower_bound=str(lower) if lower is not None else None,
                    upper_bound=str(upper) if upper is not None else None,
                    search=search.budget.report(),
                    matched_basis_digest=domain.digest(),
                )
            )
    return reports


def plan_epistemic(domain: Domain, history: list[EpistemicStep] | None = None) -> EpistemicPlan:
    # Invocation-local counters and freshly rebuilt input-derived indices.
    domain = Domain(
        domain.contract,
        domain.objects,
        domain.epistemic,
        domain.frontier,
        domain.observation_map,
        domain.excluded_actions,
        domain.excluded_interactions,
    )
    history = list(history or [])
    comparisons = compare_epistemic(domain, history)
    search = PolicySearch(domain, comparisons)
    code = "epistemic_no_guaranteed_entry"
    try:
        support = domain.replay(history, compare_epistemic(domain) if history else comparisons)
        choices = search.enumerate(support, len(history))
    except g.GrowthError as error:
        if error.code not in LIMIT_CODES | {
            "epistemic_inconsistent_support",
            "epistemic_observation_mismatch",
        }:
            raise
        code = error.code
        search.budget.complete = False
        choices = []
    best = min(choices, key=lambda p: policy_key(domain, p)) if choices else None
    search.budget.complete = search.budget.complete and all(c.search.complete for c in comparisons)
    if not search.budget.complete and code == "epistemic_no_guaranteed_entry":
        code = "epistemic_search_unknown"
    if best is not None:
        code = "epistemic_policy_found" if search.budget.complete else "epistemic_incumbent"
    return EpistemicPlan(
        metadata=domain.epistemic.metadata,
        spec=EpistemicPlanSpec(
            input_digest=domain.digest(),
            epistemic_contract_digest=document_digest(domain.epistemic),
            history=history,
            observation_map=cast(dict[str, str], domain.observation_map),
            excluded_action_ids=sorted(domain.excluded_actions),
            excluded_interactions=sorted(domain.excluded_interactions),
            code=code,
            policy=best.node if best else None,
            policy_digest=g.content_digest(best.node) if best else None,
            objective=policy_objective(domain, best) if best else None,
            search=search.budget.report(),
            comparisons=comparisons,
            peak_support=min(domain.peak_support, 512),
            primitive_transitions=domain.primitive_transitions,
        ),
    )
