# SPDX-License-Identifier: Apache-2.0
"""Tiny exhaustive observation-tree oracle, without production policy selection."""

from contextlib import suppress
from fractions import Fraction as F
from itertools import product

import pytest

from collective_phase_control_fabric.v6.epistemic import Domain, Support, canonical_support
from collective_phase_control_fabric.v6.epistemic_checking import reference_comparisons
from collective_phase_control_fabric.v6.epistemic_examples import epistemic_example
from collective_phase_control_fabric.v6.epistemic_planning import plan_epistemic
from collective_phase_control_fabric.v6.growth import GrowthError


def oracle(domain: Domain, *, rectangular: bool = False) -> tuple[F, ...] | None:
    comparisons = reference_comparisons(domain)

    def trees(support: Support, remaining: int) -> list[Support]:
        if domain.terminal(support):
            return [support]
        if remaining == 0:
            return []
        starts = [support]
        with suppress(GrowthError):
            starts.append(domain.mark_entry(support, comparisons))
        answers = []
        for start in starts:
            if rectangular:
                # Same physical kernels and symbols, but nature can change theta
                # before each action. It cannot reveal that choice to the policy.
                start = canonical_support(
                    [
                        h.model_copy(
                            update={
                                "model_id": theta,
                                "state": h.state.model_copy(update={"model_ids": [theta]}),
                            }
                        )
                        for h in start
                        for theta in domain.contract.spec.initial_state.model_ids
                    ]
                )
            for action in sorted(domain.recipes):
                try:
                    children = domain.advance(start, action)
                except GrowthError:
                    continue
                options = [trees(child, remaining - 1) for child in children.values()]
                for selection in product(*options):
                    answers.append(tuple(h for branch in selection for h in branch))
        return answers

    def rank(leaves: Support) -> tuple[F, ...]:
        c = domain.contract.spec
        return (
            max(F(h.entry.time) for h in leaves if h.entry),
            -min(
                F(h.state.capacities[k].lower) / F(c.domains[k].target)
                for h in leaves
                for k in ("task", "research")
            ),
            *(max(F(h.state.spent.get(k, "0")) for h in leaves) for k in c.cost_order),
            *(
                max(
                    sum((F(w.remaining) for w in h.state.obligations if w.stage == k), F(0))
                    for h in leaves
                )
                for k in sorted(c.domains)
            ),
            max(F(h.state.elapsed) for h in leaves),
        )

    options = trees(domain.initial(), domain.contract.spec.max_decisions)
    return min(map(rank, options)) if options else None


@pytest.mark.parametrize("scenario", ["epistemic-probe", "epistemic-ambiguous"])
def test_full_policy_objective_agrees_with_tiny_exhaustive_oracle(scenario: str) -> None:
    d = epistemic_example(scenario)
    p = plan_epistemic(d)
    assert p.spec.search.complete
    expected = oracle(d)
    obj = p.spec.objective
    if expected is None:
        assert obj is None
    else:
        assert obj is not None
        assert expected == (
            F(obj.worst_entry_time),
            -F(obj.terminal_min_attainment),
            *(F(obj.worst_cost[k]) for k in d.contract.spec.cost_order),
            *(F(obj.worst_debt[k]) for k in sorted(d.contract.spec.domains)),
            F(obj.worst_duration),
        )


def test_switching_adversary_is_strictly_more_conservative_with_same_signals() -> None:
    d = epistemic_example()
    fixed, switching = oracle(d), oracle(d, rectangular=True)
    assert fixed is not None and switching is not None
    assert fixed[0] == 2 and switching[0] == 3
