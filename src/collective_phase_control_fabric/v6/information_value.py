# SPDX-License-Identifier: Apache-2.0
"""Distinct prior-free estimands, with all three policy classes reoptimized."""

from __future__ import annotations

from fractions import Fraction as F

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.epistemic import Domain
from collective_phase_control_fabric.v6.epistemic_planning import plan_epistemic
from collective_phase_control_fabric.v6.models import (
    EpistemicPlan,
    InformationDifference,
    InformationValue,
    InformationValueSpec,
)


def difference(full: EpistemicPlan, comparator: EpistemicPlan) -> InformationDifference:
    complete = all(
        p.spec.search.complete and all(c.search.complete for c in p.spec.comparisons)
        for p in (full, comparator)
    )
    if not complete:
        return InformationDifference(comparison_complete=False, entry_status="unknown")
    a, b = full.spec.objective, comparator.spec.objective
    if a is None or b is None:
        return InformationDifference(
            comparison_complete=True,
            entry_status="full-only"
            if a is not None
            else "comparator-only"
            if b is not None
            else "neither",
        )
    return InformationDifference(
        comparison_complete=True,
        entry_status="both",
        entry_time_delta=str(F(a.worst_entry_time) - F(b.worst_entry_time)),
        terminal_attainment_delta=str(F(a.terminal_min_attainment) - F(b.terminal_min_attainment)),
        cost_delta={k: str(F(a.worst_cost[k]) - F(b.worst_cost[k])) for k in a.worst_cost},
        debt_delta={k: str(F(a.worst_debt[k]) - F(b.worst_debt[k])) for k in a.worst_debt},
        duration_delta=str(F(a.worst_duration) - F(b.worst_duration)),
    )


def information_value(
    domain: Domain, masked_channel: dict[str, str], optional_sensing_actions: list[str]
) -> InformationValue:
    g.require(
        domain.observation_map == {s: s for s in domain.epistemic.spec.observation_alphabet},
        "information_refinement_basis",
    )
    g.require(
        bool(optional_sensing_actions)
        and len(set(optional_sensing_actions)) == len(optional_sensing_actions)
        and set(optional_sensing_actions) <= set(domain.recipes),
        "information_sensing_actions",
    )
    blind = Domain(
        domain.contract,
        domain.objects,
        domain.epistemic,
        domain.frontier,
        masked_channel,
        domain.excluded_actions,
        domain.excluded_interactions,
    )
    without = Domain(
        domain.contract,
        domain.objects,
        domain.epistemic,
        domain.frontier,
        domain.observation_map,
        domain.excluded_actions | frozenset(optional_sensing_actions),
        domain.excluded_interactions,
    )
    full, masked, absent = (plan_epistemic(d) for d in (domain, blind, without))
    return InformationValue(
        metadata=domain.epistemic.metadata,
        spec=InformationValueSpec(
            full=full,
            information_blind=masked,
            without_sensing=absent,
            masked_channel=masked_channel,
            optional_sensing_actions=sorted(optional_sensing_actions),
            information_use=difference(full, masked),
            net_sensing=difference(full, absent),
        ),
    )
