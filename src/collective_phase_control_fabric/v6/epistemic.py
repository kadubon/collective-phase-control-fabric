# SPDX-License-Identifier: Apache-2.0
"""Finite fixed-parameter support semantics over the existing primitive ledger.

Only declared observation symbols are controller inputs. Clock readings, action
availability, hidden outcome IDs and actual model IDs are deliberately excluded.
All compatible full ledger/entry pairs are retained, rather than marginal bounds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction as F
from typing import cast

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6 import growth_frontier as frontier_model
from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    Document,
    EpistemicContract,
    EpistemicHypothesis,
    EpistemicStep,
    GrowthAction,
    GrowthCapabilityFrontier,
    GrowthCheckpoint,
    GrowthComparison,
    GrowthContract,
    GrowthFrontierState,
)
from collective_phase_control_fabric.v6.registry import document_digest

type Support = tuple[EpistemicHypothesis, ...]


def canonical_support(values: list[EpistemicHypothesis]) -> Support:
    normalized = [h.model_copy(update={"state": g.normalize(h.state)}) for h in values]
    unique = {g.content_digest(h): h for h in normalized}
    return tuple(unique[key] for key in sorted(unique))


def support_digest(support: Support) -> str:
    return digest_bytes(canonical_bytes({"support": [h.model_dump(mode="json") for h in support]}))


@dataclass
class Domain:
    contract: GrowthContract
    objects: dict[str, Document]
    epistemic: EpistemicContract
    frontier: GrowthCapabilityFrontier | None = None
    observation_map: dict[str, str] | None = None
    excluded_actions: frozenset[str] = frozenset()
    excluded_interactions: frozenset[str] = frozenset()
    recipes: dict[str, GrowthAction] = field(init=False)
    kernel: dict[tuple[str, str, str], tuple[str, ...]] = field(init=False)
    peak_support: int = field(default=0, init=False)
    primitive_transitions: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        g.validate_contract(self.contract, self.objects)
        if self.frontier is not None:
            frontier_model.validate_frontier(self.contract, self.objects, self.frontier)
        e = self.epistemic.spec
        g.require(
            e.growth_contract_digest == document_digest(self.contract)
            and e.frontier_digest == (document_digest(self.frontier) if self.frontier else None),
            "epistemic_input_binding",
        )
        self.recipes = {
            cast(ActionDocument, self.objects[r.action_digest]).spec.action_id: r
            for r in self.contract.spec.action_catalogue
        }
        alphabet = set(e.observation_alphabet)
        g.require(len(alphabet) == len(e.observation_alphabet), "epistemic_alphabet_invalid")
        self.kernel = {}
        for row in e.kernel:
            key = (row.model_id, row.action_digest, row.successor_id)
            g.require(
                key not in self.kernel
                and set(row.observations) <= alphabet
                and len(row.observations) == len(set(row.observations)),
                "epistemic_kernel_invalid",
            )
            self.kernel[key] = tuple(sorted(row.observations))
        expected = {
            (theta, r.action_digest, effect.successor_id)
            for r in self.recipes.values()
            for effect in r.successors
            for theta in effect.applicable_model_ids
        }
        g.require(set(self.kernel) == expected, "epistemic_kernel_incomplete")
        if self.observation_map is None:
            self.observation_map = {s: s for s in sorted(alphabet)}
        g.require(
            isinstance(self.observation_map, dict)
            and set(self.observation_map) == alphabet
            and all(
                isinstance(v, str) and 0 < len(v) <= 128 for v in self.observation_map.values()
            ),
            "epistemic_channel_invalid",
        )
        g.require(self.excluded_actions <= set(self.recipes), "epistemic_action_unknown")
        events = e.cost_events
        g.require(len({x.event_id for x in events}) == len(events), "epistemic_cost_event_invalid")
        for event in events:
            g.require(
                F(event.duration) >= 0
                and set(event.charges)
                <= {"construction", "search", "checking", "transport", "maintenance", "application"}
                and all(
                    set(amounts) <= set(self.contract.spec.resource_units)
                    and all(F(v) >= 0 for v in amounts.values())
                    for amounts in event.charges.values()
                ),
                "epistemic_cost_event_invalid",
            )

    def digest(self) -> str:
        return digest_bytes(
            canonical_bytes(
                {
                    "ledger": g.input_digest(self.contract, self.objects, self.frontier),
                    "epistemic": document_digest(self.epistemic),
                    "observation_map": self.observation_map,
                    "excluded_actions": sorted(self.excluded_actions),
                    "excluded_interactions": sorted(self.excluded_interactions),
                    "semantics": "epistemic-reference-1",
                }
            )
        )

    def bounded(self, values: list[EpistemicHypothesis]) -> Support:
        result = canonical_support(values)
        g.require(bool(result), "epistemic_inconsistent_support")
        self.peak_support = max(self.peak_support, len(result))
        g.require(len(result) <= self.epistemic.spec.max_support, "epistemic_support_budget")
        g.require(
            len(canonical_bytes({"support": [h.model_dump(mode="json") for h in result]}))
            <= self.epistemic.spec.max_support_bytes,
            "epistemic_support_budget",
        )
        return result

    def initial(self) -> Support:
        state = g.initial_state(self.contract, self.frontier)
        return self.bounded(
            [
                self.pay(
                    EpistemicHypothesis(
                        model_id=theta, state=state.model_copy(update={"model_ids": [theta]})
                    )
                )
                for theta in sorted(state.model_ids)
            ]
        )

    def pay(self, h: EpistemicHypothesis) -> EpistemicHypothesis:
        """A fixed declared fee schedule; never refresh balances between epochs."""
        for event in sorted(self.epistemic.spec.cost_events, key=lambda x: x.event_id):
            if event.after_primitive_steps != h.primitive_steps:
                continue
            totals = {
                k: str(sum((F(v.get(k, "0")) for v in event.charges.values()), F(0)))
                for k in self.contract.spec.resource_units
            }
            # Reuse the reviewed planning-delay ledger, including crossed checkpoints
            # and queue/debt deadlines. Detailed fee categories remain in the sidecar.
            charged = self.contract.model_copy(
                update={
                    "spec": self.contract.spec.model_copy(
                        update={
                            "initial_state": h.state,
                            "planning_charge": totals,
                            "planning_duration": event.duration,
                            "planning_boundary": "shared-budget",
                        }
                    )
                }
            )
            state = g.initial_state(charged)
            g.require(F(state.elapsed) <= F(self.contract.spec.deadline), "epistemic_cost_deadline")
            h = h.model_copy(update={"state": state})
        return h

    def advance(
        self, support: Support, action_id: str, budget: g.Budget | None = None
    ) -> dict[str, Support]:
        g.require(bool(support), "epistemic_inconsistent_support")
        g.require(action_id in self.recipes, "epistemic_action_unknown")
        recipe = self.recipes[action_id]
        g.require(
            action_id not in self.excluded_actions
            and not self.excluded_interactions.intersection(recipe.interactions),
            "epistemic_action_excluded",
        )
        groups: dict[str, list[EpistemicHypothesis]] = {}
        g.require(self.observation_map is not None, "epistemic_channel_invalid")
        observation_map = cast(dict[str, str], self.observation_map)
        for h in support:
            # Theta stays attached to the full state through every primitive outcome.
            g.require(h.state.model_ids == [h.model_id], "epistemic_model_switch")
            g.applicable(self.contract, h.state, recipe, self.objects, self.frontier)
            effects = g.successors(h.state, recipe)
            g.require(bool(effects), "epistemic_kernel_incomplete")
            for effect in effects:
                if budget is not None:
                    g.require(
                        budget.take("expansions", budget.limits.max_expansions),
                        "epistemic_search_budget",
                    )
                after = g.transition(
                    self.contract, h.state, recipe, effect, self.objects, self.frontier
                )
                self.primitive_transitions += 1
                g.require(
                    h.primitive_steps < self.contract.spec.max_decisions,
                    "epistemic_primitive_budget",
                )
                next_h = self.pay(
                    EpistemicHypothesis(
                        model_id=h.model_id,
                        state=after,
                        entry=h.entry,
                        primitive_steps=h.primitive_steps + 1,
                    )
                )
                for raw in self.kernel[(h.model_id, recipe.action_digest, effect.successor_id)]:
                    groups.setdefault(observation_map[raw], []).append(next_h)
        return {symbol: self.bounded(values) for symbol, values in sorted(groups.items())}

    def mark_entry(self, support: Support, comparisons: list[GrowthComparison]) -> Support:
        predicates = g.Search(
            self.contract,
            self.objects,
            g.Budget(self.contract.spec.search_limits),
            comparisons=comparisons,
            frontier=self.frontier,
        )
        g.require(
            bool(support)
            and all(h.entry is None and predicates.entry_allowed(h.state) for h in support),
            "epistemic_hidden_entry",
        )
        return self.bounded(
            [
                h.model_copy(
                    update={
                        "entry": GrowthCheckpoint(
                            time=h.state.elapsed, capacities=h.state.capacities
                        )
                    }
                )
                for h in support
            ]
        )

    def terminal(self, support: Support, endpoint: F | None = None) -> bool:
        if not support:
            return False
        predicates = g.Search(
            self.contract,
            self.objects,
            g.Budget(self.contract.spec.search_limits),
            endpoint=endpoint,
            frontier=self.frontier,
        )
        return all(predicates.terminal(h.state, h.entry) for h in support)

    def replay(self, history: list[EpistemicStep], comparisons: list[GrowthComparison]) -> Support:
        g.require(len(history) <= self.epistemic.spec.max_history, "epistemic_history_budget")
        support = self.initial()
        for index, step in enumerate(history):
            g.require(
                step.comparison_history_length <= index
                and (step.entry or step.comparison_history_length == 0),
                "epistemic_entry_epoch_invalid",
            )
            if step.entry:
                basis = comparisons
                if step.comparison_history_length:
                    from collective_phase_control_fabric.v6.epistemic_checking import (
                        reference_comparisons,
                    )

                    basis = reference_comparisons(self, history[: step.comparison_history_length])
                support = self.mark_entry(support, basis)
            branches = self.advance(support, step.action_id)
            g.require(step.observation in branches, "epistemic_observation_mismatch")
            support = branches[step.observation]
        return support

    def controller_view(self, support: Support) -> dict[str, object]:
        """Knowledge summary; never select or disclose a privileged actual simulator state."""
        g.require(bool(support), "epistemic_inconsistent_support")
        enabled = set(self.recipes)
        for h in support:
            if isinstance(h.state, GrowthFrontierState):
                enabled.intersection_update(h.state.enabled_action_ids)
        return {
            "mode": "fixed-model-adversarial-outcomes",
            "visible_channels": "declared-symbols-only",
            "support_digest": support_digest(support),
            "compatible_pairs": len(support),
            "compatible_models": sorted({h.model_id for h in support}),
            "universally_model_enabled": sorted(enabled - self.excluded_actions),
            "capacity_bounds": {
                key: {
                    "lower": str(min(F(h.state.capacities[key].lower) for h in support)),
                    "upper": str(max(F(h.state.capacities[key].upper) for h in support)),
                }
                for key in sorted(self.contract.spec.domains)
            },
            "resource_bounds": {
                key: {
                    "lower": str(min(F(h.state.resources[key]) for h in support)),
                    "upper": str(max(F(h.state.resources[key]) for h in support)),
                }
                for key in sorted(self.contract.spec.resource_units)
            },
            "spent_bounds": {
                key: {
                    "lower": str(min(F(h.state.spent.get(key, "0")) for h in support)),
                    "upper": str(max(F(h.state.spent.get(key, "0")) for h in support)),
                }
                for key in sorted(self.contract.spec.resource_units)
            },
            "elapsed_bounds": {
                "lower": str(min(F(h.state.elapsed) for h in support)),
                "upper": str(max(F(h.state.elapsed) for h in support)),
            },
            "repair_debt_bounds": {
                key: {
                    bound: str(
                        aggregate(
                            sum(
                                (F(w.remaining) for w in h.state.obligations if w.stage == key),
                                F(0),
                            )
                            for h in support
                        )
                    )
                    for bound, aggregate in (("lower", min), ("upper", max))
                }
                for key in sorted(self.contract.spec.domains)
            },
            "activation_depth_bounds": {
                bound: aggregate(
                    h.state.activation_depth if isinstance(h.state, GrowthFrontierState) else 0
                    for h in support
                )
                for bound, aggregate in (("lower", min), ("upper", max))
            },
            "bounds_are_not_a_substitute_for_correlated_support": True,
            "execution_authorized": False,
            "empirical_attribution": "undetermined",
        }
