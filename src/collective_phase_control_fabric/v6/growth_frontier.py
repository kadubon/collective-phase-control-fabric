# SPDX-License-Identifier: Apache-2.0
"""Finite model enablement; no capability admission or execution authority."""

from __future__ import annotations

from datetime import datetime
from fractions import Fraction as F
from typing import cast

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    CapabilityDocument,
    Document,
    ExecutionPolicy,
    GrowthAction,
    GrowthActivation,
    GrowthActivationRule,
    GrowthActivationWitness,
    GrowthCapabilityFrontier,
    GrowthContract,
    GrowthFrontierDiagnostics,
    GrowthFrontierState,
    GrowthInterval,
    GrowthPolicyNode,
    GrowthState,
    GrowthSuccessor,
    Lifecycle,
    UnitRegistryDocument,
)
from collective_phase_control_fabric.v6.registry import document_digest


def base_state(state: GrowthState) -> GrowthState:
    """Project the old ledger without changing its historical serialized schema."""
    return GrowthState.model_validate(
        {k: v for k, v in state.model_dump(mode="json").items() if k in GrowthState.model_fields}
    )


def validate_frontier(
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier,
) -> None:
    f = frontier.spec
    g.require(f.contract_digest == document_digest(contract), "growth_frontier_contract_mismatch")
    actions = {
        cast(ActionDocument, objects[r.action_digest]).spec.action_id: r
        for r in contract.spec.action_catalogue
    }
    initial, latent = set(f.initial_enabled_action_ids), set(f.latent_action_ids)
    g.require(
        len(initial) == len(f.initial_enabled_action_ids)
        and len(latent) == len(f.latent_action_ids)
        and not initial & latent
        and initial | latent == set(actions),
        "growth_frontier_partition_invalid",
    )
    g.require(
        len({b.action_id for b in f.bindings}) == len(f.bindings)
        and {b.action_id for b in f.bindings} == set(actions),
        "growth_frontier_binding_missing",
    )
    g.require(
        f.maximum_activation_depth <= contract.spec.max_decisions, "growth_frontier_depth_overflow"
    )
    for binding in f.bindings:
        action = objects.get(binding.action_digest)
        cap = objects.get(binding.capability_digest)
        policy = objects.get(binding.execution_policy_digest)
        g.require(
            isinstance(action, ActionDocument)
            and isinstance(cap, CapabilityDocument)
            and isinstance(policy, ExecutionPolicy),
            "growth_frontier_object_missing",
        )
        action, cap, policy = (
            cast(ActionDocument, action),
            cast(CapabilityDocument, cap),
            cast(ExecutionPolicy, policy),
        )
        g.require(
            actions[binding.action_id].action_digest == binding.action_digest
            and action.spec.action_id == binding.action_id
            and action.spec.capability_digest == binding.capability_digest
            and cap.spec.output_schema_digest == binding.output_schema_digest
            and cap.spec.execution_policy_digest == binding.execution_policy_digest
            and cap.spec.image_digest in policy.spec.allowed_image_digests,
            "growth_frontier_binding_mismatch",
        )
    g.require(
        len({r.rule_id for r in f.activation_rules}) == len(f.activation_rules),
        "growth_frontier_rule_duplicate",
    )
    for rule in f.activation_rules:
        recipe = actions.get(rule.producer_action_id)
        g.require(
            recipe is not None
            and rule.producer_successor_id in {e.successor_id for e in recipe.successors},
            "growth_frontier_producer_mismatch",
        )
        g.require(
            set(rule.activated_action_ids) <= set(actions)
            and len(set(rule.activated_action_ids)) == len(rule.activated_action_ids),
            "growth_frontier_target_undeclared",
        )
        g.require(
            all(
                isinstance(objects.get(d), CapabilityDocument)
                for d in rule.required_capability_digests
            ),
            "growth_frontier_capability_missing",
        )
        g.require(
            set(rule.required_model_ids) <= set(contract.spec.model_catalogue)
            and set(rule.minimum_capacities) <= set(contract.spec.domains)
            and set(rule.minimum_resources) <= set(contract.spec.resource_units)
            and all(
                F(v) >= 0
                for v in (*rule.minimum_capacities.values(), *rule.minimum_resources.values())
            )
            and 0 <= F(rule.valid_from) < F(rule.expires) <= F(contract.spec.deadline),
            "growth_frontier_condition_invalid",
        )
    carried_ids = [x.action_id for x in f.initial_activation_lineage]
    g.require(
        len(set(carried_ids)) == len(carried_ids) and set(carried_ids) <= initial,
        "growth_frontier_lineage_invalid",
    )
    check_frontier_state(seed(contract.spec.initial_state, frontier), frontier)


def seed(state: GrowthState, frontier: GrowthCapabilityFrontier) -> GrowthFrontierState:
    return GrowthFrontierState(
        **base_state(state).model_dump(),
        frontier_digest=document_digest(frontier),
        enabled_action_ids=sorted(frontier.spec.initial_enabled_action_ids),
        activation_depth=max(
            (x.depth for x in frontier.spec.initial_activation_lineage), default=0
        ),
        activation_lineage=sorted(
            frontier.spec.initial_activation_lineage, key=lambda x: x.action_id
        ),
    )


def check_frontier_state(
    state: GrowthState, frontier: GrowthCapabilityFrontier
) -> GrowthFrontierState:
    g.require(isinstance(state, GrowthFrontierState), "growth_frontier_state_missing")
    s = cast(GrowthFrontierState, state)
    g.require(s.frontier_digest == document_digest(frontier), "growth_frontier_digest_mismatch")
    lineage = {x.action_id: x for x in s.activation_lineage}
    carried = {x.action_id: x for x in frontier.spec.initial_activation_lineage}
    initial = set(frontier.spec.initial_enabled_action_ids) - set(carried)
    rules = {x.rule_id: x for x in frontier.spec.activation_rules}
    g.require(
        len(lineage) == len(s.activation_lineage)
        and all(lineage.get(k) == v for k, v in carried.items())
        and not initial & set(lineage)
        and set(s.enabled_action_ids) == initial | set(lineage)
        and len(s.enabled_action_ids) == len(set(s.enabled_action_ids)),
        "growth_frontier_lineage_invalid",
    )
    for event in s.activation_lineage:
        rule = rules.get(event.rule_id)
        parent = lineage.get(event.producer_action_id)
        g.require(
            rule is not None
            and event.action_id in rule.activated_action_ids
            and event.producer_action_id == rule.producer_action_id
            and event.producer_successor_id == rule.producer_successor_id
            and (event.producer_action_id in initial or parent is not None)
            and event.depth == (parent.depth + 1 if parent else 1)
            and F(event.model_time) <= F(s.elapsed)
            and (parent is None or F(parent.model_time) < F(event.model_time)),
            "growth_frontier_lineage_invalid",
        )
    g.require(
        s.activation_depth == max((x.depth for x in lineage.values()), default=0)
        and s.activation_depth <= frontier.spec.maximum_activation_depth,
        "growth_frontier_depth_overflow",
    )
    return s


def _lifecycle(
    contract: GrowthContract,
    objects: dict[str, Document],
    lifecycle: Lifecycle,
    start: F,
    end: F,
) -> None:
    units = cast(UnitRegistryDocument, objects[contract.spec.unit_registry_digest])
    scale = F(units.spec.units[units.spec.time_unit].scale)

    def seconds(at: datetime) -> F:
        delta = at - contract.spec.model_time_origin
        return F(delta.days * 86400 + delta.seconds) + F(delta.microseconds, 1_000_000)

    g.require(
        start * scale >= seconds(lifecycle.valid_from)
        and end * scale <= seconds(lifecycle.valid_until)
        and (lifecycle.withdrawn_at is None or end * scale < seconds(lifecycle.withdrawn_at)),
        "growth_frontier_object_expired",
    )


def _binding_live(
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier,
    state: GrowthState,
    action_id: str,
    end: F,
) -> None:
    binding = next(b for b in frontier.spec.bindings if b.action_id == action_id)
    recipe = next(
        r for r in contract.spec.action_catalogue if r.action_digest == binding.action_digest
    )
    g.require(
        F(state.elapsed) < F(recipe.expires) and end <= F(recipe.expires),
        "growth_frontier_object_expired",
    )
    action = cast(ActionDocument, objects[binding.action_digest])
    required = {
        binding.action_digest,
        binding.capability_digest,
        binding.execution_policy_digest,
        *action.spec.required_object_digests,
    }
    g.require(required <= set(state.live_object_digests), "growth_frontier_object_unavailable")
    _lifecycle(contract, objects, binding.lifecycle, F(state.elapsed), end)
    for digest in required:
        lifecycle = getattr(getattr(objects.get(digest), "spec", None), "lifecycle", None)
        if isinstance(lifecycle, Lifecycle):
            _lifecycle(contract, objects, lifecycle, F(state.elapsed), end)


def _conditions(rule: GrowthActivationRule, state: GrowthState, end: F) -> bool:
    return (
        F(rule.valid_from) <= F(state.elapsed)
        and end <= F(rule.expires)
        and set(state.model_ids) <= set(rule.required_model_ids)
        and set(rule.required_capability_digests) <= set(state.live_object_digests)
        and all(k in state.evidence and F(state.evidence[k]) >= end for k in rule.required_evidence)
        and all(F(state.capacities[k].lower) >= F(v) for k, v in rule.minimum_capacities.items())
        and all(F(state.resources[k]) >= F(v) for k, v in rule.minimum_resources.items())
    )


def check_use(
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier,
    state: GrowthState,
    action_id: str,
    end: F,
) -> None:
    s = check_frontier_state(state, frontier)
    g.require(action_id in s.enabled_action_ids, "growth_frontier_action_latent")
    _binding_live(contract, objects, frontier, state, action_id, end)
    lineage = {x.action_id: x for x in s.activation_lineage}
    rules = {x.rule_id: x for x in frontier.spec.activation_rules}
    # Strictly decreasing depths guarantee termination. Historical activation never
    # launders an expired/withdrawn premise into valid future use.
    parent = lineage.get(action_id)
    while parent is not None:
        rule = rules[parent.rule_id]
        _binding_live(contract, objects, frontier, state, rule.producer_action_id, end)
        g.require(_conditions(rule, state, end), "growth_frontier_premise_unavailable")
        for digest in rule.required_capability_digests:
            g.require(
                isinstance(objects.get(digest), CapabilityDocument),
                "growth_frontier_capability_missing",
            )
        parent = lineage.get(parent.producer_action_id)


def activate(
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier,
    before: GrowthState,
    after: GrowthState,
    recipe: GrowthAction,
    effect: GrowthSuccessor,
) -> GrowthFrontierState:
    s = check_frontier_state(before, frontier)
    producer = cast(ActionDocument, objects[recipe.action_digest]).spec.action_id
    check_use(contract, objects, frontier, before, producer, F(after.elapsed))
    enabled, lineage = set(s.enabled_action_ids), list(s.activation_lineage)
    parent = next((x for x in lineage if x.action_id == producer), None)
    depth = parent.depth + 1 if parent else 1
    # Simultaneous effects inspect the same post-ledger; rules cannot feed one another
    # inside a single transition. Canonical first rule wins duplicate target bindings.
    for rule in sorted(frontier.spec.activation_rules, key=lambda r: r.rule_id):
        if (
            rule.producer_action_id != producer
            or rule.producer_successor_id != effect.successor_id
            or not _conditions(rule, after, F(after.elapsed))
        ):
            continue
        for target in sorted(set(rule.activated_action_ids) - enabled):
            g.require(
                depth <= frontier.spec.maximum_activation_depth, "growth_frontier_depth_overflow"
            )
            _binding_live(contract, objects, frontier, after, target, F(after.elapsed))
            lineage.append(
                GrowthActivation(
                    action_id=target,
                    rule_id=rule.rule_id,
                    producer_action_id=producer,
                    producer_successor_id=effect.successor_id,
                    depth=depth,
                    model_time=after.elapsed,
                    parent_state_digest=g.state_digest(before),
                )
            )
            enabled.add(target)
    return GrowthFrontierState(
        **base_state(after).model_dump(),
        frontier_digest=s.frontier_digest,
        enabled_action_ids=sorted(enabled),
        activation_lineage=sorted(lineage, key=lambda x: x.action_id),
        activation_depth=max((x.depth for x in lineage), default=0),
    )


def diagnostics(
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier,
    root: GrowthPolicyNode | None,
) -> GrowthFrontierDiagnostics:
    witnesses = [
        GrowthActivationWitness(activation=x, carried_from_initial_frontier=True)
        for x in sorted(frontier.spec.initial_activation_lineage, key=lambda x: x.action_id)
    ]
    enabled: set[str] = set()
    used: set[str] = set()

    def walk(
        node: GrowthPolicyNode,
        state: GrowthState,
        path: list[str],
        continuation: bool,
        indices: dict[str, int],
    ) -> None:
        continuation |= node.entry
        action_id = node.action_id
        if action_id is None:
            return
        recipe = next(
            r
            for r in contract.spec.action_catalogue
            if cast(ActionDocument, objects[r.action_digest]).spec.action_id == action_id
        )
        if action_id in indices:
            used.add(action_id)
            i = indices[action_id]
            previous = witnesses[i]
            contributes = any(
                F(e.capacity_delta.get("verification", GrowthInterval(lower="0", upper="0")).lower)
                > 0
                for e in g.successors(state, recipe)
            )
            witnesses[i] = previous.model_copy(
                update={
                    "first_policy_node_using_activation": (
                        previous.first_policy_node_using_activation or g.content_digest(node)
                    ),
                    "policy_path": previous.policy_path
                    if previous.first_policy_node_using_activation
                    else path,
                    "continuation_use": previous.continuation_use or continuation,
                    "verification_capacity_effect": previous.verification_capacity_effect
                    or contributes,
                }
            )
        for effect in g.successors(state, recipe):
            after = cast(
                GrowthFrontierState,
                g.transition(contract, state, recipe, effect, objects, frontier),
            )
            child_indices = dict(indices)
            for event in after.activation_lineage:
                if event.action_id not in child_indices:
                    enabled.add(event.action_id)
                    child_indices[event.action_id] = len(witnesses)
                    witnesses.append(GrowthActivationWitness(activation=event))
            walk(
                node.branches[effect.successor_id],
                after,
                [*path, effect.successor_id],
                continuation,
                child_indices,
            )

    if root is not None:
        walk(
            root,
            g.initial_state(contract, frontier),
            [],
            False,
            {w.activation.action_id: i for i, w in enumerate(witnesses)},
        )
    return GrowthFrontierDiagnostics(
        newly_enabled_action_ids=sorted(enabled),
        actions_used_after_activation=sorted(used),
        maximum_activation_depth=max((w.activation.depth for w in witnesses), default=0),
        endogenous_frontier_used=bool(used),
        continuation_depends_on_frontier=any(w.continuation_use for w in witnesses),
        recursive_activation_used=any(w.activation.producer_action_id in used for w in witnesses),
        verification_capacity_contribution=any(w.verification_capacity_effect for w in witnesses),
        witnesses=witnesses,
    )
