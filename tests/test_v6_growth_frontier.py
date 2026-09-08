# SPDX-License-Identifier: Apache-2.0
"""Exact synthetic frontier regressions, independent witnesses and small oracles."""

from __future__ import annotations

from datetime import timedelta
from fractions import Fraction as F
from itertools import product
from typing import Any, cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.frontier_examples import SCENARIOS, frontier_example
from collective_phase_control_fabric.v6.growth import (
    Budget,
    GrowthError,
    Search,
    check_plan,
    check_tree,
    compare,
    content_digest,
    initial_state,
    plan_growth,
    state_digest,
    transition,
    validate_contract,
)
from collective_phase_control_fabric.v6.growth_frontier import (
    base_state,
    check_frontier_state,
    validate_frontier,
)
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    CapabilityDocument,
    GrowthCapabilityFrontier,
    GrowthFrontierPlan,
    GrowthFrontierState,
    GrowthState,
    GrowthWork,
    Lifecycle,
    ResourceObservationAttestation,
    ResourceObservationSpec,
)
from collective_phase_control_fabric.v6.registry import (
    document_digest,
    parse_document,
    registry_manifest,
)
from tests.test_v6_growth import modify, recipe_for


def changed(f: GrowthCapabilityFrontier, **updates: Any) -> GrowthCapabilityFrontier:
    return f.model_copy(update={"spec": f.spec.model_copy(update=updates)})


def step(
    case: tuple[Any, ...], state: GrowthState, name: str, outcome: str = "success"
) -> GrowthFrontierState:
    c, objects, f = case
    recipe = recipe_for(c, objects, name)
    effect = next(e for e in recipe.successors if e.outcome == outcome)
    return cast(GrowthFrontierState, transition(c, state, recipe, effect, objects, f))


@pytest.fixture(scope="module")
def planned() -> tuple[Any, ...]:
    case = frontier_example()
    return (*case, plan_growth(*case))


@pytest.mark.parametrize("name", SCENARIOS)
def test_eight_scenarios_preserve_growth_objective_and_audited_continuation(name: str) -> None:
    c, o, f = frontier_example(name)
    p = plan_growth(c, o, f)
    assert p.spec.search.complete and all(x.search.complete for x in p.spec.comparisons)
    d = p.spec.frontier_diagnostics
    assert not d.capability_admitted and not d.execution_authorized
    assert d.empirical_attribution == "undetermined" and p.spec.current_measured_bounds == {}
    if name in {"frontier-failure", "frontier-no-entry"}:
        assert p.spec.code == "growth_no_guaranteed_entry" and p.spec.policy is None
        if name == "frontier-no-entry":
            assert p.spec.safe_fallback is not None
            check_tree(
                c,
                o,
                p.spec.safe_fallback,
                initial_state(c, f),
                endpoint=F(c.spec.deadline),
                frontier=f,
            )
    else:
        assert p.spec.policy is not None and p.spec.policy.action_id == "prepare"
        assert p.spec.objective is not None
        assert p.spec.objective.worst_entry_time == ("3" if name == "frontier-verifier" else "2")
        assert check_plan(c, o, p, f) == p.spec.checker_digest
        assert d.endogenous_frontier_used == (name not in {"frontier-useless", "frontier-cycle"})
        if name == "frontier-verifier":
            assert d.verification_capacity_contribution and d.maximum_activation_depth == 3
            assert not p.spec.terminal_frontier_states[0].queue
        if name in {"frontier-chain", "frontier-comparator"}:
            assert d.maximum_activation_depth == 2 and d.continuation_depends_on_frontier
            assert d.recursive_activation_used


def test_success_unlocks_only_predeclared_action_and_latent_use_is_rejected(planned: Any) -> None:
    c, o, f, _ = planned
    start = initial_state(c, f)
    with pytest.raises(GrowthError, match=r"^growth_frontier_action_latent$"):
        step((c, o, f), start, "reuse")
    after = step((c, o, f), start, "prepare")
    assert "reuse" in after.enabled_action_ids and "continue" not in after.enabled_action_ids
    assert after.activation_depth == 1 and after.resources["credits"] == "6"
    assert after.capacities == start.capacities and after.actual_evidence_digests == []
    end = step((c, o, f), after, "reuse")
    assert end.activation_depth == 2 and "continue" in end.enabled_action_ids


@pytest.mark.parametrize("outcome", ["partial", "failure", "timeout"])
def test_nonsuccess_does_not_inherit_success_activation(outcome: str, planned: Any) -> None:
    c, o, f, _ = planned
    s = initial_state(c, f).model_copy(update={"model_ids": [outcome]})
    after = step((c, o, f), s, "prepare", outcome)
    assert after.enabled_action_ids == s.enabled_action_ids and not after.activation_lineage
    assert after.capacities == s.capacities
    rule = f.spec.activation_rules[0].model_copy(
        update={"producer_successor_id": "prepare:" + outcome}
    )
    explicit = changed(f, activation_rules=[rule])
    s = initial_state(c, explicit).model_copy(update={"model_ids": [outcome]})
    assert "reuse" in step((c, o, explicit), s, "prepare", outcome).enabled_action_ids


@pytest.mark.parametrize(
    "change,code",
    [
        ("contract", "growth_frontier_contract_mismatch"),
        ("partition", "growth_frontier_partition_invalid"),
        ("bindings", "growth_frontier_binding_missing"),
        ("target", "growth_frontier_target_undeclared"),
        ("producer", "growth_frontier_producer_mismatch"),
        ("successor", "growth_frontier_producer_mismatch"),
        ("digest", "growth_frontier_binding_mismatch"),
        ("missing", "growth_frontier_object_missing"),
        ("capability", "growth_frontier_capability_missing"),
        ("duplicate", "growth_frontier_rule_duplicate"),
        ("condition", "growth_frontier_condition_invalid"),
    ],
)
def test_unbound_or_undeclared_frontier_is_rejected(planned: Any, change: str, code: str) -> None:
    c, objects, f, _ = planned
    o = dict(objects)
    zero = "sha256:" + "0" * 64
    rule = f.spec.activation_rules[0]
    if change == "contract":
        f = changed(f, contract_digest=zero)
    elif change == "partition":
        f = changed(f, latent_action_ids=[*f.spec.latent_action_ids, "prepare"])
    elif change == "bindings":
        f = changed(f, bindings=f.spec.bindings[1:])
    elif change in {"target", "producer", "successor", "capability", "condition"}:
        key, value = {
            "target": ("activated_action_ids", ["undeclared"]),
            "producer": ("producer_action_id", "undeclared"),
            "successor": ("producer_successor_id", "reuse:success"),
            "capability": ("required_capability_digests", [zero]),
            "condition": ("minimum_resources", {"invented": "1"}),
        }[change]
        f = changed(f, activation_rules=[rule.model_copy(update={key: value})])
    elif change == "duplicate":
        f = changed(f, activation_rules=[rule, rule])
    elif change == "missing":
        o.pop(f.spec.bindings[0].execution_policy_digest)
    else:
        binding = f.spec.bindings[0].model_copy(update={"output_schema_digest": zero})
        f = changed(f, bindings=[binding, *f.spec.bindings[1:]])
    with pytest.raises(GrowthError, match=rf"^{code}$"):
        validate_frontier(c, o, f)


@pytest.mark.parametrize("mode", ["expiry", "withdrawal", "future"])
def test_model_lifecycle_blocks_activation_and_dependent_use(planned: Any, mode: str) -> None:
    c, o, f, _ = planned
    binding = next(b for b in f.spec.bindings if b.action_id == "reuse")
    changes = {
        "expiry": {"valid_until": c.spec.model_time_origin + timedelta(seconds=0.5)},
        "withdrawal": {"withdrawn_at": c.spec.model_time_origin + timedelta(seconds=1)},
        "future": {"valid_from": c.spec.model_time_origin + timedelta(seconds=2)},
    }[mode]
    binding = binding.model_copy(update={"lifecycle": binding.lifecycle.model_copy(update=changes)})
    f = changed(f, bindings=[binding if b.action_id == "reuse" else b for b in f.spec.bindings])
    with pytest.raises(GrowthError, match=r"^growth_frontier_object_expired$"):
        step((c, o, f), initial_state(c, f), "prepare")


def test_withdrawn_capability_cannot_be_used_after_model_enablement(planned: Any) -> None:
    c, o, f, _ = planned
    s = step((c, o, f), initial_state(c, f), "prepare")
    digest = next(b.capability_digest for b in f.spec.bindings if b.action_id == "reuse")
    s = s.model_copy(
        update={"live_object_digests": [d for d in s.live_object_digests if d != digest]}
    )
    with pytest.raises(GrowthError, match=r"^growth_frontier_object_unavailable$"):
        step((c, o, f), s, "reuse")


def test_depth_overflow_and_duplicate_lineage_fail_closed(planned: Any) -> None:
    c, o, f, _ = planned
    f = changed(f, maximum_activation_depth=1)
    s = step((c, o, f), initial_state(c, f), "prepare")
    with pytest.raises(GrowthError, match=r"^growth_frontier_depth_overflow$"):
        step((c, o, f), s, "reuse")
    corrupt = s.model_copy(update={"activation_lineage": s.activation_lineage * 2})
    with pytest.raises(GrowthError, match=r"^growth_frontier_lineage_invalid$"):
        check_frontier_state(corrupt, f)


def test_self_unlock_and_duplicate_rules_cannot_create_progress(planned: Any) -> None:
    c, o, f, _ = planned
    rule = f.spec.activation_rules[0].model_copy(update={"activated_action_ids": ["prepare"]})
    f = changed(f, activation_rules=[rule], maximum_activation_depth=0)
    s = step((c, o, f), initial_state(c, f), "prepare")
    assert s.activation_depth == 0 and s.activation_lineage == []
    assert s.capacities == initial_state(c, f).capacities
    c, o, f = frontier_example()
    duplicate = f.spec.activation_rules[0].model_copy(update={"rule_id": "second-rule"})
    f = changed(f, activation_rules=[*f.spec.activation_rules, duplicate])
    after = step((c, o, f), initial_state(c, f), "prepare")
    assert len(after.activation_lineage) == 1


@pytest.mark.parametrize(
    "change,code",
    [
        ("frontier", "growth_frontier_digest_mismatch"),
        ("state", "growth_frontier_state_mismatch"),
        ("terminal", "growth_frontier_state_mismatch"),
        ("witness", "growth_frontier_witness_mismatch"),
        ("node", "growth_plan_state_mismatch"),
    ],
)
def test_checker_reconstructs_frontier_instead_of_trusting_plan(
    planned: Any, change: str, code: str
) -> None:
    c, o, f, p = planned
    if change == "frontier":
        update = {"frontier_digest": "sha256:" + "0" * 64}
    elif change == "state":
        update = {
            "initial_frontier_state": p.spec.initial_frontier_state.model_copy(
                update={"enabled_action_ids": ["reuse"]}
            )
        }
    elif change == "terminal":
        update = {"terminal_frontier_states": []}
    elif change == "witness":
        update = {
            "frontier_diagnostics": p.spec.frontier_diagnostics.model_copy(
                update={"endogenous_frontier_used": False}
            )
        }
    else:
        node = p.spec.policy.model_copy(update={"state_digest": "sha256:" + "0" * 64})
        update = {"policy": node, "policy_digest": content_digest(node)}
    tampered = p.model_copy(update={"spec": p.spec.model_copy(update=update)})
    with pytest.raises(GrowthError, match=rf"^{code}$"):
        check_plan(c, o, tampered, f)


def test_frontier_documents_are_closed_and_old_schema_stays_unchanged(planned: Any) -> None:
    c, o, f, p = planned
    for doc in (f, p):
        assert parse_document(doc.model_dump(mode="json")) == doc
        value = doc.model_dump(mode="json")
        value["spec"]["authorize_execution"] = True
        with pytest.raises(ValueError, match="document_schema_invalid"):
            parse_document(value)
    validate_contract(c, o)
    assert not isinstance(plan_growth(c, o), GrowthFrontierPlan)
    with pytest.raises(GrowthError, match=r"^growth_frontier_document_required$"):
        check_plan(c, o, p)


def test_all_v061_schema_identities_remain_byte_compatible() -> None:
    manifest = registry_manifest()
    additions = {"growth-capability-frontier", "growth-frontier-plan", "growth-frontier-assessment"}
    manifest["schemas"] = [x for x in manifest["schemas"] if x["kind"] not in additions]
    assert len(manifest["schemas"]) == 52
    assert (
        digest_bytes(canonical_bytes(manifest))
        == "sha256:b2f953f493fd94c80c8617a3a172d54d21965a53c234f89a52b0cc28b1b82cde"
    )


@pytest.mark.parametrize(
    "name,digest",
    [
        ("frontier-chain", "7ff952033b2dbd0cbe0bd0209e290c6789371df5d9a68ad65a4229dcb5175cd3"),
        ("frontier-verifier", "c2187de1a217e7c059e4eb1606b14f6ba2bbd0b534b973b3faa148e899fc9fcd"),
        ("frontier-no-entry", "6b62f2135920709ef705de976d7faea883f595d24e6d4db2ef8728587db74eb3"),
    ],
)
def test_complete_frontier_witness_encodings_are_stable(name: str, digest: str) -> None:
    assert document_digest(plan_growth(*frontier_example(name))) == "sha256:" + digest


def test_state_digest_covers_every_frontier_facet(planned: Any) -> None:
    c, o, f, _ = planned
    state = step((c, o, f), initial_state(c, f), "prepare")
    variants = [
        state.model_copy(update={k: v})
        for k, v in {
            "frontier_digest": "sha256:" + "0" * 64,
            "enabled_action_ids": ["prepare"],
            "activation_depth": 0,
            "activation_lineage": [],
        }.items()
    ]
    assert len({state_digest(s) for s in [state, *variants]}) == 5
    assert state_digest(base_state(state)) != state_digest(state)


def test_comparator_reoptimizes_alternative_activation_route() -> None:
    c, o, f = frontier_example("frontier-comparator")
    results = compare(c, o, f)
    endpoint = next(x for x in results if x.endpoint == "3")
    assert endpoint.upper_bound == "4/3"
    search = Search(
        c,
        o,
        Budget(c.spec.search_limits),
        excluded=frozenset({"discovery"}),
        endpoint=F(3),
        frontier=f,
    )
    solution = search.scalar(initial_state(c, f))
    assert solution is not None and solution.candidate.node.action_id == "serial"
    check_tree(c, o, solution.candidate.node, initial_state(c, f), endpoint=F(3), frontier=f)


@pytest.mark.parametrize(
    "limit", ["max_states", "max_expansions", "max_depth", "max_policies", "max_witness_nodes"]
)
def test_frontier_search_exhaustion_stays_unknown(limit: str, planned: Any) -> None:
    c, o, f, _ = planned
    c = modify(c, search_limits=c.spec.search_limits.model_copy(update={limit: 1}))
    f = changed(f, contract_digest=document_digest(c))
    p = plan_growth(c, o, f)
    assert p.spec.code == "growth_unknown_due_to_budget" and p.spec.solution_class == "incomplete"
    assert all(x.upper_bound is None for x in p.spec.comparisons)


@given(st.permutations(["prepare", "reuse", "continue", "greedy", "serial", "idle"]))
@settings(max_examples=4, deadline=None)
def test_catalogue_permutation_preserves_policy_semantics(order: list[str]) -> None:
    c, o, f = frontier_example()
    p = plan_growth(c, o, f)
    c = modify(c, action_catalogue=[recipe_for(c, o, name) for name in order])
    f = changed(
        f,
        contract_digest=document_digest(c),
        bindings=list(reversed(f.spec.bindings)),
        activation_rules=list(reversed(f.spec.activation_rules)),
    )
    q = plan_growth(c, dict(reversed(list(o.items()))), f)
    # Input-bound state/policy digests change when the immutable model document changes.
    assert p.spec.objective == q.spec.objective
    assert (
        p.spec.frontier_diagnostics.actions_used_after_activation
        == q.spec.frontier_diagnostics.actions_used_after_activation
    )


def _oracle(budget: int) -> tuple[int, F, int] | None:
    """Arithmetic sequence oracle: no planner, checker or transition functions."""
    recipes = {
        "prepare": (1, 1, 0, 0),
        "reuse": (1, 2, 2, 2),
        "continue": (1, 1, 1, 1),
        "greedy": (1, 2, 2, 0),
        "serial": (2, 2, 1, 1),
        "idle": (1, 1, 0, 0),
    }
    best = None
    for seq in product(recipes, repeat=4):
        active, used = {"prepare", "serial", "idle", "greedy"}, set()
        time, cost, task, research = 0, 1, 1, 1
        entry = None
        for name in seq:
            if name not in active or (name in used and name in {"prepare", "reuse", "greedy"}):
                break
            dt, dc, da, db = recipes[name]
            time, cost, task, research = time + dt, cost + dc, task + da, research + db
            if time > 5 or cost > budget:
                break
            used.add(name)
            if name == "prepare":
                active.add("reuse")
            if name == "reuse":
                active.add("continue")
            if entry:
                t, a, b = entry
                if time == t + 1 and 3 * task >= 4 * a and 3 * research >= 4 * b:
                    score = (t, -min(F(task, 3), F(research, 3)), cost)
                    best = min(best, score) if best else score
                if time >= t + 1:
                    break
            baseline = 1 + min(time // 2, (budget - 1) // 2)
            if (
                time in {2, 3, 4}
                and min(task, research) >= 3
                and ("reuse" in used or "serial" in used)
                and F(min(task, research), 3) > F(baseline, 3) + F(1, 10)
            ):
                entry = (time, task, research)
    return best


@given(st.integers(min_value=3, max_value=9))
@settings(max_examples=7, deadline=None)
def test_frontier_optimum_matches_small_independent_oracle(budget: int) -> None:
    c, o, f = frontier_example()
    c = modify(
        c,
        initial_state=c.spec.initial_state.model_copy(
            update={"resources": {"credits": str(budget)}}
        ),
    )
    f = changed(f, contract_digest=document_digest(c))
    p = plan_growth(c, o, f)
    expected = _oracle(budget)
    if expected is None:
        assert p.spec.policy is None
    else:
        obj = p.spec.objective
        assert obj is not None
        assert (
            int(obj.worst_entry_time),
            -F(obj.terminal_min_attainment),
            int(obj.worst_cost["credits"]),
        ) == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("required_evidence", ["undelivered"]),
        ("required_model_ids", ["failure"]),
        ("minimum_resources", {"credits": "100"}),
        ("minimum_capacities", {"verification": "10"}),
        ("valid_from", "2"),
        ("expires", "1/2"),
    ],
)
def test_unsatisfied_rule_never_expands_the_frontier(planned: Any, field: str, value: Any) -> None:
    c, o, f, _ = planned
    rule = f.spec.activation_rules[0].model_copy(update={field: value})
    f = changed(f, activation_rules=[rule])
    validate_frontier(c, o, f)
    s = step((c, o, f), initial_state(c, f), "prepare")
    assert s.activation_lineage == [] and "reuse" not in s.enabled_action_ids


def test_unreachable_latent_actions_do_not_change_exact_optimum() -> None:
    c, o, f = frontier_example("frontier-useless")
    f = changed(f, activation_rules=[])
    p = plan_growth(c, o, f)
    removed = set(f.spec.latent_action_ids)
    retained = [b for b in f.spec.bindings if b.action_id not in removed]
    c = modify(
        c,
        action_catalogue=[
            r
            for r in c.spec.action_catalogue
            if r.action_digest in {b.action_digest for b in retained}
        ],
    )
    f = changed(f, contract_digest=document_digest(c), latent_action_ids=[], bindings=retained)
    q = plan_growth(c, o, f)
    assert p.spec.solution_class == q.spec.solution_class == "exact"
    assert p.spec.objective == q.spec.objective
    assert not p.spec.frontier_diagnostics.endogenous_frontier_used


def test_zero_progress_cycle_cannot_manufacture_entry() -> None:
    c, o, f = frontier_example("frontier-cycle")
    bindings = [b for b in f.spec.bindings if b.action_id in {"idle", "greedy"}]
    c = modify(
        c,
        action_catalogue=[
            r
            for r in c.spec.action_catalogue
            if r.action_digest in {b.action_digest for b in bindings}
        ],
    )
    f = changed(
        f,
        contract_digest=document_digest(c),
        initial_enabled_action_ids=["idle"],
        bindings=bindings,
    )
    p = plan_growth(c, o, f)
    assert p.spec.code == "growth_no_guaranteed_entry" and p.spec.safe_fallback is not None
    s = step((c, o, f), initial_state(c, f), "idle")
    after = step((c, o, f), s, "greedy")
    assert after.activation_depth == 1 and len(after.activation_lineage) == 1
    assert after.capacities == s.capacities


@pytest.mark.parametrize(
    "field,value",
    [
        ("rule_id", "invented"),
        ("producer_action_id", "reuse"),
        ("producer_successor_id", "prepare:failure"),
        ("depth", 2),
        ("model_time", "100"),
    ],
)
def test_corrupt_activation_lineage_is_rejected(planned: Any, field: str, value: Any) -> None:
    c, o, f, _ = planned
    s = step((c, o, f), initial_state(c, f), "prepare")
    s = s.model_copy(
        update={"activation_lineage": [s.activation_lineage[0].model_copy(update={field: value})]}
    )
    with pytest.raises(GrowthError, match=r"^growth_frontier_lineage_invalid$"):
        check_frontier_state(s, f)


def test_activated_target_retains_rule_evidence_through_future_use(planned: Any) -> None:
    c, o, f, _ = planned
    rule = f.spec.activation_rules[0].model_copy(update={"required_evidence": ["calibrated"]})
    f = changed(f, activation_rules=[rule])
    s = step((c, o, f), initial_state(c, f), "prepare")
    s = s.model_copy(update={"evidence": {"calibrated": "3/2"}})
    with pytest.raises(GrowthError, match=r"^growth_premise_expires_during_action$"):
        step((c, o, f), s, "reuse")
    # A frontier-only prerequisite is also retained, independent of recipe premises.
    rule = rule.model_copy(update={"required_evidence": ["separate-proof"]})
    f = changed(f, activation_rules=[rule])
    start = initial_state(c, f).model_copy(update={"evidence": {"separate-proof": "3/2"}})
    s = step((c, o, f), start, "prepare")
    with pytest.raises(GrowthError, match=r"^growth_frontier_premise_unavailable$"):
        step((c, o, f), s, "reuse")


def test_frontier_does_not_discharge_existing_queue_or_repair_debt(planned: Any) -> None:
    c, o, f, _ = planned
    start = initial_state(c, f).model_copy(
        update={
            "queue": [
                GrowthWork(work_id="queue", stage="verification", remaining="1", deadline="4")
            ],
            "obligations": [
                GrowthWork(work_id="repair", stage="research", remaining="1", deadline="4")
            ],
        }
    )
    after = step((c, o, f), start, "prepare")
    assert after.queue == start.queue and after.obligations == start.obligations
    assert after.resources["credits"] == "6" and after.capacities == start.capacities


def test_required_target_object_lifecycle_is_checked_before_activation(planned: Any) -> None:
    c, original, f, _ = planned
    o = dict(original)
    source = ResourceObservationAttestation(
        metadata=c.metadata,
        spec=ResourceObservationSpec(
            coordinate="credits",
            quantity="8",
            unit="credit",
            observed_at=c.spec.model_time_origin,
            lifecycle=Lifecycle(
                valid_from=c.spec.model_time_origin,
                valid_until=c.spec.model_time_origin + timedelta(seconds=0.5),
            ),
        ),
    )
    old = next(b for b in f.spec.bindings if b.action_id == "reuse")
    action = o[old.action_digest]
    action = action.model_copy(
        update={
            "spec": action.spec.model_copy(
                update={"required_object_digests": [document_digest(source)]}
            )
        }
    )
    o.update({document_digest(d): d for d in (source, action)})
    c = modify(
        c,
        action_catalogue=[
            r.model_copy(update={"action_digest": document_digest(action)})
            if r.action_digest == old.action_digest
            else r
            for r in c.spec.action_catalogue
        ],
        initial_state=c.spec.initial_state.model_copy(update={"live_object_digests": sorted(o)}),
    )
    f = changed(
        f,
        contract_digest=document_digest(c),
        bindings=[
            b.model_copy(update={"action_digest": document_digest(action)}) if b == old else b
            for b in f.spec.bindings
        ],
    )
    validate_contract(c, o)
    validate_frontier(c, o, f)
    with pytest.raises(GrowthError, match=r"^growth_frontier_object_expired$"):
        step((c, o, f), initial_state(c, f), "prepare")


def test_zero_cost_self_unlock_has_no_capacity_or_objective_credit(planned: Any) -> None:
    c, original, f, _ = planned
    o = dict(original)
    recipe = recipe_for(c, o, "prepare")
    action = cast(ActionDocument, o[recipe.action_digest])
    old_cap_digest = action.spec.capability_digest
    cap = cast(CapabilityDocument, o[old_cap_digest])
    cap = cap.model_copy(
        update={
            "spec": cap.spec.model_copy(
                update={
                    "branches": [
                        b.model_copy(
                            update={
                                "cost_lower": "0",
                                "cost_upper": "0",
                                "resource_delta_lower": {"credits": "0"},
                                "resource_delta_upper": {"credits": "0"},
                            }
                        )
                        for b in cap.spec.branches
                    ]
                }
            )
        }
    )
    action = action.model_copy(
        update={"spec": action.spec.model_copy(update={"capability_digest": document_digest(cap)})}
    )
    o.update({document_digest(d): d for d in (cap, action)})
    altered = recipe.model_copy(
        update={
            "action_digest": document_digest(action),
            "successors": [
                e.model_copy(update={"charges": {"investment": {"credits": "0"}}})
                for e in recipe.successors
            ],
        }
    )
    c = modify(
        c,
        action_catalogue=[altered if r == recipe else r for r in c.spec.action_catalogue],
        initial_state=c.spec.initial_state.model_copy(update={"live_object_digests": sorted(o)}),
    )
    rule = f.spec.activation_rules[0].model_copy(
        update={
            "activated_action_ids": ["prepare"],
            "required_capability_digests": [document_digest(cap)],
        }
    )
    f = changed(
        f,
        contract_digest=document_digest(c),
        activation_rules=[rule],
        maximum_activation_depth=0,
        bindings=[
            b.model_copy(
                update={
                    "action_digest": document_digest(action),
                    "capability_digest": document_digest(cap),
                }
            )
            if b.action_id == "prepare"
            else b
            for b in f.spec.bindings
        ],
    )
    validate_contract(c, o)
    validate_frontier(c, o, f)
    start = initial_state(c, f)
    after = step((c, o, f), start, "prepare")
    assert after.resources == start.resources and after.capacities == start.capacities
    assert after.activation_lineage == [] and after.activation_depth == 0
