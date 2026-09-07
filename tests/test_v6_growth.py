# SPDX-License-Identifier: Apache-2.0
"""Finite-game counterexamples and an independent small-catalogue sequence oracle."""

from __future__ import annotations

from datetime import timedelta
from fractions import Fraction as F
from itertools import product
from typing import Any, cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from collective_phase_control_fabric.v6.growth import (
    Budget,
    GrowthError,
    Search,
    attainment,
    audit_model_boundary,
    block_supported,
    check_plan,
    check_state,
    check_tree,
    compare,
    content_digest,
    initial_state,
    normalize,
    plan_growth,
    state_digest,
    successors,
    transition,
    validate_contract,
)
from collective_phase_control_fabric.v6.growth_evidence import replay
from collective_phase_control_fabric.v6.growth_examples import example
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    CapabilityDocument,
    Document,
    GrowthAction,
    GrowthContract,
    GrowthInterval,
    GrowthPlan,
    GrowthReservation,
    GrowthState,
    GrowthWork,
    Lifecycle,
    ResourceObservationAttestation,
    ResourceObservationSpec,
)
from collective_phase_control_fabric.v6.registry import (
    document_digest,
    parse_document,
    schema_for_kind,
)


def modify(contract: GrowthContract, **updates: Any) -> GrowthContract:
    return contract.model_copy(update={"spec": contract.spec.model_copy(update=updates)})


def recipe_for(contract: GrowthContract, objects: dict[str, Document], name: str) -> GrowthAction:
    return next(
        r
        for r in contract.spec.action_catalogue
        if cast(ActionDocument, objects[r.action_digest]).spec.action_id == name
    )


def step(
    contract: GrowthContract,
    objects: dict[str, Document],
    state: GrowthState,
    name: str,
    outcome: str = "success",
) -> GrowthState:
    recipe = recipe_for(contract, objects, name)
    effect = next(e for e in recipe.successors if e.outcome == outcome)
    return transition(contract, state, recipe, effect, objects)


@pytest.fixture(scope="module")
def planned() -> tuple[GrowthContract, dict[str, Document], GrowthPlan]:
    contract, objects = example()
    return contract, objects, plan_growth(contract, objects)


def test_blocker_free_preparation_has_no_immediate_gain_and_opens_funded_entry(
    planned: Any,
) -> None:
    contract, objects, plan = planned
    start = initial_state(contract)
    prepared = step(contract, objects, start, "prepare")
    assert prepared.capacities == start.capacities
    assert prepared.evidence != start.evidence
    assert plan.spec.policy.action_id == "prepare"
    assert plan.spec.objective.worst_entry_time == "2"
    assert plan.spec.objective.terminal_min_attainment == "4/3"
    assert plan.spec.objective.worst_cost == {"credits": "5"}
    assert plan.spec.model_predicted_terminal[0].resources == {"credits": "3"}
    assert plan.spec.observed_entry == "undetermined"
    assert plan.spec.current_measured_bounds == {}
    assert check_plan(contract, objects, plan) == plan.spec.checker_digest


def test_temporary_contraction_above_floor_is_allowed_only_in_registered_block(
    planned: Any,
) -> None:
    c, o, _ = planned
    s = initial_state(c)
    c = modify(
        c,
        domains={
            k: d.model_copy(update={"service_floor": "1/2"}) for k, d in c.spec.domains.items()
        },
    )
    r = recipe_for(c, o, "prepare")
    e = r.successors[0].model_copy(
        update={"capacity_delta": {"task": GrowthInterval(lower="-1/2", upper="-1/2")}}
    )
    r = r.model_copy(update={"successors": [e, *r.successors[1:]]})
    contracted = transition(c, s, r, e, o)
    assert contracted.capacities["task"].lower == "1/2"
    grown = step(c, o, contracted, "reuse")
    assert block_supported(grown, c.spec.windows[0])
    with pytest.raises(GrowthError, match="growth_service_floor"):
        check_state(planned[0], contracted)


def test_verifier_investment_resolves_capacity_bottleneck() -> None:
    c, o = example("verification")
    p = plan_growth(c, o)
    assert p.spec.policy is not None and p.spec.policy.action_id == "verifier"
    assert p.spec.model_predicted_terminal[0].capacities["verification"].lower == "4"
    assert "growth_capacity_prerequisite" in p.spec.counterexamples


def test_dense_communication_spends_continuation_budget_and_loses_to_moderate() -> None:
    c, o = example("communication")
    p = plan_growth(c, o)
    assert p.spec.policy is not None and p.spec.policy.action_id == "prepare"
    dense = step(c, o, initial_state(c), "dense")
    assert dense.resources["credits"] == "1"
    assert dense.charges["communication"]["credits"] == "6"


def test_weak_ablation_and_agent_labels_cannot_beat_reoptimized_single_process() -> None:
    c, o = example("no-advantage")
    p = plan_growth(c, o)
    assert p.spec.code == "growth_no_guaranteed_entry"
    assert p.spec.policy is None
    assert all(F(x.upper_bound) >= F(5, 3) for x in p.spec.comparisons)
    assert p.spec.safe_fallback is not None


@pytest.mark.parametrize("which", ["shared", "unit", "hidden-budget"])
def test_double_reservation_wrong_units_and_hidden_budget_fail_closed(
    planned: Any, which: str
) -> None:
    c, o, _ = planned
    if which == "shared":
        c = modify(c, shared_resources={"gpu": "3"})
        s = initial_state(c).model_copy(
            update={
                "reservations": [
                    GrowthReservation(resource="gpu", owner="task-only", quantity="3", until="2"),
                    GrowthReservation(
                        resource="gpu", owner="research-only", quantity="3", until="2"
                    ),
                ]
            }
        )
        with pytest.raises(GrowthError, match="growth_shared_resource_double_booking"):
            check_state(c, s)
    elif which == "unit":
        c = modify(c, resource_units={"credits": "task/s"})
        with pytest.raises(GrowthError, match="growth_units_mismatch"):
            validate_contract(c, o)
    else:
        r = c.spec.action_catalogue[0]
        e = r.successors[0].model_copy(update={"charges": {"evidence": {"credits": "0"}}})
        c = modify(
            c,
            action_catalogue=[
                r.model_copy(update={"successors": [e, *r.successors[1:]]}),
                *c.spec.action_catalogue[1:],
            ],
        )
        with pytest.raises(GrowthError, match="growth_capability_effect"):
            validate_contract(c, o)


def test_measurement_cost_prevents_funded_continuation(planned: Any) -> None:
    c, o, _ = planned
    c = modify(
        c, initial_state=c.spec.initial_state.model_copy(update={"resources": {"credits": "4"}})
    )
    p = plan_growth(c, o)
    assert p.spec.code == "growth_no_guaranteed_entry"
    assert p.spec.continuation == "unavailable"
    assert "growth_resource_floor" in p.spec.counterexamples


def test_hypothetical_and_duplicate_artifacts_do_not_update_measured_capacity(planned: Any) -> None:
    c, o, p = planned
    before = {k: v.model_dump(mode="json") for k, v in o.items()}
    trace = replay(c, o, p, ["prepare:success", "reuse:success"])
    assert trace["model_states"][-1]["capacities"]["task"]["lower"] == "3"
    assert trace["measured_bounds"] == {} and trace["observations_written"] == []
    assert {k: v.model_dump(mode="json") for k, v in o.items()} == before
    s = initial_state(c).model_copy(update={"pending_results": ["duplicate", "duplicate"]})
    assert normalize(s).pending_results == ["duplicate"]
    assert normalize(s).capacities == initial_state(c).capacities


@pytest.mark.parametrize("outcome", ["failure", "timeout"])
def test_failed_work_preserves_queue_debt_and_offered_service_is_not_completion(
    planned: Any, outcome: str
) -> None:
    c, o, _ = planned
    s = initial_state(c).model_copy(
        update={
            "model_ids": [outcome],
            "queue": [GrowthWork(work_id="v1", stage="verification", remaining="2", deadline="4")],
            "obligations": [
                GrowthWork(work_id="d1", stage="verification", remaining="1", deadline="4")
            ],
        }
    )
    r = recipe_for(c, o, "idle")
    index = next(i for i, e in enumerate(r.successors) if e.outcome == outcome)
    e = r.successors[index].model_copy(update={"offered_service": {"verification": "1"}})
    r = r.model_copy(
        update={"successors": [e if i == index else old for i, old in enumerate(r.successors)]}
    )
    after = transition(c, s, r, e, o)
    assert after.queue == s.queue and after.obligations == s.obligations
    assert after.offered["verification"] == "1" and after.completed["verification"] == "0"
    assert after.resources["credits"] == "6"


def test_good_marginal_expected_capacities_cannot_replace_joint_attainment(planned: Any) -> None:
    c, _, _ = planned
    s = initial_state(c)
    left = s.model_copy(
        update={
            "capacities": {
                **s.capacities,
                "task": GrowthInterval(lower="5", upper="5"),
                "research": GrowthInterval(lower="1", upper="1"),
            }
        }
    )
    right = s.model_copy(
        update={
            "capacities": {
                **s.capacities,
                "task": GrowthInterval(lower="1", upper="1"),
                "research": GrowthInterval(lower="5", upper="5"),
            }
        }
    )
    assert (F(left.capacities["task"].lower) + F(right.capacities["task"].lower)) / 2 == 3
    assert min(attainment(c, x) for x in [left, right]) == F(1, 3)


def test_empty_models_and_pending_evidence_are_never_success(planned: Any) -> None:
    c, o, _ = planned
    empty = modify(c, initial_state=c.spec.initial_state.model_copy(update={"model_ids": []}))
    p = plan_growth(empty, o)
    assert p.spec.code == "growth_inconsistent_models" and p.spec.policy is None
    pending = modify(
        c,
        initial_state=c.spec.initial_state.model_copy(update={"pending_results": ["unconfirmed"]}),
    )
    p = plan_growth(pending, o)
    assert p.spec.policy is None


@pytest.mark.parametrize(
    "limit,value",
    [
        ("max_states", 1),
        ("max_expansions", 1),
        ("max_policies", 1),
        ("max_depth", 1),
        ("max_witness_nodes", 1),
    ],
)
def test_search_exhaustion_is_unknown_and_comparator_incumbent_is_not_an_upper_bound(
    planned: Any, limit: str, value: int
) -> None:
    c, o, _ = planned
    c = modify(c, search_limits=c.spec.search_limits.model_copy(update={limit: value}))
    p = plan_growth(c, o)
    assert p.spec.code == "growth_unknown_due_to_budget"
    assert p.spec.solution_class == "incomplete"
    assert all(not x.search.complete and x.upper_bound is None for x in p.spec.comparisons)


def test_nonrepeatable_and_zero_duration_cycle_do_not_create_progress(planned: Any) -> None:
    c, o, _ = planned
    s = step(c, o, initial_state(c), "prepare")
    with pytest.raises(GrowthError, match="growth_nonrepeatable_reuse"):
        step(c, o, s, "prepare")
    r = c.spec.action_catalogue[0]
    e = r.successors[0].model_copy(update={"duration": "0"})
    c = modify(
        c,
        action_catalogue=[
            r.model_copy(update={"successors": [e, *r.successors[1:]]}),
            *c.spec.action_catalogue[1:],
        ],
    )
    with pytest.raises(GrowthError, match="growth_duration_invalid"):
        validate_contract(c, o)


def test_all_failure_branches_can_be_safe_without_guaranteed_growth() -> None:
    c, o = example("all-failure")
    p = plan_growth(c, o)
    assert p.spec.search.complete
    assert p.spec.code == "growth_no_guaranteed_entry"
    assert p.spec.safe_fallback is not None and p.spec.policy is None


def test_model_resource_and_time_changes_invalidate_old_policy_and_expiry(planned: Any) -> None:
    c, o, p = planned
    changed = modify(
        c, initial_state=c.spec.initial_state.model_copy(update={"resources": {"credits": "2"}})
    )
    with pytest.raises(GrowthError, match="growth_plan_input_mismatch"):
        check_plan(changed, o, p)
    s = step(c, o, initial_state(c), "prepare")
    s = s.model_copy(update={"evidence": {"calibrated": "1"}})
    with pytest.raises(GrowthError, match="growth_premise_missing_or_expired"):
        step(c, o, s, "reuse")
    s = s.model_copy(update={"evidence": {"calibrated": "3/2"}})
    with pytest.raises(GrowthError, match="growth_premise_expires_during_action"):
        step(c, o, s, "reuse")


@pytest.mark.parametrize(
    "change,code",
    [
        ("action", "growth_plan_action_invalid"),
        ("state", "growth_plan_state_mismatch"),
        ("effect", "growth_plan_effect_mismatch"),
        ("digest", "growth_plan_digest_mismatch"),
        ("duration", "growth_plan_objective_mismatch"),
        ("branches", "growth_plan_branches_invalid"),
        ("entry", "growth_plan_entry_invalid"),
        ("terminal", "growth_plan_terminal_mismatch"),
    ],
)
def test_independent_checker_detects_plan_tampering(planned: Any, change: str, code: str) -> None:
    c, o, p = planned
    node = p.spec.policy
    if change == "action":
        node = node.model_copy(update={"action_id": "invented-action"})
    elif change == "state":
        node = node.model_copy(update={"state_digest": "sha256:" + "0" * 64})
    elif change == "effect":
        node = node.model_copy(
            update={"effect_digests": {k: "sha256:" + "0" * 64 for k in node.effect_digests}}
        )
    elif change == "branches":
        node = node.model_copy(update={"branches": {}})
    elif change == "entry":
        node = node.model_copy(update={"entry": True})
    updates: dict[str, Any] = {"policy": node, "policy_digest": content_digest(node)}
    if change == "digest":
        updates["policy_digest"] = "sha256:" + "0" * 64
    if change == "duration":
        updates["objective"] = p.spec.objective.model_copy(update={"worst_duration": "1"})
    if change == "terminal":
        updates["model_predicted_terminal"] = []
    altered = p.model_copy(update={"spec": p.spec.model_copy(update=updates)})
    with pytest.raises(GrowthError, match=code):
        check_plan(c, o, altered)


def test_ordering_is_deterministic_and_memo_key_keeps_all_state_facets(planned: Any) -> None:
    c, o, p = planned
    reordered = modify(
        c,
        action_catalogue=list(reversed(c.spec.action_catalogue)),
        windows=list(reversed(c.spec.windows)),
    )
    again = plan_growth(reordered, dict(reversed(list(o.items()))))
    assert again.spec.policy_digest == p.spec.policy_digest
    assert again.spec.objective == p.spec.objective
    state = initial_state(c)
    variants = [
        state.model_copy(update={k: v})
        for k, v in {
            "elapsed": "1",
            "evidence": {"test": "3"},
            "pending_results": ["unresolved"],
            "used_actions": ["prepare"],
            "assumptions": {"calibration": "3"},
            "resources": {"credits": "2"},
            "attribution": "external",
            "model_ids": [],
            "reservations": [
                GrowthReservation(resource="gpu", owner="test", quantity="1", until="3")
            ],
            "queue": [GrowthWork(work_id="q", stage="task", remaining="1", deadline="2")],
            "obligations": [GrowthWork(work_id="d", stage="task", remaining="1", deadline="2")],
        }.items()
    ]
    assert len({state_digest(state), *(state_digest(v) for v in variants)}) == len(variants) + 1


def _sequence_oracle(budget: int) -> tuple[F, F, F] | None:
    """Direct arithmetic over sequences, with no planner/checker/transition calls."""
    recipes = {
        "prepare": (1, 1, 0, 0),
        "reuse": (1, 2, 2, 2),
        "continue": (1, 1, 1, 1),
        "greedy": (1, 2, 2, 0),
        "serial": (2, 2, 1, 1),
        "idle": (1, 1, 0, 0),
    }
    best: tuple[F, F, F] | None = None
    for length in range(1, 6):
        for seq in product(recipes, repeat=length):
            time, cost, task, research = 0, 1, 1, 1
            prepared = route = False
            used: set[str] = set()
            entry: tuple[int, int, int] | None = None
            for name in seq:
                if name in {"prepare", "reuse", "greedy"} and name in used:
                    break
                if (name == "reuse" and not prepared) or (name == "continue" and not route):
                    break
                dt, dc, da, db = recipes[name]
                time, cost, task, research = time + dt, cost + dc, task + da, research + db
                if time > 5 or cost > budget:
                    break
                used.add(name)
                prepared |= name == "prepare"
                route |= name in {"reuse", "serial"}
                if entry is not None:
                    t, a, b = entry
                    if time == t + 1 and 3 * task >= 4 * a and 3 * research >= 4 * b:
                        score = (F(t), -min(F(task, 3), F(research, 3)), F(cost))
                        best = min(best, score) if best else score
                    if time >= t + 1:
                        break
                # Restricted serial baseline: at most floor(time/2) paid additions.
                baseline = 1 + min(time // 2, (budget - 1) // 2)
                if (
                    time in (2, 3, 4)
                    and min(task, research) >= 3
                    and route
                    and (F(min(task, research), 3) > F(baseline, 3) + F(1, 10))
                ):
                    entry = (time, task, research)
    return best


@given(st.integers(min_value=3, max_value=10))
@settings(max_examples=8, deadline=None)
def test_exact_objective_matches_independent_small_catalogue_oracle(budget: int) -> None:
    c, o = example()
    c = modify(
        c,
        initial_state=c.spec.initial_state.model_copy(
            update={"resources": {"credits": str(budget)}}
        ),
    )
    p = plan_growth(c, o)
    expected = _sequence_oracle(budget)
    assert p.spec.solution_class == "exact"
    if expected is None:
        assert p.spec.policy is None
    else:
        assert p.spec.objective is not None
        assert (
            F(p.spec.objective.worst_entry_time),
            -F(p.spec.objective.terminal_min_attainment),
            F(p.spec.objective.worst_cost["credits"]),
        ) == expected


@given(st.lists(st.sampled_from(["nominal", "failure", "timeout"]), unique=True, min_size=1))
@settings(max_examples=7, deadline=None)
def test_every_applicable_successor_is_required_and_weakening_models_cannot_improve_guarantee(
    models: list[str],
) -> None:
    c, o = example()
    # A two-step catalogue keeps complete adversarial enumeration small.
    c = modify(
        c,
        max_decisions=3,
        initial_state=c.spec.initial_state.model_copy(update={"model_ids": models}),
    )
    p = plan_growth(c, o)
    if set(models) != {"nominal"}:
        assert p.spec.policy is None
    if p.spec.policy is not None:

        def visit(node: Any, state: GrowthState) -> None:
            if node.action_id is None:
                return
            r = recipe_for(c, o, node.action_id)
            assert set(node.branches) == {e.successor_id for e in successors(state, r)}
            for e in successors(state, r):
                visit(node.branches[e.successor_id], transition(c, state, r, e, o))

        visit(p.spec.policy, initial_state(c))


def test_closed_document_schemas_and_unregistered_successors(planned: Any) -> None:
    c, o, p = planned
    for doc in (c, p):
        assert parse_document(doc.model_dump(mode="json")) == doc
        payload = doc.model_dump(mode="json")
        payload["spec"]["fabricated_authority"] = True
        with pytest.raises(ValueError, match="document_schema_invalid"):
            parse_document(payload)
        assert schema_for_kind(doc.kind)["additionalProperties"] is False
    r = c.spec.action_catalogue[0]
    with pytest.raises(GrowthError, match="growth_undeclared_successor"):
        transition(
            c, initial_state(c), r, r.successors[0].model_copy(update={"successor_id": "new"}), o
        )


@pytest.mark.parametrize(
    "updates,code",
    [
        ({"elapsed": "9"}, "growth_deadline"),
        ({"quality": {"task": "0", "research": "1", "verification": "1"}}, "growth_quality_floor"),
        (
            {"coverage": {"task": "0", "research": "1", "verification": "1"}},
            "growth_coverage_floor",
        ),
        (
            {"queue": [GrowthWork(work_id="late", stage="task", remaining="1", deadline="0")]},
            "growth_work_deadline",
        ),
        (
            {"queue": [GrowthWork(work_id="large", stage="task", remaining="11", deadline="2")]},
            "growth_backlog_limit",
        ),
        ({"resources": {"credits": "-1"}}, "growth_resource_floor"),
        ({"model_ids": ["unregistered"]}, "growth_model_domain"),
    ],
)
def test_prefix_constraints_recomputed(planned: Any, updates: dict[str, Any], code: str) -> None:
    c, _, _ = planned
    with pytest.raises(GrowthError, match=code):
        check_state(c, initial_state(c).model_copy(update=updates))


def test_offered_completion_repair_deadlines_and_blocking_credit(planned: Any) -> None:
    c, o, _ = planned
    s = initial_state(c).model_copy(
        update={
            "queue": [GrowthWork(work_id="q", stage="verification", remaining="1", deadline="3")],
            "obligations": [
                GrowthWork(work_id="d", stage="verification", remaining="1", deadline="3")
            ],
        }
    )
    r = recipe_for(c, o, "idle")
    e = r.successors[0].model_copy(
        update={"offered_service": {"verification": "1"}, "completed_work": {"q": "1"}}
    )
    r = r.model_copy(update={"successors": [e, *r.successors[1:]]})
    after = transition(c, s, r, e, o)
    assert after.queue == [] and after.obligations == s.obligations
    assert after.completed["verification"] == "1"
    for fields, code in [
        ({"completed_work": {"phantom": "1"}}, "growth_completion_without_work"),
        ({"completed_work": {"q": "2"}}, "growth_completion_exceeds_work"),
        ({"offered_service": {"verification": "2"}}, "growth_service_overbooked"),
    ]:
        bad = e.model_copy(update=fields)
        altered = r.model_copy(update={"successors": [bad, *r.successors[1:]]})
        with pytest.raises(GrowthError, match=code):
            transition(c, s, altered, bad, o)
    c = modify(c, blocking_obligation_ids=["d"])
    prepared = step(c, o, s, "prepare")
    with pytest.raises(GrowthError, match="growth_credit_blocked_by_work"):
        step(c, o, prepared, "reuse")


def test_planner_external_charge_boundary_and_memo_are_explicit(planned: Any) -> None:
    c, o, _ = planned
    c = modify(c, planning_boundary="external-paid")
    s = initial_state(c)
    assert s.resources["credits"] == "8" and s.charges["external-planner"] == {"credits": "1"}
    search = Search(c, o, Budget(c.spec.search_limits), endpoint=F(2))
    first = search.enumerate(s)
    states = search.budget.states
    assert search.enumerate(s) == first and search.budget.states == states
    assert compare(c, o)[0].search.complete


@pytest.mark.parametrize("models", [["nominal"], ["nominal", "failure"]])
def test_scalar_backward_induction_matches_complete_contingent_policy_enumeration(
    models: list[str],
) -> None:
    c, o = example()
    c = modify(
        c,
        max_decisions=2,
        initial_state=c.spec.initial_state.model_copy(update={"model_ids": models}),
    )
    search = Search(c, o, Budget(c.spec.search_limits), endpoint=F(2))
    scalar = search.scalar(initial_state(c))
    complete = Search(c, o, Budget(c.spec.search_limits), endpoint=F(2))
    policies = complete.enumerate(initial_state(c))
    assert scalar is not None and search.budget.complete and complete.budget.complete
    assert scalar.lower == max(min(attainment(c, s) for s in p.terminals) for p in policies)
    assert scalar.upper == max(
        min(attainment(c, s, "upper") for s in p.terminals) for p in policies
    )
    check_tree(c, o, scalar.candidate.node, initial_state(c), endpoint=F(2))
    assert search.scalar(initial_state(c)) == scalar


def test_scalar_search_requires_an_explicit_endpoint() -> None:
    c, o = example()
    with pytest.raises(GrowthError, match="growth_scalar_endpoint_required"):
        Search(c, o, Budget(c.spec.search_limits)).scalar(initial_state(c))


def test_comparator_margin_requires_strict_superiority_at_the_boundary() -> None:
    c, o = example()
    # Candidate minimum 1 equals baseline upper 2/3 plus the declared 1/3 margin.
    # Equality supplies no superiority certificate; later entry cannot fund growth here.
    result = plan_growth(modify(c, comparison_margin="1/3"), o)
    assert result.spec.code == "growth_no_guaranteed_entry"
    assert result.spec.policy is None


@pytest.mark.parametrize(
    "name,digest",
    [
        ("preparation", "29507466ba74e46e5e7dada302dde508f781d6388b6a37893e2d60820019ee5c"),
        ("verification", "581769fd8e48c43faa362c0ab36fd3fd8449ee94839f7d4b9765dddf1689c4c4"),
        ("communication", "da8ac9e251ffc2cc3d0a6dc67698f42909b8a2af2b54657736df24ca2c2372fc"),
        ("all-failure", "5a8abfa1f84c9c0218885c736959f2f9b72a668b2c71cfa4570837b8995467ec"),
        ("no-advantage", "baa0d745bbd7c9e58c2b018964fa91ddfa65840dcea7cab45fa6c1e49164bfa7"),
    ],
)
def test_complete_growth_policy_and_counterexample_encodings_are_stable(
    name: str, digest: str
) -> None:
    # Bind the entire public witness, comparisons, costs, nonclaims and failure report,
    # alongside the independently computed objective oracle above.
    assert document_digest(plan_growth(*example(name))) == "sha256:" + digest


@pytest.mark.parametrize("failure", ["cost", "debt", "expiry", "withdrawal", "not-yet-valid"])
def test_inherited_capability_obligations_and_model_clock_are_rechecked(failure: str) -> None:
    c, o = example()
    r = recipe_for(c, o, "idle")
    action = cast(ActionDocument, o[r.action_digest])
    cap = cast(CapabilityDocument, o[action.spec.capability_digest])
    if failure in {"cost", "debt"}:
        update = {"cost_upper": "2"} if failure == "cost" else {"debt": ["required-repair"]}
        cap = cap.model_copy(
            update={
                "spec": cap.spec.model_copy(
                    update={"branches": [b.model_copy(update=update) for b in cap.spec.branches]}
                )
            }
        )
        o[document_digest(cap)] = cap
        action = action.model_copy(
            update={
                "spec": action.spec.model_copy(update={"capability_digest": document_digest(cap)})
            }
        )
    else:
        origin = c.spec.model_time_origin
        lifecycle = Lifecycle(
            valid_from=origin + timedelta(seconds=1) if failure == "not-yet-valid" else origin,
            valid_until=origin + timedelta(seconds=0.5 if failure == "expiry" else 6),
            withdrawn_at=origin + timedelta(seconds=1) if failure == "withdrawal" else None,
        )
        source = ResourceObservationAttestation(
            metadata=c.metadata,
            spec=ResourceObservationSpec(
                coordinate="credits",
                quantity="8",
                unit="credit",
                observed_at=lifecycle.valid_from,
                lifecycle=lifecycle,
            ),
        )
        o[document_digest(source)] = source
        action = action.model_copy(
            update={
                "spec": action.spec.model_copy(
                    update={"required_object_digests": [document_digest(source)]}
                )
            }
        )
    o[document_digest(action)] = action
    changed = r.model_copy(update={"action_digest": document_digest(action)})
    c = modify(
        c,
        action_catalogue=[changed if x == r else x for x in c.spec.action_catalogue],
        initial_state=c.spec.initial_state.model_copy(update={"live_object_digests": sorted(o)}),
    )
    if failure in {"cost", "debt"}:
        code = (
            "growth_unfunded_monetary_cost"
            if failure == "cost"
            else "growth_unaccounted_obligation"
        )
        with pytest.raises(GrowthError, match=code):
            validate_contract(c, o)
    else:
        validate_contract(c, o)
        with pytest.raises(GrowthError, match="growth_required_object_expired"):
            step(c, o, initial_state(c), "idle")


def test_arrival_burst_precedes_completion_and_fallback_is_rechecked() -> None:
    c, o = example("all-failure")
    r = recipe_for(c, o, "idle")
    e = next(e for e in r.successors if e.outcome == "failure")
    e = e.model_copy(
        update={
            "arrivals": [GrowthWork(work_id="burst", stage="task", remaining="11", deadline="3")],
            "completed_work": {"burst": "11"},
            "offered_service": {"task": "11"},
        }
    )
    r = r.model_copy(
        update={"successors": [e if x.outcome == "failure" else x for x in r.successors]}
    )
    with pytest.raises(GrowthError, match="growth_backlog_limit"):
        transition(c, initial_state(c), r, e, o)
    p = plan_growth(c, o)
    assert p.spec.safe_fallback is not None and p.spec.fallback_search.complete
    state = initial_state(c)
    result = check_tree(c, o, p.spec.safe_fallback, state, endpoint=F(c.spec.deadline))
    assert all(s.elapsed == c.spec.deadline for s in result.terminals)
    with pytest.raises(GrowthError, match="growth_plan_state_mismatch"):
        check_tree(
            c,
            o,
            p.spec.safe_fallback,
            state.model_copy(update={"resources": {"credits": "0"}}),
            endpoint=F(c.spec.deadline),
        )
    report = audit_model_boundary(c, o, state)
    assert report["model_state_digest"] == state_digest(state)
    assert not report["resource_and_time_forecasts_are_attestations"]
    changed = state.model_copy(update={"resources": {"credits": "-1"}})
    with pytest.raises(GrowthError, match="growth_resource_floor"):
        audit_model_boundary(c, o, changed)
