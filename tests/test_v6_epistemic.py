# SPDX-License-Identifier: Apache-2.0
"""Observation noninterference, correlated supports and independently checked policies."""

from __future__ import annotations

import json
from fractions import Fraction as F

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.epistemic import Domain, canonical_support, support_digest
from collective_phase_control_fabric.v6.epistemic_checking import (
    check_epistemic_plan,
    reference_comparisons,
)
from collective_phase_control_fabric.v6.epistemic_examples import epistemic_example
from collective_phase_control_fabric.v6.epistemic_planning import compare_epistemic, plan_epistemic
from collective_phase_control_fabric.v6.information_value import difference, information_value
from collective_phase_control_fabric.v6.models import EpistemicStep, GrowthInterval
from collective_phase_control_fabric.v6.registry import document_digest, parse_document


def test_paid_probe_chooses_only_visible_history_and_checked_continuation() -> None:
    d = epistemic_example()
    p = plan_epistemic(d)
    assert p.spec.code == "epistemic_policy_found" and p.spec.search.complete
    root = p.spec.policy
    assert root is not None and root.action_id == "prepare"
    assert set(root.branches) == {"red", "blue"}
    assert root.branches["red"].action_id == "reuse"
    assert root.branches["blue"].action_id == "reuse-beta"
    assert p.spec.objective is not None and p.spec.objective.worst_entry_time == "2"
    checked = check_epistemic_plan(d, p)
    assert checked["policy_feasible"] and not checked["global_optimality_checked"]
    assert not checked["execution_authorized"]
    assert parse_document(p.model_dump(mode="json")) == p
    # Prior inspection and checking must not contaminate invocation-local report counters.
    d.controller_view(d.initial())
    assert document_digest(plan_epistemic(d)) == document_digest(p)


def test_kernel_support_keeps_theta_and_multiple_same_model_states() -> None:
    d = epistemic_example("epistemic-ambiguous")
    initial = d.initial()
    result = d.advance(initial, "prepare")["recorded"]
    assert {h.model_id for h in result} == {"alpha", "beta"}
    assert all(h.state.model_ids == [h.model_id] for h in result)
    alpha = next(h for h in result if h.model_id == "alpha")
    changed = alpha.model_copy(
        update={
            "state": alpha.state.model_copy(
                update={
                    "resources": {"credits": "5"},
                }
            )
        }
    )
    expanded = d.bounded([alpha, changed])
    assert len(expanded) == 2 and support_digest(expanded) != support_digest((alpha,))
    # The same parameter does not justify discarding a distinct resource/entry state.
    assert len(d.advance(expanded, "reuse")["recorded"]) == 2


def test_latent_actions_and_foreign_models_do_not_become_available_by_union() -> None:
    d = epistemic_example()
    with pytest.raises(g.GrowthError) as exc:
        d.advance(d.initial(), "reuse")
    assert exc.value.code == "growth_frontier_action_latent"
    h = d.initial()[0]
    wrong = h.model_copy(update={"model_id": "foreign"})
    with pytest.raises(g.GrowthError) as exc:
        d.advance((wrong,), "prepare")
    assert exc.value.code == "epistemic_model_switch"


def test_impossible_observation_and_empty_support_are_not_success() -> None:
    d = epistemic_example()
    with pytest.raises(g.GrowthError) as exc:
        d.replay([EpistemicStep(action_id="prepare", observation="debug-alpha")], [])
    assert exc.value.code == "epistemic_observation_mismatch"
    with pytest.raises(g.GrowthError) as exc:
        d.bounded([])
    assert exc.value.code == "epistemic_inconsistent_support"


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("binding", "epistemic_plan_binding"),
        ("hash", "epistemic_policy_digest"),
        ("support", "epistemic_support_tampered"),
        ("branch", "epistemic_observation_branch_missing"),
        ("entry", "epistemic_hidden_entry"),
        ("objective", "epistemic_objective_tampered"),
    ],
)
def test_checker_rejects_precise_tampering(mutation: str, code: str) -> None:
    d = epistemic_example()
    p = plan_epistemic(d)
    root = p.spec.policy
    assert root is not None and p.spec.objective is not None
    if mutation == "binding":
        p = p.model_copy(
            update={"spec": p.spec.model_copy(update={"input_digest": "sha256:" + "0" * 64})}
        )
    elif mutation == "hash":
        p = p.model_copy(
            update={"spec": p.spec.model_copy(update={"policy_digest": "sha256:" + "0" * 64})}
        )
    elif mutation == "objective":
        p = p.model_copy(
            update={
                "spec": p.spec.model_copy(
                    update={
                        "objective": p.spec.objective.model_copy(update={"worst_entry_time": "0"}),
                    }
                )
            }
        )
    else:
        root = root.model_copy(
            update=(
                {"support_digest": "sha256:" + "0" * 64}
                if mutation == "support"
                else {"branches": {"red": root.branches["red"]}}
                if mutation == "branch"
                else {"entry": True}
            )
        )
        p = p.model_copy(
            update={
                "spec": p.spec.model_copy(
                    update={
                        "policy": root,
                        "policy_digest": g.content_digest(root),
                    }
                )
            }
        )
    with pytest.raises(g.GrowthError) as exc:
        check_epistemic_plan(d, p)
    assert exc.value.code == code


def test_comparator_induction_matches_enumerated_policies() -> None:
    d = epistemic_example()
    actual, oracle = compare_epistemic(d), reference_comparisons(d)
    assert [(r.endpoint, r.lower_bound, r.upper_bound) for r in actual] == [
        (r.endpoint, r.lower_bound, r.upper_bound) for r in oracle
    ]
    assert all(r.search.complete for r in actual)


def test_information_estimands_keep_paid_physics_and_reoptimize() -> None:
    d = epistemic_example()
    v = information_value(
        d, {s: "recorded" for s in d.epistemic.spec.observation_alphabet}, ["prepare"]
    )
    assert v.spec.information_use.comparison_complete
    assert v.spec.information_use.entry_time_delta == "-1"
    assert v.spec.information_blind.spec.excluded_action_ids == []
    assert v.spec.without_sensing.spec.excluded_action_ids == ["prepare"]
    assert v.spec.full.spec.objective is not None
    assert v.spec.full.spec.objective.worst_cost == {"credits": "5"}
    assert v.spec.net_sensing.direction == "full-minus-comparator"


def test_incomplete_search_does_not_establish_information_value() -> None:
    d = epistemic_example()
    p = plan_epistemic(d)
    limited = p.model_copy(
        update={
            "spec": p.spec.model_copy(
                update={
                    "search": p.spec.search.model_copy(update={"complete": False}),
                }
            )
        }
    )
    value = difference(p, limited)
    assert value.entry_status == "unknown" and value.entry_time_delta is None
    e = d.epistemic.model_copy(
        update={"spec": d.epistemic.spec.model_copy(update={"max_support": 1})}
    )
    result = plan_epistemic(Domain(d.contract, d.objects, e, d.frontier))
    assert result.spec.code == "epistemic_support_budget"
    assert not result.spec.search.complete and result.spec.policy is None


@given(st.permutations([0, 1]))
@settings(max_examples=2, deadline=None)
def test_canonical_support_permutation_and_repeat_observation(order: list[int]) -> None:
    d = epistemic_example("epistemic-ambiguous")
    initial = d.initial()
    shuffled = canonical_support([initial[i] for i in order])
    assert support_digest(shuffled) == support_digest(initial)
    first = d.advance(shuffled, "prepare")["recorded"]
    second = d.advance(first, "idle")["recorded"]
    assert {h.model_id for h in first} == {h.model_id for h in second}
    assert all(F(h.state.elapsed) == 2 for h in second)


def test_different_kernel_cannot_check_old_plan() -> None:
    d = epistemic_example()
    p = plan_epistemic(d)
    e = d.epistemic.model_copy(
        update={
            "spec": d.epistemic.spec.model_copy(
                update={
                    "kernel": [
                        r.model_copy(update={"observations": ["recorded"]})
                        for r in d.epistemic.spec.kernel
                    ],
                }
            )
        }
    )
    assert document_digest(e) != document_digest(d.epistemic)
    with pytest.raises(g.GrowthError) as exc:
        check_epistemic_plan(Domain(d.contract, d.objects, e, d.frontier), p)
    assert exc.value.code == "epistemic_plan_binding"


def test_hidden_favorable_capacity_does_not_trigger_common_entry() -> None:
    d = epistemic_example()
    h = d.initial()[0]
    optimistic = h.model_copy(
        update={
            "state": h.state.model_copy(
                update={
                    "capacities": {
                        k: GrowthInterval(lower="100", upper="100") for k in h.state.capacities
                    },
                }
            )
        }
    )
    with pytest.raises(g.GrowthError) as exc:
        d.mark_entry((h, optimistic), [])
    assert exc.value.code == "epistemic_hidden_entry"


def test_bijective_parameter_renaming_preserves_optimum() -> None:
    d = epistemic_example()
    c = type(d.contract).model_validate_json(
        json.dumps(d.contract.model_dump(mode="json"))
        .replace('"alpha"', '"theta-x"')
        .replace('"beta"', '"theta-y"')
    )
    assert d.frontier is not None
    f = type(d.frontier).model_validate_json(
        json.dumps(d.frontier.model_dump(mode="json"))
        .replace('"alpha"', '"theta-x"')
        .replace('"beta"', '"theta-y"')
    )
    f = f.model_copy(
        update={"spec": f.spec.model_copy(update={"contract_digest": document_digest(c)})}
    )
    e = type(d.epistemic).model_validate_json(
        json.dumps(d.epistemic.model_dump(mode="json"))
        .replace('"alpha"', '"theta-x"')
        .replace('"beta"', '"theta-y"')
    )
    e = e.model_copy(
        update={
            "spec": e.spec.model_copy(
                update={
                    "growth_contract_digest": document_digest(c),
                    "frontier_digest": document_digest(f),
                }
            )
        }
    )
    renamed = Domain(c, d.objects, e, f)
    a, b = plan_epistemic(d), plan_epistemic(renamed)
    assert a.spec.search.complete and b.spec.search.complete
    assert a.spec.objective == b.spec.objective
    assert a.spec.input_digest != b.spec.input_digest
