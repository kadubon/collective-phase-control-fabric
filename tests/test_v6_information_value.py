# SPDX-License-Identifier: Apache-2.0
"""Matched physical processes distinguish useful signals from expensive sensing."""

import json
from fractions import Fraction as F
from typing import Any, cast

import pytest

from collective_phase_control_fabric.v6.epistemic import Domain
from collective_phase_control_fabric.v6.epistemic_examples import epistemic_example
from collective_phase_control_fabric.v6.information_value import information_value
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    CapabilityDocument,
    GrowthContract,
)
from collective_phase_control_fabric.v6.registry import document_digest


def rebound(d: Domain, c: GrowthContract) -> Domain:
    assert d.frontier is not None
    f = d.frontier.model_copy(
        update={
            "spec": d.frontier.spec.model_copy(
                update={
                    "contract_digest": document_digest(c),
                }
            )
        }
    )
    e = d.epistemic.model_copy(
        update={
            "spec": d.epistemic.spec.model_copy(
                update={
                    "growth_contract_digest": document_digest(c),
                    "frontier_digest": document_digest(f),
                }
            )
        }
    )
    return Domain(c, d.objects, e, f)


def expensive_probe(d: Domain) -> Domain:
    """Declare a different immutable synthetic envelope, without admitting it."""
    recipe = d.recipes["prepare"]
    action = cast(ActionDocument, d.objects[recipe.action_digest])
    cap = cast(CapabilityDocument, d.objects[action.spec.capability_digest])
    new_cap = cap.model_copy(
        update={
            "spec": cap.spec.model_copy(
                update={
                    "branches": [
                        b.model_copy(update={"resource_delta_lower": {"credits": "-99"}})
                        for b in cap.spec.branches
                    ],
                }
            )
        }
    )
    new_action = action.model_copy(
        update={
            "spec": action.spec.model_copy(
                update={
                    "capability_digest": document_digest(new_cap),
                }
            )
        }
    )
    mapping = {
        document_digest(cap): document_digest(new_cap),
        document_digest(action): document_digest(new_action),
    }

    def replace(value: Any) -> Any:
        raw = json.dumps(value.model_dump(mode="json"))
        for old, new in mapping.items():
            raw = raw.replace(old, new)
        return type(value).model_validate_json(raw)

    objects = {k: v for k, v in d.objects.items() if k not in mapping}
    objects.update({document_digest(x): x for x in (new_cap, new_action)})
    c = replace(d.contract)
    f = replace(d.frontier)
    f = f.model_copy(
        update={"spec": f.spec.model_copy(update={"contract_digest": document_digest(c)})}
    )
    e = replace(d.epistemic)
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
    return Domain(c, objects, e, f)


@pytest.mark.parametrize("mode", ["overpriced", "irrelevant", "uninformative"])
def test_discrimination_is_not_itself_growth(mode: str) -> None:
    d = epistemic_example("epistemic-ambiguous" if mode == "uninformative" else "epistemic-probe")
    if mode == "overpriced":
        d = expensive_probe(d)
    recipes = []
    for recipe in d.contract.spec.action_catalogue:
        effects = recipe.successors
        if mode == "overpriced" and recipe == d.recipes["prepare"]:
            effects = [
                s.model_copy(update={"charges": {"generation": {"credits": "99"}}}) for s in effects
            ]
        if mode == "irrelevant" and recipe in (d.recipes["reuse"], d.recipes["reuse-beta"]):
            success = next(s for s in effects if s.outcome == "success")
            effects = [
                s.model_copy(
                    update={
                        "capacity_delta": success.capacity_delta,
                        "evidence_added": success.evidence_added,
                    }
                )
                if s.successor_id.endswith("wrong-direction")
                else s
                for s in effects
            ]
        recipes.append(recipe.model_copy(update={"successors": effects}))
    c = d.contract.model_copy(
        update={
            "spec": d.contract.spec.model_copy(
                update={"action_catalogue": recipes, "max_decisions": 3}
            )
        }
    )
    d = rebound(d, c)
    value = information_value(
        d, {s: "recorded" for s in d.epistemic.spec.observation_alphabet}, ["prepare"]
    )
    assert all(
        p.spec.search.complete
        for p in (value.spec.full, value.spec.information_blind, value.spec.without_sensing)
    )
    if mode == "overpriced":
        assert value.spec.full.spec.objective == value.spec.without_sensing.spec.objective
        root = value.spec.full.spec.policy
        assert root is None or root.action_id != "prepare"
    else:
        assert value.spec.full.spec.objective == value.spec.information_blind.spec.objective
        delta = value.spec.information_use
        assert delta.entry_status in {"both", "neither"}
        if delta.entry_status == "both":
            assert F(delta.entry_time_delta or "0") == 0
            assert F(delta.terminal_attainment_delta or "0") == 0
