# SPDX-License-Identifier: Apache-2.0
"""Finite support and solver limits reject unsupported or incomplete claims."""

from typing import Any

import pytest

from collective_phase_control_fabric.v6.epistemic import Domain
from collective_phase_control_fabric.v6.epistemic_checking import reference_comparisons
from collective_phase_control_fabric.v6.epistemic_examples import epistemic_example
from collective_phase_control_fabric.v6.epistemic_planning import plan_epistemic
from collective_phase_control_fabric.v6.growth import GrowthError
from collective_phase_control_fabric.v6.models import EpistemicStep
from collective_phase_control_fabric.v6.registry import document_digest


def with_limits(d: Domain, **limits: Any) -> Domain:
    c = d.contract.model_copy(
        update={
            "spec": d.contract.spec.model_copy(
                update={
                    "search_limits": d.contract.spec.search_limits.model_copy(update=limits),
                }
            )
        }
    )
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


@pytest.mark.parametrize(
    "limit", ["max_states", "max_expansions", "max_policies", "max_depth", "max_witness_nodes"]
)
def test_each_search_limit_preserves_unknown_not_optimal(limit: str) -> None:
    p = plan_epistemic(with_limits(epistemic_example(), **{limit: 1}))
    assert not p.spec.search.complete
    assert p.spec.code in {"epistemic_search_unknown", "epistemic_incumbent"}


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("duplicate-alphabet", "epistemic_alphabet_invalid"),
        ("duplicate-row", "epistemic_kernel_invalid"),
        ("foreign-symbol", "epistemic_kernel_invalid"),
        ("missing-row", "epistemic_kernel_incomplete"),
    ],
)
def test_invalid_observation_contract_rejected(mutation: str, code: str) -> None:
    d = epistemic_example()
    updates: dict[str, Any] = {}
    if mutation == "duplicate-alphabet":
        updates["observation_alphabet"] = [*d.epistemic.spec.observation_alphabet, "red"]
    elif mutation == "duplicate-row":
        updates["kernel"] = [*d.epistemic.spec.kernel, d.epistemic.spec.kernel[0]]
    elif mutation == "foreign-symbol":
        updates["kernel"] = [
            r.model_copy(update={"observations": ["hidden"]}) for r in d.epistemic.spec.kernel
        ]
    else:
        updates["kernel"] = d.epistemic.spec.kernel[1:]
    e = d.epistemic.model_copy(update={"spec": d.epistemic.spec.model_copy(update=updates)})
    with pytest.raises(GrowthError) as exc:
        Domain(d.contract, d.objects, e, d.frontier)
    assert exc.value.code == code


def test_future_entry_epoch_cannot_be_used_as_comparator_basis() -> None:
    d = epistemic_example()
    with pytest.raises(GrowthError, match=r"^epistemic_entry_epoch_invalid$"):
        d.replay(
            [
                EpistemicStep(
                    action_id="prepare", observation="red", entry=True, comparison_history_length=1
                )
            ],
            reference_comparisons(d),
        )


def test_history_and_support_bytes_have_explicit_finite_limits() -> None:
    d = epistemic_example()
    e = d.epistemic.model_copy(
        update={"spec": d.epistemic.spec.model_copy(update={"max_history": 1})}
    )
    limited = Domain(d.contract, d.objects, e, d.frontier)
    with pytest.raises(GrowthError, match=r"^epistemic_history_budget$"):
        limited.replay([EpistemicStep(action_id="idle", observation="recorded")] * 2, [])
    e = d.epistemic.model_copy(
        update={"spec": d.epistemic.spec.model_copy(update={"max_support_bytes": 1})}
    )
    p = plan_epistemic(Domain(d.contract, d.objects, e, d.frontier))
    assert not p.spec.search.complete and p.spec.code == "epistemic_support_budget"


@pytest.mark.parametrize(
    "mapping", [{}, {"red": "recorded"}, {"red": [], "blue": "b", "recorded": "r"}]
)
def test_invalid_mask_is_a_typed_failure(mapping: Any) -> None:
    d = epistemic_example()
    with pytest.raises(GrowthError, match=r"^epistemic_channel_invalid$"):
        Domain(d.contract, d.objects, d.epistemic, d.frontier, mapping)
