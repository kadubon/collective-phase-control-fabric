# SPDX-License-Identifier: Apache-2.0
"""Checked procedural reuse, no macro step discount or authority manufacture."""

from __future__ import annotations

from fractions import Fraction as F
from typing import Any

import pytest

from collective_phase_control_fabric.v6 import catalogue_revision as revisions
from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6 import synthesis as compiler
from collective_phase_control_fabric.v6.catalogue_revision import (
    propose_catalogue,
    replan_catalogue,
)
from collective_phase_control_fabric.v6.composition import (
    check_composition,
    formation_domain,
    ir_members,
)
from collective_phase_control_fabric.v6.epistemic import Domain
from collective_phase_control_fabric.v6.epistemic_checking import reference_comparisons
from collective_phase_control_fabric.v6.epistemic_examples import (
    epistemic_example,
    workflow_request,
)
from collective_phase_control_fabric.v6.epistemic_planning import plan_epistemic
from collective_phase_control_fabric.v6.models import EpistemicStep
from collective_phase_control_fabric.v6.registry import document_digest, parse_document
from collective_phase_control_fabric.v6.synthesis import synthesize
from tests.test_v6_information_value import rebound


@pytest.fixture(scope="module")
def compiled() -> tuple[Any, ...]:
    domain = epistemic_example()
    request = workflow_request(domain, [EpistemicStep(action_id="prepare", observation="red")])
    result = synthesize(domain, request)
    assert result.spec.candidates
    return domain, request, result, result.spec.candidates[0], result.spec.certificates[0]


@pytest.mark.parametrize(
    "change,code",
    [
        ({"max_candidates": 1}, "composition_search_unknown"),
        ({"max_primitive_steps": 1}, "composition_no_candidate"),
        ({"target_capacities": {"task": "100"}}, "composition_no_candidate"),
    ],
)
def test_failed_and_bounded_synthesis_preserve_formation_costs(
    compiled: tuple[Any, ...], change: dict[str, Any], code: str
) -> None:
    d, request, *_ = compiled
    request = request.model_copy(update={"spec": request.spec.model_copy(update=change)})
    result = synthesize(d, request)
    assert result.spec.code == code
    assert result.spec.formation_costs_incurred
    assert len(result.spec.proposed_epistemic_contract.spec.cost_events) == 1
    if code == "composition_search_unknown":
        assert result.spec.reuse_without_formation_preferred is None
        assert not result.spec.search.complete
    else:
        assert result.spec.candidates == [] and result.spec.search.complete
        assert result.spec.reuse_without_formation_preferred is True


def test_reported_search_counters_cannot_erase_reserved_synthesis_work(
    compiled: tuple[Any, ...],
) -> None:
    d, r, synthesis, candidate, certificate = compiled
    forged = synthesis.model_copy(
        update={
            "spec": synthesis.spec.model_copy(
                update={
                    "search": synthesis.spec.search.model_copy(update={"expansions": 0}),
                }
            )
        }
    )
    revision = propose_catalogue(d, r, forged, candidate)
    assert (
        revision.spec.cumulative_synthesis_expansions
        == d.contract.spec.search_limits.max_expansions
    )
    bad = revision.model_copy(
        update={
            "spec": revision.spec.model_copy(
                update={
                    "cumulative_synthesis_expansions": 0,
                }
            )
        }
    )
    with pytest.raises(g.GrowthError, match=r"^catalogue_synthesis_quota$"):
        replan_catalogue(d, r, candidate, certificate, bad, model_only_opt_in=True)


def test_second_checked_episode_preserves_parent_costs_and_work(compiled: tuple[Any, ...]) -> None:
    d, r, result, candidate, _ = compiled
    parent = propose_catalogue(d, r, result, candidate)
    next_domain = formation_domain(d, r)
    request = workflow_request(next_domain, r.spec.history)
    request = request.model_copy(
        update={
            "spec": request.spec.model_copy(
                update={
                    "formation_charges": {
                        k: {"credits": "1/100"} for k in request.spec.formation_charges
                    },
                    "per_use_charges": {
                        k: {"credits": "1/100"} for k in request.spec.per_use_charges
                    },
                }
            )
        }
    )
    compiled_next = synthesize(next_domain, request)
    assert compiled_next.spec.candidates
    selected = compiled_next.spec.candidates[0]
    revision = propose_catalogue(next_domain, request, compiled_next, selected, parent=parent)
    assert revision.spec.revision_number == 2
    assert (
        revision.spec.cumulative_synthesis_expansions
        == 2 * d.contract.spec.search_limits.max_expansions
    )
    assert (
        revision.spec.proposed_epistemic_contract.spec.cost_events[0]
        == next_domain.epistemic.spec.cost_events[0]
    )
    with pytest.raises(g.GrowthError, match=r"^catalogue_parent_missing$"):
        propose_catalogue(next_domain, request, compiled_next, selected)
    bad_parent = parent.model_copy(
        update={
            "spec": parent.spec.model_copy(
                update={
                    "cumulative_synthesis_expansions": 0,
                }
            )
        }
    )
    with pytest.raises(g.GrowthError, match=r"^catalogue_parent_mismatch$"):
        propose_catalogue(next_domain, request, compiled_next, selected, parent=bad_parent)


def test_checked_incumbent_survives_new_search_exhaustion(
    compiled: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    d, r, result, candidate, certificate = compiled
    revision = propose_catalogue(d, r, result, candidate)
    p = plan_epistemic(formation_domain(d, r), r.spec.history)
    exhausted = p.model_copy(
        update={
            "spec": p.spec.model_copy(
                update={
                    "policy": None,
                    "policy_digest": None,
                    "objective": None,
                    "search": p.spec.search.model_copy(update={"complete": False}),
                }
            )
        }
    )
    # Replace only the new search outcome; admission and independent checking remain real.
    monkeypatch.setattr(revisions, "plan_epistemic", lambda *_: exhausted)
    output = replan_catalogue(d, r, candidate, certificate, revision, model_only_opt_in=True)
    assert output["plan"]["spec"]["code"] == "epistemic_incumbent"
    assert not output["plan"]["spec"]["search"]["complete"]
    assert output["policy_check"]["policy_feasible"]
    assert not output["policy_check"]["global_optimality_checked"]


def test_synthesis_support_exhaustion_and_invalid_history_are_distinct(
    compiled: tuple[Any, ...],
) -> None:
    d, r, *_ = compiled
    e = d.epistemic.model_copy(
        update={"spec": d.epistemic.spec.model_copy(update={"max_support": 1})}
    )
    small = Domain(d.contract, d.objects, e, d.frontier)
    result = synthesize(small, workflow_request(small))
    assert result.spec.code == "composition_search_unknown" and not result.spec.search.complete
    assert result.spec.formation_costs_incurred and result.spec.candidates == []
    bad = r.model_copy(
        update={
            "spec": r.spec.model_copy(
                update={
                    "history": [EpistemicStep(action_id="prepare", observation="impossible")],
                }
            )
        }
    )
    with pytest.raises(g.GrowthError, match=r"^epistemic_observation_mismatch$"):
        synthesize(d, bad)


def test_checker_exhaustion_cannot_accept_an_unchecked_candidate(
    compiled: tuple[Any, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    d, r, *_ = compiled

    def exhausted(*_: Any) -> Any:
        raise g.GrowthError("composition_check_budget")

    monkeypatch.setattr(compiler, "check_composition", exhausted)
    result = synthesize(d, r)
    assert result.spec.code == "composition_search_unknown"
    assert not result.spec.search.complete and result.spec.candidates == []
    assert result.spec.certificates == [] and result.spec.formation_costs_incurred


def test_no_funded_primitive_or_composite_policy_is_not_a_reuse_advantage() -> None:
    d = epistemic_example()
    c = d.contract.model_copy(
        update={"spec": d.contract.spec.model_copy(update={"max_decisions": 1})}
    )
    d = rebound(d, c)
    result = synthesize(d, workflow_request(d))
    assert result.spec.search.complete and result.spec.code == "composition_no_candidate"
    assert result.spec.existing_primitive_alternative.spec.objective is None
    assert result.spec.reuse_without_formation_preferred is None


def test_compiler_creates_new_name_and_independent_finite_certificate(
    compiled: tuple[Any, ...],
) -> None:
    d, r, result, candidate, certificate = compiled
    assert candidate.spec.workflow_id not in d.recipes
    assert candidate.spec.expanded_primitive_steps == 2
    assert certificate == check_composition(d, r, candidate)
    assert certificate.spec.objective.worst_cost == {"credits": "28/5"}
    assert certificate.spec.acceptance == "finite-model-domain-only"
    assert not certificate.spec.capability_admitted and not certificate.spec.execution_authorized
    assert result.spec.reuse_without_formation_preferred is True
    assert parse_document(certificate.model_dump(mode="json")) == certificate


def test_copy_on_write_revision_replans_checked_expanded_policy(compiled: tuple[Any, ...]) -> None:
    d, r, result, candidate, certificate = compiled
    before = [document_digest(x) for x in (d.contract, d.epistemic, d.frontier)]
    revision = propose_catalogue(d, r, result, candidate)
    replayed = replan_catalogue(d, r, candidate, certificate, revision, model_only_opt_in=True)
    assert replayed["selected_workflow_digest"] == document_digest(candidate)
    assert replayed["expanded_primitive_steps"] == 2
    assert replayed["policy_check"]["policy_feasible"]
    assert before == [document_digest(x) for x in (d.contract, d.epistemic, d.frontier)]
    assert not replayed["signed_history_modified"] and not replayed["capability_admitted"]
    with pytest.raises(g.GrowthError, match=r"^catalogue_model_only_opt_in_required$"):
        replan_catalogue(d, r, candidate, certificate, revision)


def test_costs_and_full_frontier_history_are_carried(compiled: tuple[Any, ...]) -> None:
    d, r, _, _, _ = compiled
    original = d.replay(r.spec.history, reference_comparisons(d))
    charged = formation_domain(d, r)
    after = charged.replay(r.spec.history, reference_comparisons(charged))
    assert len(original) == len(after) == 1
    a, b = original[0].state, after[0].state
    assert F(a.resources["credits"]) - F(b.resources["credits"]) == F("3/5")
    assert F(b.spent["credits"]) - F(a.spent["credits"]) == F("3/5")
    assert a.elapsed == b.elapsed and a.queue == b.queue and a.obligations == b.obligations
    assert a.activation_lineage == b.activation_lineage
    assert a.activation_depth == b.activation_depth == 1
    assert after[0].primitive_steps == 1


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("expanded_primitive_steps", 1, "composition_primitive_budget"),
        ("expires", "999", "composition_constituent_tampered"),
        ("workflow_id", "self-improved", "composition_ir_identity"),
        ("constituent_digests", [], "composition_constituent_tampered"),
        ("checked_domain_digest", "sha256:" + "0" * 64, "composition_candidate_binding"),
    ],
)
def test_altered_certificate_inputs_fail_at_specific_boundary(
    compiled: tuple[Any, ...], field: str, value: Any, code: str
) -> None:
    d, r, _, candidate, _ = compiled
    altered = candidate.model_copy(
        update={"spec": candidate.spec.model_copy(update={field: value})}
    )
    with pytest.raises(g.GrowthError) as exc:
        check_composition(d, r, altered)
    assert exc.value.code == code


def test_missing_formation_category_and_bad_type_are_not_accepted(
    compiled: tuple[Any, ...],
) -> None:
    d, r, _, candidate, _ = compiled
    request = r.model_copy(update={"spec": r.spec.model_copy(update={"formation_charges": {}})})
    with pytest.raises(g.GrowthError, match=r"^composition_costs_missing$"):
        formation_domain(d, request)
    library = [
        b.model_copy(update={"input_schema_digest": "sha256:" + "0" * 64}) for b in r.spec.library
    ]
    request = r.model_copy(update={"spec": r.spec.model_copy(update={"library": library})})
    charged = formation_domain(d, request)
    altered = candidate.model_copy(
        update={
            "spec": candidate.spec.model_copy(
                update={
                    "request_digest": document_digest(request),
                    "checked_domain_digest": charged.digest(),
                    "constituent_digests": sorted(
                        set(candidate.spec.constituent_digests) | {"sha256:" + "0" * 64}
                    ),
                }
            )
        }
    )
    with pytest.raises(g.GrowthError, match=r"^composition_interface_type$"):
        check_composition(d, request, altered)


def test_self_reference_is_rejected_before_hashing(compiled: tuple[Any, ...]) -> None:
    _, _, _, candidate, _ = compiled
    node = candidate.spec.ir.model_copy(deep=True)
    node.branches["cycle"] = node
    with pytest.raises(g.GrowthError, match=r"^composition_grammar_bound$"):
        ir_members(node)


def test_catalogue_cannot_substitute_cached_acceptance_or_reset_parent(
    compiled: tuple[Any, ...],
) -> None:
    d, r, result, candidate, certificate = compiled
    revision = propose_catalogue(d, r, result, candidate)
    bad = revision.model_copy(
        update={"spec": revision.spec.model_copy(update={"primitive_step_limit": 16})}
    )
    with pytest.raises(g.GrowthError, match=r"^catalogue_revision_binding$"):
        replan_catalogue(d, r, candidate, certificate, bad, model_only_opt_in=True)
    bad_result = result.model_copy(
        update={"spec": result.spec.model_copy(update={"certificates": []})}
    )
    with pytest.raises(g.GrowthError, match=r"^catalogue_certificate_tampered$"):
        propose_catalogue(d, r, bad_result, candidate)


def test_flattened_macro_retains_all_primitive_steps_and_costs(compiled: tuple[Any, ...]) -> None:
    d, r, _, candidate, certificate = compiled
    charged = formation_domain(d, r)
    comparisons = reference_comparisons(charged, r.spec.history)
    support = charged.replay(r.spec.history, reference_comparisons(charged))
    node = candidate.spec.ir
    count = 0
    while node.action_id is not None:
        if node.entry:
            support = charged.mark_entry(support, comparisons)
        branches = charged.advance(support, node.action_id)
        assert set(branches) == {"recorded"}
        support, node = branches["recorded"], node.branches["recorded"]
        count += 1
    assert count == certificate.spec.primitive_steps == 2
    assert all(h.primitive_steps == 3 and F(h.state.elapsed) == 3 for h in support)
    assert all(h.state.spent == certificate.spec.objective.worst_cost for h in support)
