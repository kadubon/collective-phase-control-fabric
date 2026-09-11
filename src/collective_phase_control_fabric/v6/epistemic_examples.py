# SPDX-License-Identifier: Apache-2.0
"""Unsigned exact examples. No provider calls, receipts, test keys or live stores."""

from __future__ import annotations

from typing import cast

from collective_phase_control_fabric.v6.epistemic import Domain
from collective_phase_control_fabric.v6.frontier_examples import frontier_example
from collective_phase_control_fabric.v6.growth_examples import metadata
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    CapabilityDocument,
    EpistemicContract,
    EpistemicContractSpec,
    EpistemicKernelRow,
    EpistemicStep,
    WorkflowPrimitiveBinding,
    WorkflowRequest,
    WorkflowRequestSpec,
)
from collective_phase_control_fabric.v6.registry import document_digest


def epistemic_example(name: str = "epistemic-probe") -> Domain:
    from collective_phase_control_fabric.v6.growth import require

    require(
        name in {"epistemic-probe", "epistemic-ambiguous", "epistemic-verifier"},
        "epistemic_example_unknown",
    )
    c, objects, frontier = frontier_example(
        "frontier-verifier" if name == "epistemic-verifier" else "frontier-research"
    )
    original = next(
        r
        for r in c.spec.action_catalogue
        if cast(ActionDocument, objects[r.action_digest]).spec.action_id == "reuse"
    )
    action = cast(ActionDocument, objects[original.action_digest])
    other = action.model_copy(
        update={
            "metadata": metadata("reuse-beta"),
            "spec": action.spec.model_copy(update={"action_id": "reuse-beta"}),
        }
    )
    objects[document_digest(other)] = other
    recipes = []
    for recipe in [
        *c.spec.action_catalogue,
        original.model_copy(update={"action_digest": document_digest(other)}),
    ]:
        action_id = cast(ActionDocument, objects[recipe.action_digest]).spec.action_id
        effects = []
        for effect in recipe.successors:
            models = [m for m in effect.applicable_model_ids if m != "nominal"]
            if "nominal" in effect.applicable_model_ids:
                models.extend(["alpha", "beta"])
            if action_id in {"reuse", "reuse-beta"} and effect.outcome == "success":
                models = ["alpha" if action_id == "reuse" else "beta"]
                # Wrong research direction still pays the full primitive cost and time.
                effects.append(
                    effect.model_copy(
                        update={
                            "successor_id": action_id + ":wrong-direction",
                            "outcome": "partial",
                            "applicable_model_ids": ["beta" if action_id == "reuse" else "alpha"],
                            "capacity_delta": {},
                            "evidence_added": {},
                        }
                    )
                )
            effects.append(
                effect.model_copy(
                    update={
                        "successor_id": action_id + ":" + effect.outcome,
                        "applicable_model_ids": models,
                    }
                )
            )
        recipes.append(recipe.model_copy(update={"successors": effects}))
    c = c.model_copy(
        update={
            "spec": c.spec.model_copy(
                update={
                    "action_catalogue": recipes,
                    "model_catalogue": ["alpha", "beta", "partial", "failure", "timeout"],
                    "initial_state": c.spec.initial_state.model_copy(
                        update={
                            "model_ids": ["alpha", "beta"],
                            "live_object_digests": sorted(objects),
                        }
                    ),
                }
            )
        }
    )
    binding = next(b for b in frontier.spec.bindings if b.action_id == "reuse")
    rules = [
        r.model_copy(
            update={
                "required_model_ids": ["alpha", "beta"],
                "activated_action_ids": r.activated_action_ids
                + (["reuse-beta"] if "reuse" in r.activated_action_ids else []),
            }
        )
        for r in frontier.spec.activation_rules
    ]
    # If research produces a later activation, either checked research direction can do so.
    rules.extend(
        r.model_copy(
            update={
                "rule_id": r.rule_id + "-beta",
                "producer_action_id": "reuse-beta",
                "producer_successor_id": "reuse-beta:success",
            }
        )
        for r in list(rules)
        if r.producer_action_id == "reuse"
    )
    frontier = frontier.model_copy(
        update={
            "spec": frontier.spec.model_copy(
                update={
                    "contract_digest": document_digest(c),
                    "activation_rules": rules,
                    "latent_action_ids": sorted([*frontier.spec.latent_action_ids, "reuse-beta"]),
                    "bindings": [
                        *frontier.spec.bindings,
                        binding.model_copy(
                            update={
                                "action_id": "reuse-beta",
                                "action_digest": document_digest(other),
                            }
                        ),
                    ],
                }
            )
        }
    )
    rows = []
    for recipe in recipes:
        action_id = cast(ActionDocument, objects[recipe.action_digest]).spec.action_id
        for effect in recipe.successors:
            for theta in effect.applicable_model_ids:
                signal = (
                    ("red" if theta == "alpha" else "blue")
                    if (
                        action_id == "prepare"
                        and theta in {"alpha", "beta"}
                        and name != "epistemic-ambiguous"
                    )
                    else "recorded"
                )
                rows.append(
                    EpistemicKernelRow(
                        model_id=theta,
                        action_digest=recipe.action_digest,
                        successor_id=effect.successor_id,
                        observations=[signal],
                    )
                )
    e = EpistemicContract(
        metadata=metadata(name),
        spec=EpistemicContractSpec(
            growth_contract_digest=document_digest(c),
            frontier_digest=document_digest(frontier),
            observation_alphabet=["blue", "recorded", "red"],
            kernel=rows,
        ),
    )
    return Domain(c, objects, e, frontier)


def workflow_request(domain: Domain, history: list[EpistemicStep] | None = None) -> WorkflowRequest:
    library = []
    for recipe in domain.contract.spec.action_catalogue:
        action = cast(ActionDocument, domain.objects[recipe.action_digest])
        cap = cast(CapabilityDocument, domain.objects[action.spec.capability_digest])
        library.append(
            WorkflowPrimitiveBinding(
                action_digest=recipe.action_digest,
                capability_digest=action.spec.capability_digest,
                input_schema_digest=cap.spec.output_schema_digest,
                output_schema_digest=cap.spec.output_schema_digest,
                execution_policy_digest=cap.spec.execution_policy_digest,
            )
        )
    return WorkflowRequest(
        metadata=metadata("workflow-request"),
        spec=WorkflowRequestSpec(
            input_digest=domain.digest(),
            history=history or [],
            library=library,
            input_schema_digest=library[0].input_schema_digest,
            output_schema_digest=library[0].output_schema_digest,
            target_capacities={"task": "4", "research": "4"},
            maximum_spent={"credits": "8"},
            formation_charges={
                k: {"credits": "1/10"} for k in ("construction", "search", "checking", "transport")
            },
            formation_duration="0",
            per_use_charges={k: {"credits": "1/10"} for k in ("maintenance", "application")},
            per_use_duration="0",
            max_primitive_steps=4,
            max_candidates=32,
        ),
    )


def integrated_example() -> dict[str, object]:
    from collective_phase_control_fabric.v6.catalogue_revision import (
        propose_catalogue,
        replan_catalogue,
    )
    from collective_phase_control_fabric.v6.epistemic_checking import (
        check_epistemic_plan,
        reference_comparisons,
    )
    from collective_phase_control_fabric.v6.epistemic_planning import plan_epistemic
    from collective_phase_control_fabric.v6.synthesis import synthesize

    domain = epistemic_example()
    initial = domain.controller_view(domain.initial())
    plan = plan_epistemic(domain)
    checked = check_epistemic_plan(domain, plan)
    history = [EpistemicStep(action_id="prepare", observation="red")]
    # The signal is explicitly synthetic, never written to an admission/receipt store.
    after = domain.replay(history, reference_comparisons(domain))
    request = workflow_request(domain, history)
    compiled = synthesize(domain, request)
    if not compiled.spec.candidates:
        return {
            "code": compiled.spec.code,
            "synthesis": compiled.model_dump(mode="json"),
            "synthetic": True,
            "execution_authorized": False,
        }
    candidate, certificate = compiled.spec.candidates[0], compiled.spec.certificates[0]
    revision = propose_catalogue(domain, request, compiled, candidate)
    replanned = replan_catalogue(
        domain, request, candidate, certificate, revision, model_only_opt_in=True
    )
    return {
        "code": "epistemic_composition_example",
        "synthetic": True,
        "initial": initial,
        "plan": plan.model_dump(mode="json"),
        "policy_check": checked,
        "synthetic_observation": "red",
        "after_observation": domain.controller_view(after),
        "synthesis": compiled.model_dump(mode="json"),
        "revision": revision.model_dump(mode="json"),
        "replanned": replanned,
        "observations_written": [],
        "execution_authorized": False,
        "empirical_attribution": "undetermined",
    }
