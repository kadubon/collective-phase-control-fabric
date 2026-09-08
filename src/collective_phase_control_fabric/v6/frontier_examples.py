# SPDX-License-Identifier: Apache-2.0
"""Declared synthetic finite games; these documents are unsigned model inputs."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, cast

from collective_phase_control_fabric.v6.canonical import canonical_bytes
from collective_phase_control_fabric.v6.growth import plan_growth
from collective_phase_control_fabric.v6.growth_examples import example, metadata
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    CapabilityDocument,
    Document,
    ExecutionPolicy,
    ExecutionPolicySpec,
    GrowthActivationRule,
    GrowthCapabilityFrontier,
    GrowthCapabilityFrontierSpec,
    GrowthContract,
    GrowthFrontierBinding,
    GrowthWork,
    Lifecycle,
)
from collective_phase_control_fabric.v6.registry import document_digest

SCENARIOS = (
    "frontier-research",
    "frontier-verifier",
    "frontier-failure",
    "frontier-useless",
    "frontier-chain",
    "frontier-cycle",
    "frontier-comparator",
    "frontier-no-entry",
)


def frontier_example(
    name: str = "frontier-chain",
) -> tuple[GrowthContract, dict[str, Document], GrowthCapabilityFrontier]:
    if name not in SCENARIOS:
        raise ValueError("growth_example_unknown")
    c, objects = example("verification" if name == "frontier-verifier" else "preparation")
    first_cap = next(x for x in objects.values() if isinstance(x, CapabilityDocument))
    execution = ExecutionPolicy(
        metadata=metadata("frontier-model-execution-policy"),
        spec=ExecutionPolicySpec(
            execution_policy_id="frontier-model-only",
            allowed_image_digests=[first_cap.spec.image_digest],
            timeout_seconds=10,
            stdout_limit=4096,
            stderr_limit=4096,
            maximum_input_bytes=4096,
            maximum_output_bytes=16384,
            network_policy="none",
            filesystem_policy="none",
        ),
    )
    objects[document_digest(execution)] = execution
    recipes = []
    bindings = []
    for old in c.spec.action_catalogue:
        action = cast(ActionDocument, objects.pop(old.action_digest))
        cap = cast(CapabilityDocument, objects.pop(action.spec.capability_digest))
        if name == "frontier-verifier" and action.spec.action_id == "prepare":
            cap = cap.model_copy(
                update={
                    "spec": cap.spec.model_copy(
                        update={
                            "branches": [
                                b.model_copy(update={"verification_load_upper": "3"})
                                for b in cap.spec.branches
                            ]
                        }
                    )
                }
            )
        cap = cap.model_copy(
            update={
                "spec": cap.spec.model_copy(
                    update={"execution_policy_digest": document_digest(execution)}
                )
            }
        )
        action = action.model_copy(
            update={
                "spec": action.spec.model_copy(update={"capability_digest": document_digest(cap)})
            }
        )
        objects.update({document_digest(d): d for d in (cap, action)})
        recipe = old.model_copy(update={"action_digest": document_digest(action)})
        action_id = action.spec.action_id
        if name == "frontier-comparator" and action_id == "prepare":
            recipe = recipe.model_copy(update={"interactions": ["discovery"]})
        if name == "frontier-comparator" and action_id == "serial":
            success = recipe.successors[0]
            recipe = recipe.model_copy(
                update={
                    "successors": [
                        success.model_copy(
                            update={"evidence_added": {**success.evidence_added, "calibrated": "5"}}
                        ),
                        *recipe.successors[1:],
                    ]
                }
            )
        if name == "frontier-verifier":
            successors = list(recipe.successors)
            success = successors[0]
            if action_id == "prepare":
                success = success.model_copy(
                    update={
                        "arrivals": [
                            GrowthWork(
                                work_id="verification-queue",
                                stage="verification",
                                remaining="3",
                                deadline="3",
                            )
                        ]
                    }
                )
            if action_id == "reuse":
                success = success.model_copy(
                    update={
                        "offered_service": {"verification": "3"},
                        "completed_work": {"verification-queue": "3"},
                    }
                )
            recipe = recipe.model_copy(update={"successors": [success, *successors[1:]]})
        if name in {"frontier-useless", "frontier-cycle"} and action_id == "greedy":
            recipe = recipe.model_copy(
                update={
                    "successors": [
                        e.model_copy(update={"capacity_delta": {}}) for e in recipe.successors
                    ]
                }
            )
        recipes.append(recipe)
        bindings.append(
            GrowthFrontierBinding(
                action_id=action_id,
                action_digest=document_digest(action),
                capability_digest=document_digest(cap),
                execution_policy_digest=document_digest(execution),
                output_schema_digest=cap.spec.output_schema_digest,
                lifecycle=Lifecycle(
                    valid_from=c.spec.model_time_origin,
                    valid_until=c.spec.model_time_origin + timedelta(seconds=6),
                ),
            )
        )
    if name == "frontier-useless":
        original = next(b for b in bindings if b.action_id == "greedy")
        recipe = next(r for r in recipes if r.action_digest == original.action_digest)
        action = cast(ActionDocument, objects[original.action_digest])
        for action_id in ("unused-candidate-1", "unused-candidate-2"):
            extra = action.model_copy(
                update={"spec": action.spec.model_copy(update={"action_id": action_id})}
            )
            digest = document_digest(extra)
            objects[digest] = extra
            recipes.append(
                recipe.model_copy(
                    update={
                        "action_digest": digest,
                        "successors": [
                            e.model_copy(update={"successor_id": f"{action_id}:{e.outcome}"})
                            for e in recipe.successors
                        ],
                    }
                )
            )
            bindings.append(
                original.model_copy(update={"action_id": action_id, "action_digest": digest})
            )
    c = c.model_copy(
        update={
            "spec": c.spec.model_copy(
                update={
                    "action_catalogue": recipes,
                    "initial_state": c.spec.initial_state.model_copy(
                        update={"live_object_digests": sorted(objects)}
                    ),
                }
            )
        }
    )
    if name in {"frontier-failure", "frontier-no-entry"}:
        models = ["nominal", "failure", "timeout"] if name == "frontier-failure" else ["failure"]
        c = c.model_copy(
            update={
                "spec": c.spec.model_copy(
                    update={
                        "initial_state": c.spec.initial_state.model_copy(
                            update={"model_ids": models}
                        ),
                        "max_decisions": 3 if name == "frontier-failure" else 5,
                    }
                )
            }
        )
    if name == "frontier-comparator":
        c = c.model_copy(
            update={
                "spec": c.spec.model_copy(
                    update={
                        "comparators": [
                            c.spec.comparators[0].model_copy(
                                update={"excluded_interactions": ["discovery"]}
                            )
                        ]
                    }
                )
            }
        )
    latent = {"reuse", "continue"}
    edges = [("prepare", "reuse"), ("reuse", "continue")]
    if name == "frontier-research":
        latent, edges = {"reuse"}, [("prepare", "reuse")]
    elif name == "frontier-verifier":
        latent = {"verifier", "reuse", "continue"}
        edges = [("prepare", "verifier"), ("verifier", "reuse"), ("reuse", "continue")]
    elif name in {"frontier-useless", "frontier-cycle"}:
        latent, edges = {"greedy"}, [("idle", "greedy")]
        if name == "frontier-useless":
            latent.update({"unused-candidate-1", "unused-candidate-2"})
            edges.extend([("idle", "unused-candidate-1"), ("idle", "unused-candidate-2")])
        if name == "frontier-cycle":
            edges.append(("greedy", "idle"))
    elif name == "frontier-comparator":
        edges.append(("serial", "reuse"))
    by_id = {b.action_id: b for b in bindings}
    rules = [
        GrowthActivationRule(
            rule_id=f"{producer}-enables-{target}",
            producer_action_id=producer,
            producer_successor_id=f"{producer}:success",
            activated_action_ids=[target],
            required_capability_digests=[
                by_id[producer].capability_digest,
                by_id[target].capability_digest,
            ],
            required_model_ids=["nominal", "partial", "failure", "timeout"],
            valid_from="0",
            expires="5",
        )
        for producer, target in edges
    ]
    frontier = GrowthCapabilityFrontier(
        metadata=metadata("synthetic-frontier-" + name),
        spec=GrowthCapabilityFrontierSpec(
            contract_digest=document_digest(c),
            initial_enabled_action_ids=sorted(set(by_id) - latent),
            latent_action_ids=sorted(latent),
            bindings=bindings,
            activation_rules=rules,
            maximum_activation_depth=3,
        ),
    )
    return c, objects, frontier


def frontier_report(name: str = "frontier-chain") -> dict[str, Any]:
    c, objects, frontier = frontier_example(name)
    plan = plan_growth(c, objects, frontier)
    return {
        "code": "growth_frontier_synthetic_example",
        "scenario": name,
        "frontier": frontier.model_dump(mode="json"),
        "plan": plan.model_dump(mode="json"),
        "synthetic": True,
        "observations_written": [],
        "execution_authorized": False,
        "empirical_attribution": "undetermined",
    }


def write_frontier_example(directory: Path, name: str = "frontier-chain") -> None:
    c, objects, frontier = frontier_example(name)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "objects").mkdir(exist_ok=True)
    for filename, doc in [
        ("contract.json", c),
        ("frontier.json", frontier),
        *[(f"objects/{d[7:]}.json", x) for d, x in objects.items()],
    ]:
        (directory / filename).write_bytes(
            canonical_bytes(doc.model_dump(mode="json", exclude_none=True))
        )
