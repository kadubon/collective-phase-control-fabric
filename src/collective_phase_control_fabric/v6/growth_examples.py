# SPDX-License-Identifier: Apache-2.0
"""Deterministic synthetic catalogues for the installed offline growth CLI.

Unsigned modelling documents only. The seed and coefficients are stipulated,
not measured service capacity, runner receipts, or evidence of collective benefit.
"""

from __future__ import annotations

from datetime import UTC, datetime
from fractions import Fraction
from pathlib import Path
from typing import Any, cast

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.growth import (
    Budget,
    GrowthError,
    Search,
    attainment,
    compare,
    content_digest,
    initial_state,
    plan_growth,
    successors,
    transition,
)
from collective_phase_control_fabric.v6.models import (
    MANDATORY_DIMENSIONS,
    ActionDocument,
    ActionSpec,
    AnalysisSnapshot,
    BranchEffect,
    CapabilityDocument,
    CapabilitySpec,
    DimensionResult,
    Document,
    GrowthAction,
    GrowthComparator,
    GrowthContract,
    GrowthContractSpec,
    GrowthDomain,
    GrowthInterval,
    GrowthSearchLimits,
    GrowthState,
    GrowthSuccessor,
    GrowthVersions,
    GrowthWindow,
    Metadata,
    OperationalProfile,
    OutcomeName,
    SnapshotSpec,
    UnitDefinition,
    UnitRegistryDocument,
    UnitRegistrySpec,
)
from collective_phase_control_fabric.v6.planning import plan_actions
from collective_phase_control_fabric.v6.registry import document_digest, schema_digest
from collective_phase_control_fabric.v6.science import analysis_basis_digest


def synthetic_digest(name: str) -> str:
    return digest_bytes(name.encode("utf-8"))


def metadata(name: str) -> Metadata:
    return Metadata(
        tenant_id="synthetic",
        workspace_id="growth-example",
        object_id=name,
        created_at=datetime(2026, 9, 7, tzinfo=UTC),
    )


def example(name: str = "preparation") -> tuple[GrowthContract, dict[str, Document]]:
    if name not in {"preparation", "all-failure", "no-advantage", "verification", "communication"}:
        raise GrowthError("growth_example_unknown")
    units = UnitRegistryDocument(
        metadata=metadata("units"),
        spec=UnitRegistrySpec(
            units={
                "task/s": UnitDefinition(
                    symbol="task/s", dimensions={"task": 1, "time": -1}, scale="1"
                ),
                "research/s": UnitDefinition(
                    symbol="research/s", dimensions={"research": 1, "time": -1}, scale="1"
                ),
                "verification/s": UnitDefinition(
                    symbol="verification/s", dimensions={"verification": 1, "time": -1}, scale="1"
                ),
                "credit": UnitDefinition(symbol="credit", dimensions={"budget": 1}, scale="1"),
                "second": UnitDefinition(symbol="second", dimensions={"time": 1}, scale="1"),
                "action": UnitDefinition(symbol="action", dimensions={"action": 1}, scale="1"),
            },
            coordinate_units={
                "task": "task/s",
                "research": "research/s",
                "verification": "verification/s",
                "credits": "credit",
            },
            time_unit="second",
            action_unit="action",
        ),
    )
    snapshot = AnalysisSnapshot(
        metadata=metadata("snapshot"),
        spec=SnapshotSpec(
            generation_digest=synthetic_digest("generation"),
            analysis_basis_digest=synthetic_digest("basis"),
            contract_digest=synthetic_digest("phase-contract"),
            trust_policy_digest=synthetic_digest("policy"),
            trusted_time_receipt_digest=synthetic_digest("time"),
            unit_registry_digest=document_digest(units),
            object_digests=[document_digest(units)],
            target_ids=["task", "research"],
            required_dimensions=list(MANDATORY_DIMENSIONS),
        ),
    )
    snapshot = snapshot.model_copy(
        update={
            "spec": snapshot.spec.model_copy(
                update={"analysis_basis_digest": analysis_basis_digest(snapshot)}
            )
        }
    )
    objects: dict[str, Document] = {document_digest(x): x for x in (units, snapshot)}
    recipes: list[GrowthAction] = []

    def add_recipe(
        action_id: str,
        delta: dict[str, str],
        cost: str,
        *,
        evidence: dict[str, str] | None = None,
        requires: list[str] | None = None,
        earliest: str = "0",
        expires: str = "6",
        interaction: bool = False,
        minimum: dict[str, str] | None = None,
        repeatable: bool = False,
        category: str = "investment",
        duration: str = "1",
    ) -> None:
        branches: list[BranchEffect] = []
        effects: list[GrowthSuccessor] = []
        outcomes: tuple[OutcomeName, ...] = ("success", "partial", "failure", "timeout")
        for outcome in outcomes:
            out = outcome
            branches.append(
                BranchEffect(
                    outcome=out,
                    time_upper=duration,
                    resource_delta_lower={"credits": "-" + cost},
                    resource_delta_upper={"credits": "-" + cost},
                )
            )
            effects.append(
                GrowthSuccessor(
                    successor_id=action_id + ":" + outcome,
                    outcome=out,
                    applicable_model_ids=["nominal"] if outcome == "success" else [outcome],
                    duration=duration,
                    capacity_delta={k: GrowthInterval(lower=v, upper=v) for k, v in delta.items()}
                    if outcome == "success"
                    else {},
                    charges={category: {"credits": cost}},
                    evidence_added=evidence or {} if outcome == "success" else {},
                )
            )
        cap = CapabilityDocument(
            metadata=metadata("cap-" + action_id),
            spec=CapabilitySpec(
                capability_id="cap-" + action_id,
                adapter_principal_id="external-operator",
                verifier_principal_id="independent-evaluator",
                execution_policy_digest=synthetic_digest("execution-policy"),
                image_digest=synthetic_digest("synthetic-image"),
                argv=["synthetic-refinement", action_id],
                output_schema_name="growth-observation",
                output_schema_digest=schema_digest("growth-observation"),
                return_code_outcomes={"0": "success", "1": "failure"},
                repeatable=repeatable,
                progress_measure="elapsed-time" if repeatable else None,
                branches=branches,
            ),
        )
        action = ActionDocument(
            metadata=metadata(action_id),
            spec=ActionSpec(action_id=action_id, capability_digest=document_digest(cap)),
        )
        objects.update({document_digest(x): x for x in (cap, action)})
        recipes.append(
            GrowthAction(
                action_digest=document_digest(action),
                required_evidence=requires or [],
                minimum_capacities=minimum or {},
                earliest=earliest,
                expires=expires,
                interactions=["reuse"] if interaction else [],
                successors=effects,
            )
        )

    add_recipe("prepare", {}, "1", evidence={"calibrated": "6"}, category="calibration")
    add_recipe(
        "reuse",
        {"task": "2", "research": "2"},
        "2",
        requires=["calibrated"],
        interaction=True,
        evidence={"measured-route": "6"},
        category="joint-activity",
    )
    add_recipe(
        "continue",
        {"task": "1", "research": "1"},
        "1",
        requires=["measured-route"],
        interaction=True,
        repeatable=True,
    )
    add_recipe("greedy", {"task": "2"}, "2", category="generation")
    add_recipe(
        "serial",
        {"task": "1", "research": "1"},
        "2",
        repeatable=True,
        evidence={"measured-route": "6"},
        duration="2",
    )
    add_recipe("idle", {}, "1", repeatable=True, category="verification")
    if name == "no-advantage":
        add_recipe(
            "single-process",
            {"task": "2", "research": "2"},
            "1",
            repeatable=True,
            evidence={"measured-route": "6"},
        )
    if name == "verification":
        add_recipe(
            "verifier",
            {"verification": "3"},
            "1",
            evidence={"calibrated": "6"},
            category="verification",
        )
        recipes = [
            r.model_copy(update={"minimum_capacities": {"verification": "3"}})
            if cast(ActionDocument, objects[r.action_digest]).spec.action_id == "reuse"
            else r
            for r in recipes
        ]
    if name == "communication":
        add_recipe(
            "dense",
            {"task": "3", "research": "3"},
            "6",
            interaction=True,
            evidence={"measured-route": "6"},
            category="communication",
        )
    versions = GrowthVersions(**{k: synthetic_digest(k) for k in GrowthVersions.model_fields})
    contract = GrowthContract(
        metadata=metadata("contract-" + name),
        spec=GrowthContractSpec(
            analysis_snapshot_digest=document_digest(snapshot),
            unit_registry_digest=document_digest(units),
            versions=versions,
            model_time_origin=metadata("model-origin").created_at,
            domains={
                k: GrowthDomain(
                    unit=k + "/s",
                    target="3" if k != "verification" else "1",
                    service_floor="1",
                    quality_floor="1",
                    coverage_floor="1",
                )
                for k in ("task", "research", "verification")
            },
            resource_units={"credits": "credit"},
            resource_floors={"credits": "0"},
            shared_resources={"gpu": "100"},
            joint_coefficients={"gpu": {"task": "1", "research": "1", "verification": "1"}},
            joint_service_until="6",
            queue_limits={k: "10" for k in ("task", "research", "verification")},
            debt_limits={k: "10" for k in ("task", "research", "verification")},
            required_entry_evidence=["measured-route"],
            model_catalogue=["nominal", "partial", "failure", "timeout"],
            initial_state=GrowthState(
                capacities={
                    k: GrowthInterval(lower="1", upper="1")
                    for k in ("task", "research", "verification")
                },
                quality={k: "1" for k in ("task", "research", "verification")},
                coverage={k: "1" for k in ("task", "research", "verification")},
                resources={"credits": "8"},
                model_ids=["failure"] if name == "all-failure" else ["nominal"],
                live_object_digests=sorted(objects),
            ),
            windows=[
                GrowthWindow(start="0", end=str(t), task_factor="2", research_factor="2")
                for t in (2, 3, 4)
            ],
            continuation_horizon="1",
            continuation_task_factor="4/3",
            continuation_research_factor="4/3",
            deadline="5",
            max_decisions=5,
            action_catalogue=recipes,
            comparators=[
                GrowthComparator(
                    comparator_id="reoptimized-reuse-restricted", excluded_interactions=["reuse"]
                )
            ],
            comparison_margin="1/10",
            cost_order=["credits"],
            search_limits=GrowthSearchLimits(max_policies=100_000),
            planning_charge={"credits": "1"},
            planning_duration="0",
        ),
    )
    return contract, objects


def write_example(destination: Path, name: str = "preparation") -> GrowthContract:
    contract, objects = example(name)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "objects").mkdir(exist_ok=True)
    for digest, obj in objects.items():
        (destination / "objects" / (digest.removeprefix("sha256:") + ".json")).write_bytes(
            canonical_bytes(obj.model_dump(mode="json", exclude_none=True))
        )
    (destination / "contract.json").write_bytes(
        canonical_bytes(contract.model_dump(mode="json", exclude_none=True))
    )
    return contract


def comparison_example(name: str = "preparation") -> dict[str, Any]:
    contract, objects = example(name)
    planned = plan_growth(contract, objects)
    snapshot = cast(AnalysisSnapshot, objects[contract.spec.analysis_snapshot_digest])
    # Explicit blocker-free synthetic premise tests the OLD mode's scope only.
    profile = OperationalProfile(
        analysis_snapshot_digest=document_digest(snapshot),
        dimensions={k: DimensionResult(status="satisfied") for k in MANDATORY_DIMENSIONS},
        operational_organization_compatible=True,
        solution_class="exact",
    )
    repair = plan_actions(
        snapshot,
        objects,
        profile,
        [x for x in objects.values() if isinstance(x, ActionDocument)],
        [x for x in objects.values() if isinstance(x, CapabilityDocument)],
    )
    greedy = initial_state(contract)
    greedy_actions: list[str] = []
    while Fraction(greedy.elapsed) < Fraction(contract.spec.deadline):
        choices: list[tuple[str, GrowthState]] = []
        for recipe in contract.spec.action_catalogue:
            try:
                branches = [
                    transition(contract, greedy, recipe, e, objects)
                    for e in successors(greedy, recipe)
                ]
                # Choose the worst successor in the declared finite model.
                if branches:
                    worst = min(branches, key=lambda s: attainment(contract, s))
                    choices.append(
                        (cast(ActionDocument, objects[recipe.action_digest]).spec.action_id, worst)
                    )
            except GrowthError:
                continue
        if not choices:
            break
        action_id, greedy = min(
            choices,
            key=lambda pair: (
                -(
                    Fraction(pair[1].capacities["task"].lower)
                    / Fraction(contract.spec.domains["task"].target)
                    + Fraction(pair[1].capacities["research"].lower)
                    / Fraction(contract.spec.domains["research"].target)
                ),
                pair[0],
            ),
        )
        greedy_actions.append(action_id)

    def row(state: GrowthState | None, entry: str | None = None) -> dict[str, Any]:
        return {
            "capacities": state.capacities if state else None,
            "time_to_modelled_entry": entry,
            "continuation_feasible": entry is not None,
            "queue": state.queue if state else None,
            "debt": state.obligations if state else None,
            "evidence_cost": {
                k: v
                for k, v in state.charges.items()
                if k in {"calibration", "evidence", "joint-activity"}
            }
            if state
            else None,
            "remaining_resources": state.resources if state else None,
        }

    search = Search(
        contract,
        objects,
        Budget(contract.spec.search_limits),
        excluded=frozenset({"reuse"}),
        endpoint=Fraction(contract.spec.deadline),
    )
    baselines = search.enumerate(initial_state(contract))
    baseline = (
        min(
            baselines,
            key=lambda p: (
                -min(attainment(contract, s) for s in p.terminals),
                content_digest(p.node),
            ),
        )
        if baselines
        else None
    )
    return {
        "example": name,
        "scope": "synthetic finite ledgers; no empirical claim",
        "initial_budget": contract.spec.initial_state.resources,
        "repair": {
            "code": repair.code,
            "growth_objective": "outside-repair-scope",
            "metrics": None,
        },
        "growth": {
            "code": planned.spec.code,
            "primary_action": planned.spec.policy.action_id if planned.spec.policy else None,
            **row(
                planned.spec.model_predicted_terminal[0]
                if planned.spec.model_predicted_terminal
                else None,
                planned.spec.objective.worst_entry_time if planned.spec.objective else None,
            ),
        },
        "greedy_immediate_output": {"actions": greedy_actions, **row(greedy)},
        "reoptimized_interaction_restricted": row(baseline.terminals[0] if baseline else None),
        "comparisons": [x.model_dump(mode="json") for x in compare(contract, objects)],
    }
