# SPDX-License-Identifier: Apache-2.0
"""Bounded exact growth game. All ledgers here are conditional model quantities.

No adapter, trust admission, statistical estimator, or external command is run.
The adversary may pick any applicable successor at every decision (rectangular
uncertainty). This can overapproximate a fixed unknown model. Policy enumeration
keeps continuation value; neither immediate-output Pareto nor beam pruning is used.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from fractions import Fraction
from itertools import product
from typing import Any, cast, overload

from collective_phase_control_fabric.v6 import growth_frontier as frontier_model
from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    AnalysisSnapshot,
    CapabilityDocument,
    Document,
    GrowthAction,
    GrowthCapabilityFrontier,
    GrowthCheckpoint,
    GrowthComparison,
    GrowthContract,
    GrowthFrontierPlan,
    GrowthFrontierPlanSpec,
    GrowthFrontierState,
    GrowthInterval,
    GrowthObjective,
    GrowthPlan,
    GrowthPlanSpec,
    GrowthPolicyNode,
    GrowthSearchLimits,
    GrowthSearchReport,
    GrowthState,
    GrowthSuccessor,
    GrowthWindow,
    GrowthWork,
    Lifecycle,
    StrictModel,
    UnitRegistryDocument,
)
from collective_phase_control_fabric.v6.registry import document_digest, schema_digest

F = Fraction
CAPACITIES = {"task", "research", "verification"}
CHARGE_CATEGORIES = {
    "generation",
    "verification",
    "repair",
    "calibration",
    "communication",
    "comparison",
    "evidence",
    "joint-activity",
    "investment",
    "planner",
}
INVALIDATE_ON = [
    "state-change",
    "new-counterevidence",
    "model-change",
    "protocol-change",
    "evaluator-change",
    "ontology-change",
    "coverage-change",
    "expiry",
]


class GrowthError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise GrowthError(code)


def content_digest(value: StrictModel) -> str:
    return digest_bytes(canonical_bytes(value.model_dump(mode="json", exclude_none=True)))


def normalize(state: GrowthState) -> GrowthState:
    """Canonical semantic sets and exact rationals; every state facet is hashed."""
    data = state.model_dump(mode="json")
    for name in (
        "model_ids",
        "used_actions",
        "pending_results",
        "actual_evidence_digests",
        "live_object_digests",
        "hazards",
    ):
        data[name] = sorted(set(data[name]))
    for name in ("queue", "obligations"):
        data[name] = sorted(data[name], key=lambda x: x["work_id"])
    data["reservations"] = sorted(
        data["reservations"], key=lambda x: (x["resource"], x["owner"], F(x["until"]))
    )
    data["checkpoints"] = sorted(data["checkpoints"], key=lambda x: F(x["time"]))
    if isinstance(state, GrowthFrontierState):
        data["enabled_action_ids"] = sorted(data["enabled_action_ids"])
        data["activation_lineage"] = sorted(
            data["activation_lineage"], key=lambda x: x["action_id"]
        )
    return type(state).model_validate(data)


def state_digest(state: GrowthState) -> str:
    return content_digest(normalize(state))


def input_digest(
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier | None = None,
) -> str:
    return digest_bytes(
        canonical_bytes(
            {
                "contract": document_digest(contract),
                "objects": sorted(document_digest(item) for item in objects.values()),
                **({"frontier": document_digest(frontier)} if frontier is not None else {}),
            }
        )
    )


def _sum(values: Iterator[Fraction]) -> Fraction:
    return sum(values, F(0))


def _intervals(values: dict[str, GrowthInterval], *, nonnegative: bool = True) -> None:
    require(
        all(
            F(v.lower) <= F(v.upper) and (not nonnegative or F(v.lower) >= 0)
            for v in values.values()
        ),
        "growth_interval_invalid",
    )


def _nonnegative(values: dict[str, str]) -> None:
    require(all(F(v) >= 0 for v in values.values()), "growth_negative_quantity")


def validate_contract(contract: GrowthContract, objects: dict[str, Document]) -> None:
    """Validate the closed finite model and immutable Action/Capability bindings."""
    c = contract.spec
    require(all(k == document_digest(v) for k, v in objects.items()), "growth_object_digest")
    snapshot = objects.get(c.analysis_snapshot_digest)
    units = objects.get(c.unit_registry_digest)
    require(isinstance(snapshot, AnalysisSnapshot), "growth_snapshot_missing")
    require(isinstance(units, UnitRegistryDocument), "growth_units_missing")
    snapshot = cast(AnalysisSnapshot, snapshot)
    units = cast(UnitRegistryDocument, units)
    require(snapshot.spec.unit_registry_digest == c.unit_registry_digest, "growth_units_mismatch")
    require(set(c.domains) >= CAPACITIES, "growth_domains_missing")
    require(
        set(c.domains)
        == set(c.initial_state.capacities)
        == set(c.initial_state.quality)
        == set(c.initial_state.coverage),
        "growth_domains_mismatch",
    )
    require(
        set(c.resource_units) == set(c.initial_state.resources) == set(c.cost_order)
        and len(c.cost_order) == len(set(c.cost_order)),
        "growth_resource_domain",
    )
    require(set(c.resource_floors) <= set(c.resource_units), "growth_resource_domain")
    require(set(c.planning_charge) <= set(c.resource_units), "growth_resource_domain")
    require(set(c.shared_resources) == set(c.joint_coefficients), "growth_reservation_domain")
    require(set(c.queue_limits) == set(c.debt_limits) == set(c.domains), "growth_queue_domain")
    for coordinate, domain in c.domains.items():
        require(
            F(domain.target) > 0
            and F(domain.service_floor) > 0
            and 0 <= F(domain.quality_floor) <= 1
            and 0 <= F(domain.coverage_floor) <= 1,
            "growth_domain_invalid",
        )
        require(units.spec.coordinate_units.get(coordinate) == domain.unit, "growth_units_mismatch")
    for coordinate, unit in c.resource_units.items():
        require(units.spec.coordinate_units.get(coordinate) == unit, "growth_units_mismatch")
    for definition in units.spec.units.values():
        require(F(definition.scale) > 0, "growth_units_mismatch")
    require(
        units.spec.time_unit in units.spec.units
        and units.spec.units[units.spec.time_unit].dimensions == {"time": 1},
        "growth_units_mismatch",
    )
    require(c.model_time_origin.utcoffset() is not None, "growth_time_invalid")
    require(
        all(
            unit in units.spec.units
            for unit in [d.unit for d in c.domains.values()] + list(c.resource_units.values())
        ),
        "growth_units_mismatch",
    )
    require(
        F(c.deadline) > 0
        and F(c.continuation_horizon) > 0
        and F(c.joint_service_until) >= F(c.deadline)
        and F(c.planning_duration) >= 0,
        "growth_time_invalid",
    )
    require(
        F(c.continuation_task_factor) > 1
        and F(c.continuation_research_factor) > 1
        and F(c.comparison_margin) > 0,
        "growth_factor_invalid",
    )
    require(
        len(set(c.model_catalogue)) == len(c.model_catalogue)
        and set(c.initial_state.model_ids) <= set(c.model_catalogue),
        "growth_model_domain",
    )
    require(len({content_digest(w) for w in c.windows}) == len(c.windows), "growth_window_invalid")
    for w in c.windows:
        require(
            0 <= F(w.start) < F(w.end) <= F(c.deadline)
            and F(w.task_factor) > 1
            and F(w.research_factor) > 1,
            "growth_window_invalid",
        )
    for values in (
        c.shared_resources,
        c.resource_floors,
        c.queue_limits,
        c.debt_limits,
        c.planning_charge,
    ):
        _nonnegative(values)
    for coefficients in c.joint_coefficients.values():
        require(set(coefficients) <= set(c.domains), "growth_reservation_domain")
        _nonnegative(coefficients)
    ids: set[str] = set()
    for recipe in c.action_catalogue:
        action = objects.get(recipe.action_digest)
        require(isinstance(action, ActionDocument), "growth_action_missing")
        action = cast(ActionDocument, action)
        cap = objects.get(action.spec.capability_digest)
        require(isinstance(cap, CapabilityDocument), "growth_capability_missing")
        cap = cast(CapabilityDocument, cap)
        require(
            cap.spec.output_schema_digest == schema_digest(cap.spec.output_schema_name),
            "growth_capability_schema",
        )
        require(action.spec.action_id not in ids, "growth_action_duplicate")
        ids.add(action.spec.action_id)
        require(0 <= F(recipe.earliest) < F(recipe.expires), "growth_time_invalid")
        require(set(recipe.minimum_capacities) <= set(c.domains), "growth_domains_mismatch")
        _nonnegative(recipe.minimum_capacities)
        require(
            {s.outcome for s in recipe.successors} == {"success", "partial", "failure", "timeout"},
            "growth_successor_incomplete",
        )
        require(
            len({s.successor_id for s in recipe.successors}) == len(recipe.successors),
            "growth_successor_duplicate",
        )
        require(
            set(c.model_catalogue)
            <= {m for s in recipe.successors for m in s.applicable_model_ids},
            "growth_successor_incomplete",
        )
        for successor in recipe.successors:
            require(
                set(successor.applicable_model_ids) <= set(c.model_catalogue), "growth_model_domain"
            )
            branch = next(b for b in cap.spec.branches if b.outcome == successor.outcome)
            require(0 < F(successor.duration) <= F(branch.time_upper), "growth_duration_invalid")
            require(
                set(successor.capacity_delta) <= set(c.domains)
                and set(successor.quality) <= set(c.domains)
                and set(successor.coverage) <= set(c.domains),
                "growth_domains_mismatch",
            )
            _intervals(successor.capacity_delta, nonnegative=False)
            require(set(successor.charges) <= CHARGE_CATEGORIES, "growth_charge_category")
            totals: dict[str, Fraction] = {}
            for charge in successor.charges.values():
                require(set(charge) <= set(c.resource_units), "growth_resource_domain")
                _nonnegative(charge)
                for key, value in charge.items():
                    totals[key] = totals.get(key, F(0)) + F(value)
            require(
                set(branch.resource_delta_lower) <= set(c.resource_units), "growth_resource_domain"
            )
            for key in set(totals) | set(branch.resource_delta_lower):
                require(
                    F(branch.resource_delta_lower.get(key, "0"))
                    <= -totals.get(key, F(0))
                    <= F(branch.resource_delta_upper.get(key, "0")),
                    "growth_capability_effect",
                )
            require(
                c.monetary_resource is None or c.monetary_resource in c.resource_units,
                "growth_resource_domain",
            )
            require(
                F(branch.cost_upper) <= totals.get(c.monetary_resource or "", F(0)),
                "growth_unfunded_monetary_cost",
            )
            require(
                set(branch.debt) | set(branch.rollback_obligations)
                <= {w.work_id for w in successor.debt_added},
                "growth_unaccounted_obligation",
            )
            require(
                F(branch.verification_load_upper)
                >= _sum(F(w.remaining) for w in successor.arrivals if w.stage == "verification"),
                "growth_capability_effect",
            )
    require(
        len({x.comparator_id for x in c.comparators}) == len(c.comparators),
        "growth_comparator_duplicate",
    )
    check_state(contract, c.initial_state)


def check_state(contract: GrowthContract, state: GrowthState) -> None:
    c = contract.spec
    require(
        set(state.capacities) == set(state.quality) == set(state.coverage) == set(c.domains),
        "growth_domains_mismatch",
    )
    _intervals(state.capacities)
    require(set(state.resources) == set(c.resource_units), "growth_resource_domain")
    require(0 <= F(state.elapsed) <= F(c.deadline), "growth_deadline")
    require(set(state.model_ids) <= set(c.model_catalogue), "growth_model_domain")
    for key, domain in c.domains.items():
        require(F(state.capacities[key].lower) >= F(domain.service_floor), "growth_service_floor")
        require(F(domain.quality_floor) <= F(state.quality[key]) <= 1, "growth_quality_floor")
        require(F(domain.coverage_floor) <= F(state.coverage[key]) <= 1, "growth_coverage_floor")
    for key, value in state.resources.items():
        require(F(value) >= F(c.resource_floors.get(key, "0")), "growth_resource_floor")
    seen: set[str] = set()
    for queue, limits in ((state.queue, c.queue_limits), (state.obligations, c.debt_limits)):
        totals: dict[str, Fraction] = {}
        for work in queue:
            require(work.work_id not in seen, "growth_work_duplicate")
            seen.add(work.work_id)
            require(work.stage in c.domains and F(work.remaining) >= 0, "growth_work_invalid")
            require(
                F(work.remaining) == 0 or F(work.deadline) > F(state.elapsed),
                "growth_work_deadline",
            )
            totals[work.stage] = totals.get(work.stage, F(0)) + F(work.remaining)
        require(all(v <= F(limits[k]) for k, v in totals.items()), "growth_backlog_limit")
    reserved: dict[str, Fraction] = {}
    for r in state.reservations:
        require(
            r.resource in c.shared_resources and F(r.quantity) >= 0, "growth_reservation_domain"
        )
        if F(r.until) > F(state.elapsed):
            reserved[r.resource] = reserved.get(r.resource, F(0)) + F(r.quantity)
    for key, amount in c.shared_resources.items():
        joint = _sum(
            F(v) * F(state.capacities[k].upper) for k, v in c.joint_coefficients[key].items()
        )
        require(
            joint + reserved.get(key, F(0)) <= F(amount), "growth_shared_resource_double_booking"
        )
    for checkpoint in state.checkpoints:
        require(
            set(checkpoint.capacities) == set(c.domains)
            and 0 <= F(checkpoint.time) <= F(state.elapsed),
            "growth_checkpoint_invalid",
        )
        _intervals(checkpoint.capacities)
    times = [F(x.time) for x in state.checkpoints]
    require(len(times) == len(set(times)), "growth_checkpoint_invalid")


def initial_state(
    contract: GrowthContract, frontier: GrowthCapabilityFrontier | None = None
) -> GrowthState:
    c = contract.spec
    s = c.initial_state
    resources = dict(s.resources)
    spent = dict(s.spent)
    charges = {k: dict(v) for k, v in s.charges.items()}
    category = "planner" if c.planning_boundary == "shared-budget" else "external-planner"
    charges[category] = {
        k: str(F(charges.get(category, {}).get(k, "0")) + F(v))
        for k, v in c.planning_charge.items()
    }
    if c.planning_boundary == "shared-budget":
        for key, value in c.planning_charge.items():
            resources[key] = str(F(resources[key]) - F(value))
            spent[key] = str(F(spent.get(key, "0")) + F(value))
    elapsed = F(s.elapsed) + F(c.planning_duration)
    checkpoints = list(s.checkpoints)
    boundaries = {F(s.elapsed)} | {
        F(t) for w in c.windows for t in (w.start, w.end) if F(s.elapsed) <= F(t) <= elapsed
    }
    for boundary in sorted(boundaries):
        if not any(F(x.time) == boundary for x in checkpoints):
            checkpoints.append(GrowthCheckpoint(time=str(boundary), capacities=s.capacities))
    state = normalize(
        s.model_copy(
            update={
                "resources": resources,
                "spent": spent,
                "charges": charges,
                "elapsed": str(elapsed),
                "checkpoints": checkpoints,
            }
        )
    )
    check_state(contract, state)
    return frontier_model.seed(state, frontier) if frontier is not None else state


def applicable(
    contract: GrowthContract,
    state: GrowthState,
    recipe: GrowthAction,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier | None = None,
) -> tuple[ActionDocument, CapabilityDocument]:
    require(bool(state.model_ids), "growth_inconsistent_models")
    action = cast(ActionDocument, objects[recipe.action_digest])
    cap = cast(CapabilityDocument, objects[action.spec.capability_digest])
    if frontier is not None:
        frontier_model.check_use(
            contract, objects, frontier, state, action.spec.action_id, F(state.elapsed)
        )
    else:
        require(not isinstance(state, GrowthFrontierState), "growth_frontier_document_required")
    require(
        cap.spec.repeatable or action.spec.action_id not in state.used_actions,
        "growth_nonrepeatable_reuse",
    )
    require(F(recipe.earliest) <= F(state.elapsed) < F(recipe.expires), "growth_action_expired")
    require(
        set(action.spec.required_object_digests) <= set(state.live_object_digests),
        "growth_required_object",
    )
    require(not set(action.spec.prohibited_hazards) & set(state.hazards), "growth_hazard")
    for needed, available in (
        (recipe.required_evidence, state.evidence),
        (recipe.required_assumptions, state.assumptions),
    ):
        require(
            all(x in available and F(available[x]) > F(state.elapsed) for x in needed),
            "growth_premise_missing_or_expired",
        )
    require(
        all(F(state.capacities[k].lower) >= F(v) for k, v in recipe.minimum_capacities.items()),
        "growth_capacity_prerequisite",
    )
    return action, cap


def successors(state: GrowthState, recipe: GrowthAction) -> list[GrowthSuccessor]:
    return sorted(
        (b for b in recipe.successors if set(state.model_ids) & set(b.applicable_model_ids)),
        key=lambda b: b.successor_id,
    )


def transition(
    contract: GrowthContract,
    state: GrowthState,
    recipe: GrowthAction,
    effect: GrowthSuccessor,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier | None = None,
) -> GrowthState:
    """Recheck every prefix, transient reservation, queue and expiry after a model step."""
    action, cap = applicable(contract, state, recipe, objects, frontier)
    require(effect in successors(state, recipe), "growth_undeclared_successor")
    c = contract.spec
    end = F(state.elapsed) + F(effect.duration)
    require(end <= F(recipe.expires) and end <= F(c.deadline), "growth_deadline")
    for names, values in (
        (recipe.required_evidence, state.evidence),
        (recipe.required_assumptions, state.assumptions),
    ):
        require(all(F(values[k]) >= end for k in names), "growth_premise_expires_during_action")
    reservations = [r for r in state.reservations if F(r.until) > F(state.elapsed)]
    require(all(F(r.until) >= end for r in effect.reservations), "growth_reservation_expired")
    # Reservation is checked while the OLD service vector is still offered.
    check_state(
        contract, state.model_copy(update={"reservations": reservations + effect.reservations})
    )
    queues = list(state.queue) + effect.arrivals
    debts = list(state.obligations) + effect.debt_added
    check_state(contract, state.model_copy(update={"queue": queues, "obligations": debts}))
    work = {w.work_id: w for w in [*queues, *debts]}
    require(len(work) == len(queues) + len(debts), "growth_work_duplicate")
    require(set(effect.completed_work) <= set(work), "growth_completion_without_work")
    _nonnegative(effect.offered_service)
    require(set(effect.offered_service) <= set(c.domains), "growth_queue_domain")
    used: dict[str, Fraction] = {}
    completed = dict(state.completed)
    offered = dict(state.offered)
    for key, amount in effect.completed_work.items():
        item = work[key]
        require(0 <= F(amount) <= F(item.remaining), "growth_completion_exceeds_work")
        require(F(amount) == 0 or F(item.deadline) >= end, "growth_completion_late")
        used[item.stage] = used.get(item.stage, F(0)) + F(amount)
    for stage in c.domains:
        offer = F(effect.offered_service.get(stage, "0"))
        require(
            used.get(stage, F(0)) <= offer <= F(state.capacities[stage].lower) * F(effect.duration),
            "growth_service_overbooked",
        )
        completed[stage] = str(F(completed.get(stage, "0")) + used.get(stage, F(0)))
        offered[stage] = str(F(offered.get(stage, "0")) + offer)

    def remaining(queue: list[GrowthWork]) -> list[GrowthWork]:
        return [
            w.model_copy(
                update={
                    "remaining": str(F(w.remaining) - F(effect.completed_work.get(w.work_id, "0")))
                }
            )
            for w in queue
            if F(w.remaining) > F(effect.completed_work.get(w.work_id, "0"))
        ]

    queues, debts = remaining(queues), remaining(debts)
    resources, spent = dict(state.resources), dict(state.spent)
    charges = {k: dict(v) for k, v in state.charges.items()}
    for category, amounts in effect.charges.items():
        bucket = charges.setdefault(category, {})
        for key, amount in amounts.items():
            resources[key] = str(F(resources[key]) - F(amount))
            spent[key] = str(F(spent.get(key, "0")) + F(amount))
            bucket[key] = str(F(bucket.get(key, "0")) + F(amount))
    capacities = dict(state.capacities)
    for key, delta in effect.capacity_delta.items():
        capacities[key] = GrowthInterval(
            lower=str(F(capacities[key].lower) + F(delta.lower)),
            upper=str(F(capacities[key].upper) + F(delta.upper)),
        )
    if any(F(x.lower) > 0 for x in effect.capacity_delta.values()):
        require(
            not {w.work_id for w in debts + queues} & set(c.blocking_obligation_ids),
            "growth_credit_blocked_by_work",
        )
    branch = next(b for b in cap.spec.branches if b.outcome == effect.outcome)
    # Required signed objects expire in the MODEL clock without forging a time attestation.
    units = cast(UnitRegistryDocument, objects[c.unit_registry_digest])
    scale = F(units.spec.units[units.spec.time_unit].scale)
    for digest in action.spec.required_object_digests:
        document = objects.get(digest)
        require(document is not None, "growth_required_object")
        lifecycle = getattr(getattr(document, "spec", None), "lifecycle", None)
        if isinstance(lifecycle, Lifecycle):
            for at, lower_bound in ((lifecycle.valid_from, True), (lifecycle.valid_until, False)):
                difference = at - c.model_time_origin
                seconds = F(difference.days * 86400 + difference.seconds) + F(
                    difference.microseconds, 1_000_000
                )
                require(
                    F(state.elapsed) * scale >= seconds if lower_bound else end * scale <= seconds,
                    "growth_required_object_expired",
                )
            if lifecycle.withdrawn_at is not None:
                difference = lifecycle.withdrawn_at - c.model_time_origin
                seconds = F(difference.days * 86400 + difference.seconds) + F(
                    difference.microseconds, 1_000_000
                )
                require(end * scale < seconds, "growth_required_object_expired")
    removals = set(branch.must_remove) | set(branch.may_remove)
    require(not removals & set(action.spec.protected_object_digests), "growth_protected_object")
    evidence = {
        k: v for k, v in state.evidence.items() if k not in effect.evidence_removed and F(v) >= end
    }
    evidence.update(effect.evidence_added)
    assumptions = {
        k: v
        for k, v in state.assumptions.items()
        if k not in effect.assumptions_removed and F(v) >= end
    }
    assumptions.update(effect.assumptions_added)
    checkpoints = list(state.checkpoints)
    # Piecewise constant service during an action; credit arrives at its boundary.
    boundaries = {F(w.start) for w in c.windows} | {F(w.end) for w in c.windows}
    for t in sorted(boundaries):
        if F(state.elapsed) < t <= end:
            checkpoints.append(
                GrowthCheckpoint(
                    time=str(t), capacities=capacities if t == end else state.capacities
                )
            )
    result = normalize(
        state.model_copy(
            update={
                "capacities": capacities,
                "quality": {**state.quality, **effect.quality},
                "coverage": {**state.coverage, **effect.coverage},
                "resources": resources,
                "spent": spent,
                "charges": charges,
                "reservations": [r for r in reservations + effect.reservations if F(r.until) > end],
                "queue": queues,
                "obligations": debts,
                "elapsed": str(end),
                "checkpoints": checkpoints,
                "evidence": evidence,
                "assumptions": assumptions,
                "used_actions": state.used_actions
                + ([] if cap.spec.repeatable else [action.spec.action_id]),
                "pending_results": sorted(
                    (set(state.pending_results) - set(effect.pending_resolved))
                    | set(effect.pending_added)
                    | set(branch.must_add)
                    | set(branch.may_add)
                ),
                "live_object_digests": sorted(set(state.live_object_digests) - removals),
                "hazards": sorted(
                    (set(state.hazards) - set(branch.hazards_removed)) | set(branch.hazards_added)
                ),
                "offered": offered,
                "completed": completed,
                "attribution": "attribution-unresolved"
                if state.attribution != effect.attribution
                else state.attribution,
            }
        )
    )
    require(not set(result.hazards) & set(action.spec.prohibited_hazards), "growth_hazard")
    check_state(contract, result)
    return (
        frontier_model.activate(contract, objects, frontier, state, result, recipe, effect)
        if frontier is not None
        else result
    )


def attainment(contract: GrowthContract, state: GrowthState, bound: str = "lower") -> Fraction:
    return min(
        F(getattr(state.capacities[k], bound)) / F(contract.spec.domains[k].target)
        for k in ("task", "research")
    )


def audit_model_boundary(
    contract: GrowthContract, objects: dict[str, Document], state: GrowthState
) -> dict[str, Any]:
    """Fresh shared-kernel audit of a hypothetical removal; no forecast attestation."""
    from collective_phase_control_fabric.v6.planning import _snapshot_for_live_state
    from collective_phase_control_fabric.v6.science import audit_snapshot

    check_state(contract, state)
    baseline = cast(AnalysisSnapshot, objects[contract.spec.analysis_snapshot_digest])
    reduced = _snapshot_for_live_state(baseline, frozenset(state.live_object_digests))
    removed = set(baseline.spec.object_digests) - set(state.live_object_digests)
    profile = audit_snapshot(reduced, {k: v for k, v in objects.items() if k not in removed})
    return {
        "mode": "hypothetical-removal-audit",
        "model_state_digest": state_digest(state),
        "source_snapshot_digest": document_digest(baseline),
        "profile": profile.model_dump(mode="json"),
        "resource_and_time_forecasts_are_attestations": False,
        "future_operational_compatibility": "unknown",
    }


def block_supported(state: GrowthState, window: GrowthWindow) -> bool:
    starts = [p for p in state.checkpoints if F(p.time) == F(window.start)]
    return (
        bool(starts)
        and F(state.elapsed) == F(window.end)
        and all(
            F(state.capacities[k].lower) >= F(starts[0].capacities[k].upper) * F(factor)
            for k, factor in (("task", window.task_factor), ("research", window.research_factor))
        )
    )


@dataclass
class Budget:
    limits: GrowthSearchLimits
    states: int = 0
    expansions: int = 0
    policies: int = 0
    maximum_depth: int = 0
    complete: bool = True

    def take(self, name: str, maximum: int) -> bool:
        if getattr(self, name) >= maximum:
            self.complete = False
            return False
        setattr(self, name, getattr(self, name) + 1)
        return True

    def report(self) -> GrowthSearchReport:
        return GrowthSearchReport(
            complete=self.complete,
            states=self.states,
            expansions=self.expansions,
            policies=self.policies,
            maximum_depth=self.maximum_depth,
            limits=self.limits,
        )


@dataclass
class Candidate:
    node: GrowthPolicyNode
    terminals: list[GrowthState]
    entries: list[Fraction]
    node_count: int = 1


@dataclass
class ScalarSolution:
    lower: Fraction
    upper: Fraction
    candidate: Candidate


@dataclass
class Search:
    contract: GrowthContract
    objects: dict[str, Document]
    budget: Budget
    excluded: frozenset[str] = frozenset()
    endpoint: Fraction | None = None
    comparisons: list[GrowthComparison] = field(default_factory=list)
    counterexamples: set[str] = field(default_factory=set)
    memo: dict[tuple[str, int, str | None], list[Candidate]] = field(default_factory=dict)
    scalar_memo: dict[tuple[str, int], ScalarSolution | None] = field(default_factory=dict)
    frontier: GrowthCapabilityFrontier | None = None

    def scalar(self, state: GrowthState, depth: int = 0) -> ScalarSolution | None:
        """Backward induction for ONE terminal scalar, with no vector composition.

        Unlike the lexicographic entry objective, a max-min terminal scalar has a
        continuation-preserving Bellman recursion, so policy products are unnecessary.
        """
        key = (state_digest(state), depth)
        if key in self.scalar_memo:
            return self.scalar_memo[key]
        if not self.budget.take("states", self.budget.limits.max_states):
            return None
        self.budget.maximum_depth = max(depth, self.budget.maximum_depth)
        if self.terminal(state, None):
            return ScalarSolution(
                attainment(self.contract, state),
                attainment(self.contract, state, "upper"),
                Candidate(GrowthPolicyNode(state_digest=key[0]), [state], []),
            )
        require(self.endpoint is not None, "growth_scalar_endpoint_required")
        if (
            F(state.elapsed) >= cast(Fraction, self.endpoint)
            or depth >= self.contract.spec.max_decisions
        ):
            return None
        if depth >= self.budget.limits.max_depth:
            self.budget.complete = False
            return None
        choices: list[ScalarSolution] = []
        for recipe in sorted(
            self.contract.spec.action_catalogue,
            key=lambda r: cast(ActionDocument, self.objects[r.action_digest]).spec.action_id,
        ):
            if self.excluded & set(recipe.interactions):
                continue
            try:
                action, _ = applicable(self.contract, state, recipe, self.objects, self.frontier)
                effects = successors(state, recipe)
                require(bool(effects), "growth_successor_incomplete")
                children: list[ScalarSolution] = []
                for effect in effects:
                    if not self.budget.take("expansions", self.budget.limits.max_expansions):
                        break
                    child = self.scalar(
                        transition(
                            self.contract, state, recipe, effect, self.objects, self.frontier
                        ),
                        depth + 1,
                    )
                    if child is None:
                        break
                    children.append(child)
                if len(children) != len(effects):
                    continue
                node_count = 1 + sum(ch.candidate.node_count for ch in children)
                if node_count > self.budget.limits.max_witness_nodes:
                    self.budget.complete = False
                    self.counterexamples.add("growth_witness_limit")
                    continue
                if not self.budget.take("policies", self.budget.limits.max_policies):
                    break
                node = GrowthPolicyNode(
                    state_digest=key[0],
                    action_id=action.spec.action_id,
                    branches={
                        e.successor_id: child.candidate.node
                        for e, child in zip(effects, children, strict=True)
                    },
                    effect_digests={e.successor_id: content_digest(e) for e in effects},
                )
                choices.append(
                    ScalarSolution(
                        min(ch.lower for ch in children),
                        min(ch.upper for ch in children),
                        Candidate(
                            node,
                            [s for ch in children for s in ch.candidate.terminals],
                            [],
                            node_count,
                        ),
                    )
                )
            except GrowthError as error:
                self.counterexamples.add(error.code)
        best = (
            min(
                choices,
                key=lambda p: (
                    -p.lower,
                    p.candidate.node.action_id or "",
                    content_digest(p.candidate.node),
                ),
            )
            if choices
            else None
        )
        if best is not None:
            best = ScalarSolution(best.lower, max(p.upper for p in choices), best.candidate)
        if self.budget.complete:
            self.scalar_memo[key] = best
        return best

    def entry_allowed(self, state: GrowthState) -> bool:
        c = self.contract.spec
        comparisons = [x for x in self.comparisons if F(x.endpoint) == F(state.elapsed)]
        return (
            attainment(self.contract, state) >= 1
            and any(block_supported(state, w) for w in c.windows)
            and all(
                k in state.evidence and F(state.evidence[k]) >= F(state.elapsed)
                for k in c.required_entry_evidence
            )
            and not state.pending_results
            and not {w.work_id for w in state.queue + state.obligations}
            & set(c.blocking_obligation_ids)
            and len(comparisons) == len(c.comparators)
            and all(
                x.search.complete
                and x.upper_bound is not None
                and attainment(self.contract, state) > F(x.upper_bound) + F(c.comparison_margin)
                for x in comparisons
            )
        )

    def terminal(self, state: GrowthState, entry: GrowthCheckpoint | None) -> bool:
        if self.endpoint is not None:
            return F(state.elapsed) == self.endpoint
        if entry is None:
            return False
        c = self.contract.spec
        return F(state.elapsed) == F(entry.time) + F(c.continuation_horizon) and all(
            F(state.capacities[k].lower) >= F(entry.capacities[k].upper) * F(factor)
            for k, factor in (
                ("task", c.continuation_task_factor),
                ("research", c.continuation_research_factor),
            )
        )

    def enumerate(
        self, state: GrowthState, depth: int = 0, entry: GrowthCheckpoint | None = None
    ) -> list[Candidate]:
        key = (state_digest(state), depth, content_digest(entry) if entry else None)
        if key in self.memo:
            return self.memo[key]
        if not self.budget.take("states", self.budget.limits.max_states):
            return []
        self.budget.maximum_depth = max(self.budget.maximum_depth, depth)
        if self.terminal(state, entry):
            return [
                Candidate(
                    GrowthPolicyNode(state_digest=key[0]), [state], [F(entry.time)] if entry else []
                )
            ]
        stop = (
            self.endpoint
            if self.endpoint is not None
            else (
                F(entry.time) + F(self.contract.spec.continuation_horizon)
                if entry
                else F(self.contract.spec.deadline)
            )
        )
        if F(state.elapsed) >= stop or depth >= self.contract.spec.max_decisions:
            return []
        if depth >= self.budget.limits.max_depth:
            self.budget.complete = False
            return []
        options: list[Candidate] = []
        entries = [entry]
        if entry is None and self.endpoint is None and self.entry_allowed(state):
            entries.append(GrowthCheckpoint(time=state.elapsed, capacities=state.capacities))
        for selected_entry in entries:
            for recipe in sorted(
                self.contract.spec.action_catalogue,
                key=lambda r: cast(ActionDocument, self.objects[r.action_digest]).spec.action_id,
            ):
                if self.excluded & set(recipe.interactions):
                    continue
                try:
                    action, _ = applicable(
                        self.contract, state, recipe, self.objects, self.frontier
                    )
                    effects = successors(state, recipe)
                    require(bool(effects), "growth_successor_incomplete")
                    child_options: list[list[Candidate]] = []
                    for effect in effects:
                        if not self.budget.take("expansions", self.budget.limits.max_expansions):
                            return options
                        next_state = transition(
                            self.contract, state, recipe, effect, self.objects, self.frontier
                        )
                        next_stop = (
                            F(selected_entry.time) + F(self.contract.spec.continuation_horizon)
                            if selected_entry
                            else stop
                        )
                        if F(next_state.elapsed) > next_stop:
                            child_options.append([])
                        else:
                            child_options.append(
                                self.enumerate(next_state, depth + 1, selected_entry)
                            )
                        if not child_options[-1]:
                            # An AND node with a missing child has no currently feasible policy.
                            break
                    for children in product(*child_options):
                        if not self.budget.take("policies", self.budget.limits.max_policies):
                            return options
                        node_count = 1 + sum(ch.node_count for ch in children)
                        if node_count > self.budget.limits.max_witness_nodes:
                            self.budget.complete = False
                            self.counterexamples.add("growth_witness_limit")
                            continue
                        node = GrowthPolicyNode(
                            state_digest=key[0],
                            action_id=action.spec.action_id,
                            entry=entry is None and selected_entry is not None,
                            branches={
                                e.successor_id: child.node
                                for e, child in zip(effects, children, strict=True)
                            },
                            effect_digests={e.successor_id: content_digest(e) for e in effects},
                        )
                        options.append(
                            Candidate(
                                node,
                                [s for ch in children for s in ch.terminals],
                                [t for ch in children for t in ch.entries],
                                node_count,
                            )
                        )
                except GrowthError as error:
                    self.counterexamples.add(error.code)
        if self.budget.complete:
            self.memo[key] = options
        return options


def objective(contract: GrowthContract, candidate: Candidate) -> GrowthObjective:
    return GrowthObjective(
        worst_entry_time=str(max(candidate.entries)),
        terminal_min_attainment=str(min(attainment(contract, s) for s in candidate.terminals)),
        worst_cost={
            k: str(max(F(s.spent.get(k, "0")) for s in candidate.terminals))
            for k in contract.spec.cost_order
        },
        worst_debt={
            k: str(
                max(
                    _sum(F(w.remaining) for w in s.obligations if w.stage == k)
                    for s in candidate.terminals
                )
            )
            for k in sorted(contract.spec.domains)
        },
        worst_duration=str(max(F(s.elapsed) for s in candidate.terminals)),
    )


def objective_key(contract: GrowthContract, candidate: Candidate) -> tuple[Any, ...]:
    obj = objective(contract, candidate)
    return (
        F(obj.worst_entry_time),
        -F(obj.terminal_min_attainment),
        *(F(obj.worst_cost[k]) for k in contract.spec.cost_order),
        *(F(obj.worst_debt[k]) for k in sorted(contract.spec.domains)),
        F(obj.worst_duration),
        candidate.node.action_id or "",
        content_digest(candidate.node),
    )


def compare(
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier | None = None,
) -> list[GrowthComparison]:
    """Reoptimize each restricted class from exactly the same charged checkpoint."""
    validate_contract(contract, objects)
    if frontier is not None:
        frontier_model.validate_frontier(contract, objects, frontier)
    start = initial_state(contract, frontier)
    results: list[GrowthComparison] = []
    for comparator in sorted(contract.spec.comparators, key=lambda x: x.comparator_id):
        for endpoint in sorted({F(w.end) for w in contract.spec.windows}):
            search = Search(
                contract,
                objects,
                Budget(contract.spec.search_limits),
                excluded=frozenset(comparator.excluded_interactions),
                endpoint=endpoint,
                frontier=frontier,
            )
            solution = search.scalar(start) if start.model_ids else None
            lower: Fraction | None = None
            upper: Fraction | None = None
            best: Candidate | None = None
            if solution:
                best = solution.candidate
                lower = solution.lower
                if search.budget.complete:
                    upper = solution.upper
            results.append(
                GrowthComparison(
                    comparator_id=comparator.comparator_id,
                    endpoint=str(endpoint),
                    status="inconsistent"
                    if not start.model_ids
                    else ("supported" if upper is not None else "undetermined"),
                    lower_bound=str(lower) if lower is not None else None,
                    upper_bound=str(upper) if upper is not None else None,
                    search=search.budget.report(),
                    matched_basis_digest=input_digest(contract, objects, frontier),
                    policy_digest=content_digest(best.node) if best else None,
                )
            )
    return results


@overload
def plan_growth(
    contract: GrowthContract, objects: dict[str, Document], frontier: None = None
) -> GrowthPlan: ...


@overload
def plan_growth(
    contract: GrowthContract, objects: dict[str, Document], frontier: GrowthCapabilityFrontier
) -> GrowthFrontierPlan: ...


def plan_growth(
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier | None = None,
) -> GrowthPlan | GrowthFrontierPlan:
    validate_contract(contract, objects)
    start = initial_state(contract, frontier)
    comparisons = compare(contract, objects, frontier)
    search = Search(
        contract,
        objects,
        Budget(contract.spec.search_limits),
        comparisons=comparisons,
        frontier=frontier,
    )
    candidates = search.enumerate(start) if start.model_ids else []
    candidates.sort(key=lambda candidate: objective_key(contract, candidate))
    best = candidates[0] if candidates else None
    complete = search.budget.complete and all(x.search.complete for x in comparisons)
    # A fallback only certifies a complete safe policy to the declared deadline.
    fallback_search = Search(
        contract,
        objects,
        Budget(contract.spec.search_limits),
        endpoint=F(contract.spec.deadline),
        frontier=frontier,
    )
    safe = fallback_search.scalar(start) if not best and start.model_ids else None
    fallback = safe.candidate.node if safe else None
    if not start.model_ids:
        code = "growth_inconsistent_models"
    elif not complete:
        code = "growth_unknown_due_to_budget"
    elif best:
        code = "growth_model_policy_found"
    else:
        code = "growth_no_guaranteed_entry"
    plan: GrowthPlan | GrowthFrontierPlan = GrowthPlan(
        metadata=contract.metadata,
        spec=GrowthPlanSpec(
            contract_digest=document_digest(contract),
            input_digest=input_digest(contract, objects, frontier),
            initial_state_digest=state_digest(start),
            code=code,
            solution_class="exact" if complete else "incomplete",
            predicted_entry="inconsistent"
            if not start.model_ids
            else ("supported" if best else "undetermined"),
            continuation="model-witness" if best else "unavailable",
            policy=best.node if best else None,
            policy_digest=content_digest(best.node) if best else None,
            objective=objective(contract, best) if best else None,
            safe_fallback=fallback,
            search=search.budget.report(),
            comparisons=comparisons,
            alternatives=sorted(
                {
                    p.node.action_id
                    for p in candidates
                    if p.node.action_id
                    and p.node.action_id != (best.node.action_id if best else None)
                }
            ),
            counterexamples=sorted(search.counterexamples),
            model_predicted_terminal=[frontier_model.base_state(s) for s in best.terminals]
            if best
            else [],
            required_authority=[
                "operator-external-runner-authorization",
                "admitted-capability",
                "independent-projection-quorum",
            ],
            next_evidence=contract.spec.required_entry_evidence,
            witness_expires=contract.spec.deadline,
            invalidate_on=INVALIDATE_ON,
        ),
    )
    if frontier is not None:
        plan = GrowthFrontierPlan(
            metadata=plan.metadata,
            spec=GrowthFrontierPlanSpec(
                **plan.spec.model_dump(),
                frontier_digest=document_digest(frontier),
                declared_frontier=frontier,
                initial_frontier_state=cast(GrowthFrontierState, start),
                terminal_frontier_states=[cast(GrowthFrontierState, s) for s in best.terminals]
                if best
                else [],
                frontier_diagnostics=frontier_model.diagnostics(
                    contract, objects, frontier, best.node if best else None
                ),
            ),
        )
    # Checker walks the submitted tree, without trusting the search or cached effects.
    if best:
        checked = check_plan(contract, objects, plan, frontier)
        plan = plan.model_copy(
            update={"spec": plan.spec.model_copy(update={"checker_digest": checked})}
        )
    elif fallback is not None:
        check_tree(
            contract,
            objects,
            fallback,
            start,
            endpoint=F(contract.spec.deadline),
            frontier=frontier,
        )
    if not best and start.model_ids:
        plan = plan.model_copy(
            update={
                "spec": plan.spec.model_copy(
                    update={"fallback_search": fallback_search.budget.report()}
                )
            }
        )
    return plan


def check_plan(
    contract: GrowthContract,
    objects: dict[str, Document],
    plan: GrowthPlan | GrowthFrontierPlan,
    frontier: GrowthCapabilityFrontier | None = None,
) -> str:
    validate_contract(contract, objects)
    require(
        isinstance(plan, GrowthFrontierPlan) == (frontier is not None),
        "growth_frontier_document_required",
    )
    if frontier is not None:
        frontier_model.validate_frontier(contract, objects, frontier)
        require(
            cast(GrowthFrontierPlan, plan).spec.frontier_digest == document_digest(frontier)
            and cast(GrowthFrontierPlan, plan).spec.declared_frontier == frontier,
            "growth_frontier_digest_mismatch",
        )
    require(
        plan.spec.contract_digest == document_digest(contract)
        and plan.spec.input_digest == input_digest(contract, objects, frontier),
        "growth_plan_input_mismatch",
    )
    start = initial_state(contract, frontier)
    require(plan.spec.initial_state_digest == state_digest(start), "growth_plan_state_mismatch")
    require(plan.spec.policy is not None, "growth_plan_policy_missing")
    root = cast(GrowthPolicyNode, plan.spec.policy)
    require(plan.spec.policy_digest == content_digest(root), "growth_plan_digest_mismatch")
    comparisons = compare(contract, objects, frontier)
    require(comparisons == plan.spec.comparisons, "growth_plan_comparison_mismatch")
    candidate = check_tree(
        contract, objects, root, start, comparisons=comparisons, frontier=frontier
    )
    require(plan.spec.objective == objective(contract, candidate), "growth_plan_objective_mismatch")
    require(
        plan.spec.model_predicted_terminal
        == [frontier_model.base_state(s) for s in candidate.terminals],
        "growth_plan_terminal_mismatch",
    )
    if isinstance(plan, GrowthFrontierPlan):
        require(
            plan.spec.initial_frontier_state == start
            and plan.spec.terminal_frontier_states == candidate.terminals,
            "growth_frontier_state_mismatch",
        )
        require(
            plan.spec.frontier_diagnostics
            == frontier_model.diagnostics(
                contract, objects, cast(GrowthCapabilityFrontier, frontier), root
            ),
            "growth_frontier_witness_mismatch",
        )
    return digest_bytes(
        canonical_bytes(
            {
                "checker": "growth-tree-checker-v1",
                "input": plan.spec.input_digest,
                "policy": plan.spec.policy_digest,
                "objective": objective(contract, candidate).model_dump(mode="json"),
            }
        )
    )


def check_tree(
    contract: GrowthContract,
    objects: dict[str, Document],
    root: GrowthPolicyNode,
    start: GrowthState,
    *,
    entry: GrowthCheckpoint | None = None,
    comparisons: list[GrowthComparison] | None = None,
    endpoint: Fraction | None = None,
    frontier: GrowthCapabilityFrontier | None = None,
) -> Candidate:
    """Independent all-prefix traversal, also used to revalidate a stored fallback."""
    checker = Search(
        contract,
        objects,
        Budget(contract.spec.search_limits),
        comparisons=comparisons or [],
        endpoint=endpoint,
        frontier=frontier,
    )
    terminals: list[GrowthState] = []
    entries: list[Fraction] = []
    count = 0

    def walk(
        node: GrowthPolicyNode, state: GrowthState, depth: int, entry: GrowthCheckpoint | None
    ) -> None:
        nonlocal count
        count += 1
        require(
            count <= contract.spec.search_limits.max_witness_nodes
            and depth <= contract.spec.max_decisions,
            "growth_checker_budget",
        )
        check_state(contract, state)
        require(bool(state.model_ids), "growth_inconsistent_models")
        require(node.state_digest == state_digest(state), "growth_plan_state_mismatch")
        if node.entry:
            require(entry is None and checker.entry_allowed(state), "growth_plan_entry_invalid")
            entry = GrowthCheckpoint(time=state.elapsed, capacities=state.capacities)
        if node.action_id is None:
            require(
                not node.branches and not node.effect_digests and checker.terminal(state, entry),
                "growth_plan_continuation_invalid",
            )
            terminals.append(state)
            if entry is not None:
                entries.append(F(entry.time))
            return
        matches = [
            r
            for r in contract.spec.action_catalogue
            if cast(ActionDocument, objects[r.action_digest]).spec.action_id == node.action_id
        ]
        require(len(matches) == 1, "growth_plan_action_invalid")
        recipe = matches[0]
        effects = successors(state, recipe)
        require(
            set(node.branches) == {e.successor_id for e in effects}
            and set(node.effect_digests) == set(node.branches)
            and bool(effects),
            "growth_plan_branches_invalid",
        )
        for effect in effects:
            require(
                node.effect_digests[effect.successor_id] == content_digest(effect),
                "growth_plan_effect_mismatch",
            )
            next_state = transition(contract, state, recipe, effect, objects, frontier)
            walk(node.branches[effect.successor_id], next_state, depth + 1, entry)

    walk(root, start, 0, entry)
    return Candidate(root, terminals, entries, count)
