# SPDX-License-Identifier: Apache-2.0
"""Strong-planner branch and dominance assurance for v0.6."""

from __future__ import annotations

from dataclasses import replace
from fractions import Fraction

from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    BranchEffect,
    CapabilityDocument,
    DimensionResult,
    ResourceObservationAttestation,
    TransformationAttestation,
)
from collective_phase_control_fabric.v6.planning import (
    _dominates,
    _eligible_at_state,
    _hard_filter,
    _initial_state,
    _resource_safe,
    _semantic_key,
    _strict_progress,
    _strong_tree,
    _successor,
    _worst_coordinates,
    plan_actions,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.science import audit_snapshot
from tests.test_v6_science_planner import action, build_science_fixture, capability
from tests.v6_helpers import metadata


def blocked_fixture(*blockers: str) -> tuple[object, dict[str, object], object]:
    snapshot, raw = build_science_fixture()
    objects = dict(raw)
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    dimensions = dict(profile.dimensions)
    dimensions["causal_formation"] = DimensionResult(status="violated", blockers=list(blockers))
    return (
        snapshot,
        objects,
        profile.model_copy(
            update={"dimensions": dimensions, "operational_organization_compatible": False}
        ),
    )


def capability_with_branches(
    action_id: str,
    branches: list[BranchEffect],
    *,
    repeatable: bool = False,
    progress_measure: str | None = None,
) -> CapabilityDocument:
    original = capability(action_id, "blocker", "1")
    return original.model_copy(
        update={
            "metadata": metadata(f"cap-{action_id}"),
            "spec": original.spec.model_copy(
                update={
                    "capability_id": f"cap-{action_id}",
                    "branches": branches,
                    "repeatable": repeatable,
                    "progress_measure": progress_measure,
                }
            ),
        }
    )


def four(**changes: object) -> list[BranchEffect]:
    values: dict[str, object] = {
        "resource_delta_lower": {"A": "0"},
        "resource_delta_upper": {"A": "0"},
    }
    values.update(changes)
    return [
        BranchEffect(
            outcome=outcome,  # type: ignore[arg-type]
            **values,
        )
        for outcome in ("success", "partial", "failure", "timeout")
    ]


def test_control_state_digest_initialization_and_progress_measures() -> None:
    snapshot, objects, profile = blocked_fixture("blocker")
    state = _initial_state(snapshot, objects, profile)  # type: ignore[arg-type]
    assert dict(state.resources)["A"] == Fraction(10)
    assert state.blockers == frozenset({"blocker"})
    assert state.digest() == state.digest()

    _, observation = next(
        (digest, item)
        for digest, item in objects.items()
        if isinstance(item, ResourceObservationAttestation)
    )
    duplicate = observation.model_copy(update={"metadata": metadata("duplicate-A")})
    objects[document_digest(duplicate)] = duplicate
    unreferenced = _initial_state(snapshot, objects, profile)  # type: ignore[arg-type]
    assert dict(unreferenced.resources)["A"] == Fraction(10)

    branch = BranchEffect(
        outcome="success",
        must_add=["sha256:" + "1" * 64],
        resource_delta_lower={"A": "1"},
        resource_delta_upper={"A": "1"},
        guaranteed_evidence_routes=["route"],
        resolves_blockers=["blocker"],
        debt=["debt"],
        rollback_obligations=["rollback"],
    )
    successor = _successor(state, branch)
    assert _strict_progress(state, successor, "blocker_frontier")
    assert _strict_progress(state, successor, "evidence_routes")
    assert _strict_progress(state, successor, "resource:A")
    assert not _strict_progress(state, successor, "resource:missing")
    assert not _strict_progress(state, successor, None)
    assert successor.debt == frozenset({"debt"})
    assert successor.rollback == frozenset({"rollback"})
    assert successor.pending_projections == frozenset({"sha256:" + "1" * 64})


def test_hypothetical_outputs_remain_pending_and_removals_trigger_fresh_audit() -> None:
    snapshot, objects, profile = blocked_fixture("blocker")
    state = _initial_state(snapshot, objects, profile)  # type: ignore[arg-type]
    added = "sha256:" + "1" * 64
    optional = "sha256:" + "2" * 64
    pending = _successor(
        state,
        BranchEffect(
            outcome="success",
            must_add=[added],
            may_add=[optional],
            guaranteed_evidence_routes=["route"],
            resolves_blockers=["blocker"],
            resource_delta_lower={"A": "-1"},
            resource_delta_upper={"A": "0"},
            debt=["debt"],
            rollback_obligations=["rollback"],
            hazards_added=["hazard"],
            verification_load_upper="2",
            independence_erosion_upper="1",
            correlation_concentration_upper="3",
            cut_exposure_upper="4",
            time_upper="5",
            cost_upper="6",
            quality_lower="7",
            safety_lower="8",
        ),
    )
    assert added not in pending.live_objects
    assert optional not in pending.live_objects
    assert pending.pending_projections == frozenset({added})
    assert pending.addressed_blockers == frozenset({"blocker"})
    assert pending.resource_trajectory[-1] == (("A", Fraction(9)),)
    assert pending.hazards == frozenset({"hazard"})
    assert pending.verification_load == 2
    assert pending.independence_erosion == 1
    assert pending.correlation_concentration == 3
    assert pending.cut_exposure == 4
    assert pending.elapsed_time == 5 and pending.monetary_cost == 6
    assert pending.quality_floor == 7 and pending.safety_floor == 8

    transform_digest = next(
        digest for digest, item in objects.items() if isinstance(item, TransformationAttestation)
    )
    reduced = _successor(
        state,
        BranchEffect(outcome="failure", must_remove=[transform_digest]),
        baseline_snapshot=snapshot,
        objects=objects,  # type: ignore[arg-type]
    )
    assert transform_digest not in reduced.live_objects
    assert reduced.snapshot_digest != state.snapshot_digest
    assert dict(reduced.dimension_statuses)["causal_formation"] != "satisfied"
    assert any("formation" in blocker for blocker in reduced.blockers)


def test_hard_filter_reports_all_authority_schema_resource_and_repeatability_defects() -> None:
    snapshot, objects, profile = blocked_fixture("blocker")
    state = _initial_state(snapshot, objects, profile)  # type: ignore[arg-type]
    cap = capability("filter", "blocker", "1")
    item = action("filter", cap)
    assert _hard_filter(state, item, None) == ["capability_missing"]

    unknown_schema = cap.model_copy(
        update={
            "spec": cap.spec.model_copy(
                update={
                    "output_schema_name": "unknown-kind",
                    "output_schema_digest": "sha256:" + "0" * 64,
                    "repeatable": True,
                    "progress_measure": "resource:missing",
                    "branches": four(
                        must_remove=["sha256:" + "2" * 64],
                        resource_delta_lower={"A": "-20"},
                        resource_delta_upper={"A": "-20"},
                    ),
                }
            )
        }
    )
    forged_action = ActionDocument(
        metadata=metadata("forged"),
        spec=item.spec.model_copy(
            update={
                "capability_digest": "sha256:" + "3" * 64,
                "required_object_digests": ["sha256:" + "4" * 64],
                "protected_object_digests": ["sha256:" + "2" * 64],
            }
        ),
    )
    reasons = _hard_filter(state, forged_action, unknown_schema)
    assert "capability_digest_mismatch" in reasons
    assert "required_object_missing" in reasons
    assert "capability_output_schema_unknown" in reasons
    assert any(item.startswith("protected_object_may_be_removed:") for item in reasons)
    assert any(item.startswith("resource_floor_may_fail:") for item in reasons)
    assert any(item.startswith("repeatability_progress_not_strict:") for item in reasons)

    digest_mismatch = cap.model_copy(
        update={"spec": cap.spec.model_copy(update={"output_schema_digest": "sha256:" + "5" * 64})}
    )
    matching = action("schema-digest", digest_mismatch)
    assert "capability_output_schema_digest_mismatch" in _hard_filter(
        state, matching, digest_mismatch
    )

    hazardous_state = replace(state, hazards=frozenset({"network-access"}))
    prohibited = item.model_copy(
        update={"spec": item.spec.model_copy(update={"prohibited_hazards": ["network-access"]})}
    )
    assert "prohibited_hazard_active" in _hard_filter(hazardous_state, prohibited, cap)


def test_resource_safety_semantic_key_worst_case_and_pareto_directions() -> None:
    snapshot, objects, profile = blocked_fixture("blocker")
    state = _initial_state(snapshot, objects, profile)  # type: ignore[arg-type]
    unsafe = BranchEffect(
        outcome="failure",
        resource_delta_lower={"A": "-10"},
        resource_delta_upper={"A": "0"},
    )
    assert not _resource_safe(state, unsafe)

    better = capability("better", "blocker", "1")
    worse = capability("worse", "blocker", "2")
    coordinates = _worst_coordinates(better)
    assert coordinates["resolved"] == frozenset({"blocker"})
    assert coordinates["evidence"] == frozenset({"typed-evidence-route"})
    assert _dominates(better, worse)
    assert not _dominates(worse, better)
    assert not _dominates(better, better)
    assert _semantic_key(action("one", better), better) == _semantic_key(
        action("two", better), better
    )
    assert _eligible_at_state(state, [(action("better", better), better)]) == [
        (action("better", better), better)
    ]


def test_strong_tree_detects_cycles_unsafe_branches_and_horizon_exhaustion() -> None:
    snapshot, objects, profile = blocked_fixture("blocker")
    state = _initial_state(snapshot, objects, profile)  # type: ignore[arg-type]
    progress = capability("progress", "blocker", "1")
    progress_action = action("progress", progress)
    state_key = (state.digest(), progress_action.spec.action_id)
    cycle = _strong_tree(
        state,
        progress_action,
        progress,
        [(progress_action, progress)],
        2,
        frozenset({state_key}),
    )
    assert not cycle.strong
    assert all(value is None for value in cycle.branches.values())

    unsafe = capability_with_branches(
        "unsafe",
        four(resource_delta_lower={"A": "-20"}, resource_delta_upper={"A": "-20"}),
    )
    unsafe_action = action("unsafe", unsafe)
    unsafe_tree = _strong_tree(
        state, unsafe_action, unsafe, [(unsafe_action, unsafe)], 1, frozenset()
    )
    assert not unsafe_tree.strong

    stalled = capability("stalled", "different", "1")
    stalled_action = action("stalled", stalled)
    exhausted = _strong_tree(
        state, stalled_action, stalled, [(stalled_action, stalled)], 1, frozenset()
    )
    assert not exhausted.strong


def test_strong_tree_builds_a_safe_two_step_policy_for_every_outcome() -> None:
    snapshot, objects, profile = blocked_fixture("first-blocker", "second-blocker")
    state = _initial_state(snapshot, objects, profile)  # type: ignore[arg-type]
    first = capability("first", "first-blocker", "1")
    second = capability("second", "second-blocker", "1")
    first_action = action("first", first)
    second_action = action("second", second)
    tree = _strong_tree(
        state,
        first_action,
        first,
        [(first_action, first), (second_action, second)],
        2,
        frozenset(),
    )
    assert tree.strong
    assert all(child is not None and child.strong for child in tree.branches.values())
    assert {child.action_id for child in tree.branches.values() if child is not None} == {"second"}

    stranded = _strong_tree(
        state,
        first_action,
        first,
        [(first_action, first)],
        2,
        frozenset(),
    )
    assert not stranded.strong


def test_public_planner_handles_invalid_duplicate_missing_and_incomparable_actions() -> None:
    snapshot, objects, profile = blocked_fixture("blocker")
    invalid = plan_actions(
        snapshot,
        objects,
        profile,
        [],
        [],
        horizon=4,  # type: ignore[arg-type]
    )
    assert invalid.code == "planning_horizon_invalid"

    cap = capability("candidate", "blocker", "1")
    cap_action = action("candidate", cap)
    duplicate_capability = plan_actions(
        snapshot,
        objects,  # type: ignore[arg-type]
        profile,  # type: ignore[arg-type]
        [cap_action],
        [cap, cap],
    )
    assert duplicate_capability.rejected["candidate"] == ["capability_digest_duplicate"]

    missing = ActionDocument(
        metadata=metadata("missing"),
        spec=cap_action.spec.model_copy(
            update={
                "action_id": "missing",
                "capability_digest": "sha256:" + "9" * 64,
            }
        ),
    )
    semantic_duplicate = action("semantic-duplicate", cap)
    result = plan_actions(
        snapshot,
        objects,  # type: ignore[arg-type]
        profile,  # type: ignore[arg-type]
        [missing, cap_action, semantic_duplicate],
        [cap],
    )
    assert result.primary_action_id == "candidate"
    assert result.rejected["missing"] == ["capability_missing"]
    assert result.rejected["semantic-duplicate"] == ["exact_semantic_duplicate"]

    low_cost = capability("low-cost", "blocker", "1")
    high_quality = low_cost.model_copy(
        update={
            "metadata": metadata("cap-high-quality"),
            "spec": low_cost.spec.model_copy(
                update={
                    "capability_id": "cap-high-quality",
                    "branches": [
                        branch.model_copy(update={"cost_upper": "2", "quality_lower": "2"})
                        for branch in low_cost.spec.branches
                    ],
                }
            ),
        }
    )
    alternatives = plan_actions(
        snapshot,
        objects,  # type: ignore[arg-type]
        profile,  # type: ignore[arg-type]
        [action("low-cost", low_cost), action("high-quality", high_quality)],
        [low_cost, high_quality],
    )
    assert alternatives.code == "incomparable_safe_alternatives"
    assert alternatives.alternative_action_ids == ["high-quality", "low-cost"]
