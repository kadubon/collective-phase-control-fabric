# SPDX-License-Identifier: Apache-2.0
"""Conservative four-branch AND-OR control for CPCF v0.3."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.science_v3 import science_audit_v3
from collective_phase_control_fabric.types import JsonObject, id_set
from collective_phase_control_fabric.workspace_v3 import valid_projections_v3

BRANCHES = ("success", "partial", "failure", "timeout")


def _objects(root: Path) -> tuple[JsonObject, dict[str, list[JsonObject]]]:
    manifest, projections = valid_projections_v3(root)
    result: dict[str, list[JsonObject]] = {}
    for record, value in projections:
        name = str(record["schema_ref"]).split("@", 1)[0]
        result.setdefault(name, []).append(value)
    return manifest, result


def _marking(objects: dict[str, list[JsonObject]]) -> JsonObject:
    values = objects.get("state-marking", [])
    if len(values) != 1:
        return {"states": set(), "resources": {}}
    value = values[0]
    resources = {
        key: Fraction(str(item["quantity"]))
        for key, item in value.get("coordinates", {}).items()
        if isinstance(item, dict)
    }
    units = {
        key: str(item["unit"])
        for key, item in value.get("coordinates", {}).items()
        if isinstance(item, dict)
    }
    return {"states": id_set(value.get("state_refs")), "resources": resources, "units": units}


def _apply_branch(state: JsonObject, branch: JsonObject) -> JsonObject:
    states = set(cast(set[str], state["states"]))
    states -= id_set(branch.get("may_remove")) | id_set(branch.get("must_remove"))
    states |= id_set(branch.get("must_add"))
    resources = dict(cast(dict[str, Fraction], state["resources"]))
    units = dict(cast(dict[str, str], state.get("units", {})))
    for coordinate, interval in branch.get("resource_intervals", {}).items():
        if isinstance(interval, dict):
            resources[coordinate] = resources.get(coordinate, Fraction(0)) + Fraction(
                str(interval["lower"])
            )
            units.setdefault(coordinate, str(interval["unit"]))
    return {"states": states, "resources": resources, "units": units}


def _branch_safe(
    state: JsonObject,
    branch: JsonObject,
    contract: JsonObject,
    authority_refs: set[str],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    for coordinate, interval in branch.get("resource_intervals", {}).items():
        if not isinstance(interval, dict) or interval.get("unit") != state.get("units", {}).get(
            coordinate
        ):
            reasons.append(f"resource_interval_unit_mismatch:{coordinate}")
    projected = _apply_branch(state, branch)
    if not authority_refs <= cast(set[str], projected["states"]):
        reasons.append("authority_not_preserved")
    for coordinate, floor in contract.get("protected_floors", {}).items():
        if not isinstance(floor, dict):
            reasons.append(f"protected_floor_malformed:{coordinate}")
            continue
        if projected["units"].get(coordinate) != floor.get("unit"):
            reasons.append(f"protected_floor_unit_mismatch:{coordinate}")
            continue
        if projected["resources"].get(coordinate, Fraction(0)) < Fraction(str(floor["quantity"])):
            reasons.append(f"protected_floor_violation:{coordinate}")
    return not reasons, reasons


def _eligible(
    actions: list[JsonObject],
    capabilities: dict[str, JsonObject],
    effects: dict[str, JsonObject],
    state: JsonObject,
    contract: JsonObject,
    exhausted_actions: set[str] | None = None,
) -> tuple[list[JsonObject], list[JsonObject]]:
    eligible: list[JsonObject] = []
    rejected: list[JsonObject] = []
    epoch = datetime.fromisoformat(str(contract["evaluation_time"]).replace("Z", "+00:00"))
    for action in actions:
        action_id = str(action.get("action_id"))
        reasons: list[str] = []
        if action_id in (exhausted_actions or set()):
            reasons.append("action_retry_limit_reached")
        capability = capabilities.get(str(action.get("capability_ref")))
        if capability is None:
            reasons.append("signed_capability_missing")
        try:
            if datetime.fromisoformat(str(action["expires_at"]).replace("Z", "+00:00")) < epoch:
                reasons.append("action_expired")
        except (KeyError, ValueError):
            reasons.append("action_expiry_invalid")
        available = cast(set[str], state["states"])
        if not id_set(action.get("input_refs")) <= available:
            reasons.append("action_inputs_unavailable")
        authority = id_set(action.get("required_authority_refs"))
        if not authority <= available:
            reasons.append("action_authority_unavailable")
        hazards = id_set(action.get("required_hazard_refs"))
        if not hazards <= available:
            reasons.append("action_hazard_guard_unavailable")
        effect = effects.get(str(capability.get("branch_effect_ref"))) if capability else None
        if effect is None:
            reasons.append("signed_branch_effect_missing")
        branch_states: dict[str, JsonObject] = {}
        branch_reports: dict[str, JsonObject] = {}
        if effect is not None:
            branches = effect.get("branches", {})
            for branch_name in BRANCHES:
                branch = branches.get(branch_name) if isinstance(branches, dict) else None
                if not isinstance(branch, dict):
                    reasons.append(f"branch_missing:{branch_name}")
                    continue
                safe, unsafe = _branch_safe(state, branch, contract, authority | hazards)
                unsafe = [
                    "hazard_guard_not_preserved"
                    if reason == "authority_not_preserved" and hazards
                    else reason
                    for reason in unsafe
                ]
                branch_states[branch_name] = _apply_branch(state, branch)
                branch_reports[branch_name] = {
                    "safe": safe,
                    "unsafe_reasons": unsafe,
                    "guaranteed_addition_count": len(id_set(branch.get("must_add"))),
                    "optional_addition_credit": 0,
                    "debt_count": len(id_set(branch.get("debt"))),
                    "resource_lower_changes": {
                        key: str(item.get("lower"))
                        for key, item in branch.get("resource_intervals", {}).items()
                        if isinstance(item, dict)
                    },
                    "resource_units": {
                        key: str(item.get("unit"))
                        for key, item in branch.get("resource_intervals", {}).items()
                        if isinstance(item, dict)
                    },
                }
                if not safe:
                    reasons.append(f"unsafe_branch:{branch_name}")
        if reasons:
            rejected.append({"action_id": action_id, "reasons": sorted(set(reasons))})
            continue
        eligible.append(
            {
                **action,
                "capability": capability,
                "effect_contract": effect,
                "branch_states": branch_states,
                "branch_reports": branch_reports,
            }
        )
    return eligible, rejected


def _dominates(left: JsonObject, right: JsonObject) -> bool:
    strict = False
    for branch in BRANCHES:
        left_report = left["branch_reports"][branch]
        right_report = right["branch_reports"][branch]
        if left_report["guaranteed_addition_count"] < right_report["guaranteed_addition_count"]:
            return False
        strict |= (
            left_report["guaranteed_addition_count"] > right_report["guaranteed_addition_count"]
        )
        if left_report["debt_count"] > right_report["debt_count"]:
            return False
        strict |= left_report["debt_count"] < right_report["debt_count"]
        left_resources = left_report["resource_lower_changes"]
        right_resources = right_report["resource_lower_changes"]
        if set(left_resources) != set(right_resources):
            return False
        if left_report["resource_units"] != right_report["resource_units"]:
            return False
        for coordinate in left_resources:
            # A larger guaranteed lower change preserves more resource.
            if Fraction(left_resources[coordinate]) < Fraction(right_resources[coordinate]):
                return False
            strict |= Fraction(left_resources[coordinate]) > Fraction(right_resources[coordinate])
    return strict


def _public_action(action: JsonObject) -> JsonObject:
    return {
        key: value
        for key, value in action.items()
        if key not in {"branch_states", "capability", "effect_contract"}
    }


def _policy_tree(
    action: JsonObject,
    actions: list[JsonObject],
    capabilities: dict[str, JsonObject],
    effects: dict[str, JsonObject],
    contract: JsonObject,
    depth: int,
    width: int,
) -> JsonObject:
    targets = id_set(contract.get("target_states"))
    outcomes: dict[str, JsonObject] = {}
    strong = True
    for branch in BRANCHES:
        state = action["branch_states"][branch]
        reached = targets <= cast(set[str], state["states"])
        if reached or depth <= 1:
            outcomes[branch] = {"target_guaranteed": reached, "next_actions": []}
            strong &= reached
            continue
        children, _ = _eligible(actions, capabilities, effects, state, contract)
        children = sorted(children, key=lambda item: str(item.get("action_id")))[:width]
        child_nodes = [
            _policy_tree(child, actions, capabilities, effects, contract, depth - 1, width)
            for child in children
        ]
        branch_strong = any(child["strong_target_policy"] for child in child_nodes)
        outcomes[branch] = {
            "target_guaranteed": False,
            "next_actions": child_nodes,
            "branch_has_strong_continuation": branch_strong,
        }
        strong &= branch_strong
    return {
        "action_id": action.get("action_id"),
        "outcomes": outcomes,
        "strong_target_policy": strong,
        "fairness_assumed": False,
    }


def plan_v3(root: Path) -> JsonObject:
    try:
        manifest, objects = _objects(root)
        from collective_phase_control_fabric.generation import GenerationStore

        store = GenerationStore(root)
        contract = store.get_json(str(manifest["contract_digest"]))
        if not isinstance(contract, dict):
            raise ValueError("contract must be an object")
        contract = deepcopy(contract)
        contract["evaluation_time"] = manifest["analysis_epoch"]
    except (OSError, KeyError, ValueError) as error:
        return {
            "command_status": "failed",
            "failure_code": "planner_workspace_invalid",
            "detail": str(error),
        }
    actions = sorted(objects.get("action", []), key=lambda item: str(item.get("action_id")))
    candidate_cap = int(contract["control_policy"]["candidate_cap"])
    capped = actions[:candidate_cap]
    capabilities = {
        str(item.get("capability_id")): item for item in objects.get("adapter-capability", [])
    }
    effects = {
        str(item.get("effect_id")): item for item in objects.get("branch-effect-contract", [])
    }
    state = _marking(objects)
    retry_limit = int(contract["control_policy"]["retry_limit"])
    no_progress_counts: dict[str, int] = {}
    for event in manifest.get("history", []):
        if (
            isinstance(event, dict)
            and event.get("event_type") == "action_executed"
            and event.get("progress") == "no_progress"
        ):
            action_id = str(event.get("action_id"))
            no_progress_counts[action_id] = no_progress_counts.get(action_id, 0) + 1
    exhausted = {
        action_id for action_id, count in no_progress_counts.items() if count > retry_limit
    }
    eligible, rejected = _eligible(
        capped, capabilities, effects, state, contract, exhausted_actions=exhausted
    )
    nondominated = [
        item
        for item in eligible
        if not any(_dominates(other, item) for other in eligible if other is not item)
    ]
    strict = [
        item
        for item in eligible
        if all(other is item or _dominates(item, other) for other in eligible)
    ]
    primary = strict[0] if len(strict) == 1 else None
    horizon = int(contract["control_policy"]["planning_horizon"])
    width = int(contract["control_policy"]["beam_width"])
    policy_trees = (
        [
            _policy_tree(item, capped, capabilities, effects, contract, horizon, width)
            for item in sorted(nondominated, key=lambda action: str(action.get("action_id")))[
                :width
            ]
        ]
        if horizon > 1
        else []
    )
    audit = science_audit_v3(root)
    return {
        "command_status": "ok",
        "generation_id": manifest["generation_id"],
        "primary_action": _public_action(primary) if primary else None,
        "pareto_alternatives": [
            _public_action(item)
            for item in sorted(nondominated, key=lambda action: str(action.get("action_id")))[:3]
        ]
        if primary is None
        else [],
        "rejected_actions": rejected,
        "candidate_count_before_cap": len(actions),
        "candidate_cap": candidate_cap,
        "selection_method": "four_branch_worst_case_unit_separated_pareto",
        "solution_class": "exact" if horizon == 1 else "approximate",
        "planning_horizon": horizon,
        "beam_width": None if horizon == 1 else width,
        "and_or_policy_trees": policy_trees,
        "one_step_execution_limit": 1,
        "success_probability_used": False,
        "optional_progress_credit": False,
        "current_structural_organization_level": audit.get("structural_organization_level"),
        "operational_acceleration": audit.get("operational_acceleration"),
    }
