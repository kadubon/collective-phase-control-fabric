# SPDX-License-Identifier: Apache-2.0
"""Four-outcome evidence-bound contingent control for CPCF v0.4."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.limits import MAX_ACTIONS, MAX_ELIGIBLE_ACTIONS
from collective_phase_control_fabric.science_v4 import science_audit_v4
from collective_phase_control_fabric.types import JsonObject, id_set
from collective_phase_control_fabric.workspace_v4 import active_attestations_v4, response

BRANCHES = ("success", "partial", "failure", "timeout")


def _attributes(statement: JsonObject) -> JsonObject:
    payload = statement.get("payload")
    if not isinstance(payload, dict):
        return {}
    attributes = payload.get("attributes")
    return attributes if isinstance(attributes, dict) else {}


def _action_id(statement: JsonObject) -> str:
    payload = statement.get("payload")
    return str(payload.get("subject_id")) if isinstance(payload, dict) else ""


def _actions(statements: list[JsonObject]) -> list[JsonObject]:
    return [
        item
        for item in statements
        if isinstance(item.get("payload"), dict)
        and item["payload"].get("record_type") == "evidence"
        and _attributes(item).get("evidence_type") == "action"
    ]


def _initial_state(statements: list[JsonObject], audit: JsonObject) -> JsonObject:
    states: set[str] = set()
    resources: dict[str, Fraction] = {}
    units: dict[str, str] = {}
    authority: set[str] = set()
    hazards: set[str] = set()
    independence: set[str] = set()
    for statement in statements:
        payload = statement.get("payload")
        if not isinstance(payload, dict):
            continue
        kind = payload.get("record_type")
        subject = str(payload.get("subject_id"))
        attributes = _attributes(statement)
        if kind == "state" and attributes.get("available") is True:
            states.add(subject)
        elif kind == "authority":
            states.add(subject)
            authority.add(subject)
        elif kind == "hazard":
            states.add(subject)
            hazards.add(subject)
        elif kind == "resource_observation":
            coordinate = str(attributes.get("coordinate"))
            try:
                resources[coordinate] = Fraction(str(attributes["quantity"]))
                units[coordinate] = str(attributes["unit"])
            except (KeyError, ValueError, ZeroDivisionError):
                continue
        elif kind == "independence":
            independence.add(subject)
    return {
        "states": states,
        "resources": resources,
        "units": units,
        "debt": set(),
        "verification_load": Fraction(0),
        "independence_domains": independence,
        "authority": authority,
        "hazards": hazards,
        "scientific_profile": deepcopy(audit.get("operational_organization_profile", {})),
        "trial_bindings": set(),
    }


def _branch_state(state: JsonObject, branch: JsonObject) -> JsonObject:
    result = deepcopy(state)
    states = set(cast(set[str], result["states"]))
    states -= id_set(branch.get("must_remove")) | id_set(branch.get("may_remove"))
    states |= id_set(branch.get("must_add"))
    result["states"] = states
    resources = dict(cast(dict[str, Fraction], result["resources"]))
    for coordinate, interval in branch.get("resource_intervals", {}).items():
        if isinstance(interval, dict):
            resources[str(coordinate)] = resources.get(str(coordinate), Fraction(0)) + Fraction(
                str(interval.get("lower", "0"))
            )
    result["resources"] = resources
    result["debt"] = set(cast(set[str], result["debt"])) | id_set(branch.get("debt"))
    result["verification_load"] = cast(Fraction, result["verification_load"]) + Fraction(
        str(branch.get("verification_load_upper", "0"))
    )
    erosion = id_set(branch.get("independence_domains_removed"))
    result["independence_domains"] = set(cast(set[str], result["independence_domains"])) - erosion
    result["authority"] = set(cast(set[str], result["authority"])) & states
    result["hazards"] = set(cast(set[str], result["hazards"])) & states
    return result


def _safe_branch(
    state: JsonObject,
    branch: JsonObject,
    contract: JsonObject,
    required_authority: set[str],
    required_hazards: set[str],
) -> tuple[bool, list[str], JsonObject]:
    reasons: list[str] = []
    try:
        projected = _branch_state(state, branch)
    except (ValueError, ZeroDivisionError):
        return False, ["branch_interval_invalid"], state
    if not required_authority <= cast(set[str], projected["authority"]):
        reasons.append("authority_not_preserved")
    if not required_hazards <= cast(set[str], projected["hazards"]):
        reasons.append("hazard_guard_not_preserved")
    for coordinate, floor in contract.get("protected_floors", {}).items():
        if not isinstance(floor, dict):
            reasons.append(f"protected_floor_invalid:{coordinate}")
            continue
        if projected["units"].get(coordinate) != floor.get("unit"):
            reasons.append(f"protected_floor_unit_mismatch:{coordinate}")
        elif projected["resources"].get(coordinate, Fraction(0)) < Fraction(str(floor["quantity"])):
            reasons.append(f"protected_floor_violation:{coordinate}")
    if cast(Fraction, projected["verification_load"]) >= 1:
        reasons.append("verification_capacity_overloaded")
    return not reasons, reasons, projected


def _eligible(
    actions: list[JsonObject], state: JsonObject, contract: JsonObject, epoch: str
) -> tuple[list[JsonObject], list[JsonObject]]:
    accepted: list[JsonObject] = []
    rejected: list[JsonObject] = []
    evaluated = datetime.fromisoformat(epoch.replace("Z", "+00:00"))
    for statement in sorted(actions, key=_action_id):
        action_id = _action_id(statement)
        attributes = _attributes(statement)
        reasons: list[str] = []
        try:
            expires = datetime.fromisoformat(str(attributes["expires_at"]).replace("Z", "+00:00"))
            if expires < evaluated:
                reasons.append("action_expired")
        except (KeyError, ValueError):
            reasons.append("action_expiry_invalid")
        if not id_set(attributes.get("input_refs")) <= cast(set[str], state["states"]):
            reasons.append("action_inputs_unavailable")
        authority = id_set(attributes.get("required_authority_refs"))
        hazards = id_set(attributes.get("required_hazard_refs"))
        if not authority <= cast(set[str], state["authority"]):
            reasons.append("action_authority_unavailable")
        if not hazards <= cast(set[str], state["hazards"]):
            reasons.append("action_hazard_guard_unavailable")
        branches = attributes.get("branches")
        branch_states: dict[str, JsonObject] = {}
        branch_reports: dict[str, JsonObject] = {}
        if not isinstance(branches, dict):
            reasons.append("branch_effect_contract_missing")
        else:
            for name in BRANCHES:
                branch = branches.get(name)
                if not isinstance(branch, dict):
                    reasons.append(f"branch_missing:{name}")
                    continue
                safe, unsafe, successor = _safe_branch(state, branch, contract, authority, hazards)
                branch_states[name] = successor
                branch_reports[name] = {
                    "safe": safe,
                    "unsafe_reasons": unsafe,
                    "guaranteed_additions": sorted(id_set(branch.get("must_add"))),
                    "optional_addition_credit": 0,
                    "debt": sorted(id_set(branch.get("debt"))),
                    "resource_intervals": branch.get("resource_intervals", {}),
                    "time_interval": branch.get("time_interval"),
                    "cost_interval": branch.get("cost_interval"),
                    "quality_interval": branch.get("quality_interval"),
                    "verification_load_upper": branch.get("verification_load_upper", "0"),
                    "independence_erosion_count": len(
                        id_set(branch.get("independence_domains_removed"))
                    ),
                }
                if not safe:
                    reasons.append(f"unsafe_branch:{name}")
        if reasons:
            rejected.append({"action_id": action_id, "reasons": sorted(set(reasons))})
        else:
            accepted.append(
                {
                    "action_id": action_id,
                    "statement": statement,
                    "attributes": attributes,
                    "branch_states": branch_states,
                    "branch_reports": branch_reports,
                }
            )
    return accepted, rejected


def _interval_not_worse(left: object, right: object, *, prefer_larger: bool) -> tuple[bool, bool]:
    if not isinstance(left, dict) or not isinstance(right, dict):
        return (left == right), False
    if left.get("unit") != right.get("unit"):
        return False, False
    try:
        left_value = Fraction(str(left["lower"] if prefer_larger else left["upper"]))
        right_value = Fraction(str(right["lower"] if prefer_larger else right["upper"]))
    except (KeyError, ValueError, ZeroDivisionError):
        return False, False
    return (
        left_value >= right_value if prefer_larger else left_value <= right_value,
        left_value != right_value,
    )


def _dominates(left: JsonObject, right: JsonObject) -> bool:
    strict = False
    for name in BRANCHES:
        lhs = left["branch_reports"][name]
        rhs = right["branch_reports"][name]
        if len(lhs["guaranteed_additions"]) < len(rhs["guaranteed_additions"]):
            return False
        strict |= len(lhs["guaranteed_additions"]) > len(rhs["guaranteed_additions"])
        if len(lhs["debt"]) > len(rhs["debt"]):
            return False
        strict |= len(lhs["debt"]) < len(rhs["debt"])
        for coordinate in ("time_interval", "cost_interval"):
            okay, changed = _interval_not_worse(
                lhs[coordinate], rhs[coordinate], prefer_larger=False
            )
            if not okay:
                return False
            strict |= changed
        okay, changed = _interval_not_worse(
            lhs["quality_interval"], rhs["quality_interval"], prefer_larger=True
        )
        if not okay:
            return False
        strict |= changed
        try:
            left_load = Fraction(str(lhs["verification_load_upper"]))
            right_load = Fraction(str(rhs["verification_load_upper"]))
        except (ValueError, ZeroDivisionError):
            return False
        if (
            left_load > right_load
            or lhs["independence_erosion_count"] > rhs["independence_erosion_count"]
        ):
            return False
        strict |= left_load < right_load
        strict |= lhs["independence_erosion_count"] < rhs["independence_erosion_count"]
        left_resources = lhs["resource_intervals"]
        right_resources = rhs["resource_intervals"]
        if not isinstance(left_resources, dict) or set(left_resources) != set(right_resources):
            return False
        for coordinate in left_resources:
            okay, changed = _interval_not_worse(
                left_resources[coordinate], right_resources[coordinate], prefer_larger=True
            )
            if not okay:
                return False
            strict |= changed
    return strict


def _public(action: JsonObject) -> JsonObject:
    return {
        "action_id": action["action_id"],
        "branches": action["branch_reports"],
        "repeatable": action["attributes"].get("repeatable") is True,
    }


def _tree(
    action: JsonObject,
    all_actions: list[JsonObject],
    contract: JsonObject,
    epoch: str,
    targets: set[str],
    depth: int,
    width: int,
    visited: set[tuple[str, tuple[str, ...]]],
) -> JsonObject:
    outcomes: dict[str, JsonObject] = {}
    strong = True
    for name in BRANCHES:
        state = action["branch_states"][name]
        reached = targets <= cast(set[str], state["states"])
        if reached:
            outcomes[name] = {"target_guaranteed": True, "continuations": []}
            continue
        if depth <= 1:
            outcomes[name] = {"target_guaranteed": False, "continuations": []}
            strong = False
            continue
        key = (str(action["action_id"]), tuple(sorted(cast(set[str], state["states"]))))
        if key in visited and action["attributes"].get("repeatable") is not True:
            outcomes[name] = {"target_guaranteed": False, "non_progress_cycle": True}
            strong = False
            continue
        children, _ = _eligible(all_actions, state, contract, epoch)
        children = sorted(children, key=lambda item: str(item["action_id"]))[:width]
        nodes = [
            _tree(
                child,
                all_actions,
                contract,
                epoch,
                targets,
                depth - 1,
                width,
                {*visited, key},
            )
            for child in children
        ]
        branch_strong = any(node["strong_target_policy"] for node in nodes)
        outcomes[name] = {
            "target_guaranteed": False,
            "continuations": nodes,
            "branch_has_strong_continuation": branch_strong,
        }
        strong &= branch_strong
    return {
        "action_id": action["action_id"],
        "outcomes": outcomes,
        "strong_target_policy": strong,
        "fairness_assumed": False,
    }


def plan_v4(root: Path) -> JsonObject:
    """Plan only after full-registry hard filtering; never cap unsafe inputs first."""

    try:
        manifest, contract, statements, rejected_attestations = active_attestations_v4(root)
        audit = science_audit_v4(root)
    except (OSError, ValueError) as error:
        return response("failed", "planner_workspace_invalid", detail=str(error))
    epoch = manifest.get("analysis_epoch")
    if not isinstance(epoch, str):
        return response(
            "failed",
            "authoritative_time_receipt_required",
            generation=str(manifest["generation_id"]),
            unknowns=["planning_state_time"],
        )
    actions = _actions(statements)
    if len(actions) > MAX_ACTIONS:
        return response(
            "failed",
            "action_registry_limit_exceeded",
            generation=str(manifest["generation_id"]),
            unknowns=["eligible_action_set"],
            action_count=len(actions),
        )
    state = _initial_state(statements, audit)
    eligible, rejected = _eligible(actions, state, contract, epoch)
    nondominated = [
        item
        for item in eligible
        if not any(_dominates(other, item) for other in eligible if other is not item)
    ]
    candidate_cap = min(
        MAX_ELIGIBLE_ACTIONS, int(contract.get("control_policy", {}).get("candidate_cap", 64))
    )
    if len(nondominated) > candidate_cap:
        return response(
            "failed",
            "candidate_set_overflow_unknown",
            generation=str(manifest["generation_id"]),
            unknowns=["primary_action", "complete_contingent_policy"],
            eligible_count=len(eligible),
            nondominated_count=len(nondominated),
            candidate_cap=candidate_cap,
            rejected_actions=rejected,
            attestation_rejections=rejected_attestations,
        )
    strict = [
        item
        for item in eligible
        if all(item is other or _dominates(item, other) for other in eligible)
    ]
    primary = strict[0] if len(strict) == 1 else None
    horizon = int(contract.get("control_policy", {}).get("planning_horizon", 1))
    width = int(contract.get("control_policy", {}).get("beam_width", 32))
    targets = id_set(contract.get("target_states"))
    trees = (
        [
            _tree(item, actions, contract, epoch, targets, horizon, width, set())
            for item in sorted(nondominated, key=lambda candidate: str(candidate["action_id"]))[
                :width
            ]
        ]
        if horizon > 1
        else []
    )
    return response(
        "ok",
        None,
        effect_class="plan",
        generation=str(manifest["generation_id"]),
        claims=["four_outcome_protected_set_safe"] if eligible else [],
        unknowns=list(cast(list[str], audit.get("unknowns", []))),
        primary_action=_public(primary) if primary else None,
        pareto_alternatives=[]
        if primary
        else [
            _public(item)
            for item in sorted(nondominated, key=lambda value: str(value["action_id"]))[:3]
        ],
        rejected_actions=rejected,
        attestation_rejections=rejected_attestations,
        candidate_count_before_validation=len(actions),
        eligible_count=len(eligible),
        candidate_cap=candidate_cap,
        selection_method="complete_hard_filter_then_four_branch_unit_separated_pareto",
        solution_class="exact" if horizon == 1 else "approximate",
        planning_horizon=horizon,
        beam_width=None if horizon == 1 else width,
        and_or_policy_trees=trees,
        one_step_execution_limit=1,
        optional_progress_credit=False,
        success_probability_used=False,
        fairness_assumed=False,
        scientific_profile=audit.get("operational_organization_profile"),
    )


def explain_action_v4(root: Path, action_id: str) -> JsonObject:
    """Explain one action using the same freshly recomputed planner result."""

    plan = plan_v4(root)
    selected = [
        item
        for item in [
            plan.get("primary_action"),
            *cast(list[object], plan.get("pareto_alternatives", [])),
        ]
        if isinstance(item, dict) and item.get("action_id") == action_id
    ]
    rejected = [
        item
        for item in plan.get("rejected_actions", [])
        if isinstance(item, dict) and item.get("action_id") == action_id
    ]
    if selected:
        return response(
            "ok",
            None,
            generation=cast(str | None, plan.get("workspace_generation")),
            claims=["action_currently_protected_set_safe"],
            action=selected[0],
            selection="primary"
            if isinstance(plan.get("primary_action"), dict)
            and plan["primary_action"].get("action_id") == action_id
            else "pareto_alternative",
        )
    if rejected:
        return response(
            "ok",
            None,
            generation=cast(str | None, plan.get("workspace_generation")),
            unknowns=["action_eligibility"],
            action_id=action_id,
            rejection=rejected[0],
        )
    return response("failed", "action_not_found", action_id=action_id)
