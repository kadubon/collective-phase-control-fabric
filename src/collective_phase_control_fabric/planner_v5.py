# SPDX-License-Identifier: Apache-2.0
"""Complete-state four-outcome contingent planning for CPCF v0.5."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.limits import MAX_ACTIONS, MAX_ELIGIBLE_ACTIONS
from collective_phase_control_fabric.science_v5 import science_audit_v5
from collective_phase_control_fabric.types import JsonObject, JsonValue, id_set
from collective_phase_control_fabric.workspace_v5 import active_attestations_v5, response

BRANCHES = ("success", "partial", "failure", "timeout")


def _payload(statement: JsonObject) -> JsonObject:
    value = statement.get("payload")
    return value if isinstance(value, dict) else {}


def _attributes(statement: JsonObject) -> JsonObject:
    value = _payload(statement).get("attributes")
    return value if isinstance(value, dict) else {}


def _subject(statement: JsonObject) -> str:
    return str(_payload(statement).get("subject_id", ""))


def _evidence(statements: list[JsonObject], evidence_type: str) -> list[JsonObject]:
    return [
        item
        for item in statements
        if _payload(item).get("record_type") == "evidence"
        and _attributes(item).get("evidence_type") == evidence_type
    ]


def _initial_state(
    manifest: JsonObject, statements: list[JsonObject], audit: JsonObject
) -> JsonObject:
    states: set[str] = set()
    authority: set[str] = set()
    hazards: set[str] = set()
    resources: dict[str, Fraction] = {}
    units: dict[str, str] = {}
    independence: set[str] = set()
    for statement in statements:
        payload = _payload(statement)
        attributes = _attributes(statement)
        subject = _subject(statement)
        kind = payload.get("record_type")
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
            if coordinate in resources:
                continue
            try:
                resources[coordinate] = Fraction(str(attributes["quantity"]))
                units[coordinate] = str(attributes["unit"])
            except (KeyError, ValueError, ZeroDivisionError):
                continue
        elif kind == "independence":
            independence.add(subject)
    return {
        "generation": manifest.get("generation_id"),
        "trusted_time": manifest.get("analysis_epoch"),
        "live_typed_attestations": {digest_v3_json(item) for item in statements},
        "states": states,
        "resources": resources,
        "units": units,
        "debt": set(),
        "rollback_obligations": set(),
        "verification_load": Fraction(0),
        "effective_independence_partition": independence,
        "authority": authority,
        "hazards": hazards,
        "scientific_profile": deepcopy(audit.get("operational_organization_profile", {})),
        "trial_bindings": set(),
    }


def _state_digest(state: JsonObject) -> str:
    normalized: JsonObject = {}
    for key, value in state.items():
        if isinstance(value, set):
            normalized[key] = sorted(str(item) for item in value)
        elif isinstance(value, Fraction):
            normalized[key] = str(value)
        elif isinstance(value, dict):
            normalized[key] = {
                str(child_key): str(child) if isinstance(child, Fraction) else child
                for child_key, child in sorted(value.items())
            }
        else:
            normalized[key] = value
    return digest_v3_json(cast(JsonValue, normalized))


def _successor(state: JsonObject, branch: JsonObject) -> JsonObject:
    result = deepcopy(state)
    removed = id_set(branch.get("must_remove")) | id_set(branch.get("may_remove"))
    states = set(cast(set[str], result["states"])) - removed
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
    result["rollback_obligations"] = set(cast(set[str], result["rollback_obligations"])) | id_set(
        branch.get("rollback_obligations")
    )
    result["verification_load"] = cast(Fraction, result["verification_load"]) + Fraction(
        str(branch.get("verification_load_upper", "0"))
    )
    result["effective_independence_partition"] = set(
        cast(set[str], result["effective_independence_partition"])
    ) - id_set(branch.get("independence_domains_removed"))
    result["authority"] = set(cast(set[str], result["authority"])) & states
    result["hazards"] = set(cast(set[str], result["hazards"])) & states
    if removed or id_set(branch.get("must_add")):
        result["scientific_profile"] = {
            key: "unknown" for key in cast(JsonObject, result["scientific_profile"])
        }
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
        projected = _successor(state, branch)
    except (ValueError, ZeroDivisionError):
        return False, ["branch_interval_invalid"], state
    if not required_authority <= cast(set[str], projected["authority"]):
        reasons.append("authority_not_preserved")
    if not required_hazards <= cast(set[str], projected["hazards"]):
        reasons.append("hazard_guard_not_preserved")
    for coordinate, floor in contract.get("protected_floors", {}).items():
        if not isinstance(floor, dict):
            reasons.append(f"protected_floor_invalid:{coordinate}")
        elif projected["units"].get(coordinate) != floor.get("unit"):
            reasons.append(f"protected_floor_unit_mismatch:{coordinate}")
        elif projected["resources"].get(coordinate, Fraction(0)) < Fraction(str(floor["quantity"])):
            reasons.append(f"protected_floor_violation:{coordinate}")
    if cast(Fraction, projected["verification_load"]) >= 1:
        reasons.append("verification_capacity_overloaded")
    quality = branch.get("quality_interval")
    if not isinstance(quality, dict):
        reasons.append("quality_interval_missing")
    return not reasons, reasons, projected


def _bound_actions(
    statements: list[JsonObject], state: JsonObject, contract: JsonObject, epoch: str
) -> tuple[list[JsonObject], list[JsonObject]]:
    actions = _evidence(statements, "action")
    capabilities = {_subject(item): item for item in _evidence(statements, "adapter_capability")}
    accepted: list[JsonObject] = []
    rejected: list[JsonObject] = []
    evaluated = datetime.fromisoformat(epoch.replace("Z", "+00:00"))
    for action in sorted(actions, key=_subject):
        action_id = _subject(action)
        attributes = _attributes(action)
        reasons: list[str] = []
        capability_ref = attributes.get("capability_ref")
        capability = capabilities.get(str(capability_ref))
        capability_attributes = _attributes(capability) if capability is not None else {}
        if capability is None:
            reasons.append("independently_signed_capability_missing")
        elif action.get("protected", {}).get("principal_id") == capability.get("protected", {}).get(
            "principal_id"
        ):
            reasons.append("action_and_capability_principals_not_distinct")
        try:
            expires = datetime.fromisoformat(str(attributes["expires_at"]).replace("Z", "+00:00"))
            if expires < evaluated:
                reasons.append("action_expired")
        except (KeyError, ValueError):
            reasons.append("action_expiry_invalid")
        if not id_set(attributes.get("input_refs")) <= cast(set[str], state["states"]):
            reasons.append("action_inputs_unavailable")
        required_authority = id_set(attributes.get("required_authority_refs"))
        required_hazards = id_set(attributes.get("required_hazard_refs"))
        if not required_authority <= cast(set[str], state["authority"]):
            reasons.append("action_authority_unavailable")
        if not required_hazards <= cast(set[str], state["hazards"]):
            reasons.append("action_hazard_guard_unavailable")
        branches = capability_attributes.get("branches")
        routes = capability_attributes.get("projection_routes")
        guaranteed_route_subjects = set()
        if isinstance(routes, list):
            for route in routes:
                if isinstance(route, dict):
                    guaranteed_route_subjects |= id_set(route.get("guaranteed_subject_ids"))
        branch_states: dict[str, JsonObject] = {}
        branch_reports: dict[str, JsonObject] = {}
        if not isinstance(branches, dict):
            reasons.append("capability_branch_effect_contract_missing")
        else:
            for name in BRANCHES:
                branch = branches.get(name)
                if not isinstance(branch, dict):
                    reasons.append(f"capability_branch_missing:{name}")
                    continue
                if not id_set(branch.get("must_add")) <= guaranteed_route_subjects:
                    reasons.append(f"branch_addition_without_projection_route:{name}")
                safe, branch_reasons, successor = _safe_branch(
                    state, branch, contract, required_authority, required_hazards
                )
                branch_states[name] = successor
                branch_reports[name] = {
                    "safe": safe,
                    "reasons": branch_reasons,
                    "state_digest": _state_digest(successor),
                }
                if not safe:
                    reasons.append(f"unsafe_branch:{name}")
        bound = {
            "action_id": action_id,
            "statement": action,
            "attributes": attributes,
            "capability_statement": capability,
            "capability_attributes": capability_attributes,
            "branches": branches if isinstance(branches, dict) else {},
            "branch_states": branch_states,
            "branch_reports": branch_reports,
        }
        if reasons:
            rejected.append({"action_id": action_id, "reasons": sorted(set(reasons))})
        else:
            accepted.append(cast(JsonObject, bound))
    return accepted, rejected


def _interval_upper(branch: JsonObject, field: str) -> tuple[Fraction, str]:
    value = branch.get(field)
    if not isinstance(value, dict):
        return Fraction(10**18), "missing"
    try:
        return Fraction(str(value["upper"])), str(value["unit"])
    except (KeyError, ValueError, ZeroDivisionError):
        return Fraction(10**18), "invalid"


def _dominates(left: JsonObject, right: JsonObject) -> bool:
    """Compare guaranteed semantic sets and worst-case non-mixed coordinates."""

    left_branches = cast(JsonObject, left["branches"])
    right_branches = cast(JsonObject, right["branches"])
    better = False
    for name in BRANCHES:
        left_branch = cast(JsonObject, left_branches[name])
        right_branch = cast(JsonObject, right_branches[name])
        left_add = id_set(left_branch.get("must_add"))
        right_add = id_set(right_branch.get("must_add"))
        if not left_add >= right_add:
            return False
        better |= left_add > right_add
        for field in ("time_interval", "cost_interval", "quality_interval"):
            left_value, left_unit = _interval_upper(left_branch, field)
            right_value, right_unit = _interval_upper(right_branch, field)
            if left_unit != right_unit or left_value > right_value:
                return False
            better |= left_value < right_value
        for field in ("debt", "rollback_obligations", "independence_domains_removed"):
            left_set = id_set(left_branch.get(field))
            right_set = id_set(right_branch.get(field))
            if not left_set <= right_set:
                return False
            better |= left_set < right_set
        left_load = Fraction(str(left_branch.get("verification_load_upper", "0")))
        right_load = Fraction(str(right_branch.get("verification_load_upper", "0")))
        if left_load > right_load:
            return False
        better |= left_load < right_load
    return better


def _public(action: JsonObject) -> JsonObject:
    return {
        "action_id": action["action_id"],
        "capability_id": _subject(cast(JsonObject, action["capability_statement"])),
        "branch_reports": action["branch_reports"],
        "guaranteed_additions": {
            name: sorted(id_set(cast(JsonObject, action["branches"])[name].get("must_add")))
            for name in BRANCHES
        },
    }


def _tree(
    action: JsonObject,
    all_statements: list[JsonObject],
    contract: JsonObject,
    epoch: str,
    depth: int,
    width: int,
    visited: set[tuple[str, str]],
) -> JsonObject:
    node: JsonObject = {"action_id": action["action_id"], "outcomes": {}}
    for name in BRANCHES:
        successor = cast(JsonObject, action["branch_states"])[name]
        state_digest = _state_digest(successor)
        key = (str(action["action_id"]), state_digest)
        outcome: JsonObject = {
            "safe": cast(JsonObject, action["branch_reports"])[name]["safe"],
            "state_digest": state_digest,
        }
        if depth > 1:
            if key in visited:
                outcome["cycle"] = "non_progress_cycle_rejected"
            else:
                accepted, _ = _bound_actions(all_statements, successor, contract, epoch)
                nondominated = [
                    candidate
                    for candidate in accepted
                    if not any(
                        _dominates(other, candidate) for other in accepted if other is not candidate
                    )
                ]
                if len(nondominated) > MAX_ELIGIBLE_ACTIONS:
                    outcome["unknown"] = "successor_candidate_set_overflow_unknown"
                else:
                    selected = sorted(nondominated, key=lambda item: str(item["action_id"]))[:width]
                    outcome["children"] = [
                        _tree(
                            child,
                            all_statements,
                            contract,
                            epoch,
                            depth - 1,
                            width,
                            {*visited, key},
                        )
                        for child in selected
                    ]
        cast(JsonObject, node["outcomes"])[name] = outcome
    return node


def plan_v5(root: Path) -> JsonObject:
    try:
        manifest, contract, statements, rejected_attestations = active_attestations_v5(root)
        audit = science_audit_v5(root)
        state = _initial_state(manifest, statements, audit)
        epoch = str(manifest["analysis_epoch"])
    except (OSError, KeyError, TypeError, ValueError) as error:
        return response("failed", "planner_workspace_invalid", detail=str(error))
    actions = _evidence(statements, "action")
    if len(actions) > MAX_ACTIONS:
        return response("failed", "action_registry_limit_exceeded", unknowns=["eligible_actions"])
    eligible, rejected = _bound_actions(statements, state, contract, epoch)
    nondominated = [
        candidate
        for candidate in eligible
        if not any(_dominates(other, candidate) for other in eligible if other is not candidate)
    ]
    if len(nondominated) > MAX_ELIGIBLE_ACTIONS:
        return response(
            "failed",
            "candidate_set_overflow_unknown",
            generation=str(manifest["generation_id"]),
            unknowns=["primary_action", "complete_contingent_policy"],
            eligible_count=len(nondominated),
            candidate_cap=MAX_ELIGIBLE_ACTIONS,
            rejected_actions=rejected,
        )
    horizon = int(contract.get("control_policy", {}).get("planning_horizon", 1))
    width = min(32, int(contract.get("control_policy", {}).get("beam_width", 32)))
    ordered = sorted(nondominated, key=lambda item: str(item["action_id"]))
    trees = [_tree(item, statements, contract, epoch, horizon, width, set()) for item in ordered]
    targets = id_set(contract.get("target_states"))
    strict_winners = [
        candidate
        for candidate in ordered
        if all(_dominates(candidate, other) for other in ordered if other is not candidate)
        and all(
            targets <= cast(set[str], cast(JsonObject, candidate["branch_states"])[name]["states"])
            for name in BRANCHES
        )
    ]
    primary = strict_winners[0] if len(strict_winners) == 1 else None
    alternatives = ordered if primary is None else [item for item in ordered if item is not primary]
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        claims=["strict_conditional_pareto_winner"] if primary is not None else [],
        unknowns=[] if primary is not None else ["unique_primary_action"],
        primary_action=_public(primary) if primary is not None else None,
        pareto_alternatives=[_public(item) for item in alternatives[:3]],
        rejected_actions=rejected,
        attestation_rejections=rejected_attestations,
        eligible_count=len(eligible),
        nondominated_count=len(nondominated),
        solution_class="exact" if horizon == 1 else "approximate",
        planning_horizon=horizon,
        beam_width=None if horizon == 1 else width,
        and_or_policy_trees=trees,
        abstract_state_digest=_state_digest(state),
        one_action_per_execution=True,
        expected_utility_used=False,
        success_probability_used=False,
        scalar_intelligence_score_used=False,
    )


def explain_action_v5(root: Path, action_id: str) -> JsonObject:
    plan = plan_v5(root)
    candidates = [
        plan.get("primary_action"),
        *cast(list[object], plan.get("pareto_alternatives", [])),
    ]
    for candidate in candidates:
        if isinstance(candidate, dict) and candidate.get("action_id") == action_id:
            return response(
                "ok",
                None,
                generation=cast(str | None, plan.get("workspace_generation")),
                action=candidate,
                selected_as_primary=candidate == plan.get("primary_action"),
            )
    for rejected in plan.get("rejected_actions", []):
        if isinstance(rejected, dict) and rejected.get("action_id") == action_id:
            return response(
                "ok",
                None,
                generation=cast(str | None, plan.get("workspace_generation")),
                action_id=action_id,
                selected_as_primary=False,
                rejection=rejected,
            )
    return response("failed", "action_not_found", action_id=action_id)
