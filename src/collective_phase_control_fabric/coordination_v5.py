# SPDX-License-Identifier: Apache-2.0
"""Bounded local commit-reveal coordination protocol for CPCF v0.5."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import cast

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.generation_v5 import (
    GenerationStoreV5,
    history_event,
    ledger_entry,
)
from collective_phase_control_fabric.limits import LimitExceeded, load_json_bounded
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.trust_v5 import verify_statement
from collective_phase_control_fabric.types import JsonObject, JsonValue
from collective_phase_control_fabric.workspace_v5 import response


def _workspace(root: Path) -> tuple[GenerationStoreV5, JsonObject, JsonObject, str]:
    store = GenerationStoreV5(root)
    manifest = store.load_manifest()
    policy = store.get_json(str(manifest["trust_policy_digest"]))
    epoch = manifest.get("analysis_epoch")
    if not isinstance(policy, dict) or not isinstance(epoch, str):
        raise ValueError("workspace trust or authoritative time unavailable")
    return store, manifest, policy, epoch


def _active_sessions(
    store: GenerationStoreV5, manifest: JsonObject
) -> list[tuple[JsonObject, JsonObject]]:
    result: list[tuple[JsonObject, JsonObject]] = []
    for entry in manifest.get("objects", []):
        if (
            isinstance(entry, dict)
            and entry.get("kind") == "coordination-session"
            and entry.get("lifecycle") == "active"
        ):
            value = store.get_json(str(entry["digest"]))
            if isinstance(value, dict):
                result.append((entry, value))
    return result


def _session(
    store: GenerationStoreV5, manifest: JsonObject, session_id: str
) -> tuple[JsonObject, JsonObject] | None:
    matches = [
        item
        for item in _active_sessions(store, manifest)
        if item[1].get("session_id") == session_id
    ]
    return matches[0] if len(matches) == 1 else None


def _replace_session(
    store: GenerationStoreV5,
    manifest: JsonObject,
    old_entry: JsonObject,
    session: JsonObject,
    *,
    event_statement: JsonObject | None,
) -> JsonObject:
    new_digest = store.put_json(session)
    statement_digest: str | None = (
        store.put_json(event_statement) if event_statement is not None else None
    )
    objects: list[JsonObject] = []
    for entry in manifest.get("objects", []):
        if isinstance(entry, dict) and entry.get("digest") == old_entry.get("digest"):
            objects.append(cast(JsonObject, {**entry, "lifecycle": "withdrawn"}))
        elif isinstance(entry, dict):
            objects.append(entry)
    if event_statement is not None and statement_digest is not None:
        objects.append(
            ledger_entry(
                statement_digest,
                kind="coordination-event",
                schema_ref="signed-statement@0.5.0",
                source_chain=[str(old_entry["digest"])],
                authority_key_id=str(event_statement["protected"]["key_id"]),
                authority_policy_digest=str(manifest["trust_policy_digest"]),
            )
        )
    source_chain = [str(old_entry["digest"])]
    if statement_digest is not None:
        source_chain.append(statement_digest)
    objects.append(
        ledger_entry(
            new_digest,
            kind="coordination-session",
            schema_ref="coordination-session@0.5.0",
            source_chain=source_chain,
        )
    )
    payload = deepcopy(manifest)
    payload["objects"] = objects
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:coordination:{new_digest[7:]}",
            event_type="coordination_transition",
            subject_digests=[item for item in (new_digest, statement_digest) if item is not None],
        ),
    ]
    committed = store.commit(payload, expected_current=str(manifest["generation_id"]))
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        claims=["bounded_coordination_transition_committed"],
        session_id=session["session_id"],
        coordination_state=session["state"],
        session_digest=new_digest,
    )


def coordination_init_v5(root: Path, plan_path: Path, *, apply: bool) -> JsonObject:
    try:
        store, manifest, _, _ = _workspace(root)
        plan = load_json_bounded(plan_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "coordination_plan_input_invalid", detail=str(error))
    if not isinstance(plan, dict):
        return response("failed", "coordination_plan_not_object")
    errors = validation_errors("coordination-plan", plan, "0.5.0")
    if errors:
        return response("failed", "coordination_plan_invalid", schema_errors=errors)
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    plan_digest = store.put_json(plan)
    session: JsonObject = {
        "schema_version": "0.5.0",
        "session_id": f"session:{plan['plan_id']}",
        "state": "CREATED",
        "plan_digest": plan_digest,
        "participant_principals": plan["participant_principals"],
        "commitments": {},
        "reveals": {},
        "exposure_event_digests": [],
        "verification_capacity_satisfied": False,
        "termination_reason": None,
    }
    session_errors = validation_errors("coordination-session", session, "0.5.0")
    if session_errors:
        return response("failed", "coordination_session_invalid", schema_errors=session_errors)
    session_digest = store.put_json(session)
    payload = deepcopy(manifest)
    payload["objects"] = [
        *payload.get("objects", []),
        ledger_entry(plan_digest, kind="coordination-plan", schema_ref="coordination-plan@0.5.0"),
        ledger_entry(
            session_digest,
            kind="coordination-session",
            schema_ref="coordination-session@0.5.0",
            source_chain=[plan_digest],
        ),
    ]
    history = cast(list[JsonObject], payload.get("history", []))
    payload["history"] = [
        *history,
        history_event(
            history,
            event_id=f"history:coordination:{session_digest[7:]}",
            event_type="coordination_transition",
            subject_digests=[plan_digest, session_digest],
        ),
    ]
    committed = store.commit(payload, expected_current=str(manifest["generation_id"]))
    if committed.get("command_status") != "ok":
        return response("failed", str(committed.get("failure_code")), detail=committed)
    return response(
        "ok",
        None,
        effect_class="local_write",
        generation=str(committed["generation_id"]),
        claims=["bounded_coordination_session_created"],
        session_id=session["session_id"],
        coordination_state="CREATED",
    )


def _event_input(
    root: Path,
    session_id: str,
    statement_path: Path,
    schema_ref: str,
) -> tuple[GenerationStoreV5, JsonObject, JsonObject, JsonObject, JsonObject] | JsonObject:
    try:
        store, manifest, policy, epoch = _workspace(root)
        found = _session(store, manifest, session_id)
        statement = load_json_bounded(statement_path)
    except (OSError, ValueError, LimitExceeded) as error:
        return response("failed", "coordination_event_input_invalid", detail=str(error))
    if found is None or not isinstance(statement, dict):
        return response("failed", "coordination_session_or_event_missing")
    old_entry, session = found
    role = str(statement.get("protected", {}).get("role"))
    checked = verify_statement(
        statement,
        policy,
        authoritative_time=epoch,
        expected_schema_ref=schema_ref,
        expected_role=role,
    )
    if checked.get("status") != "true":
        return response(
            "failed", "coordination_event_signature_invalid", reasons=checked.get("reasons", [])
        )
    return store, manifest, old_entry, session, statement


def coordination_commit_v5(
    root: Path, session_id: str, statement_path: Path, *, apply: bool
) -> JsonObject:
    prepared = _event_input(root, session_id, statement_path, "proposal-commitment@0.5.0")
    if isinstance(prepared, dict):
        return prepared
    store, manifest, old_entry, session, statement = prepared
    if session.get("state") not in {"CREATED", "COMMIT_OPEN"}:
        return response("failed", "coordination_commit_state_invalid")
    payload = cast(JsonObject, statement["payload"])
    principal = str(statement["protected"]["principal_id"])
    if (
        payload.get("session_id") != session_id
        or payload.get("participant_principal_id") != principal
        or principal not in session.get("participant_principals", [])
    ):
        return response("failed", "coordination_commit_participant_binding_invalid")
    commitments = dict(cast(JsonObject, session["commitments"]))
    if principal in commitments:
        return response("failed", "coordination_duplicate_commitment")
    commitments[principal] = digest_v3_json(statement)
    updated = cast(JsonObject, {**session, "state": "COMMIT_OPEN", "commitments": commitments})
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    return _replace_session(store, manifest, old_entry, updated, event_statement=statement)


def coordination_reveal_v5(
    root: Path, session_id: str, statement_path: Path, *, apply: bool
) -> JsonObject:
    prepared = _event_input(root, session_id, statement_path, "proposal-reveal@0.5.0")
    if isinstance(prepared, dict):
        return prepared
    store, manifest, old_entry, session, statement = prepared
    if session.get("state") != "REVEAL_OPEN":
        return response("failed", "coordination_reveal_state_invalid")
    payload = cast(JsonObject, statement["payload"])
    principal = str(statement["protected"]["principal_id"])
    if (
        payload.get("session_id") != session_id
        or payload.get("participant_principal_id") != principal
    ):
        return response("failed", "coordination_reveal_participant_binding_invalid")
    commitment_digest = cast(JsonObject, session["commitments"]).get(principal)
    if commitment_digest is None:
        return response("failed", "coordination_reveal_without_commitment")
    committed_statement = store.get_json(str(commitment_digest))
    expected = digest_v3_json(
        cast(JsonValue, {"proposal": payload.get("proposal"), "nonce": payload.get("nonce")})
    )
    if (
        not isinstance(committed_statement, dict)
        or committed_statement.get("payload", {}).get("commitment_digest") != expected
    ):
        return response("failed", "coordination_commit_reveal_mismatch")
    reveals = dict(cast(JsonObject, session["reveals"]))
    if principal in reveals:
        return response("failed", "coordination_duplicate_reveal")
    reveals[principal] = digest_v3_json(statement)
    updated = cast(JsonObject, {**session, "reveals": reveals})
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    return _replace_session(store, manifest, old_entry, updated, event_statement=statement)


def coordination_route_v5(root: Path, session_id: str, *, apply: bool) -> JsonObject:
    try:
        store, manifest, _, _ = _workspace(root)
        found = _session(store, manifest, session_id)
    except (OSError, ValueError) as error:
        return response("failed", "coordination_route_input_invalid", detail=str(error))
    if found is None:
        return response("failed", "coordination_session_not_found")
    old_entry, session = found
    state = str(session.get("state"))
    participants = set(str(item) for item in session.get("participant_principals", []))
    if state == "COMMIT_OPEN" and set(session.get("commitments", {})) == participants:
        next_state = "COMMIT_CLOSED"
    elif state == "COMMIT_CLOSED":
        next_state = "REVEAL_OPEN"
    elif state == "REVEAL_OPEN" and set(session.get("reveals", {})) == participants:
        next_state = "VERIFY"
    elif state == "VERIFY":
        from collective_phase_control_fabric.science_v5 import science_audit_v5

        audit = science_audit_v5(root)
        if (
            audit.get("operational_organization_profile", {}).get("verification_capacity")
            != "satisfied"
        ):
            return response(
                "failed",
                "coordination_verification_capacity_blocked",
                unknowns=["coordination_integration"],
            )
        next_state = "INTEGRATE"
    else:
        return response(
            "failed", "coordination_route_precondition_unsatisfied", coordination_state=state
        )
    updated = cast(
        JsonObject,
        {
            **session,
            "state": next_state,
            "verification_capacity_satisfied": next_state == "INTEGRATE"
            or session.get("verification_capacity_satisfied") is True,
        },
    )
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    return _replace_session(store, manifest, old_entry, updated, event_statement=None)


def coordination_terminate_v5(
    root: Path, session_id: str, *, reason: str, apply: bool
) -> JsonObject:
    try:
        store, manifest, _, _ = _workspace(root)
        found = _session(store, manifest, session_id)
    except (OSError, ValueError) as error:
        return response("failed", "coordination_termination_input_invalid", detail=str(error))
    if found is None:
        return response("failed", "coordination_session_not_found")
    old_entry, session = found
    if session.get("state") != "INTEGRATE" and reason == "all_verified":
        return response("failed", "coordination_success_termination_precondition_unsatisfied")
    updated = cast(JsonObject, {**session, "state": "TERMINATED", "termination_reason": reason})
    if not apply:
        return response("failed", "apply_required", generation=str(manifest["generation_id"]))
    return _replace_session(store, manifest, old_entry, updated, event_statement=None)


def coordination_status_v5(root: Path) -> JsonObject:
    try:
        store, manifest, _, _ = _workspace(root)
        sessions = [value for _, value in _active_sessions(store, manifest)]
    except (OSError, ValueError) as error:
        return response("failed", "coordination_status_failed", detail=str(error))
    incomplete = [
        str(item.get("session_id")) for item in sessions if item.get("state") != "TERMINATED"
    ]
    return response(
        "ok",
        None,
        generation=str(manifest["generation_id"]),
        claims=["all_coordination_sessions_terminated"] if sessions and not incomplete else [],
        unknowns=["coordination_protocol_integrity"] if not sessions else [],
        active_sessions=sessions,
        incomplete_sessions=incomplete,
    )
