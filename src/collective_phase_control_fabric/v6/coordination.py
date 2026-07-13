# SPDX-License-Identifier: Apache-2.0
"""Authenticated finite coordination-state validation for CPCF v0.6."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import cast

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import (
    CoordinationEventDocument,
    CoordinationPlan,
    DimensionResult,
    Document,
)
from collective_phase_control_fabric.v6.registry import document_digest


def proposal_commitment_digest(
    session_id: str,
    proposal_id: str,
    actor_principal_id: str,
    artifact_digest: str,
) -> str:
    """Domain-separated commitment to one actor, proposal, and revealed artifact digest."""

    return digest_bytes(
        canonical_bytes(
            {
                "domain": "CPCF-COORDINATION-COMMITMENT-v0.6",
                "session_id": session_id,
                "proposal_id": proposal_id,
                "actor_principal_id": actor_principal_id,
                "artifact_digest": artifact_digest,
            }
        )
    )


def _ordered_events(
    events: list[CoordinationEventDocument],
) -> tuple[list[CoordinationEventDocument], list[str]]:
    blockers: list[str] = []
    by_prior: dict[str | None, list[CoordinationEventDocument]] = {}
    event_ids: set[str] = set()
    for event in events:
        if event.spec.event_id in event_ids:
            blockers.append(f"duplicate_coordination_event_id:{event.spec.event_id}")
        event_ids.add(event.spec.event_id)
        by_prior.setdefault(event.spec.prior_event_digest, []).append(event)
    if len(by_prior.get(None, [])) != 1:
        blockers.append("coordination_event_chain_root_not_unique")
        return [], blockers
    ordered: list[CoordinationEventDocument] = []
    current = by_prior[None][0]
    seen: set[str] = set()
    while True:
        digest = document_digest(current)
        seen.add(digest)
        ordered.append(current)
        children = by_prior.get(digest, [])
        if len(children) > 1:
            blockers.append(f"coordination_event_chain_fork:{current.spec.event_id}")
            break
        if not children:
            break
        current = children[0]
    if len(seen) != len(events):
        blockers.append("coordination_event_chain_disconnected")
    return ordered, blockers


def validate_coordination(
    objects: dict[str, Document],
    at: datetime,
    *,
    signer_principals: Mapping[str, frozenset[str]] | None = None,
) -> DimensionResult:
    """Validate one admitted session.

    ``signer_principals`` is supplied by the authoritative loader when this function is used at an
    admission boundary. A shared scientific snapshot may omit it only because the loader has
    already excluded subjects whose claimed actors were not verified signers.
    """

    plans = [item for item in objects.values() if isinstance(item, CoordinationPlan)]
    if len(plans) != 1:
        return DimensionResult(
            status="unknown",
            blockers=["exactly_one_signed_coordination_plan_required"],
        )
    plan = plans[0]
    plan_digest = document_digest(plan)
    events = [
        item
        for item in objects.values()
        if isinstance(item, CoordinationEventDocument)
        and item.spec.session_id == plan.spec.session_id
    ]
    ordered, blockers = _ordered_events(events)
    participants = set(plan.spec.participant_principals)
    verifiers = set(plan.spec.verifier_principals)
    if signer_principals is not None and plan.spec.plan_principal_id not in signer_principals.get(
        plan_digest, frozenset()
    ):
        blockers.append("coordination_plan_signer_mismatch")
    commitments: dict[str, tuple[str, str]] = {}
    reveals: dict[str, str] = {}
    verified: dict[str, str] = {}
    verifier_load = {principal: 0 for principal in verifiers}
    committed_actors: set[str] = set()
    state = "CREATED"
    exposure_count = 0
    previous_time: datetime | None = None
    for event in ordered:
        spec = event.spec
        digest = document_digest(event)
        kind = spec.event_type
        if previous_time is not None and spec.occurred_at < previous_time:
            blockers.append(f"coordination_event_time_reversed:{spec.event_id}")
        previous_time = spec.occurred_at
        if spec.occurred_at > at:
            blockers.append(f"coordination_event_from_future:{spec.event_id}")
        if spec.actor_principal_id not in participants:
            blockers.append(f"coordination_actor_not_registered:{spec.event_id}")
        if signer_principals is not None and spec.actor_principal_id not in signer_principals.get(
            digest, frozenset()
        ):
            blockers.append(f"coordination_event_signer_mismatch:{spec.event_id}")

        if kind == "open_commit" and state == "CREATED":
            if spec.actor_principal_id != plan.spec.plan_principal_id:
                blockers.append("commit_open_requires_plan_principal")
            state = "COMMIT_OPEN"
        elif kind == "commit" and state == "COMMIT_OPEN":
            if spec.occurred_at > plan.spec.commit_deadline:
                blockers.append(f"commit_after_deadline:{spec.event_id}")
            proposal_id = cast(str, spec.proposal_id)
            commitment = cast(str, spec.commitment_digest)
            if proposal_id in commitments:
                blockers.append(f"duplicate_proposal_commitment:{proposal_id}")
            if spec.actor_principal_id in committed_actors:
                blockers.append(f"participant_committed_more_than_once:{spec.actor_principal_id}")
            commitments[proposal_id] = (spec.actor_principal_id, commitment)
            committed_actors.add(spec.actor_principal_id)
        elif kind == "close_commit" and state == "COMMIT_OPEN":
            if spec.actor_principal_id != plan.spec.plan_principal_id:
                blockers.append("commit_close_requires_plan_principal")
            if len(commitments) < plan.spec.required_proposal_count:
                blockers.append("required_proposal_count_not_committed")
            state = "COMMIT_CLOSED"
        elif kind == "open_reveal" and state == "COMMIT_CLOSED":
            if spec.actor_principal_id != plan.spec.plan_principal_id:
                blockers.append("reveal_open_requires_plan_principal")
            state = "REVEAL_OPEN"
        elif kind == "reveal" and state == "REVEAL_OPEN":
            if spec.occurred_at > plan.spec.reveal_deadline:
                blockers.append(f"reveal_after_deadline:{spec.event_id}")
            proposal_id = cast(str, spec.proposal_id)
            artifact_digest = cast(str, spec.artifact_digest)
            committed = commitments.get(proposal_id)
            if committed is None or committed[0] != spec.actor_principal_id:
                blockers.append(f"reveal_without_actor_commitment:{proposal_id}")
            else:
                expected = proposal_commitment_digest(
                    plan.spec.session_id,
                    proposal_id,
                    spec.actor_principal_id,
                    artifact_digest,
                )
                if spec.commitment_digest != committed[1] or expected != committed[1]:
                    blockers.append(f"commitment_reveal_digest_mismatch:{proposal_id}")
                else:
                    reveals[proposal_id] = artifact_digest
        elif kind == "exposure" and state in {"COMMIT_OPEN", "REVEAL_OPEN", "VERIFY"}:
            exposure_count += 1
            if spec.recipient_principal_id not in participants:
                blockers.append(f"exposure_recipient_not_registered:{spec.event_id}")
        elif kind == "verification" and state in {"REVEAL_OPEN", "VERIFY"}:
            state = "VERIFY"
            if spec.actor_principal_id not in verifiers:
                blockers.append(f"verification_actor_not_registered:{spec.event_id}")
            else:
                verifier_load[spec.actor_principal_id] += 1
                if (
                    verifier_load[spec.actor_principal_id]
                    > plan.spec.verifier_capacity[spec.actor_principal_id]
                ):
                    blockers.append(f"verification_capacity_exceeded:{spec.actor_principal_id}")
            artifact_digest = cast(str, spec.artifact_digest)
            if artifact_digest not in set(reveals.values()):
                blockers.append(f"verification_artifact_not_revealed:{spec.event_id}")
            else:
                verified[artifact_digest] = cast(str, spec.verification_status)
        elif kind == "integration" and state == "VERIFY":
            if spec.actor_principal_id != plan.spec.integration_principal_id:
                blockers.append("integration_actor_mismatch")
            if not reveals or any(verified.get(item) != "passed" for item in reveals.values()):
                blockers.append("integration_before_all_reveals_verified")
            state = "INTEGRATE"
        elif kind == "terminate" and state == "INTEGRATE":
            if spec.actor_principal_id != plan.spec.integration_principal_id:
                blockers.append("termination_actor_mismatch")
            if spec.termination_reason == "all_verified" and any(
                value != "passed" for value in verified.values()
            ):
                blockers.append("all_verified_termination_inconsistent")
            state = "TERMINATED"
        else:
            blockers.append(f"invalid_coordination_transition:{state}:{kind}")
    if exposure_count > plan.spec.maximum_exposures:
        blockers.append("coordination_exposure_limit_exceeded")
    if state != "TERMINATED":
        blockers.append("coordination_not_terminated")
    if at > plan.spec.termination_deadline and state != "TERMINATED":
        blockers.append("coordination_termination_deadline_missed")
    return DimensionResult(
        status="violated" if blockers else "satisfied",
        blockers=sorted(set(blockers)),
        evidence_digests=[plan_digest, *(document_digest(item) for item in ordered)],
        detail=f"terminal_state={state};reveals={len(reveals)};verified={len(verified)}",
    )
