# SPDX-License-Identifier: Apache-2.0
"""Signed-event coordination state validation for CPCF v0.6."""

from __future__ import annotations

from datetime import datetime

from collective_phase_control_fabric.v6.models import (
    CoordinationEventDocument,
    CoordinationPlan,
    DimensionResult,
    Document,
)
from collective_phase_control_fabric.v6.registry import document_digest

TRANSITIONS = (
    "open_commit",
    "commit",
    "close_commit",
    "open_reveal",
    "reveal",
    "verification",
    "integration",
    "terminate",
)


def validate_coordination(objects: dict[str, Document], at: datetime) -> DimensionResult:
    plans = [item for item in objects.values() if isinstance(item, CoordinationPlan)]
    if len(plans) != 1:
        return DimensionResult(
            status="unknown",
            blockers=["exactly_one_signed_coordination_plan_required"],
        )
    plan = plans[0]
    events = sorted(
        (
            item
            for item in objects.values()
            if isinstance(item, CoordinationEventDocument)
            and item.spec.session_id == plan.spec.session_id
        ),
        key=lambda item: (item.spec.occurred_at, item.spec.event_id),
    )
    blockers: list[str] = []
    prior: str | None = None
    seen_commitments: set[str] = set()
    state = "CREATED"
    exposure_count = 0
    for event in events:
        if event.spec.prior_event_digest != prior:
            blockers.append(f"coordination_event_chain_broken:{event.spec.event_id}")
        kind = event.spec.event_type
        if kind == "open_commit" and state == "CREATED":
            state = "COMMIT_OPEN"
        elif kind == "commit" and state == "COMMIT_OPEN":
            if event.spec.commitment_digest is None:
                blockers.append("commitment_digest_required")
            else:
                seen_commitments.add(event.spec.commitment_digest)
        elif kind == "close_commit" and state == "COMMIT_OPEN":
            state = "COMMIT_CLOSED"
        elif kind == "open_reveal" and state == "COMMIT_CLOSED":
            state = "REVEAL_OPEN"
        elif kind == "reveal" and state == "REVEAL_OPEN":
            if event.spec.commitment_digest not in seen_commitments:
                blockers.append("reveal_without_matching_commitment")
        elif kind == "exposure" and state in {"REVEAL_OPEN", "VERIFY"}:
            exposure_count += 1
        elif kind == "verification" and state in {"REVEAL_OPEN", "VERIFY"}:
            state = "VERIFY"
        elif kind == "integration" and state == "VERIFY":
            if event.spec.artifact_digest is None:
                blockers.append("integration_artifact_required")
            state = "INTEGRATE"
        elif kind == "terminate" and state == "INTEGRATE":
            state = "TERMINATED"
        else:
            blockers.append(f"invalid_coordination_transition:{state}:{kind}")
        prior = document_digest(event)
    if exposure_count > plan.spec.maximum_exposures:
        blockers.append("coordination_exposure_limit_exceeded")
    if state != "TERMINATED":
        blockers.append("coordination_not_terminated")
    if at > plan.spec.termination_deadline and state != "TERMINATED":
        blockers.append("coordination_termination_deadline_missed")
    return DimensionResult(
        status="violated" if blockers else "satisfied",
        blockers=sorted(set(blockers)),
        evidence_digests=[document_digest(plan), *(document_digest(item) for item in events)],
        detail=f"terminal_state={state}",
    )
