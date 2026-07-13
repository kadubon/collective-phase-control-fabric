# SPDX-License-Identifier: Apache-2.0
"""Deterministic typed repair records for authoritative v0.6 blockers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import Metadata, RepairRecord, RepairRecordSpec


def _repair_class(blocker: str) -> tuple[list[str], list[str], list[list[str]]]:
    """Map a stable blocker namespace to evidence kinds, authority, and safe inspections."""

    if blocker.startswith(("trust", "active_trust", "genesis", "typed_subject_signer")):
        return ["trust-policy", "signed-statement"], ["workspace_root", "trust_auditor"], []
    if blocker.startswith(("time", "trusted_time", "temporal", "object_expired")):
        return ["trusted-time-receipt", "signed-statement"], ["timestamp"], []
    if blocker.startswith(("quarantine", "ledger", "source_", "evidence_")):
        return ["signed-statement"], ["evidence_producer"], []
    if blocker.startswith(("resource", "finite_horizon", "fed_siphon", "rate_")):
        return ["resource-observation-attestation", "supply-attestation"], ["state_source"], []
    if blocker.startswith(("raf", "catalyst", "formation", "organization")):
        return ["transformation-attestation", "state-attestation"], ["state_source"], []
    if blocker.startswith(("verification", "verifier", "independence", "exposure")):
        return ["verifier-stage-attestation", "exposure-ledger"], ["state_source"], []
    if blocker.startswith(("coordination", "commit", "reveal", "integration", "termination")):
        return ["coordination-plan", "coordination-event"], ["coordination_participant"], []
    if blocker.startswith(("protocol", "trial", "result", "typed_dataset", "amendment")):
        return ["measurement-protocol", "trial-artifact-record"], ["protocol_author"], []
    if blocker.startswith(("runner", "lease", "attempt")):
        return ["runner-receipt"], ["runner_receipt"], []
    if blocker.startswith(("projection", "pending_projection")):
        return ["pending-projection", "quorum-decision"], ["projection_verifier"], []
    if blocker.startswith(("candidate_set_overflow", "solver", "unknown_due_to_budget")):
        return [], ["tenant_admin"], []
    return ["signed-statement"], ["evidence_producer"], []


def generate_repairs(
    blocker_codes: Iterable[str],
    *,
    tenant_id: str,
    workspace_id: str,
    created_at: datetime,
    bound_actions: Mapping[str, str] | None = None,
) -> list[RepairRecord]:
    """Create canonical repair records without inventing authority or executable actions."""

    actions = bound_actions or {}
    repairs: list[RepairRecord] = []
    for blocker in sorted(set(blocker_codes)):
        required_kinds, authority, commands = _repair_class(blocker)
        action_digest = actions.get(blocker)
        repair_hash = digest_bytes(
            canonical_bytes(
                {
                    "domain": "CPCF-REPAIR-v0.6",
                    "tenant_id": tenant_id,
                    "workspace_id": workspace_id,
                    "blocker": blocker,
                    "action_digest": action_digest,
                }
            )
        )[7:23]
        repairs.append(
            RepairRecord(
                metadata=Metadata(
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    object_id=f"repair-{repair_hash}",
                    created_at=created_at,
                ),
                spec=RepairRecordSpec(
                    repair_id=f"repair-{repair_hash}",
                    blocker_code=blocker,
                    status="open" if action_digest is not None else "unbound",
                    effect_class="execute" if action_digest is not None else "none",
                    required_authority=authority,
                    required_document_kinds=required_kinds,
                    action_digest=action_digest,
                    next_safe_commands=commands,
                ),
            )
        )
    return repairs
