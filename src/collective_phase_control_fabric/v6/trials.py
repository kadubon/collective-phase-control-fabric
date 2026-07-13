# SPDX-License-Identifier: Apache-2.0
"""Preregistered external evidence binding without statistical or causal certification."""

from __future__ import annotations

from collections.abc import Mapping, Set

from pydantic import Field

from collective_phase_control_fabric.v6.models import (
    ArtifactRecord,
    Document,
    MeasurementProtocol,
    ProtocolAmendment,
    QuorumDecisionDocument,
    StrictModel,
    TrialResult,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.science import rational

TIER_ORDER = {
    "unmeasured": 0,
    "descriptive_observation": 1,
    "observational_association_compatible": 2,
    "quasi_experimental_compatible": 3,
    "preregistered_randomized_acceleration_bundle_compatible": 4,
}


class TrialAssessment(StrictModel):
    status: str
    tier: str
    blockers: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    protocol_digest: str | None = None
    result_digests: list[str] = Field(default_factory=list)
    statistical_method_certified: bool = False
    causality_certified: bool = False


def _artifact(objects: dict[str, Document], digest: str, expected: str) -> ArtifactRecord | None:
    item = objects.get(digest)
    if isinstance(item, ArtifactRecord) and item.spec.artifact_type == expected:
        return item
    return None


def _decisions(
    objects: dict[str, Document], decision_type: str, subject_digest: str
) -> list[QuorumDecisionDocument]:
    return [
        item
        for item in objects.values()
        if isinstance(item, QuorumDecisionDocument)
        and item.spec.decision_type == decision_type
        and item.spec.subject_digest == subject_digest
    ]


def assess_trial(
    protocol: MeasurementProtocol,
    objects: dict[str, Document],
    *,
    signer_principals: Mapping[str, frozenset[str]] | None = None,
    cas_digests: Set[str] | None = None,
) -> TrialAssessment:
    """Assess one authoritative protocol and retain every result and deviation."""

    protocol_digest = document_digest(protocol)
    blockers: list[str] = []
    contradictions: list[str] = []
    if signer_principals is not None and protocol.spec.author_principal_id not in (
        signer_principals.get(protocol_digest, frozenset())
    ):
        blockers.append("protocol_author_signature_missing")
    for digest, expected in (
        (protocol.spec.dataset_record_digest, "dataset"),
        (protocol.spec.assignment_record_digest, "assignment"),
        (protocol.spec.analysis_executable_record_digest, "analysis-executable"),
    ):
        artifact = _artifact(objects, digest, expected)
        if artifact is None:
            blockers.append(f"typed_{expected}_record_missing")
            continue
        if artifact.spec.protocol_id != protocol.spec.protocol_id:
            blockers.append(f"typed_{expected}_protocol_binding_mismatch")
        if artifact.spec.acquisition_committed_at >= protocol.spec.time_zero:
            contradictions.append(f"typed_{expected}_commitment_after_time_zero")
        if cas_digests is not None and artifact.spec.artifact_digest not in cas_digests:
            blockers.append(f"typed_{expected}_cas_object_missing")
        if signer_principals is not None and artifact.spec.producer_principal_id not in (
            signer_principals.get(digest, frozenset())
        ):
            blockers.append(f"typed_{expected}_producer_signature_missing")
    registrations = _decisions(objects, "protocol_registration", protocol_digest)
    if len(registrations) != 1:
        blockers.append("independent_protocol_registration_quorum_required")
    elif registrations[0].spec.decided_at >= protocol.spec.time_zero:
        contradictions.append("protocol_registered_after_time_zero")
    amendments = sorted(
        (
            item
            for item in objects.values()
            if isinstance(item, ProtocolAmendment) and item.spec.protocol_digest == protocol_digest
        ),
        key=lambda item: (item.spec.sequence, document_digest(item)),
    )
    prior: str | None = None
    seen_sequences: set[int] = set()
    for expected_sequence, amendment in enumerate(amendments, start=1):
        amendment_digest = document_digest(amendment)
        if amendment.spec.sequence in seen_sequences:
            contradictions.append("amendment_sequence_fork")
        seen_sequences.add(amendment.spec.sequence)
        if amendment.spec.sequence != expected_sequence:
            contradictions.append("amendment_sequence_gap_or_fork")
        if amendment.spec.prior_amendment_digest != prior:
            contradictions.append("amendment_hash_chain_fork")
        if amendment.spec.amended_at >= protocol.spec.time_zero:
            contradictions.append("post_start_protocol_amendment")
        amendment_decisions = _decisions(objects, "protocol_amendment", amendment_digest)
        if len(amendment_decisions) != 1:
            blockers.append(f"amendment_quorum_required:{amendment.spec.sequence}")
        elif (
            not amendment.spec.amended_at
            <= amendment_decisions[0].spec.decided_at
            < (protocol.spec.time_zero)
        ):
            contradictions.append(f"amendment_time_quorum_invalid:{amendment.spec.sequence}")
        if signer_principals is not None and amendment.spec.author_principal_id not in (
            signer_principals.get(amendment_digest, frozenset())
        ):
            blockers.append(f"amendment_author_signature_missing:{amendment.spec.sequence}")
        prior = amendment_digest
    all_protocol_results = [
        item
        for item in objects.values()
        if isinstance(item, TrialResult) and item.spec.protocol_digest == protocol_digest
    ]
    unexpected_results = [
        item
        for item in all_protocol_results
        if item.spec.primary_result_id != protocol.spec.primary_result_id
    ]
    if unexpected_results:
        contradictions.append("unexpected_primary_result_identity")
    results = [
        item
        for item in all_protocol_results
        if item.spec.primary_result_id == protocol.spec.primary_result_id
    ]
    if not all_protocol_results:
        return TrialAssessment(
            status="registered_not_observed" if not blockers else "unmeasured",
            tier="unmeasured",
            blockers=sorted(set(blockers)),
            contradictions=sorted(set(contradictions)),
            protocol_digest=protocol_digest,
        )
    if len(results) > 1:
        contradictions.append("multiple_primary_results")
    elif not results:
        contradictions.append("registered_primary_result_missing")
    expected_outcomes = {item.outcome_id: item for item in protocol.spec.outcomes}
    tier = "unmeasured"
    for result in all_protocol_results:
        result_digest = document_digest(result)
        if result.spec.evaluator_principal_id != protocol.spec.evaluator_principal_id:
            blockers.append("result_evaluator_mismatch")
        if result.spec.quality_verifier_principal_id != protocol.spec.quality_verifier_principal_id:
            blockers.append("result_quality_verifier_mismatch")
        if signer_principals is not None and result.spec.evaluator_principal_id not in (
            signer_principals.get(result_digest, frozenset())
        ):
            blockers.append("result_evaluator_signature_missing")
        result_decisions = _decisions(objects, "acceleration_compatibility", result_digest)
        if len(result_decisions) != 1:
            blockers.append("result_quality_time_quorum_required")
        elif result_decisions[0].spec.decided_at < result.spec.issued_at:
            contradictions.append("result_quorum_precedes_result_issuance")
        if result.spec.issued_at <= result.spec.observation_completed_at:
            contradictions.append("result_issued_before_observation_completion")
        if result.spec.observation_completed_at < protocol.spec.observation_complete_at:
            contradictions.append("result_observation_incomplete")
        if result.spec.dataset_record_digest != protocol.spec.dataset_record_digest:
            blockers.append("result_dataset_binding_mismatch")
        if result.spec.assignment_record_digest != protocol.spec.assignment_record_digest:
            blockers.append("result_assignment_binding_mismatch")
        if (
            result.spec.analysis_executable_record_digest
            != protocol.spec.analysis_executable_record_digest
        ):
            blockers.append("result_analysis_executable_binding_mismatch")
        actual = {item.outcome_id: item for item in result.spec.effects}
        if set(actual) != set(expected_outcomes):
            contradictions.append("primary_outcome_bundle_incomplete_or_extra")
        favorable = result.spec.primary_result_id == protocol.spec.primary_result_id
        for outcome_id, definition in expected_outcomes.items():
            effect = actual.get(outcome_id)
            if effect is None:
                favorable = False
                continue
            lower = rational(effect.lower)
            upper = rational(effect.upper)
            if lower > upper:
                contradictions.append(f"effect_interval_reversed:{outcome_id}")
                favorable = False
            if rational(effect.quality_value) < rational(definition.quality_floor):
                contradictions.append(f"quality_floor_contradiction:{outcome_id}")
            minimum = rational(definition.minimum_effect)
            if definition.direction == "higher" and lower < minimum:
                favorable = False
            if definition.direction == "lower" and upper > minimum:
                favorable = False
        if favorable:
            candidate = {
                "descriptive": "descriptive_observation",
                "observational": "observational_association_compatible",
                "quasi-experimental": "quasi_experimental_compatible",
                "randomized": "preregistered_randomized_acceleration_bundle_compatible",
            }[result.spec.design]
            if TIER_ORDER[candidate] > TIER_ORDER[tier]:
                tier = candidate
    if contradictions:
        status = (
            "external_quality_or_safety_contradiction"
            if any("quality_floor" in item for item in contradictions)
            else "protocol_deviation"
        )
        tier = "unmeasured"
    elif blockers:
        status = "externally_observed_inconclusive"
        tier = "unmeasured"
    elif tier == "unmeasured":
        status = "externally_observed_inconclusive"
    else:
        status = tier
    return TrialAssessment(
        status=status,
        tier=tier,
        blockers=sorted(set(blockers)),
        contradictions=sorted(set(contradictions)),
        protocol_digest=protocol_digest,
        result_digests=sorted(document_digest(item) for item in all_protocol_results),
    )
