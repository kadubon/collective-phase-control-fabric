# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import timedelta

from collective_phase_control_fabric.v6.coordination import (
    _ordered_events,
    proposal_commitment_digest,
    validate_coordination,
)
from collective_phase_control_fabric.v6.models import (
    CoordinationEventDocument,
    CoordinationEventSpec,
    CoordinationPlan,
    CoordinationPlanSpec,
    ProtocolAmendment,
    ProtocolAmendmentSpec,
    QuorumDecisionDocument,
    QuorumDecisionSpec,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.trials import assess_trial
from tests.test_v6_service_boundaries import trial_fixture
from tests.v6_helpers import NOW, metadata


def coordination_plan() -> CoordinationPlan:
    return CoordinationPlan(
        metadata=metadata("coordination-adversarial-plan"),
        spec=CoordinationPlanSpec(
            session_id="session-adversarial",
            plan_principal_id="one",
            integration_principal_id="one",
            participant_principals=["one", "two", "three"],
            verifier_principals=["two"],
            verifier_capacity={"two": 1},
            required_proposal_count=2,
            commit_deadline=NOW - timedelta(hours=1),
            reveal_deadline=NOW - timedelta(minutes=30),
            termination_deadline=NOW + timedelta(hours=1),
            maximum_exposures=0,
        ),
    )


def coordination_event(
    event_id: str,
    event_type: str,
    actor: str,
    occurred_at: object,
    prior: str | None,
    **values: object,
) -> CoordinationEventDocument:
    return CoordinationEventDocument(
        metadata=metadata(f"event-{event_id}"),
        spec=CoordinationEventSpec(
            session_id="session-adversarial",
            event_id=event_id,
            event_type=event_type,  # type: ignore[arg-type]
            actor_principal_id=actor,
            occurred_at=occurred_at,  # type: ignore[arg-type]
            prior_event_digest=prior,
            **values,  # type: ignore[arg-type]
        ),
    )


def test_coordination_chain_detects_duplicate_identifiers_forks_and_disconnection() -> None:
    root = coordination_event("root", "open_commit", "one", NOW, None)
    root_digest = document_digest(root)
    child_one = coordination_event("child", "close_commit", "one", NOW, root_digest)
    child_two = coordination_event("child", "close_commit", "one", NOW, root_digest).model_copy(
        update={"metadata": metadata("event-child-two")}
    )
    ordered, blockers = _ordered_events([root, child_one, child_two])
    assert ordered == [root]
    assert "duplicate_coordination_event_id:child" in blockers
    assert "coordination_event_chain_fork:root" in blockers
    assert "coordination_event_chain_disconnected" in blockers


def test_coordination_reports_authenticated_deadline_capacity_and_evidence_failures() -> None:
    plan = coordination_plan()
    artifact = "sha256:" + "1" * 64
    commitment = proposal_commitment_digest(plan.spec.session_id, "proposal-one", "one", artifact)
    rows = [
        ("open", "open_commit", "three", NOW - timedelta(seconds=20), {}),
        ("open-again", "open_commit", "one", NOW + timedelta(seconds=1), {}),
        (
            "commit-one",
            "commit",
            "one",
            NOW - timedelta(seconds=18),
            {"proposal_id": "proposal-one", "commitment_digest": commitment},
        ),
        (
            "commit-duplicate",
            "commit",
            "one",
            NOW - timedelta(seconds=17),
            {"proposal_id": "proposal-one", "commitment_digest": commitment},
        ),
        ("close", "close_commit", "three", NOW - timedelta(seconds=16), {}),
        ("reveal-open", "open_reveal", "three", NOW - timedelta(seconds=15), {}),
        (
            "reveal-one",
            "reveal",
            "one",
            NOW - timedelta(seconds=14),
            {
                "proposal_id": "proposal-one",
                "commitment_digest": commitment,
                "artifact_digest": artifact,
            },
        ),
        (
            "reveal-missing",
            "reveal",
            "one",
            NOW - timedelta(seconds=13),
            {
                "proposal_id": "proposal-missing",
                "commitment_digest": "sha256:" + "2" * 64,
                "artifact_digest": "sha256:" + "3" * 64,
            },
        ),
        (
            "exposure",
            "exposure",
            "outside",
            NOW - timedelta(seconds=12),
            {
                "recipient_principal_id": "outside",
                "artifact_digest": artifact,
            },
        ),
        (
            "verify-failed",
            "verification",
            "two",
            NOW - timedelta(seconds=11),
            {"artifact_digest": artifact, "verification_status": "failed"},
        ),
        (
            "verify-overload",
            "verification",
            "two",
            NOW - timedelta(seconds=10),
            {
                "artifact_digest": "sha256:" + "4" * 64,
                "verification_status": "passed",
            },
        ),
        (
            "integrate",
            "integration",
            "three",
            NOW - timedelta(seconds=9),
            {"artifact_digest": "sha256:" + "5" * 64},
        ),
        (
            "terminate",
            "terminate",
            "three",
            NOW - timedelta(seconds=8),
            {"termination_reason": "all_verified"},
        ),
    ]
    objects: dict[str, object] = {document_digest(plan): plan}
    prior: str | None = None
    for event_id, event_type, actor, occurred_at, values in rows:
        item = coordination_event(event_id, event_type, actor, occurred_at, prior, **values)
        prior = document_digest(item)
        objects[prior] = item
    result = validate_coordination(
        objects,  # type: ignore[arg-type]
        NOW,
        signer_principals={},
    )
    expected = {
        "coordination_plan_signer_mismatch",
        "commit_open_requires_plan_principal",
        "invalid_coordination_transition:COMMIT_OPEN:open_commit",
        "coordination_event_from_future:open-again",
        "coordination_event_time_reversed:commit-one",
        "commit_after_deadline:commit-one",
        "duplicate_proposal_commitment:proposal-one",
        "participant_committed_more_than_once:one",
        "commit_close_requires_plan_principal",
        "required_proposal_count_not_committed",
        "reveal_open_requires_plan_principal",
        "reveal_after_deadline:reveal-one",
        "reveal_without_actor_commitment:proposal-missing",
        "coordination_actor_not_registered:exposure",
        "exposure_recipient_not_registered:exposure",
        "coordination_exposure_limit_exceeded",
        "verification_capacity_exceeded:two",
        "verification_artifact_not_revealed:verify-overload",
        "integration_actor_mismatch",
        "integration_before_all_reveals_verified",
        "termination_actor_mismatch",
        "all_verified_termination_inconsistent",
    }
    assert expected.issubset(result.blockers)
    assert any(item.startswith("coordination_event_signer_mismatch:") for item in result.blockers)


def test_coordination_rejects_unregistered_verifier_and_mismatched_reveal_digest() -> None:
    plan = coordination_plan().model_copy(
        update={"spec": coordination_plan().spec.model_copy(update={"required_proposal_count": 1})}
    )
    artifact = "sha256:" + "6" * 64
    commitment = proposal_commitment_digest(plan.spec.session_id, "proposal", "one", artifact)
    rows = [
        ("open", "open_commit", "one", {}),
        (
            "commit",
            "commit",
            "one",
            {"proposal_id": "proposal", "commitment_digest": commitment},
        ),
        ("close", "close_commit", "one", {}),
        ("reveal-open", "open_reveal", "one", {}),
        (
            "reveal",
            "reveal",
            "one",
            {
                "proposal_id": "proposal",
                "commitment_digest": "sha256:" + "7" * 64,
                "artifact_digest": artifact,
            },
        ),
        (
            "verify",
            "verification",
            "three",
            {"artifact_digest": artifact, "verification_status": "passed"},
        ),
    ]
    objects: dict[str, object] = {document_digest(plan): plan}
    prior: str | None = None
    for index, (event_id, event_type, actor, values) in enumerate(rows):
        item = coordination_event(
            event_id,
            event_type,
            actor,
            NOW - timedelta(minutes=10 - index),
            prior,
            **values,
        )
        prior = document_digest(item)
        objects[prior] = item
    result = validate_coordination(objects, NOW)  # type: ignore[arg-type]
    assert "commitment_reveal_digest_mismatch:proposal" in result.blockers
    assert "verification_actor_not_registered:verify" in result.blockers


def test_trial_provenance_signer_cas_quality_and_time_bindings_fail_closed() -> None:
    protocol, objects, result = trial_fixture()
    for digest in (
        protocol.spec.dataset_record_digest,
        protocol.spec.assignment_record_digest,
        protocol.spec.analysis_executable_record_digest,
    ):
        artifact = objects[digest]
        objects[digest] = artifact.model_copy(  # type: ignore[attr-defined]
            update={
                "spec": artifact.spec.model_copy(  # type: ignore[attr-defined]
                    update={
                        "protocol_id": "other-protocol",
                        "acquisition_committed_at": protocol.spec.time_zero,
                    }
                )
            }
        )
    result_digest = document_digest(result)
    changed_result = result.model_copy(
        update={
            "spec": result.spec.model_copy(
                update={"quality_verifier_principal_id": "other-quality-verifier"}
            )
        }
    )
    objects.pop(result_digest)
    changed_result_digest = document_digest(changed_result)
    objects[changed_result_digest] = changed_result
    quorum_digest, quorum = next(
        (digest, item)
        for digest, item in objects.items()
        if isinstance(item, QuorumDecisionDocument)
        and item.spec.decision_type == "acceleration_compatibility"
    )
    objects[quorum_digest] = quorum.model_copy(
        update={
            "spec": quorum.spec.model_copy(
                update={
                    "subject_digest": changed_result_digest,
                    "decided_at": result.spec.issued_at - timedelta(seconds=1),
                }
            )
        }
    )
    assessment = assess_trial(
        protocol,
        objects,  # type: ignore[arg-type]
        signer_principals={},
        cas_digests=set(),
    )
    assert "protocol_author_signature_missing" in assessment.blockers
    assert "result_quality_verifier_mismatch" in assessment.blockers
    assert "result_evaluator_signature_missing" in assessment.blockers
    assert any(item.endswith("_protocol_binding_mismatch") for item in assessment.blockers)
    assert any(item.endswith("_cas_object_missing") for item in assessment.blockers)
    assert any(item.endswith("_producer_signature_missing") for item in assessment.blockers)
    assert any(item.endswith("_commitment_after_time_zero") for item in assessment.contradictions)
    assert "result_quorum_precedes_result_issuance" in assessment.contradictions


def test_trial_amendment_quorum_chain_and_author_signer_are_recomputed() -> None:
    protocol, objects, _result = trial_fixture()
    amendment = ProtocolAmendment(
        metadata=metadata("amendment-valid"),
        spec=ProtocolAmendmentSpec(
            protocol_digest=document_digest(protocol),
            author_principal_id=protocol.spec.author_principal_id,
            sequence=1,
            amended_at=NOW - timedelta(hours=2),
            changes=["estimand"],
        ),
    )
    amendment_digest = document_digest(amendment)
    objects[amendment_digest] = amendment
    decision = QuorumDecisionDocument(
        metadata=metadata("amendment-decision"),
        spec=QuorumDecisionSpec(
            decision_type="protocol_amendment",
            subject_digest=amendment_digest,
            statement_digests=["sha256:" + "8" * 64, "sha256:" + "9" * 64],
            decided_at=NOW - timedelta(hours=1),
        ),
    )
    objects[document_digest(decision)] = decision
    signers = {amendment_digest: frozenset()}
    assessed = assess_trial(
        protocol,
        objects,  # type: ignore[arg-type]
        signer_principals=signers,
    )
    assert "amendment_author_signature_missing:1" in assessed.blockers

    bad_time = decision.model_copy(
        update={"spec": decision.spec.model_copy(update={"decided_at": NOW - timedelta(hours=3)})}
    )
    objects[document_digest(decision)] = bad_time
    assessed_time = assess_trial(protocol, objects)  # type: ignore[arg-type]
    assert "amendment_time_quorum_invalid:1" in assessed_time.contradictions

    fork = amendment.model_copy(
        update={"metadata": metadata("amendment-fork"), "spec": amendment.spec.model_copy()}
    )
    objects[document_digest(fork)] = fork
    assessed_fork = assess_trial(protocol, objects)  # type: ignore[arg-type]
    assert "amendment_sequence_fork" in assessed_fork.contradictions
    assert "amendment_sequence_gap_or_fork" in assessed_fork.contradictions


def test_trial_unexpected_result_identity_and_unfavorable_higher_outcome_are_not_selected() -> None:
    protocol, objects, result = trial_fixture()
    result_digest = document_digest(result)
    result_quorum_digest = next(
        digest
        for digest, item in objects.items()
        if isinstance(item, QuorumDecisionDocument)
        and item.spec.decision_type == "acceleration_compatibility"
    )
    unexpected = result.model_copy(
        update={
            "metadata": metadata("unexpected-result"),
            "spec": result.spec.model_copy(update={"primary_result_id": "unexpected"}),
        }
    )
    objects.pop(result_digest)
    objects.pop(result_quorum_digest)
    objects[document_digest(unexpected)] = unexpected
    unexpected_assessment = assess_trial(protocol, objects)  # type: ignore[arg-type]
    assert "unexpected_primary_result_identity" in unexpected_assessment.contradictions
    assert "registered_primary_result_missing" in unexpected_assessment.contradictions

    protocol, objects, result = trial_fixture()
    higher_protocol = protocol.model_copy(
        update={
            "spec": protocol.spec.model_copy(
                update={
                    "outcomes": [
                        protocol.spec.outcomes[0].model_copy(
                            update={"direction": "higher", "minimum_effect": "5"}
                        )
                    ]
                }
            )
        }
    )
    old_protocol_digest = document_digest(protocol)
    new_protocol_digest = document_digest(higher_protocol)
    old_result_digest = document_digest(result)
    higher_result = result.model_copy(
        update={
            "spec": result.spec.model_copy(
                update={
                    "protocol_digest": new_protocol_digest,
                    "effects": [
                        result.spec.effects[0].model_copy(update={"lower": "2", "upper": "3"})
                    ],
                }
            )
        }
    )
    for digest, item in list(objects.items()):
        if isinstance(item, QuorumDecisionDocument):
            if item.spec.subject_digest == old_protocol_digest:
                objects[digest] = item.model_copy(
                    update={
                        "spec": item.spec.model_copy(update={"subject_digest": new_protocol_digest})
                    }
                )
            elif item.spec.subject_digest == old_result_digest:
                objects[digest] = item.model_copy(
                    update={
                        "spec": item.spec.model_copy(
                            update={"subject_digest": document_digest(higher_result)}
                        )
                    }
                )
    objects.pop(old_result_digest)
    objects[document_digest(higher_result)] = higher_result
    unfavorable = assess_trial(higher_protocol, objects)  # type: ignore[arg-type]
    assert unfavorable.status == "externally_observed_inconclusive"
    assert unfavorable.tier == "unmeasured"
    assert not unfavorable.blockers
    assert not unfavorable.contradictions
