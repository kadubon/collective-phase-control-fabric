# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    ActionSpec,
    AnalysisSnapshot,
    AuthorityAttestation,
    AuthoritySpec,
    BranchEffect,
    CapabilityDocument,
    CapabilitySpec,
    CatalystClause,
    CoordinationEventDocument,
    CoordinationEventSpec,
    CoordinationPlan,
    CoordinationPlanSpec,
    DimensionResult,
    EvidenceAttestation,
    EvidenceSpec,
    ExposureLedgerDocument,
    ExposureLedgerSpec,
    IndependenceAttestation,
    IndependenceSpec,
    Lifecycle,
    OrganizationSpec,
    OrganizationWitness,
    PersistencePlan,
    PersistencePlanSpec,
    PersistenceStep,
    PerturbationScenario,
    PerturbationSuite,
    PerturbationSuiteSpec,
    PhaseContract,
    PhaseContractSpec,
    QuorumDecisionDocument,
    QuorumDecisionSpec,
    ResourceObservationAttestation,
    ResourceObservationSpec,
    SnapshotSpec,
    StateAttestation,
    StateSpec,
    SupplySpec,
    TransformationAttestation,
    TransformationSpec,
    UnitDefinition,
    UnitRegistryDocument,
    UnitRegistrySpec,
    VerifierStageAttestation,
    VerifierStageSpec,
)
from collective_phase_control_fabric.v6.planning import plan_actions
from collective_phase_control_fabric.v6.registry import document_digest, schema_digest
from collective_phase_control_fabric.v6.science import (
    Budget,
    _formation,
    _raf,
    analysis_basis_digest,
    audit_snapshot,
    replay_perturbations,
)
from tests.v6_helpers import (
    NOW,
    VALID_FROM,
    VALID_UNTIL,
    mandatory_dimensions,
    metadata,
    trust_fixture,
)


def add(objects: dict[str, object], item: object) -> str:
    digest = document_digest(item)  # type: ignore[arg-type]
    objects[digest] = item
    return digest


def event(
    event_id: str,
    event_type: str,
    occurred_at: datetime,
    prior: str | None,
    *,
    commitment: str | None = None,
    artifact: str | None = None,
) -> CoordinationEventDocument:
    return CoordinationEventDocument(
        metadata=metadata(event_id),
        spec=CoordinationEventSpec(
            session_id="session-1",
            event_id=event_id,
            event_type=event_type,  # type: ignore[arg-type]
            actor_principal_id="root-principal",
            occurred_at=occurred_at,
            commitment_digest=commitment,
            artifact_digest=artifact,
            prior_event_digest=prior,
        ),
    )


def build_science_fixture() -> tuple[AnalysisSnapshot, dict[str, object]]:
    policy, trusted_time, _ = trust_fixture()
    objects: dict[str, object] = {}
    policy_digest = add(objects, policy)
    time_digest = add(objects, trusted_time)
    units = UnitRegistryDocument(
        metadata=metadata("units"),
        spec=UnitRegistrySpec(
            units={
                "quantity": UnitDefinition(
                    symbol="quantity", dimensions={"resource": 1}, scale="1"
                ),
                "second": UnitDefinition(symbol="second", dimensions={"time": 1}, scale="1"),
                "action": UnitDefinition(symbol="action", dimensions={"action": 1}, scale="1"),
                "rate": UnitDefinition(
                    symbol="rate", dimensions={"resource": 1, "time": -1}, scale="1"
                ),
            },
            coordinate_units={"A": "quantity", "target": "quantity"},
            time_unit="second",
            action_unit="action",
        ),
    )
    unit_digest = add(objects, units)
    contract = PhaseContract(
        metadata=metadata("contract"),
        spec=PhaseContractSpec(
            target_ids=["target"],
            protected_floors={"A": "1"},
            required_dimensions=mandatory_dimensions(),
            minimum_independent_domains=2,
        ),
    )
    contract_digest = add(objects, contract)
    lifecycle = Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL)
    typed_inputs = [
        StateAttestation(
            metadata=metadata("catalyst-state"),
            spec=StateSpec(state_id="cat", available=True, food=True, lifecycle=lifecycle),
        ),
        StateAttestation(
            metadata=metadata("unused-state"),
            spec=StateSpec(state_id="unused", available=True, food=True, lifecycle=lifecycle),
        ),
        ResourceObservationAttestation(
            metadata=metadata("resource-a"),
            spec=ResourceObservationSpec(
                coordinate="A",
                quantity="10",
                unit="quantity",
                observed_at=NOW,
                lifecycle=lifecycle,
            ),
        ),
        EvidenceAttestation(
            metadata=metadata("evidence"),
            spec=EvidenceSpec(
                evidence_id="evidence-1",
                evidence_type="verified-input",
                raw_artifact_digest="sha256:" + "1" * 64,
                json_pointer="/evidence",
                projected_digest="sha256:" + "2" * 64,
                lifecycle=lifecycle,
            ),
        ),
        AuthorityAttestation(
            metadata=metadata("authority"),
            spec=AuthoritySpec(
                authority_id="authority-1", scope=["transform"], lifecycle=lifecycle
            ),
        ),
        TransformationAttestation(
            metadata=metadata("transform"),
            spec=TransformationSpec(
                transformation_id="transform",
                inputs={"A": "1"},
                outputs={"A": "1", "target": "1"},
                catalyst_clauses=[CatalystClause(all_of=["cat"])],
                required_evidence=["evidence-1"],
                required_authority=["authority-1"],
                lifecycle=lifecycle,
            ),
        ),
        VerifierStageAttestation(
            metadata=metadata("verifier"),
            spec=VerifierStageSpec(
                stage_id="verify",
                arrival_upper="1",
                service_lower="2",
                rate_unit="rate",
                observation_window_start=NOW - timedelta(hours=1),
                observation_window_end=NOW,
                independence_domain="domain-a",
                lifecycle=lifecycle,
            ),
        ),
        IndependenceAttestation(
            metadata=metadata("independence-a"),
            spec=IndependenceSpec(
                domain_id="domain-a",
                principal_id="root-principal",
                key_id="root-key",
                infrastructure_domain="infra-a",
                lineage_domain="lineage-a",
                correlation_domain="correlation-a",
                lifecycle=lifecycle,
            ),
        ),
        IndependenceAttestation(
            metadata=metadata("independence-b"),
            spec=IndependenceSpec(
                domain_id="domain-b",
                principal_id="auditor-principal",
                key_id="auditor-key",
                infrastructure_domain="infra-b",
                lineage_domain="lineage-b",
                correlation_domain="correlation-b",
                lifecycle=lifecycle,
            ),
        ),
        ExposureLedgerDocument(
            metadata=metadata("exposure-ledger"),
            spec=ExposureLedgerSpec(
                events=[],
                observation_complete_through=NOW,
                observer_principal_id="time-principal",
            ),
        ),
        QuorumDecisionDocument(
            metadata=metadata("quorum"),
            spec=QuorumDecisionSpec(
                decision_type="projection_promotion",
                subject_digest="sha256:" + "3" * 64,
                statement_digests=["sha256:" + "4" * 64, "sha256:" + "5" * 64],
                decided_at=NOW,
            ),
        ),
    ]
    input_digests = [add(objects, item) for item in typed_inputs]
    plan = CoordinationPlan(
        metadata=metadata("coordination-plan"),
        spec=CoordinationPlanSpec(
            session_id="session-1",
            participant_principals=["root-principal", "auditor-principal"],
            verifier_principals=["auditor-principal"],
            commit_deadline=NOW - timedelta(minutes=40),
            reveal_deadline=NOW - timedelta(minutes=20),
            termination_deadline=NOW + timedelta(hours=1),
            maximum_exposures=0,
        ),
    )
    input_digests.append(add(objects, plan))
    prior = None
    sequence = [
        ("open", "open_commit", None, None),
        ("commit", "commit", "sha256:" + "6" * 64, None),
        ("close", "close_commit", None, None),
        ("reveal-open", "open_reveal", None, None),
        ("reveal", "reveal", "sha256:" + "6" * 64, "sha256:" + "7" * 64),
        ("verify", "verification", None, "sha256:" + "8" * 64),
        ("integrate", "integration", None, "sha256:" + "9" * 64),
        ("terminate", "terminate", None, None),
    ]
    for index, (event_id, event_type, commitment, artifact) in enumerate(sequence):
        item = event(
            event_id,
            event_type,
            NOW - timedelta(minutes=50 - index * 5),
            prior,
            commitment=commitment,
            artifact=artifact,
        )
        prior = add(objects, item)
        input_digests.append(prior)
    placeholder = AnalysisSnapshot(
        metadata=metadata("snapshot"),
        spec=SnapshotSpec(
            generation_digest="sha256:" + "a" * 64,
            analysis_basis_digest="sha256:" + "0" * 64,
            contract_digest=contract_digest,
            trust_policy_digest=policy_digest,
            trusted_time_receipt_digest=time_digest,
            unit_registry_digest=unit_digest,
            object_digests=input_digests,
            witness_digests=[],
            target_ids=["target"],
            protected_floors={"A": "1"},
            minimum_independent_domains=2,
            required_dimensions=mandatory_dimensions(),
        ),
    )
    snapshot = placeholder.model_copy(
        update={
            "spec": placeholder.spec.model_copy(
                update={"analysis_basis_digest": analysis_basis_digest(placeholder)}
            )
        }
    )
    organization = OrganizationWitness(
        metadata=metadata("organization"),
        spec=OrganizationSpec(
            analysis_snapshot_digest=snapshot.spec.analysis_basis_digest,
            target_ids=["target"],
            transformation_ids=["transform"],
            fluxes={"transform": "1"},
        ),
    )
    persistence = PersistencePlan(
        metadata=metadata("persistence"),
        spec=PersistencePlanSpec(
            analysis_snapshot_digest=snapshot.spec.analysis_basis_digest,
            duration_per_step="1",
            steps=[PersistenceStep(action_counts={"transform": "1"})],
        ),
    )
    organization_digest = add(objects, organization)
    persistence_digest = add(objects, persistence)
    unused_digest = next(
        digest
        for digest, item in objects.items()
        if isinstance(item, StateAttestation) and item.spec.state_id == "unused"
    )
    reduced_placeholder = snapshot.model_copy(
        update={
            "spec": snapshot.spec.model_copy(
                update={
                    "analysis_basis_digest": "sha256:" + "0" * 64,
                    "object_digests": [item for item in input_digests if item != unused_digest],
                    "witness_digests": [],
                }
            )
        }
    )
    reduced_basis = analysis_basis_digest(reduced_placeholder)
    reduced_org = organization.model_copy(
        update={
            "metadata": metadata("reduced-organization"),
            "spec": organization.spec.model_copy(
                update={"analysis_snapshot_digest": reduced_basis}
            ),
        }
    )
    reduced_persistence = persistence.model_copy(
        update={
            "metadata": metadata("reduced-persistence"),
            "spec": persistence.spec.model_copy(update={"analysis_snapshot_digest": reduced_basis}),
        }
    )
    reduced_org_digest = add(objects, reduced_org)
    reduced_persistence_digest = add(objects, reduced_persistence)
    suite = PerturbationSuite(
        metadata=metadata("suite"),
        spec=PerturbationSuiteSpec(
            baseline_snapshot_digest=snapshot.spec.analysis_basis_digest,
            scenarios=[
                PerturbationScenario(
                    scenario_id="remove-unused",
                    remove_object_digests=[
                        unused_digest,
                        organization_digest,
                        persistence_digest,
                    ],
                    replacement_witness_digests=[
                        reduced_org_digest,
                        reduced_persistence_digest,
                    ],
                )
            ],
            required_dimensions=mandatory_dimensions(),
        ),
    )
    suite_digest = add(objects, suite)
    snapshot = snapshot.model_copy(
        update={
            "spec": snapshot.spec.model_copy(
                update={
                    "witness_digests": [
                        organization_digest,
                        persistence_digest,
                        suite_digest,
                    ]
                }
            )
        }
    )
    return snapshot, objects


def test_shared_kernel_and_fresh_perturbation_replay() -> None:
    snapshot, raw_objects = build_science_fixture()
    objects = {key: value for key, value in raw_objects.items()}  # type: ignore[misc]
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    assert profile.operational_organization_compatible
    assert all(result.status == "satisfied" for result in profile.dimensions.values())
    suite = next(item for item in objects.values() if isinstance(item, PerturbationSuite))
    replay = replay_perturbations(snapshot, objects, suite)  # type: ignore[arg-type]
    assert replay["dimension"].status == "satisfied"  # type: ignore[union-attr]


def capability(action_id: str, blocker: str, cost: str) -> CapabilityDocument:
    branches = [
        BranchEffect(
            outcome=outcome,
            resolves_blockers=[blocker],
            guaranteed_evidence_routes=["typed-evidence-route"],
            resource_delta_lower={"A": "0"},
            resource_delta_upper={"A": "0"},
            cost_upper=cost,
            quality_lower="1",
        )
        for outcome in ("success", "partial", "failure", "timeout")
    ]
    return CapabilityDocument(
        metadata=metadata(f"cap-{action_id}"),
        spec=CapabilitySpec(
            capability_id=f"cap-{action_id}",
            adapter_principal_id="root-principal",
            verifier_principal_id="auditor-principal",
            image_digest="sha256:" + "b" * 64,
            output_schema_name="state-attestation",
            output_schema_digest=schema_digest("state-attestation"),
            repeatable=False,
            branches=branches,
        ),
    )


def action(action_id: str, capability_value: CapabilityDocument) -> ActionDocument:
    return ActionDocument(
        metadata=metadata(action_id),
        spec=ActionSpec(
            action_id=action_id,
            capability_digest=document_digest(capability_value),
        ),
    )


def test_planner_filters_before_dedup_and_uses_correct_pareto_direction() -> None:
    snapshot, raw_objects = build_science_fixture()
    objects = {key: value for key, value in raw_objects.items()}  # type: ignore[misc]
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    dimensions = dict(profile.dimensions)
    dimensions["causal_formation"] = DimensionResult(
        status="violated", blockers=["formation-blocker"]
    )
    blocked = profile.model_copy(
        update={"dimensions": dimensions, "operational_organization_compatible": False}
    )
    cheap = capability("cheap", "formation-blocker", "1")
    expensive = capability("expensive", "formation-blocker", "2")
    invalid = action("invalid", cheap).model_copy(
        update={
            "spec": action("invalid", cheap).spec.model_copy(
                update={"required_object_digests": ["sha256:" + "f" * 64]}
            )
        }
    )
    result = plan_actions(
        snapshot,
        objects,  # type: ignore[arg-type]
        blocked,
        [invalid, action("cheap", cheap), action("expensive", expensive)],
        [cheap, expensive],
    )
    assert result.primary_action_id == "cheap"
    assert result.rejected["invalid"] == ["required_object_missing"]


def test_planner_returns_unknown_instead_of_capping_nondominated_actions() -> None:
    snapshot, raw_objects = build_science_fixture()
    objects = {key: value for key, value in raw_objects.items()}  # type: ignore[misc]
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    dimensions = dict(profile.dimensions)
    dimensions["causal_formation"] = DimensionResult(
        status="violated", blockers=[f"blocker-{index}" for index in range(65)]
    )
    blocked = profile.model_copy(
        update={"dimensions": dimensions, "operational_organization_compatible": False}
    )
    capabilities = [capability(f"a{index}", f"blocker-{index}", "1") for index in range(65)]
    actions = [action(f"a{index}", item) for index, item in enumerate(capabilities)]
    result = plan_actions(
        snapshot,
        objects,  # type: ignore[arg-type]
        blocked,
        actions,
        capabilities,
    )
    assert result.code == "candidate_set_overflow_unknown"


def test_planner_requires_goal_progress_and_strict_repeatability() -> None:
    snapshot, raw_objects = build_science_fixture()
    objects = {key: value for key, value in raw_objects.items()}  # type: ignore[misc]
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    dimensions = dict(profile.dimensions)
    dimensions["causal_formation"] = DimensionResult(
        status="violated", blockers=["formation-blocker"]
    )
    blocked = profile.model_copy(
        update={"dimensions": dimensions, "operational_organization_compatible": False}
    )
    no_progress = capability("no-progress", "different-blocker", "1")
    result = plan_actions(
        snapshot,
        objects,  # type: ignore[arg-type]
        blocked,
        [action("no-progress", no_progress)],
        [no_progress],
    )
    assert result.code == "no_strong_policy_within_horizon"

    repeatable = no_progress.model_copy(
        update={
            "metadata": metadata("repeatable-capability"),
            "spec": no_progress.spec.model_copy(
                update={"repeatable": True, "progress_measure": "blocker_frontier"}
            ),
        }
    )
    repeated = plan_actions(
        snapshot,
        objects,  # type: ignore[arg-type]
        blocked,
        [action("repeatable", repeatable)],
        [repeatable],
        horizon=2,
    )
    assert repeated.code == "no_branch_safe_action"
    assert all(
        reason.startswith("repeatability_progress_not_strict")
        for reason in repeated.rejected["repeatable"]
    )


def test_branch_effect_rejects_incomplete_or_reversed_resource_intervals() -> None:
    with pytest.raises(ValueError, match="domains must match"):
        BranchEffect(
            outcome="success",
            resource_delta_lower={"A": "-1"},
            resource_delta_upper={},
        )
    with pytest.raises(ValueError, match="lower bound exceeds"):
        BranchEffect(
            outcome="success",
            resource_delta_lower={"A": "1"},
            resource_delta_upper={"A": "0"},
        )


def test_self_produced_catalyst_cannot_support_bound_organization() -> None:
    snapshot, raw_objects = build_science_fixture()
    objects = {key: value for key, value in raw_objects.items()}  # type: ignore[misc]
    transformation_digest, transformation = next(
        (digest, item)
        for digest, item in objects.items()
        if isinstance(item, TransformationAttestation)
        and item.spec.transformation_id == "transform"
    )
    circular = transformation.model_copy(
        update={
            "spec": transformation.spec.model_copy(
                update={"catalyst_clauses": [CatalystClause(all_of=["target"])]}
            )
        }
    )
    objects[transformation_digest] = circular
    formation = _formation(snapshot, objects, NOW, Budget())  # type: ignore[arg-type]
    raf = _raf(snapshot, objects, NOW, Budget())  # type: ignore[arg-type]
    assert formation.status == "violated"
    assert "strict_prior_formation_deadlock" in formation.blockers
    assert raf.status == "violated"
    assert "organization_transformation_not_generatively_supported:transform" in raf.blockers


def test_typed_observation_supply_and_verifier_intervals_fail_early() -> None:
    lifecycle = Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL)
    with pytest.raises(ValueError, match="quantity must be nonnegative"):
        ResourceObservationSpec(
            coordinate="A",
            quantity="-1",
            unit="quantity",
            observed_at=NOW,
            lifecycle=lifecycle,
        )
    with pytest.raises(ValueError, match="ordered and nonnegative"):
        SupplySpec(
            supply_id="supply",
            coordinate="A",
            rate_lower="2",
            rate_upper="1",
            unit="rate",
            window_start=NOW,
            window_end=NOW + timedelta(seconds=1),
            lifecycle=lifecycle,
        )
    with pytest.raises(ValueError, match="valid nonnegative orientation"):
        VerifierStageSpec(
            stage_id="verifier",
            arrival_upper="1",
            service_lower="0",
            rate_unit="rate",
            observation_window_start=NOW - timedelta(seconds=1),
            observation_window_end=NOW,
            independence_domain="domain-a",
            lifecycle=lifecycle,
        )
