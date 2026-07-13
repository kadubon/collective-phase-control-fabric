# SPDX-License-Identifier: Apache-2.0
"""Branch-complete assurance tests for the shared v0.6 scientific kernel."""

from __future__ import annotations

from datetime import timedelta
from fractions import Fraction

import pytest

from collective_phase_control_fabric.v6.models import (
    CurvePoint,
    EvidenceAttestation,
    ExposureEvent,
    ExposureLedgerDocument,
    IndependenceAttestation,
    Lifecycle,
    OrganizationWitness,
    PersistencePlan,
    PersistenceStep,
    PerturbationSuite,
    RateObservationAttestation,
    RateObservationSpec,
    ResourceObservationAttestation,
    ServiceCurveAttestation,
    ServiceCurveSpec,
    SupplyAttestation,
    SupplySpec,
    TransformationAttestation,
    UnitDefinition,
    UnitRegistryDocument,
    VerifierStageAttestation,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.science import (
    AnalysisBudgetExceeded,
    Budget,
    _available_sets,
    _dimensions,
    _expected_rate_dimensions,
    _formation,
    _independence,
    _live,
    _organization,
    _persistence,
    _provenance,
    _raf,
    _structural,
    _temporal,
    _trust,
    _unit_dimensions,
    _verification,
    audit_snapshot,
    rational,
    replay_perturbations,
)
from tests.test_v6_science_planner import build_science_fixture
from tests.v6_helpers import NOW, VALID_FROM, VALID_UNTIL, metadata


def typed_objects() -> tuple[object, dict[str, object]]:
    snapshot, raw = build_science_fixture()
    return snapshot, dict(raw)


def only_one(objects: dict[str, object], expected: type[object]) -> tuple[str, object]:
    matches = [(digest, item) for digest, item in objects.items() if isinstance(item, expected)]
    assert len(matches) == 1
    return matches[0]


def replace_type(objects: dict[str, object], expected: type[object], replacement: object) -> None:
    for digest in [key for key, item in objects.items() if isinstance(item, expected)]:
        del objects[digest]
    objects[document_digest(replacement)] = replacement  # type: ignore[arg-type]


def test_budget_rational_lifecycle_and_available_sets_preserve_unknown() -> None:
    with pytest.raises(AnalysisBudgetExceeded):
        Budget(operations=0).spend()
    with pytest.raises(AnalysisBudgetExceeded):
        Budget(deadline_seconds=-1).spend(0)
    with pytest.raises(AnalysisBudgetExceeded):
        rational(str(1 << 4096))
    with pytest.raises(AnalysisBudgetExceeded):
        rational(f"1/{1 << 4096}")

    assert not _live(object(), NOW)
    lifecycle = Lifecycle(
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        withdrawn_at=NOW,
    )
    assert not _live(lifecycle, NOW)

    snapshot, objects = typed_objects()
    available, food, evidence, authority = _available_sets(objects, NOW)  # type: ignore[arg-type]
    assert {"cat", "unused", "A", "evidence-1", "authority-1"}.issubset(available)
    assert {"cat", "unused", "A"}.issubset(food)
    assert evidence == {"evidence-1"}
    assert authority == {"authority-1"}
    assert snapshot is not None


def test_provenance_temporal_and_trust_fail_closed_on_each_binding() -> None:
    snapshot, objects = typed_objects()
    provenance, live = _provenance(snapshot, objects)  # type: ignore[arg-type]
    assert provenance.status == "satisfied" and live

    missing = dict(objects)
    missing.pop(snapshot.spec.contract_digest)  # type: ignore[attr-defined]
    result, _ = _provenance(snapshot, missing)  # type: ignore[arg-type]
    assert f"missing:{snapshot.spec.contract_digest}" in result.blockers  # type: ignore[attr-defined]
    assert "phase_contract_missing" in result.blockers

    expected_digest = snapshot.spec.object_digests[0]  # type: ignore[attr-defined]
    mismatch = dict(objects)
    mismatch[expected_digest] = next(
        item for digest, item in objects.items() if digest != expected_digest
    )
    assert any(
        item.startswith("digest_mismatch:")
        for item in _provenance(snapshot, mismatch)[0].blockers  # type: ignore[arg-type]
    )

    original = objects[expected_digest]
    foreign_tenant = original.model_copy(  # type: ignore[attr-defined]
        update={
            "metadata": original.metadata.model_copy(update={"tenant_id": "tenant-b"})  # type: ignore[attr-defined]
        }
    )
    mismatch[expected_digest] = foreign_tenant
    assert any(
        item.startswith("tenant_mismatch:")
        for item in _provenance(snapshot, mismatch)[0].blockers  # type: ignore[arg-type]
    )
    foreign_workspace = original.model_copy(  # type: ignore[attr-defined]
        update={
            "metadata": original.metadata.model_copy(update={"workspace_id": "workspace-b"})  # type: ignore[attr-defined]
        }
    )
    mismatch[expected_digest] = foreign_workspace
    assert any(
        item.startswith("workspace_mismatch:")
        for item in _provenance(snapshot, mismatch)[0].blockers  # type: ignore[arg-type]
    )

    unbound = snapshot.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": snapshot.spec.model_copy(  # type: ignore[attr-defined]
                update={
                    "required_dimensions": ["provenance_integrity"],
                    "target_ids": ["different-target"],
                    "analysis_basis_digest": "sha256:" + "0" * 64,
                }
            )
        }
    )
    unbound_result, _ = _provenance(unbound, objects)  # type: ignore[arg-type]
    assert {
        "mandatory_security_or_science_dimension_disabled",
        "snapshot_contract_binding_mismatch",
        "analysis_basis_digest_mismatch",
    }.issubset(unbound_result.blockers)

    temporal, at = _temporal(snapshot, objects)  # type: ignore[arg-type]
    assert temporal.status == "satisfied" and at == NOW
    without_time = dict(objects)
    without_time.pop(snapshot.spec.trusted_time_receipt_digest)  # type: ignore[attr-defined]
    assert _temporal(snapshot, without_time)[0].status == "violated"  # type: ignore[arg-type]
    outside = _temporal(snapshot, objects, NOW + timedelta(days=2))[0]  # type: ignore[arg-type]
    assert "evaluation_time_outside_trusted_receipt" in outside.blockers

    time_type = type(objects[snapshot.spec.trusted_time_receipt_digest])  # type: ignore[attr-defined]
    time_digest, time_item = only_one(objects, time_type)
    invalid_time = time_item.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": time_item.spec.model_copy(  # type: ignore[attr-defined]
                update={"valid_until": time_item.spec.issued_at - timedelta(seconds=1)}  # type: ignore[attr-defined]
            )
        }
    )
    invalid_objects = dict(objects)
    invalid_objects[time_digest] = invalid_time
    assert "trusted_time_interval_invalid" in _temporal(snapshot, invalid_objects)[0].blockers  # type: ignore[arg-type]

    assert _trust(snapshot, objects).status == "satisfied"  # type: ignore[arg-type]
    no_policy = dict(objects)
    no_policy.pop(snapshot.spec.trust_policy_digest)  # type: ignore[attr-defined]
    assert "trust_policy_missing" in _trust(snapshot, no_policy).blockers  # type: ignore[arg-type]
    no_quorum = {
        digest: item
        for digest, item in objects.items()
        if item.kind != "quorum-decision"  # type: ignore[attr-defined]
    }
    assert "no_role_quorum_decision_in_snapshot" in _trust(snapshot, no_quorum).blockers  # type: ignore[arg-type]


def test_structural_formation_organization_and_raf_negative_cases() -> None:
    snapshot, objects = typed_objects()
    assert _structural(snapshot, objects, NOW, Budget()).status == "satisfied"  # type: ignore[arg-type]
    unreachable = snapshot.model_copy(  # type: ignore[attr-defined]
        update={"spec": snapshot.spec.model_copy(update={"target_ids": ["missing"]})}  # type: ignore[attr-defined]
    )
    assert (
        "unreachable_target:missing"
        in _structural(
            unreachable,
            objects,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )

    no_witnesses = {
        digest: item
        for digest, item in objects.items()
        if not isinstance(item, OrganizationWitness)
    }
    assert _formation(snapshot, no_witnesses, NOW, Budget()).status == "unknown"  # type: ignore[arg-type]
    assert _organization(snapshot, no_witnesses, NOW, Budget()).status == "unknown"  # type: ignore[arg-type]
    assert _raf(snapshot, no_witnesses, NOW, Budget()).status == "unknown"  # type: ignore[arg-type]

    _, witness = only_one(
        {
            digest: item
            for digest, item in objects.items()
            if isinstance(item, OrganizationWitness)
            and item.spec.analysis_snapshot_digest == snapshot.spec.analysis_basis_digest  # type: ignore[attr-defined]
        },
        OrganizationWitness,
    )
    missing_transform = witness.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": witness.spec.model_copy(  # type: ignore[attr-defined]
                update={
                    "transformation_ids": ["missing-transform"],
                    "fluxes": {"missing-transform": "1"},
                }
            )
        }
    )
    missing_objects = dict(no_witnesses)
    missing_objects[document_digest(missing_transform)] = missing_transform
    assert (
        "formation_transformation_missing:missing-transform"
        in _formation(
            snapshot,
            missing_objects,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )
    assert (
        "organization_transformation_missing:missing-transform"
        in _organization(
            snapshot,
            missing_objects,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )

    wrong_target = witness.model_copy(  # type: ignore[attr-defined]
        update={"spec": witness.spec.model_copy(update={"target_ids": ["wrong"]})}  # type: ignore[attr-defined]
    )
    wrong_objects = dict(no_witnesses)
    wrong_objects[document_digest(wrong_target)] = wrong_target
    assert (
        "organization_target_set_mismatch"
        in _organization(
            snapshot,
            wrong_objects,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )

    wrong_flux = witness.model_copy(  # type: ignore[attr-defined]
        update={"spec": witness.spec.model_copy(update={"fluxes": {"other": "1"}})}  # type: ignore[attr-defined]
    )
    wrong_objects = dict(no_witnesses)
    wrong_objects[document_digest(wrong_flux)] = wrong_flux
    assert (
        "organization_flux_domain_mismatch"
        in _organization(
            snapshot,
            wrong_objects,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )

    zero_flux = witness.model_copy(  # type: ignore[attr-defined]
        update={"spec": witness.spec.model_copy(update={"fluxes": {"transform": "0"}})}  # type: ignore[attr-defined]
    )
    wrong_objects = dict(no_witnesses)
    wrong_objects[document_digest(zero_flux)] = zero_flux
    assert (
        "organization_flux_not_positive:transform"
        in _organization(
            snapshot,
            wrong_objects,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )


def test_dimensional_consistency_reports_typed_flow_defects() -> None:
    snapshot, objects = typed_objects()
    assert _dimensions(snapshot, objects, NOW, Budget()).status == "satisfied"  # type: ignore[arg-type]
    unit_digest, units = only_one(objects, UnitRegistryDocument)
    bad_units = units.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": units.spec.model_copy(  # type: ignore[attr-defined]
                update={
                    "units": {
                        **units.spec.units,  # type: ignore[attr-defined]
                        "quantity": UnitDefinition(
                            symbol="quantity", dimensions={"resource": 1}, scale="0"
                        ),
                    },
                    "time_unit": "missing-time",
                    "coordinate_units": {
                        **units.spec.coordinate_units,  # type: ignore[attr-defined]
                        "unknown-coordinate": "missing-unit",
                    },
                }
            )
        }
    )
    objects[unit_digest] = bad_units
    resource_digest, resource = only_one(objects, ResourceObservationAttestation)
    objects[resource_digest] = resource.model_copy(  # type: ignore[attr-defined]
        update={"spec": resource.spec.model_copy(update={"unit": "wrong"})}  # type: ignore[attr-defined]
    )
    transform_digest, transform = only_one(objects, TransformationAttestation)
    objects[transform_digest] = transform.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": transform.spec.model_copy(  # type: ignore[attr-defined]
                update={"inputs": {"untyped": "-1"}}
            )
        }
    )
    lifecycle = Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL)
    supply = SupplyAttestation(
        metadata=metadata("bad-supply"),
        spec=SupplySpec(
            supply_id="bad-supply",
            coordinate="A",
            rate_lower="0",
            rate_upper="1",
            unit="missing-rate",
            window_start=NOW - timedelta(minutes=1),
            window_end=NOW + timedelta(minutes=1),
            lifecycle=lifecycle,
        ),
    )
    objects[document_digest(supply)] = supply
    result = _dimensions(snapshot, objects, NOW, Budget())  # type: ignore[arg-type]
    assert {
        "unit_scale_not_positive:quantity",
        "time_or_action_unit_missing",
        "coordinate_unit_unknown:unknown-coordinate",
        "resource_unit_mismatch:A",
        "transformation_coordinate_untyped:untyped",
        "negative_stoichiometry:untyped",
        "supply_unit_unknown:bad-supply",
    }.issubset(result.blockers)


def test_persistence_reports_ambiguous_resources_prefix_and_supply_defects() -> None:
    snapshot, objects = typed_objects()
    assert _persistence(snapshot, objects, NOW, Budget()).status == "satisfied"  # type: ignore[arg-type]
    no_plan = {
        digest: item for digest, item in objects.items() if not isinstance(item, PersistencePlan)
    }
    assert _persistence(snapshot, no_plan, NOW, Budget()).status == "unknown"  # type: ignore[arg-type]

    _, observation = only_one(objects, ResourceObservationAttestation)
    duplicate = observation.model_copy(update={"metadata": metadata("duplicate-resource")})  # type: ignore[attr-defined]
    ambiguous = dict(objects)
    ambiguous[document_digest(duplicate)] = duplicate
    assert (
        "ambiguous_resource_observation:A"
        in _persistence(
            snapshot,
            ambiguous,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )

    _, plan = only_one(
        {
            digest: item
            for digest, item in objects.items()
            if isinstance(item, PersistencePlan)
            and item.spec.analysis_snapshot_digest == snapshot.spec.analysis_basis_digest  # type: ignore[attr-defined]
        },
        PersistencePlan,
    )
    transform_digest, transform = only_one(objects, TransformationAttestation)
    floor_consuming = transform.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": transform.spec.model_copy(update={"outputs": {"target": "1"}})  # type: ignore[attr-defined]
        }
    )
    negative_counter = transform.model_copy(  # type: ignore[attr-defined]
        update={
            "metadata": metadata("negative-counter-transform"),
            "spec": transform.spec.model_copy(  # type: ignore[attr-defined]
                update={"transformation_id": "negative-counter"}
            ),
        }
    )
    objects[transform_digest] = floor_consuming
    objects[document_digest(negative_counter)] = negative_counter
    defective = plan.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": plan.spec.model_copy(  # type: ignore[attr-defined]
                update={
                    "duration_per_step": "0",
                    "steps": [
                        PersistenceStep(
                            action_counts={
                                "missing": "1",
                                "transform": "20",
                                "negative-counter": "-1",
                            },
                            supply_quantities={"missing-supply": "1"},
                        )
                    ],
                }
            )
        }
    )
    replace_type(objects, PersistencePlan, defective)
    result = _persistence(snapshot, objects, NOW, Budget())  # type: ignore[arg-type]
    assert {
        "persistence_duration_not_positive",
        "persistence_transformation_missing:missing",
        "negative_action_count:negative-counter",
        "supply_attestation_missing:missing-supply",
        "prefix_floor_violation:0:A",
    }.issubset(result.blockers)


def test_verification_and_independence_cover_overload_curves_and_exposure() -> None:
    snapshot, objects = typed_objects()
    assert _verification(objects, NOW, Budget()).status == "satisfied"  # type: ignore[arg-type]
    no_stages = {
        digest: item
        for digest, item in objects.items()
        if not isinstance(item, VerifierStageAttestation)
    }
    assert _verification(no_stages, NOW, Budget()).status == "unknown"  # type: ignore[arg-type]

    _, stage = only_one(objects, VerifierStageAttestation)
    duplicate_stage = stage.model_copy(  # type: ignore[attr-defined]
        update={
            "metadata": metadata("duplicate-stage"),
            "spec": stage.spec.model_copy(  # type: ignore[attr-defined]
                update={
                    "arrival_upper": "2",
                    "service_lower": "1",
                    "rate_unit": "other-rate",
                    "observation_window_start": NOW - timedelta(hours=2),
                }
            ),
        }
    )
    objects[document_digest(duplicate_stage)] = duplicate_stage
    evidence_digest, _ = only_one(objects, EvidenceAttestation)
    lifecycle = Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL)
    rate = RateObservationAttestation(
        metadata=metadata("bad-rate"),
        spec=RateObservationSpec(
            transformation_id="missing-transform",
            rate_lower="0",
            rate_upper="1",
            action_rate_unit="action-rate",
            observation_window_start=NOW - timedelta(minutes=1),
            observation_window_end=NOW,
            source_record_digest=evidence_digest,
            lifecycle=lifecycle,
        ),
    )
    objects[document_digest(rate)] = rate
    result = _verification(objects, NOW, Budget())  # type: ignore[arg-type]
    assert {
        "duplicate_verifier_stage:verify",
        "verifier_window_mismatch:verify",
        "verifier_rate_unit_mismatch:verify",
        "verifier_overloaded:verify",
        "rate_transformation_missing:missing-transform",
    }.issubset(result.blockers)

    assert _independence(snapshot, objects, NOW, Budget()).status == "satisfied"  # type: ignore[arg-type]
    no_ledger = {
        digest: item
        for digest, item in objects.items()
        if not isinstance(item, ExposureLedgerDocument)
    }
    assert _independence(snapshot, no_ledger, NOW, Budget()).status == "unknown"  # type: ignore[arg-type]
    no_domains = {
        digest: item
        for digest, item in objects.items()
        if not isinstance(item, IndependenceAttestation)
    }
    assert (
        "independence_attestations_missing"
        in _independence(
            snapshot,
            no_domains,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )
    _, ledger = only_one(objects, ExposureLedgerDocument)
    exposed = ledger.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": ledger.spec.model_copy(  # type: ignore[attr-defined]
                update={
                    "events": [
                        ExposureEvent(
                            artifact_digest="sha256:" + "f" * 64,
                            from_domain="domain-a",
                            to_domain="domain-b",
                            observed_at=NOW,
                            pre_commit=True,
                        ),
                        ExposureEvent(
                            artifact_digest="sha256:" + "e" * 64,
                            from_domain="unknown",
                            to_domain="domain-a",
                            observed_at=NOW,
                            pre_commit=False,
                        ),
                    ]
                }
            )
        }
    )
    replace_type(objects, ExposureLedgerDocument, exposed)
    independence = _independence(snapshot, objects, NOW, Budget())  # type: ignore[arg-type]
    assert "exposure_refers_to_unknown_domain" in independence.blockers
    assert "effective_independent_domain_threshold_not_met" in independence.blockers


def test_audit_and_perturbation_preserve_budget_and_acceptance_unknowns() -> None:
    snapshot, objects = typed_objects()
    budgeted = audit_snapshot(snapshot, objects, budget=Budget(operations=0))  # type: ignore[arg-type]
    assert budgeted.solution_class == "incomplete"
    assert all(item.status == "unknown_due_to_budget" for item in budgeted.dimensions.values())

    no_provenance = dict(objects)
    no_provenance.pop(snapshot.spec.contract_digest)  # type: ignore[attr-defined]
    unavailable = audit_snapshot(snapshot, no_provenance)  # type: ignore[arg-type]
    assert unavailable.dimensions["structural_reachability"].status == "unknown"

    without_suite = {
        digest: item for digest, item in objects.items() if not isinstance(item, PerturbationSuite)
    }
    profile = audit_snapshot(snapshot, without_suite)  # type: ignore[arg-type]
    assert profile.dimensions["perturbation_robustness"].status == "unknown"
    reduced = audit_snapshot(snapshot, objects, include_robustness=False)  # type: ignore[arg-type]
    assert (
        "robustness_not_requested_for_reduced_snapshot"
        in reduced.dimensions["perturbation_robustness"].blockers
    )

    _, suite = only_one(objects, PerturbationSuite)
    incomplete_suite = suite.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": suite.spec.model_copy(  # type: ignore[attr-defined]
                update={"required_dimensions": ["provenance_integrity"]}
            )
        }
    )
    replay = replay_perturbations(snapshot, objects, incomplete_suite)  # type: ignore[arg-type]
    assert replay["dimension"].status == "violated"  # type: ignore[union-attr]
    assert replay["scenarios"] == []


def test_exact_fraction_reference_is_not_float_based() -> None:
    assert rational("1/3") + rational("2/3") == Fraction(1)


def test_unit_dimension_helpers_remove_zero_and_cancel_time_dimensions() -> None:
    quantity = UnitDefinition(
        symbol="quantity",
        dimensions={"resource": 1, "cancelled": 0},
        scale="1",
    )
    time = UnitDefinition(
        symbol="time",
        dimensions={"time": 1, "resource": 1},
        scale="1",
    )
    assert _unit_dimensions(quantity) == {"resource": 1}
    assert _expected_rate_dimensions(quantity, time) == {"time": -1}


def test_formation_and_raf_reject_each_strict_prior_dependency() -> None:
    snapshot, objects = typed_objects()
    transform_digest, transform = only_one(objects, TransformationAttestation)
    cases = (
        {"inputs": {"missing-input": "1"}},
        {"required_evidence": ["missing-evidence"]},
        {"required_authority": ["missing-authority"]},
        {"inhibitors": ["cat"]},
        {"catalyst_clauses": []},
    )
    for update in cases:
        changed = dict(objects)
        changed[transform_digest] = transform.model_copy(  # type: ignore[attr-defined]
            update={"spec": transform.spec.model_copy(update=update)}  # type: ignore[attr-defined]
        )
        assert _formation(snapshot, changed, NOW, Budget()).status == "violated"  # type: ignore[arg-type]
        assert _raf(snapshot, changed, NOW, Budget()).status == "violated"  # type: ignore[arg-type]

    uncatalyzed = transform.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": transform.spec.model_copy(  # type: ignore[attr-defined]
                update={"uncatalyzed": True, "catalyst_clauses": []}
            )
        }
    )
    objects[transform_digest] = uncatalyzed
    assert _formation(snapshot, objects, NOW, Budget()).status == "satisfied"  # type: ignore[arg-type]
    assert _raf(snapshot, objects, NOW, Budget()).status == "satisfied"  # type: ignore[arg-type]


def test_dimension_checks_cover_rate_supply_and_curve_provenance() -> None:
    snapshot, objects = typed_objects()
    unit_digest, units = only_one(objects, UnitRegistryDocument)
    extended_units = units.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": units.spec.model_copy(  # type: ignore[attr-defined]
                update={
                    "units": {
                        **units.spec.units,  # type: ignore[attr-defined]
                        "bad-rate": UnitDefinition(
                            symbol="bad-rate", dimensions={"resource": 1}, scale="1"
                        ),
                        "action-rate": UnitDefinition(
                            symbol="action-rate",
                            dimensions={"action": 1, "time": -1},
                            scale="1",
                        ),
                    }
                }
            )
        }
    )
    objects[unit_digest] = extended_units
    lifecycle = Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL)
    supply = SupplyAttestation(
        metadata=metadata("dimension-supply"),
        spec=SupplySpec(
            supply_id="dimension-supply",
            coordinate="A",
            rate_lower="0",
            rate_upper="1",
            unit="bad-rate",
            window_start=NOW - timedelta(minutes=1),
            window_end=NOW + timedelta(minutes=1),
            lifecycle=lifecycle,
        ),
    )
    supply = supply.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": supply.spec.model_copy(update={"rate_lower": "2", "rate_upper": "1"})  # type: ignore[attr-defined]
        }
    )
    objects[document_digest(supply)] = supply
    rate = RateObservationAttestation(
        metadata=metadata("dimension-rate"),
        spec=RateObservationSpec(
            transformation_id="transform",
            rate_lower="0",
            rate_upper="1",
            action_rate_unit="bad-rate",
            observation_window_start=NOW - timedelta(minutes=1),
            observation_window_end=NOW,
            source_record_digest="sha256:" + "f" * 64,
            lifecycle=lifecycle,
        ),
    )
    objects[document_digest(rate)] = rate
    curve = ServiceCurveAttestation(
        metadata=metadata("dimension-curve"),
        spec=ServiceCurveSpec(
            stage_id="verify",
            curve_type="arrival-upper",
            time_unit="wrong-time",
            work_unit="wrong-work",
            observation_window_start=NOW - timedelta(minutes=1),
            observation_window_end=NOW,
            points=[
                CurvePoint(offset="0", cumulative="0"),
                CurvePoint(offset="1", cumulative="1"),
            ],
            source_record_digest="sha256:" + "e" * 64,
            lifecycle=lifecycle,
        ),
    )
    objects[document_digest(curve)] = curve
    result = _dimensions(snapshot, objects, NOW, Budget())  # type: ignore[arg-type]
    assert {
        "supply_rate_dimension_mismatch:dimension-supply",
        "supply_rate_interval_reversed:dimension-supply",
        "transformation_rate_source_missing:transform",
        "transformation_rate_dimension_mismatch:transform",
        "service_curve_source_missing:verify",
        "service_curve_time_unit_mismatch:verify",
        "service_curve_work_unit_unknown:verify",
    }.issubset(result.blockers)

    negative_supply = supply.model_copy(  # type: ignore[attr-defined]
        update={"spec": supply.spec.model_copy(update={"rate_lower": "-1", "rate_upper": "1"})}  # type: ignore[attr-defined]
    )
    objects[document_digest(supply)] = negative_supply
    objects.pop(document_digest(rate))
    unknown_rate = rate.model_copy(  # type: ignore[attr-defined]
        update={
            "metadata": metadata("unknown-rate"),
            "spec": rate.spec.model_copy(update={"action_rate_unit": "unknown-unit"}),  # type: ignore[attr-defined]
        }
    )
    objects[document_digest(unknown_rate)] = unknown_rate
    second = _dimensions(snapshot, objects, NOW, Budget())  # type: ignore[arg-type]
    assert "supply_rate_negative:dimension-supply" in second.blockers
    assert "transformation_rate_unit_unknown:transform" in second.blockers


def test_organization_negative_balance_and_target_production_are_distinct() -> None:
    snapshot, objects = typed_objects()
    transform_digest, transform = only_one(objects, TransformationAttestation)
    negative = transform.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": transform.spec.model_copy(  # type: ignore[attr-defined]
                update={"inputs": {"A": "2"}, "outputs": {"A": "1"}}
            )
        }
    )
    objects[transform_digest] = negative
    result = _organization(snapshot, objects, NOW, Budget())  # type: ignore[arg-type]
    assert "negative_maintenance_balance:A" in result.blockers
    assert "organization_target_not_produced:target" in result.blockers


def test_persistence_supply_bounds_and_siphon_budget_are_explicit_unknowns() -> None:
    snapshot, objects = typed_objects()
    lifecycle = Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL)
    supply = SupplyAttestation(
        metadata=metadata("bounded-supply"),
        spec=SupplySpec(
            supply_id="bounded-supply",
            coordinate="A",
            rate_lower="0",
            rate_upper="1",
            unit="rate",
            window_start=NOW - timedelta(minutes=1),
            window_end=NOW + timedelta(minutes=1),
            lifecycle=lifecycle,
        ),
    )
    objects[document_digest(supply)] = supply
    _, plan = only_one(
        {
            digest: item
            for digest, item in objects.items()
            if isinstance(item, PersistencePlan)
            and item.spec.analysis_snapshot_digest == snapshot.spec.analysis_basis_digest  # type: ignore[attr-defined]
        },
        PersistencePlan,
    )
    bounded = plan.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": plan.spec.model_copy(  # type: ignore[attr-defined]
                update={"steps": [PersistenceStep(supply_quantities={"bounded-supply": "2"})]}
            )
        }
    )
    replace_type(objects, PersistencePlan, bounded)
    assert (
        "supply_quantity_outside_bound:bounded-supply"
        in _persistence(
            snapshot,
            objects,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )

    transform_digest, transform = only_one(objects, TransformationAttestation)
    many_coordinates = {f"c{index}": "1" for index in range(19)}
    objects[transform_digest] = transform.model_copy(  # type: ignore[attr-defined]
        update={"spec": transform.spec.model_copy(update={"inputs": many_coordinates})}  # type: ignore[attr-defined]
    )
    assert _persistence(snapshot, objects, NOW, Budget()).status == "unknown_due_to_budget"  # type: ignore[arg-type]


def test_verification_service_curves_cover_duplicates_pairs_basis_and_exact_bounds() -> None:
    _, objects = typed_objects()
    lifecycle = Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL)
    evidence_digest, _ = only_one(objects, EvidenceAttestation)

    def curve(
        object_id: str,
        stage_id: str,
        curve_type: str,
        *,
        time_unit: str = "second",
        work_unit: str = "quantity",
        start_offset: int = 0,
        points: tuple[tuple[str, str], ...] = (("0", "0"), ("1", "1"), ("4", "4")),
    ) -> ServiceCurveAttestation:
        return ServiceCurveAttestation(
            metadata=metadata(object_id),
            spec=ServiceCurveSpec(
                stage_id=stage_id,
                curve_type=curve_type,  # type: ignore[arg-type]
                time_unit=time_unit,
                work_unit=work_unit,
                observation_window_start=NOW - timedelta(minutes=5 + start_offset),
                observation_window_end=NOW,
                points=[CurvePoint(offset=x, cumulative=y) for x, y in points],
                source_record_digest=evidence_digest,
                lifecycle=lifecycle,
            ),
        )

    arrival = curve(
        "arrival",
        "verify",
        "arrival-upper",
        points=(("0", "0"), ("1", "2"), ("2", "4")),
    )
    service = curve("service", "verify", "service-lower")
    objects[document_digest(arrival)] = arrival
    objects[document_digest(service)] = service
    exact = _verification(objects, NOW, Budget())  # type: ignore[arg-type]
    assert "verify:backlog=2:delay=2" in exact.detail

    duplicate = arrival.model_copy(update={"metadata": metadata("duplicate-arrival")})
    orphan = curve("orphan", "missing-stage", "arrival-upper")
    incomplete = curve("incomplete", "verify", "arrival-upper")
    basis = curve(
        "basis",
        "verify",
        "service-lower",
        time_unit="other-time",
        start_offset=1,
    )
    changed = dict(objects)
    changed[document_digest(duplicate)] = duplicate
    changed[document_digest(orphan)] = orphan
    changed.pop(document_digest(service))
    changed[document_digest(incomplete)] = incomplete
    changed[document_digest(basis)] = basis
    result = _verification(changed, NOW, Budget())  # type: ignore[arg-type]
    assert any(item.startswith("duplicate_service_curve:verify") for item in result.blockers)
    assert "service_curve_stage_missing:missing-stage" in result.blockers
    assert "service_curve_basis_mismatch:verify" in result.blockers

    pair_missing = {
        digest: item
        for digest, item in objects.items()
        if not isinstance(item, ServiceCurveAttestation) or item.spec.curve_type == "arrival-upper"
    }
    assert (
        "service_curve_pair_incomplete:verify"
        in _verification(
            pair_missing,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )


def test_independence_staleness_and_shared_domains_reduce_effective_count() -> None:
    snapshot, objects = typed_objects()
    _, ledger = only_one(objects, ExposureLedgerDocument)
    stale = ledger.model_copy(  # type: ignore[attr-defined]
        update={
            "spec": ledger.spec.model_copy(  # type: ignore[attr-defined]
                update={"observation_complete_through": NOW - timedelta(seconds=1)}
            )
        }
    )
    replace_type(objects, ExposureLedgerDocument, stale)
    assert (
        "exposure_observation_not_current"
        in _independence(
            snapshot,
            objects,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )

    replace_type(objects, ExposureLedgerDocument, ledger)
    domains = [item for item in objects.values() if isinstance(item, IndependenceAttestation)]
    shared = domains[1].model_copy(  # type: ignore[attr-defined]
        update={
            "spec": domains[1].spec.model_copy(  # type: ignore[attr-defined]
                update={"infrastructure_domain": domains[0].spec.infrastructure_domain}  # type: ignore[attr-defined]
            )
        }
    )
    for digest, item in list(objects.items()):
        if item is domains[1]:
            objects[digest] = shared
    assert (
        "effective_independent_domain_threshold_not_met"
        in _independence(
            snapshot,
            objects,
            NOW,
            Budget(),  # type: ignore[arg-type]
        ).blockers
    )


def test_perturbation_collapse_is_reported_from_a_fresh_reduced_snapshot() -> None:
    snapshot, objects = typed_objects()
    _, suite = only_one(objects, PerturbationSuite)
    transform_digest, _ = only_one(objects, TransformationAttestation)
    scenario = suite.spec.scenarios[0].model_copy(
        update={
            "scenario_id": "remove-transform",
            "remove_object_digests": [transform_digest],
            "replacement_witness_digests": [],
        }
    )
    collapse_suite = suite.model_copy(  # type: ignore[attr-defined]
        update={"spec": suite.spec.model_copy(update={"scenarios": [scenario]})}  # type: ignore[attr-defined]
    )
    replay = replay_perturbations(snapshot, objects, collapse_suite)  # type: ignore[arg-type]
    assert "scenario_collapse:remove-transform" in replay["dimension"].blockers  # type: ignore[union-attr]
