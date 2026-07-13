# SPDX-License-Identifier: Apache-2.0
"""Closed-model validator assurance for every authoritative v0.6 boundary."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from collective_phase_control_fabric.v6.models import (
    BranchEffect,
    CapabilitySpec,
    CatalystClause,
    CurvePoint,
    ExposureEvent,
    ExposureLedgerSpec,
    Lifecycle,
    PerturbationScenario,
    ProjectionApprovalSpec,
    ProtocolAmendmentSpec,
    RateObservationSpec,
    ResourceObservationSpec,
    ServiceCurveSpec,
    SupplySpec,
    TransformationSpec,
    VerifierStageSpec,
)
from collective_phase_control_fabric.v6.registry import schema_digest
from tests.test_v6_service_boundaries import state_document, trial_fixture
from tests.v6_helpers import NOW, VALID_FROM, VALID_UNTIL


def lifecycle() -> Lifecycle:
    return Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL)


@pytest.mark.parametrize(
    "values",
    [
        {"valid_from": NOW, "valid_until": NOW},
        {
            "valid_from": NOW,
            "valid_until": NOW + timedelta(days=1),
            "withdrawn_at": NOW - timedelta(seconds=1),
        },
    ],
)
def test_lifecycle_ordering_is_closed(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Lifecycle.model_validate(values)


def test_extensions_require_reverse_dns_keys() -> None:
    with pytest.raises(ValidationError, match="reverse-DNS"):
        type(state_document()).model_validate(
            {
                **state_document().model_dump(mode="python"),
                "extensions": {"not-reverse-dns": True},
            }
        )


def test_observation_supply_transformation_and_verifier_temporal_validators() -> None:
    with pytest.raises(ValidationError, match="observation time"):
        ResourceObservationSpec(
            coordinate="A",
            quantity="1",
            unit="quantity",
            observed_at=VALID_UNTIL + timedelta(seconds=1),
            lifecycle=lifecycle(),
        )
    base_supply = {
        "supply_id": "supply",
        "coordinate": "A",
        "rate_lower": "0",
        "rate_upper": "1",
        "unit": "rate",
        "window_start": NOW,
        "window_end": NOW + timedelta(seconds=1),
        "lifecycle": lifecycle(),
    }
    with pytest.raises(ValidationError, match="window end"):
        SupplySpec.model_validate({**base_supply, "window_end": NOW})
    with pytest.raises(ValidationError, match="within its lifecycle"):
        SupplySpec.model_validate({**base_supply, "window_end": VALID_UNTIL + timedelta(seconds=1)})
    with pytest.raises(ValidationError, match="uncatalyzed"):
        TransformationSpec(
            transformation_id="transform",
            outputs={"A": "1"},
            catalyst_clauses=[CatalystClause(all_of=["cat"])],
            uncatalyzed=True,
            lifecycle=lifecycle(),
        )
    with pytest.raises(ValidationError, match="at least one flow"):
        TransformationSpec(
            transformation_id="empty",
            uncatalyzed=True,
            lifecycle=lifecycle(),
        )
    with pytest.raises(ValidationError, match="window end"):
        VerifierStageSpec(
            stage_id="verify",
            arrival_upper="0",
            service_lower="1",
            rate_unit="rate",
            observation_window_start=NOW,
            observation_window_end=NOW,
            independence_domain="domain",
            lifecycle=lifecycle(),
        )


def test_rate_and_service_curve_validators_cover_all_orientation_failures() -> None:
    rate = {
        "transformation_id": "transform",
        "rate_lower": "0",
        "rate_upper": "1",
        "action_rate_unit": "action-rate",
        "observation_window_start": NOW - timedelta(seconds=1),
        "observation_window_end": NOW,
        "source_record_digest": "sha256:" + "1" * 64,
        "lifecycle": lifecycle(),
    }
    with pytest.raises(ValidationError, match="ordered and nonnegative"):
        RateObservationSpec.model_validate({**rate, "rate_lower": "2"})
    with pytest.raises(ValidationError, match="window end"):
        RateObservationSpec.model_validate(
            {**rate, "observation_window_start": NOW, "observation_window_end": NOW}
        )
    with pytest.raises(ValidationError, match="within its lifecycle"):
        RateObservationSpec.model_validate(
            {
                **rate,
                "observation_window_start": VALID_FROM - timedelta(seconds=1),
            }
        )

    curve = {
        "stage_id": "verify",
        "curve_type": "arrival-upper",
        "time_unit": "second",
        "work_unit": "quantity",
        "observation_window_start": NOW - timedelta(seconds=1),
        "observation_window_end": NOW,
        "points": [
            CurvePoint(offset="0", cumulative="0"),
            CurvePoint(offset="1", cumulative="1"),
        ],
        "source_record_digest": "sha256:" + "2" * 64,
        "lifecycle": lifecycle(),
    }
    with pytest.raises(ValidationError, match="origin"):
        ServiceCurveSpec.model_validate(
            {
                **curve,
                "points": [
                    CurvePoint(offset="0", cumulative="1"),
                    CurvePoint(offset="1", cumulative="1"),
                ],
            }
        )
    with pytest.raises(ValidationError, match="strictly increasing"):
        ServiceCurveSpec.model_validate(
            {
                **curve,
                "points": [
                    CurvePoint(offset="0", cumulative="0"),
                    CurvePoint(offset="0", cumulative="1"),
                ],
            }
        )
    with pytest.raises(ValidationError, match="nonnegative and monotone"):
        ServiceCurveSpec.model_validate(
            {
                **curve,
                "points": [
                    CurvePoint(offset="0", cumulative="0"),
                    CurvePoint(offset="1", cumulative="-1"),
                ],
            }
        )
    with pytest.raises(ValidationError, match="window end"):
        ServiceCurveSpec.model_validate(
            {**curve, "observation_window_start": NOW, "observation_window_end": NOW}
        )
    with pytest.raises(ValidationError, match="within its lifecycle"):
        ServiceCurveSpec.model_validate(
            {**curve, "observation_window_start": VALID_FROM - timedelta(seconds=1)}
        )


def test_exposure_perturbation_branch_capability_and_projection_validators() -> None:
    with pytest.raises(ValidationError, match="follows completeness"):
        ExposureLedgerSpec(
            events=[
                ExposureEvent(
                    artifact_digest="sha256:" + "3" * 64,
                    from_domain="one",
                    to_domain="two",
                    observed_at=NOW + timedelta(seconds=1),
                    pre_commit=True,
                )
            ],
            observation_complete_through=NOW,
            observer_principal_id="observer",
        )
    with pytest.raises(ValidationError, match="must alter"):
        PerturbationScenario(scenario_id="empty")
    for field in (
        "time_upper",
        "cost_upper",
        "verification_load_upper",
        "independence_erosion_upper",
        "correlation_concentration_upper",
        "cut_exposure_upper",
    ):
        with pytest.raises(ValidationError, match="nonnegative"):
            BranchEffect.model_validate(
                {
                    "outcome": "success",
                    field: "-1",
                }
            )
    with pytest.raises(ValidationError, match="additions and removals"):
        BranchEffect(
            outcome="failure",
            must_add=["sha256:" + "1" * 64],
            may_remove=["sha256:" + "1" * 64],
        )
    with pytest.raises(ValidationError, match="same hazard"):
        BranchEffect(
            outcome="failure",
            hazards_added=["hazard"],
            hazards_removed=["hazard"],
        )
    with pytest.raises(ValidationError, match="selectors must be unique"):
        PerturbationScenario(
            scenario_id="duplicate-selectors",
            remove_state_ids=["state", "state"],
        )

    branches = [
        BranchEffect(outcome=outcome) for outcome in ("success", "partial", "failure", "timeout")
    ]
    base = {
        "capability_id": "capability",
        "adapter_principal_id": "adapter",
        "verifier_principal_id": "verifier",
        "execution_policy_digest": "sha256:" + "6" * 64,
        "image_digest": "sha256:" + "4" * 64,
        "argv": ["/adapter/run"],
        "output_schema_name": "state-attestation",
        "output_schema_digest": schema_digest("state-attestation"),
        "return_code_outcomes": {"0": "success"},
        "repeatable": False,
        "branches": branches,
    }
    with pytest.raises(ValidationError, match="four distinct outcomes"):
        CapabilitySpec.model_validate({**base, "branches": [branches[0]] * 4})
    with pytest.raises(ValidationError, match="independent"):
        CapabilitySpec.model_validate({**base, "verifier_principal_id": "adapter"})
    with pytest.raises(ValidationError, match="progress measure"):
        CapabilitySpec.model_validate({**base, "repeatable": True})
    with pytest.raises(ValidationError, match="must differ"):
        ProjectionApprovalSpec(
            projection_digest="sha256:" + "5" * 64,
            producer_principal_id="same",
            verifier_principal_id="same",
            approved_at=NOW,
        )


def test_protocol_amendment_and_remaining_trial_model_invariants() -> None:
    protocol, _, result = trial_fixture()
    with pytest.raises(ValidationError, match="quality verifier"):
        type(protocol.spec).model_validate(
            {
                **protocol.spec.model_dump(mode="python"),
                "quality_verifier_principal_id": protocol.spec.evaluator_principal_id,
            }
        )
    with pytest.raises(ValidationError, match="completion must follow"):
        type(protocol.spec).model_validate(
            {
                **protocol.spec.model_dump(mode="python"),
                "observation_complete_at": protocol.spec.time_zero,
            }
        )
    with pytest.raises(ValidationError, match="changes must be unique"):
        ProtocolAmendmentSpec(
            protocol_digest="sha256:" + "6" * 64,
            sequence=1,
            amended_at=NOW,
            changes=["estimand", "estimand"],
        )
    with pytest.raises(ValidationError, match="issuance must follow"):
        type(result.spec).model_validate(
            {
                **result.spec.model_dump(mode="python"),
                "issued_at": result.spec.observation_completed_at,
            }
        )
