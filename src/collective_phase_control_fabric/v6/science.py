# SPDX-License-Identifier: Apache-2.0
"""Shared exact audit kernel for CPCF v0.6 snapshots and perturbations."""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction

from collective_phase_control_fabric.v6.models import (
    MANDATORY_DIMENSIONS,
    AnalysisSnapshot,
    AuthorityAttestation,
    DimensionResult,
    Document,
    EvidenceAttestation,
    ExposureLedgerDocument,
    IndependenceAttestation,
    OperationalProfile,
    OrganizationWitness,
    PersistencePlan,
    PerturbationSuite,
    PhaseContract,
    QuorumDecisionDocument,
    RateObservationAttestation,
    ResourceObservationAttestation,
    ServiceCurveAttestation,
    StateAttestation,
    SupplyAttestation,
    TransformationAttestation,
    TrustedTimeReceipt,
    TrustPolicyDocument,
    UnitDefinition,
    UnitRegistryDocument,
    VerifierStageAttestation,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.structural_analysis import (
    deterministic_curve_bounds,
    enumerate_minimal_siphons,
    unfed_siphons,
)
from collective_phase_control_fabric.v6.trust import validate_policy

MAX_RATIONAL_BITS = 4096
MAX_OPERATIONS = 10_000_000


class AnalysisBudgetExceeded(RuntimeError):
    """Raised to preserve unknown instead of manufacturing a negative conclusion."""


@dataclass
class Budget:
    operations: int = MAX_OPERATIONS
    deadline_seconds: float = 30.0

    def __post_init__(self) -> None:
        self.remaining = self.operations
        self.deadline = time.monotonic() + self.deadline_seconds

    def spend(self, amount: int = 1) -> None:
        self.remaining -= amount
        if self.remaining < 0 or time.monotonic() > self.deadline:
            raise AnalysisBudgetExceeded


def rational(value: str) -> Fraction:
    result = Fraction(value)
    if result.numerator.bit_length() > MAX_RATIONAL_BITS:
        raise AnalysisBudgetExceeded
    if result.denominator.bit_length() > MAX_RATIONAL_BITS:
        raise AnalysisBudgetExceeded
    return result


def analysis_basis_digest(snapshot: AnalysisSnapshot) -> str:
    """Digest immutable inputs without creating a witness-to-snapshot hash cycle."""

    from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes

    value = snapshot.model_dump(mode="json", exclude_none=True)
    value["spec"]["analysis_basis_digest"] = "sha256:" + "0" * 64
    value["spec"]["witness_digests"] = []
    return digest_bytes(canonical_bytes(value))


def _result(
    status: str,
    *,
    blockers: Iterable[str] = (),
    evidence: Iterable[str] = (),
    detail: str = "",
) -> DimensionResult:
    return DimensionResult(
        status=status,  # type: ignore[arg-type]
        blockers=sorted(set(blockers)),
        evidence_digests=sorted(set(evidence)),
        detail=detail,
    )


def _live(lifecycle: object, at: datetime) -> bool:
    valid_from = getattr(lifecycle, "valid_from", None)
    valid_until = getattr(lifecycle, "valid_until", None)
    withdrawn_at = getattr(lifecycle, "withdrawn_at", None)
    return bool(
        isinstance(valid_from, datetime)
        and isinstance(valid_until, datetime)
        and valid_from <= at <= valid_until
        and (withdrawn_at is None or at < withdrawn_at)
    )


def _typed(objects: dict[str, Document], expected: type[Document]) -> list[Document]:
    return [item for item in objects.values() if isinstance(item, expected)]


def _unit_dimensions(definition: UnitDefinition) -> dict[str, int]:
    return {key: value for key, value in definition.dimensions.items() if value != 0}


def _expected_rate_dimensions(
    coordinate: UnitDefinition, time_unit: UnitDefinition
) -> dict[str, int]:
    result = _unit_dimensions(coordinate)
    for key, value in _unit_dimensions(time_unit).items():
        result[key] = result.get(key, 0) - value
        if result[key] == 0:
            del result[key]
    return result


def _provenance(
    snapshot: AnalysisSnapshot,
    all_objects: dict[str, Document],
) -> tuple[DimensionResult, dict[str, Document]]:
    blockers: list[str] = []
    live: dict[str, Document] = {}
    expected = (
        set(snapshot.spec.object_digests)
        | set(snapshot.spec.witness_digests)
        | {
            snapshot.spec.contract_digest,
            snapshot.spec.trust_policy_digest,
            snapshot.spec.trusted_time_receipt_digest,
            snapshot.spec.unit_registry_digest,
        }
    )
    for digest in sorted(expected):
        item = all_objects.get(digest)
        if item is None:
            blockers.append(f"missing:{digest}")
            continue
        if document_digest(item) != digest:
            blockers.append(f"digest_mismatch:{digest}")
            continue
        if item.metadata.tenant_id != snapshot.metadata.tenant_id:
            blockers.append(f"tenant_mismatch:{digest}")
            continue
        if item.metadata.workspace_id != snapshot.metadata.workspace_id:
            blockers.append(f"workspace_mismatch:{digest}")
            continue
        live[digest] = item
    required = set(MANDATORY_DIMENSIONS)
    if not required.issubset(snapshot.spec.required_dimensions):
        blockers.append("mandatory_security_or_science_dimension_disabled")
    contract = all_objects.get(snapshot.spec.contract_digest)
    if not isinstance(contract, PhaseContract):
        blockers.append("phase_contract_missing")
    elif (
        set(contract.spec.target_ids) != set(snapshot.spec.target_ids)
        or contract.spec.protected_floors != snapshot.spec.protected_floors
        or set(contract.spec.required_dimensions) != set(snapshot.spec.required_dimensions)
        or contract.spec.minimum_independent_domains != snapshot.spec.minimum_independent_domains
    ):
        blockers.append("snapshot_contract_binding_mismatch")
    if snapshot.spec.analysis_basis_digest != analysis_basis_digest(snapshot):
        blockers.append("analysis_basis_digest_mismatch")
    return (
        _result(
            "violated" if blockers else "satisfied",
            blockers=blockers,
            evidence=live,
        ),
        live,
    )


def _temporal(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    evaluation_at: datetime | None = None,
) -> tuple[DimensionResult, datetime | None]:
    item = objects.get(snapshot.spec.trusted_time_receipt_digest)
    if not isinstance(item, TrustedTimeReceipt):
        return _result("violated", blockers=["trusted_time_receipt_missing"]), None
    at = evaluation_at or item.spec.issued_at
    if item.spec.valid_until < item.spec.issued_at:
        return _result("violated", blockers=["trusted_time_interval_invalid"]), None
    if at < item.spec.issued_at or at > item.spec.valid_until:
        return _result("violated", blockers=["evaluation_time_outside_trusted_receipt"]), None
    return _result("satisfied", evidence=[document_digest(item)]), at


def _trust(snapshot: AnalysisSnapshot, objects: dict[str, Document]) -> DimensionResult:
    item = objects.get(snapshot.spec.trust_policy_digest)
    if not isinstance(item, TrustPolicyDocument):
        return _result("violated", blockers=["trust_policy_missing"])
    blockers = validate_policy(item)
    decisions = _typed(objects, QuorumDecisionDocument)
    if not decisions:
        blockers.append("no_role_quorum_decision_in_snapshot")
    return _result(
        "violated" if blockers else "satisfied",
        blockers=blockers,
        evidence=[document_digest(item), *(document_digest(item) for item in decisions)],
    )


def _available_sets(
    objects: dict[str, Document], at: datetime
) -> tuple[set[str], set[str], set[str], set[str]]:
    available: set[str] = set()
    food: set[str] = set()
    evidence: set[str] = set()
    authority: set[str] = set()
    for item in objects.values():
        if isinstance(item, StateAttestation) and _live(item.spec.lifecycle, at):
            if item.spec.available:
                available.add(item.spec.state_id)
                if item.spec.food:
                    food.add(item.spec.state_id)
        elif isinstance(item, ResourceObservationAttestation) and _live(item.spec.lifecycle, at):
            if rational(item.spec.quantity) > 0:
                available.add(item.spec.coordinate)
                food.add(item.spec.coordinate)
        elif isinstance(item, EvidenceAttestation) and _live(item.spec.lifecycle, at):
            evidence.add(item.spec.evidence_id)
            available.add(item.spec.evidence_id)
        elif isinstance(item, AuthorityAttestation) and _live(item.spec.lifecycle, at):
            authority.add(item.spec.authority_id)
            available.add(item.spec.authority_id)
    return available, food, evidence, authority


def _transformations(
    objects: dict[str, Document], at: datetime
) -> dict[str, TransformationAttestation]:
    return {
        item.spec.transformation_id: item
        for item in objects.values()
        if isinstance(item, TransformationAttestation) and _live(item.spec.lifecycle, at)
    }


def _organization_witness(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
) -> OrganizationWitness | None:
    witnesses = [
        item
        for item in objects.values()
        if isinstance(item, OrganizationWitness)
        and item.spec.analysis_snapshot_digest == snapshot.spec.analysis_basis_digest
    ]
    return witnesses[0] if len(witnesses) == 1 else None


def _structural(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    at: datetime,
    budget: Budget,
) -> DimensionResult:
    closure, _, _, _ = _available_sets(objects, at)
    transformations = _transformations(objects, at)
    changed = True
    while changed:
        changed = False
        for transformation_id in sorted(transformations):
            budget.spend()
            spec = transformations[transformation_id].spec
            if set(spec.inputs).issubset(closure):
                before = len(closure)
                closure.update(spec.outputs)
                changed = changed or len(closure) > before
    missing = sorted(set(snapshot.spec.target_ids) - closure)
    return _result(
        "violated" if missing else "satisfied",
        blockers=[f"unreachable_target:{item}" for item in missing],
    )


def _catalyst_satisfied(item: TransformationAttestation, available: set[str]) -> bool:
    spec = item.spec
    if spec.uncatalyzed:
        return True
    return any(set(clause.all_of).issubset(available) for clause in spec.catalyst_clauses)


def _formation(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    at: datetime,
    budget: Budget,
) -> DimensionResult:
    witness = _organization_witness(snapshot, objects)
    if witness is None:
        return _result(
            "unknown",
            blockers=["snapshot_bound_organization_required_for_formation"],
        )
    available, _, evidence, authority = _available_sets(objects, at)
    live_transformations = _transformations(objects, at)
    transformations = {
        identifier: live_transformations[identifier]
        for identifier in witness.spec.transformation_ids
        if identifier in live_transformations
    }
    missing_transformations = sorted(set(witness.spec.transformation_ids) - transformations.keys())
    if missing_transformations:
        return _result(
            "violated",
            blockers=[
                f"formation_transformation_missing:{identifier}"
                for identifier in missing_transformations
            ],
        )
    remaining = set(transformations)
    layers = 0
    while remaining:
        enabled: list[str] = []
        for transformation_id in sorted(remaining):
            budget.spend()
            item = transformations[transformation_id]
            spec = item.spec
            if not set(spec.inputs).issubset(available):
                continue
            if not set(spec.required_evidence).issubset(evidence):
                continue
            if not set(spec.required_authority).issubset(authority):
                continue
            if set(spec.inhibitors) & available:
                continue
            if not _catalyst_satisfied(item, available):
                continue
            enabled.append(transformation_id)
        if not enabled:
            break
        produced: set[str] = set()
        for transformation_id in enabled:
            produced.update(transformations[transformation_id].spec.outputs)
        available.update(produced)
        remaining.difference_update(enabled)
        layers += 1
        if layers > 10_000:
            raise AnalysisBudgetExceeded
    missing = sorted(set(snapshot.spec.target_ids) - available)
    blockers = [f"causally_unformed_target:{item}" for item in missing]
    if missing and remaining:
        blockers.append("strict_prior_formation_deadlock")
    return _result("violated" if blockers else "satisfied", blockers=blockers)


def _dimensions(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    at: datetime,
    budget: Budget,
) -> DimensionResult:
    item = objects.get(snapshot.spec.unit_registry_digest)
    if not isinstance(item, UnitRegistryDocument):
        return _result("violated", blockers=["unit_registry_missing"])
    blockers: list[str] = []
    units = item.spec.units
    for name, definition in units.items():
        budget.spend()
        if rational(definition.scale) <= 0:
            blockers.append(f"unit_scale_not_positive:{name}")
    if item.spec.time_unit not in units or item.spec.action_unit not in units:
        blockers.append("time_or_action_unit_missing")
    for coordinate, unit in item.spec.coordinate_units.items():
        if unit not in units:
            blockers.append(f"coordinate_unit_unknown:{coordinate}")
    for object_value in objects.values():
        budget.spend()
        if isinstance(object_value, ResourceObservationAttestation):
            expected = item.spec.coordinate_units.get(object_value.spec.coordinate)
            if expected != object_value.spec.unit:
                blockers.append(f"resource_unit_mismatch:{object_value.spec.coordinate}")
        elif isinstance(object_value, SupplyAttestation):
            coordinate_unit = item.spec.coordinate_units.get(object_value.spec.coordinate)
            rate_unit = units.get(object_value.spec.unit)
            time_unit = units.get(item.spec.time_unit)
            if coordinate_unit is None or rate_unit is None or time_unit is None:
                blockers.append(f"supply_unit_unknown:{object_value.spec.supply_id}")
                continue
            expected_dimensions = _expected_rate_dimensions(units[coordinate_unit], time_unit)
            if _unit_dimensions(rate_unit) != expected_dimensions:
                blockers.append(f"supply_rate_dimension_mismatch:{object_value.spec.supply_id}")
            if rational(object_value.spec.rate_lower) < 0:
                blockers.append(f"supply_rate_negative:{object_value.spec.supply_id}")
            if rational(object_value.spec.rate_lower) > rational(object_value.spec.rate_upper):
                blockers.append(f"supply_rate_interval_reversed:{object_value.spec.supply_id}")
        elif isinstance(object_value, TransformationAttestation):
            coordinates = set(object_value.spec.inputs) | set(object_value.spec.outputs)
            for coordinate in coordinates:
                if coordinate not in item.spec.coordinate_units:
                    blockers.append(f"transformation_coordinate_untyped:{coordinate}")
                value = object_value.spec.inputs.get(coordinate) or object_value.spec.outputs.get(
                    coordinate
                )
                if value is not None and rational(value) < 0:
                    blockers.append(f"negative_stoichiometry:{coordinate}")
        elif isinstance(object_value, RateObservationAttestation):
            source = objects.get(object_value.spec.source_record_digest)
            if not isinstance(source, EvidenceAttestation) or not _live(source.spec.lifecycle, at):
                blockers.append(
                    f"transformation_rate_source_missing:{object_value.spec.transformation_id}"
                )
            rate_unit = units.get(object_value.spec.action_rate_unit)
            action_unit = units.get(item.spec.action_unit)
            time_unit = units.get(item.spec.time_unit)
            if rate_unit is None or action_unit is None or time_unit is None:
                blockers.append(
                    f"transformation_rate_unit_unknown:{object_value.spec.transformation_id}"
                )
                continue
            expected_dimensions = _expected_rate_dimensions(action_unit, time_unit)
            if _unit_dimensions(rate_unit) != expected_dimensions:
                blockers.append(
                    f"transformation_rate_dimension_mismatch:{object_value.spec.transformation_id}"
                )
        elif isinstance(object_value, ServiceCurveAttestation):
            source = objects.get(object_value.spec.source_record_digest)
            if not isinstance(source, EvidenceAttestation) or not _live(source.spec.lifecycle, at):
                blockers.append(f"service_curve_source_missing:{object_value.spec.stage_id}")
            if object_value.spec.time_unit != item.spec.time_unit:
                blockers.append(f"service_curve_time_unit_mismatch:{object_value.spec.stage_id}")
            if object_value.spec.work_unit not in units:
                blockers.append(f"service_curve_work_unit_unknown:{object_value.spec.stage_id}")
    return _result(
        "violated" if blockers else "satisfied",
        blockers=blockers,
        evidence=[document_digest(item)],
    )


def _organization(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    at: datetime,
    budget: Budget,
) -> DimensionResult:
    witness = _organization_witness(snapshot, objects)
    if witness is None:
        return _result("unknown", blockers=["exactly_one_snapshot_bound_organization_required"])
    transformations = _transformations(objects, at)
    if set(witness.spec.target_ids) != set(snapshot.spec.target_ids):
        return _result("violated", blockers=["organization_target_set_mismatch"])
    if set(witness.spec.transformation_ids) != set(witness.spec.fluxes):
        return _result("violated", blockers=["organization_flux_domain_mismatch"])
    balance: dict[str, Fraction] = {}
    produced: set[str] = set()
    blockers: list[str] = []
    for transformation_id in witness.spec.transformation_ids:
        budget.spend()
        item = transformations.get(transformation_id)
        if item is None:
            blockers.append(f"organization_transformation_missing:{transformation_id}")
            continue
        flux = rational(witness.spec.fluxes[transformation_id])
        if flux <= 0:
            blockers.append(f"organization_flux_not_positive:{transformation_id}")
        for coordinate, value in item.spec.inputs.items():
            balance[coordinate] = balance.get(coordinate, Fraction(0)) - rational(value) * flux
        for coordinate, value in item.spec.outputs.items():
            balance[coordinate] = balance.get(coordinate, Fraction(0)) + rational(value) * flux
            if rational(value) > 0:
                produced.add(coordinate)
    for coordinate, balance_amount in balance.items():
        if balance_amount < 0:
            blockers.append(f"negative_maintenance_balance:{coordinate}")
    for target in snapshot.spec.target_ids:
        if target not in produced:
            blockers.append(f"organization_target_not_produced:{target}")
    return _result(
        "violated" if blockers else "satisfied",
        blockers=blockers,
        evidence=[document_digest(witness)],
    )


def _persistence(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    at: datetime,
    budget: Budget,
) -> DimensionResult:
    snapshot_digest = snapshot.spec.analysis_basis_digest
    plans = [
        item
        for item in objects.values()
        if isinstance(item, PersistencePlan)
        and item.spec.analysis_snapshot_digest == snapshot_digest
    ]
    if len(plans) != 1:
        return _result("unknown", blockers=["exactly_one_snapshot_bound_persistence_plan_required"])
    observations: dict[str, Fraction] = {}
    duplicates: set[str] = set()
    for item in objects.values():
        if isinstance(item, ResourceObservationAttestation) and _live(item.spec.lifecycle, at):
            coordinate = item.spec.coordinate
            if coordinate in observations:
                duplicates.add(coordinate)
            observations[coordinate] = rational(item.spec.quantity)
    if duplicates:
        return _result(
            "violated",
            blockers=[f"ambiguous_resource_observation:{item}" for item in sorted(duplicates)],
        )
    transformations = _transformations(objects, at)
    supplies = {
        item.spec.supply_id: item
        for item in objects.values()
        if isinstance(item, SupplyAttestation) and _live(item.spec.lifecycle, at)
    }
    marking = dict(observations)
    blockers: list[str] = []
    duration = rational(plans[0].spec.duration_per_step)
    if duration <= 0:
        blockers.append("persistence_duration_not_positive")
    for index, step in enumerate(plans[0].spec.steps):
        delta: dict[str, Fraction] = {}
        for transformation_id, count_value in step.action_counts.items():
            budget.spend()
            transformation = transformations.get(transformation_id)
            if transformation is None:
                blockers.append(f"persistence_transformation_missing:{transformation_id}")
                continue
            count = rational(count_value)
            if count < 0:
                blockers.append(f"negative_action_count:{transformation_id}")
            for coordinate, value in transformation.spec.inputs.items():
                delta[coordinate] = delta.get(coordinate, Fraction(0)) - rational(value) * count
            for coordinate, value in transformation.spec.outputs.items():
                delta[coordinate] = delta.get(coordinate, Fraction(0)) + rational(value) * count
        for supply_id, quantity_value in step.supply_quantities.items():
            budget.spend()
            supply = supplies.get(supply_id)
            if supply is None:
                blockers.append(f"supply_attestation_missing:{supply_id}")
                continue
            quantity = rational(quantity_value)
            if quantity < 0 or quantity > rational(supply.spec.rate_upper) * duration:
                blockers.append(f"supply_quantity_outside_bound:{supply_id}")
            delta[supply.spec.coordinate] = (
                delta.get(supply.spec.coordinate, Fraction(0)) + quantity
            )
        for coordinate, delta_amount in delta.items():
            marking[coordinate] = marking.get(coordinate, Fraction(0)) + delta_amount
        for coordinate, floor_value in snapshot.spec.protected_floors.items():
            floor = rational(floor_value)
            if marking.get(coordinate, Fraction(0)) < floor:
                blockers.append(f"prefix_floor_violation:{index}:{coordinate}")
    coordinates = {
        coordinate
        for transformation in transformations.values()
        for coordinate in set(transformation.spec.inputs) | set(transformation.spec.outputs)
    }
    siphons = enumerate_minimal_siphons(transformations, coordinates, budget)
    if not siphons.exhaustive:
        return _result(
            "unknown_due_to_budget",
            blockers=["minimal_siphon_coordinate_limit_exceeded"],
            evidence=[document_digest(plans[0])],
        )
    structural_markings = dict(observations)
    for object_value in objects.values():
        if (
            isinstance(object_value, StateAttestation)
            and object_value.spec.available
            and _live(object_value.spec.lifecycle, at)
        ):
            structural_markings.setdefault(object_value.spec.state_id, Fraction(1))
    unfed = unfed_siphons(
        siphons.values,
        structural_markings,
        (supply.spec.coordinate for supply in supplies.values()),
    )
    blockers.extend(f"unfed_minimal_siphon:{','.join(siphon)}" for siphon in unfed)
    return _result(
        "violated" if blockers else "satisfied",
        blockers=blockers,
        evidence=[document_digest(plans[0])],
    )


def _raf(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    at: datetime,
    budget: Budget,
) -> DimensionResult:
    witness = _organization_witness(snapshot, objects)
    if witness is None:
        return _result(
            "unknown",
            blockers=["snapshot_bound_organization_required_for_raf"],
        )
    _, food, evidence, authority = _available_sets(objects, at)
    available = set(food)
    live_transformations = _transformations(objects, at)
    transformations = {
        identifier: live_transformations[identifier]
        for identifier in witness.spec.transformation_ids
        if identifier in live_transformations
    }
    remaining = set(transformations)
    used: set[str] = set()
    while remaining:
        layer: list[str] = []
        for transformation_id in sorted(remaining):
            budget.spend()
            item = transformations[transformation_id]
            if not set(item.spec.inputs).issubset(available):
                continue
            if set(item.spec.inhibitors) & available:
                continue
            if not set(item.spec.required_evidence).issubset(evidence):
                continue
            if not set(item.spec.required_authority).issubset(authority):
                continue
            if not _catalyst_satisfied(item, available):
                continue
            layer.append(transformation_id)
        if not layer:
            break
        produced: set[str] = set()
        for transformation_id in layer:
            produced.update(transformations[transformation_id].spec.outputs)
        available.update(produced)
        used.update(layer)
        remaining.difference_update(layer)
    missing = sorted(set(snapshot.spec.target_ids) - available)
    blockers = [f"raf_target_not_generated:{item}" for item in missing]
    if not used:
        blockers.append("no_food_supported_catalytic_transformation")
    unused_organization = sorted(set(witness.spec.transformation_ids) - used)
    blockers.extend(
        f"organization_transformation_not_generatively_supported:{item}"
        for item in unused_organization
    )
    return _result("violated" if blockers else "satisfied", blockers=blockers)


def _verification(objects: dict[str, Document], at: datetime, budget: Budget) -> DimensionResult:
    stages = [
        item
        for item in objects.values()
        if isinstance(item, VerifierStageAttestation) and _live(item.spec.lifecycle, at)
    ]
    if not stages:
        return _result("unknown", blockers=["verifier_stage_attestations_missing"])
    blockers: list[str] = []
    window = (stages[0].spec.observation_window_start, stages[0].spec.observation_window_end)
    unit = stages[0].spec.rate_unit
    seen: set[str] = set()
    stage_by_id = {item.spec.stage_id: item for item in stages}
    for stage in stages:
        budget.spend()
        if stage.spec.stage_id in seen:
            blockers.append(f"duplicate_verifier_stage:{stage.spec.stage_id}")
        seen.add(stage.spec.stage_id)
        if (stage.spec.observation_window_start, stage.spec.observation_window_end) != window:
            blockers.append(f"verifier_window_mismatch:{stage.spec.stage_id}")
        if stage.spec.rate_unit != unit:
            blockers.append(f"verifier_rate_unit_mismatch:{stage.spec.stage_id}")
        arrival = rational(stage.spec.arrival_upper) * rational(
            stage.spec.routing_amplification_upper
        )
        service = rational(stage.spec.service_lower)
        if arrival >= service:
            blockers.append(f"verifier_overloaded:{stage.spec.stage_id}")
    rates = [
        item
        for item in objects.values()
        if isinstance(item, RateObservationAttestation) and _live(item.spec.lifecycle, at)
    ]
    rate_ids: set[str] = set()
    transformation_ids = set(_transformations(objects, at))
    rate_window: tuple[datetime, datetime] | None = None
    rate_unit: str | None = None
    for rate in rates:
        budget.spend()
        identifier = rate.spec.transformation_id
        if identifier in rate_ids:
            blockers.append(f"duplicate_transformation_rate:{identifier}")
        rate_ids.add(identifier)
        if identifier not in transformation_ids:
            blockers.append(f"rate_transformation_missing:{identifier}")
        observed_window = (
            rate.spec.observation_window_start,
            rate.spec.observation_window_end,
        )
        if rate_window is None:
            rate_window = observed_window
            rate_unit = rate.spec.action_rate_unit
        elif observed_window != rate_window:
            blockers.append(f"rate_observation_window_mismatch:{identifier}")
        elif rate.spec.action_rate_unit != rate_unit:
            blockers.append(f"rate_observation_unit_mismatch:{identifier}")
    curves = [
        item
        for item in objects.values()
        if isinstance(item, ServiceCurveAttestation) and _live(item.spec.lifecycle, at)
    ]
    curve_groups: dict[str, dict[str, ServiceCurveAttestation]] = {}
    for curve in curves:
        budget.spend()
        group = curve_groups.setdefault(curve.spec.stage_id, {})
        if curve.spec.curve_type in group:
            blockers.append(
                f"duplicate_service_curve:{curve.spec.stage_id}:{curve.spec.curve_type}"
            )
        group[curve.spec.curve_type] = curve
    curve_details: list[str] = []
    for stage_id, group in sorted(curve_groups.items()):
        if stage_id not in stage_by_id:
            blockers.append(f"service_curve_stage_missing:{stage_id}")
            continue
        if set(group) != {"arrival-upper", "service-lower"}:
            blockers.append(f"service_curve_pair_incomplete:{stage_id}")
            continue
        arrival_curve = group["arrival-upper"]
        service_curve = group["service-lower"]
        if (
            arrival_curve.spec.time_unit != service_curve.spec.time_unit
            or arrival_curve.spec.work_unit != service_curve.spec.work_unit
            or arrival_curve.spec.observation_window_start
            != service_curve.spec.observation_window_start
            or arrival_curve.spec.observation_window_end
            != service_curve.spec.observation_window_end
        ):
            blockers.append(f"service_curve_basis_mismatch:{stage_id}")
            continue
        bounds = deterministic_curve_bounds(
            [
                (rational(point.offset), rational(point.cumulative))
                for point in arrival_curve.spec.points
            ],
            [
                (rational(point.offset), rational(point.cumulative))
                for point in service_curve.spec.points
            ],
            budget,
        )
        if not bounds.exhaustive or bounds.delay is None:
            blockers.append(f"service_curve_horizon_insufficient:{stage_id}")
        else:
            curve_details.append(f"{stage_id}:backlog={bounds.backlog}:delay={bounds.delay}")
    return _result(
        "violated" if blockers else "satisfied",
        blockers=blockers,
        evidence=[document_digest(item) for item in [*stages, *rates, *curves]],
        detail=";".join(curve_details),
    )


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def add(self, value: str) -> None:
        self.parent.setdefault(value, value)

    def find(self, value: str) -> str:
        self.add(value)
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[max(left_root, right_root)] = min(left_root, right_root)


def _independence(
    snapshot: AnalysisSnapshot,
    objects: dict[str, Document],
    at: datetime,
    budget: Budget,
) -> DimensionResult:
    domains = [
        item
        for item in objects.values()
        if isinstance(item, IndependenceAttestation) and _live(item.spec.lifecycle, at)
    ]
    ledgers = [item for item in objects.values() if isinstance(item, ExposureLedgerDocument)]
    if len(ledgers) != 1:
        return _result("unknown", blockers=["complete_exposure_ledger_required"])
    ledger = ledgers[0]
    if ledger.spec.observation_complete_through < at:
        return _result("unknown", blockers=["exposure_observation_not_current"])
    if not domains:
        return _result("unknown", blockers=["independence_attestations_missing"])
    union = _UnionFind()
    indexes: dict[tuple[str, str], str] = {}
    for item in domains:
        budget.spend()
        domain = item.spec.domain_id
        union.add(domain)
        for category, value in (
            ("principal", item.spec.principal_id),
            ("key", item.spec.key_id),
            ("infrastructure", item.spec.infrastructure_domain),
            ("lineage", item.spec.lineage_domain),
            ("correlation", item.spec.correlation_domain),
        ):
            previous = indexes.get((category, value))
            if previous is not None:
                union.union(domain, previous)
            indexes[(category, value)] = domain
    known = {item.spec.domain_id for item in domains}
    blockers: list[str] = []
    for event in ledger.spec.events:
        budget.spend()
        if event.from_domain not in known or event.to_domain not in known:
            blockers.append("exposure_refers_to_unknown_domain")
        elif event.pre_commit:
            union.union(event.from_domain, event.to_domain)
    count = len({union.find(item) for item in known})
    if count < snapshot.spec.minimum_independent_domains:
        blockers.append("effective_independent_domain_threshold_not_met")
    return _result(
        "violated" if blockers else "satisfied",
        blockers=blockers,
        evidence=[document_digest(item) for item in [*domains, ledger]],
        detail=f"effective_domains={count}",
    )


def _coordination(objects: dict[str, Document], at: datetime) -> DimensionResult:
    from collective_phase_control_fabric.v6.coordination import validate_coordination

    return validate_coordination(objects, at)


def _budget_unknown(snapshot_digest: str) -> OperationalProfile:
    dimensions = {
        name: _result("unknown_due_to_budget", blockers=["analysis_budget_exhausted"])
        for name in MANDATORY_DIMENSIONS
    }
    return OperationalProfile(
        analysis_snapshot_digest=snapshot_digest,
        dimensions=dimensions,
        operational_organization_compatible=False,
        solution_class="incomplete",
    )


def audit_snapshot(
    snapshot: AnalysisSnapshot,
    all_objects: dict[str, Document],
    *,
    budget: Budget | None = None,
    include_robustness: bool = True,
    evaluation_at: datetime | None = None,
) -> OperationalProfile:
    """Audit one immutable snapshot. Unknown is preserved on absence or bounded exhaustion."""

    active_budget = budget or Budget()
    snapshot_digest = document_digest(snapshot)
    basis_digest = snapshot.spec.analysis_basis_digest
    try:
        provenance, objects = _provenance(snapshot, all_objects)
        temporal, at = _temporal(snapshot, objects, evaluation_at)
        dimensions: dict[str, DimensionResult] = {
            "provenance_integrity": provenance,
            "trust_quorum": _trust(snapshot, objects),
            "temporal_integrity": temporal,
        }
        if at is None or provenance.status != "satisfied":
            unavailable = "typed_live_snapshot_unavailable"
            for name in MANDATORY_DIMENSIONS[3:]:
                dimensions[name] = _result("unknown", blockers=[unavailable])
        else:
            dimensions.update(
                {
                    "structural_reachability": _structural(snapshot, objects, at, active_budget),
                    "causal_formation": _formation(snapshot, objects, at, active_budget),
                    "dimensional_consistency": _dimensions(snapshot, objects, at, active_budget),
                    "exact_self_maintenance": _organization(snapshot, objects, at, active_budget),
                    "finite_horizon_resource_persistence": _persistence(
                        snapshot, objects, at, active_budget
                    ),
                    "target_bound_generative_catalysis": _raf(snapshot, objects, at, active_budget),
                    "verification_capacity": _verification(objects, at, active_budget),
                    "effective_independence": _independence(snapshot, objects, at, active_budget),
                    "coordination_protocol_integrity": _coordination(objects, at),
                }
            )
            if include_robustness:
                suites = [
                    item
                    for item in objects.values()
                    if isinstance(item, PerturbationSuite)
                    and item.spec.baseline_snapshot_digest == basis_digest
                ]
                if len(suites) != 1:
                    dimensions["perturbation_robustness"] = _result(
                        "unknown", blockers=["exactly_one_complete_perturbation_suite_required"]
                    )
                else:
                    replay = replay_perturbations(
                        snapshot, all_objects, suites[0], budget=active_budget
                    )
                    replay_dimension = replay["dimension"]
                    if isinstance(replay_dimension, DimensionResult):
                        dimensions["perturbation_robustness"] = replay_dimension
                    else:
                        dimensions["perturbation_robustness"] = _result(
                            "unknown", blockers=["perturbation_result_invalid"]
                        )
            else:
                dimensions["perturbation_robustness"] = _result(
                    "unknown", blockers=["robustness_not_requested_for_reduced_snapshot"]
                )
        compatible = all(
            dimensions[name].status == "satisfied"
            for name in snapshot.spec.required_dimensions
            if name in dimensions
        ) and set(MANDATORY_DIMENSIONS).issubset(dimensions)
        return OperationalProfile(
            analysis_snapshot_digest=snapshot_digest,
            dimensions=dimensions,
            operational_organization_compatible=compatible,
            solution_class="exact",
        )
    except AnalysisBudgetExceeded:
        return _budget_unknown(snapshot_digest)


def replay_perturbations(
    snapshot: AnalysisSnapshot,
    all_objects: dict[str, Document],
    suite: PerturbationSuite,
    *,
    budget: Budget | None = None,
) -> dict[str, object]:
    """Construct each reduced snapshot and rerun this same kernel from raw typed inputs."""

    active_budget = budget or Budget()
    required = set(snapshot.spec.required_dimensions) - {"perturbation_robustness"}
    if not required.issubset(suite.spec.required_dimensions):
        return {
            "dimension": _result(
                "violated", blockers=["perturbation_acceptance_omits_required_dimension"]
            ),
            "scenarios": [],
        }
    scenario_results: list[dict[str, object]] = []
    blockers: list[str] = []
    for scenario in suite.spec.scenarios:
        active_budget.spend()
        removed = set(scenario.remove_object_digests)
        reduced_objects = {
            digest: item
            for digest, item in all_objects.items()
            if digest not in removed
            and not (
                isinstance(item, TrustPolicyDocument)
                and any(
                    principal.principal_id in scenario.remove_principal_ids
                    for principal in item.spec.principals
                )
            )
        }
        reduced_refs = [item for item in snapshot.spec.object_digests if item not in removed]
        reduced_witnesses = [
            item for item in snapshot.spec.witness_digests if item not in removed
        ] + list(scenario.replacement_witness_digests)
        reduced_snapshot = snapshot.model_copy(
            update={
                "spec": snapshot.spec.model_copy(
                    update={
                        "object_digests": reduced_refs,
                        "witness_digests": reduced_witnesses,
                        "analysis_basis_digest": "sha256:" + "0" * 64,
                    }
                ),
            }
        )
        reduced_snapshot = reduced_snapshot.model_copy(
            update={
                "spec": reduced_snapshot.spec.model_copy(
                    update={"analysis_basis_digest": analysis_basis_digest(reduced_snapshot)}
                )
            }
        )
        profile = audit_snapshot(
            reduced_snapshot,
            reduced_objects,
            budget=active_budget,
            include_robustness=False,
            evaluation_at=scenario.expire_at,
        )
        failed = [
            name
            for name in suite.spec.required_dimensions
            if name != "perturbation_robustness"
            if profile.dimensions.get(name, _result("unknown")).status != "satisfied"
        ]
        if failed:
            blockers.append(f"scenario_collapse:{scenario.scenario_id}")
        scenario_results.append(
            {
                "scenario_id": scenario.scenario_id,
                "reduced_snapshot_digest": document_digest(reduced_snapshot),
                "failed_dimensions": failed,
                "profile": profile,
            }
        )
    return {
        "dimension": _result("violated" if blockers else "satisfied", blockers=blockers),
        "scenarios": scenario_results,
    }
