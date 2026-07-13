# SPDX-License-Identifier: Apache-2.0
"""Closed, discriminated CPCF v0.6 authority and analysis models."""

from __future__ import annotations

from datetime import datetime
from itertools import pairwise
from typing import Annotated, Any, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

API_VERSION: Final[Literal["cpcf.io/v0.6"]] = "cpcf.io/v0.6"
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
RATIONAL_PATTERN = r"^-?(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?$"
UNIT_PATTERN = r"^[A-Za-z][A-Za-z0-9._/-]{0,63}$"
REVERSE_DNS_PATTERN = (
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

Identifier = Annotated[str, StringConstraints(pattern=ID_PATTERN, max_length=128)]
Digest = Annotated[str, StringConstraints(pattern=SHA256_PATTERN)]
Rational = Annotated[str, StringConstraints(pattern=RATIONAL_PATTERN, max_length=1234)]
UnitName = Annotated[str, StringConstraints(pattern=UNIT_PATTERN)]
ProfileStatus = Literal["satisfied", "violated", "unknown", "unknown_due_to_budget"]
OutcomeName = Literal["success", "partial", "failure", "timeout"]
type JsonScalar = None | bool | int | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class StrictModel(BaseModel):
    """Base model that rejects undeclared fields at every typed boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)


class Metadata(StrictModel):
    tenant_id: Identifier
    workspace_id: Identifier
    object_id: Identifier
    created_at: datetime


class Document(StrictModel):
    """Common v0.6 document envelope; subclasses close the `kind` discriminator."""

    api_version: Literal["cpcf.io/v0.6"] = API_VERSION
    kind: str
    metadata: Metadata
    extensions: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)

    @field_validator("extensions")
    @classmethod
    def validate_extensions(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        import re

        for key in value:
            if re.fullmatch(REVERSE_DNS_PATTERN, key) is None:
                raise ValueError("extension keys must use reverse-DNS form")
        return value


class UnitDefinition(StrictModel):
    symbol: UnitName
    dimensions: dict[Identifier, int] = Field(min_length=1, max_length=16)
    scale: Rational


class UnitRegistrySpec(StrictModel):
    units: dict[UnitName, UnitDefinition] = Field(min_length=1, max_length=256)
    coordinate_units: dict[Identifier, UnitName] = Field(min_length=1, max_length=10_000)
    time_unit: UnitName
    action_unit: UnitName


class UnitRegistryDocument(Document):
    kind: Literal["unit-registry"] = "unit-registry"
    spec: UnitRegistrySpec


class PhaseContractSpec(StrictModel):
    target_ids: list[Identifier] = Field(min_length=1, max_length=256)
    protected_floors: dict[Identifier, Rational] = Field(default_factory=dict, max_length=10_000)
    required_dimensions: list[Identifier] = Field(min_length=13, max_length=13)
    minimum_independent_domains: Annotated[int, Field(ge=1, le=256)]
    planning_horizon: Annotated[int, Field(ge=1, le=3)] = 1
    candidate_limit: Literal[64] = 64
    beam_width: Literal[32] = 32
    analysis_operation_budget: Annotated[int, Field(ge=1, le=10_000_000)] = 10_000_000
    solver_deadline_seconds: Annotated[int, Field(ge=1, le=30)] = 30


class PhaseContract(Document):
    kind: Literal["phase-contract"] = "phase-contract"
    spec: PhaseContractSpec


class Lifecycle(StrictModel):
    valid_from: datetime
    valid_until: datetime
    withdrawn_at: datetime | None = None

    @model_validator(mode="after")
    def ordered(self) -> Lifecycle:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must follow valid_from")
        if self.withdrawn_at is not None and self.withdrawn_at < self.valid_from:
            raise ValueError("withdrawn_at cannot precede valid_from")
        return self


class StateSpec(StrictModel):
    state_id: Identifier
    available: bool
    food: bool = False
    lineage_digests: list[Digest] = Field(default_factory=list, max_length=128)
    lifecycle: Lifecycle


class StateAttestation(Document):
    kind: Literal["state-attestation"] = "state-attestation"
    spec: StateSpec


class ResourceObservationSpec(StrictModel):
    coordinate: Identifier
    quantity: Rational
    unit: UnitName
    observed_at: datetime
    lifecycle: Lifecycle

    @model_validator(mode="after")
    def observation_integrity(self) -> ResourceObservationSpec:
        from fractions import Fraction

        if Fraction(self.quantity) < 0:
            raise ValueError("resource observation quantity must be nonnegative")
        if not self.lifecycle.valid_from <= self.observed_at <= self.lifecycle.valid_until:
            raise ValueError("resource observation time must be within its lifecycle")
        return self


class ResourceObservationAttestation(Document):
    kind: Literal["resource-observation-attestation"] = "resource-observation-attestation"
    spec: ResourceObservationSpec


class SupplySpec(StrictModel):
    supply_id: Identifier
    coordinate: Identifier
    rate_lower: Rational
    rate_upper: Rational
    unit: UnitName
    window_start: datetime
    window_end: datetime
    lifecycle: Lifecycle

    @model_validator(mode="after")
    def supply_integrity(self) -> SupplySpec:
        from fractions import Fraction

        lower = Fraction(self.rate_lower)
        upper = Fraction(self.rate_upper)
        if lower < 0 or upper < lower:
            raise ValueError("supply rate interval must be ordered and nonnegative")
        if self.window_end <= self.window_start:
            raise ValueError("supply window end must follow its start")
        if (
            self.window_start < self.lifecycle.valid_from
            or self.window_end > self.lifecycle.valid_until
        ):
            raise ValueError("supply window must be within its lifecycle")
        return self


class SupplyAttestation(Document):
    kind: Literal["supply-attestation"] = "supply-attestation"
    spec: SupplySpec


class CatalystClause(StrictModel):
    all_of: list[Identifier] = Field(min_length=1, max_length=32)


class TransformationSpec(StrictModel):
    transformation_id: Identifier
    inputs: dict[Identifier, Rational] = Field(default_factory=dict, max_length=512)
    outputs: dict[Identifier, Rational] = Field(default_factory=dict, max_length=512)
    catalyst_clauses: list[CatalystClause] = Field(default_factory=list, max_length=32)
    inhibitors: list[Identifier] = Field(default_factory=list, max_length=128)
    uncatalyzed: bool = False
    required_evidence: list[Identifier] = Field(default_factory=list, max_length=128)
    required_authority: list[Identifier] = Field(default_factory=list, max_length=128)
    lifecycle: Lifecycle

    @model_validator(mode="after")
    def catalytic_semantics(self) -> TransformationSpec:
        if self.uncatalyzed and self.catalyst_clauses:
            raise ValueError("uncatalyzed transformations cannot declare catalyst clauses")
        if not self.inputs and not self.outputs:
            raise ValueError("transformation must declare at least one flow")
        return self


class TransformationAttestation(Document):
    kind: Literal["transformation-attestation"] = "transformation-attestation"
    spec: TransformationSpec


class AuthoritySpec(StrictModel):
    authority_id: Identifier
    scope: list[Identifier] = Field(min_length=1, max_length=128)
    lifecycle: Lifecycle


class AuthorityAttestation(Document):
    kind: Literal["authority-attestation"] = "authority-attestation"
    spec: AuthoritySpec


class EvidenceSpec(StrictModel):
    evidence_id: Identifier
    evidence_type: Identifier
    raw_artifact_digest: Digest
    json_pointer: Annotated[str, StringConstraints(max_length=2048)]
    projected_digest: Digest
    lifecycle: Lifecycle


class EvidenceAttestation(Document):
    kind: Literal["evidence-attestation"] = "evidence-attestation"
    spec: EvidenceSpec


class SourceArtifactSpec(StrictModel):
    raw_digest: Digest
    byte_length: Annotated[int, Field(ge=0, le=67_108_864)]
    media_type: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    source_system: Identifier
    source_uri: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    acquired_at: datetime
    expected_schema_name: Identifier
    expected_schema_digest: Digest


class SourceArtifactEnvelope(Document):
    kind: Literal["source-artifact-envelope"] = "source-artifact-envelope"
    spec: SourceArtifactSpec


class VerifierStageSpec(StrictModel):
    stage_id: Identifier
    arrival_upper: Rational
    service_lower: Rational
    rate_unit: UnitName
    observation_window_start: datetime
    observation_window_end: datetime
    independence_domain: Identifier
    routing_amplification_upper: Rational = "1"
    lifecycle: Lifecycle

    @model_validator(mode="after")
    def verifier_integrity(self) -> VerifierStageSpec:
        from fractions import Fraction

        if self.observation_window_end <= self.observation_window_start:
            raise ValueError("verifier observation window end must follow its start")
        if (
            Fraction(self.arrival_upper) < 0
            or Fraction(self.service_lower) <= 0
            or Fraction(self.routing_amplification_upper) < 0
        ):
            raise ValueError("verifier rates must have valid nonnegative orientation")
        return self


class VerifierStageAttestation(Document):
    kind: Literal["verifier-stage-attestation"] = "verifier-stage-attestation"
    spec: VerifierStageSpec


class RateObservationSpec(StrictModel):
    transformation_id: Identifier
    rate_lower: Rational
    rate_upper: Rational
    action_rate_unit: UnitName
    observation_window_start: datetime
    observation_window_end: datetime
    source_record_digest: Digest
    lifecycle: Lifecycle

    @model_validator(mode="after")
    def rate_integrity(self) -> RateObservationSpec:
        from fractions import Fraction

        lower = Fraction(self.rate_lower)
        upper = Fraction(self.rate_upper)
        if lower < 0 or upper < lower:
            raise ValueError("rate interval must be ordered and nonnegative")
        if self.observation_window_end <= self.observation_window_start:
            raise ValueError("rate observation window end must follow its start")
        if (
            self.observation_window_start < self.lifecycle.valid_from
            or self.observation_window_end > self.lifecycle.valid_until
        ):
            raise ValueError("rate observation window must be within its lifecycle")
        return self


class RateObservationAttestation(Document):
    kind: Literal["rate-observation-attestation"] = "rate-observation-attestation"
    spec: RateObservationSpec


class CurvePoint(StrictModel):
    offset: Rational
    cumulative: Rational


class ServiceCurveSpec(StrictModel):
    stage_id: Identifier
    curve_type: Literal["arrival-upper", "service-lower"]
    time_unit: UnitName
    work_unit: UnitName
    observation_window_start: datetime
    observation_window_end: datetime
    points: list[CurvePoint] = Field(min_length=2, max_length=4096)
    source_record_digest: Digest
    lifecycle: Lifecycle

    @model_validator(mode="after")
    def curve_integrity(self) -> ServiceCurveSpec:
        from fractions import Fraction

        offsets = [Fraction(point.offset) for point in self.points]
        cumulative = [Fraction(point.cumulative) for point in self.points]
        if offsets[0] != 0 or cumulative[0] != 0:
            raise ValueError("service curve must start at the origin")
        if any(right <= left for left, right in pairwise(offsets)):
            raise ValueError("service curve offsets must be strictly increasing")
        if any(value < 0 for value in cumulative) or any(
            right < left for left, right in pairwise(cumulative)
        ):
            raise ValueError("service curve cumulative values must be nonnegative and monotone")
        if self.observation_window_end <= self.observation_window_start:
            raise ValueError("service curve observation window end must follow its start")
        if (
            self.observation_window_start < self.lifecycle.valid_from
            or self.observation_window_end > self.lifecycle.valid_until
        ):
            raise ValueError("service curve observation window must be within its lifecycle")
        return self


class ServiceCurveAttestation(Document):
    kind: Literal["service-curve-attestation"] = "service-curve-attestation"
    spec: ServiceCurveSpec


class IndependenceSpec(StrictModel):
    domain_id: Identifier
    principal_id: Identifier
    key_id: Identifier
    infrastructure_domain: Identifier
    lineage_domain: Identifier
    correlation_domain: Identifier
    lifecycle: Lifecycle


class IndependenceAttestation(Document):
    kind: Literal["independence-attestation"] = "independence-attestation"
    spec: IndependenceSpec


class ExposureEvent(StrictModel):
    artifact_digest: Digest
    from_domain: Identifier
    to_domain: Identifier
    observed_at: datetime
    pre_commit: bool


class ExposureLedgerSpec(StrictModel):
    events: list[ExposureEvent] = Field(default_factory=list, max_length=100_000)
    observation_complete_through: datetime
    observer_principal_id: Identifier

    @model_validator(mode="after")
    def exposure_integrity(self) -> ExposureLedgerSpec:
        if any(item.observed_at > self.observation_complete_through for item in self.events):
            raise ValueError("exposure event follows completeness observation")
        return self


class ExposureLedgerDocument(Document):
    kind: Literal["exposure-ledger"] = "exposure-ledger"
    spec: ExposureLedgerSpec


class Principal(StrictModel):
    principal_id: Identifier
    key_id: Identifier
    algorithm: Literal["ed25519", "ecdsa-p256-sha256"]
    public_key_base64: Annotated[str, StringConstraints(min_length=40, max_length=512)]
    roles: list[Identifier] = Field(min_length=1, max_length=64)
    source_systems: list[Identifier] = Field(min_length=1, max_length=64)
    allowed_kinds: list[Identifier] = Field(min_length=1, max_length=128)
    scope: list[Identifier] = Field(min_length=1, max_length=128)
    infrastructure_domain: Identifier
    correlation_domain: Identifier
    valid_from: datetime
    valid_until: datetime
    revoked_at: datetime | None = None
    compromised_at: datetime | None = None
    revocation_mode: Literal["prospective", "retroactive"] = "prospective"


class QuorumRule(StrictModel):
    decision_type: Identifier
    required_roles: list[Identifier] = Field(min_length=2, max_length=8)
    distinct_infrastructure: bool = True
    distinct_correlation: bool = True


class TrustPolicySpec(StrictModel):
    policy_sequence: Annotated[int, Field(ge=0)]
    prior_policy_digest: Digest | None = None
    root_key_id: Identifier
    principals: list[Principal] = Field(min_length=1, max_length=256)
    quorum_rules: list[QuorumRule] = Field(min_length=1, max_length=32)


class TrustPolicyDocument(Document):
    kind: Literal["trust-policy"] = "trust-policy"
    spec: TrustPolicySpec


class TrustedTimeSpec(StrictModel):
    authority_principal_id: Identifier
    issued_at: datetime
    valid_until: datetime
    nonce: Identifier


class TrustedTimeReceipt(Document):
    kind: Literal["trusted-time-receipt"] = "trusted-time-receipt"
    spec: TrustedTimeSpec


class ProtectedHeader(StrictModel):
    domain: Literal["CPCF-DSSE-STATEMENT-v0.6"] = "CPCF-DSSE-STATEMENT-v0.6"
    cpcf_version: Literal["0.6.0"] = "0.6.0"
    canonicalization_profile: Literal["RFC8785-CPCF-FLOAT-FREE-2"] = "RFC8785-CPCF-FLOAT-FREE-2"
    schema_name: Identifier
    schema_digest: Digest
    payload_digest: Digest
    key_id: Identifier
    principal_id: Identifier
    role: Identifier
    source_system: Identifier
    scope: list[Identifier] = Field(min_length=1, max_length=128)
    tenant_id: Identifier
    workspace_id: Identifier
    signing_time: datetime
    policy_sequence: Annotated[int, Field(ge=0)]
    trusted_time_receipt_digest: Digest | None = None


class SignedPayload(StrictModel):
    protected: ProtectedHeader
    subject: dict[str, Any]


class DsseSignature(StrictModel):
    keyid: Annotated[str, StringConstraints(max_length=128)] = ""
    sig: Annotated[str, StringConstraints(min_length=40, max_length=1024)]


class DsseEnvelope(StrictModel):
    payloadType: Literal["application/vnd.cpcf.statement+json;version=0.6"]
    payload: Annotated[str, StringConstraints(min_length=4, max_length=24_000_000)]
    signatures: list[DsseSignature] = Field(min_length=1, max_length=8)


class SignedStatementSpec(StrictModel):
    """A DSSE envelope admitted as a first-class immutable ledger object."""

    envelope: DsseEnvelope


class SignedStatement(Document):
    kind: Literal["signed-statement"] = "signed-statement"
    spec: SignedStatementSpec


class QuorumDecisionSpec(StrictModel):
    decision_type: Identifier
    subject_digest: Digest
    statement_digests: list[Digest] = Field(min_length=2, max_length=8)
    decided_at: datetime


class QuorumDecisionDocument(Document):
    kind: Literal["quorum-decision"] = "quorum-decision"
    spec: QuorumDecisionSpec


class OrganizationSpec(StrictModel):
    analysis_snapshot_digest: Digest
    target_ids: list[Identifier] = Field(min_length=1, max_length=256)
    transformation_ids: list[Identifier] = Field(min_length=1, max_length=10_000)
    fluxes: dict[Identifier, Rational] = Field(min_length=1, max_length=10_000)


class OrganizationWitness(Document):
    kind: Literal["organization-witness"] = "organization-witness"
    spec: OrganizationSpec


class PersistenceStep(StrictModel):
    action_counts: dict[Identifier, Rational] = Field(default_factory=dict, max_length=10_000)
    supply_quantities: dict[Identifier, Rational] = Field(default_factory=dict, max_length=10_000)


class PersistencePlanSpec(StrictModel):
    analysis_snapshot_digest: Digest
    duration_per_step: Rational
    steps: list[PersistenceStep] = Field(min_length=1, max_length=1024)


class PersistencePlan(Document):
    kind: Literal["persistence-plan"] = "persistence-plan"
    spec: PersistencePlanSpec


class SnapshotSpec(StrictModel):
    generation_digest: Digest
    analysis_basis_digest: Digest
    contract_digest: Digest
    trust_policy_digest: Digest
    trusted_time_receipt_digest: Digest
    unit_registry_digest: Digest
    object_digests: list[Digest] = Field(min_length=1, max_length=50_000)
    witness_digests: list[Digest] = Field(default_factory=list, max_length=50_000)
    target_ids: list[Identifier] = Field(min_length=1, max_length=256)
    protected_floors: dict[Identifier, Rational] = Field(default_factory=dict, max_length=10_000)
    minimum_independent_domains: Annotated[int, Field(ge=1, le=256)] = 2
    required_dimensions: list[Identifier] = Field(min_length=1, max_length=32)


class AnalysisSnapshot(Document):
    kind: Literal["analysis-snapshot"] = "analysis-snapshot"
    spec: SnapshotSpec


class DimensionResult(StrictModel):
    status: ProfileStatus
    blockers: list[Identifier] = Field(default_factory=list, max_length=10_000)
    evidence_digests: list[Digest] = Field(default_factory=list, max_length=10_000)
    detail: str = Field(default="", max_length=4096)


class OperationalProfile(StrictModel):
    analysis_snapshot_digest: Digest
    dimensions: dict[Identifier, DimensionResult] = Field(min_length=13, max_length=13)
    operational_organization_compatible: bool
    solution_class: Literal["exact", "bounded", "incomplete"]


class OperationalProfileResultSpec(StrictModel):
    analysis_snapshot_digest: Digest
    trusted_time_receipt_digest: Digest
    profile: OperationalProfile
    produced_at: datetime
    operation_count: Annotated[int, Field(ge=0, le=10_000_000)]

    @model_validator(mode="after")
    def binds_profile_snapshot(self) -> OperationalProfileResultSpec:
        if self.profile.analysis_snapshot_digest != self.analysis_snapshot_digest:
            raise ValueError("operational profile snapshot binding mismatch")
        return self


class OperationalProfileResult(Document):
    kind: Literal["operational-profile-result"] = "operational-profile-result"
    spec: OperationalProfileResultSpec


class PerturbationScenario(StrictModel):
    scenario_id: Identifier
    remove_object_digests: list[Digest] = Field(default_factory=list, max_length=50_000)
    remove_principal_ids: list[Identifier] = Field(default_factory=list, max_length=256)
    replacement_witness_digests: list[Digest] = Field(default_factory=list, max_length=50_000)
    expire_at: datetime | None = None

    @model_validator(mode="after")
    def changes_snapshot(self) -> PerturbationScenario:
        if (
            not self.remove_object_digests
            and not self.remove_principal_ids
            and self.expire_at is None
        ):
            raise ValueError("perturbation scenario must alter the snapshot")
        return self


class PerturbationSuiteSpec(StrictModel):
    baseline_snapshot_digest: Digest
    scenarios: list[PerturbationScenario] = Field(min_length=1, max_length=256)
    required_dimensions: list[Identifier] = Field(min_length=1, max_length=32)


class PerturbationSuite(Document):
    kind: Literal["perturbation-suite"] = "perturbation-suite"
    spec: PerturbationSuiteSpec


class PerturbationResultSpec(StrictModel):
    suite_digest: Digest
    scenario_id: Identifier
    baseline_snapshot_digest: Digest
    reduced_snapshot_digest: Digest
    trusted_time_receipt_digest: Digest
    profile_result_digest: Digest
    status: ProfileStatus
    blockers: list[Identifier] = Field(default_factory=list, max_length=10_000)
    operation_count: Annotated[int, Field(ge=0, le=10_000_000)]


class PerturbationResult(Document):
    kind: Literal["perturbation-result"] = "perturbation-result"
    spec: PerturbationResultSpec


class SiphonAnalysisSpec(StrictModel):
    analysis_snapshot_digest: Digest
    exhaustive: bool
    status: ProfileStatus
    minimal_siphons: list[list[Identifier]] = Field(default_factory=list, max_length=4096)
    unfed_siphons: list[list[Identifier]] = Field(default_factory=list, max_length=4096)
    operation_count: Annotated[int, Field(ge=0, le=10_000_000)]


class SiphonAnalysisResult(Document):
    kind: Literal["siphon-analysis-result"] = "siphon-analysis-result"
    spec: SiphonAnalysisSpec


class FluxCouplingSpec(StrictModel):
    analysis_snapshot_digest: Digest
    transformation_set_digest: Digest
    status: ProfileStatus
    blocked_transformations: list[Identifier] = Field(default_factory=list, max_length=10_000)
    fully_coupled_classes: list[list[Identifier]] = Field(default_factory=list, max_length=10_000)
    solver_name: Identifier
    solver_version: Identifier
    exact_model_rechecked: bool
    operation_count: Annotated[int, Field(ge=0, le=10_000_000)]


class FluxCouplingResult(Document):
    kind: Literal["flux-coupling-result"] = "flux-coupling-result"
    spec: FluxCouplingSpec


class CutSetAnalysisSpec(StrictModel):
    analysis_snapshot_digest: Digest
    target_ids: list[Identifier] = Field(min_length=1, max_length=256)
    exhaustive: bool
    status: ProfileStatus
    minimal_cut_sets: list[list[Identifier]] = Field(default_factory=list, max_length=4096)
    minimal_enablement_sets: list[list[Identifier]] = Field(default_factory=list, max_length=4096)
    operation_count: Annotated[int, Field(ge=0, le=10_000_000)]


class CutSetAnalysisResult(Document):
    kind: Literal["cut-set-analysis-result"] = "cut-set-analysis-result"
    spec: CutSetAnalysisSpec


class OccurrenceCondition(StrictModel):
    condition_id: Identifier
    state_id: Identifier
    producer_event_id: Identifier | None = None


class OccurrenceEvent(StrictModel):
    event_id: Identifier
    transformation_id: Identifier
    preset_condition_ids: list[Identifier] = Field(default_factory=list, max_length=512)
    postset_condition_ids: list[Identifier] = Field(default_factory=list, max_length=512)
    causal_predecessor_ids: list[Identifier] = Field(default_factory=list, max_length=10_000)
    conflict_event_ids: list[Identifier] = Field(default_factory=list, max_length=10_000)


class OccurrencePrefixSpec(StrictModel):
    analysis_snapshot_digest: Digest
    exhaustive: bool
    status: ProfileStatus
    conditions: list[OccurrenceCondition] = Field(default_factory=list, max_length=100_000)
    events: list[OccurrenceEvent] = Field(default_factory=list, max_length=100_000)
    cutoff_event_ids: list[Identifier] = Field(default_factory=list, max_length=100_000)
    operation_count: Annotated[int, Field(ge=0, le=10_000_000)]


class OccurrencePrefixResult(Document):
    kind: Literal["occurrence-prefix-result"] = "occurrence-prefix-result"
    spec: OccurrencePrefixSpec


class InterventionCandidate(StrictModel):
    action_digest: Digest
    guaranteed_target_ids: list[Identifier] = Field(default_factory=list, max_length=256)
    resolves_blockers: list[Identifier] = Field(default_factory=list, max_length=256)
    resource_cost_upper: dict[Identifier, Rational] = Field(default_factory=dict, max_length=10_000)
    time_upper: Rational
    monetary_cost_upper: Rational
    verification_load_upper: Rational
    independence_erosion_upper: Rational


class InterventionPortfolioSpec(StrictModel):
    analysis_snapshot_digest: Digest
    status: ProfileStatus
    blocker_frontier: list[Identifier] = Field(default_factory=list, max_length=10_000)
    candidates: list[InterventionCandidate] = Field(default_factory=list, max_length=64)
    solution_class: Literal["exact", "bounded", "incomplete"]


class InterventionPortfolio(Document):
    kind: Literal["intervention-portfolio"] = "intervention-portfolio"
    spec: InterventionPortfolioSpec


class BranchEffect(StrictModel):
    outcome: OutcomeName
    must_add: list[Digest] = Field(default_factory=list, max_length=10_000)
    may_add: list[Digest] = Field(default_factory=list, max_length=10_000)
    must_remove: list[Digest] = Field(default_factory=list, max_length=10_000)
    may_remove: list[Digest] = Field(default_factory=list, max_length=10_000)
    resource_delta_lower: dict[Identifier, Rational] = Field(
        default_factory=dict, max_length=10_000
    )
    resource_delta_upper: dict[Identifier, Rational] = Field(
        default_factory=dict, max_length=10_000
    )
    guaranteed_evidence_routes: list[Identifier] = Field(default_factory=list, max_length=256)
    resolves_blockers: list[Identifier] = Field(default_factory=list, max_length=256)
    debt: list[Identifier] = Field(default_factory=list, max_length=256)
    rollback_obligations: list[Identifier] = Field(default_factory=list, max_length=256)
    time_upper: Rational = "0"
    cost_upper: Rational = "0"
    quality_lower: Rational = "0"
    verification_load_upper: Rational = "0"

    @model_validator(mode="after")
    def interval_integrity(self) -> BranchEffect:
        from fractions import Fraction

        if set(self.resource_delta_lower) != set(self.resource_delta_upper):
            raise ValueError("resource interval coordinate domains must match")
        for coordinate, lower in self.resource_delta_lower.items():
            if Fraction(lower) > Fraction(self.resource_delta_upper[coordinate]):
                raise ValueError("resource interval lower bound exceeds upper bound")
        if Fraction(self.time_upper) < 0:
            raise ValueError("time upper bound must be nonnegative")
        if Fraction(self.cost_upper) < 0:
            raise ValueError("cost upper bound must be nonnegative")
        if Fraction(self.verification_load_upper) < 0:
            raise ValueError("verification load upper bound must be nonnegative")
        return self


class CapabilitySpec(StrictModel):
    capability_id: Identifier
    adapter_principal_id: Identifier
    verifier_principal_id: Identifier
    image_digest: Digest
    material_digests: list[Digest] = Field(default_factory=list, max_length=1024)
    output_schema_name: Identifier
    output_schema_digest: Digest
    repeatable: bool
    progress_measure: Identifier | None = None
    branches: list[BranchEffect] = Field(min_length=4, max_length=4)

    @model_validator(mode="after")
    def four_outcomes(self) -> CapabilitySpec:
        values = {branch.outcome for branch in self.branches}
        if values != {"success", "partial", "failure", "timeout"}:
            raise ValueError("capability must define exactly four distinct outcomes")
        if self.adapter_principal_id == self.verifier_principal_id:
            raise ValueError("capability verifier must be independent from adapter principal")
        if self.repeatable and self.progress_measure is None:
            raise ValueError("repeatable capability requires a progress measure")
        return self


class CapabilityDocument(Document):
    kind: Literal["adapter-capability"] = "adapter-capability"
    spec: CapabilitySpec


class ActionSpec(StrictModel):
    action_id: Identifier
    capability_digest: Digest
    required_object_digests: list[Digest] = Field(default_factory=list, max_length=10_000)
    prohibited_hazards: list[Identifier] = Field(default_factory=list, max_length=256)
    protected_object_digests: list[Digest] = Field(default_factory=list, max_length=10_000)


class ActionDocument(Document):
    kind: Literal["action"] = "action"
    spec: ActionSpec


class PlannerCounterexample(StrictModel):
    action_id: Identifier
    outcome: OutcomeName
    reason: Identifier


class PlannerResultSpec(StrictModel):
    analysis_snapshot_digest: Digest
    control_state_digest: Digest
    horizon: Annotated[int, Field(ge=1, le=3)]
    status: Literal["ok", "blocked", "unknown", "error"]
    code: Identifier
    solution_class: Literal["exact", "approximate", "incomplete", "none"]
    primary_action_id: Identifier | None = None
    alternative_action_ids: list[Identifier] = Field(default_factory=list, max_length=3)
    blocker_frontier: list[Identifier] = Field(default_factory=list, max_length=10_000)
    counterexamples: list[PlannerCounterexample] = Field(default_factory=list, max_length=256)
    policy_digest: Digest | None = None


class PlannerResult(Document):
    kind: Literal["planner-result"] = "planner-result"
    spec: PlannerResultSpec


class RunnerJobSpec(StrictModel):
    job_id: Identifier
    action_digest: Digest
    capability_digest: Digest
    generation_digest: Digest
    attempt: Annotated[int, Field(ge=1, le=32)]
    lease_id: Identifier
    lease_expires_at: datetime
    input_digests: list[Digest] = Field(default_factory=list, max_length=10_000)
    image_digest: Digest
    timeout_seconds: Annotated[int, Field(ge=1, le=300)]
    stdout_limit: Annotated[int, Field(ge=1, le=4_194_304)]
    stderr_limit: Annotated[int, Field(ge=1, le=4_194_304)]
    network_policy: Literal["runner-attested", "none"]
    filesystem_policy: Literal["runner-attested", "none"]


class RunnerJob(Document):
    kind: Literal["runner-job"] = "runner-job"
    spec: RunnerJobSpec


class RunnerReceiptSpec(StrictModel):
    job_digest: Digest
    job_id: Identifier
    attempt: Annotated[int, Field(ge=1, le=32)]
    lease_id: Identifier
    runner_principal_id: Identifier
    image_digest: Digest
    material_digests: list[Digest] = Field(default_factory=list, max_length=10_000)
    stdout_digest: Digest
    stderr_digest: Digest
    stdout_captured_bytes: Annotated[int, Field(ge=0, le=4_194_304)]
    stderr_captured_bytes: Annotated[int, Field(ge=0, le=4_194_304)]
    stdout_discarded_bytes: Annotated[int, Field(ge=0)]
    stderr_discarded_bytes: Annotated[int, Field(ge=0)]
    return_code: int | None
    timeout: bool
    cleanup_complete: bool
    isolation_profile_digest: Digest | None = None
    output_digests: list[Digest] = Field(default_factory=list, max_length=10_000)
    completed_at: datetime


class RunnerReceipt(Document):
    kind: Literal["runner-receipt"] = "runner-receipt"
    spec: RunnerReceiptSpec


class PendingProjectionSpec(StrictModel):
    projection_id: Identifier
    runner_receipt_digest: Digest
    source_artifact_envelope_digest: Digest
    producer_principal_id: Identifier
    raw_output_digest: Digest
    json_pointer: Annotated[str, StringConstraints(max_length=2048)]
    expected_schema_name: Identifier
    expected_schema_digest: Digest
    projected_digest: Digest
    changes_authoritative_state: bool


class PendingProjection(Document):
    kind: Literal["pending-projection"] = "pending-projection"
    spec: PendingProjectionSpec


class ProjectionApprovalSpec(StrictModel):
    projection_digest: Digest
    producer_principal_id: Identifier
    verifier_principal_id: Identifier
    approved_at: datetime

    @model_validator(mode="after")
    def independent_verifier(self) -> ProjectionApprovalSpec:
        if self.producer_principal_id == self.verifier_principal_id:
            raise ValueError("projection verifier must differ from producer")
        return self


class ProjectionApproval(Document):
    kind: Literal["projection-approval"] = "projection-approval"
    spec: ProjectionApprovalSpec


class LedgerEntry(StrictModel):
    object_digest: Digest
    object_kind: Identifier
    authority_status: Literal["active", "quarantined", "superseded"]
    source_digests: list[Digest] = Field(default_factory=list, max_length=1024)


class WorkspaceGenerationSpec(StrictModel):
    generation_digest: Digest
    prior_generation_digest: Digest | None = None
    sequence: Annotated[int, Field(ge=0)]
    analysis_snapshot_digest: Digest | None = None
    ledger: list[LedgerEntry] = Field(max_length=100_000)
    history_head_digest: Digest


class WorkspaceGeneration(Document):
    kind: Literal["workspace-generation"] = "workspace-generation"
    spec: WorkspaceGenerationSpec


class AuditEventSpec(StrictModel):
    event_id: Identifier
    event_type: Literal[
        "workspace_created",
        "legacy_imported",
        "object_imported",
        "analysis_completed",
        "job_dispatched",
        "runner_receipt_imported",
        "projection_promoted",
        "coordination_advanced",
        "trial_imported",
        "quarantine_changed",
    ]
    prior_event_digest: Digest | None = None
    subject_digests: list[Digest] = Field(default_factory=list, max_length=10_000)
    occurred_at: datetime


class AuditEvent(Document):
    kind: Literal["audit-event"] = "audit-event"
    spec: AuditEventSpec


class CoordinationPlanSpec(StrictModel):
    session_id: Identifier
    participant_principals: list[Identifier] = Field(min_length=2, max_length=256)
    verifier_principals: list[Identifier] = Field(min_length=1, max_length=256)
    commit_deadline: datetime
    reveal_deadline: datetime
    termination_deadline: datetime
    maximum_exposures: Annotated[int, Field(ge=0, le=100_000)]


class CoordinationPlan(Document):
    kind: Literal["coordination-plan"] = "coordination-plan"
    spec: CoordinationPlanSpec


class CoordinationEventSpec(StrictModel):
    session_id: Identifier
    event_id: Identifier
    event_type: Literal[
        "open_commit",
        "commit",
        "close_commit",
        "open_reveal",
        "reveal",
        "exposure",
        "verification",
        "integration",
        "terminate",
    ]
    actor_principal_id: Identifier
    occurred_at: datetime
    artifact_digest: Digest | None = None
    commitment_digest: Digest | None = None
    prior_event_digest: Digest | None = None


class CoordinationEventDocument(Document):
    kind: Literal["coordination-event"] = "coordination-event"
    spec: CoordinationEventSpec


class CoordinationSessionSpec(StrictModel):
    session_id: Identifier
    plan_digest: Digest
    state: Literal[
        "CREATED",
        "COMMIT_OPEN",
        "COMMIT_CLOSED",
        "REVEAL_OPEN",
        "VERIFY",
        "INTEGRATE",
        "TERMINATED",
    ]
    event_digests: list[Digest] = Field(default_factory=list, max_length=100_000)
    evaluated_at: datetime
    integrity: DimensionResult


class CoordinationSession(Document):
    kind: Literal["coordination-session"] = "coordination-session"
    spec: CoordinationSessionSpec


class ArtifactRecordSpec(StrictModel):
    artifact_type: Literal["dataset", "assignment", "analysis-executable"]
    artifact_digest: Digest
    acquisition_committed_at: datetime
    source_system: Identifier


class ArtifactRecord(Document):
    kind: Literal["trial-artifact-record"] = "trial-artifact-record"
    spec: ArtifactRecordSpec


class OutcomeDefinition(StrictModel):
    outcome_id: Identifier
    unit: UnitName
    direction: Literal["higher", "lower"]
    minimum_effect: Rational
    quality_floor: Rational


class MeasurementProtocolSpec(StrictModel):
    protocol_id: Identifier
    author_principal_id: Identifier
    registrar_principal_id: Identifier
    evaluator_principal_id: Identifier
    quality_verifier_principal_id: Identifier
    eligibility: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    treatment_strategy: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    comparison_strategy: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    time_zero: datetime
    observation_complete_at: datetime
    estimand: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    outcomes: list[OutcomeDefinition] = Field(min_length=1, max_length=64)
    multiplicity_policy: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    assignment_record_digest: Digest
    dataset_record_digest: Digest
    analysis_executable_record_digest: Digest
    missing_data_policy: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    stopping_rule: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    exclusion_policy: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    primary_result_id: Identifier

    @model_validator(mode="after")
    def protocol_integrity(self) -> MeasurementProtocolSpec:
        outcome_ids = [item.outcome_id for item in self.outcomes]
        if len(outcome_ids) != len(set(outcome_ids)):
            raise ValueError("protocol outcome identifiers must be unique")
        if self.author_principal_id == self.registrar_principal_id:
            raise ValueError("protocol author and registrar must be distinct")
        if self.evaluator_principal_id == self.quality_verifier_principal_id:
            raise ValueError("evaluator and quality verifier must be distinct")
        if self.observation_complete_at <= self.time_zero:
            raise ValueError("observation completion must follow time zero")
        return self


class MeasurementProtocol(Document):
    kind: Literal["measurement-protocol"] = "measurement-protocol"
    spec: MeasurementProtocolSpec


class ProtocolAmendmentSpec(StrictModel):
    protocol_digest: Digest
    prior_amendment_digest: Digest | None = None
    sequence: Annotated[int, Field(ge=1)]
    amended_at: datetime
    changes: list[Identifier] = Field(min_length=1, max_length=64)

    @field_validator("changes")
    @classmethod
    def unique_changes(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("amendment changes must be unique")
        return value


class ProtocolAmendment(Document):
    kind: Literal["protocol-amendment"] = "protocol-amendment"
    spec: ProtocolAmendmentSpec


class EffectInterval(StrictModel):
    outcome_id: Identifier
    lower: Rational
    upper: Rational
    quality_value: Rational


class TrialResultSpec(StrictModel):
    primary_result_id: Identifier
    protocol_digest: Digest
    dataset_record_digest: Digest
    assignment_record_digest: Digest
    analysis_executable_record_digest: Digest
    evaluator_principal_id: Identifier
    observation_completed_at: datetime
    issued_at: datetime
    design: Literal["descriptive", "observational", "quasi-experimental", "randomized"]
    effects: list[EffectInterval] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def result_integrity(self) -> TrialResultSpec:
        outcome_ids = [item.outcome_id for item in self.effects]
        if len(outcome_ids) != len(set(outcome_ids)):
            raise ValueError("trial result outcome identifiers must be unique")
        if self.issued_at <= self.observation_completed_at:
            raise ValueError("trial result issuance must follow observation completion")
        return self


class TrialResult(Document):
    kind: Literal["trial-result"] = "trial-result"
    spec: TrialResultSpec


class TrialAssessmentSpec(StrictModel):
    protocol_digest: Digest | None = None
    status: Literal[
        "unmeasured",
        "registered_not_observed",
        "externally_observed_inconclusive",
        "descriptive_observation",
        "observational_association_compatible",
        "quasi_experimental_compatible",
        "preregistered_randomized_acceleration_bundle_compatible",
        "external_quality_or_safety_contradiction",
        "protocol_deviation",
    ]
    tier: Literal[
        "unmeasured",
        "descriptive_observation",
        "observational_association_compatible",
        "quasi_experimental_compatible",
        "preregistered_randomized_acceleration_bundle_compatible",
    ]
    blocker_codes: list[Identifier] = Field(default_factory=list, max_length=10_000)
    contradiction_codes: list[Identifier] = Field(default_factory=list, max_length=10_000)
    result_digests: list[Digest] = Field(default_factory=list, max_length=10_000)
    statistical_method_certified: Literal[False] = False
    causality_certified: Literal[False] = False


class TrialAssessmentDocument(Document):
    kind: Literal["trial-assessment"] = "trial-assessment"
    spec: TrialAssessmentSpec


class RepairRecordSpec(StrictModel):
    repair_id: Identifier
    blocker_code: Identifier
    status: Literal["open", "unbound", "resolved", "superseded"]
    effect_class: Literal["inspect", "local_write", "remote_write", "execute", "none"]
    required_authority: list[Identifier] = Field(default_factory=list, max_length=32)
    required_document_kinds: list[Identifier] = Field(default_factory=list, max_length=64)
    action_digest: Digest | None = None
    next_safe_commands: list[
        list[Annotated[str, StringConstraints(min_length=1, max_length=2048)]]
    ] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def executable_repairs_are_bound(self) -> RepairRecordSpec:
        if self.effect_class == "execute" and self.action_digest is None:
            raise ValueError("executable repair requires a bound action digest")
        if self.status == "unbound" and self.action_digest is not None:
            raise ValueError("unbound repair cannot reference an action")
        return self


class RepairRecord(Document):
    kind: Literal["repair-record"] = "repair-record"
    spec: RepairRecordSpec


type DocumentType = (
    UnitRegistryDocument
    | PhaseContract
    | StateAttestation
    | ResourceObservationAttestation
    | SupplyAttestation
    | TransformationAttestation
    | AuthorityAttestation
    | EvidenceAttestation
    | SourceArtifactEnvelope
    | VerifierStageAttestation
    | RateObservationAttestation
    | ServiceCurveAttestation
    | IndependenceAttestation
    | ExposureLedgerDocument
    | TrustPolicyDocument
    | TrustedTimeReceipt
    | SignedStatement
    | QuorumDecisionDocument
    | OrganizationWitness
    | PersistencePlan
    | AnalysisSnapshot
    | OperationalProfileResult
    | PerturbationSuite
    | PerturbationResult
    | SiphonAnalysisResult
    | FluxCouplingResult
    | CutSetAnalysisResult
    | OccurrencePrefixResult
    | InterventionPortfolio
    | CapabilityDocument
    | ActionDocument
    | PlannerResult
    | RunnerJob
    | RunnerReceipt
    | PendingProjection
    | ProjectionApproval
    | WorkspaceGeneration
    | AuditEvent
    | CoordinationPlan
    | CoordinationEventDocument
    | CoordinationSession
    | ArtifactRecord
    | MeasurementProtocol
    | ProtocolAmendment
    | TrialResult
    | TrialAssessmentDocument
    | RepairRecord
)

DOCUMENT_MODELS: dict[str, type[Document]] = {
    model.model_fields["kind"].default: model
    for model in (
        UnitRegistryDocument,
        PhaseContract,
        StateAttestation,
        ResourceObservationAttestation,
        SupplyAttestation,
        TransformationAttestation,
        AuthorityAttestation,
        EvidenceAttestation,
        SourceArtifactEnvelope,
        VerifierStageAttestation,
        RateObservationAttestation,
        ServiceCurveAttestation,
        IndependenceAttestation,
        ExposureLedgerDocument,
        TrustPolicyDocument,
        TrustedTimeReceipt,
        SignedStatement,
        QuorumDecisionDocument,
        OrganizationWitness,
        PersistencePlan,
        AnalysisSnapshot,
        OperationalProfileResult,
        PerturbationSuite,
        PerturbationResult,
        SiphonAnalysisResult,
        FluxCouplingResult,
        CutSetAnalysisResult,
        OccurrencePrefixResult,
        InterventionPortfolio,
        CapabilityDocument,
        ActionDocument,
        PlannerResult,
        RunnerJob,
        RunnerReceipt,
        PendingProjection,
        ProjectionApproval,
        WorkspaceGeneration,
        AuditEvent,
        CoordinationPlan,
        CoordinationEventDocument,
        CoordinationSession,
        ArtifactRecord,
        MeasurementProtocol,
        ProtocolAmendment,
        TrialResult,
        TrialAssessmentDocument,
        RepairRecord,
    )
}

MANDATORY_DIMENSIONS: Final[tuple[str, ...]] = (
    "provenance_integrity",
    "trust_quorum",
    "temporal_integrity",
    "structural_reachability",
    "causal_formation",
    "dimensional_consistency",
    "exact_self_maintenance",
    "finite_horizon_resource_persistence",
    "target_bound_generative_catalysis",
    "verification_capacity",
    "effective_independence",
    "coordination_protocol_integrity",
    "perturbation_robustness",
)
