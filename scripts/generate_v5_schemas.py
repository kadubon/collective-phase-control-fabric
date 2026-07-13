# SPDX-License-Identifier: Apache-2.0
"""Generate the closed CPCF v0.5 schema surface from v0.4 plus native overrides."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "schemas" / "v0.4.0"
TARGET = ROOT / "schemas" / "v0.5.0"
DIGEST = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
ID = {"type": "string", "minLength": 1, "maxLength": 256}
RATIONAL = {"type": "string", "pattern": "^-?(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?$"}
EXTENSIONS = {
    "type": "object",
    "maxProperties": 256,
    "additionalProperties": {},
    "propertyNames": {
        "pattern": ("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")
    },
    "unevaluatedProperties": False,
}


def closed(properties: dict[str, Any], required: list[str], **extra: Any) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {**properties, "extensions": deepcopy(EXTENSIONS)},
        "required": required,
        "unevaluatedProperties": False,
        **extra,
    }


def document(name: str, title: str, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://example.org/cpcf/schemas/v0.5.0/{name}.schema.json",
        "title": title,
        **body,
    }


def write(name: str, schema: dict[str, Any]) -> None:
    schema = close_object_nodes(schema)
    (TARGET / f"{name}.schema.json").write_text(
        json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def replace_version(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("v0.4.0", "v0.5.0").replace("0.4.0", "0.5.0").replace("v0.4", "v0.5")
    if isinstance(value, list):
        return [replace_version(item) for item in value]
    if isinstance(value, dict):
        return {key: replace_version(item) for key, item in value.items()}
    return value


def close_object_nodes(value: Any) -> Any:
    """Fail closed for every schema node that describes an object."""

    if isinstance(value, list):
        return [close_object_nodes(item) for item in value]
    if isinstance(value, dict):
        result = {key: close_object_nodes(item) for key, item in value.items()}
        if result.get("type") == "object":
            result.setdefault("unevaluatedProperties", False)
        return result
    return value


def main() -> None:
    TARGET.mkdir(parents=True, exist_ok=True)
    for path in SOURCE.glob("*.schema.json"):
        write(
            path.name.removesuffix(".schema.json"),
            close_object_nodes(replace_version(json.loads(path.read_text()))),
        )

    signed = json.loads((TARGET / "signed-statement.schema.json").read_text())
    protected = signed["properties"]["protected"]
    protected["properties"].update(
        {
            "canonicalization_profile": {"const": "RFC8785-CPCF-FLOAT-FREE-1"},
            "schema_digest": DIGEST,
            "principal_id": ID,
        }
    )
    protected["required"] = [
        "domain",
        "cpcf_version",
        "canonicalization_profile",
        "schema_ref",
        "schema_digest",
        "key_id",
        "principal_id",
        "signed_at",
        "payload_digest",
        "role",
        "source_system",
        "scope",
    ]
    write("signed-statement", signed)

    attestation = json.loads((TARGET / "principal-attestation.schema.json").read_text())
    attributes = attestation["$defs"]["attributes"]["properties"]
    attributes["evidence_type"]["enum"].extend(
        ["adapter_capability", "typed_flow_profile", "projection_authorization"]
    )
    attributes.update(
        {
            "capability_ref": ID,
            "action_id": ID,
            "operation": ID,
            "material_digests": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": DIGEST,
            },
            "output_schema_digest": DIGEST,
            "exit_code_mapping": {
                "type": "object",
                "maxProperties": 32,
                "additionalProperties": {"enum": ["success", "partial", "failure", "timeout"]},
            },
            "progress_measure": {"type": "string", "maxLength": 256},
            "projection_routes": {
                "type": "array",
                "maxItems": 1024,
                "items": {
                    "type": "object",
                    "properties": {
                        "source_pointer": {"type": "string", "maxLength": 4096},
                        "target_schema_ref": ID,
                        "guaranteed_subject_ids": {
                            "type": "array",
                            "maxItems": 1024,
                            "uniqueItems": True,
                            "items": ID,
                        },
                    },
                    "required": [
                        "source_pointer",
                        "target_schema_ref",
                        "guaranteed_subject_ids",
                    ],
                    "unevaluatedProperties": False,
                },
            },
        }
    )
    write("principal-attestation", attestation)

    adapter_output = document(
        "adapter-output",
        "CPCF Bounded Local Adapter Output v0.5",
        closed(
            {
                "schema_version": {"const": "0.5.0"},
                "outcome": {"enum": ["success", "partial", "failure", "timeout"]},
                "projections": {
                    "type": "array",
                    "maxItems": 1024,
                    "items": {},
                },
            },
            ["schema_version", "outcome", "projections"],
        ),
    )
    write("adapter-output", adapter_output)

    policy = json.loads((TARGET / "trust-policy.schema.json").read_text())
    principal = policy["properties"]["principals"]["items"]
    principal["properties"].update(
        {
            "infrastructure_domains": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "uniqueItems": True,
                "items": ID,
            },
            "correlation_domains": {
                "type": "array",
                "maxItems": 64,
                "uniqueItems": True,
                "items": ID,
            },
            "revoked_at": {"oneOf": [{"type": "string", "format": "date-time"}, {"type": "null"}]},
            "compromised_at": {
                "oneOf": [{"type": "string", "format": "date-time"}, {"type": "null"}]
            },
        }
    )
    principal["required"].extend(
        ["infrastructure_domains", "correlation_domains", "revoked_at", "compromised_at"]
    )
    policy["properties"]["quorum_rules"] = {
        "type": "object",
        "properties": {
            name: {
                "type": "array",
                "minItems": len(roles),
                "maxItems": len(roles),
                "uniqueItems": True,
                "prefixItems": [{"const": role} for role in roles],
                "items": False,
            }
            for name, roles in {
                "trust_update": ["workspace_root", "trust_auditor", "timestamp"],
                "protocol_registration": ["protocol_author", "registration", "timestamp"],
                "acceleration_compatibility": ["evaluator", "quality_safety_verifier", "timestamp"],
                "projection_promotion": ["projection_authority", "projection_verifier"],
            }.items()
        },
        "required": [
            "trust_update",
            "protocol_registration",
            "acceleration_compatibility",
            "projection_promotion",
        ],
        "unevaluatedProperties": False,
    }
    policy["required"].append("quorum_rules")
    write("trust-policy", policy)

    dimensions = [
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
    ]
    contract = json.loads((TARGET / "phase-contract.schema.json").read_text())
    contract["properties"]["required_dimensions"]["items"] = {"enum": dimensions}
    contract["properties"]["required_dimensions"]["minItems"] = len(dimensions)
    contract["properties"]["unit_registry_ref"] = DIGEST
    contract["properties"]["minimum_effective_independence"] = {
        "type": "integer",
        "minimum": 2,
        "maximum": 4096,
    }
    contract["required"].extend(["unit_registry_ref", "minimum_effective_independence"])
    write("phase-contract", contract)

    protocol = json.loads((TARGET / "measurement-protocol.schema.json").read_text())
    protocol["properties"].update(
        {
            "design_tier": {
                "enum": ["descriptive", "observational", "quasi_experimental", "randomized"]
            },
            "primary_outcomes": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "uniqueItems": True,
                "items": closed(
                    {
                        "outcome_id": ID,
                        "direction": {"enum": ["increase", "decrease"]},
                        "unit": ID,
                        "minimum_effect": RATIONAL,
                        "multiplicity_group": ID,
                    },
                    ["outcome_id", "direction", "unit", "minimum_effect", "multiplicity_group"],
                ),
            },
            "eligibility": closed(
                {
                    "population_ref": ID,
                    "inclusion_rules": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 256,
                        "items": ID,
                    },
                    "exclusion_rules": {"type": "array", "maxItems": 256, "items": ID},
                },
                ["population_ref", "inclusion_rules", "exclusion_rules"],
            ),
            "treatment_strategy": closed({"strategy_id": ID}, ["strategy_id"]),
            "comparison_strategy": closed({"strategy_id": ID}, ["strategy_id"]),
            "assignment": closed(
                {
                    "method": {"enum": ["randomized", "as_if_random", "observed", "none"]},
                    "assignment_unit": ID,
                    "specification_digest": DIGEST,
                },
                ["method", "assignment_unit", "specification_digest"],
            ),
            "estimand": closed(
                {"population": ID, "contrast": ID, "summary_measure": ID},
                ["population", "contrast", "summary_measure"],
            ),
            "multiplicity_policy": closed(
                {"method": ID, "family_count": {"type": "integer", "minimum": 1, "maximum": 64}},
                ["method", "family_count"],
            ),
            "quality_floors": {
                "type": "object",
                "maxProperties": 64,
                "additionalProperties": closed(
                    {"quantity": RATIONAL, "unit": ID}, ["quantity", "unit"]
                ),
                "unevaluatedProperties": False,
            },
            "safety_floors": {
                "type": "object",
                "maxProperties": 64,
                "additionalProperties": closed(
                    {"quantity": RATIONAL, "unit": ID}, ["quantity", "unit"]
                ),
                "unevaluatedProperties": False,
            },
        }
    )
    protocol["required"].extend(["design_tier", "multiplicity_policy"])
    write("measurement-protocol", protocol)

    registration = json.loads((TARGET / "registration-receipt.schema.json").read_text())
    registration["properties"]["trusted_time_receipt_digest"] = DIGEST
    registration["required"].append("trusted_time_receipt_digest")
    write("registration-receipt", registration)

    result = json.loads((TARGET / "trial-result-certificate.schema.json").read_text())
    result["properties"]["effect_intervals"]["additionalProperties"]["properties"][
        "estimand_status"
    ] = {"enum": ["supported", "inconclusive", "contradicted"]}
    result["properties"]["effect_intervals"]["additionalProperties"]["required"].append(
        "estimand_status"
    )
    interval = closed(
        {"lower": RATIONAL, "upper": RATIONAL, "unit": ID},
        ["lower", "upper", "unit"],
    )
    result["properties"]["quality_intervals"] = {
        "type": "object",
        "maxProperties": 64,
        "additionalProperties": interval,
        "unevaluatedProperties": False,
    }
    result["properties"]["safety_intervals"] = {
        "type": "object",
        "maxProperties": 64,
        "additionalProperties": interval,
        "unevaluatedProperties": False,
    }
    write("trial-result-certificate", result)

    process_receipt = json.loads((TARGET / "process-receipt.schema.json").read_text())
    process_receipt["properties"].update(
        {
            "process_group_cleanup": {"enum": ["complete", "best_effort", "incomplete"]},
            "drain_status": {"enum": ["complete", "incomplete"]},
            "timeout_seconds": {"type": "string", "pattern": "^[0-9]+(?:\\.[0-9]+)?$"},
            "stdin_limit": {"type": "integer", "minimum": 0, "maximum": 4194304},
            "stdout_limit": {"type": "integer", "minimum": 0, "maximum": 4194304},
            "stderr_limit": {"type": "integer", "minimum": 0, "maximum": 4194304},
            "material_digests": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": DIGEST,
            },
        }
    )
    process_receipt["required"].extend(
        [
            "process_group_cleanup",
            "drain_status",
            "timeout_seconds",
            "stdin_limit",
            "stdout_limit",
            "stderr_limit",
            "material_digests",
        ]
    )
    write("process-receipt", process_receipt)

    action_receipt = document(
        "action-receipt",
        "CPCF Evidence-Bound Action Receipt v0.5",
        closed(
            {
                "schema_version": {"const": "0.5.0"},
                "receipt_id": ID,
                "action_id": ID,
                "generation_before": DIGEST,
                "analysis_snapshot_digest": DIGEST,
                "capability_statement_digest": DIGEST,
                "process_receipt_digest": DIGEST,
                "raw_output_digest": DIGEST,
                "outcome": {"enum": ["success", "partial", "failure", "timeout"]},
                "pending_projection_digests": {
                    "type": "array",
                    "maxItems": 1024,
                    "uniqueItems": True,
                    "items": DIGEST,
                },
                "state_promoted": {"const": False},
            },
            [
                "schema_version",
                "receipt_id",
                "action_id",
                "generation_before",
                "analysis_snapshot_digest",
                "capability_statement_digest",
                "process_receipt_digest",
                "raw_output_digest",
                "outcome",
                "pending_projection_digests",
                "state_promoted",
            ],
        ),
    )
    write("action-receipt", action_receipt)

    kinds = [
        "contract",
        "genesis-policy-statement",
        "trust-policy",
        "trust-quorum-decision",
        "trusted-time-receipt",
        "unit-registry",
        "typed-flow-profile",
        "raw-artifact",
        "principal-attestation",
        "adapter-capability",
        "execution-policy",
        "process-receipt",
        "action-receipt",
        "pending-projection",
        "projection-approval",
        "promoted-projection",
        "analysis-snapshot",
        "scientific-witness",
        "perturbation-suite",
        "perturbation-result",
        "coordination-plan",
        "coordination-session",
        "coordination-event",
        "measurement-protocol",
        "registration-receipt",
        "protocol-amendment",
        "dataset-record",
        "analysis-executable-record",
        "trial-result-certificate",
        "acceleration-evidence",
        "bundle-root-attestation",
        "legacy-manifest",
    ]
    ledger = json.loads((TARGET / "object-ledger-entry.schema.json").read_text())
    ledger["properties"]["kind"] = {"enum": kinds}
    ledger["properties"]["authority_policy_digest"] = {"oneOf": [DIGEST, {"type": "null"}]}
    ledger["required"].append("authority_policy_digest")
    write("object-ledger-entry", ledger)

    event = document(
        "history-event",
        "CPCF Hash-Chained History Event v0.5",
        closed(
            {
                "event_id": ID,
                "event_type": {
                    "enum": [
                        "workspace_initialized",
                        "legacy_migrated",
                        "object_imported",
                        "trust_updated",
                        "time_advanced",
                        "action_executed",
                        "projection_approved",
                        "coordination_transition",
                        "protocol_imported",
                        "amendment_imported",
                        "trial_result_imported",
                    ]
                },
                "subject_digests": {
                    "type": "array",
                    "maxItems": 1024,
                    "uniqueItems": True,
                    "items": DIGEST,
                },
                "previous_event_digest": {"oneOf": [DIGEST, {"type": "null"}]},
                "event_digest": DIGEST,
            },
            [
                "event_id",
                "event_type",
                "subject_digests",
                "previous_event_digest",
                "event_digest",
            ],
        ),
    )
    write("history-event", event)
    generation = json.loads((TARGET / "workspace-generation.schema.json").read_text())
    generation["properties"]["history"]["items"] = {"$ref": "history-event.schema.json"}
    write("workspace-generation", generation)

    unit = document(
        "unit-registry",
        "CPCF Rational Multiplicative Unit Registry v0.5",
        closed(
            {
                "schema_version": {"const": "0.5.0"},
                "registry_id": ID,
                "base_dimensions": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 64,
                    "uniqueItems": True,
                    "items": ID,
                },
                "units": {
                    "type": "object",
                    "minProperties": 1,
                    "maxProperties": 1024,
                    "additionalProperties": closed(
                        {
                            "scale": RATIONAL,
                            "dimension_vector": {
                                "type": "object",
                                "maxProperties": 64,
                                "additionalProperties": {
                                    "type": "integer",
                                    "minimum": -16,
                                    "maximum": 16,
                                },
                            },
                        },
                        ["scale", "dimension_vector"],
                    ),
                },
            },
            ["schema_version", "registry_id", "base_dimensions", "units"],
        ),
    )
    write("unit-registry", unit)

    typed_flow = document(
        "typed-flow-profile",
        "CPCF Exact Typed Flow Profile v0.5",
        closed(
            {
                "schema_version": {"const": "0.5.0"},
                "profile_id": ID,
                "analysis_snapshot_digest": DIGEST,
                "unit_registry_digest": DIGEST,
                "horizon_steps": {"type": "integer", "minimum": 1, "maximum": 10000},
                "step_duration": RATIONAL,
                "time_unit": ID,
                "coordinates": {
                    "type": "object",
                    "minProperties": 1,
                    "maxProperties": 10000,
                    "additionalProperties": closed(
                        {"unit": ID, "initial": RATIONAL, "protected_floor": RATIONAL},
                        ["unit", "initial", "protected_floor"],
                    ),
                },
                "transformations": {
                    "type": "object",
                    "maxProperties": 10000,
                    "additionalProperties": closed(
                        {
                            "flow": {
                                "type": "object",
                                "maxProperties": 10000,
                                "additionalProperties": RATIONAL,
                            },
                            "action_unit": ID,
                        },
                        ["flow", "action_unit"],
                    ),
                },
                "action_counts": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 10000,
                    "items": {"type": "object", "additionalProperties": RATIONAL},
                },
                "boundary_rates": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 10000,
                    "items": {"type": "object", "additionalProperties": RATIONAL},
                },
                "fed_siphons": {
                    "type": "array",
                    "maxItems": 10000,
                    "items": closed(
                        {
                            "coordinates": {
                                "type": "array",
                                "minItems": 1,
                                "uniqueItems": True,
                                "items": ID,
                            },
                            "coverage": {
                                "enum": ["initially_marked", "boundary_fed", "replenished"]
                            },
                            "source_refs": {
                                "type": "array",
                                "minItems": 1,
                                "uniqueItems": True,
                                "items": ID,
                            },
                        },
                        ["coordinates", "coverage", "source_refs"],
                    ),
                },
            },
            [
                "schema_version",
                "profile_id",
                "analysis_snapshot_digest",
                "unit_registry_digest",
                "horizon_steps",
                "step_duration",
                "time_unit",
                "coordinates",
                "transformations",
                "action_counts",
                "boundary_rates",
                "fed_siphons",
            ],
        ),
    )
    write("typed-flow-profile", typed_flow)

    for name, title, properties, required in [
        (
            "coordination-plan",
            "CPCF Bounded Coordination Plan v0.5",
            {
                "schema_version": {"const": "0.5.0"},
                "plan_id": ID,
                "participant_principals": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 4096,
                    "uniqueItems": True,
                    "items": ID,
                },
                "verifier_stage_refs": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4096,
                    "uniqueItems": True,
                    "items": ID,
                },
                "maximum_exposure_events": {"type": "integer", "minimum": 0, "maximum": 100000},
                "termination_rule": {
                    "enum": ["all_verified", "explicit_failure", "capacity_blocked"]
                },
            },
            [
                "schema_version",
                "plan_id",
                "participant_principals",
                "verifier_stage_refs",
                "maximum_exposure_events",
                "termination_rule",
            ],
        ),
        (
            "proposal-commitment",
            "CPCF Signed Proposal Commitment Payload v0.5",
            {
                "schema_version": {"const": "0.5.0"},
                "commitment_id": ID,
                "session_id": ID,
                "participant_principal_id": ID,
                "commitment_digest": DIGEST,
                "committed_at": {"type": "string", "format": "date-time"},
            },
            [
                "schema_version",
                "commitment_id",
                "session_id",
                "participant_principal_id",
                "commitment_digest",
                "committed_at",
            ],
        ),
        (
            "proposal-reveal",
            "CPCF Signed Proposal Reveal Payload v0.5",
            {
                "schema_version": {"const": "0.5.0"},
                "reveal_id": ID,
                "session_id": ID,
                "participant_principal_id": ID,
                "proposal": {},
                "nonce": {"type": "string", "minLength": 16, "maxLength": 1024},
                "revealed_at": {"type": "string", "format": "date-time"},
            },
            [
                "schema_version",
                "reveal_id",
                "session_id",
                "participant_principal_id",
                "proposal",
                "nonce",
                "revealed_at",
            ],
        ),
        (
            "trust-quorum-decision",
            "CPCF Role-Quorum Decision v0.5",
            {
                "schema_version": {"const": "0.5.0"},
                "decision_id": ID,
                "decision_type": {
                    "enum": [
                        "trust_update",
                        "protocol_registration",
                        "acceleration_compatibility",
                        "projection_promotion",
                    ]
                },
                "subject_digest": DIGEST,
                "policy_sequence": {"type": "integer", "minimum": 0},
                "trusted_time_receipt_digest": DIGEST,
            },
            [
                "schema_version",
                "decision_id",
                "decision_type",
                "subject_digest",
                "policy_sequence",
                "trusted_time_receipt_digest",
            ],
        ),
        (
            "pending-projection",
            "CPCF Pending Projection v0.5",
            {
                "schema_version": {"const": "0.5.0"},
                "projection_id": ID,
                "invocation_digest": DIGEST,
                "capability_statement_digest": DIGEST,
                "raw_output_digest": DIGEST,
                "source_pointer": {"type": "string", "maxLength": 4096},
                "target_schema_ref": ID,
                "projected_digest": DIGEST,
                "analysis_snapshot_digest": DIGEST,
            },
            [
                "schema_version",
                "projection_id",
                "invocation_digest",
                "capability_statement_digest",
                "raw_output_digest",
                "source_pointer",
                "target_schema_ref",
                "projected_digest",
                "analysis_snapshot_digest",
            ],
        ),
        (
            "projection-approval",
            "CPCF Projection Approval Payload v0.5",
            {
                "schema_version": {"const": "0.5.0"},
                "approval_id": ID,
                "projection_digest": DIGEST,
                "decision": {"const": "approve"},
                "trusted_time_receipt_digest": DIGEST,
            },
            [
                "schema_version",
                "approval_id",
                "projection_digest",
                "decision",
                "trusted_time_receipt_digest",
            ],
        ),
        (
            "coordination-session",
            "CPCF Bounded Coordination Session v0.5",
            {
                "schema_version": {"const": "0.5.0"},
                "session_id": ID,
                "state": {
                    "enum": [
                        "CREATED",
                        "COMMIT_OPEN",
                        "COMMIT_CLOSED",
                        "REVEAL_OPEN",
                        "VERIFY",
                        "INTEGRATE",
                        "TERMINATED",
                    ]
                },
                "plan_digest": DIGEST,
                "participant_principals": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 4096,
                    "uniqueItems": True,
                    "items": ID,
                },
                "commitments": {
                    "type": "object",
                    "maxProperties": 4096,
                    "additionalProperties": DIGEST,
                },
                "reveals": {
                    "type": "object",
                    "maxProperties": 4096,
                    "additionalProperties": DIGEST,
                },
                "exposure_event_digests": {
                    "type": "array",
                    "maxItems": 100000,
                    "uniqueItems": True,
                    "items": DIGEST,
                },
                "verification_capacity_satisfied": {"type": "boolean"},
                "termination_reason": {"oneOf": [ID, {"type": "null"}]},
            },
            [
                "schema_version",
                "session_id",
                "state",
                "plan_digest",
                "participant_principals",
                "commitments",
                "reveals",
                "exposure_event_digests",
                "verification_capacity_satisfied",
                "termination_reason",
            ],
        ),
        (
            "protocol-amendment",
            "CPCF Externally Timed Protocol Amendment v0.5",
            {
                "schema_version": {"const": "0.5.0"},
                "amendment_id": ID,
                "protocol_digest": DIGEST,
                "previous_amendment_digest": {"oneOf": [DIGEST, {"type": "null"}]},
                "amended_protocol_digest": DIGEST,
                "effective_at": {"type": "string", "format": "date-time"},
                "trusted_time_receipt_digest": DIGEST,
            },
            [
                "schema_version",
                "amendment_id",
                "protocol_digest",
                "previous_amendment_digest",
                "amended_protocol_digest",
                "effective_at",
                "trusted_time_receipt_digest",
            ],
        ),
        (
            "evidence-tier",
            "CPCF External Evidence Tier v0.5",
            {
                "schema_version": {"const": "0.5.0"},
                "protocol_id": ID,
                "tier": {
                    "enum": [
                        "descriptive_observation",
                        "observational_association_compatible",
                        "quasi_experimental_compatible",
                        "preregistered_randomized_acceleration_bundle_compatible",
                    ]
                },
                "result_digest": DIGEST,
                "quality_safety_status": {"enum": ["preserved", "contradicted", "unknown"]},
            },
            ["schema_version", "protocol_id", "tier", "result_digest", "quality_safety_status"],
        ),
    ]:
        write(name, document(name, title, closed(properties, required)))


if __name__ == "__main__":
    main()
