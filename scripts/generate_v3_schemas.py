# SPDX-License-Identifier: Apache-2.0
"""Generate CPCF v0.3 JSON Schemas from one deterministic definition table."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1] / "schemas" / "v0.3.0"
BASE = "https://example.org/cpcf/schemas/v0.3.0"

Json = dict[str, Any]


def array(item: Json, *, minimum: int = 0, unique: bool = False) -> Json:
    value: Json = {"type": "array", "items": item}
    if minimum:
        value["minItems"] = minimum
    if unique:
        value["uniqueItems"] = True
    return value


def closed(required: list[str], properties: Json, *, title: str) -> Json:
    properties = {
        **properties,
        "signature": SIGNATURE,
        "extensions": EXTENSIONS,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "type": "object",
        "required": required,
        "properties": properties,
        "unevaluatedProperties": False,
    }


STRING = {"type": "string", "minLength": 1, "maxLength": 1024}
ID = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"}
DIGEST = {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"}
TIME = {"type": "string", "format": "date-time"}
RATIONAL = {"type": "string", "pattern": r"^-?(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?$"}
REFS = array(ID, unique=True)
POINTER = {"type": "string", "pattern": r"^(?:/(?:[^~/]|~0|~1)*)*$"}
TRUTH = {"enum": ["true", "false", "unknown", "not_applicable"]}
SCALAR = {"type": ["string", "integer", "boolean", "null"]}
SCOPE = {"type": "object", "additionalProperties": SCALAR}
QUANTITY = {
    "type": "object",
    "required": ["quantity", "unit"],
    "properties": {"quantity": RATIONAL, "unit": STRING},
    "additionalProperties": False,
}
SIGNATURE = {
    "type": "object",
    "required": ["key_id", "signature_base64", "signed_at", "payload_digest"],
    "properties": {
        "key_id": ID,
        "signature_base64": STRING,
        "signed_at": TIME,
        "payload_digest": DIGEST,
    },
    "additionalProperties": False,
}
EXTENSIONS = {
    "type": "object",
    "propertyNames": {
        "pattern": r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$"
    },
    "additionalProperties": True,
}


def versioned(properties: Json) -> Json:
    return {"schema_version": {"const": "0.3.0"}, **properties}


def schemas() -> dict[str, Json]:
    quantity_map = {"type": "object", "additionalProperties": QUANTITY}
    ref_map = {"type": "object", "additionalProperties": REFS}
    branch = {
        "type": "object",
        "required": [
            "must_add",
            "may_add",
            "must_remove",
            "may_remove",
            "resource_intervals",
            "debt",
            "rollback_obligations",
            "projection_possibilities",
        ],
        "properties": {
            "must_add": REFS,
            "may_add": REFS,
            "must_remove": REFS,
            "may_remove": REFS,
            "resource_intervals": {
                "type": "object",
                "additionalProperties": {
                    "type": "object",
                    "required": ["lower", "upper", "unit"],
                    "properties": {"lower": RATIONAL, "upper": RATIONAL, "unit": STRING},
                    "additionalProperties": False,
                },
            },
            "debt": REFS,
            "rollback_obligations": REFS,
            "projection_possibilities": array(
                {
                    "type": "object",
                    "required": ["source_pointer", "target_schema"],
                    "properties": {"source_pointer": POINTER, "target_schema": STRING},
                    "additionalProperties": False,
                },
                unique=True,
            ),
        },
        "additionalProperties": False,
    }
    principal = {
        "type": "object",
        "required": [
            "key_id",
            "public_key_base64",
            "source_systems",
            "schema_names",
            "roles",
            "scope",
            "not_before",
            "not_after",
            "revoked",
        ],
        "properties": {
            "key_id": ID,
            "public_key_base64": STRING,
            "source_systems": array(STRING, minimum=1, unique=True),
            "schema_names": array(STRING, minimum=1, unique=True),
            "roles": array(STRING, minimum=1, unique=True),
            "scope": SCOPE,
            "not_before": TIME,
            "not_after": TIME,
            "revoked": {"type": "boolean"},
        },
        "additionalProperties": False,
    }
    node = {
        "type": "object",
        "required": ["node_id", "type", "lifecycle", "source_ref", "principal_key_id"],
        "properties": {
            "node_id": ID,
            "type": STRING,
            "lifecycle": {"enum": ["active", "expired", "revoked", "withdrawn"]},
            "source_ref": ID,
            "principal_key_id": ID,
            "available": {"type": "boolean"},
            "expires_at": TIME,
            "coordinates": quantity_map,
            "independence_domain": ID,
            "infrastructure_domain": ID,
            "correlation_group": ID,
            "lineage": REFS,
            "verifier_role": STRING,
            "extensions": EXTENSIONS,
        },
        "additionalProperties": False,
    }
    transformation = {
        "type": "object",
        "required": [
            "transformation_id",
            "required_inputs",
            "produced_outputs",
            "required_evidence",
            "required_authority_refs",
            "catalyst_clauses",
            "inhibitors",
            "coordinate_flows",
            "source_ref",
        ],
        "properties": {
            "transformation_id": ID,
            "required_inputs": REFS,
            "read_enablers": REFS,
            "produced_outputs": REFS,
            "required_evidence": REFS,
            "required_authority_refs": REFS,
            "required_hazard_refs": REFS,
            "support_refs": REFS,
            "verifier_refs": REFS,
            "catalyst_clauses": array(REFS),
            "explicitly_uncatalyzed": {"type": "boolean"},
            "inhibitors": REFS,
            "coordinate_flows": quantity_map,
            "boundary_supply_refs": REFS,
            "source_ref": ID,
            "extensions": EXTENSIONS,
        },
        "additionalProperties": False,
    }
    stage = {
        "type": "object",
        "required": [
            "stage_id",
            "arrival_lower",
            "arrival_upper",
            "service_lower",
            "service_upper",
            "backlog",
            "independence_domain",
            "source_refs",
        ],
        "properties": {
            "stage_id": ID,
            "arrival_lower": RATIONAL,
            "arrival_upper": RATIONAL,
            "service_lower": RATIONAL,
            "service_upper": RATIONAL,
            "backlog": RATIONAL,
            "independence_domain": ID,
            "source_refs": REFS,
        },
        "additionalProperties": False,
    }
    interval = {
        "type": "object",
        "required": ["metric", "direction", "lower", "upper", "unit"],
        "properties": {
            "metric": ID,
            "direction": {"enum": ["minimize", "maximize"]},
            "lower": RATIONAL,
            "upper": RATIONAL,
            "unit": STRING,
        },
        "additionalProperties": False,
    }
    return {
        "adapter-output": closed(
            ["schema_version", "action_id", "outcome"],
            versioned(
                {
                    "action_id": ID,
                    "outcome": {"enum": ["success", "partial", "failure", "timeout"]},
                    "message": STRING,
                    "observation": {
                        "type": "object",
                        "required": ["schema_version", "observation_id", "value", "source_refs"],
                        "properties": {
                            "schema_version": {"const": "0.3.0"},
                            "observation_id": ID,
                            "value": STRING,
                            "source_refs": REFS,
                        },
                        "additionalProperties": False,
                    },
                }
            ),
            title="CPCF Bounded Adapter Output v0.3",
        ),
        "adapter-observation": closed(
            ["schema_version", "observation_id", "value", "source_refs"],
            versioned({"observation_id": ID, "value": STRING, "source_refs": REFS}),
            title="CPCF Adapter Observation v0.3",
        ),
        "contract-draft": closed(
            ["schema_version", "draft_id", "profile", "missing_decisions"],
            versioned(
                {
                    "draft_id": ID,
                    "profile": {"enum": ["structural", "measured"]},
                    "missing_decisions": array(STRING, minimum=1, unique=True),
                    "candidate_contract": {"type": "object"},
                }
            ),
            title="CPCF Contract Draft v0.3",
        ),
        "phase-contract": closed(
            [
                "schema_version",
                "contract_id",
                "phase_label",
                "scope",
                "evaluation_time",
                "target_states",
                "initial_available_states",
                "state_coordinate_registry",
                "protected_floors",
                "resource_envelope",
                "control_policy",
                "formation_policy",
                "support_core_policy",
                "rate_policy",
                "analysis_limits",
                "non_claims",
            ],
            versioned(
                {
                    "contract_id": ID,
                    "phase_label": STRING,
                    "scope": SCOPE,
                    "evaluation_time": TIME,
                    "target_states": array(ID, minimum=1, unique=True),
                    "initial_available_states": REFS,
                    "state_coordinate_registry": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "required": ["unit", "proxy_only"],
                            "properties": {"unit": STRING, "proxy_only": {"type": "boolean"}},
                            "additionalProperties": False,
                        },
                    },
                    "unit_registry": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "required": ["canonical_unit", "factor"],
                            "properties": {"canonical_unit": STRING, "factor": RATIONAL},
                            "additionalProperties": False,
                        },
                    },
                    "protected_floors": quantity_map,
                    "resource_envelope": quantity_map,
                    "control_policy": {
                        "type": "object",
                        "required": [
                            "planning_horizon",
                            "beam_width",
                            "candidate_cap",
                            "retry_limit",
                        ],
                        "properties": {
                            "planning_horizon": {"type": "integer", "minimum": 1, "maximum": 3},
                            "beam_width": {"type": "integer", "minimum": 1, "maximum": 32},
                            "candidate_cap": {"type": "integer", "minimum": 1, "maximum": 64},
                            "retry_limit": {"type": "integer", "minimum": 0, "maximum": 16},
                        },
                        "additionalProperties": False,
                    },
                    "formation_policy": {
                        "type": "object",
                        "required": ["maximum_layer_count"],
                        "properties": {"maximum_layer_count": {"type": "integer", "minimum": 1}},
                        "additionalProperties": False,
                    },
                    "support_core_policy": {
                        "type": "object",
                        "required": [
                            "minimum_support_domains",
                            "minimum_verifier_domains",
                            "perturbation_suite_refs",
                        ],
                        "properties": {
                            "minimum_support_domains": {"type": "integer", "minimum": 1},
                            "minimum_verifier_domains": {"type": "integer", "minimum": 1},
                            "perturbation_suite_refs": REFS,
                        },
                        "additionalProperties": False,
                    },
                    "rate_policy": {
                        "type": "object",
                        "required": ["levels_requiring_evidence"],
                        "properties": {
                            "levels_requiring_evidence": array(
                                {"enum": ["L3", "L4", "L5"]}, unique=True
                            )
                        },
                        "additionalProperties": False,
                    },
                    "analysis_limits": {
                        "type": "object",
                        "required": [
                            "maximum_raw_bytes",
                            "maximum_json_depth",
                            "maximum_nodes",
                            "maximum_transformations",
                            "maximum_rational_bits",
                            "maximum_siphon_species",
                        ],
                        "properties": {
                            key: {"type": "integer", "minimum": 1}
                            for key in (
                                "maximum_raw_bytes",
                                "maximum_json_depth",
                                "maximum_nodes",
                                "maximum_transformations",
                                "maximum_rational_bits",
                                "maximum_siphon_species",
                            )
                        },
                        "additionalProperties": False,
                    },
                    "measurement_protocol_refs": REFS,
                    "collective_policy": {"type": "object", "additionalProperties": SCALAR},
                    "termination_policy": {"type": "object", "additionalProperties": SCALAR},
                    "non_claims": array(STRING, minimum=1, unique=True),
                }
            ),
            title="CPCF Phase Contract v0.3",
        ),
        "trust-policy": closed(
            ["schema_version", "policy_id", "principals"],
            versioned({"policy_id": ID, "principals": array(principal, minimum=1)}),
            title="CPCF Pinned-Key Trust Policy v0.3",
        ),
        "workspace-generation": closed(
            [
                "schema_version",
                "generation_id",
                "previous_generation",
                "contract_digest",
                "trust_policy_digest",
                "analysis_epoch",
                "raw_artifacts",
                "envelopes",
                "receipts",
                "projections",
                "history",
                "quarantine",
            ],
            versioned(
                {
                    "generation_id": DIGEST,
                    "previous_generation": {"oneOf": [DIGEST, {"type": "null"}]},
                    "contract_digest": DIGEST,
                    "trust_policy_digest": DIGEST,
                    "analysis_epoch": TIME,
                    "raw_artifacts": array(DIGEST, unique=True),
                    "envelopes": array(DIGEST, unique=True),
                    "receipts": array(DIGEST, unique=True),
                    "projections": array(
                        {
                            "type": "object",
                            "required": [
                                "object_digest",
                                "schema_ref",
                                "receipt_digest",
                                "source_pointer",
                            ],
                            "properties": {
                                "object_digest": DIGEST,
                                "schema_ref": STRING,
                                "receipt_digest": DIGEST,
                                "source_pointer": POINTER,
                            },
                            "additionalProperties": False,
                        },
                        unique=True,
                    ),
                    "history": array({"type": "object"}),
                    "quarantine": array({"type": "object"}),
                }
            ),
            title="CPCF Immutable Workspace Generation v0.3",
        ),
        "source-artifact-envelope": closed(
            [
                "schema_version",
                "envelope_id",
                "source_system",
                "schema_ref",
                "raw_artifact_digest",
                "raw_size",
                "scope",
                "lifecycle",
                "lineage",
                "source_pointers",
                "imported_at",
                "signature_requirement",
            ],
            versioned(
                {
                    "envelope_id": ID,
                    "source_system": ID,
                    "schema_ref": STRING,
                    "raw_artifact_digest": DIGEST,
                    "raw_size": {"type": "integer", "minimum": 0},
                    "scope": SCOPE,
                    "lifecycle": {
                        "type": "object",
                        "properties": {"expires_at": TIME},
                        "additionalProperties": False,
                    },
                    "lineage": REFS,
                    "source_pointers": array(POINTER, minimum=1, unique=True),
                    "imported_at": TIME,
                    "signature_requirement": {"enum": ["required", "process_bound"]},
                }
            ),
            title="CPCF Source Artifact Envelope v0.3",
        ),
        "projection-receipt": closed(
            [
                "schema_version",
                "receipt_id",
                "envelope_digest",
                "raw_artifact_digest",
                "invocation_digest",
                "executable_digest",
                "return_code",
                "timed_out",
                "stdout_truncated",
                "stderr_truncated",
                "projected_objects",
                "cached_validation",
                "evaluation_time",
            ],
            versioned(
                {
                    "receipt_id": ID,
                    "envelope_digest": DIGEST,
                    "raw_artifact_digest": DIGEST,
                    "invocation_digest": {"oneOf": [DIGEST, {"type": "null"}]},
                    "executable_digest": {"oneOf": [DIGEST, {"type": "null"}]},
                    "return_code": {"oneOf": [{"type": "integer"}, {"type": "null"}]},
                    "timed_out": {"type": "boolean"},
                    "stdout_truncated": {"type": "boolean"},
                    "stderr_truncated": {"type": "boolean"},
                    "projected_objects": array(
                        {
                            "type": "object",
                            "required": ["digest", "schema_ref", "source_pointer"],
                            "properties": {
                                "digest": DIGEST,
                                "schema_ref": STRING,
                                "source_pointer": POINTER,
                            },
                            "additionalProperties": False,
                        },
                        unique=True,
                    ),
                    "cached_validation": {"type": "object", "additionalProperties": TRUTH},
                    "evaluation_time": TIME,
                }
            ),
            title="CPCF Recomputable Projection Receipt v0.3",
        ),
        "branch-effect-contract": closed(
            ["schema_version", "effect_id", "branches"],
            versioned(
                {
                    "effect_id": ID,
                    "branches": {
                        "type": "object",
                        "required": ["success", "partial", "failure", "timeout"],
                        "properties": {
                            name: branch for name in ("success", "partial", "failure", "timeout")
                        },
                        "additionalProperties": False,
                    },
                }
            ),
            title="CPCF Four-Branch Effect Contract v0.3",
        ),
        "adapter-capability": closed(
            [
                "schema_version",
                "capability_id",
                "adapter",
                "operation",
                "effect_class",
                "executable",
                "executable_digest",
                "argv_prefix",
                "output_schema_ref",
                "outcome_selector",
                "branch_effect_ref",
                "signature",
            ],
            versioned(
                {
                    "capability_id": ID,
                    "adapter": ID,
                    "operation": ID,
                    "effect_class": {"enum": ["inspect", "validate", "plan", "local_write"]},
                    "executable": STRING,
                    "executable_digest": DIGEST,
                    "argv_prefix": array(STRING, minimum=1),
                    "output_schema_ref": STRING,
                    "outcome_selector": {
                        "type": "object",
                        "required": ["source_pointer", "mapping"],
                        "properties": {
                            "source_pointer": POINTER,
                            "mapping": {
                                "type": "object",
                                "additionalProperties": {
                                    "enum": ["success", "partial", "failure", "timeout"]
                                },
                            },
                        },
                        "additionalProperties": False,
                    },
                    "branch_effect_ref": ID,
                    "signature": SIGNATURE,
                }
            ),
            title="CPCF Signed Adapter Capability v0.3",
        ),
        "action": closed(
            [
                "schema_version",
                "action_id",
                "capability_ref",
                "arguments",
                "input_refs",
                "required_authority_refs",
                "required_hazard_refs",
                "expires_at",
            ],
            versioned(
                {
                    "action_id": ID,
                    "capability_ref": ID,
                    "arguments": array(STRING),
                    "input_refs": REFS,
                    "required_authority_refs": REFS,
                    "required_hazard_refs": REFS,
                    "expires_at": TIME,
                    "priority_class": {"type": "integer", "minimum": 1, "maximum": 10},
                    "signature": SIGNATURE,
                }
            ),
            title="CPCF Action v0.3",
        ),
        "action-receipt": closed(
            [
                "schema_version",
                "action_id",
                "generation_before",
                "generation_after",
                "outcome",
                "process_receipt_digest",
                "projection_receipt_digest",
                "source_backed_post_state",
            ],
            versioned(
                {
                    "action_id": ID,
                    "generation_before": DIGEST,
                    "generation_after": {"oneOf": [DIGEST, {"type": "null"}]},
                    "outcome": {"enum": ["success", "partial", "failure", "timeout"]},
                    "process_receipt_digest": DIGEST,
                    "projection_receipt_digest": {"oneOf": [DIGEST, {"type": "null"}]},
                    "source_backed_post_state": {"enum": ["true", "false", "unknown"]},
                }
            ),
            title="CPCF Action Receipt v0.3",
        ),
        "state-marking": closed(
            ["schema_version", "marking_id", "state_refs", "coordinates", "source_refs"],
            versioned(
                {
                    "marking_id": ID,
                    "state_refs": REFS,
                    "coordinates": quantity_map,
                    "source_refs": REFS,
                }
            ),
            title="CPCF Finite State Marking v0.3",
        ),
        "transformation-network": closed(
            ["schema_version", "network_id", "nodes", "transformations"],
            versioned(
                {"network_id": ID, "nodes": array(node), "transformations": array(transformation)}
            ),
            title="CPCF Transformation Network v0.3",
        ),
        "formation-sequence-witness": closed(
            [
                "schema_version",
                "witness_id",
                "network_ref",
                "target_refs",
                "transformation_refs",
                "initial_marking_ref",
                "layers",
            ],
            versioned(
                {
                    "witness_id": ID,
                    "network_ref": ID,
                    "target_refs": REFS,
                    "transformation_refs": REFS,
                    "initial_marking_ref": ID,
                    "layers": array(REFS, minimum=1),
                }
            ),
            title="CPCF Causal Formation Witness v0.3",
        ),
        "organization-witness": closed(
            [
                "schema_version",
                "witness_id",
                "network_ref",
                "target_refs",
                "state_refs",
                "transformation_refs",
                "flux",
                "source_refs",
            ],
            versioned(
                {
                    "witness_id": ID,
                    "network_ref": ID,
                    "target_refs": REFS,
                    "state_refs": REFS,
                    "transformation_refs": REFS,
                    "flux": {"type": "object", "additionalProperties": RATIONAL},
                    "source_refs": REFS,
                }
            ),
            title="CPCF Closed Self-Maintaining Organization Witness v0.3",
        ),
        "generalized-raf-witness": closed(
            [
                "schema_version",
                "witness_id",
                "network_ref",
                "target_refs",
                "transformation_refs",
                "food_state_refs",
                "layers",
                "source_refs",
            ],
            versioned(
                {
                    "witness_id": ID,
                    "network_ref": ID,
                    "target_refs": REFS,
                    "transformation_refs": REFS,
                    "food_state_refs": REFS,
                    "layers": array(REFS),
                    "source_refs": REFS,
                }
            ),
            title="CPCF Generalized Generative RAF Witness v0.3",
        ),
        "siphon-coverage-witness": closed(
            [
                "schema_version",
                "witness_id",
                "network_ref",
                "minimal_siphons",
                "coverage_refs",
                "search_complete",
                "source_refs",
            ],
            versioned(
                {
                    "witness_id": ID,
                    "network_ref": ID,
                    "minimal_siphons": array(REFS),
                    "coverage_refs": ref_map,
                    "search_complete": {"type": "boolean"},
                    "source_refs": REFS,
                }
            ),
            title="CPCF Siphon Coverage Witness v0.3",
        ),
        "rate-feasibility-witness": closed(
            [
                "schema_version",
                "witness_id",
                "network_ref",
                "observation_window",
                "canonical_unit",
                "rate_intervals",
                "feasible_flux",
                "source_refs",
            ],
            versioned(
                {
                    "witness_id": ID,
                    "network_ref": ID,
                    "observation_window": {
                        "type": "object",
                        "required": ["start", "end"],
                        "properties": {"start": TIME, "end": TIME},
                        "additionalProperties": False,
                    },
                    "canonical_unit": STRING,
                    "rate_intervals": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "required": ["lower", "upper"],
                            "properties": {"lower": RATIONAL, "upper": RATIONAL},
                            "additionalProperties": False,
                        },
                    },
                    "feasible_flux": {"type": "object", "additionalProperties": RATIONAL},
                    "source_refs": REFS,
                }
            ),
            title="CPCF Exact Interval Rate Feasibility Witness v0.3",
        ),
        "open-system-resource-witness": closed(
            [
                "schema_version",
                "witness_id",
                "network_ref",
                "coordinate_weights",
                "boundary_supply_credits",
                "protected_coordinates",
                "source_refs",
            ],
            versioned(
                {
                    "witness_id": ID,
                    "network_ref": ID,
                    "coordinate_weights": {"type": "object", "additionalProperties": RATIONAL},
                    "boundary_supply_credits": {"type": "object", "additionalProperties": RATIONAL},
                    "protected_coordinates": REFS,
                    "source_refs": REFS,
                }
            ),
            title="CPCF Open-System Resource Accounting Witness v0.3",
        ),
        "verification-network-witness": closed(
            [
                "schema_version",
                "witness_id",
                "time_unit",
                "observation_window",
                "stages",
                "routing",
                "source_refs",
            ],
            versioned(
                {
                    "witness_id": ID,
                    "time_unit": STRING,
                    "observation_window": {
                        "type": "object",
                        "required": ["start", "end"],
                        "properties": {"start": TIME, "end": TIME},
                        "additionalProperties": False,
                    },
                    "stages": array(stage, minimum=1),
                    "routing": array(
                        {
                            "type": "object",
                            "required": ["from", "to", "fanout_upper"],
                            "properties": {"from": ID, "to": ID, "fanout_upper": RATIONAL},
                            "additionalProperties": False,
                        }
                    ),
                    "source_refs": REFS,
                    "stationarity_established": {"type": "boolean"},
                    "means_established": {"type": "boolean"},
                }
            ),
            title="CPCF Verification Network Witness v0.3",
        ),
        "perturbation-suite": closed(
            ["schema_version", "suite_id", "cases", "acceptance", "source_refs"],
            versioned(
                {
                    "suite_id": ID,
                    "cases": array(
                        {
                            "type": "object",
                            "required": ["case_id", "remove_refs", "resource_reductions"],
                            "properties": {
                                "case_id": ID,
                                "remove_refs": REFS,
                                "resource_reductions": quantity_map,
                            },
                            "additionalProperties": False,
                        },
                        minimum=1,
                    ),
                    "acceptance": {
                        "type": "object",
                        "required": [
                            "maximum_lost_targets",
                            "maximum_cascade_depth",
                            "support_core_must_survive",
                        ],
                        "properties": {
                            "maximum_lost_targets": {"type": "integer", "minimum": 0},
                            "maximum_cascade_depth": {"type": "integer", "minimum": 0},
                            "support_core_must_survive": {"type": "boolean"},
                        },
                        "additionalProperties": False,
                    },
                    "source_refs": REFS,
                }
            ),
            title="CPCF Declared Perturbation Suite v0.3",
        ),
        "perturbation-result": closed(
            ["schema_version", "result_id", "suite_ref", "case_results", "accepted"],
            versioned(
                {
                    "result_id": ID,
                    "suite_ref": ID,
                    "case_results": array({"type": "object"}),
                    "accepted": {"type": "boolean"},
                }
            ),
            title="CPCF Perturbation Replay Result v0.3",
        ),
        "coordination-event-ledger": closed(
            ["schema_version", "ledger_id", "events", "source_refs"],
            versioned(
                {
                    "ledger_id": ID,
                    "events": array(
                        {
                            "type": "object",
                            "required": [
                                "event_id",
                                "event_type",
                                "principal_key_id",
                                "independence_domain",
                                "artifact_digest",
                                "occurred_at",
                            ],
                            "properties": {
                                "event_id": ID,
                                "event_type": {
                                    "enum": ["commit", "consume", "reveal", "verify", "terminate"]
                                },
                                "principal_key_id": ID,
                                "independence_domain": ID,
                                "artifact_digest": DIGEST,
                                "occurred_at": TIME,
                            },
                            "additionalProperties": False,
                        }
                    ),
                    "source_refs": REFS,
                }
            ),
            title="CPCF Coordination Exposure Ledger v0.3",
        ),
        "measurement-protocol": closed(
            [
                "schema_version",
                "protocol_id",
                "registered_at",
                "target_refs",
                "comparison",
                "assignment",
                "observation_window",
                "outcomes",
                "quality_floors",
                "stopping_rule",
                "missing_data_policy",
                "analysis_method",
                "evaluator_key_id",
                "source_refs",
                "signature",
            ],
            versioned(
                {
                    "protocol_id": ID,
                    "registered_at": TIME,
                    "target_refs": REFS,
                    "comparison": STRING,
                    "assignment": STRING,
                    "observation_window": {
                        "type": "object",
                        "required": ["start", "end"],
                        "properties": {"start": TIME, "end": TIME},
                        "additionalProperties": False,
                    },
                    "outcomes": array(
                        {
                            "type": "object",
                            "required": ["metric", "direction", "unit"],
                            "properties": {
                                "metric": ID,
                                "direction": {"enum": ["minimize", "maximize"]},
                                "unit": STRING,
                            },
                            "additionalProperties": False,
                        },
                        minimum=1,
                    ),
                    "quality_floors": quantity_map,
                    "stopping_rule": STRING,
                    "missing_data_policy": STRING,
                    "analysis_method": STRING,
                    "evaluator_key_id": ID,
                    "source_refs": REFS,
                    "signature": SIGNATURE,
                }
            ),
            title="CPCF Preregistered Measurement Protocol v0.3",
        ),
        "trial-result-certificate": closed(
            [
                "schema_version",
                "result_id",
                "protocol_digest",
                "dataset_digest",
                "analysis_executable_digest",
                "completed_at",
                "effect_intervals",
                "quality_intervals",
                "time_uniform",
                "assumptions",
                "source_refs",
                "evaluator_key_id",
                "signature",
            ],
            versioned(
                {
                    "result_id": ID,
                    "protocol_digest": DIGEST,
                    "dataset_digest": DIGEST,
                    "analysis_executable_digest": DIGEST,
                    "completed_at": TIME,
                    "effect_intervals": array(interval, minimum=1),
                    "quality_intervals": array(interval),
                    "time_uniform": {"type": "boolean"},
                    "assumptions": array(STRING, minimum=1),
                    "source_refs": REFS,
                    "evaluator_key_id": ID,
                    "signature": SIGNATURE,
                }
            ),
            title="CPCF External Trial Result Certificate v0.3",
        ),
        "acceleration-evidence": closed(
            [
                "schema_version",
                "evidence_id",
                "protocol_digest",
                "result_digest",
                "status",
                "reasons",
            ],
            versioned(
                {
                    "evidence_id": ID,
                    "protocol_digest": DIGEST,
                    "result_digest": DIGEST,
                    "status": {
                        "enum": [
                            "unmeasured",
                            "externally_observed_inconclusive",
                            "external_acceleration_bundle_compatible",
                            "external_quality_or_safety_contradiction",
                        ]
                    },
                    "reasons": array(STRING),
                }
            ),
            title="CPCF Operational Acceleration Evidence v0.3",
        ),
    }


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    for name, schema in schemas().items():
        schema["$id"] = f"{BASE}/{name}.schema.json"
        target = ROOT / f"{name}.schema.json"
        target.write_text(
            json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
