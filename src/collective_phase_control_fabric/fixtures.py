# SPDX-License-Identifier: Apache-2.0
"""Synthetic deterministic fixtures owned by this project."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

from collective_phase_control_fabric.types import JsonObject


def _base_contract() -> JsonObject:
    return {
        "schema_version": "0.1.0",
        "contract_id": "contract:demo",
        "phase_label": "bounded capability formation",
        "scope": {"domain": "synthetic-demo", "version": "1"},
        "target_states": ["state:target"],
        "target_paths": [
            {
                "path_id": "path:primary",
                "required_states": ["state:input", "state:target"],
                "transformation_ids": ["transform:produce"],
            }
        ],
        "initial_available_states": ["state:input", "evidence:source", "report:verifier"],
        "primitive_transformations": ["transform:produce"],
        "state_coordinate_registry": {
            "target_units": {"unit": "artifact", "proxy_only": False},
            "protected_resource": {"unit": "resource-unit", "proxy_only": False},
        },
        "required_evidence_classes": ["source_backed"],
        "required_verifier_roles": ["independent_verifier"],
        "collective_policy": {
            "minimum_independent_contribution_groups": 1,
            "required_integration_roles": ["integrator"],
            "required_independent_verifier_groups": 1,
            "correlation_policy": "digest-event-lineage-deduplication",
            "communication_policy": "independent-proposal-then-bounded-integration",
        },
        "task_structure": "sequential",
        "work_graph": {
            "tasks": [
                {"task_id": "work:produce", "duration": "2"},
                {"task_id": "work:verify", "duration": "1"},
            ],
            "dependencies": [{"before": "work:produce", "after": "work:verify"}],
        },
        "resource_envelope": {
            "local_io": {"unit": "operation", "maximum": "10"},
        },
        "authority_envelope_refs": [],
        "hazard_envelope_refs": ["hazard:local-only"],
        "protected_floors": {"protected_resource": "0"},
        "lifecycle_policy": {"maximum_retry_count": 1, "unknown_is_valid": False},
        "recursive_reuse_policy": {"requires_certificate": True},
        "robustness_policy": {
            "minimum_independent_target_paths": 1,
            "minimum_independent_verifiers": 1,
            "tolerated_single_failures": 8,
            "minimum_source_systems": 1,
        },
        "external_measurement_policy": {},
        "termination_policy": {"maximum_steps": 10, "explicit_termination_required": True},
        "non_claims": [
            "No real ASI claim.",
            "No performance claim.",
            "No physical phase-transition claim.",
        ],
        "created_at": "2026-01-01T00:00:00Z",
    }


def _base_network() -> JsonObject:
    return {
        "schema_version": "0.1.0",
        "network_id": "network:demo",
        "nodes": [
            {
                "node_id": "state:input",
                "type": "artifact",
                "available": True,
                "lifecycle_status": "valid",
                "source_system": "fixture",
                "contribution": True,
                "independence_group": "solver-group-a",
                "digest": "sha256:input",
                "source_event": "event:input",
                "lineage": "lineage:input",
            },
            {
                "node_id": "evidence:source",
                "type": "evidence",
                "available": True,
                "lifecycle_status": "valid",
                "source_system": "fixture-evidence",
                "evidence_class": "source_backed",
                "actor_id": "actor:source",
                "correlation_group": "source-group",
                "digest": "sha256:evidence",
                "source_event": "event:evidence",
                "lineage": "lineage:evidence",
                "expiry": "2027-01-01T00:00:00Z",
            },
            {
                "node_id": "report:verifier",
                "type": "verifier_report",
                "available": True,
                "lifecycle_status": "valid",
                "source_system": "fixture-verifier",
                "verifier_role": "independent_verifier",
                "independent": True,
                "independence_group": "verifier-group-b",
                "actor_id": "actor:verifier",
                "correlation_group": "verifier-group-b",
                "digest": "sha256:verifier",
                "source_event": "event:verifier",
                "lineage": "lineage:verifier",
                "expiry": "2027-01-01T00:00:00Z",
            },
            {
                "node_id": "state:target",
                "type": "target_state",
                "available": False,
                "lifecycle_status": "valid",
                "source_system": "fixture",
            },
        ],
        "transformations": [
            {
                "transformation_id": "transform:produce",
                "source_system": "fixture",
                "source_operation": "synthetic_production",
                "required_inputs": ["state:input"],
                "read_enablers": ["evidence:source", "report:verifier"],
                "reusable_enablers": ["evidence:source"],
                "consumed_coordinates": {
                    "protected_resource": {"quantity": "1", "unit": "resource-unit"}
                },
                "produced_coordinates": {"target_units": {"quantity": "2", "unit": "artifact"}},
                "produced_outputs": ["state:target"],
                "inhibitors": [],
                "required_evidence": ["evidence:source", "report:verifier"],
                "required_verifier_roles": ["independent_verifier"],
                "required_authority_refs": [],
                "resource_upper_bounds": {"local_io": {"quantity": "1", "unit": "operation"}},
                "lifecycle_requirements": ["valid-inputs"],
                "rollback_requirements": ["projection-only"],
                "effect_class": "validate",
                "output_contract": {"type": "target_state"},
                "postcondition_contract": {"available_states": ["state:target"]},
                "scope": {"domain": "synthetic-demo"},
                "source_refs": ["fixture:base"],
                "schema_valid": True,
                "authority_status": True,
                "hazard_status": True,
                "lifecycle_status": True,
                "source_version_supported": True,
                "output_contract_status": True,
                "protected_floor_violation": False,
                "source_backed": True,
                "integration_edge": True,
                "integration_roles": ["integrator"],
            }
        ],
    }


def productive_witness() -> JsonObject:
    return {
        "schema_version": "0.1.0",
        "witness_id": "productive-witness:demo",
        "transformation_coefficients": {"transform:produce": "1"},
        "external_supplies": {"protected_resource": {"quantity": "1", "unit": "resource-unit"}},
        "expected_net_balances": {"protected_resource": "0", "target_units": "2"},
        "target_positive_coordinates": ["target_units"],
        "protected_nonnegative_coordinates": ["protected_resource"],
        "scope": {"domain": "synthetic-demo"},
        "horizon": "one-step",
        "source_refs": ["fixture:productive-witness"],
    }


def maintenance_witness() -> JsonObject:
    return {
        "schema_version": "0.1.0",
        "witness_id": "maintenance-witness:demo",
        "validity_horizon": "P30D",
        "renewal_obligations": ["obligation:renew"],
        "expiry_refresh_refs": ["lifecycle:refresh"],
        "resource_supply_refs": ["resource:supply"],
        "verifier_capacity_refs": ["resource:verifier-capacity"],
        "rollback_refs": ["rollback:projection"],
        "maintenance_cost_refs": ["cost:maintenance"],
        "failure_response_refs": ["response:failure"],
        "source_refs": ["fixture:maintenance-witness"],
    }


def fixture(name: str) -> JsonObject:
    """Build a deterministic named fixture without external source material."""

    contract = _base_contract()
    network = _base_network()
    productive: JsonObject | None = None
    maintenance: JsonObject | None = None
    expected: JsonObject = {}
    if name == "reachability_without_productivity":
        expected = {"ladder_level": "L1", "productivity": "unknown"}
    elif name == "verified_productive_organization":
        productive = productive_witness()
        expected = {"ladder_level": "L2"}
    elif name == "productivity_without_maintenance":
        productive = productive_witness()
        expected = {"ladder_level": "L2", "maintenance": "unknown"}
    elif name == "certified_catalyst":
        productive = productive_witness()
        maintenance = maintenance_witness()
        contract["robustness_policy"]["minimum_independent_target_paths"] = 2
        maintenance_nodes = [
            ("obligation:renew", "obligation"),
            ("lifecycle:refresh", "lifecycle_record"),
            ("resource:supply", "resource_record"),
            ("resource:verifier-capacity", "resource_record"),
            ("rollback:projection", "artifact"),
            ("cost:maintenance", "resource_record"),
            ("response:failure", "artifact"),
        ]
        network["nodes"].extend(
            {
                "node_id": node_id,
                "type": node_type,
                "available": True,
                "lifecycle_status": "valid",
                "source_system": "maintenance-fixture",
            }
            for node_id, node_type in maintenance_nodes
        )
        network["nodes"].extend(
            [
                {
                    "node_id": "artifact:reuse",
                    "type": "artifact",
                    "available": False,
                    "lifecycle_status": "valid",
                    "source_system": "PCS-fixture",
                },
                {
                    "node_id": "catalyst:pcs",
                    "type": "certified_catalyst",
                    "available": True,
                    "lifecycle_status": "valid",
                    "source_system": "PCS-fixture",
                    "certificate_kind": "pcs_receipt",
                    "certificate_valid": True,
                    "bound_transformations": ["transform:produce", "transform:reuse"],
                },
            ]
        )
        reuse = deepcopy(network["transformations"][0])
        reuse.update(
            {
                "transformation_id": "transform:reuse",
                "source_operation": "synthetic_certified_reuse",
                "required_inputs": ["state:target"],
                "read_enablers": ["catalyst:pcs", "evidence:source", "report:verifier"],
                "reusable_enablers": ["catalyst:pcs"],
                "consumed_coordinates": {},
                "produced_coordinates": {},
                "produced_outputs": ["artifact:reuse"],
                "integration_edge": False,
            }
        )
        network["transformations"].append(reuse)
        expected = {"ladder_level": "L4", "performance_claim": False}
    elif name == "false_autocatalysis":
        network = deepcopy(_base_network())
        contract["target_states"] = ["state:absent-target"]
        contract["target_paths"] = []
        common = {
            "available": True,
            "lifecycle_status": "valid",
            "source_system": "same-source-fixture",
            "actor_id": "actor:same",
            "correlation_group": "group:same",
            "independence_group": "group:same",
        }
        network["nodes"] = [
            {**common, "node_id": "candidate:same", "type": "capability_candidate"},
            {
                **common,
                "node_id": "evidence:source",
                "type": "evidence",
                "digest": "sha256:same",
                "source_event": "event:same",
                "lineage": "lineage:same",
            },
            {
                **common,
                "node_id": "report:verifier",
                "type": "verifier_report",
                "verifier_role": "independent_verifier",
                "digest": "sha256:same-report",
                "source_event": "event:same-report",
                "lineage": "lineage:same-report",
            },
        ]
        contract["initial_available_states"] = [
            "candidate:same",
            "evidence:source",
            "report:verifier",
        ]
        base_edge = deepcopy(_base_network()["transformations"][0])
        base_edge["consumed_coordinates"] = {}
        base_edge["produced_coordinates"] = {}
        base_edge["read_enablers"] = []
        base_edge["required_evidence"] = ["evidence:source", "report:verifier"]
        network["transformations"] = []
        for index, (required, output) in enumerate(
            (
                ("candidate:same", "evidence:source"),
                ("evidence:source", "report:verifier"),
                ("report:verifier", "candidate:same"),
            )
        ):
            edge = deepcopy(base_edge)
            edge["transformation_id"] = f"transform:cycle-{index}"
            edge["required_inputs"] = [required]
            edge["produced_outputs"] = [output]
            edge["actor_id"] = "actor:same"
            edge["correlation_group"] = "group:same"
            network["transformations"].append(edge)
        expected = {"detectors": ["self_certifying_cycle", "nonproductive_cycle"]}
    elif name == "regeneration_deadlock":
        network["nodes"][0]["available"] = False
        contract["initial_available_states"] = ["evidence:source", "report:verifier"]
        contract["target_paths"][0]["required_states"] = ["state:input", "state:target"]
        network["transformations"][0]["required_inputs"] = ["state:input"]
        network["transformations"][0]["produced_outputs"] = ["state:input"]
        network["transformations"][0]["source_system"] = "external-fixture"
        expected = {"deadlock_exactness": "singleton_exact"}
    elif name == "verification_overload":
        contract["external_measurement_policy"] = {
            "verification_load": {
                "eligible_candidate_arrival_rate": "2",
                "verifier_service_rate": "1",
                "time_unit": "hour",
                "observation_window": "P1D",
                "source_refs": ["fixture:load-report"],
            }
        }
        expected = {"verification_load": "verification_overload", "fan_out": False}
    elif name == "sequential_task_guard":
        expected = {"parallel_fan_out_allowed": False}
    elif name == "external_claim_bundle":
        kinds = ("collective_advantage", "frontier_exceedance", "phase_evidence")
        for kind in kinds:
            network["nodes"].append(
                {
                    "node_id": f"certificate:{kind}",
                    "type": "external_certificate",
                    "available": True,
                    "lifecycle_status": "valid",
                    "source_system": "external-evaluator-fixture",
                    "certificate_kind": kind,
                    "schema_valid": True,
                    "digest_valid": True,
                    "scope_compatible": True,
                    "resource_compatible": True,
                    "baseline_compatible": True,
                    "not_expired": True,
                    "non_claims_present": True,
                    "signature_supplied": False,
                    "evaluator_identity": "evaluator:independent-fixture",
                    "source_refs": [f"fixture:certificate:{kind}"],
                }
            )
        phase_certificate = network["nodes"][-1]
        phase_certificate.update(
            {
                "preregistered_control_parameter": "synthetic-control",
                "system_sizes": ["small", "medium", "large"],
                "resource_matched_protocol": "synthetic-resource-envelope-v1",
                "declared_order_parameter_vector": ["coordinate-a", "coordinate-b"],
                "perturbation_or_robustness_evidence": ["fixture:perturbation"],
                "evaluator_and_method": "external-evaluator-fixture:synthetic-method",
                "uncertainty_representation": "interval",
                "source_artifact_refs": ["fixture:external-phase-evidence"],
            }
        )
        expected = {"external_claim_bundle_compatible": False}
    else:
        raise KeyError(f"unknown fixture: {name}")
    return {
        "fixture_name": name,
        "generated_at": datetime(2026, 1, 1, tzinfo=UTC).isoformat().replace("+00:00", "Z"),
        "contract": contract,
        "network": network,
        "productive_witness": productive,
        "maintenance_witness": maintenance,
        "expected": expected,
    }


FIXTURE_NAMES = (
    "reachability_without_productivity",
    "verified_productive_organization",
    "productivity_without_maintenance",
    "certified_catalyst",
    "false_autocatalysis",
    "regeneration_deadlock",
    "verification_overload",
    "sequential_task_guard",
    "external_claim_bundle",
)
