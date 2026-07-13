# SPDX-License-Identifier: Apache-2.0
"""Receipt-backed synthetic v0.2 demonstrations, including adversarial failures."""

from __future__ import annotations

from pathlib import Path

from collective_phase_control_fabric.bundle import create_bundle
from collective_phase_control_fabric.canonical import canonical_bytes, digest_json, write_canonical
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.types import JsonObject
from collective_phase_control_fabric.workspace_v2 import state_digest

DEMO_SCENARIOS = (
    "orientation-only-reachability",
    "spoofed-receipt-rejection",
    "causal-cycle-without-formation",
    "generative-catalyst",
    "verification-overload-repair",
    "interdependent-cascade-repair",
    "external-l6-l8-certificate-import",
)


def _contract() -> JsonObject:
    return {
        "schema_version": "0.2.0",
        "contract_id": "contract:v0.2-demo",
        "phase_label": "synthetic bounded collective organization",
        "scope": {"domain": "cpcf-synthetic-v0.2", "version": "1"},
        "evaluation_time": "2026-01-01T00:00:00Z",
        "target_states": ["state:target"],
        "target_paths": [{"path_id": "path:primary", "transformation_ids": ["transform:produce"]}],
        "initial_available_states": ["state:input", "evidence:source", "report:verifier"],
        "primitive_transformations": ["transform:produce"],
        "state_coordinate_registry": {
            "protected_resource": {"unit": "resource-unit", "proxy_only": False},
            "target_units": {"unit": "artifact", "proxy_only": False},
        },
        "protected_floors": {"protected_resource": "0"},
        "resource_envelope": {"local_io": {"unit": "operation", "maximum": "10"}},
        "control_policy": {
            "planning_horizon": 1,
            "beam_width": 32,
            "candidate_cap": 64,
            "retry_policy": {"maximum_retries": 1},
        },
        "formation_policy": {"causal_sequence_required": True, "maximum_layer_count": 16},
        "support_core_policy": {
            "minimum_independent_support_groups": 1,
            "minimum_independent_verifier_groups": 1,
            "perturbation_suite_refs": [],
        },
        "rate_policy": {"levels_requiring_external_rate_evidence": ["L3", "L4", "L5"]},
        "collective_policy": {
            "minimum_independent_contribution_groups": 1,
            "required_integration_roles": ["integrator"],
            "required_independent_verifier_groups": 1,
            "correlation_policy": "digest-event-lineage-deduplication",
            "communication_policy": "commit-before-bounded-reveal",
            "compartments": ["proposal", "integration", "verification"],
        },
        "robustness_policy": {
            "minimum_independent_target_paths": 1,
            "minimum_independent_verifiers": 1,
            "tolerated_single_failures": 8,
            "minimum_source_systems": 1,
        },
        "external_measurement_policy": {"baseline": {"protocol": "synthetic-baseline-v1"}},
        "termination_policy": {"maximum_steps": 10, "explicit_termination_required": True},
        "task_structure": "sequential",
        "work_graph": {"tasks": [], "dependencies": []},
        "non_claims": [
            "No collective-superintelligence claim.",
            "No measured-acceleration claim.",
            "No physical-phase-transition claim.",
        ],
    }


def _network() -> JsonObject:
    nodes = [
        {
            "node_id": "state:input",
            "type": "artifact",
            "available": True,
            "lifecycle_status": "valid",
            "source_system": "synthetic",
            "contribution": True,
            "independence_group": "proposal-a",
            "digest": "sha256:synthetic-input",
            "source_event": "event:input",
            "lineage": "lineage:input",
        },
        {
            "node_id": "evidence:source",
            "type": "evidence",
            "available": True,
            "lifecycle_status": "valid",
            "source_system": "synthetic-evidence",
            "independence_group": "support-a",
            "digest": "sha256:synthetic-evidence",
            "source_event": "event:evidence",
            "lineage": "lineage:evidence",
            "expiry": "2027-01-01T00:00:00Z",
        },
        {
            "node_id": "report:verifier",
            "type": "verifier_report",
            "available": True,
            "lifecycle_status": "valid",
            "source_system": "synthetic-verifier",
            "independence_group": "verifier-b",
            "verifier_role": "independent_verifier",
            "independent": True,
            "digest": "sha256:synthetic-verifier",
            "source_event": "event:verifier",
            "lineage": "lineage:verifier",
            "expiry": "2027-01-01T00:00:00Z",
        },
        {
            "node_id": "state:target",
            "type": "target_state",
            "available": False,
            "lifecycle_status": "valid",
            "source_system": "synthetic",
        },
        {
            "node_id": "resource:supply",
            "type": "resource_record",
            "available": True,
            "lifecycle_status": "valid",
            "source_system": "synthetic-resource-report",
            "expiry": "2027-01-01T00:00:00Z",
        },
    ]
    edge: JsonObject = {
        "schema_version": "0.2.0",
        "transformation_id": "transform:produce",
        "source_system": "synthetic",
        "required_inputs": ["state:input"],
        "read_enablers": ["evidence:source", "report:verifier"],
        "required_evidence": ["evidence:source", "report:verifier"],
        "required_verifier_roles": ["independent_verifier"],
        "required_authority_refs": [],
        "required_catalysts": [],
        "support_refs": ["evidence:source"],
        "verifier_refs": ["report:verifier"],
        "consumed_coordinates": {"protected_resource": {"quantity": "1", "unit": "resource-unit"}},
        "produced_coordinates": {"target_units": {"quantity": "2", "unit": "artifact"}},
        "produced_outputs": ["state:target"],
        "inhibitors": [],
        "effect_class": "validate",
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
    return {
        "schema_version": "0.2.0",
        "network_id": "network:v0.2-demo",
        "nodes": nodes,
        "transformations": [edge],
    }


def _productive() -> JsonObject:
    return {
        "schema_version": "0.1.0",
        "witness_id": "productive:v0.2-demo",
        "transformation_coefficients": {"transform:produce": "1"},
        "external_supplies": {
            "protected_resource": {
                "quantity": "1",
                "unit": "resource-unit",
                "source_ref": "resource:supply",
            }
        },
        "expected_net_balances": {"protected_resource": "0", "target_units": "2"},
        "target_positive_coordinates": ["target_units"],
        "protected_nonnegative_coordinates": ["protected_resource"],
        "scope": {"domain": "cpcf-synthetic-v0.2", "version": "1"},
        "horizon": "one-step",
        "source_refs": ["synthetic:productive"],
    }


def _formation() -> JsonObject:
    return {
        "schema_version": "0.2.0",
        "witness_id": "formation:v0.2-demo",
        "layers": [["transform:produce"]],
        "initial_coordinate_balances": {"protected_resource": "1", "target_units": "0"},
    }


def _rate() -> JsonObject:
    return {
        "schema_version": "0.2.0",
        "witness_id": "rates:v0.2-demo",
        "observation_window": {"start": "2025-01-01T00:00:00Z", "end": "2025-02-01T00:00:00Z"},
        "intervals": [
            {
                "transformation_id": "transform:produce",
                "lower": "1",
                "upper": "2",
                "unit": "operation/hour",
            }
        ],
        "source_refs": ["synthetic:external-rate-report"],
    }


def _persistence() -> JsonObject:
    return {
        "schema_version": "0.2.0",
        "witness_id": "persistence:v0.2-demo",
        "conserved_coordinates": [],
        "replenished_coordinates": ["protected_resource"],
        "renewal_refs": ["synthetic:renewal"],
        "expiry_coverage_refs": ["synthetic:expiry"],
        "verifier_capacity_refs": ["synthetic:capacity"],
        "rollback_refs": ["synthetic:rollback"],
        "failure_response_refs": ["synthetic:failure-response"],
    }


def demo_documents(scenario: str) -> tuple[JsonObject, JsonObject, dict[str, JsonObject]]:
    """Build one finite scenario; no result is empirical evidence."""

    if scenario not in DEMO_SCENARIOS:
        raise KeyError(scenario)
    contract, network = _contract(), _network()
    witnesses: dict[str, JsonObject] = {}
    if scenario == "causal-cycle-without-formation":
        network["transformations"][0]["required_inputs"] = ["state:target"]
        witnesses["formation-sequence-witness@0.2.0"] = _formation()
    elif scenario == "generative-catalyst":
        catalyst = {
            "node_id": "catalyst:seed",
            "type": "certified_catalyst",
            "available": True,
            "lifecycle_status": "valid",
            "source_system": "synthetic",
        }
        network["nodes"].append(catalyst)
        contract["initial_available_states"].append("catalyst:seed")
        network["transformations"][0]["required_catalysts"] = ["catalyst:seed"]
        witnesses.update(
            {
                "productive-plan-witness@0.1.0": _productive(),
                "formation-sequence-witness@0.2.0": _formation(),
                "persistence-witness@0.2.0": _persistence(),
                "rate-interval-witness@0.2.0": _rate(),
                "resource-potential-witness@0.2.0": {
                    "schema_version": "0.2.0",
                    "witness_id": "resource-potential:v0.2-demo",
                    "coordinate_weights": {
                        "protected_resource": "1",
                        "target_units": "0",
                    },
                    "external_supply_refs": ["resource:supply"],
                },
                "generative-catalytic-witness@0.2.0": {
                    "schema_version": "0.2.0",
                    "witness_id": "catalysis:v0.2-demo",
                    "food_states": ["catalyst:seed"],
                    "catalyst_bindings": {"transform:produce": ["catalyst:seed"]},
                },
            }
        )
    elif scenario == "verification-overload-repair":
        witnesses["verification-network-witness@0.2.0"] = {
            "schema_version": "0.2.0",
            "witness_id": "verification:v0.2-overload",
            "time_unit": "hour",
            "observation_window": {"start": "2025-01-01T00:00:00Z", "end": "2025-02-01T00:00:00Z"},
            "stages": [
                {
                    "stage_id": "stage:independent-review",
                    "arrival_lower": "2",
                    "arrival_upper": "3",
                    "service_lower": "1",
                    "service_upper": "2",
                    "backlog": "4",
                    "independence_group": "verifier-b",
                }
            ],
            "routing": [],
            "stationarity_established": False,
            "means_established": False,
            "source_refs": ["synthetic:queue-report"],
        }
    elif scenario == "interdependent-cascade-repair":
        contract["perturbation_suites"] = [
            {"suite_id": "perturbation:input-loss", "remove_ids": ["state:input"]}
        ]
        contract["support_core_policy"]["perturbation_suite_refs"] = ["perturbation:input-loss"]
    return contract, network, witnesses


def _install_projection(
    root: Path, schema_ref: str, value: JsonObject, source_system: str = "cpcf-synthetic-demo"
) -> JsonObject:
    raw = canonical_bytes(value) + b"\n"
    store = ContentAddressedStore(root / ".cpcf" / "cas")
    artifact = store.put(raw)
    projection_digest = digest_json(value)
    envelope_id = f"envelope:{artifact.digest.split(':', 1)[1][:24]}"
    envelope: JsonObject = {
        "schema_version": "0.2.0",
        "envelope_id": envelope_id,
        "source_system": source_system,
        "schema_ref": schema_ref,
        "raw_artifact_digest": artifact.digest,
        "raw_size": len(raw),
        "scope": value.get("scope", {}),
        "lifecycle": {},
        "lineage": [],
        "source_pointers": ["/"],
        "imported_at": "2026-01-01T00:00:00Z",
        "signature": None,
    }
    receipt: JsonObject = {
        "schema_version": "0.2.0",
        "action_id": "demo:install",
        "envelope_ref": envelope_id,
        "executable_digest": None,
        "invocation_digest": digest_json({"scenario": source_system, "schema": schema_ref}),
        "raw_artifact_digest": artifact.digest,
        "projected_object_digests": [projection_digest],
        "projected_objects": [
            {"digest": projection_digest, "schema_ref": schema_ref, "source_pointer": "/"}
        ],
        "source_pointers": ["/"],
        "validation_results": {
            "schema": "true",
            "digest": "true",
            "expiry": "true",
            "scope": "true",
            "resource": "true",
            "baseline": "true",
            "signature": "true",
        },
        "evaluation_time": "2026-01-01T00:00:00Z",
    }
    receipt["receipt_id"] = f"receipt:{digest_json(receipt).split(':', 1)[1][:24]}"
    write_canonical(
        root / ".cpcf" / "envelopes" / f"{envelope_id.replace(':', '-')}.json", envelope
    )
    write_canonical(
        root / ".cpcf" / "receipts" / f"{receipt['receipt_id'].replace(':', '-')}.json", receipt
    )
    return receipt


def bootstrap_demo(root: Path, scenario: str = DEMO_SCENARIOS[0]) -> JsonObject:
    """Create a native synthetic workspace with auditable receipts and no executable fake action."""

    if root.exists() and any(root.iterdir()):
        raise FileExistsError(f"output directory is not empty: {root}")
    contract, network, witnesses = demo_documents(scenario)
    root.mkdir(parents=True, exist_ok=True)
    write_canonical(root / "contract.json", contract)
    write_canonical(root / "network.json", network)
    write_canonical(root / "actions.json", {"schema_version": "0.2.0", "actions": []})
    network_receipt = _install_projection(root, "transformation-network@0.2.0", network)
    for schema_ref, witness in witnesses.items():
        token = digest_json(witness).split(":", 1)[1]
        write_canonical(root / "witnesses" / f"{token}.json", witness)
        _install_projection(root, schema_ref, witness)
    if scenario == "spoofed-receipt-rejection":
        network_receipt["raw_artifact_digest"] = "sha256:" + "0" * 64
        write_canonical(
            root / ".cpcf" / "receipts" / f"{network_receipt['receipt_id'].replace(':', '-')}.json",
            network_receipt,
        )
    if scenario == "external-l6-l8-certificate-import":
        for kind in ("collective_advantage", "frontier_exceedance", "phase_evidence"):
            certificate: JsonObject = {
                "schema_version": "0.2.0",
                "certificate_id": f"certificate:{kind}",
                "certificate_kind": kind,
                "issued_at": "2025-01-01T00:00:00Z",
                "expires_at": "2027-01-01T00:00:00Z",
                "scope": contract["scope"],
                "resource_envelope": contract["resource_envelope"],
                "baseline": contract["external_measurement_policy"]["baseline"],
                "evaluator_identity": "synthetic:independent-evaluator",
                "measurement_protocol": {"kind": "synthetic-demo-only", "uncertainty": "interval"},
                "source_artifact_refs": [f"synthetic:{kind}:raw"],
                "non_claims": ["Synthetic compatibility demonstration; no empirical claim."],
                "signature": None,
            }
            token = digest_json(certificate).split(":", 1)[1]
            write_canonical(root / ".cpcf" / "projections" / f"{token}.json", certificate)
            _install_projection(root, "external-certificate@0.2.0", certificate)
    manifest: JsonObject = {
        "schema_version": "0.2.0",
        "contract_digest": digest_json(contract),
        "state_digest": state_digest(root),
        "migration": None,
        "source_of_record_migrated": False,
        "synthetic_demo": True,
        "scenario": scenario,
    }
    write_canonical(root / ".cpcf" / "workspace.json", manifest)
    write_canonical(root / ".cpcf" / "history.json", {"records": []})
    bundle = create_bundle(root, root / "bundle")
    return {
        "command_status": "ok",
        "workspace": str(root.resolve()),
        "scenario": scenario,
        "synthetic": True,
        "executable_actions": 0,
        "bundle_object_count": len(bundle["objects"]),
        "next_safe_command": [
            "cpcf",
            "doctor",
            "--workspace",
            str(root.resolve()),
            "--strict",
            "--json",
        ],
    }
