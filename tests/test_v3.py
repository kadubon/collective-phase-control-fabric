# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import sys
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collective_phase_control_fabric.canonical import (
    canonical_v3_bytes,
    digest_bytes,
    digest_v3_json,
    load_json_strict,
    loads_json_strict,
    write_canonical,
)
from collective_phase_control_fabric.execution_v3 import run_action_v3
from collective_phase_control_fabric.generation import GenerationStore
from collective_phase_control_fabric.planner_v3 import _dominates, plan_v3
from collective_phase_control_fabric.schema import load_schema, schema_names, validation_errors
from collective_phase_control_fabric.science_v3 import effective_independence, science_audit_v3
from collective_phase_control_fabric.trust import signable_payload, verify_pinned_signature
from collective_phase_control_fabric.workspace_v3 import (
    doctor_v3,
    import_source_v3,
    initialize_workspace_v3,
    scaffold_contract,
)

EPOCH = "2026-01-15T00:00:00Z"
SIGNED_AT = "2026-01-10T00:00:00Z"
SCOPE = {"project": "test"}


def _contract() -> dict[str, object]:
    return {
        "schema_version": "0.3.0",
        "contract_id": "contract:test",
        "phase_label": "user-defined external label",
        "scope": SCOPE,
        "evaluation_time": EPOCH,
        "target_states": ["target"],
        "initial_available_states": ["authority", "evidence", "seed", "supply"],
        "state_coordinate_registry": {"resource": {"unit": "token", "proxy_only": True}},
        "unit_registry": {},
        "protected_floors": {"resource": {"quantity": "1", "unit": "token"}},
        "resource_envelope": {"resource": {"quantity": "10", "unit": "token"}},
        "control_policy": {
            "planning_horizon": 2,
            "beam_width": 8,
            "candidate_cap": 16,
            "retry_limit": 0,
        },
        "formation_policy": {"maximum_layer_count": 8},
        "support_core_policy": {
            "minimum_support_domains": 1,
            "minimum_verifier_domains": 1,
            "perturbation_suite_refs": ["suite:baseline"],
        },
        "rate_policy": {"levels_requiring_evidence": ["L3", "L4", "L5"]},
        "measurement_protocol_refs": ["protocol:test"],
        "analysis_limits": {
            "maximum_raw_bytes": 1_048_576,
            "maximum_json_depth": 32,
            "maximum_nodes": 100,
            "maximum_transformations": 100,
            "maximum_rational_bits": 256,
            "maximum_siphon_species": 10,
        },
        "non_claims": [
            "collective superintelligence",
            "measured acceleration",
            "physical phase transition",
        ],
    }


def _key_material() -> tuple[Ed25519PrivateKey, dict[str, object]]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    policy = {
        "schema_version": "0.3.0",
        "policy_id": "trust:test",
        "principals": [
            {
                "key_id": "key:test",
                "public_key_base64": base64.b64encode(public).decode(),
                "source_systems": ["fixture"],
                "schema_names": [
                    "action",
                    "adapter-capability",
                    "branch-effect-contract",
                    "coordination-event-ledger",
                    "formation-sequence-witness",
                    "generalized-raf-witness",
                    "measurement-protocol",
                    "open-system-resource-witness",
                    "organization-witness",
                    "perturbation-suite",
                    "rate-feasibility-witness",
                    "siphon-coverage-witness",
                    "state-marking",
                    "transformation-network",
                    "trial-result-certificate",
                    "verification-network-witness",
                ],
                "roles": ["action_author", "adapter_capability", "evaluator", "source"],
                "scope": SCOPE,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
            }
        ],
    }
    return private, policy


def _signed(
    private: Ed25519PrivateKey, value: dict[str, object], schema_ref: str
) -> dict[str, object]:
    signed = deepcopy(value)
    message, payload_digest = signable_payload(signed, schema_ref)
    signed["signature"] = {
        "key_id": "key:test",
        "signature_base64": base64.b64encode(private.sign(message)).decode(),
        "signed_at": SIGNED_AT,
        "payload_digest": payload_digest,
    }
    return signed


def _workspace(tmp_path: Path) -> tuple[Path, Ed25519PrivateKey, dict[str, object]]:
    private, policy = _key_material()
    contract_path = tmp_path / "contract.json"
    trust_path = tmp_path / "trust.json"
    write_canonical(contract_path, _contract())
    write_canonical(trust_path, policy)
    root = tmp_path / "workspace"
    result = initialize_workspace_v3(contract_path, trust_path, root)
    assert result["command_status"] == "ok"
    return root, private, policy


def _import(
    tmp_path: Path,
    root: Path,
    private: Ed25519PrivateKey,
    name: str,
    value: dict[str, object],
) -> None:
    path = tmp_path / f"{name}.json"
    write_canonical(path, _signed(private, value, f"{name}@0.3.0"))
    result = import_source_v3(path, root, "fixture", f"{name}@0.3.0", apply=True)
    assert result["command_status"] == "ok", result


def _scientific_documents() -> dict[str, dict[str, object]]:
    nodes = [
        {
            "node_id": identifier,
            "type": node_type,
            "lifecycle": "active",
            "source_ref": "source:fixture",
            "principal_key_id": "key:test",
            "available": identifier != "target",
            "coordinates": {},
            "independence_domain": "domain:test",
            "infrastructure_domain": "infra:test",
            "correlation_group": "correlation:test",
            "lineage": [f"lineage:{identifier}"],
        }
        for identifier, node_type in (
            ("authority", "authority_record"),
            ("evidence", "verifier_report"),
            ("seed", "artifact"),
            ("supply", "resource_record"),
            ("target", "target_state"),
        )
    ]
    edge = {
        "transformation_id": "transform:target",
        "required_inputs": ["seed"],
        "read_enablers": [],
        "produced_outputs": ["target"],
        "required_evidence": ["evidence"],
        "required_authority_refs": ["authority"],
        "required_hazard_refs": [],
        "support_refs": ["evidence"],
        "verifier_refs": ["evidence"],
        "catalyst_clauses": [],
        "explicitly_uncatalyzed": True,
        "inhibitors": [],
        "coordinate_flows": {"resource": {"quantity": "0", "unit": "token"}},
        "boundary_supply_refs": [],
        "source_ref": "source:fixture",
    }
    siphons = [[item] for item in ("authority", "evidence", "seed", "supply")]
    return {
        "transformation-network": {
            "schema_version": "0.3.0",
            "network_id": "network:test",
            "nodes": nodes,
            "transformations": [edge],
        },
        "state-marking": {
            "schema_version": "0.3.0",
            "marking_id": "marking:test",
            "state_refs": ["authority", "evidence", "seed", "supply"],
            "coordinates": {"resource": {"quantity": "10", "unit": "token"}},
            "source_refs": ["evidence"],
        },
        "organization-witness": {
            "schema_version": "0.3.0",
            "witness_id": "witness:organization",
            "network_ref": "network:test",
            "target_refs": ["target"],
            "state_refs": ["authority", "evidence", "seed", "supply", "target"],
            "transformation_refs": ["transform:target"],
            "flux": {"transform:target": "1"},
            "source_refs": ["evidence"],
        },
        "formation-sequence-witness": {
            "schema_version": "0.3.0",
            "witness_id": "witness:formation",
            "network_ref": "network:test",
            "target_refs": ["target"],
            "transformation_refs": ["transform:target"],
            "initial_marking_ref": "marking:test",
            "layers": [["transform:target"]],
        },
        "open-system-resource-witness": {
            "schema_version": "0.3.0",
            "witness_id": "witness:resource",
            "network_ref": "network:test",
            "coordinate_weights": {"resource": "1"},
            "boundary_supply_credits": {},
            "protected_coordinates": ["resource"],
            "source_refs": ["evidence"],
        },
        "rate-feasibility-witness": {
            "schema_version": "0.3.0",
            "witness_id": "witness:rate",
            "network_ref": "network:test",
            "observation_window": {
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-01-14T00:00:00Z",
            },
            "canonical_unit": "event/hour",
            "rate_intervals": {"transform:target": {"lower": "1", "upper": "1"}},
            "feasible_flux": {"transform:target": "1"},
            "source_refs": ["evidence"],
        },
        "siphon-coverage-witness": {
            "schema_version": "0.3.0",
            "witness_id": "witness:siphon",
            "network_ref": "network:test",
            "minimal_siphons": siphons,
            "coverage_refs": {item[0]: ["evidence"] for item in siphons},
            "search_complete": True,
            "source_refs": ["evidence"],
        },
        "verification-network-witness": {
            "schema_version": "0.3.0",
            "witness_id": "witness:verification",
            "time_unit": "hour",
            "observation_window": {
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-01-14T00:00:00Z",
            },
            "stages": [
                {
                    "stage_id": "stage:verify",
                    "arrival_lower": "0",
                    "arrival_upper": "1",
                    "service_lower": "2",
                    "service_upper": "3",
                    "backlog": "0",
                    "independence_domain": "domain:test",
                    "source_refs": ["evidence"],
                }
            ],
            "routing": [],
            "source_refs": ["evidence"],
            "stationarity_established": False,
            "means_established": False,
        },
        "generalized-raf-witness": {
            "schema_version": "0.3.0",
            "witness_id": "witness:raf",
            "network_ref": "network:test",
            "target_refs": ["target"],
            "transformation_refs": ["transform:target"],
            "food_state_refs": ["authority", "evidence", "seed", "supply"],
            "layers": [["transform:target"]],
            "source_refs": ["evidence"],
        },
        "perturbation-suite": {
            "schema_version": "0.3.0",
            "suite_id": "suite:baseline",
            "cases": [{"case_id": "case:none", "remove_refs": [], "resource_reductions": {}}],
            "acceptance": {
                "maximum_lost_targets": 0,
                "maximum_cascade_depth": 0,
                "support_core_must_survive": True,
            },
            "source_refs": ["evidence"],
        },
    }


def test_strict_json_and_pinned_key_reject_spoofing() -> None:
    assert loads_json_strict(b'{"a":1}') == {"a": 1}
    try:
        loads_json_strict(b'{"a":1,"a":2}')
    except ValueError as error:
        assert "duplicate JSON key" in str(error)
    else:
        raise AssertionError("duplicate key was accepted")
    try:
        canonical_v3_bytes({"value": 0.5})
    except ValueError as error:
        assert "floating-point" in str(error)
    else:
        raise AssertionError("float was accepted")

    private, policy = _key_material()
    attacker = Ed25519PrivateKey.generate()
    value = _signed(attacker, {"schema_version": "0.3.0"}, "artifact@0.3.0")
    value["signature"]["key_id"] = "key:test"  # type: ignore[index]
    checked = verify_pinned_signature(
        value,
        policy,
        schema_ref="artifact@0.3.0",
        source_system="fixture",
        role="source",
        evaluation_time=EPOCH,
    )
    assert checked["status"] == "false"
    assert "ed25519_signature_invalid" in checked["reasons"]
    assert private is not None


def test_generation_scaffold_source_recomputation_and_science_l5(tmp_path: Path) -> None:
    scaffold = scaffold_contract(tmp_path / "draft", "measured")
    assert scaffold["draft_executable"] is False
    draft = load_json_strict(tmp_path / "draft" / "contract-draft.json")
    assert isinstance(draft, dict) and draft["missing_decisions"]

    root, private, _ = _workspace(tmp_path)
    initial_id = GenerationStore(root).current_id()
    for name, value in _scientific_documents().items():
        _import(tmp_path, root, private, name, value)
    assert GenerationStore(root).current_id() != initial_id
    assert doctor_v3(root)["command_status"] == "ok"
    report = science_audit_v3(root)
    assert report["structural_organization_level"] == "L5", report
    assert report["collective_superintelligence_phase_inferred"] is False
    assert report["physical_phase_transition_inferred"] is False
    assert report["operational_acceleration"]["status"] == "unmeasured"

    protocol = {
        "schema_version": "0.3.0",
        "protocol_id": "protocol:test",
        "registered_at": "2026-01-01T00:00:00Z",
        "target_refs": ["target"],
        "comparison": "paired external comparison",
        "assignment": "externally preregistered assignment",
        "observation_window": {
            "start": "2026-01-02T00:00:00Z",
            "end": "2026-01-12T00:00:00Z",
        },
        "outcomes": [{"metric": "duration", "direction": "minimize", "unit": "second"}],
        "quality_floors": {"quality": {"quantity": "4/5", "unit": "score"}},
        "stopping_rule": "externally declared fixed stopping rule",
        "missing_data_policy": "externally declared complete-case policy",
        "analysis_method": "external time-uniform interval method",
        "evaluator_key_id": "key:test",
        "source_refs": ["evidence"],
    }
    signed_protocol = _signed(private, protocol, "measurement-protocol@0.3.0")
    protocol_path = tmp_path / "measurement-protocol.json"
    write_canonical(protocol_path, signed_protocol)
    assert (
        import_source_v3(
            protocol_path,
            root,
            "fixture",
            "measurement-protocol@0.3.0",
            apply=True,
        )["command_status"]
        == "ok"
    )
    result = {
        "schema_version": "0.3.0",
        "result_id": "result:test",
        "protocol_digest": digest_v3_json(signed_protocol),
        "dataset_digest": "sha256:" + "1" * 64,
        "analysis_executable_digest": "sha256:" + "2" * 64,
        "completed_at": "2026-01-13T00:00:00Z",
        "effect_intervals": [
            {
                "metric": "duration",
                "direction": "minimize",
                "lower": "-2",
                "upper": "-1",
                "unit": "second",
            }
        ],
        "quality_intervals": [
            {
                "metric": "quality",
                "direction": "maximize",
                "lower": "1",
                "upper": "1",
                "unit": "score",
            }
        ],
        "time_uniform": True,
        "assumptions": ["external method assumptions declared"],
        "source_refs": ["evidence"],
        "evaluator_key_id": "key:test",
    }
    _import(tmp_path, root, private, "trial-result-certificate", result)
    measured = science_audit_v3(root)
    assert (
        measured["operational_acceleration"]["status"] == "external_acceleration_bundle_compatible"
    )
    assert measured["operational_acceleration"]["causal_proof"] is False
    assert measured["structural_organization_level"] == "L5"

    # Cached flags are not authority. Changing them cannot alter recomputed truth.
    store = GenerationStore(root)
    manifest = store.load_manifest()
    record = deepcopy(manifest["projections"][0])
    receipt = store.get_json(record["receipt_digest"])
    assert isinstance(receipt, dict)
    receipt["cached_validation"] = {key: "false" for key in receipt["cached_validation"]}
    new_receipt_digest = store.put_json(receipt)
    for item in manifest["projections"]:
        if item["receipt_digest"] == record["receipt_digest"]:
            item["receipt_digest"] = new_receipt_digest
    manifest["receipts"] = sorted({*manifest["receipts"], new_receipt_digest})
    committed = store.commit(manifest, expected_current=store.current_id())
    assert committed["command_status"] == "ok"
    assert doctor_v3(root)["command_status"] == "ok"


def test_generation_commit_compare_and_swap(tmp_path: Path) -> None:
    root, _, _ = _workspace(tmp_path)
    store = GenerationStore(root)
    manifest = store.load_manifest()
    stale = str(manifest["generation_id"])
    manifest["analysis_epoch"] = "2026-01-16T00:00:00Z"
    first = store.commit(manifest, expected_current=stale)
    assert first["command_status"] == "ok"
    current = store.current_id()
    second = store.commit(manifest, expected_current=stale)
    assert second["failure_code"] == "concurrent_generation_comparison_failed"
    assert store.current_id() == current


def test_v3_schemas_are_closed() -> None:
    for name in schema_names("0.3.0"):
        schema = load_schema(name, "0.3.0")
        assert schema["unevaluatedProperties"] is False
    invalid = _contract()
    invalid["undeclared_authority"] = True
    errors = validation_errors("phase-contract", invalid, "0.3.0")
    assert any("Unevaluated properties" in item["message"] for item in errors)
    invalid_extension = _contract()
    invalid_extension["extensions"] = {"not-reverse-dns": True}
    errors = validation_errors("phase-contract", invalid_extension, "0.3.0")
    assert any(item["json_pointer"] == "/extensions" for item in errors)


def test_v3_resource_dominance() -> None:
    def candidate(change: str, unit: str = "token") -> dict[str, object]:
        report = {
            "guaranteed_addition_count": 1,
            "debt_count": 0,
            "resource_lower_changes": {"resource": change},
            "resource_units": {"resource": unit},
        }
        return {
            "branch_reports": {
                name: deepcopy(report) for name in ("success", "partial", "failure", "timeout")
            }
        }

    assert _dominates(candidate("0"), candidate("-1")) is True
    assert _dominates(candidate("0", "token"), candidate("-1", "second")) is False


def test_v3_independence_erosion() -> None:
    network = _scientific_documents()["transformation-network"]
    ledger = {
        "events": [
            {
                "event_id": "event:consume",
                "event_type": "consume",
                "principal_key_id": "key:test",
                "independence_domain": "domain:test",
                "artifact_digest": "sha256:" + "3" * 64,
                "occurred_at": SIGNED_AT,
            }
        ]
    }
    report = effective_independence(network, ledger, {"key:test"})
    assert report["status"] == "false"
    assert report["effective_domain_count"] == 0
    assert report["eroded_domains"] == ["domain:test"]


def test_contingent_planner_and_nonzero_exit_cannot_select_success(tmp_path: Path) -> None:
    root, private, _ = _workspace(tmp_path)
    documents = _scientific_documents()
    for name in ("transformation-network", "state-marking"):
        _import(tmp_path, root, private, name, documents[name])
    branch = {
        "must_add": ["target"],
        "may_add": [],
        "must_remove": [],
        "may_remove": [],
        "resource_intervals": {"resource": {"lower": "0", "upper": "0", "unit": "token"}},
        "debt": [],
        "rollback_obligations": [],
        "projection_possibilities": [],
    }
    effect = {
        "schema_version": "0.3.0",
        "effect_id": "effect:test",
        "branches": {
            name: deepcopy(branch) for name in ("success", "partial", "failure", "timeout")
        },
    }
    executable = Path(sys.executable).resolve()
    script = (
        "import json,sys;"
        "print(json.dumps({'schema_version':'0.3.0','action_id':'action:test','outcome':'success'}));"
        "sys.exit(7)"
    )
    capability = {
        "schema_version": "0.3.0",
        "capability_id": "capability:test",
        "adapter": "fixture",
        "operation": "test",
        "effect_class": "inspect",
        "executable": str(executable),
        "executable_digest": digest_bytes(executable.read_bytes()),
        "argv_prefix": [str(executable), "-c", script],
        "output_schema_ref": "adapter-output@0.3.0",
        "outcome_selector": {
            "source_pointer": "/outcome",
            "mapping": {
                "success": "success",
                "partial": "partial",
                "failure": "failure",
                "timeout": "timeout",
            },
        },
        "branch_effect_ref": "effect:test",
    }
    action = {
        "schema_version": "0.3.0",
        "action_id": "action:test",
        "capability_ref": "capability:test",
        "arguments": [],
        "input_refs": ["seed"],
        "required_authority_refs": ["authority"],
        "required_hazard_refs": [],
        "expires_at": "2026-12-31T00:00:00Z",
        "priority_class": 1,
    }
    for name, value in (
        ("branch-effect-contract", effect),
        ("adapter-capability", capability),
        ("action", action),
    ):
        _import(tmp_path, root, private, name, value)
    plan = plan_v3(root)
    assert plan["primary_action"]["action_id"] == "action:test"
    assert plan["solution_class"] == "approximate"
    assert plan["and_or_policy_trees"][0]["strong_target_policy"] is True
    result = run_action_v3(root, "action:test", apply=True)
    assert result["command_status"] == "ok"
    assert result["outcome"] == "failure"
    assert result["one_step_execution_limit"] == 1
    assert result["source_backed_post_state"] == "true"
