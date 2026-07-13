# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from collective_phase_control_fabric.canonical import digest_v3_json, write_canonical
from collective_phase_control_fabric.generation_v4 import GenerationStoreV4
from collective_phase_control_fabric.limits import LimitExceeded, loads_json_bounded
from collective_phase_control_fabric.schema import schema_names, validation_errors
from collective_phase_control_fabric.science_v4 import (
    intervention_analysis_v4,
    perturbation_replay_v4,
    science_audit_v4,
)
from collective_phase_control_fabric.trust_v4 import (
    key_fingerprint,
    protected_header,
    statement_message,
    validate_policy,
    verify_statement,
)
from collective_phase_control_fabric.workspace_v4 import (
    doctor_v4,
    import_attestation_v4,
    import_raw_v4,
    initialize_workspace_v4,
    workspace_version,
)

SCOPE = {"project": "v4-test"}
NOW = "2026-07-13T00:00:00Z"


def _key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _public(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _statement(
    key: Ed25519PrivateKey,
    payload: object,
    *,
    schema_ref: str,
    key_id: str,
    role: str,
    source_system: str,
    signed_at: str = NOW,
) -> dict[str, object]:
    protected = protected_header(
        payload,
        schema_ref=schema_ref,
        key_id=key_id,
        signed_at=signed_at,
        role=role,
        source_system=source_system,
        scope=SCOPE,
    )
    return {
        "schema_version": "0.4.0",
        "protected": protected,
        "payload": payload,
        "signature_base64": base64.b64encode(key.sign(statement_message(protected))).decode(),
    }


def _contract() -> dict[str, object]:
    return {
        "schema_version": "0.4.0",
        "contract_id": "contract:test",
        "scope": SCOPE,
        "target_states": ["state:seed"],
        "initial_available_states": [],
        "protected_floors": {},
        "resource_envelope": {},
        "control_policy": {
            "planning_horizon": 1,
            "beam_width": 32,
            "candidate_cap": 64,
            "retry_limit": 0,
        },
        "required_dimensions": ["provenance_integrity", "structural_reachability"],
        "perturbation_suite_refs": [],
        "analysis_limits": {
            "maximum_raw_bytes": 1_000_000,
            "maximum_json_depth": 32,
            "maximum_nodes": 100,
            "maximum_transformations": 100,
            "maximum_rational_bits": 256,
            "maximum_operations": 10_000,
            "solver_seconds": 5,
        },
        "non_claims": ["collective superintelligence inference"],
    }


def _policy(root: Ed25519PrivateKey, source: Ed25519PrivateKey) -> dict[str, object]:
    return {
        "schema_version": "0.4.0",
        "policy_id": "policy:test",
        "policy_sequence": 0,
        "previous_policy_digest": None,
        "root_key_id": "key:root",
        "principals": [
            {
                "principal_id": "principal:root",
                "key_id": "key:root",
                "public_key_base64": _public(root),
                "source_systems": ["clock", "author", "registry", "evaluator", "bundle"],
                "schema_names": [
                    "trusted-time-receipt",
                    "trust-policy",
                    "measurement-protocol",
                    "registration-receipt",
                    "trial-result-certificate",
                    "bundle-root-attestation",
                ],
                "roles": [
                    "workspace_root",
                    "timestamp",
                    "protocol_author",
                    "registration",
                    "evaluator",
                    "bundle_signer",
                ],
                "scope": SCOPE,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
            },
            {
                "principal_id": "principal:source",
                "key_id": "key:source",
                "public_key_base64": _public(source),
                "source_systems": ["local"],
                "schema_names": ["principal-attestation"],
                "roles": ["source"],
                "scope": SCOPE,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
            },
        ],
    }


def _workspace(
    tmp_path: Path, contract_override: dict[str, object] | None = None
) -> tuple[Path, Ed25519PrivateKey, dict[str, object]]:
    root = _key(1)
    source = _key(2)
    contract = contract_override or _contract()
    policy = _policy(root, source)
    receipt_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "time:test",
        "receipt_type": "trusted_time",
        "event_time": NOW,
        "subject_digest": digest_v3_json(contract),
        "serial": 1,
    }
    receipt = _statement(
        root,
        receipt_payload,
        schema_ref="trusted-time-receipt@0.4.0",
        key_id="key:root",
        role="timestamp",
        source_system="clock",
    )
    contract_path = tmp_path / "contract.json"
    policy_path = tmp_path / "trust.json"
    receipt_path = tmp_path / "time.json"
    write_canonical(contract_path, contract)
    write_canonical(policy_path, policy)
    write_canonical(receipt_path, receipt)
    workspace = tmp_path / "workspace"
    result = initialize_workspace_v4(
        contract_path,
        policy_path,
        workspace,
        key_fingerprint(_public(root)),
        receipt_path,
    )
    assert result["command_status"] == "ok"
    return workspace, source, policy


def _import_record(
    tmp_path: Path,
    workspace: Path,
    source: Ed25519PrivateKey,
    *,
    attestation_id: str,
    record_type: str,
    subject_id: str,
    attributes: dict[str, object],
    lineage_refs: list[str] | None = None,
    correlation_domains: list[str] | None = None,
) -> dict[str, str]:
    projected = {
        "record_type": record_type,
        "subject_id": subject_id,
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "lineage_refs": lineage_refs or [],
        "correlation_domains": correlation_domains or [],
        "attributes": attributes,
    }
    raw_path = tmp_path / f"{attestation_id.replace(':', '-')}-raw.json"
    write_canonical(raw_path, {"value": projected})
    imported = import_raw_v4(raw_path, workspace, "local", "typed-record@0.4.0", apply=True)
    assert imported["command_status"] == "ok"
    payload = {
        "schema_version": "0.4.0",
        "attestation_id": attestation_id,
        **projected,
        "subject_digest": digest_v3_json(projected),
        "source_artifact_digest": imported["raw_digest"],
        "source_pointer": "/value",
    }
    statement = _statement(
        source,
        payload,
        schema_ref="principal-attestation@0.4.0",
        key_id="key:source",
        role="source",
        source_system="local",
    )
    statement_path = tmp_path / f"{attestation_id.replace(':', '-')}.json"
    write_canonical(statement_path, statement)
    result = import_attestation_v4(statement_path, workspace, apply=True)
    assert result["command_status"] == "ok", result
    return {
        "attestation_id": attestation_id,
        "subject_digest": digest_v3_json(projected),
        "raw_digest": str(imported["raw_digest"]),
    }


def test_v4_schema_surface_is_closed_and_complete() -> None:
    names = set(schema_names("0.4.0"))
    assert {
        "signed-statement",
        "trusted-time-receipt",
        "principal-attestation",
        "workspace-generation",
        "process-receipt",
        "intervention-portfolio",
        "trial-result-certificate",
    } <= names
    payload = {
        "schema_version": "0.4.0",
        "attestation_id": "a",
        "record_type": "state",
        "subject_id": "s",
        "subject_digest": "sha256:" + "0" * 64,
        "source_artifact_digest": "sha256:" + "1" * 64,
        "source_pointer": "",
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "lineage_refs": [],
        "correlation_domains": [],
        "attributes": {"available": True, "embedded_witness": {}},
    }
    assert validation_errors("principal-attestation", payload, "0.4.0")


def test_protected_signature_metadata_cannot_be_rewritten() -> None:
    root, source = _key(1), _key(2)
    policy = _policy(root, source)
    payload = {"value": "evidence"}
    statement = _statement(
        source,
        payload,
        schema_ref="principal-attestation@0.4.0",
        key_id="key:source",
        role="source",
        source_system="local",
    )
    assert verify_statement(statement, policy, authoritative_time=NOW)["status"] == "true"
    for field, replacement in (
        ("key_id", "key:root"),
        ("signed_at", "2026-07-12T00:00:00Z"),
        ("role", "timestamp"),
        ("source_system", "clock"),
        ("schema_ref", "trusted-time-receipt@0.4.0"),
    ):
        forged = deepcopy(statement)
        forged["protected"][field] = replacement
        assert verify_statement(forged, policy, authoritative_time=NOW)["status"] == "false"


def test_policy_rejects_public_key_reuse() -> None:
    root, source = _key(1), _key(2)
    policy = _policy(root, source)
    policy["principals"][1]["public_key_base64"] = policy["principals"][0]["public_key_base64"]
    assert any("reused" in item["message"] for item in validate_policy(policy))


def test_bounded_parser_rejects_depth_before_materialization() -> None:
    value = b"[" * 65 + b"0" + b"]" * 65
    try:
        loads_json_bounded(value)
    except LimitExceeded as error:
        assert error.code == "maximum_json_depth_exceeded"
    else:
        raise AssertionError("deep input was accepted")


def test_attestation_must_reproduce_source_pointer(tmp_path: Path) -> None:
    workspace, source, _ = _workspace(tmp_path)
    projected = {
        "record_type": "state",
        "subject_id": "state:seed",
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "lineage_refs": [],
        "correlation_domains": [],
        "attributes": {"available": True},
    }
    raw = {"value": projected}
    raw_path = tmp_path / "raw.json"
    write_canonical(raw_path, raw)
    imported = import_raw_v4(raw_path, workspace, "local", "raw-state@0.4.0", apply=True)
    assert imported["command_status"] == "ok"
    raw_digest = imported["raw_digest"]
    payload = {
        "schema_version": "0.4.0",
        "attestation_id": "attestation:seed",
        "record_type": "state",
        "subject_id": "state:seed",
        "subject_digest": digest_v3_json(projected),
        "source_artifact_digest": raw_digest,
        "source_pointer": "/missing",
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "lineage_refs": [],
        "correlation_domains": [],
        "attributes": {"available": True},
    }
    forged = _statement(
        source,
        payload,
        schema_ref="principal-attestation@0.4.0",
        key_id="key:source",
        role="source",
        source_system="local",
    )
    attestation_path = tmp_path / "attestation.json"
    write_canonical(attestation_path, forged)
    rejected = import_attestation_v4(attestation_path, workspace, apply=True)
    assert rejected["failure_code"] == "attestation_source_chain_invalid"
    payload["source_pointer"] = "/value"
    accepted = _statement(
        source,
        payload,
        schema_ref="principal-attestation@0.4.0",
        key_id="key:source",
        role="source",
        source_system="local",
    )
    write_canonical(attestation_path, accepted)
    assert import_attestation_v4(attestation_path, workspace, apply=True)["command_status"] == "ok"
    assert doctor_v4(workspace)["command_status"] == "ok"
    audit = science_audit_v4(workspace)
    assert audit["operational_organization_profile"]["provenance_integrity"] == "satisfied"
    assert audit["operational_organization_profile"]["structural_reachability"] == "satisfied"
    assert workspace_version(workspace) == "0.4.0"


def test_full_profile_and_perturbation_share_one_audit_kernel(tmp_path: Path) -> None:
    contract = _contract()
    contract["target_states"] = ["state:target"]
    contract["protected_floors"] = {"energy": {"quantity": "1", "unit": "unit"}}
    contract["required_dimensions"] = [
        "provenance_integrity",
        "structural_reachability",
        "causal_formation",
        "exact_self_maintenance",
        "finite_resource_persistence",
        "target_bound_generative_catalysis",
        "verification_capacity",
        "effective_independence",
        "perturbation_robustness",
    ]
    contract["perturbation_suite_refs"] = ["suite:baseline"]
    workspace, source, _ = _workspace(tmp_path, contract)
    seed = _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:seed",
        record_type="state",
        subject_id="state:seed",
        attributes={"available": True},
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:catalyst",
        record_type="catalyst",
        subject_id="catalyst:one",
        attributes={},
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:authority",
        record_type="authority",
        subject_id="authority:run",
        attributes={},
    )
    transformation = _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:transform",
        record_type="transformation",
        subject_id="transform:one",
        attributes={
            "inputs": ["state:seed"],
            "outputs": ["state:target"],
            "authority_refs": ["authority:run"],
            "evidence_refs": [],
            "inhibitors": [],
            "catalyst_clauses": [["catalyst:one"]],
            "explicitly_uncatalyzed": False,
            "coordinate_flows": {"energy": "0"},
            "validated_boundary_supply_credit": "0",
        },
    )
    resource = _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:resource",
        record_type="resource_observation",
        subject_id="resource:energy",
        attributes={"coordinate": "energy", "quantity": "10", "unit": "unit"},
    )
    commitment = _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:commitment",
        record_type="evidence",
        subject_id="commitment:one",
        attributes={"evidence_type": "proposal_commitment"},
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:verifier",
        record_type="verifier",
        subject_id="verifier:one",
        attributes={
            "arrival_upper": "1",
            "service_lower": "2",
            "arrival_unit": "item/hour",
            "service_unit": "item/hour",
            "observation_window": {
                "start": "2026-07-01T00:00:00Z",
                "end": "2026-07-02T00:00:00Z",
            },
            "routing_amplification": "1",
            "independence_domain": "verifier-domain:one",
            "source_record_digest": seed["raw_digest"],
            "backlog_upper": "0",
        },
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:independence",
        record_type="independence",
        subject_id="independence:one",
        attributes={
            "observed_closed_boundary": True,
            "commitment_digest": commitment["subject_digest"],
            "observer_attestation_ref": "attestation:verifier",
            "infrastructure_domains": ["infrastructure:one"],
        },
        lineage_refs=["lineage:one"],
        correlation_domains=["correlation:one"],
    )
    base_generation = str(GenerationStoreV4(workspace).current_id())
    snapshot = digest_v3_json(
        {
            "analysis_base_generation_id": base_generation,
            "targets": ["state:target"],
            "transformations": [transformation["subject_digest"]],
            "markings": sorted([seed["subject_digest"], resource["subject_digest"]]),
        }
    )
    common = {
        "analysis_base_generation_id": base_generation,
        "analysis_snapshot_digest": snapshot,
    }
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:formation",
        record_type="evidence",
        subject_id="witness:formation",
        attributes={
            "evidence_type": "formation_sequence_witness",
            **common,
            "steps": [{"transformation_id": "transform:one", "multiplier": "1"}],
        },
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:organization",
        record_type="evidence",
        subject_id="witness:organization",
        attributes={
            "evidence_type": "organization_witness",
            **common,
            "flux": {"transform:one": "1"},
        },
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:rate",
        record_type="evidence",
        subject_id="witness:rate",
        attributes={
            "evidence_type": "rate_feasibility_witness",
            **common,
            "source_refs": ["attestation:seed"],
            "transformation_refs": ["transform:one"],
            "feasible_flux": {"transform:one": "1"},
            "rate_intervals": {"transform:one": {"lower": "1", "upper": "2", "unit": "item/hour"}},
            "observation_window": {
                "start": "2026-07-01T00:00:00Z",
                "end": "2026-07-02T00:00:00Z",
            },
        },
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:siphon",
        record_type="evidence",
        subject_id="witness:siphon",
        attributes={
            "evidence_type": "siphon_coverage_witness",
            **common,
            "covered_siphons": [["state:seed"]],
        },
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:resource-profile",
        record_type="evidence",
        subject_id="witness:resource-profile",
        attributes={
            "evidence_type": "open_system_resource_profile",
            **common,
            "balance_mode": "steady_state",
            "internal_coordinates": ["energy"],
            "boundary_coordinates": [],
            "potential_weights": {"energy": "1"},
        },
    )
    _import_record(
        tmp_path,
        workspace,
        source,
        attestation_id="attestation:suite",
        record_type="evidence",
        subject_id="suite:baseline",
        attributes={
            "evidence_type": "perturbation_suite",
            **common,
            "scenarios": [
                {"scenario_id": "scenario:none", "remove_subjects": [], "remove_key_ids": []}
            ],
            "acceptance_dimensions": contract["required_dimensions"][:-1],
        },
    )
    audit = science_audit_v4(workspace)
    assert audit["command_status"] == "ok"
    assert set(audit["operational_organization_profile"].values()) == {"satisfied"}
    assert audit["operational_organization_compatible"] is True
    assert audit["perturbation_results"][0]["failed_dimensions"] == []
    assert perturbation_replay_v4(workspace, "suite:baseline")["command_status"] == "ok"
    assert perturbation_replay_v4(workspace, "suite:missing")["failure_code"] == (
        "perturbation_suite_not_found"
    )
    intervention = intervention_analysis_v4(workspace)
    assert intervention["command_status"] == "ok"
    assert intervention["minimal_cut_sets"]["cut_sets"] == [["transform:one"]]
