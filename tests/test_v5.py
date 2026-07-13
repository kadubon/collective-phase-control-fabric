# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import subprocess
import sys
from copy import deepcopy
from fractions import Fraction
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from collective_phase_control_fabric.canonical import digest_v3_json, write_canonical
from collective_phase_control_fabric.cli import build_parser
from collective_phase_control_fabric.coordination_v5 import (
    coordination_commit_v5,
    coordination_init_v5,
    coordination_reveal_v5,
    coordination_route_v5,
    coordination_status_v5,
    coordination_terminate_v5,
)
from collective_phase_control_fabric.execution_v5 import (
    approve_projection_v5,
    pending_projections_v5,
    run_action_v5,
)
from collective_phase_control_fabric.generation_v5 import (
    GenerationStoreV5,
    history_event,
    ledger_entry,
)
from collective_phase_control_fabric.planner_v5 import plan_v5
from collective_phase_control_fabric.schema import load_schema, schema_names
from collective_phase_control_fabric.science_v5 import (
    analysis_snapshot_digest_v5,
    science_audit_v5,
    validate_typed_flow_profile,
)
from collective_phase_control_fabric.structural_v5 import (
    bounded_minimal_cut_sets,
    bounded_one_safe_occurrence_prefix,
    exact_flux_coupling,
    exact_nullspace,
)
from collective_phase_control_fabric.trials_v5 import (
    acceleration_status_v5,
    import_protocol_v5,
    import_result_v5,
)
from collective_phase_control_fabric.trust_v5 import (
    QUORUM_ROLES,
    key_fingerprint,
    protected_header,
    schema_digest,
    statement_message,
    verify_role_quorum,
    verify_statement,
)
from collective_phase_control_fabric.workspace_v5 import (
    MANDATORY_DIMENSIONS,
    active_attestations_v5,
    advance_time_v5,
    doctor_v5,
    import_raw_v5,
    import_signed_object_v5,
    initialize_workspace_v5,
    update_trust_policy_v5,
)

NOW = "2026-07-13T00:00:00Z"
SCOPE = {"project": "v5-test"}


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
    principal_id: str,
    role: str,
    source_system: str,
    signed_at: str = NOW,
) -> dict[str, object]:
    protected = protected_header(
        payload,
        schema_ref=schema_ref,
        key_id=key_id,
        principal_id=principal_id,
        signed_at=signed_at,
        role=role,
        source_system=source_system,
        scope=SCOPE,
    )
    return {
        "schema_version": "0.5.0",
        "protected": protected,
        "payload": payload,
        "signature_base64": base64.b64encode(key.sign(statement_message(protected))).decode(),
    }


def _principal(
    key: Ed25519PrivateKey,
    principal_id: str,
    key_id: str,
    roles: list[str],
    schemas: list[str],
    infrastructure: str,
) -> dict[str, object]:
    return {
        "principal_id": principal_id,
        "key_id": key_id,
        "public_key_base64": _public(key),
        "source_systems": [principal_id],
        "schema_names": schemas,
        "roles": roles,
        "scope": SCOPE,
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
        "revoked": False,
        "infrastructure_domains": [infrastructure],
        "correlation_domains": [],
        "revoked_at": None,
        "compromised_at": None,
    }


def _policy() -> tuple[dict[str, object], dict[str, Ed25519PrivateKey]]:
    names = (
        "root",
        "auditor",
        "time",
        "p1",
        "p2",
        "source",
        "protocol",
        "registration",
        "evaluator",
        "quality",
        "dataset",
        "analysis",
        "capability",
        "action",
        "projection",
    )
    keys = {name: _key(index) for index, name in enumerate(names, 1)}
    policy = {
        "schema_version": "0.5.0",
        "policy_id": "policy:test",
        "policy_sequence": 0,
        "previous_policy_digest": None,
        "root_key_id": "key:root",
        "principals": [
            _principal(
                keys["root"],
                "principal:root",
                "key:root",
                ["workspace_root"],
                ["trust-policy", "trust-quorum-decision"],
                "infra:root",
            ),
            _principal(
                keys["auditor"],
                "principal:auditor",
                "key:auditor",
                ["trust_auditor"],
                ["trust-quorum-decision"],
                "infra:auditor",
            ),
            _principal(
                keys["time"],
                "principal:time",
                "key:time",
                ["timestamp"],
                ["trusted-time-receipt", "trust-quorum-decision"],
                "infra:time",
            ),
            _principal(
                keys["p1"],
                "principal:p1",
                "key:p1",
                ["proposal_author"],
                ["proposal-commitment", "proposal-reveal"],
                "infra:p1",
            ),
            _principal(
                keys["p2"],
                "principal:p2",
                "key:p2",
                ["proposal_author", "source"],
                ["proposal-commitment", "proposal-reveal", "principal-attestation"],
                "infra:p2",
            ),
            _principal(
                keys["source"],
                "principal:source",
                "key:source",
                ["source"],
                ["principal-attestation", "typed-flow-profile"],
                "infra:source",
            ),
            _principal(
                keys["protocol"],
                "principal:protocol",
                "key:protocol",
                ["protocol_author"],
                ["measurement-protocol", "protocol-amendment"],
                "infra:protocol",
            ),
            _principal(
                keys["registration"],
                "principal:registration",
                "key:registration",
                ["registration"],
                ["registration-receipt"],
                "infra:registration",
            ),
            _principal(
                keys["evaluator"],
                "principal:evaluator",
                "key:evaluator",
                ["evaluator"],
                ["trial-result-certificate"],
                "infra:evaluator",
            ),
            _principal(
                keys["quality"],
                "principal:quality",
                "key:quality",
                ["quality_safety_verifier"],
                ["evidence-tier"],
                "infra:quality",
            ),
            _principal(
                keys["dataset"],
                "principal:dataset",
                "key:dataset",
                ["dataset_custodian"],
                ["dataset-record"],
                "infra:dataset",
            ),
            _principal(
                keys["analysis"],
                "principal:analysis",
                "key:analysis",
                ["analysis_author"],
                ["analysis-executable-record"],
                "infra:analysis",
            ),
            _principal(
                keys["capability"],
                "principal:capability",
                "key:capability",
                ["projection_authority"],
                ["principal-attestation"],
                "infra:capability",
            ),
            _principal(
                keys["action"],
                "principal:action",
                "key:action",
                ["action_author"],
                ["principal-attestation"],
                "infra:action",
            ),
            _principal(
                keys["projection"],
                "principal:projection",
                "key:projection",
                ["projection_verifier"],
                ["projection-approval"],
                "infra:projection",
            ),
        ],
        "quorum_rules": {name: list(roles) for name, roles in QUORUM_ROLES.items()},
    }
    return policy, keys


def _registry() -> dict[str, object]:
    return {
        "schema_version": "0.5.0",
        "registry_id": "units:test",
        "base_dimensions": ["amount", "time"],
        "units": {
            "unit": {"scale": "1", "dimension_vector": {"amount": 1}},
            "second": {"scale": "1", "dimension_vector": {"time": 1}},
            "action": {"scale": "1", "dimension_vector": {}},
        },
    }


def _contract(registry: dict[str, object]) -> dict[str, object]:
    from collective_phase_control_fabric.workspace_v5 import MANDATORY_DIMENSIONS

    return {
        "schema_version": "0.5.0",
        "contract_id": "contract:test",
        "scope": SCOPE,
        "target_states": ["state:target"],
        "initial_available_states": [],
        "protected_floors": {},
        "resource_envelope": {},
        "control_policy": {
            "planning_horizon": 1,
            "beam_width": 32,
            "candidate_cap": 64,
            "retry_limit": 0,
        },
        "required_dimensions": sorted(MANDATORY_DIMENSIONS),
        "perturbation_suite_refs": ["suite:required"],
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
        "unit_registry_ref": digest_v3_json(registry),
        "minimum_effective_independence": 2,
    }


def _workspace(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, Ed25519PrivateKey]]:
    policy, keys = _policy()
    registry = _registry()
    contract = _contract(registry)
    genesis = _statement(
        keys["root"],
        policy,
        schema_ref="trust-policy@0.5.0",
        key_id="key:root",
        principal_id="principal:root",
        role="workspace_root",
        source_system="principal:root",
    )
    time_payload = {
        "schema_version": "0.5.0",
        "receipt_id": "time:genesis",
        "receipt_type": "trusted_time",
        "event_time": NOW,
        "subject_digest": digest_v3_json(contract),
        "serial": 1,
    }
    time_receipt = _statement(
        keys["time"],
        time_payload,
        schema_ref="trusted-time-receipt@0.5.0",
        key_id="key:time",
        principal_id="principal:time",
        role="timestamp",
        source_system="principal:time",
    )
    paths = {}
    for name, value in {
        "contract": contract,
        "policy": policy,
        "genesis": genesis,
        "registry": registry,
        "time": time_receipt,
    }.items():
        paths[name] = tmp_path / f"{name}.json"
        write_canonical(paths[name], value)
    workspace = tmp_path / "workspace"
    result = initialize_workspace_v5(
        paths["contract"],
        paths["policy"],
        paths["genesis"],
        paths["registry"],
        workspace,
        key_fingerprint(_public(keys["root"])),
        paths["time"],
    )
    assert result["command_status"] == "ok", result
    return workspace, policy, keys


def _import_record_v5(
    tmp_path: Path,
    workspace: Path,
    key_value: Ed25519PrivateKey,
    signer: str,
    *,
    attestation_id: str,
    record_type: str,
    subject_id: str,
    attributes: dict[str, object],
    role: str = "source",
    lineage_refs: list[str] | None = None,
    correlation_domains: list[str] | None = None,
) -> str:
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
    stem = attestation_id.replace(":", "-")
    raw_path = tmp_path / f"{stem}-raw.json"
    write_canonical(raw_path, {"value": projected})
    raw_result = import_raw_v5(
        raw_path, workspace, f"principal:{signer}", "typed-record@0.5.0", apply=True
    )
    assert raw_result["command_status"] == "ok", raw_result
    payload = {
        "schema_version": "0.5.0",
        "attestation_id": attestation_id,
        **projected,
        "subject_digest": digest_v3_json(projected),
        "source_artifact_digest": raw_result["raw_digest"],
        "source_pointer": "/value",
    }
    statement = _statement(
        key_value,
        payload,
        schema_ref="principal-attestation@0.5.0",
        key_id=f"key:{signer}",
        principal_id=f"principal:{signer}",
        role=role,
        source_system=f"principal:{signer}",
    )
    path = tmp_path / f"{stem}.json"
    write_canonical(path, statement)
    imported = import_signed_object_v5(path, workspace, apply=True)
    assert imported["command_status"] == "ok", imported
    return digest_v3_json(statement)


def test_v5_protected_schema_and_identity_metadata_are_signed() -> None:
    policy, keys = _policy()
    payload = {
        "schema_version": "0.5.0",
        "decision_id": "decision:test",
        "decision_type": "trust_update",
        "subject_digest": "sha256:" + "1" * 64,
        "policy_sequence": 0,
        "trusted_time_receipt_digest": "sha256:" + "2" * 64,
    }
    statement = _statement(
        keys["root"],
        payload,
        schema_ref="trust-quorum-decision@0.5.0",
        key_id="key:root",
        principal_id="principal:root",
        role="workspace_root",
        source_system="principal:root",
    )
    assert verify_statement(statement, policy, authoritative_time=NOW)["status"] == "true"
    for field, replacement in (
        ("principal_id", "principal:auditor"),
        ("canonicalization_profile", "different"),
        ("schema_digest", "sha256:" + "0" * 64),
        ("key_id", "key:auditor"),
    ):
        forged = deepcopy(statement)
        forged["protected"][field] = replacement
        assert verify_statement(forged, policy, authoritative_time=NOW)["status"] == "false"


def test_v5_every_declared_object_schema_node_is_closed() -> None:
    def visit(value: object) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("unevaluatedProperties") is False
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    for name in schema_names("0.5.0"):
        visit(load_schema(name, "0.5.0"))


def test_v5_disjoint_role_quorum_rejects_role_reuse() -> None:
    policy, keys = _policy()
    payload = {
        "schema_version": "0.5.0",
        "decision_id": "decision:update",
        "decision_type": "trust_update",
        "subject_digest": "sha256:" + "a" * 64,
        "policy_sequence": 0,
        "trusted_time_receipt_digest": "sha256:" + "b" * 64,
    }
    statements = [
        _statement(
            keys[name],
            payload,
            schema_ref="trust-quorum-decision@0.5.0",
            key_id=f"key:{name}",
            principal_id=f"principal:{name}",
            role=role,
            source_system=f"principal:{name}",
        )
        for name, role in (
            ("root", "workspace_root"),
            ("auditor", "trust_auditor"),
            ("time", "timestamp"),
        )
    ]
    assert (
        verify_role_quorum(
            statements,
            policy,
            decision_type="trust_update",
            authoritative_time=NOW,
            subject_digest=payload["subject_digest"],
        )["status"]
        == "true"
    )
    reused = [statements[0], statements[0], statements[2]]
    assert (
        verify_role_quorum(
            reused,
            policy,
            decision_type="trust_update",
            authoritative_time=NOW,
            subject_digest=payload["subject_digest"],
        )["status"]
        == "false"
    )


def test_v5_trust_update_preserves_historical_authority_policy(tmp_path: Path) -> None:
    workspace, policy, keys = _workspace(tmp_path)
    store = GenerationStoreV5(workspace)
    manifest = store.load_manifest()
    new_policy = deepcopy(policy)
    new_policy["policy_sequence"] = 1
    new_policy["previous_policy_digest"] = manifest["trust_policy_digest"]
    new_policy_digest = digest_v3_json(new_policy)
    later = "2026-07-14T00:00:00Z"
    time_receipt = _statement(
        keys["time"],
        {
            "schema_version": "0.5.0",
            "receipt_id": "time:trust-update",
            "receipt_type": "trusted_time",
            "event_time": later,
            "subject_digest": new_policy_digest,
            "serial": 2,
        },
        schema_ref="trusted-time-receipt@0.5.0",
        key_id="key:time",
        principal_id="principal:time",
        role="timestamp",
        source_system="principal:time",
        signed_at=later,
    )
    time_digest = digest_v3_json(time_receipt)
    decision = {
        "schema_version": "0.5.0",
        "decision_id": "decision:trust-update",
        "decision_type": "trust_update",
        "subject_digest": new_policy_digest,
        "policy_sequence": 0,
        "trusted_time_receipt_digest": time_digest,
    }
    statements = [
        _statement(
            keys[name],
            decision,
            schema_ref="trust-quorum-decision@0.5.0",
            key_id=f"key:{name}",
            principal_id=f"principal:{name}",
            role=role,
            source_system=f"principal:{name}",
            signed_at=later,
        )
        for name, role in (
            ("root", "workspace_root"),
            ("auditor", "trust_auditor"),
            ("time", "timestamp"),
        )
    ]
    policy_path = tmp_path / "new-policy.json"
    time_path = tmp_path / "trust-time.json"
    write_canonical(policy_path, new_policy)
    write_canonical(time_path, time_receipt)
    statement_paths: list[Path] = []
    for index, statement in enumerate(statements):
        path = tmp_path / f"quorum-{index}.json"
        write_canonical(path, statement)
        statement_paths.append(path)
    updated = update_trust_policy_v5(
        workspace,
        policy_path,
        time_path,
        statement_paths,
        apply=True,
    )
    assert updated["command_status"] == "ok", updated
    assert doctor_v5(workspace)["command_status"] == "ok"


def test_v5_workspace_genesis_and_complete_doctor(tmp_path: Path) -> None:
    workspace, _, _ = _workspace(tmp_path)
    audit = doctor_v5(workspace)
    assert audit["command_status"] == "ok", audit
    assert audit["claims"] == ["complete_typed_ledger_reference_closure"]
    store = GenerationStoreV5(workspace)
    assert store.verify_chain() == []
    store.current_path.write_text("sha256:../../escape\n", encoding="ascii")
    assert doctor_v5(workspace)["failure_code"] == "workspace_generation_invalid"


def test_v5_exact_typed_flow_checks_every_prefix_and_fed_siphon() -> None:
    registry = _registry()
    snapshot = "sha256:" + "3" * 64
    profile = {
        "schema_version": "0.5.0",
        "profile_id": "flow:test",
        "analysis_snapshot_digest": snapshot,
        "unit_registry_digest": digest_v3_json(registry),
        "horizon_steps": 2,
        "step_duration": "1",
        "time_unit": "second",
        "coordinates": {"resource": {"unit": "unit", "initial": "2", "protected_floor": "0"}},
        "transformations": {"consume": {"flow": {"resource": "-1"}, "action_unit": "action"}},
        "action_counts": [{"consume": "1"}, {"consume": "1"}],
        "boundary_rates": [{}, {}],
        "fed_siphons": [
            {
                "coordinates": ["resource"],
                "coverage": "initially_marked",
                "source_refs": ["source:resource"],
            }
        ],
    }
    checked = validate_typed_flow_profile(
        profile, registry, live_source_ids={"source:resource"}, snapshot=snapshot
    )
    assert checked["status"] == "satisfied", checked
    broken = deepcopy(profile)
    broken["action_counts"][1]["consume"] = "2"
    violated = validate_typed_flow_profile(
        broken, registry, live_source_ids={"source:resource"}, snapshot=snapshot
    )
    assert violated["status"] == "violated"
    assert any("prefix_floor_violation" in item for item in violated["reasons"])


def test_v5_shared_science_kernel_can_satisfy_a_complete_declared_profile(
    tmp_path: Path,
) -> None:
    workspace, _, keys = _workspace(tmp_path)
    source = keys["source"]
    state_projected = {
        "record_type": "state",
        "subject_id": "state:seed",
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "lineage_refs": [],
        "correlation_domains": [],
        "attributes": {"available": True},
    }
    state_subject_digest = digest_v3_json(state_projected)
    _import_record_v5(
        tmp_path,
        workspace,
        source,
        "source",
        attestation_id="attestation:state",
        record_type="state",
        subject_id="state:seed",
        attributes={"available": True},
    )
    _import_record_v5(
        tmp_path,
        workspace,
        source,
        "source",
        attestation_id="attestation:transformation",
        record_type="transformation",
        subject_id="transformation:produce",
        attributes={
            "inputs": ["state:seed"],
            "outputs": ["state:target"],
            "authority_refs": [],
            "evidence_refs": [],
            "inhibitors": [],
            "catalyst_clauses": [],
            "explicitly_uncatalyzed": True,
            "coordinate_flows": {"resource": "0"},
        },
    )
    _import_record_v5(
        tmp_path,
        workspace,
        source,
        "source",
        attestation_id="attestation:verifier",
        record_type="verifier",
        subject_id="verifier:stage",
        attributes={
            "arrival_upper": "1",
            "service_lower": "2",
            "arrival_unit": "item/second",
            "service_unit": "item/second",
            "routing_amplification": "1",
            "source_record_digest": state_subject_digest,
            "source_refs": ["state:seed"],
        },
    )
    for signer, observer in (
        ("source", "attestation:independence-p2"),
        ("p2", "attestation:independence-source"),
    ):
        _import_record_v5(
            tmp_path,
            workspace,
            keys[signer],
            signer,
            attestation_id=f"attestation:independence-{signer}",
            record_type="independence",
            subject_id=f"independence:{signer}",
            attributes={
                "observer_attestation_ref": observer,
                "commitment_digest": "sha256:" + ("1" if signer == "source" else "2") * 64,
                "infrastructure_domains": [f"independence-infrastructure:{signer}"],
            },
        )
    _import_record_v5(
        tmp_path,
        workspace,
        source,
        "source",
        attestation_id="attestation:suite",
        record_type="evidence",
        subject_id="suite:required",
        attributes={
            "evidence_type": "perturbation_suite",
            "scenarios": [{"scenario_id": "control", "remove_subjects": [], "remove_key_ids": []}],
            "acceptance_dimensions": sorted(MANDATORY_DIMENSIONS - {"perturbation_robustness"}),
        },
    )
    store = GenerationStoreV5(workspace)
    manifest = store.load_manifest()
    plan = {
        "schema_version": "0.5.0",
        "plan_id": "plan:completed",
        "participant_principals": ["principal:p1", "principal:p2"],
        "verifier_stage_refs": ["verifier:stage"],
        "maximum_exposure_events": 0,
        "termination_rule": "all_verified",
    }
    plan_digest = store.put_json(plan)
    session = {
        "schema_version": "0.5.0",
        "session_id": "session:completed",
        "state": "TERMINATED",
        "plan_digest": plan_digest,
        "participant_principals": ["principal:p1", "principal:p2"],
        "commitments": {
            "principal:p1": "sha256:" + "3" * 64,
            "principal:p2": "sha256:" + "4" * 64,
        },
        "reveals": {
            "principal:p1": "sha256:" + "5" * 64,
            "principal:p2": "sha256:" + "6" * 64,
        },
        "exposure_event_digests": [],
        "verification_capacity_satisfied": True,
        "termination_reason": "all_verified",
    }
    session_digest = store.put_json(session)
    generation_payload = deepcopy(manifest)
    generation_payload["objects"] = [
        *generation_payload["objects"],
        ledger_entry(plan_digest, kind="coordination-plan", schema_ref="coordination-plan@0.5.0"),
        ledger_entry(
            session_digest,
            kind="coordination-session",
            schema_ref="coordination-session@0.5.0",
            source_chain=[plan_digest],
        ),
    ]
    history = generation_payload["history"]
    generation_payload["history"] = [
        *history,
        history_event(
            history,
            event_id="history:completed-session",
            event_type="coordination_transition",
            subject_digests=[plan_digest, session_digest],
        ),
    ]
    committed = store.commit(generation_payload, expected_current=str(manifest["generation_id"]))
    assert committed["command_status"] == "ok"
    manifest, contract, statements, _ = active_attestations_v5(workspace)
    snapshot = analysis_snapshot_digest_v5(manifest, contract, statements)
    _import_record_v5(
        tmp_path,
        workspace,
        source,
        "source",
        attestation_id="attestation:organization",
        record_type="evidence",
        subject_id="witness:organization",
        attributes={
            "evidence_type": "organization_witness",
            "analysis_snapshot_digest": snapshot,
            "transformation_refs": ["transformation:produce"],
            "feasible_flux": {"transformation:produce": "1"},
        },
    )
    registry = _registry()
    flow_profile = {
        "schema_version": "0.5.0",
        "profile_id": "flow:complete",
        "analysis_snapshot_digest": snapshot,
        "unit_registry_digest": digest_v3_json(registry),
        "horizon_steps": 1,
        "step_duration": "1",
        "time_unit": "second",
        "coordinates": {"resource": {"unit": "unit", "initial": "1", "protected_floor": "0"}},
        "transformations": {
            "transformation:produce": {
                "flow": {"resource": "0"},
                "action_unit": "action",
            }
        },
        "action_counts": [{"transformation:produce": "1"}],
        "boundary_rates": [{}],
        "fed_siphons": [
            {
                "coordinates": ["resource"],
                "coverage": "initially_marked",
                "source_refs": ["state:seed"],
            }
        ],
    }
    flow_statement = _statement(
        source,
        flow_profile,
        schema_ref="typed-flow-profile@0.5.0",
        key_id="key:source",
        principal_id="principal:source",
        role="source",
        source_system="principal:source",
    )
    flow_path = tmp_path / "flow-profile.json"
    write_canonical(flow_path, flow_statement)
    assert import_signed_object_v5(flow_path, workspace, apply=True)["command_status"] == "ok"
    audit = science_audit_v5(workspace)
    assert audit["operational_organization_compatible"] is True, audit
    assert set(audit["operational_organization_profile"].values()) == {"satisfied"}


def test_v5_cli_exposes_native_operational_commands() -> None:
    parser = build_parser()
    assert (
        parser.parse_args(
            ["execution", "inspect-risk", "--workspace", "workspace", "--json"]
        ).command
        == "inspect-risk"
    )
    assert (
        parser.parse_args(["projection", "pending", "--workspace", "workspace", "--json"]).command
        == "pending"
    )
    assert (
        parser.parse_args(
            [
                "coordination",
                "terminate",
                "--workspace",
                "workspace",
                "--session",
                "session:test",
                "--reason",
                "explicit_failure",
                "--apply",
                "--json",
            ]
        ).command
        == "terminate"
    )


def test_v5_exact_structural_diagnostics_and_occurrence_conflict() -> None:
    basis = exact_nullspace(
        [
            [Fraction(-1), Fraction(1), Fraction(0)],
            [Fraction(0), Fraction(-1), Fraction(1)],
        ]
    )
    assert basis == [[Fraction(1), Fraction(1), Fraction(1)]]
    transformations = {
        "left": {
            "inputs": ["seed"],
            "outputs": ["left-output"],
            "coordinate_flows": {"resource": "-1"},
        },
        "right": {
            "inputs": ["seed"],
            "outputs": ["right-output"],
            "coordinate_flows": {"resource": "1"},
        },
    }
    coupling = exact_flux_coupling(transformations, ["resource"])
    assert coupling["fully_coupled_classes"] == [["left", "right"]]
    cuts = bounded_minimal_cut_sets(
        {"seed"},
        transformations,
        {"left-output"},
        maximum_cut_size=1,
        operation_budget=10,
    )
    assert cuts["minimal_cut_sets"] == [["left"]]
    prefix = bounded_one_safe_occurrence_prefix({"seed"}, transformations, operation_budget=20)
    assert len(prefix["events"]) == 2
    assert len(prefix["conflicts"]) == 1


def test_v5_coordination_enforces_commit_reveal_and_explicit_termination(
    tmp_path: Path,
) -> None:
    workspace, _, keys = _workspace(tmp_path)
    plan_path = tmp_path / "coordination-plan.json"
    write_canonical(
        plan_path,
        {
            "schema_version": "0.5.0",
            "plan_id": "plan:test",
            "participant_principals": ["principal:p1", "principal:p2"],
            "verifier_stage_refs": ["verifier:required"],
            "maximum_exposure_events": 0,
            "termination_rule": "capacity_blocked",
        },
    )
    initialized = coordination_init_v5(workspace, plan_path, apply=True)
    assert initialized["coordination_state"] == "CREATED"
    session_id = str(initialized["session_id"])
    proposals = {
        "p1": ({"answer": "one"}, "nonce-000000000001"),
        "p2": ({"answer": "two"}, "nonce-000000000002"),
    }
    for name, (proposal, nonce) in proposals.items():
        commitment_payload = {
            "schema_version": "0.5.0",
            "commitment_id": f"commitment:{name}",
            "session_id": session_id,
            "participant_principal_id": f"principal:{name}",
            "commitment_digest": digest_v3_json({"proposal": proposal, "nonce": nonce}),
            "committed_at": NOW,
        }
        path = tmp_path / f"commitment-{name}.json"
        write_canonical(
            path,
            _statement(
                keys[name],
                commitment_payload,
                schema_ref="proposal-commitment@0.5.0",
                key_id=f"key:{name}",
                principal_id=f"principal:{name}",
                role="proposal_author",
                source_system=f"principal:{name}",
            ),
        )
        assert (
            coordination_commit_v5(workspace, session_id, path, apply=True)["command_status"]
            == "ok"
        )
    assert (
        coordination_route_v5(workspace, session_id, apply=True)["coordination_state"]
        == "COMMIT_CLOSED"
    )
    assert (
        coordination_route_v5(workspace, session_id, apply=True)["coordination_state"]
        == "REVEAL_OPEN"
    )
    for name, (proposal, nonce) in proposals.items():
        reveal_payload = {
            "schema_version": "0.5.0",
            "reveal_id": f"reveal:{name}",
            "session_id": session_id,
            "participant_principal_id": f"principal:{name}",
            "proposal": proposal,
            "nonce": nonce,
            "revealed_at": NOW,
        }
        path = tmp_path / f"reveal-{name}.json"
        write_canonical(
            path,
            _statement(
                keys[name],
                reveal_payload,
                schema_ref="proposal-reveal@0.5.0",
                key_id=f"key:{name}",
                principal_id=f"principal:{name}",
                role="proposal_author",
                source_system=f"principal:{name}",
            ),
        )
        assert (
            coordination_reveal_v5(workspace, session_id, path, apply=True)["command_status"]
            == "ok"
        )
    assert (
        coordination_route_v5(workspace, session_id, apply=True)["coordination_state"] == "VERIFY"
    )
    assert (
        coordination_route_v5(workspace, session_id, apply=True)["failure_code"]
        == "coordination_verification_capacity_blocked"
    )
    assert (
        coordination_terminate_v5(workspace, session_id, reason="capacity_blocked", apply=True)[
            "coordination_state"
        ]
        == "TERMINATED"
    )
    assert coordination_status_v5(workspace)["incomplete_sessions"] == []


def test_v5_randomized_evidence_requires_typed_artifacts_and_quality_quorum(
    tmp_path: Path,
) -> None:
    workspace, _, keys = _workspace(tmp_path)
    raw_dataset = tmp_path / "dataset.bin"
    raw_analysis = tmp_path / "analysis.bin"
    raw_dataset.write_bytes(b"tutorial dataset")
    raw_analysis.write_bytes(b"tutorial analysis executable")
    dataset_raw_digest = import_raw_v5(
        raw_dataset, workspace, "dataset", "binary@0.5.0", apply=True
    )["raw_digest"]
    analysis_raw_digest = import_raw_v5(
        raw_analysis, workspace, "analysis", "binary@0.5.0", apply=True
    )["raw_digest"]
    dataset_statement = _statement(
        keys["dataset"],
        {
            "schema_version": "0.5.0",
            "dataset_id": "dataset:test",
            "raw_digest": dataset_raw_digest,
            "acquisition_commitment_digest": dataset_raw_digest,
            "source_record_digests": [dataset_raw_digest],
        },
        schema_ref="dataset-record@0.5.0",
        key_id="key:dataset",
        principal_id="principal:dataset",
        role="dataset_custodian",
        source_system="principal:dataset",
    )
    analysis_statement = _statement(
        keys["analysis"],
        {
            "schema_version": "0.5.0",
            "executable_id": "analysis:test",
            "executable_digest": analysis_raw_digest,
            "specification_digest": analysis_raw_digest,
            "capability_attestation_digest": analysis_raw_digest,
        },
        schema_ref="analysis-executable-record@0.5.0",
        key_id="key:analysis",
        principal_id="principal:analysis",
        role="analysis_author",
        source_system="principal:analysis",
    )
    dataset_path = tmp_path / "dataset-record.json"
    analysis_path = tmp_path / "analysis-record.json"
    write_canonical(dataset_path, dataset_statement)
    write_canonical(analysis_path, analysis_statement)
    assert import_signed_object_v5(dataset_path, workspace, apply=True)["command_status"] == "ok"
    assert import_signed_object_v5(analysis_path, workspace, apply=True)["command_status"] == "ok"
    dataset_digest = digest_v3_json(dataset_statement)
    analysis_digest = digest_v3_json(analysis_statement)
    protocol_payload = {
        "schema_version": "0.5.0",
        "protocol_id": "protocol:test",
        "primary_result_id": "result:primary",
        "eligibility": {
            "population_ref": "population:test",
            "inclusion_rules": ["eligible"],
            "exclusion_rules": [],
        },
        "treatment_strategy": {"strategy_id": "strategy:cpcf"},
        "comparison_strategy": {"strategy_id": "strategy:control"},
        "assignment": {
            "method": "randomized",
            "assignment_unit": "collective",
            "specification_digest": "sha256:" + "1" * 64,
        },
        "time_zero": "2026-08-01T00:00:00Z",
        "observation_end": "2026-10-01T00:00:00Z",
        "estimand": {
            "population": "eligible",
            "contrast": "treatment-minus-control",
            "summary_measure": "difference",
        },
        "primary_outcomes": [
            {
                "outcome_id": "throughput",
                "direction": "increase",
                "unit": "task",
                "minimum_effect": "1",
                "multiplicity_group": "primary",
            }
        ],
        "dataset_commitment_digest": dataset_digest,
        "analysis_executable_digest": analysis_digest,
        "quality_floors": {},
        "safety_floors": {},
        "missing_data_policy": {},
        "stopping_rule": {},
        "exclusion_policy": {},
        "amendment_policy": {},
        "evaluator_key_id": "key:evaluator",
        "registration_key_id": "key:registration",
        "design_tier": "randomized",
        "multiplicity_policy": {"method": "single-primary", "family_count": 1},
    }
    protocol = _statement(
        keys["protocol"],
        protocol_payload,
        schema_ref="measurement-protocol@0.5.0",
        key_id="key:protocol",
        principal_id="principal:protocol",
        role="protocol_author",
        source_system="principal:protocol",
    )
    protocol_digest = digest_v3_json(protocol)
    registration_time_payload = {
        "schema_version": "0.5.0",
        "receipt_id": "time:registration",
        "receipt_type": "trusted_time",
        "event_time": NOW,
        "subject_digest": protocol_digest,
        "serial": 10,
    }
    registration_time = _statement(
        keys["time"],
        registration_time_payload,
        schema_ref="trusted-time-receipt@0.5.0",
        key_id="key:time",
        principal_id="principal:time",
        role="timestamp",
        source_system="principal:time",
    )
    registration = _statement(
        keys["registration"],
        {
            "schema_version": "0.5.0",
            "receipt_id": "registration:test",
            "protocol_digest": protocol_digest,
            "registered_at": NOW,
            "serial": 1,
            "trusted_time_receipt_digest": digest_v3_json(registration_time),
        },
        schema_ref="registration-receipt@0.5.0",
        key_id="key:registration",
        principal_id="principal:registration",
        role="registration",
        source_system="principal:registration",
    )
    protocol_path = tmp_path / "protocol.json"
    registration_path = tmp_path / "registration.json"
    registration_time_path = tmp_path / "registration-time.json"
    write_canonical(protocol_path, protocol)
    write_canonical(registration_path, registration)
    write_canonical(registration_time_path, registration_time)
    imported_protocol = import_protocol_v5(
        protocol_path,
        registration_path,
        registration_time_path,
        workspace,
        apply=True,
    )
    assert imported_protocol["command_status"] == "ok", imported_protocol
    current = GenerationStoreV5(workspace).current_id()
    assert current is not None
    later = "2026-12-01T00:00:00Z"
    later_receipt = _statement(
        keys["time"],
        {
            "schema_version": "0.5.0",
            "receipt_id": "time:later",
            "receipt_type": "trusted_time",
            "event_time": later,
            "subject_digest": current,
            "serial": 20,
        },
        schema_ref="trusted-time-receipt@0.5.0",
        key_id="key:time",
        principal_id="principal:time",
        role="timestamp",
        source_system="principal:time",
        signed_at=later,
    )
    later_path = tmp_path / "later-time.json"
    write_canonical(later_path, later_receipt)
    assert advance_time_v5(workspace, later_path, apply=True)["command_status"] == "ok"
    result_statement = _statement(
        keys["evaluator"],
        {
            "schema_version": "0.5.0",
            "result_id": "result:primary",
            "protocol_id": "protocol:test",
            "protocol_digest": protocol_digest,
            "dataset_digest": dataset_digest,
            "analysis_executable_digest": analysis_digest,
            "observation_started_at": "2026-08-01T00:00:01Z",
            "observation_ended_at": "2026-09-30T00:00:00Z",
            "completed_at": "2026-10-02T00:00:00Z",
            "effect_intervals": {
                "throughput": {
                    "lower": "2",
                    "upper": "3",
                    "unit": "task",
                    "estimand_status": "supported",
                }
            },
            "quality_intervals": {},
            "safety_intervals": {},
            "amendment_chain_digest": None,
        },
        schema_ref="trial-result-certificate@0.5.0",
        key_id="key:evaluator",
        principal_id="principal:evaluator",
        role="evaluator",
        source_system="principal:evaluator",
        signed_at="2026-10-03T00:00:00Z",
    )
    result_path = tmp_path / "result.json"
    write_canonical(result_path, result_statement)
    imported_result = import_result_v5(result_path, workspace, apply=True)
    assert imported_result["command_status"] == "ok", imported_result
    assert acceleration_status_v5(workspace)["acceleration_status"] == (
        "externally_observed_inconclusive"
    )
    result_digest = digest_v3_json(result_statement)
    evidence = _statement(
        keys["quality"],
        {
            "schema_version": "0.5.0",
            "protocol_id": "protocol:test",
            "tier": "preregistered_randomized_acceleration_bundle_compatible",
            "result_digest": result_digest,
            "quality_safety_status": "preserved",
        },
        schema_ref="evidence-tier@0.5.0",
        key_id="key:quality",
        principal_id="principal:quality",
        role="quality_safety_verifier",
        source_system="principal:quality",
        signed_at="2026-10-04T00:00:00Z",
    )
    evidence_path = tmp_path / "evidence-tier.json"
    write_canonical(evidence_path, evidence)
    assert import_signed_object_v5(evidence_path, workspace, apply=True)["command_status"] == "ok"
    compatible = acceleration_status_v5(workspace)
    assert compatible["acceleration_status"] == "external_acceleration_bundle_compatible"
    assert doctor_v5(workspace)["command_status"] == "ok"


def test_v5_tutorial_generates_a_root_authenticated_workspace(tmp_path: Path) -> None:
    assets = tmp_path / "tutorial-assets"
    subprocess.run(
        [
            sys.executable,
            "docs/tutorial-v0.5/generate.py",
            "--out",
            str(assets),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    workspace = tmp_path / "tutorial-workspace"
    result = initialize_workspace_v5(
        assets / "phase-contract.json",
        assets / "trust-policy.json",
        assets / "genesis.json",
        assets / "unit-registry.json",
        workspace,
        (assets / "ROOT_FINGERPRINT.txt").read_text(encoding="ascii").strip(),
        assets / "trusted-time.json",
    )
    assert result["command_status"] == "ok", result
    assert doctor_v5(workspace)["command_status"] == "ok"
    for filename, schema_ref in (
        ("adapter-runtime.exe" if sys.platform == "win32" else "adapter-runtime", "binary@0.5.0"),
        ("capability-raw.json", "typed-record@0.5.0"),
        ("action-raw.json", "typed-record@0.5.0"),
    ):
        imported = import_raw_v5(assets / filename, workspace, "tutorial", schema_ref, apply=True)
        assert imported["command_status"] == "ok", imported
    for filename in ("capability-attestation.json", "action-attestation.json"):
        imported = import_signed_object_v5(assets / filename, workspace, apply=True)
        assert imported["command_status"] == "ok", imported
    planned = plan_v5(workspace)
    assert planned["pareto_alternatives"][0]["action_id"] == "action:tutorial"
    missing_ack = run_action_v5(workspace, "action:tutorial", apply=True, risk_acknowledgement=None)
    assert missing_ack["failure_code"] == "unsandboxed_execution_risk_acknowledgement_required"
    executed = run_action_v5(
        workspace,
        "action:tutorial",
        apply=True,
        risk_acknowledgement="UNSANDBOXED_LOCAL_EXECUTION",
    )
    assert executed["command_status"] == "ok", executed
    assert executed["outcome"] == "success"
    assert doctor_v5(workspace)["command_status"] == "ok"


def test_v5_pending_projection_requires_exact_reconstruction_and_disjoint_approval(
    tmp_path: Path,
) -> None:
    workspace, _, keys = _workspace(tmp_path)
    target_projected = {
        "record_type": "state",
        "subject_id": "state:target",
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "lineage_refs": ["lineage:target"],
        "correlation_domains": [],
        "attributes": {"available": True},
    }
    target_raw_path = tmp_path / "target-raw.json"
    write_canonical(target_raw_path, {"value": target_projected})
    target_raw = import_raw_v5(
        target_raw_path, workspace, "principal:source", "typed-record@0.5.0", apply=True
    )
    target_statement = _statement(
        keys["source"],
        {
            "schema_version": "0.5.0",
            "attestation_id": "attestation:target",
            **target_projected,
            "subject_digest": digest_v3_json(target_projected),
            "source_artifact_digest": target_raw["raw_digest"],
            "source_pointer": "/value",
        },
        schema_ref="principal-attestation@0.5.0",
        key_id="key:source",
        principal_id="principal:source",
        role="source",
        source_system="principal:source",
    )
    runtime = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    runtime_import = import_raw_v5(runtime, workspace, "local-runtime", "binary@0.5.0", apply=True)
    adapter_output = {
        "schema_version": "0.5.0",
        "outcome": "success",
        "projections": [target_statement],
    }
    code = f"import json;print(json.dumps({adapter_output!r}))"

    def effect(additions: list[str]) -> dict[str, object]:
        return {
            "must_add": additions,
            "may_add": [],
            "must_remove": [],
            "may_remove": [],
            "debt": [],
            "rollback_obligations": [],
            "independence_domains_removed": [],
            "resource_intervals": {},
            "time_interval": {"lower": "0", "upper": "1", "unit": "second"},
            "cost_interval": {"lower": "0", "upper": "0", "unit": "credit"},
            "quality_interval": {"lower": "0", "upper": "0", "unit": "quality"},
            "verification_load_upper": "0",
            "projection_possibilities": [],
        }

    capability_attributes = {
        "evidence_type": "adapter_capability",
        "executable": "CAS_ONLY",
        "executable_digest": runtime_import["raw_digest"],
        "material_digests": [],
        "argv_prefix": ["{executable}", "-c", code],
        "arguments": [],
        "execution_policy": {
            "schema_version": "0.5.0",
            "policy_id": "execution:projection-test",
            "timeout_seconds": 10,
            "stdin_bytes": 0,
            "stdout_bytes": 1_048_576,
            "stderr_bytes": 1_048_576,
            "permitted_environment_keys": ["PATH", "SYSTEMROOT"],
        },
        "output_schema_ref": "adapter-output@0.5.0",
        "output_schema_digest": schema_digest("adapter-output@0.5.0"),
        "exit_code_mapping": {"0": "success"},
        "outcome_selector": {
            "source_pointer": "/outcome",
            "mapping": {"success": "success"},
        },
        "projection_routes": [
            {
                "source_pointer": "/projections/0",
                "target_schema_ref": "signed-statement@0.5.0",
                "guaranteed_subject_ids": ["state:target"],
            }
        ],
        "branches": {
            "success": effect(["state:target"]),
            "partial": effect([]),
            "failure": effect([]),
            "timeout": effect([]),
        },
    }
    _import_record_v5(
        tmp_path,
        workspace,
        keys["capability"],
        "capability",
        attestation_id="attestation:capability-projection",
        record_type="evidence",
        subject_id="capability:projection",
        attributes=capability_attributes,
        role="projection_authority",
    )
    _import_record_v5(
        tmp_path,
        workspace,
        keys["action"],
        "action",
        attestation_id="attestation:action-projection",
        record_type="evidence",
        subject_id="action:projection",
        attributes={
            "evidence_type": "action",
            "capability_ref": "capability:projection",
            "arguments": [],
            "input_refs": [],
            "required_authority_refs": [],
            "required_hazard_refs": [],
            "expires_at": "2026-12-31T00:00:00Z",
            "repeatable": False,
            "must_add": ["state:target"],
            "resource_intervals": {},
            "debt": [],
            "verification_load": "0",
            "independence_erosion": 0,
        },
        role="action_author",
    )
    executed = run_action_v5(
        workspace,
        "action:projection",
        apply=True,
        risk_acknowledgement="UNSANDBOXED_LOCAL_EXECUTION",
    )
    assert executed["outcome"] == "success", executed
    pending = pending_projections_v5(workspace)["pending_projections"]
    assert len(pending) == 1
    projection_id = pending[0]["projection_id"]
    store = GenerationStoreV5(workspace)
    manifest = store.load_manifest()
    pending_entry = next(
        item
        for item in manifest["objects"]
        if item["kind"] == "pending-projection"
        and store.get_json(item["digest"])["projection_id"] == projection_id
    )
    approval = _statement(
        keys["projection"],
        {
            "schema_version": "0.5.0",
            "approval_id": "approval:target",
            "projection_digest": pending_entry["digest"],
            "decision": "approve",
            "trusted_time_receipt_digest": manifest["trusted_time_receipt_digest"],
        },
        schema_ref="projection-approval@0.5.0",
        key_id="key:projection",
        principal_id="principal:projection",
        role="projection_verifier",
        source_system="principal:projection",
    )
    approval_path = tmp_path / "approval.json"
    write_canonical(approval_path, approval)
    approved = approve_projection_v5(workspace, str(projection_id), approval_path, apply=True)
    assert approved["source_backed_post_state"] == "true", approved
    assert approved["promoted_kind"] == "principal-attestation"
    assert doctor_v5(workspace)["command_status"] == "ok"
