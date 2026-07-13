# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from collective_phase_control_fabric.canonical import canonical_bytes, write_canonical
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.coordination import derive_coordination_plan
from collective_phase_control_fabric.demos import bootstrap_demo, demo_documents
from collective_phase_control_fabric.fixtures import fixture
from collective_phase_control_fabric.index import index_artifact, inspect_index
from collective_phase_control_fabric.provenance import (
    import_source,
    inspect_source,
    parse_schema_ref,
    receipt_source_backed,
    recompute_validation,
    signature_status,
    validate_unique_ids,
)
from collective_phase_control_fabric.repairs import generate_repairs
from collective_phase_control_fabric.science import (
    exact_nullspace,
    independent_support_core,
    intervention_cover,
    invariant_diagnostics,
    perturbation_replay,
    stoichiometric_matrix,
    validate_coordinate_invariant,
    validate_formation_sequence,
    validate_generative_catalysis,
    validate_persistence,
    validate_rate_intervals,
    validate_resource_potential,
    verification_network,
)
from collective_phase_control_fabric.types import JsonObject
from collective_phase_control_fabric.workspace_v2 import (
    initialize_workspace,
    migrate_workspace,
    rebuild_projections,
    state_digest,
    workspace_version,
)


def test_schema_ref_and_recomputed_certificate_coordinates() -> None:
    assert parse_schema_ref("v0.2.0/phase-contract") == ("phase-contract", "0.2.0")
    assert parse_schema_ref("phase-contract@0.2.0") == ("phase-contract", "0.2.0")
    assert parse_schema_ref("phase-contract") == ("phase-contract", "0.2.0")
    contract, _, _ = demo_documents("orientation-only-reachability")
    certificate: JsonObject = {
        "schema_version": "0.2.0",
        "certificate_id": "certificate:expired",
        "certificate_kind": "collective_advantage",
        "issued_at": "2020-01-01T00:00:00Z",
        "expires_at": "2021-01-01T00:00:00Z",
        "scope": contract["scope"],
        "resource_envelope": contract["resource_envelope"],
        "baseline": contract["external_measurement_policy"]["baseline"],
        "evaluator_identity": "evaluator:test",
        "measurement_protocol": {},
        "source_artifact_refs": ["source:test"],
        "non_claims": ["test only"],
        "schema_valid": True,
        "not_expired": True,
    }
    raw = json.dumps(certificate).encode()
    checked = recompute_validation(
        certificate,
        raw,
        "external-certificate@0.2.0",
        str(contract["evaluation_time"]),
        contract,
        "sha256:" + "0" * 64,
    )
    assert checked["expiry"] == "false"
    assert checked["digest"] == "false"
    assert checked["scope"] == "true"
    assert signature_status({"signature": {"algorithm": "unknown"}}) in {"false", "unknown"}


def test_source_inspection_import_preview_invalid_and_rebuild(tmp_path: Path) -> None:
    contract, network, _ = demo_documents("orientation-only-reachability")
    contract_path = tmp_path / "contract.json"
    write_canonical(contract_path, contract)
    workspace = tmp_path / "workspace"
    assert initialize_workspace(contract_path, workspace)["command_status"] == "ok"
    assert workspace_version(workspace) == "0.2.0"
    initial_digest = state_digest(workspace)

    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(b"not-json")
    assert (
        inspect_source(malformed, "source", "transformation-network@0.2.0")["command_status"]
        == "failed"
    )
    assert (
        import_source(
            malformed,
            workspace,
            "source",
            "transformation-network@0.2.0",
            apply=True,
        )["failure_code"]
        == "source_schema_invalid"
    )

    report = tmp_path / "network.json"
    write_canonical(report, network)
    preview = import_source(
        report,
        workspace,
        "source",
        "transformation-network@0.2.0",
        apply=False,
    )
    assert preview["applied"] is False
    assert state_digest(workspace) == initial_digest
    applied = import_source(
        report,
        workspace,
        "source",
        "transformation-network@0.2.0",
        apply=True,
    )
    assert applied["applied"] is True
    rebuilt = rebuild_projections(workspace)
    assert rebuilt["rebuilt"]


def test_initialize_and_migration_failure_branches(tmp_path: Path) -> None:
    bad_contract = tmp_path / "bad.json"
    write_canonical(bad_contract, {"schema_version": "0.2.0"})
    assert (
        initialize_workspace(bad_contract, tmp_path / "bad-workspace")["failure_code"]
        == "contract_schema_invalid"
    )
    old = tmp_path / "legacy"
    old.mkdir()
    write_canonical(old / "contract.json", {})
    write_canonical(old / "network.json", {})
    assert (
        migrate_workspace(old, tmp_path / "unsupported", "9.9.9")["failure_code"]
        == "unsupported_migration_target"
    )
    assert workspace_version(old) == "0.1.0"
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "file").write_text("occupied", encoding="utf-8")
    contract, _, _ = demo_documents("orientation-only-reachability")
    valid_contract = tmp_path / "valid-contract.json"
    write_canonical(valid_contract, contract)
    with pytest.raises(FileExistsError):
        initialize_workspace(valid_contract, occupied)


def test_migration_quarantines_actions_and_legacy_witnesses(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy-rich"
    legacy.mkdir()
    data = fixture("verified_productive_organization")
    write_canonical(legacy / "contract.json", data["contract"])
    write_canonical(legacy / "network.json", data["network"])
    write_canonical(
        legacy / "actions.json",
        {
            "actions": [
                {
                    "action_id": "action:embedded",
                    "postcondition_contract": {"productive_witness": data["productive_witness"]},
                }
            ]
        },
    )
    write_canonical(legacy / "productive_witness.json", data["productive_witness"])
    native = tmp_path / "native-rich"
    migrated = migrate_workspace(legacy, native, "0.2.0")
    assert migrated["quarantined_legacy_actions"] == 1
    repairs = json.loads((native / ".cpcf" / "legacy-repairs.json").read_text())
    assert repairs["repairs"][0]["executable"] is False
    assert (native / ".cpcf" / "legacy-artifacts" / "productive_witness.json").is_file()


def test_rebuild_rejects_spoof_and_legacy_workspace(tmp_path: Path) -> None:
    spoof = tmp_path / "spoof"
    bootstrap_demo(spoof, "spoofed-receipt-rejection")
    rebuilt = rebuild_projections(spoof)
    assert rebuilt["rebuilt"]
    legacy = tmp_path / "legacy-empty"
    legacy.mkdir()
    assert rebuild_projections(legacy)["failure_code"] == "legacy_workspace_requires_migration"


def test_receipt_chain_and_duplicate_identifier_validation(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cas")
    artifact = store.put(b"payload")
    receipt: JsonObject = {
        "raw_artifact_digest": artifact.digest,
        "validation_results": {
            "schema": "true",
            "digest": "true",
            "expiry": "true",
            "scope": "true",
            "resource": "true",
            "baseline": "true",
            "signature": "true",
        },
    }
    assert receipt_source_backed(receipt, store) == "true"
    receipt["validation_results"]["signature"] = "unknown"
    assert receipt_source_backed(receipt, store) == "unknown"
    receipt["validation_results"]["digest"] = "false"
    assert receipt_source_backed(receipt, store) == "false"
    network = {
        "nodes": [{"node_id": "same"}, {"node_id": "same"}],
        "transformations": [{"transformation_id": "t"}, {"transformation_id": "t"}],
    }
    duplicates = validate_unique_ids(
        network,
        [{"action_id": "a"}, {"action_id": "a"}],
        [{"envelope_id": "e"}, {"envelope_id": "e"}],
    )
    assert len(duplicates) == 4
    index_path = tmp_path / "index.sqlite3"
    index_artifact(index_path, artifact.digest, artifact.path, artifact.size)
    assert inspect_index(index_path)["object_count"] == 1


def test_optional_ed25519_signature_is_recomputed() -> None:
    cryptography = pytest.importorskip("cryptography")
    del cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    value: JsonObject = {"payload": "bound"}
    signature = private.sign(canonical_bytes(value))
    value["signature"] = {
        "algorithm": "ed25519",
        "public_key_pem": private.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode(),
        "signature_base64": base64.b64encode(signature).decode(),
    }
    assert signature_status(value) == "true"
    value["payload"] = "tampered"
    assert signature_status(value) == "false"


def test_scientific_diagnostics_persistence_perturbation_and_cover() -> None:
    contract, network, _ = demo_documents("interdependent-cascade-repair")
    matrix = stoichiometric_matrix(contract, network)
    assert matrix["matrix"] == [["-1"], ["2"]]
    assert invariant_diagnostics(contract, network)["p_nullspace_basis"] == [["2", "1"]]
    persistence = {
        "conserved_coordinates": [],
        "replenished_coordinates": ["protected_resource"],
        "renewal_refs": ["renew"],
        "expiry_coverage_refs": ["expiry"],
        "verifier_capacity_refs": ["capacity"],
        "rollback_refs": ["rollback"],
        "failure_response_refs": ["failure"],
    }
    assert validate_persistence(contract, network, persistence)["valid"] is True
    persistence["replenished_coordinates"] = []
    assert validate_persistence(contract, network, persistence)["valid"] is False
    replay = perturbation_replay(contract, network)
    assert replay["declared_suite_count"] == 1
    contract["intervention_requirements"] = ["target:a", "target:b"]
    actions = [
        {"action_id": "a", "covers": ["target:a"]},
        {"action_id": "b", "covers": ["target:b"]},
    ]
    cover = intervention_cover(contract, actions)
    assert cover["minimum_covers"] == [["a", "b"]]
    assert cover["general_controllability_claim"] is False


def test_queue_little_law_coordination_and_repairs() -> None:
    contract, network, _ = demo_documents("orientation-only-reachability")
    plan = derive_coordination_plan(contract, network)
    assert plan["all_to_all_default"] is False
    queue = verification_network(
        {
            "stages": [
                {
                    "stage_id": "review",
                    "arrival_upper": "1",
                    "service_lower": "2",
                }
            ],
            "stationarity_established": True,
            "means_established": True,
        }
    )
    assert queue["candidate_fan_out_allowed"] is True
    assert queue["little_law"]["eligible"] is True
    repairs = generate_repairs(
        {
            "verification_network": {"bottleneck_set": ["review"]},
            "regeneration_deadlocks": [{}],
            "formation_sequence": {"valid": False, "reasons": ["cycle"]},
            "productive_witness": {"valid": False},
            "persistence": {"valid": False},
            "generative_catalysis": {"valid": False},
            "independent_support_core": {"status": "false"},
        },
        {"errors": [{"code": "schema_invalid"}, {"code": "digest_mismatch"}]},
    )
    assert any(item["repair_kind"] == "verifier_overload" for item in repairs)
    assert all(item["executable"] is False for item in repairs)


def test_fail_closed_scientific_input_branches() -> None:
    contract, network, _ = demo_documents("orientation-only-reachability")
    assert validate_coordinate_invariant(contract, network, None)["status"] == "unknown"
    assert (
        validate_coordinate_invariant(contract, network, {"kind": "wrong", "coefficients": {}})[
            "valid"
        ]
        is False
    )
    negative = {
        "kind": "p_semiflow_analog",
        "coefficients": {"protected_resource": "-2", "target_units": "-1"},
    }
    assert validate_coordinate_invariant(contract, network, negative)["valid"] is False
    t_invariant = {
        "kind": "t_semiflow_analog",
        "coefficients": {"transform:produce": "1"},
    }
    assert validate_coordinate_invariant(contract, network, t_invariant)["valid"] is False
    assert validate_formation_sequence(contract, network, None)["status"] == "unknown"
    assert validate_formation_sequence(contract, network, {"layers": []})["valid"] is False
    malformed_formation = {
        "layers": [[], ["missing"], ["transform:produce", "transform:produce"]],
        "initial_coordinate_balances": {"protected_resource": "bad"},
    }
    assert validate_formation_sequence(contract, network, malformed_formation)["valid"] is False
    contract["formation_policy"]["maximum_layer_count"] = 0
    contract["protected_floors"]["protected_resource"] = {
        "quantity": "bad",
        "unit": "resource-unit",
    }
    assert (
        validate_formation_sequence(
            contract,
            network,
            {
                "layers": [["transform:produce"]],
                "initial_coordinate_balances": {"protected_resource": "1"},
            },
        )["valid"]
        is False
    )
    assert validate_generative_catalysis(contract, network, None)["status"] == "unknown"
    assert (
        validate_generative_catalysis(
            contract, network, {"food_states": [], "catalyst_bindings": []}
        )["valid"]
        is False
    )
    empty_catalysis = validate_generative_catalysis(
        contract, network, {"food_states": [], "catalyst_bindings": {}}
    )
    assert empty_catalysis["status"] == "unknown"
    assert validate_rate_intervals(None)["status"] == "unknown"
    assert (
        validate_rate_intervals(
            {
                "observation_window": {"start": "bad", "end": "bad"},
                "intervals": [None, {"transformation_id": "t", "lower": "bad", "upper": "1"}],
                "source_refs": ["source"],
            }
        )["valid"]
        is False
    )
    assert validate_resource_potential(network, None)["status"] == "unknown"
    assert (
        validate_resource_potential(
            network, {"coordinate_weights": {"x": "bad"}, "external_supply_refs": []}
        )["valid"]
        is False
    )
    assert (
        validate_resource_potential(
            network, {"coordinate_weights": {"target_units": "1"}, "external_supply_refs": []}
        )["valid"]
        is True
    )
    assert validate_persistence(contract, network, None)["status"] == "unknown"
    assert validate_persistence(contract, network, {})["valid"] is False
    assert independent_support_core({}, network)["status"] == "unknown"
    assert verification_network(None)["status"] == "unknown"
    invalid_queue = verification_network(
        {
            "stages": [None, {"stage_id": "bad", "arrival_upper": "1", "service_lower": "0"}],
            "stationarity_established": False,
            "means_established": False,
        }
    )
    assert invalid_queue["status"] == "false"
    with pytest.raises(ValueError, match="ragged"):
        exact_nullspace([["1"], ["1", "2"]])


def test_invalid_stoichiometric_flow_is_diagnostic() -> None:
    contract, network, _ = demo_documents("orientation-only-reachability")
    network["transformations"][0]["produced_coordinates"]["target_units"]["quantity"] = "bad"
    report = stoichiometric_matrix(contract, network)
    assert report["errors"]
    assert invariant_diagnostics(contract, network)["p_nullspace_basis"] == []
    assert (
        validate_coordinate_invariant(
            contract,
            network,
            {
                "kind": "p_semiflow_analog",
                "coefficients": {"protected_resource": "1", "target_units": "1"},
            },
        )["valid"]
        is False
    )
