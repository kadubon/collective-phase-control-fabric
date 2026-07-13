# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from collective_phase_control_fabric.canonical import digest_v3_json, write_canonical
from collective_phase_control_fabric.generation_v4 import GenerationStoreV4
from collective_phase_control_fabric.trust_v4 import key_fingerprint
from collective_phase_control_fabric.workspace_v4 import (
    _pointer,
    advance_time_v4,
    doctor_v4,
    explain_missing_contract_v4,
    import_attestation_v4,
    import_raw_v4,
    initialize_workspace_v4,
    inspect_attestation_v4,
    inspect_source_v4,
    inspect_time_receipt_v4,
    migrate_workspace_v4,
    onboard_v4,
    repair_show_v4,
    scaffold_contract_v4,
    status_v4,
    update_trust_policy_v4,
    validate_trust_policy_v4,
    workspace_version,
)
from tests.test_v4 import (
    NOW,
    _contract,
    _key,
    _policy,
    _public,
    _statement,
    _workspace,
)


def test_workspace_discovery_validation_and_inspection_matrix(tmp_path: Path) -> None:
    assert workspace_version(tmp_path / "missing") is None
    malformed = tmp_path / "malformed"
    (malformed / ".cpcf").mkdir(parents=True)
    (malformed / ".cpcf" / "CURRENT").write_text("bad", encoding="ascii")
    assert workspace_version(malformed) is None
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    write_canonical(legacy / "contract.json", {"schema_version": "0.2.0"})
    assert workspace_version(legacy) == "0.2.0"
    assert status_v4(legacy)["failure_code"] == "legacy_workspace_inspect_only"
    assert onboard_v4(legacy)["failure_code"] == "legacy_workspace_inspect_only"

    root, source = _key(1), _key(2)
    policy = _policy(root, source)
    policy_path = tmp_path / "policy.json"
    write_canonical(policy_path, policy)
    assert (
        validate_trust_policy_v4(policy_path, key_fingerprint(_public(root)))["command_status"]
        == "ok"
    )
    assert (
        validate_trust_policy_v4(policy_path, "sha256:" + "0" * 64)["failure_code"]
        == "trust_policy_invalid"
    )
    assert validate_trust_policy_v4(tmp_path / "missing.json")["failure_code"] == (
        "trust_policy_parse_failed"
    )

    contract = _contract()
    time_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "time:inspect",
        "receipt_type": "trusted_time",
        "event_time": NOW,
        "subject_digest": digest_v3_json(contract),
        "serial": 1,
    }
    time_statement = _statement(
        root,
        time_payload,
        schema_ref="trusted-time-receipt@0.4.0",
        key_id="key:root",
        role="timestamp",
        source_system="clock",
    )
    time_path = tmp_path / "time.json"
    write_canonical(time_path, time_statement)
    assert inspect_time_receipt_v4(time_path, policy_path)["command_status"] == "ok"
    write_canonical(tmp_path / "bad-time.json", [])
    assert inspect_time_receipt_v4(tmp_path / "bad-time.json", policy_path)["failure_code"] == (
        "trusted_time_input_not_object"
    )


def test_workspace_initialization_import_preview_and_attestation_inspection(tmp_path: Path) -> None:
    workspace, source, policy = _workspace(tmp_path)
    raw_path = tmp_path / "raw.json"
    projected = {
        "record_type": "state",
        "subject_id": "state:preview",
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "lineage_refs": [],
        "correlation_domains": [],
        "attributes": {"available": True},
    }
    write_canonical(raw_path, {"value": projected})
    preview = import_raw_v4(raw_path, workspace, "local", "typed-record@0.4.0", apply=False)
    assert preview["failure_code"] == "apply_required"
    imported = import_raw_v4(raw_path, workspace, "local", "typed-record@0.4.0", apply=True)
    payload = {
        "schema_version": "0.4.0",
        "attestation_id": "attestation:preview",
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
    statement_path = tmp_path / "attestation.json"
    policy_path = tmp_path / "inspect-policy.json"
    write_canonical(statement_path, statement)
    write_canonical(policy_path, policy)
    assert inspect_attestation_v4(statement_path, policy_path)["command_status"] == "ok"
    assert (
        inspect_source_v4(statement_path, policy_path, "local", "principal-attestation@0.4.0")[
            "signature_status"
        ]
        == "true"
    )
    malformed_statement = deepcopy(statement)
    malformed_statement["payload"]["attributes"]["unexpected"] = True
    malformed_path = tmp_path / "malformed-attestation.json"
    write_canonical(malformed_path, malformed_statement)
    assert inspect_attestation_v4(malformed_path, policy_path)["failure_code"] == (
        "attestation_invalid"
    )
    assert import_attestation_v4(statement_path, workspace, apply=False)["failure_code"] == (
        "apply_required"
    )
    assert (
        inspect_source_v4(raw_path, policy_path, "local", "typed-record@0.4.0")["signature_status"]
        == "not_applicable"
    )
    write_canonical(tmp_path / "bad-raw.json", {"duplicate": 1})
    assert (
        import_raw_v4(
            tmp_path / "bad-raw.json",
            tmp_path / "missing-workspace",
            "local",
            "x@0.4.0",
            apply=True,
        )["failure_code"]
        == "source_read_failed"
    )
    no_time_root, no_time_source = _key(1), _key(2)
    no_time_contract = _contract()
    no_time_policy = _policy(no_time_root, no_time_source)
    no_time_contract_path = tmp_path / "no-time-contract.json"
    no_time_policy_path = tmp_path / "no-time-policy.json"
    write_canonical(no_time_contract_path, no_time_contract)
    write_canonical(no_time_policy_path, no_time_policy)
    no_time_workspace = tmp_path / "no-time"
    assert (
        initialize_workspace_v4(
            no_time_contract_path,
            no_time_policy_path,
            no_time_workspace,
            key_fingerprint(_public(no_time_root)),
            None,
        )["command_status"]
        == "ok"
    )
    assert (
        import_attestation_v4(statement_path, no_time_workspace, apply=True)["failure_code"]
        == "authoritative_time_receipt_required"
    )


def test_time_and_policy_previews_reject_rollback_and_bad_sequences(tmp_path: Path) -> None:
    workspace, _, policy = _workspace(tmp_path)
    root = _key(1)
    store = GenerationStoreV4(workspace)
    current = str(store.current_id())
    older_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "time:older",
        "receipt_type": "trusted_time",
        "event_time": "2026-07-12T00:00:00Z",
        "subject_digest": current,
        "serial": 2,
    }
    older = _statement(
        root,
        older_payload,
        schema_ref="trusted-time-receipt@0.4.0",
        key_id="key:root",
        role="timestamp",
        source_system="clock",
        signed_at="2026-07-12T00:00:00Z",
    )
    older_path = tmp_path / "older.json"
    write_canonical(older_path, older)
    assert advance_time_v4(workspace, older_path, apply=True)["failure_code"] == (
        "analysis_epoch_rollback_rejected"
    )
    newer_payload = deepcopy(older_payload)
    newer_payload["event_time"] = "2026-07-14T00:00:00Z"
    newer = _statement(
        root,
        newer_payload,
        schema_ref="trusted-time-receipt@0.4.0",
        key_id="key:root",
        role="timestamp",
        source_system="clock",
        signed_at="2026-07-14T00:00:00Z",
    )
    newer_path = tmp_path / "newer.json"
    write_canonical(newer_path, newer)
    assert advance_time_v4(workspace, newer_path, apply=False)["failure_code"] == "apply_required"

    manifest = store.load_manifest()
    bad_policy = deepcopy(policy)
    bad_policy["policy_sequence"] = 4
    bad_policy["previous_policy_digest"] = manifest["trust_policy_digest"]
    policy_statement = _statement(
        root,
        bad_policy,
        schema_ref="trust-policy@0.4.0",
        key_id="key:root",
        role="workspace_root",
        source_system="clock",
    )
    policy_path = tmp_path / "bad-policy-update.json"
    write_canonical(policy_path, policy_statement)
    receipt_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "time:policy-bad",
        "receipt_type": "trusted_time",
        "event_time": NOW,
        "subject_digest": digest_v3_json(bad_policy),
        "serial": 2,
    }
    receipt = _statement(
        root,
        receipt_payload,
        schema_ref="trusted-time-receipt@0.4.0",
        key_id="key:root",
        role="timestamp",
        source_system="clock",
    )
    receipt_path = tmp_path / "bad-policy-time.json"
    write_canonical(receipt_path, receipt)
    assert (
        update_trust_policy_v4(workspace, policy_path, receipt_path, apply=True)["failure_code"]
        == "trust_policy_update_invalid"
    )


def test_contract_repair_and_migration_failure_surfaces(tmp_path: Path) -> None:
    missing = tmp_path / "missing-contract.json"
    assert explain_missing_contract_v4(missing)["failure_code"] == "contract_parse_failed"
    write_canonical(missing, {"schema_version": "0.4.0"})
    explained = explain_missing_contract_v4(missing)
    assert "contract_id" in explained["missing_decisions"]
    output = tmp_path / "scaffold"
    assert scaffold_contract_v4(output, "structural")["command_status"] == "ok"
    assert scaffold_contract_v4(output, "structural")["failure_code"] == "output_already_exists"
    workspace, _, _ = _workspace(tmp_path / "workspace-root")
    assert repair_show_v4(workspace, "repair:missing")["failure_code"] == "repair_not_found"
    assert doctor_v4(workspace, quick=True)["execution_allowed"] is False
    assert (
        migrate_workspace_v4(
            tmp_path / "unknown", tmp_path / "trust", tmp_path / "time", tmp_path / "out", "x"
        )["failure_code"]
        == "unsupported_migration_source"
    )


def test_workspace_v4_parse_preview_and_pointer_failure_matrix(tmp_path: Path) -> None:
    value = {"a": ["zero", {"b": 2}]}
    assert _pointer(value, "") == value
    assert _pointer(value, "/a/1/b") == 2
    with pytest.raises(ValueError):
        _pointer({"a": []}, "/a/4")

    missing = tmp_path / "missing.json"
    assert validate_trust_policy_v4(missing)["failure_code"] == "trust_policy_parse_failed"
    nonobject = tmp_path / "nonobject.json"
    write_canonical(nonobject, [])
    assert validate_trust_policy_v4(nonobject)["failure_code"] == "trust_policy_not_object"
    assert inspect_time_receipt_v4(missing, nonobject)["failure_code"] == (
        "trusted_time_input_invalid"
    )
    assert inspect_time_receipt_v4(nonobject, nonobject)["failure_code"] == (
        "trusted_time_input_not_object"
    )
    assert inspect_attestation_v4(missing, nonobject)["failure_code"] == (
        "attestation_input_invalid"
    )
    assert inspect_attestation_v4(nonobject, nonobject)["failure_code"] == (
        "attestation_input_not_object"
    )
    assert inspect_source_v4(missing, nonobject, "local", "x@0.4.0")["failure_code"] == (
        "source_inspection_input_invalid"
    )
    source = tmp_path / "source.json"
    write_canonical(source, {"value": 1})
    assert inspect_source_v4(source, nonobject, "local", "x@0.4.0")["failure_code"] == (
        "trust_policy_not_object"
    )

    root, source_key = _key(1), _key(2)
    contract = _contract()
    policy = _policy(root, source_key)
    contract_path = tmp_path / "contract.json"
    policy_path = tmp_path / "policy.json"
    write_canonical(contract_path, contract)
    write_canonical(policy_path, policy)
    existing = tmp_path / "existing"
    existing.mkdir()
    assert (
        initialize_workspace_v4(
            contract_path,
            policy_path,
            existing,
            key_fingerprint(_public(root)),
            None,
        )["failure_code"]
        == "output_already_exists"
    )
    assert (
        initialize_workspace_v4(
            missing,
            policy_path,
            tmp_path / "missing-input",
            key_fingerprint(_public(root)),
            None,
        )["failure_code"]
        == "workspace_input_invalid"
    )
    assert (
        initialize_workspace_v4(
            nonobject,
            policy_path,
            tmp_path / "nonobject-input",
            key_fingerprint(_public(root)),
            None,
        )["failure_code"]
        == "workspace_input_not_object"
    )
    bad_receipt_path = tmp_path / "bad-time.json"
    write_canonical(bad_receipt_path, [])
    assert (
        initialize_workspace_v4(
            contract_path,
            policy_path,
            tmp_path / "bad-time-workspace",
            key_fingerprint(_public(root)),
            bad_receipt_path,
        )["failure_code"]
        == "trusted_time_receipt_not_object"
    )

    ready = tmp_path / "ready"
    ready.mkdir()
    workspace, source_private, _ = _workspace(ready)
    projected = {
        "record_type": "state",
        "subject_id": "state:preview",
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "lineage_refs": [],
        "correlation_domains": [],
        "attributes": {"available": True},
    }
    raw_path = tmp_path / "preview-raw.json"
    write_canonical(raw_path, {"value": projected})
    raw = import_raw_v4(raw_path, workspace, "local", "typed-record@0.4.0", apply=True)
    payload = {
        "schema_version": "0.4.0",
        "attestation_id": "attestation:preview",
        **projected,
        "subject_digest": digest_v3_json(projected),
        "source_artifact_digest": raw["raw_digest"],
        "source_pointer": "/value",
    }
    statement = _statement(
        source_private,
        payload,
        schema_ref="principal-attestation@0.4.0",
        key_id="key:source",
        role="source",
        source_system="local",
    )
    statement_path = tmp_path / "preview-attestation.json"
    write_canonical(statement_path, statement)
    assert import_attestation_v4(statement_path, workspace, apply=False)["failure_code"] == (
        "apply_required"
    )
