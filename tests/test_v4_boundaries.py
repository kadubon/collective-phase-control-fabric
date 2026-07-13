# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
from copy import deepcopy
from pathlib import Path

import pytest

from collective_phase_control_fabric.canonical import digest_v3_json
from collective_phase_control_fabric.generation_v4 import GenerationStoreV4, empty_generation_v4
from collective_phase_control_fabric.limits import (
    MAX_JSON_BYTES,
    LimitExceeded,
    bounded_object,
    load_json_bounded,
    loads_json_bounded,
)
from collective_phase_control_fabric.trust_v4 import (
    key_fingerprint,
    validate_policy,
    verify_statement,
    verify_time_receipt,
)
from tests.test_v4 import NOW, _key, _policy, _statement


def test_trust_failure_matrix_is_fail_closed() -> None:
    root, source = _key(1), _key(2)
    policy = _policy(root, source)
    payload = {"value": "bound"}
    valid = _statement(
        source,
        payload,
        schema_ref="principal-attestation@0.4.0",
        key_id="key:source",
        role="source",
        source_system="local",
    )
    variants: list[dict[str, object]] = []
    missing = deepcopy(valid)
    missing.pop("protected")
    variants.append(missing)
    wrong_payload = deepcopy(valid)
    wrong_payload["payload"] = {"value": "edited"}
    variants.append(wrong_payload)
    future = deepcopy(valid)
    future["protected"]["signed_at"] = "2026-07-14T00:00:00Z"
    variants.append(future)
    bad_signature = deepcopy(valid)
    bad_signature["signature_base64"] = base64.b64encode(b"x" * 64).decode()
    variants.append(bad_signature)
    bad_scope = deepcopy(valid)
    bad_scope["protected"]["scope"] = {"project": "other"}
    variants.append(bad_scope)
    unknown = deepcopy(valid)
    unknown["protected"]["key_id"] = "key:unknown"
    variants.append(unknown)
    for statement in variants:
        assert verify_statement(statement, policy, authoritative_time=NOW)["status"] == "false"
    expected_mismatch = verify_statement(
        valid,
        policy,
        authoritative_time=NOW,
        expected_schema_ref="other@0.4.0",
        expected_role="other",
        expected_source_system="other",
        expected_scope={"project": "other"},
    )
    assert {
        "signed_schema_mismatch",
        "signed_role_mismatch",
        "signed_source_system_mismatch",
        "signed_scope_mismatch",
    } <= set(expected_mismatch["reasons"])
    bad_domain = deepcopy(valid)
    bad_domain["protected"]["domain"] = "OTHER"
    assert (
        "signature_domain_or_version_mismatch"
        in verify_statement(bad_domain, policy, authoritative_time=NOW)["reasons"]
    )
    assert (
        "authoritative_or_signing_time_invalid"
        in verify_statement(valid, policy, authoritative_time="invalid")["reasons"]
    )

    revoked = deepcopy(policy)
    revoked["principals"][1]["revoked"] = True
    assert verify_statement(valid, revoked, authoritative_time=NOW)["status"] == "false"
    expired = deepcopy(policy)
    expired["principals"][1]["not_after"] = "2026-01-02T00:00:00Z"
    assert verify_statement(valid, expired, authoritative_time=NOW)["status"] == "false"
    with pytest.raises(ValueError):
        key_fingerprint(base64.b64encode(b"short").decode())


def test_time_receipt_failure_matrix() -> None:
    root, source = _key(1), _key(2)
    policy = _policy(root, source)
    payload = {
        "schema_version": "0.4.0",
        "receipt_id": "time",
        "receipt_type": "trusted_time",
        "event_time": NOW,
        "subject_digest": "sha256:" + "a" * 64,
        "serial": 1,
    }
    statement = _statement(
        root,
        payload,
        schema_ref="trusted-time-receipt@0.4.0",
        key_id="key:root",
        role="timestamp",
        source_system="clock",
    )
    assert (
        verify_time_receipt(statement, policy, expected_subject_digest=payload["subject_digest"])[
            "status"
        ]
        == "true"
    )
    for key, value, reason in (
        ("receipt_type", "local", "time_receipt_type_invalid"),
        ("serial", -1, "time_receipt_serial_invalid"),
        ("event_time", "invalid", "time_receipt_event_time_invalid"),
    ):
        changed_payload = deepcopy(payload)
        changed_payload[key] = value
        changed = _statement(
            root,
            changed_payload,
            schema_ref="trusted-time-receipt@0.4.0",
            key_id="key:root",
            role="timestamp",
            source_system="clock",
        )
        checked = verify_time_receipt(changed, policy)
        assert checked["status"] == "false"
        assert reason in checked["reasons"]
    assert (
        verify_time_receipt(statement, policy, expected_subject_digest="sha256:" + "b" * 64)[
            "status"
        ]
        == "false"
    )
    assert verify_time_receipt({"payload": []}, policy)["status"] == "false"


def test_policy_bootstrap_failure_matrix() -> None:
    root, source = _key(1), _key(2)
    policy = _policy(root, source)
    duplicate_id = deepcopy(policy)
    duplicate_id["principals"][1]["key_id"] = "key:root"
    assert validate_policy(duplicate_id)
    no_root = deepcopy(policy)
    no_root["principals"][0]["roles"] = ["timestamp"]
    assert validate_policy(no_root)
    wrong_root = deepcopy(policy)
    wrong_root["root_key_id"] = "key:source"
    assert validate_policy(wrong_root)
    malformed = deepcopy(policy)
    malformed["principals"][0]["public_key_base64"] = "!"
    assert validate_policy(malformed)
    assert validate_policy(policy, "sha256:" + "0" * 64)


def test_bounded_json_file_shape_and_size_matrix(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(b"{]")
    with pytest.raises(ValueError):
        load_json_bounded(malformed)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_JSON_BYTES + 1))
    with pytest.raises(LimitExceeded):
        load_json_bounded(oversized)
    with pytest.raises(LimitExceeded):
        loads_json_bounded(b"{}", maximum_bytes=1)
    (tmp_path / "array.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        bounded_object(tmp_path / "array.json")


def test_generation_concurrency_schema_and_chain_failures(tmp_path: Path) -> None:
    store = GenerationStoreV4(tmp_path / "workspace")
    with pytest.raises(FileNotFoundError):
        store.load_manifest()
    with pytest.raises(ValueError):
        store.manifest_path("bad")
    contract = store.put_json({"schema_version": "0.4.0"})
    trust = store.put_json({"schema_version": "0.4.0"})
    payload = empty_generation_v4(
        contract_digest=contract,
        trust_policy_digest=trust,
        trusted_time_receipt_digest=None,
        analysis_epoch=None,
        objects=[],
    )
    committed = store.commit(payload, expected_current=None)
    assert committed["command_status"] == "ok"
    assert store.commit(payload, expected_current=None)["failure_code"] == (
        "concurrent_generation_comparison_failed"
    )
    malformed = deepcopy(store.load_manifest())
    malformed["objects"] = [
        {
            "digest": contract,
            "kind": "contract",
            "schema_ref": "phase-contract@0.4.0",
            "source_chain": [],
            "authority_key_id": None,
            "lifecycle": "active",
        },
        {
            "digest": contract,
            "kind": "duplicate",
            "schema_ref": "phase-contract@0.4.0",
            "source_chain": [],
            "authority_key_id": None,
            "lifecycle": "active",
        },
    ]
    rejected = store.commit(malformed, expected_current=store.current_id())
    assert rejected["failure_code"] == "generation_schema_invalid"
    assert digest_v3_json([]) == malformed["history_root"]
