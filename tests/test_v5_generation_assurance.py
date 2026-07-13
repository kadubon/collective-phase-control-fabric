# SPDX-License-Identifier: Apache-2.0
"""Generation-chain security branches for the inspection-only v0.5 format."""

from __future__ import annotations

from pathlib import Path

import pytest

from collective_phase_control_fabric.canonical import write_canonical
from collective_phase_control_fabric.generation_v5 import (
    GenerationStoreV5,
    _assert_no_link_components,
    empty_generation_v5,
    generation_digest,
    history_event,
    ledger_entry,
)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64


def test_generation_identifiers_current_and_containment(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    store = GenerationStoreV5(root)
    assert store.current_id() is None
    with pytest.raises(ValueError, match="malformed generation"):
        store.manifest_path("bad")
    with pytest.raises(ValueError, match="escapes workspace"):
        _assert_no_link_components(root, tmp_path / "outside")
    with pytest.raises(ValueError, match="unregistered ledger kind"):
        ledger_entry(SHA_A, kind="unknown", schema_ref="unknown@0.5.0")

    store.control.mkdir(parents=True)
    store.current_path.write_bytes(b"x" * 73)
    with pytest.raises(ValueError, match="bounded identifier"):
        store.current_id()
    store.current_path.write_bytes(b"\xff")
    with pytest.raises(ValueError, match="ASCII"):
        store.current_id()
    store.current_path.write_text("not-a-generation", encoding="ascii")
    with pytest.raises(ValueError, match="malformed generation"):
        store.current_id()


def test_generation_history_validation_and_digest_helpers() -> None:
    event = history_event([], event_id="event:a", event_type="object_imported", subject_digests=[])
    next_event = history_event(
        [event], event_id="event:b", event_type="object_imported", subject_digests=[SHA_A, SHA_A]
    )
    assert next_event["previous_event_digest"] == event["event_digest"]
    assert next_event["subject_digests"] == [SHA_A]
    assert generation_digest({"generation_id": SHA_A, "value": 1}) == generation_digest(
        {"generation_id": SHA_B, "value": 1}
    )
    assert GenerationStoreV5._validate_history("bad") == [
        {"message": "history must be an array", "json_pointer": "/history"}
    ]
    invalid = [
        "not-an-event",
        {**event, "previous_event_digest": SHA_A, "event_digest": SHA_B},
        {**event, "previous_event_digest": SHA_B, "event_digest": SHA_B},
    ]
    messages = {item["message"] for item in GenerationStoreV5._validate_history(invalid)}
    assert "history event must be an object" in messages
    assert "history previous digest mismatch" in messages
    assert "history event digest mismatch" in messages
    assert "duplicate history event_id" in messages


def test_generation_load_commit_and_chain_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    store = GenerationStoreV5(root)
    with pytest.raises(FileNotFoundError, match="CURRENT"):
        store.load_manifest()

    store.control.mkdir(parents=True, exist_ok=True)
    generation_path = store.manifest_path(SHA_A)
    generation_path.parent.mkdir(parents=True)
    write_canonical(generation_path, [])
    store.current_path.write_bytes((SHA_A + "\n").encode("ascii"))
    with pytest.raises(ValueError, match="must be an object"):
        store.load_manifest()
    write_canonical(generation_path, {"schema_version": "0.4.0"})
    with pytest.raises(ValueError, match="not a native"):
        store.load_manifest()
    write_canonical(generation_path, {"schema_version": "0.5.0", "generation_id": SHA_A})
    with pytest.raises(ValueError, match="digest mismatch"):
        store.load_manifest()

    store.current_path.unlink()
    payload = empty_generation_v5(
        contract_digest=SHA_A,
        trust_policy_digest=SHA_B,
        trusted_time_receipt_digest=None,
        analysis_epoch=None,
        objects=[],
    )
    assert store.commit(payload, expected_current=SHA_A)["failure_code"] == (
        "concurrent_generation_comparison_failed"
    )
    invalid = dict(payload)
    invalid["objects"] = [
        {
            "digest": SHA_A,
            "kind": "unknown",
            "schema_ref": "unknown@0.5.0",
            "source_chain": [SHA_B],
            "authority_key_id": None,
            "authority_policy_digest": None,
            "lifecycle": "active",
        },
        {
            "digest": SHA_A,
            "kind": "unknown",
            "schema_ref": "unknown@0.5.0",
            "source_chain": [],
            "authority_key_id": None,
            "authority_policy_digest": None,
            "lifecycle": "active",
        },
    ]
    failed = store.commit(invalid, expected_current=None)
    assert failed["failure_code"] == "generation_schema_invalid"
    messages = {item["message"] for item in failed["schema_errors"]}
    assert "duplicate object digest" in messages
    assert "unregistered object kind" in messages
    assert "dangling source-chain digest" in messages

    class TimeoutLock:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        def __enter__(self) -> None:
            raise TimeoutError

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr("collective_phase_control_fabric.generation_v5.WorkspaceLock", TimeoutLock)
    assert store.commit(payload, expected_current=None)["failure_code"] == "workspace_lock_timeout"

    monkeypatch.setattr(store, "current_id", lambda: SHA_A)
    monkeypatch.setattr(
        store,
        "load_manifest",
        lambda selected=None: {"previous_generation": SHA_A},
    )
    assert store.verify_chain()[-1]["code"] == "generation_cycle"
    monkeypatch.setattr(
        store,
        "load_manifest",
        lambda selected=None: (_ for _ in ()).throw(ValueError("invalid")),
    )
    assert store.verify_chain()[-1]["code"] == "generation_invalid"


def test_generation_chain_depth_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GenerationStoreV5(tmp_path)
    counter = {"value": 0}

    def manifest(_: str | None = None) -> dict[str, object]:
        counter["value"] += 1
        return {"previous_generation": f"sha256:{counter['value']:064x}"}

    monkeypatch.setattr("collective_phase_control_fabric.generation_v5.MAX_GENERATION_DEPTH", 1)
    monkeypatch.setattr(store, "current_id", lambda: SHA_A)
    monkeypatch.setattr(store, "load_manifest", manifest)
    assert store.verify_chain()[-1]["code"] == "generation_chain_limit_exceeded"
