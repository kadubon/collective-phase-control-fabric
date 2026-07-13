# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from collective_phase_control_fabric.canonical import DuplicateKeyError
from collective_phase_control_fabric.v6.canonical import (
    InputLimitError,
    canonical_bytes,
    digest_bytes,
    loads_bounded,
)
from collective_phase_control_fabric.v6.kms import normalize_p256_raw
from collective_phase_control_fabric.v6.models import (
    DOCUMENT_MODELS,
    Lifecycle,
    StateAttestation,
    StateSpec,
)
from collective_phase_control_fabric.v6.registry import (
    document_digest,
    parse_document,
    registry_manifest,
    schema_for_kind,
)
from collective_phase_control_fabric.v6.trust import (
    build_protected_header,
    inspect_genesis,
    public_key_fingerprint,
    sign_document,
    validate_policy,
    verify_envelope,
)
from tests.v6_helpers import NOW, VALID_FROM, VALID_UNTIL, metadata, trust_fixture


def state() -> StateAttestation:
    return StateAttestation(
        metadata=metadata("state-a"),
        spec=StateSpec(
            state_id="state-a",
            available=True,
            food=True,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
        ),
    )


def test_registry_is_closed_and_runtime_bound() -> None:
    value = state().model_dump(mode="json", exclude_none=True)
    value["unexpected"] = True
    with pytest.raises(ValidationError):
        StateAttestation.model_validate(value)
    with pytest.raises(ValueError, match="unknown_document_kind"):
        parse_document({**value, "kind": "invented-kind"})
    manifest = registry_manifest()
    assert len(manifest["schemas"]) == len(DOCUMENT_MODELS)
    for kind in DOCUMENT_MODELS:
        schema = schema_for_kind(kind)
        assert schema["unevaluatedProperties"] is False
        assert schema["additionalProperties"] is False


def test_bounded_parser_rejects_duplicates_depth_floats_and_size() -> None:
    with pytest.raises(DuplicateKeyError):
        loads_bounded(b'{"api_version":"cpcf.io/v0.6","kind":"x","kind":"y"}')
    with pytest.raises(InputLimitError, match="json_nesting_too_deep"):
        loads_bounded(("[" * 65 + "0" + "]" * 65).encode())
    with pytest.raises(ValueError, match="floating_point_values_are_forbidden"):
        loads_bounded(b'{"value":1.5}')
    with pytest.raises(InputLimitError, match="json_document_too_large"):
        loads_bounded(b"{}", limit=1)


def test_dsse_binds_protected_fields_but_not_envelope_key_hint() -> None:
    policy, trusted_time, keys = trust_fixture()
    document = state()
    root = policy.spec.principals[0]
    protected = build_protected_header(
        document,
        principal=root,
        role="state_source",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=document_digest(trusted_time),
    )
    envelope = sign_document(document, private_key=keys["root"], protected=protected)
    result, projected = verify_envelope(envelope, policy, trusted_time=trusted_time)
    assert result.valid and projected == document

    hint_changed = envelope.model_copy(
        update={
            "signatures": [envelope.signatures[0].model_copy(update={"keyid": "attacker-hint"})]
        }
    )
    assert verify_envelope(hint_changed, policy, trusted_time=trusted_time)[0].valid

    payload = loads_bounded(base64.b64decode(envelope.payload))
    payload["protected"]["role"] = "projection_authority"
    tampered = envelope.model_copy(
        update={"payload": base64.b64encode(canonical_bytes(payload)).decode("ascii")}
    )
    tampered_result, _ = verify_envelope(tampered, policy, trusted_time=trusted_time)
    assert not tampered_result.valid
    assert "signature_invalid" in tampered_result.reasons


def test_historical_signature_survives_later_key_expiry() -> None:
    policy, trusted_time, keys = trust_fixture()
    root = policy.spec.principals[0]
    expired_root = root.model_copy(update={"valid_until": datetime(2026, 1, 1, 1, tzinfo=UTC)})
    historical_policy = policy.model_copy(
        update={
            "spec": policy.spec.model_copy(
                update={"principals": [expired_root, *policy.spec.principals[1:]]}
            )
        }
    )
    document = state()
    protected = build_protected_header(
        document,
        principal=expired_root,
        role="state_source",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=document_digest(trusted_time),
    )
    envelope = sign_document(document, private_key=keys["root"], protected=protected)
    assert verify_envelope(envelope, historical_policy, trusted_time=trusted_time)[0].valid


def test_genesis_authenticates_root_and_complete_envelope() -> None:
    policy, _, keys = trust_fixture()
    root = policy.spec.principals[0]
    protected = build_protected_header(
        policy,
        principal=root,
        role="workspace_root",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=None,
    )
    envelope = sign_document(policy, private_key=keys["root"], protected=protected)
    envelope_digest = digest_bytes(canonical_bytes(envelope.model_dump(mode="json")))
    result = inspect_genesis(
        envelope,
        expected_root_spki_fingerprint=public_key_fingerprint(root),
        expected_envelope_fingerprint=envelope_digest,
    )
    assert result.valid
    assert not validate_policy(policy)
    wrong = inspect_genesis(
        envelope,
        expected_root_spki_fingerprint=public_key_fingerprint(root),
        expected_envelope_fingerprint="sha256:" + "0" * 64,
    )
    assert not wrong.valid


def test_trusted_time_is_self_anchored_to_its_authority_not_local_wall_time() -> None:
    policy, receipt, keys = trust_fixture()
    time_principal = policy.spec.principals[2]
    protected = build_protected_header(
        receipt,
        principal=time_principal,
        role="timestamp",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=receipt.spec.issued_at,
        policy_sequence=0,
        trusted_time_receipt_digest=None,
    )
    envelope = sign_document(receipt, private_key=keys["time"], protected=protected)
    assert verify_envelope(envelope, policy, trusted_time=None)[0].valid

    wrong_authority = receipt.model_copy(
        update={
            "spec": receipt.spec.model_copy(update={"authority_principal_id": "root-principal"})
        }
    )
    wrong_header = build_protected_header(
        wrong_authority,
        principal=time_principal,
        role="timestamp",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=wrong_authority.spec.issued_at,
        policy_sequence=0,
        trusted_time_receipt_digest=None,
    )
    wrong_envelope = sign_document(
        wrong_authority,
        private_key=keys["time"],
        protected=wrong_header,
    )
    result, _ = verify_envelope(wrong_envelope, policy, trusted_time=None)
    assert not result.valid
    assert "trusted_time_authority_principal_mismatch" in result.reasons


def test_kms_raw_ecdsa_normalization_rejects_invalid_and_canonicalizes_high_s() -> None:
    from collective_phase_control_fabric.v6.trust import P256_ORDER

    with pytest.raises(ValueError, match="length_invalid"):
        normalize_p256_raw(b"short")
    with pytest.raises(ValueError, match="out_of_range"):
        normalize_p256_raw(b"\x00" * 64)
    high_s = P256_ORDER - 2
    normalized = normalize_p256_raw((1).to_bytes(32, "big") + high_s.to_bytes(32, "big"))
    assert int.from_bytes(normalized[:32], "big") == 1
    assert int.from_bytes(normalized[32:], "big") == 2
