# SPDX-License-Identifier: Apache-2.0
"""Pinned Ed25519 identity verification for CPCF v0.3."""

from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from collective_phase_control_fabric.canonical import canonical_v3_bytes, digest_bytes
from collective_phase_control_fabric.types import JsonObject, JsonValue, TruthStatus


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def signature_message(value: JsonObject, schema_ref: str) -> bytes:
    """Return the domain-separated bytes signed by a v0.3 principal."""

    payload = deepcopy(value)
    payload.pop("signature", None)
    domain = f"CPCF\0v0.3.0\0{schema_ref}\0".encode()
    return domain + canonical_v3_bytes(payload)


def _principal(policy: JsonObject, key_id: str) -> JsonObject | None:
    matches = [
        item
        for item in policy.get("principals", [])
        if isinstance(item, dict) and item.get("key_id") == key_id
    ]
    return matches[0] if len(matches) == 1 else None


def verify_pinned_signature(
    value: JsonObject,
    policy: JsonObject,
    *,
    schema_ref: str,
    source_system: str,
    role: str,
    evaluation_time: str,
) -> JsonObject:
    """Verify identity, authorization, lifecycle, scope, digest, and Ed25519 signature."""

    signature = value.get("signature")
    if not isinstance(signature, dict):
        return {"status": "false", "reasons": ["required_signature_missing"]}
    key_id = signature.get("key_id")
    if not isinstance(key_id, str):
        return {"status": "false", "reasons": ["signature_key_id_invalid"]}
    principal = _principal(policy, key_id)
    if principal is None:
        return {"status": "false", "reasons": ["pinned_key_unknown_or_duplicate"]}
    reasons: list[str] = []
    schema_name = schema_ref.split("@", 1)[0]
    if source_system not in principal.get("source_systems", []):
        reasons.append("source_system_not_authorized")
    if schema_name not in principal.get("schema_names", []):
        reasons.append("schema_not_authorized")
    if role not in principal.get("roles", []):
        reasons.append("role_not_authorized")
    if role == "evaluator" and value.get("evaluator_key_id") != key_id:
        reasons.append("evaluator_identity_signature_mismatch")
    if principal.get("revoked") is not False:
        reasons.append("pinned_key_revoked")
    evaluated = _time(evaluation_time)
    signed = _time(signature.get("signed_at"))
    not_before = _time(principal.get("not_before"))
    not_after = _time(principal.get("not_after"))
    if evaluated is None or signed is None or not_before is None or not_after is None:
        reasons.append("key_or_signature_time_invalid")
    else:
        if not (not_before <= signed <= evaluated <= not_after):
            reasons.append("key_or_signature_outside_validity_interval")
    principal_scope = principal.get("scope")
    value_scope = value.get("scope")
    if value_scope is not None and value_scope != principal_scope:
        reasons.append("signature_scope_mismatch")
    message = signature_message(value, schema_ref)
    if signature.get("payload_digest") != digest_bytes(message):
        reasons.append("signed_payload_digest_mismatch")
    try:
        key_bytes = base64.b64decode(str(principal["public_key_base64"]), validate=True)
        supplied = base64.b64decode(str(signature["signature_base64"]), validate=True)
        if len(key_bytes) != 32:
            raise ValueError("Ed25519 public key must contain 32 bytes")
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(supplied, message)
    except (KeyError, TypeError, ValueError, InvalidSignature):
        reasons.append("ed25519_signature_invalid")
    return {
        "status": "true" if not reasons else "false",
        "key_id": key_id,
        "reasons": sorted(set(reasons)),
        "single_key_compromise_resilient": False,
    }


def signature_coordinate(
    value: JsonValue,
    policy: JsonObject,
    *,
    schema_ref: str,
    source_system: str,
    role: str,
    evaluation_time: str,
    required: bool,
) -> TruthStatus | str:
    """Return a conservative signature coordinate for projection validation."""

    if not required:
        return "not_applicable"
    if not isinstance(value, dict):
        return "false"
    return str(
        verify_pinned_signature(
            value,
            policy,
            schema_ref=schema_ref,
            source_system=source_system,
            role=role,
            evaluation_time=evaluation_time,
        )["status"]
    )


def signable_payload(value: JsonObject, schema_ref: str) -> tuple[bytes, str]:
    """Expose signing bytes and digest for test fixtures and external tooling."""

    message = signature_message(value, schema_ref)
    return message, digest_bytes(message)
