# SPDX-License-Identifier: Apache-2.0
"""Evidence-bound Ed25519 statements and trusted time for CPCF v0.4."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from collective_phase_control_fabric.canonical import canonical_v3_bytes, digest_v3_json
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject, JsonValue

V4 = "0.4.0"
DOMAIN = "CPCF-SIGNED-STATEMENT"


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def key_fingerprint(public_key_base64: str) -> str:
    """Return the out-of-band fingerprint of one raw Ed25519 public key."""

    key = base64.b64decode(public_key_base64, validate=True)
    if len(key) != 32:
        raise ValueError("Ed25519 public key must contain 32 bytes")
    return "sha256:" + hashlib.sha256(key).hexdigest()


def validate_policy(policy: JsonObject, root_fingerprint: str | None = None) -> list[JsonObject]:
    """Validate schema, unique principals, unique public keys, and root bootstrap."""

    errors = validation_errors("trust-policy", policy, V4)
    principals = [item for item in policy.get("principals", []) if isinstance(item, dict)]
    key_ids = [str(item.get("key_id")) for item in principals]
    if len(key_ids) != len(set(key_ids)):
        errors.append({"message": "duplicate key_id", "json_pointer": "/principals"})
    decoded: list[bytes] = []
    for index, principal in enumerate(principals):
        try:
            key = base64.b64decode(str(principal["public_key_base64"]), validate=True)
            if len(key) != 32:
                raise ValueError("wrong Ed25519 key length")
            decoded.append(key)
        except (KeyError, ValueError):
            errors.append(
                {
                    "message": "invalid Ed25519 public key",
                    "json_pointer": f"/principals/{index}/public_key_base64",
                }
            )
    if len(decoded) != len(set(decoded)):
        errors.append(
            {"message": "public key reused by multiple principals", "json_pointer": "/principals"}
        )
    roots = [item for item in principals if "workspace_root" in item.get("roles", [])]
    if len(roots) != 1:
        errors.append(
            {
                "message": "exactly one workspace_root principal is required",
                "json_pointer": "/principals",
            }
        )
    elif roots[0].get("key_id") != policy.get("root_key_id"):
        errors.append({"message": "root_key_id mismatch", "json_pointer": "/root_key_id"})
    if root_fingerprint is not None and roots:
        try:
            actual = key_fingerprint(str(roots[0]["public_key_base64"]))
        except (KeyError, ValueError):
            actual = "invalid"
        if actual != root_fingerprint:
            errors.append(
                {"message": "out-of-band root fingerprint mismatch", "json_pointer": "/root_key_id"}
            )
    return errors


def _principal(policy: JsonObject, key_id: str) -> JsonObject | None:
    matches = [
        item
        for item in policy.get("principals", [])
        if isinstance(item, dict) and item.get("key_id") == key_id
    ]
    return matches[0] if len(matches) == 1 else None


def statement_message(protected: JsonObject) -> bytes:
    """Return the only bytes signed by a v0.4 statement."""

    return canonical_v3_bytes(protected)


def protected_header(
    payload: JsonValue,
    *,
    schema_ref: str,
    key_id: str,
    signed_at: str,
    role: str,
    source_system: str,
    scope: JsonObject,
) -> JsonObject:
    """Construct a complete protected header for external signing."""

    return {
        "domain": DOMAIN,
        "cpcf_version": V4,
        "schema_ref": schema_ref,
        "key_id": key_id,
        "signed_at": signed_at,
        "payload_digest": digest_v3_json(payload),
        "role": role,
        "source_system": source_system,
        "scope": scope,
    }


def verify_statement(
    statement: JsonObject,
    policy: JsonObject,
    *,
    authoritative_time: str,
    expected_schema_ref: str | None = None,
    expected_role: str | None = None,
    expected_source_system: str | None = None,
    expected_scope: JsonObject | None = None,
) -> JsonObject:
    """Verify protected metadata, payload binding, authorization, lifecycle, and signature."""

    reasons: list[str] = []
    reasons.extend(
        f"schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("signed-statement", statement, V4)
    )
    protected = statement.get("protected")
    payload = statement.get("payload")
    if not isinstance(protected, dict):
        return {"status": "false", "reasons": sorted(set([*reasons, "protected_header_missing"]))}
    key_id = protected.get("key_id")
    principal = _principal(policy, str(key_id)) if isinstance(key_id, str) else None
    if principal is None:
        reasons.append("pinned_key_unknown_or_duplicate")
    if protected.get("domain") != DOMAIN or protected.get("cpcf_version") != V4:
        reasons.append("signature_domain_or_version_mismatch")
    schema_ref = protected.get("schema_ref")
    role = protected.get("role")
    source_system = protected.get("source_system")
    scope = protected.get("scope")
    if expected_schema_ref is not None and schema_ref != expected_schema_ref:
        reasons.append("signed_schema_mismatch")
    if expected_role is not None and role != expected_role:
        reasons.append("signed_role_mismatch")
    if expected_source_system is not None and source_system != expected_source_system:
        reasons.append("signed_source_system_mismatch")
    if expected_scope is not None and scope != expected_scope:
        reasons.append("signed_scope_mismatch")
    if protected.get("payload_digest") != digest_v3_json(payload):
        reasons.append("signed_payload_digest_mismatch")
    evaluated = _time(authoritative_time)
    signed = _time(protected.get("signed_at"))
    if evaluated is None or signed is None:
        reasons.append("authoritative_or_signing_time_invalid")
    elif signed > evaluated:
        reasons.append("signature_from_future")
    if principal is not None:
        if principal.get("revoked") is not False:
            reasons.append("pinned_key_revoked")
        if role not in principal.get("roles", []):
            reasons.append("role_not_authorized")
        if source_system not in principal.get("source_systems", []):
            reasons.append("source_system_not_authorized")
        name = str(schema_ref).split("@", 1)[0]
        if name not in principal.get("schema_names", []):
            reasons.append("schema_not_authorized")
        if scope != principal.get("scope"):
            reasons.append("principal_scope_mismatch")
        not_before = _time(principal.get("not_before"))
        not_after = _time(principal.get("not_after"))
        if signed is None or evaluated is None or not_before is None or not_after is None:
            reasons.append("key_validity_time_invalid")
        elif not (not_before <= signed <= evaluated <= not_after):
            reasons.append("key_or_statement_outside_validity_interval")
        try:
            public = base64.b64decode(str(principal["public_key_base64"]), validate=True)
            signature = base64.b64decode(str(statement["signature_base64"]), validate=True)
            if len(public) != 32:
                raise ValueError("wrong Ed25519 key length")
            Ed25519PublicKey.from_public_bytes(public).verify(
                signature, statement_message(protected)
            )
        except (KeyError, TypeError, ValueError, InvalidSignature):
            reasons.append("ed25519_signature_invalid")
    return {
        "status": "true" if not reasons else "false",
        "key_id": key_id,
        "payload_digest": protected.get("payload_digest"),
        "reasons": sorted(set(reasons)),
        "single_key_compromise_resilient": False,
    }


def verify_time_receipt(
    statement: JsonObject, policy: JsonObject, *, expected_subject_digest: str | None = None
) -> JsonObject:
    """Verify one externally signed time assertion and return its authoritative event time."""

    payload = statement.get("payload")
    if not isinstance(payload, dict):
        return {"status": "false", "reasons": ["time_receipt_payload_missing"]}
    event_time = payload.get("event_time")
    if _time(event_time) is None:
        return {"status": "false", "reasons": ["time_receipt_event_time_invalid"]}
    verified = verify_statement(
        statement,
        policy,
        authoritative_time=str(event_time),
        expected_schema_ref="trusted-time-receipt@0.4.0",
        expected_role="timestamp",
    )
    reasons = list(verified.get("reasons", []))
    if payload.get("receipt_type") != "trusted_time":
        reasons.append("time_receipt_type_invalid")
    if (
        expected_subject_digest is not None
        and payload.get("subject_digest") != expected_subject_digest
    ):
        reasons.append("time_receipt_subject_mismatch")
    if not isinstance(payload.get("serial"), int) or int(payload["serial"]) < 0:
        reasons.append("time_receipt_serial_invalid")
    return {
        **verified,
        "status": "true" if not reasons else "false",
        "event_time": event_time,
        "serial": payload.get("serial"),
        "subject_digest": payload.get("subject_digest"),
        "reasons": sorted(set(reasons)),
    }
