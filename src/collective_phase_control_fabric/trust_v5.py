# SPDX-License-Identifier: Apache-2.0
"""Schema-bound Ed25519 statements and disjoint-role quorum trust for CPCF v0.5."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from collective_phase_control_fabric.canonical import canonical_v3_bytes, digest_v3_json
from collective_phase_control_fabric.schema import load_schema, validation_errors
from collective_phase_control_fabric.types import JsonObject, JsonValue

V5 = "0.5.0"
DOMAIN = "CPCF-SIGNED-STATEMENT"
CANONICALIZATION_PROFILE = "RFC8785-CPCF-FLOAT-FREE-1"

QUORUM_ROLES: dict[str, tuple[str, ...]] = {
    "trust_update": ("workspace_root", "trust_auditor", "timestamp"),
    "protocol_registration": ("protocol_author", "registration", "timestamp"),
    "acceleration_compatibility": ("evaluator", "quality_safety_verifier", "timestamp"),
    "projection_promotion": ("projection_authority", "projection_verifier"),
}


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def key_fingerprint(public_key_base64: str) -> str:
    key = base64.b64decode(public_key_base64, validate=True)
    if len(key) != 32:
        raise ValueError("Ed25519 public key must contain 32 bytes")
    return "sha256:" + hashlib.sha256(key).hexdigest()


def schema_digest(schema_ref: str) -> str:
    """Return the canonical digest of the exact installed schema named by a schema reference."""

    try:
        name, version = schema_ref.rsplit("@", 1)
    except ValueError as error:
        raise ValueError("schema reference must be NAME@VERSION") from error
    if version != V5:
        raise ValueError("native statement schema version must be 0.5.0")
    return digest_v3_json(cast(JsonValue, load_schema(name, version)))


def validate_policy(policy: JsonObject, root_fingerprint: str | None = None) -> list[JsonObject]:
    """Validate one v0.5 policy and its identity, role, and genesis invariants."""

    errors = validation_errors("trust-policy", policy, V5)
    principals = [item for item in policy.get("principals", []) if isinstance(item, dict)]
    for field in ("principal_id", "key_id"):
        values = [str(item.get(field)) for item in principals]
        if len(values) != len(set(values)):
            errors.append({"message": f"duplicate {field}", "json_pointer": "/principals"})
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
        if principal.get("revoked") is False and principal.get("revoked_at") is not None:
            errors.append(
                {
                    "message": "non-revoked principal cannot declare revoked_at",
                    "json_pointer": f"/principals/{index}/revoked_at",
                }
            )
        revoked_at = _time(principal.get("revoked_at"))
        compromised_at = _time(principal.get("compromised_at"))
        if principal.get("revoked") is True and revoked_at is None:
            errors.append(
                {
                    "message": "revoked principal requires revoked_at",
                    "json_pointer": f"/principals/{index}/revoked_at",
                }
            )
        if revoked_at is not None and compromised_at is not None and compromised_at > revoked_at:
            errors.append(
                {
                    "message": "compromised_at cannot follow revoked_at",
                    "json_pointer": f"/principals/{index}/compromised_at",
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
    rules = policy.get("quorum_rules")
    if isinstance(rules, dict):
        for decision, expected in QUORUM_ROLES.items():
            if tuple(rules.get(decision, [])) != expected:
                errors.append(
                    {
                        "message": (
                            f"quorum roles for {decision} do not match the native safety profile"
                        ),
                        "json_pointer": f"/quorum_rules/{decision}",
                    }
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
    return canonical_v3_bytes(protected)


def protected_header(
    payload: JsonValue,
    *,
    schema_ref: str,
    key_id: str,
    principal_id: str,
    signed_at: str,
    role: str,
    source_system: str,
    scope: JsonObject,
) -> JsonObject:
    """Construct all signature-protected v0.5 metadata."""

    return {
        "domain": DOMAIN,
        "cpcf_version": V5,
        "canonicalization_profile": CANONICALIZATION_PROFILE,
        "schema_ref": schema_ref,
        "schema_digest": schema_digest(schema_ref),
        "key_id": key_id,
        "principal_id": principal_id,
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
    validate_payload: bool = True,
) -> JsonObject:
    """Recompute schema, payload, identity, lifecycle, scope, and Ed25519 validity."""

    reasons = [
        f"statement_schema:{item['json_pointer']}:{item['message']}"
        for item in validation_errors("signed-statement", statement, V5)
    ]
    protected = statement.get("protected")
    payload = statement.get("payload")
    if not isinstance(protected, dict):
        return {"status": "false", "reasons": sorted(set([*reasons, "protected_header_missing"]))}
    key_id = protected.get("key_id")
    principal = _principal(policy, str(key_id)) if isinstance(key_id, str) else None
    if principal is None:
        reasons.append("pinned_key_unknown_or_duplicate")
    if protected.get("domain") != DOMAIN or protected.get("cpcf_version") != V5:
        reasons.append("signature_domain_or_version_mismatch")
    if protected.get("canonicalization_profile") != CANONICALIZATION_PROFILE:
        reasons.append("canonicalization_profile_mismatch")
    schema_ref = protected.get("schema_ref")
    if isinstance(schema_ref, str):
        try:
            installed_digest = schema_digest(schema_ref)
        except (KeyError, ValueError):
            reasons.append("signed_schema_unknown")
        else:
            if protected.get("schema_digest") != installed_digest:
                reasons.append("signed_schema_digest_mismatch")
            if validate_payload:
                name = schema_ref.rsplit("@", 1)[0]
                reasons.extend(
                    f"payload_schema:{item['json_pointer']}:{item['message']}"
                    for item in validation_errors(name, cast(JsonValue, payload), V5)
                )
    else:
        reasons.append("signed_schema_missing")
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
    if protected.get("payload_digest") != digest_v3_json(cast(JsonValue, payload)):
        reasons.append("signed_payload_digest_mismatch")
    evaluated = _time(authoritative_time)
    signed = _time(protected.get("signed_at"))
    if evaluated is None or signed is None:
        reasons.append("authoritative_or_signing_time_invalid")
    elif signed > evaluated:
        reasons.append("signature_from_future")
    if principal is not None:
        if protected.get("principal_id") != principal.get("principal_id"):
            reasons.append("principal_identity_mismatch")
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
        revoked_at = _time(principal.get("revoked_at"))
        compromised_at = _time(principal.get("compromised_at"))
        if signed is None or evaluated is None or not_before is None or not_after is None:
            reasons.append("key_validity_time_invalid")
        elif not (not_before <= signed <= evaluated <= not_after):
            reasons.append("key_or_statement_outside_validity_interval")
        if signed is not None:
            if principal.get("revoked") is True and (revoked_at is None or signed >= revoked_at):
                reasons.append("pinned_key_revoked_at_signing_time")
            if compromised_at is not None and signed >= compromised_at:
                reasons.append("pinned_key_compromised_at_signing_time")
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
        "principal_id": protected.get("principal_id"),
        "payload_digest": protected.get("payload_digest"),
        "schema_digest": protected.get("schema_digest"),
        "reasons": sorted(set(reasons)),
        "role_separation": True,
        "threshold_cryptography": False,
    }


def verify_genesis(
    policy: JsonObject,
    genesis_statement: JsonObject,
    root_fingerprint: str,
    authoritative_time: str,
) -> JsonObject:
    """Authenticate the complete genesis policy with its out-of-band pinned root."""

    reasons = [str(item["message"]) for item in validate_policy(policy, root_fingerprint)]
    if genesis_statement.get("payload") != policy:
        reasons.append("genesis_statement_payload_not_complete_policy")
    roots = [
        item
        for item in policy.get("principals", [])
        if isinstance(item, dict) and item.get("key_id") == policy.get("root_key_id")
    ]
    root_scope = cast(JsonObject, roots[0].get("scope", {})) if len(roots) == 1 else {}
    checked = verify_statement(
        genesis_statement,
        policy,
        authoritative_time=authoritative_time,
        expected_schema_ref="trust-policy@0.5.0",
        expected_role="workspace_root",
        expected_scope=root_scope,
    )
    reasons.extend(str(item) for item in checked.get("reasons", []))
    if genesis_statement.get("protected", {}).get("key_id") != policy.get("root_key_id"):
        reasons.append("genesis_not_signed_by_declared_root")
    return {"status": "true" if not reasons else "false", "reasons": sorted(set(reasons))}


def verify_time_receipt(
    statement: JsonObject, policy: JsonObject, *, expected_subject_digest: str | None = None
) -> JsonObject:
    payload = statement.get("payload")
    if not isinstance(payload, dict) or _time(payload.get("event_time")) is None:
        return {"status": "false", "reasons": ["time_receipt_payload_or_event_time_invalid"]}
    checked = verify_statement(
        statement,
        policy,
        authoritative_time=str(payload["event_time"]),
        expected_schema_ref="trusted-time-receipt@0.5.0",
        expected_role="timestamp",
    )
    reasons = list(checked.get("reasons", []))
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
        **checked,
        "status": "true" if not reasons else "false",
        "event_time": payload.get("event_time"),
        "serial": payload.get("serial"),
        "subject_digest": payload.get("subject_digest"),
        "reasons": sorted(set(reasons)),
    }


def verify_role_quorum(
    statements: list[JsonObject],
    policy: JsonObject,
    *,
    decision_type: str,
    authoritative_time: str,
    subject_digest: str,
) -> JsonObject:
    """Verify a fixed disjoint-role quorum over one identical decision payload."""

    expected_roles = QUORUM_ROLES.get(decision_type)
    if expected_roles is None:
        return {"status": "false", "reasons": ["unknown_quorum_decision_type"]}
    reasons: list[str] = []
    verified_by_role: dict[str, JsonObject] = {}
    payload_digest: str | None = None
    for statement in statements:
        protected = statement.get("protected")
        payload = statement.get("payload")
        if not isinstance(protected, dict) or not isinstance(payload, dict):
            reasons.append("quorum_statement_malformed")
            continue
        role = str(protected.get("role"))
        checked = verify_statement(
            statement,
            policy,
            authoritative_time=authoritative_time,
            expected_schema_ref="trust-quorum-decision@0.5.0",
            expected_role=role,
        )
        reasons.extend(str(item) for item in checked.get("reasons", []))
        if role not in expected_roles:
            reasons.append(f"unexpected_quorum_role:{role}")
        elif role in verified_by_role:
            reasons.append(f"duplicate_quorum_role:{role}")
        else:
            verified_by_role[role] = statement
        current_digest = digest_v3_json(payload)
        payload_digest = current_digest if payload_digest is None else payload_digest
        if payload_digest != current_digest:
            reasons.append("quorum_payload_mismatch")
        if payload.get("decision_type") != decision_type:
            reasons.append("quorum_decision_type_mismatch")
        if payload.get("subject_digest") != subject_digest:
            reasons.append("quorum_subject_digest_mismatch")
        if payload.get("policy_sequence") != policy.get("policy_sequence"):
            reasons.append("quorum_policy_sequence_mismatch")
    missing = sorted(set(expected_roles) - set(verified_by_role))
    reasons.extend(f"missing_quorum_role:{role}" for role in missing)
    principals: list[JsonObject] = []
    for statement in verified_by_role.values():
        protected = cast(JsonObject, statement["protected"])
        principal = _principal(policy, str(protected["key_id"]))
        if principal is not None:
            principals.append(principal)
    key_ids = [str(item.get("key_id")) for item in principals]
    principal_ids = [str(item.get("principal_id")) for item in principals]
    if len(key_ids) != len(set(key_ids)) or len(principal_ids) != len(set(principal_ids)):
        reasons.append("quorum_identity_not_disjoint")
    for domain_field in ("infrastructure_domains", "correlation_domains"):
        observed: set[str] = set()
        for principal in principals:
            domains = {str(item) for item in principal.get(domain_field, [])}
            if observed & domains:
                reasons.append(f"quorum_{domain_field}_not_disjoint")
            observed |= domains
    return {
        "status": "true" if not reasons else "false",
        "decision_type": decision_type,
        "roles": sorted(verified_by_role),
        "principal_ids": sorted(principal_ids),
        "reasons": sorted(set(reasons)),
        "threshold_cryptography": False,
    }
