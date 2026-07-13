# SPDX-License-Identifier: Apache-2.0
"""DSSE statements, pinned identity, trusted time, and role-separated quorum trust."""

from __future__ import annotations

import base64
from collections.abc import Iterable
from datetime import datetime
from typing import Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from collective_phase_control_fabric.v6.canonical import (
    canonical_bytes,
    digest_bytes,
    loads_bounded,
)
from collective_phase_control_fabric.v6.models import (
    Document,
    DsseEnvelope,
    DsseSignature,
    Principal,
    ProtectedHeader,
    SignedPayload,
    StrictModel,
    TrustedTimeReceipt,
    TrustPolicyDocument,
)
from collective_phase_control_fabric.v6.registry import (
    document_digest,
    parse_document,
    schema_digest,
)

PAYLOAD_TYPE: Literal["application/vnd.cpcf.statement+json;version=0.6"] = (
    "application/vnd.cpcf.statement+json;version=0.6"
)
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class VerificationResult(StrictModel):
    valid: bool
    code: str
    reasons: list[str]
    document_digest: str | None = None
    principal_id: str | None = None
    role: str | None = None
    protected: ProtectedHeader | None = None


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Produce DSSE v1 pre-authentication encoding."""

    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _public_key(principal: Principal) -> ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey:
    try:
        encoded = base64.b64decode(principal.public_key_base64, validate=True)
    except ValueError as error:
        raise ValueError("public_key_base64_invalid") from error
    if principal.algorithm == "ed25519":
        if len(encoded) != 32:
            raise ValueError("ed25519_public_key_length_invalid")
        return ed25519.Ed25519PublicKey.from_public_bytes(encoded)
    try:
        key = serialization.load_der_public_key(encoded)
    except ValueError as error:
        raise ValueError("ecdsa_public_key_der_invalid") from error
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("ecdsa_public_key_curve_invalid")
    return key


def public_key_fingerprint(principal: Principal) -> str:
    key = _public_key(principal)
    spki = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return digest_bytes(spki)


def validate_policy(policy: TrustPolicyDocument) -> list[str]:
    reasons: list[str] = []
    principals = policy.spec.principals
    for attribute in ("principal_id", "key_id"):
        values = [getattr(principal, attribute) for principal in principals]
        if len(values) != len(set(values)):
            reasons.append(f"duplicate_{attribute}")
    fingerprints: list[str] = []
    for principal in principals:
        try:
            fingerprints.append(public_key_fingerprint(principal))
        except ValueError as error:
            reasons.append(str(error))
        if principal.valid_until <= principal.valid_from:
            reasons.append("principal_validity_interval_invalid")
        if principal.compromised_at is not None and principal.revoked_at is None:
            reasons.append("compromise_requires_revocation")
    if len(fingerprints) != len(set(fingerprints)):
        reasons.append("public_key_reused_by_multiple_principals")
    roots = [item for item in principals if "workspace_root" in item.roles]
    if len(roots) != 1 or roots[0].key_id != policy.spec.root_key_id:
        reasons.append("exactly_one_matching_workspace_root_required")
    rules = [rule.decision_type for rule in policy.spec.quorum_rules]
    if len(rules) != len(set(rules)):
        reasons.append("duplicate_quorum_decision_type")
    if policy.spec.policy_sequence == 0 and policy.spec.prior_policy_digest is not None:
        reasons.append("genesis_policy_cannot_have_predecessor")
    if policy.spec.policy_sequence > 0 and policy.spec.prior_policy_digest is None:
        reasons.append("non_genesis_policy_requires_predecessor")
    return sorted(set(reasons))


def _principal(policy: TrustPolicyDocument, key_id: str, principal_id: str) -> Principal | None:
    matches = [
        item
        for item in policy.spec.principals
        if item.key_id == key_id and item.principal_id == principal_id
    ]
    return matches[0] if len(matches) == 1 else None


def _signature_bytes(
    private_key: ed25519.Ed25519PrivateKey  # gitleaks:allow -- type annotation only
    | ec.EllipticCurvePrivateKey,
    message: bytes,
) -> bytes:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(message)
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    s = min(s, P256_ORDER - s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify_signature(
    principal: Principal,
    message: bytes,
    signature: bytes,
) -> None:
    key = _public_key(principal)
    if isinstance(key, ed25519.Ed25519PublicKey):
        key.verify(signature, message)
        return
    if len(signature) != 64:
        raise InvalidSignature
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r <= 0 or r >= P256_ORDER or s <= 0 or s > P256_ORDER // 2:
        raise InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))


def build_protected_header(
    document: Document,
    *,
    principal: Principal,
    role: str,
    source_system: str,
    scope: list[str],
    signing_time: datetime,
    policy_sequence: int,
    trusted_time_receipt_digest: str | None,
) -> ProtectedHeader:
    return ProtectedHeader(
        schema_name=document.kind,
        schema_digest=schema_digest(document.kind),
        payload_digest=document_digest(document),
        key_id=principal.key_id,
        principal_id=principal.principal_id,
        role=role,
        source_system=source_system,
        scope=scope,
        tenant_id=document.metadata.tenant_id,
        workspace_id=document.metadata.workspace_id,
        signing_time=signing_time,
        policy_sequence=policy_sequence,
        trusted_time_receipt_digest=trusted_time_receipt_digest,
    )


def sign_document(
    document: Document,
    *,
    private_key: ed25519.Ed25519PrivateKey  # gitleaks:allow -- type annotation only
    | ec.EllipticCurvePrivateKey,
    protected: ProtectedHeader,
    envelope_key_hint: str = "",
) -> DsseEnvelope:
    """Create a DSSE envelope. This helper is for fixtures and KMS adapter conformance."""

    payload = SignedPayload(
        protected=protected,
        subject=document.model_dump(mode="json", exclude_none=True),
    )
    payload_bytes = canonical_bytes(payload.model_dump(mode="json", exclude_none=True))
    signature = _signature_bytes(private_key, dsse_pae(PAYLOAD_TYPE, payload_bytes))
    return DsseEnvelope(
        payloadType=PAYLOAD_TYPE,
        payload=base64.b64encode(payload_bytes).decode("ascii"),
        signatures=[
            DsseSignature(keyid=envelope_key_hint, sig=base64.b64encode(signature).decode("ascii"))
        ],
    )


def _time_status(
    principal: Principal,
    signed_at: datetime,
    authoritative_time: datetime,
) -> list[str]:
    reasons: list[str] = []
    if signed_at > authoritative_time:
        reasons.append("signature_from_future")
    if signed_at < principal.valid_from or signed_at > principal.valid_until:
        reasons.append("signing_time_outside_key_validity")
    if principal.revoked_at is not None:
        if principal.revocation_mode == "prospective" and signed_at >= principal.revoked_at:
            reasons.append("signature_after_revocation")
        if principal.revocation_mode == "retroactive":
            cutoff = principal.compromised_at
            if cutoff is None or signed_at >= cutoff:
                reasons.append("signature_invalidated_by_retroactive_revocation")
    return reasons


def verify_envelope(
    envelope: DsseEnvelope,
    policy: TrustPolicyDocument,
    *,
    trusted_time: TrustedTimeReceipt | None,
) -> tuple[VerificationResult, Document | None]:
    reasons = validate_policy(policy)
    try:
        payload_bytes = base64.b64decode(envelope.payload, validate=True)
        raw_payload = loads_bounded(payload_bytes)
        payload = SignedPayload.model_validate_json(canonical_bytes(raw_payload), strict=True)
        document = parse_document(payload.subject)
    except (ValueError, TypeError) as error:
        return VerificationResult(
            valid=False, code="signed_payload_invalid", reasons=[str(error)]
        ), None
    protected = payload.protected
    principal = _principal(policy, protected.key_id, protected.principal_id)
    if principal is None:
        reasons.append("pinned_principal_unknown_or_ambiguous")
    if protected.schema_name != document.kind:
        reasons.append("schema_kind_mismatch")
    if protected.schema_digest != schema_digest(document.kind):
        reasons.append("schema_digest_mismatch")
    actual_digest = document_digest(document)
    if protected.payload_digest != actual_digest:
        reasons.append("payload_digest_mismatch")
    if protected.tenant_id != document.metadata.tenant_id:
        reasons.append("tenant_binding_mismatch")
    if protected.workspace_id != document.metadata.workspace_id:
        reasons.append("workspace_binding_mismatch")
    if protected.policy_sequence > policy.spec.policy_sequence:
        reasons.append("policy_sequence_from_future")
    authoritative_time: datetime | None = None
    if trusted_time is not None:
        if document_digest(trusted_time) != protected.trusted_time_receipt_digest:
            reasons.append("trusted_time_receipt_binding_mismatch")
        authoritative_time = trusted_time.spec.issued_at
        if trusted_time.spec.valid_until < authoritative_time:
            reasons.append("trusted_time_receipt_expired_at_issue")
    elif isinstance(document, TrustedTimeReceipt):
        authoritative_time = document.spec.issued_at
        if document.spec.authority_principal_id != protected.principal_id:
            reasons.append("trusted_time_authority_principal_mismatch")
        if document.spec.valid_until < document.spec.issued_at:
            reasons.append("trusted_time_receipt_expired_at_issue")
    elif isinstance(document, TrustPolicyDocument) and document.spec.policy_sequence == 0:
        # Genesis has an out-of-band envelope fingerprint but cannot establish wall-clock time.
        authoritative_time = protected.signing_time
    else:
        reasons.append("authoritative_time_receipt_required")
    if principal is not None:
        if protected.role not in principal.roles:
            reasons.append("role_not_authorized")
        if protected.source_system not in principal.source_systems:
            reasons.append("source_system_not_authorized")
        if document.kind not in principal.allowed_kinds:
            reasons.append("document_kind_not_authorized")
        if not set(protected.scope).issubset(principal.scope):
            reasons.append("scope_not_authorized")
        if authoritative_time is not None:
            reasons.extend(_time_status(principal, protected.signing_time, authoritative_time))
        message = dsse_pae(envelope.payloadType, payload_bytes)
        valid_signature = False
        for signature_entry in envelope.signatures:
            signature_verified = False
            try:
                signature = base64.b64decode(signature_entry.sig, validate=True)
                _verify_signature(principal, message, signature)
            except Exception:
                # Cryptographic verification is a fail-closed boundary. Provider, parser, and
                # backend exceptions cannot promote authority; process-control exceptions are
                # BaseException subclasses and are deliberately not swallowed.
                signature_verified = False
            else:
                signature_verified = True
            if signature_verified:
                valid_signature = True
                break
        if not valid_signature:
            reasons.append("signature_invalid")
    reasons = sorted(set(reasons))
    return (
        VerificationResult(
            valid=not reasons,
            code="verified" if not reasons else "statement_not_verified",
            reasons=reasons,
            document_digest=actual_digest,
            principal_id=protected.principal_id,
            role=protected.role,
            protected=protected,
        ),
        document,
    )


def evaluate_quorum(
    decision_type: str,
    subject_digest: str,
    envelopes: Iterable[DsseEnvelope],
    policy: TrustPolicyDocument,
    *,
    trusted_time: TrustedTimeReceipt,
) -> VerificationResult:
    rule = next(
        (item for item in policy.spec.quorum_rules if item.decision_type == decision_type), None
    )
    if rule is None:
        return VerificationResult(valid=False, code="quorum_rule_missing", reasons=[decision_type])
    results: list[VerificationResult] = []
    principals: list[Principal] = []
    for envelope in envelopes:
        result, _ = verify_envelope(envelope, policy, trusted_time=trusted_time)
        if result.valid and result.protected is not None:
            if result.protected.payload_digest != subject_digest:
                return VerificationResult(
                    valid=False,
                    code="quorum_subject_mismatch",
                    reasons=[result.protected.payload_digest],
                )
            principal = _principal(policy, result.protected.key_id, result.protected.principal_id)
            if principal is not None:
                results.append(result)
                principals.append(principal)
    roles = [cast(str, item.role) for item in results]
    reasons: list[str] = []
    if set(roles) != set(rule.required_roles) or len(roles) != len(rule.required_roles):
        reasons.append("required_quorum_roles_not_satisfied")
    for attribute in ("principal_id", "key_id"):
        values = [getattr(item, attribute) for item in principals]
        if len(values) != len(set(values)):
            reasons.append(f"quorum_{attribute}_collision")
    if rule.distinct_infrastructure:
        values = [item.infrastructure_domain for item in principals]
        if len(values) != len(set(values)):
            reasons.append("quorum_infrastructure_collision")
    if rule.distinct_correlation:
        values = [item.correlation_domain for item in principals]
        if len(values) != len(set(values)):
            reasons.append("quorum_correlation_collision")
    reasons = sorted(set(reasons))
    return VerificationResult(
        valid=not reasons,
        code="quorum_satisfied" if not reasons else "quorum_not_satisfied",
        reasons=reasons,
        document_digest=subject_digest,
    )


def inspect_genesis(
    envelope: DsseEnvelope,
    *,
    expected_root_spki_fingerprint: str,
    expected_envelope_fingerprint: str,
) -> VerificationResult:
    envelope_bytes = canonical_bytes(envelope.model_dump(mode="json", exclude_none=True))
    reasons: list[str] = []
    if digest_bytes(envelope_bytes) != expected_envelope_fingerprint:
        reasons.append("genesis_envelope_fingerprint_mismatch")
    try:
        raw_payload = loads_bounded(base64.b64decode(envelope.payload, validate=True))
        payload = SignedPayload.model_validate_json(canonical_bytes(raw_payload), strict=True)
        document = parse_document(payload.subject)
    except (ValueError, TypeError) as error:
        return VerificationResult(valid=False, code="genesis_invalid", reasons=[str(error)])
    if not isinstance(document, TrustPolicyDocument) or document.spec.policy_sequence != 0:
        reasons.append("genesis_policy_required")
        return VerificationResult(valid=False, code="genesis_invalid", reasons=reasons)
    root = next(
        (item for item in document.spec.principals if item.key_id == document.spec.root_key_id),
        None,
    )
    if root is None or public_key_fingerprint(root) != expected_root_spki_fingerprint:
        reasons.append("genesis_root_spki_fingerprint_mismatch")
    result, _ = verify_envelope(envelope, document, trusted_time=None)
    reasons.extend(result.reasons)
    reasons = sorted(set(reasons))
    return VerificationResult(
        valid=not reasons,
        code="genesis_verified" if not reasons else "genesis_invalid",
        reasons=reasons,
        document_digest=document_digest(document),
    )


def verify_policy_update(
    prior_policy: TrustPolicyDocument,
    candidate_policy: TrustPolicyDocument,
    statements: Iterable[DsseEnvelope],
    *,
    trusted_time: TrustedTimeReceipt,
) -> VerificationResult:
    """Verify one monotonic role-separated policy transition under the prior policy."""

    reasons = validate_policy(candidate_policy)
    if candidate_policy.spec.policy_sequence != prior_policy.spec.policy_sequence + 1:
        reasons.append("trust_policy_sequence_not_monotonic")
    if candidate_policy.spec.prior_policy_digest != document_digest(prior_policy):
        reasons.append("trust_policy_predecessor_mismatch")
    quorum = evaluate_quorum(
        "trust_update",
        document_digest(candidate_policy),
        statements,
        prior_policy,
        trusted_time=trusted_time,
    )
    if not quorum.valid:
        reasons.extend(quorum.reasons)
    reasons = sorted(set(reasons))
    return VerificationResult(
        valid=not reasons,
        code="trust_policy_update_verified" if not reasons else "trust_policy_update_rejected",
        reasons=reasons,
        document_digest=document_digest(candidate_policy),
    )


def verify_trusted_time_advance(
    previous: TrustedTimeReceipt,
    candidate_envelope: DsseEnvelope,
    policy: TrustPolicyDocument,
) -> tuple[VerificationResult, TrustedTimeReceipt | None]:
    """Verify externally signed monotonic time without consulting the local wall clock."""

    preliminary, document = verify_envelope(candidate_envelope, policy, trusted_time=None)
    if not isinstance(document, TrustedTimeReceipt):
        reasons = [*preliminary.reasons, "trusted_time_receipt_subject_required"]
        return (
            VerificationResult(
                valid=False,
                code="trusted_time_advance_rejected",
                reasons=sorted(set(reasons)),
            ),
            None,
        )
    bound, verified = verify_envelope(candidate_envelope, policy, trusted_time=document)
    reasons = [*preliminary.reasons, *bound.reasons]
    if document.spec.issued_at <= previous.spec.issued_at:
        reasons.append("trusted_time_not_monotonic")
    if document.spec.nonce == previous.spec.nonce:
        reasons.append("trusted_time_nonce_reused")
    reasons = sorted(set(reasons))
    return (
        VerificationResult(
            valid=not reasons,
            code="trusted_time_advanced" if not reasons else "trusted_time_advance_rejected",
            reasons=reasons,
            document_digest=document_digest(document),
            principal_id=bound.principal_id,
            role=bound.role,
            protected=bound.protected,
        ),
        cast(TrustedTimeReceipt, verified) if not reasons else None,
    )
