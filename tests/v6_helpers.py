# SPDX-License-Identifier: Apache-2.0
"""Deterministic typed fixtures for v0.6 tests."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collective_phase_control_fabric.v6.models import (
    DOCUMENT_MODELS,
    MANDATORY_DIMENSIONS,
    Metadata,
    Principal,
    QuorumRule,
    TrustedTimeReceipt,
    TrustedTimeSpec,
    TrustPolicyDocument,
    TrustPolicySpec,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
VALID_FROM = datetime(2020, 1, 1, tzinfo=UTC)
VALID_UNTIL = datetime(2030, 1, 1, tzinfo=UTC)
TENANT = "tenant-a"
WORKSPACE = "workspace-a"


def metadata(object_id: str, at: datetime = NOW) -> Metadata:
    return Metadata(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        object_id=object_id,
        created_at=at,
    )


def keypair(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def principal(
    principal_id: str,
    key_id: str,
    key: Ed25519PrivateKey,
    roles: list[str],
    domain: str,
) -> Principal:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return Principal(
        principal_id=principal_id,
        key_id=key_id,
        algorithm="ed25519",
        public_key_base64=base64.b64encode(raw).decode("ascii"),
        roles=roles,
        source_systems=["fixture-source"],
        allowed_kinds=sorted(DOCUMENT_MODELS),
        scope=[WORKSPACE],
        infrastructure_domain=f"infra-{domain}",
        correlation_domain=f"correlation-{domain}",
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
    )


def trust_fixture() -> tuple[
    TrustPolicyDocument,
    TrustedTimeReceipt,
    dict[str, Ed25519PrivateKey],
]:
    keys = {
        "root": keypair(1),
        "auditor": keypair(2),
        "time": keypair(3),
        "runner": keypair(4),
    }
    principals = [
        principal(
            "root-principal",
            "root-key",
            keys["root"],
            [
                "workspace_root",
                "protocol_author",
                "evaluator",
                "projection_authority",
                "state_source",
                "job_dispatcher",
                "capability_authority",
            ],
            "root",
        ),
        principal(
            "auditor-principal",
            "auditor-key",
            keys["auditor"],
            [
                "trust_auditor",
                "registration",
                "quality_safety_verifier",
                "projection_verifier",
                "execution_policy_authority",
            ],
            "auditor",
        ),
        principal(
            "time-principal",
            "time-key",
            keys["time"],
            ["timestamp"],
            "time",
        ),
        principal(
            "runner-principal",
            "runner-key",
            keys["runner"],
            ["runner_receipt"],
            "runner",
        ),
    ]
    policy = TrustPolicyDocument(
        metadata=metadata("policy-0"),
        spec=TrustPolicySpec(
            policy_sequence=0,
            root_key_id="root-key",
            principals=principals,
            quorum_rules=[
                QuorumRule(
                    decision_type="trust_update",
                    required_roles=["workspace_root", "trust_auditor", "timestamp"],
                ),
                QuorumRule(
                    decision_type="protocol_registration",
                    required_roles=["protocol_author", "registration", "timestamp"],
                ),
                QuorumRule(
                    decision_type="acceleration_compatibility",
                    required_roles=["evaluator", "quality_safety_verifier", "timestamp"],
                ),
                QuorumRule(
                    decision_type="projection_promotion",
                    required_roles=["projection_authority", "projection_verifier"],
                ),
            ],
        ),
    )
    time_receipt = TrustedTimeReceipt(
        metadata=metadata("time-1"),
        spec=TrustedTimeSpec(
            authority_principal_id="time-principal",
            issued_at=NOW,
            valid_until=datetime(2026, 1, 2, tzinfo=UTC),
            nonce="time-nonce-1",
        ),
    )
    return policy, time_receipt, keys


def mandatory_dimensions() -> list[str]:
    return list(MANDATORY_DIMENSIONS)
