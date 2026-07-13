# SPDX-License-Identifier: Apache-2.0
"""Machine-readable v0.6 agent guidance and stable local failure catalog."""

from __future__ import annotations

from typing import Final

AGENT_GUIDANCE: Final[dict[str, object]] = {
    "api_version": "cpcf.io/v0.6",
    "native_result": "operational_organization_profile",
    "acceleration_authority": "externally_registered_evidence_only",
    "first_safe_commands": [
        ["cpcf", "agent", "explain", "--json"],
        ["cpcf", "self-check", "--json"],
        ["cpcf", "schema", "list", "--json"],
    ],
    "offline_capabilities": [
        "schema inspection",
        "installation self-check",
        "portable bundle verification",
        "read-only legacy inspection",
    ],
    "nonclaims": [
        "collective-superintelligence phase detection or creation",
        "causality or statistical validity",
        "thermodynamic feasibility or physical phase behavior",
        "local process sandboxing",
        "production readiness without completed release gates",
    ],
}

ERROR_CATALOG: Final[dict[str, dict[str, object]]] = {
    "authoritative_time_required": {
        "effect_class": "none",
        "recovery": ["Import a trusted-time receipt admitted under the active policy."],
    },
    "bearer_token_required": {
        "effect_class": "none",
        "recovery": ["Set CPCF_TOKEN to a short-lived OIDC access token."],
    },
    "bundle_verification_failed": {
        "effect_class": "none",
        "recovery": ["Re-export the bundle from its authoritative generation."],
    },
    "candidate_set_overflow_unknown": {
        "effect_class": "none",
        "recovery": ["Narrow the signed action registry without dropping safety filters."],
    },
    "control_plane_unavailable": {
        "effect_class": "none",
        "recovery": ["Verify CPCF_API_URL, OIDC authority, and service readiness."],
    },
    "document_schema_invalid": {
        "effect_class": "none",
        "recovery": ["Validate the object against the installed schema digest."],
    },
    "legacy_mutation_blocked": {
        "effect_class": "none",
        "recovery": ["Use cpcf legacy inspect only for a registered read-only command."],
    },
    "offline_self_check_failed": {
        "effect_class": "none",
        "recovery": ["Reinstall the wheel under a supported CPython version."],
    },
    "projection_not_promoted": {
        "effect_class": "none",
        "recovery": ["Reconstruct source pointers and obtain the required independent approval."],
    },
    "quorum_not_satisfied": {
        "effect_class": "none",
        "recovery": ["Obtain role-separated signatures from distinct admitted principals."],
    },
    "unknown_document_kind": {
        "effect_class": "none",
        "recovery": ["Run cpcf schema list --json and select a registered kind."],
    },
    "unsupported_document_version": {
        "effect_class": "none",
        "recovery": ["Inspect legacy content read-only and migrate by copy."],
    },
}
