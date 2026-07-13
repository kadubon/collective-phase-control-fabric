# SPDX-License-Identifier: Apache-2.0
"""Shared JSON-oriented types and conservative status helpers."""

from __future__ import annotations

from typing import Any, Literal

type JsonObject = dict[str, Any]
type JsonValue = None | bool | int | float | str | list[Any] | JsonObject
type TruthStatus = Literal["true", "false", "unknown"]

VALID_NODE_TYPES = frozenset(
    {
        "artifact",
        "claim",
        "evidence",
        "verifier_report",
        "residual",
        "obligation",
        "task_reference",
        "authority_record",
        "hazard_record",
        "resource_record",
        "skill_candidate",
        "structural_enabler",
        "certified_catalyst",
        "capability_candidate",
        "admitted_capability",
        "memory_candidate",
        "admitted_memory",
        "lifecycle_record",
        "observation",
        "external_certificate",
        "target_state",
    }
)

EFFECT_CLASSES = ("inspect", "validate", "plan", "local_write", "external_effect")
VALID_LIFECYCLE = frozenset({"valid", "active"})
INVALID_LIFECYCLE = frozenset({"expired", "revoked", "deprecated"})


def tri(value: object) -> TruthStatus:
    """Return an explicit three-valued status without optimistic coercion."""

    if value is True or value == "true" or value == "valid":
        return "true"
    if value is False or value == "false" or value in INVALID_LIFECYCLE:
        return "false"
    return "unknown"


def id_set(values: object) -> set[str]:
    """Return string identifiers from a JSON list, rejecting other shapes."""

    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str)}
