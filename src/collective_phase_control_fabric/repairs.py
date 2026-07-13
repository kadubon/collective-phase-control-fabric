# SPDX-License-Identifier: Apache-2.0
"""Deterministic, typed repair generation without placeholder actions."""

from __future__ import annotations

from collective_phase_control_fabric.canonical import digest_json
from collective_phase_control_fabric.types import JsonObject


def _repair(kind: str, reason_refs: list[str], resolved: JsonObject | None = None) -> JsonObject:
    seed: JsonObject = {"repair_kind": kind, "reason_refs": sorted(reason_refs)}
    seed["repair_id"] = f"repair:{kind}:{digest_json(seed).split(':', 1)[1][:12]}"
    if resolved is None:
        seed.update(
            {
                "binding_status": "unbound_repair",
                "executable": False,
                "missing_bindings": [
                    "adapter",
                    "operation",
                    "exact_argv",
                    "authority",
                    "resource_bounds",
                    "output_schema",
                ],
            }
        )
    else:
        required = {
            "adapter",
            "operation",
            "exact_argv",
            "input_refs",
            "authority_refs",
            "resource_upper_bounds",
            "output_schema",
        }
        if required <= set(resolved):
            seed.update({"binding_status": "resolved", "executable": True, **resolved})
        else:
            seed.update({"binding_status": "unbound_repair", "executable": False})
    return seed


def generate_repairs(
    analysis: JsonObject, doctor_report: JsonObject | None = None
) -> list[JsonObject]:
    """Map observed deficits to stable repair classes."""

    repairs: list[JsonObject] = []
    doctor_report = doctor_report or {}
    for error in doctor_report.get("errors", []):
        code = str(error.get("code", "unknown")) if isinstance(error, dict) else str(error)
        mapping = {
            "schema_invalid": "ambiguous_schema",
            "digest_mismatch": "missing_or_invalid_digest",
            "receipt_missing": "missing_receipt",
            "unsupported_version": "unsupported_version",
            "expiry_invalid": "lifecycle_or_expiry_failure",
            "authority_invalid": "authority_gap",
            "hazard_invalid": "hazard_gap",
        }
        repairs.append(_repair(mapping.get(code, "missing_typed_input_or_output"), [code]))
    verification = analysis.get("verification_network", analysis.get("verification_load", {}))
    if not isinstance(verification, dict):
        verification = {}
    if verification.get("bottleneck_set") or verification.get("overloaded") is True:
        repairs.append(_repair("verifier_overload", ["verification:bottleneck"]))
    if analysis.get("regeneration_deadlocks"):
        repairs.append(_repair("deadlock_or_resource_sink", ["analysis:regeneration_deadlocks"]))
    formation = analysis.get("formation_sequence", {})
    if not isinstance(formation, dict):
        formation = {}
    if formation.get("valid") is not True:
        repairs.append(
            _repair(
                "formation_seed_deficit",
                formation.get("reasons", ["formation:unknown"]),
            )
        )
    for field, kind in (
        ("productive_witness", "missing_productive_evidence"),
        ("persistence", "missing_maintenance_evidence"),
        ("generative_catalysis", "missing_catalyst_evidence"),
        ("independent_support_core", "missing_robustness_evidence"),
    ):
        value = analysis.get(field, {})
        if (
            isinstance(value, dict)
            and value.get("valid", value.get("status") == "true") is not True
        ):
            repairs.append(_repair(kind, [f"analysis:{field}"]))
    unique = {str(item["repair_id"]): item for item in repairs}
    return [unique[key] for key in sorted(unique)]
