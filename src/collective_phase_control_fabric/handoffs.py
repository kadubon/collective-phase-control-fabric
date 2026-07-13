# SPDX-License-Identifier: Apache-2.0
"""Fixture-verifiable candidate handoff and external certificate boundaries."""

from __future__ import annotations

from pathlib import Path

from collective_phase_control_fabric.canonical import digest_bytes, load_json
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject

HANDOFF_KINDS = frozenset(
    {
        "capability_admission_candidate",
        "proof_carrying_skill_candidate",
        "residual_evidence_candidate",
        "governed_memory_candidate",
    }
)
EXTERNAL_KINDS = frozenset({"collective_advantage", "phase_evidence"})


def verify_handoff(path: Path) -> JsonObject:
    """Validate a candidate without representing downstream acceptance."""

    raw = path.read_bytes()
    value = load_json(path)
    if not isinstance(value, dict):
        return {"command_status": "failed", "errors": ["handoff_must_be_an_object"]}
    kind = value.get("kind", value.get("certificate_kind"))
    if kind in HANDOFF_KINDS:
        errors = validation_errors("handoff-candidate", value)
        source_system = value.get("source_system", "unknown")
        source_ref = value.get("handoff_id", "unknown")
    elif kind in EXTERNAL_KINDS:
        errors = []
        required = {
            "certificate_id",
            "certificate_kind",
            "evaluator_and_method" if kind == "phase_evidence" else "evaluator",
        }
        errors.extend(
            {"message": f"required field missing: {field}", "json_pointer": f"/{field}"}
            for field in sorted(required - set(value))
        )
        if value.get("measurement_reproved_by_cpcf") is not False:
            errors.append(
                {
                    "message": "measurement_reproved_by_cpcf must be false",
                    "json_pointer": "/measurement_reproved_by_cpcf",
                }
            )
        if kind == "phase_evidence":
            errors.extend(validation_errors("phase-evidence-certificate", value))
        source_system = value.get("evaluator", "external-evaluator")
        source_ref = value.get("certificate_id", "unknown")
    else:
        return {"command_status": "failed", "errors": ["unsupported_handoff_kind"]}
    return {
        "command_status": "ok" if not errors else "failed",
        "handoff_status": "candidate" if not errors else "invalid",
        "kind": kind,
        "errors": errors,
        "source_decisions": [
            {
                "source_system": source_system,
                "source_ref": source_ref,
                "accepted": "unknown",
                "settled": "unknown",
                "authorized": "not_applicable",
                "operationally_usable": "unknown",
                "executed": "not_applicable",
                "physical_outcome_verified": "not_applicable",
                "source_json_pointers": ["/kind" if kind in HANDOFF_KINDS else "/certificate_kind"],
                "raw_artifact_ref": digest_bytes(raw),
            }
        ],
        "downstream_acceptance_inferred": False,
        "measurement_reproved_by_cpcf": False,
    }
