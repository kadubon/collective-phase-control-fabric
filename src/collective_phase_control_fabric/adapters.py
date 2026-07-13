# SPDX-License-Identifier: Apache-2.0
"""Verified read-only CCR 1.6.0 and PIC 1.1.0 adapters."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from collective_phase_control_fabric.canonical import digest_bytes
from collective_phase_control_fabric.process import run_process
from collective_phase_control_fabric.schema import validation_errors
from collective_phase_control_fabric.types import JsonObject

SUPPORTED_UPSTREAMS = {"ccr": "1.6.0", "pic": "1.1.0"}

ADAPTER_OPERATIONS: dict[str, dict[str, list[str]]] = {
    "ccr": {
        "agent_explain": ["agent", "explain", "--json"],
    },
    "pic": {
        "agent_explain": ["agent", "explain"],
        "agent_check": [
            "agent",
            "check",
            "--compact",
            "--no-allow-live-connectors",
            "--text",
            "CPCF compatibility probe; preserve unresolved obligations.",
            "--profile",
            "development",
        ],
        "phase_plan": [
            "phase",
            "plan",
            "--compact",
            "--no-allow-live-connectors",
            "--text",
            "CPCF compatibility probe; preserve unresolved obligations.",
            "--profile",
            "development",
        ],
        "canonical_readiness": [
            "audit",
            "canonical-readiness",
            "--profile",
            "development",
            "--format",
            "json",
        ],
    },
}

REQUIRED_KEYS: dict[tuple[str, str], set[str]] = {
    ("ccr", "agent_explain"): {"ok", "agent_manifest", "safe_boundaries", "v1_6_runtime"},
    ("pic", "agent_explain"): {"name", "version", "machine_contract", "safe_first_commands"},
    ("pic", "agent_check"): {
        "accepted",
        "operationally_usable",
        "settled",
        "unresolved_obligations",
        "schema_refs",
    },
    ("pic", "phase_plan"): {
        "accepted",
        "operationally_usable",
        "settled",
        "phase_gap_vector",
        "cannot_promote_because",
    },
    ("pic", "canonical_readiness"): {"accepted", "profile"},
}

PROJECTION_MAPPINGS: dict[tuple[str, str], list[JsonObject]] = {
    key: [{"source_pointer": "/", "target_schema": "pending"}] for key in REQUIRED_KEYS
}

REPORT_SCHEMAS = {
    ("ccr", "agent_explain"): "ccr-agent-explain-report",
    ("pic", "agent_explain"): "pic-agent-explain-report",
    ("pic", "agent_check"): "pic-agent-check-report",
    ("pic", "phase_plan"): "pic-phase-plan-report",
    ("pic", "canonical_readiness"): "pic-canonical-readiness-report",
}
for mapping_key, mapping in PROJECTION_MAPPINGS.items():
    mapping[0]["target_schema"] = f"{REPORT_SCHEMAS[mapping_key]}@0.2.0"
    mapping[0]["required_source_pointers"] = [
        f"/{field}" for field in sorted(REQUIRED_KEYS[mapping_key])
    ]


def capability_manifest() -> JsonObject:
    """Return only operations verified against latest source CLI help and report shapes."""

    return {
        "manifest_version": "0.2.0",
        "adapters": [
            {
                "adapter": adapter,
                "supported_source_version": SUPPORTED_UPSTREAMS[adapter],
                "operations": sorted(operations),
                "effect_classes": (
                    ["inspect"] if adapter == "ccr" else ["inspect", "validate", "plan"]
                ),
                "network_class": "upstream_process_network_disabled_or_not_requested",
                "external_effect_supported": False,
                "safe_commands_are_authority": False,
                "projection_mappings": {
                    operation: PROJECTION_MAPPINGS[(adapter, operation)]
                    for operation in sorted(operations)
                },
            }
            for adapter, operations in sorted(ADAPTER_OPERATIONS.items())
        ],
    }


def _parse(receipt: JsonObject) -> JsonObject | None:
    try:
        value = json.loads(str(receipt["stdout_utf8"]))
    except (json.JSONDecodeError, KeyError):
        return None
    return value if isinstance(value, dict) else None


def _version_handshake(adapter: str, executable: str, cwd: Path) -> tuple[bool, JsonObject]:
    command = ADAPTER_OPERATIONS[adapter]["agent_explain"]
    receipt = run_process([executable, *command], cwd, cwd, timeout_seconds=30)
    report = _parse(receipt)
    valid = report is not None and not validation_errors(
        REPORT_SCHEMAS[(adapter, "agent_explain")], report, "0.2.0"
    )
    return valid, receipt


def invoke_read_only_adapter(adapter: str, operation: str, cwd: Path) -> JsonObject:
    """Invoke a registered read-only operation after a latest-version handshake."""

    if adapter not in ADAPTER_OPERATIONS or operation not in ADAPTER_OPERATIONS[adapter]:
        return {"command_status": "failed", "reason": "unsupported_adapter_operation"}
    executable = shutil.which(adapter)
    if executable is None:
        return {"command_status": "failed", "reason": "upstream_executable_not_found"}
    version_valid, handshake = _version_handshake(adapter, executable, cwd.resolve())
    if not version_valid:
        return {
            "command_status": "failed",
            "reason": "unsupported_version",
            "supported_source_version": SUPPORTED_UPSTREAMS[adapter],
            "handshake_receipt": handshake,
        }
    command = ADAPTER_OPERATIONS[adapter][operation]
    argv = [executable]
    argv.extend(command)
    receipt = run_process(argv, cwd.resolve(), cwd.resolve(), timeout_seconds=60)
    report = _parse(receipt)
    required = REQUIRED_KEYS[(adapter, operation)]
    missing = sorted(required - set(report or {}))
    schema_errors = (
        validation_errors(REPORT_SCHEMAS[(adapter, operation)], report, "0.2.0")
        if report is not None
        else [{"message": "report is not a JSON object", "json_pointer": "/"}]
    )
    schema_valid = not schema_errors
    raw = bytes.fromhex(str(receipt["stdout_raw_hex"]))
    artifact_digest = digest_bytes(raw)
    accepted: object = "not_applicable"
    settled: object = "not_applicable"
    operationally_usable: object = "unknown"
    if report is not None:
        accepted = report.get("accepted", "not_applicable")
        settled = report.get("settled", "not_applicable")
        operationally_usable = report.get("operationally_usable", report.get("ok", "unknown"))
    return {
        "command_status": "ok" if schema_valid else "failed",
        "adapter": adapter,
        "operation": operation,
        "supported_source_version": SUPPORTED_UPSTREAMS[adapter],
        "schema_valid": schema_valid,
        "missing_required_fields": missing,
        "schema_ref": f"{REPORT_SCHEMAS[(adapter, operation)]}@0.2.0",
        "schema_errors": schema_errors,
        "source_decisions": [
            {
                "source_system": adapter,
                "source_ref": artifact_digest,
                "accepted": accepted,
                "settled": settled,
                "authorized": "not_applicable",
                "operationally_usable": operationally_usable,
                "executed": "not_applicable",
                "physical_outcome_verified": "not_applicable",
                "source_json_pointers": [f"/{key}" for key in sorted(required)],
                "raw_artifact_ref": artifact_digest,
            }
        ],
        "process_receipt": receipt,
        "handshake_receipt": handshake,
        "raw_report": report,
        "raw_artifact_persisted": False,
        "persistence_command": "cpcf source import ... --workspace CPCF_WORKSPACE --apply",
        "safe_commands_executed": False,
        "external_effect": False,
    }
