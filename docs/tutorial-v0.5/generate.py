# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic and explicitly non-production CPCF v0.5 tutorial assets."""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from collective_phase_control_fabric.canonical import digest_bytes, digest_v3_json, write_canonical
from collective_phase_control_fabric.trust_v5 import (
    QUORUM_ROLES,
    key_fingerprint,
    protected_header,
    schema_digest,
    statement_message,
)
from collective_phase_control_fabric.workspace_v5 import MANDATORY_DIMENSIONS

SCOPE = {"project": "cpcf-v0.5-tutorial", "environment": "disposable-local"}
NOW = "2026-07-13T00:00:00Z"


def key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def public(private: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def sign(
    private: Ed25519PrivateKey,
    payload: object,
    *,
    name: str,
    role: str,
    source_system: str,
) -> dict[str, object]:
    protected = protected_header(
        payload,
        schema_ref=f"{name}@0.5.0",
        key_id=f"key:{source_system}",
        principal_id=f"principal:{source_system}",
        signed_at=NOW,
        role=role,
        source_system=source_system,
        scope=SCOPE,
    )
    return {
        "schema_version": "0.5.0",
        "protected": protected,
        "payload": payload,
        "signature_base64": base64.b64encode(private.sign(statement_message(protected))).decode(),
    }


def interval(unit: str) -> dict[str, str]:
    return {"lower": "0", "upper": "0", "unit": unit}


def branch(additions: list[str]) -> dict[str, object]:
    return {
        "must_add": additions,
        "may_add": [],
        "must_remove": [],
        "may_remove": [],
        "debt": [],
        "rollback_obligations": [],
        "independence_domains_removed": [],
        "resource_intervals": {},
        "time_interval": interval("second"),
        "cost_interval": interval("credit"),
        "quality_interval": interval("quality"),
        "verification_load_upper": "0",
        "projection_possibilities": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    output = args.out.absolute()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    names = (
        "root",
        "auditor",
        "time",
        "source",
        "action",
        "capability",
        "projection-verifier",
    )
    keys = {name: key(index) for index, name in enumerate(names, 1)}
    roles = {
        "root": ["workspace_root"],
        "auditor": ["trust_auditor"],
        "time": ["timestamp"],
        "source": ["source"],
        "action": ["action_author"],
        "capability": ["projection_authority"],
        "projection-verifier": ["projection_verifier"],
    }
    schemas = {
        "root": ["trust-policy", "trust-quorum-decision"],
        "auditor": ["trust-quorum-decision"],
        "time": ["trusted-time-receipt", "trust-quorum-decision"],
        "source": ["principal-attestation"],
        "action": ["principal-attestation"],
        "capability": ["principal-attestation"],
        "projection-verifier": ["projection-approval"],
    }
    policy = {
        "schema_version": "0.5.0",
        "policy_id": "policy:tutorial",
        "policy_sequence": 0,
        "previous_policy_digest": None,
        "root_key_id": "key:root",
        "principals": [
            {
                "principal_id": f"principal:{name}",
                "key_id": f"key:{name}",
                "public_key_base64": public(keys[name]),
                "source_systems": [name],
                "schema_names": schemas[name],
                "roles": roles[name],
                "scope": SCOPE,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
                "infrastructure_domains": [f"infrastructure:{name}"],
                "correlation_domains": [],
                "revoked_at": None,
                "compromised_at": None,
            }
            for name in names
        ],
        "quorum_rules": {name: list(value) for name, value in QUORUM_ROLES.items()},
    }
    registry = {
        "schema_version": "0.5.0",
        "registry_id": "units:tutorial",
        "base_dimensions": ["amount", "time", "cost", "quality"],
        "units": {
            "unit": {"scale": "1", "dimension_vector": {"amount": 1}},
            "second": {"scale": "1", "dimension_vector": {"time": 1}},
            "credit": {"scale": "1", "dimension_vector": {"cost": 1}},
            "quality": {"scale": "1", "dimension_vector": {"quality": 1}},
        },
    }
    contract = {
        "schema_version": "0.5.0",
        "contract_id": "contract:tutorial",
        "scope": SCOPE,
        "target_states": ["state:target"],
        "initial_available_states": [],
        "protected_floors": {},
        "resource_envelope": {},
        "control_policy": {
            "planning_horizon": 1,
            "beam_width": 32,
            "candidate_cap": 64,
            "retry_limit": 0,
        },
        "required_dimensions": sorted(MANDATORY_DIMENSIONS),
        "perturbation_suite_refs": ["suite:tutorial"],
        "analysis_limits": {
            "maximum_raw_bytes": 1_048_576,
            "maximum_json_depth": 32,
            "maximum_nodes": 100,
            "maximum_transformations": 100,
            "maximum_rational_bits": 256,
            "maximum_operations": 10_000,
            "solver_seconds": 5,
        },
        "non_claims": [
            "collective superintelligence inference",
            "physical phase equivalence",
            "causal acceleration certification",
        ],
        "unit_registry_ref": digest_v3_json(registry),
        "minimum_effective_independence": 2,
    }
    genesis = sign(
        keys["root"], policy, name="trust-policy", role="workspace_root", source_system="root"
    )
    time_payload = {
        "schema_version": "0.5.0",
        "receipt_id": "time:tutorial",
        "receipt_type": "trusted_time",
        "event_time": NOW,
        "subject_digest": digest_v3_json(contract),
        "serial": 1,
    }
    trusted_time = sign(
        keys["time"],
        time_payload,
        name="trusted-time-receipt",
        role="timestamp",
        source_system="time",
    )
    for filename, value in (
        ("trust-policy.json", policy),
        ("unit-registry.json", registry),
        ("phase-contract.json", contract),
        ("genesis.json", genesis),
        ("trusted-time.json", trusted_time),
    ):
        write_canonical(output / filename, value)

    runtime = output / ("adapter-runtime.exe" if sys.platform == "win32" else "adapter-runtime")
    # This digest-pinned interpreter is retained as an inspection fixture only. A copied
    # interpreter is not a hermetic adapter because its standard library and shared-library
    # closure are not present in CAS; v0.6 never treats this legacy object as executable.
    shutil.copy2(getattr(sys, "_base_executable", sys.executable), runtime)
    runtime_digest = digest_bytes(runtime.read_bytes())
    adapter_output = {
        "schema_version": "0.5.0",
        "outcome": "success",
        "projections": [],
    }
    adapter_code = f"import json;print(json.dumps({adapter_output!r}))"
    capability_attributes = {
        "evidence_type": "adapter_capability",
        "executable": "CAS_ONLY",
        "executable_digest": runtime_digest,
        "material_digests": [],
        "argv_prefix": ["{executable}", "-c", adapter_code],
        "arguments": [],
        "execution_policy": {
            "schema_version": "0.5.0",
            "policy_id": "execution:tutorial",
            "timeout_seconds": 10,
            "stdin_bytes": 0,
            "stdout_bytes": 1_048_576,
            "stderr_bytes": 1_048_576,
            "permitted_environment_keys": ["PATH", "SYSTEMROOT"],
        },
        "output_schema_ref": "adapter-output@0.5.0",
        "output_schema_digest": schema_digest("adapter-output@0.5.0"),
        "exit_code_mapping": {"0": "success"},
        "outcome_selector": {
            "source_pointer": "/outcome",
            "mapping": {"success": "success"},
        },
        "projection_routes": [],
        "branches": {name: branch([]) for name in ("success", "partial", "failure", "timeout")},
    }
    action_attributes = {
        "evidence_type": "action",
        "capability_ref": "capability:tutorial",
        "arguments": [],
        "input_refs": [],
        "required_authority_refs": [],
        "required_hazard_refs": [],
        "expires_at": "2026-12-31T00:00:00Z",
        "repeatable": False,
        "must_add": [],
        "resource_intervals": {},
        "debt": [],
        "verification_load": "0",
        "independence_erosion": 0,
    }
    for stem, signer, subject, attributes in (
        ("capability", "capability", "capability:tutorial", capability_attributes),
        ("action", "action", "action:tutorial", action_attributes),
    ):
        projected = {
            "record_type": "evidence",
            "subject_id": subject,
            "lifecycle": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-12-31T00:00:00Z",
            "lineage_refs": [f"lineage:{stem}"],
            "correlation_domains": [],
            "attributes": attributes,
        }
        raw_path = output / f"{stem}-raw.json"
        write_canonical(raw_path, {"value": projected})
        payload = {
            "schema_version": "0.5.0",
            "attestation_id": f"attestation:{stem}",
            **projected,
            "subject_digest": digest_v3_json(projected),
            "source_artifact_digest": digest_bytes(raw_path.read_bytes()),
            "source_pointer": "/value",
        }
        role = "projection_authority" if signer == "capability" else "action_author"
        write_canonical(
            output / f"{stem}-attestation.json",
            sign(
                keys[signer],
                payload,
                name="principal-attestation",
                role=role,
                source_system=signer,
            ),
        )
    write_canonical(
        output / "coordination-plan.json",
        {
            "schema_version": "0.5.0",
            "plan_id": "plan:tutorial",
            "participant_principals": ["principal:action", "principal:source"],
            "verifier_stage_refs": ["verifier:tutorial"],
            "maximum_exposure_events": 10,
            "termination_rule": "all_verified",
        },
    )
    (output / "ROOT_FINGERPRINT.txt").write_text(
        key_fingerprint(public(keys["root"])) + "\n", encoding="ascii"
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "root_fingerprint": key_fingerprint(public(keys["root"])),
                "non_production": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
