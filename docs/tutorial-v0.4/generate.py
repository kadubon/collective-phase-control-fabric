# SPDX-License-Identifier: Apache-2.0
"""Generate deterministic, explicitly non-production CPCF v0.4 tutorial assets."""

from __future__ import annotations

import argparse
import base64
import sys
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collective_phase_control_fabric.canonical import digest_bytes, digest_v3_json, write_canonical
from collective_phase_control_fabric.trust_v4 import (
    key_fingerprint,
    protected_header,
    statement_message,
)

SCOPE = {"project": "cpcf-v0.4-tutorial", "environment": "disposable-local"}
SIGNED_AT = "2026-01-01T00:00:00Z"
EPOCH = "2026-04-01T00:00:00Z"


def key(number: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)


def public(private: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()


def sign(
    private: Ed25519PrivateKey,
    payload: object,
    *,
    schema_ref: str,
    key_id: str,
    role: str,
    source_system: str,
    signed_at: str = SIGNED_AT,
) -> dict[str, object]:
    protected = protected_header(
        payload,
        schema_ref=schema_ref,
        key_id=key_id,
        signed_at=signed_at,
        role=role,
        source_system=source_system,
        scope=SCOPE,
    )
    return {
        "schema_version": "0.4.0",
        "protected": protected,
        "payload": payload,
        "signature_base64": base64.b64encode(private.sign(statement_message(protected))).decode(),
    }


def file_digest(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def typed_attestation(
    output: Path,
    private: Ed25519PrivateKey,
    stem: str,
    *,
    record_type: str,
    subject_id: str,
    attributes: dict[str, object],
) -> tuple[Path, Path]:
    projected = {
        "record_type": record_type,
        "subject_id": subject_id,
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "lineage_refs": [f"lineage:{stem}"],
        "correlation_domains": ["correlation:tutorial"],
        "attributes": attributes,
    }
    raw_path = output / f"{stem}-raw.json"
    write_canonical(raw_path, {"value": projected})
    payload = {
        "schema_version": "0.4.0",
        "attestation_id": f"attestation:{stem}",
        **projected,
        "subject_digest": digest_v3_json(projected),
        "source_artifact_digest": file_digest(raw_path),
        "source_pointer": "/value",
    }
    statement = sign(
        private,
        payload,
        schema_ref="principal-attestation@0.4.0",
        key_id="key:source",
        role="source",
        source_system="tutorial",
    )
    attestation_path = output / f"{stem}-attestation.json"
    write_canonical(attestation_path, statement)
    return raw_path, attestation_path


def branch() -> dict[str, object]:
    interval = {"lower": "0", "upper": "0", "unit": "tutorial-unit"}
    return {
        "must_add": [],
        "may_add": [],
        "must_remove": [],
        "may_remove": [],
        "debt": [],
        "rollback_obligations": [],
        "independence_domains_removed": [],
        "resource_intervals": {},
        "time_interval": interval,
        "cost_interval": interval,
        "quality_interval": interval,
        "verification_load_upper": "0",
        "projection_possibilities": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    root, clock, source, trial, registrar, attacker = (key(index) for index in range(1, 7))
    principals = [
        ("root", root, ["root"], ["trust-policy"], ["workspace_root"]),
        ("clock", clock, ["clock"], ["trusted-time-receipt"], ["timestamp"]),
        ("source", source, ["tutorial"], ["principal-attestation"], ["source"]),
        (
            "trial",
            trial,
            ["tutorial-trial"],
            ["measurement-protocol", "trial-result-certificate"],
            ["protocol_author", "evaluator"],
        ),
        (
            "registration",
            registrar,
            ["tutorial-registry"],
            ["registration-receipt"],
            ["registration"],
        ),
    ]
    policy = {
        "schema_version": "0.4.0",
        "policy_id": "policy:tutorial",
        "policy_sequence": 0,
        "previous_policy_digest": None,
        "root_key_id": "key:root",
        "principals": [
            {
                "principal_id": f"principal:{name}",
                "key_id": f"key:{name}",
                "public_key_base64": public(private),
                "source_systems": systems,
                "schema_names": schemas,
                "roles": roles,
                "scope": SCOPE,
                "not_before": "2025-12-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
            }
            for name, private, systems, schemas, roles in principals
        ],
    }
    contract = {
        "schema_version": "0.4.0",
        "contract_id": "contract:tutorial",
        "scope": {**SCOPE, "one_safe_profile": True},
        "target_states": ["state:seed"],
        "initial_available_states": [],
        "protected_floors": {},
        "resource_envelope": {},
        "control_policy": {
            "planning_horizon": 1,
            "beam_width": 32,
            "candidate_cap": 64,
            "retry_limit": 0,
        },
        "required_dimensions": [
            "provenance_integrity",
            "structural_reachability",
            "perturbation_robustness",
        ],
        "perturbation_suite_refs": ["suite:tutorial"],
        "analysis_limits": {
            "maximum_raw_bytes": 1048576,
            "maximum_json_depth": 32,
            "maximum_nodes": 100,
            "maximum_transformations": 100,
            "maximum_rational_bits": 256,
            "maximum_operations": 10000,
            "solver_seconds": 5,
        },
        "non_claims": [
            "collective superintelligence inference",
            "physical phase inference",
            "causal certification",
        ],
    }
    write_canonical(output / "phase-contract.json", contract)
    write_canonical(output / "trust-policy.json", policy)
    time_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "time:tutorial",
        "receipt_type": "trusted_time",
        "event_time": EPOCH,
        "subject_digest": digest_v3_json(contract),
        "serial": 1,
    }
    write_canonical(
        output / "trusted-time.json",
        sign(
            clock,
            time_payload,
            schema_ref="trusted-time-receipt@0.4.0",
            key_id="key:clock",
            role="timestamp",
            source_system="clock",
            signed_at=EPOCH,
        ),
    )
    typed_attestation(
        output,
        source,
        "state",
        record_type="state",
        subject_id="state:seed",
        attributes={"available": True},
    )
    typed_attestation(
        output,
        source,
        "suite",
        record_type="evidence",
        subject_id="suite:tutorial",
        attributes={
            "evidence_type": "perturbation_suite",
            "scenarios": [
                {"scenario_id": "no-removal-control", "remove_subjects": [], "remove_key_ids": []}
            ],
            "acceptance_dimensions": ["provenance_integrity", "structural_reachability"],
        },
    )
    adapter = output / "adapter.py"
    adapter.write_text(
        "import json\n"
        "print(json.dumps({'outcome': 'success', "
        "'observation': {'tutorial': True}}))\n",
        encoding="utf-8",
    )
    action_attributes = {
        "evidence_type": "action",
        "executable": sys.executable,
        "executable_digest": file_digest(Path(sys.executable)),
        "argv_prefix": [sys.executable, str(adapter)],
        "arguments": [],
        "execution_policy": {
            "schema_version": "0.4.0",
            "policy_id": "execution:tutorial",
            "timeout_seconds": 10,
            "stdin_bytes": 0,
            "stdout_bytes": 65536,
            "stderr_bytes": 65536,
            "permitted_environment_keys": [],
        },
        "output_schema_ref": "tutorial-output@0.4.0",
        "outcome_selector": {
            "source_pointer": "/outcome",
            "mapping": {"success": "success"},
        },
        "input_refs": ["state:seed"],
        "required_authority_refs": [],
        "required_hazard_refs": [],
        "expires_at": "2026-12-31T23:59:59Z",
        "repeatable": False,
        "branches": {
            name: deepcopy(branch()) for name in ("success", "partial", "failure", "timeout")
        },
        "must_add": [],
        "resource_intervals": {},
        "debt": [],
        "verification_load": "0",
        "independence_erosion": 0,
    }
    typed_attestation(
        output,
        source,
        "action",
        record_type="evidence",
        subject_id="action:tutorial",
        attributes=action_attributes,
    )

    forged_projected = {
        "record_type": "independence",
        "subject_id": "independence:forged",
        "lifecycle": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "lineage_refs": [],
        "correlation_domains": [],
        "attributes": {"independence_domain": "invented"},
    }
    forged_payload = {
        "schema_version": "0.4.0",
        "attestation_id": "attestation:forged",
        **forged_projected,
        "subject_digest": digest_v3_json(forged_projected),
        "source_artifact_digest": "sha256:" + "0" * 64,
        "source_pointer": "/value",
    }
    write_canonical(
        output / "forged-independence.json",
        sign(
            attacker,
            forged_payload,
            schema_ref="principal-attestation@0.4.0",
            key_id="key:source",
            role="source",
            source_system="tutorial",
        ),
    )

    dataset = {"schema_version": "0.4.0", "dataset_id": "dataset:tutorial", "rows": 4}
    analysis = {
        "schema_version": "0.4.0",
        "executable_id": "analysis:tutorial",
        "method": "externally-declared-placeholder",
    }
    write_canonical(output / "dataset.json", dataset)
    write_canonical(output / "analysis-spec.json", analysis)
    dataset_digest = file_digest(output / "dataset.json")
    analysis_digest = file_digest(output / "analysis-spec.json")
    protocol_payload = {
        "schema_version": "0.4.0",
        "protocol_id": "protocol:tutorial",
        "primary_result_id": "result:tutorial-primary",
        "eligibility": {"declared": True},
        "treatment_strategy": {"name": "cpcf"},
        "comparison_strategy": {"name": "preregistered-control"},
        "assignment": {"method": "external"},
        "time_zero": "2026-02-01T00:00:00Z",
        "observation_end": "2026-03-01T00:00:00Z",
        "estimand": {"name": "time-difference"},
        "primary_outcomes": ["time", "quality"],
        "dataset_commitment_digest": dataset_digest,
        "analysis_executable_digest": analysis_digest,
        "quality_floors": {"quality": {"quantity": "0", "unit": "score"}},
        "safety_floors": {},
        "missing_data_policy": {"method": "external"},
        "stopping_rule": {"fixed_end": True},
        "exclusion_policy": {"declared": True},
        "amendment_policy": {"post_start_compatible": False},
        "evaluator_key_id": "key:trial",
        "registration_key_id": "key:registration",
    }
    protocol = sign(
        trial,
        protocol_payload,
        schema_ref="measurement-protocol@0.4.0",
        key_id="key:trial",
        role="protocol_author",
        source_system="tutorial-trial",
    )
    write_canonical(output / "protocol.json", protocol)
    registration_payload = {
        "schema_version": "0.4.0",
        "receipt_id": "registration:tutorial",
        "protocol_digest": digest_v3_json(protocol),
        "registered_at": "2026-01-02T00:00:00Z",
        "serial": 1,
    }
    write_canonical(
        output / "registration.json",
        sign(
            registrar,
            registration_payload,
            schema_ref="registration-receipt@0.4.0",
            key_id="key:registration",
            role="registration",
            source_system="tutorial-registry",
            signed_at="2026-01-02T00:00:00Z",
        ),
    )
    for name, interval in (
        ("inconclusive", {"lower": "-1", "upper": "1", "unit": "hour"}),
        ("supported", {"lower": "-2", "upper": "-1", "unit": "hour"}),
    ):
        result_payload = {
            "schema_version": "0.4.0",
            "result_id": "result:tutorial-primary",
            "protocol_id": "protocol:tutorial",
            "protocol_digest": digest_v3_json(protocol),
            "dataset_digest": dataset_digest,
            "analysis_executable_digest": analysis_digest,
            "observation_started_at": "2026-02-01T00:00:00Z",
            "observation_ended_at": "2026-03-01T00:00:00Z",
            "completed_at": "2026-03-02T00:00:00Z",
            "effect_intervals": {"time": interval},
            "quality_intervals": {"quality": {"lower": "0", "upper": "1", "unit": "score"}},
            "safety_intervals": {},
            "amendment_chain_digest": None,
        }
        write_canonical(
            output / f"result-{name}.json",
            sign(
                trial,
                result_payload,
                schema_ref="trial-result-certificate@0.4.0",
                key_id="key:trial",
                role="evaluator",
                source_system="tutorial-trial",
                signed_at="2026-03-02T00:00:00Z",
            ),
        )
    manifest = {
        "schema_version": "0.4.0",
        "non_production": True,
        "root_fingerprint": key_fingerprint(public(root)),
        "files": {
            path.name: file_digest(path) for path in sorted(output.iterdir()) if path.is_file()
        },
        "expected": {
            "forged_independence": "invalid_signature",
            "unsigned_bundle_authenticity": "unknown",
            "inconclusive_result": "externally_observed_inconclusive",
            "supported_result": "external_acceleration_bundle_compatible",
            "sandbox_status": "not_provided",
        },
    }
    write_canonical(output / "manifest.json", manifest)
    print(manifest["root_fingerprint"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
