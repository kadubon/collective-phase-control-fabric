# SPDX-License-Identifier: Apache-2.0
"""Generate the portable CPCF v0.3 signed local tutorial assets."""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from collective_phase_control_fabric.canonical import digest_bytes, digest_v3_json, write_canonical
from collective_phase_control_fabric.trust import signable_payload

EPOCH = "2026-01-15T00:00:00Z"
SCOPE = {"project": "cpcf-v0.3-tutorial", "environment": "local"}
TEST_SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
ATTACKER_SEED = bytes.fromhex("f0e0d0c0b0a090807060504030201000102030405060708090a0b0c0d0e0f000")


def sign(
    private: Ed25519PrivateKey, value: dict[str, object], schema_ref: str
) -> dict[str, object]:
    result = deepcopy(value)
    result["signature"] = {
        "key_id": "key:tutorial",
        "signature_base64": "",
        "signed_at": EPOCH,
        "payload_digest": "sha256:" + "0" * 64,
    }
    message, payload_digest = signable_payload(result, schema_ref)
    result["signature"]["payload_digest"] = payload_digest  # type: ignore[index]
    message, payload_digest = signable_payload(result, schema_ref)
    result["signature"]["payload_digest"] = payload_digest  # type: ignore[index]
    result["signature"]["signature_base64"] = base64.b64encode(  # type: ignore[index]
        private.sign(message)
    ).decode()
    return result


def node(identifier: str, kind: str) -> dict[str, object]:
    return {
        "node_id": identifier,
        "type": kind,
        "lifecycle": "active",
        "source_ref": "evidence",
        "principal_key_id": "key:tutorial",
        "available": True,
        "coordinates": {},
        "independence_domain": "domain:tutorial",
        "infrastructure_domain": "infrastructure:tutorial",
        "correlation_group": "correlation:tutorial",
        "lineage": [f"lineage:{identifier}"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    private = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    attacker = Ed25519PrivateKey.from_private_bytes(ATTACKER_SEED)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    schema_names = [
        "transformation-network",
        "state-marking",
        "branch-effect-contract",
        "adapter-capability",
        "action",
        "measurement-protocol",
        "trial-result-certificate",
    ]
    trust = {
        "schema_version": "0.3.0",
        "policy_id": "trust:tutorial",
        "principals": [
            {
                "key_id": "key:tutorial",
                "public_key_base64": base64.b64encode(public).decode(),
                "source_systems": ["tutorial"],
                "schema_names": schema_names,
                "roles": ["source", "adapter_capability", "action_author", "evaluator"],
                "scope": SCOPE,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
            }
        ],
    }
    contract = {
        "schema_version": "0.3.0",
        "contract_id": "contract:tutorial",
        "phase_label": "tutorial-only user label",
        "evaluation_time": EPOCH,
        "scope": SCOPE,
        "target_states": ["target"],
        "initial_available_states": ["authority", "evidence", "seed"],
        "state_coordinate_registry": {"resource": {"unit": "token", "proxy_only": True}},
        "protected_floors": {"resource": {"quantity": "0", "unit": "token"}},
        "resource_envelope": {"resource": {"quantity": "10", "unit": "token"}},
        "unit_registry": {},
        "control_policy": {
            "planning_horizon": 1,
            "beam_width": 8,
            "candidate_cap": 16,
            "retry_limit": 0,
        },
        "formation_policy": {"maximum_layer_count": 8},
        "support_core_policy": {
            "minimum_support_domains": 1,
            "minimum_verifier_domains": 1,
            "perturbation_suite_refs": [],
        },
        "rate_policy": {"levels_requiring_evidence": ["L3", "L4", "L5"]},
        "analysis_limits": {
            "maximum_raw_bytes": 1048576,
            "maximum_json_depth": 64,
            "maximum_nodes": 64,
            "maximum_transformations": 64,
            "maximum_rational_bits": 256,
            "maximum_siphon_species": 12,
        },
        "measurement_protocol_refs": ["protocol:tutorial"],
        "collective_policy": {},
        "termination_policy": {},
        "non_claims": ["No intelligence, causality, or physical-phase claim."],
    }
    network = {
        "schema_version": "0.3.0",
        "network_id": "network:tutorial",
        "nodes": [
            node("authority", "authority_record"),
            node("evidence", "verifier_report"),
            node("seed", "artifact"),
            node("target", "target_state"),
        ],
        "transformations": [
            {
                "transformation_id": "transform:tutorial",
                "required_inputs": ["seed"],
                "read_enablers": [],
                "produced_outputs": ["target"],
                "required_evidence": ["evidence"],
                "required_authority_refs": ["authority"],
                "required_hazard_refs": [],
                "support_refs": ["evidence"],
                "verifier_refs": ["evidence"],
                "catalyst_clauses": [],
                "explicitly_uncatalyzed": True,
                "inhibitors": [],
                "coordinate_flows": {"resource": {"quantity": "0", "unit": "token"}},
                "boundary_supply_refs": [],
                "source_ref": "evidence",
            }
        ],
    }
    marking = {
        "schema_version": "0.3.0",
        "marking_id": "marking:tutorial",
        "state_refs": ["authority", "evidence", "seed"],
        "coordinates": {"resource": {"quantity": "10", "unit": "token"}},
        "source_refs": ["evidence"],
    }
    adapter_path = output / "adapter.py"
    adapter_source = (
        "import json\n"
        "print(json.dumps({'schema_version':'0.3.0','action_id':'action:tutorial',"
        "'outcome':'success','observation':{'schema_version':'0.3.0',"
        "'observation_id':'observation:tutorial','value':'local deterministic output',"
        "'source_refs':['evidence']}}))\n"
    )
    adapter_path.write_text(adapter_source, encoding="utf-8", newline="\n")
    executable = Path(sys.executable).resolve()
    projection = {
        "source_pointer": "/observation",
        "target_schema": "adapter-observation@0.3.0",
    }
    branch = {
        "must_add": [],
        "may_add": ["target"],
        "must_remove": [],
        "may_remove": [],
        "resource_intervals": {"resource": {"lower": "0", "upper": "0", "unit": "token"}},
        "debt": [],
        "rollback_obligations": [],
        "projection_possibilities": [projection],
    }
    effect = {
        "schema_version": "0.3.0",
        "effect_id": "effect:tutorial",
        "branches": {
            name: deepcopy(branch) for name in ("success", "partial", "failure", "timeout")
        },
    }
    capability = {
        "schema_version": "0.3.0",
        "capability_id": "capability:tutorial",
        "adapter": "tutorial",
        "operation": "local-observation",
        "effect_class": "inspect",
        "executable": str(executable),
        "executable_digest": digest_bytes(executable.read_bytes()),
        "argv_prefix": [str(executable), str(adapter_path)],
        "output_schema_ref": "adapter-output@0.3.0",
        "outcome_selector": {
            "source_pointer": "/outcome",
            "mapping": {name: name for name in ("success", "partial", "failure", "timeout")},
        },
        "branch_effect_ref": "effect:tutorial",
    }
    action = {
        "schema_version": "0.3.0",
        "action_id": "action:tutorial",
        "capability_ref": "capability:tutorial",
        "arguments": [],
        "input_refs": ["seed"],
        "required_authority_refs": ["authority"],
        "required_hazard_refs": [],
        "expires_at": "2026-12-31T00:00:00Z",
        "priority_class": 1,
    }
    protocol = {
        "schema_version": "0.3.0",
        "protocol_id": "protocol:tutorial",
        "registered_at": "2026-01-01T00:00:00Z",
        "target_refs": ["target"],
        "comparison": "synthetic tutorial comparison",
        "assignment": "synthetic fixed assignment",
        "observation_window": {"start": "2026-01-02T00:00:00Z", "end": "2026-01-12T00:00:00Z"},
        "outcomes": [{"metric": "duration", "direction": "minimize", "unit": "second"}],
        "quality_floors": {"quality": {"quantity": "1", "unit": "score"}},
        "stopping_rule": "synthetic fixed stopping rule",
        "missing_data_policy": "synthetic complete-case declaration",
        "analysis_method": "externally supplied interval",
        "evaluator_key_id": "key:tutorial",
        "source_refs": ["evidence"],
    }
    signed_protocol = sign(private, protocol, "measurement-protocol@0.3.0")

    def trial(identifier: str, lower: str, upper: str) -> dict[str, object]:
        return {
            "schema_version": "0.3.0",
            "result_id": identifier,
            "protocol_digest": digest_v3_json(signed_protocol),
            "dataset_digest": "sha256:" + hashlib.sha256(identifier.encode()).hexdigest(),
            "analysis_executable_digest": digest_bytes(adapter_path.read_bytes()),
            "completed_at": "2026-01-13T00:00:00Z",
            "effect_intervals": [
                {
                    "metric": "duration",
                    "direction": "minimize",
                    "lower": lower,
                    "upper": upper,
                    "unit": "second",
                }
            ],
            "quality_intervals": [
                {
                    "metric": "quality",
                    "direction": "maximize",
                    "lower": "1",
                    "upper": "2",
                    "unit": "score",
                }
            ],
            "time_uniform": False,
            "assumptions": ["synthetic tutorial assumptions"],
            "source_refs": ["evidence"],
            "evaluator_key_id": "key:tutorial",
        }

    documents = {
        "phase-contract.json": contract,
        "trust-policy.json": trust,
        "transformation-network.json": sign(private, network, "transformation-network@0.3.0"),
        "state-marking.json": sign(private, marking, "state-marking@0.3.0"),
        "branch-effect-contract.json": sign(private, effect, "branch-effect-contract@0.3.0"),
        "adapter-capability.json": sign(private, capability, "adapter-capability@0.3.0"),
        "action.json": sign(private, action, "action@0.3.0"),
        "measurement-protocol.json": signed_protocol,
        "result-inconclusive.json": sign(
            private, trial("result:inconclusive", "-1", "1"), "trial-result-certificate@0.3.0"
        ),
        "result-supported.json": sign(
            private, trial("result:supported", "-3", "-1"), "trial-result-certificate@0.3.0"
        ),
        "spoofed-state-marking.json": sign(attacker, marking, "state-marking@0.3.0"),
    }
    for name, value in documents.items():
        write_canonical(output / name, value)
    manifest = {
        "schema_version": "0.3.0",
        "tutorial_only": True,
        "private_key_is_public_test_material": True,
        "pinned_public_key_base64": base64.b64encode(public).decode(),
        "adapter_digest": digest_bytes(adapter_path.read_bytes()),
        "expected_action_outcome": "success",
        "expected_spoof_status": "false",
        "files": {
            path.name: digest_bytes(path.read_bytes())
            for path in sorted(output.iterdir())
            if path.is_file()
        },
    }
    write_canonical(output / "manifest.json", manifest)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
