# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
from pathlib import Path

import pytest

from collective_phase_control_fabric.canonical import (
    canonical_bytes,
    digest_json,
    load_json,
    write_canonical,
)
from collective_phase_control_fabric.cas import ContentAddressedStore
from collective_phase_control_fabric.fixtures import fixture, productive_witness
from collective_phase_control_fabric.network import feasible_closure, verified_closure
from collective_phase_control_fabric.schema import load_schema, schema_names, validation_errors
from collective_phase_control_fabric.types import id_set, tri
from collective_phase_control_fabric.witnesses import exact_number, validate_productive_witness


def test_canonical_json_and_file_round_trip(tmp_path: Path) -> None:
    value = {"z": "Unicode path Ω", "a": [2, 1]}
    assert canonical_bytes(value) == b'{"a":[2,1],"z":"Unicode path \xce\xa9"}'
    assert digest_json(value).startswith("sha256:")
    path = tmp_path / "path with spaces Ω" / "value.json"
    write_canonical(path, value)
    assert load_json(path) == value


def test_canonical_rejects_non_finite() -> None:
    with pytest.raises(ValueError):
        canonical_bytes({"bad": float("nan")})


def test_cas_round_trip_corruption_and_bad_digest(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path / "cas with spaces")
    artifact = store.put(b"payload")
    assert store.get(artifact.digest) == b"payload"
    assert store.verify(artifact.digest)
    assert store.put(b"payload") == artifact
    artifact.path.write_bytes(b"corrupted")
    assert not store.verify(artifact.digest)
    with pytest.raises(ValueError):
        store.get("md5:bad")
    with pytest.raises(ValueError):
        store.get("sha256:" + "g" * 64)


def test_schemas_validate_base_documents() -> None:
    data = fixture("verified_productive_organization")
    assert "phase-contract" in schema_names()
    assert load_schema("phase-contract")["title"] == "PhaseContract"
    assert not validation_errors("phase-contract", data["contract"])
    assert not validation_errors("transformation-network", data["network"])
    assert not validation_errors("productive-plan-witness", data["productive_witness"])
    malformed = deepcopy(data["contract"])
    del malformed["target_states"]
    assert validation_errors("phase-contract", malformed)
    with pytest.raises(KeyError):
        load_schema("absent")


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1/3", "1/3"), ("0.1", "1/10"), ("2", "2")],
)
def test_exact_number(value: str, expected: str) -> None:
    assert str(exact_number(value)) == expected
    assert exact_number(str(Decimal(value)) if "/" not in value else value)


@pytest.mark.parametrize("value", ["", "1/0", "bad", 1.2])
def test_exact_number_rejects_invalid(value: object) -> None:
    with pytest.raises(ValueError):
        exact_number(value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, "true"), ("valid", "true"), (False, "false"), ("expired", "false"), (None, "unknown")],
)
def test_tri_state(value: object, expected: str) -> None:
    assert tri(value) == expected


def test_id_set_rejects_non_lists_and_non_strings() -> None:
    assert id_set(None) == set()
    assert id_set(["a", 1, "b"]) == {"a", "b"}


@pytest.mark.parametrize(
    ("field", "value", "blocker"),
    [
        ("schema_valid", False, "schema_invalid_or_unknown"),
        ("hazard_status", None, "hazard_invalid_or_unknown"),
        ("lifecycle_status", "unknown", "lifecycle_invalid_or_unknown"),
        ("source_version_supported", False, "source_version_unsupported_or_unknown"),
        ("output_contract_status", None, "output_contract_unknown"),
        ("effect_class", "external_effect", "external_effect_rejected"),
    ],
)
def test_feasible_closure_fails_closed(field: str, value: object, blocker: str) -> None:
    data = fixture("reachability_without_productivity")
    data["network"]["transformations"][0][field] = value
    result = feasible_closure(data["contract"], data["network"])
    assert "state:target" not in result.available_states
    assert blocker in result.blocked[0]["blockers"]


def test_inhibitor_and_missing_input_block_closure() -> None:
    data = fixture("reachability_without_productivity")
    edge = data["network"]["transformations"][0]
    edge["inhibitors"] = ["state:input"]
    result = feasible_closure(data["contract"], data["network"])
    assert "active_inhibitor" in result.blocked[0]["blockers"]
    edge["inhibitors"] = []
    edge["required_inputs"] = ["state:absent"]
    result = feasible_closure(data["contract"], data["network"])
    assert "missing_input_closure" in result.blocked[0]["blockers"]


def test_missing_node_lifecycle_is_not_available_or_produced() -> None:
    data = fixture("reachability_without_productivity")
    del data["network"]["nodes"][0]["lifecycle_status"]
    result = feasible_closure(data["contract"], data["network"])
    assert "state:input" not in result.available_states
    data = fixture("reachability_without_productivity")
    del data["network"]["nodes"][-1]["lifecycle_status"]
    result = feasible_closure(data["contract"], data["network"])
    assert "output_lifecycle_invalid_or_unknown" in result.blocked[0]["blockers"]


def test_verified_closure_requires_evidence_and_verifier() -> None:
    data = fixture("reachability_without_productivity")
    edge = data["network"]["transformations"][0]
    edge["required_evidence"] = []
    result = verified_closure(data["contract"], data["network"])
    assert "evidence_missing" in result.blocked[0]["blockers"]
    edge["required_evidence"] = ["evidence:source"]
    edge["required_verifier_roles"] = ["absent-role"]
    result = verified_closure(data["contract"], data["network"])
    assert "verifier_missing" in result.blocked[0]["blockers"]


def test_productive_witness_rejects_mismatch_proxy_and_negative() -> None:
    data = fixture("verified_productive_organization")
    verified = verified_closure(data["contract"], data["network"])
    witness = productive_witness()
    witness["expected_net_balances"]["target_units"] = "3"
    result = validate_productive_witness(data["contract"], data["network"], verified, witness)
    assert not result.valid
    assert "expected_balance_mismatch:target_units" in result.reasons
    witness = productive_witness()
    data["contract"]["state_coordinate_registry"]["target_units"]["proxy_only"] = True
    result = validate_productive_witness(data["contract"], data["network"], verified, witness)
    assert "proxy_only_target_coordinate:target_units" in result.reasons
