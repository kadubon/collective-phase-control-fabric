# SPDX-License-Identifier: Apache-2.0
"""Golden and exhaustive checks that make native v0.6 semantics mutation-sensitive."""

from __future__ import annotations

from fractions import Fraction
from itertools import combinations

import pytest

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.models import (
    DimensionResult,
    WorkspaceGeneration,
    WorkspaceGenerationSpec,
)
from collective_phase_control_fabric.v6.planning import _semantic_key, plan_actions
from collective_phase_control_fabric.v6.projection import resolve_pointer
from collective_phase_control_fabric.v6.registry import (
    DocumentValidationError,
    _close_schema,
    registry_manifest,
)
from collective_phase_control_fabric.v6.science import (
    Budget,
    analysis_basis_digest,
    audit_snapshot,
    rational,
)
from collective_phase_control_fabric.v6.storage import generation_digest
from collective_phase_control_fabric.v6.structural_analysis import (
    EnumerationResult,
    enumerate_minimal_cut_sets,
    enumerate_minimal_enablement_sets,
    enumerate_minimal_siphons,
    structural_closure,
)
from collective_phase_control_fabric.v6.trials import assess_trial
from collective_phase_control_fabric.v6.trust import (
    PAYLOAD_TYPE,
    build_protected_header,
    dsse_pae,
    sign_document,
    verify_envelope,
)
from tests.test_v6_models_trust import state
from tests.test_v6_science_planner import (
    action,
    build_science_fixture,
    capability,
)
from tests.test_v6_service_boundaries import trial_fixture
from tests.test_v6_structural_analysis import transformation
from tests.v6_helpers import NOW, metadata, trust_fixture


def test_native_digest_and_encoding_goldens_are_stable() -> None:
    snapshot, snapshot_objects = build_science_fixture()
    assert analysis_basis_digest(snapshot) == (
        "sha256:e79e1688e54eb4f11737adcd4d2e5515c42abf872ad3e95958ed2c6654faad0a"
    )
    capability_value = capability("golden", "blocker", "3/2")
    action_value = action("action:golden", capability_value)
    assert _semantic_key(action_value, capability_value) == (
        "sha256:ef88048e203a6bc77f93a480dfa783c442593fdbfd1ae34f008b3a454d22e657"
    )
    generation = WorkspaceGeneration(
        metadata=metadata("generation:golden"),
        spec=WorkspaceGenerationSpec(
            generation_digest="sha256:" + "0" * 64,
            sequence=7,
            ledger=[],
            history_head_digest="sha256:" + "1" * 64,
        ),
    )
    assert generation_digest(generation) == (
        "sha256:134da671f3f3f573195def58972a3192edd4c35611718cf0b33d0eb8fea52706"
    )
    assert digest_bytes(canonical_bytes(registry_manifest())) == (
        "sha256:2662418e5bef5dd68abd9ef6049d258a7751761b15d683784175e3c678e7cd5d"
    )
    assert dsse_pae("type", b"abc") == b"DSSEv1 4 type 3 abc"
    assert dsse_pae(PAYLOAD_TYPE, b"") == (
        b"DSSEv1 47 application/vnd.cpcf.statement+json;version=0.6 0 "
    )
    profile = audit_snapshot(snapshot, snapshot_objects)  # type: ignore[arg-type]
    assert digest_bytes(canonical_bytes(profile.model_dump(mode="json", exclude_none=True))) == (
        "sha256:bce8b93ecc9717fa85176e84bbbf361888b8a35cef7e2eb26c55208c81fb730e"
    )


def test_trust_and_trial_result_goldens_bind_complete_outputs() -> None:
    policy, trusted_time, keys = trust_fixture()
    document = state()
    root = policy.spec.principals[0]
    header = build_protected_header(
        document,
        principal=root,
        role="state_source",
        source_system="fixture-source",
        scope=["workspace-a"],
        signing_time=NOW,
        policy_sequence=0,
        trusted_time_receipt_digest=digest_bytes(
            canonical_bytes(trusted_time.model_dump(mode="json", exclude_none=True))
        ),
    )
    envelope = sign_document(document, private_key=keys["root"], protected=header)
    verification, projected = verify_envelope(envelope, policy, trusted_time=trusted_time)
    assert projected == document
    assert (
        digest_bytes(canonical_bytes(verification.model_dump(mode="json", exclude_none=True)))
        == "sha256:bcb46a4b3101542c7479cb7f59fcc2757c35a3b5217d2b30206a79199148b7b3"
    )

    protocol, objects, _result = trial_fixture()
    assessment = assess_trial(protocol, objects)
    assert digest_bytes(canonical_bytes(assessment.model_dump(mode="json", exclude_none=True))) == (
        "sha256:3c2d2fa17236ca29394042f8e0ded643ba9f39b0679595c5c40f6d5021889ef6"
    )
    missing = dict(objects)
    for digest, item in list(missing.items()):
        if item.kind == "quorum-decision":
            del missing[digest]
    for digest in (
        protocol.spec.dataset_record_digest,
        protocol.spec.assignment_record_digest,
        protocol.spec.analysis_executable_record_digest,
    ):
        missing.pop(digest)
    incomplete = assess_trial(protocol, missing)
    assert digest_bytes(canonical_bytes(incomplete.model_dump(mode="json", exclude_none=True))) == (
        "sha256:cd41539a4d31662ea63817ee5cd5dc1bcfda33f9ceca17d4e1f3f7a13cc2697f"
    )


def test_complete_planner_result_golden_binds_policy_and_rejections() -> None:
    snapshot, objects = build_science_fixture()
    profile = audit_snapshot(snapshot, objects)  # type: ignore[arg-type]
    dimensions = dict(profile.dimensions)
    dimensions["causal_formation"] = DimensionResult(
        status="violated", blockers=["formation-blocker"]
    )
    blocked = profile.model_copy(
        update={"dimensions": dimensions, "operational_organization_compatible": False}
    )
    cheap = capability("cheap", "formation-blocker", "1")
    expensive = capability("expensive", "formation-blocker", "2")
    invalid_base = action("invalid", cheap)
    invalid = invalid_base.model_copy(
        update={
            "spec": invalid_base.spec.model_copy(
                update={"required_object_digests": ["sha256:" + "f" * 64]}
            )
        }
    )
    result = plan_actions(
        snapshot,
        objects,  # type: ignore[arg-type]
        blocked,
        [invalid, action("cheap", cheap), action("expensive", expensive)],
        [cheap, expensive],
    )
    assert digest_bytes(canonical_bytes(result.model_dump(mode="json", exclude_none=True))) == (
        "sha256:3c420589b04a6d0b4888f2e3aa6aa88a42a450beb627e810ec4bf629bf3515b3"
    )


def test_registry_closure_and_validation_error_contract_are_exact() -> None:
    source = {
        "properties": {
            "nested": {"properties": {"items": {"type": "array", "items": [{"type": "string"}]}}}
        }
    }
    assert _close_schema(source) == {
        "properties": {
            "nested": {
                "properties": {"items": {"type": "array", "items": [{"type": "string"}]}},
                "additionalProperties": False,
                "unevaluatedProperties": False,
            }
        },
        "additionalProperties": False,
        "unevaluatedProperties": False,
    }
    error = DocumentValidationError("stable_code", "stable detail")
    assert error.code == "stable_code"
    assert error.detail == "stable detail"
    assert str(error) == "stable_code: stable detail"
    assert str(DocumentValidationError("stable_code")) == "stable_code"


@pytest.mark.parametrize(
    ("pointer", "expected"),
    [
        ("", {"a/b": {"~key": ["zero", {"answer": 42}]}}),
        ("/a~1b/~0key/0", "zero"),
        ("/a~1b/~0key/1/answer", 42),
    ],
)
def test_json_pointer_resolution_goldens(pointer: str, expected: object) -> None:
    value = {"a/b": {"~key": ["zero", {"answer": 42}]}}
    assert resolve_pointer(value, pointer) == expected


@pytest.mark.parametrize(
    ("pointer", "code"),
    [
        ("bad", "json_pointer_must_start_with_slash"),
        ("/missing", "json_pointer_member_missing"),
        ("/a~1b/~0key/-", "json_pointer_array_index_invalid"),
        ("/a~1b/~0key/not-index", "json_pointer_array_index_invalid"),
        ("/a~1b/~0key/9", "json_pointer_array_index_missing"),
        ("/a~1b/~0key/0/child", "json_pointer_traverses_scalar"),
    ],
)
def test_json_pointer_failures_are_stable(pointer: str, code: str) -> None:
    value = {"a/b": {"~key": ["zero", {"answer": 42}]}}
    with pytest.raises(ValueError, match=f"^{code}$"):
        resolve_pointer(value, pointer)


def reference_closure(
    initial: set[str], network: dict[str, object], allowed: set[str] | None = None
) -> set[str]:
    selected = set(network) if allowed is None else set(network).intersection(allowed)
    reached = set(initial)
    while True:
        additions = {
            output
            for identifier in selected
            if {
                state
                for state, amount in network[identifier].spec.inputs.items()  # type: ignore[union-attr]
                if Fraction(amount) > 0
            }.issubset(reached)
            for output, amount in network[identifier].spec.outputs.items()  # type: ignore[union-attr]
            if Fraction(amount) > 0
        }
        if additions.issubset(reached):
            return reached
        reached |= additions


def minimal_sets(values: list[frozenset[str]]) -> tuple[tuple[str, ...], ...]:
    minimal = [value for value in values if not any(other < value for other in values)]
    return tuple(
        tuple(sorted(value))
        for value in sorted(minimal, key=lambda item: (len(item), tuple(sorted(item))))
    )


def test_structural_enumerations_match_independent_exhaustive_reference() -> None:
    full = {
        "ab": transformation("ab", {"A": "1"}, {"B": "1"}),
        "bc": transformation("bc", {"B": "1"}, {"C": "1"}),
        "ac": transformation("ac", {"A": "1"}, {"C": "1"}),
    }
    identifiers = tuple(sorted(full))
    for edge_count in range(len(identifiers) + 1):
        for selected_ids in combinations(identifiers, edge_count):
            network = {item: full[item] for item in selected_ids}
            assert structural_closure({"A"}, network, budget=Budget(1000)) == reference_closure(
                {"A"}, network
            )

            candidates = [
                frozenset(item)
                for size in range(1, 4)
                for item in combinations(("A", "B", "C"), size)
            ]
            siphon_reference: list[frozenset[str]] = []
            for candidate in candidates:
                is_siphon = True
                for edge in network.values():
                    inputs = {
                        state for state, amount in edge.spec.inputs.items() if Fraction(amount) > 0
                    }
                    outputs = {
                        state for state, amount in edge.spec.outputs.items() if Fraction(amount) > 0
                    }
                    if outputs & candidate and not inputs & candidate:
                        is_siphon = False
                if is_siphon:
                    siphon_reference.append(candidate)
            expected_siphons = minimal_sets(siphon_reference)
            assert enumerate_minimal_siphons(
                network, {"A", "B", "C"}, Budget(10_000)
            ) == EnumerationResult(expected_siphons, True)

            subsets = [
                frozenset(item)
                for size in range(len(selected_ids) + 1)
                for item in combinations(selected_ids, size)
            ]
            enable_reference = [
                subset
                for subset in subsets
                if "C" in reference_closure({"A"}, network, set(subset))
            ]
            expected_enablement = minimal_sets(enable_reference)
            assert enumerate_minimal_enablement_sets(
                {"A"}, {"C"}, network, Budget(10_000)
            ) == EnumerationResult(expected_enablement, True)

            if "C" not in reference_closure({"A"}, network):
                expected_cuts = ((),)
            else:
                cut_reference = [
                    subset
                    for subset in subsets
                    if "C" not in reference_closure({"A"}, network, set(network) - set(subset))
                ]
                expected_cuts = minimal_sets(cut_reference)
            assert enumerate_minimal_cut_sets(
                {"A"}, {"C"}, network, Budget(10_000)
            ) == EnumerationResult(expected_cuts, True)

    boundary_network = {"ab": full["ab"], "bc": full["bc"]}
    assert enumerate_minimal_siphons(
        boundary_network,
        {"A", "B", "C"},
        Budget(1000),
        maximum_coordinates=3,
    ).exhaustive
    assert enumerate_minimal_cut_sets(
        {"A"}, {"C"}, boundary_network, Budget(1000), maximum_transformations=2
    ).exhaustive
    assert enumerate_minimal_enablement_sets(
        {"A"}, {"C"}, boundary_network, Budget(1000), maximum_transformations=2
    ).exhaustive


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0", Fraction(0)),
        ("-3", Fraction(-3)),
        ("7/11", Fraction(7, 11)),
        (5, Fraction(5)),
        (Fraction(2, 3), Fraction(2, 3)),
    ],
)
def test_exact_rational_parser_golden(value: object, expected: Fraction) -> None:
    assert rational(value) == expected  # type: ignore[arg-type]
