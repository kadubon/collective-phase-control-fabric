# SPDX-License-Identifier: Apache-2.0
"""Coordinate-wise barrier vectors and partial-order comparisons."""

from __future__ import annotations

from collective_phase_control_fabric.network import ClosureResult
from collective_phase_control_fabric.types import JsonObject

BARRIER_COORDINATES = (
    "integrity",
    "provenance",
    "schema_interoperability",
    "observability",
    "evidence",
    "verifier",
    "independence",
    "collective_integration",
    "authority",
    "hazard",
    "resource",
    "lifecycle",
    "rollback",
    "productivity",
    "maintenance",
    "transfer",
    "source_disagreement",
)

BLOCKER_COORDINATE = {
    "schema": "schema_interoperability",
    "output_contract": "observability",
    "evidence": "evidence",
    "verifier": "verifier",
    "self_issued": "independence",
    "duplicate": "provenance",
    "authority": "authority",
    "hazard": "hazard",
    "resource": "resource",
    "lifecycle": "lifecycle",
    "stale": "lifecycle",
    "protected_floor": "integrity",
}


def build_barrier_vector(
    verified: ClosureResult,
    detector_results: list[JsonObject],
    deadlocks: list[JsonObject],
    seeds: list[JsonObject],
    productivity_status: str,
    maintenance_status: str,
    collective: JsonObject,
) -> JsonObject:
    """Build a non-scalar barrier vector with explicit unknown coordinates."""

    mapping: dict[str, set[str]] = {coordinate: set() for coordinate in BARRIER_COORDINATES}
    refs: dict[str, set[str]] = {coordinate: set() for coordinate in BARRIER_COORDINATES}
    for blocked in verified.blocked:
        transformation_id = str(blocked.get("transformation_id"))
        for blocker in blocked.get("blockers", []):
            text = str(blocker)
            coordinate = next(
                (value for key, value in BLOCKER_COORDINATE.items() if key in text), "integrity"
            )
            mapping[coordinate].add(f"{transformation_id}:{text}")
            refs[coordinate].add(transformation_id)
    for result in detector_results:
        if result.get("blocking") is True:
            detector = str(result["detector"])
            coordinate = "provenance" if detector == "duplicate_mass" else "integrity"
            mapping[coordinate].update(str(item) for item in result.get("blocker_ids", []))
            refs[coordinate].update(str(item) for item in result.get("source_refs", []))
    for deadlock in deadlocks:
        mapping["productivity"].add(str(deadlock["deadlock_id"]))
        refs["productivity"].update(str(item) for item in deadlock.get("states", []))
    for seed in seeds:
        mapping["productivity"].add(str(seed["seed_id"]))
        refs["productivity"].update(str(item) for item in seed.get("unmet_states", []))
    if productivity_status == "unknown":
        mapping["productivity"].add("productive_witness_missing")
    elif productivity_status != "productive_organization_candidate":
        mapping["productivity"].add("productive_witness_invalid")
    if maintenance_status == "unknown":
        mapping["maintenance"].add("maintenance_witness_missing")
    elif maintenance_status != "maintained_organization_candidate":
        mapping["maintenance"].add("maintenance_witness_invalid")
    if collective.get("status") != "true":
        mapping["independence"].update(str(item) for item in collective.get("reasons", []))
        mapping["collective_integration"].update(
            str(item) for item in collective.get("reasons", [])
        )
    coordinates = {}
    for coordinate in BARRIER_COORDINATES:
        blockers = sorted(mapping[coordinate])
        coordinates[coordinate] = {
            "blocker_ids": blockers,
            "severity": "blocking" if blockers else "none",
            "known_or_unknown": (
                "unknown"
                if not blockers and coordinate in {"transfer", "source_disagreement"}
                else "known"
            ),
            "required_resolution": [f"resolve:{blocker}" for blocker in blockers],
            "source_refs": sorted(refs[coordinate]),
        }
    return {"coordinates": coordinates, "comparison": "partial_order", "weighted_sum": None}


def dominates(candidate: JsonObject, baseline: JsonObject) -> bool:
    """Return strict set-wise dominance; no cross-coordinate weights are used."""

    candidate_coordinates = candidate.get("coordinates", {})
    baseline_coordinates = baseline.get("coordinates", {})
    if not isinstance(candidate_coordinates, dict) or not isinstance(baseline_coordinates, dict):
        return False
    strictly_smaller = False
    for coordinate in BARRIER_COORDINATES:
        left = set(candidate_coordinates.get(coordinate, {}).get("blocker_ids", []))
        right = set(baseline_coordinates.get(coordinate, {}).get("blocker_ids", []))
        if (
            candidate_coordinates.get(coordinate, {}).get("known_or_unknown") != "known"
            and left != right
        ):
            return False
        if not left <= right:
            return False
        strictly_smaller = strictly_smaller or left < right
    return strictly_smaller
