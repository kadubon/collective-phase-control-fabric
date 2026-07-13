# SPDX-License-Identifier: Apache-2.0
"""Exact productive, maintenance, and catalyst witness validation."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction

from collective_phase_control_fabric.network import ClosureResult, transformation_index
from collective_phase_control_fabric.types import JsonObject, id_set


def exact_number(value: object) -> Fraction:
    """Parse a decimal or rational string without binary floating-point arithmetic."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("quantity must be a non-empty decimal or rational string")
    text = value.strip()
    try:
        if "/" in text:
            numerator, denominator = text.split("/", maxsplit=1)
            return Fraction(int(numerator), int(denominator))
        return Fraction(Decimal(text))
    except (InvalidOperation, ValueError, ZeroDivisionError) as error:
        raise ValueError(f"invalid exact quantity: {value}") from error


@dataclass(frozen=True)
class WitnessResult:
    """A conservative witness validation result."""

    status: str
    valid: bool | None
    reasons: tuple[str, ...]
    balances: JsonObject
    witness_ref: str | None


def _coordinate_registry(contract: JsonObject) -> dict[str, JsonObject]:
    registry = contract.get("state_coordinate_registry", {})
    return registry if isinstance(registry, dict) else {}


def _flows(edge: JsonObject, field: str) -> dict[str, JsonObject]:
    value = edge.get(field, {})
    return value if isinstance(value, dict) else {}


def validate_productive_witness(
    contract: JsonObject,
    network: JsonObject,
    verified: ClosureResult,
    witness: JsonObject | None,
) -> WitnessResult:
    """Recompute a supplied plan; CPCF never searches for one."""

    if witness is None:
        return WitnessResult("unknown", None, ("productive_witness_missing",), {}, None)
    reasons: list[str] = []
    transformations = transformation_index(network)
    coefficients = witness.get("transformation_coefficients")
    if not isinstance(coefficients, dict) or not coefficients:
        reasons.append("transformation_coefficients_missing")
        coefficients = {}
    verified_ids = set(verified.applied_transformations)
    registry = _coordinate_registry(contract)
    balances: dict[str, Fraction] = {coordinate: Fraction(0) for coordinate in registry}
    known = True
    for transformation_id, coefficient_text in sorted(coefficients.items()):
        if transformation_id not in verified_ids or transformation_id not in transformations:
            reasons.append(f"transformation_not_in_verified_closure:{transformation_id}")
            continue
        try:
            coefficient = exact_number(coefficient_text)
        except ValueError:
            reasons.append(f"invalid_coefficient:{transformation_id}")
            continue
        if coefficient < 0:
            reasons.append(f"negative_coefficient:{transformation_id}")
            continue
        edge = transformations[transformation_id]
        for sign, field in ((-1, "consumed_coordinates"), (1, "produced_coordinates")):
            for coordinate, flow in sorted(_flows(edge, field).items()):
                if coordinate not in registry or not isinstance(flow, dict):
                    reasons.append(f"unknown_coordinate:{coordinate}")
                    known = False
                    continue
                if flow.get("unit") != registry[coordinate].get("unit"):
                    reasons.append(f"unit_mismatch:{coordinate}")
                    known = False
                    continue
                try:
                    quantity = exact_number(flow.get("quantity"))
                except ValueError:
                    reasons.append(f"invalid_quantity:{transformation_id}:{coordinate}")
                    known = False
                    continue
                balances[coordinate] += sign * coefficient * quantity
    supplies = witness.get("external_supplies", {})
    if not isinstance(supplies, dict):
        reasons.append("external_supplies_malformed")
        supplies = {}
    resource_records = {
        str(node.get("node_id"))
        for node in network.get("nodes", [])
        if isinstance(node, dict)
        and node.get("type") == "resource_record"
        and node.get("available") is True
        and node.get("lifecycle_status") in {"valid", "active"}
    }
    for coordinate, supply in sorted(supplies.items()):
        if coordinate not in registry or not isinstance(supply, dict):
            reasons.append(f"unknown_external_supply:{coordinate}")
            known = False
            continue
        if supply.get("unit") != registry[coordinate].get("unit"):
            reasons.append(f"external_supply_unit_mismatch:{coordinate}")
            known = False
            continue
        try:
            balances[coordinate] += exact_number(supply.get("quantity"))
        except ValueError:
            reasons.append(f"invalid_external_supply:{coordinate}")
            known = False
        if contract.get("schema_version") == "0.2.0":
            source_ref = supply.get("source_ref")
            if not isinstance(source_ref, str) or source_ref not in resource_records:
                reasons.append(f"external_supply_source_invalid_or_unknown:{coordinate}")
    expected = witness.get("expected_net_balances", {})
    if not isinstance(expected, dict):
        reasons.append("expected_balances_malformed")
        expected = {}
    for coordinate, actual in balances.items():
        if coordinate not in expected:
            reasons.append(f"unknown_expected_balance:{coordinate}")
            known = False
            continue
        try:
            if exact_number(expected[coordinate]) != actual:
                reasons.append(f"expected_balance_mismatch:{coordinate}")
        except ValueError:
            reasons.append(f"invalid_expected_balance:{coordinate}")
    targets = id_set(witness.get("target_positive_coordinates"))
    protected = id_set(witness.get("protected_nonnegative_coordinates"))
    contract_protected = set(contract.get("protected_floors", {}))
    if not contract_protected <= protected:
        reasons.append("contract_protected_coordinates_missing")
    if not targets:
        reasons.append("target_positive_coordinates_missing")
    for coordinate in sorted(targets):
        if coordinate not in balances:
            reasons.append(f"unknown_target_coordinate:{coordinate}")
        elif registry[coordinate].get("proxy_only") is True:
            reasons.append(f"proxy_only_target_coordinate:{coordinate}")
        elif balances[coordinate] <= 0:
            reasons.append(f"target_not_strictly_positive:{coordinate}")
    for coordinate in sorted(protected):
        if coordinate not in balances:
            reasons.append(f"unknown_protected_coordinate:{coordinate}")
        elif balances[coordinate] < 0:
            reasons.append(f"protected_coordinate_negative:{coordinate}")
    for coordinate, balance in sorted(balances.items()):
        if balance < 0 and coordinate not in supplies:
            reasons.append(f"internal_coordinate_not_regenerated:{coordinate}")
    valid = known and not reasons
    return WitnessResult(
        "productive_organization_candidate" if valid else "not_productive",
        valid,
        tuple(sorted(set(reasons))),
        {coordinate: str(value) for coordinate, value in sorted(balances.items())},
        str(witness.get("witness_id")) if witness.get("witness_id") else None,
    )


MAINTENANCE_FIELDS = (
    "renewal_obligations",
    "expiry_refresh_refs",
    "resource_supply_refs",
    "verifier_capacity_refs",
    "rollback_refs",
    "maintenance_cost_refs",
    "failure_response_refs",
    "source_refs",
)


def validate_maintenance_witness(
    witness: JsonObject | None, network: JsonObject | None = None
) -> WitnessResult:
    """Require every declared maintenance obligation class for the horizon."""

    if witness is None:
        return WitnessResult("unknown", None, ("maintenance_witness_missing",), {}, None)
    reasons: list[str] = []
    if not isinstance(witness.get("validity_horizon"), str) or not witness["validity_horizon"]:
        reasons.append("validity_horizon_missing")
    for field in MAINTENANCE_FIELDS:
        if not id_set(witness.get(field)):
            reasons.append(f"{field}_missing")
    if network is None:
        reasons.append("maintenance_dependency_records_unknown")
    else:
        nodes = {
            str(node["node_id"]): node
            for node in network.get("nodes", [])
            if isinstance(node, dict) and isinstance(node.get("node_id"), str)
        }
        for field in MAINTENANCE_FIELDS[:-1]:
            for reference in sorted(id_set(witness.get(field))):
                node = nodes.get(reference)
                if (
                    node is None
                    or node.get("available") is not True
                    or node.get("lifecycle_status") not in {"valid", "active"}
                ):
                    reasons.append(f"maintenance_dependency_invalid_or_unknown:{reference}")
    valid = not reasons
    return WitnessResult(
        "maintained_organization_candidate" if valid else "not_maintained",
        valid,
        tuple(reasons),
        {},
        str(witness.get("witness_id")) if witness.get("witness_id") else None,
    )


def validate_catalysts(network: JsonObject, maintained: bool) -> WitnessResult:
    """Distinguish certified catalysts from merely reusable-looking enablers."""

    if not maintained:
        return WitnessResult("unknown", None, ("maintained_organization_required",), {}, None)
    candidates = [
        node
        for node in network.get("nodes", [])
        if isinstance(node, dict) and node.get("type") == "certified_catalyst"
    ]
    transformation_ids = {
        str(edge["transformation_id"])
        for edge in network.get("transformations", [])
        if isinstance(edge, dict) and isinstance(edge.get("transformation_id"), str)
    }
    valid = [
        node
        for node in candidates
        if node.get("certificate_kind")
        in {"pcs_receipt", "alt_admission", "external_reuse", "external_resource_reduction"}
        and node.get("certificate_valid") is True
        and len(id_set(node.get("bound_transformations"))) >= 1
        and id_set(node.get("bound_transformations")) <= transformation_ids
    ]
    if not candidates:
        return WitnessResult("unknown", None, ("certified_catalyst_missing",), {}, None)
    if not valid:
        return WitnessResult("not_catalytic", False, ("catalyst_certificate_invalid",), {}, None)
    return WitnessResult(
        "catalytic_organization_candidate",
        True,
        (),
        {"certified_catalyst_ids": sorted(str(node["node_id"]) for node in valid)},
        None,
    )
