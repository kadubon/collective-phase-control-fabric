# SPDX-License-Identifier: Apache-2.0
"""Collective independence and external certificate compatibility."""

from __future__ import annotations

from collective_phase_control_fabric.types import JsonObject, id_set


def collective_condition(contract: JsonObject, network: JsonObject) -> JsonObject:
    """Evaluate explicit contribution, integration, and verifier independence rules."""

    policy = contract.get("collective_policy", {})
    if not isinstance(policy, dict):
        return {"status": "unknown", "reasons": ["collective_policy_malformed"]}
    minimum = policy.get("minimum_independent_contribution_groups")
    required_roles = id_set(policy.get("required_integration_roles"))
    minimum_verifiers = policy.get("required_independent_verifier_groups")
    if not isinstance(minimum, int) or not isinstance(minimum_verifiers, int):
        return {"status": "unknown", "reasons": ["collective_minima_unknown"]}
    nodes = [node for node in network.get("nodes", []) if isinstance(node, dict)]
    contributions: dict[tuple[object, object, object], set[str]] = {}
    unknown_independence = False
    for node in nodes:
        if node.get("contribution") is not True:
            continue
        group = node.get("independence_group")
        if not isinstance(group, str):
            unknown_independence = True
            continue
        key = (node.get("digest"), node.get("source_event"), node.get("lineage"))
        contributions.setdefault(key, set()).add(group)
    groups = {sorted(groups)[0] for groups in contributions.values() if groups}
    integration_edges = [
        edge
        for edge in network.get("transformations", [])
        if isinstance(edge, dict)
        and edge.get("integration_edge") is True
        and edge.get("source_backed") is True
        and required_roles <= id_set(edge.get("integration_roles"))
    ]
    verifier_groups = {
        str(node["independence_group"])
        for node in nodes
        if node.get("type") == "verifier_report"
        and node.get("independent") is True
        and isinstance(node.get("independence_group"), str)
    }
    reasons: list[str] = []
    if len(groups) < minimum:
        reasons.append("insufficient_independent_contribution_groups")
    if not integration_edges:
        reasons.append("source_backed_integration_edge_missing")
    if len(verifier_groups) < minimum_verifiers:
        reasons.append("insufficient_independent_verifier_groups")
    if unknown_independence:
        reasons.append("contribution_independence_unknown")
    status = "true" if not reasons else ("unknown" if unknown_independence else "false")
    return {
        "status": status,
        "contribution_groups": sorted(groups),
        "integration_transformation_ids": sorted(
            str(edge["transformation_id"]) for edge in integration_edges
        ),
        "verifier_groups": sorted(verifier_groups),
        "reasons": reasons,
    }


def external_claim_bundle(
    contract: JsonObject, network: JsonObject, collective: JsonObject
) -> JsonObject:
    """Inspect imported L6-L8 certificates without re-proving their measurements."""

    certificates = [
        node
        for node in network.get("nodes", [])
        if isinstance(node, dict) and node.get("type") == "external_certificate"
    ]
    required = {
        "collective_advantage": "L6",
        "frontier_exceedance": "L7",
        "phase_evidence": "L8",
    }
    valid_levels: dict[str, str] = {}
    invalid_present = False
    for certificate in certificates:
        kind = certificate.get("certificate_kind")
        if kind not in required:
            continue
        if certificate.get("schema_version") == "0.2.0":
            validation = certificate.get("_cpcf_validation", {})
            compatible = isinstance(validation, dict) and all(
                validation.get(field) == "true"
                for field in ("schema", "digest", "expiry", "scope", "resource", "baseline")
            )
            compatible = compatible and bool(certificate.get("non_claims"))
            supplied_signature = certificate.get("signature") is not None
            if supplied_signature:
                compatible = compatible and validation.get("signature") == "true"
        else:
            # Legacy certificates remain visible for inspection, but self-declared validation
            # Booleans never establish compatibility in the executable trust model.
            compatible = False
        source_field = (
            "source_artifact_refs"
            if certificate.get("schema_version") == "0.2.0"
            else "source_refs"
        )
        compatible = (
            compatible
            and bool(id_set(certificate.get(source_field)))
            and isinstance(certificate.get("evaluator_identity"), str)
        )
        if kind == "phase_evidence" and certificate.get("schema_version") != "0.2.0":
            compatible = compatible and all(
                certificate.get(field)
                for field in (
                    "preregistered_control_parameter",
                    "system_sizes",
                    "resource_matched_protocol",
                    "declared_order_parameter_vector",
                    "perturbation_or_robustness_evidence",
                    "evaluator_and_method",
                    "uncertainty_representation",
                    "source_artifact_refs",
                )
            )
        if (
            certificate.get("schema_version") != "0.2.0"
            and certificate.get("signature_supplied") is True
        ):
            compatible = compatible and certificate.get("signature_valid") is True
        if compatible:
            valid_levels[str(kind)] = required[str(kind)]
        else:
            invalid_present = True
    if collective.get("status") != "true":
        compatibility: bool | str = False if collective.get("status") == "false" else "unknown"
    elif set(valid_levels) == set(required):
        compatibility = True
    elif invalid_present:
        compatibility = False
    else:
        compatibility = "unknown"
    return {
        "external_claim_bundle_compatible": compatibility,
        "imported_levels": [valid_levels[key] for key in sorted(valid_levels)],
        "certificate_refs": sorted(
            str(certificate.get("node_id", certificate.get("certificate_id")))
            for certificate in certificates
            if certificate.get("certificate_kind") in required
        ),
        "inspection_scope": [
            "schema",
            "digest",
            "signature_when_supplied",
            "source_refs",
            "scope",
            "resource_envelope",
            "baseline",
            "expiry",
            "evaluator_identity",
            "non_claims",
        ],
        "legacy_self_declared_validation_authoritative": False,
    }
