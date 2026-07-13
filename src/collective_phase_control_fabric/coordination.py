# SPDX-License-Identifier: Apache-2.0
"""Bounded collective coordination with explicit independence erosion."""

from __future__ import annotations

from collective_phase_control_fabric.canonical import digest_json
from collective_phase_control_fabric.types import JsonObject


def derive_coordination_plan(contract: JsonObject, network: JsonObject) -> JsonObject:
    """Derive protocol structure without inventing participants or independence groups."""

    policy = contract.get("collective_policy", {})
    groups = sorted(
        {
            str(node["independence_group"])
            for node in network.get("nodes", [])
            if isinstance(node, dict) and isinstance(node.get("independence_group"), str)
        }
    )
    compartments = policy.get("compartments", []) if isinstance(policy, dict) else []
    plan: JsonObject = {
        "schema_version": "0.2.0",
        "protocol": [
            "independent_proposal",
            "digest_commitment",
            "bounded_reveal",
            "central_evidence_integration",
            "independent_verification",
            "termination",
        ],
        "independence_groups": groups,
        "compartments": compartments if isinstance(compartments, list) else [],
        "all_to_all_default": False,
        "recursive_self_review_counts_as_independent": False,
        "deduplication_keys": [
            "raw_artifact_digest",
            "source_event",
            "lineage",
            "correlation_group",
        ],
        "termination": contract.get("termination_policy", {"status": "undeclared"}),
    }
    plan["plan_id"] = f"coordination:{digest_json(plan).split(':', 1)[1][:16]}"
    return plan


def independence_exposure_ledger(events: list[JsonObject]) -> JsonObject:
    """Track pre-commit shared-artifact exposure; names and prompts convey no independence."""

    committed: set[str] = set()
    exposed_before_commit: dict[str, set[str]] = {}
    ledger: list[JsonObject] = []
    for event in events:
        group = event.get("independence_group")
        event_type = event.get("event_type")
        if not isinstance(group, str):
            ledger.append({"event_id": event.get("event_id"), "status": "unknown_group"})
            continue
        if event_type == "commit":
            committed.add(group)
        elif event_type == "consume" and group not in committed:
            digest = event.get("artifact_digest")
            if isinstance(digest, str):
                exposed_before_commit.setdefault(group, set()).add(digest)
        ledger.append(
            {"event_id": event.get("event_id"), "group": group, "committed": group in committed}
        )
    eroded = sorted(group for group, digests in exposed_before_commit.items() if digests)
    return {
        "events": ledger,
        "eroded_independence_groups": eroded,
        "status": "false" if eroded else "true",
        "retroactive_independence_allowed": False,
    }
