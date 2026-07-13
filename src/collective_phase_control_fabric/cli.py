# SPDX-License-Identifier: Apache-2.0
"""Argparse command line interface for CPCF."""

from __future__ import annotations

import argparse
import json
import sys
from importlib.resources import files
from pathlib import Path

from collective_phase_control_fabric.adapters import capability_manifest, invoke_read_only_adapter
from collective_phase_control_fabric.bundle import create_bundle, verify_bundle
from collective_phase_control_fabric.coordination_v5 import (
    coordination_commit_v5,
    coordination_init_v5,
    coordination_reveal_v5,
    coordination_route_v5,
    coordination_status_v5,
    coordination_terminate_v5,
)
from collective_phase_control_fabric.demos import DEMO_SCENARIOS
from collective_phase_control_fabric.execution_v5 import (
    approve_projection_v5,
    inspect_execution_risk_v5,
    pending_projections_v5,
    run_action_v5,
)
from collective_phase_control_fabric.fixtures import FIXTURE_NAMES, fixture
from collective_phase_control_fabric.generation_v4 import V4
from collective_phase_control_fabric.generation_v5 import V5
from collective_phase_control_fabric.handoffs import verify_handoff
from collective_phase_control_fabric.limits import load_json_bounded
from collective_phase_control_fabric.planner_v3 import plan_v3
from collective_phase_control_fabric.planner_v4 import explain_action_v4, plan_v4
from collective_phase_control_fabric.planner_v5 import explain_action_v5, plan_v5
from collective_phase_control_fabric.provenance import import_source, inspect_source
from collective_phase_control_fabric.repairs import generate_repairs
from collective_phase_control_fabric.schema import (
    SCHEMA_VERSIONS,
    load_schema,
    schema_names,
    validation_errors,
)
from collective_phase_control_fabric.science_v3 import science_audit_v3
from collective_phase_control_fabric.science_v4 import (
    intervention_analysis_v4,
    perturbation_replay_v4,
    science_audit_v4,
)
from collective_phase_control_fabric.science_v5 import (
    intervention_analysis_v5,
    perturbation_replay_v5,
    science_audit_v5,
)
from collective_phase_control_fabric.trials_v4 import (
    import_protocol_v4,
    import_result_v4,
    inspect_protocol_v4,
    inspect_result_v4,
)
from collective_phase_control_fabric.trials_v5 import (
    import_amendment_v5,
    import_protocol_v5,
    import_result_v5,
    inspect_protocol_v5,
    inspect_result_v5,
)
from collective_phase_control_fabric.workspace import (
    bootstrap_demo,
    doctor,
    explain_action,
    inspect_workspace,
    next_actions,
    prepare_step,
)
from collective_phase_control_fabric.workspace_v2 import (
    initialize_workspace,
    migrate_workspace,
    rebuild_projections,
)
from collective_phase_control_fabric.workspace_v3 import (
    advance_time_v3,
    doctor_v3,
    import_source_v3,
    import_trial_v3,
    initialize_workspace_v3,
    inspect_source_v3,
    inspect_trial_v3,
    migrate_workspace_v3,
    onboard_agent_v3,
    rebuild_projections_v3,
    validate_trust_policy,
    workspace_status_v3,
    workspace_version_v3,
)
from collective_phase_control_fabric.workspace_v4 import (
    advance_time_v4,
    doctor_v4,
    explain_missing_contract_v4,
    import_attestation_v4,
    import_raw_v4,
    initialize_workspace_v4,
    inspect_attestation_v4,
    inspect_source_v4,
    inspect_time_receipt_v4,
    migrate_workspace_v4,
    onboard_v4,
    repair_list_v4,
    repair_show_v4,
    status_v4,
    update_trust_policy_v4,
    validate_trust_policy_v4,
    workspace_version,
)
from collective_phase_control_fabric.workspace_v5 import (
    advance_time_v5,
    doctor_v5,
    explain_missing_contract_v5,
    import_raw_v5,
    import_signed_object_v5,
    initialize_workspace_v5,
    inspect_genesis_v5,
    inspect_quorum_v5,
    inspect_signed_object_v5,
    inspect_time_receipt_v5,
    migrate_workspace_v5,
    onboard_v5,
    repair_list_v5,
    repair_show_v5,
    scaffold_contract_v5,
    status_v5,
    update_trust_policy_v5,
    validate_policy_v5,
)

LEGACY_CLI_VERSION = "0.5.0"
LEGACY_SCHEMA_VERSIONS = tuple(version for version in SCHEMA_VERSIONS if version != "v0.6.0")


def _emit(value: object, compact: bool = False) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=None if compact else 2))


def agent_explain() -> dict[str, object]:
    """Return the complete machine-readable first-time-agent contract."""

    packaged_docs = Path(str(files("collective_phase_control_fabric") / "data" / "docs"))
    docs_root = (
        packaged_docs if packaged_docs.is_dir() else Path(__file__).resolve().parents[2] / "docs"
    )
    return {
        "purpose": (
            "Project external records into a finite capability transformation network and analyze "
            "structural conditions deterministically."
        ),
        "version": LEGACY_CLI_VERSION,
        "default_mode": "evidence_bound_immutable_generation_with_explicit_apply",
        "first_safe_commands": [
            ["cpcf", "agent", "explain", "--compact", "--json"],
            [
                "cpcf",
                "contract",
                "scaffold",
                "--profile",
                "measured",
                "--out",
                "cpcf-onboarding",
                "--json",
            ],
        ],
        "source_of_record": {
            "external_domains": "remain in their named upstream systems",
            "cpcf_authoritative": [
                "content-addressed artifacts",
                "cross-system projection",
                "closure",
                "formation seeds",
                "barrier vectors",
                "planner decisions",
            ],
            "workspace_generation": "immutable typed ledger selected by .cpcf/CURRENT",
        },
        "supported_schemas": {
            "current_version": "v0.5.0",
            "versions": list(LEGACY_SCHEMA_VERSIONS),
            "names": {version: schema_names(version) for version in LEGACY_SCHEMA_VERSIONS},
        },
        "installed_adapters": capability_manifest()["adapters"],
        "effect_classes": ["inspect", "validate", "plan", "local_write", "external_effect"],
        "local_write_boundaries": [
            "explicit workspace",
            "workspace .cpcf directory",
            "portable bundle output",
        ],
        "network_boundaries": {
            "core_requires_network": False,
            "external_effects": "networked and arbitrary external effects are rejected",
            "subprocess_network_sandbox_claim": False,
        },
        "native_operational_profile": [
            "provenance_integrity",
            "trust_quorum",
            "temporal_integrity",
            "structural_reachability",
            "causal_formation",
            "dimensional_consistency",
            "exact_self_maintenance",
            "finite_horizon_resource_persistence",
            "target_bound_generative_catalysis",
            "verification_capacity",
            "effective_independence",
            "coordination_protocol_integrity",
            "perturbation_robustness",
        ],
        "legacy_claim_ladder_inspection_only": [f"L{level}" for level in range(9)],
        "status_semantics": ["satisfied", "violated", "unknown", "unknown_due_to_budget"],
        "progress_semantics": ["structural_progress", "no_progress"],
        "analogy_non_equivalences": [
            "formation_seed is not a critical nucleus",
            "regeneration_deadlock is not a claim of a chemical siphon",
            "structural reachability is not productivity",
            "structural acceleration is not measured acceleration",
            "structural organization is not a collective-superintelligence phase",
        ],
        "non_claims": [
            "real ASI",
            "collective superintelligence",
            "consciousness",
            "general intelligence",
            "model performance",
            "physical phase transition",
            "truth",
            "legal authority",
            "training or model-weight update",
            "autonomous self-modification or spawning",
            "settlement or external dispatch",
            "thermodynamic equivalence",
        ],
        "v0_5_trust_model": {
            "identity": "one pinned Ed25519 key per principal with disjoint-role quorums",
            "protected_metadata_signed": True,
            "schema_digest_and_canonicalization_profile_signed": True,
            "external_time_receipt_required_for_promotion": True,
            "self_carried_public_keys_authoritative": False,
            "threshold_compromise_resilience_claim": False,
        },
        "execution_boundary": {
            "default": "disabled",
            "explicit_acknowledgement": "UNSANDBOXED_LOCAL_EXECUTION",
            "filesystem_read_containment": False,
            "network_containment": False,
        },
        "docs": [
            str(docs_root / name)
            for name in ("for-agents.md", "first-ten-minutes.md", "command-map.md")
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cpcf",
        description=(
            "Evidence-bound analysis and contingent control of finite operational organizations."
        ),
        epilog=(
            "Core commands make no network calls. Local writes require an explicit workspace "
            "and, where applicable, --apply."
        ),
    )
    parser.add_argument("--version", action="version", version=LEGACY_CLI_VERSION)
    groups = parser.add_subparsers(dest="group", required=True)

    agent = groups.add_parser("agent")
    agent_commands = agent.add_subparsers(dest="command", required=True)
    explain = agent_commands.add_parser("explain")
    explain.add_argument("--compact", action="store_true")
    explain.add_argument("--json", action="store_true")
    next_parser = agent_commands.add_parser("next")
    next_parser.add_argument("--workspace", type=Path, required=True)
    next_parser.add_argument("--compact", action="store_true")
    next_parser.add_argument("--json", action="store_true")
    why = agent_commands.add_parser("why")
    why.add_argument("--workspace", type=Path, required=True)
    why.add_argument("action_id")
    why.add_argument("--json", action="store_true")
    onboard = agent_commands.add_parser(
        "onboard", help="Inspect one workspace and return exact next safe commands."
    )
    onboard.add_argument("--workspace", type=Path, required=True)
    onboard.add_argument("--compact", action="store_true")
    onboard.add_argument("--json", action="store_true")

    demo = groups.add_parser("demo")
    demo_commands = demo.add_subparsers(dest="command", required=True)
    bootstrap = demo_commands.add_parser("bootstrap")
    bootstrap.add_argument("--out", type=Path, required=True)
    bootstrap.add_argument("--scenario", choices=DEMO_SCENARIOS, default=DEMO_SCENARIOS[0])
    bootstrap.add_argument("--json", action="store_true")

    control = groups.add_parser("control", help="Plan a receipt-safe next control action.")
    control_commands = control.add_subparsers(dest="command", required=True)
    control_next = control_commands.add_parser("next", help="Evaluate four outcome branches.")
    control_next.add_argument("--workspace", type=Path, required=True)
    control_next.add_argument("--compact", action="store_true")
    control_next.add_argument("--json", action="store_true")
    control_run = control_commands.add_parser(
        "run", help="Execute exactly one currently safe local action."
    )
    control_run.add_argument("--workspace", type=Path, required=True)
    control_run.add_argument("action_id")
    control_run.add_argument("--apply", action="store_true")
    control_run.add_argument("--ack-risk")
    control_run.add_argument("--json", action="store_true")

    execution = groups.add_parser(
        "execution", help="Inspect the explicit local execution risk boundary."
    )
    execution_commands = execution.add_subparsers(dest="command", required=True)
    execution_risk = execution_commands.add_parser("inspect-risk")
    execution_risk.add_argument("--workspace", type=Path, required=True)
    execution_risk.add_argument("--json", action="store_true")

    projection = groups.add_parser(
        "projection", help="Inspect and approve receipt-backed pending projections."
    )
    projection_commands = projection.add_subparsers(dest="command", required=True)
    projection_pending = projection_commands.add_parser("pending")
    projection_pending.add_argument("--workspace", type=Path, required=True)
    projection_pending.add_argument("--json", action="store_true")
    projection_approve = projection_commands.add_parser("approve")
    projection_approve.add_argument("--workspace", type=Path, required=True)
    projection_approve.add_argument("projection_id")
    projection_approve.add_argument("--attestation", type=Path, required=True)
    projection_approve.add_argument("--apply", action="store_true")
    projection_approve.add_argument("--json", action="store_true")

    workspace = groups.add_parser("workspace", help="Create or copy-on-write migrate a workspace.")
    workspace_commands = workspace.add_subparsers(dest="command", required=True)
    workspace_init = workspace_commands.add_parser("init", help="Create a native workspace.")
    workspace_init.add_argument("--contract", type=Path, required=True)
    workspace_init.add_argument("--trust-policy", type=Path)
    workspace_init.add_argument("--root-key-fingerprint")
    workspace_init.add_argument("--time-receipt", type=Path)
    workspace_init.add_argument("--genesis-statement", type=Path)
    workspace_init.add_argument("--unit-registry", type=Path)
    workspace_init.add_argument("--out", type=Path, required=True)
    workspace_init.add_argument("--json", action="store_true")
    workspace_migrate = workspace_commands.add_parser(
        "migrate", help="Copy a legacy workspace; never modify it."
    )
    workspace_migrate.add_argument("--workspace", type=Path, required=True)
    workspace_migrate.add_argument("--trust-policy", type=Path)
    workspace_migrate.add_argument("--root-key-fingerprint")
    workspace_migrate.add_argument("--time-receipt", type=Path)
    workspace_migrate.add_argument("--contract", type=Path)
    workspace_migrate.add_argument("--genesis-statement", type=Path)
    workspace_migrate.add_argument("--unit-registry", type=Path)
    workspace_migrate.add_argument("--out", type=Path, required=True)
    workspace_migrate.add_argument("--to", required=True)
    workspace_migrate.add_argument("--json", action="store_true")
    workspace_status = workspace_commands.add_parser(
        "status", help="Inspect the authoritative generation and execution eligibility."
    )
    workspace_status.add_argument("--workspace", type=Path, required=True)
    workspace_status.add_argument("--json", action="store_true")
    workspace_advance = workspace_commands.add_parser(
        "advance-time", help="Commit a nondecreasing externally attested analysis epoch."
    )
    workspace_advance.add_argument("--workspace", type=Path, required=True)
    advance_mode = workspace_advance.add_mutually_exclusive_group(required=True)
    advance_mode.add_argument("--to")
    advance_mode.add_argument("--time-receipt", type=Path)
    workspace_advance.add_argument("--apply", action="store_true")
    workspace_advance.add_argument("--json", action="store_true")

    schema_parser = groups.add_parser("schema", help="Discover bundled versioned JSON Schemas.")
    schema_commands = schema_parser.add_subparsers(dest="command", required=True)
    schema_list = schema_commands.add_parser("list")
    schema_list.add_argument("--json", action="store_true")
    schema_show = schema_commands.add_parser("show")
    schema_show.add_argument("name")
    schema_show.add_argument("--version", default=V5)
    schema_show.add_argument("--json", action="store_true")

    contract_parser = groups.add_parser("contract", help="Validate a user-supplied PhaseContract.")
    contract_commands = contract_parser.add_subparsers(dest="command", required=True)
    contract_validate = contract_commands.add_parser("validate")
    contract_validate.add_argument("contract", type=Path)
    contract_validate.add_argument("--json", action="store_true")
    contract_scaffold = contract_commands.add_parser(
        "scaffold", help="Create a non-executable draft without inventing user decisions."
    )
    contract_scaffold.add_argument("--profile", choices=("structural", "measured"), required=True)
    contract_scaffold.add_argument("--out", type=Path, required=True)
    contract_scaffold.add_argument("--json", action="store_true")
    contract_missing = contract_commands.add_parser(
        "explain-missing", help="List unresolved v0.4 contract decisions."
    )
    contract_missing.add_argument("draft", type=Path)
    contract_missing.add_argument("--json", action="store_true")

    trust = groups.add_parser("trust", help="Validate pinned-key authority policies.")
    trust_commands = trust.add_subparsers(dest="command", required=True)
    trust_validate = trust_commands.add_parser("validate")
    trust_validate.add_argument("trust_policy", type=Path)
    trust_validate.add_argument("--root-key-fingerprint")
    trust_validate.add_argument("--json", action="store_true")
    trust_update = trust_commands.add_parser("update")
    trust_update.add_argument("--workspace", type=Path, required=True)
    trust_update.add_argument("--policy", type=Path, required=True)
    trust_update.add_argument("--time-receipt", type=Path, required=True)
    trust_update.add_argument("--quorum-statement", type=Path, action="append", default=[])
    trust_update.add_argument("--apply", action="store_true")
    trust_update.add_argument("--json", action="store_true")
    trust_genesis = trust_commands.add_parser("genesis-inspect")
    trust_genesis.add_argument("policy", type=Path)
    trust_genesis.add_argument("--genesis-statement", type=Path, required=True)
    trust_genesis.add_argument("--time-receipt", type=Path, required=True)
    trust_genesis.add_argument("--root-fingerprint", required=True)
    trust_genesis.add_argument("--json", action="store_true")
    trust_quorum = trust_commands.add_parser("quorum-inspect")
    trust_quorum.add_argument("statements", type=Path, nargs="+")
    trust_quorum.add_argument("--workspace", type=Path, required=True)
    trust_quorum.add_argument("--decision-type", required=True)
    trust_quorum.add_argument("--subject-digest", required=True)
    trust_quorum.add_argument("--json", action="store_true")

    time_parser = groups.add_parser("time", help="Validate externally signed time receipts.")
    time_commands = time_parser.add_subparsers(dest="command", required=True)
    time_inspect = time_commands.add_parser("inspect")
    time_inspect.add_argument("receipt", type=Path)
    time_inspect.add_argument("--trust-policy", type=Path, required=True)
    time_inspect.add_argument("--json", action="store_true")

    attestation = groups.add_parser("attestation", help="Validate and import typed attestations.")
    attestation_commands = attestation.add_subparsers(dest="command", required=True)
    attestation_inspect = attestation_commands.add_parser("inspect")
    attestation_inspect.add_argument("attestation", type=Path)
    attestation_inspect.add_argument("--trust-policy", type=Path, required=True)
    attestation_inspect.add_argument("--json", action="store_true")
    attestation_import = attestation_commands.add_parser("import")
    attestation_import.add_argument("attestation", type=Path)
    attestation_import.add_argument("--workspace", type=Path, required=True)
    attestation_import.add_argument("--apply", action="store_true")
    attestation_import.add_argument("--json", action="store_true")

    source = groups.add_parser(
        "source", help="Inspect or copy raw upstream artifacts into workspace CAS."
    )
    source_commands = source.add_subparsers(dest="command", required=True)
    source_inspect = source_commands.add_parser("inspect")
    source_inspect.add_argument("report", type=Path)
    source_inspect.add_argument("--source-system", required=True)
    source_inspect.add_argument("--schema-ref", required=True)
    source_inspect.add_argument("--trust-policy", type=Path)
    source_inspect.add_argument("--json", action="store_true")
    source_import = source_commands.add_parser("import")
    source_import.add_argument("report", type=Path)
    source_import.add_argument("--workspace", type=Path, required=True)
    source_import.add_argument("--source-system", required=True)
    source_import.add_argument("--schema-ref", required=True)
    source_import.add_argument("--apply", action="store_true")
    source_import.add_argument("--json", action="store_true")

    project = groups.add_parser(
        "project", help="Rebuild local projections from verified raw CAS objects."
    )
    project_commands = project.add_subparsers(dest="command", required=True)
    project_rebuild = project_commands.add_parser("rebuild")
    project_rebuild.add_argument("--workspace", type=Path, required=True)
    project_rebuild.add_argument("--json", action="store_true")

    repair = groups.add_parser(
        "repair", help="List typed repairs; unresolved repairs are never executable."
    )
    repair_commands = repair.add_subparsers(dest="command", required=True)
    repair_list = repair_commands.add_parser("list")
    repair_list.add_argument("--workspace", type=Path, required=True)
    repair_list.add_argument("--json", action="store_true")
    repair_show = repair_commands.add_parser("show")
    repair_show.add_argument("--workspace", type=Path, required=True)
    repair_show.add_argument("repair_id")
    repair_show.add_argument("--json", action="store_true")

    doctor_parser = groups.add_parser(
        "doctor", help="Audit the complete typed ledger, references, CAS, trust, and receipts."
    )
    doctor_parser.add_argument("--workspace", type=Path, required=True)
    doctor_parser.add_argument("--json", action="store_true")
    doctor_parser.add_argument("--strict", action="store_true")
    doctor_parser.add_argument("--quick", action="store_true")

    phase = groups.add_parser("phase")
    phase_commands = phase.add_subparsers(dest="command", required=True)
    inspect = phase_commands.add_parser("inspect")
    inspect.add_argument("--workspace", type=Path, required=True)
    inspect.add_argument("--compact", action="store_true")
    inspect.add_argument("--json", action="store_true")

    science = groups.add_parser(
        "science", help="Audit the nine-dimensional three-valued operational profile."
    )
    science_commands = science.add_subparsers(dest="command", required=True)
    science_audit = science_commands.add_parser("audit")
    science_audit.add_argument("--workspace", type=Path, required=True)
    science_audit.add_argument("--compact", action="store_true")
    science_audit.add_argument("--json", action="store_true")

    perturbation = groups.add_parser(
        "perturbation", help="Replay a complete v0.4 audit per scenario."
    )
    perturbation_commands = perturbation.add_subparsers(dest="command", required=True)
    perturbation_replay = perturbation_commands.add_parser("replay")
    perturbation_replay.add_argument("--workspace", type=Path, required=True)
    perturbation_replay.add_argument("--suite", required=True)
    perturbation_replay.add_argument("--json", action="store_true")

    coordination = groups.add_parser(
        "coordination", help="Run a bounded local commit-reveal protocol."
    )
    coordination_commands = coordination.add_subparsers(dest="command", required=True)
    coordination_init = coordination_commands.add_parser("init")
    coordination_init.add_argument("--workspace", type=Path, required=True)
    coordination_init.add_argument("--plan", type=Path, required=True)
    coordination_init.add_argument("--apply", action="store_true")
    coordination_init.add_argument("--json", action="store_true")
    coordination_status = coordination_commands.add_parser("status")
    coordination_status.add_argument("--workspace", type=Path, required=True)
    coordination_status.add_argument("--json", action="store_true")
    for command_name in ("commit", "reveal"):
        command = coordination_commands.add_parser(command_name)
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--session", required=True)
        command.add_argument("--proposal", type=Path, required=True)
        command.add_argument("--apply", action="store_true")
        command.add_argument("--json", action="store_true")
    coordination_route = coordination_commands.add_parser("route")
    coordination_route.add_argument("--workspace", type=Path, required=True)
    coordination_route.add_argument("--session", required=True)
    coordination_route.add_argument("--apply", action="store_true")
    coordination_route.add_argument("--json", action="store_true")
    coordination_terminate = coordination_commands.add_parser("terminate")
    coordination_terminate.add_argument("--workspace", type=Path, required=True)
    coordination_terminate.add_argument("--session", required=True)
    coordination_terminate.add_argument(
        "--reason", choices=("all_verified", "explicit_failure", "capacity_blocked"), required=True
    )
    coordination_terminate.add_argument("--apply", action="store_true")
    coordination_terminate.add_argument("--json", action="store_true")

    intervention = groups.add_parser(
        "intervention", help="Analyze finite evidence-bound interventions."
    )
    intervention_commands = intervention.add_subparsers(dest="command", required=True)
    intervention_analyze = intervention_commands.add_parser("analyze")
    intervention_analyze.add_argument("--workspace", type=Path, required=True)
    intervention_analyze.add_argument("--compact", action="store_true")
    intervention_analyze.add_argument("--json", action="store_true")

    trial = groups.add_parser(
        "trial", help="Inspect or import preregistered external trial results."
    )
    trial_commands = trial.add_subparsers(dest="command", required=True)
    trial_inspect = trial_commands.add_parser("inspect")
    trial_inspect.add_argument("result", type=Path)
    trial_inspect.add_argument("--workspace", type=Path, required=True)
    trial_inspect.add_argument("--json", action="store_true")
    trial_import = trial_commands.add_parser("import")
    trial_import.add_argument("result", type=Path)
    trial_import.add_argument("--workspace", type=Path, required=True)
    trial_import.add_argument("--apply", action="store_true")
    trial_import.add_argument("--json", action="store_true")
    protocol_inspect = trial_commands.add_parser("protocol-inspect")
    protocol_inspect.add_argument("protocol", type=Path)
    protocol_inspect.add_argument("--registration-receipt", type=Path, required=True)
    protocol_inspect.add_argument("--time-receipt", type=Path)
    protocol_inspect.add_argument("--workspace", type=Path, required=True)
    protocol_inspect.add_argument("--json", action="store_true")
    protocol_import = trial_commands.add_parser("protocol-import")
    protocol_import.add_argument("protocol", type=Path)
    protocol_import.add_argument("--registration-receipt", type=Path, required=True)
    protocol_import.add_argument("--time-receipt", type=Path)
    protocol_import.add_argument("--workspace", type=Path, required=True)
    protocol_import.add_argument("--apply", action="store_true")
    protocol_import.add_argument("--json", action="store_true")
    amendment_inspect = trial_commands.add_parser("amendment-inspect")
    amendment_inspect.add_argument("amendment", type=Path)
    amendment_inspect.add_argument("--time-receipt", type=Path, required=True)
    amendment_inspect.add_argument("--workspace", type=Path, required=True)
    amendment_inspect.add_argument("--json", action="store_true")
    amendment_import = trial_commands.add_parser("amendment-import")
    amendment_import.add_argument("amendment", type=Path)
    amendment_import.add_argument("--time-receipt", type=Path, required=True)
    amendment_import.add_argument("--workspace", type=Path, required=True)
    amendment_import.add_argument("--apply", action="store_true")
    amendment_import.add_argument("--json", action="store_true")

    seed = groups.add_parser("seed")
    seed_commands = seed.add_subparsers(dest="command", required=True)
    seed_list = seed_commands.add_parser("list")
    seed_list.add_argument("--workspace", type=Path, required=True)
    seed_list.add_argument("--json", action="store_true")

    step = groups.add_parser("step")
    step_commands = step.add_subparsers(dest="command", required=True)
    prepare = step_commands.add_parser("prepare")
    prepare.add_argument("--workspace", type=Path, required=True)
    prepare.add_argument("action_id")
    prepare.add_argument("--json", action="store_true")
    run = step_commands.add_parser("run")
    run.add_argument("--workspace", type=Path, required=True)
    run.add_argument("action_id")
    mode = run.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    run.add_argument("--json", action="store_true")

    bundle = groups.add_parser("bundle")
    bundle_commands = bundle.add_subparsers(dest="command", required=True)
    create = bundle_commands.add_parser("create")
    create.add_argument("--workspace", type=Path, required=True)
    create.add_argument("--out", type=Path, required=True)
    create.add_argument("--json", action="store_true")
    verify = bundle_commands.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--trust-policy", type=Path)
    verify.add_argument("--json", action="store_true")

    fixture_parser = groups.add_parser("fixture")
    fixture_commands = fixture_parser.add_subparsers(dest="command", required=True)
    fixture_show = fixture_commands.add_parser("show")
    fixture_show.add_argument("name", choices=FIXTURE_NAMES)
    fixture_show.add_argument("--json", action="store_true")

    adapter = groups.add_parser("adapter")
    adapter_commands = adapter.add_subparsers(dest="command", required=True)
    adapter_manifest = adapter_commands.add_parser("manifest")
    adapter_manifest.add_argument("--json", action="store_true")
    invoke = adapter_commands.add_parser("invoke")
    invoke.add_argument("--adapter", choices=("ccr", "pic"), required=True)
    invoke.add_argument("--operation", required=True)
    invoke.add_argument("--cwd", type=Path, required=True)
    invoke.add_argument("--json", action="store_true")

    handoff = groups.add_parser("handoff")
    handoff_commands = handoff.add_subparsers(dest="command", required=True)
    handoff_verify = handoff_commands.add_parser("verify")
    handoff_verify.add_argument("file", type=Path)
    handoff_verify.add_argument("--json", action="store_true")
    return parser


def dispatch(args: argparse.Namespace) -> object:
    if args.group == "agent" and args.command == "explain":
        return agent_explain()
    if args.group == "agent" and args.command == "next":
        version = workspace_version(args.workspace)
        if version == V5:
            return plan_v5(args.workspace)
        if version == V4:
            return plan_v4(args.workspace)
        return plan_v3(args.workspace) if version == "0.3.0" else next_actions(args.workspace)
    if args.group == "agent" and args.command == "onboard":
        if workspace_version(args.workspace) == V5:
            return onboard_v5(args.workspace)
        return (
            onboard_v4(args.workspace)
            if workspace_version(args.workspace) == V4
            else onboard_agent_v3(args.workspace)
        )
    if args.group == "control" and args.command == "next":
        version = workspace_version(args.workspace)
        if version == V5:
            return plan_v5(args.workspace)
        if version == V4:
            return plan_v4(args.workspace)
        return plan_v3(args.workspace) if version == "0.3.0" else next_actions(args.workspace)
    if args.group == "control" and args.command == "run":
        version = workspace_version(args.workspace)
        if version == V5:
            return run_action_v5(
                args.workspace,
                args.action_id,
                apply=args.apply,
                risk_acknowledgement=args.ack_risk,
            )
        return {
            "command_status": "failed",
            "failure_code": "legacy_workspace_inspect_only",
            "execution_allowed": False,
            "legacy_schema_version": version,
        }
    if args.group == "agent" and args.command == "why":
        if workspace_version(args.workspace) == V5:
            return explain_action_v5(args.workspace, args.action_id)
        if workspace_version(args.workspace) == V4:
            return explain_action_v4(args.workspace, args.action_id)
        return explain_action(args.workspace, args.action_id)
    if args.group == "demo":
        return bootstrap_demo(args.out, args.scenario)
    if args.group == "execution" and args.command == "inspect-risk":
        return inspect_execution_risk_v5(args.workspace)
    if args.group == "projection" and args.command == "pending":
        return pending_projections_v5(args.workspace)
    if args.group == "projection" and args.command == "approve":
        return approve_projection_v5(
            args.workspace, args.projection_id, args.attestation, apply=args.apply
        )
    if args.group == "doctor":
        if workspace_version(args.workspace) == V5:
            return doctor_v5(args.workspace, quick=args.quick)
        if workspace_version(args.workspace) == V4:
            return doctor_v4(args.workspace, quick=args.quick)
        if workspace_version(args.workspace) == "0.3.0":
            return doctor_v3(args.workspace, quick=args.quick)
        return doctor(args.workspace, args.strict)
    if args.group == "workspace" and args.command == "init":
        value = load_json_bounded(args.contract)
        if isinstance(value, dict) and value.get("schema_version") == V5:
            if any(
                item is None
                for item in (
                    args.trust_policy,
                    args.root_key_fingerprint,
                    args.time_receipt,
                    args.genesis_statement,
                    args.unit_registry,
                )
            ):
                return {
                    "command_status": "failed",
                    "failure_code": "v0.5_genesis_policy_time_registry_and_root_required",
                    "next_safe_commands": [
                        [
                            "cpcf",
                            "trust",
                            "genesis-inspect",
                            "POLICY.json",
                            "--genesis-statement",
                            "GENESIS.json",
                            "--time-receipt",
                            "TIME.json",
                            "--root-fingerprint",
                            "sha256:ROOT",
                            "--json",
                        ]
                    ],
                }
            return initialize_workspace_v5(
                args.contract,
                args.trust_policy,
                args.genesis_statement,
                args.unit_registry,
                args.out,
                args.root_key_fingerprint,
                args.time_receipt,
            )
        if isinstance(value, dict) and value.get("schema_version") == V4:
            if args.trust_policy is None or args.root_key_fingerprint is None:
                return {
                    "command_status": "failed",
                    "failure_code": "v0.4_trust_policy_and_root_fingerprint_required",
                }
            return initialize_workspace_v4(
                args.contract,
                args.trust_policy,
                args.out,
                args.root_key_fingerprint,
                args.time_receipt,
            )
        if args.trust_policy is not None:
            return initialize_workspace_v3(args.contract, args.trust_policy, args.out)
        return initialize_workspace(args.contract, args.out)
    if args.group == "workspace" and args.command == "migrate":
        if args.to in {V5, f"v{V5}"}:
            required = (
                args.contract,
                args.trust_policy,
                args.genesis_statement,
                args.unit_registry,
                args.time_receipt,
                args.root_key_fingerprint,
            )
            if any(item is None for item in required):
                return {
                    "command_status": "failed",
                    "failure_code": (
                        "v0.5_migration_fresh_contract_genesis_time_registry_and_root_required"
                    ),
                }
            return migrate_workspace_v5(
                args.workspace,
                args.contract,
                args.trust_policy,
                args.genesis_statement,
                args.unit_registry,
                args.time_receipt,
                args.out,
                args.root_key_fingerprint,
            )
        if args.to in {V4, f"v{V4}"}:
            if (
                args.trust_policy is None
                or args.time_receipt is None
                or args.root_key_fingerprint is None
            ):
                return {
                    "command_status": "failed",
                    "failure_code": "v0.4_migration_trust_time_and_root_required",
                }
            return migrate_workspace_v4(
                args.workspace,
                args.trust_policy,
                args.time_receipt,
                args.out,
                args.root_key_fingerprint,
            )
        if args.to in {"0.3.0", "v0.3.0"}:
            if args.trust_policy is None:
                return {
                    "command_status": "failed",
                    "failure_code": "trust_policy_required_for_v0.3_migration",
                }
            return migrate_workspace_v3(
                args.workspace, args.trust_policy, args.out, args.to.removeprefix("v")
            )
        return migrate_workspace(args.workspace, args.out, args.to)
    if args.group == "workspace" and args.command == "status":
        if workspace_version(args.workspace) == V5:
            return status_v5(args.workspace)
        return (
            status_v4(args.workspace)
            if workspace_version(args.workspace) == V4
            else workspace_status_v3(args.workspace)
        )
    if args.group == "workspace" and args.command == "advance-time":
        version = workspace_version(args.workspace)
        if version == V5:
            if args.time_receipt is None:
                return {
                    "command_status": "failed",
                    "failure_code": "authoritative_time_receipt_required",
                }
            return advance_time_v5(args.workspace, args.time_receipt, apply=args.apply)
        if version == V4:
            if args.time_receipt is None:
                return {
                    "command_status": "failed",
                    "failure_code": "authoritative_time_receipt_required",
                }
            return advance_time_v4(args.workspace, args.time_receipt, apply=args.apply)
        if version != "0.3.0":
            return {"command_status": "failed", "failure_code": "legacy_workspace_inspect_only"}
        if args.to is None:
            return {"command_status": "failed", "failure_code": "legacy_analysis_time_required"}
        return advance_time_v3(args.workspace, args.to, apply=args.apply)
    if args.group == "schema" and args.command == "list":
        return {
            "command_status": "ok",
            "current_version": "0.5.0",
            "versions": {
                version.removeprefix("v"): schema_names(version)
                for version in LEGACY_SCHEMA_VERSIONS
            },
        }
    if args.group == "schema" and args.command == "show":
        return load_schema(args.name, args.version)
    if args.group == "contract" and args.command == "validate":
        value = load_json_bounded(args.contract)
        version = str(value.get("schema_version", "0.1.0")) if isinstance(value, dict) else "0.2.0"
        if version == "0.3.0":
            from collective_phase_control_fabric.canonical import load_json_strict

            value = load_json_strict(args.contract)
        errors = validation_errors("phase-contract", value, version)
        return {
            "command_status": "ok" if not errors else "failed",
            "contract": str(args.contract.resolve()),
            "schema_version": version,
            "schema_errors": errors,
            "external_effect": False,
        }
    if args.group == "contract" and args.command == "explain-missing":
        draft = load_json_bounded(args.draft)
        if isinstance(draft, dict) and draft.get("schema_version") == V5:
            return explain_missing_contract_v5(args.draft)
        return explain_missing_contract_v4(args.draft)
    if args.group == "contract" and args.command == "scaffold":
        return scaffold_contract_v5(args.out, args.profile)
    if args.group == "trust" and args.command == "validate":
        value = load_json_bounded(args.trust_policy)
        if isinstance(value, dict) and value.get("schema_version") == V5:
            return validate_policy_v5(args.trust_policy, args.root_key_fingerprint)
        if isinstance(value, dict) and value.get("schema_version") == V4:
            return validate_trust_policy_v4(args.trust_policy, args.root_key_fingerprint)
        return validate_trust_policy(args.trust_policy)
    if args.group == "trust" and args.command == "update":
        if workspace_version(args.workspace) == V5:
            return update_trust_policy_v5(
                args.workspace,
                args.policy,
                args.time_receipt,
                args.quorum_statement,
                apply=args.apply,
            )
        if workspace_version(args.workspace) != V4:
            return {"command_status": "failed", "failure_code": "v0.4_workspace_required"}
        return update_trust_policy_v4(
            args.workspace, args.policy, args.time_receipt, apply=args.apply
        )
    if args.group == "trust" and args.command == "genesis-inspect":
        return inspect_genesis_v5(
            args.policy,
            args.genesis_statement,
            args.root_fingerprint,
            args.time_receipt,
        )
    if args.group == "trust" and args.command == "quorum-inspect":
        return inspect_quorum_v5(
            args.statements,
            args.workspace,
            args.decision_type,
            args.subject_digest,
        )
    if args.group == "time" and args.command == "inspect":
        policy = load_json_bounded(args.trust_policy)
        if isinstance(policy, dict) and policy.get("schema_version") == V5:
            return inspect_time_receipt_v5(args.receipt, args.trust_policy)
        return inspect_time_receipt_v4(args.receipt, args.trust_policy)
    if args.group == "attestation" and args.command == "inspect":
        policy = load_json_bounded(args.trust_policy)
        if isinstance(policy, dict) and policy.get("schema_version") == V5:
            return inspect_signed_object_v5(args.attestation, args.trust_policy)
        return inspect_attestation_v4(args.attestation, args.trust_policy)
    if args.group == "attestation" and args.command == "import":
        if workspace_version(args.workspace) == V5:
            return import_signed_object_v5(args.attestation, args.workspace, apply=args.apply)
        if workspace_version(args.workspace) != V4:
            return {"command_status": "failed", "failure_code": "v0.4_workspace_required"}
        return import_attestation_v4(args.attestation, args.workspace, apply=args.apply)
    if args.group == "source" and args.command == "inspect":
        if args.trust_policy is not None:
            trust_value = load_json_bounded(args.trust_policy)
            if isinstance(trust_value, dict) and trust_value.get("schema_version") == V5:
                return inspect_signed_object_v5(args.report, args.trust_policy)
            if isinstance(trust_value, dict) and trust_value.get("schema_version") == V4:
                return inspect_source_v4(
                    args.report, args.trust_policy, args.source_system, args.schema_ref
                )
            return inspect_source_v3(
                args.report, args.trust_policy, args.source_system, args.schema_ref
            )
        return inspect_source(args.report, args.source_system, args.schema_ref)
    if args.group == "source" and args.command == "import":
        if workspace_version(args.workspace) == V5:
            return import_raw_v5(
                args.report,
                args.workspace,
                args.source_system,
                args.schema_ref,
                apply=args.apply,
            )
        if workspace_version(args.workspace) == V4:
            return import_raw_v4(
                args.report,
                args.workspace,
                args.source_system,
                args.schema_ref,
                apply=args.apply,
            )
        if workspace_version_v3(args.workspace) == "0.3.0":
            return import_source_v3(
                args.report,
                args.workspace,
                args.source_system,
                args.schema_ref,
                apply=args.apply,
            )
        return import_source(
            args.report,
            args.workspace,
            args.source_system,
            args.schema_ref,
            apply=args.apply,
        )
    if args.group == "project" and args.command == "rebuild":
        if workspace_version(args.workspace) == V5:
            return doctor_v5(args.workspace)
        if workspace_version(args.workspace) == V4:
            return doctor_v4(args.workspace)
        if workspace_version_v3(args.workspace) == "0.3.0":
            return rebuild_projections_v3(args.workspace)
        return rebuild_projections(args.workspace)
    if args.group == "repair" and args.command == "list":
        if workspace_version(args.workspace) == V5:
            return repair_list_v5(args.workspace)
        if workspace_version(args.workspace) == V4:
            return repair_list_v4(args.workspace)
        return {
            "command_status": "ok",
            "repairs": generate_repairs(inspect_workspace(args.workspace)),
        }
    if args.group == "repair" and args.command == "show":
        if workspace_version(args.workspace) == V5:
            return repair_show_v5(args.workspace, args.repair_id)
        if workspace_version(args.workspace) != V4:
            return {"command_status": "failed", "failure_code": "v0.4_workspace_required"}
        return repair_show_v4(args.workspace, args.repair_id)
    if args.group == "phase":
        if workspace_version(args.workspace) == V5:
            return science_audit_v5(args.workspace)
        if workspace_version(args.workspace) == V4:
            return science_audit_v4(args.workspace)
        if workspace_version(args.workspace) == "0.3.0":
            return science_audit_v3(args.workspace)
        return inspect_workspace(args.workspace)
    if args.group == "science" and args.command == "audit":
        if workspace_version(args.workspace) == V5:
            return science_audit_v5(args.workspace)
        if workspace_version(args.workspace) == V4:
            return science_audit_v4(args.workspace)
        if workspace_version(args.workspace) != "0.3.0":
            return {"command_status": "failed", "failure_code": "native_workspace_required"}
        return science_audit_v3(args.workspace)
    if args.group == "perturbation" and args.command == "replay":
        if workspace_version(args.workspace) == V5:
            return perturbation_replay_v5(args.workspace, args.suite)
        return perturbation_replay_v4(args.workspace, args.suite)
    if args.group == "intervention" and args.command == "analyze":
        if workspace_version(args.workspace) == V5:
            return intervention_analysis_v5(args.workspace)
        return intervention_analysis_v4(args.workspace)
    if args.group == "coordination" and args.command == "init":
        return coordination_init_v5(args.workspace, args.plan, apply=args.apply)
    if args.group == "coordination" and args.command == "status":
        return coordination_status_v5(args.workspace)
    if args.group == "coordination" and args.command == "commit":
        return coordination_commit_v5(args.workspace, args.session, args.proposal, apply=args.apply)
    if args.group == "coordination" and args.command == "reveal":
        return coordination_reveal_v5(args.workspace, args.session, args.proposal, apply=args.apply)
    if args.group == "coordination" and args.command == "route":
        return coordination_route_v5(args.workspace, args.session, apply=args.apply)
    if args.group == "coordination" and args.command == "terminate":
        return coordination_terminate_v5(
            args.workspace, args.session, reason=args.reason, apply=args.apply
        )
    if args.group == "trial" and args.command == "inspect":
        if workspace_version(args.workspace) == V5:
            return inspect_result_v5(args.result, args.workspace)
        if workspace_version(args.workspace) == V4:
            return inspect_result_v4(args.result, args.workspace)
        return inspect_trial_v3(args.result, args.workspace)
    if args.group == "trial" and args.command == "import":
        if workspace_version(args.workspace) == V5:
            return import_result_v5(args.result, args.workspace, apply=args.apply)
        if workspace_version(args.workspace) == V4:
            return import_result_v4(args.result, args.workspace, apply=args.apply)
        return import_trial_v3(args.result, args.workspace, apply=args.apply)
    if args.group == "trial" and args.command == "protocol-inspect":
        if workspace_version(args.workspace) == V5:
            if args.time_receipt is None:
                return {
                    "command_status": "failed",
                    "failure_code": "registration_time_receipt_required",
                }
            return inspect_protocol_v5(
                args.protocol, args.registration_receipt, args.time_receipt, args.workspace
            )
        return inspect_protocol_v4(args.protocol, args.registration_receipt, args.workspace)
    if args.group == "trial" and args.command == "protocol-import":
        if workspace_version(args.workspace) == V5:
            if args.time_receipt is None:
                return {
                    "command_status": "failed",
                    "failure_code": "registration_time_receipt_required",
                }
            return import_protocol_v5(
                args.protocol,
                args.registration_receipt,
                args.time_receipt,
                args.workspace,
                apply=args.apply,
            )
        return import_protocol_v4(
            args.protocol,
            args.registration_receipt,
            args.workspace,
            apply=args.apply,
        )
    if args.group == "trial" and args.command == "amendment-inspect":
        return import_amendment_v5(args.amendment, args.time_receipt, args.workspace, apply=False)
    if args.group == "trial" and args.command == "amendment-import":
        return import_amendment_v5(
            args.amendment, args.time_receipt, args.workspace, apply=args.apply
        )
    if args.group == "seed":
        analysis = inspect_workspace(args.workspace)
        return {
            "command_status": analysis["command_status"],
            "formation_seeds": analysis.get("formation_seeds", []),
            "phase_projection": analysis.get("phase_projection"),
        }
    if args.group == "step" and args.command == "prepare":
        if workspace_version(args.workspace) == V5:
            return explain_action_v5(args.workspace, args.action_id)
        if workspace_version(args.workspace) == V4:
            return explain_action_v4(args.workspace, args.action_id)
        return prepare_step(args.workspace, args.action_id)
    if args.group == "step" and args.command == "run":
        if workspace_version(args.workspace) == V5:
            return {
                "command_status": "failed",
                "failure_code": "use_control_run_with_explicit_unsandboxed_risk_acknowledgement",
                "next_safe_commands": [
                    [
                        "cpcf",
                        "execution",
                        "inspect-risk",
                        "--workspace",
                        str(args.workspace),
                        "--json",
                    ]
                ],
            }
        return {
            "command_status": "failed",
            "failure_code": "legacy_workspace_inspect_only",
            "execution_allowed": False,
        }
    if args.group == "bundle":
        if args.command == "create":
            manifest = create_bundle(args.workspace, args.out)
            return {
                "command_status": "ok",
                "failure_code": None,
                "bundle": str(args.out.resolve()),
                "bundle_schema_version": manifest["bundle_schema_version"],
                "object_count": len(manifest["objects"]),
                "effect_class": "local_write",
                "files_written": [str((args.out / "manifest.json").resolve())],
                "authority_required": [],
                "next_safe_commands": [["cpcf", "bundle", "verify", str(args.out), "--json"]],
            }
        return verify_bundle(args.bundle, args.trust_policy)
    if args.group == "fixture":
        return fixture(args.name)
    if args.group == "adapter" and args.command == "manifest":
        return capability_manifest()
    if args.group == "adapter" and args.command == "invoke":
        return invoke_read_only_adapter(args.adapter, args.operation, args.cwd)
    if args.group == "handoff":
        return verify_handoff(args.file)
    raise RuntimeError("unreachable command")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        result = dispatch(args)
    except (FileNotFoundError, KeyError, ValueError) as error:
        code = {
            FileNotFoundError: "required_file_missing",
            KeyError: "required_field_or_schema_missing",
            ValueError: "input_validation_failed",
        }.get(type(error), "command_exception")
        _emit(
            {
                "command_status": "failed",
                "failure_code": code,
                "error": str(error),
                "effect_class": "inspect",
                "files_written": [],
                "authority_required": [],
                "next_safe_commands": [["cpcf", "agent", "explain", "--compact", "--json"]],
                "next_safe_command": ["cpcf", "agent", "explain", "--compact", "--json"],
            }
        )
        return 2
    if isinstance(result, dict):
        result.setdefault(
            "failure_code",
            str(result.get("reason", "command_failed"))
            if result.get("command_status") == "failed"
            else None,
        )
        result.setdefault("effect_class", "inspect")
        result.setdefault("files_written", [])
        result.setdefault("authority_required", [])
        result.setdefault("status", result.get("command_status"))
        result.setdefault("code", result.get("failure_code"))
        result.setdefault("workspace_generation", result.get("generation_id"))
        result.setdefault("claims", [])
        result.setdefault("unknowns", [])
        result.setdefault("quarantined_objects", [])
        result.setdefault("next_safe_commands", [])
        if result.get("command_status") == "failed" and not result["next_safe_commands"]:
            result["next_safe_commands"] = [["cpcf", "agent", "explain", "--compact", "--json"]]
        if result["next_safe_commands"]:
            result.setdefault("next_safe_command", result["next_safe_commands"][0])
    _emit(result, compact=bool(getattr(args, "compact", False)))
    if isinstance(result, dict) and result.get("command_status") == "failed":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
