# SPDX-License-Identifier: Apache-2.0
"""Installed-wheel offline growth workflow; file output is never an execution request."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.frontier_examples import (
    SCENARIOS,
    frontier_report,
    write_frontier_example,
)
from collective_phase_control_fabric.v6.growth import (
    check_plan,
    compare,
    initial_state,
    plan_growth,
    require,
    state_digest,
    validate_contract,
)
from collective_phase_control_fabric.v6.growth_evidence import (
    export_proposal,
    reassess,
    replan_contract,
    replay,
)
from collective_phase_control_fabric.v6.growth_examples import comparison_example, write_example
from collective_phase_control_fabric.v6.growth_frontier import validate_frontier
from collective_phase_control_fabric.v6.growth_frontier_evidence import (
    reassess_frontier,
    replan_frontier,
)
from collective_phase_control_fabric.v6.models import (
    AnalysisSnapshot,
    Document,
    GrowthCapabilityFrontier,
    GrowthContract,
    GrowthFrontierPlan,
    GrowthObservation,
    GrowthPlan,
    RunnerJob,
    TrustedTimeReceipt,
    TrustPolicyDocument,
    WorkspaceGeneration,
)
from collective_phase_control_fabric.v6.registry import document_digest, parse_document_bytes
from collective_phase_control_fabric.v6.science import audit_snapshot
from collective_phase_control_fabric.v6.storage import MemoryObjectStore


def add_parser(commands: Any) -> None:
    parser = commands.add_parser("growth", help="Plan and check finite model growth offline.")
    subs = parser.add_subparsers(dest="subcommand", required=True)
    for name, help_text in (
        ("inspect", "Inspect the finite contract and separate operational profile."),
        ("plan", "Enumerate a bounded exact contingent growth policy."),
        ("check-plan", "Independently replay every submitted policy branch."),
        ("compare", "Reoptimize the interaction-restricted comparator catalogue."),
        ("export", "Export an operator-supplied proposed runner job; never execute."),
        ("replay", "Read-only hypothetical replay; never admit an observation."),
        ("ingest", "Recompute independent receipt admission and observation compatibility."),
        ("reassess", "Recheck external observation, arithmetic and model scope."),
        ("replan", "Reassess first, then propose a new unsigned model contract and plan."),
        ("example", "Run a deterministic synthetic comparison; optionally write its inputs."),
        ("support", "Inspect correlated fixed-model support from visible history."),
        ("information-value", "Reoptimize information-blind and no-sensing policy classes."),
        ("synthesize", "Compile bounded typed primitive observation workflows."),
        ("check-composition", "Independently unfold a finite workflow candidate."),
        ("catalogue-propose", "Propose a checked unsigned next model catalogue."),
        ("catalogue-replan", "Replan with an explicitly model-only checked catalogue."),
    ):
        leaf = subs.add_parser(name, help=help_text)
        leaf.add_argument("--json", action="store_true")
        leaf.add_argument("--output", type=Path, help="Write the complete result as UTF-8 JSON.")
        if name == "example":
            leaf.add_argument("directory", type=Path, nargs="?")
            leaf.add_argument(
                "--scenario",
                default="preparation",
                choices=[
                    "preparation",
                    "all-failure",
                    "no-advantage",
                    "verification",
                    "communication",
                    *SCENARIOS,
                    "epistemic-probe",
                    "epistemic-ambiguous",
                    "epistemic-verifier",
                    "epistemic-information",
                    "epistemic-composition",
                    "epistemic-integrated",
                    "epistemic-budget",
                    "epistemic-uninformative",
                    "epistemic-no-composition",
                    "epistemic-rejected-composition",
                ],
            )
            continue
        leaf.add_argument("contract", type=Path)
        leaf.add_argument(
            "--epistemic", type=Path, help="Opt-in closed fixed-model observation sidecar."
        )
        leaf.add_argument(
            "--history", type=Path, help="JSON array of visible action/observation steps."
        )
        leaf.add_argument(
            "--frontier", type=Path, help="Optional closed model-only capability frontier."
        )
        leaf.add_argument(
            "--objects", type=Path, required=True, help="Directory of immutable model documents."
        )
        if name in {"check-plan", "export", "replay"}:
            leaf.add_argument("--plan", type=Path, required=True)
        if name == "export":
            leaf.add_argument(
                "--job",
                type=Path,
                required=True,
                help="Unsigned operator-prepared runner-job draft.",
            )
        if name == "replay":
            leaf.add_argument("--branch", action="append", default=[])
            leaf.add_argument("--observation-symbol", action="append", default=[])
        if name == "information-value":
            leaf.add_argument("--masked-channel", type=Path, required=True)
            leaf.add_argument("--sensing-action", action="append", required=True)
        if name in {"synthesize", "check-composition", "catalogue-propose", "catalogue-replan"}:
            leaf.add_argument("--request", type=Path, required=True)
        if name in {"check-composition", "catalogue-propose", "catalogue-replan"}:
            leaf.add_argument("--candidate", type=Path, required=True)
        if name == "catalogue-propose":
            leaf.add_argument("--synthesis", type=Path, required=True)
            leaf.add_argument("--parent", type=Path)
        if name == "catalogue-replan":
            leaf.add_argument("--revision", type=Path, required=True)
            leaf.add_argument("--certificate", type=Path, required=True)
            leaf.add_argument("--model-only", action="store_true")
        if name in {"ingest", "reassess", "replan"}:
            leaf.add_argument("--epistemic-observation", type=Path)
            leaf.add_argument("--observation", type=Path, required=True)
            leaf.add_argument("--generation", type=Path, required=True)
            leaf.add_argument(
                "--cas", type=Path, required=True, help="Read-only CAS files named HEX.bin."
            )
            leaf.add_argument("--trust-policy", type=Path, required=True)
            leaf.add_argument("--trusted-time", type=Path, required=True)
            leaf.add_argument("--root-spki-fingerprint", required=True)
            leaf.add_argument("--genesis-envelope-fingerprint", required=True)


def _read[D: Document](path: Path, expected: type[D]) -> D:
    value = parse_document_bytes(path.read_bytes())
    require(isinstance(value, expected), "growth_cli_document_kind")
    return cast(D, value)


def _objects(path: Path) -> dict[str, Document]:
    paths = sorted(path.glob("*.json"))
    require(0 < len(paths) <= 512, "growth_cli_object_limit")
    result: dict[str, Document] = {}
    for p in paths:
        obj = parse_document_bytes(p.read_bytes())
        digest = document_digest(obj)
        require(digest not in result, "growth_cli_duplicate_object")
        result[digest] = obj
    return result


def _admission(args: argparse.Namespace) -> dict[str, Any]:
    generation = _read(args.generation, WorkspaceGeneration)
    store = MemoryObjectStore()
    total = 0
    for entry in generation.spec.ledger:
        filename = entry.object_digest.removeprefix("sha256:") + ".bin"
        path = args.cas / filename
        if not path.is_file():
            continue
        total += path.stat().st_size
        require(total <= 67_108_864, "growth_cli_cas_limit")
        raw = path.read_bytes()
        require(digest_bytes(raw) == entry.object_digest, "growth_cli_cas_digest")
        store.put(generation.metadata.tenant_id, raw)
    return dict(
        generation=generation,
        store=store,
        policy=_read(args.trust_policy, TrustPolicyDocument),
        trusted_time=_read(args.trusted_time, TrustedTimeReceipt),
        expected_root_spki_fingerprint=args.root_spki_fingerprint,
        expected_genesis_envelope_fingerprint=args.genesis_envelope_fingerprint,
    )


def _external(
    args: argparse.Namespace,
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier | None = None,
) -> Any:
    admission = _admission(args)
    observation = _read(args.observation, GrowthObservation)
    if frontier is not None:
        function = replan_frontier if args.subcommand == "replan" else reassess_frontier
        return function(contract, objects, observation, frontier, **admission)
    return reassess(contract, objects, observation, **admission)


def run(args: argparse.Namespace) -> int:
    try:
        result = _run(args)
        raw = canonical_bytes(result)
        if args.output:
            args.output.write_bytes(raw + b"\n")
        if args.json:
            print(raw.decode("utf-8"))
        else:
            _text(result)
        return 0
    except (OSError, ValueError, KeyError) as error:
        code = getattr(error, "code", "growth_cli_input_invalid")
        print(json.dumps({"status": "error", "code": code, "executed": False}))
        return 1


def _run(args: argparse.Namespace) -> dict[str, Any]:
    name = args.subcommand
    if name == "example":
        if args.scenario.startswith("epistemic-"):
            from cpcf_cli.epistemic import example_report

            return example_report(args.scenario, args.directory)
        if args.scenario in SCENARIOS:
            if args.directory:
                write_frontier_example(args.directory, args.scenario)
            return frontier_report(args.scenario)
        if args.directory:
            write_example(args.directory, args.scenario)
        # Convert the nested typed example ledgers without floats or custom encoders.
        report = comparison_example(args.scenario)
        return cast(
            dict[str, Any],
            json.loads(json.dumps(report, default=lambda obj: obj.model_dump(mode="json"))),
        )
    contract = _read(args.contract, GrowthContract)
    objects = _objects(args.objects)
    validate_contract(contract, objects)
    frontier = _read(args.frontier, GrowthCapabilityFrontier) if args.frontier else None
    if frontier is not None:
        validate_frontier(contract, objects, frontier)
    if args.epistemic is not None:
        from cpcf_cli.epistemic import run_epistemic

        return run_epistemic(args, contract, objects, frontier)
    require(
        name
        not in {
            "support",
            "information-value",
            "synthesize",
            "check-composition",
            "catalogue-propose",
            "catalogue-replan",
        },
        "epistemic_sidecar_required",
    )
    if name == "inspect":
        snapshot = cast(AnalysisSnapshot, objects[contract.spec.analysis_snapshot_digest])
        return {
            "code": "growth_contract_inspected",
            "contract_digest": document_digest(contract),
            "model_state": initial_state(contract, frontier).model_dump(mode="json"),
            "state_digest": state_digest(initial_state(contract, frontier)),
            **({"frontier": frontier.model_dump(mode="json")} if frontier is not None else {}),
            "operational_organization_profile": audit_snapshot(snapshot, objects).model_dump(
                mode="json"
            ),
            "measured_bounds": {},
            "model_condition": "conditional-on-declared-finite-model",
            "constraints": {
                "domains": {k: v.model_dump(mode="json") for k, v in contract.spec.domains.items()},
                "shared_resources": contract.spec.shared_resources,
                "deadline": contract.spec.deadline,
                "continuation_horizon": contract.spec.continuation_horizon,
                "planning_boundary": contract.spec.planning_boundary,
                "planning_charge": contract.spec.planning_charge,
            },
            "executed": False,
        }
    if name == "plan":
        return plan_growth(contract, objects, frontier).model_dump(mode="json", exclude_none=True)
    if name == "compare":
        return {
            "code": "growth_comparison_completed",
            "comparisons": [
                x.model_dump(mode="json") for x in compare(contract, objects, frontier)
            ],
            **({"frontier": frontier.model_dump(mode="json")} if frontier is not None else {}),
            "executed": False,
        }
    if name in {"check-plan", "export", "replay"}:
        doc = _read(args.plan, Document)
        require(isinstance(doc, (GrowthPlan, GrowthFrontierPlan)), "growth_cli_document_kind")
        plan = cast(GrowthPlan | GrowthFrontierPlan, doc)
        if name == "check-plan":
            return {
                "code": "growth_plan_checked",
                "checker_digest": check_plan(contract, objects, plan, frontier),
                **(
                    {"frontier_diagnostics": plan.spec.frontier_diagnostics.model_dump(mode="json")}
                    if isinstance(plan, GrowthFrontierPlan)
                    else {}
                ),
                "claim": (
                    "all-prefix feasibility and objective checked; "
                    "optimality requires complete search"
                ),
            }
        if name == "export":
            return export_proposal(contract, objects, plan, _read(args.job, RunnerJob), frontier)
        return replay(contract, objects, plan, args.branch, frontier)
    assessment = _external(args, contract, objects, frontier)
    if name == "replan":
        proposed_frontier = None
        if frontier is not None:
            derived, proposed_frontier, assessment = assessment
        else:
            derived = replan_contract(contract, assessment)
        planned = plan_growth(derived, objects, proposed_frontier)
        return {
            "code": "growth_replanned_proposal",
            "assessment": assessment.model_dump(mode="json"),
            "unsigned_contract_proposal": derived.model_dump(mode="json"),
            **(
                {"unsigned_frontier_proposal": proposed_frontier.model_dump(mode="json")}
                if proposed_frontier is not None
                else {}
            ),
            "plan": planned.model_dump(mode="json"),
            "registration": "required-before-external-use",
        }
    return cast(dict[str, Any], assessment.model_dump(mode="json"))


def _text(result: dict[str, Any]) -> None:
    spec = result.get("spec", result)
    print(spec.get("code", "growth_synthetic_comparison"))
    if "predicted_entry" in spec:
        policy = spec.get("policy") or {}
        print(f"Recommended action: {policy.get('action_id', 'none')}")
        print(f"Model entry: {spec['predicted_entry']}; observed entry: {spec['observed_entry']}")
        print(f"Continuation: {spec['continuation']}; search: {spec['solution_class']}")
        print("Objective: " + json.dumps(spec.get("objective"), sort_keys=True))
        print("Constraints/counterexamples: " + ", ".join(spec["counterexamples"]))
        print("Required evidence: " + ", ".join(spec["next_evidence"]))
        print("Required authority: " + ", ".join(spec["required_authority"]))
        print("Input digest: " + spec["input_digest"])
        if "frontier_diagnostics" in spec:
            declared = spec["declared_frontier"]["spec"]
            print("Initially model-enabled: " + ", ".join(declared["initial_enabled_action_ids"]))
            print("Latent: " + ", ".join(declared["latent_action_ids"]))
            print(
                "Declared activation rules: "
                + json.dumps(declared["activation_rules"], sort_keys=True)
            )
            print(
                "Model activation witness: "
                + json.dumps(spec["frontier_diagnostics"], sort_keys=True)
            )
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    print("Offline model output; no adapter executed and no capacity admitted.")
