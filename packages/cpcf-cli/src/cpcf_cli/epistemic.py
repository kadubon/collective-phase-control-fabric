# SPDX-License-Identifier: Apache-2.0
"""Fixed-model observation CLI; privileged simulator IDs are never replay inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from collective_phase_control_fabric.v6 import growth as g
from collective_phase_control_fabric.v6.canonical import canonical_bytes
from collective_phase_control_fabric.v6.catalogue_revision import (
    propose_catalogue,
    replan_catalogue,
)
from collective_phase_control_fabric.v6.composition import check_composition
from collective_phase_control_fabric.v6.epistemic import Domain
from collective_phase_control_fabric.v6.epistemic_checking import (
    check_epistemic_plan,
    reference_comparisons,
)
from collective_phase_control_fabric.v6.epistemic_evidence import (
    export_epistemic,
    reassess_epistemic,
    replan_epistemic,
)
from collective_phase_control_fabric.v6.epistemic_examples import (
    epistemic_example,
    integrated_example,
    workflow_request,
)
from collective_phase_control_fabric.v6.epistemic_planning import compare_epistemic, plan_epistemic
from collective_phase_control_fabric.v6.information_value import information_value
from collective_phase_control_fabric.v6.models import (
    CatalogueRevision,
    Document,
    EpistemicContract,
    EpistemicObservation,
    EpistemicPlan,
    EpistemicStep,
    GrowthCapabilityFrontier,
    GrowthContract,
    GrowthObservation,
    RunnerJob,
    WorkflowCandidate,
    WorkflowCertificate,
    WorkflowRequest,
    WorkflowSynthesis,
)
from collective_phase_control_fabric.v6.registry import document_digest
from collective_phase_control_fabric.v6.synthesis import synthesize


def example_report(name: str, directory: Path | None = None) -> dict[str, Any]:
    domain = epistemic_example(
        "epistemic-ambiguous"
        if name == "epistemic-uninformative"
        else name
        if name in {"epistemic-probe", "epistemic-ambiguous", "epistemic-verifier"}
        else "epistemic-probe"
    )
    if name == "epistemic-budget":
        sidecar = domain.epistemic.model_copy(
            update={"spec": domain.epistemic.spec.model_copy(update={"max_support": 1})}
        )
        domain = Domain(domain.contract, domain.objects, sidecar, domain.frontier)
    request = workflow_request(
        domain,
        [EpistemicStep(action_id="prepare", observation="red")]
        if name
        in {"epistemic-composition", "epistemic-no-composition", "epistemic-rejected-composition"}
        else None,
    )
    if name == "epistemic-no-composition":
        request = request.model_copy(
            update={"spec": request.spec.model_copy(update={"target_capacities": {"task": "100"}})}
        )
    if directory is not None:
        directory.mkdir(parents=True, exist_ok=True)
        objects = directory / "objects"
        objects.mkdir(exist_ok=True)
        for digest, obj in domain.objects.items():
            (objects / (digest.removeprefix("sha256:") + ".json")).write_bytes(
                canonical_bytes(obj.model_dump(mode="json", exclude_none=True))
            )
        for filename, doc in (
            ("contract.json", domain.contract),
            ("epistemic.json", domain.epistemic),
            ("frontier.json", domain.frontier),
            ("request.json", request),
        ):
            if doc is not None:
                (directory / filename).write_bytes(canonical_bytes(doc.model_dump(mode="json")))
    if name == "epistemic-integrated":
        return integrated_example()
    if name in {"epistemic-information", "epistemic-uninformative"}:
        return information_value(
            domain, {s: "recorded" for s in domain.epistemic.spec.observation_alphabet}, ["prepare"]
        ).model_dump(mode="json")
    if name in {"epistemic-composition", "epistemic-no-composition"}:
        return synthesize(domain, request).model_dump(mode="json")
    if name == "epistemic-rejected-composition":
        result = synthesize(domain, request)
        g.require(bool(result.spec.candidates), "composition_no_candidate")
        candidate = result.spec.candidates[0]
        altered = candidate.model_copy(
            update={"spec": candidate.spec.model_copy(update={"constituent_digests": []})}
        )
        try:
            check_composition(domain, request, altered)
        except g.GrowthError as error:
            return {
                "code": error.code,
                "synthetic": True,
                "candidate_accepted": False,
                "execution_authorized": False,
            }
        raise g.GrowthError("composition_tamper_not_rejected")
    plan = plan_epistemic(domain)
    return {
        "scenario": name,
        "synthetic": True,
        "plan": plan.model_dump(mode="json"),
        "policy_check": check_epistemic_plan(domain, plan) if plan.spec.policy else None,
        "execution_authorized": False,
        "observations_written": [],
    }


def run_epistemic(
    args: argparse.Namespace,
    contract: GrowthContract,
    objects: dict[str, Document],
    frontier: GrowthCapabilityFrontier | None,
) -> dict[str, Any]:
    from cpcf_cli.growth import _admission, _read

    d = Domain(contract, objects, _read(args.epistemic, EpistemicContract), frontier)
    history = (
        TypeAdapter(list[EpistemicStep]).validate_json(args.history.read_bytes())
        if args.history
        else []
    )
    g.require(len(history) <= d.epistemic.spec.max_history, "epistemic_history_budget")
    name = args.subcommand
    if name in {"inspect", "support"}:
        support = d.replay(history, reference_comparisons(d))
        return {
            "code": "epistemic_support_inspected",
            **d.controller_view(support),
            "input_digest": d.digest(),
            "epistemic_contract_digest": document_digest(d.epistemic),
        }
    if name == "plan":
        return plan_epistemic(d, history).model_dump(mode="json")
    if name == "compare":
        return {
            "code": "epistemic_comparators",
            "comparisons": [c.model_dump(mode="json") for c in compare_epistemic(d, history)],
        }
    if name == "information-value":
        mapping = json.loads(args.masked_channel.read_text(encoding="utf-8"))
        return information_value(d, mapping, args.sensing_action).model_dump(mode="json")
    if name in {"check-plan", "export", "replay"}:
        plan = _read(args.plan, EpistemicPlan)
        d = Domain(
            contract,
            objects,
            d.epistemic,
            frontier,
            plan.spec.observation_map,
            frozenset(plan.spec.excluded_action_ids),
            frozenset(plan.spec.excluded_interactions),
        )
        checked = check_epistemic_plan(d, plan)
        if name == "check-plan":
            return checked
        if name == "export":
            return export_epistemic(d, plan, _read(args.job, RunnerJob))
        g.require(not args.branch, "epistemic_hidden_branch_not_an_observation")
        trace = list(plan.spec.history)
        node = plan.spec.policy
        for symbol in args.observation_symbol:
            if node is None or node.action_id is None:
                raise g.GrowthError("epistemic_replay_terminal")
            g.require(symbol in node.branches, "epistemic_observation_mismatch")
            trace.append(
                EpistemicStep(
                    action_id=node.action_id,
                    observation=symbol,
                    entry=node.entry,
                    comparison_history_length=len(plan.spec.history) if node.entry else 0,
                )
            )
            node = node.branches[symbol]
        support = d.replay(trace, reference_comparisons(d))
        return {
            "code": "epistemic_hypothetical_replay",
            **d.controller_view(support),
            "next_action": node.action_id if node else None,
            "observations_written": [],
        }
    if name in {"ingest", "reassess", "replan"}:
        g.require(args.epistemic_observation is not None, "epistemic_observation_required")
        observed = _read(args.epistemic_observation, EpistemicObservation)
        base = _read(args.observation, GrowthObservation)
        if name == "replan":
            return replan_epistemic(d, observed, base, **_admission(args))
        return reassess_epistemic(d, observed, base, **_admission(args)).model_dump(mode="json")
    request = _read(args.request, WorkflowRequest)
    if name == "synthesize":
        return synthesize(d, request).model_dump(mode="json")
    candidate = _read(args.candidate, WorkflowCandidate)
    if name == "check-composition":
        return check_composition(d, request, candidate).model_dump(mode="json")
    if name == "catalogue-propose":
        return propose_catalogue(
            d,
            request,
            _read(args.synthesis, WorkflowSynthesis),
            candidate,
            parent=_read(args.parent, CatalogueRevision) if args.parent else None,
        ).model_dump(mode="json")
    return replan_catalogue(
        d,
        request,
        candidate,
        _read(args.certificate, WorkflowCertificate),
        _read(args.revision, CatalogueRevision),
        model_only_opt_in=args.model_only,
    )
