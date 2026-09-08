# SPDX-License-Identifier: Apache-2.0
"""Synthetic, independently signed admission tests; never operational receipts."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from collective_phase_control_fabric.v6 import growth_examples
from collective_phase_control_fabric.v6.canonical import canonical_bytes, digest_bytes
from collective_phase_control_fabric.v6.growth import GrowthError, initial_state, plan_growth
from collective_phase_control_fabric.v6.growth_evidence import (
    _bounded_measurement,
    _within_prediction,
    export_proposal,
    reassess,
    replan_contract,
)
from collective_phase_control_fabric.v6.models import (
    ActionDocument,
    ArtifactRecord,
    ArtifactRecordSpec,
    CapabilityDocument,
    Document,
    EffectInterval,
    ExecutionPolicy,
    ExecutionPolicySpec,
    GrowthActivation,
    GrowthActivationRule,
    GrowthCapabilityFrontier,
    GrowthCapabilityFrontierSpec,
    GrowthFrontierBinding,
    GrowthObservation,
    GrowthObservationSpec,
    Lifecycle,
    MeasurementProtocol,
    MeasurementProtocolSpec,
    OutcomeDefinition,
    QuorumDecisionDocument,
    QuorumDecisionSpec,
    ResourceObservationAttestation,
    ResourceObservationSpec,
    RunnerJob,
    RunnerJobSpec,
    RunnerReceipt,
    RunnerReceiptSpec,
    SignedStatement,
    SignedStatementSpec,
    SourceArtifactEnvelope,
    SourceArtifactSpec,
    TrialResult,
    TrialResultSpec,
)
from collective_phase_control_fabric.v6.registry import document_digest, schema_digest
from collective_phase_control_fabric.v6.storage import MemoryObjectStore
from collective_phase_control_fabric.v6.trust import (
    build_protected_header,
    public_key_fingerprint,
    sign_document,
)
from tests.test_v6_authority import _generation
from tests.test_v6_growth import modify, recipe_for, step
from tests.v6_helpers import NOW, VALID_FROM, VALID_UNTIL, metadata, trust_fixture


def admitted_case(
    monkeypatch: pytest.MonkeyPatch,
    *,
    observation_updates: dict[str, Any] | None = None,
    omit_observation_quorum: bool = False,
    observation_lag: int = 1,
    receipt_start_shift_us: int = 0,
    job_updates: dict[str, Any] | None = None,
    receipt_updates: dict[str, Any] | None = None,
    frontier_mode: str | None = None,
) -> tuple[Any, ...]:
    monkeypatch.setattr(growth_examples, "metadata", metadata)
    c, objects = growth_examples.example()
    c = modify(
        c,
        model_time_origin=NOW - timedelta(seconds=3 + observation_lag),
        planning_duration="1",
        continuation_horizon="2",
        deadline="6",
        joint_service_until="6",
        windows=[c.spec.windows[0].model_copy(update={"start": "1", "end": "3"})],
    )
    policy, trusted_time, keys = trust_fixture()
    execution = ExecutionPolicy(
        metadata=metadata("growth-execution-policy"),
        spec=ExecutionPolicySpec(
            execution_policy_id="growth-execution",
            allowed_image_digests=[growth_examples.synthetic_digest("synthetic-image")],
            timeout_seconds=10,
            stdout_limit=4096,
            stderr_limit=4096,
            maximum_input_bytes=4096,
            maximum_output_bytes=16384,
            network_policy="none",
            filesystem_policy="none",
        ),
    )
    signed: list[Document] = []

    def statement(doc: Document, role: str, key: str, seconds: int = 0) -> SignedStatement:
        principal = next(p for p in policy.spec.principals if p.principal_id == key + "-principal")
        header = build_protected_header(
            doc,
            principal=principal,
            role=role,
            source_system="fixture-source",
            scope=["workspace-a"],
            signing_time=NOW + timedelta(seconds=seconds),
            policy_sequence=0,
            trusted_time_receipt_digest=None if doc is policy else document_digest(trusted_time),
        )
        result = SignedStatement(
            metadata=metadata("growth-sign-" + role + "-" + document_digest(doc)),
            spec=SignedStatementSpec(
                envelope=sign_document(doc, private_key=keys[key], protected=header)
            ),
        )
        signed.append(result)
        return result

    root = statement(policy, "workspace_root", "root")
    statement(trusted_time, "timestamp", "time")
    execution_statement = statement(execution, "execution_policy_authority", "auditor")
    updated_recipes = []
    caps: dict[str, tuple[CapabilityDocument, SignedStatement]] = {}
    # Bind the model recipes to independent fixture runner materials, keeping output pending.
    for r in c.spec.action_catalogue:
        old_action = cast(ActionDocument, objects.pop(r.action_digest))
        old_cap = cast(CapabilityDocument, objects.pop(old_action.spec.capability_digest))
        cap = old_cap.model_copy(
            update={
                "spec": old_cap.spec.model_copy(
                    update={
                        "execution_policy_digest": document_digest(execution),
                        "output_schema_name": "resource-observation-attestation",
                        "output_schema_digest": schema_digest("resource-observation-attestation"),
                    }
                )
            }
        )
        action = old_action.model_copy(
            update={
                "spec": old_action.spec.model_copy(
                    update={"capability_digest": document_digest(cap)}
                )
            }
        )
        objects.update({document_digest(x): x for x in (action, cap)})
        cap_statement = statement(cap, "capability_authority", "root")
        caps[action.spec.action_id] = (cap, cap_statement)
        statement(action, "state_source", "root")
        updated_recipes.append(r.model_copy(update={"action_digest": document_digest(action)}))
    c = modify(
        c,
        action_catalogue=updated_recipes,
        initial_state=c.spec.initial_state.model_copy(
            update={"live_object_digests": sorted(objects)}
        ),
    )
    if frontier_mode is not None:
        objects[document_digest(execution)] = execution
        c = modify(
            c,
            initial_state=c.spec.initial_state.model_copy(
                update={"live_object_digests": sorted(objects)}
            ),
        )
        if frontier_mode == "ambiguous":
            preparation = c.spec.action_catalogue[0]
            alternate = preparation.successors[0].model_copy(
                update={"successor_id": "prepare:alternate"}
            )
            c = modify(
                c,
                action_catalogue=[
                    preparation.model_copy(
                        update={"successors": [*preparation.successors, alternate]}
                    ),
                    *c.spec.action_catalogue[1:],
                ],
            )
        if frontier_mode == "unfunded":
            c = modify(
                c,
                initial_state=c.spec.initial_state.model_copy(
                    update={"resources": {"credits": "5"}}
                ),
            )
        if frontier_mode == "frontier-sensitive-comparator":
            continuation = recipe_for(c, objects, "continue")
            c = modify(
                c,
                action_catalogue=[
                    r.model_copy(update={"required_evidence": [], "interactions": []})
                    if r == continuation
                    else r
                    for r in c.spec.action_catalogue
                ],
            )
        if frontier_mode in {"no-superiority", "comparison-tie"}:
            c = modify(c, comparison_margin="10" if frontier_mode == "no-superiority" else "1/3")
    states = [initial_state(c)]
    for name in ("prepare", "reuse"):
        states.append(step(c, objects, states[-1], name))
    raw_objects: list[bytes] = []
    artifacts: list[ArtifactRecord] = []
    for kind in ("dataset", "assignment", "analysis-executable"):
        raw = canonical_bytes({"synthetic": kind})
        raw_objects.append(raw)
        artifact = ArtifactRecord(
            metadata=metadata("growth-" + kind),
            spec=ArtifactRecordSpec(
                artifact_type=kind,
                protocol_id="growth-measurement",
                producer_principal_id="root-principal",
                artifact_digest=digest_bytes(raw),
                acquisition_committed_at=NOW - timedelta(seconds=40),
                recorded_at=NOW - timedelta(seconds=35),
                source_system="fixture-source",
            ),
        )
        artifacts.append(artifact)
        statement(artifact, "trial_artifact_producer", "root", -35)
    protocol = MeasurementProtocol(
        metadata=metadata("growth-protocol"),
        spec=MeasurementProtocolSpec(
            protocol_id="growth-measurement",
            author_principal_id="root-principal",
            registrar_principal_id="auditor-principal",
            evaluator_principal_id="root-principal",
            quality_verifier_principal_id="auditor-principal",
            eligibility="Synthetic registered services only",
            treatment_strategy="Paid reuse",
            comparison_strategy="Reoptimized restricted catalogue",
            time_zero=c.spec.model_time_origin,
            observation_complete_at=NOW - timedelta(seconds=observation_lag),
            estimand="Externally recorded joint service intervals",
            outcomes=[
                OutcomeDefinition(
                    outcome_id=f"{key}:{index}",
                    unit=c.spec.domains[key].unit,
                    direction="higher",
                    minimum_effect="0",
                    quality_floor="1",
                )
                for index in range(3)
                for key in c.spec.domains
            ],
            multiplicity_policy="Registered finite simultaneous family",
            dataset_record_digest=document_digest(artifacts[0]),
            assignment_record_digest=document_digest(artifacts[1]),
            analysis_executable_record_digest=document_digest(artifacts[2]),
            missing_data_policy="Unresolved",
            stopping_rule="Two prespecified seconds",
            exclusion_policy="Retain every failure",
            primary_result_id="growth-primary",
        ),
    )
    c = modify(
        c,
        versions=c.spec.versions.model_copy(update={"protocol_digest": document_digest(protocol)}),
    )

    def quorum(doc: Document, kind: str, roles: list[tuple[str, str]], at: int = 0) -> None:
        documents = [statement(doc, role, key, at) for role, key in roles]
        signed.append(
            QuorumDecisionDocument(
                metadata=metadata("growth-quorum-" + document_digest(doc)),
                spec=QuorumDecisionSpec(
                    decision_type=kind,
                    subject_digest=document_digest(doc),
                    statement_digests=[document_digest(s) for s in documents],
                    decided_at=NOW + timedelta(seconds=at),
                ),
            )
        )

    quorum(
        protocol,
        "protocol_registration",
        [("protocol_author", "root"), ("registration", "auditor"), ("timestamp", "time")],
        -30,
    )
    frontier = None
    if frontier_mode is not None:
        bindings = []
        for recipe in c.spec.action_catalogue:
            action = cast(ActionDocument, objects[recipe.action_digest])
            cap = cast(CapabilityDocument, objects[action.spec.capability_digest])
            bindings.append(
                GrowthFrontierBinding(
                    action_id=action.spec.action_id,
                    action_digest=document_digest(action),
                    capability_digest=document_digest(cap),
                    execution_policy_digest=document_digest(execution),
                    output_schema_digest=cap.spec.output_schema_digest,
                    lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
                )
            )
        by_id = {b.action_id: b for b in bindings}
        frontier = GrowthCapabilityFrontier(
            metadata=metadata("synthetic-admitted-frontier"),
            spec=GrowthCapabilityFrontierSpec(
                contract_digest=document_digest(c),
                initial_enabled_action_ids=sorted(set(by_id) - {"reuse", "continue"}),
                latent_action_ids=["continue", "reuse"],
                bindings=bindings,
                maximum_activation_depth=3,
                activation_rules=[
                    GrowthActivationRule(
                        rule_id=f"{producer}-enables-{target}",
                        producer_action_id=producer,
                        producer_successor_id=f"{producer}:success",
                        activated_action_ids=[target],
                        required_capability_digests=[
                            by_id[producer].capability_digest,
                            by_id[target].capability_digest,
                        ],
                        required_model_ids=["nominal"],
                        valid_from="0",
                        expires="6",
                    )
                    for producer, target in [("prepare", "reuse"), ("reuse", "continue")]
                ],
            ),
        )
        if frontier_mode == "ambiguous":
            rule = frontier.spec.activation_rules[0].model_copy(
                update={
                    "rule_id": "alternate-activation",
                    "producer_successor_id": "prepare:alternate",
                    "activated_action_ids": ["continue"],
                }
            )
            frontier = frontier.model_copy(
                update={
                    "spec": frontier.spec.model_copy(
                        update={"activation_rules": [*frontier.spec.activation_rules, rule]}
                    )
                }
            )
        if frontier_mode == "no-rule":
            frontier = frontier.model_copy(
                update={"spec": frontier.spec.model_copy(update={"activation_rules": []})}
            )
        if frontier_mode == "carried-missing-capability":
            rule = frontier.spec.activation_rules[0].model_copy(
                update={"rule_id": "prior-continue", "activated_action_ids": ["continue"]}
            )
            prior = GrowthActivation(
                action_id="continue",
                rule_id=rule.rule_id,
                producer_action_id="prepare",
                producer_successor_id="prepare:success",
                depth=1,
                model_time="0",
                parent_state_digest="sha256:" + "a" * 64,
            )
            frontier = frontier.model_copy(
                update={
                    "spec": frontier.spec.model_copy(
                        update={
                            "initial_enabled_action_ids": sorted(
                                [*frontier.spec.initial_enabled_action_ids, "continue"]
                            ),
                            "latent_action_ids": ["reuse"],
                            "initial_activation_lineage": [prior],
                            "activation_rules": [*frontier.spec.activation_rules, rule],
                        }
                    )
                }
            )
        if frontier_mode == "missing-rule-capability":
            producer_rule = frontier.spec.activation_rules[0]
            producer_rule = producer_rule.model_copy(
                update={
                    "required_capability_digests": [
                        *producer_rule.required_capability_digests,
                        by_id["greedy"].capability_digest,
                    ]
                }
            )
            # An unused rule must not substitute its different admitted prerequisites.
            decoy = GrowthActivationRule(
                rule_id="unused-self-activation",
                producer_action_id="idle",
                producer_successor_id="idle:success",
                activated_action_ids=["idle"],
                required_capability_digests=[by_id["idle"].capability_digest],
                required_model_ids=["nominal"],
                valid_from="0",
                expires="6",
            )
            frontier = frontier.model_copy(
                update={
                    "spec": frontier.spec.model_copy(
                        update={
                            "activation_rules": [
                                decoy,
                                producer_rule,
                                frontier.spec.activation_rules[1],
                            ]
                        }
                    )
                }
            )
            signed.remove(caps["greedy"][1])
        if frontier_mode == "missing-frontier-quorum":
            statement(frontier, "protocol_author", "root")
        else:
            quorum(
                frontier,
                "protocol_registration",
                [("protocol_author", "root"), ("registration", "auditor"), ("timestamp", "time")],
                -30,
            )
        if frontier_mode in {"missing-capability", "carried-missing-capability"}:
            signed.remove(caps["continue"][1])
    result = TrialResult(
        metadata=metadata("growth-result"),
        spec=TrialResultSpec(
            primary_result_id="growth-primary",
            protocol_digest=document_digest(protocol),
            dataset_record_digest=document_digest(artifacts[0]),
            assignment_record_digest=document_digest(artifacts[1]),
            analysis_executable_record_digest=document_digest(artifacts[2]),
            evaluator_principal_id="root-principal",
            quality_verifier_principal_id="auditor-principal",
            observation_completed_at=NOW - timedelta(seconds=observation_lag),
            issued_at=NOW,
            design="descriptive",
            effects=[
                EffectInterval(
                    outcome_id=f"{key}:{index}",
                    lower=interval.lower,
                    upper=interval.upper,
                    quality_value=state.quality[key],
                )
                for index, state in enumerate(states)
                for key, interval in state.capacities.items()
            ],
        ),
    )
    quorum(
        result,
        "acceleration_compatibility",
        [("evaluator", "root"), ("quality_safety_verifier", "auditor"), ("timestamp", "time")],
    )
    receipt_digests: list[str] = []
    source_digests: list[str] = []
    jobs: list[RunnerJob] = []
    for index, name in enumerate(("prepare", "reuse")):
        cap, cap_statement = caps[name]
        r = recipe_for(c, objects, name)
        raw_document = ResourceObservationAttestation(
            metadata=metadata("growth-raw-" + name),
            spec=ResourceObservationSpec(
                coordinate="credits",
                quantity=states[index + 1].resources["credits"],
                unit="credit",
                observed_at=NOW - timedelta(seconds=1 + observation_lag - index),
                lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
            ),
        )
        raw = canonical_bytes(raw_document.model_dump(mode="json", exclude_none=True))
        raw_objects.append(raw)
        source_digests.append(digest_bytes(raw))
        source = SourceArtifactEnvelope(
            metadata=metadata("growth-source-" + name),
            spec=SourceArtifactSpec(
                raw_digest=digest_bytes(raw),
                byte_length=len(raw),
                media_type="application/json",
                source_system="fixture-source",
                source_uri="urn:cpcf:synthetic:" + name,
                acquired_at=NOW,
                expected_schema_name=raw_document.kind,
                expected_schema_digest=schema_digest(raw_document.kind),
            ),
        )
        statement(source, "state_source", "root")
        job = RunnerJob(
            metadata=metadata("growth-job-" + name, NOW - timedelta(seconds=5)),
            spec=RunnerJobSpec(
                job_id="growth-job-" + name,
                action_digest=r.action_digest,
                capability_digest=document_digest(cap),
                capability_statement_digest=document_digest(cap_statement),
                execution_policy_digest=document_digest(execution),
                execution_policy_statement_digest=document_digest(execution_statement),
                generation_digest=objects[c.spec.analysis_snapshot_digest].spec.generation_digest,
                attempt=1,
                lease_id="growth-lease-" + name,
                lease_expires_at=NOW + timedelta(seconds=5),
                image_digest=cap.spec.image_digest,
                timeout_seconds=10,
                stdout_limit=4096,
                stderr_limit=4096,
                network_policy="none",
                filesystem_policy="none",
            ),
        )
        if job_updates:
            job = job.model_copy(update={"spec": job.spec.model_copy(update=job_updates)})
        statement(job, "job_dispatcher", "root")
        jobs.append(job)
        receipt = RunnerReceipt(
            metadata=metadata("growth-receipt-" + name),
            spec=RunnerReceiptSpec(
                job_digest=document_digest(job),
                job_id=job.spec.job_id,
                attempt=1,
                lease_id=job.spec.lease_id,
                runner_principal_id="runner-principal",
                image_digest=cap.spec.image_digest,
                material_digests=[
                    document_digest(cap_statement),
                    document_digest(execution_statement),
                ],
                stdout_digest=digest_bytes(raw),
                stderr_digest=digest_bytes(b""),
                stdout_captured_bytes=len(raw),
                stderr_captured_bytes=0,
                stdout_discarded_bytes=0,
                stderr_discarded_bytes=0,
                return_code=0,
                timeout=False,
                claimed_outcome="success",
                cleanup_complete=True,
                output_digests=[digest_bytes(raw)],
                started_at=NOW
                - timedelta(seconds=2 + observation_lag - index)
                + timedelta(microseconds=receipt_start_shift_us),
                completed_at=NOW - timedelta(seconds=1 + observation_lag - index),
            ),
        )
        if receipt_updates:
            receipt = receipt.model_copy(
                update={"spec": receipt.spec.model_copy(update=receipt_updates)}
            )
        statement(receipt, "runner_receipt", "runner")
        receipt_digests.append(document_digest(receipt))
    observation = GrowthObservation(
        metadata=metadata("growth-observation"),
        spec=GrowthObservationSpec(
            contract_digest=document_digest(c),
            versions=c.spec.versions,
            lifecycle=Lifecycle(valid_from=VALID_FROM, valid_until=VALID_UNTIL),
            window=c.spec.windows[0],
            states=states,
            source_artifact_digests=source_digests,
            runner_receipt_digests=receipt_digests,
            trial_result_digest=document_digest(result),
            evaluator_principal_id="root-principal",
            calibration_allowance={k: "0" for k in c.spec.domains},
            drift_allowance={k: "0" for k in c.spec.domains},
            coverage_meaning="Stipulated exact intervals for a synthetic deterministic fixture",
            simultaneous_assumptions="Every declared decision boundary included",
            monitoring="preregistered-boundaries",
        ),
    )
    if observation_updates:
        observation = observation.model_copy(
            update={"spec": observation.spec.model_copy(update=observation_updates)}
        )
    if omit_observation_quorum:
        statement(observation, "evaluator", "root")
    else:
        quorum(
            observation,
            "acceleration_compatibility",
            [("evaluator", "root"), ("quality_safety_verifier", "auditor"), ("timestamp", "time")],
        )
    store = MemoryObjectStore()
    generation = _generation(store, signed, raw_objects=(*raw_objects, b""))
    kwargs = {
        "generation": generation,
        "store": store,
        "policy": policy,
        "trusted_time": trusted_time,
        "expected_root_spki_fingerprint": public_key_fingerprint(policy.spec.principals[0]),
        "expected_genesis_envelope_fingerprint": digest_bytes(
            canonical_bytes(root.spec.envelope.model_dump(mode="json"))
        ),
    }
    result = (c, objects, observation, kwargs, jobs)
    return (*result, frontier) if frontier_mode is not None else result


def test_independently_admitted_receipts_reassess_and_replan_without_capacity_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, o, obs, kwargs, jobs = admitted_case(monkeypatch)
    assessment = reassess(c, o, obs, **kwargs)
    assert assessment.spec.reasons == []
    assert assessment.spec.external_evidence_compatibility == "compatible"
    assert assessment.spec.arithmetic_check == "satisfied"
    assert assessment.spec.observed_entry == "compatible"
    assert assessment.spec.empirical_attribution == "undetermined"
    assert assessment.spec.measured_bounds["task"].lower == "3"
    assert assessment.spec.continuation == "model-witness"
    assert assessment.spec.continuation_expires == "5"
    proposed = replan_contract(c, assessment)
    assert proposed != c and proposed.extensions["org.cpcf.growth"]["hypothetical"] is True
    assert obs.spec.contract_digest == document_digest(c)
    updated = plan_growth(proposed, o)
    assert updated.spec.observed_entry == "undetermined"
    plan = plan_growth(c, o)
    exported = export_proposal(c, o, plan, jobs[0])
    assert exported["executed"] is False and exported["authorized"] is False
    assert exported["runner_job"] == jobs[0].model_dump(mode="json")


@pytest.mark.parametrize(
    "mode,code",
    [
        ("missing-quorum", "growth_observation_not_admitted"),
        ("wrong-root", "growth_observation_not_admitted"),
        ("tampered", "growth_observation_not_admitted"),
        ("versions", "growth_observation_versions_changed"),
        ("window", "growth_observation_window_changed"),
        ("duplicate", "growth_duplicate_evidence"),
        ("calibration", "growth_observed_block_not_supported"),
    ],
)
def test_evidence_weakening_never_strengthens_empirical_verdict(
    monkeypatch: pytest.MonkeyPatch, mode: str, code: str
) -> None:
    updates: dict[str, Any] = {}
    c, o, obs, kwargs, _ = admitted_case(monkeypatch)
    if mode == "missing-quorum":
        c, o, obs, kwargs, _ = admitted_case(monkeypatch, omit_observation_quorum=True)
    elif mode == "wrong-root":
        kwargs["expected_root_spki_fingerprint"] = "sha256:" + "0" * 64
    elif mode == "tampered":
        obs = obs.model_copy(
            update={"spec": obs.spec.model_copy(update={"coverage_meaning": "changed"})}
        )
    else:
        if mode == "versions":
            updates["versions"] = obs.spec.versions.model_copy(
                update={"ontology_digest": "sha256:" + "0" * 64}
            )
        elif mode == "window":
            updates["monitoring"] = "unprotected-selection"
        elif mode == "duplicate":
            updates["source_artifact_digests"] = obs.spec.source_artifact_digests * 2
        elif mode == "calibration":
            # End lower=3-1/2, start upper=1+1/2; lower/lower would overstate growth.
            updates["calibration_allowance"] = {
                k: "1/2" if k != "verification" else "0" for k in c.spec.domains
            }
            # Retain floor feasibility to isolate the conservative block inequality.
            c = modify(
                c,
                domains={
                    k: d.model_copy(update={"service_floor": "1/2"})
                    for k, d in c.spec.domains.items()
                },
            )
            updates["contract_digest"] = document_digest(c)
        rebuilt_c, o, obs, kwargs, _ = admitted_case(monkeypatch, observation_updates=updates)
        if mode != "calibration":
            c = rebuilt_c
    assessment = reassess(c, o, obs, **kwargs)
    assert code in assessment.spec.reasons
    assert assessment.spec.observed_entry == "undetermined"
    assert assessment.spec.empirical_attribution == "undetermined"
    assert not assessment.spec.statistics_certified and not assessment.spec.causality_certified


def test_measurement_bias_widens_intervals_and_ledger_mismatch_is_not_admitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, obs, _, _ = admitted_case(monkeypatch)
    state = obs.spec.states[-1]
    widened = obs.model_copy(
        update={
            "spec": obs.spec.model_copy(
                update={"drift_allowance": {k: "1/4" for k in state.capacities}}
            )
        }
    )
    bounded = _bounded_measurement(widened, state)
    assert bounded.capacities["task"].lower == "11/4"
    assert bounded.capacities["task"].upper == "13/4"
    assert not _within_prediction(
        state.model_copy(update={"resources": {"credits": "1000"}}), state
    )
    assert not _within_prediction(bounded, state)


def test_stale_entry_preserves_past_evidence_but_cannot_reuse_a_continuation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, o, obs, kwargs, _ = admitted_case(monkeypatch, observation_lag=2)
    assessed = reassess(c, o, obs, **kwargs)
    assert assessed.spec.observed_entry == "compatible"
    assert assessed.spec.continuation == "unavailable"
    assert assessed.spec.continuation_policy is None
    assert assessed.spec.reasons == ["growth_continuation_state_stale"]
    assert assessed.spec.reassessed_state.elapsed == "3"


def test_receipt_physical_time_cannot_be_substituted_by_model_step_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, o, obs, kwargs, _ = admitted_case(monkeypatch, receipt_start_shift_us=1)
    assessed = reassess(c, o, obs, **kwargs)
    assert assessed.spec.reasons == ["growth_receipt_physical_time_mismatch"]
    assert assessed.spec.external_evidence_compatibility == "unknown"
    assert assessed.spec.continuation == "unavailable"


@pytest.mark.parametrize(
    "change,code",
    [
        ("contract", "growth_observation_contract_mismatch"),
        ("trace", "growth_observation_trace_incomplete"),
        ("source-missing", "growth_source_missing"),
        ("source-untyped", "growth_source_not_admitted"),
        ("trial-missing", "growth_trial_missing"),
        ("measurement-missing", "growth_trial_measurement_incomplete"),
        ("measurement-changed", "growth_trial_measurement_mismatch"),
        ("seed-budget", "growth_observation_seed_mismatch"),
        ("receipt-missing", "growth_receipt_not_admitted"),
        ("hidden-budget", "growth_observation_outside_model"),
        ("negative-bias", "growth_calibration_invalid"),
        ("bias-domain", "growth_calibration_domain"),
    ],
)
def test_signed_incompatible_measurement_material_cannot_admit_growth(
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    code: str,
) -> None:
    _, _, original, _, _ = admitted_case(monkeypatch)
    obs = original.spec
    zero = "sha256:" + "0" * 64
    updates: dict[str, Any] = {}
    if change == "contract":
        updates["contract_digest"] = zero
    elif change == "trace":
        updates["runner_receipt_digests"] = obs.runner_receipt_digests[:1]
    elif change == "source-missing":
        updates["source_artifact_digests"] = [zero]
    elif change == "source-untyped":
        updates["source_artifact_digests"] = [digest_bytes(b"")]
    elif change == "trial-missing":
        updates["trial_result_digest"] = zero
    elif change == "measurement-missing":
        updates["states"] = [*obs.states, obs.states[-1]]
        updates["runner_receipt_digests"] = [*obs.runner_receipt_digests, zero]
    elif change == "measurement-changed":
        updates["states"] = [
            obs.states[0].model_copy(update={"quality": {**obs.states[0].quality, "task": "1/2"}}),
            *obs.states[1:],
        ]
    elif change == "seed-budget":
        updates["states"] = [
            obs.states[0].model_copy(update={"resources": {"credits": "999"}}),
            *obs.states[1:],
        ]
    elif change == "receipt-missing":
        updates["runner_receipt_digests"] = [zero, obs.runner_receipt_digests[1]]
    elif change == "hidden-budget":
        updates["states"] = [
            obs.states[0],
            obs.states[1].model_copy(update={"resources": {"credits": "999"}}),
            obs.states[2],
        ]
    elif change == "negative-bias":
        updates["calibration_allowance"] = {**obs.calibration_allowance, "task": "-1"}
    else:
        updates["calibration_allowance"] = {"task": "0", "research": "0", "unregistered": "0"}
    c, o, observation, kwargs, _ = admitted_case(monkeypatch, observation_updates=updates)
    assessed = reassess(c, o, observation, **kwargs)
    assert code in assessed.spec.reasons
    assert assessed.spec.observed_entry == "undetermined"
    assert assessed.spec.continuation_policy is None
    assert assessed.spec.empirical_attribution == "undetermined"


@pytest.mark.parametrize(
    "job_change,receipt_change,code",
    [
        ({}, {"job_digest": "sha256:" + "0" * 64}, "growth_job_not_admitted"),
        ({"capability_digest": "sha256:" + "0" * 64}, {}, "growth_runner_materials_not_admitted"),
        ({}, {"return_code": 1}, "growth_receipt_nonconformant"),
        ({"action_digest": "sha256:" + "0" * 64}, {}, "growth_receipt_action_mismatch"),
    ],
)
def test_signed_receipt_and_job_bindings_are_recomputed(
    monkeypatch: pytest.MonkeyPatch,
    job_change: dict[str, Any],
    receipt_change: dict[str, Any],
    code: str,
) -> None:
    c, o, obs, kwargs, _ = admitted_case(
        monkeypatch, job_updates=job_change, receipt_updates=receipt_change
    )
    assessed = reassess(c, o, obs, **kwargs)
    assert assessed.spec.reasons == [code]
    assert assessed.spec.external_evidence_compatibility == "unknown"
    assert assessed.spec.observed_entry == "undetermined"


@pytest.mark.parametrize(
    "field",
    [
        "action_digest",
        "capability_digest",
        "execution_policy_digest",
        "image_digest",
        "generation_digest",
    ],
)
def test_unsigned_export_does_not_accept_an_unbound_runner_request(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    c, o, _, _, jobs = admitted_case(monkeypatch)
    plan = plan_growth(c, o)
    job = jobs[0].model_copy(
        update={"spec": jobs[0].spec.model_copy(update={field: "sha256:" + "0" * 64})}
    )
    code = (
        "growth_proposal_generation_mismatch"
        if field == "generation_digest"
        else "growth_proposal_binding_mismatch"
    )
    with pytest.raises(GrowthError, match=rf"\A{code}\Z"):
        export_proposal(c, o, plan, job)


def test_empty_reassessment_model_is_inconsistent_even_when_evidence_is_unusable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c, o, obs, kwargs, _ = admitted_case(monkeypatch)
    c = modify(c, initial_state=c.spec.initial_state.model_copy(update={"model_ids": []}))
    assessed = reassess(c, o, obs, **kwargs)
    assert assessed.spec.model_condition == "inconsistent"
    assert "growth_inconsistent_models" in assessed.spec.reasons
    assert assessed.spec.observed_entry == "undetermined"


def write_admission_fixture(directory: Path, case: tuple[Any, ...]) -> list[str]:
    c, o, obs, kwargs, _ = case
    directory.mkdir(exist_ok=True)
    objects = directory / "objects"
    objects.mkdir(exist_ok=True)
    for digest, doc in o.items():
        (objects / (digest[7:] + ".json")).write_bytes(
            canonical_bytes(doc.model_dump(mode="json", exclude_none=True))
        )
    for name, doc in {
        "contract": c,
        "observation": obs,
        "generation": kwargs["generation"],
        "trust-policy": kwargs["policy"],
        "trusted-time": kwargs["trusted_time"],
    }.items():
        (directory / (name + ".json")).write_bytes(
            canonical_bytes(doc.model_dump(mode="json", exclude_none=True))
        )
    cas = directory / "cas"
    cas.mkdir(exist_ok=True)
    for (_, digest), raw in kwargs["store"].values.items():
        (cas / (digest[7:] + ".bin")).write_bytes(raw)
    return [
        str(directory / "contract.json"),
        "--objects",
        str(objects),
        "--observation",
        str(directory / "observation.json"),
        "--generation",
        str(directory / "generation.json"),
        "--cas",
        str(cas),
        "--trust-policy",
        str(directory / "trust-policy.json"),
        "--trusted-time",
        str(directory / "trusted-time.json"),
        "--root-spki-fingerprint",
        kwargs["expected_root_spki_fingerprint"],
        "--genesis-envelope-fingerprint",
        kwargs["expected_genesis_envelope_fingerprint"],
    ]
