# Finite collective capability growth planning

The explicit offline `growth` mode chooses a paid intervention and a contingent continuation
within a declared finite model. It keeps task capacity, research capacity, verification,
quality, coverage, shared reservations, work queues, repair obligations, evidence costs and
elapsed physical time in one ledger. Agent count and artifact count are not objectives.
The existing repair planner and `operational_organization_profile` retain their meanings.

## Run the complete offline path

The base wheel contains the implementation, examples and four closed document kinds:
`growth-contract`, `growth-observation`, `growth-plan`, and `growth-assessment`.
No server, solver extra, credentials or model provider is required for planning.

```text
cpcf growth example growth-demo --scenario preparation --json
cpcf growth inspect growth-demo/contract.json --objects growth-demo/objects --json
cpcf growth plan growth-demo/contract.json --objects growth-demo/objects --output growth-plan.json
cpcf growth check-plan growth-demo/contract.json --objects growth-demo/objects --plan growth-plan.json --json
cpcf growth compare growth-demo/contract.json --objects growth-demo/objects --json
cpcf growth replay growth-demo/contract.json --objects growth-demo/objects --plan growth-plan.json --branch prepare:success --branch reuse:success --json
```

The example writes **unsigned synthetic modelling inputs**. It does not create receipts,
trusted-time material or signatures. JSON uses rational strings such as `4/3`; text output
identifies the chosen action, constraints, counterexamples, authority, evidence and objective.
`--output` writes the complete JSON result even when text output is selected.

For external execution, an operator prepares an **unsigned** existing `runner-job` document:

```text
cpcf growth export growth-demo/contract.json --objects growth-demo/objects --plan growth-plan.json --job operator-job-draft.json --output proposed-job.json --json
```

Export checks the policy and job's action, capability, generation and input bindings. It does
not mint a lease, sign a capability, authorize an executable or dispatch anything. The operator
must use the existing independently admitted capability, execution-policy and external-runner
protocol. A synthetic example capability has no execution authority.

## Exact scope and objective

The finite game has a declared action catalogue, at most 16 decisions, nonzero rational action
durations, a final deadline and preregistered growth windows. Every action binds an immutable
`ActionDocument` and `CapabilityDocument`. All four outcomes have nonempty successor definitions
and explicit applicable model IDs. Only applicability declared in the model can exclude an
outcome; an outcome name or exit code never establishes growth. An empty active model set is
`growth_inconsistent_models`.

The observation premise is `successor-id-is-observed`: the external refinement must distinguish
the declared successor before the next policy decision. This implementation does not solve a
partially observed game. `rectangular-adversarial` uncertainty permits a fresh applicable model
choice at each step. This is conservative for a fixed unknown parameter; no fixed-parameter
or stochastic optimality is claimed.

The growth solver enumerates AND–OR policy products and compares, in order:

1. Worst time of model-supported entry with a funded continuation on **every** branch.
2. Guaranteed terminal `min(task / target_task, research / target_research)`.
3. Worst resource consumption in the contract's `cost_order`, then each typed repair backlog
   in canonical stage order, terminal physical time, root action ID and canonical policy digest.

Each branch terminates exactly at its chosen entry time plus `continuation_horizon`. This is a
finite endpoint convention, not an optimization over arbitrary later terminal times. The
continuation must meet both registered capacity growth factors and every intermediate protected
condition. Mere survival, favorable marginal expectations and resource floors alone are insufficient.
If no qualifying policy exists after complete search, the result is
`growth_no_guaranteed_entry`; a separately checked safe fallback may still be available.

`max_decisions` defines the finite policy domain. `max_states`, `max_expansions`, `max_policies`
and `max_depth` are computational limits. `max_witness_nodes` bounds the exported tree
to at most 4,096 nodes. Exhausting a computational or witness limit yields
`growth_unknown_due_to_budget`, retains any feasible incumbent and makes the search incomplete.
It never establishes global nonexistence or optimality. Candidate, comparator and fallback
search quantities are reported separately. No beam or immediate-action Pareto pruning is used.
The independent `check-plan` traversal verifies all submitted actions, effect digests, branches,
state digests, prefix constraints, continuation and objective. It checks feasibility and the
reported objective; a submitted tree alone is not an optimality certificate.

## Accounting and comparison

All quantities are exact `Fraction` arithmetic in the registered coordinate units. Capacities
are services per registered time unit; queue and repair work use the corresponding service-work
unit. Joint coefficients have shared-resource units per capacity unit. Resource costs and repair
backlogs of different units are ordered separately, never added into an invented scalar quantity.

`shared_resources` and `joint_coefficients` describe the one simultaneous service reservation.
Both task and research demands, verification and every additional reservation must fit together.
Service is piecewise constant within an action; new credit arrives at its end. Long actions
retain the old service vector at registered interior boundaries. Every prefix checks quality,
coverage and service floors. Temporary contraction is allowed above those floors, with growth
checked only against preregistered block endpoints. Nonrepeatable actions remain used.

The `charges` categories partition real cost; a joint output/evidence activity is charged once.
Capability resource envelopes must contain the declared charges. Nonzero capability monetary
cost needs an explicitly funded `monetary_resource`. Capability debt and rollback identifiers
require concrete repair workloads. Offered service, completed work and capacity are distinct.
Arrivals are checked against burst limits before completion, all completion is bounded by actual
remaining work and offered service, and unfinished work keeps its deadline and debt after a
failure or timeout. No average-load queue guarantee is inferred.

`planning_charge` and `planning_duration` reserve a fixed allowance for the whole invocation,
including candidate/comparator search, checker and fallback. These are model premises to validate
externally, not measured CPU costs. The full allowance is prepaid rather than made contingent on
search success. `external-paid` records a separately paid computation boundary; it is not free
compute. Reassessment reserves another allowance in its prospective continuation ledger and
keeps that forecast out of the measured ledger.

Each comparator starts from the same charged checkpoint, knowledge/input distribution, time and
resource budgets. Removing its declared interaction filters the catalogue and **reoptimizes** the
remaining actions. A single-process refinement is included whenever it is represented by an
allowed action; its process count earns no reward. Only deterministic policies are admitted.

The P0 comparison is explicitly a **finite worst-case scalar** comparison. It compares candidate
guaranteed minimum attainment to an upper bound on the restricted class's optimal guaranteed
minimum attainment at the same endpoint. Scalar comparator bounds use exact backward induction;
interval lower and upper recursions stay separate. A best-so-far baseline is only a lower bound.
Incomplete comparison leaves the upper bound unknown. No coordinatewise stitching, convex-hull
randomization, expected-vector separation or probability/reliability advantage is asserted.
The comparison is accumulated from the contract checkpoint to the registered endpoint.

## Independently admitted external evidence

Hypothetical output, pending projection, receipt-backed observation and admitted capability remain
different states. Replay is read-only. Predictions never update a measured capacity or a scientific
dimension. Source removals can be replayed through the existing snapshot/audit kernel; the report
marks this as hypothetical and does not turn forecast resources or forecast time into attestations.
Required-object lifecycles are also checked against the separately declared **model** time origin.

A `GrowthObservation` binds the original contract, all version/checkpoint/information digests,
one registered window, every recorded decision boundary, capacity intervals, quality/coverage,
resource and work ledgers, source bytes, receipts, and an external registered `TrialResult`.
The protocol outcome IDs are `COORDINATE:BOUNDARY_INDEX`, for example `task:0` and `research:2`.
All intervals and quality values must match the external result and the declared units.
One admitted receipt is required per transition; its physical timestamps must match the registered
time origin in the measurement protocol. No receipt is synthesized from a prediction.

The signed observation requires the existing `acceleration_compatibility` quorum roles, including
the bound evaluator, independent quality/safety verifier and timestamp role. This reuses an
admission mechanism; it is not an assertion of acceleration. The loader recomputes signatures,
historical time, pinned roots, lifecycle, sources and quorum. Trial registration, amendments,
artifact commitments, provenance and results pass through `assess_trial`. Runner jobs, signed
capabilities, execution policies, material closure, attempts, output and leases are independently
checked through `validate_receipt`.

Place the external immutable generation, trust policy, trusted-time receipt and observation in
their existing document formats. The read-only CAS directory contains `HEX_SHA256.bin` files for
the generation's ledger objects, including raw output and signed statements. Supply both root
fingerprints independently of that directory:

```text
cpcf growth ingest contract.json --objects model-objects --observation observation.json --generation generation.json --cas admitted-cas --trust-policy trust-policy.json --trusted-time trusted-time.json --root-spki-fingerprint sha256:PINNED_ROOT --genesis-envelope-fingerprint sha256:PINNED_GENESIS --output assessment.json --json
```

Use the same arguments with `reassess` to revalidate, or `replan` to revalidate and emit a new
unsigned modelling proposal plus a plan. The original signed contract and observations are
unchanged. The new proposal requires registration before external use. A cached assessment is
never accepted by the CLI in place of fresh admission materials.

The sufficient arithmetic growth test uses **end lower / start upper**. Bias and drift allowances
widen both endpoints. Unprotected window selection, changed ontology/evaluator/coverage,
stale comparison, unconfirmed results, conflicting model scope or missing evidence keep the
conclusion inconclusive. Output separates `model_condition`, `arithmetic_check`,
`external_evidence_compatibility`, and `empirical_attribution`. `observed_entry=compatible`
concerns the recorded past condition; funded continuation is a separate field and model witness.
The contract model-time origin must match the registered protocol. A prospective continuation
starts after the separately paid planning interval and cannot start before the admitted current
time. Constant capacity and no additional arrivals during that declared computation interval are
model premises. A longer admission delay keeps the prospective continuation unavailable;
compatible past evidence cannot bridge an additional unobserved waiting/arrival interval.
Attribution stays undetermined, even with complete signatures. CPCF does not validate a statistical
method, construct validity, causality, endogenous attribution, physical intelligence growth,
AGI/ASI, or indefinite continuation.

## Reproducible comparisons and remaining assumptions

Run `python scripts/run_growth_examples.py` in the frozen development environment for preparation,
verification bottleneck, communication cost, all-failure, and no-advantage cases. The installed
equivalent is `cpcf growth example --scenario NAME --json`. The old repair planner is marked
outside the growth objective when given the explicit blocker-free synthetic premise; it is never
assigned a fabricated failure score. [Generated comparison results](examples/growth-comparison.json)
retain both capacities, verification, time, queue/debt, evidence costs and resources.

The exact arithmetic, finite search, independent checker and receipt/registration compatibility
are P0. Real action refinements, external measurement/coverage validity, independently registered
trials and deployment assurance remain external obligations. Statistical estimators, probabilistic
optimization, fixed-parameter belief states, larger search and real LLM trials are P1. No extra
server, cloud connector, autonomous execution, dashboard or training framework is introduced.

See [the paper mapping](growth-research-mapping.md) and the unchanged
[scientific boundaries](scientific-boundaries.md).
