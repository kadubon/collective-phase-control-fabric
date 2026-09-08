# Bounded Endogenous Capability Frontier Expansion

CPCF 0.7.0 can plan over an immutable finite super-catalogue whose active action set changes
after declared model outcomes. Research or preparation may enable a later research action;
that action may enable a verifier or another capability investment. Every candidate action
already exists before planning starts. There is no generated executable definition, code
admission, self-modification or adapter execution.

This is a finite model and software-control mechanism. No external empirical acceleration
experiment was performed. It does not establish real-world capability reproduction,
collective intelligence, AGI, ASI, causal acceleration or indefinite growth. The package remains
Beta. Model examples and test signatures are synthetic, not operational receipts.

## Documents and compatibility

The additive closed kinds are `growth-capability-frontier`, `growth-frontier-plan` and
`growth-frontier-assessment`. Protocol identity remains `cpcf.io/v0.6`; the original 52 schema
identities and no-frontier plan encodings remain unchanged. Package version and OpenAPI package
metadata are 0.7.0; historical protocol identifiers are not package versions.

A frontier binds one exact `growth-contract` digest. Its initial enabled and latent action IDs
partition the contract's finite action catalogue (at most 16 actions). Each binding includes
the immutable action, capability, output-schema and execution-policy digests plus a declared
model lifecycle. Existing capability branches specify the resource envelope, outcomes,
repeatability, hazards and obligations. The execution policy object must exist and allow the
bound image. These checks establish model consistency, not admission or permission.

No `--frontier` means the original fixed-catalogue semantics. A frontier plan requires its exact
frontier when checked, exported or replayed. Merely placing an unrelated frontier in the objects
directory does not change planning semantics.

## Active state and transitions

Write the declared super-catalogue as `A_super` and the currently model-enabled set as `A_t`.
Always `A_t ⊆ A_super`. `GrowthFrontierState` extends the original resource/evidence ledger with
`frontier_digest`, sorted `enabled_action_ids`, `activation_depth` and `activation_lineage`.
Every facet participates in normalization, state digest, memoization, policy nodes, checking
and replay. Frontier plans retain both a projection onto the original ledger and complete
terminal frontier states; the checker reconstructs and compares both.

An activation rule binds an exact producer action and successor ID, target action IDs,
required capability digests, allowed model IDs, optional evidence labels, minimum capacities
and remaining resources, and a model-time validity interval. Model IDs must all satisfy the
rule's allowed set. Evidence labels here are model premises, never signatures or observations.

The existing transition first accounts for costs, physical duration, transient reservations,
arrival bursts, offered service, completed work, repair debt, capacity, expiry and hazards.
Rules then inspect that same post-transition ledger. A failed prerequisite gives no activation.
Matching rules may add only existing inactive targets with live bound objects and a valid
lifecycle. A depth overflow or invalid target lifecycle rejects the transition. A producer
must be active and valid throughout its action. No rule can erase queue, debt or evidence
obligations, and no rule reads another rule's activation as an intra-transition premise.

Success-only rules never apply to partial, failure or timeout outcomes. Those outcomes can
activate an explicit subset only when their own successor IDs have a declared rule. The AND–OR
policy must handle every applicable successor, including discovery failure.

The target's depth is its producer's depth plus one; initially active roots have depth zero.
Duplicate activation is a no-op. If several simultaneously matching rules name the same target,
the lexicographically first rule ID supplies its permanent lineage. Re-activation cannot reset
depth, replace prerequisites or extend expiry. Active actions still need valid object bindings
and all lineage prerequisites throughout future use. Withdrawal or expiry can therefore make
an enabled action unusable without deleting its historical model lineage.

## Objective and exactness

The objective is unchanged: minimize worst-case growth-entry time with funded continuation on
every branch; maximize guaranteed terminal minimum normalized task/research attainment; then
order typed costs, debt, duration and deterministic tie-breakers. Neither frontier size nor
agent, capability or generated-file counts enter the objective.

Action duration remains strictly positive. A self-unlock of an already enabled action adds
nothing. Mutual activation eventually saturates the finite set and cannot create capacity,
evidence, resources or objective credit. All paths remain bounded by decisions, model deadline,
activation depth, resource constraints and explicit search limits. Empty model sets are
inconsistent; exhausted search is unknown. A safe deadline fallback is separate from guaranteed
growth entry and from a funded continuation witness.

The interaction-restricted comparator starts with the same frontier, information and paid
planning allowance. It reoptimizes every legally reachable remaining action, including
alternative activation paths. Removing an interaction can remove a producer and its reachable
descendants. The comparator is never frozen at the original active set. A single attainable
worst-case scalar is compared; incomplete search supplies no superiority certificate.

## Model activation witnesses

The selected policy reports newly enabled actions, actions actually used after activation,
maximum depth, lineage records and first subsequent policy-node use. Each record binds the
producer, exact successor, parent state digest and model time. The witness is descriptive:
`downstream_objective_effect` is `not-marginally-attributed`. No exact causal marginal effect
or empirical contribution is inferred.

`endogenous_frontier_used` means the selected policy uses an action after activation.
`continuation_depends_on_frontier` means an activated action is used at or after entry in that
selected policy. It does not assert that every possible continuation requires it. Verification
contribution means an applicable branch of such an action increases declared verification
capacity; it is not a measured verifier improvement. Carried initial lineage is identified
separately, and its targets are not counted as newly enabled in the current policy.

Exact replay uses the checked policy and immutable inputs. It writes no observation, receipt,
capability admission, lease, signature or execution authorization.

## Synthetic scenarios

Run `cpcf growth example --scenario frontier-chain --json`. Supply a directory to write
`contract.json`, `frontier.json` and immutable `objects/` inputs.

| Scenario | Selected model behavior and reason |
| --- | --- |
| A `frontier-research` | `prepare → reuse → continue`: no immediate preparation gain, but research activation permits entry at time 2 and paid continuation |
| B `frontier-verifier` | `prepare → verifier → reuse → continue`: research enables verifier investment; increased verification capacity clears the declared queue and permits entry at time 3 |
| C `frontier-failure` | No guaranteed entry: success enables research; failure/timeout branches do not inherit that activation |
| D `frontier-useless` | Uses the productive preparation route without activating the three useless candidates; frontier size has no reward |
| E `frontier-chain` | `prepare → reuse → continue`: reuse is activated at depth 1 and activates continuation at depth 2 |
| F `frontier-cycle` | Mutual `idle ↔ greedy` activation has no capacity effect and gives no growth credit; the productive route wins |
| G `frontier-comparator` | Candidate uses preparation; the restricted comparator can instead use `serial → reuse` and is reoptimized over that alternative activation path |
| H `frontier-no-entry` | All-failure model has a checked safe fallback and no guaranteed growth entry |

The [generated report](examples/frontier-comparison.json) records exact objectives, selected
paths, comparison bounds, blockers and witnesses. Regenerate it with
`uv run --frozen python scripts/run_frontier_examples.py`; CI checks it with `--check`.

## CLI workflow

```text
cpcf growth example frontier-demo --scenario frontier-chain --json
cpcf growth inspect frontier-demo/contract.json --objects frontier-demo/objects --frontier frontier-demo/frontier.json --json
cpcf growth plan frontier-demo/contract.json --objects frontier-demo/objects --frontier frontier-demo/frontier.json --output frontier-plan.json
cpcf growth check-plan frontier-demo/contract.json --objects frontier-demo/objects --frontier frontier-demo/frontier.json --plan frontier-plan.json --json
cpcf growth compare frontier-demo/contract.json --objects frontier-demo/objects --frontier frontier-demo/frontier.json --json
cpcf growth replay frontier-demo/contract.json --objects frontier-demo/objects --frontier frontier-demo/frontier.json --plan frontier-plan.json --branch prepare:success --branch reuse:success --json
```

`growth export` also takes `--frontier` and the existing operator-supplied `--job`. The same
option applies to `ingest`, `reassess` and `replan`, with their original observation, generation,
CAS, trust policy, trusted time and independently supplied root pins.

## Receipt-backed advancement and admission

Keep these stages distinct: latent; model-enabled; receipt-backed candidate; admitted
capability; externally authorized execution. Offline planning establishes only model enablement.
There is no second admission authority.

Frontier reassessment first runs the original independent observation, DSSE/quorum, trial,
physical-time and receipt checks. It freshly loads the original generation again, requires the
frontier's existing `protocol_registration` quorum, and reconstructs the frontier from the
initial state and all receipt-compatible model outcomes. If an outcome does not uniquely
determine the same activation state, advancement is unknown. A favorable branch cannot be
selected from an ambiguous receipt. Target actions, capabilities, execution policies and
required capability subjects must independently be admitted.

`replan` accepts those original materials again, never a cached assessment. It creates a new
unsigned contract and frontier proposal, preserves signed historical bytes, records parent and
admitted evidence digests, and carries forward the justified lineage and depth. Original
prerequisite and lifecycle constraints remain in force; replanning does not reset the depth
bound or extend an expired premise. The proposed pair requires registration/admission before
external use. A receipt-compatible activation can exist without supported growth entry or an
affordable continuation. Attribution remains undetermined in every case.

## Research relationship and next step

See [the mapping](growth-research-mapping.md) to Takahashi, K. (2026), *Observing and
Accelerating Collective Capability Growth*, Zenodo,
[doi:10.5281/zenodo.22604358](https://doi.org/10.5281/zenodo.22604358).
Finite endogenous activation represents capability reproduction within a declared model;
the paper does not empirically validate this implementation or its executable refinement.

The next major formal extension is fixed-parameter, set-valued model uncertainty with
observation-driven model-set contraction and prior-free value-of-information planning.
The current rectangular adversary can choose a different applicable model at each step.
A future `Theta_t` would retain the models compatible with the full observed history and
contract that set after observations. That extension is not implemented in 0.7.0.
