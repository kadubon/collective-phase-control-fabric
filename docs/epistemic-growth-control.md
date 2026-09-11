# Fixed-model epistemic growth control

The opt-in `epistemic-contract` sidecar defines a finite observation game over an
existing growth contract and optional capability frontier. Omitting it preserves
the released rectangular-adversarial planner and its successor-ID replay format.
All documents retain `cpcf.io/v0.6` protocol identity.

## Information state and observation boundary

The state is a canonical finite support `B = {(theta, x)}`. A parameter `theta`
is fixed for the episode. Within that parameter, every applicable successor is
adversarial. The full ledger `x` retains resources, elapsed physical model time,
queues, obligations, reservations, checkpoints, used actions, activation lineage,
and entry commitments. Several states for one parameter remain distinct.

For action `a` and visible symbol `o`, retain exactly those successors with the
same parameter whose declared kernel includes `o`. The kernel explicitly covers
every declared model/action/successor tuple. Overlapping observations represent
set-valued ambiguity; they do not imply a probability or confidence level.
An impossible observation is model mismatch. It never selects a replacement model.

This reference domain exposes **only declared observation symbols**. Physical
time and resource quantities affect feasibility but are not additional public
observations. Hidden outcome IDs, actual simulator parameters, receipt debug
fields and privileged state dumps cannot select policy branches. Applications
requiring public timing or availability signals must declare them in a new kernel.

An action must be applicable in every compatible state. The union of enabled
frontier actions is insufficient. A common entry decision and a common
observation-based funded continuation must work across the entire support.
Eliminating a hypothesis can reveal that an existing action is usable; it creates
no physical capability, admitted document or execution permission.

## Exact search and checking

Search enumerates observation trees and retains their complete terminal supports.
It does not prune a policy by its immediate effect. Memoization includes the full
support (including entry checkpoints and primitive count) and remaining depth;
future primitive feasibility and all terminal objective coordinates depend on
these fields. Alternative terminal supports are retained until complete policies
are compared, avoiding an unjustified scalar Bellman decomposition.

The objective remains earliest worst-case growth entry with funded continuation,
then maximum guaranteed terminal minimum task/research attainment, then typed
costs, repair debt, time and canonical tie-breaking. Restricted comparators are
reoptimized under the same observation semantics. Replanning starts comparators
at the same observed checkpoint and resources.

The independent checker reconstructs every observation partition and ledger
prefix. Its comparator reference induction does not invoke policy enumeration.
It checks feasibility and objective values, **not global optimality**. A valid
incumbent remains distinct from a complete search. Support, history, expansion,
depth and witness bounds produce unknown/incomplete results when exhausted.
The tiny test oracle independently enumerates complete observation trees without
the planner's memoization or selection functions.

## Evidence and replay

Offline replay consumes action/observation history and writes no evidence.
`epistemic-observation` binds the sidecar and original `growth-observation`.
Reassessment reruns original DSSE/quorum, trial, source, receipt, clock and
lifecycle admission. The registered `receipt-stdout-symbol-v1` mapping reads
`epistemic_contract_digest` and `observation` from receipt-covered stdout JSON.
Other JSON fields are not controller inputs. Support reconstruction retains all
compatible states rather than selecting a favorable measured branch.

Replanning requires fresh validation; an earlier assessment is not authority.
Original signed bytes remain unchanged. Proposed plans remain unsigned and need
registration before external use. A signature authenticates the observation
record, not the scientific validity of its model-elimination rule.

## Running the finite examples

```sh
cpcf growth example --scenario epistemic-probe --json
cpcf growth example --scenario epistemic-ambiguous --json
cpcf growth example --scenario epistemic-verifier --json
cpcf growth example --scenario epistemic-integrated --json
cpcf growth example --scenario epistemic-budget --json
cpcf growth example --scenario epistemic-uninformative --json
```

The probe example selects `prepare`, then `reuse` after red or `reuse-beta` after
blue. The integrated example supplies an explicitly synthetic red symbol, forms
a checked workflow, proposes a catalogue revision, and checks its replanned
continuation. These are finite model demonstrations, not external experiments.

The budget control permits only one support pair and reports unknown rather than
discarding the second parameter. The uninformative control coarsens the probe to
one shared symbol. [Generated scenario records](examples/epistemic-comparison.json)
are reproduced with `python scripts/run_epistemic_examples.py --check`.

See [information value](information-value.md),
[checked composition](checked-capability-composition.md), and
[public API](public-api.md). No external empirical acceleration experiment was
performed. This mechanism does not establish real-world collective intelligence,
capability reproduction, AGI, ASI, causal acceleration or indefinite growth.
