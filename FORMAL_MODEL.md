# CPCF v0.6 Formal Model

The equations below define the target operational semantics. They are not physical laws and do not
imply that every bounded diagnostic is implemented. Current conformance gaps are listed in
`docs/release-readiness.md`.

Let an immutable snapshot be

```text
S = (G, P, τ, U, A, N, m₀, B, C, I, V, E, Q, T)
```

where `G` is the generation, `P` the trust policy, `τ` trusted time, `U` the unit registry, `A` live
typed attestations, `N` the rational stoichiometric matrix, `m₀` receipt-backed initial marking, `B`
validated boundary supplies, `C` catalyst clauses, `I` inhibitors, `V` verifier stages, `E` the
independence/exposure state, `Q` coordination, and `T` trial bindings.

The analysis-basis digest covers every immutable input but excludes witness digests. A witness binds
that basis digest, so the object graph is acyclic while cross-snapshot witness composition remains
invalid. The complete snapshot digest additionally covers witness digests.

## Exact resource trajectory

For rational action counts `u[k]`, boundary quantities `s[k]`, and duration `Δt`:

```text
m[k+1] = m[k] + N u[k] + B s[k]
0 ≤ s_j[k] ≤ supply_upper_j · Δt
m_i[k] ≥ protected_floor_i for every protected i and every prefix k
```

Quantities, stoichiometry, action counts, flux, boundary rates, and time use exact dimension vectors.
Unit scales are positive rational multipliers; affine conversions are invalid.

## Formation and catalysis

A transformation enters formation layer `k` only when every input, required evidence, authority, and
one complete catalyst clause is available before `k`, and no inhibitor is available. Outputs become
available after the layer. Consequently, a catalyst produced only by its own dependent transformation
cannot establish formation or generative RAF membership.

An exact organization is a target-bound transformation subset `R` with strictly positive rational
flux `v` satisfying

```text
N_R v ≥ 0
```

for every internally maintained coordinate and producing every target. This is a stoichiometric
organization witness, not a kinetic, energetic, or thermodynamic proof.

## Independence

Target effective independence is the number of components after unioning shared principal, key,
infrastructure, lineage, correlation, verifier, and pre-commit artifact-exposure relations. Missing a
signed completeness observation yields unknown. The current kernel unions principal, key,
infrastructure, lineage, correlation, and declared pre-commit domain exposures; verifier/shared-
artifact expansion and DSSE completeness recomputation remain open.

## Perturbation

Each conforming perturbation `p` constructs a new snapshot `p(S)` by removing, expiring, revoking, or
replacing declared inputs and evaluates `Audit(p(S))` with the baseline kernel. The current v0.6
implementation constructs fresh reduced snapshots for object removal and replacement witnesses;
expiry, key revocation, and value modification remain incomplete and therefore cannot establish full
perturbation conformance.

## Contingent control

An action has successors for `success`, `partial`, `failure`, and `timeout`. A policy is strong to
horizon `h` only when every successor preserves protected constraints and either reaches the declared
blocker condition or has a strong continuation at `h-1`. No fairness or eventual-success assumption
is introduced. The current planner searches this structure over abstract capability effects; it does
not yet recompute the full snapshot kernel per successor and is not a conformance proof. Pareto
comparison preserves resource, time, cost, quality, debt, verification, independence, cut exposure,
and evidence dimensions separately.

## Finite growth control

With the optional 0.7 frontier, the finite action domain is a predeclared `A_super` and the
state carries its active subset `A_t`, bounded depth and immutable activation lineage.
For a declared successor `s`, let `U(s,x)` be the targets whose bound rule prerequisites
hold in the post-ledger state. The only frontier update is `A_(t+1) = A_t union U(s,x)`;
it has no direct reward. New targets have producer depth plus one; duplicate targets
retain their first canonical lineage. Costs, debt, queues and physical time follow the
unchanged transition ledger. Future use still requires all lineage premises and lifecycles.

The existing finite AND–OR recursion, scalar comparator and lexicographic growth objective
apply to this enlarged finite state. All frontier facets are hashed and independently
reconstructed. Comparator restriction changes reachability through the same transition
function, never freezes the initial frontier. An activation witness establishes a use-after-
activation relation in the selected model policy; it is not marginal causal attribution.
See [complete semantics and counterexamples](docs/endogenous-capability-frontier.md).

The separate opt-in growth mode models a finite game with exact rational time, nonempty
applicable successors, and rectangular adversarial uncertainty. Each decision preserves
joint task/research service, verification, shared resources, queues, deadlines and evidence
premises at every prefix. Its lexicographic objective minimizes worst-case entry time with
a funded growth continuation, then maximizes terminal minimum normalized task/research
attainment, then orders typed costs, typed debt, time and canonical identifiers.

The checker recomputes the submitted tree and reoptimized finite scalar comparator bounds.
Computational exhaustion is unknown, not nonexistence. Model-predicted states and clocks
never become observed attestations. See [the exact domain and equations](docs/growth-planning.md)
and [the paper-to-code mapping](docs/growth-research-mapping.md). These additions do not close
the repair planner's existing full-snapshot conformance gap or establish empirical acceleration.

## Fixed-parameter observation support and finite composition

In the opt-in domain, `B_t = {(theta, x)}` retains every compatible fixed parameter
and full ledger state. The update retains `(theta, x_next)` exactly when
`x_next` is an applicable same-theta successor and the visible symbol belongs to
its declared kernel. No model switches, coordinatewise stitching or hidden-state
policy choices are allowed. Action and entry decisions must work in all members.

Search retains complete terminal supports across observation-tree alternatives;
it evaluates the original path-dependent lexicographic objective only after
combining every adverse branch. A certificate checks one finite domain, not global
optimality or a universal program theorem. Typed compositions unfold to the same
primitive transition relation, horizon and costs. New names do not add elementary
reachability. See [the finite reference domain](docs/epistemic-growth-control.md)
and [typed unfolding](docs/checked-capability-composition.md).
