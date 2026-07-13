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
