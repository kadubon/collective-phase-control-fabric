# Checked finite capability composition

The compiler searches a finite typed grammar of primitive sequences and branches
on declared observation symbols. A generated workflow has a new content-bound
name, but all elementary effects come from immutable declared actions. Parallel
execution, general programs, recursion and unbounded loops are unsupported.

A `workflow-request` binds its model domain and visible history, eligible primitive
library, input/output schema types, target capacity lower bounds, maximum spent
resources and synthesis limits. Each library binding identifies the action,
capability, interface schemas and execution policy. Interface assumptions are
part of the checked request; checking does not certify arbitrary executable code.

Candidates contain observation-tree IR, constituent digests, primitive-step count,
domain binding and lifecycle intersection. The independent checker unfolds every
applicable outcome, checks every interior ledger prefix and typed handoff, and
verifies terminal postconditions and funded continuation. It does not trust a
candidate's claimed resource savings or capacity effects. Its certificate applies
only to the specified finite initial support and assumptions, not all future uses.

Construction, search, checking and transport are formation allowances; maintenance
and application are per-use allowances. The current certificate covers one
application at its bound checkpoint. All six are paid in the proposed ledger,
including a synthesis attempt that returns no candidate. Reuse at a different
checkpoint requires a new checked request and its costs. These exact allowances
are externally unvalidated model premises, separate from measured software runtime.

The existing primitive alternative is also optimized without formation charges.
`reuse_without_formation_preferred` compares that explicit different cost option
only after both searches complete. A workflow name itself earns no objective
credit. Flattened primitive transitions preserve physical time, queues, debt,
reservations and the full primitive horizon; one macro does not buy free steps.

## Catalogue proposals

`catalogue-propose` creates an unsigned copy-on-write `catalogue-revision` binding
the parent sidecar, request, candidate, fresh certificate and charged next sidecar.
Revision count, candidate count, declared synthesis work and primitive horizons
are bounded. The cumulative synthesis counter reserves each episode's maximum
enumeration expansions rather than trusting submitted actual-use counters.
Independent checking has its own bounded witness and transition checks.
`catalogue-replan --model-only` independently checks the composition
again against current objects. Its policy is represented by primitive transitions.
A freshly checked incumbent can survive incomplete search; that is not an optimum.

History is replayed from the immutable original contract with accumulated cost
events. Time, spent resources, debt and activation depth are not reset. Actual
admission uses the existing registration/quorum system. Primitive export emits an
operator-supplied proposed job requiring existing external runner authorization.
No composite name inherits permission to execute, signs itself or creates a lease.

```sh
cpcf growth example --scenario epistemic-composition --json
cpcf growth example --scenario epistemic-integrated --json
cpcf growth example --scenario epistemic-no-composition --json
cpcf growth example --scenario epistemic-rejected-composition --json
```

See the [public API](public-api.md) and [epistemic model](epistemic-growth-control.md).
Procedural reuse usually represents an already expressible primitive policy. It
does not demonstrate a new elementary discovery or empirical capability growth.
