# Prior-free information value

`cpcf growth information-value` uses the fixed-model observation planner to
reoptimize three policy classes. No model probability, entropy objective or
universal intelligence score is introduced.

| Class | Physical optional probe | Visible probe channel |
| --- | --- | --- |
| Full | Available and paid | Declared symbols |
| Information-blind | Same available and paid action | Explicit deterministic coarsening |
| Without sensing | Specified optional actions excluded | Remaining declared symbols |

Information-use value compares full and information-blind policies with matched
physics, resources and costs. Net sensing benefit compares full and without-sensing
policies and includes avoided measurement cost, time and downstream effects.
These are different estimands. Timing, resources and debug data cannot leak the
masked symbol: this domain excludes them from public observation channels.

The output gives full-minus-comparator differences separately for entry time,
terminal normalized attainment, each typed cost, each repair debt and duration.
Negative entry-time difference means earlier modeled entry; positive attainment
difference means greater guaranteed terminal attainment. The lexicographic order
is retained rather than converted into a scalar. Absent entry is categorical
(`full-only`, `comparator-only`, `neither`), never a fabricated numerical infinity.
Incomplete search in either class makes the comparison unknown.

A free refinement can be ignored and therefore cannot worsen the exact optimum
when every physical transition, available action, resource and cost remains
matched. This result does not apply to adding a costly probe. Discrimination
without a useful downstream decision can have zero decision value. Measurement
allowances are declared model premises, not measured solver or laboratory costs.

```sh
cpcf growth example --scenario epistemic-information --json
```

The example's probe enables model-contingent research. Its result is conditional
on its finite kernel and ledger, not statistical or causal evidence. See
[epistemic semantics](epistemic-growth-control.md) for the observation boundary.
