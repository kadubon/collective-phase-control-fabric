# Growth planning: theory-to-implementation mapping

Reference: K. Takahashi (2026), *Observing and Accelerating Collective Capability Growth:
Joint Service, Evidence Costs, and Executable Continuation*,
[Zenodo record 22604358](https://doi.org/10.5281/zenodo.22604358), published September 7, 2026.

The public TeX source was retrieved and read on September 7, 2026. Its SHA-256 is
`35ce99f1885fb0fbb75365ac4e973b8c61cefc6e1b1376398d62e8074a7fc97e`.
The implementation follows the finite model requested for CPCF; it does not substitute an earlier
working title or a spectral-radius argument for the published text. The source is a CC-BY-4.0
preprint; this repository's implementation and original documentation remain Apache-2.0.

| Paper location | CPCF P0 correspondence | Scope limit |
| --- | --- | --- |
| Section 1, joint service and minimum attainment | Typed task/research targets, quality/coverage/service floors, simultaneous shared-resource reservation, minimum normalized attainment | Service validity and the correctness of the concrete refinement are external premises |
| Section 2, reoptimized comparison class | Same checkpoint, information, resources and endpoint; interaction-restricted actions are reoptimized; permitted single-process refinements remain candidates | P0 implements the explicitly labelled worst-case scalar comparison, not the paper's expected-vector separation or reliable-probability comparison |
| Section 2, block growth and three-valued observation | Registered windows; end lower versus start upper; temporary contraction above every domain floor; empty models are inconsistent | No independent statistical coverage or causal certification; labels are relative to the supplied finite model |
| Section 3, calibration bias and drift | Externally supplied allowances widen intervals, evaluator/coverage/protocol digests are pinned, unprotected selection is rejected | No confidence-sequence estimator, KL recognition bound, or power calculation is implemented |
| Section 4, joint resource and obligation ledgers | Charges, verification/repair workloads, unfinished debt, joint productive/evidence activities and external cost boundaries | Supporting prices, time-varying dual bounds and information/debt theorems are not implemented or inferred |
| Section 5, finite control and executable continuation | Bounded AND–OR reference search, lexicographic entry/attainment/cost objective, all-branch continuation witnesses, independent tree checker and evidence-driven re-evaluation | Fully observed successor symbols, rectangular adversary, fixed finite catalogue; terminal time is each entry plus the registered continuation horizon |
| Section 6, synthetic verification/communication/evidence tradeoffs | Separate deterministic CPCF examples and negative controls under one budget | CPCF's small catalogue is not a reproduction of the paper's 40 stochastic recipes or evidence of a deployed system |
| Queue appendix | Offered service differs from completion; burst, work deadline and typed repair backlog constraints remain explicit | No mean-load, queue-stability, causal or indefinite-growth claim |

## P0.7: endogenous finite frontier

The Section 5 finite state can additionally contain the active subset of a predeclared finite
super-catalogue. CPCF 0.7.0 implements this bounded model extension with exact successor-bound
activation, lineage, independent checking and frontier-aware comparator reoptimization. It keeps
the original objective and all resource/evidence obligations. The
[frontier guide](endogenous-capability-frontier.md) maps eight synthetic examples and counterexamples.
This models finite endogenous capability reproduction; it does not demonstrate real-world
capability creation or experimentally validate the paper. No external empirical acceleration
experiment was performed.

The next formal extension is fixed-parameter, set-valued model uncertainty with observation-driven
model-set contraction and prior-free value-of-information planning. It is not implemented in 0.7.0;
the current adversary remains rectangular and can choose another applicable model at each step.

The paper's mathematical sufficient conditions require coverage and executable refinement.
CPCF's signatures establish bounded record provenance and role separation; they cannot supply
those scientific premises. The operational profile, external-runner boundary and existing audit
findings retain their independent status. See [the implementation guide](growth-planning.md).

## 1.0 development: M8, M9 and M10

The fixed-parameter extension described above as future work for 0.7.0 is now the
subject of the opt-in [epistemic implementation](epistemic-growth-control.md).
It retains correlated finite model/ledger supports and visible-history policies.
[Information value](information-value.md) separates matched paid-channel
coarsening from removal of optional sensing. [Composition](checked-capability-composition.md)
checks bounded typed primitive workflows and charged catalogue proposals.
These are finite software refinements with their own explicit assumptions, not a
proof of the paper's broader sufficient conditions, empirical validation, or
an implementation of probabilistic calibration or causal identification.
The [verification matrix](roadmap-to-1.0.md) records actual release qualification.
