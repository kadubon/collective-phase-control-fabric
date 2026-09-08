# Endogenous frontier validation record

Scope: package 0.7.0, protocol `cpcf.io/v0.6`, Beta research release. This record describes
software checks and synthetic finite examples, not external empirical validation.

## Implementation and compatibility

- Additive closed frontier, frontier-plan and frontier-assessment kinds preserve the preceding
  52 native schema digests and original no-frontier plan goldens.
- Finite super-catalogue bindings, exact outcome rules, sorted active state, bounded lineage and
  retained lifecycle/prerequisite checks are reconstructed in search, checking and replay.
- Reoptimized restricted comparators include alternative reachable activation paths; incomplete
  searches remain unknown. No count-based reward is introduced.
- Fresh evidence advancement reuses independent DSSE/quorum/trial/receipt checks and the existing
  registration quorum. Replanning preserves historical signed bytes, activation depth and premises.
- Eight [generated synthetic scenarios](examples/frontier-comparison.json) cover research,
  verifier investment/queue pressure, discovery failure, useless candidates, multi-step chains,
  zero-progress cycles, comparator alternatives and safe fallback without guaranteed growth.

## Regression and property families

`test_v6_growth_frontier.py` checks latent-use rejection, exact success/partial/failure/timeout,
unbound targets and digests, expiry/withdrawal, duplicate/no-cost self-activation, cycles,
depth and lineage tampering, rule resource/evidence conditions, immutable ledger obligations,
policy/state digests, permutation semantics, unreachable candidates, an independent sequence
oracle and search-budget exhaustion. Original 0.6.1 growth tests and full-plan goldens remain.

`test_v6_frontier_evidence_cli.py` uses explicitly synthetic independently signed fixtures for
fresh evidence reconstruction, missing quorum/capability/root rejection, ambiguous successors,
model advancement without growth/continuation, read-only replay, unsigned export and the complete
installed CLI path. These fixtures are not external experiments or operational receipts.

## Release measurements

Final full-suite, critical coverage, mutation, security, packaging and remote-CI measurements
are recorded after their required runs complete. In-progress checks do not count as passed.
The unchanged gates are full branch-enabled coverage 90%, critical aggregate and each subsystem
95%, and mutation 85%. Every release measurement must identify the validated release tree.

No external empirical acceleration experiment was performed. The next formal extension is
fixed-parameter, set-valued uncertainty with observation-driven model-set contraction and
prior-free value-of-information planning; no part of it is implemented in this release.
