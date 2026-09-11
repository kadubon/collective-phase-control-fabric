# CPCF 1.0.0 qualification record

**In progress; not release approval or publication evidence.** The implementation
is being prepared on `codex/cpcf-1.0-epistemic-growth`. The source baseline is the
released 0.7.0 commit recorded in the [requirement matrix](roadmap-to-1.0.md).
Historical 0.7.0 measurements are not reused as 1.0.0 evidence.

| Area | Verification and current status |
| --- | --- |
| Fixed-model information states | Correlation, model persistence, ambiguity, visible-history decisions, kernel tampering and finite limit tests added; final source qualification pending |
| Independent optimization oracle | Separate exhaustive observation-tree oracle agrees on tiny examples; same-symbol switching adversary example has entry 3 versus fixed-model entry 2 |
| Information comparisons | Matched paid/masked versus no-probe cases, uninformative, irrelevant and overpriced controls; final qualification pending |
| Composition and revisions | Fresh primitive unfolding, typed interfaces, costs, parent work reservations, preserved histories and tamper tests; coverage qualification pending |
| Evidence | Synthetic independently signed original admission tests, fresh root checks, exact stdout mapping and unsigned replan; no operational evidence |
| Backward compatibility | Old signed-fixture scope and expected golden hashes preserved; 55 released schema identities retained |
| Public API and installed base wheel | Local 1.0.0 wheel installed outside checkout; all five import versions/origins, pip check and six network-disabled scenarios passed; public-index publication verification pending |
| Coverage | Local full, CI-selected and release-selected critical suites passed the unchanged aggregate and all 17 per-subsystem gates; metrics below; hosted matrix pending |
| Mutation | New critical modules and tests selected; complete expanded catalogue, all five shards and 85% aggregate gate pending |
| Security and publication hygiene | Local Ruff, strict mypy (131 sources), Bandit, OSV audit, generated references, 225 schemas, 9 fixtures, source/history/archive hygiene, Gitleaks, build and Twine passed; final staged/push and hosted security checks pending |
| GitHub, Wiki and PyPI | Source PR, normal required review/checks, Wiki push and publication verification pending |

## Local source qualification

Core source commit: `13383d1` on the feature branch. Windows Python 3.14.6,
frozen dependencies, branch-enabled coverage and all five import packages:

| Suite | Tests | Statements | Branch destinations | Combined |
| --- | --- | --- | --- | --- |
| Full suite | 928 passed, 3 skipped | 17,774 / 19,023 (93.43%) | 6,164 / 7,156 (86.14%) | 91.44% |
| CI critical selection | 613 passed | 8,218 / 8,486 (96.84%) | 2,584 / 2,788 (92.68%) | 95.81% |
| Release critical selection | 632 passed | 8,246 / 8,486 (97.17%) | 2,593 / 2,788 (93.01%) | 96.14% |

The three local skips are the existing PostgreSQL tests without configured
application/owner URLs. Required hosted PostgreSQL integration remains pending.
All 17 critical subsystem combined percentages passed 95%; the newly included
epistemic control, checked composition and growth CLI groups achieved 96.52%,
96.72% and 97.77%, respectively. Their final hosted checks remain required.

All original growth/frontier examples and nine generated epistemic/composition
records matched their checked-in outputs. The external-directory local-wheel
check covers preparation, frontier chain, fixed-model probe, information value,
composition and the integrated proposal/replanning workflow, with sockets disabled.
This is not installation of 1.0.0 from the public index and is not publication evidence.

An earlier pair of local coverage runs was interrupted after an environment setup
failure. Those runs were discarded; the values above come from fresh runs after
restoring the frozen environment, with separate coverage databases.

Coverage reports must distinguish statement coverage (covered executable lines /
all executable lines), branch coverage (covered branch destinations / all branch
destinations), and the repository's combined line/branch percentage. The combined
percentage is not labeled branch-only coverage. Incomplete/failed mutation shards
cannot qualify an aggregate. Search operation counters and declared model resource
allowances are separate from measured test or solver wall-clock time.

The [generated finite examples](examples/epistemic-comparison.json) record model
policies, input digests, checks and negative controls. They are synthetic software
outputs. No external empirical acceleration experiment was performed. These
mechanisms do not establish real-world capability reproduction, collective
intelligence, AGI, ASI, causal acceleration, indefinite growth or operational
assurance. The publication classifier remains Beta.
