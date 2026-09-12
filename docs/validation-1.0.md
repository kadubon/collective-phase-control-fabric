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
| Mutation | Complete generated inventory of 17,581 names reviewed; all 30 configured modules and required control methods included; full execution, all five shards and 85% aggregate gate pending |
| Security and publication hygiene | Local Ruff, strict mypy (133 sources), Bandit, OSV audit, generated references, 225 schemas, 9 fixtures, source/history/archive hygiene, Gitleaks, build and Twine passed; final staged/push and hosted security checks pending |
| GitHub, Wiki and PyPI | Feature branch and candidate Wiki pushed; PR, required checks, owner-authorized merge and publication verification pending; the specific review exception is recorded in the requirement matrix |

## Local source qualification

Core source commit: `5624681` on the feature branch. Windows Python 3.14.6,
frozen dependencies, branch-enabled coverage and all five import packages:

These fresh runs include the control-class mutation-scope correction. The later
isolated-layout preparation has two additional passing regression tests; the full
pre-PR rerun at `dec0a9c` passed with those tests. Mutation execution remains pending.

| Suite | Tests | Statements | Branch destinations | Combined |
| --- | --- | --- | --- | --- |
| Full suite | 935 passed, 3 skipped | 17,772 / 19,021 (93.43%) | 6,164 / 7,156 (86.14%) | 91.44% |
| CI critical selection | 613 passed | 8,216 / 8,484 (96.84%) | 2,584 / 2,788 (92.68%) | 95.81% |
| Release critical selection | 632 passed | 8,244 / 8,484 (97.17%) | 2,593 / 2,788 (93.01%) | 96.14% |

The three local skips are the existing PostgreSQL tests without configured
application/owner URLs. Hosted PostgreSQL integration, all six platform jobs and
quality/security checks passed at `dec0a9c`; a changed head requires fresh checks.
All 17 critical subsystem combined percentages passed 95%; the newly included
epistemic control, checked composition and growth CLI groups achieved 96.51%,
96.72% and 97.77%, respectively. Their final hosted checks remain required.

All original growth/frontier examples and nine generated epistemic/composition
records matched their checked-in outputs. The external-directory local-wheel
check covers preparation, frontier chain, fixed-model probe, information value,
composition and the integrated proposal/replanning workflow, with sockets disabled.
This is not installation of 1.0.0 from the public index and is not publication evidence.

An earlier pair of local coverage runs was interrupted after an environment setup
failure. Those runs were discarded; the values above come from fresh runs after
restoring the frozen environment, with separate coverage databases.

The actual Wiki's nine candidate pages were pushed and verified at commit
`30733f9019bb22b2139a76ecd84fee7c5763609c`. Source links, page links, content,
secret scanning and archive hygiene were checked. The pages explicitly retain
candidate status; released labels remain pending actual publication verification.

The first mutation attempt was interrupted and not counted. Inspection of the
resumed catalogue found that decorated control classes and nested CLI imports
were silently excluded by the pinned tool. That catalogue was rejected. The
control classes now expose their methods to mutation. An isolated, hash-checked
single-source layout makes nested package mutation names agree with their import
names; copied package origins are checked. A separate catalogue-scope gate prevents this omission
from passing. The corrected complete native inventory is registered in
`audit/mutation-catalogue-v1.0.json` so local execution and PR CI can proceed in
parallel. That fingerprint is membership-only: a complete execution and passing
score are still required, without selecting a successful subset.

CI run `34668423252` failed when all five expanded mutation jobs reached the
300-minute limit; its aggregate correctly rejected the incomplete runs. The
five logical shards now each have four disjoint physical parts, with all 20
success dependencies and complete-catalogue validation. This scheduling repair
has no effect on test selection, mutation operators, timeouts or the score floor.
The independent native full run continues; neither run is reported as passed.

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
