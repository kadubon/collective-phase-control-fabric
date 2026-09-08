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

Exact-boundary regressions also cover inclusive minimums, subsecond/scaled physical time,
ancestor prerequisites, distinct rule admission requirements, strict comparator equality and
the exact proposal pair bound to a returned continuation witness. See audit finding V6-038.

## Local candidate measurements

The following local results bind implementation commit
`3ce607a250317337c65252d3e791e4088f56f231` (tree
`55859c815f06a8635878235b78cc72439a74a671`). All 517 allowlisted mutation inputs were
hash-compared with that committed working tree before the final documentation-only update.
These results include the V6-038 correction and additional mutation-driven regressions.
Windows checks use Python 3.14.6 and the frozen lock; mutation
uses a fresh native Linux checkout of the same inputs and Python 3.14.6.

| Check | Local result |
| --- | --- |
| Full suite with branch measurement | 828 passed, 3 skipped; 91.13% combined statement/branch coverage |
| Focused critical suite | 538 passed; 95.60% combined statement/branch coverage |
| Critical subsystem gates | All 14 pass the unchanged 95% floor |
| Endogenous-frontier critical group | 97.83% combined; activation kernel 100% statements and branches |
| Growth-planning critical group | 97.86% combined |
| Ruff formatting/lint and strict mypy | Passed; 179 formatted files checked, 116 typed files |
| Bandit / OSV pip-audit | No issues / no known vulnerabilities reported |
| Schema / fixture / generated references | 215 schemas, 9 fixtures, references match runtime registries |
| Executable examples | All 5 original and 8 frontier scenarios reproduce their checked-in results |
| Source / staged / history / content hygiene | Passed, including Gitleaks with no detected secrets |
| Distributions | One 0.7.0 wheel and sdist; metadata/tag, Twine and archive hygiene passed |
| Fresh installed base wheel | Five imports report 0.7.0; pip check, self-check, preparation and depth-two frontier pass |
| Mutation | 87.50% (10,749/12,284); no incomplete mutants; 1,530 survived, 4 timeout, 0 segfault, 1 untested; unchanged 85% gate passed |
| New frontier mutation scope | Activation kernel 733/764 (95.94%); fresh evidence advancement 426/461 (92.41%); combined 1,159/1,225 (94.61%) |

The three local skips are the existing PostgreSQL tests whose disposable database URLs were
not configured. The required remote PostgreSQL job supplies that service; local skips do not
satisfy that job.

The repository's coverage gates use coverage.py's combined statement/branch percentage with
branch measurement enabled: full 90%, critical aggregate and each subsystem 95%. For clarity,
branch-only fractions are 5,934/6,908 (85.90%) in the full suite and 2,354/2,540 (92.68%) in the
focused suite; those are not the gate percentages. The mutation floor remains 85%, counting
timeouts and untested mutants as failures. No threshold or failure accounting is weakened.

Required remote CI and release workflow runs must bind their own exact commit. These local
results do not assert a successful merge, publication, external service experiment or public
PyPI installation. The release procedure requires those later outcomes to be verified separately.

CLI reference generation also checks portable empty-remainder parsing. Python 3.12.3 marks
this optional positional argument as internally required, unlike newer interpreters; the
generator now documents the actual accepted argument semantics. The seven release-surface
regressions and generated-reference check pass on Linux Python 3.12.3 and Windows Python 3.14.6.
The generated documents, CLI behavior, mutation-target modules and selected mutation tests
are unchanged by this generator correction.

The first complete-scope hosted mutation attempt reached 10,627/12,284 evaluated mutants
before the six-hour job limit cancelled it; this is an incomplete run, not a passing result.
CI and release therefore use five disjoint shards with complete catalogue reconstruction
and the same 85% gate. The reviewed catalogue fingerprint binds all 12,284 names from the
complete local run above. Portable negative regressions reject missing, changed, overlapping,
unknown and unfinished results; a native Mutmut 3.6.0 oracle confirms that a 12-mutant
synthetic catalogue has exactly the same complete status map before and after five-way
partitioning. This changes execution scheduling, not CPCF mutation targets or test selection.

After the scheduling correction, the full local suite passes 853 tests with the same three
optional PostgreSQL skips and 91.13% combined coverage. The 25 new shard regressions pass;
the shard/release-surface subset also passes on Linux Python 3.12.3. Ruff checks 182 files and
strict mypy checks 118 files. Core/frontier source and the selected mutation tests still match
the complete local mutation run above; remote runs must verify the final workflow and commit.

No external empirical acceleration experiment was performed. The next formal extension is
fixed-parameter, set-valued uncertainty with observation-driven model-set contraction and
prior-free value-of-information planning; no part of it is implemented in this release.
