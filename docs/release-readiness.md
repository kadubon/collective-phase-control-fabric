# CPCF v0.6 Local Release-Gate Report

This report records local evidence collected on 2026-07-13. It is not a release, service-level
commitment, external experiment, deployment-assurance claim, or measured-acceleration claim.

## Verdict

The source is eligible for Beta OSS package publication after the staged-content hygiene and
automated release gates succeed. Package publication is distinct from operational assurance; the
external evidence required for the latter is unavailable.

The native result is a thirteen-dimensional operational organization profile. It does not infer
intelligence, causal acceleration, a physical phase, entropy production, thermodynamic efficiency,
statistical validity, or general controllability.

## Passing local evidence

- Environment: `uv 0.11.28` with CPython 3.14.6 on Windows.
- Frozen universal lock: base plus all extras, development, and security groups synchronize.
- Regression suite: 547 tests passed; three integration tests skipped because disposable
  PostgreSQL and object-store services were not configured locally.
- Full branch-enabled coverage is 90.46 percent. The focused native assurance run is 95.38 percent,
  and the fail-closed per-group checker reports every critical subsystem at or above 95 percent;
  it does not permit a stronger group to mask a weaker group.
- Ruff formatting and lint: passed.
- Strict mypy: passed across the core and all four optional import-package source trees.
- Schema meta-validation: 208 schemas passed across v0.1–v0.6; the native v0.6 registry contains 48
  closed kinds.
- Fixture consistency: nine compatibility fixtures passed.
- Runtime-generated CLI, OpenAPI, error, and agent references match the checked-in documents.
- Bandit: no issues; two line-scoped checks are disabled at documented legacy read-only boundaries.
- Dependency audit: the initial scan detected vulnerable Click and pytest versions. The lock was
  updated to Click 8.4.2 and pytest 9.1.1; a subsequent OSV-backed `pip-audit` scan reported no known
  vulnerabilities in the synchronized local environment.
- Packaging: exactly one wheel and one source distribution are produced for
  `collective-phase-control-fabric`; Twine metadata validation passes.
- Reproducibility: two builds with the same `SOURCE_DATE_EPOCH` produced identical SHA-256 hashes.
- Installed base-wheel conformance: offline explanation, self-check, schema inspection, all five
  import packages, PEP 561 markers, and exact missing-extra guidance passed in isolated environments.
- Publication hygiene: source allowlist and rebuilt wheel/sdist scans passed without printing
  matched values. Generated coverage, local paths, caches, databases, credentials, and build output
  are excluded.
- CI and release mutation jobs retain the names and statuses of evaluated mutants for 14 days as a
  non-distribution diagnostic artifact, so a failed score can be corrected without weakening the
  gate or repeating a full run merely to recover the survivor list.

## Failing or unavailable release gates

- The final tree passes the configured combined branch-enabled thresholds locally. The native-Linux
  mutation job and platform matrix remain authoritative; results from an earlier stacked branch do
  not establish the final commit's mutation or cross-platform status.
- An exact Linux ext4 reproduction of the parent commit reported 83.64 percent across 7,617
  mutants and exposed an overlapping repair-prefix defect. Exact namespace tests killed 151 of 159
  repair-routing mutants after the correction. The parent native-Linux PR job then passed at 85.37
  percent across 7,623 mutants. The child PR must repeat this gate for its final commit.
- The initial public commit passed Gitleaks, Semgrep, CodeQL, and Trivy. These immutable-action jobs
  remain required on protected changes and do not replace an independent penetration test.
- PostgreSQL RLS, serializable generation commits, object-store interruption, OIDC/KMS rotation,
  mTLS runner leasing, and complete crash injection require live integration evidence.
- The 100-tenant, 10,000-workspace, 100-concurrent-audit in-memory reference profile passed. It is
  not PostgreSQL, object-store, Kubernetes, availability, or production-latency evidence.
- API/worker/database/object-store/KMS/OIDC chaos tests, backup restoration, and the sustained 99.9%
  availability soak are absent.
- Independent threat-model review and penetration testing are absent.
- Complete authoritative DSSE/quorum recomputation, full-state planner successors, full
  perturbation classes, live onboarding aggregation, and runner transport remain implementation
  blockers listed in `audit/findings-v0.6.json`.

## Publication controls

The trusted-publishing workflow is `.github/workflows/workflow.yml`. Manual dispatch verifies only.
The PyPI job requires a non-prerelease GitHub Release, exact tag/metadata agreement, the protected
`pypi` environment, and `PYPI_PUBLISH_ENABLED=true`. The 0.6 workflow explicitly classifies the
artifact as a Beta package and reports missing external operational evidence without treating that
evidence as satisfied.

The pending publisher claims are project
`collective-phase-control-fabric`, repository `kadubon/collective-phase-control-fabric`, workflow
`workflow.yml`, and environment `pypi`. Reviewer `kadubon` is configured with
`prevent_self_review=false`; this is explicitly self-approval and is not independent release
review. Independent external gates remain mandatory for any later operational-assurance decision.
