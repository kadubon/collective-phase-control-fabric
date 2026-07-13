# CPCF v0.6 Local Release-Gate Report

This report records local evidence collected on 2026-07-13. It is not a release, service-level
commitment, external experiment, production-readiness claim, or measured-acceleration claim.

## Verdict

The source is eligible for public review only after the staged-content hygiene process succeeds.
It is not eligible for a stable tag, GitHub Release, PyPI upload, or production-ready label.

The native result is a thirteen-dimensional operational organization profile. It does not infer
intelligence, causal acceleration, a physical phase, entropy production, thermodynamic efficiency,
statistical validity, or general controllability.

## Passing local evidence

- Environment: `uv 0.11.28` with CPython 3.14.6 on Windows.
- Frozen universal lock: base plus all extras, development, and security groups synchronize.
- Regression suite: 291 tests passed; two PostgreSQL integration tests skipped because disposable
  owner/application database URLs were not configured locally.
- Ruff formatting and lint: passed.
- Strict mypy: passed across the core and all four optional import-package source trees.
- Schema meta-validation: 200 schemas passed across v0.1–v0.6; the native v0.6 registry contains 40
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

## Failing or unavailable release gates

- Overall branch coverage is 81%, below the required 90%.
- Focused v0.6 critical-subsystem branch coverage is 72.20%, below the required 95%.
- The required 85% mutation score has not been established; native Windows Mutmut execution is not
  supported, so the pinned Linux CI gate is authoritative.
- Gitleaks, Semgrep, CodeQL, and Trivy are configured as immutable-action CI gates but have not run
  against a public commit.
- PostgreSQL RLS, serializable generation commits, object-store interruption, OIDC/KMS rotation,
  mTLS runner leasing, and complete crash injection require live integration evidence.
- The 100-tenant, 10,000-workspace, 100-concurrent-audit load profile has not run.
- API/worker/database/object-store/KMS/OIDC chaos tests, backup restoration, and the sustained 99.9%
  availability soak are absent.
- Independent threat-model review and penetration testing are absent.
- Complete authoritative DSSE/quorum recomputation, full-state planner successors, full
  perturbation classes, live onboarding aggregation, and runner transport remain implementation
  blockers listed in `audit/findings-v0.6.json`.

## Publication controls

The trusted-publishing workflow is `.github/workflows/workflow.yml`. Manual dispatch verifies only.
The PyPI job requires a non-prerelease GitHub Release, exact tag/metadata agreement, the protected
`pypi` environment, and `PYPI_PUBLISH_ENABLED=true`.

`PYPI_PUBLISH_ENABLED` must remain false. The PyPI pending publisher currently names environment
“Any”; it must be changed to `pypi`, and an independent GitHub reviewer who cannot self-approve must
be configured before publication can be enabled.
