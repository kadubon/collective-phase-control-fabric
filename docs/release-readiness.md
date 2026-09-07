# CPCF growth extension release-gate report

Local evidence was collected on 2026-09-08 (Japan Standard Time). This report concerns a
Beta research package. It is not operational assurance or evidence of measured acceleration.
The [growth validation record](growth-validation.md) lists the changed surfaces, commands,
synthetic comparison results and exactness limits. The previous report is retained in the
[v0.6.0 release tree](https://github.com/kadubon/collective-phase-control-fabric/blob/v0.6.0/docs/release-readiness.md).

## Local verification

- Frozen environment: uv 0.11.28 and CPython 3.14.6 on Windows; all extras and development/security
  groups synchronize without dependency changes to `uv.lock`.
- Full suite after the final functional changes: 615 passed and 3 skipped, with 90.95% branch
  coverage across all five import packages. Skips require disposable external integration services.
- Final focused critical suite, including five additional complete-growth golden checks:
  349 passed, 95.81% branch coverage. Every one of the 13 critical groups passes its separate 95%
  gate; growth is 97.68%, repair planning 97.05%, and parsing/schemas 95.93%.
- Ruff format/lint, strict mypy across core/packages/scripts, and Bandit pass. OSV-backed
  `pip-audit` reports no known vulnerabilities in the synchronized Python environment.
- All 212 schemas validate, including 52 native closed kinds; all 9 existing fixtures validate.
  Generated CLI, schema, agent and error references match runtime registries.
- All five deterministic growth comparisons reproduce. Independent sequence and contingent-policy
  oracles, prefix constraints, all outcome branches, receipt/registration weakening, physical
  clocks and stale-continuation regressions are included.
- The repository skill validates. Source-content hygiene, allowlisted Gitleaks content, Git-history
  Gitleaks, Wiki Gitleaks and staged-content/archive hygiene are required before each source push.
- Packaging produces one wheel and one source distribution; Twine checks and isolated base-wheel
  self-check/growth commands pass. Distribution version/tag/hash checks are repeated for release.

## Remote verification and publication

The final-commit GitHub CI, platform matrix, PostgreSQL service, mutation gate and image/security
jobs remain required; local successes do not substitute for their results. Native Linux mutation
is running with the expanded growth selection and the unchanged 85% threshold. Its result is
not yet claimed in this local record. Refer to the final commit's
[GitHub Actions runs](https://github.com/kadubon/collective-phase-control-fabric/actions).

The pre-existing scheduled image scan reported vulnerable Alpine OpenSSL and libuuid packages.
API/worker recipes now pin libcrypto3/libssl3 3.5.8-r0 and libuuid 2.42.3-r1 from the
[Alpine v3.24 package repository](https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/).
Image build/scanner results are verified separately from the Python dependency audit.

The trusted publisher requires a non-prerelease GitHub Release, matching package/tag version,
the protected `pypi` environment and `PYPI_PUBLISH_ENABLED=true`. The workflow reports absent
external operational evidence under its explicit Beta publication class. Environment reviewer
`kadubon` permits self-review; this authorizes package distribution, not independent review.
PyPI publication is established only after the actual release workflow and a clean installation
from the public index succeed. See [the release process](release.md).

## Unavailable external evidence and retained boundaries

The native result remains the thirteen-dimensional operational organization profile. Growth
output is a separate conditional finite-model result. CPCF does not certify consciousness,
collective superintelligence, a physical phase, thermodynamics, statistical validity, causality,
endogenous attribution or measured acceleration. Synthetic oracles and signed fixtures do not
close those scientific obligations.

Real action-model refinement, measurement construct/coverage validity, independently registered
trials, production availability, intended-deployment restore, a sustained soak, independent
threat review and penetration evidence remain unavailable. Live OIDC/KMS/S3/runner containment
and transport require separate integration evidence. The existing partial findings in
`audit/findings-v0.6.json` remain open; fresh admission in the new read-only path does not imply
complete conformance of every existing control-plane path. No adapter or deployment is executed
by this growth feature.
