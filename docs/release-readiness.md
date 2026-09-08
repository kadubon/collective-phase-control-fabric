# CPCF 0.7.0 release readiness

This is the Beta package release for Bounded Endogenous Capability Frontier Expansion.
Its local, CI and publication results must belong to the exact release commit. Historical
0.6.1 results remain in the [0.6.1 release tree](https://github.com/kadubon/collective-phase-control-fabric/blob/v0.6.1/docs/release-readiness.md).

## Required verification

The release keeps the frozen lock, full branch-enabled coverage floor of 90%, aggregate and
per-critical-subsystem floor of 95%, and mutation floor of 85%. The new endogenous-frontier
critical group covers model activation and fresh evidence advancement. The existing growth
group retains search, transition accounting, independent checking and observation reassessment.
CI/release test selections and mutation sources include the new code and tests.

Mutation runs use five disjoint shards to fit hosted job time limits. Each produces the
entire generated status catalogue, leaving other shards' entries unchecked. The mandatory
aggregate job requires all shard jobs to succeed, checks their catalogue identities against
`audit/mutation-catalogue-v0.7.json`, rejects omitted, duplicated or incomplete assignments,
and applies the same 85% score to every unique mutant. A failed or skipped shard cannot turn
the aggregate gate into a successful skipped job. See [release procedures](release.md).

Required gates include formatting, lint, strict types across core/packages/scripts, full and
focused tests, schema/fixture/reference checks, old and new executable examples, Bandit,
OSV pip-audit, source/staged/history/content/archive publication hygiene, package metadata,
Twine, and clean installed-wheel CLI checks. Remote checks additionally include the protected
platform matrix, PostgreSQL integration and security/image jobs. No threshold is reduced.

The [frontier validation record](frontier-validation.md) records implementation scope, test
families and final measurements. The original [growth validation record](growth-validation.md)
describes the 0.6.1 work and is not new release evidence.

## Publication and review

Normal branch policy applies: required checks, current-head review, linear history and resolved
conversations. The Wiki must be committed and pushed before release. The exact merged main
commit must expose package version 0.7.0; `v0.7.0` and PyPI 0.7.0 must be unused beforehand.

The existing release workflow uses OIDC trusted publishing, the protected `pypi` environment
and `PYPI_PUBLISH_ENABLED=true`. A verification-only workflow dispatch does not publish.
The package remains `Development Status :: 4 - Beta`; absent operational evidence is reported
as unavailable under the existing Beta publication class. Publication is complete only after
the exact release run succeeds, release assets/provenance are verified, and a fresh public-index
installation of all five import packages passes version, dependency and CLI checks.

## Scientific and operational limits

No external empirical acceleration experiment was performed. The endogenous capability frontier
is a finite model and software-control mechanism. It does not establish real-world capability
reproduction, collective intelligence, AGI, ASI, causal acceleration or indefinite growth.
Model clocks are not attestations, model enablement is not admission, and admission is not
external execution authorization.

External model refinement, measurement constructs/coverage, statistical or causal validity,
production availability, intended-deployment restore, sustained soak, independent threat review,
penetration testing and live provider/runner containment evidence remain external obligations.
Existing partial audit findings remain partial. No receipts, trials or operational-assurance
records are fabricated for package publication. See [release procedures](release.md) and the
[frontier specification](endogenous-capability-frontier.md).
