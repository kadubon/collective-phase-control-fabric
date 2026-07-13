# CPCF v0.6 Final Pre-Release Audit

## Verdict

The repository now builds one installable distribution with a useful offline first-run path,
runtime-derived references, frozen `uv` resolution, and a fail-closed publication workflow. It is
appropriate for public source review after the staged-content hygiene gate passes.

It is not eligible for a stable tag, GitHub Release, PyPI upload, or production-ready label. Several
authority paths remain incomplete, and the required coverage, mutation, integration, load, chaos,
restore, soak, threat-model, and independent-penetration-test gates have not passed.

This audit lists known findings only. It does not assert that undiscovered defects are impossible.

## Closed publication and first-use findings

- The root now publishes exactly one distribution, `collective-phase-control-fabric`, containing all
  five import packages. No runtime dependency refers to an unpublished `cpcf-*` distribution.
- `agent explain`, `self-check`, schema inspection, and bundle verification work offline from the
  base wheel.
- The primary v0.6 documentation hierarchy and installed-wheel tutorial describe only commands that
  exist. CLI, OpenAPI, error, and agent references are runtime-derived and drift-checked.
- The source and built-artifact hygiene checker rejects local home paths, credential patterns,
  sensitive artifacts, generated output, oversized files, and content outside the explicit source
  manifest without printing matched values.
- Generated coverage, build directories, local databases, caches, key material, and SBOM output are
  excluded. The prior absolute Windows source paths were replaced with symbolic paths.
- The release workflow builds one wheel and one sdist in a non-OIDC job. PyPI upload is isolated,
  release-only, version-matched, protected by the `pypi` environment, and disabled unless
  `PYPI_PUBLISH_ENABLED=true`.
- The universal lock now resolves under Windows CPython 3.14.6. `pip-audit` was updated to 2.10.1;
  Semgrep remains a pinned external CI action because its Python dependency constraints conflict
  with the required runtime `jsonschema` baseline.
- The public legacy bridge now accepts only registered read-only commands. Direct legacy mutation,
  including v0.5 process execution, is rejected by the v0.6 CLI.
- Initial public CI exposed and corrected platform-neutral reference generation, Linux strict-mypy
  handling of OS-specific APIs, PostgreSQL role provisioning, and Mutmut shadow-tree construction.
- The online Alembic path now wraps revision execution in an explicit migration transaction; the
  PostgreSQL integration test verifies that the committed schema has forced RLS before tenant tests.
- Mutation execution covers the eight configured critical modules. Mutmut result export now passes
  the explicit Boolean required by Mutmut 3.6 before the unchanged 85 percent score gate runs.

## Open authority and scientific findings

1. Authoritative API reads do not yet recompute the complete DSSE, quorum, trusted-time, source,
   lifecycle, and projection chain before every domain decision.
2. PostgreSQL code does not yet commit the full CAS ledger, audit event, idempotency record, outbox
   event, and generation pointer as one serializable domain transaction for every mutation.
3. The reference runner gateway now enforces an Envoy-sanitized certificate identity, signed
   capability and execution-policy authority, leases, attempts, heartbeats, digest-scoped material
   and output admission, receipt replay protection, cleanup evidence, and pending-only projection.
   Its multi-replica PostgreSQL repository, deployed Envoy sidecar, and integration evidence are not
   complete.
4. Minimal/fed siphons, exact flux coupling, cut/enablement sets, deterministic service curves, and
   bounded occurrence prefixes now have closed result kinds and bounded exact reference algorithms.
   Their large-network solver integration, mutation score, and exhaustive differential gate remain
   incomplete.
5. Perturbations support bounded object removal but not every expiry, revocation, and typed value
   change required by the plan.
6. Planner successors do not recompute the complete provenance, lifecycle, scientific,
   coordination, trial, and projection snapshot for every outcome.
7. Coordination and trial kernels validate supplied records, but the authoritative API does not yet
   recompute every event/registration/amendment/result quorum on admission.
8. Remote onboarding still returns conservative bootstrap blockers instead of aggregating every
   live subsystem.

These gaps block any claim that CPCF operationally accelerates a collective. The strongest permitted
statement remains a bounded evidence-control analysis plus separately validated external evidence.

## Publication decision

Public source push is permitted only after the explicit staged allowlist, staged diff, staged
hygiene scan, redacted Gitleaks scan, license/SPDX review, and built wheel/sdist scan pass. PyPI,
tags, and GitHub Releases remain prohibited. The pending publisher claims are project
`collective-phase-control-fabric`, repository `kadubon/collective-phase-control-fabric`, workflow
`workflow.yml`, and environment `pypi`. The GitHub environment requires reviewer `kadubon` with
`prevent_self_review=false`. This is self-approval, not independent release review, and does not
satisfy the independent-review release blocker. `PYPI_PUBLISH_ENABLED` remains false.

Machine-readable status is in `audit/findings-v0.6.json`.
