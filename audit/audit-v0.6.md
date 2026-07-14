# CPCF v0.6 Final Pre-Release Audit

## Verdict

The repository now builds one installable distribution with a useful offline first-run path,
runtime-derived references, frozen `uv` resolution, and a fail-closed publication workflow. It is
appropriate for public source review after the staged-content hygiene gate passes.

It is not eligible for a stable tag, GitHub Release, PyPI upload, or operational-assurance label. Several
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
  release-only, version-matched, protected by the `pypi` environment, disabled unless
  `PYPI_PUBLISH_ENABLED=true`, and now depends on closed commit-bound external evidence. No release
  manifest exists, so stable release assets and publication fail closed.
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
- Exact repair-namespace tests exposed and corrected `trusted_time_*` blockers being classified as
  generic trust blockers because of overlapping prefix order. The tests cover every registered
  namespace and its exact required document and authority outputs. The parent native-Linux
  mutation job passed at 85.37 percent across 7,623 counted mutants; the child commit still requires
  its own run.
- CI and release mutation jobs retain a short-lived diagnostic result artifact before enforcing the
  unchanged score. This artifact is evidence for test repair, not a release distribution.
- The first OCI conformance run exposed missing package forced-includes in both service build
  contexts. Images now copy the same agent guidance, fixtures, and documentation required by the
  wheel, and missing SARIF files no longer produce a misleading upload error after a build failure.

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
4. Minimal/fed siphons, exact flux coupling, cut/enablement sets, deterministic service curves,
   inhibited generalized/generative RAFs, and bounded occurrence prefixes now have closed result
   kinds, an integrated intervention portfolio, exact bounded reference algorithms, and
   small-network differential tests. Large-network solver profiles and the full mutation gate remain
   incomplete.
5. Perturbations now resolve typed object, principal, key, source, state, transformation, resource,
   supply, rate, catalyst, inhibitor, verifier, infrastructure, coordination, and independence
   selectors; they can advance only through a trusted-time receipt and can bind typed replacement
   objects. A loader-authenticated signed replacement chain and every revocation/value-change
   integration path remain release gates.
6. Planner successors keep hypothetical additions pending, preserve exact resource trajectories and
   operational facets, apply worst-case removal, and rerun the shared audit kernel for every outcome.
   API use of only loader-approved capabilities and differential coverage for every typed replacement
   remains incomplete.
7. Coordination now binds plan and event actors to verified statement principals and validates the
   event hash chain, deadlines, commitments, reveals, exposure, verifier capacity, integration, and
   termination. Trial assessment retains every primary result and checks typed artifacts, CAS
   presence, signer identity, registration/amendment/result quorums, time order, and outcome
   completeness. The API queues these admissions fail-closed, but the production worker's
   end-to-end admission transaction remains a release gate.
8. Remote onboarding now aggregates typed live diagnostics for trust, time, ledger, quarantine,
   science, perturbation, solver, planner, runner, projections, coordination, trials, quotas, and
   repairs. Missing diagnostics remain unknown and repairs remain unbound unless they carry a
   signed action digest. PostgreSQL-backed end-to-end diagnostic population remains a release gate.
9. The API and worker image dependency omission is corrected: both install their explicit extras,
   use digest-pinned base images, and expose provider-specific KMS targets. Helm uses separate
   service accounts and an explicit owner-only migration hook. The incomplete tenant-scoped worker
   and migration hook are disabled by default; multi-tenant worker processing remains a release
   blocker.
10. Deterministic load, chaos, and restore reference harnesses now emit commit-bound exact JSON.
    They are deliberately not accepted as availability, PostgreSQL, S3, RPO/RTO, or intended-
    deployment evidence. The stable-release checker requires those external gates separately.

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

## Science/control assurance added in the staged implementation

- The perturbation API no longer accepts an unsigned caller-selected evaluation time. Time movement
  requires a referenced `trusted-time-receipt`, must be monotonic, and must match tenant/workspace.
- Duplicate live typed identities now invalidate provenance instead of being overwritten by map
  construction.
- A persistence action count must have a live transformation-rate attestation and remain inside its
  exact rational interval; only a positive lower supply rate can discharge a fed-siphon obligation.
- Inhibited generalized RAF membership is enumerated exactly within the fixed 20-transformation
  profile, and strict-prior generative layers are checked separately. Exhaustion remains unknown.
- Planner `must_add` values create pending projections only. They cannot enter `live_objects`, clear a
  scientific dimension, or become evidence before independent receipt-backed promotion.
- The focused science, structural, planning, and intervention branch-coverage gate is above 95
  percent. Full mutation and external integration gates remain blocking.

## Coordination, trial, and onboarding assurance added in the staged implementation

- The authoritative loader exposes verified subject-to-statement/principal bindings and rejects a
  typed coordination or trial actor that is not a verified signer in its declared role.
- Measurement protocols, amendments, and trial results require exactly one recomputed matching
  quorum decision before they can remain authoritative.
- The coordination kernel reconstructs one event chain and validates proposal preimages, actor
  binding, deadlines, exposure recipients, verifier capacity and outcome, integration evidence, and
  signed termination. Its focused branch coverage is complete.
- Trial assessment distinguishes provenance blockers from outcome contradictions, retains
  unexpected and duplicate primary results, and never selects a favorable replacement. Its focused
  branch coverage is complete.
- The CLI and API expose generation- and idempotency-bound queued workflows. A `202 accepted`
  response explicitly grants no admission or scientific claim.
- OIDC device login uses the current keyring 25.7 series and stores an access token only in a secure
  OS keyring. `CPCF_TOKEN` remains the explicit non-persistent fallback.

## Operations and release assurance added in the staged implementation

- Local regression: 547 passed and three service-dependent tests skipped. Full branch-enabled
  coverage is 90.46 percent; all 12 named critical groups independently exceed 95 percent.
- Strict mypy now covers operational scripts and exposed an archive-member type error that was
  corrected. The source, wheel, and sdist hygiene gate also rejects critical coverage reports.
- OTLP/HTTP telemetry is opt-in, credential-free, payload-free, and HTTPS-only unless a controlled
  deployment explicitly acknowledges insecure transport.
- Helm 3.21.1 is checksum-pinned for Kubernetes 1.36 lint/render checks. OCI security jobs build and
  scan both service images in addition to scanning the source tree.
