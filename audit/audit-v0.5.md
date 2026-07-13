# CPCF v0.5 Adversarial Audit

## Verdict

The v0.5 repository was an inspectable research prototype, not an operational or commercial control
system. The checked-in coverage artifact reported 83.18% combined coverage and 76.19% branch coverage;
planning, trials, storage, trust, and execution had substantially lower branch coverage. Passing tests
did not establish semantic assurance.

The audit does not assert that undiscovered defects are impossible. A finding is closed only when a
v0.6 correction and adversarial regression test cover the affected authority path. Several
architectural corrections exist but do not yet satisfy that standard; their machine-readable status
is `partial` or `open`. Release-readiness gates remain independent of finding closure.

## Findings

1. **Schema/runtime substitution — critical.** Native actions, capabilities, and witnesses referred to
   a permissive generic payload rather than one closed runtime type. v0.6 has an exhaustive kind/model
   registry and mechanically generated schema digest. Unknown kinds and fields fail before authority.

2. **Incomplete source binding — critical; partial.** v0.6 models and reconstructs the raw digest,
   source envelope, runner receipt, JSON pointer, projected digest, producer, and independent
   approval. The API transaction that persists and revalidates this complete chain remains open.

3. **Historical trust ambiguity — critical.** Key expiry and later revocation could be applied at the
   wrong time. v0.6 evaluates validity at trusted signing time and gives revocation explicit
   prospective/retroactive semantics. Genesis binds both root SPKI and complete-envelope fingerprints.

4. **Filesystem CAS redirection — high.** Legacy local CAS components could cross a link/reparse-point
   boundary. v0.6 authoritative storage uses validated tenant-bound S3 keys and digest rechecks; legacy
   filesystem input is read-only and link-rejected.

5. **Non-hermetic local execution — critical; partial.** v0.6 removes adapter execution from API and
   analysis workers and validates lease-bound runner receipts. The outbound-mTLS claim, lease API,
   artifact transfer, descendant conformance, and deployed runner identity checks remain open.

6. **Witness-invented science — critical; partial.** The kernel derives resources, food, supply, rates,
   and independence from closed typed documents. The authoritative-read path does not yet recompute
   every DSSE and quorum chain before admitting those documents to the snapshot.

7. **Optimistic perturbation replay — critical; partial.** Object-removal replay constructs a reduced
   basis and invokes the shared kernel. Expiry, revocation, resource modification, and several
   replacement classes are not yet represented by the reduced-snapshot model.

8. **Incomplete contingent planning — critical; partial.** v0.6 hard-filters the complete registry,
   preserves Pareto coordinates, propagates four outcomes, rejects overflow, and detects repeated
   states. Successors do not yet recompute a complete provenance/science/trial snapshot.

9. **Unauthenticated coordination — high; partial.** v0.6 validates a hash-chained event state machine
   with commitments, reveals, integration, exposure bounds, deadlines, and termination. Admission
   still depends on an upstream authoritative ledger; the validator itself does not verify each
   event's DSSE.

10. **Selective trial evidence — critical; partial.** v0.6 retains duplicate results and makes several
    timing, artifact, outcome, and quality failures overriding. Registration and amendment quorum
    signatures are not yet recomputed by the trial evaluator.

11. **Misleading onboarding and operations — high; open.** v0.6 adds a stable response envelope,
    OIDC/RLS reference server, immutable jobs, runner models, Helm deployment, and conservative
    onboarding. Onboarding currently reports a safe static blocker set rather than aggregating every
    live subsystem required by the plan.

12. **Unreproducible Python environment — high.** The declared Python range conflicted with NetworkX
    metadata and CI used pip with stale critical modules. v0.6 uses uv 0.11.28, Python 3.14.6,
    CPython 3.12–3.14 compatibility, a universal lock, frozen CI, and current v0.6 coverage targets.

## Findings discovered during v0.6 verification

13. **Cross-request idempotency replay — critical; partial.** The initial v0.6 control-plane cache
    keyed responses only by tenant and caller-provided idempotency key. Reusing a key for a different
    path, body, subject, or expected generation could replay an unrelated response. Cache entries now
    bind a canonical request fingerprint and conflicting reuse returns a stable 409 response. Atomic
    coupling of the idempotency record and every future domain mutation remains a database-level
    release blocker.

14. **Public schema discovery required credentials — medium.** The API intentionally exposes its
    immutable schema registry without authentication, but the CLI initially required `CPCF_TOKEN`
    for every request. Schema commands now omit authorization when no token exists, while all tenant
    operations continue to fail closed.

15. **Universal lock excluded from source control — high.** The initial conversion retained a legacy
    `.gitignore` rule for `uv.lock`, so a clean checkout could not reproduce the reviewed environment.
    The rule is removed; only generated requirement exports and reproduction directories are ignored.

Machine-readable details and regression-test mappings are in `audit/findings-v0.5.json`. Local
focused v0.6 branch coverage is 71.50%, so the 95% critical-module gate remains open.
