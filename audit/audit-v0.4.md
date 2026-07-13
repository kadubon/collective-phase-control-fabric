# CPCF v0.4 Adversarial Audit

## Verdict

The v0.4 implementation was internally consistent but not operationally trustworthy. Its test
count and aggregate branch coverage did not expose semantic gaps in genesis authentication,
schema enforcement, path construction, adapter material pinning, dimensional resource equations,
perturbation replay, multi-step planning, trial registration, or onboarding.

v0.5 is intentionally incompatible. v0.1-v0.4 workspaces remain inspectable, but their signatures,
actions, projections, receipts, certificates, and witnesses cannot execute or promote state. A
copy-on-write v0.5 migration preserves legacy bytes under quarantine and requires a fresh signed
genesis, unit registry, trusted time, contract, and attestations.

## Corrections

- Genesis now signs the complete trust policy and is checked against an out-of-band root
  fingerprint. Signed headers bind the canonicalization profile, schema digest, principal, key,
  role, scope, source, time, and payload digest.
- High-impact trust updates, protocol registration, projection promotion, and strongest empirical
  compatibility require distinct roles, principals, keys, and infrastructure domains. This is not
  threshold cryptography.
- The ledger uses a closed kind-to-schema registry. Generation identifiers, `CURRENT`, chain depth,
  lock acquisition, history events, symlinks, junctions, and reparse points are bounded or rejected.
- Execution copies every declared executable and material from CAS, validates output against the
  signed schema and selector, inventories the complete workspace, records descendant cleanup, and
  requires `UNSANDBOXED_LOCAL_EXECUTION`. CPCF still provides no read or network sandbox.
- Adapter output creates pending projections. Promotion reconstructs exact raw pointers and
  requires disjoint projection authority and verification.
- Resource persistence uses rational dimensioned markings, action counts, boundary rates, duration,
  exact prefix equations, protected floors, and source-backed fed-siphon obligations.
- Structural diagnostics now include exact rational nullspaces and coupling, bounded minimal cuts,
  and a scoped 1-safe occurrence prefix with conflict and cutoff events.
- Perturbations rebuild reduced snapshots and rerun the shared trust and science kernel. Planning
  propagates generation, time, provenance, resources, debt, verification, independence, hazards,
  scientific status, and trial bindings through all outcomes.
- Coordination is an explicit bounded commit-reveal state machine. Trial evidence preserves
  descriptive, observational, quasi-experimental, and randomized tiers and requires independent
  registration time, typed artifacts, amendments, evaluator binding, complete outcomes, and one
  primary result.

## Scientific boundary

CPCF uses closure, formation, open-boundary accounting, constrained flux, catalysis, siphons, and
persistence as formal distinctions. It does not infer chemical kinetics, thermodynamic
feasibility, entropy production, a physical phase, intelligence, or causality. Its strongest native
statement is `operational_organization_compatible`; measured acceleration remains a separately
validated external evidence state.

The machine-readable finding registry is `audit/findings-v0.4.json`. A closed entry means the
specific known exploit has a correction and regression test. It does not imply that undiscovered
defects are impossible. The coverage acceptance finding remains open until the required per-module
branch thresholds are measured and met.

## Verification status

The final v0.5 implementation run completed 253 tests on Windows with Python 3.13 and again in a
clean Python 3.14 environment with the declared solver extra. Ruff formatting and linting, strict
mypy, Bandit, all 160 schema checks, and all fixture checks passed. Branch coverage was measured
without omissions at 83.18%, below the 90% aggregate and 95% native-subsystem acceptance
thresholds. Therefore `V5-QA-001` remains open and this audit does not represent v0.5 as
release-qualified.
