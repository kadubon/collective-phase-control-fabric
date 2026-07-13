# CPCF v0.6 Normative Specification

This document defines the v0.6 target semantics. A target clause is not an implementation claim.
The conformance gaps in `audit/audit-v0.5.md` and `docs/release-readiness.md` are normative blockers:
an implementation must return unknown or refuse promotion when an unimplemented authority path is
required.

## Native result

CPCF evaluates one immutable `AnalysisSnapshot` and returns thirteen named dimensions with status
`satisfied`, `violated`, `unknown`, or `unknown_due_to_budget`. The Boolean
`operational_organization_compatible` is true only when every mandatory dimension is satisfied.
Legacy phase levels are inspection metadata and have no ordering relation to v0.6.

## Documents and schemas

Every native document has `api_version`, a closed `kind`, typed `metadata`, typed `spec`, and bounded
reverse-DNS `extensions`. One registry maps each kind to one Pydantic model and one immutable generated
JSON Schema digest. Unknown fields and unknown kinds fail before authority evaluation.

Raw inputs are byte-limited and lexically depth-scanned before JSON parsing. Duplicate keys,
floating-point values, oversized collections, excessive rational bit length, and computation-budget
exhaustion return stable failures or `unknown_due_to_budget`.

## Authority

DSSE signs exact canonical bytes containing a protected header and typed subject. The protected header
binds identity, schema, content, tenant, workspace, role, source, scope, policy sequence, signing time,
and trusted-time receipt. Envelope key IDs are hints only. Key validity is evaluated at trusted signing
time; revocation and compromise follow their declared effective-time and prospective/retroactive mode.

Role-quorum signatures cover an identical subject digest. Required principals and public keys are
distinct; policy-selected infrastructure and correlation domains are also disjoint. This is not
threshold cryptography.

## Storage

CAS objects are immutable tenant-bound SHA-256 bytes. A conforming PostgreSQL implementation commits
the typed ledger, event-chain head, outbox records, and current-generation pointer in one serializable
transaction after every CAS object is verified. Mutations compare the expected generation. The
checked-in PostgreSQL unit of work implements this atomic boundary for generation commits. API-wide
use and crash-matrix evidence remain required before storage conformance can be claimed.

## Execution and projection

A conforming control plane signs finite job specifications but executes no adapter. An authenticated
external runner claims a short lease and returns a signed receipt. Timeout, stale lease, replay,
image/material substitution, truncated required output, incomplete cleanup, or unrecognized
isolation maps to failure. Output remains pending until exact pointer reconstruction and independent
approval. The checked-in reference runner gateway implements certificate-identity parsing, bounded
leases, attempts, heartbeats, artifact admission, signed receipt validation, and pending projection
creation behind an identity-sanitizing Envoy boundary contract. A multi-replica PostgreSQL runner
repository, deployed Envoy sidecar, and transactional promotion endpoint remain release blockers.

## Science and planning

The shared kernel is normative for baseline, perturbation, and planner states. Initial quantities and
boundary supply derive only from live typed attestations. Formation requires inputs, catalyst clauses,
evidence, and authority strictly before a transformation layer. Exact organization uses one
target-bound transformation set and positive rational maintenance flux. Finite-horizon persistence
checks every resource prefix. RAF, verifier capacity, effective independence, coordination, and
perturbations remain separate dimensions.

The planner gives no credit for optional output. Safety uses worst-case removal and resource bounds.
After complete hard filtering, exact semantic duplicates and branch-wise dominated actions are
removed. More than 64 eligible nondominated actions returns unknown. Horizon one is exhaustive;
horizons two and three use deterministic width-32 AND–OR search. The current planner propagates a
bounded abstract effect state rather than rerunning the full authority and scientific kernel at each
successor; it must not be described as full-state strong control until that gap closes. The planner
emits no scalar intelligence, utility, or probability score.

## External measurement

CPCF must retain every registered primary result and protocol deviation. It validates provenance,
registration order, assignment/dataset/executable bindings, outcome completeness, interval direction,
and quality floors. It does not validate the statistical method or certify causality. Contradiction or
protocol deviation overrides favorable evidence tiers. The current trial evaluator checks typed
artifact bindings and contradictions but does not independently recompute all registration and
amendment DSSE quorums; strongest-tier promotion remains blocked on that path.
