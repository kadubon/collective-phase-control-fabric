# Evidence Model

The 0.7 frontier adds closed companion kinds without changing the existing signed schemas.
Offline model activation creates no observation or admission. Frontier evidence reassessment
reuses the existing `protocol_registration` quorum, validates original growth observations and
runner receipts, and requires admitted action/capability/execution-policy subjects before an
activation can be carried into a new unsigned modelling proposal. Ambiguous receipt outcomes
cannot select a favorable frontier. Replanning preserves signed history, depth and prerequisite
expiry, and requires fresh original materials rather than a cached assessment. See the
[frontier evidence path](endogenous-capability-frontier.md#receipt-backed-advancement-and-admission).

Every native v0.6 document uses `api_version`, a closed `kind`, metadata, a typed `spec`, and
non-authoritative reverse-DNS extensions. One runtime model maps to one generated schema digest.

Signed evidence uses DSSE. The canonical payload binds schema identity, subject digest, tenant,
workspace, principal, role, scope, signing time, policy sequence, and trusted-time receipt. Envelope
key identifiers are lookup hints; admitted public keys and the protected payload establish
authority.

Ordinary attestations are single-principal statements. High-impact decisions require identical
subjects signed by role-separated principals and keys. This is role separation, not threshold
cryptography. Compromise of all principals required for one decision compromises that decision.

Historical verification distinguishes signing-time validity, later expiry, prospective revocation,
and retroactive compromise. Local wall-clock time cannot establish authoritative expiry or
preregistration order.

Unknown evidence never receives favorable treatment. Cached validation fields are diagnostic only;
an authoritative reader must recompute signatures, schema identity, source pointers, lifecycle,
quorum, and projection chains.

## Growth observation admission

Growth plans preserve hypothetical output, pending results, receipt-backed observations
and independently admitted capability as separate states. The new observation kind
requires the existing evaluator/quality-safety/timestamp quorum and full admission material.
Reassessment reuses authoritative-generation loading, runner receipt validation, and
registered trial compatibility; a cached assessment Boolean has no admission role.
Raw CAS artifacts remain opaque even when their bytes parse as a native document. Only
explicitly typed, admitted ledger records participate in authority evaluation.
See [the complete external evidence path](growth-planning.md#independently-admitted-external-evidence).

Frontier assessments additionally retain the exact unsigned contract/frontier proposal pair
used to check prospective continuation. Replanning freshly validates the original admission
materials and returns that same pair, keeping the policy and state digests consistent. A cached
assessment or an embedded modelling proposal does not supply admission or execution authority.
