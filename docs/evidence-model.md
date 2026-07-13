# Evidence Model

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
