# Agent Contract

CPCF v0.6 is an evidence-control platform, not an autonomous agent runtime. Start with
`cpcf auth login --json`, inspect `cpcf schema list --json`, and then use
`cpcf agent onboard --workspace WORKSPACE --json`. Follow `next_safe_commands` only after checking
their tenant, generation, authority, and effect class.

The CLI sends authenticated requests to the configured control plane. It does not persist bearer
tokens. The API and analysis worker never execute adapter code. Customer runners pull short-lived,
signed jobs using an external mTLS boundary and return attempt- and lease-bound receipts. A runner's
isolation assertion is not a containment proof.

Scientific audit keeps provenance, trust, time, reachability, formation, dimensions, organization,
finite-horizon resources, RAF, verifier capacity, independence, coordination, and perturbations as
separate results. Unknown or budget-limited evidence remains unknown. External acceleration tiers
mean that registered records are binding-compatible; CPCF does not validate causality or a
statistical method.

v0.1-v0.5 are read-only. Legacy import may copy raw bytes, but every authority-bearing legacy
object remains quarantined until a new v0.6 attestation and required quorum decision exist.
