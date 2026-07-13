# Deployment

The reference deployment targets a single-region, multi-availability-zone Kubernetes 1.36 cluster,
PostgreSQL 18, an S3-compatible immutable object store, OIDC, and KMS/HSM-backed signing. It is a
reference architecture, not a production-readiness claim.

API and worker images run non-root with read-only roots, dropped capabilities, RuntimeDefault
seccomp, resource limits, topology spreading, disruption budgets, distinct service accounts, and
default-deny network policies. The analysis worker never runs adapter code.

Customer-controlled runners are intended to use outbound-only mTLS pull. The repository currently
contains closed job/receipt models and conformance checks; the complete lease transport and its
chaos/load evidence remain release blockers.

Production configuration must provide image digests, OIDC issuer/audience/JWKS, tenant database
roles, object-store policy, KMS identities, trusted roots, backup policy, egress policy, and
observability endpoints. Application database roles must neither own protected tables nor hold
`BYPASSRLS`.
