# Deployment

The reference deployment targets a single-region, multi-availability-zone Kubernetes 1.36 cluster,
PostgreSQL 18, an S3-compatible immutable object store, OIDC, and KMS/HSM-backed signing. It is a
reference architecture, not a production-readiness claim.

API and worker images run non-root with read-only roots, dropped capabilities, RuntimeDefault
seccomp, resource limits, topology spreading, disruption budgets, distinct service accounts, and
default-deny network policies. The analysis worker never runs adapter code.

Customer-controlled runners use outbound-only mTLS pull. The reference gateway now validates the
single sanitized client-certificate identity supplied by Envoy, binds it to a registered runner,
and enforces signed leases, attempts, artifact limits, receipts, and pending projections. It is an
in-memory conformance implementation. The multi-replica PostgreSQL repository, deployed Envoy
sidecar, and chaos/load evidence remain release blockers.

Production configuration must provide image digests, OIDC issuer/audience/JWKS, tenant database
roles, object-store policy, KMS identities, trusted roots, backup policy, egress policy, and
observability endpoints. Application database roles must neither own protected tables nor hold
`BYPASSRLS`.
