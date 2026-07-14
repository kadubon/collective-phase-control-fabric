# Deployment

The reference deployment targets a single-region, multi-availability-zone Kubernetes 1.36 cluster,
PostgreSQL 18, an S3-compatible immutable object store, OIDC, and KMS/HSM-backed signing. It is a
reference architecture, not evidence of deployment assurance.

API and worker images install their explicit `server` and `worker` extras, use digest-pinned base
images, and provide separate AWS, Google Cloud, Azure, and PKCS#11 KMS build targets. Pods run
non-root with read-only roots, dropped capabilities, RuntimeDefault seccomp, resource limits,
topology spreading, disruption budgets, distinct service accounts, and default-deny network
policies. The analysis worker never runs adapter code.

The Helm chart enables only the API by default. Worker deployment requires an explicit tenant
partition because the current forced-RLS claim path is tenant-scoped. Database migration is a
separate, disabled-by-default hook image and requires an owner credential distinct from the
application credential. These defaults prevent an incomplete worker or privileged migration role
from being deployed implicitly.

Customer-controlled runners use outbound-only mTLS pull. The reference gateway now validates the
single sanitized client-certificate identity supplied by Envoy, binds it to a registered runner,
and enforces signed leases, attempts, artifact limits, receipts, and pending projections. It is an
in-memory conformance implementation. The multi-replica PostgreSQL repository, deployed Envoy
sidecar, and chaos/load evidence remain release blockers.

Production configuration must provide image digests, OIDC issuer/audience/JWKS, tenant database
roles, object-store policy, KMS identities, trusted roots, backup policy, egress policy, and
observability endpoints. Application database roles must neither own protected tables nor hold
`BYPASSRLS`. OTLP telemetry is opt-in, records method/status and service metrics only, and rejects
plain HTTP unless `CPCF_OTEL_ALLOW_INSECURE=true` is set explicitly for a controlled environment.
