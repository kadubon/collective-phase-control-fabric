# Security Policy

## Supported versions

Only v0.6 receives security fixes. v0.1–v0.5 are inspection-only and must not execute or establish
v0.6 authority.

## Security boundary

CPCF authenticates typed evidence, immutable generations, role quorums, and external runner receipts.
It does not protect against compromise of the local administrator, kernel, PostgreSQL superuser,
object-store administrator, tenant KMS quorum, OIDC issuer, or trusted-time authority. Single-region
failure and simultaneous compromise of every required quorum role remain outside the integrity claim.

The API and worker never execute adapter code. Customer runners are separate trust domains. mTLS and
a signed receipt authenticate a runner statement; they do not prove filesystem, network, kernel, or
descendant-process containment. Isolation is reported only from a policy-recognized independent
attestation.

PostgreSQL RLS is defense in depth. Application roles must not own tables, be superusers, or hold
`BYPASSRLS`. The schema uses `FORCE ROW LEVEL SECURITY`; backup and migration roles are isolated and
audited. Object keys include a validated tenant and SHA-256 digest, and retrieved bytes are rehashed.

## Static-analysis exceptions

Bandit B404 and B603 are suppressed only at the legacy read-only process boundary. The import is
required for v0.1-v0.5 inspection compatibility; invocation uses a canonical argument list,
`shell=False`, a minimal environment, bounded streams, and process-group cleanup. Native v0.6 API
and worker code contains no subprocess execution path.

## Reporting

Use the repository host's private vulnerability-reporting channel. Include the affected version,
minimal reproduction, security impact, and proposed remediation if known. Do not include production
keys, tokens, tenant data, evidence payloads, or live endpoints.

Public issues are appropriate only after sensitive details have been removed. No response-time or
remediation-time guarantee is claimed until a staffed security response process is externally
established.
