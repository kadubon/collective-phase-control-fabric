# Runner mTLS Gateway Contract

`runner-gateway.yaml` is the checked-in Envoy sidecar contract for the separate runner API. Envoy
requires a TLS 1.3 client certificate rooted in the mounted runner CA, restricts the URI SAN shape,
replaces any inbound `X-Forwarded-Client-Cert` value with its verified certificate observation,
removes untrusted CPCF identity headers, and forwards only to `127.0.0.1:8081`.

The Python gateway independently binds the resulting URI SAN and certificate fingerprint to a
registered runner principal. The header is not accepted from an Internet-facing path that bypasses
this Envoy listener. Kubernetes deployment of the sidecar and the multi-replica PostgreSQL lease
repository remain release blockers; this file alone is not a containment or production-readiness
claim.
