# Operations Evidence

CPCF separates deterministic reference harnesses from deployment evidence.

The CI reference job executes:

```text
uv run --frozen python scripts/run_load_harness.py --commit COMMIT --out load.json
uv run --frozen python scripts/run_chaos_harness.py --commit COMMIT --out chaos.json
uv run --frozen python scripts/run_restore_harness.py --commit COMMIT --out restore.json
```

The load profile creates 100 tenants and 10,000 in-memory workspaces and admits 100 concurrent
audit jobs. The chaos harness exercises deterministic transaction, duplicate-delivery, lease,
object-store, and identity-rotation models. The restore harness checks canonical metadata, CAS,
generation, and history reconstruction. Each result is commit-bound and content-digested.

These harnesses do not establish Kubernetes availability, PostgreSQL failover, S3 durability, KMS
or OIDC availability, RPO/RTO, or production latency. Those claims require evidence from the
intended deployment. A stable release consumes a closed manifest described in
[`release-evidence/README.md`](../release-evidence/README.md); missing evidence blocks release
assets and PyPI publication.

No evidence payload is exported through telemetry. Operators may configure an HTTPS OTLP/HTTP
collector endpoint for request method/status, service counters, worker budgets, queue depth,
quarantine counts, lease state, and trust-expiry metadata. Tenant evidence contents, bearer tokens,
DSSE payloads, and source artifacts must not be attributes, logs, or trace events.
