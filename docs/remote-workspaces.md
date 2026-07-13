# Remote Workspace Use

Remote commands use `CPCF_API_URL` and a short-lived bearer token in `CPCF_TOKEN`. The CLI does not
store credentials.

```text
set CPCF_API_URL=https://cpcf.example.org
set CPCF_TOKEN=OIDC_ACCESS_TOKEN
cpcf workspace create WORKSPACE --root-spki-fingerprint sha256:ROOT_SPKI_SHA256 --genesis-envelope-fingerprint sha256:GENESIS_ENVELOPE_SHA256 --json
cpcf object upload WORKSPACE SIGNED_STATEMENT.json --generation sha256:GENERATION --json
cpcf workspace status WORKSPACE --json
cpcf audit start WORKSPACE --generation sha256:GENERATION --json
cpcf audit status JOB_ID --json
cpcf agent onboard --workspace WORKSPACE --json
```

`workspace create`, `object upload`, and `audit start` are state-changing. Uploaded CAS bytes remain
quarantined and non-authoritative until a later signed admission generation. The CLI supplies an idempotency key; callers
should set `CPCF_IDEMPOTENCY_KEY` when retries must share one identity. Existing-generation
mutations require `If-Match` and fail on a stale generation.

The public control-plane API surface is deliberately narrow. A separate generated runner-gateway
OpenAPI contract covers claim, heartbeat, bounded artifact upload, and completion. Its checked-in
implementation is a deterministic in-memory conformance service, not the multi-replica production
transport. Trust admission, projection approval, coordination, trials, production runner storage,
and complete live onboarding aggregation remain release blockers until their authoritative
endpoints and integration tests are present.
